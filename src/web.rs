//! Phase 8 HTTP/TLS web foundation: bounded observations, no crawling.
//!
//! Takes confirmed HTTP/HTTPS services (Phase 7) and records what a single
//! request/response exchange proves: status, headers, cookies (bounded),
//! title, bounded body metadata/sample, redirect chains, and TLS/certificate
//! facts for HTTPS. One exchange per URL, redirects followed only within a
//! small policy cap — never recursive link following, robots/sitemap
//! traversal, directory discovery, endpoint enumeration, fuzzing, wordlists,
//! or vulnerability scanning. Those belong to later phases.
//!
//! # Scope discipline
//!
//! Every connection target — initial URLs and every redirect hop — passes
//! the Scope Guard *before* any byte is sent. Out-of-scope redirect
//! destinations are recorded as observations and never contacted, so no
//! redirect may silently expand scan scope.
//!
//! # Bounds
//!
//! Header count/bytes, body bytes, cookie count/size, redirect hops, read
//! and connect timeouts, task deadlines, and cancellation are all enforced.
//! Oversized responses truncate with explicit flags; malformed responses
//! become evidence, never panics.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::execution::CancellationToken;
use crate::plan::{ScanGoal, SpeedSetting};
use crate::probes::ProbeCtx;

/// Hard ceiling on redirect hops for any single chain, regardless of level.
pub const MAX_REDIRECT_HOPS_HARD: u8 = 5;
/// Maximum response headers parsed per response.
pub const MAX_RESPONSE_HEADERS: usize = 64;
/// Maximum bytes retained for the header block.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
/// Maximum body bytes retained per response.
pub const MAX_WEB_BODY_BYTES: usize = 16 * 1024;
/// Body sample kept inside evidence (prefix of the retained body).
pub const BODY_SAMPLE_BYTES: usize = 1024;
/// Maximum cookies recorded per response.
pub const MAX_COOKIES: usize = 8;
/// Maximum bytes retained per cookie value.
pub const MAX_COOKIE_VALUE_BYTES: usize = 256;
/// Maximum local path+query characters carried into an endpoint identity.
pub const MAX_ENDPOINT_IDENTITY_CHARS: usize = 512;
/// Read slice keeping cancellation prompt during body transfers.
const READ_SLICE_MS: u64 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().as_str() {
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            _ => None,
        }
    }
}

/// Canonical web target. Normalization is deliberately narrow: scheme and
/// host lowercased (trailing dot trimmed), default ports filled so
/// `http://h/` and `http://h:80/` share one stable identity, empty path
/// becoming `/`, query preserved verbatim. Path case, percent-encoding, and
/// query order are preserved — meaningful distinctions are never merged.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WebTarget {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: Option<String>,
}

impl WebTarget {
    pub fn parse(url: &str) -> Result<Self, String> {
        let parsed = url::Url::parse(url.trim()).map_err(|_| format!("invalid URL '{url}'"))?;
        let scheme = Scheme::parse(parsed.scheme())
            .ok_or_else(|| format!("unsupported scheme in '{url}'"))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| format!("URL has no host: '{url}'"))?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if host.is_empty() {
            return Err(format!("URL has empty host: '{url}'"));
        }
        let port = parsed.port().unwrap_or_else(|| scheme.default_port());
        if port == 0 {
            return Err(format!("URL has invalid port: '{url}'"));
        }
        let path = {
            let raw = parsed.path();
            if raw.is_empty() { "/" } else { raw }.to_owned()
        };
        let query = parsed.query().map(str::to_owned);
        Ok(Self {
            scheme,
            host,
            port,
            path,
            query,
        })
    }

    /// Canonical string form. IPv6 hosts render bracketed; the port always
    /// renders so identities never depend on elision rules.
    pub fn canonical(&self) -> String {
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let mut out = format!(
            "{}://{}:{}{}",
            self.scheme.as_str(),
            host,
            self.port,
            self.path
        );
        if let Some(query) = &self.query {
            out.push('?');
            out.push_str(query);
        }
        out
    }

    /// Value shown in human output; default ports elide for readability while
    /// the canonical form (and therefore the stable ID) keeps them.
    pub fn display(&self) -> String {
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let mut out = format!("{}://{}", self.scheme.as_str(), host);
        if self.port != self.scheme.default_port() {
            out.push(':');
            out.push_str(&self.port.to_string());
        }
        out.push_str(&self.path);
        if let Some(query) = &self.query {
            out.push('?');
            out.push_str(query);
        }
        out
    }

    /// `Host` header value: hostname/IP as-is (bracketed for IPv6), with an
    /// explicit port suffix whenever it differs from the scheme default.
    pub fn host_header(&self) -> String {
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == self.scheme.default_port() {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    pub fn is_ip_literal(&self) -> bool {
        self.host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok()
    }

    pub fn ip_literal(&self) -> Option<IpAddr> {
        self.host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .ok()
    }

    /// Resolve a `Location` value against this URL. Returns an error string
    /// for malformed destinations (recorded, never followed, never panics).
    pub fn resolve_location(&self, location: &str) -> Result<Self, String> {
        let location = location.trim();
        if location.is_empty() {
            return Err("empty Location header".to_owned());
        }
        if location.len() > 2048 {
            return Err("Location header exceeds bounds".to_owned());
        }
        let base = url::Url::parse(&self.canonical())
            .map_err(|_| format!("cannot re-parse canonical URL '{}'", self.canonical()))?;
        let joined = base
            .join(location)
            .map_err(|_| format!("malformed redirect destination {location:?}"))?;
        Self::parse(joined.as_str())
    }
}

/// Stable endpoint identity suffix: path plus query, length-capped with an
/// explicit truncation marker so distinct long URLs never merge silently.
pub fn endpoint_local_identity(target: &WebTarget) -> (String, bool) {
    let mut identity = target.path.clone();
    if let Some(query) = &target.query {
        identity.push('?');
        identity.push_str(query);
    }
    if !identity.starts_with('/') {
        identity.insert(0, '/');
    }
    let mut chars: Vec<char> = identity.chars().collect();
    if chars.len() <= MAX_ENDPOINT_IDENTITY_CHARS {
        return (chars.into_iter().collect(), false);
    }
    chars.truncate(MAX_ENDPOINT_IDENTITY_CHARS);
    let mut truncated: String = chars.into_iter().collect();
    truncated.push('…');
    (truncated, true)
}

fn fnv_hex(input: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

/// Stable endpoint-asset ID: full canonical URL including scheme, host,
/// port, path, and query. Different scheme/host/port/path identities never
/// collide by construction.
pub fn endpoint_asset_id(target: &WebTarget) -> String {
    format!("asset_endpoint_{}", fnv_hex(&target.canonical()))
}

/// Bounded observed cookie: name plus a truncated value. No jar is kept and
/// cookies are never replayed in Phase 8 — observations only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedCookie {
    pub name: String,
    pub value: String,
    pub value_truncated: bool,
}

pub fn parse_set_cookies(header_block: &str) -> (Vec<ObservedCookie>, bool) {
    let mut cookies = Vec::new();
    let mut truncated = false;
    for line in header_block.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        if cookies.len() >= MAX_COOKIES {
            truncated = true;
            break;
        }
        let pair = value.split(';').next().unwrap_or("").trim();
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = name.trim().to_owned();
        if name.is_empty() || name.len() > 256 {
            continue;
        }
        let value = value.trim();
        let mut chars: Vec<char> = value.chars().collect();
        let value_truncated = chars.len() > MAX_COOKIE_VALUE_BYTES;
        if value_truncated {
            chars.truncate(MAX_COOKIE_VALUE_BYTES);
        }
        cookies.push(ObservedCookie {
            name,
            value: chars.into_iter().collect(),
            value_truncated,
        });
    }
    (cookies, truncated)
}

/// One fetched HTTP response: protocol facts plus bounded content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub version: String,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub headers_truncated: bool,
    pub server: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<String>,
    pub location: Option<String>,
    pub cookies: Vec<ObservedCookie>,
    pub cookies_truncated: bool,
    pub title: Option<String>,
    pub body_bytes: usize,
    pub body_truncated: bool,
    pub body_sample: String,
    pub latency_ms: u64,
}

impl HttpResponse {
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status) && self.location.is_some()
    }
}

/// Parse a raw response head+body into a bounded [`HttpResponse`].
/// Returns `None` when the bytes are not valid HTTP — malformed input is a
/// miss, never a panic, never a guess.
pub fn parse_response(raw: &[u8], latency_ms: u64) -> Option<HttpResponse> {
    let (facts, header_end) = crate::probes::parse_http_response(raw)?;
    let head = std::str::from_utf8(&raw[..header_end]).ok()?;
    let mut headers = Vec::new();
    let mut headers_truncated = false;
    for line in head.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if headers.len() >= MAX_RESPONSE_HEADERS {
            headers_truncated = true;
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.is_empty() || name.len() > 256 || value.len() > 4096 {
            continue;
        }
        if name.eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        headers.push((name.to_owned(), value.to_owned()));
    }
    let (cookies, cookies_truncated) = parse_set_cookies(head);
    let body = &raw[header_end.min(raw.len())..];
    let body_truncated = body.len() >= MAX_WEB_BODY_BYTES;
    let title = crate::probes::extract_title(body);
    let sample: String = String::from_utf8_lossy(&body[..body.len().min(BODY_SAMPLE_BYTES)])
        .chars()
        .take(BODY_SAMPLE_BYTES)
        .collect();
    Some(HttpResponse {
        version: facts.version,
        status: facts.status,
        reason: facts.reason,
        headers,
        headers_truncated,
        server: facts.server,
        content_type: facts.content_type,
        content_length: facts.content_length,
        location: facts.location,
        cookies,
        cookies_truncated,
        title,
        body_bytes: body.len(),
        body_truncated,
        body_sample: sample,
        latency_ms,
    })
}

/// Read a close-delimited response body up to `max_bytes`, in short slices
/// so cancellation stays prompt. Returns (bytes, truncated).
pub fn read_bounded_body<R: Read>(
    reader: &mut R,
    max_bytes: usize,
    timeout: Duration,
    cancel: &CancellationToken,
    deadline: Instant,
    started: Instant,
) -> (Vec<u8>, bool) {
    let mut body = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if cancel.is_cancelled() || Instant::now() >= deadline || started.elapsed() >= timeout {
            return (body, true);
        }
        if body.len() >= max_bytes {
            // Drain nothing further: remaining bytes belong to the socket,
            // not to us. Mark truncation and stop.
            return (body, true);
        }
        match reader.read(&mut chunk) {
            Ok(0) => return (body, false),
            Ok(count) => {
                let room = max_bytes.saturating_sub(body.len());
                if room == 0 {
                    return (body, true);
                }
                let take = count.min(room);
                body.extend_from_slice(&chunk[..take]);
                if take < count {
                    return (body, true);
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                return (body, false);
            }
            Err(_) => return (body, true),
        }
    }
}

/// One hop of a redirect chain: what was requested, what answered, and
/// whether the destination was followed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectHop {
    pub url: String,
    pub status: u16,
    pub location: Option<String>,
    pub followed: bool,
    pub follow_reason: String,
}

/// Raw fetched bytes plus transport facts, before classification.
#[derive(Debug)]
pub struct RawFetch {
    pub head: Vec<u8>,
    pub body: Vec<u8>,
    pub head_truncated: bool,
    pub body_truncated: bool,
    pub latency_ms: u64,
    pub tls: Option<crate::tls::TlsObservation>,
    pub tls_leaf_der: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub enum FetchFailure {
    Cancelled,
    Timeout,
    Connection(String),
    Tls(String),
}

/// Position just past the `\r\n\r\n` header terminator, if present.
pub(crate) fn head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

/// Read one response head (until `\r\n\r\n`) plus an optional bounded body
/// from any byte stream. Shared by plaintext and TLS transports.
fn read_head_and_body<R: Read>(
    reader: &mut R,
    read_body: bool,
    body_cap: usize,
    timeout: Duration,
    cancel: &CancellationToken,
    deadline: Instant,
    started: Instant,
) -> (Vec<u8>, Vec<u8>, bool, bool) {
    let mut head = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut head_truncated = false;
    // Bytes arriving past the header terminator belong to the body, not the
    // head: without this handoff a single segment carrying head+body would
    // defeat the body cap (same framing discipline as the MySQL reader).
    let mut surplus = Vec::new();
    loop {
        if cancel.is_cancelled() || Instant::now() >= deadline || started.elapsed() >= timeout {
            return (head, Vec::new(), true, true);
        }
        if head.len() >= MAX_HEADER_BYTES {
            head_truncated = true;
            break;
        }
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                let room = MAX_HEADER_BYTES.saturating_sub(head.len());
                if room == 0 {
                    head_truncated = true;
                    break;
                }
                let take = count.min(room);
                head.extend_from_slice(&chunk[..take]);
                if let Some(end) = head_end(&head) {
                    surplus.extend_from_slice(&head[end..]);
                    head.truncate(end);
                    break;
                }
                if take < count {
                    head_truncated = true;
                    break;
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(_) => break,
        }
    }
    if !read_body {
        return (head, Vec::new(), head_truncated, false);
    }
    let (mut body, mut body_truncated) =
        read_bounded_body(reader, body_cap, timeout, cancel, deadline, started);
    if !surplus.is_empty() {
        // Surplus arrived inside the head window: it counts against the body
        // budget first, preserving arrival order.
        let mut combined = std::mem::take(&mut surplus);
        let room = body_cap.saturating_sub(combined.len());
        if room < body.len() {
            body.truncate(room);
            body_truncated = true;
        }
        combined.extend_from_slice(&body);
        body = combined;
    }
    (head, body, head_truncated, body_truncated)
}

/// Fetch one URL over plaintext HTTP. Exactly one request is written.
#[allow(clippy::too_many_arguments)]
/// `body_cap` bounds retained body bytes (Phase 8 passes
/// [`MAX_WEB_BODY_BYTES`]; Phase 9 crawling passes a larger extraction cap).
/// Header caps are unchanged.
pub fn fetch_plain(
    ip: IpAddr,
    target: &WebTarget,
    method: &str,
    read_body: bool,
    body_cap: usize,
    connect_timeout: Duration,
    response_timeout: Duration,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<RawFetch, FetchFailure> {
    if cancel.is_cancelled() {
        return Err(FetchFailure::Cancelled);
    }
    let started = Instant::now();
    let ctx = ProbeCtx {
        ip,
        port: target.port,
        host_label: &target.host,
        timeout: connect_timeout,
        deadline,
        cancel,
    };
    let mut stream = ctx.connect().map_err(|reason| {
        if reason.contains("cancelled") || reason.contains("deadline") {
            FetchFailure::Cancelled
        } else {
            FetchFailure::Connection(reason)
        }
    })?;
    ProbeCtx::timebox(&stream, READ_SLICE_MS);
    let request = build_request(method, target, &request_path_query(target));
    if started.elapsed() >= response_timeout || Instant::now() >= deadline {
        return Err(FetchFailure::Timeout);
    }
    stream
        .write_all(&request)
        .map_err(|error| FetchFailure::Connection(format!("request write: {error}")))?;
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .min(response_timeout);
    let (head, body, head_truncated, body_truncated) = read_head_and_body(
        &mut stream,
        read_body,
        body_cap,
        remaining,
        cancel,
        deadline,
        started,
    );
    if cancel.is_cancelled() {
        return Err(FetchFailure::Cancelled);
    }
    Ok(RawFetch {
        head,
        body,
        head_truncated,
        body_truncated,
        latency_ms: started.elapsed().as_millis() as u64,
        tls: None,
        tls_leaf_der: None,
    })
}

/// Fetch one URL over TLS (HTTPS). Reuses the Phase 7 observation-only TLS
/// session primitive; the handshake observation and leaf DER travel with the
/// raw bytes for certificate evidence.
#[allow(clippy::too_many_arguments)]
/// See [`fetch_plain`]: `body_cap` bounds retained body bytes for
/// extraction-heavy callers.
pub fn fetch_tls(
    ip: IpAddr,
    target: &WebTarget,
    server_name: Option<&str>,
    method: &str,
    read_body: bool,
    body_cap: usize,
    connect_timeout: Duration,
    response_timeout: Duration,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<RawFetch, FetchFailure> {
    if cancel.is_cancelled() {
        return Err(FetchFailure::Cancelled);
    }
    let started = Instant::now();
    let mut session = crate::tls::connect_tls(
        ip,
        target.port,
        server_name,
        connect_timeout.min(Duration::from_millis(3000)),
        cancel,
    )
    .map_err(|failure| match failure {
        crate::tls::TlsFailure::Cancelled => FetchFailure::Cancelled,
        crate::tls::TlsFailure::Timeout => FetchFailure::Timeout,
        crate::tls::TlsFailure::ConnectionFailed(reason) => FetchFailure::Connection(reason),
        crate::tls::TlsFailure::HandshakeFailed(reason) => FetchFailure::Tls(reason),
    })?;
    if cancel.is_cancelled() || Instant::now() >= deadline {
        return Err(FetchFailure::Cancelled);
    }
    let request = build_request(method, target, &request_path_query(target));
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .min(response_timeout);
    let max_bytes = MAX_HEADER_BYTES + body_cap;
    let raw = session
        .exchange_http(&request, max_bytes, remaining, cancel)
        .map_err(|reason| {
            if reason == "cancelled" {
                FetchFailure::Cancelled
            } else {
                FetchFailure::Tls(format!("application data: {reason}"))
            }
        })?;
    let split = head_end(&raw).unwrap_or(raw.len().min(MAX_HEADER_BYTES));
    let head = raw[..split].to_vec();
    let mut body = if read_body {
        raw[split..].to_vec()
    } else {
        Vec::new()
    };
    let head_truncated = split >= MAX_HEADER_BYTES && head_end(&raw).is_none();
    let mut body_truncated = raw.len() > split + body_cap;
    if body.len() > body_cap {
        body.truncate(body_cap);
        body_truncated = true;
    }
    Ok(RawFetch {
        head,
        body,
        head_truncated,
        body_truncated,
        latency_ms: started.elapsed().as_millis() as u64,
        tls_leaf_der: session.observation.peer_certs_der.first().cloned(),
        tls: Some(session.observation.clone()),
    })
}

/// Centralized Phase 8 web policy: level sets breadth, speed sets pressure.
#[derive(Debug, Clone)]
pub struct WebPolicy {
    pub level: u8,
    pub goal: ScanGoal,
    pub speed: SpeedSetting,
}

impl WebPolicy {
    pub fn new(level: u8, goal: ScanGoal, speed: SpeedSetting) -> Self {
        Self {
            level: level.clamp(1, 5),
            goal,
            speed,
        }
    }

    /// HTTP method per level: minimal HEAD observations at L1–L2 (headers
    /// only, no body), full GET with body/title from L3 up.
    pub fn method(&self) -> &'static str {
        if self.level <= 2 { "HEAD" } else { "GET" }
    }

    pub fn wants_body(&self) -> bool {
        self.level >= 3
    }

    /// Redirect hops followed per chain: none at L1–L2 (record only),
    /// bounded follows above, never beyond the hard cap.
    pub fn max_redirects(&self) -> u8 {
        match self.level {
            1 | 2 => 0,
            3 => 2,
            _ => 4,
        }
        .min(MAX_REDIRECT_HOPS_HARD)
    }

    pub fn connect_timeout(&self) -> Duration {
        crate::ports::tcp_timeout_for_speed(self.speed)
    }

    pub fn response_timeout(&self) -> Duration {
        crate::service::service_timeout_for_speed(self.speed)
    }

    pub fn describe(&self) -> String {
        format!(
            "web level {} ({:?}): method {}, redirects ≤{}, connect {}ms, response {}ms",
            self.level,
            self.goal,
            self.method(),
            self.max_redirects(),
            self.connect_timeout().as_millis(),
            self.response_timeout().as_millis(),
        )
    }
}

/// Resolve a target to dialable socket addresses without expanding scope:
/// IP literals directly; hostnames via bounded resolution filtered by the
/// caller-provided permit check. Returns sorted, deduped addresses.
pub fn resolve_web_addresses(
    target: &WebTarget,
    permit: &dyn Fn(IpAddr) -> bool,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<Vec<IpAddr>, String> {
    if cancel.is_cancelled() {
        return Err("cancelled".to_owned());
    }
    if let Some(ip) = target.ip_literal() {
        return Ok(vec![ip]);
    }
    match crate::host_discovery::resolve_hostname_bounded(&target.host, timeout, cancel) {
        Ok(addresses) => {
            let mut permitted: Vec<IpAddr> =
                addresses.into_iter().filter(|ip| permit(*ip)).collect();
            permitted.sort();
            permitted.dedup();
            Ok(permitted)
        }
        Err(reason) if reason == "cancelled" => Err("cancelled".to_owned()),
        Err(reason) => Err(reason),
    }
}

/// Open one TCP connection to `ip:port` within the remaining budget.
pub fn connect_web(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<TcpStream, String> {
    if cancel.is_cancelled() {
        return Err("cancelled".to_owned());
    }
    let now = Instant::now();
    if now >= deadline {
        return Err("task deadline reached".to_owned());
    }
    let remaining = deadline.saturating_duration_since(now).min(timeout);
    TcpStream::connect_timeout(
        &SocketAddr::new(ip, port),
        remaining.min(Duration::from_millis(3000)),
    )
    .map_err(|error| error.to_string())
}

pub fn set_stream_timeouts(stream: &TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(READ_SLICE_MS)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(READ_SLICE_MS)));
}

/// Build the exact request bytes for a target (single source of truth, also
/// used by no-crawl boundary tests).
pub fn build_request(method: &str, target: &WebTarget, path_query: &str) -> Vec<u8> {
    format!(
        "{method} {path_query} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: rxscan-phase8\r\n\r\n",
        target.host_header()
    )
    .into_bytes()
}

pub fn request_path_query(target: &WebTarget) -> String {
    match &target.query {
        Some(query) => format!("{}?{query}", target.path),
        None => target.path.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalization_fills_defaults_and_brackets_ipv6() {
        let root = WebTarget::parse("HTTP://Example.COM").unwrap();
        assert_eq!(root.canonical(), "http://example.com:80/");
        assert_eq!(root.host_header(), "example.com");
        let explicit = WebTarget::parse("http://example.com:80/").unwrap();
        assert_eq!(explicit, root);
        let v6 = WebTarget::parse("http://[::1]:8080/a?b=c").unwrap();
        assert_eq!(v6.canonical(), "http://[::1]:8080/a?b=c");
        assert_eq!(v6.host_header(), "[::1]:8080");
        let std_v6 = WebTarget::parse("https://[::1]/").unwrap();
        assert_eq!(std_v6.host_header(), "[::1]");
    }

    #[test]
    fn rejects_non_web_and_malformed_urls() {
        assert!(WebTarget::parse("ftp://example.test/").is_err());
        assert!(WebTarget::parse("not a url").is_err());
        assert!(WebTarget::parse("http:///").is_err());
        assert!(WebTarget::parse("http://example.test:0/").is_err());
    }

    #[test]
    fn relative_locations_resolve_and_bad_ones_error() {
        let base = WebTarget::parse("http://example.test:8080/a/b?x=1").unwrap();
        assert_eq!(
            base.resolve_location("/login").unwrap().canonical(),
            "http://example.test:8080/login"
        );
        assert_eq!(
            base.resolve_location("c").unwrap().canonical(),
            "http://example.test:8080/a/c"
        );
        assert_eq!(
            base.resolve_location("https://other.test/")
                .unwrap()
                .canonical(),
            "https://other.test:443/"
        );
        assert!(base.resolve_location("").is_err());
        assert!(base.resolve_location("http://[::1").is_err());
    }

    #[test]
    fn level_sets_method_and_redirect_cap() {
        let low = WebPolicy::new(1, ScanGoal::Recon, SpeedSetting::default());
        let high = WebPolicy::new(5, ScanGoal::Recon, SpeedSetting::default());
        assert_eq!(low.method(), "HEAD");
        assert_eq!(high.method(), "GET");
        assert_eq!(low.max_redirects(), 0);
        assert!(high.max_redirects() <= MAX_REDIRECT_HOPS_HARD);
    }

    #[test]
    fn speed_changes_timeouts_not_policy_shape() {
        let slow = WebPolicy::new(3, ScanGoal::Recon, SpeedSetting::Numeric(0));
        let fast = WebPolicy::new(3, ScanGoal::Recon, SpeedSetting::Numeric(100));
        assert_eq!(slow.method(), fast.method());
        assert_eq!(slow.max_redirects(), fast.max_redirects());
        assert!(fast.connect_timeout() < slow.connect_timeout());
        assert!(fast.response_timeout() < slow.response_timeout());
    }
}
