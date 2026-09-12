//! Native protocol probes for Phase 7 service intelligence.
//!
//! Each probe speaks just enough of one protocol to *identify* it — never to
//! authenticate, enumerate, crawl, or destroy. Exact bytes sent per probe:
//!
//! * `ssh`: sends NOTHING (passive banner read, ≤2048B).
//! * `http`: `GET / HTTP/1.0` + Host/Connection/User-Agent (<160B); reads
//!   headers ≤16KiB and body ≤16KiB; redirects observed, never followed.
//! * `tls`: TLS ClientHello only (rustls); reads the handshake + chain
//!   ≤32KiB. `https`/`smtps` compositions reuse that session.
//! * `ftp`: sends NOTHING (passive `220` greeting read, ≤2048B).
//! * `smtp`: reads the `220` greeting, then one `EHLO rxscan.local` (17B);
//!   capabilities parsed from `250` lines. Never MAIL/AUTH/VRFY/EXPN.
//! * `redis`: one `PING` (7B: `PING\r\n`); expects `+PONG`.
//! * `mysql`: sends NOTHING (passive handshake packet read, ≤16KiB).
//! * `postgres`: one 8-byte SSLRequest; expects a single `S`/`N` byte.
//! * `generic`: sends NOTHING (passive banner read ≤2048B, short budget).
//!
//! Tests assert fixtures never observe authentication verbs or destructive
//! commands. Unknown input stays `unknown` — port hints are recorded as the
//! *reason a probe ran*, never as proof of identity.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::execution::CancellationToken;
use crate::service::{
    MAX_BANNER_BYTES, MAX_HTTP_BODY_BYTES, MAX_HTTP_HEADER_BYTES, MAX_SMTP_REPLY_BYTES,
    split_product_token, truncate_bounded,
};

/// What one probe run concluded.
#[derive(Debug, Clone)]
pub struct ProbeAttempt {
    pub probe_id: &'static str,
    /// Classified protocol (`unknown` when nothing was proven).
    pub protocol: String,
    /// True when application data ran inside TLS.
    pub tls: bool,
    pub protocol_version: Option<String>,
    pub product_hint: Option<String>,
    pub version_hint: Option<String>,
    pub banner: Option<String>,
    pub capabilities: Vec<String>,
    /// Certificate facts (TLS-family probes only).
    pub cert: Option<CertFacts>,
    pub confidence: u8,
    pub evidence: Vec<String>,
    pub bytes_in: usize,
    pub bytes_out: usize,
    pub truncated: bool,
}

/// Safely observed certificate facts (leaf only).
#[derive(Debug, Clone, Default)]
pub struct CertFacts {
    pub subject: String,
    pub issuer: String,
    pub san_dns: Vec<String>,
    pub san_ip: Vec<String>,
    pub not_before_epoch: i64,
    pub not_after_epoch: i64,
    pub not_before: String,
    pub not_after: String,
    pub fingerprint_sha256: String,
    pub hostname_match: bool,
    pub hostname_detail: String,
}

impl ProbeAttempt {
    fn miss(probe_id: &'static str, reason: impl Into<String>) -> Self {
        Self {
            probe_id,
            protocol: "unknown".to_owned(),
            tls: false,
            protocol_version: None,
            product_hint: None,
            version_hint: None,
            banner: None,
            capabilities: Vec::new(),
            cert: None,
            confidence: 0,
            evidence: vec![reason.into()],
            bytes_in: 0,
            bytes_out: 0,
            truncated: false,
        }
    }

    pub fn classified(&self) -> bool {
        self.protocol != "unknown"
    }
}

/// Shared per-probe I/O context.
pub struct ProbeCtx<'a> {
    pub ip: IpAddr,
    pub port: u16,
    pub host_label: &'a str,
    /// Total wall budget for this probe run.
    pub timeout: Duration,
    /// Task-level deadline (hard stop).
    pub deadline: Instant,
    pub cancel: &'a CancellationToken,
}

impl ProbeCtx<'_> {
    pub(crate) fn remaining(&self) -> Option<Duration> {
        let now = Instant::now();
        if now >= self.deadline || self.cancel.is_cancelled() {
            return None;
        }
        Some(
            self.deadline
                .saturating_duration_since(now)
                .min(self.timeout),
        )
    }

    pub(crate) fn connect(&self) -> Result<TcpStream, String> {
        let remaining = self
            .remaining()
            .ok_or_else(|| "cancelled or task deadline reached".to_owned())?;
        let address = SocketAddr::new(self.ip, self.port);
        TcpStream::connect_timeout(&address, remaining.min(Duration::from_millis(1500)))
            .map_err(|error| format!("connect: {error}"))
    }

    pub(crate) fn timebox(stream: &TcpStream, millis: u64) {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(millis)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(millis)));
    }
}

/// Read until `delimiter` or `max_bytes`, in short socket slices so
/// cancellation stays prompt. Returns (bytes, saw_delimiter, truncated).
fn read_until(
    stream: &mut TcpStream,
    delimiter: &[u8],
    max_bytes: usize,
    ctx: &ProbeCtx,
    started: Instant,
) -> (Vec<u8>, bool, bool) {
    ProbeCtx::timebox(stream, 500);
    let mut buffer = Vec::new();
    let mut window: Vec<u8> = Vec::new();
    loop {
        if ctx.cancel.is_cancelled()
            || Instant::now() >= ctx.deadline
            || started.elapsed() >= ctx.timeout
        {
            break;
        }
        if buffer.len() >= max_bytes {
            return (buffer, false, true);
        }
        let mut chunk = [0u8; 1024];
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                let room = max_bytes.saturating_sub(buffer.len());
                if room == 0 {
                    return (buffer, false, true);
                }
                let take = count.min(room);
                buffer.extend_from_slice(&chunk[..take]);
                window.extend_from_slice(&chunk[..take]);
                if window.len() > delimiter.len() + 8 {
                    let drop = window.len() - (delimiter.len() + 8);
                    window.drain(..drop);
                }
                if ends_with(&buffer, delimiter) {
                    return (buffer, true, false);
                }
                if take < count {
                    return (buffer, false, true);
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
    let done = ends_with(&buffer, delimiter);
    (buffer, done, false)
}

fn ends_with(buffer: &[u8], delimiter: &[u8]) -> bool {
    buffer.len() >= delimiter.len() && &buffer[buffer.len() - delimiter.len()..] == delimiter
}

/// Bounded exact read that preserves framing: bytes arriving beyond `needed`
/// are stashed (not discarded) for the next call. Without the stash, a
/// single TCP segment carrying header+body would lose the body.
fn read_exact_bounded(
    stream: &mut TcpStream,
    mut needed: usize,
    max_bytes: usize,
    ctx: &ProbeCtx,
    started: Instant,
    stash: &mut Vec<u8>,
) -> (Vec<u8>, bool) {
    ProbeCtx::timebox(stream, 500);
    let mut buffer = Vec::new();
    needed = needed.min(max_bytes);
    // Serve from previously over-read bytes first.
    if !stash.is_empty() {
        let take = stash.len().min(needed);
        buffer.extend_from_slice(&stash[..take]);
        stash.drain(..take);
    }
    while buffer.len() < needed {
        if ctx.cancel.is_cancelled()
            || Instant::now() >= ctx.deadline
            || started.elapsed() >= ctx.timeout
        {
            break;
        }
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                let want = needed.saturating_sub(buffer.len());
                let take = count.min(want);
                buffer.extend_from_slice(&chunk[..take]);
                // Stash the framing surplus instead of dropping it. The
                // stash itself is hard-capped; `max_bytes` only bounds this
                // call's own buffer (a 4-byte header read must still keep a
                // 20-byte body arriving in the same segment).
                if count > take {
                    let room = (16 * 1024usize).saturating_sub(stash.len());
                    let keep = (count - take).min(room);
                    stash.extend_from_slice(&chunk[take..take + keep]);
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
    let complete = buffer.len() >= needed;
    (buffer, complete)
}

fn lossy_capped(bytes: &[u8], max_bytes: usize) -> (String, bool) {
    let text = String::from_utf8_lossy(bytes);
    truncate_bounded(&text, max_bytes)
}

// ---------------- SSH ----------------

/// Passive SSH identification read. Sends nothing, never authenticates.
pub fn probe_ssh(ctx: &ProbeCtx) -> ProbeAttempt {
    let started = Instant::now();
    let mut stream = match ctx.connect() {
        Ok(stream) => stream,
        Err(reason) => return ProbeAttempt::miss("ssh", format!("ssh: {reason}")),
    };
    let (bytes, saw_newline, truncated) =
        read_until(&mut stream, b"\n", MAX_BANNER_BYTES, ctx, started);
    let bytes_in = bytes.len();
    if bytes.is_empty() {
        let mut attempt = ProbeAttempt::miss("ssh", "ssh: no banner received (silent/timeout)");
        attempt.bytes_in = bytes_in;
        attempt.truncated = truncated;
        return attempt;
    }
    // SSH identification strings are line-based: an unterminated fragment is
    // not a banner and never classifies (strictness over guessing).
    if !saw_newline {
        let mut attempt = ProbeAttempt::miss("ssh", "ssh: incomplete banner line (no terminator)");
        attempt.bytes_in = bytes_in;
        attempt.truncated = truncated;
        return attempt;
    }
    let (line, _) = lossy_capped(&bytes, MAX_BANNER_BYTES);
    let line = line.trim_end_matches(['\r', '\n']);
    let mut attempt = ProbeAttempt::miss("ssh", String::new());
    attempt.bytes_in = bytes_in;
    attempt.truncated = truncated;
    let Some(rest) = line.strip_prefix("SSH-") else {
        attempt.evidence = vec!["ssh: banner is not an SSH identification string".to_owned()];
        attempt.banner = Some(line.chars().take(120).collect());
        return attempt;
    };
    let mut parts = rest.splitn(3, '-');
    let proto = parts.next().unwrap_or("");
    if !proto
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_digit())
        || !proto.contains('.')
    {
        attempt.evidence = vec![format!("ssh: malformed protocol version '{proto}'")];
        return attempt;
    }
    let software = parts.next().unwrap_or("").to_owned();
    let comment = parts.next().unwrap_or("").to_owned();
    let Some(parsed) = parse_ssh_software(&software, &comment) else {
        attempt.evidence = vec!["ssh: malformed software string".to_owned()];
        return attempt;
    };
    attempt.protocol = "ssh".to_owned();
    attempt.protocol_version = Some(proto.to_owned());
    if !parsed.0.is_empty() {
        attempt.product_hint = Some(parsed.0);
    }
    attempt.version_hint = parsed.1;
    attempt.banner = Some(format!("SSH-{rest}").chars().take(200).collect());
    attempt.confidence = if attempt.product_hint.is_some() {
        90
    } else {
        75
    };
    attempt.evidence = vec![format!("ssh: received protocol banner SSH-{rest}")];
    attempt
}

/// Split an SSH software string (`OpenSSH_9.8`, `dropbear_2022.83`) into a
/// product hint and optional version hint. Raw observed text only.
pub fn parse_ssh_software(software: &str, comment: &str) -> Option<(String, Option<String>)> {
    if software.is_empty() {
        return Some((String::new(), None));
    }
    // Prefer `Product_Version` / `Product-Version`, fall back to `/`.
    // Versions stop at whitespace (trailing comments are not versions).
    for separator in ['_', '-'] {
        if let Some((product, version)) = software.split_once(separator) {
            if !product.is_empty() && !version.is_empty() {
                let version = version.split_whitespace().next().unwrap_or("").to_owned();
                if !version.is_empty() {
                    return Some((product.to_owned(), Some(version)));
                }
            }
        }
    }
    let (product, version) = split_product_token(software);
    if product.is_empty() {
        return None;
    }
    let version = version.or_else(|| (!comment.is_empty()).then(|| comment.to_owned()));
    Some((product, version))
}

// ---------------- HTTP ----------------

/// Parsed minimal HTTP response (status + selected headers + bounded body).
#[derive(Debug, Clone, Default)]
pub struct HttpFacts {
    pub version: String,
    pub status: u16,
    pub reason: String,
    pub server: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<String>,
    pub location: Option<String>,
    pub title: Option<String>,
    pub truncated: bool,
}

pub fn parse_http_response(bytes: &[u8]) -> Option<(HttpFacts, usize)> {
    let header_end = find_header_end(bytes)?;
    if header_end > MAX_HTTP_HEADER_BYTES {
        return None;
    }
    let header_text = std::str::from_utf8(&bytes[..header_end]).ok()?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next()?.trim();
    let version_rest = status_line.strip_prefix("HTTP/")?;
    let (version, rest) = version_rest.split_once(' ')?;
    if version.is_empty()
        || !(version.starts_with("1.") || version.starts_with("2") || version.starts_with("3"))
    {
        return None;
    }
    let rest = rest.trim_start();
    let (code_text, reason) = rest.split_once(' ').unwrap_or((rest, ""));
    let status: u16 = code_text.trim().parse().ok()?;
    let mut facts = HttpFacts {
        version: version.to_owned(),
        status,
        reason: reason.trim().to_owned(),
        ..HttpFacts::default()
    };
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "server" => facts.server = Some(value.trim().to_owned()),
            "content-type" => facts.content_type = Some(value.trim().to_owned()),
            "content-length" => facts.content_length = Some(value.trim().to_owned()),
            "location" => facts.location = Some(value.trim().to_owned()),
            _ => {}
        }
    }
    Some((facts, header_end))
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

pub(crate) fn extract_title(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body).to_ascii_lowercase();
    let start = text.find("<title>")? + "<title>".len();
    let end = text[start..].find("</title>")? + start;
    let title = text[start..end].trim();
    if title.is_empty() {
        return None;
    }
    Some(title.chars().take(200).collect())
}

/// Minimal HTTP/1.0 detection: one GET, bounded read, no redirects followed.
pub fn probe_http(ctx: &ProbeCtx) -> ProbeAttempt {
    probe_http_inner(ctx, None)
}

pub(crate) fn probe_http_inner(ctx: &ProbeCtx, tls_body: Option<Vec<u8>>) -> ProbeAttempt {
    let started = Instant::now();
    if let Some(body) = tls_body {
        let bytes_in = body.len();
        return finish_http_body(bytes_in, 0, &body);
    }
    let request = format!(
        "GET / HTTP/1.0\r\nHost: {}\r\nConnection: close\r\nUser-Agent: rxscan-phase7\r\n\r\n",
        ctx.host_label
    );
    let mut stream = match ctx.connect() {
        Ok(stream) => stream,
        Err(reason) => return ProbeAttempt::miss("http", format!("http: {reason}")),
    };
    ProbeCtx::timebox(&stream, 500);
    if stream.write_all(request.as_bytes()).is_err() {
        return ProbeAttempt::miss("http", "http: request write failed");
    }
    let max_total = MAX_HTTP_HEADER_BYTES + MAX_HTTP_BODY_BYTES;
    let mut stash = Vec::new();
    let (bytes, _) =
        read_exact_bounded(&mut stream, max_total, max_total, ctx, started, &mut stash);
    if bytes.is_empty() {
        return ProbeAttempt::miss("http", "http: empty response");
    }
    finish_http_body(bytes.len(), request.len(), &bytes)
}

fn finish_http_body(bytes_in: usize, bytes_out: usize, raw: &[u8]) -> ProbeAttempt {
    let header_cap = raw.len().min(MAX_HTTP_HEADER_BYTES);
    let Some((mut facts, header_end)) = parse_http_response(&raw[..header_cap]) else {
        let mut attempt = ProbeAttempt::miss("http", "http: response is not valid HTTP");
        attempt.bytes_in = bytes_in;
        return attempt;
    };
    let body = &raw[header_end.min(raw.len())..raw.len().min(header_end + MAX_HTTP_BODY_BYTES)];
    facts.title = extract_title(body);
    facts.truncated = raw.len() >= MAX_HTTP_HEADER_BYTES + MAX_HTTP_BODY_BYTES;
    let mut attempt = ProbeAttempt::miss("http", String::new());
    attempt.bytes_in = bytes_in;
    attempt.bytes_out = bytes_out;
    attempt.protocol = "http".to_owned();
    attempt.protocol_version = Some(format!("1.{}", facts.version));
    if let Some(server) = &facts.server {
        let (product, version) = split_product_token(server);
        if !product.is_empty() {
            attempt.product_hint = Some(product);
        }
        attempt.version_hint = version;
    }
    attempt.confidence = if attempt.product_hint.is_some() {
        90
    } else {
        85
    };
    let mut lines = vec![format!(
        "http: received HTTP/{} {} {} with valid HTTP headers",
        facts.version, facts.status, facts.reason
    )];
    if let Some(server) = &facts.server {
        lines.push(format!("http: Server header {server:?}"));
    }
    if let Some(content_type) = &facts.content_type {
        lines.push(format!("http: Content-Type {content_type:?}"));
    }
    if let Some(location) = &facts.location {
        lines.push(format!(
            "http: redirect Location observed {location:?} (not followed)"
        ));
        attempt.capabilities.push(format!("redirect:{location}"));
    }
    if let Some(title) = &facts.title {
        lines.push(format!("http: title {title:?}"));
    }
    if facts.truncated {
        lines.push("http: response truncated at byte budget".to_owned());
    }
    attempt.evidence = lines;
    attempt.truncated = facts.truncated;
    attempt
}

// ---------------- TLS / certs ----------------

/// Parse leaf-certificate facts from DER bytes (best effort; handshake
/// success alone still classifies TLS when parsing fails).
pub fn parse_cert_facts(leaf_der: &[u8], server_label: &str) -> Option<CertFacts> {
    let (_, cert) = parse_x509_certificate(leaf_der).ok()?;
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let mut san_dns = Vec::new();
    let mut san_ip = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(pattern) => san_dns.push(pattern.to_string()),
                GeneralName::IPAddress(bytes) => {
                    san_ip.push(
                        bytes
                            .iter()
                            .map(u8::to_string)
                            .collect::<Vec<_>>()
                            .join("."),
                    );
                }
                _ => {}
            }
        }
    }
    let not_before_epoch = cert.validity().not_before.timestamp();
    let not_after_epoch = cert.validity().not_after.timestamp();
    let fingerprint = {
        let mut hasher = Sha256::new();
        hasher.update(leaf_der);
        hex_bytes(&hasher.finalize())
    };
    let (hostname_match, hostname_detail) =
        match_hostname(server_label, &san_dns, &san_ip, &subject);
    Some(CertFacts {
        subject,
        issuer,
        san_dns,
        san_ip,
        not_before_epoch,
        not_after_epoch,
        not_before: epoch_date(not_before_epoch),
        not_after: epoch_date(not_after_epoch),
        fingerprint_sha256: fingerprint,
        hostname_match,
        hostname_detail,
    })
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn epoch_date(epoch: i64) -> String {
    if epoch < 0 {
        return "invalid".to_owned();
    }
    let days = epoch.div_euclid(86_400);
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}")
}

fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    // Howard Hinnant's civil-from-days algorithm (days since 1970-01-01).
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        (month_prime + 3) as u32
    } else {
        (month_prime - 9) as u32
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

fn match_hostname(
    label: &str,
    san_dns: &[String],
    san_ip: &[String],
    subject: &str,
) -> (bool, String) {
    let label = label.trim().trim_end_matches('.').to_ascii_lowercase();
    if label.is_empty() {
        return (false, "no hostname label to match".to_owned());
    }
    if label.parse::<IpAddr>().is_ok() {
        let hit = san_ip
            .iter()
            .any(|entry| entry.to_ascii_lowercase() == label);
        return (
            hit,
            if hit {
                format!("IP {label} present in certificate SAN")
            } else {
                format!("IP {label} absent from certificate SAN")
            },
        );
    }
    let dns_hit = san_dns.iter().any(|pattern| dns_matches(pattern, &label));
    if dns_hit {
        return (true, format!("hostname {label} matched by certificate SAN"));
    }
    if !san_dns.is_empty() {
        return (
            false,
            format!("hostname {label} matched no certificate SAN"),
        );
    }
    // No SANs: fall back to subject CN (legacy behavior, noted as such).
    let cn = subject
        .split(',')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("CN="))
        .unwrap_or("")
        .to_ascii_lowercase();
    if !cn.is_empty() && dns_matches(&cn, &label) {
        return (
            true,
            format!("hostname {label} matched by subject CN (no SAN present)"),
        );
    }
    (
        false,
        format!("hostname {label} matched neither SAN nor subject CN"),
    )
}

fn dns_matches(pattern: &str, label: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = pattern.strip_prefix("*.") {
        // Leftmost-only wildcard: exactly one extra label.
        return label
            .split_once('.')
            .is_some_and(|(_, parent)| parent == rest);
    }
    pattern == label
}

/// TLS service probe: handshake + leaf-cert facts. Compositions (HTTPS,
/// SMTPS) reuse the established session and live in the module layer.
pub fn probe_tls(ctx: &ProbeCtx) -> TlsProbeOutcome {
    let server_name = (ctx.host_label != ctx.ip.to_string()).then_some(ctx.host_label);
    match crate::tls::connect_tls(ctx.ip, ctx.port, server_name, ctx.timeout, ctx.cancel) {
        Ok(session) => {
            let observation = session.observation.clone();
            let leaf = observation.peer_certs_der.first().cloned();
            TlsProbeOutcome::Established(Box::new(session), observation, leaf)
        }
        Err(crate::tls::TlsFailure::Cancelled) => TlsProbeOutcome::Cancelled,
        Err(crate::tls::TlsFailure::Timeout) => TlsProbeOutcome::Miss(Box::new(ProbeAttempt {
            protocol: "unknown".to_owned(),
            tls: false,
            protocol_version: None,
            product_hint: None,
            version_hint: None,
            banner: None,
            capabilities: Vec::new(),
            cert: None,
            confidence: 0,
            evidence: vec!["tls: handshake timed out".to_owned()],
            bytes_in: 0,
            bytes_out: 0,
            truncated: false,
            probe_id: "tls",
        })),
        Err(other) => TlsProbeOutcome::Miss(Box::new(ProbeAttempt {
            protocol: "unknown".to_owned(),
            tls: false,
            protocol_version: None,
            product_hint: None,
            version_hint: None,
            banner: None,
            capabilities: Vec::new(),
            cert: None,
            confidence: 0,
            evidence: vec![format!("tls: handshake failed ({other:?})")],
            bytes_in: 0,
            bytes_out: 0,
            truncated: false,
            probe_id: "tls",
        })),
    }
}

pub enum TlsProbeOutcome {
    Established(
        Box<crate::tls::EstablishedTls>,
        crate::tls::TlsObservation,
        Option<Vec<u8>>,
    ),
    Miss(Box<ProbeAttempt>),
    Cancelled,
}

// ---------------- FTP ----------------

/// Passive FTP greeting read. Sends nothing, never authenticates.
pub fn probe_ftp(ctx: &ProbeCtx) -> ProbeAttempt {
    let started = Instant::now();
    let mut stream = match ctx.connect() {
        Ok(stream) => stream,
        Err(reason) => return ProbeAttempt::miss("ftp", format!("ftp: {reason}")),
    };
    let (bytes, _, truncated) = read_until(&mut stream, b"\n", MAX_BANNER_BYTES, ctx, started);
    let bytes_in = bytes.len();
    if bytes.is_empty() {
        let mut attempt = ProbeAttempt::miss("ftp", "ftp: no greeting received");
        attempt.bytes_in = bytes_in;
        return attempt;
    }
    let (text, _) = lossy_capped(&bytes, MAX_BANNER_BYTES);
    let first_line = text.lines().next().unwrap_or("").trim();
    let mut attempt = ProbeAttempt::miss("ftp", String::new());
    attempt.bytes_in = bytes_in;
    attempt.truncated = truncated;
    let Some(rest) = first_line.strip_prefix("220") else {
        attempt.evidence = vec!["ftp: greeting is not an FTP 220 banner".to_owned()];
        attempt.banner = Some(first_line.chars().take(120).collect());
        return attempt;
    };
    let remainder = rest.trim_start_matches(['-', ' ']).trim().to_owned();
    let (product, version) = crate::service::product_and_version(&remainder);
    attempt.protocol = "ftp".to_owned();
    if !product.is_empty() {
        attempt.product_hint = Some(product);
    }
    attempt.version_hint = version;
    attempt.banner = Some(first_line.chars().take(200).collect());
    attempt.confidence = if attempt.product_hint.is_some() {
        85
    } else {
        80
    };
    attempt.evidence = vec![format!("ftp: received greeting {first_line:?}")];
    attempt
}

// ---------------- SMTP ----------------

/// SMTP identification: greeting + one bounded EHLO. Never sends mail,
/// credentials, VRFY, or EXPN.
pub fn probe_smtp(ctx: &ProbeCtx) -> ProbeAttempt {
    probe_smtp_inner(ctx, None)
}

pub(crate) fn probe_smtp_inner(ctx: &ProbeCtx, tls_body: Option<Vec<u8>>) -> ProbeAttempt {
    let started = Instant::now();
    let via_tls = tls_body.is_some();
    let raw_greeting;
    let mut bytes_out = 0usize;
    let mut capabilities = Vec::new();
    let mut ehlo_evidence: Vec<String> = Vec::new();
    if let Some(body) = tls_body {
        raw_greeting = body;
    } else {
        let mut stream = match ctx.connect() {
            Ok(stream) => stream,
            Err(reason) => return ProbeAttempt::miss("smtp", format!("smtp: {reason}")),
        };
        let (greeting, _, _) = read_until(&mut stream, b"\n", MAX_BANNER_BYTES, ctx, started);
        if greeting.is_empty() {
            return ProbeAttempt::miss("smtp", "smtp: no greeting received");
        }
        // Bounded EHLO capability enumeration (safe, read-only).
        let ehlo = b"EHLO rxscan.local\r\n";
        ProbeCtx::timebox(&stream, 500);
        if stream.write_all(ehlo).is_ok() {
            bytes_out = ehlo.len();
            let (reply, _, _) = read_until(&mut stream, b"\n", MAX_SMTP_REPLY_BYTES, ctx, started);
            capabilities = parse_ehlo_capabilities(&reply);
            if !capabilities.is_empty() {
                ehlo_evidence.push(format!(
                    "smtp: EHLO capabilities {}",
                    capabilities.join(", ")
                ));
            }
        }
        raw_greeting = greeting;
    }
    let bytes_in = raw_greeting.len();
    let (text, _) = lossy_capped(&raw_greeting, MAX_BANNER_BYTES);
    let first_line = text.lines().next().unwrap_or("").trim();
    let mut attempt = ProbeAttempt::miss("smtp", String::new());
    attempt.bytes_in = bytes_in;
    // The in-TLS path always follows the greeting with exactly one EHLO.
    attempt.bytes_out = if via_tls {
        b"EHLO rxscan.local\r\n".len()
    } else {
        bytes_out
    };
    attempt.capabilities = capabilities;
    let Some(rest) = first_line.strip_prefix("220") else {
        attempt.evidence = vec!["smtp: greeting is not an SMTP 220 banner".to_owned()];
        attempt.banner = Some(first_line.chars().take(120).collect());
        return attempt;
    };
    let remainder = rest.trim_start_matches(['-', ' ']).trim().to_owned();
    let (product, version) = crate::service::product_and_version(&remainder);
    attempt.protocol = "smtp".to_owned();
    if !product.is_empty() {
        attempt.product_hint = Some(product);
    }
    attempt.version_hint = version;
    attempt.banner = Some(first_line.chars().take(200).collect());
    attempt.confidence = if attempt.capabilities.is_empty() {
        75
    } else {
        85
    };
    attempt.evidence = vec![format!("smtp: received greeting {first_line:?}")];
    attempt.evidence.extend(ehlo_evidence);
    attempt
}

fn parse_ehlo_capabilities(reply: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(reply);
    let mut capabilities = Vec::new();
    // The first 250 line echoes the greeting hostname, not a capability.
    for line in text.lines().skip(1) {
        let line = line.trim();
        let body = line
            .strip_prefix("250-")
            .or_else(|| line.strip_prefix("250 "))
            .unwrap_or("");
        let token = body
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        if token.is_empty() {
            continue;
        }
        capabilities.push(token);
        if capabilities.len() >= 16 {
            break;
        }
    }
    capabilities.sort();
    capabilities.dedup();
    capabilities
}

// ---------------- Redis ----------------

/// Redis identification: one inline PING, expects +PONG. Read-only.
pub fn probe_redis(ctx: &ProbeCtx) -> ProbeAttempt {
    let started = Instant::now();
    let mut stream = match ctx.connect() {
        Ok(stream) => stream,
        Err(reason) => return ProbeAttempt::miss("redis", format!("redis: {reason}")),
    };
    let ping = b"PING\r\n";
    ProbeCtx::timebox(&stream, 500);
    if stream.write_all(ping).is_err() {
        return ProbeAttempt::miss("redis", "redis: PING write failed");
    }
    let (bytes, _, _) = read_until(&mut stream, b"\n", 256, ctx, started);
    let mut attempt = ProbeAttempt::miss("redis", String::new());
    attempt.bytes_in = bytes.len();
    attempt.bytes_out = ping.len();
    let line = String::from_utf8_lossy(&bytes);
    let line = line.trim();
    if line == "+PONG" {
        attempt.protocol = "redis".to_owned();
        attempt.confidence = 90;
        attempt.evidence = vec!["redis: received +PONG to inline PING".to_owned()];
    } else if line.starts_with("-NOAUTH") || line.starts_with("-WRONGPASS") {
        attempt.protocol = "redis".to_owned();
        attempt.confidence = 70;
        attempt.evidence =
            vec!["redis: server requires authentication (no credentials sent)".to_owned()];
    } else if line.is_empty() {
        attempt.evidence = vec!["redis: empty reply to PING".to_owned()];
    } else {
        attempt.evidence = vec![format!("redis: unexpected reply {line:?}")];
    }
    attempt
}

// ---------------- MySQL ----------------

/// Passive MySQL handshake read. Sends nothing, never authenticates.
pub fn probe_mysql(ctx: &ProbeCtx) -> ProbeAttempt {
    let started = Instant::now();
    let mut stream = match ctx.connect() {
        Ok(stream) => stream,
        Err(reason) => return ProbeAttempt::miss("mysql", format!("mysql: {reason}")),
    };
    // Handshake packet: 3-byte LE length + 1-byte sequence, then payload.
    let mut stash = Vec::new();
    let (header, complete) = read_exact_bounded(&mut stream, 4, 4, ctx, started, &mut stash);
    let mut attempt = ProbeAttempt::miss("mysql", String::new());
    if !complete || header.len() < 4 {
        attempt.evidence = vec!["mysql: no handshake packet received".to_owned()];
        return attempt;
    }
    let length = (u32::from(header[0]) | (u32::from(header[1]) << 8) | (u32::from(header[2]) << 16))
        as usize;
    if length == 0 || length > 16 * 1024 {
        attempt.evidence = vec!["mysql: implausible handshake length".to_owned()];
        return attempt;
    }
    let (payload, complete) =
        read_exact_bounded(&mut stream, length, 16 * 1024, ctx, started, &mut stash);
    attempt.bytes_in = 4 + payload.len();
    if !complete || payload.is_empty() {
        attempt.evidence = vec!["mysql: truncated handshake packet".to_owned()];
        return attempt;
    }
    let protocol = payload[0];
    if protocol != 10 && protocol != 9 {
        attempt.evidence = vec![format!("mysql: unexpected protocol byte {protocol}")];
        return attempt;
    }
    let version_end = payload[1..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|position| position + 1)
        .unwrap_or(payload.len());
    let version = String::from_utf8_lossy(&payload[1..version_end]).to_string();
    if version.is_empty() {
        attempt.evidence = vec!["mysql: empty server version".to_owned()];
        return attempt;
    }
    let (product, detected) = split_product_token(&version);
    attempt.protocol = "mysql".to_owned();
    attempt.protocol_version = Some(format!("handshake-{protocol}"));
    attempt.product_hint = Some(if product.is_empty() {
        "MySQL".to_owned()
    } else {
        product
    });
    attempt.version_hint = detected.or(Some(version.clone()));
    attempt.banner = Some(version.chars().take(120).collect());
    attempt.confidence = 85;
    attempt.evidence = vec![format!(
        "mysql: received handshake protocol {protocol} version {version:?}"
    )];
    attempt
}

// ---------------- PostgreSQL ----------------

/// PostgreSQL identification: one 8-byte SSLRequest, single-byte reply.
/// No credentials, no startup parameters, no queries.
pub fn probe_postgres(ctx: &ProbeCtx) -> ProbeAttempt {
    let started = Instant::now();
    let mut stream = match ctx.connect() {
        Ok(stream) => stream,
        Err(reason) => return ProbeAttempt::miss("postgres", format!("postgres: {reason}")),
    };
    // SSLRequest: length 8, request code 80877103 (big-endian).
    let request = [0u8, 0, 0, 8, 4, 210, 22, 47];
    ProbeCtx::timebox(&stream, 500);
    if stream.write_all(&request).is_err() {
        return ProbeAttempt::miss("postgres", "postgres: SSLRequest write failed");
    }
    let mut stash = Vec::new();
    let (bytes, _) = read_exact_bounded(&mut stream, 1, 1, ctx, started, &mut stash);
    let mut attempt = ProbeAttempt::miss("postgres", String::new());
    attempt.bytes_in = bytes.len();
    attempt.bytes_out = request.len();
    match bytes.first() {
        Some(b'S') => {
            attempt.protocol = "postgres".to_owned();
            attempt.confidence = 70;
            attempt.evidence = vec![
                "postgres: server accepted SSLRequest ('S'); closing without authentication"
                    .to_owned(),
            ];
        }
        Some(b'N') => {
            attempt.protocol = "postgres".to_owned();
            attempt.confidence = 70;
            attempt.evidence = vec![
                "postgres: server refused SSL ('N'); closing without authentication".to_owned(),
            ];
        }
        _ => {
            attempt.evidence = vec!["postgres: no SSLRequest reply".to_owned()];
        }
    }
    attempt
}

// ---------------- Generic ----------------

/// Extremely conservative banner read for unknown services. Sends nothing;
/// stays `unknown` unless the banner satisfies a concrete protocol grammar
/// (currently: the SSH identification string). Vague banner text — including
/// a bare `SSH-` prefix with no valid version — is preserved as evidence but
/// never classified. Silence yields low-confidence unknown.
pub fn probe_generic(ctx: &ProbeCtx) -> ProbeAttempt {
    let started = Instant::now();
    let budget = ctx.timeout.min(Duration::from_millis(1500));
    let mut stream = match ctx.connect() {
        Ok(stream) => stream,
        Err(reason) => return ProbeAttempt::miss("generic", format!("generic: {reason}")),
    };
    let short = ProbeCtx {
        ip: ctx.ip,
        port: ctx.port,
        host_label: ctx.host_label,
        timeout: budget,
        deadline: ctx.deadline.min(started + budget),
        cancel: ctx.cancel,
    };
    let (bytes, saw_newline, truncated) =
        read_until(&mut stream, b"\n", MAX_BANNER_BYTES, &short, started);
    let mut attempt = ProbeAttempt::miss("generic", String::new());
    attempt.bytes_in = bytes.len();
    attempt.truncated = truncated;
    if bytes.is_empty() {
        attempt.confidence = 0;
        attempt.evidence = vec!["generic: silent service, no banner received".to_owned()];
        return attempt;
    }
    let (text, text_truncated) = lossy_capped(&bytes, MAX_BANNER_BYTES);
    let first_line = text.lines().next().unwrap_or("").trim().to_owned();
    attempt.truncated = truncated || text_truncated;
    // Line-terminated SSH identification strings with valid grammar are
    // concrete protocol evidence; fragments and vague prefixes stay Unknown.
    if saw_newline && first_line.starts_with("SSH-") {
        // Same strict grammar as the dedicated SSH probe: only a fully
        // valid identification string (`SSH-<digit>.<dot…>-<software>`)
        // counts as concrete protocol evidence. A bare `SSH-` prefix or a
        // malformed version is NOT enough — vague banners stay Unknown.
        let rest = first_line.strip_prefix("SSH-").unwrap_or("");
        let mut parts = rest.splitn(3, '-');
        let proto = parts.next().unwrap_or("");
        let software = parts.next().unwrap_or("");
        let comment = parts.next().unwrap_or("");
        if proto
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_digit())
            && proto.contains('.')
            && let Some((product, version)) = parse_ssh_software(software, comment)
        {
            attempt.protocol = "ssh".to_owned();
            attempt.protocol_version = Some(proto.to_owned());
            if !product.is_empty() {
                attempt.product_hint = Some(product);
            }
            attempt.version_hint = version;
            attempt.confidence = 80;
            attempt.banner = Some(first_line.chars().take(200).collect());
            attempt.evidence =
                vec!["generic: banner satisfies the SSH identification-string grammar".to_owned()];
            return attempt;
        }
    }
    attempt.protocol = "unknown".to_owned();
    attempt.confidence = 50;
    attempt.banner = Some(first_line.chars().take(200).collect());
    let mut lines = vec![format!(
        "generic: unknown TCP service, banner preserved ({} bytes)",
        bytes.len()
    )];
    if attempt.truncated {
        lines.push("generic: banner truncated at byte budget".to_owned());
    }
    attempt.evidence = lines;
    attempt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_parses_product_and_version() {
        assert_eq!(
            split_product_token("OpenSSH_9.8"),
            ("OpenSSH_9.8".to_owned(), None)
        );
        assert_eq!(
            parse_ssh_software("OpenSSH_9.8", ""),
            Some(("OpenSSH".to_owned(), Some("9.8".to_owned())))
        );
        assert_eq!(
            parse_ssh_software("dropbear_2022.83", ""),
            Some(("dropbear".to_owned(), Some("2022.83".to_owned())))
        );
        assert_eq!(
            parse_ssh_software("", "comment"),
            Some((String::new(), None))
        );
        assert_eq!(
            split_product_token("nginx/1.27.2"),
            ("nginx".to_owned(), Some("1.27.2".to_owned()))
        );
    }

    #[test]
    fn http_parses_status_headers_and_title() {
        let raw = b"HTTP/1.1 200 OK\r\nServer: nginx/1.27.2\r\nContent-Type: text/html\r\nLocation: /login\r\n\r\n<html><head><title>Hello</title></head></html>";
        let (facts, header_end) = parse_http_response(raw).unwrap();
        assert_eq!(facts.status, 200);
        assert_eq!(facts.server.as_deref(), Some("nginx/1.27.2"));
        assert_eq!(facts.location.as_deref(), Some("/login"));
        assert_eq!(extract_title(&raw[header_end..]).as_deref(), Some("hello"));
        assert!(parse_http_response(b"SSH-2.0-x\r\n\r\n").is_none());
    }

    #[test]
    fn hostname_matching_prefers_san_then_cn() {
        let (hit, _) = match_hostname("a.test", &["a.test".to_owned()], &[], "");
        assert!(hit);
        let (hit, _) = match_hostname("b.a.test", &["*.a.test".to_owned()], &[], "");
        assert!(hit);
        let (hit, _) = match_hostname("evil.test", &["a.test".to_owned()], &[], "");
        assert!(!hit);
        let (hit, _) = match_hostname("127.0.0.1", &[], &["127.0.0.1".to_owned()], "");
        assert!(hit);
    }

    #[test]
    fn epoch_dates_are_sane() {
        assert_eq!(epoch_date(0), "1970-01-01");
        assert_eq!(epoch_date(1_700_000_000).len(), 10);
    }
}
