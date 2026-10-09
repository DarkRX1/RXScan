//! Local Web/API front-end for RXScan (localhost milestone).
//!
//! Same-origin GUI + versioned typed API (`/api/v1/...`) backed by the same
//! core the CLI uses: [`crate::run`], [`crate::investigate`], and
//! [`crate::project_db`]. There is no second scanner, no second OSINT
//! engine, and no parallel evidence store. HTTP handlers validate and
//! translate; the core decides.
//!
//! Transport notes:
//! - Implemented on `std::net` only (no new HTTP dependencies): one thread
//!   per connection, one worker thread per job. Localhost scale only.
//! - Default bind is loopback. A non-loopback bind requires explicit
//!   opt-in (`allow_remote`) and stays unauthenticated, so it is marked
//!   dangerous and must not be used for remote hosting.
//! - Long operations are jobs (`queued/running/completed/partial/failed/`
//!   `cancelled/timed_out`). Cancellation sets the same `Arc<AtomicBool>`
//!   the core polls: scans reach [`crate::execution::Scheduler`] through
//!   [`crate::run::execute_with_cancellation`], investigations through
//!   [`crate::investigate::run_investigation`]. Partial evidence is kept.
//! - Progress is server-sent events (`GET /api/v1/jobs/:id/events`).
//! - There is deliberately no `/execute`, `/command`, or `/shell` route:
//!   the browser requests typed operations only.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    capabilities,
    cli::Cli,
    investigate::{self, InvestigationConfig, MAX_DEPTH as INVEST_MAX_DEPTH, SeedKind},
    plan::{ScanGoal, ScanPlan, SpeedSetting},
    project_db::ProjectDb,
    run::{self, RunError},
    target::TargetSpec,
};

// ---------------------------------------------------------------------------
// Constants: versioning and hard bounds.
// ---------------------------------------------------------------------------

/// Versioned API namespace: every route lives under `/api/v1/`.
pub const API_VERSION: u32 = 1;
/// Tool version stamped into capability responses (never secrets).
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum JSON request body (larger -> `413 payload_too_large`).
pub const MAX_BODY_BYTES: usize = 512 * 1024;
/// Absolute connection coherence cap: bodies up to this size are drained
/// before the `413` is sent so the client gets a clean response instead of
/// a reset; anything larger is dropped with the connection (abuse case).
const MAX_DRAIN_BYTES: usize = 8 * 1024 * 1024;
/// Maximum request-line + headers block.
pub const MAX_HEAD_BYTES: usize = 32 * 1024;
/// Maximum stored jobs (oldest terminal jobs evict first; running jobs
/// are never evicted).
pub const MAX_JOBS_STORED: usize = 128;
/// Maximum concurrently running jobs (excess -> `429 rate_limited`).
pub const MAX_RUNNING_JOBS: usize = 8;
/// Maximum events retained per job (SSE replays from this buffer).
pub const MAX_EVENTS_PER_JOB: usize = 200;
/// Default page size for list endpoints.
pub const DEFAULT_PAGE_LIMIT: usize = 50;
/// Hard page ceiling for every list endpoint.
pub const MAX_PAGE_LIMIT: usize = 500;
/// Maximum graph nodes returned in one response.
pub const MAX_GRAPH_NODES: usize = 500;
/// Maximum ports in one explicit scan request.
pub const MAX_SCAN_PORTS: usize = 5000;
/// Maximum scope/exclude entries per scan request.
pub const MAX_SCOPE_ENTRIES: usize = 64;
/// Project name policy: filesystem-safe, traversal-proof.
const PROJECT_NAME_MAX: usize = 64;
/// Maximum request-line length (longer -> `414 uri_too_long`).
pub const MAX_REQUEST_LINE_BYTES: usize = 8192;
/// Maximum request path length.
pub const MAX_PATH_BYTES: usize = 4096;
/// Maximum request header count.
pub const MAX_HEADER_COUNT: usize = 100;
/// Default scan-job deadline (seconds) when the request omits one.
pub const DEFAULT_SCAN_DEADLINE_SECS: u64 = 60;
/// Hard scan-job deadline ceiling (seconds).
pub const MAX_SCAN_DEADLINE_SECS: u64 = 3600;
/// Default username-search deadline (seconds) when the request omits one.
pub const DEFAULT_SEARCH_DEADLINE_SECS: u64 = 25;
/// Hard username-search deadline ceiling (seconds).
pub const MAX_SEARCH_DEADLINE_SECS: u64 = 120;
/// Default investigation deadline (seconds) when the request omits one.
pub const DEFAULT_INVESTIGATION_DEADLINE_SECS: u64 = 60;
/// Hard investigation deadline ceiling (seconds).
pub const MAX_INVESTIGATION_DEADLINE_SECS: u64 = 600;

// ---------------------------------------------------------------------------
// Error model.
// ---------------------------------------------------------------------------

/// Typed API error envelope. `code` is stable for clients; `message` is
/// human-readable and never contains Rust debug dumps, filesystem paths,
/// or credentials. Server-side detail stays in stderr logs keyed by the
/// request id.
#[derive(Debug, Clone, Serialize)]
pub struct ApiErrorBody {
    pub error: ApiError,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiError {
    pub code: &'static str,
    pub message: String,
}

impl ApiErrorBody {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            error: ApiError {
                code,
                message: message.into(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// DTOs: requests.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub target: Option<String>,
    #[serde(default)]
    pub ports: Option<PortsSpec>,
    #[serde(default)]
    pub all_ports: bool,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub level: Option<u8>,
    #[serde(default)]
    pub goal: Option<String>,
    #[serde(default)]
    pub speed: Option<String>,
    #[serde(default)]
    pub udp: bool,
    /// Explicit bounded active OS fingerprinting (`--os` parity with CLI).
    /// Default off; scope/cancellation/deadline rules are identical.
    #[serde(default)]
    pub os: bool,
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub deadline_seconds: Option<u64>,
    #[serde(default)]
    pub project: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum PortsSpec {
    Text(String),
    List(Vec<u64>),
}

#[derive(Debug, Deserialize)]
pub struct InvestigationRequest {
    pub entity_type: Option<String>,
    pub value: Option<String>,
    #[serde(default)]
    pub depth: Option<u8>,
    #[serde(default)]
    pub deadline_seconds: Option<u64>,
    #[serde(default)]
    pub project: Option<String>,
    /// Explicit authorized network bridge (default off). Requires `scope`;
    /// the core Scope Guard stays authoritative for every pivot.
    #[serde(default)]
    pub network: bool,
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ProjectCreateRequest {
    pub name: Option<String>,
}

/// Synchronous passive entity search (zero network).
///
/// Supports the real `rxscan search --email/--domain/...` kinds:
/// `email`, `domain`, `hostname`, `ip`, `asn`, `url`, `repo`/`repository`,
/// `org`/`organization`. `username` provider search contacts public
/// sources and lives at `POST /api/v1/username-searches` as a cancellable
/// job instead: this endpoint stays instant and local-only.
#[derive(Debug, Deserialize)]
pub struct EntitySearchRequest {
    pub entity_type: Option<String>,
    pub value: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
}

/// Asynchronous public-source username search (bounded public HTTP).
///
/// Same core as `rxscan search --username`: typed observations with
/// status/evidence/confidence/coverage and candidate-vs-observed honesty.
/// Runs as a job so progress/cancellation stream over SSE like scans and
/// investigations.
///
/// Category/provider selection uses the SAME registry and planning as the
/// CLI (`rxscan search --category/--provider`): identical options yield
/// the identical provider execution plan.
#[derive(Debug, Deserialize)]
pub struct UsernameSearchRequest {
    pub value: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub deadline_seconds: Option<u64>,
    #[serde(default)]
    pub project: Option<String>,
    /// Category selection (machine IDs, e.g. `social`, `developer`).
    /// Same vocabulary and planning as CLI `--category`.
    #[serde(default)]
    pub categories: Vec<String>,
    /// Explicit provider selection (IDs, e.g. `github`).
    /// Same planning as CLI `--provider`.
    #[serde(default)]
    pub providers: Vec<String>,
    /// Providers to exclude (same as CLI `--exclude-provider`).
    #[serde(default)]
    pub exclude_providers: Vec<String>,
}

// ---------------------------------------------------------------------------
// DTOs: responses.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub api_version: u32,
    pub tool_version: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityDto {
    pub name: String,
    pub state: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilitiesResponse {
    pub api_version: u32,
    pub tool_version: &'static str,
    pub capabilities: Vec<CapabilityDto>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EntityDto {
    pub entity_id: String,
    pub kind: String,
    pub label: String,
    pub first_seen_scan: String,
    pub last_seen_scan: String,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub observation_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingDto {
    pub entity_id: String,
    pub kind: String,
    pub label: String,
    pub confidence: u8,
    pub evidence_excerpt: String,
    pub module: String,
    pub task_id: String,
    pub scan_run: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphNodeDto {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub observation_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphEdgeDto {
    pub from: String,
    pub to: String,
    pub relation: String,
    pub confidence: u8,
    pub scan_run: String,
    pub module: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelineEventDto {
    pub timestamp_ms: u64,
    pub entity_id: String,
    pub kind: String,
    pub label: String,
    pub scan_run: String,
    pub module: String,
    /// True when the observation belongs to the latest run (current),
    /// false for superseded historical observations.
    pub current: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobEventDto {
    pub seq: u64,
    pub r#type: String,
    pub message: String,
    pub timestamp_ms: u64,
}

// ---------------------------------------------------------------------------
// Jobs.
// ---------------------------------------------------------------------------

/// Job lifecycle. `partial` is orthogonal detail: a `cancelled`/`timed_out`
/// job with collected evidence keeps it (partial evidence, never silently
/// dropped or relabeled as failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Partial,
    Failed,
    Cancelled,
    TimedOut,
}

impl JobStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobKind {
    Scan,
    Investigation,
    UsernameSearch,
}

impl JobKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::Investigation => "investigation",
            Self::UsernameSearch => "username_search",
        }
    }
}

struct JobRecord {
    id: String,
    kind: JobKind,
    status: JobStatus,
    partial: bool,
    progress: String,
    project: String,
    label: String,
    cancel: Arc<AtomicBool>,
    events: Vec<JobEventDto>,
    event_seq: u64,
    result: Option<serde_json::Value>,
    error: Option<ApiError>,
    created_ms: u64,
    started_ms: Option<u64>,
    finished_ms: Option<u64>,
}

struct JobStore {
    jobs: HashMap<String, JobRecord>,
    order: VecDeque<String>,
    counter: u64,
}

impl JobStore {
    fn new() -> Self {
        Self {
            jobs: HashMap::new(),
            order: VecDeque::new(),
            counter: 0,
        }
    }

    fn running_count(&self) -> usize {
        self.jobs
            .values()
            .filter(|job| matches!(job.status, JobStatus::Queued | JobStatus::Running))
            .count()
    }

    fn evict_oldest_terminal(&mut self) {
        while self.jobs.len() >= MAX_JOBS_STORED {
            let victim = self
                .order
                .iter()
                .find(|id| {
                    self.jobs.get(*id).is_some_and(|job| {
                        !matches!(job.status, JobStatus::Queued | JobStatus::Running)
                    })
                })
                .cloned();
            match victim {
                Some(id) => {
                    self.jobs.remove(&id);
                    self.order.retain(|other| other != &id);
                }
                None => break,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Server state.
// ---------------------------------------------------------------------------

/// Server options. The binary defaults to loopback; `allow_remote` is the
/// explicit dangerous/advanced opt-in and must never be set silently.
#[derive(Debug, Clone)]
pub struct WebOptions {
    pub bind: String,
    pub port: u16,
    pub data_dir: PathBuf,
    pub allow_remote: bool,
    /// Test-only: investigation workers use deterministic fixture backends
    /// (no network). The shipped binary never enables this.
    pub fixture_investigation: bool,
}

impl Default for WebOptions {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1".to_owned(),
            port: 8080,
            data_dir: PathBuf::from(".rxscan-web"),
            allow_remote: false,
            fixture_investigation: false,
        }
    }
}

struct ServerState {
    options: WebOptions,
    jobs: Mutex<JobStore>,
    requests: AtomicU64,
    shutdown: Arc<AtomicBool>,
}

pub struct ServerHandle {
    base_url: String,
    shutdown: Arc<AtomicBool>,
    port: u16,
    accept_thread: Mutex<Option<JoinHandle<()>>>,
    state: Arc<ServerState>,
}

impl ServerHandle {
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Graceful shutdown: stop accepting work, signal cancellation to
    /// running jobs (partial evidence preserved by the core drain path),
    /// allow a bounded drain for workers, then return.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        // Cancel in-flight jobs through the real core machinery.
        if let Ok(store) = self.state.jobs.lock() {
            for job in store.jobs.values() {
                if matches!(job.status, JobStatus::Queued | JobStatus::Running) {
                    job.cancel.store(true, Ordering::Release);
                }
            }
        }
        // Wake the blocking acceptor so it observes shutdown promptly.
        let _ = TcpStream::connect(format!("127.0.0.1:{}", self.port));
        if let Ok(mut slot) = self.accept_thread.lock() {
            if let Some(thread) = slot.take() {
                let _ = thread.join();
            }
        }
        // Bounded drain: give workers a moment to reach terminal states
        // and persist partial evidence; never block forever.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let done =
                self.state
                    .jobs
                    .lock()
                    .map(|store| {
                        store.jobs.values().all(|job| {
                            !matches!(job.status, JobStatus::Queued | JobStatus::Running)
                        })
                    })
                    .unwrap_or(true);
            if done || Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn percent_decode(input: &str) -> String {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                out.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        if bytes[index] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[index]);
        }
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_query(query: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        match pair.split_once('=') {
            Some((key, value)) => {
                out.insert(percent_decode(key), percent_decode(value));
            }
            None => {
                out.insert(percent_decode(pair), String::new());
            }
        }
    }
    out
}

fn parse_pagination(query: &BTreeMap<String, String>) -> Result<(usize, usize), ApiErrorBody> {
    let limit = match query.get("limit") {
        None => DEFAULT_PAGE_LIMIT,
        Some(raw) => raw.parse::<usize>().map_err(|_| {
            ApiErrorBody::new("bad_request", "limit must be a non-negative integer")
        })?,
    };
    let offset = match query.get("offset") {
        None => 0,
        Some(raw) => raw.parse::<usize>().map_err(|_| {
            ApiErrorBody::new("bad_request", "offset must be a non-negative integer")
        })?,
    };
    if limit == 0 || limit > MAX_PAGE_LIMIT {
        return Err(ApiErrorBody::new(
            "bad_request",
            format!("limit must be 1..={MAX_PAGE_LIMIT}"),
        ));
    }
    if offset > 1_000_000 {
        return Err(ApiErrorBody::new("bad_request", "offset out of range"));
    }
    Ok((limit, offset))
}

fn validate_project_name(name: &str) -> Result<String, ApiErrorBody> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > PROJECT_NAME_MAX {
        return Err(ApiErrorBody::new(
            "bad_request",
            "project name must be 1..=64 characters",
        ));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ApiErrorBody::new(
            "bad_request",
            "project name may only contain letters, digits, '-' and '_'",
        ));
    }
    Ok(trimmed.to_owned())
}

fn project_db_path(data_dir: &std::path::Path, project: &str) -> PathBuf {
    data_dir.join(format!("{project}.db"))
}

/// Truncate to a byte budget on a char boundary (terminal's similarly
/// named helper counts chars instead — the units differ, so the names do).
fn truncate_bytes(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

// ---------------------------------------------------------------------------
// HTTP plumbing (std only).
// ---------------------------------------------------------------------------

struct HttpRequest {
    method: String,
    path: String,
    query: BTreeMap<String, String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        _ => "Error",
    }
}

fn error_status(code: &'static str) -> u16 {
    match code {
        "bad_request" | "invalid_json" | "unsupported_media_type" => 400,
        "foreign_host" | "foreign_origin" => 403,
        "not_found" => 404,
        "method_not_allowed" => 405,
        "conflict" => 409,
        "payload_too_large" => 413,
        "invalid_target" | "invalid_entity" | "invalid_scope" | "unprocessable" => 422,
        "rate_limited" => 429,
        "not_implemented" => 501,
        _ => 500,
    }
}

fn read_request(stream: &mut BufReader<TcpStream>) -> Result<HttpRequest, ApiErrorBody> {
    let mut request_line = String::new();
    stream
        .read_line(&mut request_line)
        .map_err(|_| ApiErrorBody::new("bad_request", "could not read request"))?;
    if request_line.len() > MAX_REQUEST_LINE_BYTES || request_line.is_empty() {
        return Err(ApiErrorBody::new("bad_request", "malformed request line"));
    }
    let parts: Vec<&str> = request_line.trim_end().splitn(3, ' ').collect();
    if parts.len() != 3 {
        return Err(ApiErrorBody::new("bad_request", "malformed request line"));
    }
    let method = parts[0].to_owned();
    let target = parts[1];
    if !parts[2].starts_with("HTTP/") {
        return Err(ApiErrorBody::new("bad_request", "unsupported HTTP version"));
    }
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_owned(), parse_query(query)),
        None => (target.to_owned(), BTreeMap::new()),
    };
    if path.len() > MAX_PATH_BYTES || !path.starts_with('/') {
        return Err(ApiErrorBody::new("bad_request", "malformed request path"));
    }
    let mut headers = HashMap::new();
    let mut head_bytes = request_line.len();
    loop {
        let mut line = String::new();
        stream
            .read_line(&mut line)
            .map_err(|_| ApiErrorBody::new("bad_request", "could not read headers"))?;
        head_bytes += line.len();
        if head_bytes > MAX_HEAD_BYTES {
            return Err(ApiErrorBody::new("bad_request", "headers too large"));
        }
        if headers.len() > MAX_HEADER_COUNT {
            return Err(ApiErrorBody::new("bad_request", "too many headers"));
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        match trimmed.split_once(':') {
            Some((name, value)) => {
                headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
            }
            None => {
                return Err(ApiErrorBody::new("bad_request", "malformed header"));
            }
        }
    }
    if headers
        .get("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        return Err(ApiErrorBody::new(
            "not_implemented",
            "chunked transfer encoding is not supported",
        ));
    }
    let content_length: usize = match headers.get("content-length") {
        None => 0,
        Some(raw) => raw
            .parse()
            .map_err(|_| ApiErrorBody::new("bad_request", "invalid Content-Length"))?,
    };
    if content_length > MAX_DRAIN_BYTES {
        // Unbounded abuse: drop the connection without buffering.
        return Err(ApiErrorBody::new(
            "payload_too_large",
            format!("request body exceeds {MAX_BODY_BYTES} bytes"),
        ));
    }
    if content_length > MAX_BODY_BYTES {
        // Bounded best-effort drain: consume the body with a fixed-size
        // buffer so the client receives a clean response instead of seeing
        // leftover bytes. Oversized-ness is already proven by the declared
        // Content-Length, so a drain failure (peer gone, timeout) must not
        // downgrade the rejection to bad_request; it stays payload_too_large.
        let mut remaining = content_length;
        let mut buf = [0u8; 4096];
        while remaining > 0 {
            let chunk_len = remaining.min(buf.len());
            match stream.read(&mut buf[..chunk_len]) {
                Ok(0) => break,
                Ok(n) => remaining -= n,
                Err(_) => break,
            }
        }
        return Err(ApiErrorBody::new(
            "payload_too_large",
            format!("request body exceeds {MAX_BODY_BYTES} bytes"),
        ));
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        stream
            .read_exact(&mut body)
            .map_err(|_| ApiErrorBody::new("bad_request", "truncated request body"))?;
    }
    Ok(HttpRequest {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn write_response(
    stream: &mut TcpStream,
    request_id: u64,
    code: u16,
    content_type: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nX-Request-Id: {:016x}\r\n",
        code,
        status_text(code),
        content_type,
        body.len(),
        request_id,
    );
    for (name, value) in extra_headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn json_response<T: Serialize>(stream: &mut TcpStream, request_id: u64, code: u16, value: &T) {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    write_response(stream, request_id, code, "application/json", &[], &body);
}

fn error_response(stream: &mut TcpStream, request_id: u64, error: &ApiErrorBody) {
    let code = error_status(error.error.code);
    json_response(stream, request_id, code, error);
}

// ---------------------------------------------------------------------------
// Localhost security: Host + Origin + Content-Type gates.
// ---------------------------------------------------------------------------

fn host_is_loopback(host_header: Option<&str>) -> bool {
    let Some(header) = host_header else {
        return false;
    };
    // Strip an optional port (`[::1]:8080`, `127.0.0.1:8080`).
    let host = if header.starts_with('[') {
        header
            .split(']')
            .next()
            .unwrap_or("")
            .trim_start_matches('[')
    } else {
        header.split(':').next().unwrap_or("")
    };
    let host = host.trim().to_ascii_lowercase();
    host == "127.0.0.1" || host == "localhost" || host == "::1"
}

fn origin_is_allowed(origin: Option<&str>) -> bool {
    let Some(origin) = origin else {
        // Non-browser clients send no Origin: same-origin by construction.
        return true;
    };
    // `Origin: http://127.0.0.1:8080` or `http://localhost:8080`.
    let without_scheme = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .unwrap_or("");
    let host = if without_scheme.starts_with('[') {
        without_scheme
            .split(']')
            .next()
            .unwrap_or("")
            .trim_start_matches('[')
    } else {
        without_scheme.split(':').next().unwrap_or("")
    };
    let host = host.to_ascii_lowercase();
    host == "127.0.0.1" || host == "localhost" || host == "::1"
}

/// Reject DNS-rebinding and cross-site abuse before routing:
/// the Host must be loopback, and unsafe methods require either no Origin
/// (non-browser client) or a loopback Origin. No CORS is emitted at all:
/// the GUI is same-origin, so foreign origins get nothing to reuse.
fn check_local_origin(request: &HttpRequest) -> Result<(), ApiErrorBody> {
    if !host_is_loopback(request.headers.get("host").map(String::as_str)) {
        return Err(ApiErrorBody::new(
            "foreign_host",
            "Host must be a loopback address for this local server",
        ));
    }
    if request.method != "GET" && request.method != "HEAD" {
        if !origin_is_allowed(request.headers.get("origin").map(String::as_str)) {
            return Err(ApiErrorBody::new(
                "foreign_origin",
                "foreign Origin rejected by the local server",
            ));
        }
        // JSON request types for mutation APIs: simple-form POSTs from a
        // hostile site cannot set `application/json` without preflight,
        // which this server never answers. Only methods that carry a
        // mutation body are gated (bodiless probes fall through to the
        // router's 404/405 handling).
        if matches!(request.method.as_str(), "POST" | "PUT" | "PATCH") {
            let content_type = request
                .headers
                .get("content-type")
                .map(String::as_str)
                .unwrap_or("");
            if !content_type
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json")
            {
                return Err(ApiErrorBody::new(
                    "unsupported_media_type",
                    "mutation APIs require Content-Type: application/json",
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Static assets (embedded so one binary serves GUI + API same-origin).
// ---------------------------------------------------------------------------

struct StaticAsset {
    content_type: &'static str,
    body: &'static [u8],
}

fn static_asset(path: &str) -> Option<StaticAsset> {
    // RXScan GUI only: `/` serves the application directly and `/app` is
    // kept as a backwards-compatible alias. The personal portfolio is a
    // separate project/deployment and is never served from `rxscan web`:
    // no `/site/`, `/portfolio/`, or portfolio asset routes exist here.
    match path {
        "/" | "/app" | "/app/" => Some(StaticAsset {
            content_type: "text/html; charset=utf-8",
            body: include_str!("../app/index.html").as_bytes(),
        }),
        "/rxscan.js" | "/app/rxscan.js" => Some(StaticAsset {
            content_type: "application/javascript; charset=utf-8",
            body: include_str!("../app/rxscan.js").as_bytes(),
        }),
        "/rxscan.css" | "/app/rxscan.css" => Some(StaticAsset {
            content_type: "text/css; charset=utf-8",
            body: include_str!("../app/rxscan.css").as_bytes(),
        }),
        "/app/assets/RXScanlogo.png" | "/assets/RXScanlogo.png" | "/RXScanlogo.png" => {
            Some(StaticAsset {
                content_type: "image/png",
                body: include_bytes!("../app/assets/RXScanlogo.png"),
            })
        }
        "/favicon.png" | "/app/favicon.png" | "/assets/favicon.png" => Some(StaticAsset {
            content_type: "image/png",
            body: include_bytes!("../app/assets/RXScanlogo.png"),
        }),
        "/favicon.ico" | "/app/favicon.ico" => Some(StaticAsset {
            content_type: "image/png",
            body: include_bytes!("../app/assets/RXScanlogo.png"),
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Request validation -> core operation inputs.
// ---------------------------------------------------------------------------

struct ValidatedScan {
    cli: Cli,
    project: String,
    target_label: String,
}

fn build_scan_cli(request: ScanRequest) -> Result<ValidatedScan, ApiErrorBody> {
    let target = request.target.as_deref().unwrap_or("").trim().to_owned();
    if target.is_empty() || target.len() > 253 {
        return Err(ApiErrorBody::new(
            "invalid_target",
            "target must be 1..=253 characters",
        ));
    }
    if target == "-" {
        return Err(ApiErrorBody::new(
            "invalid_target",
            "standard-input targets are not supported by the web API",
        ));
    }
    // Real target validation through the core parser (same as CLI).
    TargetSpec::parse(&target)
        .map_err(|error| ApiErrorBody::new("invalid_target", format!("invalid target: {error}")))?;

    // All-ports intent: `all` (case-insensitive) in the ports field and the
    // explicit `all_ports` checkbox are the SAME core option. The frontend
    // never generates a 65,535-element array; the API expresses intent
    // structurally (`all_ports: true`) and the core planner expands it as
    // one bounded task. UDP stays bounded (never full-range).
    let mut all_ports = request.all_ports;
    let ports: Option<String> = match request.ports {
        None => None,
        Some(PortsSpec::Text(text)) => {
            let text = text.trim().to_owned();
            if text.len() > 4096 {
                return Err(ApiErrorBody::new(
                    "invalid_target",
                    "ports specification too long",
                ));
            }
            if text.is_empty() {
                None
            } else if text.eq_ignore_ascii_case("all") {
                // Textual `all` means all TCP ports 1-65535 (same as CLI
                // `--all-ports` and the GUI checkbox). Do not expand here.
                all_ports = true;
                None
            } else {
                // Validate eagerly so malformed input fails with 422 instead
                // of silently falling back to default ports.
                if let Err(reason) = crate::ports::parse_port_selection(&text) {
                    return Err(ApiErrorBody::new("invalid_target", reason));
                }
                Some(text)
            }
        }
        Some(PortsSpec::List(list)) => {
            if list.len() > MAX_SCAN_PORTS {
                return Err(ApiErrorBody::new(
                    "payload_too_large",
                    format!("at most {MAX_SCAN_PORTS} explicit ports per request"),
                ));
            }
            if list.is_empty() {
                None
            } else {
                for port in &list {
                    if *port == 0 || *port > 65535 {
                        return Err(ApiErrorBody::new(
                            "invalid_target",
                            "ports must be 1..=65535",
                        ));
                    }
                }
                let text = list
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                Some(text)
            }
        }
    };

    if let Some(mode) = &request.mode {
        if !matches!(mode.as_str(), "connect" | "syn" | "auto") {
            return Err(ApiErrorBody::new(
                "unprocessable",
                "mode must be one of connect, syn, auto",
            ));
        }
    }
    if let Some(level) = request.level {
        if !(1..=5).contains(&level) {
            return Err(ApiErrorBody::new("unprocessable", "level must be 1..=5"));
        }
    }
    if let Some(goal) = &request.goal {
        ScanGoal::parse(goal).map_err(|error| ApiErrorBody::new("unprocessable", error))?;
    }
    if let Some(speed) = &request.speed {
        speed
            .parse::<SpeedSetting>()
            .map_err(|error: String| ApiErrorBody::new("unprocessable", error))?;
    }
    if request.scope.len() > MAX_SCOPE_ENTRIES || request.exclude.len() > MAX_SCOPE_ENTRIES {
        return Err(ApiErrorBody::new(
            "unprocessable",
            format!("at most {MAX_SCOPE_ENTRIES} scope/exclude entries"),
        ));
    }
    // Scope defaults to the target itself; every extra entry parses
    // through the core target parser (same enforcement as CLI).
    let mut scope = vec![target.clone()];
    for entry in &request.scope {
        if entry.len() > 253 {
            return Err(ApiErrorBody::new(
                "invalid_scope",
                "scope entry must be 1..=253 characters",
            ));
        }
        TargetSpec::parse(entry).map_err(|_| {
            ApiErrorBody::new("invalid_scope", format!("invalid scope entry '{entry}'"))
        })?;
        scope.push(entry.clone());
    }
    for entry in &request.exclude {
        if entry.len() > 253 {
            return Err(ApiErrorBody::new(
                "invalid_scope",
                "exclude entry must be 1..=253 characters",
            ));
        }
        TargetSpec::parse(entry).map_err(|_| {
            ApiErrorBody::new("invalid_scope", format!("invalid exclude entry '{entry}'"))
        })?;
    }
    let deadline = request
        .deadline_seconds
        .unwrap_or(DEFAULT_SCAN_DEADLINE_SECS);
    if deadline == 0 || deadline > MAX_SCAN_DEADLINE_SECS {
        return Err(ApiErrorBody::new(
            "unprocessable",
            "deadline_seconds must be 1..=3600",
        ));
    }
    let project = validate_project_name(request.project.as_deref().unwrap_or("default"))?;

    // Placeholder project path: the worker resolves the real path against
    // the server data dir (never from client-controlled path text).
    let cli = Cli {
        target: Some(target.clone()),
        targets: None,
        config: None,
        project_config: None,
        goal: request.goal.clone(),
        level: request.level,
        speed: request
            .speed
            .as_deref()
            .map(|value| value.parse())
            .transpose()
            .map_err(ApiErrorBody::new_unprocessable())?,
        profile: None,
        scope,
        exclude: request.exclude.clone(),
        ports,
        all_ports,
        ping: false,
        discover: false,
        udp: request.udp,
        os: request.os,
        wordlist: None,
        scan_mode: request.mode.clone(),
        explain: false,
        max_tasks: None,
        max_retries: None,
        max_concurrency: None,
        max_hosts: None,
        max_execution_time: Some(format!("{deadline}s")),
        max_evidence_bytes: None,
        output: None,
        checkpoint: None,
        resume: None,
        project_db: None,
        format: None,
        color: None,
    };
    // Synchronous plan validation: invalid targets/scopes/budgets fail
    // here with 422 before any job exists (no network contact involved).
    ScanPlan::compile(cli.clone())
        .map_err(|error| ApiErrorBody::new("invalid_target", format!("invalid scan: {error}")))?;
    Ok(ValidatedScan {
        cli,
        project,
        target_label: target,
    })
}

impl ApiErrorBody {
    fn new_unprocessable() -> impl Fn(String) -> ApiErrorBody {
        |message| ApiErrorBody::new("unprocessable", message)
    }
}

struct ValidatedInvestigation {
    config: InvestigationConfig,
    project: String,
}

fn build_investigation_config(
    request: InvestigationRequest,
) -> Result<ValidatedInvestigation, ApiErrorBody> {
    let kind_text = request.entity_type.as_deref().unwrap_or("").trim();
    let Some(kind) = SeedKind::parse(kind_text) else {
        return Err(ApiErrorBody::new(
            "invalid_entity",
            "entity_type must be one of username, domain, url, email, ip, asn, repository, organization",
        ));
    };
    let value = request.value.as_deref().unwrap_or("").trim().to_owned();
    if value.is_empty() || value.len() > 512 {
        return Err(ApiErrorBody::new(
            "invalid_entity",
            "value must be 1..=512 characters",
        ));
    }
    let depth = request.depth.unwrap_or(investigate::DEFAULT_DEPTH);
    if depth > INVEST_MAX_DEPTH {
        return Err(ApiErrorBody::new(
            "unprocessable",
            format!("depth must be 0..={INVEST_MAX_DEPTH}"),
        ));
    }
    let deadline = request
        .deadline_seconds
        .unwrap_or(DEFAULT_INVESTIGATION_DEADLINE_SECS);
    if deadline == 0 || deadline > MAX_INVESTIGATION_DEADLINE_SECS {
        return Err(ApiErrorBody::new(
            "unprocessable",
            "deadline_seconds must be 1..=600",
        ));
    }
    if request.scope.len() > MAX_SCOPE_ENTRIES || request.exclude.len() > MAX_SCOPE_ENTRIES {
        return Err(ApiErrorBody::new(
            "unprocessable",
            format!("at most {MAX_SCOPE_ENTRIES} scope/exclude entries"),
        ));
    }
    let project = validate_project_name(request.project.as_deref().unwrap_or("default"))?;
    let mut config = InvestigationConfig::seeded(kind, &value);
    config.depth = depth;
    config.deadline = Duration::from_secs(deadline);
    // The passive/active boundary: the bridge is explicit or absent.
    // `network: false` (default) never port scans, never probes.
    config.network = request.network;
    config.scopes = request.scope.clone();
    config.scope_exclusions = request.exclude.clone();
    // Core validation decides valid transforms, budgets, and bridge
    // authorization (JavaScript never schedules transforms).
    config
        .validate()
        .map_err(|message| ApiErrorBody::new("invalid_entity", message))?;
    Ok(ValidatedInvestigation { config, project })
}

// ---------------------------------------------------------------------------
// Job lifecycle helpers (shared by workers).
// ---------------------------------------------------------------------------

fn push_event(store: &mut JobStore, id: &str, event_type: &str, message: String) {
    if let Some(job) = store.jobs.get_mut(id) {
        job.event_seq += 1;
        let event = JobEventDto {
            seq: job.event_seq,
            r#type: event_type.to_owned(),
            message: message.clone(),
            timestamp_ms: now_ms(),
        };
        job.events.push(event);
        if job.events.len() > MAX_EVENTS_PER_JOB {
            let excess = job.events.len() - MAX_EVENTS_PER_JOB;
            job.events.drain(..excess);
        }
        if event_type == "progress" || event_type.starts_with("job_") {
            job.progress = message;
        }
    }
}

fn finish_job(
    store: &mut JobStore,
    id: &str,
    status: JobStatus,
    partial: bool,
    result: Option<serde_json::Value>,
    error: Option<ApiError>,
) {
    if let Some(job) = store.jobs.get_mut(id) {
        job.status = status;
        job.partial = partial;
        job.result = result;
        job.error = error;
        job.finished_ms = Some(now_ms());
        let terminal = match status {
            JobStatus::Completed => "job_completed",
            JobStatus::Partial => "job_partial",
            JobStatus::Failed => "job_failed",
            JobStatus::Cancelled => "job_cancelled",
            JobStatus::TimedOut => "job_partial",
            JobStatus::Queued | JobStatus::Running => "progress",
        };
        let message = if partial && status != JobStatus::Completed {
            format!("{} (partial evidence preserved)", status.as_str())
        } else {
            status.as_str().to_owned()
        };
        job.event_seq += 1;
        job.events.push(JobEventDto {
            seq: job.event_seq,
            r#type: terminal.to_owned(),
            message: message.clone(),
            timestamp_ms: now_ms(),
        });
        job.progress = message;
    }
}

fn new_job_id(store: &mut JobStore, kind: &str, label: &str) -> String {
    store.counter += 1;
    let counter = store.counter;
    let nanos = now_ms();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    counter.hash(&mut hasher);
    nanos.hash(&mut hasher);
    kind.hash(&mut hasher);
    label.hash(&mut hasher);
    format!("job_{:016x}", hasher.finish())
}

fn job_summary(job: &JobRecord, include_detail: bool) -> serde_json::Value {
    let mut value = serde_json::json!({
        "id": job.id,
        "kind": job.kind.as_str(),
        "status": job.status.as_str(),
        "partial": job.partial,
        "progress": job.progress,
        "project": job.project,
        "label": job.label,
        "created_ms": job.created_ms,
        "started_ms": job.started_ms,
        "finished_ms": job.finished_ms,
    });
    if include_detail {
        value["events"] = serde_json::to_value(&job.events).unwrap_or_default();
        value["result"] = job.result.clone().unwrap_or(serde_json::Value::Null);
        value["error"] = job
            .error
            .clone()
            .map(|error| serde_json::json!({"code": error.code, "message": error.message}))
            .unwrap_or(serde_json::Value::Null);
    } else {
        value["has_result"] = serde_json::Value::Bool(job.result.is_some());
    }
    value
}

// ---------------------------------------------------------------------------
// Workers: typed core calls on background threads.
// ---------------------------------------------------------------------------

fn run_error_message(error: &RunError) -> (&'static str, String) {
    // Input/plan failures are safe to surface (operator's own input);
    // runtime/persistence failures stay generic client-side with full
    // detail in the server log.
    match error {
        RunError::Plan(error) => ("invalid_target", format!("invalid scan: {error}")),
        RunError::Lower(error) => ("invalid_target", format!("invalid scan: {error}")),
        RunError::Scheduler(_)
        | RunError::Output(_)
        | RunError::Persistence(_)
        | RunError::ProjectDb(_)
        | RunError::InvalidResume(_) => {
            ("internal", "scan execution failed unexpectedly".to_owned())
        }
    }
}

fn spawn_scan_worker(state: Arc<ServerState>, id: String, validated: ValidatedScan) {
    let project_path = project_db_path(&state.options.data_dir, &validated.project);
    thread::spawn(move || {
        let cancel = {
            let store = state.jobs.lock().expect("job store poisoned");
            store
                .jobs
                .get(&id)
                .map(|job| job.cancel.clone())
                .unwrap_or_else(|| Arc::new(AtomicBool::new(false)))
        };
        {
            let mut store = state.jobs.lock().expect("job store poisoned");
            if let Some(job) = store.jobs.get_mut(&id) {
                job.status = JobStatus::Running;
                job.started_ms = Some(now_ms());
            }
            push_event(&mut store, &id, "progress", "scope validated".to_owned());
        }
        if cancel.load(Ordering::Acquire) {
            let mut store = state.jobs.lock().expect("job store poisoned");
            finish_job(&mut store, &id, JobStatus::Cancelled, false, None, None);
            return;
        }
        {
            let mut store = state.jobs.lock().expect("job store poisoned");
            push_event(&mut store, &id, "progress", "executing scan".to_owned());
        }
        let mut cli = validated.cli;
        cli.project_db = Some(project_path);
        let report = run::execute_with_cancellation(cli, Some(cancel.clone()));
        let mut store = state.jobs.lock().expect("job store poisoned");
        match report {
            Ok(report) => {
                let termination = report.scheduler_report.termination.to_string();
                let has_evidence = !report.port_details.is_empty()
                    || report.tcp_totals.open > 0
                    || report.services_identified > 0
                    || report.graph_entities > 0
                    || report.os_hosts.iter().any(|host| host.family != "Unknown");
                // Findings-first details: every field is evidence-backed
                // (`None` stays null, never fabricated). The GUI renders
                // these as the PORT/SERVICE/DETAILS/CONFIDENCE table.
                let open_ports: Vec<serde_json::Value> = report
                    .port_details
                    .iter()
                    .take(200)
                    .map(|detail| {
                        serde_json::json!({
                            "port": detail.port,
                            "service": detail.service,
                            "product": detail.product,
                            "version": detail.version,
                            "banner": detail.banner.as_deref().map(|b| truncate_bytes(b, 512)),
                            "endpoint": detail.endpoint,
                            "http_title": detail.title,
                            "technologies": detail.technologies,
                            "tls_name": detail.tls_name,
                            "tls_issuer": detail.tls_issuer,
                            "ssh_key": detail.ssh_key.as_deref().map(|k| truncate_bytes(k, 256)),
                        })
                    })
                    .collect();
                let project = report.project_import.as_ref().map(|import| {
                    serde_json::json!({
                        "entities_upserted": import.entities_upserted,
                        "observations_added": import.observations_added,
                        "relationships_upserted": import.relationships_upserted,
                    })
                });
                // OS inference from the SAME Rust core the CLI renders: best
                // candidate (or explicit Unknown) per host with confidence,
                // coverage, and limitation notes. No JavaScript scoring.
                let operating_systems: Vec<serde_json::Value> = report
                    .os_hosts
                    .iter()
                    .take(256)
                    .map(|host| {
                        serde_json::json!({
                            "host": host.host,
                            "family": host.family,
                            "generation": host.generation,
                            "confidence": host.confidence,
                            "band": host.band,
                            "coverage": host.coverage,
                            "limitation": host.limitation,
                        })
                    })
                    .collect();
                let result = serde_json::json!({
                    "scan_id": report.scan_id,
                    "termination": termination,
                    "duration_ms": report.duration_ms,
                    "tcp": {
                        "requested": report.tcp_totals.ports_requested,
                        "attempted": report.tcp_totals.ports_attempted,
                        "open": report.tcp_totals.open,
                        "closed": report.tcp_totals.closed,
                        "filtered_or_timed_out": report.tcp_totals.filtered_or_timed_out,
                        "unscanned": report.tcp_totals.unscanned,
                    },
                    "services_identified": report.services_identified,
                    "open_ports": open_ports,
                    "operating_systems": operating_systems,
                    "graph": {
                        "entities": report.graph_entities,
                        "edges": report.graph_edges,
                        "truncated": report.graph_truncated,
                    },
                    "project_import": project,
                });
                let status = match report.scheduler_report.termination {
                    // A cancel that lands as the last task finishes still
                    // completed real work: report completion honestly.
                    crate::execution::TerminationReason::Completed => JobStatus::Completed,
                    crate::execution::TerminationReason::UserCancelled => JobStatus::Cancelled,
                    crate::execution::TerminationReason::GlobalDeadline => JobStatus::TimedOut,
                    crate::execution::TerminationReason::TaskBudget
                    | crate::execution::TerminationReason::RetryBudget
                    | crate::execution::TerminationReason::EvidenceBudget
                    | crate::execution::TerminationReason::OutputBudget => JobStatus::Partial,
                    crate::execution::TerminationReason::InternalFailure => JobStatus::Failed,
                };
                let partial =
                    has_evidence && !matches!(status, JobStatus::Completed | JobStatus::Failed);
                if status == JobStatus::Failed {
                    push_event(
                        &mut store,
                        &id,
                        "warning",
                        "scheduler reported an internal failure".to_owned(),
                    );
                }
                finish_job(&mut store, &id, status, partial, Some(result), None);
            }
            Err(error) => {
                let (code, public) = run_error_message(&error);
                eprintln!("[rxscan-web] job={id} scan failed: {error}");
                finish_job(
                    &mut store,
                    &id,
                    JobStatus::Failed,
                    false,
                    None,
                    Some(ApiError {
                        code,
                        message: public,
                    }),
                );
            }
        }
    });
}

fn spawn_investigation_worker(
    state: Arc<ServerState>,
    id: String,
    validated: ValidatedInvestigation,
) {
    let project_path = project_db_path(&state.options.data_dir, &validated.project);
    let fixture = state.options.fixture_investigation;
    thread::spawn(move || {
        let cancel = {
            let store = state.jobs.lock().expect("job store poisoned");
            store
                .jobs
                .get(&id)
                .map(|job| job.cancel.clone())
                .unwrap_or_else(|| Arc::new(AtomicBool::new(false)))
        };
        {
            let mut store = state.jobs.lock().expect("job store poisoned");
            if let Some(job) = store.jobs.get_mut(&id) {
                job.status = JobStatus::Running;
                job.started_ms = Some(now_ms());
            }
            push_event(&mut store, &id, "progress", "seed validated".to_owned());
        }
        if cancel.load(Ordering::Acquire) {
            let mut store = state.jobs.lock().expect("job store poisoned");
            finish_job(&mut store, &id, JobStatus::Cancelled, false, None, None);
            return;
        }
        {
            let mut store = state.jobs.lock().expect("job store poisoned");
            push_event(&mut store, &id, "progress", "running transforms".to_owned());
        }
        let config = validated.config;
        let seed_value = config.seed_value.clone();
        let seed_kind = config.seed_kind.as_str().to_owned();
        // Real engine path in both modes; only the contact backends
        // differ (production public providers vs deterministic fixtures).
        let outcome: Result<investigate::InvestigationReport, String> = if fixture {
            fixture_investigation(config, &seed_value, &cancel)
        } else {
            investigate::run_investigation(config, &cancel)
        };
        let mut store = state.jobs.lock().expect("job store poisoned");
        match outcome {
            Ok(report) => {
                let entities = report.entities.len();
                let relationships = report.relationships.len();
                let observations = report.observations.len();
                let was_cancelled = cancel.load(Ordering::Acquire);
                // Persist through the existing project layer (same call
                // the CLI uses); a persistence failure warns but never
                // destroys collected evidence.
                let persisted = match ProjectDb::open(&project_path) {
                    Ok(mut db) => match investigate::persist_investigation(&mut db, &report) {
                        Ok(stats) => Some(serde_json::json!({
                            "entities_upserted": stats.entities_upserted,
                            "observations_added": stats.observations_added,
                            "relationships_upserted": stats.relationships_upserted,
                        })),
                        Err(error) => {
                            push_event(
                                &mut store,
                                &id,
                                "warning",
                                format!("project persistence failed: {error}"),
                            );
                            None
                        }
                    },
                    Err(error) => {
                        push_event(
                            &mut store,
                            &id,
                            "warning",
                            format!("project database unavailable: {error}"),
                        );
                        None
                    }
                };
                let correlations: Vec<serde_json::Value> = report
                    .correlations()
                    .into_iter()
                    .take(10)
                    .map(|(entity, sources)| {
                        serde_json::json!({
                            "entity": entity,
                            "sources": sources.into_iter().take(5).collect::<Vec<_>>(),
                        })
                    })
                    .collect();
                let sample: Vec<serde_json::Value> = report
                    .ordered_entities()
                    .into_iter()
                    .take(100)
                    .map(|entity| {
                        serde_json::json!({
                            "id": entity.id,
                            "kind": entity.kind.to_string(),
                            "label": entity.label,
                            "depth": entity.depth,
                            "observations": entity.observations,
                        })
                    })
                    .collect();
                let partial = was_cancelled && (entities > 1 || observations > 0);
                let result = serde_json::json!({
                    "run_id": report.run_id,
                    "seed_kind": seed_kind,
                    "seed_value": seed_value,
                    "depth": report.depth,
                    "max_depth": report.max_depth,
                    "entities": entities,
                    "relationships": relationships,
                    "observations": observations,
                    "entities_sample": sample,
                    "correlations": correlations,
                    "pivots": report.pivots,
                    "network_scans": report.network_scans,
                    "persisted": persisted,
                });
                let status = if was_cancelled {
                    JobStatus::Cancelled
                } else {
                    JobStatus::Completed
                };
                finish_job(&mut store, &id, status, partial, Some(result), None);
            }
            Err(message) => {
                push_event(&mut store, &id, "warning", message.clone());
                finish_job(
                    &mut store,
                    &id,
                    JobStatus::Failed,
                    false,
                    None,
                    Some(ApiError {
                        code: "investigation_failed",
                        message: truncate_bytes(&message, 512),
                    }),
                );
            }
        }
    });
}

/// Deterministic fixture backends for tests (no network): the real
/// planner/transform/correlation engine runs; only contact resolves from
/// canned records under `example.test` / TEST-NET documentation space.
fn fixture_investigation(
    config: InvestigationConfig,
    seed_value: &str,
    cancel: &Arc<AtomicBool>,
) -> Result<investigate::InvestigationReport, String> {
    use investigate::{
        FixtureDnsFetcher, FixtureProfileFetcher, FixtureSearchRunner, SlowDnsFetcher,
    };
    use std::time::Duration;

    let lower = seed_value.trim().to_ascii_lowercase();
    let profile_url = format!("https://example.test/u/{lower}");
    // Every username seed resolves to one fixture account so the full
    // planner -> transform -> correlation path executes deterministically.
    let search = match config.seed_kind {
        SeedKind::Username => FixtureSearchRunner::default().with_account(
            &lower,
            "fixture-provider",
            "Fixture",
            &profile_url,
        ),
        _ => FixtureSearchRunner::default(),
    };
    let body = format!(
        "<html><head><title>{lower}</title></head><body>\
         <a href=\"https://example.test/p/{lower}\">posts</a>\
         <a href=\"https://example.org/about\">about</a></body></html>"
    );
    let profile = FixtureProfileFetcher::default().with_page(&profile_url, &profile_url, &body);
    // Cancellation E2E hook (test-only backend): this seed's DNS stage
    // blocks on a cancellable slow backend, so API cancel provably aborts
    // real in-flight transform work.
    if lower == "slowcanceluser" {
        let dns = SlowDnsFetcher {
            delay: Duration::from_secs(10),
        };
        return investigate::run_investigation_with(config, &search, &profile, &dns, cancel);
    }
    let dns = FixtureDnsFetcher::default()
        .with_records("example.test", "A", &["192.0.2.10"])
        .with_records("example.test", "AAAA", &["2001:db8::10"])
        .with_records("example.test", "MX", &["10 mail.example.test"])
        .with_records("example.test", "TXT", &["v=spf1 -all"]);
    investigate::run_investigation_with(config, &search, &profile, &dns, cancel)
}

// ---------------------------------------------------------------------------
// Search: passive entity (sync) + username provider (async job).
// ---------------------------------------------------------------------------

/// Normalize a search entity_type token to the canonical web name.
/// Returns `None` for unknown input (callers report usage, never default).
fn normalize_search_kind(text: &str) -> Option<&'static str> {
    match text.trim().to_ascii_lowercase().as_str() {
        "email" | "email_address" => Some("email"),
        "domain" => Some("domain"),
        "hostname" => Some("hostname"),
        "ip" | "ip_address" => Some("ip"),
        "asn" => Some("asn"),
        "url" => Some("url"),
        "repo" | "repository" => Some("repository"),
        "org" | "organization" => Some("organization"),
        "username" => Some("username"),
        _ => None,
    }
}

fn search_entity_kind(kind: &str) -> Option<crate::search::SearchEntityKind> {
    use crate::search::SearchEntityKind as K;
    match kind {
        "email" => Some(K::EmailAddress),
        "domain" => Some(K::Domain),
        "hostname" => Some(K::Hostname),
        "ip" => Some(K::IpAddress),
        "asn" => Some(K::Asn),
        "url" => Some(K::Url),
        "repository" => Some(K::Repository),
        "organization" => Some(K::Organization),
        "username" => Some(K::Username),
        _ => None,
    }
}

struct ValidatedUsernameSearch {
    username: String,
    deadline: Duration,
    project: String,
    categories: std::collections::BTreeSet<String>,
    providers: Option<std::collections::BTreeSet<String>>,
    exclude_providers: std::collections::BTreeSet<String>,
}

fn build_username_search(
    request: UsernameSearchRequest,
) -> Result<ValidatedUsernameSearch, ApiErrorBody> {
    let raw = request
        .value
        .as_deref()
        .or(request.username.as_deref())
        .unwrap_or("")
        .trim()
        .to_owned();
    if raw.is_empty() || raw.len() > 128 {
        return Err(ApiErrorBody::new(
            "invalid_entity",
            "username must be 1..=128 characters",
        ));
    }
    // Real canonicalization through the core (same as CLI): control
    // characters and empty values fail here with 422 before any job.
    {
        let now = now_ms() / 1000;
        if let Err(e) = crate::search::SearchEntity::username(&raw, now) {
            return Err(ApiErrorBody::new("invalid_entity", e.to_string()));
        }
    }
    let deadline = request
        .deadline_seconds
        .unwrap_or(DEFAULT_SEARCH_DEADLINE_SECS);
    if deadline == 0 || deadline > MAX_SEARCH_DEADLINE_SECS {
        return Err(ApiErrorBody::new(
            "unprocessable",
            "deadline_seconds must be 1..=120",
        ));
    }
    let project = validate_project_name(request.project.as_deref().unwrap_or("default"))?;
    // Shared planning validation (same as CLI): unknown categories/providers
    // fail here with 422 before any job exists. Selection affects the REAL
    // execution plan (never post-filters).
    let mut categories: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for entry in request.categories {
        for part in entry.split(',') {
            let trimmed = part.trim().to_owned();
            if !trimmed.is_empty() {
                categories.insert(trimmed);
            }
        }
    }
    let mut providers_set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for entry in request.providers {
        for part in entry.split(',') {
            let trimmed = part.trim().to_owned();
            if !trimmed.is_empty() {
                providers_set.insert(trimmed);
            }
        }
    }
    let providers = if providers_set.is_empty() {
        None
    } else {
        Some(providers_set)
    };
    let mut exclude_providers: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for entry in request.exclude_providers {
        for part in entry.split(',') {
            let trimmed = part.trim().to_owned();
            if !trimmed.is_empty() {
                exclude_providers.insert(trimmed);
            }
        }
    }
    // Validate against the real registry via the shared core planner.
    match crate::search::embedded_username_pack() {
        Ok(pack) => {
            if let Err(message) = crate::search::plan_username_providers(
                &pack,
                providers.as_ref(),
                &exclude_providers,
                &categories,
            ) {
                // Distinguish unknown provider vs category for stable codes.
                if message.contains("unknown provider") {
                    return Err(ApiErrorBody::new("invalid_entity", message));
                }
                return Err(ApiErrorBody::new("unprocessable", message));
            }
        }
        Err(error) => {
            return Err(ApiErrorBody::new(
                "internal",
                format!("provider registry unavailable: {error}"),
            ));
        }
    }
    Ok(ValidatedUsernameSearch {
        username: raw,
        deadline: Duration::from_secs(deadline),
        project,
        categories,
        providers,
        exclude_providers,
    })
}

fn spawn_username_search_worker(
    state: Arc<ServerState>,
    id: String,
    validated: ValidatedUsernameSearch,
) {
    let project_path = project_db_path(&state.options.data_dir, &validated.project);
    let fixture = state.options.fixture_investigation;
    thread::spawn(move || {
        let cancel = {
            let store = state.jobs.lock().expect("job store poisoned");
            store
                .jobs
                .get(&id)
                .map(|job| job.cancel.clone())
                .unwrap_or_else(|| Arc::new(AtomicBool::new(false)))
        };
        {
            let mut store = state.jobs.lock().expect("job store poisoned");
            if let Some(job) = store.jobs.get_mut(&id) {
                job.status = JobStatus::Running;
                job.started_ms = Some(now_ms());
            }
            push_event(
                &mut store,
                &id,
                "progress",
                "username search started".to_owned(),
            );
        }
        if cancel.load(Ordering::Acquire) {
            let mut store = state.jobs.lock().expect("job store poisoned");
            finish_job(&mut store, &id, JobStatus::Cancelled, false, None, None);
            return;
        }
        {
            let mut store = state.jobs.lock().expect("job store poisoned");
            push_event(&mut store, &id, "progress", "querying providers".to_owned());
        }
        // Bounded SSE progress with the real scheduled denominator: at most
        // ~21 progress events per run (one per 5% step + completion), so a
        // 2,500-vector search streams live counts without flooding the
        // 200-event buffer. The denominator is scheduled vectors, never the
        // registry total.
        let progress_hook = {
            let progress_state = state.clone();
            let progress_id = id.clone();
            let progress_step = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
            move |completed: usize, total: usize| {
                if total == 0 {
                    return;
                }
                let step = (completed.saturating_mul(20) / total) as u64;
                let last = progress_step.swap(step, Ordering::Release);
                if step != last || completed >= total {
                    if let Ok(mut store) = progress_state.jobs.lock() {
                        push_event(
                            &mut store,
                            &progress_id,
                            "progress",
                            format!("{completed}/{total} complete"),
                        );
                    }
                }
            }
        };
        let outcome: Result<crate::search::UsernameSearchReport, String> = if fixture {
            fixture_username_search(&validated.username, &cancel)
        } else {
            crate::search::execute_username_search_full(
                &validated.username,
                crate::search::DEFAULT_SEARCH_CONCURRENCY,
                crate::search::MAX_SEARCH_PER_HOST,
                validated.deadline,
                validated.providers.as_ref(),
                &validated.exclude_providers,
                &validated.categories,
                &cancel,
                Some(&progress_hook),
            )
            .map_err(|e| e.to_string())
        };
        let mut store = state.jobs.lock().expect("job store poisoned");
        match outcome {
            Ok(report) => {
                let was_cancelled = cancel.load(Ordering::Acquire);
                let persisted = match ProjectDb::open(&project_path) {
                    Ok(mut db) => match crate::search::persist_username_report(&mut db, &report) {
                        Ok(stats) => Some(serde_json::json!({
                            "entities_upserted": stats.entities_upserted,
                            "observations_added": stats.observations_added,
                            "relationships_upserted": stats.relationships_upserted,
                        })),
                        Err(error) => {
                            push_event(
                                &mut store,
                                &id,
                                "warning",
                                format!("project persistence failed: {error}"),
                            );
                            None
                        }
                    },
                    Err(error) => {
                        push_event(
                            &mut store,
                            &id,
                            "warning",
                            format!("project database unavailable: {error}"),
                        );
                        None
                    }
                };
                // Findings-first sample with the SAME semantics as the CLI:
                // category, url_kind, metadata, evidence, provenance all come
                // from the core (never reinterpreted by the API layer).
                // Semantic colors match the terminal: confirmed=green,
                // possible/blocked/rate-limited=amber, error=red,
                // negative/unavailable/unscanned=gray, urls/metadata=cyan.
                //
                // Bounded at any corpus size: confirmed/probable/possible
                // sort first, then the first 100. `results_total` carries
                // the honest total; the GUI pages from it and never renders
                // thousands of cards at once.
                fn sample_rank(status: &crate::search::SearchStatus) -> u8 {
                    match status {
                        crate::search::SearchStatus::Confirmed => 0,
                        crate::search::SearchStatus::Probable => 1,
                        crate::search::SearchStatus::Possible => 2,
                        _ => 3,
                    }
                }
                let mut ordered: Vec<&crate::search::SearchObservation> =
                    report.results.iter().collect();
                ordered.sort_by(|a, b| {
                    sample_rank(&a.status)
                        .cmp(&sample_rank(&b.status))
                        .then(a.provider_id.cmp(&b.provider_id))
                });
                let results_total = ordered.len();
                let sample: Vec<serde_json::Value> = ordered
                    .into_iter()
                    .take(100)
                    .map(|r| {
                        let profile = r.attributes.get("profile_url").cloned().unwrap_or_default();
                        let final_url = r.attributes.get("final_url").cloned().unwrap_or_default();
                        let category = r.attributes.get("category").cloned().unwrap_or_default();
                        let category_label = r.attributes.get("category_label").cloned().unwrap_or_else(|| crate::search::category_label(&category).to_owned());
                        let observed = matches!(
                            r.status,
                            crate::search::SearchStatus::Confirmed
                                | crate::search::SearchStatus::Probable
                        ) && (!final_url.is_empty() || !profile.is_empty());
                        let kind_url = if !final_url.is_empty() { final_url.clone() } else { profile.clone() };
                        let url_kind = crate::search::core_url_kind(&kind_url, &report.seed.display_value, observed && !kind_url.trim().is_empty());
                        let url_label = match url_kind {
                            "observed_profile" => "Profile",
                            "observed_resource" => "Resource",
                            "candidate" => "Candidate",
                            "provider_endpoint" => "Provider Endpoint",
                            _ => "",
                        };
                        serde_json::json!({
                            "provider": r.provider_id,
                            "status": format!("{:?}", r.status).to_ascii_lowercase(),
                            "confidence": r.confidence,
                            "confidence_label": match r.confidence { 75..=100 => "high", 40..=74 => "medium", _ => "low" },
                            "category": category,
                            "category_label": category_label,
                            "evidence": r.evidence.iter().take(8).collect::<Vec<_>>(),
                            "profile_url": profile,
                            "final_url": final_url,
                            "url": kind_url,
                            "url_kind": url_kind,
                            "url_label": url_label,
                            "url_observed": observed,
                            "metadata": r.attributes,
                            "provenance": {
                                "provider_id": r.provider_id,
                                "provider_version": r.provider_version,
                                "task_id": r.task_id,
                                "input_entity_id": r.input_entity_id,
                                "contact_class": r.contact_class,
                                "module": format!("search.provider.{}", r.provider_id),
                            },
                            "observed_at": r.timestamp,
                            "started_at": report.started_at,
                        })
                    })
                    .collect();
                // Per-category coverage from the real plan + real results.
                let by_category = {
                    // For scheduled-but-uncompleted providers the pack lookup
                    // fills gaps; here we derive from observations only (the
                    // full plan coverage is in `coverage_by_category` when the
                    // effective set is known — the sample stays honest).
                    let mut counts: std::collections::BTreeMap<String, usize> =
                        std::collections::BTreeMap::new();
                    for item in &sample {
                        if let Some(category) = item.get("category").and_then(|v| v.as_str()) {
                            if !category.is_empty() {
                                *counts.entry(category.to_owned()).or_default() += 1;
                            }
                        }
                    }
                    counts
                        .into_iter()
                        .map(|(category, complete)| {
                            serde_json::json!({
                                "category": category,
                                "label": crate::search::category_label(&category),
                                "complete": complete,
                            })
                        })
                        .collect::<Vec<_>>()
                };
                // Denominators shared with Core/CLI/JSONL: scheduled is the
                // effective plan for this run; configured/enabled/usable
                // describe the registry. All from real data.
                let registry = crate::search::embedded_username_pack()
                    .map(|pack| crate::search::username_registry_counts(&pack))
                    .unwrap_or(crate::search::RegistryCounts {
                        providers_configured: 0,
                        vectors_registered: 0,
                        enabled: 0,
                        usable: 0,
                        unavailable: 0,
                        disabled: 0,
                    });
                let coverage = serde_json::json!({
                    "requested": report.accounting.providers_requested,
                    "scheduled": report.accounting.scheduled(),
                    "remaining": report.accounting.remaining(),
                    "completed": report.accounting.providers_completed,
                    "skipped": report.accounting.skipped,
                    "cancelled": report.accounting.cancelled,
                    "unscanned": report.accounting.unscanned,
                    "truncated": report.accounting.truncated,
                    "configured": registry.vectors_registered,
                    "enabled": registry.enabled,
                    "usable": registry.usable,
                    "by_category": by_category,
                });
                let result = serde_json::json!({
                    "run_id": report.run_id,
                    "seed": report.seed.display_value,
                    "seed_canonical": report.seed.canonical_value,
                    "provider_pack": report.provider_pack_version,
                    "categories": validated.categories.iter().collect::<Vec<_>>(),
                    "coverage": coverage,
                    "results": sample.len(),
                    "results_total": results_total,
                    "results_truncated": results_total > sample.len(),
                    "results_sample": sample,
                    "network_scans": report.network_scans,
                    "deadline_seconds": validated.deadline.as_secs(),
                    "persisted": persisted,
                });
                let status = if was_cancelled {
                    JobStatus::Cancelled
                } else {
                    JobStatus::Completed
                };
                let partial = was_cancelled && !report.results.is_empty();
                finish_job(&mut store, &id, status, partial, Some(result), None);
            }
            Err(message) => {
                push_event(&mut store, &id, "warning", message.clone());
                finish_job(
                    &mut store,
                    &id,
                    JobStatus::Failed,
                    false,
                    None,
                    Some(ApiError {
                        code: "search_failed",
                        message: truncate_bytes(&message, 512),
                    }),
                );
            }
        }
    });
}

/// Deterministic fixture username search (test mode only, no network).
fn fixture_username_search(
    username: &str,
    cancel: &Arc<AtomicBool>,
) -> Result<crate::search::UsernameSearchReport, String> {
    use crate::search::{
        ContactClass, SearchAccounting, SearchEntity, SearchObservation, SearchStatus,
        UsernameSearchReport,
    };
    if cancel.load(Ordering::Acquire) {
        return Err("cancelled".to_owned());
    }
    // Cancellation E2E hook parity with investigations.
    if username.trim().eq_ignore_ascii_case("slowcanceluser") {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if cancel.load(Ordering::Acquire) {
                return Err("cancelled".to_owned());
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
    let now = now_ms() / 1000;
    let lower = username.trim().to_ascii_lowercase();
    let seed = SearchEntity::username(&lower, now).map_err(|e| e.to_string())?;
    let profile_url = format!("https://example.test/u/{lower}");
    let obs = SearchObservation {
        provider_id: "fixture-provider".to_owned(),
        provider_version: "1".to_owned(),
        task_id: crate::assets::public_entity_id(
            "search_task",
            &format!("fixture-provider:{}:search", seed.id),
        ),
        input_entity_id: seed.id.clone(),
        contact_class: ContactClass::PublicHttp,
        status: SearchStatus::Confirmed,
        confidence: 90,
        timestamp: now,
        evidence: vec!["fixture account observed".to_owned()],
        attributes: [
            ("profile_url".to_owned(), profile_url.clone()),
            ("final_url".to_owned(), profile_url.clone()),
        ]
        .into_iter()
        .collect(),
    };
    let mut graph = crate::graph::ScanGraph::default();
    graph.upsert_entity(
        seed.id.clone(),
        crate::graph::EntityKind::Username,
        seed.display_value.clone(),
        std::collections::BTreeMap::from([(
            "canonical_value".to_owned(),
            seed.canonical_value.clone(),
        )]),
        &crate::graph::EntityProvenance {
            scan_plan_id: "search".to_owned(),
            module: "search.seed".to_owned(),
            task_id: None,
            target: Some(seed.id.clone()),
            timestamp: now,
            reason: Some("operator-supplied username seed".to_owned()),
            rule_id: None,
        },
    );
    crate::search::add_username_observation_to_graph(&mut graph, &seed, &obs);
    Ok(UsernameSearchReport {
        schema_version: 1,
        run_id: crate::assets::public_entity_id("search_run", &format!("{}:fixture", seed.id)),
        seed,
        provider_pack_version: "fixture".to_owned(),
        accounting: SearchAccounting {
            providers_requested: 1,
            providers_completed: 1,
            skipped: 0,
            cancelled: 0,
            unscanned: 0,
            counts: [(SearchStatus::Confirmed, 1)].into_iter().collect(),
            truncated: false,
        },
        results: vec![obs],
        graph,
        network_scans: 0,
        started_at: now,
        completed_at: now,
    })
}

// ---------------------------------------------------------------------------
// Route handlers.
// ---------------------------------------------------------------------------

fn handle_health(stream: &mut TcpStream, rid: u64) {
    json_response(
        stream,
        rid,
        200,
        &HealthResponse {
            status: "ok",
            api_version: API_VERSION,
            tool_version: TOOL_VERSION,
        },
    );
}

fn configured_capability(name: &str) -> bool {
    name == "search_username"
        || name.starts_with("username_providers")
        || name.starts_with("investigation")
        || name == "search_project_db"
        || name == "fingerprints"
}

fn handle_capabilities(stream: &mut TcpStream, rid: u64) {
    let probed = capabilities::probe();
    let mut capabilities: Vec<CapabilityDto> = probed
        .entries
        .iter()
        .map(|entry| {
            let state = if !entry.available {
                "unavailable"
            } else if configured_capability(&entry.name) {
                "configured"
            } else {
                "available"
            };
            CapabilityDto {
                name: entry.name.clone(),
                state,
                // Capability detail is operator-safe diagnostics (no
                // paths, tokens, or environment); never secrets.
                detail: entry.detail.clone(),
            }
        })
        .collect();
    capabilities.sort_by(|a, b| a.name.cmp(&b.name));
    json_response(
        stream,
        rid,
        200,
        &CapabilitiesResponse {
            api_version: API_VERSION,
            tool_version: TOOL_VERSION,
            capabilities,
        },
    );
}

fn ensure_data_dir(state: &ServerState) -> Result<(), ApiErrorBody> {
    std::fs::create_dir_all(&state.options.data_dir)
        .map_err(|_| ApiErrorBody::new("internal", "project storage unavailable"))?;
    Ok(())
}

fn handle_projects_list(
    state: &Arc<ServerState>,
    stream: &mut TcpStream,
    rid: u64,
    query: &BTreeMap<String, String>,
) {
    if let Err(error) = ensure_data_dir(state) {
        error_response(stream, rid, &error);
        return;
    }
    let (limit, offset) = match parse_pagination(query) {
        Ok(page) => page,
        Err(error) => {
            error_response(stream, rid, &error);
            return;
        }
    };
    let mut names: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&state.options.data_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "db") {
                if let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) {
                    if validate_project_name(stem).is_ok() {
                        names.push(stem.to_owned());
                    }
                }
            }
        }
    }
    names.sort();
    names.dedup();
    let total = names.len();
    let projects: Vec<serde_json::Value> = names
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|name| serde_json::json!({"name": name}))
        .collect();
    json_response(
        stream,
        rid,
        200,
        &serde_json::json!({"projects": projects, "total": total}),
    );
}

fn handle_project_create(state: &Arc<ServerState>, stream: &mut TcpStream, rid: u64, body: &[u8]) {
    let request: ProjectCreateRequest = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(_) => {
            error_response(
                stream,
                rid,
                &ApiErrorBody::new("invalid_json", "request body must be valid JSON"),
            );
            return;
        }
    };
    let name = match request.name.as_deref() {
        Some(name) => name,
        None => {
            error_response(
                stream,
                rid,
                &ApiErrorBody::new("bad_request", "name is required"),
            );
            return;
        }
    };
    let name = match validate_project_name(name) {
        Ok(name) => name,
        Err(error) => {
            error_response(stream, rid, &error);
            return;
        }
    };
    if let Err(error) = ensure_data_dir(state) {
        error_response(stream, rid, &error);
        return;
    }
    let path = project_db_path(&state.options.data_dir, &name);
    if path.exists() {
        error_response(
            stream,
            rid,
            &ApiErrorBody::new("conflict", "project already exists"),
        );
        return;
    }
    match ProjectDb::open(&path) {
        Ok(_) => json_response(stream, rid, 201, &serde_json::json!({"name": name})),
        Err(error) => {
            eprintln!("[rxscan-web] rid={rid:016x} project create failed: {error}");
            error_response(
                stream,
                rid,
                &ApiErrorBody::new("internal", "could not create project"),
            );
        }
    }
}

fn open_project(state: &Arc<ServerState>, name: &str) -> Result<(String, ProjectDb), ApiErrorBody> {
    let name = validate_project_name(name)?;
    ensure_data_dir(state)?;
    let path = project_db_path(&state.options.data_dir, &name);
    if !path.exists() {
        return Err(ApiErrorBody::new("not_found", "unknown project"));
    }
    match ProjectDb::open(&path) {
        Ok(db) => Ok((name, db)),
        Err(error) => {
            eprintln!("[rxscan-web] project open failed: {error}");
            Err(ApiErrorBody::new(
                "internal",
                "project database unavailable",
            ))
        }
    }
}

fn handle_project_get(state: &Arc<ServerState>, stream: &mut TcpStream, rid: u64, name: &str) {
    let (name, db) = match open_project(state, name) {
        Ok(opened) => opened,
        Err(error) => {
            error_response(stream, rid, &error);
            return;
        }
    };
    let runs = db.scan_ids().unwrap_or_default();
    let (entities, observations, relationships, run_count) = db.counts().unwrap_or_default();
    let latest = runs.last().cloned().unwrap_or_default();
    json_response(
        stream,
        rid,
        200,
        &serde_json::json!({
            "name": name,
            "runs": run_count,
            "run_ids": runs.iter().take(100).collect::<Vec<_>>(),
            "latest_run": latest,
            "entities": entities,
            "observations": observations,
            "relationships": relationships,
        }),
    );
}

fn handle_project_entities(
    state: &Arc<ServerState>,
    stream: &mut TcpStream,
    rid: u64,
    name: &str,
    query: &BTreeMap<String, String>,
) {
    let (limit, offset) = match parse_pagination(query) {
        Ok(page) => page,
        Err(error) => {
            error_response(stream, rid, &error);
            return;
        }
    };
    let kind = query
        .get("kind")
        .map(String::as_str)
        .filter(|kind| !kind.is_empty());
    let (_, db) = match open_project(state, name) {
        Ok(opened) => opened,
        Err(error) => {
            error_response(stream, rid, &error);
            return;
        }
    };
    match db.entities_page(kind, limit, offset) {
        Ok(rows) => {
            let entities: Vec<EntityDto> = rows
                .into_iter()
                .map(|row| EntityDto {
                    entity_id: row.entity_id,
                    kind: row.kind,
                    label: row.label,
                    first_seen_scan: row.first_seen_scan,
                    last_seen_scan: row.last_seen_scan,
                    first_seen_ms: row.first_seen_ms,
                    last_seen_ms: row.last_seen_ms,
                    observation_count: row.observation_count,
                })
                .collect();
            json_response(stream, rid, 200, &serde_json::json!({"entities": entities}));
        }
        Err(error) => {
            eprintln!("[rxscan-web] rid={rid:016x} entities failed: {error}");
            error_response(
                stream,
                rid,
                &ApiErrorBody::new("internal", "entities unavailable"),
            );
        }
    }
}

fn handle_project_findings(
    state: &Arc<ServerState>,
    stream: &mut TcpStream,
    rid: u64,
    name: &str,
    query: &BTreeMap<String, String>,
) {
    let (limit, offset) = match parse_pagination(query) {
        Ok(page) => page,
        Err(error) => {
            error_response(stream, rid, &error);
            return;
        }
    };
    let (_, db) = match open_project(state, name) {
        Ok(opened) => opened,
        Err(error) => {
            error_response(stream, rid, &error);
            return;
        }
    };
    match db.observations_page(limit, offset) {
        Ok(rows) => {
            let findings: Vec<FindingDto> = rows
                .into_iter()
                .map(|row| FindingDto {
                    entity_id: row.entity_id,
                    kind: row.kind,
                    label: row.label,
                    confidence: row.confidence,
                    // Evidence excerpts are retention-bounded by the
                    // project layer; the GUI renders them as text.
                    evidence_excerpt: row.evidence_excerpt,
                    module: row.module,
                    task_id: row.task_id,
                    scan_run: row.scan_run,
                    timestamp_ms: row.timestamp_ms,
                })
                .collect();
            json_response(stream, rid, 200, &serde_json::json!({"findings": findings}));
        }
        Err(error) => {
            eprintln!("[rxscan-web] rid={rid:016x} findings failed: {error}");
            error_response(
                stream,
                rid,
                &ApiErrorBody::new("internal", "findings unavailable"),
            );
        }
    }
}

fn handle_project_graph(
    state: &Arc<ServerState>,
    stream: &mut TcpStream,
    rid: u64,
    name: &str,
    query: &BTreeMap<String, String>,
) {
    let seed = query.get("seed").map(String::as_str).unwrap_or("").trim();
    if seed.is_empty() || seed.len() > 512 {
        error_response(
            stream,
            rid,
            &ApiErrorBody::new("bad_request", "graph requires a seed entity id"),
        );
        return;
    }
    let depth: usize = match query
        .get("depth")
        .map(String::as_str)
        .unwrap_or("2")
        .parse()
    {
        Ok(depth) => depth,
        Err(_) => {
            error_response(
                stream,
                rid,
                &ApiErrorBody::new("bad_request", "depth must be an integer"),
            );
            return;
        }
    };
    if depth > INVEST_MAX_DEPTH as usize {
        error_response(
            stream,
            rid,
            &ApiErrorBody::new(
                "unprocessable",
                format!("depth must be 0..={INVEST_MAX_DEPTH}"),
            ),
        );
        return;
    }
    let limit: usize = query
        .get("limit")
        .map(String::as_str)
        .unwrap_or("100")
        .parse()
        .unwrap_or(0);
    if limit == 0 || limit > MAX_GRAPH_NODES {
        error_response(
            stream,
            rid,
            &ApiErrorBody::new(
                "bad_request",
                format!("limit must be 1..={MAX_GRAPH_NODES}"),
            ),
        );
        return;
    }
    let (_, db) = match open_project(state, name) {
        Ok(opened) => opened,
        Err(error) => {
            error_response(stream, rid, &error);
            return;
        }
    };
    // Bounded breadth-first expansion from the seed over stored
    // relationships; the server walks the graph, the GUI only renders it.
    let mut nodes: Vec<GraphNodeDto> = Vec::new();
    let mut edges: Vec<GraphEdgeDto> = Vec::new();
    let mut visited: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut frontier: Vec<(String, usize)> = vec![(seed.to_owned(), 0)];
    visited.insert(seed.to_owned());
    while let Some((current, current_depth)) = frontier.pop() {
        if nodes.len() >= limit {
            break;
        }
        let row = match db.entity(&current) {
            Ok(row) => row,
            Err(_) => continue,
        };
        if let Some(row) = row {
            nodes.push(GraphNodeDto {
                id: row.entity_id,
                kind: row.kind,
                label: row.label,
                first_seen_ms: row.first_seen_ms,
                last_seen_ms: row.last_seen_ms,
                observation_count: row.observation_count,
            });
        }
        if current_depth >= depth {
            continue;
        }
        let mut adjacent = db.edges_from(&current).unwrap_or_default();
        adjacent.extend(db.edges_to(&current).unwrap_or_default());
        for edge in adjacent {
            if edges.len() >= limit * 2 {
                break;
            }
            let neighbor = if edge.from_id == current {
                edge.to_id.clone()
            } else {
                edge.from_id.clone()
            };
            edges.push(GraphEdgeDto {
                from: edge.from_id.clone(),
                to: edge.to_id.clone(),
                relation: edge.relation.clone(),
                confidence: edge.confidence,
                scan_run: edge.scan_run.clone(),
                module: edge.module.clone(),
                evidence: truncate_bytes(&edge.evidence, 512),
            });
            if visited.insert(neighbor.clone()) && nodes.len() + frontier.len() < limit {
                frontier.push((neighbor, current_depth + 1));
            }
        }
    }
    // Deduplicate edges (from/to pairs appear from both directions).
    edges.sort_by(|a, b| (&a.from, &a.to, &a.relation).cmp(&(&b.from, &b.to, &b.relation)));
    edges.dedup_by(|a, b| a.from == b.from && a.to == b.to && a.relation == b.relation);
    edges.truncate(limit * 2);
    json_response(
        stream,
        rid,
        200,
        &serde_json::json!({"nodes": nodes, "edges": edges}),
    );
}

fn handle_project_timeline(
    state: &Arc<ServerState>,
    stream: &mut TcpStream,
    rid: u64,
    name: &str,
    query: &BTreeMap<String, String>,
) {
    let (limit, offset) = match parse_pagination(query) {
        Ok(page) => page,
        Err(error) => {
            error_response(stream, rid, &error);
            return;
        }
    };
    let (_, db) = match open_project(state, name) {
        Ok(opened) => opened,
        Err(error) => {
            error_response(stream, rid, &error);
            return;
        }
    };
    let latest = db.scan_ids().unwrap_or_default().pop().unwrap_or_default();
    match db.observations_page(limit, offset) {
        Ok(rows) => {
            let events: Vec<TimelineEventDto> = rows
                .into_iter()
                .map(|row| {
                    let current = !latest.is_empty() && row.scan_run == latest;
                    TimelineEventDto {
                        timestamp_ms: row.timestamp_ms,
                        entity_id: row.entity_id,
                        kind: row.kind,
                        label: row.label,
                        scan_run: row.scan_run,
                        module: row.module,
                        current,
                    }
                })
                .collect();
            json_response(stream, rid, 200, &serde_json::json!({"events": events}));
        }
        Err(error) => {
            eprintln!("[rxscan-web] rid={rid:016x} timeline failed: {error}");
            error_response(
                stream,
                rid,
                &ApiErrorBody::new("internal", "timeline unavailable"),
            );
        }
    }
}

fn handle_scan_create(state: &Arc<ServerState>, stream: &mut TcpStream, rid: u64, body: &[u8]) {
    let request: ScanRequest = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(_) => {
            error_response(
                stream,
                rid,
                &ApiErrorBody::new("invalid_json", "request body must be valid JSON"),
            );
            return;
        }
    };
    let validated = match build_scan_cli(request) {
        Ok(validated) => validated,
        Err(error) => {
            error_response(stream, rid, &error);
            return;
        }
    };
    let label = validated.target_label.clone();
    let mut store = state.jobs.lock().expect("job store poisoned");
    if store.running_count() >= MAX_RUNNING_JOBS {
        error_response(
            stream,
            rid,
            &ApiErrorBody::new("rate_limited", "too many running jobs; retry later"),
        );
        return;
    }
    store.evict_oldest_terminal();
    let id = new_job_id(&mut store, "scan", &label);
    store.jobs.insert(
        id.clone(),
        JobRecord {
            id: id.clone(),
            kind: JobKind::Scan,
            status: JobStatus::Queued,
            partial: false,
            progress: "queued".to_owned(),
            project: validated.project.clone(),
            label,
            cancel: Arc::new(AtomicBool::new(false)),
            events: Vec::new(),
            event_seq: 0,
            result: None,
            error: None,
            created_ms: now_ms(),
            started_ms: None,
            finished_ms: None,
        },
    );
    push_event(&mut store, &id, "job_started", "scan queued".to_owned());
    drop(store);
    spawn_scan_worker(state.clone(), id.clone(), validated);
    json_response(
        stream,
        rid,
        202,
        &serde_json::json!({"job_id": id, "status": "queued"}),
    );
}

fn handle_investigation_create(
    state: &Arc<ServerState>,
    stream: &mut TcpStream,
    rid: u64,
    body: &[u8],
) {
    let request: InvestigationRequest = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(_) => {
            error_response(
                stream,
                rid,
                &ApiErrorBody::new("invalid_json", "request body must be valid JSON"),
            );
            return;
        }
    };
    let validated = match build_investigation_config(request) {
        Ok(validated) => validated,
        Err(error) => {
            error_response(stream, rid, &error);
            return;
        }
    };
    let label = validated.config.seed_value.clone();
    let mut store = state.jobs.lock().expect("job store poisoned");
    if store.running_count() >= MAX_RUNNING_JOBS {
        error_response(
            stream,
            rid,
            &ApiErrorBody::new("rate_limited", "too many running jobs; retry later"),
        );
        return;
    }
    store.evict_oldest_terminal();
    let id = new_job_id(&mut store, "investigation", &label);
    store.jobs.insert(
        id.clone(),
        JobRecord {
            id: id.clone(),
            kind: JobKind::Investigation,
            status: JobStatus::Queued,
            partial: false,
            progress: "queued".to_owned(),
            project: validated.project.clone(),
            label,
            cancel: Arc::new(AtomicBool::new(false)),
            events: Vec::new(),
            event_seq: 0,
            result: None,
            error: None,
            created_ms: now_ms(),
            started_ms: None,
            finished_ms: None,
        },
    );
    push_event(
        &mut store,
        &id,
        "job_started",
        "investigation queued".to_owned(),
    );
    drop(store);
    spawn_investigation_worker(state.clone(), id.clone(), validated);
    json_response(
        stream,
        rid,
        202,
        &serde_json::json!({"job_id": id, "status": "queued"}),
    );
}

/// Synchronous passive entity search: zero network, instant.
///
/// Validates through the real core constructors (`SearchEntity::*`);
/// persists into the existing project DB when `project` is given (same
/// store the GUI project browser reads, no second database).
fn handle_search_sync(state: &Arc<ServerState>, stream: &mut TcpStream, rid: u64, body: &[u8]) {
    let request: EntitySearchRequest = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(_) => {
            error_response(
                stream,
                rid,
                &ApiErrorBody::new("invalid_json", "request body must be valid JSON"),
            );
            return;
        }
    };
    let kind_raw = request.entity_type.as_deref().unwrap_or("").trim();
    let Some(kind_name) = normalize_search_kind(kind_raw) else {
        error_response(
            stream,
            rid,
            &ApiErrorBody::new(
                "invalid_entity",
                "entity_type must be one of username, email, domain, hostname, ip, asn, url, repository, organization",
            ),
        );
        return;
    };
    // Username provider search is network-backed and cancellable: it runs
    // as a job so progress streams over SSE. This endpoint stays instant
    // and local-only; direct username callers to the job endpoint.
    if kind_name == "username" {
        error_response(
            stream,
            rid,
            &ApiErrorBody::new(
                "unprocessable",
                "username provider search runs at POST /api/v1/username-searches (async job); this endpoint is local-only",
            ),
        );
        return;
    }
    let value = request.value.as_deref().unwrap_or("").trim().to_owned();
    if value.is_empty() || value.len() > 512 {
        error_response(
            stream,
            rid,
            &ApiErrorBody::new("invalid_entity", "value must be 1..=512 characters"),
        );
        return;
    }
    let Some(kind) = search_entity_kind(kind_name) else {
        error_response(
            stream,
            rid,
            &ApiErrorBody::new("invalid_entity", "unsupported entity type"),
        );
        return;
    };
    let report = match crate::entity_search::execute_entity_search(kind, &value) {
        Ok(report) => report,
        Err(error) => {
            error_response(
                stream,
                rid,
                &ApiErrorBody::new("invalid_entity", error.to_string()),
            );
            return;
        }
    };
    let project_name = request.project.as_deref().unwrap_or("").trim();
    let persisted = if project_name.is_empty() {
        None
    } else {
        let name = match validate_project_name(project_name) {
            Ok(name) => name,
            Err(error) => {
                error_response(stream, rid, &error);
                return;
            }
        };
        if let Err(error) = ensure_data_dir(state) {
            error_response(stream, rid, &error);
            return;
        }
        let path = project_db_path(&state.options.data_dir, &name);
        match ProjectDb::open(&path) {
            Ok(mut db) => match crate::entity_search::persist_entity_report(&mut db, &report) {
                Ok(stats) => Some(serde_json::json!({
                    "project": name,
                    "entities_upserted": stats.entities_upserted,
                    "observations_added": stats.observations_added,
                    "relationships_upserted": stats.relationships_upserted,
                })),
                Err(error) => {
                    eprintln!("[rxscan-web] rid={rid:016x} entity search persist failed: {error}");
                    error_response(
                        stream,
                        rid,
                        &ApiErrorBody::new("internal", "could not persist search report"),
                    );
                    return;
                }
            },
            Err(error) => {
                eprintln!("[rxscan-web] rid={rid:016x} entity search db failed: {error}");
                error_response(
                    stream,
                    rid,
                    &ApiErrorBody::new("internal", "project database unavailable"),
                );
                return;
            }
        }
    };
    let entities: Vec<serde_json::Value> = report
        .graph
        .entities
        .values()
        .take(100)
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "kind": format!("{:?}", e.kind).to_ascii_lowercase(),
                "label": e.label,
            })
        })
        .collect();
    let observations: Vec<serde_json::Value> = report
        .observations
        .iter()
        .take(100)
        .map(|o| {
            serde_json::json!({
                "provider": o.provider_id,
                "status": format!("{:?}", o.status).to_ascii_lowercase(),
                "confidence": o.confidence,
                "evidence": o.evidence,
                "attributes": o.attributes,
            })
        })
        .collect();
    let relationships: Vec<serde_json::Value> = report
        .graph
        .edges
        .iter()
        .take(100)
        .map(|e| {
            serde_json::json!({
                "from": e.from,
                "to": e.to,
                "relation": format!("{:?}", e.relation),
                "confidence": e.confidence,
            })
        })
        .collect();
    json_response(
        stream,
        rid,
        200,
        &serde_json::json!({
            "run_id": report.run_id,
            "seed_kind": kind_name,
            "seed_display": report.seed.display_value,
            "seed_canonical": report.seed.canonical_value,
            "seed_id": report.seed.id,
            "contact_class": "passive_public",
            "network_scans": 0,
            "entities": entities,
            "observations": observations,
            "relationships": relationships,
            "persisted": persisted,
        }),
    );
}

/// Category discovery from the real registry (same as CLI `search categories`).
fn handle_username_categories(stream: &mut TcpStream, rid: u64) {
    let pack = match crate::search::embedded_username_pack() {
        Ok(pack) => pack,
        Err(error) => {
            error_response(
                stream,
                rid,
                &ApiErrorBody::new("internal", format!("registry unavailable: {error}")),
            );
            return;
        }
    };
    let mut categories = crate::search::username_category_summary(&pack);
    // Explicit vector counts per category (1:1 with providers today).
    let categories = categories
        .drain(..)
        .map(|entry| {
            serde_json::json!({
                "category": entry.category,
                "label": entry.label,
                "configured": entry.configured,
                "vectors": entry.configured,
                "usable": entry.usable,
                "unavailable": entry.unavailable,
                "disabled": entry.disabled,
            })
        })
        .collect::<Vec<_>>();
    let registry = crate::search::username_registry_counts(&pack);
    json_response(
        stream,
        rid,
        200,
        &serde_json::json!({
            "pack_version": pack.pack_version,
            "providers": registry.providers_configured,
            "vectors": registry.vectors_registered,
            "categories": categories,
        }),
    );
}

/// Provider discovery from the real registry (same as CLI `search providers`).
fn handle_username_providers(stream: &mut TcpStream, rid: u64, query: &BTreeMap<String, String>) {
    let pack = match crate::search::embedded_username_pack() {
        Ok(pack) => pack,
        Err(error) => {
            error_response(
                stream,
                rid,
                &ApiErrorBody::new("internal", format!("registry unavailable: {error}")),
            );
            return;
        }
    };
    // Optional `?category=` filter (repeatable via comma). Unknown categories
    // are rejected with the known set (same as CLI). `?state=` filters by
    // discovery state (`usable`/`unavailable`/`disabled`); `?q=` matches a
    // case-insensitive id/name substring. `?limit=`/`?offset=` paginate so
    // the GUI never has to render thousands of rows at once — pass no limit
    // for the full registry (backwards compatible).
    let mut filter_categories: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    if let Some(raw) = query.get("category") {
        for part in raw.split(',') {
            let trimmed = part.trim().to_owned();
            if !trimmed.is_empty() {
                filter_categories.insert(trimmed);
            }
        }
    }
    let filter_state = query
        .get("state")
        .map(|raw| raw.trim().to_ascii_lowercase())
        .filter(|state| !state.is_empty());
    if let Some(state) = filter_state.as_deref() {
        if !matches!(state, "usable" | "unavailable" | "disabled") {
            error_response(
                stream,
                rid,
                &ApiErrorBody::new(
                    "unprocessable",
                    "state must be one of usable, unavailable, disabled",
                ),
            );
            return;
        }
    }
    let filter_query = query
        .get("q")
        .map(|raw| raw.trim().to_ascii_lowercase())
        .filter(|q| !q.is_empty());
    // Bounded pagination: defaults to the full registry for backwards
    // compatibility; the GUI always passes an explicit small limit.
    let limit: usize = match query.get("limit") {
        None => usize::MAX,
        Some(raw) => match raw.trim().parse::<usize>() {
            Ok(limit) if (1..=5000).contains(&limit) => limit,
            _ => {
                error_response(
                    stream,
                    rid,
                    &ApiErrorBody::new("bad_request", "limit must be 1..=5000"),
                );
                return;
            }
        },
    };
    let offset: usize = match query.get("offset") {
        None => 0,
        Some(raw) => match raw.trim().parse::<usize>() {
            Ok(offset) => offset,
            _ => {
                error_response(
                    stream,
                    rid,
                    &ApiErrorBody::new("bad_request", "offset must be a non-negative integer"),
                );
                return;
            }
        },
    };
    if !filter_categories.is_empty() {
        let known: std::collections::BTreeSet<&str> = crate::search::known_username_categories()
            .into_iter()
            .collect();
        let unknown: Vec<String> = filter_categories
            .iter()
            .filter(|c| !known.contains(c.as_str()))
            .cloned()
            .collect();
        if !unknown.is_empty() {
            error_response(
                stream,
                rid,
                &ApiErrorBody::new(
                    "unprocessable",
                    format!("unknown category: {}", unknown.join(", ")),
                ),
            );
            return;
        }
    }
    let filtered: Vec<&crate::search::UsernameProviderDefinition> = pack
        .providers
        .iter()
        .filter(|definition| {
            (filter_categories.is_empty() || filter_categories.contains(&definition.category))
                && filter_state
                    .as_deref()
                    .is_none_or(|state| crate::search::provider_state(definition) == state)
                && filter_query.as_deref().is_none_or(|q| {
                    definition.metadata.id.to_ascii_lowercase().contains(q)
                        || definition.platform.to_ascii_lowercase().contains(q)
                })
        })
        .collect();
    let total = filtered.len();
    // Each provider registers exactly one vector today; report both so the
    // GUI can show "N vectors" per provider without double-counting sites.
    let providers: Vec<serde_json::Value> = filtered
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|definition| {
            serde_json::json!({
                "id": definition.metadata.id,
                "name": definition.platform,
                "category": definition.category,
                "category_label": crate::search::category_label(&definition.category),
                "state": crate::search::provider_state(definition),
                "type": "profile",
                "vectors": 1,
                "health_state": definition.health_state.as_str(),
                "verified_at": definition.verified_at,
            })
        })
        .collect();
    let registry = crate::search::username_registry_counts(&pack);
    json_response(
        stream,
        rid,
        200,
        &serde_json::json!({
            "pack_version": pack.pack_version,
            "total_providers": pack.providers.len(),
            "total": total,
            "limit": if limit == usize::MAX { serde_json::Value::Null } else { serde_json::json!(limit) },
            "offset": offset,
            "active_providers": providers.len(),
            "providers_count": registry.providers_configured,
            "vectors_count": registry.vectors_registered,
            "providers": providers,
        }),
    );
}

fn handle_username_search_create(
    state: &Arc<ServerState>,
    stream: &mut TcpStream,
    rid: u64,
    body: &[u8],
) {
    let request: UsernameSearchRequest = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(_) => {
            error_response(
                stream,
                rid,
                &ApiErrorBody::new("invalid_json", "request body must be valid JSON"),
            );
            return;
        }
    };
    let validated = match build_username_search(request) {
        Ok(validated) => validated,
        Err(error) => {
            error_response(stream, rid, &error);
            return;
        }
    };
    if let Err(error) = ensure_data_dir(state) {
        error_response(stream, rid, &error);
        return;
    }
    let label = validated.username.clone();
    let mut store = state.jobs.lock().expect("job store poisoned");
    if store.running_count() >= MAX_RUNNING_JOBS {
        error_response(
            stream,
            rid,
            &ApiErrorBody::new("rate_limited", "too many running jobs; retry later"),
        );
        return;
    }
    store.evict_oldest_terminal();
    let id = new_job_id(&mut store, "username_search", &label);
    store.jobs.insert(
        id.clone(),
        JobRecord {
            id: id.clone(),
            kind: JobKind::UsernameSearch,
            status: JobStatus::Queued,
            partial: false,
            progress: "queued".to_owned(),
            project: validated.project.clone(),
            label,
            cancel: Arc::new(AtomicBool::new(false)),
            events: Vec::new(),
            event_seq: 0,
            result: None,
            error: None,
            created_ms: now_ms(),
            started_ms: None,
            finished_ms: None,
        },
    );
    push_event(
        &mut store,
        &id,
        "job_started",
        "username search queued".to_owned(),
    );
    drop(store);
    spawn_username_search_worker(state.clone(), id.clone(), validated);
    json_response(
        stream,
        rid,
        202,
        &serde_json::json!({"job_id": id, "status": "queued"}),
    );
}

fn job_id_valid(id: &str) -> bool {
    id.len() == 20 && id.starts_with("job_") && id[4..].chars().all(|c| c.is_ascii_hexdigit())
}

fn handle_job_get(
    state: &Arc<ServerState>,
    stream: &mut TcpStream,
    rid: u64,
    id: &str,
    expected_kind: Option<JobKind>,
) {
    if !job_id_valid(id) {
        error_response(stream, rid, &ApiErrorBody::new("not_found", "unknown job"));
        return;
    }
    let store = state.jobs.lock().expect("job store poisoned");
    match store.jobs.get(id) {
        None => error_response(stream, rid, &ApiErrorBody::new("not_found", "unknown job")),
        Some(job) => {
            if expected_kind.is_some_and(|kind| kind != job.kind) {
                error_response(stream, rid, &ApiErrorBody::new("not_found", "unknown job"));
                return;
            }
            let body = job_summary(job, true);
            json_response(stream, rid, 200, &body);
        }
    }
}

fn handle_jobs_list(
    state: &Arc<ServerState>,
    stream: &mut TcpStream,
    rid: u64,
    query: &BTreeMap<String, String>,
) {
    let (limit, offset) = match parse_pagination(query) {
        Ok(page) => page,
        Err(error) => {
            error_response(stream, rid, &error);
            return;
        }
    };
    let store = state.jobs.lock().expect("job store poisoned");
    let mut jobs: Vec<&JobRecord> = store.jobs.values().collect();
    jobs.sort_by_key(|job| std::cmp::Reverse(job.created_ms));
    let total = jobs.len();
    let items: Vec<serde_json::Value> = jobs
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|job| job_summary(job, false))
        .collect();
    json_response(
        stream,
        rid,
        200,
        &serde_json::json!({"jobs": items, "total": total}),
    );
}

fn handle_job_cancel(state: &Arc<ServerState>, stream: &mut TcpStream, rid: u64, id: &str) {
    if !job_id_valid(id) {
        error_response(stream, rid, &ApiErrorBody::new("not_found", "unknown job"));
        return;
    }
    let store = state.jobs.lock().expect("job store poisoned");
    match store.jobs.get(id) {
        None => error_response(stream, rid, &ApiErrorBody::new("not_found", "unknown job")),
        Some(job) => {
            if !matches!(job.status, JobStatus::Queued | JobStatus::Running) {
                error_response(
                    stream,
                    rid,
                    &ApiErrorBody::new("conflict", "job is already terminal"),
                );
                return;
            }
            job.cancel.store(true, Ordering::Release);
            let job_id = job.id.clone();
            let status = job.status.as_str().to_owned();
            drop(store);
            let mut store = state.jobs.lock().expect("job store poisoned");
            push_event(&mut store, id, "progress", "cancel requested".to_owned());
            json_response(
                stream,
                rid,
                200,
                &serde_json::json!({"job_id": job_id, "status": status}),
            );
        }
    }
}

fn handle_job_events(
    state: &Arc<ServerState>,
    stream: &mut TcpStream,
    rid: u64,
    id: &str,
    query: &BTreeMap<String, String>,
) {
    if !job_id_valid(id) {
        error_response(stream, rid, &ApiErrorBody::new("not_found", "unknown job"));
        return;
    }
    {
        let store = state.jobs.lock().expect("job store poisoned");
        if !store.jobs.contains_key(id) {
            drop(store);
            error_response(stream, rid, &ApiErrorBody::new("not_found", "unknown job"));
            return;
        }
    }
    let mut cursor: u64 = query
        .get("cursor")
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(0);
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\nX-Request-Id: {rid:016x}\r\n\r\n"
    );
    if stream.write_all(head.as_bytes()).is_err() {
        return;
    }
    // Replay buffered events, then stream until the job is terminal,
    // the server shuts down, or the client disconnects.
    loop {
        let (events, terminal) = {
            let store = state.jobs.lock().expect("job store poisoned");
            match store.jobs.get(id) {
                None => (Vec::new(), true),
                Some(job) => {
                    let events: Vec<JobEventDto> = job
                        .events
                        .iter()
                        .filter(|event| event.seq > cursor)
                        .cloned()
                        .collect();
                    let terminal = !matches!(job.status, JobStatus::Queued | JobStatus::Running);
                    (events, terminal)
                }
            }
        };
        for event in &events {
            cursor = cursor.max(event.seq);
            let data = serde_json::to_string(event).unwrap_or_default();
            let frame = format!(
                "id: {}\nevent: {}\ndata: {}\n\n",
                event.seq, event.r#type, data
            );
            if stream.write_all(frame.as_bytes()).is_err() {
                return;
            }
        }
        let _ = stream.flush();
        if terminal {
            return;
        }
        if state.shutdown.load(Ordering::Acquire) {
            return;
        }
        thread::sleep(Duration::from_millis(200));
    }
}

// ---------------------------------------------------------------------------
// Router.
// ---------------------------------------------------------------------------

fn route_request(state: &Arc<ServerState>, stream: &mut TcpStream, rid: u64, request: HttpRequest) {
    if let Err(error) = check_local_origin(&request) {
        error_response(stream, rid, &error);
        return;
    }
    // Static GUI (same origin as the API).
    if request.method == "GET" {
        if let Some(asset) = static_asset(&request.path) {
            write_response(stream, rid, 200, asset.content_type, &[], asset.body);
            return;
        }
    }
    let segments: Vec<&str> = request.path.split('/').collect();
    match (request.method.as_str(), segments.as_slice()) {
        ("GET", ["", "api", "v1", "health"]) => handle_health(stream, rid),
        ("GET", ["", "api", "v1", "capabilities"]) => handle_capabilities(stream, rid),
        ("GET", ["", "api", "v1", "projects"]) => {
            handle_projects_list(state, stream, rid, &request.query);
        }
        ("POST", ["", "api", "v1", "projects"]) => {
            handle_project_create(state, stream, rid, &request.body);
        }
        ("GET", ["", "api", "v1", "projects", name]) => {
            handle_project_get(state, stream, rid, name);
        }
        ("GET", ["", "api", "v1", "projects", name, "entities"]) => {
            handle_project_entities(state, stream, rid, name, &request.query);
        }
        ("GET", ["", "api", "v1", "projects", name, "findings"]) => {
            handle_project_findings(state, stream, rid, name, &request.query);
        }
        ("GET", ["", "api", "v1", "projects", name, "graph"]) => {
            handle_project_graph(state, stream, rid, name, &request.query);
        }
        ("GET", ["", "api", "v1", "projects", name, "timeline"]) => {
            handle_project_timeline(state, stream, rid, name, &request.query);
        }
        ("POST", ["", "api", "v1", "scans"]) => {
            handle_scan_create(state, stream, rid, &request.body);
        }
        ("GET", ["", "api", "v1", "scans", id]) => {
            handle_job_get(state, stream, rid, id, Some(JobKind::Scan));
        }
        ("POST", ["", "api", "v1", "investigations"]) => {
            handle_investigation_create(state, stream, rid, &request.body);
        }
        ("GET", ["", "api", "v1", "investigations", id]) => {
            handle_job_get(state, stream, rid, id, Some(JobKind::Investigation));
        }
        ("POST", ["", "api", "v1", "search"]) => {
            handle_search_sync(state, stream, rid, &request.body);
        }
        ("POST", ["", "api", "v1", "username-searches"]) => {
            handle_username_search_create(state, stream, rid, &request.body);
        }
        ("GET", ["", "api", "v1", "username-searches", "categories"]) => {
            handle_username_categories(stream, rid);
        }
        ("GET", ["", "api", "v1", "username-searches", "providers"]) => {
            handle_username_providers(stream, rid, &request.query);
        }
        ("GET", ["", "api", "v1", "username-searches", id]) => {
            handle_job_get(state, stream, rid, id, Some(JobKind::UsernameSearch));
        }
        ("GET", ["", "api", "v1", "jobs"]) => {
            handle_jobs_list(state, stream, rid, &request.query);
        }
        ("GET", ["", "api", "v1", "jobs", id]) => {
            handle_job_get(state, stream, rid, id, None);
        }
        ("POST", ["", "api", "v1", "jobs", id, "cancel"]) => {
            handle_job_cancel(state, stream, rid, id);
        }
        ("GET", ["", "api", "v1", "jobs", id, "events"]) => {
            handle_job_events(state, stream, rid, id, &request.query);
        }
        ("GET" | "POST", ["", "api", "v1", ..]) => error_response(
            stream,
            rid,
            &ApiErrorBody::new("not_found", "unknown API route"),
        ),
        ("GET" | "POST", _) => {
            error_response(stream, rid, &ApiErrorBody::new("not_found", "not found"))
        }
        _ => error_response(
            stream,
            rid,
            &ApiErrorBody::new("method_not_allowed", "method not allowed"),
        ),
    }
}

fn handle_connection(state: Arc<ServerState>, stream: TcpStream) {
    let rid = state.requests.fetch_add(1, Ordering::Relaxed) + 1;
    let started = Instant::now();
    let peer = stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_owned());
    // Defense in depth: only loopback peers are ever served, even if the
    // socket was somehow bound wider than intended.
    let loopback_peer = stream
        .peer_addr()
        .map(|addr| addr.ip().is_loopback())
        .unwrap_or(false);
    if !loopback_peer {
        eprintln!("[rxscan-web] rid={rid:016x} refused non-loopback peer={peer}");
        return;
    }
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));
    // `read_request` borrows the stream through a buffered reader; the
    // reader releases the raw stream before the response is written.
    let request = {
        let cloned = match stream.try_clone() {
            Ok(cloned) => cloned,
            Err(_) => return,
        };
        let mut reader = BufReader::new(cloned);
        match read_request(&mut reader) {
            Ok(request) => request,
            Err(error) => {
                let code = error_status(error.error.code);
                let body = serde_json::to_vec(&error).unwrap_or_default();
                let mut raw = reader.into_inner();
                write_response(&mut raw, rid, code, "application/json", &[], &body);
                eprintln!(
                    "[rxscan-web] rid={rid:016x} method=? route=? status={code} ms={} peer={peer}",
                    started.elapsed().as_millis()
                );
                return;
            }
        }
    };
    let method = request.method.clone();
    let path = request.path.clone();
    let mut owned = stream;
    // SSE handlers write streaming frames directly; all other routes
    // finish here and the connection closes.
    route_request(&state, &mut owned, rid, request);
    eprintln!(
        "[rxscan-web] rid={rid:016x} method={method} route={path} ms={} peer={peer}",
        started.elapsed().as_millis()
    );
}

// ---------------------------------------------------------------------------
// Lifecycle.
// ---------------------------------------------------------------------------

/// Start the local server. Returns a handle (accept loop runs on its own
/// thread). Validates the bind address: non-loopback requires `allow_remote`.
pub fn serve(options: WebOptions) -> std::io::Result<ServerHandle> {
    let bind_ip: IpAddr = options.bind.parse().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid bind address")
    })?;
    if !bind_ip.is_loopback() && !options.allow_remote {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing non-loopback bind without --allow-remote (dangerous, unauthenticated)",
        ));
    }
    std::fs::create_dir_all(&options.data_dir).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("cannot use data dir: {error}"),
        )
    })?;
    let listener = TcpListener::bind((options.bind.as_str(), options.port))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let base_url = format!("http://{}:{port}", options.bind);
    let shutdown = Arc::new(AtomicBool::new(false));
    let state = Arc::new(ServerState {
        options,
        jobs: Mutex::new(JobStore::new()),
        requests: AtomicU64::new(0),
        shutdown: shutdown.clone(),
    });
    let accept_state = state.clone();
    let accept_shutdown = shutdown.clone();
    let accept_thread = thread::spawn(move || {
        loop {
            if accept_shutdown.load(Ordering::Acquire) {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let peer_ok = stream
                        .peer_addr()
                        .map(|addr| addr.ip().is_loopback())
                        .unwrap_or(false);
                    if !peer_ok {
                        eprintln!("[rxscan-web] refused non-loopback peer");
                        continue;
                    }
                    let worker = accept_state.clone();
                    thread::spawn(move || handle_connection(worker, stream));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(_) => {
                    if accept_shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
    });
    Ok(ServerHandle {
        base_url,
        shutdown,
        port,
        accept_thread: Mutex::new(Some(accept_thread)),
        state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_hosts_accepted() {
        assert!(host_is_loopback(Some("127.0.0.1:8080")));
        assert!(host_is_loopback(Some("localhost")));
        assert!(host_is_loopback(Some("[::1]:8080")));
        assert!(!host_is_loopback(Some("evil.test")));
        assert!(!host_is_loopback(Some("192.168.1.2:8080")));
        assert!(!host_is_loopback(None));
    }

    #[test]
    fn foreign_origins_rejected() {
        assert!(origin_is_allowed(None));
        assert!(origin_is_allowed(Some("http://127.0.0.1:8080")));
        assert!(origin_is_allowed(Some("http://localhost:9999")));
        assert!(!origin_is_allowed(Some("https://evil.test")));
        assert!(!origin_is_allowed(Some("http://192.168.1.2:8080")));
    }

    #[test]
    fn project_names_are_filesystem_safe() {
        assert!(validate_project_name("default").is_ok());
        assert!(validate_project_name("a-b_c9").is_ok());
        assert!(validate_project_name("../evil").is_err());
        assert!(validate_project_name("a/b").is_err());
        assert!(validate_project_name("").is_err());
    }
}
