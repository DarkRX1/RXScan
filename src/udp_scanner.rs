//! Native UDP discovery scanner: one scheduler task, bounded internal work.
//!
//! Boundary (documented):
//! * The scheduler coordinates target-level `UdpDiscovery` tasks (one per
//!   target, never 65k tasks for `--all-ports`-style scans).
//! * This scanner manages strictly bounded per-port work inside the task:
//!   a sliding window of connected non-blocking UDP sockets multiplexed
//!   with `poll(2)`. No thread per port; at most `max_in_flight` sockets
//!   (hard-capped 64).
//!
//! # UDP evidence semantics (never TCP semantics)
//!
//! * One connected socket per in-flight port: the kernel attributes ICMP
//!   errors and filters stray datagrams to the probed peer, so every
//!   conclusion is attributable. Unconnected sockets cannot see ICMP.
//! * Response datagram ⇒ `Open` (responsiveness only; protocol identity
//!   comes from an optional grammar match, never assumed).
//! * `ECONNREFUSED` / `SO_ERROR==111` on that port's socket ⇒ `Closed`.
//! * Nothing after the bounded retry policy ⇒ `OpenOrFiltered`
//!   (uncertainty — never called open or closed).
//! * Unreachable/local failures ⇒ `Error` (not target state).
//!
//! Every attempt honors timeout, cancellation (prompt, ~25ms poll slices),
//! bounded retries (silence only, at most one retry), overall task
//! deadline, and immediate FD cleanup.

use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::os::raw::{c_int, c_void};
use std::time::{Duration, Instant};

use crate::execution::CancellationToken;

// ---- libc constants (Linux; other platforms degrade to Error) ---
const AF_INET: c_int = 2;
const AF_INET6: c_int = 10;
const SOCK_DGRAM: c_int = 2;
const IPPROTO_UDP: c_int = 17;
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const O_NONBLOCK: c_int = 2048;
const EINPROGRESS: c_int = 115;
const EINTR: c_int = 4;
const EAGAIN: c_int = 11;
const ECONNREFUSED: c_int = 111;
const EHOSTUNREACH: c_int = 113;
const ENETUNREACH: c_int = 101;
const EMFILE: c_int = 24;
const ENFILE: c_int = 23;
const ENOMEM: c_int = 12;
const POLLIN: i16 = 0x0001;
const POLLERR: i16 = 0x0008;
const POLLHUP: i16 = 0x0010;
const SOL_SOCKET: c_int = 1;
const SO_ERROR: c_int = 4;
const MSG_NOSIGNAL: c_int = 0x4000;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: [u8; 4],
    sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockaddrIn6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

unsafe extern "C" {
    fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, arg: c_int) -> c_int;
    fn connect(fd: c_int, addr: *const c_void, len: u32) -> c_int;
    fn poll(fds: *mut PollFd, nfds: u64, timeout: c_int) -> c_int;
    fn getsockopt(
        fd: c_int,
        level: c_int,
        optname: c_int,
        optval: *mut c_void,
        optlen: *mut u32,
    ) -> c_int;
    fn send(fd: c_int, buf: *const c_void, len: usize, flags: c_int) -> isize;
    fn recv(fd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize;
    fn __errno_location() -> *mut c_int;
}

fn last_errno() -> c_int {
    unsafe { *__errno_location() }
}

struct OwnedFd(c_int);
impl OwnedFd {
    fn new(fd: c_int) -> Option<Self> {
        (fd >= 0).then_some(Self(fd))
    }
}
impl Drop for OwnedFd {
    fn drop(&mut self) {
        unsafe {
            close(self.0);
        }
    }
}

/// Evidence-backed UDP conclusion. Silence is never Open or Closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpPortState {
    Open,
    Closed,
    OpenOrFiltered,
    Error,
}

impl std::fmt::Display for UdpPortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Closed => write!(f, "closed"),
            Self::OpenOrFiltered => write!(f, "open_or_filtered"),
            Self::Error => write!(f, "error"),
        }
    }
}

/// One port's final UDP record.
#[derive(Debug, Clone)]
pub struct UdpProbe {
    pub port: u16,
    pub state: UdpPortState,
    pub latency: Duration,
    pub detail: String,
    /// Sends performed (1 + retries).
    pub attempts: u32,
    /// Grammar-matched protocol (`dns`/`ntp`/`ssdp`) on responses, if any.
    /// `None` for non-responses and for unrecognized responses (Open with
    /// unknown protocol — never invented).
    pub protocol: Option<String>,
    pub datagrams_sent: u32,
    pub datagrams_received: u32,
}

/// Per-port probe payload + response grammar. Implementations are pure,
/// deterministic, and tiny; fakes drive scanner unit tests.
pub trait UdpProbeSource: Send + Sync {
    /// Bounded request datagram for (`ip`, `port`) (possibly empty).
    /// `ip` lets unicast probes address the target correctly.
    fn payload(&self, ip: &IpAddr, port: u16) -> Vec<u8>;
    /// Grammar match on a response from `port`. `Some(protocol)` only for
    /// validated structure; `None` keeps Open with unknown protocol.
    fn classify(&self, port: u16, response: &[u8]) -> Option<String>;
}

/// Scanner configuration (all bounds enforced by caller + clamped here).
#[derive(Debug, Clone)]
pub struct UdpScanConfig {
    pub timeout: Duration,
    pub max_in_flight: usize,
    /// Retries for silence only (0 or 1). Closed/answered never retry.
    pub max_retries: u32,
    /// Retain every per-port record (`true` for detailed scans). When
    /// `false` (huge scans), only Open records are retained; all states
    /// stay exactly counted above.
    pub retain_detail: bool,
    pub deadline: Option<Instant>,
    pub cancel: CancellationToken,
}

impl UdpScanConfig {
    pub fn bounded(
        timeout: Duration,
        max_in_flight: usize,
        max_retries: u32,
        deadline: Option<Instant>,
        cancel: CancellationToken,
    ) -> Self {
        Self::bounded_detailed(timeout, max_in_flight, max_retries, true, deadline, cancel)
    }

    pub fn bounded_detailed(
        timeout: Duration,
        max_in_flight: usize,
        max_retries: u32,
        retain_detail: bool,
        deadline: Option<Instant>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            timeout: timeout.clamp(Duration::from_millis(100), Duration::from_secs(10)),
            max_in_flight: max_in_flight.clamp(1, crate::ports::MAX_UDP_IN_FLIGHT_HARD),
            max_retries: max_retries.min(crate::ports::MAX_UDP_RETRIES),
            retain_detail,
            deadline,
            cancel,
        }
    }
}

/// Outcome of one `scan` call (partial on cancel/deadline, sorted by port).
#[derive(Debug, Clone, Default)]
pub struct UdpScanOutcome {
    /// Retained per-port records. ALWAYS complete for detailed scans;
    /// for huge scans only Open records are retained (Closed/Filtered/
    /// Error outcomes are counted below and dropped) so retained memory
    /// scales with interesting results, not requested ports.
    pub probes: Vec<UdpProbe>,
    /// Exact terminal-state counts (always complete, both modes).
    pub open_count: u64,
    pub closed_count: u64,
    pub filtered_count: u64,
    pub error_count: u64,
    pub truncated: bool,
    pub cancelled: bool,
    /// Ports never attempted due to deadline/cancel.
    pub unscanned: usize,
    /// Peak simultaneously held in-flight sockets.
    pub fd_peak: usize,

    pub datagrams_sent: u64,
    pub datagrams_received: u64,
    pub retries: u64,
    pub closed_errors: u64,
    pub timeouts: u64,
}

impl UdpScanOutcome {
    /// Record one terminal per-port outcome. Counters stay exact in both
    /// modes; the rich record is retained always in detailed mode but only
    /// for Open ports in huge mode (Closed/Filtered/Error outcomes are
    /// fully described by counts + ledger there).
    fn record(&mut self, probe: UdpProbe, retain_detail: bool) {
        match probe.state {
            UdpPortState::Open => self.open_count += 1,
            UdpPortState::Closed => self.closed_count += 1,
            UdpPortState::OpenOrFiltered => self.filtered_count += 1,
            UdpPortState::Error => self.error_count += 1,
        }
        if retain_detail || matches!(probe.state, UdpPortState::Open) {
            self.probes.push(probe);
        }
    }
}

/// Trait for UDP scanning (real poll-window + fakes for tests).
pub trait UdpScanner: Send + Sync {
    fn scan(
        &self,
        ip: IpAddr,
        ports: &[u16],
        source: &dyn UdpProbeSource,
        config: &UdpScanConfig,
    ) -> UdpScanOutcome;
}

/// Native poll-window UDP scanner (unprivileged, no raw sockets).
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeUdpScanner;

impl UdpScanner for NativeUdpScanner {
    fn scan(
        &self,
        ip: IpAddr,
        ports: &[u16],
        source: &dyn UdpProbeSource,
        config: &UdpScanConfig,
    ) -> UdpScanOutcome {
        scan_ports_udp(ip, ports, source, config)
    }
}

struct Pending {
    port: u16,
    #[allow(dead_code)]
    fd: OwnedFd,
    started: Instant,
    attempt_deadline: Instant,
    attempts: u32,
}

fn sockaddr_for(ip: &IpAddr, port: u16) -> (Vec<u8>, u32) {
    match ip {
        IpAddr::V4(v4) => {
            let addr = SockaddrIn {
                sin_family: AF_INET as u16,
                sin_port: port.to_be(),
                sin_addr: v4.octets(),
                sin_zero: [0; 8],
            };
            let bytes: Vec<u8> = unsafe {
                std::slice::from_raw_parts(
                    &addr as *const SockaddrIn as *const u8,
                    size_of::<SockaddrIn>(),
                )
            }
            .to_vec();
            (bytes, size_of::<SockaddrIn>() as u32)
        }
        IpAddr::V6(v6) => {
            let addr = SockaddrIn6 {
                sin6_family: AF_INET6 as u16,
                sin6_port: port.to_be(),
                sin6_flowinfo: 0,
                sin6_addr: v6.octets(),
                sin6_scope_id: 0,
            };
            let bytes: Vec<u8> = unsafe {
                std::slice::from_raw_parts(
                    &addr as *const SockaddrIn6 as *const u8,
                    size_of::<SockaddrIn6>(),
                )
            }
            .to_vec();
            (bytes, size_of::<SockaddrIn6>() as u32)
        }
    }
}

fn set_nonblocking(fd: c_int) -> bool {
    unsafe {
        let flags = fcntl(fd, F_GETFL, 0);
        if flags < 0 {
            return false;
        }
        fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0
    }
}

fn socket_error(fd: c_int) -> c_int {
    let mut error: c_int = 0;
    let mut length = size_of::<c_int>() as u32;
    unsafe {
        getsockopt(
            fd,
            SOL_SOCKET,
            SO_ERROR,
            &mut error as *mut c_int as *mut c_void,
            &mut length,
        );
    }
    error
}

fn send_datagram(fd: c_int, payload: &[u8]) -> Result<(), c_int> {
    let result = unsafe {
        send(
            fd,
            payload.as_ptr() as *const c_void,
            payload.len(),
            MSG_NOSIGNAL,
        )
    };
    if result < 0 {
        Err(last_errno())
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_lines)]
fn scan_ports_udp(
    ip: IpAddr,
    ports: &[u16],
    source: &dyn UdpProbeSource,
    config: &UdpScanConfig,
) -> UdpScanOutcome {
    // Normalize deterministically; port 0 never scanned.
    let mut queue: VecDeque<(u16, u32)> = {
        let mut sorted: Vec<u16> = ports.iter().copied().filter(|port| *port > 0).collect();
        sorted.sort_unstable();
        sorted.dedup();
        sorted.into_iter().map(|port| (port, 1)).collect()
    };
    let mut outcome = UdpScanOutcome::default();
    let mut pending: BTreeMap<c_int, Pending> = BTreeMap::new();
    let mut backoff_until = Instant::now();

    let overall_deadline = config.deadline;
    let is_expired = |now: Instant| overall_deadline.is_some_and(|deadline| now >= deadline);

    'outer: while !queue.is_empty() || !pending.is_empty() {
        if config.cancel.is_cancelled() {
            outcome.cancelled = true;
            outcome.truncated = true;
            break;
        }
        let now = Instant::now();
        if is_expired(now) {
            outcome.truncated = true;
            break;
        }
        // Fill window up to max_in_flight.
        while pending.len() < config.max_in_flight {
            let Some((port, attempts)) = queue.pop_front() else {
                break;
            };
            if config.cancel.is_cancelled() {
                queue.push_front((port, attempts));
                outcome.cancelled = true;
                outcome.truncated = true;
                break 'outer;
            }
            let now = Instant::now();
            if is_expired(now) {
                queue.push_front((port, attempts));
                outcome.truncated = true;
                break 'outer;
            }
            if Instant::now() < backoff_until {
                queue.push_front((port, attempts));
                break;
            }
            let domain = match ip {
                IpAddr::V4(_) => AF_INET,
                IpAddr::V6(_) => AF_INET6,
            };
            let raw = unsafe { socket(domain, SOCK_DGRAM, IPPROTO_UDP) };
            let Some(fd) = OwnedFd::new(raw) else {
                let errno = last_errno();
                if errno == EMFILE || errno == ENFILE || errno == ENOMEM {
                    backoff_until = Instant::now() + Duration::from_millis(20);
                    queue.push_front((port, attempts));
                    break;
                }
                outcome.record(
                    UdpProbe {
                        port,
                        state: UdpPortState::Error,
                        latency: Duration::ZERO,
                        detail: format!("UDP socket creation failed (errno {errno})"),
                        attempts,
                        protocol: None,
                        datagrams_sent: 0,
                        datagrams_received: 0,
                    },
                    config.retain_detail,
                );
                continue;
            };
            // Blocking connect (instant for UDP: no handshake), then
            // non-blocking I/O. This ordering avoids EINPROGRESS entirely.
            let (addr_bytes, addr_len) = sockaddr_for(&ip, port);
            let connected =
                unsafe { connect(fd.0, addr_bytes.as_ptr() as *const c_void, addr_len) };
            if connected != 0 {
                let errno = last_errno();
                if errno == EINPROGRESS || errno == EAGAIN {
                    // Harmless on UDP (no handshake); proceed non-blocking.
                } else if errno == ECONNREFUSED {
                    // Immediate refusal on connect path: attributable close.
                    outcome.closed_errors += 1;
                    outcome.record(
                        UdpProbe {
                            port,
                            state: UdpPortState::Closed,
                            latency: now.elapsed(),
                            detail: format!("UDP {ip}:{port} refused on connect (errno {errno})"),
                            attempts,
                            protocol: None,
                            datagrams_sent: 0,
                            datagrams_received: 0,
                        },
                        config.retain_detail,
                    );
                    continue;
                } else if errno == EHOSTUNREACH || errno == ENETUNREACH {
                    outcome.record(
                        UdpProbe {
                            port,
                            state: UdpPortState::Error,
                            latency: now.elapsed(),
                            detail: format!(
                                "UDP {ip}:{port} unreachable on connect (errno {errno})"
                            ),
                            attempts,
                            protocol: None,
                            datagrams_sent: 0,
                            datagrams_received: 0,
                        },
                        config.retain_detail,
                    );
                    continue;
                } else {
                    outcome.record(
                        UdpProbe {
                            port,
                            state: UdpPortState::Error,
                            latency: now.elapsed(),
                            detail: format!("UDP connect to {ip}:{port} failed (errno {errno})"),
                            attempts,
                            protocol: None,
                            datagrams_sent: 0,
                            datagrams_received: 0,
                        },
                        config.retain_detail,
                    );
                    continue;
                }
            }
            if !set_nonblocking(fd.0) {
                outcome.record(
                    UdpProbe {
                        port,
                        state: UdpPortState::Error,
                        latency: Duration::ZERO,
                        detail: "failed to set non-blocking socket".to_owned(),
                        attempts,
                        protocol: None,
                        datagrams_sent: 0,
                        datagrams_received: 0,
                    },
                    config.retain_detail,
                );
                continue;
            }
            let payload = source.payload(&ip, port);
            let started = Instant::now();
            match send_datagram(fd.0, &payload) {
                Ok(()) => {
                    outcome.datagrams_sent += 1;
                    pending.insert(
                        fd.0,
                        Pending {
                            port,
                            fd,
                            started,
                            attempt_deadline: started + config.timeout,
                            attempts,
                        },
                    );
                    outcome.fd_peak = outcome.fd_peak.max(pending.len());
                }
                Err(ECONNREFUSED) => {
                    outcome.closed_errors += 1;
                    outcome.datagrams_sent += 1;
                    outcome.record(
                        UdpProbe {
                            port,
                            state: UdpPortState::Closed,
                            latency: started.elapsed(),
                            detail: format!("UDP {ip}:{port} refused on send; host responded"),
                            attempts,
                            protocol: None,
                            datagrams_sent: 1,
                            datagrams_received: 0,
                        },
                        config.retain_detail,
                    );
                }
                Err(errno) => {
                    outcome.record(
                        UdpProbe {
                            port,
                            state: UdpPortState::Error,
                            latency: started.elapsed(),
                            detail: format!("UDP send to {ip}:{port} failed (errno {errno})"),
                            attempts,
                            protocol: None,
                            datagrams_sent: 0,
                            datagrams_received: 0,
                        },
                        config.retain_detail,
                    );
                }
            }
        }
        if pending.is_empty() {
            if !queue.is_empty() && Instant::now() < backoff_until {
                std::thread::sleep(Duration::from_millis(5));
            }
            continue;
        }
        // Poll with a short slice so cancellation/deadlines stay prompt.
        let now = Instant::now();
        let next_deadline = pending
            .values()
            .map(|item| item.attempt_deadline)
            .min()
            .unwrap_or(now + Duration::from_millis(25));
        let poll_timeout = next_deadline
            .saturating_duration_since(now)
            .min(Duration::from_millis(25))
            .as_millis()
            .min(c_int::MAX as u128) as c_int;
        let mut poll_fds: Vec<PollFd> = pending
            .keys()
            .map(|fd| PollFd {
                fd: *fd,
                events: POLLIN | POLLERR,
                revents: 0,
            })
            .collect();
        let ready = unsafe { poll(poll_fds.as_mut_ptr(), poll_fds.len() as u64, poll_timeout) };
        if config.cancel.is_cancelled() {
            outcome.cancelled = true;
            outcome.truncated = true;
            break;
        }
        if is_expired(Instant::now()) {
            outcome.truncated = true;
            break;
        }
        if ready < 0 {
            let errno = last_errno();
            if errno == EINTR {
                continue;
            }
        }
        let ready_map: BTreeMap<c_int, i16> = poll_fds
            .iter()
            .map(|item| (item.fd, item.revents))
            .collect();
        let now = Instant::now();
        let mut finished: Vec<c_int> = Vec::new();
        let mut to_retry: Vec<(u16, u32)> = Vec::new();
        for (fd, item) in pending.iter() {
            let revents = ready_map.get(fd).copied().unwrap_or(0);
            // Error signal first: attributable closed vs network error.
            if (revents & (POLLERR | POLLHUP)) != 0 {
                let error = socket_error(*fd);
                match error {
                    0 => {
                        // Spurious wakeup without error: keep waiting.
                    }
                    e if e == ECONNREFUSED => {
                        outcome.closed_errors += 1;
                        outcome.record(
                            UdpProbe {
                                port: item.port,
                                state: UdpPortState::Closed,
                                latency: item.started.elapsed(),
                                detail: format!(
                                    "UDP port unreachable on {}:{} (errno {e}); host responded",
                                    ip, item.port
                                ),
                                attempts: item.attempts,
                                protocol: None,
                                datagrams_sent: item.attempts,
                                datagrams_received: 0,
                            },
                            config.retain_detail,
                        );
                        finished.push(*fd);
                        continue;
                    }
                    e => {
                        outcome.record(
                            UdpProbe {
                                port: item.port,
                                state: UdpPortState::Error,
                                latency: item.started.elapsed(),
                                detail: format!(
                                    "UDP socket error on {}:{} (errno {e})",
                                    ip, item.port
                                ),
                                attempts: item.attempts,
                                protocol: None,
                                datagrams_sent: item.attempts,
                                datagrams_received: 0,
                            },
                            config.retain_detail,
                        );
                        finished.push(*fd);
                        continue;
                    }
                }
            }
            if (revents & POLLIN) != 0 {
                let mut buffer = [0u8; 2048];
                let received = unsafe {
                    recv(
                        *fd,
                        buffer.as_mut_ptr() as *mut c_void,
                        buffer.len(),
                        MSG_NOSIGNAL,
                    )
                };
                if received > 0 {
                    let count = received as usize;
                    outcome.datagrams_received += 1;
                    let protocol = source.classify(item.port, &buffer[..count]);
                    let detail = match &protocol {
                        Some(name) => {
                            format!("UDP response on {}:{} matched {name}", ip, item.port)
                        }
                        None => format!(
                            "UDP response on {}:{} ({} bytes, unrecognized)",
                            ip, item.port, count
                        ),
                    };
                    outcome.record(
                        UdpProbe {
                            port: item.port,
                            state: UdpPortState::Open,
                            latency: item.started.elapsed(),
                            detail,
                            attempts: item.attempts,
                            protocol,
                            datagrams_sent: item.attempts,
                            datagrams_received: 1,
                        },
                        config.retain_detail,
                    );
                    finished.push(*fd);
                    continue;
                }
                if received < 0 {
                    let errno = last_errno();
                    if errno == ECONNREFUSED {
                        outcome.closed_errors += 1;
                        outcome.record(
                            UdpProbe {
                                port: item.port,
                                state: UdpPortState::Closed,
                                latency: item.started.elapsed(),
                                detail: format!(
                                    "UDP port unreachable on {}:{} (errno {errno})",
                                    ip, item.port
                                ),
                                attempts: item.attempts,
                                protocol: None,
                                datagrams_sent: item.attempts,
                                datagrams_received: 0,
                            },
                            config.retain_detail,
                        );
                        finished.push(*fd);
                        continue;
                    }
                    if errno == EHOSTUNREACH || errno == ENETUNREACH {
                        outcome.record(
                            UdpProbe {
                                port: item.port,
                                state: UdpPortState::Error,
                                latency: item.started.elapsed(),
                                detail: format!(
                                    "UDP {}:{} unreachable (errno {errno})",
                                    ip, item.port
                                ),
                                attempts: item.attempts,
                                protocol: None,
                                datagrams_sent: item.attempts,
                                datagrams_received: 0,
                            },
                            config.retain_detail,
                        );
                        finished.push(*fd);
                        continue;
                    }
                    // EAGAIN or transient: fall through to deadline check.
                    if errno != EAGAIN && errno != EINTR {
                        outcome.record(
                            UdpProbe {
                                port: item.port,
                                state: UdpPortState::Error,
                                latency: item.started.elapsed(),
                                detail: format!(
                                    "UDP recv on {}:{} failed (errno {errno})",
                                    ip, item.port
                                ),
                                attempts: item.attempts,
                                protocol: None,
                                datagrams_sent: item.attempts,
                                datagrams_received: 0,
                            },
                            config.retain_detail,
                        );
                        finished.push(*fd);
                        continue;
                    }
                }
                // Empty datagram (0 bytes): a response with no payload still
                // proves responsiveness.
                if received == 0 {
                    outcome.datagrams_received += 1;
                    let protocol = source.classify(item.port, &[]);
                    outcome.record(
                        UdpProbe {
                            port: item.port,
                            state: UdpPortState::Open,
                            latency: item.started.elapsed(),
                            detail: format!("UDP empty response on {}:{}", ip, item.port),
                            attempts: item.attempts,
                            protocol,
                            datagrams_sent: item.attempts,
                            datagrams_received: 1,
                        },
                        config.retain_detail,
                    );
                    finished.push(*fd);
                    continue;
                }
            }
            if now >= item.attempt_deadline {
                if item.attempts <= config.max_retries {
                    // Silence only: resend the identical payload (never on
                    // closed/answered; those terminal states return above).
                    outcome.retries += 1;
                    to_retry.push((item.port, item.attempts + 1));
                } else {
                    outcome.timeouts += 1;
                    outcome.record(
                        UdpProbe {
                            port: item.port,
                            state: UdpPortState::OpenOrFiltered,
                            latency: item.started.elapsed(),
                            detail: format!(
                                "UDP {}:{} silent after {} attempt(s); uncertain, not closed",
                                ip, item.port, item.attempts
                            ),
                            attempts: item.attempts,
                            protocol: None,
                            datagrams_sent: item.attempts,
                            datagrams_received: 0,
                        },
                        config.retain_detail,
                    );
                }
                finished.push(*fd);
            }
        }
        for fd in finished {
            pending.remove(&fd);
        }
        // Retries go to the front (deterministic) for the next fill.
        for (port, attempts) in to_retry.into_iter().rev() {
            queue.push_front((port, attempts));
        }
    }
    // Pending dropped here closes all FDs (no leaks). Unattempted queue tail
    // counts as unscanned when truncated.
    let unscanned = queue.len();
    if unscanned > 0 {
        outcome.truncated = true;
    }
    outcome.unscanned = unscanned;
    outcome.probes.sort_by_key(|probe| probe.port);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Empty-payload source: closed vs filtered separation only.
    #[derive(Debug, Default)]
    struct EmptySource;
    impl UdpProbeSource for EmptySource {
        fn payload(&self, _ip: &IpAddr, _port: u16) -> Vec<u8> {
            Vec::new()
        }
        fn classify(&self, _port: u16, _response: &[u8]) -> Option<String> {
            None
        }
    }

    fn test_config(timeout_ms: u64, retries: u32) -> UdpScanConfig {
        UdpScanConfig::bounded(
            Duration::from_millis(timeout_ms),
            16,
            retries,
            None,
            CancellationToken::default(),
        )
    }

    fn closed_port() -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        port
    }

    #[test]
    fn states_stay_distinct() {
        assert_ne!(UdpPortState::Open, UdpPortState::Closed);
        assert_ne!(UdpPortState::Closed, UdpPortState::OpenOrFiltered);
        assert_ne!(UdpPortState::OpenOrFiltered, UdpPortState::Error);
    }

    #[test]
    fn loopback_closed_is_closed_not_filtered() {
        let outcome = NativeUdpScanner.scan(
            "127.0.0.1".parse().unwrap(),
            &[closed_port()],
            &EmptySource,
            &test_config(500, 0),
        );
        assert_eq!(outcome.probes.len(), 1);
        assert_eq!(outcome.probes[0].state, UdpPortState::Closed);
        assert!(!outcome.cancelled);
    }

    #[test]
    fn echo_response_is_open() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = std::thread::spawn(move || {
            server
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            while !stop_thread.load(Ordering::SeqCst) {
                if let Ok((count, addr)) = server.recv_from(&mut [0u8; 2048]) {
                    let _ = server.send_to(&[9u8; 8][..count.min(8)], addr);
                }
            }
        });
        let outcome = NativeUdpScanner.scan(
            "127.0.0.1".parse().unwrap(),
            &[port],
            &EmptySource,
            &test_config(2000, 0),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        assert_eq!(outcome.probes.len(), 1);
        assert_eq!(outcome.probes[0].state, UdpPortState::Open);
        assert_eq!(outcome.datagrams_received, 1);
    }

    #[test]
    fn silent_bound_port_is_open_or_filtered() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let outcome = NativeUdpScanner.scan(
            "127.0.0.1".parse().unwrap(),
            &[port],
            &EmptySource,
            &test_config(300, 0),
        );
        drop(server);
        assert_eq!(outcome.probes.len(), 1);
        // Silence is uncertainty: never Open, never Closed.
        assert_eq!(outcome.probes[0].state, UdpPortState::OpenOrFiltered);
    }

    #[test]
    fn retry_resends_identical_payload_on_silence() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let received = Arc::new(AtomicUsize::new(0));
        let received_thread = received.clone();
        let handle = std::thread::spawn(move || {
            server
                .set_read_timeout(Some(Duration::from_millis(2000)))
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline && received_thread.load(Ordering::SeqCst) < 2 {
                if server.recv_from(&mut [0u8; 2048]).is_ok() {
                    received_thread.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        let outcome = NativeUdpScanner.scan(
            "127.0.0.1".parse().unwrap(),
            &[port],
            &EmptySource,
            &test_config(300, 1),
        );
        handle.join().unwrap();
        assert_eq!(outcome.probes.len(), 1);
        assert_eq!(outcome.probes[0].attempts, 2);
        assert_eq!(outcome.retries, 1);
        assert_eq!(received.load(Ordering::SeqCst), 2);
        assert_eq!(outcome.probes[0].state, UdpPortState::OpenOrFiltered);
    }

    #[test]
    fn cancellation_interrupts_promptly() {
        let token = CancellationToken::default();
        token.cancel();
        let outcome = UdpScanConfig::bounded(Duration::from_millis(500), 16, 0, None, token);
        let scanned = NativeUdpScanner.scan(
            "127.0.0.1".parse().unwrap(),
            &[closed_port()],
            &EmptySource,
            &outcome,
        );
        assert!(scanned.cancelled);
    }
}
