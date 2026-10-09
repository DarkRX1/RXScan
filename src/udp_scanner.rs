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
//! # State-model interpretation
//!
//! `Open` means open_confirmed (a response was received); a grammar match
//! adds protocol_response identity on top. `Closed` covers ICMP port
//! unreachable. `OpenOrFiltered` covers both silent timeout and
//! administratively filtered without a distinguishing signal. `Error` is a
//! local failure, never a statement about the target.
//!
//! Every attempt honors timeout, cancellation (prompt, ~25ms poll slices),
//! bounded retries (silence only, at most one retry), overall task
//! deadline, and immediate FD cleanup.

#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::execution::CancellationToken;

// ---- Linux raw backend (Linux-only linkage; portable fallback below) ---
#[cfg(target_os = "linux")]
mod linux_raw {
    use std::os::raw::{c_int, c_void};
    pub use std::os::raw::{c_int as CInt, c_void as CVoid};
    pub const AF_INET: c_int = 2;
    pub const AF_INET6: c_int = 10;
    pub const SOCK_DGRAM: c_int = 2;
    pub const IPPROTO_UDP: c_int = 17;
    pub const F_GETFL: c_int = 3;
    pub const F_SETFL: c_int = 4;
    pub const O_NONBLOCK: c_int = 2048;
    pub const EINPROGRESS: c_int = 115;
    pub const EINTR: c_int = 4;
    pub const EAGAIN: c_int = 11;
    pub const ECONNREFUSED: c_int = 111;
    pub const EHOSTUNREACH: c_int = 113;
    pub const ENETUNREACH: c_int = 101;
    pub const EMFILE: c_int = 24;
    pub const ENFILE: c_int = 23;
    pub const ENOMEM: c_int = 12;
    pub const POLLIN: i16 = 0x0001;
    pub const POLLERR: i16 = 0x0008;
    pub const POLLHUP: i16 = 0x0010;
    pub const SOL_SOCKET: c_int = 1;
    pub const SO_ERROR: c_int = 4;
    pub const MSG_NOSIGNAL: c_int = 0x4000;

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct SockaddrIn {
        pub sin_family: u16,
        pub sin_port: u16,
        pub sin_addr: [u8; 4],
        pub sin_zero: [u8; 8],
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct SockaddrIn6 {
        pub sin6_family: u16,
        pub sin6_port: u16,
        pub sin6_flowinfo: u32,
        pub sin6_addr: [u8; 16],
        pub sin6_scope_id: u32,
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct PollFd {
        pub fd: c_int,
        pub events: i16,
        pub revents: i16,
    }

    unsafe extern "C" {
        pub fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
        pub fn close(fd: c_int) -> c_int;
        pub fn fcntl(fd: c_int, cmd: c_int, arg: c_int) -> c_int;
        pub fn connect(fd: c_int, addr: *const c_void, len: u32) -> c_int;
        pub fn poll(fds: *mut PollFd, nfds: u64, timeout: c_int) -> c_int;
        pub fn getsockopt(
            fd: c_int,
            level: c_int,
            optname: c_int,
            optval: *mut c_void,
            optlen: *mut u32,
        ) -> c_int;
        pub fn send(fd: c_int, buf: *const c_void, len: usize, flags: c_int) -> isize;
        pub fn recv(fd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize;
        pub fn __errno_location() -> *mut c_int;
    }

    pub fn last_errno() -> c_int {
        unsafe { *__errno_location() }
    }

    pub struct OwnedFd(pub c_int);
    impl OwnedFd {
        pub fn new(fd: c_int) -> Option<Self> {
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
}
#[cfg(target_os = "linux")]
use linux_raw::*;

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

#[cfg(target_os = "linux")]
struct Pending {
    port: u16,
    #[allow(dead_code)]
    fd: OwnedFd,
    started: Instant,
    attempt_deadline: Instant,
    attempts: u32,
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn set_nonblocking(fd: CInt) -> bool {
    unsafe {
        let flags = fcntl(fd, F_GETFL, 0);
        if flags < 0 {
            return false;
        }
        fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0
    }
}

#[cfg(target_os = "linux")]
fn socket_error(fd: CInt) -> CInt {
    let mut error: CInt = 0;
    let mut length = size_of::<CInt>() as u32;
    unsafe {
        getsockopt(
            fd,
            SOL_SOCKET,
            SO_ERROR,
            &mut error as *mut CInt as *mut CVoid,
            &mut length,
        );
    }
    error
}

#[cfg(target_os = "linux")]
fn send_datagram(fd: CInt, payload: &[u8]) -> Result<(), CInt> {
    let result = unsafe {
        send(
            fd,
            payload.as_ptr() as *const CVoid,
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

#[cfg(target_os = "linux")]
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
    let mut pending: BTreeMap<CInt, Pending> = BTreeMap::new();
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
            let connected = unsafe { connect(fd.0, addr_bytes.as_ptr() as *const CVoid, addr_len) };
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
            .min(CInt::MAX as u128) as CInt;
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
        let ready_map: BTreeMap<CInt, i16> = poll_fds
            .iter()
            .map(|item| (item.fd, item.revents))
            .collect();
        let now = Instant::now();
        let mut finished: Vec<CInt> = Vec::new();
        let mut to_retry: Vec<(u16, u32)> = Vec::new();
        let mut to_requeue: Vec<(u16, u32)> = Vec::new();
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
                        buffer.as_mut_ptr() as *mut CVoid,
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
                // No new retries after cancellation or overall deadline:
                // preserve the probe for unscanned accounting instead of
                // counting a retry that can never be sent.
                if config.cancel.is_cancelled() || is_expired(Instant::now()) {
                    to_requeue.push((item.port, item.attempts));
                    finished.push(*fd);
                    continue;
                }
                // Final evidence check before resending: late ICMP/response
                // arriving after poll must not trigger an unnecessary retry.
                // Definitive CLOSED and valid responses never retry.
                let final_error = socket_error(*fd);
                if final_error == ECONNREFUSED {
                    outcome.closed_errors += 1;
                    outcome.record(
                        UdpProbe {
                            port: item.port,
                            state: UdpPortState::Closed,
                            latency: item.started.elapsed(),
                            detail: format!(
                                "UDP port unreachable on {}:{} (errno {final_error}); host responded",
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
                if final_error != 0 {
                    outcome.record(
                        UdpProbe {
                            port: item.port,
                            state: UdpPortState::Error,
                            latency: item.started.elapsed(),
                            detail: format!(
                                "UDP socket error on {}:{} (errno {final_error})",
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
                // Non-blocking probe for a late response (socket is already
                // non-blocking, so this never waits).
                {
                    let mut buffer = [0u8; 2048];
                    let received = unsafe {
                        recv(
                            *fd,
                            buffer.as_mut_ptr() as *mut CVoid,
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
                    // received < 0: distinguish terminal errors from silence.
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
                    // EAGAIN/EINTR: genuine silence, fall through to retry
                    // budget below.
                }
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
        // Denied retries (cancel/deadline) rejoin the queue unconsumed so
        // they count as unscanned, preserving exact accounting.
        for (port, attempts) in to_requeue.into_iter().rev() {
            queue.push_front((port, attempts));
        }
        // Retries go to the front (deterministic) for the next fill.
        for (port, attempts) in to_retry.into_iter().rev() {
            queue.push_front((port, attempts));
        }
    }
    // Pending dropped here closes all FDs (no leaks). Queue tail plus
    // in-flight probes abandoned on deadline/cancel count as unscanned so
    // `retained + unscanned` accounting stays exact (P11).
    let unscanned = queue.len().saturating_add(pending.len());
    if unscanned > 0 {
        outcome.truncated = true;
    }
    outcome.unscanned = unscanned;
    outcome.probes.sort_by_key(|probe| probe.port);
    outcome
}

/// Portable fallback for Windows/macOS/other: bounded worker-pool UDP
/// probes via `std::net::UdpSocket` with read timeouts. Same evidence
/// semantics (Open on response, Closed on ICMP-refused, OpenOrFiltered on
/// silence, Error on local failure); no raw `poll(2)` linkage.
///
/// Concurrency: `min(max_in_flight, 16)` workers share one queue; one socket
/// per port reused across retries; recv timeout clamped to the remaining
/// global deadline; deterministic sorted output.
#[cfg(not(target_os = "linux"))]
fn scan_ports_udp(
    ip: IpAddr,
    ports: &[u16],
    source: &dyn UdpProbeSource,
    config: &UdpScanConfig,
) -> UdpScanOutcome {
    scan_ports_udp_portable(ip, ports, source, config)
}

/// Portable `recv_from` failure decision (pure, deterministic).
///
/// Evidence contract (never TCP semantics):
/// * Silence (`TimedOut`/`WouldBlock`) with budget remaining ⇒ `Retry`.
/// * Silence exhausted ⇒ `Filtered` (terminal `OpenOrFiltered`).
/// * Explicit normalized `ConnectionRefused` ⇒ `Closed` (positive closure
///   evidence), never retry.
/// * Receive-context truncation (`WSAEMSGSIZE` on `recv_from`
///   only) ⇒ `TruncatedOpen` (positive response evidence, never retry).
/// * Any other local failure ⇒ `Error`, never retry.
///
/// Apple/BSD kernels do not guarantee ICMP port-unreachable delivery on
/// unconnected sockets the way Linux connected sockets do, so silence
/// without closure evidence must stay `OpenOrFiltered` — never inferred
/// `Closed` merely because the test selected an unused local port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortableRecvDecision {
    /// Retryable silence: resend identical payload.
    Retry,
    /// Silence exhausted: terminal `OpenOrFiltered`.
    Filtered,
    /// Positive closure evidence: terminal `Closed`, never retry.
    Closed,
    /// Truncated response evidence: terminal `Open`, never retry.
    ///
    /// Receive context only: Winsock reports a datagram larger than the
    /// supplied receive buffer as `WSAEMSGSIZE (10040)` via `recv_from`
    /// `Err`, while Unix returns truncated `Ok`. Both prove a datagram
    /// arrived. Never parse bytes Rust did not return; never invent length.
    TruncatedOpen,
    /// Local failure: terminal `Error`, never retry.
    Error,
}

/// Receive-context raw OS code proving a datagram arrived but did not fit
/// the supplied receive buffer. Checked ONLY in
/// [`decide_portable_recv_failure`] (portable `recv_from` failures); never
/// added to generic network normalization, where a message-too-large error
/// during `send` has different semantics. Windows-only: raw errno values are
/// platform-specific, and Linux oversized receive is already handled through
/// `Ok(truncated_count)`.
const WSAEMSGSIZE_RAW: i32 = 10040;

/// Pure classifier for portable `recv_from` failures. Production
/// `scan_ports_udp_portable` branches on this; unit tests prove the
/// mapping with synthetic `io::Error`s so no test depends on a kernel
/// surfacing ICMP.
pub fn decide_portable_recv_failure(
    error: &std::io::Error,
    attempts: u32,
    max_retries: u32,
) -> PortableRecvDecision {
    use std::io::ErrorKind;
    // Receive-context truncation first: on Windows `recv_from` surfaces an
    // oversized datagram as `Err(WSAEMSGSIZE)` with no `Ok(n)` bytes, while
    // Unix returns truncated `Ok`. The Windows error proves responsiveness.
    if error.raw_os_error() == Some(WSAEMSGSIZE_RAW) {
        return PortableRecvDecision::TruncatedOpen;
    }
    match error.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => {
            if attempts <= max_retries {
                PortableRecvDecision::Retry
            } else {
                PortableRecvDecision::Filtered
            }
        }
        _ => match crate::platform::network::normalize_io_error(error) {
            crate::execution::ErrorCategory::ConnectionRefused => PortableRecvDecision::Closed,
            _ => PortableRecvDecision::Error,
        },
    }
}

/// Shared portable UDP logic, available on all platforms so Linux tests can
/// prove concurrency/accounting without raw sockets.
#[allow(dead_code)]
fn scan_ports_udp_portable(
    ip: IpAddr,
    ports: &[u16],
    source: &dyn UdpProbeSource,
    config: &UdpScanConfig,
) -> UdpScanOutcome {
    use std::collections::VecDeque;
    use std::net::{SocketAddr, UdpSocket};
    use std::sync::Mutex;
    let mut sorted: Vec<u16> = ports.iter().copied().filter(|port| *port > 0).collect();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.is_empty() {
        return UdpScanOutcome::default();
    }
    let workers = config.max_in_flight.clamp(1, 16);
    let queue = Mutex::new(sorted.into_iter().collect::<VecDeque<u16>>());
    let outcome = Mutex::new(UdpScanOutcome::default());
    let bind_addr: SocketAddr = match ip {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    // `source` and `config` are shared by reference; `thread::scope` keeps
    // lifetimes bounded without `Arc`.
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    // Poison recovery: the queue holds only port numbers, so
                    // a poisoned mutex remains structurally valid. Recover
                    // the guard and keep draining instead of abandoning
                    // queued work. An unexpected worker programmer panic still
                    // propagates via `thread::scope` (no catch_unwind, no
                    // fabricated network evidence).
                    let port = queue.lock().unwrap_or_else(|e| e.into_inner()).pop_front();
                    let Some(port) = port else { return };
                    if config.cancel.is_cancelled() {
                        let mut out = outcome.lock().unwrap_or_else(|e| e.into_inner());
                        out.cancelled = true;
                        out.truncated = true;
                        out.unscanned += 1;
                        continue;
                    }
                    if config.deadline.is_some_and(|d| Instant::now() >= d) {
                        let mut out = outcome.lock().unwrap_or_else(|e| e.into_inner());
                        out.truncated = true;
                        out.unscanned += 1;
                        continue;
                    }
                    let target = SocketAddr::new(ip, port);
                    let payload = source.payload(&ip, port);
                    let started = Instant::now();
                    // One socket per port, reused across silence retries.
                    // Definitive closure never retries (returns below).
                    let socket = match UdpSocket::bind(bind_addr) {
                        Ok(s) => s,
                        Err(error) => {
                            let category =
                                crate::platform::network::normalize_io_error(&error);
                            let mut out = outcome.lock().unwrap_or_else(|e| e.into_inner());
                            out.record(
                                UdpProbe {
                                    port,
                                    state: UdpPortState::Error,
                                    latency: started.elapsed(),
                                    detail: format!(
                                        "UDP socket bind failed ({category}): {error}"
                                    ),
                                    attempts: 1,
                                    protocol: None,
                                    datagrams_sent: 1,
                                    datagrams_received: 0,
                                },
                                config.retain_detail,
                            );
                            continue;
                        }
                    };
                    let mut attempts: u32 = 1;
                    loop {
                        if config.cancel.is_cancelled() {
                            let mut out = outcome.lock().unwrap_or_else(|e| e.into_inner());
                            out.cancelled = true;
                            out.truncated = true;
                            out.unscanned += 1;
                            break;
                        }
                        if config.deadline.is_some_and(|d| Instant::now() >= d) {
                            let mut out = outcome.lock().unwrap_or_else(|e| e.into_inner());
                            out.truncated = true;
                            out.unscanned += 1;
                            break;
                        }
                        // Clamp to remaining global budget so a long per-port
                        // timeout cannot overshoot the scan deadline.
                        let mut recv_timeout =
                            config.timeout.min(Duration::from_secs(5));
                        if let Some(deadline) = config.deadline {
                            let remaining =
                                deadline.saturating_duration_since(Instant::now());
                            if remaining.is_zero() {
                                let mut out =
                                    outcome.lock().unwrap_or_else(|e| e.into_inner());
                                out.truncated = true;
                                out.unscanned += 1;
                                break;
                            }
                            recv_timeout = recv_timeout.min(remaining);
                        }
                        let _ = socket.set_read_timeout(Some(recv_timeout));
                        if let Err(error) = socket.send_to(&payload, target) {
                            let category =
                                crate::platform::network::normalize_io_error(&error);
                            let mut out = outcome.lock().unwrap_or_else(|e| e.into_inner());
                            out.record(
                                UdpProbe {
                                    port,
                                    state: UdpPortState::Error,
                                    latency: started.elapsed(),
                                    detail: format!(
                                        "UDP send to {ip}:{port} failed ({category}): {error}"
                                    ),
                                    attempts,
                                    protocol: None,
                                    datagrams_sent: attempts,
                                    datagrams_received: 0,
                                },
                                config.retain_detail,
                            );
                            break;
                        }
                        {
                            let mut out = outcome.lock().unwrap_or_else(|e| e.into_inner());
                            out.datagrams_sent += 1;
                        }
                        let mut buffer = [0u8; 2048];
                        match socket.recv_from(&mut buffer) {
                            Ok((count, _)) => {
                                let protocol = source.classify(port, &buffer[..count]);
                                let detail = match &protocol {
                                    Some(name) => format!(
                                        "UDP response on {ip}:{port} matched {name}"
                                    ),
                                    None => format!(
                                        "UDP response on {ip}:{port} ({count} bytes, unrecognized)"
                                    ),
                                };
                                let mut out =
                                    outcome.lock().unwrap_or_else(|e| e.into_inner());
                                out.datagrams_received += 1;
                                out.record(
                                    UdpProbe {
                                        port,
                                        state: UdpPortState::Open,
                                        latency: started.elapsed(),
                                        detail,
                                        attempts,
                                        protocol,
                                        datagrams_sent: attempts,
                                        datagrams_received: 1,
                                    },
                                    config.retain_detail,
                                );
                                break;
                            }
                            Err(error) => {
                                match decide_portable_recv_failure(
                                    &error,
                                    attempts,
                                    config.max_retries,
                                ) {
                                    PortableRecvDecision::Retry => {
                                        attempts += 1;
                                        {
                                            let mut out = outcome
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner());
                                            out.retries += 1;
                                        }
                                        continue;
                                    }
                                    PortableRecvDecision::Filtered => {
                                        let mut out =
                                            outcome.lock().unwrap_or_else(|e| e.into_inner());
                                        out.timeouts += 1;
                                        out.record(
                                            UdpProbe {
                                                port,
                                                state: UdpPortState::OpenOrFiltered,
                                                latency: started.elapsed(),
                                                detail: format!(
                                                    "UDP {ip}:{port} silent after {attempts} attempt(s); uncertain, not closed"
                                                ),
                                                attempts,
                                                protocol: None,
                                                datagrams_sent: attempts,
                                                datagrams_received: 0,
                                            },
                                            config.retain_detail,
                                        );
                                        break;
                                    }
                                    PortableRecvDecision::Closed => {
                                        let mut out = outcome
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner());
                                        out.closed_errors += 1;
                                        out.record(
                                            UdpProbe {
                                                port,
                                                state: UdpPortState::Closed,
                                                latency: started.elapsed(),
                                                detail: format!(
                                                    "UDP port unreachable on {ip}:{port}; host responded"
                                                ),
                                                attempts,
                                                protocol: None,
                                                datagrams_sent: attempts,
                                                datagrams_received: 0,
                                            },
                                            config.retain_detail,
                                        );
                                        break;
                                    }
                                    PortableRecvDecision::TruncatedOpen => {
                                        // Receive-context truncation proves a
                                        // datagram arrived: Windows
                                        // `recv_from` reports
                                        // `WSAEMSGSIZE (10040)` as `Err`
                                        // with no `Ok(n)` bytes, while Unix
                                        // returns truncated `Ok`. Rust did
                                        // not return response bytes here, so
                                        // never parse the buffer, never
                                        // invent length/content/protocol.
                                        let mut out = outcome
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner());
                                        out.datagrams_received += 1;
                                        out.record(
                                            UdpProbe {
                                                port,
                                                state: UdpPortState::Open,
                                                latency: started.elapsed(),
                                                detail: format!(
                                                    "UDP response on {ip}:{port} truncated by receive buffer; responsiveness proven, length unknown"
                                                ),
                                                attempts,
                                                protocol: None,
                                                datagrams_sent: attempts,
                                                datagrams_received: 1,
                                            },
                                            config.retain_detail,
                                        );
                                        break;
                                    }
                                    PortableRecvDecision::Error => {
                                        let category =
                                            crate::platform::network::normalize_io_error(&error);
                                        let mut out = outcome
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner());
                                        out.record(
                                            UdpProbe {
                                                port,
                                                state: UdpPortState::Error,
                                                latency: started.elapsed(),
                                                detail: format!(
                                                    "UDP recv on {ip}:{port} failed ({category}): {error}"
                                                ),
                                                attempts,
                                                protocol: None,
                                                datagrams_sent: attempts,
                                                datagrams_received: 0,
                                            },
                                            config.retain_detail,
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }
    });
    // Recover collected outcome on poison (structurally valid counters +
    // probes); never discard completed evidence.
    let mut outcome = outcome.into_inner().unwrap_or_else(|e| e.into_inner());
    outcome.fd_peak = workers;
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
        // Real-socket smoke: Apple/BSD kernels do not guarantee ICMP
        // port-unreachable delivery on unconnected sockets, so a closed
        // loopback port may surface as `Closed` (positive refusal) or as
        // `OpenOrFiltered` (silence without closure evidence). Both are
        // honest evidence outcomes; only `Open`/`Error` would fabricate.
        // Never infer `Closed` merely because the port was unused.
        let outcome = NativeUdpScanner.scan(
            "127.0.0.1".parse().unwrap(),
            &[closed_port()],
            &EmptySource,
            &test_config(500, 0),
        );
        assert_eq!(outcome.probes.len(), 1);
        let probe = &outcome.probes[0];
        assert!(
            matches!(
                probe.state,
                UdpPortState::Closed | UdpPortState::OpenOrFiltered
            ),
            "real-socket closed-port smoke must be Closed (refusal) or OpenOrFiltered (silence), got {:?}",
            probe.state
        );
        // Evidence accounting stays exact for whichever outcome the kernel
        // surfaced; definitive closure never retries.
        match probe.state {
            UdpPortState::Closed => {
                assert_eq!(probe.attempts, 1);
                assert_eq!(outcome.retries, 0);
                assert_eq!(outcome.closed_errors, 1);
            }
            UdpPortState::OpenOrFiltered => {
                assert_eq!(probe.attempts, 1);
                assert_eq!(outcome.retries, 0);
                assert_eq!(outcome.timeouts, 1);
            }
            _ => unreachable!("guarded above"),
        }
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

    /// Release-gate regression (real-socket smoke): definitive CLOSED never
    /// retries, even when a retry budget is available. On kernels that do
    /// not surface ICMP to unconnected sockets the same port honestly
    /// reports silence (`OpenOrFiltered`) with exactly one budgeted retry;
    /// that silence path must never be misread as closure. Deterministic
    /// proof that explicit refusal maps to `Closed` with zero retries lives
    /// in `explicit_closed_never_retries_with_budget` below.
    #[test]
    fn closed_never_retries_even_with_budget() {
        let outcome = NativeUdpScanner.scan(
            "127.0.0.1".parse().unwrap(),
            &[closed_port()],
            &EmptySource,
            &test_config(500, 1),
        );
        assert_eq!(outcome.probes.len(), 1);
        let probe = &outcome.probes[0];
        assert!(
            matches!(
                probe.state,
                UdpPortState::Closed | UdpPortState::OpenOrFiltered
            ),
            "closed-port smoke must be Closed or OpenOrFiltered, got {:?}",
            probe.state
        );
        match probe.state {
            UdpPortState::Closed => {
                assert_eq!(probe.attempts, 1);
                assert_eq!(outcome.retries, 0);
            }
            UdpPortState::OpenOrFiltered => {
                // Silence honestly uses the single budgeted retry.
                assert_eq!(probe.attempts, 2);
                assert_eq!(outcome.retries, 1);
            }
            _ => unreachable!("guarded above"),
        }
    }

    /// Deterministic: explicit closure evidence maps to `Closed`.
    /// Synthetic `ConnectionRefused` inputs stand in for OS-surfaced
    /// ICMP/port-unreachable; silence inputs must never map to `Closed`.
    #[test]
    fn explicit_closure_evidence_maps_to_closed() {
        use std::io::{Error, ErrorKind};
        // Portable kind-form refusal (synthetic, no live network).
        let refused = Error::new(ErrorKind::ConnectionRefused, "synthetic port unreachable");
        assert_eq!(
            decide_portable_recv_failure(&refused, 1, 1),
            PortableRecvDecision::Closed
        );
        assert_eq!(
            decide_portable_recv_failure(&refused, 1, 0),
            PortableRecvDecision::Closed
        );
        // Silence is uncertainty, never closure: timeout with and without
        // budget maps to retry/filtered, never `Closed`.
        let timeout = Error::new(ErrorKind::TimedOut, "synthetic silence");
        assert_eq!(
            decide_portable_recv_failure(&timeout, 1, 1),
            PortableRecvDecision::Retry
        );
        assert_eq!(
            decide_portable_recv_failure(&timeout, 2, 1),
            PortableRecvDecision::Filtered
        );
        let would_block = Error::new(ErrorKind::WouldBlock, "synthetic silence");
        assert_eq!(
            decide_portable_recv_failure(&would_block, 1, 1),
            PortableRecvDecision::Retry
        );
        // Local failures are `Error`, never `Closed`, even with budget.
        let local = Error::new(ErrorKind::InvalidInput, "synthetic bad socket");
        assert_eq!(
            decide_portable_recv_failure(&local, 1, 1),
            PortableRecvDecision::Error
        );
    }

    /// Deterministic: explicit `Closed`/`ConnectionRefused` evidence admits
    /// ZERO retries even when retry budget > 0. Only silence retries, and
    /// only within budget.
    #[test]
    fn explicit_closed_never_retries_with_budget() {
        use std::io::{Error, ErrorKind};
        let refused = Error::new(ErrorKind::ConnectionRefused, "synthetic port unreachable");
        // Budget available, yet refusal is terminal: never `Retry`.
        for attempts in [1, 2] {
            assert_ne!(
                decide_portable_recv_failure(&refused, attempts, 1),
                PortableRecvDecision::Retry,
                "closure evidence must never admit a retry (attempts={attempts})"
            );
            assert_eq!(
                decide_portable_recv_failure(&refused, attempts, 1),
                PortableRecvDecision::Closed
            );
        }
        // Contrast: silence DOES retry while budget remains, then filters.
        let silence = Error::new(ErrorKind::TimedOut, "synthetic silence");
        assert_eq!(
            decide_portable_recv_failure(&silence, 1, 1),
            PortableRecvDecision::Retry
        );
        assert_eq!(
            decide_portable_recv_failure(&silence, 2, 1),
            PortableRecvDecision::Filtered
        );
        // Local errors never retry either, even with budget.
        let local = Error::new(ErrorKind::InvalidInput, "synthetic bad socket");
        assert_eq!(
            decide_portable_recv_failure(&local, 1, 1),
            PortableRecvDecision::Error
        );
    }

    /// Deterministic: receive-context truncation maps to `TruncatedOpen`.
    /// Synthetic `WSAEMSGSIZE (10040)` stands in for the Windows-surfaced
    /// oversized-datagram signal on `recv_from` only. It proves a datagram
    /// arrived, so production records `Open` with
    /// `datagrams_received == 1`, never retry/Closed/Filtered/Error, and
    /// never invents length/content/protocol.
    #[test]
    fn wsaemsgsize_receive_means_truncated_open() {
        use std::io::Error;
        const CODE: i32 = 10040;
        for (attempts, max_retries) in [(1, 0), (1, 1), (2, 1)] {
            let error = Error::from_raw_os_error(CODE);
            assert_eq!(
                decide_portable_recv_failure(&error, attempts, max_retries),
                PortableRecvDecision::TruncatedOpen,
                "receive-context raw {CODE} must be truncated-open (attempts={attempts})"
            );
            assert_ne!(
                decide_portable_recv_failure(&error, attempts, max_retries),
                PortableRecvDecision::Retry,
                "truncation evidence must never admit a retry (raw {CODE})"
            );
            assert_ne!(
                decide_portable_recv_failure(&error, attempts, max_retries),
                PortableRecvDecision::Closed,
                "truncation is responsiveness, not closure (raw {CODE})"
            );
            assert_ne!(
                decide_portable_recv_failure(&error, attempts, max_retries),
                PortableRecvDecision::Filtered,
                "truncation is responsiveness, not silence (raw {CODE})"
            );
            assert_ne!(
                decide_portable_recv_failure(&error, attempts, max_retries),
                PortableRecvDecision::Error,
                "truncation is responsiveness, not local failure (raw {CODE})"
            );
        }
        // Accounting the production `TruncatedOpen` arm performs: terminal
        // `Open`, exactly one receipt, no retry, no invented bytes/protocol.
        let mut outcome = UdpScanOutcome::default();
        outcome.datagrams_received += 1;
        outcome.record(
            UdpProbe {
                port: 9999,
                state: UdpPortState::Open,
                latency: Duration::ZERO,
                detail:
                    "UDP response on 127.0.0.1:9999 truncated by receive buffer; responsiveness proven, length unknown"
                        .to_owned(),
                attempts: 1,
                protocol: None,
                datagrams_sent: 1,
                datagrams_received: 1,
            },
            true,
        );
        assert_eq!(outcome.open_count, 1);
        assert_eq!(outcome.closed_count, 0);
        assert_eq!(outcome.filtered_count, 0);
        assert_eq!(outcome.error_count, 0);
        assert_eq!(outcome.datagrams_received, 1);
        assert_eq!(outcome.retries, 0);
        assert_eq!(outcome.probes.len(), 1);
        assert_eq!(outcome.probes[0].state, UdpPortState::Open);
        assert_eq!(outcome.probes[0].datagrams_received, 1);
        assert_eq!(outcome.probes[0].protocol, None);
    }

    /// Release-gate regression: a valid response never retries, even with
    /// budget available. Exactly one attempt, zero retries.
    #[test]
    fn valid_response_never_retries_with_budget() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = std::thread::spawn(move || {
            server
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while !stop_thread.load(Ordering::SeqCst) && Instant::now() < deadline {
                let mut buf = [0u8; 2048];
                if let Ok((count, addr)) = server.recv_from(&mut buf) {
                    let _ = server.send_to(&buf[..count.min(8)], addr);
                }
            }
        });
        let outcome = NativeUdpScanner.scan(
            "127.0.0.1".parse().unwrap(),
            &[port],
            &EmptySource,
            &test_config(2000, 1),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        assert_eq!(outcome.probes.len(), 1);
        assert_eq!(outcome.probes[0].state, UdpPortState::Open);
        assert_eq!(outcome.probes[0].attempts, 1);
        assert_eq!(outcome.retries, 0);
    }

    /// Release-gate regression: silence without budget never retries.
    #[test]
    fn silence_without_budget_never_retries() {
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
        assert_eq!(outcome.probes[0].state, UdpPortState::OpenOrFiltered);
        assert_eq!(outcome.probes[0].attempts, 1);
        assert_eq!(outcome.retries, 0);
    }

    /// Release-gate regression: non-retryable local errors never retry,
    /// even with budget available.
    #[test]
    fn non_retryable_send_error_never_retries() {
        struct OversizedSource;
        impl UdpProbeSource for OversizedSource {
            fn payload(&self, _ip: &IpAddr, _port: u16) -> Vec<u8> {
                vec![0u8; 70_000]
            }
            fn classify(&self, _port: u16, _response: &[u8]) -> Option<String> {
                None
            }
        }
        let outcome = NativeUdpScanner.scan(
            "127.0.0.1".parse().unwrap(),
            &[closed_port()],
            &OversizedSource,
            &test_config(500, 1),
        );
        assert_eq!(outcome.probes.len(), 1);
        assert_eq!(outcome.probes[0].state, UdpPortState::Error);
        assert_eq!(outcome.probes[0].attempts, 1);
        assert_eq!(outcome.retries, 0);
    }

    /// Release-gate regression: retryable silence never exceeds the
    /// configured attempt budget (initial + at most `max_retries`).
    #[test]
    fn retryable_silence_never_exceeds_budget() {
        let holders: Vec<UdpSocket> = (0..3)
            .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect();
        let ports: Vec<u16> = holders
            .iter()
            .map(|socket| socket.local_addr().unwrap().port())
            .collect();
        let outcome = NativeUdpScanner.scan(
            "127.0.0.1".parse().unwrap(),
            &ports,
            &EmptySource,
            &test_config(300, 1),
        );
        drop(holders);
        assert_eq!(outcome.probes.len(), 3);
        for probe in &outcome.probes {
            assert_eq!(probe.state, UdpPortState::OpenOrFiltered);
            assert_eq!(probe.attempts, 2, "silence uses exactly budget 1+1");
            assert!(probe.attempts <= 1 + 1);
        }
        assert_eq!(outcome.retries, 3);
        assert_eq!(outcome.datagrams_sent, 6);
    }

    /// Release-gate regression: cancellation admits no new retries.
    #[test]
    fn cancelled_scan_admits_no_new_retries() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let token = CancellationToken::default();
        token.cancel();
        let config = UdpScanConfig::bounded(Duration::from_millis(300), 16, 1, None, token);
        let outcome =
            NativeUdpScanner.scan("127.0.0.1".parse().unwrap(), &[port], &EmptySource, &config);
        drop(server);
        assert!(outcome.cancelled);
        assert_eq!(outcome.retries, 0);
        assert_eq!(outcome.unscanned, 1);
        assert!(outcome.probes.is_empty());
    }

    /// Release-gate regression: an already-expired overall deadline admits
    /// no new retries.
    #[test]
    fn expired_deadline_admits_no_new_retries() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let past = Instant::now() - Duration::from_secs(1);
        let config = UdpScanConfig::bounded(
            Duration::from_millis(300),
            16,
            1,
            Some(past),
            CancellationToken::default(),
        );
        let outcome =
            NativeUdpScanner.scan("127.0.0.1".parse().unwrap(), &[port], &EmptySource, &config);
        drop(server);
        assert_eq!(outcome.retries, 0);
        assert!(outcome.truncated);
        assert!(outcome.unscanned >= 1);
    }

    /// Tracking source to prove portable concurrency without wall-clock
    /// thresholds: records max concurrent payload calls.
    struct TrackingSource {
        active: Arc<AtomicUsize>,
        max_active: Arc<AtomicUsize>,
    }

    impl UdpProbeSource for TrackingSource {
        fn payload(&self, _ip: &IpAddr, _port: u16) -> Vec<u8> {
            let cur = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(cur, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(120));
            self.active.fetch_sub(1, Ordering::SeqCst);
            Vec::new()
        }
        fn classify(&self, _port: u16, _response: &[u8]) -> Option<String> {
            None
        }
    }

    #[test]
    fn portable_progress_is_concurrent_and_ordered() {
        // Silent holders keep ports OpenOrFiltered; payload overlap proves
        // worker-pool concurrency (sequential would keep max==1).
        let holders: Vec<UdpSocket> = (0..6)
            .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect();
        let ports: Vec<u16> = holders
            .iter()
            .map(|s| s.local_addr().unwrap().port())
            .collect();
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let source = TrackingSource {
            active: active.clone(),
            max_active: max_active.clone(),
        };
        let config = UdpScanConfig::bounded(
            Duration::from_millis(400),
            16,
            0,
            None,
            CancellationToken::default(),
        );
        let outcome =
            scan_ports_udp_portable("127.0.0.1".parse().unwrap(), &ports, &source, &config);
        drop(holders);
        assert_eq!(outcome.probes.len(), 6);
        assert!(
            max_active.load(Ordering::SeqCst) >= 2,
            "expected concurrent payloads, max={}",
            max_active.load(Ordering::SeqCst)
        );
        let got: Vec<u16> = outcome.probes.iter().map(|p| p.port).collect();
        let mut expected = got.clone();
        expected.sort_unstable();
        assert_eq!(got, expected);
        assert!(
            outcome
                .probes
                .iter()
                .all(|p| p.state == UdpPortState::OpenOrFiltered)
        );
    }

    #[test]
    fn portable_deadline_clamps_and_preserves_accounting() {
        let holders: Vec<UdpSocket> = (0..2)
            .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect();
        let ports: Vec<u16> = holders
            .iter()
            .map(|s| s.local_addr().unwrap().port())
            .collect();
        // Deadline 150ms with 500ms per-port timeout: must truncate quickly,
        // not overshoot to 1000ms sequential.
        let deadline = Instant::now() + Duration::from_millis(150);
        let config = UdpScanConfig::bounded(
            Duration::from_millis(500),
            8,
            1,
            Some(deadline),
            CancellationToken::default(),
        );
        let start = Instant::now();
        let outcome =
            scan_ports_udp_portable("127.0.0.1".parse().unwrap(), &ports, &EmptySource, &config);
        drop(holders);
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(1200),
            "deadline not respected: {elapsed:?}"
        );
        assert_eq!(
            outcome.probes.len() + outcome.unscanned,
            2,
            "exact accounting"
        );
    }

    #[test]
    fn portable_cancellation_is_prompt_and_exact() {
        let token = CancellationToken::default();
        token.cancel();
        let config = UdpScanConfig::bounded(Duration::from_millis(300), 8, 1, None, token);
        let outcome = scan_ports_udp_portable(
            "127.0.0.1".parse().unwrap(),
            &[4000, 4001, 4002],
            &EmptySource,
            &config,
        );
        assert!(outcome.cancelled);
        assert_eq!(outcome.unscanned, 3);
        assert!(outcome.probes.is_empty());
    }
}
