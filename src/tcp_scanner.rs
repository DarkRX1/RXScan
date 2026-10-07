//! Native TCP connect scanner: one scheduler task, bounded internal work.
//!
//! Boundary (documented):
//! * The scheduler coordinates target-level `PortDiscovery` tasks (one per
//!   target, never 65k tasks for `--all-ports`).
//! * This scanner manages strictly bounded per-port work inside the task:
//!   a sliding window of non-blocking connects multiplexed with `poll(2)`.
//!   No OS thread per port; at most `max_concurrent` sockets at once
//!   (speed-derived 16..=128, hard-capped 256).
//!
//! Every attempt honors timeout, cancellation (prompt, ~25ms poll slices),
//! bounded retries (only timeout/filtered, at most one retry), overall task
//! deadline, and immediate FD cleanup. Results return sorted by port for
//! deterministic output.

#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::execution::CancellationToken;

// ---- Linux raw constants (Linux-only; other platforms use the portable
// ---- std fallback below and never link these symbols) ---
#[cfg(target_os = "linux")]
mod linux_raw {
    use std::os::raw::{c_int, c_void};
    pub use std::os::raw::{c_int as CInt, c_void as CVoid};
    pub const AF_INET: c_int = 2;
    pub const AF_INET6: c_int = 10;
    pub const SOCK_STREAM: c_int = 1;
    pub const IPPROTO_TCP: c_int = 6;
    pub const F_GETFL: c_int = 3;
    pub const F_SETFL: c_int = 4;
    pub const O_NONBLOCK: c_int = 2048;
    pub const EINPROGRESS: c_int = 115;
    pub const EINTR: c_int = 4;
    pub const EAGAIN: c_int = 11;
    pub const ECONNREFUSED: c_int = 111;
    pub const ECONNRESET: c_int = 104;
    pub const ETIMEDOUT: c_int = 110;
    pub const EHOSTUNREACH: c_int = 113;
    pub const ENETUNREACH: c_int = 101;
    pub const EACCES: c_int = 13;
    pub const EPERM: c_int = 1;
    pub const EMFILE: c_int = 24;
    pub const ENFILE: c_int = 23;
    pub const ENOMEM: c_int = 12;
    pub const POLLOUT: i16 = 0x0004;
    pub const POLLERR: i16 = 0x0008;
    pub const POLLHUP: i16 = 0x0010;
    pub const SOL_SOCKET: c_int = 1;
    pub const SO_ERROR: c_int = 4;

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

/// Explicit per-port conclusion. Timeouts stay distinct from closed.
/// `FilteredOrTimedOut` is the legacy connect-scan label for silence;
/// new code prefers `OpenOrFiltered` (silence proves neither open nor
/// closed). `Filtered` requires positive filtered evidence (ICMP
/// admin-prohibited or equivalent); `Unknown` means no conclusion was
/// reached within budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    FilteredOrTimedOut,
    Filtered,
    OpenOrFiltered,
    Unknown,
    Error,
}

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Closed => write!(f, "closed"),
            Self::FilteredOrTimedOut => write!(f, "filtered_or_timed_out"),
            Self::Filtered => write!(f, "filtered"),
            Self::OpenOrFiltered => write!(f, "open_or_filtered"),
            Self::Unknown => write!(f, "unknown"),
            Self::Error => write!(f, "error"),
        }
    }
}

impl PortState {
    pub fn is_silence(self) -> bool {
        matches!(
            self,
            Self::FilteredOrTimedOut | Self::Filtered | Self::OpenOrFiltered | Self::Unknown
        )
    }
}

/// One port's final probe record.
#[derive(Debug, Clone)]
pub struct PortProbe {
    pub port: u16,
    pub state: PortState,
    pub latency: Duration,
    pub detail: String,
    pub attempts: u32,
}

/// Scanner configuration (all bounds enforced by caller + clamped here).
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub timeout: Duration,
    pub max_concurrent: usize,
    /// Retries for timeout/filtered only (0 or 1). Refused/open never retry.
    pub max_retries: u32,
    pub deadline: Option<Instant>,
    pub cancel: CancellationToken,
}

impl ScanConfig {
    pub fn bounded(
        timeout: Duration,
        max_concurrent: usize,
        max_retries: u32,
        deadline: Option<Instant>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            timeout: timeout.clamp(Duration::from_millis(100), Duration::from_secs(10)),
            max_concurrent: max_concurrent.clamp(1, crate::ports::MAX_TCP_CONCURRENCY_HARD),
            max_retries: max_retries.min(1),
            deadline,
            cancel,
        }
    }
}

/// Outcome of one `scan` call (partial on cancel/deadline, sorted by port).
#[derive(Debug, Clone)]
pub struct ScanOutcome {
    pub probes: Vec<PortProbe>,
    pub truncated: bool,
    pub cancelled: bool,
    /// Ports never attempted due to deadline/cancel (for evidence counts).
    pub unscanned: usize,
    /// Peak simultaneously held in-flight sockets during the scan.
    ///
    /// Phase 19 observability: always `<= ScanConfig::max_concurrent <=
    /// MAX_TCP_CONCURRENCY_HARD` (256). Immediate-refused connects hold
    /// their descriptor only transiently and are not counted here; the
    /// sustained descriptor pressure that matters for EMFILE bounding is
    /// exactly `pending.len()`.
    pub fd_peak: usize,
}

/// Trait for port scanning (real non-blocking + fakes for tests).
pub trait PortScanner: Send + Sync {
    fn scan(&self, ip: IpAddr, ports: &[u16], config: &ScanConfig) -> ScanOutcome;
    /// Runtime fallback note (e.g. SYN requested but connect executed).
    /// `None` when the executed mechanism matches the configured one.
    fn runtime_note(&self) -> Option<String> {
        None
    }
    /// Actual mechanism used per address (`syn` or `connect`). Defaults to
    /// connect; scanners with multiple mechanisms override.
    fn address_mechanisms(&self) -> Vec<(IpAddr, String)> {
        Vec::new()
    }
    /// Adaptive pacing decisions from the most recent scans (bounded).
    /// Empty when the scanner uses fixed policy windows.
    fn pacing_log(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Native non-blocking connect scanner (unprivileged baseline, no raw SYN).
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeTcpScanner;

impl PortScanner for NativeTcpScanner {
    fn scan(&self, ip: IpAddr, ports: &[u16], config: &ScanConfig) -> ScanOutcome {
        scan_ports_nonblocking(ip, ports, config)
    }
}

#[cfg(target_os = "linux")]
struct Pending {
    port: u16,
    #[allow(dead_code)]
    fd: OwnedFd,
    started: Instant,
    port_deadline: Instant,
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
#[allow(clippy::too_many_lines)]
fn scan_ports_nonblocking(ip: IpAddr, ports: &[u16], config: &ScanConfig) -> ScanOutcome {
    // Normalize deterministically; port 0 never scanned.
    let mut queue: VecDeque<(u16, u32)> = {
        let mut sorted: Vec<u16> = ports.iter().copied().filter(|port| *port > 0).collect();
        sorted.sort_unstable();
        sorted.dedup();
        sorted.into_iter().map(|port| (port, 1)).collect()
    };
    let total = queue.len();
    let mut probes: Vec<PortProbe> = Vec::with_capacity(total.min(1024));
    let mut pending: BTreeMap<CInt, Pending> = BTreeMap::new();
    let mut truncated = false;
    let mut cancelled = false;
    // Phase 19: peak in-flight socket observability (O(1) counter).
    let mut fd_peak = 0usize;
    let mut backoff_until = Instant::now();

    let overall_deadline = config.deadline;
    let is_expired = |now: Instant| overall_deadline.is_some_and(|deadline| now >= deadline);

    'outer: while !queue.is_empty() || !pending.is_empty() {
        if config.cancel.is_cancelled() {
            cancelled = true;
            truncated = true;
            break;
        }
        let now = Instant::now();
        if is_expired(now) {
            truncated = true;
            break;
        }
        // Fill window up to max_concurrent.
        while pending.len() < config.max_concurrent {
            let Some((port, attempts)) = queue.pop_front() else {
                break;
            };
            if config.cancel.is_cancelled() {
                queue.push_front((port, attempts));
                cancelled = true;
                truncated = true;
                break 'outer;
            }
            let now = Instant::now();
            if is_expired(now) {
                queue.push_front((port, attempts));
                truncated = true;
                break 'outer;
            }
            // FD-exhaustion backoff: pause new connects briefly.
            if Instant::now() < backoff_until {
                queue.push_front((port, attempts));
                break;
            }
            let domain = match ip {
                IpAddr::V4(_) => AF_INET,
                IpAddr::V6(_) => AF_INET6,
            };
            let raw = unsafe { socket(domain, SOCK_STREAM, IPPROTO_TCP) };
            let Some(fd) = OwnedFd::new(raw) else {
                let errno = last_errno();
                if errno == EMFILE || errno == ENFILE || errno == ENOMEM {
                    backoff_until = Instant::now() + Duration::from_millis(20);
                    queue.push_front((port, attempts));
                    break;
                }
                probes.push(PortProbe {
                    port,
                    state: PortState::Error,
                    latency: Duration::ZERO,
                    detail: format!("socket creation failed (errno {errno})"),
                    attempts,
                });
                continue;
            };
            if !set_nonblocking(fd.0) {
                probes.push(PortProbe {
                    port,
                    state: PortState::Error,
                    latency: Duration::ZERO,
                    detail: "failed to set non-blocking socket".to_owned(),
                    attempts,
                });
                continue;
            }
            let (addr_bytes, addr_len) = sockaddr_for(&ip, port);
            let started = Instant::now();
            let port_deadline = started + config.timeout;
            let result = unsafe { connect(fd.0, addr_bytes.as_ptr() as *const CVoid, addr_len) };
            if result == 0 {
                let latency = started.elapsed();
                probes.push(PortProbe {
                    port,
                    state: PortState::Open,
                    latency,
                    detail: format!("TCP connect to {ip}:{port} succeeded"),
                    attempts,
                });
                continue;
            }
            let errno = last_errno();
            match errno {
                0 => {
                    let latency = started.elapsed();
                    probes.push(PortProbe {
                        port,
                        state: PortState::Open,
                        latency,
                        detail: format!("TCP connect to {ip}:{port} succeeded"),
                        attempts,
                    });
                }
                e if e == EINPROGRESS || e == EAGAIN => {
                    pending.insert(
                        fd.0,
                        Pending {
                            port,
                            fd,
                            started,
                            port_deadline,
                            attempts,
                        },
                    );
                    fd_peak = fd_peak.max(pending.len());
                }
                e if e == EINTR => {
                    // Single immediate retry for interrupted connects.
                    let retry =
                        unsafe { connect(fd.0, addr_bytes.as_ptr() as *const CVoid, addr_len) };
                    if retry == 0 {
                        probes.push(PortProbe {
                            port,
                            state: PortState::Open,
                            latency: started.elapsed(),
                            detail: format!("TCP connect to {ip}:{port} succeeded"),
                            attempts,
                        });
                    } else {
                        let errno2 = last_errno();
                        if errno2 == EINPROGRESS || errno2 == EAGAIN {
                            pending.insert(
                                fd.0,
                                Pending {
                                    port,
                                    fd,
                                    started,
                                    port_deadline,
                                    attempts,
                                },
                            );
                            fd_peak = fd_peak.max(pending.len());
                        } else {
                            probes.push(classify_immediate(ip, port, errno2, started, attempts));
                        }
                    }
                }
                other => {
                    probes.push(classify_immediate(ip, port, other, started, attempts));
                }
            }
        }
        if pending.is_empty() {
            // Nothing to poll (all immediate or backoff); loop to refill.
            if !queue.is_empty() && Instant::now() < backoff_until {
                std::thread::sleep(Duration::from_millis(5));
            }
            continue;
        }
        // Poll with a short slice so cancellation/deadlines stay prompt.
        let now = Instant::now();
        let next_deadline = pending
            .values()
            .map(|item| item.port_deadline)
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
                events: POLLOUT,
                revents: 0,
            })
            .collect();
        let ready = unsafe { poll(poll_fds.as_mut_ptr(), poll_fds.len() as u64, poll_timeout) };
        if config.cancel.is_cancelled() {
            cancelled = true;
            truncated = true;
            break;
        }
        if is_expired(Instant::now()) {
            truncated = true;
            break;
        }
        if ready < 0 {
            let errno = last_errno();
            if errno == EINTR {
                continue;
            }
            // Poll failure degrades to per-port timeout handling below.
        }
        let ready_map: BTreeMap<CInt, i16> = poll_fds
            .iter()
            .map(|item| (item.fd, item.revents))
            .collect();
        let now = Instant::now();
        let mut finished: Vec<CInt> = Vec::new();
        let mut to_retry: Vec<(u16, u32)> = Vec::new();
        for (fd, item) in pending.iter() {
            let revents = ready_map.get(fd).copied().unwrap_or(0);
            let signalled = (revents & (POLLOUT | POLLERR | POLLHUP)) != 0;
            if signalled {
                let error = socket_error(*fd);
                match error {
                    0 => probes.push(PortProbe {
                        port: item.port,
                        state: PortState::Open,
                        latency: item.started.elapsed(),
                        detail: format!("TCP connect to {}:{} succeeded", ip, item.port),
                        attempts: item.attempts,
                    }),
                    e if e == ECONNREFUSED || e == ECONNRESET => probes.push(PortProbe {
                        port: item.port,
                        state: PortState::Closed,
                        latency: item.started.elapsed(),
                        detail: format!(
                            "TCP connection refused/reset on {}:{} (errno {e}); host responded, port closed",
                            ip, item.port
                        ),
                        attempts: item.attempts,
                    }),
                    e if e == ETIMEDOUT => {
                        if item.attempts <= config.max_retries {
                            to_retry.push((item.port, item.attempts + 1));
                        } else {
                            probes.push(PortProbe {
                                port: item.port,
                                state: PortState::FilteredOrTimedOut,
                                latency: item.started.elapsed(),
                                detail: format!(
                                    "TCP connect to {}:{} timed out (errno {e})",
                                    ip, item.port
                                ),
                                attempts: item.attempts,
                            });
                        }
                    }
                    e if e == EHOSTUNREACH || e == ENETUNREACH => probes.push(PortProbe {
                        port: item.port,
                        state: PortState::Error,
                        latency: item.started.elapsed(),
                        detail: format!(
                            "TCP connect to {}:{} unreachable (errno {e})",
                            ip, item.port
                        ),
                        attempts: item.attempts,
                    }),
                    e => probes.push(PortProbe {
                        port: item.port,
                        state: PortState::Error,
                        latency: item.started.elapsed(),
                        detail: format!(
                            "TCP connect to {}:{} failed (errno {e})",
                            ip, item.port
                        ),
                        attempts: item.attempts,
                    }),
                }
                finished.push(*fd);
            } else if now >= item.port_deadline {
                if item.attempts <= config.max_retries {
                    to_retry.push((item.port, item.attempts + 1));
                } else {
                    probes.push(PortProbe {
                        port: item.port,
                        state: PortState::FilteredOrTimedOut,
                        latency: item.started.elapsed(),
                        detail: format!(
                            "TCP connect to {}:{} timed out after {}ms",
                            ip,
                            item.port,
                            config.timeout.as_millis()
                        ),
                        attempts: item.attempts,
                    });
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
    // plus in-flight probes abandoned on deadline/cancel count as unscanned
    // so `probes.len() + unscanned == requested` always holds (P11). Pending
    // probes had socket operations but no conclusion; reporting them as
    // unscanned (never attempted to completion) keeps `attempted =
    // requested - unscanned` exact.
    let unscanned = queue.len().saturating_add(pending.len());
    if unscanned > 0 {
        truncated = true;
    }
    probes.sort_by_key(|probe| probe.port);
    ScanOutcome {
        probes,
        truncated,
        cancelled,
        unscanned,
        fd_peak,
    }
}

#[cfg(target_os = "linux")]
fn classify_immediate(
    ip: IpAddr,
    port: u16,
    errno: CInt,
    started: Instant,
    attempts: u32,
) -> PortProbe {
    let latency = started.elapsed();
    match errno {
        e if e == ECONNREFUSED || e == ECONNRESET => PortProbe {
            port,
            state: PortState::Closed,
            latency,
            detail: format!(
                "TCP connection refused/reset on {ip}:{port} (errno {e}); host responded, port closed"
            ),
            attempts,
        },
        e if e == ETIMEDOUT => PortProbe {
            port,
            state: PortState::FilteredOrTimedOut,
            latency,
            detail: format!("TCP connect to {ip}:{port} timed out (errno {e})"),
            attempts,
        },
        e if e == EHOSTUNREACH || e == ENETUNREACH => PortProbe {
            port,
            state: PortState::Error,
            latency,
            detail: format!("TCP connect to {ip}:{port} unreachable (errno {e})"),
            attempts,
        },
        e if e == EACCES || e == EPERM => PortProbe {
            port,
            state: PortState::Error,
            latency,
            detail: format!("TCP connect to {ip}:{port} permission/resource error (errno {e})"),
            attempts,
        },
        e => PortProbe {
            port,
            state: PortState::Error,
            latency,
            detail: format!("TCP connect to {ip}:{port} failed (errno {e})"),
            attempts,
        },
    }
}

/// Portable fallback for Windows/macOS/other: bounded worker-pool
/// `TcpStream::connect_timeout` per port. Same evidence semantics
/// (Open/Closed/FilteredOrTimedOut/Error) via normalized errors; no raw
/// `poll(2)` linkage required.
///
/// Concurrency: `min(config.max_concurrent, 32)` workers pull from a shared
/// queue (no thread-per-port, bounded FD use). Results sorted for
/// determinism; cancellation/deadline checked before each port and retry.
#[cfg(not(target_os = "linux"))]
fn scan_ports_nonblocking(ip: IpAddr, ports: &[u16], config: &ScanConfig) -> ScanOutcome {
    scan_ports_portable_with_connector(ip, ports, config, &StdTcpConnector)
}

/// Injectable TCP connector for portable scans (production + tests).
/// Available on all platforms so Linux tests can prove the portable
/// worker-pool logic without raw sockets or external network.
pub trait TcpConnector: Send + Sync {
    fn connect(
        &self,
        addr: std::net::SocketAddr,
        timeout: Duration,
    ) -> std::io::Result<std::net::TcpStream>;
}

/// Production connector: std `connect_timeout` via the platform helper.
pub struct StdTcpConnector;

impl TcpConnector for StdTcpConnector {
    fn connect(
        &self,
        addr: std::net::SocketAddr,
        timeout: Duration,
    ) -> std::io::Result<std::net::TcpStream> {
        crate::platform::network::tcp_connect(addr, timeout)
    }
}

#[allow(dead_code)]
fn scan_ports_portable_with_connector(
    ip: IpAddr,
    ports: &[u16],
    config: &ScanConfig,
    connector: &dyn TcpConnector,
) -> ScanOutcome {
    // Allowed dead on Linux production (tested via unit tests); used on
    // Windows/macOS/other.
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    let mut sorted: Vec<u16> = ports.iter().copied().filter(|port| *port > 0).collect();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.is_empty() {
        return ScanOutcome {
            probes: Vec::new(),
            truncated: false,
            cancelled: false,
            unscanned: 0,
            fd_peak: 0,
        };
    }
    let workers = config.max_concurrent.clamp(1, 32);
    let queue = Mutex::new(sorted.into_iter().collect::<VecDeque<u16>>());
    let probes = Mutex::new(Vec::new());
    let unscanned = AtomicUsize::new(0);
    let saw_cancelled = AtomicBool::new(false);
    let saw_truncated = AtomicBool::new(false);
    let queue_ref = &queue;
    let probes_ref = &probes;
    let unscanned_ref = &unscanned;
    let saw_cancelled_ref = &saw_cancelled;
    let saw_truncated_ref = &saw_truncated;
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(move || {
                loop {
                    // Poison recovery: the queue holds only port numbers, so a
                    // poisoned mutex remains structurally valid. Recover the
                    // guard and keep draining instead of abandoning queued
                    // work. An unexpected worker programmer panic still
                    // propagates via `thread::scope` (no catch_unwind, no
                    // fabricated network evidence).
                    let port = queue_ref
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .pop_front();
                    let Some(port) = port else { return };
                    if config.cancel.is_cancelled() {
                        saw_cancelled_ref.store(true, Ordering::Release);
                        saw_truncated_ref.store(true, Ordering::Release);
                        unscanned_ref.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if config.deadline.is_some_and(|d| Instant::now() >= d) {
                        saw_truncated_ref.store(true, Ordering::Release);
                        unscanned_ref.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let addr = SocketAddr::new(ip, port);
                    // Per-attempt timeout clamped to remaining global budget.
                    let remaining = config
                        .deadline
                        .map(|d| d.saturating_duration_since(Instant::now()));
                    if remaining.is_some_and(|r| r.is_zero()) {
                        saw_truncated_ref.store(true, Ordering::Release);
                        unscanned_ref.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let mut timeout = config.timeout;
                    if let Some(remaining) = remaining {
                        timeout = timeout.min(remaining);
                    }
                    let started = Instant::now();
                    let mut attempts: u32 = 1;
                    loop {
                        if config.cancel.is_cancelled() {
                            saw_cancelled_ref.store(true, Ordering::Release);
                            saw_truncated_ref.store(true, Ordering::Release);
                            unscanned_ref.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        if config.deadline.is_some_and(|d| Instant::now() >= d) {
                            saw_truncated_ref.store(true, Ordering::Release);
                            unscanned_ref.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        match connector.connect(addr, timeout) {
                            Ok(stream) => {
                                drop(stream);
                                let mut guard = probes_ref.lock().unwrap_or_else(|e| e.into_inner());
                                guard.push(PortProbe {
                                    port,
                                    state: PortState::Open,
                                    latency: started.elapsed(),
                                    detail: format!("TCP connect to {ip}:{port} succeeded"),
                                    attempts,
                                });
                                break;
                            }
                            Err(error) => {
                                let category =
                                    crate::platform::network::normalize_io_error(&error);
                                match category {
                                    crate::execution::ErrorCategory::ConnectionRefused => {
                                        let mut guard =
                                            probes_ref.lock().unwrap_or_else(|e| e.into_inner());
                                        guard.push(PortProbe {
                                            port,
                                            state: PortState::Closed,
                                            latency: started.elapsed(),
                                            detail: format!(
                                                "TCP connection refused on {ip}:{port}; host responded, port closed"
                                            ),
                                            attempts,
                                        });
                                        break;
                                    }
                                    crate::execution::ErrorCategory::ConnectTimeout => {
                                        if attempts <= config.max_retries {
                                            attempts += 1;
                                            // Re-clamp retry timeout to remaining budget.
                                            if let Some(d) = config.deadline {
                                                let rem =
                                                    d.saturating_duration_since(Instant::now());
                                                if rem.is_zero() {
                                                    saw_truncated_ref.store(
                                                        true,
                                                        Ordering::Release,
                                                    );
                                                    unscanned_ref.fetch_add(1, Ordering::Relaxed);
                                                    break;
                                                }
                                                timeout = config.timeout.min(rem);
                                            }
                                            continue;
                                        }
                                        let mut guard =
                                            probes_ref.lock().unwrap_or_else(|e| e.into_inner());
                                        guard.push(PortProbe {
                                            port,
                                            state: PortState::FilteredOrTimedOut,
                                            latency: started.elapsed(),
                                            detail: format!(
                                                "TCP connect to {ip}:{port} timed out after {}ms",
                                                timeout.as_millis()
                                            ),
                                            attempts,
                                        });
                                        break;
                                    }
                                    _ => {
                                        let mut guard =
                                            probes_ref.lock().unwrap_or_else(|e| e.into_inner());
                                        guard.push(PortProbe {
                                            port,
                                            state: PortState::Error,
                                            latency: started.elapsed(),
                                            detail: format!(
                                                "TCP connect to {ip}:{port} failed ({category}): {error}"
                                            ),
                                            attempts,
                                        });
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
    // Recover collected probes on poison (structurally valid Vec); never
    // discard completed evidence.
    let mut probes = probes.into_inner().unwrap_or_else(|e| e.into_inner());
    probes.sort_by_key(|probe| probe.port);
    let unscanned = unscanned.load(Ordering::Relaxed);
    let cancelled = saw_cancelled.load(Ordering::Acquire);
    let truncated = saw_truncated.load(Ordering::Acquire) || unscanned > 0;
    // Exact accounting preserved: probes + unscanned == requested is
    // maintained by counting deadline/cancel before-start as unscanned.
    // Retry-denied mid-port paths also count as unscanned above.
    ScanOutcome {
        probes,
        truncated,
        cancelled,
        unscanned,
        fd_peak: workers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn states_stay_distinct() {
        assert_ne!(PortState::Open, PortState::Closed);
        assert_ne!(PortState::Closed, PortState::FilteredOrTimedOut);
        assert_ne!(PortState::FilteredOrTimedOut, PortState::Error);
    }

    #[test]
    fn loopback_refused_is_closed_not_timeout() {
        // High loopback port is almost certainly closed (refused fast).
        let config = ScanConfig::bounded(
            Duration::from_millis(500),
            16,
            0,
            None,
            CancellationToken::default(),
        );
        let outcome = NativeTcpScanner.scan("127.0.0.1".parse().unwrap(), &[65_000], &config);
        assert_eq!(outcome.probes.len(), 1);
        assert!(!outcome.cancelled);
        // Refused (Closed) is the expected loopback result; accept Error only
        // if the sandbox blocks loopback connects, but never Timeout/Open.
        assert!(
            matches!(
                outcome.probes[0].state,
                PortState::Closed | PortState::Error
            ),
            "unexpected {:?}",
            outcome.probes[0]
        );
    }

    /// Mock connector for portable worker-pool proofs (no external network).
    struct MockConnector {
        active: Arc<AtomicUsize>,
        max_active: Arc<AtomicUsize>,
        delay: Duration,
        mode: MockMode,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum MockMode {
        Timeout,
        Refused,
    }

    impl TcpConnector for MockConnector {
        fn connect(
            &self,
            _addr: std::net::SocketAddr,
            _timeout: Duration,
        ) -> std::io::Result<std::net::TcpStream> {
            let cur = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(cur, Ordering::SeqCst);
            std::thread::sleep(self.delay);
            self.active.fetch_sub(1, Ordering::SeqCst);
            match self.mode {
                MockMode::Timeout => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "mock timeout",
                )),
                MockMode::Refused => Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "mock refused",
                )),
            }
        }
    }

    fn portable_config(timeout_ms: u64, concurrency: usize, retries: u32) -> ScanConfig {
        ScanConfig::bounded(
            Duration::from_millis(timeout_ms),
            concurrency,
            retries,
            None,
            CancellationToken::default(),
        )
    }

    #[test]
    fn portable_progress_is_concurrent_not_sequential() {
        // 8 slow ports with 4 workers must overlap; sequential would keep
        // max_active==1. Synchronization proof, not wall-clock threshold.
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let connector = MockConnector {
            active: active.clone(),
            max_active: max_active.clone(),
            delay: Duration::from_millis(150),
            mode: MockMode::Timeout,
        };
        let config = portable_config(1000, 8, 0);
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        let ports: Vec<u16> = (1..=8).collect();
        let outcome = scan_ports_portable_with_connector(ip, &ports, &config, &connector);
        assert_eq!(outcome.probes.len(), 8);
        assert_eq!(outcome.unscanned, 0);
        assert!(
            max_active.load(Ordering::SeqCst) >= 2,
            "expected concurrent progress, max_active={}",
            max_active.load(Ordering::SeqCst)
        );
        // Deterministic ordering despite concurrency.
        let sorted = outcome.probes.iter().map(|p| p.port).collect::<Vec<_>>();
        let mut expected = sorted.clone();
        expected.sort_unstable();
        assert_eq!(sorted, expected);
        // Timeouts never become Open/Closed.
        assert!(
            outcome
                .probes
                .iter()
                .all(|p| p.state == PortState::FilteredOrTimedOut)
        );
    }

    #[test]
    fn portable_timeout_does_not_take_sequential_duration() {
        // 4×300ms timeouts with 4 workers must finish well under sequential
        // 1200ms. Generous 1000ms bound avoids flakiness while still catching
        // sequential regression (1200ms+).
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let connector = MockConnector {
            active,
            max_active,
            delay: Duration::from_millis(300),
            mode: MockMode::Timeout,
        };
        let config = portable_config(300, 4, 0);
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        let start = Instant::now();
        let outcome =
            scan_ports_portable_with_connector(ip, &[1001, 1002, 1003, 1004], &config, &connector);
        let elapsed = start.elapsed();
        assert_eq!(outcome.probes.len(), 4);
        assert!(
            elapsed < Duration::from_millis(1000),
            "portable took {elapsed:?}, expected concurrent (<1000ms for 4×300ms)"
        );
    }

    #[test]
    fn portable_closed_never_retries_and_timeout_retries_once() {
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let refused = MockConnector {
            active: active.clone(),
            max_active: max_active.clone(),
            delay: Duration::from_millis(5),
            mode: MockMode::Refused,
        };
        let config = portable_config(500, 4, 1);
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        let outcome = scan_ports_portable_with_connector(ip, &[80], &config, &refused);
        assert_eq!(outcome.probes[0].state, PortState::Closed);
        assert_eq!(outcome.probes[0].attempts, 1, "refused must not retry");

        let timeout = MockConnector {
            active,
            max_active,
            delay: Duration::from_millis(5),
            mode: MockMode::Timeout,
        };
        let outcome = scan_ports_portable_with_connector(ip, &[81], &config, &timeout);
        assert_eq!(outcome.probes[0].state, PortState::FilteredOrTimedOut);
        assert_eq!(outcome.probes[0].attempts, 2, "timeout retries once");
    }

    #[test]
    fn portable_cancellation_and_deadline_preserve_accounting() {
        // Cancelled before start: all unscanned.
        let cancel = CancellationToken::default();
        cancel.cancel();
        let config = ScanConfig::bounded(Duration::from_millis(300), 4, 0, None, cancel);
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let connector = MockConnector {
            active,
            max_active,
            delay: Duration::from_millis(5),
            mode: MockMode::Timeout,
        };
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        let outcome = scan_ports_portable_with_connector(ip, &[80, 81, 82], &config, &connector);
        assert!(outcome.cancelled);
        assert_eq!(outcome.unscanned, 3);
        assert!(outcome.probes.is_empty());

        // Past deadline: all unscanned, truncated.
        let config = ScanConfig::bounded(
            Duration::from_millis(300),
            4,
            0,
            Some(Instant::now() - Duration::from_millis(10)),
            CancellationToken::default(),
        );
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let connector = MockConnector {
            active,
            max_active,
            delay: Duration::from_millis(5),
            mode: MockMode::Timeout,
        };
        let outcome = scan_ports_portable_with_connector(ip, &[80, 81], &config, &connector);
        assert_eq!(outcome.unscanned, 2);
        assert!(outcome.truncated);
        assert_eq!(outcome.probes.len() + outcome.unscanned, 2);
    }

    #[test]
    fn portable_open_and_closed_on_loopback() {
        // Real loopback: listener is Open, free port is Closed/Error.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap().port();
        let closed = {
            let s = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let p = s.local_addr().unwrap().port();
            drop(s);
            p
        };
        let config = portable_config(800, 8, 0);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let outcome =
            scan_ports_portable_with_connector(ip, &[open, closed], &config, &StdTcpConnector);
        assert_eq!(outcome.probes.len(), 2);
        let by_port: std::collections::BTreeMap<u16, PortState> =
            outcome.probes.iter().map(|p| (p.port, p.state)).collect();
        assert_eq!(by_port.get(&open), Some(&PortState::Open));
        assert!(matches!(
            by_port.get(&closed),
            Some(PortState::Closed) | Some(PortState::Error)
        ));
        // IPv6 loopback where available: refused or error, never panic.
        let config = portable_config(400, 4, 0);
        let ip6: IpAddr = "::1".parse().unwrap();
        let outcome = scan_ports_portable_with_connector(ip6, &[65_000], &config, &StdTcpConnector);
        assert_eq!(outcome.probes.len() + outcome.unscanned, 1);
    }
}
