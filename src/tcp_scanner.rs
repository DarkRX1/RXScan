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

use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::os::raw::{c_int, c_void};
use std::time::{Duration, Instant};

use crate::execution::CancellationToken;

// ---- libc constants (Linux/Athena/Arch; other platforms degrade to Error) ---
const AF_INET: c_int = 2;
const AF_INET6: c_int = 10;
const SOCK_STREAM: c_int = 1;
const IPPROTO_TCP: c_int = 6;
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const O_NONBLOCK: c_int = 2048;
const EINPROGRESS: c_int = 115;
const EINTR: c_int = 4;
const EAGAIN: c_int = 11;
const ECONNREFUSED: c_int = 111;
const ECONNRESET: c_int = 104;
const ETIMEDOUT: c_int = 110;
const EHOSTUNREACH: c_int = 113;
const ENETUNREACH: c_int = 101;
const EACCES: c_int = 13;
const EPERM: c_int = 1;
const EMFILE: c_int = 24;
const ENFILE: c_int = 23;
const ENOMEM: c_int = 12;
const POLLOUT: i16 = 0x0004;
const POLLERR: i16 = 0x0008;
const POLLHUP: i16 = 0x0010;
const SOL_SOCKET: c_int = 1;
const SO_ERROR: c_int = 4;

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

/// Explicit per-port conclusion. Timeouts stay distinct from closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    FilteredOrTimedOut,
    Error,
}

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Closed => write!(f, "closed"),
            Self::FilteredOrTimedOut => write!(f, "filtered_or_timed_out"),
            Self::Error => write!(f, "error"),
        }
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
}

/// Trait for port scanning (real non-blocking + fakes for tests).
pub trait PortScanner: Send + Sync {
    fn scan(&self, ip: IpAddr, ports: &[u16], config: &ScanConfig) -> ScanOutcome;
}

/// Native non-blocking connect scanner (unprivileged baseline, no raw SYN).
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeTcpScanner;

impl PortScanner for NativeTcpScanner {
    fn scan(&self, ip: IpAddr, ports: &[u16], config: &ScanConfig) -> ScanOutcome {
        scan_ports_nonblocking(ip, ports, config)
    }
}

struct Pending {
    port: u16,
    #[allow(dead_code)]
    fd: OwnedFd,
    started: Instant,
    port_deadline: Instant,
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
    let mut pending: BTreeMap<c_int, Pending> = BTreeMap::new();
    let mut truncated = false;
    let mut cancelled = false;
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
            let result = unsafe { connect(fd.0, addr_bytes.as_ptr() as *const c_void, addr_len) };
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
                }
                e if e == EINTR => {
                    // Single immediate retry for interrupted connects.
                    let retry =
                        unsafe { connect(fd.0, addr_bytes.as_ptr() as *const c_void, addr_len) };
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
            .min(c_int::MAX as u128) as c_int;
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
        let ready_map: BTreeMap<c_int, i16> = poll_fds
            .iter()
            .map(|item| (item.fd, item.revents))
            .collect();
        let now = Instant::now();
        let mut finished: Vec<c_int> = Vec::new();
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
    // counts as unscanned when truncated.
    let unscanned = queue.len();
    if unscanned > 0 {
        truncated = true;
    }
    probes.sort_by_key(|probe| probe.port);
    ScanOutcome {
        probes,
        truncated,
        cancelled,
        unscanned,
    }
}

fn classify_immediate(
    ip: IpAddr,
    port: u16,
    errno: c_int,
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
