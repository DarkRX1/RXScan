//! Native ICMP echo probing without shelling out to `ping`.
//!
//! Uses unprivileged `SOCK_DGRAM` "ping sockets" (`IPPROTO_ICMP` /
//! `IPPROTO_ICMPV6`) where the platform permits them. Raw `SOCK_RAW` sockets
//! are never required for RXScan to function: when privileges are missing the
//! prober returns a structured `Unavailable` outcome
//! (`ICMP probe unavailable: insufficient privileges ...`) so TCP fallback
//! can proceed. Every probe honors timeout, cancellation, bounded retries
//! (via attempts), and prompt resource cleanup (socket closed on every path).

use std::net::IpAddr;
use std::os::raw::{c_int, c_void};
use std::time::{Duration, Instant};

use crate::discovery::{DiscoveryTechnique, ProbeOutcome, ProbeRecord};
use crate::execution::CancellationToken;

// Linux constants (portable enough for Athena/Arch; other platforms return
// `Unavailable` cleanly instead of crashing).
const AF_INET: c_int = 2;
const AF_INET6: c_int = 10;
const SOCK_DGRAM: c_int = 2;
const IPPROTO_ICMP: c_int = 1;
const IPPROTO_ICMPV6: c_int = 58;
const SOL_SOCKET: c_int = 1;
const SO_RCVTIMEO: c_int = 20;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i64,
}

// Minimal sockaddr structs for sendto/recvfrom. Layout matches Linux.
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
struct SockaddrStorage {
    data: [u8; 128],
}

unsafe extern "C" {
    fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn sendto(
        fd: c_int,
        buf: *const c_void,
        len: usize,
        flags: c_int,
        addr: *const c_void,
        addrlen: u32,
    ) -> isize;
    fn recvfrom(
        fd: c_int,
        buf: *mut c_void,
        len: usize,
        flags: c_int,
        addr: *mut c_void,
        addrlen: *mut u32,
    ) -> isize;
    fn setsockopt(
        fd: c_int,
        level: c_int,
        optname: c_int,
        optval: *const c_void,
        optlen: u32,
    ) -> c_int;
    fn __errno_location() -> *mut c_int;
}

fn last_errno() -> c_int {
    unsafe { *__errno_location() }
}

fn icmp_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (u16::from(last) as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_icmp_v4_echo(identifier: u16, sequence: u16) -> Vec<u8> {
    // Type 8 (echo request), code 0, checksum, id, seq, 24-byte payload.
    let mut packet = vec![0u8; 8 + 24];
    packet[0] = 8;
    packet[1] = 0;
    packet[4..6].copy_from_slice(&identifier.to_be_bytes());
    packet[6..8].copy_from_slice(&sequence.to_be_bytes());
    for (index, byte) in packet.iter_mut().enumerate().skip(8) {
        *byte = (index & 0xFF) as u8;
    }
    let checksum = icmp_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn build_icmp_v6_echo(identifier: u16, sequence: u16) -> Vec<u8> {
    // Type 128 (echo request), code 0. Checksum left zero so a kernel that
    // auto-fills ping-socket checksums can do so; kernels requiring a full
    // pseudo-header checksum will simply not reply (Timeout, not an error).
    let mut packet = vec![0u8; 8 + 24];
    packet[0] = 128;
    packet[1] = 0;
    packet[4..6].copy_from_slice(&identifier.to_be_bytes());
    packet[6..8].copy_from_slice(&sequence.to_be_bytes());
    for (index, byte) in packet.iter_mut().enumerate().skip(8) {
        *byte = (index & 0xFF) as u8;
    }
    packet
}

fn set_recv_timeout(fd: c_int, timeout: Duration) {
    let timeval = Timeval {
        tv_sec: timeout.as_secs() as i64,
        tv_usec: i64::from(timeout.subsec_micros()),
    };
    unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeval as *const Timeval as *const c_void,
            size_of::<Timeval>() as u32,
        );
    }
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

/// Result of one ICMP echo attempt (single packet, single wait).
fn icmp_echo_once(ip: IpAddr, timeout: Duration, cancel: &CancellationToken) -> ProbeOutcome {
    if cancel.is_cancelled() {
        return ProbeOutcome::Cancelled;
    }
    let identifier = (std::process::id() & 0xFFFF) as u16;
    let sequence: u16 = 0;
    let started = Instant::now();

    match ip {
        IpAddr::V4(v4) => {
            let fd = unsafe { socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) };
            let Some(socket) = OwnedFd::new(fd) else {
                let errno = last_errno();
                // EACCES (13) / EPERM (1) / EPROTONOSUPPORT (93) all mean
                // "cannot use ICMP here": structured unavailable, not dead.
                return ProbeOutcome::Unavailable {
                    reason: format!(
                        "ICMP probe unavailable: insufficient privileges or unsupported protocol (errno {errno})"
                    ),
                };
            };
            set_recv_timeout(socket.0, Duration::from_millis(100));
            let packet = build_icmp_v4_echo(identifier, sequence);
            let octets = v4.octets();
            let destination = SockaddrIn {
                sin_family: AF_INET as u16,
                sin_port: 0,
                sin_addr: octets,
                sin_zero: [0; 8],
            };
            let sent = unsafe {
                sendto(
                    socket.0,
                    packet.as_ptr() as *const c_void,
                    packet.len(),
                    0,
                    &destination as *const SockaddrIn as *const c_void,
                    size_of::<SockaddrIn>() as u32,
                )
            };
            if sent < 0 {
                let errno = last_errno();
                if errno == 13 || errno == 1 {
                    return ProbeOutcome::Unavailable {
                        reason: format!(
                            "ICMP probe unavailable: insufficient privileges (errno {errno})"
                        ),
                    };
                }
                return ProbeOutcome::Unavailable {
                    reason: format!("ICMP send failed (errno {errno})"),
                };
            }
            let mut buffer = vec![0u8; 1500];
            loop {
                if cancel.is_cancelled() {
                    return ProbeOutcome::Cancelled;
                }
                if started.elapsed() >= timeout {
                    return ProbeOutcome::Timeout;
                }
                let mut source = SockaddrStorage { data: [0; 128] };
                let mut source_len = size_of::<SockaddrStorage>() as u32;
                let received = unsafe {
                    recvfrom(
                        socket.0,
                        buffer.as_mut_ptr() as *mut c_void,
                        buffer.len(),
                        0,
                        &mut source as *mut SockaddrStorage as *mut c_void,
                        &mut source_len,
                    )
                };
                if received < 0 {
                    let errno = last_errno();
                    // EAGAIN (11) / EWOULDBLOCK: 100ms slice expired; loop
                    // so cancellation and the overall timeout stay prompt.
                    if errno == 11 || errno == 4 {
                        continue;
                    }
                    return ProbeOutcome::Timeout;
                }
                let received = received as usize;
                // Ping sockets return the ICMP message (no IP header).
                // NOTE: unprivileged SOCK_DGRAM ping sockets use the local
                // port as the ICMP identifier (kernel rewrites it), so we
                // accept any echo reply (type 0) here; the per-socket
                // demultiplexing already isolates our target. Strict id
                // matching would timeout forever on loopback.
                if received >= 8 && buffer[0] == 0 && buffer[1] == 0 {
                    let latency = started.elapsed();
                    return ProbeOutcome::Success {
                        latency,
                        detail: format!("ICMP echo reply from {} in {}ms", ip, latency.as_millis()),
                    };
                }
                // Wrong packet (unrelated ping traffic): keep waiting.
            }
        }
        IpAddr::V6(v6) => {
            let fd = unsafe { socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6) };
            let Some(socket) = OwnedFd::new(fd) else {
                let errno = last_errno();
                return ProbeOutcome::Unavailable {
                    reason: format!(
                        "ICMPv6 probe unavailable: insufficient privileges or unsupported protocol (errno {errno})"
                    ),
                };
            };
            set_recv_timeout(socket.0, Duration::from_millis(100));
            let packet = build_icmp_v6_echo(identifier, sequence);
            let destination = SockaddrIn6 {
                sin6_family: AF_INET6 as u16,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: v6.octets(),
                sin6_scope_id: 0,
            };
            let sent = unsafe {
                sendto(
                    socket.0,
                    packet.as_ptr() as *const c_void,
                    packet.len(),
                    0,
                    &destination as *const SockaddrIn6 as *const c_void,
                    size_of::<SockaddrIn6>() as u32,
                )
            };
            if sent < 0 {
                let errno = last_errno();
                if errno == 13 || errno == 1 {
                    return ProbeOutcome::Unavailable {
                        reason: format!(
                            "ICMPv6 probe unavailable: insufficient privileges (errno {errno})"
                        ),
                    };
                }
                return ProbeOutcome::Unavailable {
                    reason: format!("ICMPv6 send failed (errno {errno})"),
                };
            }
            let mut buffer = vec![0u8; 1500];
            loop {
                if cancel.is_cancelled() {
                    return ProbeOutcome::Cancelled;
                }
                if started.elapsed() >= timeout {
                    return ProbeOutcome::Timeout;
                }
                let mut source = SockaddrStorage { data: [0; 128] };
                let mut source_len = size_of::<SockaddrStorage>() as u32;
                let received = unsafe {
                    recvfrom(
                        socket.0,
                        buffer.as_mut_ptr() as *mut c_void,
                        buffer.len(),
                        0,
                        &mut source as *mut SockaddrStorage as *mut c_void,
                        &mut source_len,
                    )
                };
                if received < 0 {
                    let errno = last_errno();
                    if errno == 11 || errno == 4 {
                        continue;
                    }
                    return ProbeOutcome::Timeout;
                }
                let received = received as usize;
                if received >= 8 && buffer[0] == 129 && buffer[1] == 0 {
                    let latency = started.elapsed();
                    return ProbeOutcome::Success {
                        latency,
                        detail: format!(
                            "ICMPv6 echo reply from {} in {}ms",
                            ip,
                            latency.as_millis()
                        ),
                    };
                }
            }
        }
    }
}

/// Trait for ICMP probing (real + fake/mock backends for tests).
pub trait IcmpProber: Send + Sync {
    fn probe(&self, ip: IpAddr, timeout: Duration, cancel: &CancellationToken) -> ProbeOutcome;
}

/// Native prober: real `SOCK_DGRAM` ping sockets, no shell `ping`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeIcmpProber;

impl IcmpProber for NativeIcmpProber {
    fn probe(&self, ip: IpAddr, timeout: Duration, cancel: &CancellationToken) -> ProbeOutcome {
        let timeout = timeout.clamp(Duration::from_millis(100), Duration::from_secs(10));
        icmp_echo_once(ip, timeout, cancel)
    }
}

/// Run `attempts` bounded ICMP attempts; stops early on success,
/// cancellation, or unavailability. Returns per-attempt records.
pub fn icmp_probe_with_retries(
    prober: &dyn IcmpProber,
    ip: IpAddr,
    attempts: u32,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Vec<ProbeRecord> {
    let attempts = attempts.clamp(1, 5);
    let mut records = Vec::new();
    for _ in 0..attempts {
        if cancel.is_cancelled() {
            records.push(ProbeRecord {
                technique: DiscoveryTechnique::IcmpEcho,
                target: ip,
                port: None,
                outcome: ProbeOutcome::Cancelled,
                latency: None,
            });
            break;
        }
        let outcome = prober.probe(ip, timeout, cancel);
        let latency = match &outcome {
            ProbeOutcome::Success { latency, .. } => Some(*latency),
            _ => None,
        };
        let terminal = matches!(
            outcome,
            ProbeOutcome::Success { .. } | ProbeOutcome::Cancelled
        );
        // Unavailable is terminal for ICMP: retrying a permission error is
        // pointless; TCP fallback handles reachability instead.
        let unavailable = matches!(outcome, ProbeOutcome::Unavailable { .. });
        records.push(ProbeRecord {
            technique: DiscoveryTechnique::IcmpEcho,
            target: ip,
            port: None,
            outcome,
            latency,
        });
        if terminal || unavailable {
            break;
        }
        // Bounded pacing between attempts (10ms), still cancellable.
        if records.len() < attempts as usize {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    records
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_is_correct_for_known_packet() {
        // Empty payload echo with id/seq zero: type 8, code 0.
        let packet = build_icmp_v4_echo(0, 0);
        assert_eq!(packet[0], 8);
        assert_eq!(icmp_checksum(&packet), 0);
    }

    #[test]
    fn native_prober_never_panics_on_loopback() {
        // Must return Success, Timeout, or Unavailable — never panic, never
        // claim Unreachable without evidence.
        let prober = NativeIcmpProber;
        let outcome = prober.probe(
            IpAddr::from([127, 0, 0, 1]),
            Duration::from_millis(300),
            &CancellationToken::default(),
        );
        match outcome {
            ProbeOutcome::Success { .. }
            | ProbeOutcome::Timeout
            | ProbeOutcome::Unavailable { .. } => {}
            ProbeOutcome::Unreachable { .. } | ProbeOutcome::Cancelled => {
                panic!("unexpected ICMP outcome: {outcome:?}")
            }
        }
    }
}
