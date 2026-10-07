use std::net::Ipv6Addr;
#[cfg(target_os = "linux")]
use std::os::raw::{c_int, c_void};
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

use crate::execution::CancellationToken;

#[cfg(target_os = "linux")]
const AF_INET6: c_int = 10;
#[cfg(target_os = "linux")]
const SOCK_RAW: c_int = 3;
#[cfg(target_os = "linux")]
const IPPROTO_ICMPV6: c_int = 58;
#[cfg(target_os = "linux")]
const POLLIN: i16 = 0x0001;
#[cfg(target_os = "linux")]
const SOL_SOCKET: c_int = 1;
#[cfg(target_os = "linux")]
const SO_RCVTIMEO: c_int = 20;
#[cfg(target_os = "linux")]
const EAGAIN: c_int = 11;
#[cfg(target_os = "linux")]
const EINTR: c_int = 4;
#[cfg(target_os = "linux")]
const EPERM: c_int = 1;
#[cfg(target_os = "linux")]
const EACCES: c_int = 13;

pub const MAX_NS_PER_PROBE: u32 = 2;
pub const MAX_IFINFO_BYTES: usize = 64 * 1024;
pub const MAX_NDP_INTERFACES: usize = 8;

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockaddrIn6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i64,
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn setsockopt(
        fd: c_int,
        level: c_int,
        optname: c_int,
        optval: *const c_void,
        optlen: u32,
    ) -> c_int;
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
    fn poll(fds: *mut PollFd, nfds: u64, timeout: c_int) -> c_int;
    fn __errno_location() -> *mut c_int;
}

#[cfg(target_os = "linux")]
fn last_errno() -> c_int {
    unsafe { *__errno_location() }
}

#[cfg(target_os = "linux")]
struct OwnedFd(c_int);
#[cfg(target_os = "linux")]
impl OwnedFd {
    fn new(fd: c_int) -> Option<Self> {
        (fd >= 0).then_some(Self(fd))
    }
}
#[cfg(target_os = "linux")]
impl Drop for OwnedFd {
    fn drop(&mut self) {
        unsafe {
            close(self.0);
        }
    }
}

pub fn solicited_node_multicast(target: Ipv6Addr) -> Ipv6Addr {
    let octets = target.octets();
    Ipv6Addr::new(
        0xFF02,
        0,
        0,
        0,
        0,
        0x0001,
        0xFF00 | u16::from(octets[13]),
        (u16::from(octets[14]) << 8) | u16::from(octets[15]),
    )
}

fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, message: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in src.octets().chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.octets().chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += message.len() as u32;
    sum += 58;
    let mut chunks = message.chunks_exact(2);
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

pub fn build_ns(src: Ipv6Addr, target: Ipv6Addr) -> Vec<u8> {
    let dst = solicited_node_multicast(target);
    let mut message = vec![0u8; 24];
    message[0] = 135;
    message[1] = 0;
    message[8..24].copy_from_slice(&target.octets());
    let sum = icmpv6_checksum(src, dst, &message);
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    message
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NaInfo {
    pub target: Ipv6Addr,
    pub router: bool,
    pub solicited: bool,
}

pub fn parse_na(bytes: &[u8], want: Ipv6Addr) -> Option<NaInfo> {
    if bytes.len() < 24 || bytes[0] != 136 || bytes[1] != 0 {
        return None;
    }
    let mut target_octets = [0u8; 16];
    target_octets.copy_from_slice(&bytes[8..24]);
    if Ipv6Addr::from(target_octets) != want {
        return None;
    }
    Some(NaInfo {
        target: want,
        router: bytes[4] & 0x80 != 0,
        solicited: bytes[4] & 0x40 != 0,
    })
}

/// Pure /proc/net/if_inet6 parser. Intentionally portable (no syscalls):
/// unit tests prove the enumeration logic on every platform even though
/// only the Linux implementation reads the live interface table.
pub(crate) fn link_local_interfaces(text: &str) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let (Ok(addr_value), Ok(ifindex)) = (
            u128::from_str_radix(fields[0], 16),
            u32::from_str_radix(fields[1], 16),
        ) else {
            continue;
        };
        let addr = Ipv6Addr::from(addr_value.to_be_bytes());
        if !addr.is_unicast_link_local() {
            continue;
        }
        if !out.iter().any(|(index, _)| *index == ifindex) {
            out.push((ifindex, fields[5].to_owned()));
        }
        if out.len() >= MAX_NDP_INTERFACES {
            break;
        }
    }
    out
}

/// Linux-only file reader for /proc lookups. Only the Linux NDP
/// implementation calls it; other platforms use the portable fallback
/// below, so it is cfg'd with that implementation. The pure parser
/// [`link_local_interfaces`] stays portable (unit-tested everywhere).
#[cfg(target_os = "linux")]
fn read_bounded(path: &str, cap: usize) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() > cap {
        return None;
    }
    String::from_utf8(bytes).ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NdpOutcome {
    Alive { latency_ms: u64, router: bool },
    Timeout,
    Unavailable(String),
    Cancelled,
}

#[cfg(target_os = "linux")]
pub fn probe_ndp(
    target: std::net::IpAddr,
    timeout: Duration,
    cancel: &CancellationToken,
) -> NdpOutcome {
    if cancel.is_cancelled() {
        return NdpOutcome::Cancelled;
    }
    let std::net::IpAddr::V6(target) = target else {
        return NdpOutcome::Unavailable("NDP applies to IPv6 targets only".to_owned());
    };
    if target.is_loopback() {
        return NdpOutcome::Unavailable("NDP skips loopback targets".to_owned());
    }
    let started = Instant::now();
    let scope_ids: Vec<u32> = if target.is_unicast_link_local() {
        let text = match read_bounded("/proc/net/if_inet6", MAX_IFINFO_BYTES) {
            Some(text) => text,
            None => {
                return NdpOutcome::Unavailable("NDP requires a link-local interface".to_owned());
            }
        };
        let interfaces = link_local_interfaces(&text);
        if interfaces.is_empty() {
            return NdpOutcome::Unavailable("NDP requires a link-local interface".to_owned());
        }
        interfaces.into_iter().map(|(index, _)| index).collect()
    } else {
        vec![0]
    };
    let fd = unsafe { socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6) };
    let Some(socket) = OwnedFd::new(fd) else {
        let errno = last_errno();
        if errno == EPERM || errno == EACCES {
            return NdpOutcome::Unavailable(
                "NDP unavailable: CAP_NET_RAW not available".to_owned(),
            );
        }
        return NdpOutcome::Unavailable(format!("NDP socket failed (errno {errno})"));
    };
    let timeval = Timeval {
        tv_sec: 0,
        tv_usec: 25_000,
    };
    unsafe {
        setsockopt(
            socket.0,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeval as *const Timeval as *const c_void,
            size_of::<Timeval>() as u32,
        );
    }
    let local = Ipv6Addr::UNSPECIFIED;
    let request = build_ns(local, target);
    let multicast = solicited_node_multicast(target);
    let mut buffer = vec![0u8; 2048];
    for scope_id in scope_ids {
        if cancel.is_cancelled() {
            return NdpOutcome::Cancelled;
        }
        let dest = SockaddrIn6 {
            sin6_family: AF_INET6 as u16,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: multicast.octets(),
            sin6_scope_id: scope_id,
        };
        for attempt in 0..MAX_NS_PER_PROBE {
            if cancel.is_cancelled() {
                return NdpOutcome::Cancelled;
            }
            if started.elapsed() >= timeout {
                return NdpOutcome::Timeout;
            }
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(200).min(timeout / 4));
            }
            let sent = unsafe {
                sendto(
                    socket.0,
                    request.as_ptr() as *const c_void,
                    request.len(),
                    0,
                    &dest as *const SockaddrIn6 as *const c_void,
                    size_of::<SockaddrIn6>() as u32,
                )
            };
            if sent < 0 {
                continue;
            }
            let window = timeout
                .saturating_sub(started.elapsed())
                .min(Duration::from_millis(500));
            let window_end = Instant::now() + window;
            while Instant::now() < window_end {
                if cancel.is_cancelled() {
                    return NdpOutcome::Cancelled;
                }
                let mut poll_fd = PollFd {
                    fd: socket.0,
                    events: POLLIN,
                    revents: 0,
                };
                let ready = unsafe { poll(&mut poll_fd as *mut PollFd, 1, 25) };
                if ready < 0 && last_errno() == EINTR {
                    continue;
                }
                if ready <= 0 || poll_fd.revents & POLLIN == 0 {
                    continue;
                }
                let received = unsafe {
                    recvfrom(
                        socket.0,
                        buffer.as_mut_ptr() as *mut c_void,
                        buffer.len(),
                        0,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                };
                if received <= 0 {
                    let errno = last_errno();
                    if errno == EAGAIN || errno == EINTR {
                        continue;
                    }
                    continue;
                }
                if let Some(info) = parse_na(&buffer[..received as usize], target) {
                    return NdpOutcome::Alive {
                        latency_ms: started.elapsed().as_millis() as u64,
                        router: info.router,
                    };
                }
            }
        }
    }
    NdpOutcome::Timeout
}

/// Portable fallback: NDP requires raw ICMPv6, unavailable outside Linux.
#[cfg(not(target_os = "linux"))]
pub fn probe_ndp(
    target: std::net::IpAddr,
    timeout: Duration,
    cancel: &CancellationToken,
) -> NdpOutcome {
    if cancel.is_cancelled() {
        return NdpOutcome::Cancelled;
    }
    let _ = (target, timeout);
    NdpOutcome::Unavailable("NDP unavailable: Linux-only implementation in this build".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solicited_node_multicast_derivation() {
        let target: Ipv6Addr = "fe80::aabb:ccdd".parse().unwrap();
        assert_eq!(
            solicited_node_multicast(target).to_string(),
            "ff02::1:ffbb:ccdd"
        );
    }

    #[test]
    fn ns_is_well_formed() {
        let target: Ipv6Addr = "fe80::1".parse().unwrap();
        let packet = build_ns(Ipv6Addr::UNSPECIFIED, target);
        assert_eq!(packet.len(), 24);
        assert_eq!(packet[0], 135);
        assert_eq!(&packet[8..24], &target.octets());
    }

    fn na_packet(target: Ipv6Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 32];
        packet[0] = 136;
        packet[4] = 0x60;
        packet[8..24].copy_from_slice(&target.octets());
        packet[24] = 2;
        packet[25] = 1;
        packet
    }

    #[test]
    fn valid_na_parses() {
        let target: Ipv6Addr = "fe80::1".parse().unwrap();
        let info = parse_na(&na_packet(target), target).unwrap();
        assert!(!info.router);
        assert!(info.solicited);
    }

    #[test]
    fn unrelated_target_rejected() {
        let target: Ipv6Addr = "fe80::1".parse().unwrap();
        let other: Ipv6Addr = "fe80::2".parse().unwrap();
        assert!(parse_na(&na_packet(other), target).is_none());
    }

    #[test]
    fn malformed_never_panics() {
        let target: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(parse_na(&[], target).is_none());
        assert!(parse_na(&[136, 0], target).is_none());
        assert!(parse_na(&[135u8; 24], target).is_none());
        assert!(parse_na(&[0u8; 64], target).is_none());
    }

    #[test]
    fn link_local_interface_enumeration() {
        let text = "fe800000000000000000000000000001 05 40 20 80 eth0\n20010db8000000000000000000000001 05 40 00 80 eth0\n";
        let interfaces = link_local_interfaces(text);
        assert_eq!(interfaces.len(), 1);
        assert_eq!(interfaces[0].0, 5);
    }

    #[test]
    fn v4_and_loopback_refused() {
        let outcome = probe_ndp(
            "192.0.2.1".parse().unwrap(),
            Duration::from_millis(50),
            &CancellationToken::default(),
        );
        assert!(matches!(outcome, NdpOutcome::Unavailable(_)));
        let outcome = probe_ndp(
            "::1".parse().unwrap(),
            Duration::from_millis(50),
            &CancellationToken::default(),
        );
        assert!(matches!(outcome, NdpOutcome::Unavailable(_)));
    }

    #[test]
    fn cancelled_probe_returns_promptly() {
        let cancel = CancellationToken::default();
        cancel.cancel();
        assert_eq!(
            probe_ndp("fe80::1".parse().unwrap(), Duration::from_secs(5), &cancel),
            NdpOutcome::Cancelled
        );
    }
}
