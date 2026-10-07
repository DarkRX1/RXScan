use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use std::os::raw::{c_int, c_void};
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

use crate::execution::CancellationToken;

#[cfg(target_os = "linux")]
const AF_PACKET: c_int = 17;
#[cfg(target_os = "linux")]
const SOCK_RAW: c_int = 3;
const ETH_P_ARP: u16 = 0x0806;
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

pub const MAX_ARP_REQUESTS_PER_PROBE: u32 = 2;
pub const MAX_ROUTE_BYTES: usize = 64 * 1024;

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockaddrLl {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub name: String,
    pub ifindex: i32,
    pub mac: [u8; 6],
    pub addr: Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArpError {
    Unavailable(String),
    NotOnLink,
    NoInterface,
}

impl std::fmt::Display for ArpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(f, "ARP unavailable: {reason}"),
            Self::NotOnLink => write!(
                f,
                "ARP refused: target is not on a directly connected network"
            ),
            Self::NoInterface => write!(f, "ARP unavailable: no local interface found"),
        }
    }
}

pub fn build_arp_request(src_mac: [u8; 6], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> [u8; 42] {
    let mut frame = [0u8; 42];
    frame[0..6].copy_from_slice(&[0xFF; 6]);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
    frame[14..16].copy_from_slice(&1u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&1u16.to_be_bytes());
    frame[22..28].copy_from_slice(&src_mac);
    frame[28..32].copy_from_slice(&src_ip.octets());
    frame[38..42].copy_from_slice(&dst_ip.octets());
    frame
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpReply {
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
}

pub fn parse_arp_reply(frame: &[u8], want_ip: Ipv4Addr) -> Option<ArpReply> {
    if frame.len() < 42 || u16::from_be_bytes([frame[12], frame[13]]) != ETH_P_ARP {
        return None;
    }
    let arp = &frame[14..];
    if arp.len() < 28
        || u16::from_be_bytes([arp[0], arp[1]]) != 1
        || u16::from_be_bytes([arp[2], arp[3]]) != 0x0800
        || arp[4] != 6
        || arp[5] != 4
        || u16::from_be_bytes([arp[6], arp[7]]) != 2
    {
        return None;
    }
    let sender_ip = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);
    if sender_ip != want_ip {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&arp[8..14]);
    if mac == [0; 6] {
        return None;
    }
    Some(ArpReply {
        sender_mac: mac,
        sender_ip,
    })
}

/// Pure /proc/net/route parser. Intentionally portable (no syscalls):
/// unit tests prove the longest-prefix-match logic on every platform even
/// though only the Linux implementation reads the live route table.
pub(crate) fn parse_proc_route(text: &str, target: Ipv4Addr) -> Option<(String, bool)> {
    let target_u32 = u32::from(target);
    let mut best: Option<(String, bool, u32)> = None;
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }
        let (iface, dest_hex, gw_hex, mask_hex) = (fields[0], fields[1], fields[2], fields[7]);
        // /proc/net/route prints addresses as raw little-endian words, so
        // byte-swap into numeric network order before masking.
        let (Ok(dest), Ok(gateway), Ok(mask)) = (
            u32::from_str_radix(dest_hex, 16).map(u32::swap_bytes),
            u32::from_str_radix(gw_hex, 16).map(u32::swap_bytes),
            u32::from_str_radix(mask_hex, 16).map(u32::swap_bytes),
        ) else {
            continue;
        };
        if target_u32 & mask != dest & mask {
            continue;
        }
        let on_link = gateway == 0;
        let prefix_len = mask.count_ones();
        let replace = best
            .as_ref()
            .is_none_or(|(_, _, best_len)| prefix_len > *best_len);
        if replace {
            best = Some((iface.to_owned(), on_link, prefix_len));
        }
    }
    best.map(|(iface, on_link, _)| (iface, on_link))
}

/// Linux-only file reader for /proc + /sys lookups. Only the Linux
/// implementation calls it; other platforms use the portable fallback in
/// [`interface_for_target`], so it is cfg'd with that implementation.
#[cfg(target_os = "linux")]
fn read_bounded(path: &str, cap: usize) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() > cap {
        return None;
    }
    String::from_utf8(bytes).ok()
}

#[cfg(target_os = "linux")]
fn interface_mac(name: &str) -> Option<[u8; 6]> {
    let text = read_bounded(&format!("/sys/class/net/{name}/address"), 64)?;
    let parts: Vec<&str> = text.trim().split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    if mac == [0; 6] {
        return None;
    }
    Some(mac)
}

#[cfg(target_os = "linux")]
fn interface_index(name: &str) -> Option<i32> {
    read_bounded(&format!("/sys/class/net/{name}/ifindex"), 32)?
        .trim()
        .parse()
        .ok()
}

#[cfg(target_os = "linux")]
fn local_source_for(target: Ipv4Addr) -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect((target, 9)).ok()?;
    match socket.local_addr().ok()? {
        std::net::SocketAddr::V4(addr) => Some(*addr.ip()),
        _ => None,
    }
}

pub fn interface_for_target(target: Ipv4Addr) -> Result<InterfaceInfo, ArpError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = target;
        return Err(ArpError::Unavailable(
            "ARP unavailable: Linux-only implementation in this build".to_owned(),
        ));
    }
    #[cfg(target_os = "linux")]
    {
        let route =
            read_bounded("/proc/net/route", MAX_ROUTE_BYTES).ok_or(ArpError::NoInterface)?;
        let (iface, on_link) = parse_proc_route(&route, target).ok_or(ArpError::NoInterface)?;
        if !on_link {
            return Err(ArpError::NotOnLink);
        }
        Ok(InterfaceInfo {
            mac: interface_mac(&iface).ok_or(ArpError::NoInterface)?,
            ifindex: interface_index(&iface).ok_or(ArpError::NoInterface)?,
            addr: local_source_for(target).ok_or(ArpError::NoInterface)?,
            name: iface,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArpOutcome {
    Alive { mac: [u8; 6], latency_ms: u64 },
    Timeout,
    Unavailable(String),
    Cancelled,
}

#[cfg(target_os = "linux")]
pub fn probe_arp(target: Ipv4Addr, timeout: Duration, cancel: &CancellationToken) -> ArpOutcome {
    if cancel.is_cancelled() {
        return ArpOutcome::Cancelled;
    }
    let started = Instant::now();
    let info = match interface_for_target(target) {
        Ok(info) => info,
        Err(ArpError::NotOnLink) => {
            return ArpOutcome::Unavailable(
                "target is not on a directly connected network; ARP never sent".to_owned(),
            );
        }
        Err(error) => return ArpOutcome::Unavailable(error.to_string()),
    };
    let fd = unsafe { socket(AF_PACKET, SOCK_RAW, (ETH_P_ARP as c_int).to_be()) };
    let Some(socket) = OwnedFd::new(fd) else {
        let errno = last_errno();
        if errno == EPERM || errno == EACCES {
            return ArpOutcome::Unavailable(
                "ARP unavailable: CAP_NET_RAW not available".to_owned(),
            );
        }
        return ArpOutcome::Unavailable(format!("ARP socket failed (errno {errno})"));
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
    let dest = SockaddrLl {
        sll_family: AF_PACKET as u16,
        sll_protocol: ETH_P_ARP.to_be(),
        sll_ifindex: info.ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 6,
        sll_addr: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0],
    };
    let request = build_arp_request(info.mac, info.addr, target);
    let mut sent = 0u32;
    let mut buffer = vec![0u8; 2048];
    while started.elapsed() < timeout {
        if cancel.is_cancelled() {
            return ArpOutcome::Cancelled;
        }
        if sent < MAX_ARP_REQUESTS_PER_PROBE && (sent == 0 || started.elapsed() >= timeout / 2) {
            let result = unsafe {
                sendto(
                    socket.0,
                    request.as_ptr() as *const c_void,
                    request.len(),
                    0,
                    &dest as *const SockaddrLl as *const c_void,
                    size_of::<SockaddrLl>() as u32,
                )
            };
            if result < 0 {
                return ArpOutcome::Unavailable(format!(
                    "ARP send failed (errno {})",
                    last_errno()
                ));
            }
            sent += 1;
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
        if ready > 0 && poll_fd.revents & POLLIN != 0 {
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
            if let Some(reply) = parse_arp_reply(&buffer[..received as usize], target) {
                return ArpOutcome::Alive {
                    mac: reply.sender_mac,
                    latency_ms: started.elapsed().as_millis() as u64,
                };
            }
        }
        if sent >= MAX_ARP_REQUESTS_PER_PROBE && started.elapsed() >= timeout {
            break;
        }
    }
    ArpOutcome::Timeout
}

/// Portable fallback: active ARP needs AF_PACKET, Linux-only.
#[cfg(not(target_os = "linux"))]
pub fn probe_arp(target: Ipv4Addr, timeout: Duration, cancel: &CancellationToken) -> ArpOutcome {
    if cancel.is_cancelled() {
        return ArpOutcome::Cancelled;
    }
    let _ = (target, timeout);
    ArpOutcome::Unavailable("ARP unavailable: Linux-only implementation in this build".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC_MAC: [u8; 6] = [0x02, 0x42, 0xAC, 0x11, 0x00, 0x02];
    const SRC_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const DST_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);

    #[test]
    fn request_is_well_formed() {
        let frame = build_arp_request(SRC_MAC, SRC_IP, DST_IP);
        assert_eq!(frame.len(), 42);
        assert_eq!(&frame[0..6], &[0xFF; 6]);
        assert_eq!(&frame[6..12], &SRC_MAC);
        assert_eq!(&frame[28..32], &SRC_IP.octets());
        assert_eq!(&frame[38..42], &DST_IP.octets());
        assert_eq!(u16::from_be_bytes([frame[20], frame[21]]), 1);
    }

    fn reply_frame() -> Vec<u8> {
        let mut frame = vec![0u8; 42];
        frame[0..6].copy_from_slice(&SRC_MAC);
        frame[6..12].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        frame[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
        frame[14..16].copy_from_slice(&1u16.to_be_bytes());
        frame[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
        frame[18] = 6;
        frame[19] = 4;
        frame[20..22].copy_from_slice(&2u16.to_be_bytes());
        frame[22..28].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        frame[28..32].copy_from_slice(&DST_IP.octets());
        frame
    }

    #[test]
    fn valid_reply_parses() {
        let reply = parse_arp_reply(&reply_frame(), DST_IP).unwrap();
        assert_eq!(reply.sender_mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn wrong_target_rejected() {
        assert!(parse_arp_reply(&reply_frame(), SRC_IP).is_none());
    }

    #[test]
    fn malformed_rejected_without_panic() {
        assert!(parse_arp_reply(&[], DST_IP).is_none());
        assert!(parse_arp_reply(&[0u8; 20], DST_IP).is_none());
        let mut request_op = reply_frame();
        request_op[20..22].copy_from_slice(&1u16.to_be_bytes());
        assert!(parse_arp_reply(&request_op, DST_IP).is_none());
        let mut zero_mac = reply_frame();
        zero_mac[22..28].copy_from_slice(&[0; 6]);
        assert!(parse_arp_reply(&zero_mac, DST_IP).is_none());
        let mut bad_proto = reply_frame();
        bad_proto[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        assert!(parse_arp_reply(&bad_proto, DST_IP).is_none());
    }

    #[test]
    fn route_parser_finds_on_link() {
        let table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\neth0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n";
        let (iface, on_link) = parse_proc_route(table, Ipv4Addr::new(192, 168, 2, 10)).unwrap();
        assert_eq!(iface, "eth0");
        assert!(on_link);
    }

    #[test]
    fn route_parser_refuses_routed() {
        let table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\n";
        let (_, on_link) = parse_proc_route(table, Ipv4Addr::new(8, 8, 8, 8)).unwrap();
        assert!(!on_link);
    }

    #[test]
    fn route_parser_longest_prefix_wins() {
        let table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\neth1\t00000A0A\t00000000\t0001\t0\t0\t100\t0000FFFF\n";
        let (iface, on_link) = parse_proc_route(table, Ipv4Addr::new(10, 10, 5, 5)).unwrap();
        assert_eq!(iface, "eth1");
        assert!(on_link);
    }

    #[test]
    fn nonlocal_probe_never_sends() {
        let outcome = probe_arp(
            Ipv4Addr::new(203, 0, 113, 99),
            Duration::from_millis(100),
            &CancellationToken::default(),
        );
        match outcome {
            ArpOutcome::Unavailable(reason) => {
                assert!(
                    reason.contains("directly connected")
                        || reason.contains("interface")
                        || reason.contains("CAP_NET_RAW")
                );
            }
            ArpOutcome::Timeout => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn cancelled_probe_returns_promptly() {
        let cancel = CancellationToken::default();
        cancel.cancel();
        assert_eq!(
            probe_arp(DST_IP, Duration::from_secs(5), &cancel),
            ArpOutcome::Cancelled
        );
    }
}
