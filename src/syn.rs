use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
#[cfg(target_os = "linux")]
use std::os::raw::{c_int, c_void};
use std::sync::{Mutex, atomic::AtomicBool};
use std::time::{Duration, Instant};

use crate::tcp_scanner::{
    NativeTcpScanner, PortProbe, PortScanner, PortState, ScanConfig, ScanOutcome,
};

#[cfg(target_os = "linux")]
const AF_INET: c_int = 2;
#[cfg(target_os = "linux")]
const SOCK_RAW: c_int = 3;
#[cfg(target_os = "linux")]
const IPPROTO_TCP: c_int = 6;
#[cfg(target_os = "linux")]
const IPPROTO_ICMP: c_int = 1;
#[cfg(target_os = "linux")]
const IP_HDRINCL: c_int = 3;
#[cfg(target_os = "linux")]
const IPPROTO_IP: c_int = 0;
#[cfg(target_os = "linux")]
const SOL_SOCKET: c_int = 1;
#[cfg(target_os = "linux")]
const SO_RCVTIMEO: c_int = 20;
#[cfg(target_os = "linux")]
const EINTR: c_int = 4;
#[cfg(target_os = "linux")]
const EAGAIN: c_int = 11;
#[cfg(target_os = "linux")]
const EPERM: c_int = 1;
#[cfg(target_os = "linux")]
const EACCES: c_int = 13;
#[cfg(target_os = "linux")]
const POLLIN: i16 = 0x0001;

pub const MAX_SYN_IN_FLIGHT_HARD: usize = 128;
pub const DEFAULT_SYN_MIN_INTERVAL: Duration = Duration::from_micros(1000);
pub const SYN_SEQ_BASE: u32 = 0x5258_0000;

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: [u8; 4],
    sin_zero: [u8; 8],
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

fn checksum(words: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = words.chunks_exact(2);
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

pub fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, tcp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp);
    checksum(&pseudo)
}

pub fn sequence_for_port(port: u16) -> u32 {
    SYN_SEQ_BASE | u32::from(port)
}

pub fn build_syn(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16, seq: u32) -> Vec<u8> {
    let mut packet = vec![0u8; 20 + 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&40u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    let ip_sum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    let tcp = &mut packet[20..40];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 0x02;
    tcp[14..16].copy_from_slice(&64240u16.to_be_bytes());
    let tcp_sum = tcp_checksum(src, dst, tcp);
    tcp[16..18].copy_from_slice(&tcp_sum.to_be_bytes());
    packet
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpResponse {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub syn: bool,
    pub ack_flag: bool,
    pub rst: bool,
}

pub fn parse_tcp_response(bytes: &[u8]) -> Option<TcpResponse> {
    if bytes.len() < 20 {
        return None;
    }
    let ihl = (bytes[0] & 0x0F) as usize * 4;
    if bytes[0] >> 4 != 4 || ihl < 20 || bytes.len() < ihl + 20 || bytes[9] != 6 {
        return None;
    }
    let total = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if total < ihl + 20 || bytes.len() < total {
        return None;
    }
    let src_ip = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let dst_ip = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    let tcp = &bytes[ihl..ihl + 20];
    let data_offset = (tcp[12] >> 4) as usize * 4;
    if data_offset < 20 || ihl + data_offset > total {
        return None;
    }
    Some(TcpResponse {
        src_ip,
        dst_ip,
        src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        ack: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        syn: tcp[13] & 0x02 != 0,
        ack_flag: tcp[13] & 0x10 != 0,
        rst: tcp[13] & 0x04 != 0,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynVerdict {
    Open,
    Closed,
}

pub fn classify_syn_response(
    target: Ipv4Addr,
    local: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    response: &TcpResponse,
) -> Option<SynVerdict> {
    if response.src_ip != target
        || response.dst_ip != local
        || response.src_port != dst_port
        || response.dst_port != src_port
        || response.ack != seq.wrapping_add(1)
    {
        return None;
    }
    if response.syn && response.ack_flag && !response.rst {
        Some(SynVerdict::Open)
    } else if response.rst && !response.syn {
        Some(SynVerdict::Closed)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpVerdict {
    Filtered,
}

pub fn classify_icmp_unreachable(
    bytes: &[u8],
    target: Ipv4Addr,
    local: Ipv4Addr,
    src_port: u16,
) -> Option<(IcmpVerdict, u16, u32)> {
    if bytes.len() < 20 + 8 {
        return None;
    }
    let ihl = (bytes[0] & 0x0F) as usize * 4;
    if bytes[0] >> 4 != 4 || ihl < 20 || bytes[9] != 1 || bytes.len() < ihl + 8 {
        return None;
    }
    let icmp = &bytes[ihl..];
    if icmp[0] != 3 || !matches!(icmp[1], 1 | 2 | 3 | 9 | 10 | 13) {
        return None;
    }
    if icmp.len() < 8 + 20 + 8 {
        return None;
    }
    let inner = &icmp[8..];
    let inner_ihl = (inner[0] & 0x0F) as usize * 4;
    if inner[0] >> 4 != 4 || inner_ihl < 20 || inner.len() < inner_ihl + 8 || inner[9] != 6 {
        return None;
    }
    let inner_src = Ipv4Addr::new(inner[12], inner[13], inner[14], inner[15]);
    let inner_dst = Ipv4Addr::new(inner[16], inner[17], inner[18], inner[19]);
    if inner_src != local || inner_dst != target {
        return None;
    }
    let inner_sport = u16::from_be_bytes([inner[inner_ihl], inner[inner_ihl + 1]]);
    let inner_dport = u16::from_be_bytes([inner[inner_ihl + 2], inner[inner_ihl + 3]]);
    if inner_sport != src_port || inner_dport == 0 {
        return None;
    }
    let inner_seq = u32::from_be_bytes([
        inner[inner_ihl + 4],
        inner[inner_ihl + 5],
        inner[inner_ihl + 6],
        inner[inner_ihl + 7],
    ]);
    Some((IcmpVerdict::Filtered, inner_dport, inner_seq))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SynError {
    Unavailable(String),
    NoLocalAddress,
    Ipv6Unsupported,
}

impl std::fmt::Display for SynError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(f, "raw SYN unavailable: {reason}"),
            Self::NoLocalAddress => write!(f, "raw SYN unavailable: no local source address"),
            Self::Ipv6Unsupported => write!(
                f,
                "raw SYN unavailable: IPv6 not implemented (Linux IPv4 only)"
            ),
        }
    }
}

pub fn local_address_for(dst: Ipv4Addr) -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect((dst, 9)).ok()?;
    match socket.local_addr().ok()? {
        std::net::SocketAddr::V4(addr) => Some(*addr.ip()),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn open_raw_tcp() -> Result<OwnedFd, SynError> {
    let fd = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_TCP) };
    match OwnedFd::new(fd) {
        Some(owned) => {
            let one: c_int = 1;
            unsafe {
                setsockopt(
                    owned.0,
                    IPPROTO_IP,
                    IP_HDRINCL,
                    &one as *const c_int as *const c_void,
                    size_of::<c_int>() as u32,
                );
            }
            Ok(owned)
        }
        None => Err(match last_errno() {
            e if e == EPERM || e == EACCES => {
                SynError::Unavailable("CAP_NET_RAW not available".to_owned())
            }
            e => SynError::Unavailable(format!("raw TCP socket failed (errno {e})")),
        }),
    }
}

#[cfg(target_os = "linux")]
fn open_raw_icmp() -> Option<OwnedFd> {
    OwnedFd::new(unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) })
}

#[cfg(target_os = "linux")]
fn set_timeout(fd: c_int, timeout: Duration) {
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

struct Outstanding {
    seq: u32,
    deadline: Instant,
    attempts: u32,
    first_sent: Instant,
}

pub struct SynOutcome {
    pub outcome: ScanOutcome,
    pub icmp_listening: bool,
    pub pacing_log: Vec<String>,
}

/// Raw SYN scanner implementing [`PortScanner`].
///
/// IPv4 targets use the bounded raw SYN path when the process can open raw
/// sockets; IPv6 targets and raw-unavailable hosts fall back to TCP connect
/// with the fallback recorded (never reported as SYN). Mechanism use per
/// address is retained in a bounded map for event honesty.
pub struct SynScanner {
    connect: NativeTcpScanner,
    fallback: AtomicBool,
    fallback_reason: Mutex<Option<String>>,
    mechanisms: Mutex<BTreeMap<IpAddr, String>>,
    pacing: Mutex<Vec<String>>,
}

impl Default for SynScanner {
    fn default() -> Self {
        Self {
            connect: NativeTcpScanner,
            fallback: AtomicBool::new(false),
            fallback_reason: Mutex::new(None),
            mechanisms: Mutex::new(BTreeMap::new()),
            pacing: Mutex::new(Vec::new()),
        }
    }
}

impl SynScanner {
    fn record(&self, ip: IpAddr, mechanism: &str, fallback: Option<String>) {
        if let Ok(mut mechanisms) = self.mechanisms.lock() {
            if mechanisms.len() >= 1024 {
                mechanisms.clear();
            }
            mechanisms.insert(ip, mechanism.to_owned());
        }
        if let Some(reason) = fallback {
            self.fallback
                .store(true, std::sync::atomic::Ordering::Release);
            if let Ok(mut slot) = self.fallback_reason.lock() {
                if slot.is_none() {
                    *slot = Some(reason);
                }
            }
        }
    }
}

impl PortScanner for SynScanner {
    fn scan(&self, ip: IpAddr, ports: &[u16], config: &ScanConfig) -> ScanOutcome {
        let IpAddr::V4(target) = ip else {
            self.record(
                ip,
                "connect",
                Some("raw SYN unavailable: IPv6 not implemented (Linux IPv4 only)".to_owned()),
            );
            return self.connect.scan(ip, ports, config);
        };
        match scan_syn(target, ports, config, DEFAULT_SYN_MIN_INTERVAL) {
            Ok(syn) => {
                self.record(ip, "syn", None);
                if let Ok(mut pacing) = self.pacing.lock() {
                    for line in syn.pacing_log {
                        if pacing.len() < 8 {
                            pacing.push(line);
                        }
                    }
                }
                syn.outcome
            }
            Err(error) => {
                self.record(ip, "connect", Some(error.to_string()));
                self.connect.scan(ip, ports, config)
            }
        }
    }

    fn pacing_log(&self) -> Vec<String> {
        self.pacing
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    fn runtime_note(&self) -> Option<String> {
        self.fallback_reason
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    fn address_mechanisms(&self) -> Vec<(IpAddr, String)> {
        self.mechanisms
            .lock()
            .map(|guard| guard.clone().into_iter().collect())
            .unwrap_or_default()
    }
}

#[cfg(target_os = "linux")]
pub fn scan_syn(
    target: Ipv4Addr,
    ports: &[u16],
    config: &ScanConfig,
    min_interval: Duration,
) -> Result<SynOutcome, SynError> {
    let local = local_address_for(target).ok_or(SynError::NoLocalAddress)?;
    let send_fd = open_raw_tcp()?;
    let recv_fd = open_raw_tcp()?;
    let icmp_fd = open_raw_icmp();
    let icmp_listening = icmp_fd.is_some();
    set_timeout(recv_fd.0, Duration::from_millis(25));
    if let Some(icmp) = &icmp_fd {
        set_timeout(icmp.0, Duration::from_millis(25));
    }
    let src_port: u16 = 50000 + (std::process::id() % 10000) as u16;
    let window_max = config.max_concurrent.clamp(1, MAX_SYN_IN_FLIGHT_HARD);
    let mut eff_window = window_max;
    let mut eff_timeout = config.timeout;
    let mut eff_interval = min_interval;
    let pacing_bounds = crate::pacing::PacingBounds {
        min_concurrency: 1,
        max_concurrency: window_max,
        min_timeout_ms: 100,
        max_timeout_ms: 10_000,
        min_delay_ms: 0,
        max_delay_ms: 1000,
    };
    let mut pacing_log: Vec<String> = Vec::new();
    let mut window_completions: usize = 0;
    let mut window_timeouts: usize = 0;
    let mut window_rtt_ms: u64 = 0;
    let mut queue: VecDeque<(u16, u32)> = {
        let mut sorted: Vec<u16> = ports.iter().copied().filter(|p| *p > 0).collect();
        sorted.sort_unstable();
        sorted.dedup();
        sorted.into_iter().map(|p| (p, 1)).collect()
    };
    let total = queue.len();
    let mut probes: Vec<PortProbe> = Vec::with_capacity(total.min(1024));
    let mut outstanding: BTreeMap<u16, Outstanding> = BTreeMap::new();
    let mut truncated = false;
    let mut cancelled = false;
    let fd_peak = 2 + usize::from(icmp_listening);
    let mut last_send = Instant::now()
        .checked_sub(min_interval)
        .unwrap_or(Instant::now());
    let is_expired = |now: Instant| config.deadline.is_some_and(|d| now >= d);
    let destination = SockaddrIn {
        sin_family: AF_INET as u16,
        sin_port: 0,
        sin_addr: target.octets(),
        sin_zero: [0; 8],
    };

    let send_one = |port: u16, seq: u32| -> bool {
        let packet = build_syn(local, target, src_port, port, seq);
        unsafe {
            sendto(
                send_fd.0,
                packet.as_ptr() as *const c_void,
                packet.len(),
                0,
                &destination as *const SockaddrIn as *const c_void,
                size_of::<SockaddrIn>() as u32,
            ) >= 0
        }
    };

    'outer: while !queue.is_empty() || !outstanding.is_empty() {
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
        while outstanding.len() < eff_window {
            let Some((port, attempts)) = queue.pop_front() else {
                break;
            };
            if config.cancel.is_cancelled() || is_expired(Instant::now()) {
                queue.push_front((port, attempts));
                cancelled |= config.cancel.is_cancelled();
                truncated = true;
                break 'outer;
            }
            if last_send.elapsed() < eff_interval {
                queue.push_front((port, attempts));
                break;
            }
            let seq = sequence_for_port(port);
            if !send_one(port, seq) {
                let errno = last_errno();
                if errno == EPERM || errno == EACCES {
                    queue.push_front((port, attempts));
                    return Err(SynError::Unavailable(
                        "raw SYN send denied mid-scan (privilege revoked?)".to_owned(),
                    ));
                }
                probes.push(PortProbe {
                    port,
                    state: PortState::Error,
                    latency: Duration::ZERO,
                    detail: format!("SYN send to {target}:{port} failed (errno {errno})"),
                    attempts,
                });
                window_completions += 1;
                continue;
            }
            last_send = Instant::now();
            outstanding.insert(
                port,
                Outstanding {
                    seq,
                    deadline: Instant::now() + eff_timeout,
                    attempts,
                    first_sent: Instant::now(),
                },
            );
        }
        let mut poll_fds = vec![PollFd {
            fd: recv_fd.0,
            events: POLLIN,
            revents: 0,
        }];
        if let Some(icmp) = &icmp_fd {
            poll_fds.push(PollFd {
                fd: icmp.0,
                events: POLLIN,
                revents: 0,
            });
        }
        let ready = unsafe { poll(poll_fds.as_mut_ptr(), poll_fds.len() as u64, 25) };
        if config.cancel.is_cancelled() {
            cancelled = true;
            truncated = true;
            break;
        }
        if is_expired(Instant::now()) {
            truncated = true;
            break;
        }
        if ready < 0 && last_errno() == EINTR {
            continue;
        }
        let tcp_ready = poll_fds.first().is_some_and(|p| p.revents & POLLIN != 0);
        let icmp_ready = poll_fds.get(1).is_some_and(|p| p.revents & POLLIN != 0);
        let mut finished: Vec<u16> = Vec::new();
        let mut to_retry: Vec<(u16, u32)> = Vec::new();
        if tcp_ready {
            let mut buffer = vec![0u8; 2048];
            loop {
                let received = unsafe {
                    recvfrom(
                        recv_fd.0,
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
                        break;
                    }
                    break;
                }
                let Some(response) = parse_tcp_response(&buffer[..received as usize]) else {
                    continue;
                };
                let mut matched: Option<(u16, SynVerdict)> = None;
                for (&port, entry) in outstanding.iter() {
                    if finished.contains(&port) {
                        continue;
                    }
                    if let Some(verdict) =
                        classify_syn_response(target, local, src_port, port, entry.seq, &response)
                    {
                        matched = Some((port, verdict));
                        break;
                    }
                }
                let Some((port, verdict)) = matched else {
                    continue;
                };
                let entry = &outstanding[&port];
                let latency = entry.first_sent.elapsed();
                let attempts = entry.attempts;
                match verdict {
                    SynVerdict::Open => probes.push(PortProbe {
                        port,
                        state: PortState::Open,
                        latency,
                        detail: format!("SYN+ACK from {target}:{port} (raw SYN)"),
                        attempts,
                    }),
                    SynVerdict::Closed => probes.push(PortProbe {
                        port,
                        state: PortState::Closed,
                        latency,
                        detail: format!(
                            "RST from {target}:{port} (raw SYN); host responded, port closed"
                        ),
                        attempts,
                    }),
                }
                finished.push(port);
            }
        }
        if icmp_ready {
            if let Some(icmp) = &icmp_fd {
                let mut buffer = vec![0u8; 2048];
                loop {
                    let received = unsafe {
                        recvfrom(
                            icmp.0,
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
                            break;
                        }
                        break;
                    }
                    let Some((_, inner_dport, inner_seq)) = classify_icmp_unreachable(
                        &buffer[..received as usize],
                        target,
                        local,
                        src_port,
                    ) else {
                        continue;
                    };
                    if outstanding
                        .get(&inner_dport)
                        .is_some_and(|entry| entry.seq == inner_seq)
                        && !finished.contains(&inner_dport)
                    {
                        let entry = &outstanding[&inner_dport];
                        probes.push(PortProbe {
                            port: inner_dport,
                            state: PortState::Filtered,
                            latency: entry.first_sent.elapsed(),
                            detail: format!(
                                "ICMP destination unreachable for {target}:{inner_dport} (raw SYN)"
                            ),
                            attempts: entry.attempts,
                        });
                        finished.push(inner_dport);
                    }
                }
            }
        }
        let now = Instant::now();
        for (&port, entry) in outstanding.iter() {
            if finished.contains(&port) {
                continue;
            }
            if now >= entry.deadline {
                window_timeouts += 1;
                if entry.attempts <= config.max_retries {
                    to_retry.push((port, entry.attempts + 1));
                } else {
                    probes.push(PortProbe {
                        port,
                        state: PortState::OpenOrFiltered,
                        latency: entry.first_sent.elapsed(),
                        detail: format!(
                            "no response from {target}:{port} after {} attempts (raw SYN); filtered or silently dropped",
                            entry.attempts
                        ),
                        attempts: entry.attempts,
                    });
                }
                finished.push(port);
            }
        }
        for port in finished.iter() {
            window_completions += 1;
            if let Some(entry) = outstanding.get(port) {
                window_rtt_ms += entry.first_sent.elapsed().as_millis() as u64;
            }
        }
        for port in finished {
            outstanding.remove(&port);
        }
        for (port, attempts) in to_retry.into_iter().rev() {
            queue.push_front((port, attempts));
        }
        if window_completions >= 32 {
            let completed = window_completions as f64;
            let sample = crate::pacing::PacingSample {
                rtt_ms: window_rtt_ms / window_completions.max(1) as u64,
                timeout_ratio: window_timeouts as f64 / completed,
                failure_ratio: 0.0,
                backlog: queue.len(),
                socket_pressure: outstanding.len() as f64 / window_max.max(1) as f64,
            };
            let decision = crate::pacing::suggest(
                eff_window,
                eff_timeout,
                Duration::from_millis(0),
                sample,
                pacing_bounds,
            );
            eff_window = decision.concurrency;
            eff_timeout = Duration::from_millis(decision.timeout_ms);
            eff_interval = Duration::from_micros(500)
                .max(Duration::from_micros(
                    decision.retry_delay_ms.saturating_mul(10),
                ))
                .min(Duration::from_millis(8));
            if pacing_log.len() < 8 {
                pacing_log.push(crate::pacing::describe(&decision));
            }
            window_completions = 0;
            window_timeouts = 0;
            window_rtt_ms = 0;
        }
    }
    let unscanned = queue.len() + outstanding.len();
    if unscanned > 0 {
        truncated = true;
    }
    probes.sort_by_key(|p| p.port);
    Ok(SynOutcome {
        outcome: ScanOutcome {
            probes,
            truncated,
            cancelled,
            unscanned,
            fd_peak,
        },
        icmp_listening,
        pacing_log,
    })
}

/// Portable fallback: raw SYN is Linux-IPv4 only.
#[cfg(not(target_os = "linux"))]
pub fn scan_syn(
    target: Ipv4Addr,
    ports: &[u16],
    config: &ScanConfig,
    min_interval: Duration,
) -> Result<SynOutcome, SynError> {
    let _ = (target, ports, config, min_interval);
    Err(SynError::Unavailable(
        "raw SYN unavailable: Linux-only implementation in this build".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const DST: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);

    #[test]
    fn syn_packet_has_valid_checksums() {
        let packet = build_syn(SRC, DST, 50000, 80, 0x1234);
        assert_eq!(packet.len(), 40);
        assert_eq!(packet[9], 6);
        assert_eq!(checksum(&packet[..20]), 0);
        assert_eq!(packet[33], 0x02);
        assert_eq!(tcp_checksum(SRC, DST, &packet[20..40]), 0);
    }

    #[test]
    fn sequences_are_deterministic_per_port() {
        assert_eq!(sequence_for_port(80), sequence_for_port(80));
        assert_ne!(sequence_for_port(80), sequence_for_port(443));
    }

    fn synack(src_port: u16, dst_port: u16, seq: u32) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[9] = 6;
        packet[12..16].copy_from_slice(&DST.octets());
        packet[16..20].copy_from_slice(&SRC.octets());
        let tcp = &mut packet[20..40];
        tcp[0..2].copy_from_slice(&dst_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&src_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&0x9ABCDEFu32.to_be_bytes());
        tcp[8..12].copy_from_slice(&seq.wrapping_add(1).to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x12;
        packet
    }

    #[test]
    fn synack_classifies_open() {
        let bytes = synack(50000, 80, 1000);
        let response = parse_tcp_response(&bytes).unwrap();
        assert!(response.syn && response.ack_flag && !response.rst);
        assert_eq!(
            classify_syn_response(DST, SRC, 50000, 80, 1000, &response),
            Some(SynVerdict::Open)
        );
    }

    #[test]
    fn rst_classifies_closed() {
        let mut bytes = synack(50000, 80, 1000);
        bytes[33] = 0x14;
        let response = parse_tcp_response(&bytes).unwrap();
        assert_eq!(
            classify_syn_response(DST, SRC, 50000, 80, 1000, &response),
            Some(SynVerdict::Closed)
        );
    }

    #[test]
    fn unrelated_packets_rejected() {
        let bytes = synack(50000, 80, 1000);
        let response = parse_tcp_response(&bytes).unwrap();
        assert_eq!(
            classify_syn_response(DST, SRC, 50000, 443, 1000, &response),
            None,
            "wrong port must not correlate"
        );
        assert_eq!(
            classify_syn_response(DST, SRC, 59999, 80, 1000, &response),
            None,
            "wrong source port must not correlate"
        );
        assert_eq!(
            classify_syn_response(DST, SRC, 50000, 80, 9999, &response),
            None,
            "wrong sequence must not correlate"
        );
        let other_ip = Ipv4Addr::new(203, 0, 113, 7);
        assert_eq!(
            classify_syn_response(other_ip, SRC, 50000, 80, 1000, &response),
            None,
            "wrong source IP must not correlate"
        );
    }

    #[test]
    fn malformed_packets_never_panic() {
        assert!(parse_tcp_response(&[]).is_none());
        assert!(parse_tcp_response(&[0u8; 10]).is_none());
        assert!(parse_tcp_response(&[0x46u8; 40]).is_none());
        assert!(parse_tcp_response(&[0x45, 0, 0, 200]).is_none());
        let mut truncated = synack(50000, 80, 1);
        truncated.truncate(30);
        assert!(parse_tcp_response(&truncated).is_none());
        let mut bad_proto = synack(50000, 80, 1);
        bad_proto[9] = 17;
        assert!(parse_tcp_response(&bad_proto).is_none());
        assert!(parse_tcp_response(&vec![0x45u8; 1500]).is_none());
    }

    #[test]
    fn icmp_unreachable_means_filtered() {
        let mut outer = vec![0u8; 20 + 8 + 20 + 8];
        outer[0] = 0x45;
        outer[9] = 1;
        outer[20] = 3;
        outer[21] = 3;
        let inner = &mut outer[28..];
        inner[0] = 0x45;
        inner[9] = 6;
        inner[12..16].copy_from_slice(&SRC.octets());
        inner[16..20].copy_from_slice(&DST.octets());
        inner[20..22].copy_from_slice(&50000u16.to_be_bytes());
        inner[22..24].copy_from_slice(&80u16.to_be_bytes());
        inner[24..28].copy_from_slice(&sequence_for_port(80).to_be_bytes());
        assert_eq!(
            classify_icmp_unreachable(&outer, DST, SRC, 50000),
            Some((IcmpVerdict::Filtered, 80, sequence_for_port(80)))
        );
        assert_eq!(classify_icmp_unreachable(&outer, SRC, DST, 50000), None);
        assert_eq!(classify_icmp_unreachable(&outer, DST, SRC, 50001), None);
        let mut echo = outer.clone();
        echo[20] = 8;
        assert!(classify_icmp_unreachable(&echo, DST, SRC, 50000).is_none());
        assert!(classify_icmp_unreachable(&[0u8; 10], DST, SRC, 50000).is_none());
        let mut no_ports = outer.clone();
        no_ports.truncate(20 + 8 + 20);
        assert!(classify_icmp_unreachable(&no_ports, DST, SRC, 50000).is_none());
    }

    #[test]
    fn error_display_identifies_cause() {
        assert!(SynError::Ipv6Unsupported.to_string().contains("IPv6"));
        assert!(
            SynError::Unavailable("x".to_owned())
                .to_string()
                .contains("raw SYN unavailable")
        );
    }
}
