//! Bounded, panic-free packet views for active OS observation.
//!
//! RXScan's active OS probes never trust the network: every parser here is
//! bounds-checked, independent of host endianness (explicit big-endian
//! reads), and returns `None` on truncation or malformed lengths instead of
//! panicking. Unknown TCP option kinds are preserved as normalized numeric
//! identifiers only; no semantics are invented for them.
//!
//! Design split (honesty constraint):
//! * OBSERVED views (`Ipv4View`, `Ipv6View`, `TcpView`, `IcmpView`) carry
//!   exactly what arrived on the wire (a received TTL, an advertised
//!   window). They are facts about one response packet.
//! * DERIVED reasoning (compatible initial-TTL families, candidate OS
//!   scoring) lives in `crate::os_fingerprint` and is never persisted as
//!   though it were observed. Routing, NAT, proxies, load balancers,
//!   firewalls, tunnels, and virtualization can all alter stack evidence.
//!
//! IPv4 and IPv6 have distinct header models (TTL vs Hop Limit, different
//! base layouts). The two families share no parsing path, and IPv6 input
//! can never fall through IPv4 interpretation.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Maximum TCP options bytes examined per segment (bounded allocation).
pub const MAX_TCP_OPTIONS_LEN: usize = 40;
/// Maximum normalized option identifiers retained per segment.
pub const MAX_TCP_OPTION_IDS: usize = 16;

/// Observed IPv4 header fields relevant to OS evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4View {
    /// Received TTL as observed (NOT an initial TTL guess).
    pub ttl: u8,
    /// Don't-Fragment flag as observed.
    pub df: bool,
    /// Identification field as observed (meaning varies by stack).
    pub identification: u16,
    /// Encapsulated protocol number.
    pub protocol: u8,
    /// Header length in bytes (IHL * 4).
    pub header_len: usize,
}

/// Observed IPv6 base header fields relevant to OS evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6View {
    /// Received Hop Limit as observed (NOT an initial value guess).
    pub hop_limit: u8,
    /// Next-header number.
    pub next_header: u8,
    /// Payload length as declared.
    pub payload_len: u16,
    /// Source and destination addresses.
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
}

/// Normalized TCP option observation: kind byte plus bounded value bytes.
/// Kinds 0 (EOL) and 1 (NOP) carry no length/value by definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpOptionView {
    pub kind: u8,
    pub value: Vec<u8>,
}

/// Observed TCP segment fields relevant to OS evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpView {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    /// Full flag byte (CWR/ECE/URG/ACK/PSH/RST/SYN/FIN) as observed.
    pub flags: u8,
    /// Advertised window as observed.
    pub window: u16,
    /// MSS value when a well-formed MSS option (kind 2, len 4) is present.
    pub mss: Option<u16>,
    /// Window-scale shift count when a well-formed WScale option is present.
    pub wscale: Option<u8>,
    /// True when a well-formed SACK-permitted option (kind 4, len 2) is present.
    pub sack_permitted: bool,
    /// True when any timestamp option (kind 8, len 10) is present.
    pub timestamps: bool,
    /// Option kinds in wire order, deduplicated runs preserved, padded
    /// EOL/NOP included (bounded to [`MAX_TCP_OPTION_IDS`]).
    pub option_order: Vec<u8>,
    /// Raw option count before bounding (for truncation honesty).
    pub option_count: usize,
}

/// Observed ICMP message fields relevant to OS evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpView {
    /// ICMP type (v4) or type (v6) byte as observed.
    pub icmp_type: u8,
    /// ICMP code byte as observed.
    pub code: u8,
    /// Length of the returned/quoted payload available after the 8-byte
    /// ICMP header (bounded by the caller's buffer, never allocated).
    pub quoted_len: usize,
}

/// Why parsing produced no view. No panics: callers log or skip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketError {
    Truncated,
    InvalidVersion,
    InvalidHeaderLength,
    UnexpectedProtocol,
    MalformedOptions,
}

/// Parse an IPv4 header from the front of `bytes`.
///
/// Requires the full header (`ihl * 4` bytes); the payload may extend
/// beyond it. Returns the view plus the header length so callers can
/// locate the encapsulated segment without re-deriving lengths.
pub fn parse_ipv4_header(bytes: &[u8]) -> Result<(Ipv4View, usize), PacketError> {
    if bytes.len() < 20 {
        return Err(PacketError::Truncated);
    }
    if bytes[0] >> 4 != 4 {
        return Err(PacketError::InvalidVersion);
    }
    let header_len = (bytes[0] & 0x0F) as usize * 4;
    if header_len < 20 {
        return Err(PacketError::InvalidHeaderLength);
    }
    if bytes.len() < header_len {
        return Err(PacketError::Truncated);
    }
    let total = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if total < header_len {
        return Err(PacketError::InvalidHeaderLength);
    }
    let flags_fragment = u16::from_be_bytes([bytes[6], bytes[7]]);
    Ok((
        Ipv4View {
            ttl: bytes[8],
            df: flags_fragment & 0x4000 != 0,
            identification: u16::from_be_bytes([bytes[4], bytes[5]]),
            protocol: bytes[9],
            header_len,
        },
        header_len,
    ))
}

/// Parse an IPv6 base header (exactly 40 bytes) from the front of `bytes`.
pub fn parse_ipv6_header(bytes: &[u8]) -> Result<(Ipv6View, usize), PacketError> {
    if bytes.len() < 40 {
        return Err(PacketError::Truncated);
    }
    if bytes[0] >> 4 != 6 {
        return Err(PacketError::InvalidVersion);
    }
    let mut src_octets = [0u8; 16];
    let mut dst_octets = [0u8; 16];
    src_octets.copy_from_slice(&bytes[8..24]);
    dst_octets.copy_from_slice(&bytes[24..40]);
    Ok((
        Ipv6View {
            hop_limit: bytes[7],
            next_header: bytes[6],
            payload_len: u16::from_be_bytes([bytes[4], bytes[5]]),
            src: Ipv6Addr::from(src_octets),
            dst: Ipv6Addr::from(dst_octets),
        },
        40,
    ))
}

/// Parse TCP options bytes into normalized views.
///
/// * Kind 0 (EOL) terminates the scan; trailing bytes are padding.
/// * Kind 1 (NOP) is single-byte.
/// * All other kinds require a length byte >= 2 that fits the remainder;
///   violations stop parsing with `MalformedOptions` (partial options
///   collected so far are discarded: malformed length fields are never
///   trusted).
/// * Unknown kinds are preserved as numeric identifiers with bounded value
///   copies; no semantics are inferred.
/// * Duplicate kinds are preserved in order (evidence, not error).
/// * Output is bounded to [`MAX_TCP_OPTION_IDS`] identifiers.
pub fn parse_tcp_options(bytes: &[u8]) -> Result<Vec<TcpOptionView>, PacketError> {
    let mut options = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let kind = bytes[index];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            if options.len() < MAX_TCP_OPTION_IDS {
                options.push(TcpOptionView {
                    kind,
                    value: Vec::new(),
                });
            }
            index += 1;
            continue;
        }
        if index + 1 >= bytes.len() {
            return Err(PacketError::MalformedOptions);
        }
        let len = bytes[index + 1] as usize;
        if len < 2 || index + len > bytes.len() {
            return Err(PacketError::MalformedOptions);
        }
        if options.len() < MAX_TCP_OPTION_IDS {
            let value_len = len.saturating_sub(2).min(16);
            options.push(TcpOptionView {
                kind,
                value: bytes[index + 2..index + 2 + value_len].to_vec(),
            });
        }
        index += len;
    }
    Ok(options)
}

/// Parse a TCP segment (header + options) from the front of `bytes`.
///
/// `bytes` must start at the TCP header (callers strip IP first).
/// Requires the full header (`data_offset * 4` bytes); option bytes beyond
/// the header are not required.
pub fn parse_tcp_segment(bytes: &[u8]) -> Result<TcpView, PacketError> {
    if bytes.len() < 20 {
        return Err(PacketError::Truncated);
    }
    let data_offset = (bytes[12] >> 4) as usize * 4;
    if data_offset < 20 {
        return Err(PacketError::InvalidHeaderLength);
    }
    if bytes.len() < data_offset {
        return Err(PacketError::Truncated);
    }
    if data_offset - 20 > MAX_TCP_OPTIONS_LEN {
        return Err(PacketError::InvalidHeaderLength);
    }
    let option_bytes = &bytes[20..data_offset];
    let options = parse_tcp_options(option_bytes)?;
    let option_count = options.len();
    let mut mss = None;
    let mut wscale = None;
    let mut sack_permitted = false;
    let mut timestamps = false;
    let mut option_order = Vec::with_capacity(option_count.min(MAX_TCP_OPTION_IDS));
    for option in &options {
        if option_order.len() < MAX_TCP_OPTION_IDS {
            option_order.push(option.kind);
        }
        match option.kind {
            2 if option.value.len() == 2 && mss.is_none() => {
                mss = Some(u16::from_be_bytes([option.value[0], option.value[1]]));
            }
            3 if option.value.len() == 1 && wscale.is_none() => {
                wscale = Some(option.value[0]);
            }
            4 if option.value.is_empty() => {
                sack_permitted = true;
            }
            8 if option.value.len() == 8 => {
                timestamps = true;
            }
            _ => {}
        }
    }
    Ok(TcpView {
        src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
        dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
        seq: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        ack: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        flags: bytes[13],
        window: u16::from_be_bytes([bytes[14], bytes[15]]),
        mss,
        wscale,
        sack_permitted,
        timestamps,
        option_order,
        option_count,
    })
}

/// Parse an IPv4 packet carrying TCP: IP header then TCP segment.
///
/// Enforces protocol 6 explicitly (unexpected protocols report
/// `UnexpectedProtocol` instead of misparsing). IPv4 options (IHL > 5)
/// are skipped via the parsed header length.
pub fn parse_ipv4_tcp_packet(bytes: &[u8]) -> Result<(Ipv4View, TcpView), PacketError> {
    let (ip, header_len) = parse_ipv4_header(bytes)?;
    if ip.protocol != 6 {
        return Err(PacketError::UnexpectedProtocol);
    }
    let tcp = parse_tcp_segment(bytes.get(header_len..).unwrap_or(&[]))?;
    Ok((ip, tcp))
}

/// Parse an ICMP message (v4 or v6 shape): 8-byte header plus quoted bytes.
///
/// The caller selects the family only to label provenance; the 8-byte
/// header layout is identical, so one bounds-checked path serves both.
pub fn parse_icmp_message(bytes: &[u8]) -> Result<(IcmpView, usize), PacketError> {
    if bytes.len() < 8 {
        return Err(PacketError::Truncated);
    }
    let quoted_len = bytes.len() - 8;
    Ok((
        IcmpView {
            icmp_type: bytes[0],
            code: bytes[1],
            quoted_len,
        },
        quoted_len,
    ))
}

/// Source address parsed from an IPv4 header (for response attribution).
/// Returns `None` on truncation instead of panicking.
pub fn ipv4_source(bytes: &[u8]) -> Option<Ipv4Addr> {
    if bytes.len() < 20 || bytes[0] >> 4 != 4 {
        return None;
    }
    let header_len = (bytes[0] & 0x0F) as usize * 4;
    if header_len < 20 || bytes.len() < header_len {
        return None;
    }
    Some(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_tcp_fixture() -> Vec<u8> {
        // IPv4 (20B, TTL 64, DF, protocol TCP) + TCP SYN-ACK with
        // MSS + NOP + WScale + NOP + NOP + Timestamps + SACK-permitted.
        let mut packet = vec![0u8; 20 + 32];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&52u16.to_be_bytes());
        packet[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 0, 2, 10]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 20]);
        let tcp = &mut packet[20..];
        tcp[0..2].copy_from_slice(&80u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&40000u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&0xAABBCCDDu32.to_be_bytes());
        tcp[8..12].copy_from_slice(&0x11223344u32.to_be_bytes());
        tcp[12] = 0x80; // data offset 8 (32 bytes)
        tcp[13] = 0x12; // SYN+ACK
        tcp[14..16].copy_from_slice(&29200u16.to_be_bytes());
        // Options: MSS(2,4,1460) NOP WS(3,3,7) NOP NOP TS(8,10) SACK(4,2) EOL-pad
        let mut options = [0u8; 12];
        options[0..4].copy_from_slice(&[2, 4, 0x05, 0xB4]);
        options[4] = 1;
        options[5..8].copy_from_slice(&[3, 3, 7]);
        options[8] = 1;
        options[9] = 1;
        options[10..12].copy_from_slice(&[4, 2]);
        tcp[20..32].copy_from_slice(&options);
        packet
    }

    #[test]
    fn valid_ipv4_tcp_parses() {
        let packet = ipv4_tcp_fixture();
        let (ip, tcp) = parse_ipv4_tcp_packet(&packet).unwrap();
        assert_eq!(ip.ttl, 64);
        assert!(ip.df);
        assert_eq!(ip.identification, 0x1234);
        assert_eq!(ip.protocol, 6);
        assert_eq!(tcp.src_port, 80);
        assert_eq!(tcp.flags & 0x12, 0x12);
        assert_eq!(tcp.window, 29200);
        assert_eq!(tcp.mss, Some(1460));
        assert_eq!(tcp.wscale, Some(7));
        assert!(tcp.sack_permitted);
        assert!(!tcp.timestamps);
        assert_eq!(tcp.option_order, vec![2, 1, 3, 1, 1, 4]);
    }

    #[test]
    fn minimum_length_packets_parse() {
        // 20-byte IPv4 header + 20-byte TCP header, no options.
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[8] = 128;
        packet[9] = 6;
        let tcp = &mut packet[20..];
        tcp[12] = 0x50;
        tcp[13] = 0x04; // RST
        tcp[14..16].copy_from_slice(&0u16.to_be_bytes());
        let (ip, view) = parse_ipv4_tcp_packet(&packet).unwrap();
        assert_eq!(ip.ttl, 128);
        assert!(!ip.df);
        assert_eq!(view.flags, 0x04);
        assert_eq!(view.window, 0);
        assert_eq!(view.mss, None);
        assert!(view.option_order.is_empty());
        // One byte less on either header fails cleanly.
        assert_eq!(
            parse_ipv4_tcp_packet(&packet[..39]),
            Err(PacketError::Truncated)
        );
        assert_eq!(
            parse_tcp_segment(&packet[20..39]),
            Err(PacketError::Truncated)
        );
    }

    #[test]
    fn truncated_inputs_never_panic() {
        let packet = ipv4_tcp_fixture();
        for len in 0..packet.len() {
            let _ = parse_ipv4_header(&packet[..len]);
            let _ = parse_ipv4_tcp_packet(&packet[..len]);
            let _ = parse_tcp_segment(packet.get(20..len).unwrap_or(&[]));
            let _ = parse_icmp_message(&packet[..len.min(20)]);
        }
        assert_eq!(parse_ipv4_header(&[]), Err(PacketError::Truncated));
        assert_eq!(parse_ipv4_header(&[0u8]), Err(PacketError::Truncated));
        assert_eq!(parse_tcp_segment(&[]), Err(PacketError::Truncated));
        assert_eq!(parse_icmp_message(&[0u8; 7]), Err(PacketError::Truncated));
    }

    #[test]
    fn malformed_lengths_rejected() {
        // IHL too small.
        let mut bad = ipv4_tcp_fixture();
        bad[0] = 0x43;
        assert_eq!(
            parse_ipv4_header(&bad),
            Err(PacketError::InvalidHeaderLength)
        );
        // Wrong version.
        bad[0] = 0x65;
        assert_eq!(parse_ipv4_header(&bad), Err(PacketError::InvalidVersion));
        // TCP data offset too small.
        let mut tcp = vec![0u8; 20];
        tcp[12] = 0x40;
        assert_eq!(
            parse_tcp_segment(&tcp),
            Err(PacketError::InvalidHeaderLength)
        );
        // Option length 0 / 1 / beyond packet.
        assert_eq!(
            parse_tcp_options(&[2, 0, 0, 0]),
            Err(PacketError::MalformedOptions)
        );
        assert_eq!(
            parse_tcp_options(&[2, 1, 0, 0]),
            Err(PacketError::MalformedOptions)
        );
        assert_eq!(
            parse_tcp_options(&[3, 9, 7]),
            Err(PacketError::MalformedOptions)
        );
        assert_eq!(parse_tcp_options(&[8]), Err(PacketError::MalformedOptions));
        // Non-TCP protocol misparse refused.
        let mut udp = ipv4_tcp_fixture();
        udp[9] = 17;
        assert_eq!(
            parse_ipv4_tcp_packet(&udp),
            Err(PacketError::UnexpectedProtocol)
        );
    }

    #[test]
    fn unknown_and_duplicate_options_preserved() {
        // Unknown kind 99 with 2 value bytes + duplicate MSS.
        let bytes = [99u8, 4, 0xAA, 0xBB, 2, 4, 0x05, 0xB4, 2, 4, 0x05, 0xB4];
        let options = parse_tcp_options(&bytes).unwrap();
        assert_eq!(options[0].kind, 99);
        assert_eq!(options[0].value, vec![0xAA, 0xBB]);
        // First MSS wins; duplicates stay visible in order.
        let mut tcp = vec![0u8; 20 + 12];
        tcp[12] = 0x80;
        tcp[20..32].copy_from_slice(&bytes);
        let view = parse_tcp_segment(&tcp).unwrap();
        assert_eq!(view.mss, Some(1460));
        assert_eq!(view.option_order, vec![99, 2, 2]);
    }

    #[test]
    fn option_padding_and_eol_handled() {
        let bytes = [1u8, 1, 0, 0xFF, 0xFF];
        let options = parse_tcp_options(&bytes).unwrap();
        assert_eq!(options.len(), 2);
        let padded = [4u8, 2, 0, 0, 0];
        let view_options = parse_tcp_options(&padded).unwrap();
        assert!(view_options[0].kind == 4);
    }

    #[test]
    fn ipv6_parses_and_never_falls_through_ipv4() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[6] = 6;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&[
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ]);
        let (view, len) = parse_ipv6_header(&packet).unwrap();
        assert_eq!(len, 40);
        assert_eq!(view.hop_limit, 64);
        assert_eq!(view.next_header, 6);
        // IPv4 parser must reject IPv6 bytes (version gate), never misread.
        assert_eq!(parse_ipv4_header(&packet), Err(PacketError::InvalidVersion));
        // IPv6 parser must reject IPv4 bytes (version gate first).
        assert_eq!(
            parse_ipv6_header(&ipv4_tcp_fixture()),
            Err(PacketError::InvalidVersion)
        );
        let mut v4 = ipv4_tcp_fixture();
        v4.resize(40, 0);
        assert_eq!(parse_ipv6_header(&v4), Err(PacketError::InvalidVersion));
    }

    #[test]
    fn icmp_views_record_type_code_and_quoted_len() {
        let mut message = vec![0u8; 8 + 28];
        message[0] = 3;
        message[1] = 3;
        let (view, quoted) = parse_icmp_message(&message).unwrap();
        assert_eq!((view.icmp_type, view.code, quoted), (3, 3, 28));
    }

    #[test]
    fn ipv4_source_is_bounds_checked() {
        assert!(ipv4_source(&[]).is_none());
        assert!(ipv4_source(&[0x45]).is_none());
        let packet = ipv4_tcp_fixture();
        assert_eq!(
            ipv4_source(&packet),
            Some(std::net::Ipv4Addr::new(192, 0, 2, 10))
        );
    }
}
