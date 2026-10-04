//! Wave-1 UDP protocol probes: tiny deterministic request builders and
//! strict response-grammar matchers.
//!
//! Rules (P23): every probe is deterministic, tiny, non-destructive,
//! non-authenticating, unicast-only, and bounded. A response proves UDP
//! responsiveness (`Open`); only a validated grammar proves protocol
//! identity; anything else stays `Open` with unknown protocol. No
//! credential strings (SNMP community probing is explicitly out of Wave 1),
//! no amplification behavior (no monlist/AXFR/walking/broadcast).
//!
//! Fixed transaction details are deliberate, not lazy: one outstanding
//! request per connected socket means responses are attributed by socket
//! peer, so constant TXIDs stay unambiguous and runs stay deterministic.

use std::net::IpAddr;

use crate::udp_scanner::UdpProbeSource;

/// Deterministic DNS transaction ID used for every discovery query.
/// Constant by design: attribution comes from the connected socket peer,
/// and a fixed value keeps runs byte-identical. Validated on receipt.
pub const DNS_TXID: u16 = 0x1a2b;

/// Maximum UDP probe request size (all Wave-1 requests are far smaller).
pub const MAX_UDP_REQUEST_BYTES: usize = 256;

/// Maximum UDP response bytes retained for classification.
pub const MAX_UDP_RESPONSE_BYTES: usize = 2048;

/// Wave-1 probe source: DNS (53), NTP (123), SSDP unicast (1900),
/// plus Wave-2 safe unicast probes: TFTP (69), IKE (500), SIP (5060),
/// mDNS unicast (5353). SNMP (161), RADIUS (1812/1813), and QUIC (443) send
/// no handshake bytes: an empty datagram separates attributable Closed from
/// OpenOrFiltered, and only a strict response grammar reports protocol
/// identity. DHCP is intentionally unprobed (broadcast + lease state).
/// Every other port gets an empty datagram: enough to separate attributable
/// Closed (ICMP) from OpenOrFiltered silence, never enough to invent Open.
#[derive(Debug, Default, Clone, Copy)]
pub struct Wave1UdpProbes;

impl UdpProbeSource for Wave1UdpProbes {
    fn payload(&self, ip: &IpAddr, port: u16) -> Vec<u8> {
        match port {
            53 => dns_query(),
            123 => ntp_request(),
            69 => tftp_rrq(),
            500 => ike_sa_init(),
            1900 => ssdp_search(ip, port),
            5060 => sip_options(ip, port),
            5353 => mdns_query(),
            _ => Vec::new(),
        }
    }

    fn classify(&self, port: u16, response: &[u8]) -> Option<String> {
        match port {
            53 => classify_dns(response).then_some("dns".to_owned()),
            123 => classify_ntp(response).then_some("ntp".to_owned()),
            69 => classify_tftp(response).then_some("tftp".to_owned()),
            161 => classify_snmp(response).then_some("snmp".to_owned()),
            443 => classify_quic_indicator(response).then_some("quic-indicator".to_owned()),
            500 => classify_ike(response).then_some("ike".to_owned()),
            1900 => classify_ssdp(response).then_some("ssdp".to_owned()),
            5060 => classify_sip(response).then_some("sip".to_owned()),
            5353 => classify_dns(response).then_some("mdns".to_owned()),
            1812 | 1813 => classify_radius(response).then_some("radius".to_owned()),
            _ => None,
        }
    }
}

/// Minimal normal DNS query: header (RD=0: no recursion desired — polite,
/// non-abusive), one root A question. 17 bytes total.
pub fn dns_query() -> Vec<u8> {
    let header = DNS_TXID.to_be_bytes();
    vec![
        header[0], header[1], // TXID (validated on receipt)
        0x00, 0x00, // flags: standard query, RD=0
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
        0x00, // QNAME: root (empty label)
        0x00, 0x01, // QTYPE = A
        0x00, 0x01, // QCLASS = IN
    ]
}

/// Validate a DNS response header: long enough, matching TXID, QR bit set.
/// RCODE is intentionally unchecked (even errors prove a DNS speaker).
/// Malformed input stays `false` (Open + unknown, never misclassified).
pub fn classify_dns(response: &[u8]) -> bool {
    if response.len() < 12 {
        return false;
    }
    let txid = u16::from_be_bytes([response[0], response[1]]);
    if txid != DNS_TXID {
        return false;
    }
    response[2] & 0x80 != 0
}

/// Normal NTP client request: LI=0, VN=3 (broadest server acceptance),
/// Mode=3 (client). 48 bytes, rest zero. No control/mode-6 content of any
/// kind (monlist-style amplification is never sent).
pub fn ntp_request() -> Vec<u8> {
    let mut packet = vec![0u8; 48];
    packet[0] = 0x1b;
    packet
}

/// Validate an NTP server response: exactly 48 bytes, version 3..=4,
/// mode 4 (server). Stratum is unchecked (0/kiss still speaks NTP).
pub fn classify_ntp(response: &[u8]) -> bool {
    if response.len() != 48 {
        return false;
    }
    let first = response[0];
    let version = (first >> 3) & 0x07;
    let mode = first & 0x07;
    (3..=4).contains(&version) && mode == 4
}

/// Unicast SSDP M-SEARCH (never multicast/broadcast). Bounded well under
/// [`MAX_UDP_REQUEST_BYTES`]. `MX: 1` keeps responses prompt and singular.
pub fn ssdp_search(ip: &IpAddr, port: u16) -> Vec<u8> {
    let text = format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: {ip}:{port}\r\nMAN: \"ns=01\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
    );
    let mut bytes = text.into_bytes();
    bytes.truncate(MAX_UDP_REQUEST_BYTES);
    bytes
}

/// Validate an SSDP unicast reply: `HTTP/1.x 200` status line, terminated
/// headers, and one discovery header (`ST:`, `USN:`, or `LOCATION:`).
/// Case-insensitive names; body (if any) ignored.
pub fn classify_ssdp(response: &[u8]) -> bool {
    let text = String::from_utf8_lossy(response);
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap_or("");
    let status_ok = status.starts_with("HTTP/1.1 200") || status.starts_with("HTTP/1.0 200");
    if !status_ok {
        return false;
    }
    let mut terminated = false;
    let mut discovery_header = false;
    for line in lines {
        if line.is_empty() {
            terminated = true;
            break;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("st:") || lower.starts_with("usn:") || lower.starts_with("location:") {
            discovery_header = true;
        }
    }
    terminated && discovery_header
}

/// Minimal TFTP read request for a nonexistent file. A compliant server
/// answers ERROR (opcode 5) without transferring anything; ERROR, DATA (3),
/// ACK (4), or OACK (6) all prove a TFTP speaker. Never requests a real file.
pub fn tftp_rrq() -> Vec<u8> {
    let mut out = vec![0x00, 0x01];
    out.extend_from_slice(b"rxscan");
    out.push(0x00);
    out.extend_from_slice(b"octet");
    out.push(0x00);
    out.truncate(MAX_UDP_REQUEST_BYTES);
    out
}

pub fn classify_tftp(response: &[u8]) -> bool {
    if response.len() < 4 {
        return false;
    }
    matches!(u16::from_be_bytes([response[0], response[1]]), 3..=6)
}

/// Minimal SIP OPTIONS request (no registration, no authentication).
pub fn sip_options(ip: &IpAddr, port: u16) -> Vec<u8> {
    let text = format!(
        "OPTIONS sip:{ip}:{port} SIP/2.0\r\nVia: SIP/2.0/UDP probe;branch=z9hG4bK-rxscan\r\nMax-Forwards: 0\r\nTo: <sip:{ip}:{port}>\r\nFrom: <sip:probe@invalid>;tag=rxscan\r\nCall-ID: rxscan@invalid\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
    );
    let mut bytes = text.into_bytes();
    bytes.truncate(MAX_UDP_REQUEST_BYTES);
    bytes
}

pub fn classify_sip(response: &[u8]) -> bool {
    let text = String::from_utf8_lossy(response);
    let line = text.split("\r\n").next().unwrap_or("");
    line.starts_with("SIP/2.0")
}

/// Minimal IKE_SA_INIT header (28 bytes, no KE/Nonce payloads, zero SPIs).
/// A responder answers with exchange type 34; the header shape alone is
/// validated, never credentials.
pub fn ike_sa_init() -> Vec<u8> {
    let mut header = vec![0u8; 28];
    header[16] = 0x00;
    header[17] = 0x20;
    header[18] = 0x22;
    header[19] = 0x00;
    header.truncate(MAX_UDP_REQUEST_BYTES);
    header
}

pub fn classify_ike(response: &[u8]) -> bool {
    if response.len() < 28 {
        return false;
    }
    response[17] == 0x20 && response[18] == 0x22
}

/// Unicast mDNS query: same root-A grammar as DNS with the shared TXID.
/// Multicast is never sent; unicast to port 5353 only.
pub fn mdns_query() -> Vec<u8> {
    dns_query()
}

/// SNMP is never probed with a community string. Only a response to the
/// empty datagram is classified: BER SEQUENCE, INTEGER version 0/1,
/// OCTET-STRING community, and an SNMP PDU tag (0xA0-0xA3).
pub fn classify_snmp(response: &[u8]) -> bool {
    if response.len() < 8 || response[0] != 0x30 {
        return false;
    }
    let mut index = 2usize;
    if response[1] & 0x80 != 0 {
        let count = (response[1] & 0x7f) as usize;
        if count == 0 || count > 2 || response.len() < 2 + count {
            return false;
        }
        index = 2 + count;
    }
    if response.len() < index + 3 || response[index] != 0x02 {
        return false;
    }
    let version_len = response[index + 1] as usize;
    if version_len != 1 || response.len() < index + 2 + version_len {
        return false;
    }
    if response[index + 2] > 1 {
        return false;
    }
    index += 2 + version_len;
    if response.len() < index + 2 || response[index] != 0x04 {
        return false;
    }
    let community_len = response[index + 1] as usize;
    if community_len > 32 || response.len() < index + 2 + community_len + 1 {
        return false;
    }
    matches!(response[index + 2 + community_len], 0xa0..=0xa3)
}

/// QUIC indicator only: QUIC long header bit with a nonzero version.
/// Never a QUIC handshake; reported as `quic-indicator`, not `quic`.
pub fn classify_quic_indicator(response: &[u8]) -> bool {
    if response.len() < 7 || response[0] & 0x80 == 0 {
        return false;
    }
    let version = u32::from_be_bytes([response[1], response[2], response[3], response[4]]);
    version != 0 && version != 0xffff_ffff
}

/// RADIUS is never probed with credentials or a shared secret. Only a
/// response to the empty datagram is classified: Code in
/// {Access-Accept, Access-Reject, Access-Challenge} with a consistent
/// Length field and a 16-byte Authenticator.
pub fn classify_radius(response: &[u8]) -> bool {
    if response.len() < 20 || !matches!(response[0], 2 | 3 | 11) {
        return false;
    }
    let length = u16::from_be_bytes([response[2], response[3]]) as usize;
    length >= 20 && length <= response.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_query_is_tiny_and_deterministic() {
        let first = dns_query();
        assert_eq!(first, dns_query());
        assert!(first.len() <= 32);
        // TXID + RD=0 + one question.
        assert_eq!(u16::from_be_bytes([first[0], first[1]]), DNS_TXID);
        assert_eq!(first[2] & 0x80, 0);
        assert_eq!(first[2] & 0x01, 0);
    }

    #[test]
    fn dns_grammar_accepts_errors_rejects_mismatch() {
        // Minimal valid response header (QR=1, matching TXID, RCODE=3).
        let mut response = vec![0u8; 12];
        response[0..2].copy_from_slice(&DNS_TXID.to_be_bytes());
        response[2] = 0x80;
        response[3] = 0x03;
        assert!(classify_dns(&response));
        // Wrong TXID: not attributable DNS evidence.
        let mut wrong = response.clone();
        wrong[0] ^= 0xff;
        assert!(!classify_dns(&wrong));
        // Query (QR=0), short packet: rejected.
        assert!(!classify_dns(&dns_query()));
        assert!(!classify_dns(&[0u8; 4]));
    }

    #[test]
    fn ntp_request_and_grammar() {
        let request = ntp_request();
        assert_eq!(request.len(), 48);
        assert_eq!(request[0] & 0x07, 3);
        // Valid server reply: VN=4, mode=4.
        let mut reply = vec![0u8; 48];
        reply[0] = 0x24;
        assert!(classify_ntp(&reply));
        // Client echo, wrong length, garbage: rejected.
        assert!(!classify_ntp(&request));
        assert!(!classify_ntp(&[0u8; 47]));
        assert!(!classify_ntp(&[0u8; 49]));
        assert!(!classify_ntp(b"not ntp at all, way too short"));
    }

    #[test]
    fn ssdp_search_is_unicast_and_bounded() {
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        let request = ssdp_search(&ip, 1900);
        assert!(request.len() <= MAX_UDP_REQUEST_BYTES);
        let text = String::from_utf8(request.clone()).unwrap();
        assert!(text.starts_with("M-SEARCH * HTTP/1.1"));
        assert!(text.contains("HOST: 192.0.2.10:1900"));
        assert!(!text.contains("239.255.255.250"));
        // Valid reply with discovery headers.
        let reply = b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nUSN: uuid:x\r\n\r\n";
        assert!(classify_ssdp(reply));
        // Missing terminator, wrong status, no discovery header: rejected.
        // (A datagram ending exactly after headers still terminates: UDP
        // datagram boundaries delimit the message.)
        assert!(!classify_ssdp(b"HTTP/1.1 200 OK\r\nST: x"));
        assert!(!classify_ssdp(
            b"HTTP/1.1 404 NF\r\nST: upnp:rootdevice\r\n\r\n"
        ));
        assert!(!classify_ssdp(b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n"));
        assert!(!classify_ssdp(b"garbage"));
    }

    #[test]
    fn wave1_source_covers_common_ports_only() {
        let source = Wave1UdpProbes;
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(!source.payload(&ip, 53).is_empty());
        assert!(!source.payload(&ip, 123).is_empty());
        assert!(!source.payload(&ip, 1900).is_empty());
        assert!(!source.payload(&ip, 69).is_empty());
        assert!(!source.payload(&ip, 500).is_empty());
        assert!(!source.payload(&ip, 5060).is_empty());
        assert!(!source.payload(&ip, 5353).is_empty());
        assert!(source.payload(&ip, 161).is_empty());
        assert!(source.payload(&ip, 9999).is_empty());
        assert_eq!(source.classify(9999, b"anything"), None);
    }

    #[test]
    fn tftp_error_proves_speaker() {
        assert!(tftp_rrq().len() <= MAX_UDP_REQUEST_BYTES);
        assert!(classify_tftp(&[0x00, 0x05, 0x00, 0x01]));
        assert!(classify_tftp(&[0x00, 0x03, 0x00, 0x01, 0x00]));
        assert!(!classify_tftp(&[0x00, 0x01]));
        assert!(!classify_tftp(b"garbage!!"));
    }

    #[test]
    fn sip_requires_status_line() {
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        assert!(sip_options(&ip, 5060).len() <= MAX_UDP_REQUEST_BYTES);
        assert!(classify_sip(b"SIP/2.0 200 OK\r\n\r\n"));
        assert!(!classify_sip(b"HTTP/1.1 200 OK\r\n\r\n"));
        assert!(!classify_sip(b"garbage"));
    }

    #[test]
    fn ike_validates_header_shape() {
        assert_eq!(ike_sa_init().len(), 28);
        let mut reply = vec![0u8; 28];
        reply[17] = 0x20;
        reply[18] = 0x22;
        assert!(classify_ike(&reply));
        assert!(!classify_ike(&[0u8; 10]));
        assert!(!classify_ike(&[0u8; 28]));
    }

    #[test]
    fn snmp_never_matches_without_grammar() {
        assert!(!classify_snmp(b""));
        assert!(!classify_snmp(b"public"));
        assert!(!classify_snmp(&[0x30, 0x03, 0x02, 0x01, 0x05]));
        let valid = [
            0x30, 0x0b, 0x02, 0x01, 0x01, 0x04, 0x04, b'p', b'u', b'b', b'l', 0xa2, 0x00,
        ];
        assert!(classify_snmp(&valid));
    }

    #[test]
    fn quic_is_indicator_only() {
        assert!(classify_quic_indicator(&[
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03
        ]));
        assert!(!classify_quic_indicator(&[
            0x40, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03
        ]));
        assert!(!classify_quic_indicator(&[0xc0, 0x00]));
    }

    #[test]
    fn radius_requires_framing() {
        let mut valid = vec![2u8, 0x07, 0x00, 0x14];
        valid.extend_from_slice(&[0u8; 16]);
        assert!(classify_radius(&valid));
        assert!(!classify_radius(b""));
        assert!(!classify_radius(&[1u8; 20]));
        assert!(!classify_radius(&[2u8, 0, 0, 5]));
    }
}
