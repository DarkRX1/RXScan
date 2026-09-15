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

/// Wave-1 probe source: DNS (53), NTP (123), SSDP unicast (1900).
/// Every other port gets an empty datagram: enough to separate attributable
/// Closed (ICMP) from OpenOrFiltered silence, never enough to invent Open.
#[derive(Debug, Default, Clone, Copy)]
pub struct Wave1UdpProbes;

impl UdpProbeSource for Wave1UdpProbes {
    fn payload(&self, ip: &IpAddr, port: u16) -> Vec<u8> {
        match port {
            53 => dns_query(),
            123 => ntp_request(),
            1900 => ssdp_search(ip, port),
            _ => Vec::new(),
        }
    }

    fn classify(&self, port: u16, response: &[u8]) -> Option<String> {
        match port {
            53 => classify_dns(response).then_some("dns".to_owned()),
            123 => classify_ntp(response).then_some("ntp".to_owned()),
            1900 => classify_ssdp(response).then_some("ssdp".to_owned()),
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
        assert!(source.payload(&ip, 9999).is_empty());
        assert_eq!(source.classify(9999, b"anything"), None);
    }
}
