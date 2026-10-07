use std::net::{IpAddr, Ipv4Addr};

/// Linux ARP cache path. Only consulted on Linux; other platforms use
/// capability-gated discovery and return `None` here (one controlled
/// explanation upstream, never repeated failures).
#[cfg(target_os = "linux")]
pub const ARP_CACHE_PATH: &str = "/proc/net/arp";
#[cfg(not(target_os = "linux"))]
pub const ARP_CACHE_PATH: &str = "";
pub const MAX_ARP_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborSource {
    ArpCache,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborEntry {
    pub ip: IpAddr,
    pub mac: String,
    pub complete: bool,
}

pub fn lookup_arp_cache(target: Ipv4Addr) -> Option<NeighborEntry> {
    #[cfg(target_os = "linux")]
    {
        lookup_arp_cache_at(ARP_CACHE_PATH, target)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = target;
        None
    }
}

/// Bounded file-backed ARP-cache lookup. The pure parser below
/// ([`parse_arp_table`]) is intentionally portable and unit-tested on every
/// platform; only the live `/proc/net/arp` path is Linux-gated via the
/// caller. `any(linux, test)` keeps portable test coverage on
/// Windows/macOS without dead_code in non-test builds.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn lookup_arp_cache_at(path: &str, target: Ipv4Addr) -> Option<NeighborEntry> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() > MAX_ARP_BYTES {
        return None;
    }
    let text = String::from_utf8_lossy(&bytes);
    parse_arp_table(&text, target)
}

/// Pure `/proc/net/arp` table parser. Portable (no syscalls) and
/// unit-tested everywhere; shares the `any(linux, test)` boundary with its
/// file-backed caller so non-test Windows/macOS builds stay dead-code-free.
#[cfg(any(target_os = "linux", test))]
fn parse_arp_table(text: &str, target: Ipv4Addr) -> Option<NeighborEntry> {
    for line in text.lines().skip(1) {
        let mut parts = line.split_whitespace();
        let (Some(ip), Some(_hw), Some(flags), Some(mac)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if ip.parse::<Ipv4Addr>().ok() != Some(target) {
            continue;
        }
        if !is_mac(mac) {
            continue;
        }
        let complete = flags.starts_with("0x2");
        return Some(NeighborEntry {
            ip: IpAddr::V4(target),
            mac: mac.to_ascii_lowercase(),
            complete,
        });
    }
    None
}

#[cfg(any(target_os = "linux", test))]
fn is_mac(value: &str) -> bool {
    let parts: Vec<&str> = value.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkScope {
    Loopback,
    LinkLocal,
    PrivateLocal,
    Global,
}

pub fn link_scope_of(ip: &IpAddr) -> LinkScope {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                LinkScope::Loopback
            } else if v4.is_link_local() {
                LinkScope::LinkLocal
            } else if v4.is_private() {
                LinkScope::PrivateLocal
            } else {
                LinkScope::Global
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                LinkScope::Loopback
            } else if v6.is_unicast_link_local() {
                LinkScope::LinkLocal
            } else if is_unique_local(v6) {
                LinkScope::PrivateLocal
            } else {
                LinkScope::Global
            }
        }
    }
}

fn is_unique_local(v6: &std::net::Ipv6Addr) -> bool {
    (v6.octets()[0] & 0xfe) == 0xfc
}

pub fn arp_applicable(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if !v4.is_loopback())
        && matches!(
            link_scope_of(ip),
            LinkScope::LinkLocal | LinkScope::PrivateLocal
        )
}

pub fn nd_applicable(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V6(_)) && !matches!(link_scope_of(ip), LinkScope::Loopback)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdpStatus {
    Deferred,
}

pub fn ndp_status() -> NdpStatus {
    NdpStatus::Deferred
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn fixture_table() -> String {
        "IP address       HW type     Flags       HW address            Mask     Device\n192.0.2.10       0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n192.0.2.11       0x1         0x0         00:00:00:00:00:00     *        eth0\n".to_owned()
    }

    #[test]
    fn complete_arp_entry_parses() {
        let entry =
            parse_arp_table(&fixture_table(), "192.0.2.10".parse::<Ipv4Addr>().unwrap()).unwrap();
        assert_eq!(entry.mac, "aa:bb:cc:dd:ee:ff");
        assert!(entry.complete);
    }

    #[test]
    fn incomplete_entry_is_not_alive_evidence() {
        let entry =
            parse_arp_table(&fixture_table(), "192.0.2.11".parse::<Ipv4Addr>().unwrap()).unwrap();
        assert!(!entry.complete);
    }

    #[test]
    fn missing_entry_yields_none() {
        assert!(parse_arp_table(&fixture_table(), "192.0.2.99".parse().unwrap()).is_none());
    }

    #[test]
    fn malformed_mac_rejected() {
        let table = "IP address       HW type     Flags       HW address            Mask     Device\n192.0.2.10       0x1         0x2         not-a-mac             *        eth0\n";
        assert!(parse_arp_table(table, "192.0.2.10".parse().unwrap()).is_none());
    }

    #[test]
    fn cache_file_is_bounded() {
        let dir = std::env::temp_dir();
        let path = dir.join("rxscan-arp-bound-test");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&vec![b' '; MAX_ARP_BYTES + 1]).unwrap();
        drop(file);
        assert!(
            lookup_arp_cache_at(path.to_str().unwrap(), "192.0.2.10".parse().unwrap()).is_none()
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn link_scope_classifies() {
        assert_eq!(
            link_scope_of(&"127.0.0.1".parse().unwrap()),
            LinkScope::Loopback
        );
        assert_eq!(
            link_scope_of(&"192.0.2.10".parse().unwrap()),
            LinkScope::Global
        );
        assert_eq!(
            link_scope_of(&"10.0.0.5".parse().unwrap()),
            LinkScope::PrivateLocal
        );
        assert_eq!(
            link_scope_of(&"169.254.1.1".parse().unwrap()),
            LinkScope::LinkLocal
        );
        assert_eq!(link_scope_of(&"::1".parse().unwrap()), LinkScope::Loopback);
        assert_eq!(
            link_scope_of(&"fe80::1".parse().unwrap()),
            LinkScope::LinkLocal
        );
        assert_eq!(
            link_scope_of(&"fd00::1".parse().unwrap()),
            LinkScope::PrivateLocal
        );
    }

    #[test]
    fn arp_only_for_local_v4_neighbors() {
        assert!(!arp_applicable(&"127.0.0.1".parse().unwrap()));
        assert!(arp_applicable(&"10.0.0.5".parse().unwrap()));
        assert!(!arp_applicable(&"8.8.8.8".parse().unwrap()));
        assert!(!arp_applicable(&"fe80::1".parse().unwrap()));
    }

    #[test]
    fn nd_only_for_non_loopback_v6() {
        assert!(nd_applicable(&"fe80::1".parse().unwrap()));
        assert!(!nd_applicable(&"::1".parse().unwrap()));
        assert!(!nd_applicable(&"10.0.0.5".parse().unwrap()));
    }
}
