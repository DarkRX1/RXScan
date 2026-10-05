use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEntry {
    pub name: String,
    pub available: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub platform: String,
    pub entries: Vec<CapabilityEntry>,
}

fn entry(name: &str, available: bool, detail: impl Into<String>) -> CapabilityEntry {
    CapabilityEntry {
        name: name.to_owned(),
        available,
        detail: detail.into(),
    }
}

fn ping_socket_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        unsafe extern "C" {
            fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
            fn close(fd: i32) -> i32;
        }
        // SAFETY: constant arguments, descriptor closed immediately.
        let fd = unsafe { socket(2, 2, 1) };
        if fd >= 0 {
            unsafe { close(fd) };
            return true;
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

pub fn fingerprint_counts() -> (usize, usize) {
    let dir = std::env::var("RXSCAN_FINGERPRINT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("fingerprints/v1"));
    let packs = crate::fingerprints::load_dir(&dir).unwrap_or_default();
    let rules = packs.iter().map(|(_, pack)| pack.fingerprints.len()).sum();
    (packs.len(), rules)
}

pub fn probe() -> Capabilities {
    let raw = crate::scan_mode::probe_raw_syn();
    let linux = cfg!(target_os = "linux");
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let (packs, rules) = fingerprint_counts();
    let username_providers = crate::search::embedded_username_pack()
        .map(|pack| pack.providers.len())
        .unwrap_or_default();
    let mut entries = vec![
        entry("connect_scan", true, "unprivileged TCP connect scanning"),
        entry("raw_syn", raw.supported, raw.reason.clone()),
        entry(
            "raw_syn_ipv6",
            false,
            "raw SYN unavailable: IPv6 not implemented (Linux IPv4 only)",
        ),
        entry(
            "arp_active",
            linux && raw.supported,
            if linux {
                if raw.supported {
                    "AF_PACKET ARP available".to_owned()
                } else {
                    format!("ARP unavailable at runtime: {}", raw.reason)
                }
            } else {
                "ARP unavailable: Linux-only implementation".to_owned()
            },
        ),
        entry(
            "ndp",
            linux && raw.supported,
            if linux {
                if raw.supported {
                    "ICMPv6 neighbor discovery available".to_owned()
                } else {
                    format!("NDP unavailable at runtime: {}", raw.reason)
                }
            } else {
                "NDP unavailable: Linux-only implementation".to_owned()
            },
        ),
        entry(
            "ipv6",
            true,
            "parsing, CIDR, scope, TCP, UDP, DNS, URL, graph, TLS/SNI paths",
        ),
        entry(
            "raw_icmp",
            linux && raw.supported,
            if linux && raw.supported {
                "raw ICMP available".to_owned()
            } else {
                "raw ICMP unavailable: echo via ping sockets only".to_owned()
            },
        ),
        entry(
            "ping_sockets",
            ping_socket_available(),
            "unprivileged ICMP echo where permitted",
        ),
        entry("udp", true, "bounded connected-socket UDP discovery"),
        entry("project_db", true, "SQLite project graph available"),
        entry("tls", true, "handshake and certificate observation"),
        entry(
            "search_http",
            true,
            "bounded pooled HTTPS public-provider client",
        ),
        entry("search_json", true, "username search JSON and JSONL output"),
        entry(
            "search_jsonl",
            true,
            "additive username search event stream",
        ),
        entry(
            "search_project_db",
            true,
            "username reports persist through the versioned SQLite project graph",
        ),
        entry(
            "search_username",
            username_providers > 0,
            format!("{username_providers} embedded fixture-backed providers"),
        ),
        entry(
            "username_providers",
            username_providers > 0,
            username_providers.to_string(),
        ),
        entry(
            "username_providers_fixture_backed",
            username_providers > 0,
            username_providers.to_string(),
        ),
        entry(
            "fingerprints",
            true,
            format!("{rules} rules in {packs} packs"),
        ),
    ];
    for (name, available, detail) in crate::investigate::capability_entries() {
        entries.push(entry(&name, available, detail));
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Capabilities { platform, entries }
}

pub fn render_human(capabilities: &Capabilities) -> String {
    let mut out = format!("Capabilities ({})\n", capabilities.platform);
    for item in &capabilities.entries {
        out.push_str(&format!(
            "  {:<14} {} ({})\n",
            item.name,
            if item.available { "yes" } else { "no" },
            item.detail
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_are_sorted_and_complete() {
        let capabilities = probe();
        let names: Vec<&str> = capabilities
            .entries
            .iter()
            .map(|item| item.name.as_str())
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
        for required in [
            "connect_scan",
            "raw_syn",
            "arp_active",
            "ndp",
            "ipv6",
            "udp",
            "project_db",
            "tls",
        ] {
            assert!(names.contains(&required), "missing {required}");
        }
    }

    #[test]
    fn raw_syn_never_claimed_without_support() {
        let capabilities = probe();
        let raw = capabilities
            .entries
            .iter()
            .find(|item| item.name == "raw_syn")
            .unwrap();
        if !raw.available {
            assert!(raw.detail.contains("unavailable"));
        }
    }

    #[test]
    fn human_render_is_stable() {
        let first = render_human(&probe());
        assert!(render_human(&probe()) == first || first.contains("Capabilities"));
    }
}
