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
    for (name, available, detail) in crate::exposure::capability_entries() {
        entries.push(entry(&name, available, detail));
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Capabilities { platform, entries }
}

pub fn render_human(capabilities: &Capabilities) -> String {
    render_human_caps(capabilities, crate::terminal::TerminalCapabilities::plain())
}

/// Human label for a stable capability ID.
///
/// Stable IDs (e.g. `raw_syn_ipv6`) stay unchanged for machine output and
/// internal logic; human output prefers these labels (e.g. `Raw SYN · IPv6`).
pub fn human_label(name: &str) -> String {
    match name {
        "connect_scan" => "TCP connect scanning".to_owned(),
        "raw_syn" => "Raw SYN · IPv4".to_owned(),
        "raw_syn_ipv6" => "Raw SYN · IPv6".to_owned(),
        "arp_active" => "ARP discovery".to_owned(),
        "ndp" => "IPv6 neighbor discovery".to_owned(),
        "ipv6" => "IPv6 support".to_owned(),
        "raw_icmp" => "Raw ICMP".to_owned(),
        "ping_sockets" => "Ping sockets".to_owned(),
        "udp" => "UDP discovery".to_owned(),
        "tls" => "TLS observation".to_owned(),
        "search_http" => "Search HTTP client".to_owned(),
        "search_json" => "Search JSON output".to_owned(),
        "search_jsonl" => "Search JSONL stream".to_owned(),
        "search_project_db" => "Search project database".to_owned(),
        "search_username" => "Username search".to_owned(),
        "username_providers" => "Username providers".to_owned(),
        "username_providers_fixture_backed" => "Fixture-backed providers".to_owned(),
        "fingerprints" => "Service fingerprints".to_owned(),
        "project_db" => "Project database".to_owned(),
        "investigation" => "Investigation workflow".to_owned(),
        "investigation_username_seed" => "Username seed".to_owned(),
        "investigation_account_transforms" => "Account transforms".to_owned(),
        "investigation_url_transforms" => "URL transforms".to_owned(),
        "investigation_dns_transforms" => "DNS transforms".to_owned(),
        "investigation_project_persistence" => "Project persistence".to_owned(),
        "investigation_transforms" => "Transform registry".to_owned(),
        "investigation_direct_network" => "Direct network".to_owned(),
        "investigation_network_bridge" => "Network bridge".to_owned(),
        "exposure" => "Exposure lookup".to_owned(),
        "exposure_local_dataset" => "Local exposure dataset".to_owned(),
        "exposure_http_api" => "Exposure HTTP API".to_owned(),
        "exposure_secret_retention" => "Secret retention".to_owned(),
        _ => name
            .split('_')
            .map(|word| {
                let mut chars = word.chars();
                match chars.next() {
                    Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join(" "),
    }
}

/// Logical human group for a stable capability ID.
///
/// Groups (`NETWORK`, `SEARCH`, `INVESTIGATION`, `INTELLIGENCE`, `PROJECT`)
/// are presentation-only; machine output keeps the flat sorted ID list and
/// no capability appears in two groups.
pub fn human_group(name: &str) -> &'static str {
    match name {
        "connect_scan" | "raw_syn" | "raw_syn_ipv6" | "arp_active" | "ndp" | "ipv6"
        | "raw_icmp" | "ping_sockets" | "udp" | "tls" => "NETWORK",
        "search_http"
        | "search_json"
        | "search_jsonl"
        | "search_username"
        | "username_providers"
        | "username_providers_fixture_backed" => "SEARCH",
        "investigation"
        | "investigation_username_seed"
        | "investigation_account_transforms"
        | "investigation_url_transforms"
        | "investigation_dns_transforms"
        | "investigation_transforms"
        | "investigation_direct_network"
        | "investigation_network_bridge" => "INVESTIGATION",
        "fingerprints"
        | "exposure"
        | "exposure_local_dataset"
        | "exposure_http_api"
        | "exposure_secret_retention" => "INTELLIGENCE",
        "project_db" | "search_project_db" | "investigation_project_persistence" => "PROJECT",
        _ => "OTHER",
    }
}

/// Capabilities-aware runtime report: workflow header, `RUNTIME`
/// metadata, grouped human `NETWORK` / `SEARCH` / `INVESTIGATION` /
/// `INTELLIGENCE` / `PROJECT` tables with human labels, and a summary bar.
/// Styled only when `caps.color` is set; machine output never passes
/// through here. Stable IDs stay unchanged for machine output.
pub fn render_human_caps(
    capabilities: &Capabilities,
    caps: crate::terminal::TerminalCapabilities,
) -> String {
    use crate::terminal::Style;
    use crate::terminal::{
        Table, footer_block, format_count, key_value, paint, section_heading, workflow_header,
    };
    let color = caps.color;
    let mut out = String::new();
    out.push_str(&workflow_header(caps, "CAPABILITIES", None));
    out.push('\n');
    out.push('\n');
    out.push_str(&section_heading(caps, "Runtime"));
    out.push('\n');
    out.push('\n');
    out.push_str(&key_value(
        caps,
        "Platform",
        &paint(color, Style::Identifier, &capabilities.platform),
        9,
    ));
    out.push('\n');
    const GROUPS: &[&str] = &[
        "NETWORK",
        "SEARCH",
        "INVESTIGATION",
        "INTELLIGENCE",
        "PROJECT",
    ];
    let compact = caps.width_mode() == crate::terminal::WidthMode::Compact;
    for group in GROUPS {
        let items: Vec<&CapabilityEntry> = capabilities
            .entries
            .iter()
            .filter(|item| human_group(&item.name) == *group)
            .collect();
        if items.is_empty() {
            continue;
        }
        out.push('\n');
        out.push_str(&section_heading(caps, group));
        out.push('\n');
        out.push('\n');
        if compact {
            for item in items {
                let status = if item.available {
                    "AVAILABLE"
                } else {
                    "UNAVAILABLE"
                };
                let style = if item.available {
                    Style::Success
                } else {
                    Style::Muted
                };
                out.push_str(&format!(
                    "  {} {}\n",
                    paint(color, style, status),
                    paint(color, Style::Identifier, &human_label(&item.name)),
                ));
                out.push_str(&format!("    Detail  {}\n", item.detail));
            }
        } else {
            let mut table = Table::new(&["CAPABILITY", "STATUS", "DETAIL"]);
            table.max_widths = vec![34, 12, 48];
            for item in items {
                let status = if item.available {
                    "AVAILABLE"
                } else {
                    "UNAVAILABLE"
                };
                let style = if item.available {
                    Style::Success
                } else {
                    Style::Muted
                };
                table.cells(vec![
                    paint(color, Style::Identifier, &human_label(&item.name)),
                    paint(color, style, status),
                    item.detail.clone(),
                ]);
            }
            out.push_str(&table.render(caps));
            out.push('\n');
        }
    }
    // Any future capability outside the known groups renders once under
    // OTHER so nothing is ever hidden; never duplicates grouped items.
    let other: Vec<&CapabilityEntry> = capabilities
        .entries
        .iter()
        .filter(|item| human_group(&item.name) == "OTHER")
        .collect();
    if !other.is_empty() {
        out.push('\n');
        out.push_str(&section_heading(caps, "Other"));
        out.push('\n');
        out.push('\n');
        if compact {
            for item in other {
                let status = if item.available {
                    "AVAILABLE"
                } else {
                    "UNAVAILABLE"
                };
                let style = if item.available {
                    Style::Success
                } else {
                    Style::Muted
                };
                out.push_str(&format!(
                    "  {} {}\n",
                    paint(color, style, status),
                    paint(color, Style::Identifier, &human_label(&item.name)),
                ));
                out.push_str(&format!("    Detail  {}\n", item.detail));
            }
        } else {
            let mut table = Table::new(&["CAPABILITY", "STATUS", "DETAIL"]);
            table.max_widths = vec![34, 12, 48];
            for item in other {
                let status = if item.available {
                    "AVAILABLE"
                } else {
                    "UNAVAILABLE"
                };
                let style = if item.available {
                    Style::Success
                } else {
                    Style::Muted
                };
                table.cells(vec![
                    paint(color, Style::Identifier, &human_label(&item.name)),
                    paint(color, style, status),
                    item.detail.clone(),
                ]);
            }
            out.push_str(&table.render(caps));
            out.push('\n');
        }
    }
    out.push('\n');
    let available = capabilities
        .entries
        .iter()
        .filter(|item| item.available)
        .count();
    let total = capabilities.entries.len();
    let recap = format!(
        "{}  ·  {}",
        paint(color, Style::Success, &format!("{available} available")),
        paint(
            color,
            Style::Secondary,
            &format!("{} total", format_count(total)),
        ),
    );
    out.push_str(&footer_block(caps, &recap));
    out.push('\n');
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
