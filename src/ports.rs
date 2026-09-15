//! Phase 6 canonical TCP port-selection model.
//!
//! Centralizes every port-set decision so `--level`, goal, profiles, and
//! explicit operator intent do not scatter across CLI handlers.
//!
//! Selection kinds:
//! * `common` — level-derived automatic set (default when the operator
//!   chooses no ports).
//! * `explicit` — normalized, deduped, sorted list from `--ports`
//!   (single ports, lists, ranges; overlapping inputs scan once).
//! * `all` — all 65_535 TCP ports as ONE scheduler task (never 65k tasks).
//!
//! Precedence: explicit `--ports` / `--all-ports` always win over
//! level-derived automatic selection. `--level` never silently overrides
//! explicit operator intent.
//!
//! Level breadth for automatic (`common`) selection (bounded, documented):
//! * L1 — no port scanning (reachability only); the L1 pair below is kept
//!   for API stability and explicit-compat, not used by default plans.
//! * L2–L3 — `common-100`: 100 curated high-value ports (the default scan).
//! * L4+ — `common-1000`: the well-known range 1–1000. Port breadth
//!   saturates here by design; higher levels deepen investigation, not port
//!   count.
//!
//! Speed never changes the port set; it controls concurrency, pacing,
//! timeouts, and retries only.
//!
//! Validation rejects: port 0, ports > 65535 (via `u16`), reversed ranges,
//! malformed input. Deterministic ordering (sorted) is mandatory.

use serde::{Deserialize, Serialize};

use crate::plan::{ScanGoal, SpeedSetting, TcpPortSelection};

/// Versioned common-port profile so future packs can replace/extend it.
pub const COMMON_PROFILE_VERSION: &str = "v1";

/// Full `v1` common profile (20 ports, sorted). This is the stable core of
/// the `common-100` set: every profile port appears in the default scan set, so
/// profile-based tooling keeps working as the default set evolves around it.
pub const COMMON_PORTS_V1: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900,
    8080,
];

/// Default scan set (`common-100`): the 20 profile ports plus 80 high-value
/// ports across web, remote access, file sharing, mail, databases,
/// infrastructure, and common alternate/devops ports. Sorted, disjoint from
/// the profile list above.
///
/// Heuristic ordering, not empirical measurement: this list makes no claim
/// to match any external top-ports dataset. It is curated for breadth per
/// unit of scan time on typical networks.
///
/// Review status (2026-09): v1 is FROZEN at exactly 100 ports. Candidates
/// for a future benchmark-backed v2 (remove 123/NTP + 161/SNMP, both
/// UDP-primary with negligible TCP hit rates; add 111/rpcbind,
/// 5601/Kibana, 10250/kubelet, 2376/docker-TLS) were evaluated on protocol
/// knowledge alone; without loopback-external hit-rate evidence the list
/// stays unchanged. Any v2 must remain exactly 100 unique ports, bump
/// `COMMON_PROFILE_VERSION`, and update deterministic tests.
pub const COMMON_100_EXTRA: &[u16] = &[
    88, 123, 161, 389, 465, 515, 548, 554, 587, 593, 631, 636, 873, 1433, 1521, 1883, 1935, 2049,
    2082, 2083, 2086, 2087, 2095, 2096, 2222, 2375, 2525, 3000, 3001, 3128, 3268, 3307, 3388, 3390,
    4000, 4040, 5000, 5001, 5060, 5432, 5433, 5631, 5672, 5901, 5984, 5985, 5986, 6379, 6443, 7000,
    7001, 8000, 8001, 8008, 8009, 8010, 8081, 8089, 8090, 8118, 8443, 8444, 8554, 8888, 9000, 9001,
    9042, 9080, 9090, 9092, 9100, 9200, 9300, 9443, 10000, 11211, 15672, 20000, 27017, 27018,
];

/// Canonical name for an automatic selection (for `--explain` and evidence).
pub fn automatic_set_name(level: u8) -> &'static str {
    match level.clamp(1, 5) {
        2 | 3 => "common-100",
        4 | 5 => "common-1000",
        _ => "none",
    }
}

/// Hard safety cap for a single task's port list (all-ports).
pub const MAX_PORTS_PER_TASK: usize = 65_535;

/// Per-host concurrent connection attempts cap (hard ceiling).
/// Speed-derived values never exceed this.
pub const MAX_TCP_CONCURRENCY_HARD: usize = 256;

/// Canonical resolved port list for one task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedPorts {
    pub ports: Vec<u16>,
    pub source: PortSource,
}

/// Where the port list came from (for evidence/explain).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortSource {
    LevelAutomatic,
    Explicit,
    All,
}

impl std::fmt::Display for PortSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LevelAutomatic => write!(f, "level-automatic"),
            Self::Explicit => write!(f, "explicit"),
            Self::All => write!(f, "all"),
        }
    }
}

/// Level-derived automatic set (used when selection is `Common`).
pub fn automatic_ports_for_level(level: u8) -> Vec<u16> {
    match level.clamp(1, 5) {
        1 => vec![80, 443],
        2 | 3 => {
            let mut ports = COMMON_PORTS_V1.to_vec();
            ports.extend_from_slice(COMMON_100_EXTRA);
            ports.sort_unstable();
            ports.dedup();
            ports
        }
        // Well-known range 1–1000 ("common-1000"). Port breadth saturates
        // here by design; L4/L5 deepen investigation, not port count.
        _ => (1..=1000).collect(),
    }
}

/// Canonical compact rendering of an explicit port list for task params.
///
/// Sorted runs collapse to ranges (`22,80,443,8000-8100`), so contiguous
/// selections like `1-1000` ride in 6 characters instead of ~4 KiB. Output
/// is deterministic and re-parses losslessly via [`parse_port_selection`].
/// Task params stay far below persistence caps for every realistic set.
pub fn compress_port_list(ports: &[u16]) -> String {
    let mut sorted: Vec<u16> = ports.iter().copied().filter(|port| *port > 0).collect();
    sorted.sort_unstable();
    sorted.dedup();
    let mut parts: Vec<String> = Vec::new();
    let mut iter = sorted.into_iter().peekable();
    while let Some(start) = iter.next() {
        let mut end = start;
        while iter
            .peek()
            .is_some_and(|next| *next == end.saturating_add(1))
        {
            end = iter.next().unwrap_or(end);
        }
        if end > start {
            parts.push(format!("{start}-{end}"));
        } else {
            parts.push(start.to_string());
        }
    }
    parts.join(",")
}

/// Resolve a plan-level selection to a concrete sorted port list.
///
/// * `Common` → level-derived automatic set.
/// * `Explicit(ports)` → normalized (sorted, deduped) operator list.
/// * `All` → `1..=65535`.
pub fn resolve_ports(selection: &TcpPortSelection, level: u8) -> ResolvedPorts {
    match selection {
        TcpPortSelection::Common => ResolvedPorts {
            ports: automatic_ports_for_level(level),
            source: PortSource::LevelAutomatic,
        },
        TcpPortSelection::Explicit(ports) => {
            let mut normalized = ports.clone();
            normalized.sort_unstable();
            normalized.dedup();
            normalized.retain(|port| *port > 0);
            ResolvedPorts {
                ports: normalized,
                source: PortSource::Explicit,
            }
        }
        TcpPortSelection::All => ResolvedPorts {
            ports: (1..=65_535).collect(),
            source: PortSource::All,
        },
    }
}

/// Parse `--ports` text into a normalized sorted list.
///
/// Accepts `22`, `22,80,443`, `1-1024`, mixes, whitespace. Rejects port 0,
/// reversed ranges, malformed input, and values > 65535.
pub fn parse_port_selection(value: &str) -> Result<Vec<u16>, String> {
    let mut ports = std::collections::BTreeSet::new();
    for component in value.split(',') {
        let component = component.trim();
        if component.is_empty() {
            return Err(format!("invalid --ports value '{value}'"));
        }
        if let Some((start, end)) = component.split_once('-') {
            let start: u32 = start
                .trim()
                .parse()
                .map_err(|_| format!("invalid --ports value '{value}'"))?;
            let end: u32 = end
                .trim()
                .parse()
                .map_err(|_| format!("invalid --ports value '{value}'"))?;
            if start == 0 || end == 0 || start > 65_535 || end > 65_535 || start > end {
                return Err(format!("invalid --ports value '{value}'"));
            }
            ports.extend(start..=end);
        } else {
            let port: u32 = component
                .parse()
                .map_err(|_| format!("invalid --ports value '{value}'"))?;
            if port == 0 || port > 65_535 {
                return Err(format!("invalid --ports value '{value}'"));
            }
            ports.insert(port);
        }
    }
    if ports.is_empty() {
        return Err(format!("invalid --ports value '{value}'"));
    }
    Ok(ports.into_iter().map(|port| port as u16).collect())
}

/// Per-port connect timeout derived from speed (pressure only).
/// Bounded 200..=3000ms. Faster fails faster; slower waits longer.
pub fn tcp_timeout_for_speed(speed: SpeedSetting) -> std::time::Duration {
    use crate::plan::NamedSpeed;
    let millis = match speed {
        SpeedSetting::Named(NamedSpeed::Slow) => 1500,
        SpeedSetting::Named(NamedSpeed::Balanced) => 800,
        SpeedSetting::Named(NamedSpeed::Fast) => 350,
        SpeedSetting::Named(NamedSpeed::Auto) => 800,
        SpeedSetting::Numeric(value) => 1500u64.saturating_sub((1300u64 * u64::from(value)) / 100),
    };
    std::time::Duration::from_millis(millis.clamp(200, 3000))
}

/// Concurrent connection attempts derived from speed (pressure only).
/// Bounded 16..=128, hard-capped by [`MAX_TCP_CONCURRENCY_HARD`].
pub fn tcp_concurrency_for_speed(speed: SpeedSetting) -> usize {
    use crate::plan::NamedSpeed;
    let concurrent = match speed {
        SpeedSetting::Named(NamedSpeed::Slow) => 32,
        SpeedSetting::Named(NamedSpeed::Balanced) => 64,
        SpeedSetting::Named(NamedSpeed::Fast) => 128,
        SpeedSetting::Named(NamedSpeed::Auto) => 64,
        SpeedSetting::Numeric(value) => 16 + ((112u16 * u16::from(value)) / 100) as usize,
    };
    concurrent.clamp(16, 128).min(MAX_TCP_CONCURRENCY_HARD)
}

/// Whether a goal/level/select combination is eligible for PortDiscovery.
/// Explicit port requests are always eligible (explicit wins, mirroring
/// `level::eligible_task_kinds`); otherwise natural level+goal membership.
pub fn port_eligible_for_plan(goal: ScanGoal, level: u8, ports_requested: bool) -> bool {
    if ports_requested {
        return true;
    }
    crate::level::eligible_task_kinds(goal, level, false, false, false)
        .contains(&crate::execution::TaskKind::PortDiscovery)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_overrides_level_and_dedupes() {
        let resolved = resolve_ports(&TcpPortSelection::Explicit(vec![443, 80, 80, 22]), 1);
        assert_eq!(resolved.ports, vec![22, 80, 443]);
        assert_eq!(resolved.source, PortSource::Explicit);
    }

    #[test]
    fn level_controls_automatic_breadth_only() {
        let l1 = automatic_ports_for_level(1);
        let l2 = automatic_ports_for_level(2);
        let l3 = automatic_ports_for_level(3);
        let l4 = automatic_ports_for_level(4);
        assert_eq!(l2.len(), 100);
        assert!(COMMON_PORTS_V1.iter().all(|port| l2.contains(port)));
        assert_eq!(l3, l2);
        assert_eq!(l4, (1..=1000).collect::<Vec<_>>());
        assert_eq!(automatic_ports_for_level(5), l4);
        assert!(l1.len() < l2.len() && l3.len() < l4.len());
        // Speed never changes the set (checked elsewhere); level sets sorted.
        let mut sorted = l4.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, l4);
        assert_eq!(automatic_set_name(2), "common-100");
        assert_eq!(automatic_set_name(3), "common-100");
        assert_eq!(automatic_set_name(4), "common-1000");
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse_port_selection("0").is_err());
        assert!(parse_port_selection("0,80").is_err());
        assert!(parse_port_selection("90-80").is_err());
        assert!(parse_port_selection("65536").is_err());
        assert!(parse_port_selection("").is_err());
        assert!(parse_port_selection("22,,80").is_err());
    }

    #[test]
    fn all_ports_generator_yields_every_port_exactly_once() {
        // The `--all-ports` generator (never 65k tasks: one task carries
        // `ports=all`) must produce every TCP port 1..=65535 exactly once.
        // Runtime event details intentionally omit the 65k arrays (bounded
        // details cap); the ledger proves coverage via counts + unscanned.
        let resolved = resolve_ports(&TcpPortSelection::All, 3);
        assert_eq!(resolved.source, PortSource::All);
        assert_eq!(resolved.ports.len(), 65_535);
        assert_eq!(resolved.ports, (1u16..=65_535).collect::<Vec<_>>());
        // Same set through the module policy path for `ports=all` params,
        // at every level (level never narrows an explicit/all selection).
        for level in 1..=5 {
            let policy = crate::tcp_discovery::TcpScanPolicy::new(
                level,
                crate::plan::ScanGoal::Recon,
                TcpPortSelection::All,
                crate::plan::SpeedSetting::default(),
            );
            assert_eq!(policy.ports_for_task(Some("all")).ports.len(), 65_535);
        }
    }

    #[test]
    fn ranges_normalize_and_overlap_once() {
        assert_eq!(
            parse_port_selection("80-82,82,81").unwrap(),
            vec![80, 81, 82]
        );
        assert_eq!(parse_port_selection("1-3").unwrap(), vec![1, 2, 3]);
    }
}
