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
//! * L1 — minimal `[80, 443]`
//! * L2 — small common `[22, 80, 443, 8080, 8443]`
//! * L3 — standard common (10 ports)
//! * L4 — expanded common (20 ports, full `COMMON_PORTS_V1`)
//! * L5 — broad common (32 ports: full profile + 12 extended)
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

/// Full `v1` common profile (20 ports, sorted). Levels take prefixes or the
/// extended L5 set below; the list lives here and nowhere else.
pub const COMMON_PORTS_V1: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900,
    8080,
];

/// Extended ports for L5 broad set (12 ports, sorted, disjoint from profile).
pub const EXTENDED_PORTS_L5: &[u16] = &[
    3000, 3307, 3388, 5000, 5432, 6379, 8000, 8443, 8888, 9000, 9090, 9200,
];

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
        2 => vec![22, 80, 443, 8080, 8443],
        3 => vec![21, 22, 23, 25, 80, 110, 143, 443, 3306, 8080],
        4 => COMMON_PORTS_V1.to_vec(),
        _ => {
            let mut broad = COMMON_PORTS_V1.to_vec();
            broad.extend_from_slice(EXTENDED_PORTS_L5);
            broad.sort_unstable();
            broad.dedup();
            broad
        }
    }
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
        let l5 = automatic_ports_for_level(5);
        assert!(l1.len() < l5.len());
        assert!(l5.len() <= 32);
        // Speed never changes the set (checked elsewhere); level sets sorted.
        let mut sorted = l5.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, l5);
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
    fn ranges_normalize_and_overlap_once() {
        assert_eq!(
            parse_port_selection("80-82,82,81").unwrap(),
            vec![80, 81, 82]
        );
        assert_eq!(parse_port_selection("1-3").unwrap(), vec![1, 2, 3]);
    }
}
