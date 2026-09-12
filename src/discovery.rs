//! Phase 5 host-discovery policy and state model.
//!
//! Centralizes discovery breadth (`--level`), execution pressure (`--speed`),
//! technique selection (`--ping` / `--discover` / lightweight), CIDR bounding,
//! and host-state semantics (`Alive` / `Unreachable` / `Unknown`).
//!
//! # Host-state semantics
//!
//! * `Alive`: credible positive evidence (ICMP echo reply, TCP connect
//!   success, or TCP RST/refused). Confidence 85–95.
//! * `Unreachable`: definitive negative evidence (ICMP destination
//!   unreachable, TCP host/network unreachable). Confidence ~70.
//! * `Unknown`: no definitive evidence (all probes timed out, or all
//!   techniques unavailable). ICMP failure alone NEVER means dead; a host
//!   may block ICMP while accepting TCP. Confidence ~20–30.
//!
//! # Level policy (breadth, NOT pressure)
//!
//! * L1: minimal single-probe (`icmp x1 + tcp [80]`; `Discover` promotes to L2
//!   breadth so `--discover` is always multi-probe).
//! * L2: `icmp x1 + tcp [80,443]` (minimal fallback).
//! * L3: standard multi-probe (`icmp x2 + tcp [22,80,443]`).
//! * L4: broader safe set (`icmp x2 + tcp [22,80,443,8080]`).
//! * L5: deepest bounded set (`icmp x3 + tcp [22,80,443,8080,8443]`).
//!
//! Level 5 is bounded to 5 TCP ports and 3 ICMP attempts. `--ping`
//! prioritizes ICMP (TCP fallback truncated to a single port, disabled
//! entirely at L1). An explicit `discovery_ports` configuration override
//! replaces the level-derived TCP set (bounded to 8 ports, sorted).
//!
//! # Speed policy (pressure, NOT meaning)
//!
//! `--speed` controls per-probe timeouts, retry delays, and scheduler host
//! concurrency. It never changes `Alive`/`Unknown`/`Unreachable` meaning.
//! Speed 100 is still capped by `max_concurrency` and hard budgets.
//!
//! # Scope / CIDR
//!
//! CIDR expansion is lazy/bounded: iterate `hosts()` in deterministic order,
//! keep only `ScopePolicy::permits` addresses, take at most `max_hosts`.
//! Exclusions always win. No discovery-derived address (DNS resolution,
//! CIDR host) may expand scope; each is re-checked before probing.
//!
//! # Deferred sub-capabilities
//!
//! ARP (local IPv4) and IPv6 Neighbor Discovery require raw link-layer
//! access and are documented as deferred. Their technique variants exist so
//! policy can reference them, but the executor returns `Unavailable` with
//! structured evidence and never fakes support.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::plan::{NamedSpeed, SpeedSetting};
use crate::scope::ScopePolicy;

/// Explicit host reachability state. There is no `Dead`; use `Unknown` when
/// evidence is inconclusive and `Unreachable` only with definitive negative
/// evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostState {
    Alive,
    Unreachable,
    Unknown,
}

impl std::fmt::Display for HostState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Alive => write!(f, "alive"),
            Self::Unreachable => write!(f, "unreachable"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Address family of a discovery target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    V4,
    V6,
}

impl AddressFamily {
    pub fn of(ip: &IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }
}

/// Discovery technique. `Arp` and `NeighborDiscovery` are deferred: policy
/// may reference them, but execution returns `Unavailable` (never faked).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryTechnique {
    IcmpEcho,
    TcpConnect,
    Arp,
    NeighborDiscovery,
}

impl std::fmt::Display for DiscoveryTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IcmpEcho => write!(f, "icmp_echo"),
            Self::TcpConnect => write!(f, "tcp_connect"),
            Self::Arp => write!(f, "arp"),
            Self::NeighborDiscovery => write!(f, "neighbor_discovery"),
        }
    }
}

/// How discovery was requested. Centralized here so CLI handlers stay thin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMode {
    /// No `--ping`/`--discover`: lightweight per-level discovery.
    #[default]
    Lightweight,
    /// `--ping`: prioritize ICMP reachability.
    Ping,
    /// `--discover`: configured multi-probe policy.
    Discover,
}

impl DiscoveryMode {
    pub fn from_flags(ping: bool, discover: bool) -> Self {
        if ping {
            Self::Ping
        } else if discover {
            Self::Discover
        } else {
            Self::Lightweight
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lightweight => "lightweight",
            Self::Ping => "ping",
            Self::Discover => "discover",
        }
    }
}

/// Outcome of a single probe attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Credible positive evidence (echo reply, connect success, RST/refused).
    Success { latency: Duration, detail: String },
    /// Definitive negative evidence (host/net unreachable).
    Unreachable { detail: String },
    /// No response within the per-probe timeout.
    Timeout,
    /// Technique could not run (privileges, unsupported platform, deferred).
    Unavailable { reason: String },
    /// Cancelled promptly (maps to scheduler `Cancelled`, not a host state).
    Cancelled,
}

/// One probe attempt with technique, target, and outcome.
#[derive(Debug, Clone)]
pub struct ProbeRecord {
    pub technique: DiscoveryTechnique,
    pub target: IpAddr,
    pub port: Option<u16>,
    pub outcome: ProbeOutcome,
    pub latency: Option<Duration>,
}

impl ProbeRecord {
    pub fn success(
        technique: DiscoveryTechnique,
        target: IpAddr,
        port: Option<u16>,
        latency: Duration,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            technique,
            target,
            port,
            outcome: ProbeOutcome::Success {
                latency,
                detail: detail.into(),
            },
            latency: Some(latency),
        }
    }

    pub fn unreachable(
        technique: DiscoveryTechnique,
        target: IpAddr,
        port: Option<u16>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            technique,
            target,
            port,
            outcome: ProbeOutcome::Unreachable {
                detail: detail.into(),
            },
            latency: None,
        }
    }

    pub fn timeout(technique: DiscoveryTechnique, target: IpAddr, port: Option<u16>) -> Self {
        Self {
            technique,
            target,
            port,
            outcome: ProbeOutcome::Timeout,
            latency: None,
        }
    }

    pub fn unavailable(
        technique: DiscoveryTechnique,
        target: IpAddr,
        port: Option<u16>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            technique,
            target,
            port,
            outcome: ProbeOutcome::Unavailable {
                reason: reason.into(),
            },
            latency: None,
        }
    }

    /// Human-readable one-line evidence for this probe.
    pub fn describe(&self) -> String {
        let target = match self.port {
            Some(port) => format!("{}:{}", self.target, port),
            None => self.target.to_string(),
        };
        match &self.outcome {
            ProbeOutcome::Success { detail, .. } => {
                format!("{} {} succeeded: {}", self.technique, target, detail)
            }
            ProbeOutcome::Unreachable { detail } => {
                format!("{} {} unreachable: {}", self.technique, target, detail)
            }
            ProbeOutcome::Timeout => format!("{} {} timed out", self.technique, target),
            ProbeOutcome::Unavailable { reason } => {
                format!("{} {} unavailable: {}", self.technique, target, reason)
            }
            ProbeOutcome::Cancelled => format!("{} {} cancelled", self.technique, target),
        }
    }
}

/// Centralized host-discovery policy (breadth from level/mode, pressure from
/// speed, bounds from budgets/config).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDiscoveryPolicy {
    pub mode: DiscoveryMode,
    pub level: u8,
    pub use_icmp: bool,
    pub use_tcp: bool,
    pub tcp_ports: Vec<u16>,
    pub icmp_attempts: u32,
    pub icmp_timeout_ms: u64,
    pub tcp_timeout_ms: u64,
}

/// Default TCP reachability candidates per level (conservative, bounded).
fn base_tcp_ports_for_level(level: u8) -> Vec<u16> {
    match level {
        0 | 1 => vec![80],
        2 => vec![80, 443],
        3 => vec![22, 80, 443],
        4 => vec![22, 80, 443, 8080],
        _ => vec![22, 80, 443, 8080, 8443],
    }
}

fn base_icmp_attempts_for_level(level: u8) -> u32 {
    match level {
        0..=2 => 1,
        3 | 4 => 2,
        _ => 3,
    }
}

/// Per-probe timeout derived from speed (pressure only, never state meaning).
/// Slow waits longer, fast fails faster. Always bounded 300..=3000ms.
pub fn probe_timeout_ms_for_speed(speed: SpeedSetting) -> u64 {
    let millis = match speed {
        SpeedSetting::Named(NamedSpeed::Slow) => 2000,
        SpeedSetting::Named(NamedSpeed::Balanced) => 1000,
        SpeedSetting::Named(NamedSpeed::Fast) => 500,
        SpeedSetting::Named(NamedSpeed::Auto) => 1000,
        SpeedSetting::Numeric(value) => {
            // 0 -> 2000ms, 100 -> 300ms, linear.
            2000u64.saturating_sub((1700u64 * u64::from(value)) / 100)
        }
    };
    millis.clamp(300, 3000)
}

/// Parse an explicit `discovery_ports` configuration value (`"80,443"`).
/// Bounded to 8 ports, sorted, deduped. Errors are fail-fast strings.
pub fn parse_discovery_ports(value: &str) -> Result<Vec<u16>, String> {
    let mut ports = BTreeSet::new();
    for component in value.split(',') {
        let component = component.trim();
        if component.is_empty() {
            return Err(format!("empty discovery port in '{value}'"));
        }
        let port: u16 = component
            .parse()
            .map_err(|_| format!("invalid discovery port '{component}' in '{value}'"))?;
        if port == 0 {
            return Err("discovery port must be 1..=65535, got 0".to_owned());
        }
        ports.insert(port);
        if ports.len() > 8 {
            return Err(format!(
                "discovery_ports is bounded to 8 ports (got more in '{value}')"
            ));
        }
    }
    if ports.is_empty() {
        return Err(format!("empty discovery_ports '{value}'"));
    }
    Ok(ports.into_iter().collect())
}

impl HostDiscoveryPolicy {
    /// Centralized policy constructor. `discovery_ports_override` comes from
    /// configuration (`discovery_ports`); `None` means level-derived ports.
    pub fn for_level(
        level: u8,
        mode: DiscoveryMode,
        speed: SpeedSetting,
        discovery_ports_override: Option<&[u16]>,
    ) -> Self {
        let level = level.clamp(1, 5);
        // Discover at L1 is promoted to L2 breadth so it is always
        // multi-probe even when the task level is minimal.
        let effective_level = match (level, mode) {
            (1, DiscoveryMode::Discover) => 2,
            (other, _) => other,
        };
        let mut tcp_ports = if let Some(custom) = discovery_ports_override {
            let mut bounded: Vec<u16> = custom.to_vec();
            bounded.sort_unstable();
            bounded.dedup();
            bounded.truncate(8);
            bounded
        } else {
            base_tcp_ports_for_level(effective_level)
        };
        // Ping prioritizes ICMP: truncate TCP fallback to a single port,
        // disabled entirely at L1 (ICMP-only minimal probe).
        let (use_icmp, use_tcp) = match mode {
            DiscoveryMode::Ping if effective_level <= 1 => {
                tcp_ports.clear();
                (true, false)
            }
            DiscoveryMode::Ping => {
                tcp_ports.truncate(1);
                (true, !tcp_ports.is_empty())
            }
            DiscoveryMode::Discover => (true, !tcp_ports.is_empty()),
            DiscoveryMode::Lightweight => (true, !tcp_ports.is_empty()),
        };
        let timeout = probe_timeout_ms_for_speed(speed);
        Self {
            mode,
            level,
            use_icmp,
            use_tcp,
            tcp_ports,
            icmp_attempts: base_icmp_attempts_for_level(effective_level),
            icmp_timeout_ms: timeout,
            tcp_timeout_ms: timeout,
        }
    }

    /// Short policy description for `--explain` and evidence.
    pub fn describe(&self) -> String {
        format!(
            "discovery {} level {}: icmp {} (x{}, {}ms), tcp {} ({}, {}ms)",
            self.mode.as_str(),
            self.level,
            if self.use_icmp { "on" } else { "off" },
            self.icmp_attempts,
            self.icmp_timeout_ms,
            if self.use_tcp { "on" } else { "off" },
            if self.tcp_ports.is_empty() {
                "no ports".to_owned()
            } else {
                self.tcp_ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            },
            self.tcp_timeout_ms,
        )
    }
}

/// Conclude host state from correlated probe records.
///
/// * Any `Success` => `Alive` (ICMP reply 95, TCP connect 90, TCP RST 85).
/// * Else any `Unreachable` => `Unreachable` (70).
/// * Else `Unknown` (30, or 20 when every probe was `Unavailable`).
///
/// Cancelled probes are ignored for state (caller maps cancellation to the
/// scheduler `Cancelled` terminal state, not a host state).
pub fn conclude_state(probes: &[ProbeRecord]) -> (HostState, u8, Vec<DiscoveryTechnique>, String) {
    let mut techniques: BTreeSet<DiscoveryTechnique> = BTreeSet::new();
    for probe in probes {
        // Stable ordering for technique display.
        techniques.insert(probe.technique);
    }
    // Stable technique order: icmp, tcp, arp, nd.
    let ordered_techniques = [
        DiscoveryTechnique::IcmpEcho,
        DiscoveryTechnique::TcpConnect,
        DiscoveryTechnique::Arp,
        DiscoveryTechnique::NeighborDiscovery,
    ]
    .into_iter()
    .filter(|technique| techniques.contains(technique))
    .collect::<Vec<_>>();

    // Alive: first success in probe order wins for confidence wording.
    for probe in probes {
        if let ProbeOutcome::Success { detail, .. } = &probe.outcome {
            let confidence = if probe.technique == DiscoveryTechnique::IcmpEcho {
                95
            } else if detail.contains("refused") || detail.contains("RST") {
                85
            } else {
                90
            };
            let evidence = format!(
                "Host is Alive: {}. Confidence {confidence} via {}.",
                detail, probe.technique
            );
            return (HostState::Alive, confidence, ordered_techniques, evidence);
        }
    }
    for probe in probes {
        if let ProbeOutcome::Unreachable { detail } = &probe.outcome {
            let evidence = format!(
                "Host is Unreachable: definitive unreachable response received ({detail}). Confidence 70."
            );
            return (HostState::Unreachable, 70, ordered_techniques, evidence);
        }
    }
    // Unknown: summarize what was tried without over-claiming.
    let lines: Vec<String> = probes.iter().map(ProbeRecord::describe).collect();
    let all_unavailable = !probes.is_empty()
        && probes
            .iter()
            .all(|probe| matches!(probe.outcome, ProbeOutcome::Unavailable { .. }));
    let confidence = if all_unavailable { 20 } else { 30 };
    let evidence = if lines.is_empty() {
        "Host state is Unknown: no discovery probes were executed within policy and budgets. No definitive reachable or unreachable response was received.".to_owned()
    } else {
        format!(
            "Host state is Unknown: {}. No definitive reachable or unreachable response was received; ICMP failure alone does not mean the host is dead.",
            lines.join("; ")
        )
    };
    (HostState::Unknown, confidence, ordered_techniques, evidence)
}

/// Expand a CIDR into bounded, deterministic, scope-checked host addresses.
///
/// Iterates `hosts()` lazily (never materializes massive ranges), keeps only
/// addresses permitted by `scope`, preserves order, and takes at most
/// `max_hosts`. A scan cap avoids pathological walks when a huge prefix is
/// mostly excluded.
pub fn expand_cidr_bounded(cidr: IpNet, scope: &ScopePolicy, max_hosts: usize) -> Vec<IpAddr> {
    if max_hosts == 0 {
        return Vec::new();
    }
    // Scan at most max_hosts + a bounded exclusion allowance so a heavily
    // excluded prefix cannot force an unbounded walk (e.g. a /64 that is
    // mostly excluded still terminates).
    const SCAN_ALLOWANCE: usize = 4096;
    let scan_cap = max_hosts.saturating_add(SCAN_ALLOWANCE);
    let mut hosts = Vec::new();
    for (scanned, address) in cidr.hosts().enumerate() {
        if scanned >= scan_cap || hosts.len() >= max_hosts {
            break;
        }
        if scope.permits(Some(address), None) {
            hosts.push(address);
        }
    }
    hosts
}

/// Deterministic sort for host addresses (v4 before v6, then octets).
pub fn sort_hosts_deterministic(hosts: &mut [IpAddr]) {
    hosts.sort_by(|left, right| {
        let family_rank = |address: &IpAddr| match address {
            IpAddr::V4(_) => 0u8,
            IpAddr::V6(_) => 1u8,
        };
        family_rank(left)
            .cmp(&family_rank(right))
            .then_with(|| match (left, right) {
                (IpAddr::V4(left), IpAddr::V4(right)) => u32::from(*left).cmp(&u32::from(*right)),
                (IpAddr::V6(left), IpAddr::V6(right)) => left.octets().cmp(&right.octets()),
                _ => std::cmp::Ordering::Equal,
            })
    });
}

/// Stable asset identity for a discovered address (matches `model` hashing).
pub fn asset_id_for_ip(ip: &IpAddr) -> String {
    // FNV-1a 64-bit over "ip:<canonical>", matching model::Asset scoped IDs.
    let input = format!("ip:{}", ip);
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("asset_ip_{hash:016x}")
}

/// Canonical IPv4/IPv6 loopback helpers for tests and fixtures.
pub fn loopback_v4() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

pub fn loopback_v6() -> IpAddr {
    IpAddr::V6(Ipv6Addr::LOCALHOST)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_controls_breadth_not_pressure() {
        let l1 = HostDiscoveryPolicy::for_level(
            1,
            DiscoveryMode::Lightweight,
            SpeedSetting::Numeric(50),
            None,
        );
        let l5 = HostDiscoveryPolicy::for_level(
            5,
            DiscoveryMode::Lightweight,
            SpeedSetting::Numeric(50),
            None,
        );
        assert!(l1.tcp_ports.len() < l5.tcp_ports.len());
        assert!(l1.icmp_attempts < l5.icmp_attempts);
        assert!(l5.tcp_ports.len() <= 5);
        assert!(l5.icmp_attempts <= 3);
    }

    #[test]
    fn speed_controls_timeouts_not_state() {
        let slow = HostDiscoveryPolicy::for_level(
            3,
            DiscoveryMode::Discover,
            SpeedSetting::Numeric(0),
            None,
        );
        let fast = HostDiscoveryPolicy::for_level(
            3,
            DiscoveryMode::Discover,
            SpeedSetting::Numeric(100),
            None,
        );
        assert!(fast.tcp_timeout_ms < slow.tcp_timeout_ms);
        assert!(fast.icmp_timeout_ms < slow.icmp_timeout_ms);
        // Same breadth regardless of speed.
        assert_eq!(slow.tcp_ports, fast.tcp_ports);
        assert_eq!(slow.icmp_attempts, fast.icmp_attempts);
    }

    #[test]
    fn icmp_timeout_does_not_mean_dead() {
        let target = loopback_v4();
        let probes = vec![
            ProbeRecord::timeout(DiscoveryTechnique::IcmpEcho, target, None),
            ProbeRecord::timeout(DiscoveryTechnique::TcpConnect, target, Some(80)),
        ];
        let (state, confidence, _, evidence) = conclude_state(&probes);
        assert_eq!(state, HostState::Unknown);
        assert!(confidence <= 30);
        assert!(evidence.contains("does not mean"));
    }

    #[test]
    fn tcp_refused_is_alive_evidence() {
        let target = loopback_v4();
        let probes = vec![
            ProbeRecord::timeout(DiscoveryTechnique::IcmpEcho, target, None),
            ProbeRecord::success(
                DiscoveryTechnique::TcpConnect,
                target,
                Some(9),
                Duration::from_millis(1),
                "TCP connection refused (RST) on port 9; host responded so it is reachable",
            ),
        ];
        let (state, confidence, _, evidence) = conclude_state(&probes);
        assert_eq!(state, HostState::Alive);
        assert_eq!(confidence, 85);
        assert!(evidence.contains("Alive"));
    }
}
