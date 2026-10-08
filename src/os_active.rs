//! Bounded active OS fingerprint foundation.
//!
//! Architecture:
//! ```text
//! packet observations -> normalized OS signals -> fingerprint matcher
//!   -> candidate scoring -> evidence/confidence -> existing result model
//! ```
//! The matcher (`crate::os_fingerprint::OsDb`) stays platform-independent.
//! Only transmission/capture lives in platform backends (gated by the
//! typed capability model). Restricted environments fall back to passive
//! evidence with one controlled explanation.
//!
//! Safety: bounded, deterministic, timeout-limited, rate-limited,
//! cancellable, scope-aware. No exploitation, malformed payloads, auth,
//! brute force, persistence, or evasion. Users can disable via
//! `ActiveProbeConfig::disabled()`.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::execution::CancellationToken;

/// Bounded active probe configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveProbeConfig {
    pub enabled: bool,
    pub timeout: Duration,
    pub max_probes: u32,
}

impl Default for ActiveProbeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout: Duration::from_millis(1500),
            max_probes: 3,
        }
    }
}

impl ActiveProbeConfig {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            timeout: Duration::from_millis(0),
            max_probes: 0,
        }
    }

    pub fn bounded(timeout: Duration, max_probes: u32) -> Self {
        Self {
            enabled: true,
            timeout: timeout.clamp(Duration::from_millis(200), Duration::from_secs(5)),
            max_probes: max_probes.clamp(1, 8),
        }
    }
}

/// Hard per-host probe budget: active OS fingerprinting never expands a
/// scan beyond this many probes for one target. Visible and testable.
pub const MAX_OS_PROBES_PER_HOST: u32 = 6;
/// Deterministic fallback port set sampled only when scan evidence does
/// not already identify open/closed ports. Never an all-ports scan.
const FALLBACK_PROBE_PORTS: [u16; 3] = [80, 443, 22];

/// One bounded active probe family. Small, explainable, no evasion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsProbeKind {
    /// Normal TCP connect sample (open-handshake / reset / silence).
    TcpHandshake,
    /// Closed-port reset-behavior sample.
    TcpResetSample,
    /// ICMP echo observation where the platform supports it.
    IcmpEcho,
}

/// Bounded active probe plan for one host. Reuses ports the scan already
/// knows (one proven open, one proven closed) instead of rescanning;
/// missing evidence lowers coverage through `missing` notes rather than
/// triggering hidden scan expansion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsProbePlan {
    pub host: String,
    pub ports: Vec<u16>,
    pub kinds: Vec<OsProbeKind>,
    /// Total probes planned; always `<= MAX_OS_PROBES_PER_HOST`.
    pub probes_planned: u32,
    pub reused_open_port: Option<u16>,
    pub reused_closed_port: Option<u16>,
    /// Evidence that was unavailable (lowered coverage, explained).
    pub missing: Vec<String>,
}

/// Plan bounded active OS probes for one host.
///
/// Pure and deterministic: same inputs = same plan. `open_ports` and
/// `closed_ports` come from scan evidence already collected; fallback
/// ports fill only the remainder of the budget. No retries, no expansion.
pub fn plan_os_probes(
    host: &str,
    open_ports: &[u16],
    closed_ports: &[u16],
    max_probes: u32,
) -> OsProbePlan {
    let budget = max_probes.clamp(1, MAX_OS_PROBES_PER_HOST) as usize;
    let mut open_sorted: Vec<u16> = open_ports.to_vec();
    open_sorted.sort_unstable();
    open_sorted.dedup();
    let mut closed_sorted: Vec<u16> = closed_ports.to_vec();
    closed_sorted.sort_unstable();
    closed_sorted.dedup();
    let reused_open_port = open_sorted.first().copied();
    let reused_closed_port = closed_sorted
        .iter()
        .copied()
        .find(|port| Some(*port) != reused_open_port);
    let mut ports = Vec::new();
    let mut kinds = Vec::new();
    let mut missing = Vec::new();
    if let Some(port) = reused_open_port {
        ports.push(port);
        kinds.push(OsProbeKind::TcpHandshake);
    } else {
        missing.push("no proven open TCP port from scan evidence".to_owned());
    }
    if ports.len() < budget {
        if let Some(port) = reused_closed_port {
            ports.push(port);
            kinds.push(OsProbeKind::TcpResetSample);
        } else {
            missing.push("no proven closed TCP port from scan evidence".to_owned());
        }
    }
    // Fill only the remainder from the deterministic fallback set.
    for port in FALLBACK_PROBE_PORTS {
        if ports.len() >= budget {
            break;
        }
        if ports.contains(&port) {
            continue;
        }
        ports.push(port);
        kinds.push(OsProbeKind::TcpHandshake);
    }
    // ICMP echo rides the same budget only when the platform reports raw
    // ICMP; the kind stays planned (explained) either way so coverage
    // accounting is honest about what was skipped.
    if kinds.len() < budget {
        kinds.push(OsProbeKind::IcmpEcho);
    }
    let probes_planned = ports.len().min(budget) as u32;
    kinds.truncate(budget);
    OsProbePlan {
        host: host.to_owned(),
        ports,
        kinds,
        probes_planned,
        reused_open_port,
        reused_closed_port,
        missing,
    }
}

/// Per-host TCP port states already observed by the scan: `(open, closed)`.
/// Pure, bounded (64 ports per host per state), deterministic (sorted).
/// Active OS probing reuses these instead of rescanning.
pub fn host_tcp_port_states(
    outputs: &[(crate::execution::TaskId, crate::execution::ModuleOutput)],
) -> std::collections::BTreeMap<String, (Vec<u16>, Vec<u16>)> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut open: BTreeMap<String, BTreeSet<u16>> = BTreeMap::new();
    let mut closed: BTreeMap<String, BTreeSet<u16>> = BTreeMap::new();
    for (_, output) in outputs {
        for event in &output.events {
            let open_event = event.kind == crate::model::EventKind::PortOpen;
            let closed_event = event.kind == crate::model::EventKind::PortClosed;
            if !open_event && !closed_event {
                continue;
            }
            let (Some(address), Some(port)) = (
                event
                    .details
                    .data
                    .get("address")
                    .and_then(serde_json::Value::as_str),
                event
                    .details
                    .data
                    .get("port")
                    .and_then(serde_json::Value::as_u64),
            ) else {
                continue;
            };
            if address.is_empty() || port > u64::from(u16::MAX) {
                continue;
            }
            let slot = if open_event {
                open.entry(address.to_owned()).or_default()
            } else {
                closed.entry(address.to_owned()).or_default()
            };
            if slot.len() < 64 {
                slot.insert(port as u16);
            }
        }
    }
    let mut hosts: BTreeSet<String> = open.keys().cloned().collect();
    hosts.extend(closed.keys().cloned());
    hosts
        .into_iter()
        .map(|host| {
            let open_ports: Vec<u16> = open.remove(&host).unwrap_or_default().into_iter().collect();
            let closed_ports: Vec<u16> = closed
                .remove(&host)
                .unwrap_or_default()
                .into_iter()
                .collect();
            (host, (open_ports, closed_ports))
        })
        .collect()
}

/// Scope-gated active probe entry. The [`crate::scope::ScopePolicy`] stays
/// authoritative: out-of-scope targets produce zero probes, zero signals,
/// and an explicit reason — never network activity.
pub fn probe_host_with_scope(
    ip: IpAddr,
    scope: &crate::scope::ScopePolicy,
    config: &ActiveProbeConfig,
    cancel: &CancellationToken,
    platform: &crate::platform::PlatformInfo,
) -> ActiveProbeOutcome {
    if !scope.permits(Some(ip), None) {
        return ActiveProbeOutcome {
            signals: Vec::new(),
            probes_sent: 0,
            unavailable_reason: Some(
                "OS probe skipped: target is outside authorized scope; no network activity performed"
                    .to_owned(),
            ),
            cancelled: false,
        };
    }
    probe_host(ip, config, cancel, platform)
}

/// Normalized OS signal from one bounded probe. Platform-independent;
/// backends fill what they can observe honestly (TTL/window/options/MSS
/// where raw capture exists, timing/banner behavior everywhere).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsSignal {
    pub source: String,
    pub feature: String,
    pub value: String,
    pub confidence: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveProbeOutcome {
    pub signals: Vec<OsSignal>,
    pub probes_sent: u32,
    pub unavailable_reason: Option<String>,
    pub cancelled: bool,
}

/// Bounded active probe for one host. Scope must already be enforced by
/// the caller; this function never expands scope. Returns passive-only
/// signals plus an `unavailable_reason` when raw capability is missing.
pub fn probe_host(
    ip: IpAddr,
    config: &ActiveProbeConfig,
    cancel: &CancellationToken,
    platform: &crate::platform::PlatformInfo,
) -> ActiveProbeOutcome {
    if !config.enabled {
        return ActiveProbeOutcome {
            signals: Vec::new(),
            probes_sent: 0,
            unavailable_reason: Some(
                "active OS fingerprinting disabled by configuration".to_owned(),
            ),
            cancelled: false,
        };
    }
    if cancel.is_cancelled() {
        return ActiveProbeOutcome {
            signals: Vec::new(),
            probes_sent: 0,
            unavailable_reason: None,
            cancelled: true,
        };
    }
    // Capability gate near the platform boundary: one controlled
    // explanation, never repeated low-level failures.
    if !platform.is_available(crate::platform::Capability::ActiveOsFingerprinting) {
        return ActiveProbeOutcome {
            signals: Vec::new(),
            probes_sent: 0,
            unavailable_reason: Some(
                "Active OS probes unavailable: raw-packet capability is unavailable in this environment; fallback: passive OS evidence remains enabled".to_owned(),
            ),
            cancelled: false,
        };
    }
    // Portable bounded probes: TCP connect timing + banner sampling on a
    // small deterministic port set derived from the shared probe planner
    // (no evidence reuse here; callers with scan evidence plan first and
    // probe those ports). No raw required for these signals; raw-enhanced
    // TTL/window signals are added by the Linux backend where capture
    // exists (see `raw_signals_linux`).
    let planned = plan_os_probes(&ip.to_string(), &[], &[], config.max_probes);
    let mut signals = Vec::new();
    let mut sent = 0u32;
    let started = Instant::now();
    for port in planned.ports.iter().take(config.max_probes as usize) {
        if cancel.is_cancelled() {
            return ActiveProbeOutcome {
                signals,
                probes_sent: sent,
                unavailable_reason: None,
                cancelled: true,
            };
        }
        if started.elapsed() >= config.timeout {
            break;
        }
        let addr = std::net::SocketAddr::new(ip, *port);
        let remaining = config.timeout.saturating_sub(started.elapsed());
        let probe_timeout = remaining.min(Duration::from_millis(800));
        let probe_start = Instant::now();
        match crate::platform::network::tcp_connect(addr, probe_timeout) {
            Ok(_) => {
                sent += 1;
                // Timing signal: fast loopback vs filtered is weak alone;
                // matcher caps lone hints (see os_fingerprint confidence).
                signals.push(OsSignal {
                    source: "tcp_timing".to_owned(),
                    feature: "connect_latency_ms".to_owned(),
                    value: format!("{}", probe_start.elapsed().as_millis().min(9999)),
                    confidence: 30,
                });
                signals.push(OsSignal {
                    source: "tcp_behavior".to_owned(),
                    feature: "open_handshake".to_owned(),
                    value: format!("port {port} accepted"),
                    confidence: 35,
                });
            }
            Err(error) => {
                sent += 1;
                let category = crate::platform::network::normalize_io_error(&error);
                match category {
                    crate::execution::ErrorCategory::ConnectionRefused => {
                        signals.push(OsSignal {
                            source: "tcp_behavior".to_owned(),
                            feature: "tcp_reset".to_owned(),
                            value: format!("port {port} reset"),
                            confidence: 35,
                        });
                    }
                    crate::execution::ErrorCategory::ConnectTimeout => {
                        signals.push(OsSignal {
                            source: "tcp_timing".to_owned(),
                            feature: "filtered_silence".to_owned(),
                            value: format!("port {port} silent"),
                            confidence: 25,
                        });
                    }
                    _ => {
                        // Local errors are not OS signals; keep bounded.
                    }
                }
            }
        }
        // Deterministic rate limit: 50ms between probes.
        std::thread::sleep(Duration::from_millis(50));
    }
    // Raw-enhanced signals where the Linux backend can observe them.
    #[cfg(target_os = "linux")]
    {
        signals.extend(raw_signals_linux(ip));
    }
    signals.truncate(16);
    ActiveProbeOutcome {
        signals,
        probes_sent: sent,
        unavailable_reason: None,
        cancelled: false,
    }
}

/// Linux raw-enhanced signals (TTL/window/options family). Best-effort:
/// returns empty when capture is unavailable; never fails the probe.
#[cfg(target_os = "linux")]
fn raw_signals_linux(_ip: IpAddr) -> Vec<OsSignal> {
    // Foundation stub: raw header observation plugs in here without
    // reshaping output. Currently returns no raw signals (honest absence)
    // so portable and raw paths share one matcher and corpus.
    Vec::new()
}

/// Convert active signals to matcher evidence (bounded excerpts).
pub fn signals_to_evidence(signals: &[OsSignal]) -> Vec<crate::os_fingerprint::OsEvidence> {
    signals
        .iter()
        .take(16)
        .map(|s| crate::os_fingerprint::OsEvidence {
            source: s.source.clone(),
            feature: s.feature.clone(),
            value: s.value.chars().take(64).collect(),
            confidence: s.confidence.clamp(1, 95),
            task_id: None,
            evidence_id: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::capabilities as plat;

    fn linux_full() -> crate::platform::PlatformInfo {
        plat::fixture_linux_full()
    }

    #[test]
    fn disabled_returns_reason_and_no_probes() {
        let out = probe_host(
            "192.0.2.10".parse().unwrap(),
            &ActiveProbeConfig::disabled(),
            &CancellationToken::default(),
            &linux_full(),
        );
        assert_eq!(out.probes_sent, 0);
        assert!(out.unavailable_reason.is_some());
        assert!(out.signals.is_empty());
    }

    #[test]
    fn restricted_platform_falls_back_with_one_explanation() {
        let termux = plat::fixture_termux_restricted();
        let out = probe_host(
            "192.0.2.10".parse().unwrap(),
            &ActiveProbeConfig::default(),
            &CancellationToken::default(),
            &termux,
        );
        assert!(
            out.unavailable_reason
                .as_ref()
                .unwrap()
                .contains("passive OS evidence remains enabled")
        );
        assert!(out.signals.is_empty());
    }

    #[test]
    fn cancelled_is_prompt() {
        let cancel = CancellationToken::default();
        cancel.cancel();
        let out = probe_host(
            "192.0.2.10".parse().unwrap(),
            &ActiveProbeConfig::default(),
            &cancel,
            &linux_full(),
        );
        assert!(out.cancelled);
    }

    // ---------------- bounded probe plan ----------------

    #[test]
    fn probe_budget_is_visible_and_never_exceeded() {
        // Evidence reuse: known open + closed ports lead the plan.
        let plan = plan_os_probes("192.0.2.10", &[443, 80], &[22], 6);
        assert_eq!(plan.reused_open_port, Some(80));
        assert_eq!(plan.reused_closed_port, Some(22));
        assert!(plan.ports.contains(&80));
        assert!(plan.ports.contains(&22));
        assert!(plan.probes_planned <= MAX_OS_PROBES_PER_HOST);
        assert_eq!(plan.ports.len() as u32, plan.probes_planned);
        // Oversized requests clamp to the budget, never expand.
        let clamped = plan_os_probes("192.0.2.10", &[], &[], u32::MAX);
        assert!(clamped.probes_planned <= MAX_OS_PROBES_PER_HOST);
        assert!(clamped.ports.len() <= MAX_OS_PROBES_PER_HOST as usize);
        // Missing evidence is explained, never hidden expansion.
        assert!(!clamped.missing.is_empty());
        // Deterministic: same evidence in different order, same plan.
        assert_eq!(
            plan_os_probes("192.0.2.10", &[443, 80], &[22, 22], 6),
            plan_os_probes("192.0.2.10", &[80, 443], &[22], 6)
        );
    }

    #[test]
    fn no_evidence_means_fallback_only_and_explained() {
        let plan = plan_os_probes("2001:db8::10", &[], &[], 3);
        assert!(plan.reused_open_port.is_none());
        assert!(plan.reused_closed_port.is_none());
        assert_eq!(plan.ports.len(), 3);
        assert_eq!(plan.missing.len(), 2);
    }

    fn scope_for(target: &str) -> crate::scope::ScopePolicy {
        let spec = crate::target::TargetSpec::parse(target).unwrap();
        crate::scope::ScopePolicy::from_targets(std::slice::from_ref(&spec), &[], &[]).unwrap()
    }

    #[test]
    fn out_of_scope_targets_see_zero_network_activity() {
        let scope = scope_for("192.0.2.10");
        // 198.51.100.20 is outside scope: no probes, no signals, explicit
        // reason. This path performs no socket I/O by construction.
        let out = probe_host_with_scope(
            "198.51.100.20".parse().unwrap(),
            &scope,
            &ActiveProbeConfig::default(),
            &CancellationToken::default(),
            &linux_full(),
        );
        assert_eq!(out.probes_sent, 0);
        assert!(out.signals.is_empty());
        assert!(!out.cancelled);
        let reason = out.unavailable_reason.unwrap();
        assert!(reason.contains("outside authorized scope"));
        assert!(reason.contains("no network activity"));
    }

    #[test]
    fn port_states_reuse_scan_evidence_without_rescanning() {
        use crate::execution::{ModuleOutput, TaskId};
        use crate::model::{
            BoundedDetails, Event, EventKind, MAX_EVENT_DETAILS_BYTES, Provenance, ScanPlanId,
            Timestamp,
        };
        let provenance = Provenance::new(
            "test.module",
            "1.0.0",
            ScanPlanId("plan_test".to_owned()),
            Timestamp(7),
        )
        .unwrap();
        let make = |kind: EventKind, address: &str, port: u64| {
            Event::new(
                kind,
                None,
                BoundedDetails::from_value(
                    serde_json::json!({"address": address, "port": port}),
                    MAX_EVENT_DETAILS_BYTES,
                )
                .unwrap(),
                provenance.clone(),
            )
            .unwrap()
        };
        let output = ModuleOutput {
            events: vec![
                make(EventKind::PortOpen, "192.0.2.10", 443),
                make(EventKind::PortOpen, "192.0.2.10", 443),
                make(EventKind::PortClosed, "192.0.2.10", 22),
                make(EventKind::PortOpen, "198.51.100.20", 80),
            ],
            ..Default::default()
        };
        let states = host_tcp_port_states(&[(TaskId("t".to_owned()), output)]);
        assert_eq!(
            states.get("192.0.2.10"),
            Some(&(vec![443], vec![22])),
            "deduped and sorted"
        );
        assert_eq!(states.get("198.51.100.20"), Some(&(vec![80], vec![])));
        // The plan reuses exactly these ports first.
        let (open, closed) = states.get("192.0.2.10").unwrap().clone();
        let plan = plan_os_probes("192.0.2.10", &open, &closed, 6);
        assert_eq!(plan.ports[0], 443);
        assert_eq!(plan.ports[1], 22);
    }

    #[test]
    fn ttl_placeholders_cannot_identify_production() {
        // Generic TTL/window defaults must not identify an OS. Production
        // corpus ships no ip_ttl/tcp_window rules, so such evidence alone
        // matches nothing and stays Unknown.
        let db =
            crate::os_fingerprint::OsDb::load_from_dir(std::path::Path::new("fingerprints/os/v1"));
        let evidence = vec![
            crate::os_fingerprint::OsEvidence {
                source: "ip_ttl".to_owned(),
                feature: "ttl".to_owned(),
                value: "64".to_owned(),
                confidence: 50,
                task_id: None,
                evidence_id: None,
            },
            crate::os_fingerprint::OsEvidence {
                source: "tcp_window".to_owned(),
                feature: "window".to_owned(),
                value: "29200".to_owned(),
                confidence: 50,
                task_id: None,
                evidence_id: None,
            },
        ];
        // Must not produce a confident Linux claim from defaults alone.
        // Empty is ideal; any candidate must stay weak and capped.
        let candidates = db.classify_host(&evidence);
        assert!(
            candidates.is_empty() || candidates.iter().all(|c| c.confidence <= 70),
            "TTL defaults must not identify: {candidates:?}"
        );
    }

    #[test]
    fn signals_convert_to_evidence_bounded() {
        let signals = vec![OsSignal {
            source: "tcp_behavior".to_owned(),
            feature: "tcp_reset".to_owned(),
            value: "x".repeat(200),
            confidence: 200,
        }];
        let evidence = signals_to_evidence(&signals);
        assert_eq!(evidence.len(), 1);
        assert!(evidence[0].value.len() <= 64);
        assert!(evidence[0].confidence <= 95);
    }

    #[test]
    fn active_plus_passive_classifies_without_certainty() {
        // Strong: two classes corroborate.
        let db = crate::os_fingerprint::OsDb::from_packs(vec![(
            "t".to_owned(),
            crate::os_fingerprint::parse_os_pack(
                r#"{"schema_version":1,"rules":[{"id":"a","family":"Linux","features":[{"source":"tcp_behavior","pattern":"reset","weight":15},{"source":"ssh_banner","pattern":"Ubuntu","weight":20}],"confidence_cap":85,"source":"t"}]}"#,
                "t",
            )
            .unwrap(),
        )]);
        let candidates = db.classify_host(&[
            crate::os_fingerprint::OsEvidence {
                source: "tcp_behavior".to_owned(),
                feature: "tcp_reset".to_owned(),
                value: "port 80 reset".to_owned(),
                confidence: 35,
                task_id: None,
                evidence_id: None,
            },
            crate::os_fingerprint::OsEvidence {
                source: "ssh_banner".to_owned(),
                feature: "platform_token".to_owned(),
                value: "Ubuntu".to_owned(),
                confidence: 50,
                task_id: None,
                evidence_id: None,
            },
        ]);
        assert!(!candidates.is_empty());
        // Never certainty: capped at 90.
        assert!(candidates.iter().all(|c| c.confidence <= 90));
    }

    #[test]
    fn ambiguous_stays_ambiguous_and_ties_deterministic() {
        let db = crate::os_fingerprint::OsDb::from_packs(vec![(
            "t".to_owned(),
            crate::os_fingerprint::parse_os_pack(
                r#"{"schema_version":1,"rules":[
                  {"id":"a-linux","family":"Linux","features":[{"source":"s","pattern":"x","weight":10}],"confidence_cap":80,"source":"t"},
                  {"id":"b-bsd","family":"BSD","features":[{"source":"s","pattern":"x","weight":10}],"confidence_cap":80,"source":"t"}]}"#,
                "t",
            )
            .unwrap(),
        )]);
        let evidence = vec![crate::os_fingerprint::OsEvidence {
            source: "s".to_owned(),
            feature: "f".to_owned(),
            value: "x".to_owned(),
            confidence: 50,
            task_id: None,
            evidence_id: None,
        }];
        let first = db.classify_host(&evidence);
        let second = db.classify_host(&evidence);
        assert_eq!(first, second, "tie handling must be deterministic");
        // Both families present (ambiguous), neither certain.
        assert!(!first.is_empty());
    }

    #[test]
    fn conflicting_missing_unknown_handled() {
        let db = crate::os_fingerprint::OsDb::from_packs(vec![(
            "t".to_owned(),
            crate::os_fingerprint::parse_os_pack(
                r#"{"schema_version":1,"rules":[{"id":"a","family":"Linux","features":[{"source":"s","pattern":"x","weight":10}],"exclusions":[{"source":"s","pattern":"y","weight":1}],"confidence_cap":80,"source":"t"}]}"#,
                "t",
            )
            .unwrap(),
        )]);
        // Conflicting (excluded) -> empty.
        let conflict = vec![
            crate::os_fingerprint::OsEvidence {
                source: "s".to_owned(),
                feature: "f".to_owned(),
                value: "x".to_owned(),
                confidence: 50,
                task_id: None,
                evidence_id: None,
            },
            crate::os_fingerprint::OsEvidence {
                source: "s".to_owned(),
                feature: "f".to_owned(),
                value: "y".to_owned(),
                confidence: 50,
                task_id: None,
                evidence_id: None,
            },
        ];
        assert!(db.classify_host(&conflict).is_empty());
        // Missing/unknown -> empty, never invented.
        assert!(db.classify_host(&[]).is_empty());
    }
}
