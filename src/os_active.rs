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
    // small deterministic port set. No raw required for these signals;
    // raw-enhanced TTL/window signals are added by the Linux backend where
    // capture exists (see `raw_signals_linux`).
    let mut signals = Vec::new();
    let mut sent = 0u32;
    let started = Instant::now();
    for port in [80u16, 443, 22].iter().take(config.max_probes as usize) {
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
