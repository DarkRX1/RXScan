//! Phase 7 service-intelligence model: observations, confidence, planning.
//!
//! Takes open TCP ports (Phase 6) and determines what protocol is actually
//! speaking there — never guessing from the port number alone.
//!
//! # Evidence tiers (confidence)
//!
//! * Port hint only (no probe evidence): NEVER emitted as a classification.
//!   There is no `ServiceObservation` without probe evidence.
//! * Valid protocol handshake (e.g. `SSH-2.0-…`, `HTTP/1.1 200`, TLS
//!   ServerHello, `220` FTP greeting, `+PONG`): medium/high (70–90).
//! * Handshake + banner/details (product/version strings, cert fields,
//!   SMTP capabilities): high (85–95).
//! * Unparseable banner or silence: `unknown` (20–55), banner preserved.
//!
//! Three facts stay separate: `port_hint` (why a probe ran first),
//! `observed_protocol` (what the handshake proved), and
//! `product/version_hint` (strings copied from protocol data, never inferred
//! from the port).
//!
//! # Planner inputs → ordered probes
//!
//! Port, transport, level, goal, and budgets select a small ordered probe set
//! (deterministic by priority then probe id). `--level` controls breadth,
//! `--speed` controls pressure only. Unknown high ports get a conservative
//! generic set; web/API goals try HTTP one level earlier on unknown ports.
//!
//! # Boundaries
//!
//! No authentication (no USER/PASS/AUTH/LOGIN bytes are ever sent —
//! asserted by tests), no destructive commands, no crawling, no fuzzing.
//! Product/version hints are raw observed strings; the full technology
//! fingerprint engine belongs to a later phase.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::discovery::AddressFamily;
use crate::plan::{ScanGoal, SpeedSetting};

/// Probe identifiers. New protocols register here without touching the
/// scheduler; the planner orders them deterministically.
pub const PROBE_SSH: &str = "ssh";
pub const PROBE_HTTP: &str = "http";
pub const PROBE_TLS: &str = "tls";
pub const PROBE_FTP: &str = "ftp";
pub const PROBE_SMTP: &str = "smtp";
pub const PROBE_REDIS: &str = "redis";
pub const PROBE_MYSQL: &str = "mysql";
pub const PROBE_POSTGRES: &str = "postgres";
pub const PROBE_GENERIC: &str = "generic";

/// Deferred seams (documented, NOT implemented): imap, pop3, ldap, mqtt,
/// rdp, smb, dns-over-tcp, rpc, ntp, kerberos.
pub const DEFERRED_PROTOCOLS: &[&str] = &[
    "imap",
    "pop3",
    "ldap",
    "mqtt",
    "rdp",
    "smb",
    "dns-over-tcp",
    "rpc",
    "ntp",
    "kerberos",
];

/// One registered probe: identity, transports, likely ports, order.
/// Lower `priority` runs first; ties break by probe id (deterministic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeSpec {
    pub id: &'static str,
    pub priority: u8,
    pub likely_ports: &'static [u16],
}

pub static PROBE_REGISTRY: &[ProbeSpec] = &[
    ProbeSpec {
        id: PROBE_SSH,
        priority: 10,
        likely_ports: &[22],
    },
    ProbeSpec {
        id: PROBE_HTTP,
        priority: 10,
        likely_ports: &[80, 3000, 5000, 8000, 8001, 8080, 8081, 8888, 9000, 9090],
    },
    ProbeSpec {
        id: PROBE_TLS,
        priority: 10,
        likely_ports: &[443, 8443, 465],
    },
    ProbeSpec {
        id: PROBE_FTP,
        priority: 10,
        likely_ports: &[21],
    },
    ProbeSpec {
        id: PROBE_SMTP,
        priority: 10,
        likely_ports: &[25, 465, 587],
    },
    ProbeSpec {
        id: PROBE_REDIS,
        priority: 10,
        likely_ports: &[6379],
    },
    ProbeSpec {
        id: PROBE_MYSQL,
        priority: 10,
        likely_ports: &[3306, 3307],
    },
    ProbeSpec {
        id: PROBE_POSTGRES,
        priority: 10,
        likely_ports: &[5432],
    },
    ProbeSpec {
        id: PROBE_GENERIC,
        priority: 100,
        likely_ports: &[],
    },
];

/// Maximum probes executed per port task (hard bound; plans rarely reach it
/// because classification stops the sequence early).
pub const MAX_PROBES_PER_PORT: usize = 6;

/// Response/request byte budgets (neither side may grow without bound).
pub const MAX_BANNER_BYTES: usize = 2048;
pub const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_HTTP_BODY_BYTES: usize = 16 * 1024;
pub const MAX_CERT_CHAIN_BYTES: usize = 32 * 1024;
pub const MAX_SMTP_REPLY_BYTES: usize = 4096;

/// Normalized service observation: one open port, one conclusion, evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceObservation {
    pub target: String,
    pub address: String,
    pub address_family: AddressFamily,
    pub port: u16,
    pub transport: String,
    pub parent_port_asset_id: String,
    pub asset_id: String,
    /// Observed protocol: ssh|http|ftp|smtp|redis|mysql|postgres|tls|unknown.
    /// `tls` alone means a bare TLS session with no application classification.
    pub protocol: String,
    /// True when application data ran inside TLS (https/smtps composition).
    pub tls: bool,
    /// Human label: `https`/`smtps` when `tls`, else `protocol`.
    pub service_label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub confidence: u8,
    pub evidence_lines: Vec<String>,
    pub timestamp: u64,
}

impl ServiceObservation {
    pub fn is_classified(&self) -> bool {
        self.protocol != "unknown"
    }
}

/// Stable FNV-1a hex (mirrors asset-ID stability elsewhere).
fn fnv_hex(input: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

/// Stable service-asset ID: parent port asset + protocol + TLS flag.
/// Distinct protocols on one port never collide.
pub fn service_asset_id(parent_port_asset_id: &str, protocol: &str, tls: bool) -> String {
    format!(
        "asset_service_{}",
        fnv_hex(&format!(
            "service:{parent_port_asset_id}:{protocol}:tls={tls}"
        ))
    )
}

pub fn service_asset_identity(parent_port_asset_id: &str, protocol: &str, tls: bool) -> String {
    let label = if tls && protocol == "http" {
        "https".to_owned()
    } else if tls && protocol == "smtp" {
        "smtps".to_owned()
    } else {
        protocol.to_owned()
    };
    format!("{parent_port_asset_id}:service/{label}")
}

/// Deterministic probe plan for one open port.
///
/// * Known ports: primary probe first, alternates per level, generic last.
/// * Unknown ports: generic first (passive), HTTP at L3+ (L2+ for web/API
///   goals), nothing else — conservative by design.
/// * L1 caps at 1 probe; L2 at 2; L3 at 3; L4 at 4; L5 at [`MAX_PROBES_PER_PORT`].
pub fn plan_probes(port: u16, level: u8, goal: ScanGoal) -> Vec<&'static str> {
    let level = level.clamp(1, 5);
    let mut ordered: Vec<&'static str> = Vec::new();
    let mut seen: BTreeSet<&'static str> = BTreeSet::new();
    let mut push = |id: &'static str| {
        if seen.insert(id) {
            ordered.push(id);
        }
    };

    let primary: Option<&'static str> = PROBE_REGISTRY
        .iter()
        .find(|spec| spec.id != PROBE_GENERIC && spec.likely_ports.contains(&port))
        .map(|spec| spec.id);
    // Alternates only where a second handshake is genuinely sensible:
    // TLS-wrapped SMTP on 465 tries TLS first, then plaintext SMTP.
    let alternates: &[&'static str] = match port {
        465 => &[PROBE_SMTP],
        _ => &[],
    };

    match primary {
        Some(first) => {
            push(first);
            // Port 443/8443 compose HTTPS inside the TLS session (module
            // behavior), so no separate plaintext HTTP probe is planned.
            if level >= 4 {
                for alternate in alternates {
                    push(alternate);
                }
            }
            if level >= 2 {
                push(PROBE_GENERIC);
            }
        }
        None => {
            push(PROBE_GENERIC);
            let http_early = matches!(goal, ScanGoal::Web | ScanGoal::Full);
            if (level >= 3 || (http_early && level >= 2)) && port != 0 {
                push(PROBE_HTTP);
            }
        }
    }

    let cap = match level {
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        _ => MAX_PROBES_PER_PORT,
    };
    ordered.truncate(cap);
    ordered
}

/// Per-probe wall-clock budget derived from speed (pressure only).
/// Bounded 500..=5000ms. Truth criteria never change with speed.
pub fn service_timeout_for_speed(speed: SpeedSetting) -> Duration {
    use crate::plan::NamedSpeed;
    let millis = match speed {
        SpeedSetting::Named(NamedSpeed::Slow) => 3000,
        SpeedSetting::Named(NamedSpeed::Balanced) => 2000,
        SpeedSetting::Named(NamedSpeed::Fast) => 1000,
        SpeedSetting::Named(NamedSpeed::Auto) => 2000,
        SpeedSetting::Numeric(value) => 3000u64.saturating_sub((2500u64 * u64::from(value)) / 100),
    };
    Duration::from_millis(millis.clamp(500, 5000))
}

/// Split `Server`-style `Product/Version (...)` tokens into a product hint
/// and optional version hint. Raw observed strings only — never inferred.
pub fn split_product_token(value: &str) -> (String, Option<String>) {
    let first = value.split_whitespace().next().unwrap_or("").trim();
    if first.is_empty() {
        return (String::new(), None);
    }
    match first.split_once('/') {
        Some((product, version)) if !product.is_empty() && !version.is_empty() => {
            (product.to_owned(), Some(version.to_owned()))
        }
        _ => (first.to_owned(), None),
    }
}

/// Split a greeting remainder (`FixtureFTP 1.0 ready`, `server ESMTP`) into
/// a product hint and optional version hint. Handles `Product/Version`,
/// `Product_Version`, and bare `Product Version` word order (common in
/// FTP/SMTP greetings). Raw observed text only — never inferred from ports.
pub fn product_and_version(remainder: &str) -> (String, Option<String>) {
    let mut words = remainder.split_whitespace();
    let first = words.next().unwrap_or("");
    if first.is_empty() {
        return (String::new(), None);
    }
    let (product, version) = split_product_token(first);
    if product.is_empty() {
        return (String::new(), None);
    }
    if version.is_some() {
        return (product, version);
    }
    if let Some(next) = words.next() {
        if next
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_digit())
        {
            return (product, Some(next.to_owned()));
        }
    }
    (product, None)
}

/// Truncate evidence text to a byte budget on a char boundary, reporting
/// whether truncation happened.
pub fn truncate_bounded(text: &str, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text.to_owned(), false);
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_owned(), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planner_prioritizes_likely_probes_first() {
        assert_eq!(plan_probes(22, 3, ScanGoal::Recon)[0], PROBE_SSH);
        assert_eq!(plan_probes(80, 3, ScanGoal::Recon)[0], PROBE_HTTP);
        assert_eq!(plan_probes(443, 3, ScanGoal::Recon)[0], PROBE_TLS);
    }

    #[test]
    fn level_controls_breadth_with_hard_cap() {
        let l1 = plan_probes(443, 1, ScanGoal::Recon);
        let l5 = plan_probes(443, 5, ScanGoal::Recon);
        assert!(l1.len() <= 1);
        assert!(l5.len() <= MAX_PROBES_PER_PORT);
        assert!(l1.len() <= l5.len());
        let unknown_l1 = plan_probes(54321, 1, ScanGoal::Recon);
        assert_eq!(unknown_l1, vec![PROBE_GENERIC]);
    }

    #[test]
    fn unknown_ports_stay_conservative() {
        assert_eq!(plan_probes(54321, 2, ScanGoal::Recon), vec![PROBE_GENERIC]);
        assert_eq!(plan_probes(54321, 3, ScanGoal::Recon)[0], PROBE_GENERIC);
        assert!(plan_probes(54321, 3, ScanGoal::Recon).contains(&PROBE_HTTP));
        // Web goals try HTTP one level earlier on unknown ports.
        assert!(plan_probes(54321, 2, ScanGoal::Web).contains(&PROBE_HTTP));
    }

    #[test]
    fn speed_changes_timeout_not_plan() {
        let slow = plan_probes(80, 3, ScanGoal::Recon);
        let fast = plan_probes(80, 3, ScanGoal::Recon);
        assert_eq!(slow, fast);
        assert!(
            service_timeout_for_speed(SpeedSetting::Numeric(100))
                < service_timeout_for_speed(SpeedSetting::Numeric(0))
        );
    }
}
