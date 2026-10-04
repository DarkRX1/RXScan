//! Device-role classification: what a host IS, separate from its OS.
//!
//! A device role (`router`, `printer`, `server`, …) is inferred from
//! correlated signals: service combinations, HTTP fingerprints,
//! certificate naming, DNS names, SSH products, management services, and
//! OS family. Role, vendor, and model carry SEPARATE confidences —
//! `role: router @94` with `model: unknown` is preferable to guessing.
//!
//! Anti-overclassification rules (structural, not advisory):
//! * a role needs at least two distinct signal KINDS (a lone `port 80 +
//!   DNS` never classifies);
//! * weak single-kind evidence caps at [`WEAK_ROLE_CAP`] (55);
//! * role confidence never exceeds [`DEVICE_CONFIDENCE_CAP`] (90);
//! * vendor confidence derives only from vendor-specific signals;
//! * model confidence derives only from model-specific signals
//!   (absent model evidence → `None`, never invented).
//!
//! Rules live outside Rust in versioned packs (`fingerprints/device/v1/`)
//! with the same validation discipline as OS packs. Device classification
//! runs post-scan over the correlation graph (no new packets).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DEVICE_PACK_SCHEMA_VERSION: u32 = 1;
pub const MAX_DEVICE_RULES_PER_FILE: usize = 512;
pub const MAX_DEVICE_SIGNALS_PER_RULE: usize = 16;
pub const MAX_DEVICE_STRING_LEN: usize = 128;
/// Device role confidence ceiling.
pub const DEVICE_CONFIDENCE_CAP: u8 = 90;
/// Ceiling when only one signal kind supports the role.
pub const WEAK_ROLE_CAP: u8 = 55;
/// Minimum distinct signal kinds for a confident role.
pub const MIN_ROLE_SIGNAL_KINDS: usize = 2;

#[derive(Debug, Error)]
pub enum DevicePackError {
    #[error("could not read device pack '{path}': {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("could not parse device pack '{path}': {detail}")]
    Parse { path: String, detail: String },
    #[error("invalid device pack '{path}': {reason}")]
    Invalid { path: String, reason: String },
}

/// One device-role hypothesis for a host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCandidate {
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_hint: Option<String>,
    pub role_confidence: u8,
    /// Vendor confidence, scored from vendor-specific signals only;
    /// `None` (rendered null) means unknown, never a guess.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_confidence: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_confidence: Option<u8>,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub rule_ids: Vec<String>,
}

/// One matchable signal inside a device rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSignal {
    /// Signal kind (`service_product`, `http_server`, `banner_token`,
    /// `cert_name`, `dns_name`, `ssh_product`, `os_family`, `open_port`).
    /// Kinds drive the two-kind minimum; `open_port` alone is the weakest.
    pub kind: String,
    pub pattern: String,
    #[serde(default = "default_contains")]
    pub match_kind: DeviceMatchKind,
    #[serde(default = "default_true")]
    pub case_insensitive: bool,
    /// Weight contribution 1..=50 when matched.
    pub weight: u8,
    /// Whether this signal identifies the vendor (vs the role).
    #[serde(default)]
    pub vendor_signal: bool,
    /// Whether this signal identifies the model (vs the role).
    #[serde(default)]
    pub model_signal: bool,
}

fn default_contains() -> DeviceMatchKind {
    DeviceMatchKind::Contains
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceMatchKind {
    Exact,
    Prefix,
    Contains,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRule {
    pub id: String,
    pub role: String,
    pub signals: Vec<DeviceSignal>,
    #[serde(default)]
    pub exclusions: Vec<DeviceSignal>,
    /// Rule confidence ceiling 1..=90.
    pub confidence_cap: u8,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePack {
    pub schema_version: u32,
    #[serde(default)]
    pub rules: Vec<DeviceRule>,
}

impl DevicePack {
    fn validate(&self, path: &str) -> Result<(), DevicePackError> {
        let invalid = |reason: String| DevicePackError::Invalid {
            path: path.to_owned(),
            reason,
        };
        if self.schema_version != DEVICE_PACK_SCHEMA_VERSION {
            return Err(invalid(format!(
                "unsupported schema_version {}, expected {DEVICE_PACK_SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.rules.len() > MAX_DEVICE_RULES_PER_FILE {
            return Err(invalid(format!(
                "too many rules ({} > {MAX_DEVICE_RULES_PER_FILE})",
                self.rules.len()
            )));
        }
        let mut ids = BTreeSet::new();
        for rule in &self.rules {
            if rule.id.trim().is_empty() || rule.id.len() > 128 {
                return Err(invalid("rule id must be 1..=128 chars".to_owned()));
            }
            if !ids.insert(rule.id.clone()) {
                return Err(invalid(format!("duplicate rule id '{}'", rule.id)));
            }
            for (field, value) in [("role", &rule.role), ("source", &rule.source)] {
                if value.trim().is_empty() || value.len() > MAX_DEVICE_STRING_LEN {
                    return Err(invalid(format!(
                        "rule '{}': {field} must be 1..={MAX_DEVICE_STRING_LEN} chars",
                        rule.id
                    )));
                }
            }
            if rule.confidence_cap == 0 || rule.confidence_cap > DEVICE_CONFIDENCE_CAP {
                return Err(invalid(format!(
                    "rule '{}': confidence_cap must be 1..={DEVICE_CONFIDENCE_CAP}",
                    rule.id
                )));
            }
            if rule.signals.is_empty() || rule.signals.len() > MAX_DEVICE_SIGNALS_PER_RULE {
                return Err(invalid(format!(
                    "rule '{}': signals must be 1..={MAX_DEVICE_SIGNALS_PER_RULE}",
                    rule.id
                )));
            }
            for signal in rule.signals.iter().chain(rule.exclusions.iter()) {
                if signal.kind.trim().is_empty() || signal.kind.len() > 64 {
                    return Err(invalid(format!(
                        "rule '{}': signal kind must be 1..=64 chars",
                        rule.id
                    )));
                }
                if signal.pattern.is_empty() || signal.pattern.len() > MAX_DEVICE_STRING_LEN {
                    return Err(invalid(format!(
                        "rule '{}': pattern must be 1..={MAX_DEVICE_STRING_LEN} chars",
                        rule.id
                    )));
                }
                if signal.weight == 0 || signal.weight > 50 {
                    return Err(invalid(format!(
                        "rule '{}': weight must be 1..=50",
                        rule.id
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Parse + validate one pack from JSON text. Never panics on input.
pub fn parse_device_pack(json: &str, label: &str) -> Result<DevicePack, DevicePackError> {
    let pack: DevicePack = serde_json::from_str(json).map_err(|error| DevicePackError::Parse {
        path: label.to_owned(),
        detail: error.to_string(),
    })?;
    pack.validate(label)?;
    Ok(pack)
}

/// Load statistics for diagnostics honesty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceLoadStats {
    pub packs_loaded: usize,
    pub rules_accepted: usize,
    pub files_rejected: usize,
    #[serde(default)]
    pub rejected_files: Vec<String>,
    #[serde(default)]
    pub pack_paths: Vec<String>,
}

#[derive(Debug, Clone)]
struct CompiledDeviceRule {
    id: String,
    role: String,
    signals: Vec<DeviceSignal>,
    exclusions: Vec<DeviceSignal>,
    confidence_cap: u8,
}

/// Immutable compiled device database, loaded once per scan and shared.
#[derive(Debug, Clone, Default)]
pub struct DeviceDb {
    rules: Vec<CompiledDeviceRule>,
    stats: DeviceLoadStats,
}

impl DeviceDb {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn stats(&self) -> &DeviceLoadStats {
        &self.stats
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn from_packs(packs: Vec<(String, DevicePack)>) -> Self {
        let mut rules = Vec::new();
        let mut seen = BTreeSet::new();
        let mut stats = DeviceLoadStats {
            packs_loaded: packs.len(),
            ..Default::default()
        };
        for (path, pack) in packs {
            if !stats.pack_paths.contains(&path) {
                stats.pack_paths.push(path.clone());
            }
            for rule in pack.rules {
                if !seen.insert(rule.id.clone()) {
                    continue;
                }
                stats.rules_accepted += 1;
                rules.push(CompiledDeviceRule {
                    id: rule.id,
                    role: rule.role,
                    signals: rule.signals,
                    exclusions: rule.exclusions,
                    confidence_cap: rule.confidence_cap,
                });
            }
        }
        rules.sort_by(|a, b| a.id.cmp(&b.id));
        Self { rules, stats }
    }

    /// Load every pack in `dir` once. Missing directory yields an empty DB;
    /// malformed files are counted and skipped.
    pub fn load_from_dir(dir: &Path) -> Self {
        let mut packs = Vec::new();
        let mut stats = DeviceLoadStats::default();
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => return Self::empty(),
        };
        let mut files = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                files.push(path);
            }
        }
        files.sort();
        for path in files {
            let label = path.display().to_string();
            let contents = match std::fs::read_to_string(&path) {
                Ok(contents) => contents,
                Err(_) => {
                    stats.files_rejected += 1;
                    stats.rejected_files.push(label);
                    continue;
                }
            };
            match serde_json::from_str::<DevicePack>(&contents).map(|pack| {
                pack.validate(&label)?;
                Ok::<_, DevicePackError>(pack)
            }) {
                Ok(Ok(pack)) => packs.push((label, pack)),
                _ => {
                    stats.files_rejected += 1;
                    stats.rejected_files.push(label);
                }
            }
        }
        let mut db = Self::from_packs(packs);
        db.stats.files_rejected = stats.files_rejected;
        db.stats.rejected_files = stats.rejected_files;
        db
    }

    /// Classify one host from its signal map (`kind -> observed texts`).
    /// Returns candidates sorted by (role confidence desc, role asc),
    /// at most 3. Deterministic and bounded.
    pub fn classify_host(&self, signals: &BTreeMap<String, Vec<String>>) -> Vec<DeviceCandidate> {
        let mut candidates = Vec::new();
        for rule in &self.rules {
            if rule.exclusions.iter().any(|signal| {
                signals
                    .get(signal.kind.as_str())
                    .is_some_and(|texts| texts.iter().any(|text| signal_matches(signal, text)))
            }) {
                continue;
            }
            let mut weight_sum: u32 = 0;
            let mut kinds: BTreeSet<&str> = BTreeSet::new();
            let mut vendor_weight: u32 = 0;
            let mut model_weight: u32 = 0;
            let mut vendor_text: Option<String> = None;
            let mut model_text: Option<String> = None;
            let mut evidence = Vec::new();
            for signal in &rule.signals {
                let Some(texts) = signals.get(signal.kind.as_str()) else {
                    continue;
                };
                let Some(hit) = texts.iter().find(|text| signal_matches(signal, text)) else {
                    continue;
                };
                weight_sum += u32::from(signal.weight);
                kinds.insert(signal.kind.as_str());
                if signal.vendor_signal {
                    vendor_weight += u32::from(signal.weight);
                    vendor_text = vendor_text.or_else(|| extract_vendor_token(hit));
                }
                if signal.model_signal {
                    model_weight += u32::from(signal.weight);
                    model_text = model_text.or_else(|| extract_model_token(hit));
                }
                if evidence.len() < 8 {
                    evidence.push(format!("{}:{}", signal.kind, truncate(hit, 80)));
                }
            }
            if kinds.is_empty() {
                continue;
            }
            // Structural weak-signal guard: one kind alone caps low even
            // with heavy weight (e.g. HTTP + DNS must not imply router).
            let mut role_confidence = 30u32 + 15 * kinds.len() as u32 + weight_sum.min(25);
            if kinds.len() < MIN_ROLE_SIGNAL_KINDS {
                role_confidence = role_confidence.min(u32::from(WEAK_ROLE_CAP));
            }
            role_confidence = role_confidence.min(u32::from(rule.confidence_cap));
            let (vendor, vendor_confidence) = match (vendor_text, vendor_weight) {
                (Some(text), weight) if weight >= 15 => (Some(text), Some(weight.min(90) as u8)),
                _ => (None, None),
            };
            let (model_hint, model_confidence) = match (model_text, model_weight) {
                (Some(text), weight) if weight >= 20 => (Some(text), Some(weight.min(85) as u8)),
                _ => (None, None),
            };
            candidates.push(DeviceCandidate {
                role: rule.role.clone(),
                vendor,
                model_hint,
                role_confidence: role_confidence.min(95) as u8,
                vendor_confidence,
                model_confidence,
                evidence,
                rule_ids: vec![rule.id.clone()],
            });
        }
        candidates.sort_by(|a, b| {
            b.role_confidence
                .cmp(&a.role_confidence)
                .then_with(|| a.role.cmp(&b.role))
        });
        // Same role from several rules keeps the strongest (dedup).
        let mut merged: Vec<DeviceCandidate> = Vec::new();
        for candidate in candidates {
            if let Some(existing) = merged
                .iter_mut()
                .find(|existing| existing.role == candidate.role)
            {
                if candidate.role_confidence > existing.role_confidence {
                    *existing = candidate;
                }
            } else {
                merged.push(candidate);
            }
        }
        merged.sort_by(|a, b| {
            b.role_confidence
                .cmp(&a.role_confidence)
                .then_with(|| a.role.cmp(&b.role))
        });
        merged.truncate(3);
        merged
    }
}

/// Vendor token: first clean alphanumeric token of the matched text
/// (bounded). Model token: first version-like or model-number token.
fn extract_vendor_token(text: &str) -> Option<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .find(|token| {
            token.len() >= 3 && token.len() <= 32 && token.chars().any(|c| c.is_ascii_alphabetic())
        })
        .map(str::to_owned)
}

fn extract_model_token(text: &str) -> Option<String> {
    text.split_whitespace()
        .find(|token| {
            token.len() >= 3
                && token.len() <= 32
                && token.bytes().any(|b| b.is_ascii_digit())
                && token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
        .map(str::to_owned)
}

fn truncate(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

fn signal_matches(signal: &DeviceSignal, text: &str) -> bool {
    let apply = |haystack: &str, needle: &str| match signal.match_kind {
        DeviceMatchKind::Exact => haystack == needle,
        DeviceMatchKind::Prefix => haystack.starts_with(needle),
        DeviceMatchKind::Contains => haystack.contains(needle),
    };
    if signal.case_insensitive {
        apply(
            &text.to_ascii_lowercase(),
            &signal.pattern.to_ascii_lowercase(),
        )
    } else {
        apply(text, &signal.pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACK: &str = r#"{
        "schema_version": 1,
        "rules": [
            {"id": "dev-router", "role": "router",
             "signals": [
               {"kind": "service_product", "pattern": "dnsmasq", "weight": 20},
               {"kind": "http_server", "pattern": "router", "weight": 15}
             ],
             "confidence_cap": 85, "source": "seed"},
            {"id": "dev-printer", "role": "printer",
             "signals": [
               {"kind": "service_product", "pattern": "CUPS", "weight": 25, "vendor_signal": true}
             ],
             "confidence_cap": 80, "source": "seed"},
            {"id": "dev-server", "role": "server",
             "signals": [
               {"kind": "service_product", "pattern": "nginx", "weight": 12},
               {"kind": "service_product", "pattern": "OpenSSH", "weight": 12}
             ],
             "confidence_cap": 75, "source": "seed"}
        ]
    }"#;

    fn test_db() -> DeviceDb {
        DeviceDb::from_packs(vec![(
            "device.json".to_owned(),
            parse_device_pack(PACK, "t").unwrap(),
        )])
    }

    fn signals(pairs: &[(&str, &str)]) -> BTreeMap<String, Vec<String>> {
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (kind, text) in pairs {
            map.entry((*kind).to_owned())
                .or_default()
                .push((*text).to_owned());
        }
        map
    }

    #[test]
    fn correlated_signals_classify_router() {
        let db = test_db();
        let candidates = db.classify_host(&signals(&[
            ("service_product", "dnsmasq 2.80"),
            ("http_server", "Router Admin Panel"),
        ]));
        let router = candidates.iter().find(|c| c.role == "router").unwrap();
        assert!(router.role_confidence > WEAK_ROLE_CAP);
    }

    #[test]
    fn weak_single_kind_signals_stay_capped() {
        let db = test_db();
        // HTTP + DNS name alone must not imply router: only one rule kind
        // matches here (http_server), so the router stays capped.
        let candidates = db.classify_host(&signals(&[("http_server", "Router Admin")]));
        assert!(
            candidates
                .iter()
                .all(|c| c.role_confidence <= WEAK_ROLE_CAP)
        );
        // HTTP + SSH (two products, one kind family... here two kinds?
        // service_product twice = ONE kind) must not yield server.
        let candidates = db.classify_host(&signals(&[
            ("service_product", "nginx/1.24"),
            ("service_product", "OpenSSH_9.8"),
        ]));
        assert!(
            candidates
                .iter()
                .filter(|c| c.role == "server")
                .all(|c| c.role_confidence <= WEAK_ROLE_CAP)
        );
    }

    #[test]
    fn vendor_model_scored_separately() {
        let db = test_db();
        let candidates = db.classify_host(&signals(&[("service_product", "CUPS 2.4")]));
        let printer = candidates.iter().find(|c| c.role == "printer").unwrap();
        // Vendor comes from a vendor-marked signal; model stays unknown
        // without model-marked evidence.
        assert!(printer.vendor_confidence.is_some());
        assert_eq!(printer.model_hint, None);
        assert_eq!(printer.model_confidence, None);
    }

    #[test]
    fn malformed_packs_fail_safely() {
        assert!(parse_device_pack(r#"{"schema_version": 9, "rules": []}"#, "t").is_err());
        assert!(
            parse_device_pack(
                r#"{"schema_version": 1, "rules": [
                {"id": "x", "role": "router", "signals": [],
                 "confidence_cap": 80, "source": "t"}]}"#,
                "t",
            )
            .is_err()
        );
        assert!(
            parse_device_pack(
                r#"{"schema_version": 1, "rules": [
                {"id": "x", "role": "router",
                 "signals": [{"kind": "k", "pattern": "p", "weight": 99}],
                 "confidence_cap": 80, "source": "t"}]}"#,
                "t",
            )
            .is_err()
        );
        assert!(
            parse_device_pack(
                r#"{"schema_version": 1, "rules": [
                {"id": "x", "role": "router",
                 "signals": [{"kind": "k", "pattern": "p", "weight": 5}],
                 "confidence_cap": 99, "source": "t"}]}"#,
                "t",
            )
            .is_err()
        );
        assert!(parse_device_pack("{{{", "t").is_err());
    }
}

/// Per-host device report streamed as a `device_candidate` JSONL record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceHostReport {
    pub host: String,
    pub candidates: Vec<DeviceCandidate>,
    pub signal_kinds: usize,
}

/// Collect per-host signal maps from a built correlation graph plus OS
/// family hints (`host ip -> family`). Sources: service products (and
/// `ssh_product` duplicates for SSH services), open ports (`tcp/80`
/// style), certificate subjects/SAN hostnames (`cert_name`), resolving
/// hostnames (`dns_name`), and OS families (`os_family`). Pure, bounded
/// by graph size (already capped upstream).
pub fn collect_host_signals(
    graph: &crate::graph::ScanGraph,
    os_families: &std::collections::BTreeMap<String, String>,
) -> std::collections::BTreeMap<String, std::collections::BTreeMap<String, Vec<String>>> {
    use crate::graph::{EdgeRelation, EntityKind};
    use std::collections::{BTreeMap, BTreeSet};

    let mut signals: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
    let mut push = |host: &str, kind: &str, text: &str| {
        if host.is_empty() || text.trim().is_empty() || text.len() > 256 {
            return;
        }
        let entry = signals.entry(host.to_owned()).or_default();
        let texts: &mut Vec<String> = entry.entry(kind.to_owned()).or_default();
        if texts.len() < 16 && !texts.iter().any(|known| known == text) {
            texts.push(text.to_owned());
        }
    };
    // Service products + open ports per host.
    for entity in graph.entities.values() {
        match entity.kind {
            EntityKind::Service => {
                let (Some(address), product) = (
                    entity.attributes.get("address"),
                    entity.attributes.get("product_hint"),
                ) else {
                    continue;
                };
                if let Some(product) = product.filter(|p| !p.is_empty()) {
                    push(address, "service_product", product);
                    if entity
                        .attributes
                        .get("protocol")
                        .is_some_and(|protocol| protocol == "ssh")
                    {
                        push(address, "ssh_product", product);
                    }
                }
            }
            EntityKind::Port => {
                let (Some(address), Some(port), transport) = (
                    entity.attributes.get("address"),
                    entity.attributes.get("port"),
                    entity
                        .attributes
                        .get("transport")
                        .map(String::as_str)
                        .unwrap_or("tcp"),
                ) else {
                    continue;
                };
                push(address, "open_port", &format!("{transport}/{port}"));
            }
            EntityKind::Certificate => {
                // Certificate subjects/SAN-adjacent names are weak
                // device hints (naming conventions, not proof).
                if let Some(subject) = entity.attributes.get("subject") {
                    // Attribute to every host presenting this cert.
                    let mut presenters = BTreeSet::new();
                    for edge in &graph.edges {
                        if edge.relation == EdgeRelation::PresentsCertificate
                            && edge.to == entity.id
                        {
                            if let Some(port) = graph.entities.get(&edge.from) {
                                if let Some(address) = port.attributes.get("address") {
                                    presenters.insert(address.clone());
                                }
                            }
                        }
                    }
                    for host in presenters {
                        push(&host, "cert_name", subject);
                    }
                }
            }
            _ => {}
        }
    }
    // DNS names resolving to observed hosts.
    for edge in &graph.edges {
        if edge.relation != EdgeRelation::ResolvesTo {
            continue;
        }
        if let (Some(name), Some(ip)) =
            (edge.from.strip_prefix("host:"), edge.to.strip_prefix("ip:"))
        {
            push(ip, "dns_name", name);
        }
    }
    // OS families from the OS pass (weak device evidence, explicit kind).
    for (host, family) in os_families {
        push(host, "os_family", family);
    }
    signals
}
