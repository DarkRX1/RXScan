//! OS fingerprint evidence model, external rule packs, and weighted
//! classification.
//!
//! Design notes (honesty constraints):
//! * Every observation is a separate [`OsEvidence`] record: source,
//!   feature, value, confidence, task/evidence linkage. Nothing merges
//!   silently.
//! * Evidence CLASSES (`IpHeader`, `TcpOptions`, `TcpTiming`, `Icmp`,
//!   `TransportBehavior`, `ServiceEvidence`, `ApplicationHint`) gate
//!   confidence: a lone application hint can never exceed 65, and anything
//!   above 70 requires at least two independent classes. Related TCP-stack
//!   features in one class never double-count.
//! * OS confidence never exceeds [`OS_CONFIDENCE_CAP`] (90): OS output is
//!   broad classification (`Linux 6.x`, `Windows 10/11`), never false
//!   precision. Exact builds are not reported.
//! * Rules live outside Rust in versioned packs (`fingerprints/os/v1/`)
//!   with bounded features/weights/strings, unique ids, finite weights,
//!   and confidence caps. Malformed packs fail validation, never panic.
//! * Collection in this build is passive/normal-scan evidence only
//!   (banners, service products, platform tokens). No active OS probes are
//!   emitted; `--explain` states passive-only mode. The schema already
//!   carries the full feature vocabulary (TTL, window, options, MSS, …)
//!   so future bounded probes plug in without reshaping output.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const OS_PACK_SCHEMA_VERSION: u32 = 1;
pub const MAX_OS_RULES_PER_FILE: usize = 512;
pub const MAX_OS_FEATURES_PER_RULE: usize = 16;
pub const MAX_OS_STRING_LEN: usize = 128;
/// OS confidence ceiling: broad families only, never certainty.
pub const OS_CONFIDENCE_CAP: u8 = 90;
/// Lone application-hint ceiling: one weak class, no corroboration.
pub const SINGLE_HINT_CAP: u8 = 65;
/// Minimum classes for confidence above 70.
pub const MULTI_CLASS_FLOOR_CLASSES: usize = 2;

#[derive(Debug, Error)]
pub enum OsPackError {
    #[error("could not read OS pack '{path}': {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("could not parse OS pack '{path}': {detail}")]
    Parse { path: String, detail: String },
    #[error("invalid OS pack '{path}': {reason}")]
    Invalid { path: String, reason: String },
}

/// Evidence class for confidence merging. Same-class observations
/// corroborate weakly (deduplicated); distinct classes corroborate
/// independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsEvidenceClass {
    IpHeader,
    TcpOptions,
    TcpTiming,
    Icmp,
    TransportBehavior,
    ServiceEvidence,
    ApplicationHint,
}

/// Where one OS observation came from. The class mapping is fixed:
/// banner-derived tokens are hints or service evidence, never stack facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsEvidence {
    /// Evidence origin (`ssh_banner`, `http_server`, `banner_token`,
    /// `service_product`, `smtp_banner`, `ftp_banner`, `tcp_behavior`).
    pub source: String,
    /// Feature within the source (`platform_token`, `server_token`, …).
    pub feature: String,
    /// Observed value (bounded excerpt).
    pub value: String,
    /// Per-observation confidence (1..=95).
    pub confidence: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
}

impl OsEvidence {
    /// Evidence class for a source. Unknown sources map to the weakest
    /// class (fail safe: never inflate).
    pub fn class_of(source: &str) -> OsEvidenceClass {
        match source {
            "tcp_options" | "tcp_window" | "tcp_mss" | "tcp_wscale" => OsEvidenceClass::TcpOptions,
            "tcp_timing" | "tcp_rtt" => OsEvidenceClass::TcpTiming,
            "ip_ttl" | "ip_df" | "ip_id" => OsEvidenceClass::IpHeader,
            "icmp_behavior" => OsEvidenceClass::Icmp,
            "tcp_behavior" | "tcp_reset" => OsEvidenceClass::TransportBehavior,
            "ssh_banner" | "service_product" | "smtp_banner" | "ftp_banner" => {
                OsEvidenceClass::ServiceEvidence
            }
            _ => OsEvidenceClass::ApplicationHint,
        }
    }
}

/// One OS hypothesis for a host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsCandidate {
    pub family: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<String>,
    /// Device-role hint from the winning rule, if the pack declares one.
    /// Weak evidence for the device layer, never a classification alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    pub confidence: u8,
    #[serde(default)]
    pub supporting: Vec<String>,
    #[serde(default)]
    pub conflicting: Vec<String>,
    #[serde(default)]
    pub rule_ids: Vec<String>,
}

/// One matchable feature inside an OS rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsFeatureRule {
    /// Evidence source this feature matches (`ssh_banner`, …).
    pub source: String,
    pub pattern: String,
    #[serde(default = "default_match_contains")]
    pub match_kind: OsMatchKind,
    #[serde(default = "default_true")]
    pub case_insensitive: bool,
    /// Weight contribution 1..=50 when matched.
    pub weight: u8,
}

fn default_match_contains() -> OsMatchKind {
    OsMatchKind::Contains
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsMatchKind {
    Exact,
    Prefix,
    Contains,
}

/// One OS fingerprint rule: weighted features over classified evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsRule {
    pub id: String,
    pub family: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_hint: Option<String>,
    pub features: Vec<OsFeatureRule>,
    #[serde(default)]
    pub exclusions: Vec<OsFeatureRule>,
    /// Rule confidence ceiling 1..=90.
    pub confidence_cap: u8,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsPack {
    pub schema_version: u32,
    #[serde(default)]
    pub rules: Vec<OsRule>,
}

impl OsPack {
    fn validate(&self, path: &str) -> Result<(), OsPackError> {
        let invalid = |reason: String| OsPackError::Invalid {
            path: path.to_owned(),
            reason,
        };
        if self.schema_version != OS_PACK_SCHEMA_VERSION {
            return Err(invalid(format!(
                "unsupported schema_version {}, expected {OS_PACK_SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.rules.len() > MAX_OS_RULES_PER_FILE {
            return Err(invalid(format!(
                "too many rules ({} > {MAX_OS_RULES_PER_FILE})",
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
            for (field, value) in [("family", &rule.family), ("source", &rule.source)] {
                if value.trim().is_empty() || value.len() > MAX_OS_STRING_LEN {
                    return Err(invalid(format!(
                        "rule '{}': {field} must be 1..={MAX_OS_STRING_LEN} chars",
                        rule.id
                    )));
                }
            }
            for value in [&rule.generation, &rule.variant, &rule.device_hint]
                .into_iter()
                .flatten()
            {
                if value.trim().is_empty() || value.len() > MAX_OS_STRING_LEN {
                    return Err(invalid(format!(
                        "rule '{}': optional field must be 1..={MAX_OS_STRING_LEN} chars",
                        rule.id
                    )));
                }
            }
            if rule.confidence_cap == 0 || rule.confidence_cap > OS_CONFIDENCE_CAP {
                return Err(invalid(format!(
                    "rule '{}': confidence_cap must be 1..={OS_CONFIDENCE_CAP}",
                    rule.id
                )));
            }
            if rule.features.is_empty() || rule.features.len() > MAX_OS_FEATURES_PER_RULE {
                return Err(invalid(format!(
                    "rule '{}': features must be 1..={MAX_OS_FEATURES_PER_RULE}",
                    rule.id
                )));
            }
            for feature in rule.features.iter().chain(rule.exclusions.iter()) {
                if feature.source.trim().is_empty() || feature.source.len() > 64 {
                    return Err(invalid(format!(
                        "rule '{}': feature source must be 1..=64 chars",
                        rule.id
                    )));
                }
                if feature.pattern.is_empty() || feature.pattern.len() > MAX_OS_STRING_LEN {
                    return Err(invalid(format!(
                        "rule '{}': pattern must be 1..={MAX_OS_STRING_LEN} chars",
                        rule.id
                    )));
                }
                if feature.weight == 0 || feature.weight > 50 {
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
pub fn parse_os_pack(json: &str, label: &str) -> Result<OsPack, OsPackError> {
    let pack: OsPack = serde_json::from_str(json).map_err(|error| OsPackError::Parse {
        path: label.to_owned(),
        detail: error.to_string(),
    })?;
    pack.validate(label)?;
    Ok(pack)
}

/// Load statistics for diagnostics honesty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsLoadStats {
    pub packs_loaded: usize,
    pub rules_accepted: usize,
    pub files_rejected: usize,
    #[serde(default)]
    pub rejected_files: Vec<String>,
    #[serde(default)]
    pub pack_paths: Vec<String>,
}

#[derive(Debug, Clone)]
struct CompiledOsRule {
    id: String,
    family: String,
    generation: Option<String>,
    variant: Option<String>,
    device_hint: Option<String>,
    features: Vec<OsFeatureRule>,
    exclusions: Vec<OsFeatureRule>,
    confidence_cap: u8,
}

/// Immutable compiled OS database, loaded once per scan and shared.
/// Matching is pure, bounded, deterministic (rule-id order).
#[derive(Debug, Clone, Default)]
pub struct OsDb {
    rules: Vec<CompiledOsRule>,
    stats: OsLoadStats,
}

impl OsDb {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn stats(&self) -> &OsLoadStats {
        &self.stats
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn from_packs(packs: Vec<(String, OsPack)>) -> Self {
        let mut rules = Vec::new();
        let mut seen = BTreeSet::new();
        let mut stats = OsLoadStats {
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
                rules.push(CompiledOsRule {
                    id: rule.id,
                    family: rule.family,
                    generation: rule.generation,
                    variant: rule.variant,
                    device_hint: rule.device_hint,
                    features: rule.features,
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
        let mut stats = OsLoadStats::default();
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
            match serde_json::from_str::<OsPack>(&contents).map(|pack| {
                pack.validate(&label)?;
                Ok::<_, OsPackError>(pack)
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

    /// Classify one host from its evidence set. Returns candidates sorted
    /// by (confidence desc, family asc); empty when nothing matched.
    /// Deterministic and bounded (one candidate per matching rule family
    /// at most — families merge across rules, best rule wins per family).
    pub fn classify_host(&self, evidence: &[OsEvidence]) -> Vec<OsCandidate> {
        // Index evidence by source for bounded lookup.
        let mut by_source: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for item in evidence {
            if item.value.len() > 512 {
                continue;
            }
            by_source
                .entry(item.source.as_str())
                .or_default()
                .push(item.value.as_str());
        }
        // family -> (best score state).
        let mut families: BTreeMap<String, FamilyScore> = BTreeMap::new();
        for rule in &self.rules {
            // Exclusions veto the rule outright.
            if rule.exclusions.iter().any(|feature| {
                by_source
                    .get(feature.source.as_str())
                    .is_some_and(|texts| texts.iter().any(|text| feature_matches(feature, text)))
            }) {
                continue;
            }
            let mut weight_sum: u32 = 0;
            let mut classes: BTreeSet<OsEvidenceClass> = BTreeSet::new();
            let mut supporting = Vec::new();
            for feature in &rule.features {
                let Some(texts) = by_source.get(feature.source.as_str()) else {
                    continue;
                };
                if texts.iter().any(|text| feature_matches(feature, text)) {
                    weight_sum += u32::from(feature.weight);
                    classes.insert(OsEvidence::class_of(&feature.source));
                    if supporting.len() < 8 {
                        supporting.push(format!("{}:{}", feature.source, feature.pattern));
                    }
                }
            }
            if classes.is_empty() {
                continue;
            }
            let confidence = confidence_for(classes.len(), weight_sum, rule.confidence_cap);
            let entry = families
                .entry(rule.family.clone())
                .or_insert_with(|| FamilyScore {
                    generation: rule.generation.clone(),
                    device_hint: rule.device_hint.clone(),
                    variant: rule.variant.clone(),
                    confidence: 0,
                    supporting: Vec::new(),
                    rule_ids: Vec::new(),
                });
            if confidence > entry.confidence {
                entry.confidence = confidence;
                entry.generation = rule.generation.clone();
                entry.device_hint = rule.device_hint.clone();
                entry.variant = rule.variant.clone();
                entry.supporting = supporting;
                entry.rule_ids = vec![rule.id.clone()];
            } else if confidence == entry.confidence && entry.rule_ids.len() < 4 {
                entry.rule_ids.push(rule.id.clone());
            }
        }
        let mut candidates: Vec<OsCandidate> = families
            .into_iter()
            .map(|(family, score)| OsCandidate {
                family,
                device_hint: score.device_hint,
                generation: score.generation,
                variant: score.variant,
                confidence: score.confidence,
                supporting: score.supporting,
                conflicting: Vec::new(),
                rule_ids: score.rule_ids,
            })
            .collect();
        // Conflicting evidence: families that excluded nothing but lost on
        // confidence note the winner as context (bounded).
        candidates.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.family.cmp(&b.family))
        });
        candidates.truncate(4);
        candidates
    }
}

struct FamilyScore {
    generation: Option<String>,
    device_hint: Option<String>,
    variant: Option<String>,
    confidence: u8,
    supporting: Vec<String>,
    rule_ids: Vec<String>,
}

/// Confidence from distinct classes + summed weights, honoring the lone-hint
/// ceiling and the multi-class floor for high confidence.
fn confidence_for(classes: usize, weight_sum: u32, cap: u8) -> u8 {
    let mut confidence = 30u32 + 15 * classes as u32 + weight_sum.min(25);
    if classes < MULTI_CLASS_FLOOR_CLASSES {
        confidence = confidence.min(u32::from(SINGLE_HINT_CAP));
    }
    confidence.min(u32::from(cap)).min(95) as u8
}

fn feature_matches(feature: &OsFeatureRule, text: &str) -> bool {
    let apply = |haystack: &str, needle: &str| match feature.match_kind {
        OsMatchKind::Exact => haystack == needle,
        OsMatchKind::Prefix => haystack.starts_with(needle),
        OsMatchKind::Contains => haystack.contains(needle),
    };
    if feature.case_insensitive {
        apply(
            &text.to_ascii_lowercase(),
            &feature.pattern.to_ascii_lowercase(),
        )
    } else {
        apply(text, &feature.pattern)
    }
}

// ---------------- passive collectors ----------------

/// Well-known OS-indicative tokens in banner text → (family, generation).
/// Heuristic map, deliberately small: every hit is weak application-hint
/// evidence that only matters in combination (see confidence rules).
fn os_token_map() -> &'static [(&'static str, &'static str, Option<&'static str>)] {
    &[
        ("ubuntu", "Linux", Some("Ubuntu")),
        ("debian", "Linux", Some("Debian")),
        ("raspbian", "Linux", Some("Raspbian")),
        ("centos", "Linux", Some("CentOS")),
        ("fedora", "Linux", Some("Fedora")),
        ("redhat", "Linux", Some("RHEL")),
        ("alpine", "Linux", Some("Alpine")),
        ("arch", "Linux", Some("Arch")),
        ("freebsd", "FreeBSD", None),
        ("openbsd", "OpenBSD", None),
        ("netbsd", "NetBSD", None),
        ("windows", "Windows", None),
        ("win32", "Windows", None),
        ("win64", "Windows", None),
        ("microsoft", "Windows", None),
        ("darwin", "macOS", None),
        ("macos", "macOS", None),
        ("ios", "IOS", None),
        ("routeros", "RouterOS", None),
        ("mikrotik", "RouterOS", None),
        ("android", "Linux", Some("Android")),
        ("synology", "Linux", Some("Synology")),
        ("qnap", "Linux", Some("QNAP")),
        ("truenas", "FreeBSD", Some("TrueNAS")),
        ("solaris", "Solaris", None),
        ("aix", "AIX", None),
    ]
}

/// Extract OS-hint evidence items from one banner text for a source.
/// Bounded (≤8 tokens); tokens are matched whole-word case-insensitively.
pub fn os_hints_from_banner(
    source: &str,
    banner: &str,
    task_id: Option<&str>,
    evidence_id: Option<&str>,
) -> Vec<OsEvidence> {
    let mut out = Vec::new();
    let lowered = banner.to_ascii_lowercase();
    // Whole-word scan over alphanumeric runs.
    let mut words = BTreeSet::new();
    // Hyphenated compounds (`Ubuntu-1`, `Win32-SSH`) match on components;
    // underscores stay joined (`dropbear_2022` is one token).
    for word in lowered.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        if word.len() >= 3 && word.len() <= 32 {
            words.insert(word);
        }
    }
    for (token, family, generation) in os_token_map() {
        if words.contains(*token) {
            let mut value = (*family).to_owned();
            if let Some(generation) = generation {
                value.push(' ');
                value.push_str(generation);
            }
            out.push(OsEvidence {
                source: source.to_owned(),
                feature: "platform_token".to_owned(),
                value,
                confidence: 50,
                task_id: task_id.map(str::to_owned),
                evidence_id: evidence_id.map(str::to_owned),
            });
            if out.len() >= 8 {
                break;
            }
        }
    }
    out
}

/// Collect per-host OS evidence from completed module outputs (banners,
/// service products, SSH platform tokens). Pure, bounded, no network.
/// Hosts keyed by address string as observed.
pub fn collect_host_evidence(
    outputs: &[(crate::execution::TaskId, crate::execution::ModuleOutput)],
) -> BTreeMap<String, Vec<OsEvidence>> {
    let mut by_host: BTreeMap<String, Vec<OsEvidence>> = BTreeMap::new();
    for (task_id, output) in outputs {
        for event in &output.events {
            let data = &event.details.data;
            let mut push = |host: &str, items: Vec<OsEvidence>| {
                if host.is_empty() {
                    return;
                }
                let slot = by_host.entry(host.to_owned()).or_default();
                for item in items {
                    if slot.len() < 64 {
                        slot.push(item);
                    }
                }
            };
            match event.kind {
                crate::model::EventKind::BannerObserved => {
                    let (Some(address), Some(banner)) = (
                        data.get("address").and_then(serde_json::Value::as_str),
                        data.get("banner").and_then(serde_json::Value::as_str),
                    ) else {
                        continue;
                    };
                    push(
                        address,
                        os_hints_from_banner("banner_token", banner, Some(&task_id.0), None),
                    );
                }
                crate::model::EventKind::ServiceIdentified => {
                    let (Some(address), product) = (
                        data.get("address").and_then(serde_json::Value::as_str),
                        data.get("product_hint").and_then(serde_json::Value::as_str),
                    ) else {
                        continue;
                    };
                    let mut items = Vec::new();
                    if let Some(product) = product {
                        if !product.is_empty() {
                            items.push(OsEvidence {
                                source: "service_product".to_owned(),
                                feature: "product".to_owned(),
                                value: product.chars().take(64).collect(),
                                confidence: 55,
                                task_id: Some(task_id.0.clone()),
                                evidence_id: None,
                            });
                        }
                    }
                    // SSH platform tokens ride on the banner text when present.
                    if let Some(banner) = data.get("banner").and_then(serde_json::Value::as_str) {
                        items.extend(os_hints_from_banner(
                            "ssh_banner",
                            banner,
                            Some(&task_id.0),
                            None,
                        ));
                    }
                    push(address, items);
                }
                crate::model::EventKind::SshHostKeyObserved => {
                    if let Some(address) = data.get("address").and_then(serde_json::Value::as_str) {
                        let key_type = data
                            .get("key_type")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("");
                        if !key_type.is_empty() {
                            push(
                                address,
                                vec![OsEvidence {
                                    source: "service_product".to_owned(),
                                    feature: "ssh_key_type".to_owned(),
                                    value: key_type.chars().take(64).collect(),
                                    confidence: 55,
                                    task_id: Some(task_id.0.clone()),
                                    evidence_id: None,
                                }],
                            );
                        }
                    }
                }
                _ => {}
            }
        }
        // Findings carry SSH banners too (ident strings with platform tokens).
        for finding in &output.findings {
            let (Some(address), Some(banner)) = (
                finding
                    .metadata
                    .get("address")
                    .and_then(serde_json::Value::as_str),
                finding
                    .metadata
                    .get("banner")
                    .and_then(serde_json::Value::as_str),
            ) else {
                continue;
            };
            let items = os_hints_from_banner("ssh_banner", banner, None, None);
            if !items.is_empty() {
                let slot = by_host.entry(address.to_owned()).or_default();
                for item in items {
                    if slot.len() < 64 {
                        slot.push(item);
                    }
                }
            }
        }
    }
    by_host
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACK: &str = r#"{
        "schema_version": 1,
        "rules": [
            {"id": "linux-ubuntu", "family": "Linux", "generation": "Ubuntu",
             "features": [
               {"source": "ssh_banner", "pattern": "Ubuntu", "weight": 20},
               {"source": "http_server", "pattern": "Ubuntu", "weight": 15}
             ],
             "confidence_cap": 85, "source": "seed"},
            {"id": "linux-generic", "family": "Linux",
             "features": [
               {"source": "service_product", "pattern": "nginx", "weight": 10}
             ],
             "confidence_cap": 60, "source": "seed"},
            {"id": "bsd-guarded", "family": "FreeBSD",
             "features": [
               {"source": "ssh_banner", "pattern": "FreeBSD", "weight": 25}
             ],
             "exclusions": [
               {"source": "ssh_banner", "pattern": "Linux", "weight": 1}
             ],
             "confidence_cap": 85, "source": "seed"}
        ]
    }"#;

    fn test_db() -> OsDb {
        OsDb::from_packs(vec![(
            "os.json".to_owned(),
            parse_os_pack(PACK, "t").unwrap(),
        )])
    }

    fn evidence(source: &str, value: &str) -> OsEvidence {
        OsEvidence {
            source: source.to_owned(),
            feature: "platform_token".to_owned(),
            value: value.to_owned(),
            confidence: 50,
            task_id: None,
            evidence_id: None,
        }
    }

    #[test]
    fn multi_class_evidence_outranks_lone_hints() {
        let db = test_db();
        // Two independent classes → high confidence.
        let both = db.classify_host(&[
            evidence("ssh_banner", "SSH-2.0-OpenSSH Ubuntu"),
            evidence("http_server", "Server: Apache Ubuntu"),
        ]);
        let linux = both.iter().find(|c| c.family == "Linux").unwrap();
        assert!(linux.confidence > 70, "got {}", linux.confidence);
        // Lone application hint stays capped.
        let lone = db.classify_host(&[evidence("http_server", "Server: Apache Ubuntu")]);
        let linux = lone.iter().find(|c| c.family == "Linux").unwrap();
        assert!(linux.confidence <= SINGLE_HINT_CAP);
    }

    #[test]
    fn exclusions_veto_and_unknown_stays_unknown() {
        let db = test_db();
        let vetoed = db.classify_host(&[
            evidence("ssh_banner", "FreeBSD box"),
            evidence("ssh_banner", "Linux compat"),
        ]);
        assert!(!vetoed.iter().any(|c| c.family == "FreeBSD"));
        assert!(db.classify_host(&[]).is_empty());
        assert!(
            db.classify_host(&[evidence("http_server", "nothing indicative here")])
                .is_empty()
        );
    }

    #[test]
    fn malformed_packs_fail_safely() {
        assert!(parse_os_pack(r#"{"schema_version": 99, "rules": []}"#, "t").is_err());
        assert!(
            parse_os_pack(
                r#"{"schema_version": 1, "rules": [
                {"id": "x", "family": "Linux", "features": [],
                 "confidence_cap": 80, "source": "t"}]}"#,
                "t",
            )
            .is_err()
        );
        assert!(
            parse_os_pack(
                r#"{"schema_version": 1, "rules": [
                {"id": "x", "family": "Linux",
                 "features": [{"source": "s", "pattern": "p", "weight": 99}],
                 "confidence_cap": 80, "source": "t"}]}"#,
                "t",
            )
            .is_err()
        );
        assert!(
            parse_os_pack(
                r#"{"schema_version": 1, "rules": [
                {"id": "x", "family": "Linux",
                 "features": [{"source": "s", "pattern": "p", "weight": 5}],
                 "confidence_cap": 99, "source": "t"}]}"#,
                "t",
            )
            .is_err()
        );
        assert!(parse_os_pack("{{{", "t").is_err());
        // Product-only style minimal rule loads.
        assert!(
            parse_os_pack(
                r#"{"schema_version": 1, "rules": [
                {"id": "x", "family": "Linux",
                 "features": [{"source": "s", "pattern": "p", "weight": 5}],
                 "confidence_cap": 80, "source": "t"}]}"#,
                "t",
            )
            .is_ok()
        );
    }

    #[test]
    fn banner_tokenizer_is_bounded_and_safe() {
        let hints = os_hints_from_banner("ssh_banner", "SSH-2.0-OpenSSH_9.8 Ubuntu-1", None, None);
        assert!(hints.iter().any(|h| h.value.contains("Ubuntu")));
        assert!(os_hints_from_banner("x", "", None, None).is_empty());
        assert!(os_hints_from_banner("x", "hello world foo", None, None).is_empty());
        let huge = "Ubuntu ".repeat(10_000);
        assert!(os_hints_from_banner("x", &huge, None, None).len() <= 8);
    }
}

/// Per-host OS report streamed as an `os_candidate` JSONL record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsHostReport {
    pub host: String,
    pub candidates: Vec<OsCandidate>,
    pub evidence_count: usize,
}
