//! Offline vulnerability correlation: normalized software identity →
//! advisory candidates. Passive and offline by construction.
//!
//! What this module is: a provider abstraction, a safe version-range
//! engine, deterministic candidate scoring, and provenance-preserving
//! records. Lookup runs post-scan over collected identities; the scan hot
//! path never touches the network and scan execution never waits on feeds.
//!
//! What it is not: exploitation, proof-of-exposure probing, brute force,
//! or a vulnerability verdict. Output says *potential match* with the
//! evidence that produced it. `host is vulnerable` is never stated.
//!
//! Confidence discipline: candidate confidence cannot exceed the
//! underlying identity confidence without justification; product-only
//! matches stay low; ambiguous versions yield `indeterminate`, never a
//! silent match or a silent miss.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const VULN_DATASET_SCHEMA_VERSION: u32 = 1;
pub const MAX_ADVISORIES_PER_FILE: usize = 4096;
pub const MAX_RANGES_PER_ADVISORY: usize = 16;
pub const MAX_VERSION_LEN: usize = 64;

#[derive(Debug, Error)]
pub enum VulnError {
    #[error("could not read vulnerability dataset '{path}': {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("could not parse vulnerability dataset '{path}': {detail}")]
    Parse { path: String, detail: String },
    #[error("invalid vulnerability dataset '{path}': {reason}")]
    Invalid { path: String, reason: String },
}

/// Normalized software identity: the single input shape every provider
/// consumes. Built from service observations and web technologies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftwareIdentity {
    pub vendor: Option<String>,
    pub product: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpe: Option<String>,
    /// Product-identification confidence (0..=95).
    pub product_confidence: u8,
    /// Version confidence where known (0 when unknown).
    pub version_confidence: u8,
    #[serde(default)]
    pub evidence: Vec<String>,
}

/// One parsed version segment: numeric compares numerically, text
/// lexically; mixed kinds are incomparable (see [`compare_versions`]).
#[derive(Debug, Clone, PartialEq, Eq)]
enum VersionPart {
    Numeric(u64),
    Text(String),
}

/// Normalized version: at most 12 segments, each bounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    parts: Vec<VersionPart>,
}

impl Version {
    /// Parse a version string. Returns `None` for empty, overlong,
    /// non-ASCII, or charset-violating input (never a guess).
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty() || raw.len() > MAX_VERSION_LEN || !raw.is_ascii() {
            return None;
        }
        let mut parts = Vec::new();
        for chunk in raw.split(['.', '-', '_', '+', '~', ':']) {
            if chunk.is_empty() {
                continue;
            }
            if chunk.len() > 16
                || !chunk
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'~')
            {
                return None;
            }
            if chunk.bytes().all(|b| b.is_ascii_digit()) {
                parts.push(VersionPart::Numeric(
                    chunk.parse::<u64>().ok().filter(|_| chunk.len() <= 18)?,
                ));
            } else {
                parts.push(VersionPart::Text(chunk.to_ascii_lowercase()));
            }
            if parts.len() > 12 {
                return None;
            }
        }
        if parts.is_empty() {
            return None;
        }
        Some(Self { parts })
    }
}

/// Compare two versions. Returns `None` (indeterminate) whenever the
/// comparison cannot be made confidently: differing alphanumeric suffix
/// kinds, or any unparseable side. Callers must treat `None` as
/// indeterminate, never as equal or unequal.
pub fn compare_versions(left: &Version, right: &Version) -> Option<Ordering> {
    let width = left.parts.len().max(right.parts.len());
    for index in 0..width {
        let l = left.parts.get(index);
        let r = right.parts.get(index);
        match (l, r) {
            (None, None) => return Some(Ordering::Equal),
            (None, Some(VersionPart::Numeric(0))) | (Some(VersionPart::Numeric(0)), None) => {
                continue;
            }
            (None, Some(_)) | (Some(_), None) => {
                // One side has more segments. A trailing all-zero numeric
                // tail is equality (`1.24` == `1.24.0`); anything else
                // (notably text suffixes like `rc1`, `p1`) is indeterminate
                // rather than guessed ordering.
                let (extra, _) = if l.is_none() {
                    (&right.parts[index..], true)
                } else {
                    (&left.parts[index..], false)
                };
                if extra
                    .iter()
                    .all(|part| matches!(part, VersionPart::Numeric(0)))
                {
                    continue;
                }
                return None;
            }
            (Some(VersionPart::Numeric(a)), Some(VersionPart::Numeric(b))) => match a.cmp(b) {
                Ordering::Equal => continue,
                ordering => return Some(ordering),
            },
            (Some(VersionPart::Text(a)), Some(VersionPart::Text(b))) => match a.cmp(b) {
                Ordering::Equal => continue,
                ordering => return Some(ordering),
            },
            // Numeric vs text at the same position: different versioning
            // schemes colliding (e.g. `1.0` vs `1.0a` families) — refuse.
            _ => return None,
        }
    }
    Some(Ordering::Equal)
}

/// One version constraint inside an advisory's affected range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum VersionReq {
    Exact {
        version: String,
    },
    LessThan {
        version: String,
    },
    LessThanOrEqual {
        version: String,
    },
    GreaterThan {
        version: String,
    },
    GreaterThanOrEqual {
        version: String,
    },
    Range {
        low: String,
        low_inclusive: bool,
        high: String,
        high_inclusive: bool,
    },
}

impl VersionReq {
    fn validate(&self, advisory: &str) -> Result<(), String> {
        let versions: Vec<&String> = match self {
            Self::Exact { version }
            | Self::LessThan { version }
            | Self::LessThanOrEqual { version }
            | Self::GreaterThan { version }
            | Self::GreaterThanOrEqual { version } => vec![version],
            Self::Range { low, high, .. } => vec![low, high],
        };
        for version in versions {
            if version.is_empty() || version.len() > MAX_VERSION_LEN {
                return Err(format!("advisory '{advisory}': version bound out of range"));
            }
            if Version::parse(version).is_none() {
                return Err(format!(
                    "advisory '{advisory}': unparseable version bound '{version}'"
                ));
            }
        }
        if let Self::Range {
            low,
            low_inclusive: _,
            high,
            high_inclusive: _,
        } = self
        {
            let (Some(low_v), Some(high_v)) = (Version::parse(low), Version::parse(high)) else {
                return Err(format!("advisory '{advisory}': bad range bounds"));
            };
            if compare_versions(&low_v, &high_v) == Some(Ordering::Greater) {
                return Err(format!("advisory '{advisory}': empty range {low}..{high}"));
            }
        }
        Ok(())
    }

    /// Evaluate one constraint: `None` = indeterminate.
    fn evaluate(&self, version: &Version) -> Option<bool> {
        let check = |bound: &str| Version::parse(bound).and_then(|b| compare_versions(version, &b));
        match self {
            Self::Exact { version } => check(version).map(|order| order == Ordering::Equal),
            Self::LessThan { version } => check(version).map(|order| order == Ordering::Less),
            Self::LessThanOrEqual { version } => {
                check(version).map(|order| order != Ordering::Greater)
            }
            Self::GreaterThan { version } => check(version).map(|order| order == Ordering::Greater),
            Self::GreaterThanOrEqual { version } => {
                check(version).map(|order| order != Ordering::Less)
            }
            Self::Range {
                low,
                low_inclusive,
                high,
                high_inclusive,
            } => {
                let low_ok = check(low).map(|order| {
                    order == Ordering::Greater || (*low_inclusive && order == Ordering::Equal)
                });
                let high_ok = check(high).map(|order| {
                    order == Ordering::Less || (*high_inclusive && order == Ordering::Equal)
                });
                match (low_ok, high_ok) {
                    (Some(true), Some(true)) => Some(true),
                    (Some(false), _) | (_, Some(false)) => Some(false),
                    _ => None,
                }
            }
        }
    }
}

/// One advisory entry in a local dataset.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Advisory {
    pub id: String,
    pub vendor: Option<String>,
    pub product: String,
    #[serde(default)]
    pub affected: Vec<VersionReq>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
    #[serde(default)]
    pub summary: String,
}

impl Advisory {
    fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() || self.id.len() > 64 {
            return Err("advisory id must be 1..=64 chars".to_owned());
        }
        if self.product.trim().is_empty() || self.product.len() > 64 {
            return Err(format!("advisory '{}': product out of range", self.id));
        }
        if let Some(vendor) = &self.vendor {
            if vendor.trim().is_empty() || vendor.len() > 64 {
                return Err(format!("advisory '{}': vendor out of range", self.id));
            }
        }
        if self.affected.len() > MAX_RANGES_PER_ADVISORY {
            return Err(format!("advisory '{}': too many ranges", self.id));
        }
        for req in &self.affected {
            req.validate(&self.id)?;
        }
        if let Some(score) = self.score {
            if !(0.0..=10.0).contains(&score) {
                return Err(format!("advisory '{}': score out of range", self.id));
            }
        }
        Ok(())
    }
}

/// Local vulnerability dataset file format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnDataset {
    pub schema_version: u32,
    pub provider: String,
    #[serde(default)]
    pub dataset_version: String,
    #[serde(default)]
    pub advisories: Vec<Advisory>,
}

/// Match outcome for one advisory against one identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchOutcome {
    Matched,
    NotMatched,
    Indeterminate,
}

/// How a candidate matched: exact version evidence, family heuristic,
/// product-only (no usable version), or indeterminate inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchType {
    ExactVersion,
    VersionFamily,
    ProductOnly,
    Indeterminate,
}

/// One vulnerability candidate: potential match with provenance, never a
/// verdict. Severity labels pass through the provider's wording prefixed
/// by provider (no invented ratings).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VulnerabilityCandidate {
    pub advisory_id: String,
    pub provider: String,
    pub product: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_version: Option<String>,
    pub match_type: MatchType,
    pub outcome: MatchOutcome,
    pub confidence: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
    #[serde(default)]
    pub evidence: Vec<String>,
}

/// Provider metadata for provenance records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub name: String,
    pub dataset_version: String,
    pub advisory_count: usize,
}

/// Vulnerability data source abstraction. Implementations are offline
/// datasets (local NVD-derived JSON, OSV-shaped feeds, vendor feeds, or
/// operator-supplied files). Fetching/updating datasets is out of band;
/// the scan hot path never calls a provider.
pub trait VulnerabilityProvider: Send + Sync {
    fn info(&self) -> ProviderInfo;
    fn query(&self, identity: &SoftwareIdentity) -> Vec<VulnerabilityCandidate>;
}

/// Local JSON-file dataset provider.
#[derive(Debug, Clone)]
pub struct LocalVulnDb {
    provider: String,
    dataset_version: String,
    advisories: Vec<Advisory>,
    /// product (lowercased) → advisory indexes. Bounded per-product lists
    /// keep pathological products from exploding query cost.
    by_product: BTreeMap<String, Vec<usize>>,
}

impl LocalVulnDb {
    pub fn from_dataset(dataset: VulnDataset) -> Result<Self, VulnError> {
        if dataset.schema_version != VULN_DATASET_SCHEMA_VERSION {
            return Err(VulnError::Invalid {
                path: "(memory)".to_owned(),
                reason: format!(
                    "unsupported schema_version {}, expected {VULN_DATASET_SCHEMA_VERSION}",
                    dataset.schema_version
                ),
            });
        }
        if dataset.provider.trim().is_empty() || dataset.provider.len() > 64 {
            return Err(VulnError::Invalid {
                path: "(memory)".to_owned(),
                reason: "provider must be 1..=64 chars".to_owned(),
            });
        }
        if dataset.advisories.len() > MAX_ADVISORIES_PER_FILE {
            return Err(VulnError::Invalid {
                path: "(memory)".to_owned(),
                reason: "too many advisories".to_owned(),
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        for advisory in &dataset.advisories {
            if !seen.insert(advisory.id.clone()) {
                return Err(VulnError::Invalid {
                    path: "(memory)".to_owned(),
                    reason: format!("duplicate advisory id '{}'", advisory.id),
                });
            }
            advisory.validate().map_err(|reason| VulnError::Invalid {
                path: "(memory)".to_owned(),
                reason,
            })?;
        }
        let mut by_product: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, advisory) in dataset.advisories.iter().enumerate() {
            by_product
                .entry(advisory.product.to_ascii_lowercase())
                .or_default()
                .push(index);
        }
        Ok(Self {
            provider: dataset.provider,
            dataset_version: dataset.dataset_version,
            advisories: dataset.advisories,
            by_product,
        })
    }

    pub fn load_file(path: &Path) -> Result<Self, VulnError> {
        let text = std::fs::read_to_string(path).map_err(|source| VulnError::Read {
            path: path.display().to_string(),
            source,
        })?;
        if text.len() > 16 * 1024 * 1024 {
            return Err(VulnError::Invalid {
                path: path.display().to_string(),
                reason: "dataset file exceeds 16 MiB".to_owned(),
            });
        }
        let dataset: VulnDataset =
            serde_json::from_str(&text).map_err(|error| VulnError::Parse {
                path: path.display().to_string(),
                detail: error.to_string(),
            })?;
        Self::from_dataset(dataset).map_err(|error| match error {
            VulnError::Invalid { reason, .. } => VulnError::Invalid {
                path: path.display().to_string(),
                reason,
            },
            other => other,
        })
    }

    fn match_advisory(
        &self,
        advisory: &Advisory,
        identity: &SoftwareIdentity,
    ) -> Option<VulnerabilityCandidate> {
        // Product gate (normalized, case-insensitive). No product match →
        // no candidate at all (never correlate from thin air).
        if !advisory.product.eq_ignore_ascii_case(&identity.product) {
            return None;
        }
        // Vendor gate: when BOTH sides name a vendor and they differ, this
        // advisory is for somebody else's product. Unknown either side →
        // proceed with capped confidence (ambiguity, not exclusion).
        let vendor_agrees = match (&advisory.vendor, &identity.vendor) {
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
            _ => false,
        };
        let vendor_known_both = advisory.vendor.is_some() && identity.vendor.is_some();
        if vendor_known_both && !vendor_agrees {
            return None;
        }
        let evidence = vec![
            format!("product match: {}", identity.product),
            format!(
                "vendor: {}",
                if vendor_agrees {
                    "agreed"
                } else {
                    "single-sided (capped)"
                }
            ),
        ];
        // Version evaluation over the advisory's affected ranges (AND).
        let Some(version_text) = identity.version.as_deref().filter(|v| !v.trim().is_empty())
        else {
            // Product match, unknown version: low-confidence candidate.
            let confidence = identity.product_confidence.min(45);
            return Some(VulnerabilityCandidate {
                advisory_id: advisory.id.clone(),
                provider: self.provider.clone(),
                product: identity.product.clone(),
                matched_version: None,
                match_type: MatchType::ProductOnly,
                outcome: MatchOutcome::Matched,
                confidence,
                severity_label: advisory.severity_label.clone(),
                score: advisory.score,
                evidence,
            });
        };
        let Some(version) = Version::parse(version_text) else {
            return Some(VulnerabilityCandidate {
                advisory_id: advisory.id.clone(),
                provider: self.provider.clone(),
                product: identity.product.clone(),
                matched_version: Some(version_text.to_owned()),
                match_type: MatchType::Indeterminate,
                outcome: MatchOutcome::Indeterminate,
                confidence: identity.product_confidence.min(40),
                severity_label: advisory.severity_label.clone(),
                score: advisory.score,
                evidence: vec!["version unparseable: indeterminate".to_owned()],
            });
        };
        if advisory.affected.is_empty() {
            // Advisory names no range: product-level relevance only.
            let confidence = identity.product_confidence.min(45);
            return Some(VulnerabilityCandidate {
                advisory_id: advisory.id.clone(),
                provider: self.provider.clone(),
                product: identity.product.clone(),
                matched_version: Some(version_text.to_owned()),
                match_type: MatchType::ProductOnly,
                outcome: MatchOutcome::Matched,
                confidence,
                severity_label: advisory.severity_label.clone(),
                score: advisory.score,
                evidence,
            });
        }
        let mut saw_indeterminate = false;
        for req in &advisory.affected {
            match req.evaluate(&version) {
                Some(true) => {}
                Some(false) => {
                    return Some(VulnerabilityCandidate {
                        advisory_id: advisory.id.clone(),
                        provider: self.provider.clone(),
                        product: identity.product.clone(),
                        matched_version: Some(version_text.to_owned()),
                        match_type: MatchType::ExactVersion,
                        outcome: MatchOutcome::NotMatched,
                        confidence: identity.product_confidence.min(60),
                        severity_label: advisory.severity_label.clone(),
                        score: advisory.score,
                        evidence: vec!["version outside affected range".to_owned()],
                    });
                }
                None => saw_indeterminate = true,
            }
        }
        if saw_indeterminate {
            return Some(VulnerabilityCandidate {
                advisory_id: advisory.id.clone(),
                provider: self.provider.clone(),
                product: identity.product.clone(),
                matched_version: Some(version_text.to_owned()),
                match_type: MatchType::Indeterminate,
                outcome: MatchOutcome::Indeterminate,
                confidence: identity.product_confidence.min(40),
                severity_label: advisory.severity_label.clone(),
                score: advisory.score,
                evidence: vec!["range comparison indeterminate".to_owned()],
            });
        }
        // All constraints matched on an exact observed version.
        let mut confidence = identity
            .product_confidence
            .min(identity.version_confidence.max(50))
            .min(90);
        if !vendor_agrees {
            confidence = confidence.min(70);
        }
        Some(VulnerabilityCandidate {
            advisory_id: advisory.id.clone(),
            provider: self.provider.clone(),
            product: identity.product.clone(),
            matched_version: Some(version_text.to_owned()),
            match_type: MatchType::ExactVersion,
            outcome: MatchOutcome::Matched,
            confidence,
            severity_label: advisory.severity_label.clone(),
            score: advisory.score,
            evidence,
        })
    }
}

impl VulnerabilityProvider for LocalVulnDb {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            name: self.provider.clone(),
            dataset_version: self.dataset_version.clone(),
            advisory_count: self.advisories.len(),
        }
    }

    fn query(&self, identity: &SoftwareIdentity) -> Vec<VulnerabilityCandidate> {
        if identity.product.trim().is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        if let Some(indexes) = self.by_product.get(&identity.product.to_ascii_lowercase()) {
            for index in indexes.iter().take(64) {
                if let Some(advisory) = self.advisories.get(*index) {
                    // All three outcomes are returned: callers distinguish
                    // checked-unaffected (`NotMatched`) from inapplicable
                    // (absent) and ambiguous (`Indeterminate`). Bounded.
                    if let Some(candidate) = self.match_advisory(advisory, identity) {
                        out.push(candidate);
                        if out.len() >= 16 {
                            break;
                        }
                    }
                }
            }
        }
        out.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.advisory_id.cmp(&b.advisory_id))
        });
        out
    }
}

/// observed. Streamed as `software_identity`; persisted per scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SoftwareInventoryEntry {
    #[serde(flatten)]
    pub identity: SoftwareIdentity,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub endpoints: Vec<String>,
}

/// location it matched. Streamed as `vulnerability_candidate`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VulnMatchRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub identity: SoftwareIdentity,
    pub candidate: VulnerabilityCandidate,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dataset(advisories: Vec<Advisory>) -> LocalVulnDb {
        LocalVulnDb::from_dataset(VulnDataset {
            schema_version: VULN_DATASET_SCHEMA_VERSION,
            provider: "test-provider".to_owned(),
            dataset_version: "2026-10-03".to_owned(),
            advisories,
        })
        .unwrap()
    }

    fn advisory(id: &str, product: &str, affected: Vec<VersionReq>) -> Advisory {
        Advisory {
            id: id.to_owned(),
            vendor: Some("f5".to_owned()),
            product: product.to_owned(),
            affected,
            severity_label: Some("provider:high".to_owned()),
            score: Some(7.5),
            summary: String::new(),
        }
    }

    fn identity(product: &str, version: Option<&str>) -> SoftwareIdentity {
        SoftwareIdentity {
            vendor: Some("f5".to_owned()),
            product: product.to_owned(),
            version: version.map(str::to_owned),
            version_family: None,
            cpe: None,
            product_confidence: 90,
            version_confidence: version.map_or(0, |_| 80),
            evidence: Vec::new(),
        }
    }

    #[test]
    fn exact_and_range_boundaries() {
        let db = dataset(vec![advisory(
            "RXSCAN-TEST-1",
            "nginx",
            vec![VersionReq::Range {
                low: "1.20.0".to_owned(),
                low_inclusive: true,
                high: "1.24.0".to_owned(),
                high_inclusive: false,
            }],
        )]);
        // Inside (low inclusive).
        let hits = db.query(&identity("nginx", Some("1.20.0")));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].outcome, MatchOutcome::Matched);
        assert_eq!(hits[0].match_type, MatchType::ExactVersion);
        // Upper bound exclusive.
        let hits = db.query(&identity("nginx", Some("1.24.0")));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].outcome, MatchOutcome::NotMatched);
        // Clearly above.
        let hits = db.query(&identity("nginx", Some("1.26.0")));
        assert_eq!(hits[0].outcome, MatchOutcome::NotMatched);
        // Clearly below.
        let hits = db.query(&identity("nginx", Some("1.18.0")));
        assert_eq!(hits[0].outcome, MatchOutcome::NotMatched);
    }

    #[test]
    fn unknown_version_stays_low_and_indeterminate_cases() {
        let db = dataset(vec![advisory(
            "RXSCAN-TEST-1",
            "nginx",
            vec![VersionReq::LessThan {
                version: "1.24.0".to_owned(),
            }],
        )]);
        // Unknown version: product-only, low confidence.
        let hits = db.query(&identity("nginx", None));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].match_type, MatchType::ProductOnly);
        assert!(hits[0].confidence <= 45);
        // Unparseable version: indeterminate, never matched.
        let hits = db.query(&identity("nginx", Some("not-a-version!!")));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].outcome, MatchOutcome::Indeterminate);
        // Suffix families that cannot compare: indeterminate.
        let hits = db.query(&identity("nginx", Some("1.24.0P1")));
        assert_eq!(hits[0].outcome, MatchOutcome::Indeterminate);
    }

    #[test]
    fn vendor_product_and_cpe_ambiguity() {
        let db = dataset(vec![Advisory {
            vendor: Some("other-vendor".to_owned()),
            ..advisory("RXSCAN-TEST-1", "nginx", vec![])
        }]);
        // Both sides name different vendors: excluded.
        assert!(db.query(&identity("nginx", Some("1.24.0"))).is_empty());
        // Single-sided vendor: proceeds, capped.
        let db = dataset(vec![Advisory {
            vendor: None,
            ..advisory("RXSCAN-TEST-2", "nginx", vec![])
        }]);
        let hits = db.query(&identity("nginx", Some("1.24.0")));
        assert_eq!(hits.len(), 1);
        assert!(hits[0].confidence <= 70);
        // Wrong product: silence.
        assert!(db.query(&identity("apache", Some("1.24.0"))).is_empty());
        assert!(db.query(&identity("", Some("1.24.0"))).is_empty());
    }

    #[test]
    fn conflicting_entries_and_provider_unavailable() {
        let db = dataset(vec![
            advisory(
                "RXSCAN-TEST-A",
                "nginx",
                vec![VersionReq::LessThan {
                    version: "1.24.0".to_owned(),
                }],
            ),
            advisory(
                "RXSCAN-TEST-B",
                "nginx",
                vec![VersionReq::GreaterThanOrEqual {
                    version: "1.24.0".to_owned(),
                }],
            ),
        ]);
        // 1.24.0 matches exactly one of the two conflicting entries.
        let hits = db.query(&identity("nginx", Some("1.24.0")));
        let matched: Vec<_> = hits
            .iter()
            .filter(|c| c.outcome == MatchOutcome::Matched)
            .collect();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].advisory_id, "RXSCAN-TEST-B");
        // Empty dataset: no candidates, no panic.
        let empty = dataset(vec![]);
        assert!(empty.query(&identity("nginx", Some("1.0"))).is_empty());
        assert_eq!(empty.info().advisory_count, 0);
    }

    #[test]
    fn malformed_inputs_never_panic() {
        assert!(Version::parse("").is_none());
        assert!(Version::parse(&"9".repeat(200)).is_none());
        assert!(Version::parse("1.2é").is_none());
        assert!(Version::parse("1..2").is_some());
        // Dataset validation rejects bad ranges, dupes, bad scores.
        assert!(
            LocalVulnDb::from_dataset(VulnDataset {
                schema_version: 99,
                provider: "x".to_owned(),
                dataset_version: String::new(),
                advisories: vec![],
            })
            .is_err()
        );
        assert!(
            LocalVulnDb::from_dataset(VulnDataset {
                schema_version: VULN_DATASET_SCHEMA_VERSION,
                provider: "x".to_owned(),
                dataset_version: String::new(),
                advisories: vec![
                    advisory("DUP", "nginx", vec![]),
                    advisory("DUP", "nginx", vec![]),
                ],
            })
            .is_err()
        );
        assert!(
            LocalVulnDb::from_dataset(VulnDataset {
                schema_version: VULN_DATASET_SCHEMA_VERSION,
                provider: "x".to_owned(),
                dataset_version: String::new(),
                advisories: vec![Advisory {
                    score: Some(99.0),
                    ..advisory("S", "nginx", vec![])
                }],
            })
            .is_err()
        );
        // Stale/empty dataset metadata is preserved verbatim.
        let db = dataset(vec![]);
        assert_eq!(db.info().name, "test-provider");
    }

    #[test]
    fn version_compare_semantics() {
        let v = |s: &str| Version::parse(s).unwrap();
        assert_eq!(
            compare_versions(&v("1.24.0"), &v("1.24.0")),
            Some(Ordering::Equal)
        );
        assert_eq!(
            compare_versions(&v("1.24"), &v("1.24.0")),
            Some(Ordering::Equal)
        );
        assert_eq!(
            compare_versions(&v("1.23.9"), &v("1.24.0")),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare_versions(&v("8.0.36"), &v("8.0.4")),
            Some(Ordering::Greater)
        );
        // Suffix families refuse comparison.
        assert_eq!(compare_versions(&v("1.20.0"), &v("1.20.0P1")), None);
        assert_eq!(compare_versions(&v("9.7p1"), &v("9.7")), None);
    }
}
