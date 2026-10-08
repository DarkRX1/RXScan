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

/// Address family an observation was made on. IPv4 TTL and IPv6 Hop
/// Limit share no semantics; the family travels with the value so IPv6
/// evidence can never fall through IPv4 interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsAddressFamily {
    V4,
    V6,
}

/// Where one OS observation came from. Network-stack provenance
/// (`ActiveTcp`, `ActiveIcmp`, `ExistingTcpScan`) is never collapsed with
/// application-context provenance (`ServiceEvidence`, `Ssh`, `Http`, `Tls`):
/// a banner associated with an OS only corroborates, it never establishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsProvenance {
    ActiveTcp,
    ActiveIcmp,
    ActiveIp,
    ExistingTcpScan,
    ServiceEvidence,
    Ssh,
    Http,
    Tls,
    Fixture,
    Imported,
}

impl OsProvenance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ActiveTcp => "active TCP observation",
            Self::ActiveIcmp => "active ICMP observation",
            Self::ActiveIp => "active IP observation",
            Self::ExistingTcpScan => "existing TCP scan",
            Self::ServiceEvidence => "service fingerprint",
            Self::Ssh => "SSH observation",
            Self::Http => "HTTP observation",
            Self::Tls => "TLS observation",
            Self::Fixture => "fixture",
            Self::Imported => "imported project evidence",
        }
    }
}

/// Quality/reliability of one observation. Application hints are always
/// `Contextual`: weak alone, meaningful only in combination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsQuality {
    Strong,
    Medium,
    Weak,
    Contextual,
}

impl OsQuality {
    /// Per-observation confidence prior (1..=95). Classification-level
    /// caps (lone-hint ceiling, multi-class floor, family ceiling) still
    /// apply downstream; a strong single observation can never report
    /// high confidence alone.
    pub fn confidence(self) -> u8 {
        match self {
            Self::Strong => 70,
            Self::Medium => 55,
            Self::Weak => 35,
            Self::Contextual => 45,
        }
    }
}

/// One typed OS observation: OBSERVED fact, never a derived guess.
///
/// A received TTL of 64 is `kind: "ttl", value: "64"`. The compatible
/// initial-TTL families derived from it are reasoning, not observation,
/// and are never persisted through this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsObservation {
    /// Observation kind within the source (`ttl`, `window`, `mss`,
    /// `option_order`, `tcp_reset`, `platform_token`, …).
    pub kind: String,
    /// Normalized value (bounded excerpt, e.g. `"64"`, `"29200"`,
    /// `"2,1,3"`).
    pub value: String,
    /// Protocol/source key (must be a known key per
    /// [`is_known_os_source`]; unknown keys stay unmatchable).
    pub source: String,
    /// Address family the observation was made on, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<OsAddressFamily>,
    /// Probe identifier that produced this observation, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_id: Option<String>,
    /// Observation timestamp (ms since UNIX epoch) when the existing
    /// evidence conventions require it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_ms: Option<u64>,
    pub provenance: OsProvenance,
    pub quality: OsQuality,
    /// Bounded supporting detail (never raw packet payload material).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl OsObservation {
    /// Normalize into matcher evidence. Values truncate to 64 chars and
    /// confidence derives from quality; provenance travels alongside via
    /// [`provenance_of_source`] labels in detailed inference (this flat
    /// evidence row keeps the stable matcher schema unchanged).
    pub fn to_evidence(&self) -> OsEvidence {
        OsEvidence {
            source: self.source.clone(),
            feature: self.kind.chars().take(64).collect(),
            value: self.value.chars().take(64).collect(),
            confidence: self.quality.confidence(),
            task_id: self.probe_id.clone(),
            evidence_id: None,
        }
    }

    /// Observations from a parsed IPv4 header view: received TTL, DF
    /// behavior. The TTL value is the observed remainder, never an
    /// initial-TTL guess.
    pub fn from_ipv4_view(
        view: &crate::os_packets::Ipv4View,
        probe_id: Option<&str>,
    ) -> Vec<OsObservation> {
        vec![
            OsObservation {
                kind: "ttl".to_owned(),
                value: view.ttl.to_string(),
                source: "ip_ttl".to_owned(),
                family: Some(OsAddressFamily::V4),
                probe_id: probe_id.map(str::to_owned),
                timestamp_ms: None,
                provenance: OsProvenance::ActiveIp,
                quality: OsQuality::Medium,
                detail: None,
            },
            OsObservation {
                kind: "df".to_owned(),
                value: view.df.to_string(),
                source: "ip_df".to_owned(),
                family: Some(OsAddressFamily::V4),
                probe_id: probe_id.map(str::to_owned),
                timestamp_ms: None,
                provenance: OsProvenance::ActiveIp,
                quality: OsQuality::Weak,
                detail: None,
            },
        ]
    }

    /// Observations from a parsed IPv6 base header view: received Hop
    /// Limit (distinct semantics from IPv4 TTL, typed as V6).
    pub fn from_ipv6_view(
        view: &crate::os_packets::Ipv6View,
        probe_id: Option<&str>,
    ) -> Vec<OsObservation> {
        vec![OsObservation {
            kind: "hop_limit".to_owned(),
            value: view.hop_limit.to_string(),
            source: "ip_ttl".to_owned(),
            family: Some(OsAddressFamily::V6),
            probe_id: probe_id.map(str::to_owned),
            timestamp_ms: None,
            provenance: OsProvenance::ActiveIp,
            quality: OsQuality::Medium,
            detail: None,
        }]
    }

    /// Observations from a parsed TCP segment view: flags, window, MSS,
    /// window scale, SACK/timestamp presence, and option ordering.
    /// Bounded: at most 8 observations per segment.
    pub fn from_tcp_view(
        view: &crate::os_packets::TcpView,
        family: OsAddressFamily,
        probe_id: Option<&str>,
    ) -> Vec<OsObservation> {
        let mut out = vec![
            OsObservation {
                kind: "flags".to_owned(),
                value: format!("0x{:02x}", view.flags),
                source: "tcp_behavior".to_owned(),
                family: Some(family),
                probe_id: probe_id.map(str::to_owned),
                timestamp_ms: None,
                provenance: OsProvenance::ActiveTcp,
                quality: OsQuality::Medium,
                detail: None,
            },
            OsObservation {
                kind: "window".to_owned(),
                value: view.window.to_string(),
                source: "tcp_window".to_owned(),
                family: Some(family),
                probe_id: probe_id.map(str::to_owned),
                timestamp_ms: None,
                provenance: OsProvenance::ActiveTcp,
                quality: OsQuality::Medium,
                detail: None,
            },
        ];
        if let Some(mss) = view.mss {
            out.push(OsObservation {
                kind: "mss".to_owned(),
                value: mss.to_string(),
                source: "tcp_mss".to_owned(),
                family: Some(family),
                probe_id: probe_id.map(str::to_owned),
                timestamp_ms: None,
                provenance: OsProvenance::ActiveTcp,
                quality: OsQuality::Medium,
                detail: None,
            });
        }
        if let Some(wscale) = view.wscale {
            out.push(OsObservation {
                kind: "wscale".to_owned(),
                value: wscale.to_string(),
                source: "tcp_wscale".to_owned(),
                family: Some(family),
                probe_id: probe_id.map(str::to_owned),
                timestamp_ms: None,
                provenance: OsProvenance::ActiveTcp,
                quality: OsQuality::Medium,
                detail: None,
            });
        }
        if view.sack_permitted {
            out.push(OsObservation {
                kind: "sack_permitted".to_owned(),
                value: "true".to_owned(),
                source: "tcp_options".to_owned(),
                family: Some(family),
                probe_id: probe_id.map(str::to_owned),
                timestamp_ms: None,
                provenance: OsProvenance::ActiveTcp,
                quality: OsQuality::Weak,
                detail: None,
            });
        }
        if view.timestamps {
            out.push(OsObservation {
                kind: "timestamps".to_owned(),
                value: "true".to_owned(),
                source: "tcp_options".to_owned(),
                family: Some(family),
                probe_id: probe_id.map(str::to_owned),
                timestamp_ms: None,
                provenance: OsProvenance::ActiveTcp,
                quality: OsQuality::Weak,
                detail: None,
            });
        }
        if !view.option_order.is_empty() {
            let order = view
                .option_order
                .iter()
                .map(|kind| kind.to_string())
                .collect::<Vec<_>>()
                .join(",");
            out.push(OsObservation {
                kind: "option_order".to_owned(),
                value: order.chars().take(64).collect(),
                source: "tcp_options".to_owned(),
                family: Some(family),
                probe_id: probe_id.map(str::to_owned),
                timestamp_ms: None,
                provenance: OsProvenance::ActiveTcp,
                quality: OsQuality::Strong,
                detail: None,
            });
        }
        out.truncate(8);
        out
    }

    /// Observation from a parsed ICMP message view: type/code response
    /// behavior (or silence, recorded by the caller as a separate weak
    /// observation — missing evidence is never negative evidence).
    pub fn from_icmp_view(
        view: &crate::os_packets::IcmpView,
        family: OsAddressFamily,
        probe_id: Option<&str>,
    ) -> Vec<OsObservation> {
        vec![OsObservation {
            kind: "type_code".to_owned(),
            value: format!("{}/{}", view.icmp_type, view.code),
            source: "icmp_behavior".to_owned(),
            family: Some(family),
            probe_id: probe_id.map(str::to_owned),
            timestamp_ms: None,
            provenance: OsProvenance::ActiveIcmp,
            quality: OsQuality::Medium,
            detail: None,
        }]
    }
}

/// Evidence sources with defined matching semantics. Pack features that
/// reference any other key are reported by [`unknown_os_sources`] (lint)
/// and classify at most as weak application hints (single-class ceiling),
/// never strong evidence. The matcher itself never fails on them: unknown
/// stays safe and weak.
pub fn is_known_os_source(source: &str) -> bool {
    matches!(
        source,
        "tcp_options"
            | "tcp_window"
            | "tcp_mss"
            | "tcp_wscale"
            | "tcp_timing"
            | "tcp_rtt"
            | "ip_ttl"
            | "ip_df"
            | "ip_id"
            | "icmp_behavior"
            | "tcp_behavior"
            | "tcp_reset"
            | "ssh_banner"
            | "service_product"
            | "smtp_banner"
            | "ftp_banner"
            | "banner_token"
            | "http_server"
            | "tls_subject"
            | "tls_issuer"
    )
}

/// Provenance label for an evidence source. Network-stack observations
/// and application-context hints never share a label.
pub fn provenance_of_source(source: &str) -> &'static str {
    match source {
        "ip_ttl" | "ip_df" | "ip_id" => OsProvenance::ActiveIp.as_str(),
        "tcp_options" | "tcp_window" | "tcp_mss" | "tcp_wscale" => OsProvenance::ActiveTcp.as_str(),
        "tcp_timing" | "tcp_rtt" => "active TCP timing",
        "icmp_behavior" => OsProvenance::ActiveIcmp.as_str(),
        "tcp_behavior" | "tcp_reset" => OsProvenance::ExistingTcpScan.as_str(),
        "ssh_banner" => OsProvenance::Ssh.as_str(),
        "http_server" => OsProvenance::Http.as_str(),
        "service_product" => OsProvenance::ServiceEvidence.as_str(),
        "tls_subject" | "tls_issuer" => OsProvenance::Tls.as_str(),
        _ => "application hint",
    }
}

/// Confidence label vocabulary (shared with project intelligence bands:
/// high >= 75, medium >= 50, low below; unknown is absence of evidence).
pub fn confidence_label(confidence: u8) -> &'static str {
    if confidence >= 75 {
        "high"
    } else if confidence >= 50 {
        "medium"
    } else {
        "low"
    }
}

/// Report unknown observation keys in one pack (deterministic, sorted).
/// Used by corpus lint: unknown keys are reported, never silently matched.
pub fn unknown_os_sources(pack: &OsPack) -> Vec<String> {
    let mut unknown = BTreeSet::new();
    for rule in &pack.rules {
        for feature in rule.features.iter().chain(rule.exclusions.iter()) {
            if !is_known_os_source(&feature.source) {
                unknown.insert(feature.source.clone());
            }
        }
    }
    unknown.into_iter().collect()
}

/// One explainable OS candidate: score inputs stay visible instead of
/// collapsing into a bare label.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OsDetailedCandidate {
    pub family: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_hint: Option<String>,
    pub confidence: u8,
    /// Explainable band for `confidence` (`high`/`medium`/`low`).
    pub confidence_band: String,
    /// 0..=1: matched features over the best rule's feature count.
    pub coverage: f32,
    /// Matched evidence (`source:pattern`), bounded.
    pub matched: Vec<String>,
    /// Explicitly contradicted evidence (`source:pattern`), bounded.
    pub conflicting: Vec<String>,
    /// Rule evidence kinds with no observation at all, bounded.
    pub unavailable: Vec<String>,
    /// Distinct provenance labels behind the matched evidence.
    pub provenance: Vec<String>,
    #[serde(default)]
    pub rule_ids: Vec<String>,
}

/// Full inference result for one host. `Unknown` (no candidates) is a
/// first-class result with an explicit reason, never a guessed label.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OsInference {
    pub best: Option<OsDetailedCandidate>,
    #[serde(default)]
    pub alternatives: Vec<OsDetailedCandidate>,
    pub unknown: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown_reason: Option<String>,
}

impl OsInference {
    /// Flatten to the stable candidate list (best first, then
    /// alternatives). Empty when unknown.
    pub fn candidates(&self) -> Vec<OsCandidate> {
        let mut candidates = Vec::new();
        if let Some(best) = &self.best {
            candidates.push(detailed_to_candidate(best));
        }
        for alternative in &self.alternatives {
            candidates.push(detailed_to_candidate(alternative));
        }
        candidates
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

/// Cross-file duplicate OS rule ID, deterministic (path-sorted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateOsId {
    pub id: String,
    pub first_source: String,
    pub second_source: String,
}

impl std::fmt::Display for DuplicateOsId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "duplicate OS rule id '{}': first in {}, again in {}",
            self.id, self.first_source, self.second_source
        )
    }
}

/// Detect cross-file duplicate OS IDs. Sorted by path, deterministic.
/// Strict production loaders reject duplicates; callers that must fail on
/// shadowing check this first.
pub fn find_duplicate_os_id(packs: &[(String, OsPack)]) -> Option<DuplicateOsId> {
    let mut paths: Vec<String> = packs.iter().map(|(p, _)| p.clone()).collect();
    paths.sort();
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for path in &paths {
        if let Some((_, pack)) = packs.iter().find(|(p, _)| p == path) {
            for rule in &pack.rules {
                if let Some(first) = seen.get(&rule.id) {
                    return Some(DuplicateOsId {
                        id: rule.id.clone(),
                        first_source: first.clone(),
                        second_source: path.clone(),
                    });
                }
                seen.insert(rule.id.clone(), path.clone());
            }
        }
    }
    None
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

    /// Strict production constructor: duplicate OS rule IDs across packs
    /// are a validation failure. Inputs are sorted by pack path before
    /// validation so the reported pair is deterministic regardless of
    /// caller order. Returns `Invalid` identifying the duplicate ID, first
    /// source, and conflicting source.
    pub fn try_from_packs(packs: Vec<(String, OsPack)>) -> Result<Self, OsPackError> {
        let mut sorted = packs;
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        if let Some(dup) = find_duplicate_os_id(&sorted) {
            return Err(OsPackError::Invalid {
                path: dup.second_source.clone(),
                reason: dup.to_string(),
            });
        }
        Ok(Self::from_packs(sorted))
    }

    /// Permissive internal constructor kept for backwards compatibility
    /// and tests: duplicates keep the first pack's rule (path-sorted order
    /// for determinism). Production strict loading MUST use
    /// [`try_from_packs`](Self::try_from_packs) or
    /// [`load_from_dir`](Self::load_from_dir), which reject duplicates.
    pub fn from_packs(packs: Vec<(String, OsPack)>) -> Self {
        let mut sorted = packs;
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let mut rules = Vec::new();
        let mut seen = BTreeSet::new();
        let mut stats = OsLoadStats {
            packs_loaded: sorted.len(),
            ..Default::default()
        };
        for (path, pack) in sorted {
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

    /// Strict production loader: every pack in `dir` is loaded once.
    /// Missing directory yields an empty DB; malformed files are counted
    /// and skipped. Duplicate OS rule IDs across packs are a validation
    /// failure: no silent first-wins shadowing. On duplicates the loader
    /// returns an empty DB with the duplicate explicitly recorded in
    /// `files_rejected`/`rejected_files` (deterministic ID + both sources).
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
        // Cross-pack duplicates fail deterministically (path-sorted sources).
        if let Some(dup) = find_duplicate_os_id(&packs) {
            let mut empty = Self::empty();
            empty.stats.files_rejected = stats.files_rejected + 1;
            let mut rejected = stats.rejected_files;
            rejected.push(format!("{}: {dup}", dup.second_source));
            rejected.sort();
            empty.stats.rejected_files = rejected;
            return empty;
        }
        match Self::try_from_packs(packs) {
            Ok(mut db) => {
                db.stats.files_rejected = stats.files_rejected;
                db.stats.rejected_files = stats.rejected_files;
                db
            }
            Err(OsPackError::Invalid { path, reason }) => {
                let mut empty = Self::empty();
                empty.stats.files_rejected = stats.files_rejected + 1;
                let mut rejected = stats.rejected_files;
                rejected.push(format!("{path}: {reason}"));
                rejected.sort();
                empty.stats.rejected_files = rejected;
                empty
            }
            Err(_) => Self::empty(),
        }
    }

    /// Classify one host from its evidence set. Returns candidates sorted
    /// by (confidence desc, family asc); empty when nothing matched.
    /// Deterministic and bounded (one candidate per matching rule family
    /// at most — families merge across rules, best rule wins per family).
    /// Compatibility wrapper over [`classify_detailed`](Self::classify_detailed).
    pub fn classify_host(&self, evidence: &[OsEvidence]) -> Vec<OsCandidate> {
        let inference = self.classify_detailed(evidence);
        let mut candidates = Vec::new();
        if let Some(best) = inference.best {
            candidates.push(detailed_to_candidate(&best));
        }
        for alternative in inference.alternatives {
            candidates.push(detailed_to_candidate(&alternative));
        }
        candidates
    }

    /// Classify one host with full explanation: coverage, conflicting
    /// evidence, unavailable evidence kinds, and provenance per candidate.
    /// Same evidence + same corpus = same result; evidence and fingerprint
    /// order never change the semantic result (inputs sort by rule id,
    /// families merge in a `BTreeMap`, candidates sort deterministically).
    pub fn classify_detailed(&self, evidence: &[OsEvidence]) -> OsInference {
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
        // Families with at least one rule vetoed by contradictory evidence
        // while other evidence still matched that family (bounded notes).
        let mut family_conflicts: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut any_feature_hit = false;
        for rule in &self.rules {
            // Exclusions veto the rule outright; the hit is recorded as an
            // explicit contradiction for the family instead of vanishing.
            let vetoed: Vec<String> = rule
                .exclusions
                .iter()
                .filter(|feature| {
                    by_source.get(feature.source.as_str()).is_some_and(|texts| {
                        texts.iter().any(|text| feature_matches(feature, text))
                    })
                })
                .map(|feature| format!("{}:{}", feature.source, feature.pattern))
                .take(4)
                .collect();
            if !vetoed.is_empty() {
                let slot = family_conflicts.entry(rule.family.clone()).or_default();
                for hit in vetoed {
                    if slot.len() < 4 && !slot.contains(&hit) {
                        slot.push(hit);
                    }
                }
                // A vetoed rule whose features still matched is explicit
                // contradiction (not mere absence): unknown reports it.
                if rule.features.iter().any(|feature| {
                    by_source.get(feature.source.as_str()).is_some_and(|texts| {
                        texts.iter().any(|text| feature_matches(feature, text))
                    })
                }) {
                    any_feature_hit = true;
                }
                continue;
            }
            let mut weight_sum: u32 = 0;
            let mut matched_count: u32 = 0;
            let mut classes: BTreeSet<OsEvidenceClass> = BTreeSet::new();
            let mut supporting = Vec::new();
            let mut matched_sources = BTreeSet::new();
            let mut unavailable = Vec::new();
            for feature in &rule.features {
                match by_source.get(feature.source.as_str()) {
                    None => {
                        if unavailable.len() < 8 && !unavailable.contains(&feature.source) {
                            unavailable.push(feature.source.clone());
                        }
                    }
                    Some(texts) => {
                        if texts.iter().any(|text| feature_matches(feature, text)) {
                            weight_sum += u32::from(feature.weight);
                            matched_count += 1;
                            classes.insert(OsEvidence::class_of(&feature.source));
                            matched_sources.insert(feature.source.clone());
                            if supporting.len() < 8 {
                                supporting.push(format!("{}:{}", feature.source, feature.pattern));
                            }
                        }
                    }
                }
            }
            if matched_count > 0 {
                any_feature_hit = true;
            }
            if classes.is_empty() {
                continue;
            }
            let confidence = confidence_for(classes.len(), weight_sum, rule.confidence_cap);
            let coverage =
                (matched_count as f32 / rule.features.len().max(1) as f32).clamp(0.0, 1.0);
            let provenance = matched_sources
                .iter()
                .map(|source| provenance_of_source(source).to_owned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let entry = families
                .entry(rule.family.clone())
                .or_insert_with(|| FamilyScore {
                    generation: rule.generation.clone(),
                    device_hint: rule.device_hint.clone(),
                    variant: rule.variant.clone(),
                    confidence: 0,
                    coverage: 0.0,
                    supporting: Vec::new(),
                    unavailable: Vec::new(),
                    provenance: Vec::new(),
                    rule_ids: Vec::new(),
                });
            if confidence > entry.confidence {
                entry.confidence = confidence;
                entry.coverage = coverage;
                entry.generation = rule.generation.clone();
                entry.device_hint = rule.device_hint.clone();
                entry.variant = rule.variant.clone();
                entry.supporting = supporting;
                entry.unavailable = unavailable;
                entry.provenance = provenance;
                entry.rule_ids = vec![rule.id.clone()];
            } else if confidence == entry.confidence && entry.rule_ids.len() < 4 {
                entry.rule_ids.push(rule.id.clone());
            }
        }
        let mut detailed: Vec<OsDetailedCandidate> = families
            .into_iter()
            .map(|(family, score)| {
                let conflicting = family_conflicts.remove(&family).unwrap_or_default();
                OsDetailedCandidate {
                    family,
                    generation: score.generation,
                    variant: score.variant,
                    device_hint: score.device_hint,
                    confidence: score.confidence,
                    confidence_band: confidence_label(score.confidence).to_owned(),
                    coverage: score.coverage,
                    matched: score.supporting,
                    conflicting,
                    unavailable: score.unavailable,
                    provenance: score.provenance,
                    rule_ids: score.rule_ids,
                }
            })
            .collect();
        detailed.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.family.cmp(&b.family))
        });
        detailed.truncate(4);
        if detailed.is_empty() {
            let reason = if evidence.is_empty() {
                "no OS evidence was collected for this host"
            } else if any_feature_hit {
                "contradictory evidence vetoed every matching candidate"
            } else {
                "no fingerprint matched the collected evidence"
            };
            return OsInference {
                best: None,
                alternatives: Vec::new(),
                unknown: true,
                unknown_reason: Some(reason.to_owned()),
            };
        }
        let mut detailed_iter = detailed.into_iter();
        let best = detailed_iter.next();
        OsInference {
            best,
            alternatives: detailed_iter.collect(),
            unknown: false,
            unknown_reason: None,
        }
    }
}

struct FamilyScore {
    generation: Option<String>,
    device_hint: Option<String>,
    variant: Option<String>,
    confidence: u8,
    coverage: f32,
    supporting: Vec<String>,
    unavailable: Vec<String>,
    provenance: Vec<String>,
    rule_ids: Vec<String>,
}

/// Flatten a detailed candidate back to the stable candidate record.
fn detailed_to_candidate(detailed: &OsDetailedCandidate) -> OsCandidate {
    OsCandidate {
        family: detailed.family.clone(),
        generation: detailed.generation.clone(),
        device_hint: detailed.device_hint.clone(),
        variant: detailed.variant.clone(),
        confidence: detailed.confidence,
        supporting: detailed.matched.clone(),
        conflicting: detailed.conflicting.clone(),
        rule_ids: detailed.rule_ids.clone(),
    }
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

    #[test]
    fn cross_file_duplicates_are_deterministic() {
        let a = parse_os_pack(
            r#"{"schema_version": 1, "rules": [
            {"id": "dup", "family": "Linux",
             "features": [{"source": "s", "pattern": "a", "weight": 10}],
             "confidence_cap": 80, "source": "t"}]}"#,
            "a.json",
        )
        .unwrap();
        let b = parse_os_pack(
            r#"{"schema_version": 1, "rules": [
            {"id": "dup", "family": "Linux",
             "features": [{"source": "s", "pattern": "b", "weight": 10}],
             "confidence_cap": 80, "source": "t"}]}"#,
            "b.json",
        )
        .unwrap();
        let dup =
            find_duplicate_os_id(&[("b.json".to_owned(), b), ("a.json".to_owned(), a)]).unwrap();
        assert_eq!(dup.id, "dup");
        assert_eq!(dup.first_source, "a.json");
        assert_eq!(dup.second_source, "b.json");
    }

    fn os_pack_with_id(id: &str, pattern: &str) -> OsPack {
        parse_os_pack(
            &format!(
                r#"{{"schema_version": 1, "rules": [
                {{"id": "{id}", "family": "Linux",
                  "features": [{{"source": "s", "pattern": "{pattern}", "weight": 10}}],
                  "confidence_cap": 80, "source": "t"}}]}}"#
            ),
            "t",
        )
        .unwrap()
    }

    #[test]
    fn strict_try_from_packs_rejects_os_duplicates_deterministically() {
        // Same-pack duplicate already rejected by pack validation.
        assert!(
            parse_os_pack(
                r#"{"schema_version": 1, "rules": [
                {"id": "dup-os", "family": "Linux",
                 "features": [{"source": "s", "pattern": "a", "weight": 10}],
                 "confidence_cap": 80, "source": "t"},
                {"id": "dup-os", "family": "Linux",
                 "features": [{"source": "s", "pattern": "b", "weight": 10}],
                 "confidence_cap": 80, "source": "t"}]}"#,
                "t",
            )
            .is_err()
        );
        let a = os_pack_with_id("dup-os", "a");
        let b = os_pack_with_id("dup-os", "b");
        let err = OsDb::try_from_packs(vec![
            ("b.json".to_owned(), b.clone()),
            ("a.json".to_owned(), a.clone()),
        ])
        .expect_err("duplicate across OS packs must fail");
        let text = err.to_string();
        assert!(text.contains("dup-os"), "error identifies ID: {text}");
        assert!(text.contains("a.json"), "error identifies first: {text}");
        assert!(text.contains("b.json"), "error identifies conflict: {text}");
        let reverse = OsDb::try_from_packs(vec![
            ("a.json".to_owned(), a.clone()),
            ("b.json".to_owned(), b.clone()),
        ])
        .expect_err("order must not matter");
        assert_eq!(err.to_string(), reverse.to_string(), "deterministic");
        let ok = OsDb::try_from_packs(vec![
            ("b.json".to_owned(), os_pack_with_id("os-b", "b")),
            ("a.json".to_owned(), os_pack_with_id("os-a", "a")),
        ])
        .expect("distinct OS IDs load");
        assert_eq!(ok.rule_count(), 2);
    }

    #[test]
    fn production_loader_rejects_duplicate_os_ids() {
        // Real production loader (filesystem), not merely the helper.
        let base =
            std::env::temp_dir().join(format!("rxscan-os-dup-{}-{}", std::process::id(), "prod"));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let write = |name: &str, id: &str, pattern: &str| {
            std::fs::write(
                base.join(name),
                format!(
                    r#"{{"schema_version": 1, "rules": [
                    {{"id": "{id}", "family": "Linux",
                      "features": [{{"source": "s", "pattern": "{pattern}", "weight": 10}}],
                      "confidence_cap": 80, "source": "t"}}]}}"#
                ),
            )
            .unwrap();
        };
        write("a.json", "dup-os", "a");
        write("b.json", "dup-os", "b");
        let db = OsDb::load_from_dir(&base);
        assert_eq!(db.rule_count(), 0, "no silent first-wins");
        assert!(db.stats().files_rejected >= 1);
        let rejected = db.stats().rejected_files.join("\n");
        assert!(rejected.contains("dup-os"), "ID recorded: {rejected}");
        assert!(rejected.contains("a.json"), "first source: {rejected}");
        assert!(rejected.contains("b.json"), "conflict source: {rejected}");
        // Same-pack duplicate: single bad file rejected.
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(
            base.join("only.json"),
            r#"{"schema_version": 1, "rules": [
                {"id": "dup-os", "family": "Linux",
                 "features": [{"source": "s", "pattern": "a", "weight": 10}],
                 "confidence_cap": 80, "source": "t"},
                {"id": "dup-os", "family": "Linux",
                 "features": [{"source": "s", "pattern": "b", "weight": 10}],
                 "confidence_cap": 80, "source": "t"}]}"#,
        )
        .unwrap();
        let db = OsDb::load_from_dir(&base);
        assert_eq!(db.rule_count(), 0);
        assert!(db.stats().files_rejected >= 1);
        // Valid distinct packs still load through the same production path.
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        write("a.json", "os-a", "alpha");
        write("b.json", "os-b", "beta");
        let db = OsDb::load_from_dir(&base);
        assert_eq!(db.rule_count(), 2);
        assert_eq!(db.stats().files_rejected, 0);
        let _ = std::fs::remove_dir_all(&base);
    }

    // ---------------- active OS observation model ----------------

    #[test]
    fn observation_serializes_and_converts_bounded() {
        let observation = OsObservation {
            kind: "ttl".to_owned(),
            value: "64".to_owned(),
            source: "ip_ttl".to_owned(),
            family: Some(OsAddressFamily::V4),
            probe_id: Some("tcp-80".to_owned()),
            timestamp_ms: Some(1_700_000_000_000),
            provenance: OsProvenance::ActiveIp,
            quality: OsQuality::Medium,
            detail: None,
        };
        let json = serde_json::to_string(&observation).unwrap();
        let decoded: OsObservation = serde_json::from_str(&json).unwrap();
        assert_eq!(observation, decoded);
        let evidence = observation.to_evidence();
        assert_eq!(evidence.source, "ip_ttl");
        assert_eq!(evidence.feature, "ttl");
        assert_eq!(evidence.value, "64");
        // Oversized values truncate, never grow the matcher.
        let big = OsObservation {
            value: "x".repeat(5000),
            ..observation.clone()
        };
        assert!(big.to_evidence().value.len() <= 64);
    }

    #[test]
    fn ipv4_and_ipv6_observations_stay_distinct() {
        let v4 = OsObservation::from_ipv4_view(
            &crate::os_packets::Ipv4View {
                ttl: 64,
                df: true,
                identification: 1,
                protocol: 6,
                header_len: 20,
            },
            Some("p1"),
        );
        let v6 = OsObservation::from_ipv6_view(
            &crate::os_packets::Ipv6View {
                hop_limit: 64,
                next_header: 6,
                payload_len: 32,
                src: "::1".parse().unwrap(),
                dst: "::1".parse().unwrap(),
            },
            Some("p1"),
        );
        assert!(
            v4.iter()
                .any(|item| item.kind == "ttl" && item.family == Some(OsAddressFamily::V4))
        );
        assert!(
            v6.iter()
                .all(|item| item.family == Some(OsAddressFamily::V6))
        );
        assert!(v6.iter().any(|item| item.kind == "hop_limit"));
        // Same numeric value, different families: never equal as observations.
        assert_ne!(v4[0].family, v6[0].family);
    }

    #[test]
    fn tcp_and_icmp_views_become_typed_observations() {
        let tcp = crate::os_packets::parse_tcp_segment(&{
            let mut segment = vec![0u8; 32];
            segment[12] = 0x80;
            segment[13] = 0x12;
            segment[14..16].copy_from_slice(&29200u16.to_be_bytes());
            segment[20..24].copy_from_slice(&[2, 4, 0x05, 0xB4]);
            segment[24] = 1;
            segment[25..28].copy_from_slice(&[3, 3, 7]);
            segment
        })
        .unwrap();
        let observations = OsObservation::from_tcp_view(&tcp, OsAddressFamily::V4, None);
        let kinds: Vec<&str> = observations.iter().map(|item| item.kind.as_str()).collect();
        assert!(kinds.contains(&"flags"));
        assert!(kinds.contains(&"window"));
        assert!(kinds.contains(&"mss"));
        assert!(kinds.contains(&"wscale"));
        assert!(kinds.contains(&"option_order"));
        assert!(observations.len() <= 8);
        assert!(
            observations
                .iter()
                .all(|item| item.provenance == OsProvenance::ActiveTcp)
        );
        let icmp = crate::os_packets::parse_icmp_message(&[3u8, 3, 0, 0, 0, 0, 0, 0])
            .unwrap()
            .0;
        let icmp_observations =
            OsObservation::from_icmp_view(&icmp, OsAddressFamily::V4, Some("icmp-1"));
        assert_eq!(icmp_observations[0].value, "3/3");
        assert_eq!(icmp_observations[0].probe_id.as_deref(), Some("icmp-1"));
    }

    #[test]
    fn known_sources_cover_matcher_vocabulary_and_lint_reports_unknown() {
        for source in [
            "ssh_banner",
            "http_server",
            "banner_token",
            "service_product",
            "ip_ttl",
            "tcp_window",
            "tcp_options",
            "icmp_behavior",
            "tcp_behavior",
        ] {
            assert!(is_known_os_source(source), "known: {source}");
        }
        assert!(!is_known_os_source("port_22_open"));
        assert!(!is_known_os_source("apache"));
        let pack = parse_os_pack(
            r#"{"schema_version": 1, "rules": [
            {"id": "lint-x", "family": "Linux",
             "features": [{"source": "port_22_open", "pattern": "x", "weight": 10}],
             "confidence_cap": 80, "source": "lint"}]}"#,
            "lint",
        )
        .unwrap();
        assert_eq!(unknown_os_sources(&pack), vec!["port_22_open".to_owned()]);
        // Unknown keys never produce strong claims: weakest class, capped
        // at the lone-hint ceiling. Lint flags them for maintainers.
        let db = OsDb::from_packs(vec![("lint".to_owned(), pack)]);
        let weak = db.classify_host(&[evidence("port_22_open", "x")]);
        assert!(
            weak.iter()
                .all(|candidate| candidate.confidence <= SINGLE_HINT_CAP)
        );
    }

    #[test]
    fn provenance_never_collapses_stack_and_service() {
        assert_eq!(provenance_of_source("ip_ttl"), "active IP observation");
        assert_eq!(provenance_of_source("tcp_window"), "active TCP observation");
        assert_eq!(
            provenance_of_source("icmp_behavior"),
            "active ICMP observation"
        );
        assert_eq!(provenance_of_source("tcp_behavior"), "existing TCP scan");
        assert_eq!(provenance_of_source("ssh_banner"), "SSH observation");
        assert_eq!(provenance_of_source("http_server"), "HTTP observation");
        assert_eq!(
            provenance_of_source("service_product"),
            "service fingerprint"
        );
        assert_ne!(
            provenance_of_source("tcp_window"),
            provenance_of_source("service_product")
        );
    }

    #[test]
    fn confidence_bands_match_project_intelligence() {
        assert_eq!(confidence_label(90), "high");
        assert_eq!(confidence_label(75), "high");
        assert_eq!(confidence_label(74), "medium");
        assert_eq!(confidence_label(50), "medium");
        assert_eq!(confidence_label(49), "low");
        assert_eq!(confidence_label(0), "low");
    }

    fn detail_db() -> OsDb {
        OsDb::from_packs(vec![(
            "d.json".to_owned(),
            parse_os_pack(
                r#"{"schema_version": 1, "rules": [
                {"id": "d-linux", "family": "Linux",
                 "features": [
                   {"source": "tcp_behavior", "pattern": "reset", "weight": 15},
                   {"source": "ssh_banner", "pattern": "Ubuntu", "weight": 20}],
                 "exclusions": [
                   {"source": "ssh_banner", "pattern": "Windows", "weight": 1}],
                 "confidence_cap": 85, "source": "d"},
                {"id": "d-linux-banner", "family": "Linux",
                 "features": [
                   {"source": "ssh_banner", "pattern": "Ubuntu", "weight": 18}],
                 "confidence_cap": 65, "source": "d"},
                {"id": "d-win", "family": "Windows",
                 "features": [
                   {"source": "ssh_banner", "pattern": "Windows", "weight": 22}],
                 "confidence_cap": 80, "source": "d"}]}"#,
                "d",
            )
            .unwrap(),
        )])
    }

    #[test]
    fn detailed_inference_explains_coverage_conflicts_and_gaps() {
        let db = detail_db();
        let inference = db.classify_detailed(&[
            evidence("tcp_behavior", "port 80 reset"),
            evidence("ssh_banner", "Ubuntu"),
        ]);
        assert!(!inference.unknown);
        let best = inference.best.unwrap();
        assert_eq!(best.family, "Linux");
        assert_eq!(best.coverage, 1.0);
        assert!(best.unavailable.is_empty());
        assert_eq!(best.confidence_band, confidence_label(best.confidence));
        assert!(best.confidence <= OS_CONFIDENCE_CAP);
        assert!(best.provenance.contains(&"existing TCP scan".to_owned()));
        assert!(best.provenance.contains(&"SSH observation".to_owned()));
        // Partial evidence: coverage drops, confidence cannot claim more.
        let partial = db
            .classify_detailed(&[evidence("ssh_banner", "Ubuntu")])
            .best
            .unwrap();
        assert!(partial.coverage < 1.0);
        assert!(!partial.unavailable.is_empty());
        assert!(partial.confidence <= SINGLE_HINT_CAP);
        // Contradiction is explicit, not silent: the vetoed rule's hit is
        // recorded on the surviving same-family candidate, and a fully
        // vetoed corpus reports unknown with the contradiction reason.
        let conflict = db.classify_detailed(&[
            evidence("tcp_behavior", "port 80 reset"),
            evidence("ssh_banner", "Ubuntu Windows box"),
        ]);
        assert!(!conflict.unknown);
        let linux = conflict
            .best
            .iter()
            .chain(conflict.alternatives.iter())
            .find(|candidate| candidate.family == "Linux")
            .expect("Linux survives through its unvetoed rule");
        assert!(
            linux.conflicting.contains(&"ssh_banner:Windows".to_owned()),
            "conflict exposed: {:?}",
            linux.conflicting
        );
        let veto_only = OsDb::from_packs(vec![(
            "v.json".to_owned(),
            parse_os_pack(
                r#"{"schema_version": 1, "rules": [
                {"id": "v-linux", "family": "Linux",
                 "features": [
                   {"source": "tcp_behavior", "pattern": "reset", "weight": 15},
                   {"source": "ssh_banner", "pattern": "Ubuntu", "weight": 20}],
                 "exclusions": [
                   {"source": "ssh_banner", "pattern": "Windows", "weight": 1}],
                 "confidence_cap": 85, "source": "v"}]}"#,
                "v",
            )
            .unwrap(),
        )]);
        let vetoed = veto_only.classify_detailed(&[
            evidence("tcp_behavior", "port 80 reset"),
            evidence("ssh_banner", "Ubuntu Windows box"),
        ]);
        assert!(vetoed.unknown);
        assert_eq!(
            vetoed.unknown_reason.as_deref(),
            Some("contradictory evidence vetoed every matching candidate")
        );
        // No evidence at all: unknown with its own reason.
        let empty = db.classify_detailed(&[]);
        assert!(empty.unknown);
        assert!(empty.unknown_reason.is_some());
        // Evidence that matches nothing: unknown, never invented.
        let nomatch = db.classify_detailed(&[evidence("ssh_banner", "hello world")]);
        assert!(nomatch.unknown);
    }

    #[test]
    fn classic_candidates_carry_conflicts() {
        let db = detail_db();
        // Windows evidence present alongside Linux evidence: the strict
        // Linux rule is vetoed by its exclusion, Linux survives through its
        // unvetoed rule with the conflict attached, and Windows leads on
        // confidence. Vetoed rules never report as candidates themselves.
        let candidates = db.classify_host(&[
            evidence("tcp_behavior", "port 80 reset"),
            evidence("ssh_banner", "Ubuntu Windows box"),
        ]);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].family, "Windows");
        let linux = candidates
            .iter()
            .find(|candidate| candidate.family == "Linux")
            .unwrap();
        assert!(linux.conflicting.contains(&"ssh_banner:Windows".to_owned()));
    }

    #[test]
    fn evidence_permutation_and_pack_order_never_change_results() {
        let db = detail_db();
        let first = vec![
            evidence("tcp_behavior", "port 80 reset"),
            evidence("ssh_banner", "Ubuntu"),
            evidence("http_server", "noise"),
        ];
        let mut permuted = first.clone();
        permuted.reverse();
        assert_eq!(db.classify_host(&first), db.classify_host(&permuted));
        assert_eq!(
            db.classify_detailed(&first),
            db.classify_detailed(&permuted)
        );
        // Fingerprint order independence: reversed pack input, same result.
        let pack_a = parse_os_pack(
            r#"{"schema_version": 1, "rules": [
            {"id": "o-a", "family": "Linux",
             "features": [{"source": "ssh_banner", "pattern": "Ubuntu", "weight": 20}],
             "confidence_cap": 85, "source": "o"}]}"#,
            "a",
        )
        .unwrap();
        let pack_b = parse_os_pack(
            r#"{"schema_version": 1, "rules": [
            {"id": "o-b", "family": "Windows",
             "features": [{"source": "ssh_banner", "pattern": "Windows", "weight": 20}],
             "confidence_cap": 85, "source": "o"}]}"#,
            "b",
        )
        .unwrap();
        let forward = OsDb::from_packs(vec![
            ("a".to_owned(), pack_a.clone()),
            ("b".to_owned(), pack_b.clone()),
        ]);
        let backward = OsDb::from_packs(vec![("b".to_owned(), pack_b), ("a".to_owned(), pack_a)]);
        let probe = vec![evidence("ssh_banner", "Ubuntu Windows")];
        assert_eq!(
            forward.classify_host(&probe),
            backward.classify_host(&probe)
        );
    }

    #[test]
    fn supporting_evidence_is_monotonic_without_new_contradiction() {
        let db = detail_db();
        let weak = vec![evidence("tcp_behavior", "port 80 reset")];
        let stronger = vec![
            evidence("tcp_behavior", "port 80 reset"),
            evidence("ssh_banner", "Ubuntu"),
        ];
        let weak_conf = db
            .classify_host(&weak)
            .iter()
            .find(|candidate| candidate.family == "Linux")
            .map(|candidate| candidate.confidence)
            .unwrap_or(0);
        let strong_conf = db
            .classify_host(&stronger)
            .iter()
            .find(|candidate| candidate.family == "Linux")
            .map(|candidate| candidate.confidence)
            .unwrap_or(0);
        assert!(strong_conf >= weak_conf);
        // Adding contradiction cannot silently increase confidence.
        let contradicted = vec![
            evidence("tcp_behavior", "port 80 reset"),
            evidence("ssh_banner", "Ubuntu"),
            evidence("ssh_banner", "Windows"),
        ];
        let contra_conf = db
            .classify_host(&contradicted)
            .iter()
            .find(|candidate| candidate.family == "Linux")
            .map(|candidate| candidate.confidence)
            .unwrap_or(0);
        assert!(contra_conf <= strong_conf);
    }

    #[test]
    fn missing_evidence_is_not_contradiction() {
        // A rule needing two features still matches on one (partial
        // coverage); absence of the second source never vetoes.
        let db = detail_db();
        let partial = db.classify_host(&[evidence("ssh_banner", "Ubuntu")]);
        assert!(partial.iter().any(|candidate| candidate.family == "Linux"));
    }
}

/// Per-host OS report streamed as an `os_candidate` JSONL record.
/// Additive detail fields (`coverage`, `unavailable`, `probe_availability`,
/// `provenance`) default for old readers; new readers explain exactly how
/// strong the evidence is, what conflicts, and what could not be observed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OsHostReport {
    pub host: String,
    pub candidates: Vec<OsCandidate>,
    pub evidence_count: usize,
    /// Best-candidate coverage 0..=1 (0 when unknown).
    #[serde(default)]
    pub coverage: f32,
    /// Evidence kinds the winning rule needed but nothing observed.
    #[serde(default)]
    pub unavailable: Vec<String>,
    /// Active-probe availability for this host (`None` = passive-only run).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_availability: Option<String>,
    /// Distinct provenance labels behind the best candidate.
    #[serde(default)]
    pub provenance: Vec<String>,
}
