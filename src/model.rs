//! Phase 2's bounded, typed interchange model.  It records observations only;
//! it intentionally contains no scheduling or network-execution capability.

use std::{
    collections::BTreeMap,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use url::Url;

use crate::{plan::ScanPlan, scope::ScopePolicy};

pub const SCHEMA_VERSION: u16 = 1;
pub const MAX_EVIDENCE_DETAILS_BYTES: usize = 64 * 1024;
pub const MAX_EVENT_DETAILS_BYTES: usize = 64 * 1024;

/// Canonical one-record JSON suitable for append-only JSONL output.
pub trait JsonLine: Serialize {
    fn to_json_line(&self) -> Result<String, ModelError> {
        serde_json::to_string(self).map_err(|_| ModelError::Serialization)
    }
}

/// Unix milliseconds avoid timezone ambiguity and serialize as a JSON number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(pub u64);
impl Timestamp {
    pub fn now() -> Self {
        Self(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AssetId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FindingId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EvidenceId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScanPlanId(pub String);

impl ScanPlanId {
    pub fn from_serializable(plan: &ScanPlan) -> Self {
        // serde's struct field order and all collections in ScanPlan are deterministic.
        let bytes = serde_json::to_vec(plan).expect("ScanPlan is serializable");
        Self(format!("plan_{}", stable_hash_bytes(&bytes)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub module_name: String,
    pub module_version: String,
    pub scan_plan_id: ScanPlanId,
    pub timestamp: Timestamp,
}
impl Provenance {
    pub fn new(
        module_name: impl Into<String>,
        module_version: impl Into<String>,
        scan_plan_id: ScanPlanId,
        timestamp: Timestamp,
    ) -> Result<Self, ModelError> {
        let result = Self {
            module_name: module_name.into(),
            module_version: module_version.into(),
            scan_plan_id,
            timestamp,
        };
        if result.module_name.trim().is_empty()
            || result.module_version.trim().is_empty()
            || result.scan_plan_id.0.trim().is_empty()
        {
            return Err(ModelError::MissingProvenance);
        }
        Ok(result)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Host,
    Ip,
    Port,
    Service,
    Url,
    Endpoint,
    Certificate,
    Technology,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    pub schema_version: u16,
    pub id: AssetId,
    pub kind: AssetKind,
    /// Canonical, kind-specific identity text; never an opaque random identifier.
    pub identity: String,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub provenance: Provenance,
}
impl Asset {
    /// Creates a recorded asset after checking the host/IP/URL against the central Scope Guard.
    pub fn scoped(
        kind: AssetKind,
        identity: impl AsRef<str>,
        scope: &ScopePolicy,
        provenance: Provenance,
    ) -> Result<Self, ModelError> {
        if !matches!(kind, AssetKind::Host | AssetKind::Ip | AssetKind::Url) {
            return Err(ModelError::RootAssetMustBeScoped);
        }
        let identity = canonical_identity(&kind, identity.as_ref())?;
        enforce_scope(&kind, &identity, scope)?;
        let id = AssetId(format!(
            "asset_{}_{}",
            kind_name(&kind),
            stable_hash(&format!("{}:{identity}", kind_name(&kind)))
        ));
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            id,
            kind,
            identity,
            attributes: BTreeMap::new(),
            first_seen: provenance.timestamp,
            last_seen: provenance.timestamp,
            provenance,
        })
    }
    pub fn with_attributes(mut self, attributes: BTreeMap<String, String>) -> Self {
        self.attributes = attributes;
        self
    }

    /// Creates a child resource (for example `host -> port` or `URL -> endpoint`).
    /// Its identity is namespaced by the already scope-checked parent asset.
    pub fn child(
        kind: AssetKind,
        parent: &AssetId,
        local_identity: impl AsRef<str>,
        provenance: Provenance,
    ) -> Result<Self, ModelError> {
        if parent.0.trim().is_empty() {
            return Err(ModelError::InvalidAssetIdentity);
        }
        if matches!(kind, AssetKind::Host | AssetKind::Ip | AssetKind::Url) {
            return Err(ModelError::ChildAssetMustHaveParentKind);
        }
        let local_identity = canonical_identity(&kind, local_identity.as_ref())?;
        let identity = format!("{}:{}", parent.0, local_identity);
        let id = AssetId(format!(
            "asset_{}_{}",
            kind_name(&kind),
            stable_hash(&format!("{}:{identity}", kind_name(&kind)))
        ));
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            id,
            kind,
            identity,
            attributes: BTreeMap::new(),
            first_seen: provenance.timestamp,
            last_seen: provenance.timestamp,
            provenance,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Confidence(pub u8);
impl Confidence {
    pub fn new(value: u8) -> Result<Self, ModelError> {
        (value <= 100)
            .then_some(Self(value))
            .ok_or(ModelError::InvalidConfidence(value))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub schema_version: u16,
    pub id: FindingId,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub affected_asset_id: AssetId,
    #[serde(default)]
    pub evidence_ids: Vec<EvidenceId>,
    pub provenance: Provenance,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}
impl Finding {
    pub fn new(
        title: impl Into<String>,
        severity: Severity,
        confidence: Confidence,
        affected_asset_id: AssetId,
        provenance: Provenance,
    ) -> Result<Self, ModelError> {
        let title = title.into();
        if title.trim().is_empty() || affected_asset_id.0.trim().is_empty() {
            return Err(ModelError::InvalidFinding);
        }
        let id = FindingId(format!(
            "finding_{}",
            stable_hash(&format!(
                "{}:{}:{}",
                provenance.module_name, title, affected_asset_id.0
            ))
        ));
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            id,
            title,
            severity,
            confidence,
            affected_asset_id,
            evidence_ids: Vec::new(),
            first_seen: provenance.timestamp,
            last_seen: provenance.timestamp,
            provenance,
            metadata: BTreeMap::new(),
            remediation: None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoundedDetails {
    pub data: Value,
    pub captured_bytes: usize,
    pub original_bytes: usize,
    pub truncated: bool,
}
impl BoundedDetails {
    pub fn from_value(data: Value, max_bytes: usize) -> Result<Self, ModelError> {
        let captured_bytes = serde_json::to_vec(&data)
            .map_err(|_| ModelError::InvalidDetails)?
            .len();
        if captured_bytes > max_bytes {
            return Err(ModelError::DetailsTooLarge {
                actual: captured_bytes,
                limit: max_bytes,
            });
        }
        Ok(Self {
            data,
            captured_bytes,
            original_bytes: captured_bytes,
            truncated: false,
        })
    }
    pub fn from_text(text: &str, max_bytes: usize) -> Self {
        let original_bytes = text.len();
        let end = original_bytes.min(max_bytes);
        let mut boundary = end;
        while boundary > 0 && !text.is_char_boundary(boundary) {
            boundary -= 1;
        }
        Self {
            data: Value::String(text[..boundary].to_owned()),
            captured_bytes: boundary,
            original_bytes,
            truncated: boundary < original_bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub schema_version: u16,
    pub id: EvidenceId,
    pub source: String,
    pub timestamp: Timestamp,
    pub asset_id: AssetId,
    pub details: BoundedDetails,
    pub confidence: Confidence,
    pub provenance: Provenance,
}
impl Evidence {
    pub fn new(
        source: impl Into<String>,
        asset_id: AssetId,
        details: BoundedDetails,
        confidence: Confidence,
        provenance: Provenance,
    ) -> Result<Self, ModelError> {
        let source = source.into();
        if source.trim().is_empty() || asset_id.0.trim().is_empty() {
            return Err(ModelError::InvalidEvidence);
        }
        if details.captured_bytes > MAX_EVIDENCE_DETAILS_BYTES {
            return Err(ModelError::DetailsTooLarge {
                actual: details.captured_bytes,
                limit: MAX_EVIDENCE_DETAILS_BYTES,
            });
        }
        let id = EvidenceId(format!(
            "evidence_{}",
            stable_hash(&format!(
                "{}:{}:{}",
                source,
                asset_id.0,
                serde_json::to_string(&details.data).map_err(|_| ModelError::InvalidDetails)?
            ))
        ));
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            id,
            source,
            timestamp: provenance.timestamp,
            asset_id,
            details,
            confidence,
            provenance,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipKind {
    Exposes,
    Runs,
    BelongsTo,
    DiscoveredFrom,
    Affects,
    Supports,
    Other,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "subject_type", content = "id", rename_all = "snake_case")]
pub enum RelationshipSubject {
    Asset(AssetId),
    Finding(FindingId),
    Evidence(EvidenceId),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relationship {
    pub kind: RelationshipKind,
    pub from: RelationshipSubject,
    pub to: RelationshipSubject,
    pub provenance: Provenance,
}
impl Relationship {
    pub fn new(
        kind: RelationshipKind,
        from: RelationshipSubject,
        to: RelationshipSubject,
        provenance: Provenance,
    ) -> Result<Self, ModelError> {
        if from == to {
            return Err(ModelError::SelfRelationship);
        }
        Ok(Self {
            kind,
            from,
            to,
            provenance,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    HostDiscovered,
    PortDiscovered,
    ServiceIdentified,
    HttpResponseObserved,
    TlsInformationObserved,
    DnsInformationObserved,
    EndpointDiscovered,
    DirectoryPathDiscovered,
    TechnologyFingerprintDetected,
    CrawlResult,
    FuzzResult,
    FindingCreated,
    EvidenceCollected,
    // Phase 5 host-discovery lifecycle (typed, quiet by default; verbose in
    // JSONL). `HostDiscovered` is retained for Alive hosts;
    // `HostStateConcluded` carries the final Alive/Unreachable/Unknown state
    // with confidence, techniques, latency, and evidence for every host.
    DiscoveryStarted,
    ProbeAttempted,
    ProbeSucceeded,
    ProbeTimedOut,
    ProbeUnavailable,
    HostStateConcluded,
    // Phase 6 TCP port-discovery lifecycle. Per-port outcome events are
    // emitted for small scans; huge scans emit opens + a completed summary
    // so JSONL stays bounded. Terminal output shows opens only.
    PortScanStarted,
    PortProbeAttempted,
    PortOpen,
    PortClosed,
    PortTimedOut,
    PortProbeError,
    PortScanCompleted,
    // Phase 7 service-intelligence lifecycle. Per-probe outcome events stay
    // in JSONL (quiet on the terminal); the human table shows one row per
    // classified service with product hints, never guessed versions.
    // (`ServiceIdentified` from the Phase 2 model is reused for
    // classifications, with a Port→Service `Runs` relationship attached.)
    ServiceProbeStarted,
    ProtocolDetected,
    BannerObserved,
    ServiceProbeTimedOut,
    ServiceProbeUnavailable,
    ServiceProbeError,
    TlsObserved,
    HttpObserved,
    ServiceProbeCompleted,
    // Phase 8 web-foundation lifecycle. Per-URL observations stay in JSONL
    // (quiet on the terminal); redirects are first-class events so chains,
    // loops, caps, and out-of-scope stops are all auditable.
    WebProbeStarted,
    WebProbeCompleted,
    RedirectObserved,
    EndpointObserved,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub schema_version: u16,
    pub kind: EventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<AssetId>,
    pub details: BoundedDetails,
    #[serde(default)]
    pub relationships: Vec<Relationship>,
    pub provenance: Provenance,
}
impl Event {
    pub fn new(
        kind: EventKind,
        asset_id: Option<AssetId>,
        details: BoundedDetails,
        provenance: Provenance,
    ) -> Result<Self, ModelError> {
        if details.captured_bytes > MAX_EVENT_DETAILS_BYTES {
            return Err(ModelError::DetailsTooLarge {
                actual: details.captured_bytes,
                limit: MAX_EVENT_DETAILS_BYTES,
            });
        }
        if asset_id.as_ref().is_some_and(|id| id.0.trim().is_empty()) {
            return Err(ModelError::InvalidEvent);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            kind,
            asset_id,
            details,
            relationships: Vec::new(),
            provenance,
        })
    }
}

impl JsonLine for Asset {}
impl JsonLine for Finding {}
impl JsonLine for Evidence {}
impl JsonLine for Relationship {}
impl JsonLine for Event {}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ModelError {
    #[error("only host, IP, and URL assets may be roots; create other assets from a parent")]
    RootAssetMustBeScoped,
    #[error("host, IP, and URL assets must be created through the Scope Guard")]
    ChildAssetMustHaveParentKind,
    #[error("asset identity is invalid for its kind")]
    InvalidAssetIdentity,
    #[error("asset is outside the current Scope Guard")]
    OutsideScope,
    #[error("module name, version, and plan ID are required")]
    MissingProvenance,
    #[error("confidence must be 0..=100, got {0}")]
    InvalidConfidence(u8),
    #[error("finding requires a title and affected asset")]
    InvalidFinding,
    #[error("evidence requires a source and associated asset")]
    InvalidEvidence,
    #[error("event has invalid data")]
    InvalidEvent,
    #[error("details are invalid JSON")]
    InvalidDetails,
    #[error("details are {actual} bytes; the limit is {limit}")]
    DetailsTooLarge { actual: usize, limit: usize },
    #[error("a relationship cannot refer to itself")]
    SelfRelationship,
    #[error("could not serialize model record")]
    Serialization,
}

fn canonical_identity(kind: &AssetKind, raw: &str) -> Result<String, ModelError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(ModelError::InvalidAssetIdentity);
    }
    match kind {
        AssetKind::Host => Ok(raw.trim_end_matches('.').to_ascii_lowercase()),
        AssetKind::Ip => raw
            .parse::<IpAddr>()
            .map(|ip| ip.to_string())
            .map_err(|_| ModelError::InvalidAssetIdentity),
        AssetKind::Url => {
            let mut url = Url::parse(raw).map_err(|_| ModelError::InvalidAssetIdentity)?;
            url.set_fragment(None);
            Ok(url.to_string())
        }
        AssetKind::Endpoint => raw
            .starts_with('/')
            .then(|| raw.to_owned())
            .ok_or(ModelError::InvalidAssetIdentity),
        AssetKind::Port => raw
            .parse::<u16>()
            .ok()
            .filter(|p| *p > 0)
            .map(|p| p.to_string())
            .ok_or(ModelError::InvalidAssetIdentity),
        _ => Ok(raw.to_owned()),
    }
}
fn enforce_scope(kind: &AssetKind, identity: &str, scope: &ScopePolicy) -> Result<(), ModelError> {
    let permitted = match kind {
        AssetKind::Host => scope.permits(None, Some(identity)),
        AssetKind::Ip => scope.permits(identity.parse().ok(), None),
        AssetKind::Url => {
            let url = Url::parse(identity).map_err(|_| ModelError::InvalidAssetIdentity)?;
            match url.host_str() {
                Some(host) => match host.parse() {
                    Ok(ip) => scope.permits(Some(ip), None),
                    Err(_) => scope.permits(None, Some(host)),
                },
                None => false,
            }
        }
        _ => true,
    };
    permitted.then_some(()).ok_or(ModelError::OutsideScope)
}
fn kind_name(kind: &AssetKind) -> &'static str {
    match kind {
        AssetKind::Host => "host",
        AssetKind::Ip => "ip",
        AssetKind::Port => "port",
        AssetKind::Service => "service",
        AssetKind::Url => "url",
        AssetKind::Endpoint => "endpoint",
        AssetKind::Certificate => "certificate",
        AssetKind::Technology => "technology",
        AssetKind::Other => "other",
    }
}
fn stable_hash(input: &str) -> String {
    stable_hash_bytes(input.as_bytes())
}
fn stable_hash_bytes(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}
