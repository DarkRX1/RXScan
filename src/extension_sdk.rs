//! Extension SDK (Phase 8): versioned interface for fingerprints and
//! bounded public-source transforms.
//!
//! Two extension kinds, one permission model:
//!
//! * **Fingerprint packs** (`kind = "fingerprint_pack"`): JSON service
//!   fingerprint rules validated by the same loader as built-in packs,
//!   stamped with the extension id as provenance.
//! * **Public transforms** (`kind = "public_transform"`): in-process
//!   [`ExtensionTransform`] implementations. No `dlopen`, no WASM, no
//!   subprocesses — the SDK is traits plus a manifest, and every contact
//!   flows through [`ExtensionContext`], which enforces the compiled
//!   [`ScopeGrant`] before touching the network.
//!
//! Permission model: the manifest *declares* required contact
//! ([`ExtensionContact`]) and hosts; the operator *grants* a subset at
//! load time ([`ScopeGrant::compile`]). Undeclared or ungranted contact
//! is rejected before any packet moves ([`ExtensionError::PermissionDenied`]).
//! Grants are deny-by-default, request-counted, deadline- and
//! cancellation-aware. Derived confidence never exceeds
//! [`EXTENSION_CONFIDENCE_CAP`] (below native observation strength).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Extension SDK interface version. Manifests must declare exactly this.
pub const EXTENSION_SDK_VERSION: u32 = 1;
/// Maximum manifest file size.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// Maximum HTTP response body an extension may read.
pub const MAX_EXTENSION_RESPONSE_BYTES: usize = 256 * 1024;
/// Maximum requests per grant (hard ceiling; manifests request fewer).
pub const MAX_EXTENSION_REQUESTS: u32 = 1000;
/// Derived extension confidence never exceeds this.
pub const EXTENSION_CONFIDENCE_CAP: u8 = 70;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionError {
    TooLarge(String),
    Malformed(String),
    SchemaMismatch { expected: u32, found: u32 },
    DuplicateId(String),
    PermissionDenied(String),
    BudgetExceeded(String),
    Deadline,
    Cancelled,
    ContactFailed(String),
    InvalidHost(String),
}

impl std::fmt::Display for ExtensionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge(detail) => write!(f, "extension too large: {detail}"),
            Self::Malformed(detail) => write!(f, "malformed extension: {detail}"),
            Self::SchemaMismatch { expected, found } => {
                write!(f, "extension SDK schema {found} != expected {expected}")
            }
            Self::DuplicateId(id) => write!(f, "duplicate extension id '{id}'"),
            Self::PermissionDenied(detail) => write!(f, "extension permission denied: {detail}"),
            Self::BudgetExceeded(detail) => write!(f, "extension budget exceeded: {detail}"),
            Self::Deadline => write!(f, "extension deadline expired"),
            Self::Cancelled => write!(f, "extension cancelled"),
            Self::ContactFailed(detail) => write!(f, "extension contact failed: {detail}"),
            Self::InvalidHost(host) => write!(f, "invalid extension host '{host}'"),
        }
    }
}

// ---------------------------------------------------------------------------
// Manifest.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionKind {
    FingerprintPack,
    PublicTransform,
}

impl ExtensionKind {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "fingerprint_pack" => Some(Self::FingerprintPack),
            "public_transform" => Some(Self::PublicTransform),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FingerprintPack => "fingerprint_pack",
            Self::PublicTransform => "public_transform",
        }
    }
}

/// Contact classes an extension may declare, narrowest to broadest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExtensionContact {
    LocalOnly,
    Dns,
    PublicHttp,
}

impl ExtensionContact {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "local_only" | "none" => Some(Self::LocalOnly),
            "dns" => Some(Self::Dns),
            "public_http" | "https" => Some(Self::PublicHttp),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalOnly => "local_only",
            Self::Dns => "dns",
            Self::PublicHttp => "public_http",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeRequest {
    pub contact: ExtensionContact,
    pub hosts: Vec<String>,
    pub max_requests: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionManifest {
    pub sdk_version: u32,
    pub id: String,
    pub version: String,
    pub kind: ExtensionKind,
    pub description: String,
    pub requires: ScopeRequest,
}

fn valid_id(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

fn valid_host(text: &str) -> bool {
    let host = text.trim().trim_end_matches('.');
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Parse and strictly validate an extension manifest.
pub fn parse_manifest(text: &str) -> Result<ExtensionManifest, ExtensionError> {
    if text.len() > MAX_MANIFEST_BYTES {
        return Err(ExtensionError::TooLarge(format!(
            "manifest {} bytes exceeds {MAX_MANIFEST_BYTES}",
            text.len()
        )));
    }
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|error| ExtensionError::Malformed(format!("manifest is not JSON: {error}")))?;
    let get = |key: &str| {
        value
            .get(key)
            .ok_or_else(|| ExtensionError::Malformed(format!("manifest lacks '{key}'")))
    };
    let sdk_version = get("sdk_version")?
        .as_u64()
        .ok_or_else(|| ExtensionError::Malformed("sdk_version must be a number".to_owned()))?
        as u32;
    if sdk_version != EXTENSION_SDK_VERSION {
        return Err(ExtensionError::SchemaMismatch {
            expected: EXTENSION_SDK_VERSION,
            found: sdk_version,
        });
    }
    let id = get("id")?
        .as_str()
        .ok_or_else(|| ExtensionError::Malformed("id must be a string".to_owned()))?;
    if !valid_id(id) {
        return Err(ExtensionError::Malformed("invalid extension id".to_owned()));
    }
    let version = get("version")?
        .as_str()
        .ok_or_else(|| ExtensionError::Malformed("version must be a string".to_owned()))?;
    if version.is_empty() || version.len() > 32 {
        return Err(ExtensionError::Malformed(
            "invalid extension version".to_owned(),
        ));
    }
    let kind = get("kind")?
        .as_str()
        .ok_or_else(|| ExtensionError::Malformed("kind must be a string".to_owned()))?;
    let kind = ExtensionKind::parse(kind)
        .ok_or_else(|| ExtensionError::Malformed("unknown extension kind".to_owned()))?;
    let description = get("description")?
        .as_str()
        .ok_or_else(|| ExtensionError::Malformed("description must be a string".to_owned()))?;
    if description.is_empty() || description.len() > 512 {
        return Err(ExtensionError::Malformed("invalid description".to_owned()));
    }
    let requires = value.get("requires").ok_or_else(|| {
        ExtensionError::Malformed("manifest lacks 'requires' scope declaration".to_owned())
    })?;
    let contact = requires
        .get("contact")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ExtensionError::Malformed("requires.contact must be a string".to_owned()))?;
    let contact = ExtensionContact::parse(contact)
        .ok_or_else(|| ExtensionError::Malformed("unknown requires.contact".to_owned()))?;
    let mut hosts = Vec::new();
    if let Some(list) = requires.get("hosts") {
        let list = list.as_array().ok_or_else(|| {
            ExtensionError::Malformed("requires.hosts must be an array".to_owned())
        })?;
        if list.len() > 64 {
            return Err(ExtensionError::Malformed(
                "too many requires.hosts".to_owned(),
            ));
        }
        for host in list {
            let host = host
                .as_str()
                .ok_or_else(|| ExtensionError::Malformed("host must be a string".to_owned()))?;
            if !valid_host(host) {
                return Err(ExtensionError::InvalidHost(host.to_owned()));
            }
            hosts.push(host.trim().trim_end_matches('.').to_ascii_lowercase());
        }
        hosts.sort();
        hosts.dedup();
    }
    if contact != ExtensionContact::LocalOnly && hosts.is_empty() {
        return Err(ExtensionError::Malformed(
            "contact beyond local_only requires at least one host".to_owned(),
        ));
    }
    let max_requests = requires
        .get("max_requests")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(10) as u32;
    if max_requests == 0 || max_requests > MAX_EXTENSION_REQUESTS {
        return Err(ExtensionError::Malformed(format!(
            "max_requests must be 1..={MAX_EXTENSION_REQUESTS}"
        )));
    }
    Ok(ExtensionManifest {
        sdk_version,
        id: id.to_owned(),
        version: version.to_owned(),
        kind,
        description: description.to_owned(),
        requires: ScopeRequest {
            contact,
            hosts,
            max_requests,
        },
    })
}

// ---------------------------------------------------------------------------
// Scope grants: declare vs allow, enforced at every contact.
// ---------------------------------------------------------------------------

/// Compiled operator grant for one manifest. Deny-by-default: only
/// declared contact classes to explicitly allowed hosts, up to the
/// declared request budget.
pub struct ScopeGrant {
    extension_id: String,
    contact: ExtensionContact,
    hosts: BTreeSet<String>,
    max_requests: u32,
    used: AtomicUsize,
}

impl ScopeGrant {
    /// Compile a grant: the operator allows `contact` and each host in
    /// `allowed_hosts` (case-insensitive). Every host the manifest
    /// requires must be allowed, or compilation fails — no partial
    /// grants, no silent narrowing.
    pub fn compile(
        manifest: &ExtensionManifest,
        allow_contact: ExtensionContact,
        allowed_hosts: &[String],
    ) -> Result<Self, ExtensionError> {
        if allow_contact < manifest.requires.contact {
            return Err(ExtensionError::PermissionDenied(format!(
                "extension '{}' requires {}, operator allows {}",
                manifest.id,
                manifest.requires.contact.as_str(),
                allow_contact.as_str()
            )));
        }
        let allowed: BTreeSet<String> = allowed_hosts
            .iter()
            .map(|host| host.trim().trim_end_matches('.').to_ascii_lowercase())
            .collect();
        for host in &manifest.requires.hosts {
            if !allowed.contains(host) {
                return Err(ExtensionError::PermissionDenied(format!(
                    "extension '{}' requires host '{host}', not granted",
                    manifest.id
                )));
            }
        }
        Ok(Self {
            extension_id: manifest.id.clone(),
            contact: manifest.requires.contact,
            hosts: manifest.requires.hosts.iter().cloned().collect(),
            max_requests: manifest.requires.max_requests,
            used: AtomicUsize::new(0),
        })
    }

    pub fn extension_id(&self) -> &str {
        &self.extension_id
    }

    pub fn requests_used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    /// Enforce the grant for one contact attempt. Counts admitted
    /// requests; anything undeclared, ungranted, or over budget is
    /// rejected before contact.
    pub fn check(&self, contact: ExtensionContact, host: &str) -> Result<(), ExtensionError> {
        if contact > self.contact {
            return Err(ExtensionError::PermissionDenied(format!(
                "{} contact exceeds granted {}",
                contact.as_str(),
                self.contact.as_str()
            )));
        }
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if !self.hosts.contains(&host) {
            return Err(ExtensionError::PermissionDenied(format!(
                "host '{host}' not in grant for '{}'",
                self.extension_id
            )));
        }
        let used = self.used.fetch_add(1, Ordering::AcqRel);
        if used >= self.max_requests as usize {
            return Err(ExtensionError::BudgetExceeded(format!(
                "grant budget {} requests exhausted",
                self.max_requests
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Transform interface.
// ---------------------------------------------------------------------------

/// Input entity for an extension transform (plain values, no core
/// internals leak across the boundary).
#[derive(Debug, Clone)]
pub struct TransformInput {
    pub entity_id: String,
    pub stored_kind: String,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputEntity {
    /// Suffix namespaced by the SDK as `ext:<manifest-id>:<suffix>`.
    pub id_suffix: String,
    pub stored_kind: String,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputRelationship {
    /// Endpoint suffixes (same namespace as entities).
    pub from_suffix: String,
    pub to_suffix: String,
    pub stored_relation: String,
    pub confidence: u8,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ExtensionOutput {
    pub entities: Vec<OutputEntity>,
    pub relationships: Vec<OutputRelationship>,
}

/// Bounded execution context: the ONLY contact surface transforms get.
/// Every method enforces the grant, deadline, cancellation, and size
/// caps before acting.
pub struct ExtensionContext<'a> {
    pub grant: &'a ScopeGrant,
    pub deadline: Instant,
    pub cancelled: &'a AtomicBool,
    pub now: u64,
}

impl ExtensionContext<'_> {
    fn preflight(&self, contact: ExtensionContact, host: &str) -> Result<(), ExtensionError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(ExtensionError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(ExtensionError::Deadline);
        }
        self.grant.check(contact, host)
    }

    /// Grant-checked HTTPS GET (loopback literals may use HTTP; anything
    /// else over plaintext is rejected). Bounded time and body. The port
    /// rides separately so grants match on host identity, not sockets.
    pub fn http_get(&self, host: &str, port: u16, path: &str) -> Result<String, ExtensionError> {
        if port == 0 {
            return Err(ExtensionError::Malformed(
                "port must be 1..=65535".to_owned(),
            ));
        }
        if !path.starts_with('/') || path.bytes().any(|b| b <= 0x20) {
            return Err(ExtensionError::Malformed(
                "request path must start with /".to_owned(),
            ));
        }
        if path.len() > 1024 {
            return Err(ExtensionError::Malformed(
                "request path too long".to_owned(),
            ));
        }
        self.preflight(ExtensionContact::PublicHttp, host)?;
        let loopback = host == "127.0.0.1" || host == "::1" || host == "localhost";
        let scheme = if loopback { "http" } else { "https" };
        if !loopback && !valid_host(host) {
            return Err(ExtensionError::InvalidHost(host.to_owned()));
        }
        let url = format!("{scheme}://{host}:{port}{path}");
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ExtensionError::Deadline);
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(remaining.min(Duration::from_secs(10)))
            .no_proxy()
            .build()
            .map_err(|error| ExtensionError::ContactFailed(error.to_string()))?;
        let response = client
            .get(&url)
            .send()
            .map_err(|error| ExtensionError::ContactFailed(error.to_string()))?;
        if !response.status().is_success() {
            return Err(ExtensionError::ContactFailed(format!(
                "HTTP {}",
                response.status()
            )));
        }
        let body = response
            .text()
            .map_err(|error| ExtensionError::ContactFailed(error.to_string()))?;
        if body.len() > MAX_EXTENSION_RESPONSE_BYTES {
            return Err(ExtensionError::ContactFailed(
                "response exceeds 256 KiB".to_owned(),
            ));
        }
        Ok(body)
    }

    /// Grant-checked DNS lookup (system resolver). Returns up to 16
    /// addresses as text; never panics on resolver output.
    pub fn dns_lookup(&self, host: &str) -> Result<Vec<String>, ExtensionError> {
        self.preflight(ExtensionContact::Dns, host)?;
        if !valid_host(host) {
            return Err(ExtensionError::InvalidHost(host.to_owned()));
        }
        use std::net::ToSocketAddrs as _;
        let mut out = Vec::new();
        let addresses = (host, 0)
            .to_socket_addrs()
            .map_err(|error| ExtensionError::ContactFailed(error.to_string()))?;
        for address in addresses.take(16) {
            out.push(address.ip().to_string());
        }
        if out.is_empty() {
            return Err(ExtensionError::ContactFailed("no addresses".to_owned()));
        }
        Ok(out)
    }
}

/// Extension transform: pure logic plus grant-checked context contact.
pub trait ExtensionTransform: Send + Sync {
    fn manifest(&self) -> &ExtensionManifest;
    fn execute(
        &self,
        ctx: &ExtensionContext<'_>,
        input: &TransformInput,
    ) -> Result<ExtensionOutput, ExtensionError>;
}

/// Versioned registry: manifests are checked on registration (SDK
/// version match, no duplicate ids).
#[derive(Default)]
pub struct ExtensionRegistry {
    manifests: BTreeMap<String, ExtensionManifest>,
}

impl ExtensionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, manifest: ExtensionManifest) -> Result<(), ExtensionError> {
        if manifest.sdk_version != EXTENSION_SDK_VERSION {
            return Err(ExtensionError::SchemaMismatch {
                expected: EXTENSION_SDK_VERSION,
                found: manifest.sdk_version,
            });
        }
        if self.manifests.contains_key(&manifest.id) {
            return Err(ExtensionError::DuplicateId(manifest.id));
        }
        self.manifests.insert(manifest.id.clone(), manifest);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&ExtensionManifest> {
        self.manifests.get(id)
    }

    pub fn list(&self) -> Vec<&ExtensionManifest> {
        self.manifests.values().collect()
    }

    pub fn len(&self) -> usize {
        self.manifests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.manifests.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Fingerprint packs through the shared validator, stamped by extension.
// ---------------------------------------------------------------------------

/// Extension fingerprint rules: validated by the same loader as
/// built-in packs, with the extension id as provenance.
#[derive(Debug, Clone)]
pub struct ExtensionFingerprints {
    pub extension_id: String,
    pub packs: Vec<(String, crate::fingerprints::FingerprintPack)>,
}

/// Load an extension fingerprint directory (bounded reads, schema and
/// duplicate checks via the shared loader).
pub fn load_extension_fingerprints(
    extension_id: &str,
    dir: &std::path::Path,
) -> Result<ExtensionFingerprints, ExtensionError> {
    if !valid_id(extension_id) {
        return Err(ExtensionError::Malformed("invalid extension id".to_owned()));
    }
    let packs = crate::fingerprints::load_dir(dir)
        .map_err(|error| ExtensionError::Malformed(format!("fingerprint pack invalid: {error}")))?;
    Ok(ExtensionFingerprints {
        extension_id: extension_id.to_owned(),
        packs,
    })
}

/// Namespace an extension entity suffix (`ext:<id>:<suffix>`, bounded).
pub fn extension_entity_id(manifest_id: &str, suffix: &str) -> String {
    let suffix: String = suffix.chars().take(256).collect();
    format!(
        "ext:{}:{suffix}",
        manifest_id.chars().take(64).collect::<String>()
    )
}

/// Cap extension-derived confidence (never above
/// [`EXTENSION_CONFIDENCE_CAP`], never above the native floor it
/// cites — callers pass the cited native confidence when fusing).
pub fn cap_extension_confidence(confidence: u8) -> u8 {
    confidence.min(EXTENSION_CONFIDENCE_CAP)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"{
        "sdk_version": 1,
        "id": "demo-rdss",
        "version": "0.1.0",
        "kind": "public_transform",
        "description": "Demonstration transform with bounded public contact.",
        "requires": {
            "contact": "public_http",
            "hosts": ["127.0.0.1"],
            "max_requests": 4
        }
    }"#;

    #[test]
    fn manifest_parses_and_validates() {
        let manifest = parse_manifest(MANIFEST).unwrap();
        assert_eq!(manifest.id, "demo-rdss");
        assert_eq!(manifest.requires.contact, ExtensionContact::PublicHttp);
        assert_eq!(manifest.requires.hosts, vec!["127.0.0.1".to_owned()]);
        // Wrong SDK version is a schema mismatch, not a parse.
        let newer = MANIFEST.replace("\"sdk_version\": 1", "\"sdk_version\": 99");
        assert!(matches!(
            parse_manifest(&newer),
            Err(ExtensionError::SchemaMismatch {
                expected: 1,
                found: 99
            })
        ));
        // Missing scope declaration is malformed.
        assert!(parse_manifest(r#"{"sdk_version":1,"id":"a","version":"1","kind":"public_transform","description":"d"}"#).is_err());
        // Contact without hosts is malformed.
        let no_hosts = MANIFEST.replace("\"hosts\": [\"127.0.0.1\"]", "\"hosts\": []");
        assert!(parse_manifest(&no_hosts).is_err());
        // Oversize manifests rejected before parsing.
        assert!(matches!(
            parse_manifest(&" ".repeat(MAX_MANIFEST_BYTES + 1)),
            Err(ExtensionError::TooLarge(_))
        ));
    }

    #[test]
    fn grants_are_deny_by_default_and_counted() {
        let manifest = parse_manifest(MANIFEST).unwrap();
        // Operator grants less contact than required: compile fails.
        assert!(
            ScopeGrant::compile(&manifest, ExtensionContact::Dns, &["127.0.0.1".to_owned()])
                .is_err()
        );
        // Operator omits a required host: compile fails.
        assert!(
            ScopeGrant::compile(
                &manifest,
                ExtensionContact::PublicHttp,
                &["other.test".to_owned()]
            )
            .is_err()
        );
        let grant = ScopeGrant::compile(
            &manifest,
            ExtensionContact::PublicHttp,
            &["127.0.0.1".to_owned()],
        )
        .unwrap();
        // Granted contact works up to budget, then stops.
        for _ in 0..4 {
            grant
                .check(ExtensionContact::PublicHttp, "127.0.0.1")
                .unwrap();
        }
        assert!(
            grant
                .check(ExtensionContact::PublicHttp, "127.0.0.1")
                .is_err()
        );
        assert_eq!(grant.requests_used(), 5);
        // Ungranted hosts rejected without counting.
        let grant = ScopeGrant::compile(
            &manifest,
            ExtensionContact::PublicHttp,
            &["127.0.0.1".to_owned()],
        )
        .unwrap();
        assert!(
            grant
                .check(ExtensionContact::PublicHttp, "evil.test")
                .is_err()
        );
        assert_eq!(grant.requests_used(), 0);
        // Narrower contact within a broader grant is fine.
        grant.check(ExtensionContact::Dns, "127.0.0.1").unwrap();
    }

    #[test]
    fn registry_versions_and_dedupes() {
        let mut registry = ExtensionRegistry::new();
        assert!(registry.is_empty());
        let manifest = parse_manifest(MANIFEST).unwrap();
        registry.register(manifest.clone()).unwrap();
        assert!(registry.register(manifest).is_err());
        assert_eq!(registry.len(), 1);
        assert!(registry.get("demo-rdss").is_some());
    }

    #[test]
    fn confidence_capped_and_ids_namespaced() {
        assert_eq!(cap_extension_confidence(95), EXTENSION_CONFIDENCE_CAP);
        assert_eq!(cap_extension_confidence(40), 40);
        assert_eq!(extension_entity_id("demo", "thing"), "ext:demo:thing");
    }

    #[test]
    fn out_of_scope_contact_rejected_before_network() {
        let manifest = parse_manifest(MANIFEST).unwrap();
        // Grant covers only the manifest host; ungranted.test is outside.
        let grant = ScopeGrant::compile(
            &manifest,
            ExtensionContact::PublicHttp,
            &["127.0.0.1".to_owned()],
        )
        .unwrap();
        let cancelled = AtomicBool::new(false);
        let used_before = grant.requests_used();
        let ctx = ExtensionContext {
            grant: &grant,
            deadline: Instant::now() + Duration::from_secs(5),
            cancelled: &cancelled,
            now: 1,
        };
        // Direct denial path (no listener on 127.0.0.1 here either, but
        // the ungranted host must fail as PermissionDenied specifically).
        let error = ctx.http_get("ungranted.test", 443, "/").unwrap_err();
        assert!(matches!(error, ExtensionError::PermissionDenied(_)));
        // Denied attempts never consume budget.
        assert_eq!(grant.requests_used(), used_before);
    }
}
