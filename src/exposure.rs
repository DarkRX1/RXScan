//! Stage 3 defensive exposure intelligence.
//!
//! Correlates operator-supplied identifiers (email, username, domain)
//! against legitimate, configured exposure-intelligence sources: breach
//! intelligence, infostealer/malware observations, credential- and
//! session-exposure indicators, and operator-supplied local datasets.
//!
//! Hard boundaries (never relaxed):
//!
//! * No scraping of criminal leak forums or stolen-database archives, no
//!   access-control bypass, no credential marketplace interface.
//! * Exposure may report that secret material was exposed. It must never
//!   persist, display, or replay usable secret material (passwords,
//!   hashes, cookies, tokens, keys, recovery codes, card data). Provider
//!   responses carrying secrets are normalized to boolean metadata
//!   (`credential_material_exposed`), then the secrets are dropped.
//! * Raw provider responses are never persisted (`store_raw_response`
//!   defaults to false and has no opt-in in this phase).
//! * External queries that send identifiers to third parties are opt-in:
//!   ordinary passive investigation never performs them unless the
//!   operator passes `--exposure`. `--explain` always discloses which
//!   providers send which identifiers where.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::graph::{EdgeRelation, EntityKind};
use crate::search::ContactClass;

// ---------------------------------------------------------------------------
// Identifiers and normalized exposure types.
// ---------------------------------------------------------------------------

/// Identifier classes exposure providers can be queried with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierKind {
    Email,
    Username,
    Domain,
}

impl IdentifierKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Username => "username",
            Self::Domain => "domain",
        }
    }
}

/// Normalized exposure classes. These describe *that* exposure happened
/// and *what field types* were affected — never secret values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposureType {
    Breach,
    Infostealer,
    Credential,
    Session,
    Paste,
    Malware,
}

impl ExposureType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Breach => "breach",
            Self::Infostealer => "infostealer",
            Self::Credential => "credential",
            Self::Session => "session",
            Self::Paste => "paste",
            Self::Malware => "malware",
        }
    }
}

/// Exposed *field types* (metadata, never values). The word `password`
/// here means "the provider reports password material was exposed".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposedField {
    Email,
    Username,
    Password,
    PasswordHash,
    BrowserSession,
    AuthToken,
    ApiKey,
    Phone,
    Address,
    PaymentCard,
    Device,
    Other,
}

impl ExposedField {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Username => "username",
            Self::Password => "password",
            Self::PasswordHash => "password_hash",
            Self::BrowserSession => "browser_session",
            Self::AuthToken => "auth_token",
            Self::ApiKey => "api_key",
            Self::Phone => "phone",
            Self::Address => "address",
            Self::PaymentCard => "payment_card",
            Self::Device => "device",
            Self::Other => "other",
        }
    }
}

// ---------------------------------------------------------------------------
// Secret-material policy: detect, classify, drop. Never retain.
// ---------------------------------------------------------------------------

/// Provider-response keys whose values are usable secret material and must
/// be dropped (presence still classifies the exposure type).
const SECRET_KEY_MARKERS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "pass_hash",
    "password_hash",
    "passhash",
    "session_cookie",
    "sessioncookie",
    "cookie",
    "cookies",
    "auth_token",
    "authtoken",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "secret",
    "private_key",
    "recovery_code",
    "security_answer",
    "card_number",
    "pan",
    "cvv",
    "stealer_log",
    "session_data",
];

fn is_secret_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect::<String>()
        .to_ascii_lowercase();
    SECRET_KEY_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker))
}

/// Keys safe to retain verbatim from a provider response (bounded).
const SAFE_KEYS: &[&str] = &[
    "source",
    "breach",
    "breach_name",
    "name",
    "title",
    "type",
    "exposure_type",
    "domain",
    "affected_domain",
    "targeted_domain",
    "malware",
    "malware_family",
    "family",
    "exposure_date",
    "breach_date",
    "first_observed",
    "last_observed",
    "description",
    "url",
    "count",
];

/// Normalized safe metadata extracted from one raw provider record.
/// Secret values are dropped; their presence becomes boolean metadata.
#[derive(Debug, Clone, Default)]
pub struct NormalizedRecord {
    pub safe_fields: BTreeMap<String, String>,
    pub exposed_fields: BTreeSet<ExposedField>,
    pub credential_material_exposed: bool,
    pub session_material_exposed: bool,
    pub secrets_dropped: usize,
}

pub fn normalize_record(value: &serde_json::Value) -> NormalizedRecord {
    let mut record = NormalizedRecord::default();
    let Some(object) = value.as_object() else {
        return record;
    };
    for (key, item) in object {
        if is_secret_key(key) {
            // Presence classifies; value is dropped, never retained.
            record.secrets_dropped += 1;
            classify_secret_presence(key, &mut record);
            continue;
        }
        if SAFE_KEYS.contains(&key.as_str()) {
            let text = match item {
                serde_json::Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            if !text.is_empty() && text.len() <= 512 {
                record.safe_fields.insert(key.clone(), text);
            }
        }
    }
    record
}

fn classify_secret_presence(key: &str, record: &mut NormalizedRecord) {
    let normalized = key.to_ascii_lowercase();
    if normalized.contains("password")
        || normalized.contains("passwd")
        || normalized.contains("pwd")
    {
        record.exposed_fields.insert(ExposedField::Password);
        record.credential_material_exposed = true;
    }
    if normalized.contains("hash") {
        record.exposed_fields.insert(ExposedField::PasswordHash);
        record.credential_material_exposed = true;
    }
    if normalized.contains("session") || normalized.contains("cookie") {
        record.exposed_fields.insert(ExposedField::BrowserSession);
        record.session_material_exposed = true;
    }
    if normalized.contains("token")
        || normalized.contains("api_key")
        || normalized.contains("apikey")
    {
        record.exposed_fields.insert(ExposedField::AuthToken);
        record.credential_material_exposed = true;
    }
    if normalized.contains("secret")
        || normalized.contains("private_key")
        || normalized.contains("recovery")
    {
        record.credential_material_exposed = true;
    }
    if normalized.contains("card") || normalized.contains("pan") || normalized.contains("cvv") {
        record.exposed_fields.insert(ExposedField::PaymentCard);
    }
}

/// Assert a rendered artifact carries no secret material. Used by tests
/// with unmistakably fake placeholder secrets.
#[cfg(test)]
pub fn assert_no_secrets(text: &str, secrets: &[&str]) {
    for secret in secrets {
        assert!(
            !text.contains(secret),
            "secret material leaked into artifact"
        );
    }
}

// ---------------------------------------------------------------------------
// Normalized exposure: the only thing that persists.
// ---------------------------------------------------------------------------

/// One normalized exposure observation. Contains metadata only:
/// `secret_material_retained` is always false by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedExposure {
    pub id: String,
    pub exposure_type: ExposureType,
    /// Provider/source name (e.g. configured API name, dataset path label).
    pub source: String,
    /// Upstream breach/dataset name when reported.
    pub source_name: Option<String>,
    pub identifier_type: IdentifierKind,
    /// SHA-256 of the queried identifier (raw identifiers never persist).
    pub identifier_hash: String,
    pub affected_domain: Option<String>,
    pub malware_family: Option<String>,
    pub exposed_fields: BTreeSet<ExposedField>,
    pub credential_material_exposed: bool,
    pub session_material_exposed: bool,
    pub secret_material_retained: bool,
    pub exposure_date: Option<String>,
    pub confidence: u8,
    pub timestamp: u64,
    #[serde(default)]
    pub evidence: Vec<String>,
}

impl NormalizedExposure {
    pub fn entity_kind(&self) -> EntityKind {
        EntityKind::Exposure
    }

    pub fn label(&self) -> String {
        match &self.source_name {
            Some(name) => format!(
                "{} exposure via {} ({})",
                self.exposure_type.as_str(),
                self.source,
                name
            ),
            None => format!(
                "{} exposure via {}",
                self.exposure_type.as_str(),
                self.source
            ),
        }
    }
}

pub fn identifier_hash(identifier: &str) -> String {
    use sha2::Digest as _;
    format!(
        "{:x}",
        sha2::Sha256::digest(identifier.trim().to_ascii_lowercase().as_bytes())
    )
}

pub fn exposure_entity_id(source: &str, exposure_type: ExposureType, id_hash: &str) -> String {
    let short = id_hash.chars().take(16).collect::<String>();
    format!(
        "exposure:{}:{}:{}",
        source.trim().to_ascii_lowercase(),
        exposure_type.as_str(),
        short
    )
}

pub fn exposure_source_id(source: &str) -> String {
    format!("exposuresource:{}", source.trim().to_ascii_lowercase())
}

// ---------------------------------------------------------------------------
// Provider abstraction (internal; no public plugin SDK yet).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExposureError {
    Unavailable(String),
    AuthRequired,
    RateLimited,
    Malformed(String),
    Deadline,
    Cancelled,
}

impl std::fmt::Display for ExposureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(detail) => write!(f, "provider unavailable: {detail}"),
            Self::AuthRequired => write!(f, "provider authentication required"),
            Self::RateLimited => write!(f, "provider rate limited"),
            Self::Malformed(detail) => write!(f, "malformed provider response: {detail}"),
            Self::Deadline => write!(f, "exposure deadline expired"),
            Self::Cancelled => write!(f, "exposure cancelled"),
        }
    }
}

pub struct ExposureContext<'a> {
    pub deadline: Instant,
    pub cancelled: &'a AtomicBool,
    pub now: u64,
}

/// Internal exposure-provider interface.
pub trait ExposureProvider: Send + Sync {
    fn id(&self) -> &'static str;
    fn accepts(&self, kind: IdentifierKind) -> bool;
    fn contact_class(&self) -> ContactClass;
    /// True when querying sends the identifier to a third party.
    fn sends_identifier(&self) -> bool;
    fn requires_auth(&self) -> bool;
    fn describe(&self) -> &'static str;
    fn query(
        &self,
        identifier: &str,
        kind: IdentifierKind,
        ctx: &ExposureContext<'_>,
    ) -> Result<(Vec<NormalizedExposure>, usize), ExposureError>;
}

/// Static provider metadata for planning, explain, and capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureProviderInfo {
    pub id: String,
    pub accepts: Vec<String>,
    pub contact_class: ContactClass,
    pub sends_identifier: bool,
    pub requires_auth: bool,
    pub available: bool,
    pub availability_detail: String,
    pub description: String,
}

// ---------------------------------------------------------------------------
// Fixture provider (deterministic tests, zero network).
// ---------------------------------------------------------------------------

/// Deterministic fixture provider. The `secret_record` carries
/// unmistakably fake secret values to prove redaction end to end.
pub struct FixtureExposureProvider {
    pub secret_record: serde_json::Value,
}

impl Default for FixtureExposureProvider {
    fn default() -> Self {
        Self {
            secret_record: serde_json::json!({
                "source": "fixture-breach",
                "breach_name": "FixtureBreach",
                "exposure_date": "2024-01-15",
                "password": "FAKE-SECRET-PW-0000",
                "password_hash": "FAKE-SECRET-HASH-0000",
                "session_cookie": "FAKE-SECRET-SESSION-0000",
                "api_key": "FAKE-SECRET-APIKEY-0000",
            }),
        }
    }
}

impl ExposureProvider for FixtureExposureProvider {
    fn id(&self) -> &'static str {
        "fixture-exposure"
    }
    fn accepts(&self, _kind: IdentifierKind) -> bool {
        true
    }
    fn contact_class(&self) -> ContactClass {
        ContactClass::LocalDataset
    }
    fn sends_identifier(&self) -> bool {
        false
    }
    fn requires_auth(&self) -> bool {
        false
    }
    fn describe(&self) -> &'static str {
        "deterministic fixture exposure source (tests only)"
    }
    fn query(
        &self,
        identifier: &str,
        kind: IdentifierKind,
        ctx: &ExposureContext<'_>,
    ) -> Result<(Vec<NormalizedExposure>, usize), ExposureError> {
        if ctx.cancelled.load(Ordering::Acquire) {
            return Err(ExposureError::Cancelled);
        }
        if Instant::now() >= ctx.deadline {
            return Err(ExposureError::Deadline);
        }
        // Only identifiers containing "exposed" match; everything else is
        // a clean no-match. Keeps match/no-match tests deterministic.
        if !identifier.to_ascii_lowercase().contains("exposed") {
            return Ok((Vec::new(), 0));
        }
        let record = normalize_record(&self.secret_record);
        let hash = identifier_hash(identifier);
        let mut exposures = vec![NormalizedExposure {
            id: exposure_entity_id("fixture-breach", ExposureType::Breach, &hash),
            exposure_type: ExposureType::Breach,
            source: "fixture-breach".to_owned(),
            source_name: record
                .safe_fields
                .get("breach_name")
                .or_else(|| record.safe_fields.get("source"))
                .cloned(),
            identifier_type: kind,
            identifier_hash: hash.clone(),
            affected_domain: None,
            malware_family: None,
            exposed_fields: record.exposed_fields.clone(),
            credential_material_exposed: record.credential_material_exposed,
            session_material_exposed: record.session_material_exposed,
            secret_material_retained: false,
            exposure_date: record.safe_fields.get("exposure_date").cloned(),
            confidence: 85,
            timestamp: ctx.now,
            evidence: vec!["fixture breach reports identifier exposure".to_owned()],
        }];
        // A provider-reported malware family becomes an infostealer
        // observation linked to the same identifier.
        exposures.push(NormalizedExposure {
            id: exposure_entity_id("fixture-stealer", ExposureType::Infostealer, &hash),
            exposure_type: ExposureType::Infostealer,
            source: "fixture-stealer".to_owned(),
            source_name: Some("FixtureStealerFeed".to_owned()),
            identifier_type: kind,
            identifier_hash: hash,
            affected_domain: Some("example.test".to_owned()),
            malware_family: Some("FixtureRat".to_owned()),
            exposed_fields: BTreeSet::from([ExposedField::BrowserSession, ExposedField::Password]),
            credential_material_exposed: true,
            session_material_exposed: true,
            secret_material_retained: false,
            exposure_date: None,
            confidence: 70,
            timestamp: ctx.now,
            evidence: vec!["fixture stealer feed reports session observation".to_owned()],
        });
        Ok((exposures, record.secrets_dropped))
    }
}

// ---------------------------------------------------------------------------
// Operator-supplied local dataset provider.
// ---------------------------------------------------------------------------

/// Bounded local exposure dataset. Explicitly supplied, local-only, never
/// uploaded. Schema (JSON):
///
/// ```json
/// { "exposures": [
///     { "identifier_type": "email", "identifier": "user@example.test",
///       "source": "operator-dataset", "exposure_type": "breach",
///       "source_name": "LocalList", "affected_domain": "example.test",
///       "malware_family": null, "exposure_date": "2024-01-01",
///       "confidence": 80, "record": { "password": "secret-if-any" } }
/// ] }
/// ```
///
/// The optional `record` object passes through the same secret
/// normalization: secrets classify, then are dropped.
pub struct LocalDatasetProvider {
    pub label: String,
    pub path: std::path::PathBuf,
    pub max_entries: usize,
}

impl LocalDatasetProvider {
    pub const MAX_DATASET_BYTES: usize = 1024 * 1024;
    pub const MAX_ENTRIES: usize = 1000;
}

impl ExposureProvider for LocalDatasetProvider {
    fn id(&self) -> &'static str {
        "local-dataset"
    }
    fn accepts(&self, _kind: IdentifierKind) -> bool {
        true
    }
    fn contact_class(&self) -> ContactClass {
        ContactClass::LocalDataset
    }
    fn sends_identifier(&self) -> bool {
        false
    }
    fn requires_auth(&self) -> bool {
        false
    }
    fn describe(&self) -> &'static str {
        "operator-supplied local exposure dataset (local-only)"
    }
    fn query(
        &self,
        identifier: &str,
        kind: IdentifierKind,
        ctx: &ExposureContext<'_>,
    ) -> Result<(Vec<NormalizedExposure>, usize), ExposureError> {
        if ctx.cancelled.load(Ordering::Acquire) {
            return Err(ExposureError::Cancelled);
        }
        let text = std::fs::read_to_string(&self.path)
            .map_err(|error| ExposureError::Unavailable(format!("cannot read dataset: {error}")))?;
        if text.len() > Self::MAX_DATASET_BYTES {
            return Err(ExposureError::Malformed("dataset exceeds 1 MiB".to_owned()));
        }
        let dataset: serde_json::Value = serde_json::from_str(&text).map_err(|error| {
            ExposureError::Malformed(format!("dataset is not valid JSON: {error}"))
        })?;
        let entries = dataset
            .get("exposures")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| ExposureError::Malformed("dataset lacks exposures[]".to_owned()))?;
        if entries.len() > self.max_entries.min(Self::MAX_ENTRIES) {
            return Err(ExposureError::Malformed(
                "dataset exceeds entry bound".to_owned(),
            ));
        }
        let wanted = identifier.trim().to_ascii_lowercase();
        let mut out = Vec::new();
        let mut dropped = 0usize;
        for entry in entries.iter().take(self.max_entries.min(Self::MAX_ENTRIES)) {
            if ctx.cancelled.load(Ordering::Acquire) {
                return Err(ExposureError::Cancelled);
            }
            if Instant::now() >= ctx.deadline {
                return Err(ExposureError::Deadline);
            }
            let entry_type = entry
                .get("identifier_type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            if entry_type != kind.as_str() {
                continue;
            }
            let entry_id = entry
                .get("identifier")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            if entry_id.trim().to_ascii_lowercase() != wanted {
                continue;
            }
            let exposure_type = match entry
                .get("exposure_type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("breach")
            {
                "infostealer" => ExposureType::Infostealer,
                "credential" => ExposureType::Credential,
                "session" => ExposureType::Session,
                "paste" => ExposureType::Paste,
                "malware" => ExposureType::Malware,
                _ => ExposureType::Breach,
            };
            let record = entry
                .get("record")
                .map(normalize_record)
                .unwrap_or_default();
            dropped += record.secrets_dropped;
            let source = entry
                .get("source")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(&self.label)
                .chars()
                .take(64)
                .collect::<String>();
            let hash = identifier_hash(identifier);
            out.push(NormalizedExposure {
                id: exposure_entity_id(&source, exposure_type, &hash),
                exposure_type,
                source: source.clone(),
                source_name: entry
                    .get("source_name")
                    .and_then(serde_json::Value::as_str)
                    .map(|name| name.chars().take(128).collect()),
                identifier_type: kind,
                identifier_hash: hash,
                affected_domain: entry
                    .get("affected_domain")
                    .and_then(serde_json::Value::as_str)
                    .map(|domain| domain.chars().take(253).collect()),
                malware_family: entry
                    .get("malware_family")
                    .and_then(serde_json::Value::as_str)
                    .map(|family| family.chars().take(64).collect()),
                exposed_fields: record.exposed_fields,
                credential_material_exposed: record.credential_material_exposed,
                session_material_exposed: record.session_material_exposed,
                secret_material_retained: false,
                exposure_date: entry
                    .get("exposure_date")
                    .and_then(serde_json::Value::as_str)
                    .map(|date| date.chars().take(32).collect()),
                confidence: entry
                    .get("confidence")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(70)
                    .min(95) as u8,
                timestamp: ctx.now,
                evidence: vec![format!("local dataset {source} reports exposure")],
            });
            if out.len() >= 32 {
                break;
            }
        }
        Ok((out, dropped))
    }
}

// ---------------------------------------------------------------------------
// Configured HTTP API provider (explicit credentials, never logged).
// ---------------------------------------------------------------------------

/// Legitimate threat-intelligence HTTP API. Credentials come only from
/// explicit environment configuration (`RXSCAN_EXPOSURE_ENDPOINT`,
/// `RXSCAN_EXPOSURE_TOKEN`); they are never printed, persisted, or
/// included in structured output. Without configuration the provider
/// reports `credential_not_configured` via capabilities.
pub struct HttpApiProvider {
    pub name: String,
}

impl HttpApiProvider {
    pub fn endpoint() -> Option<String> {
        std::env::var("RXSCAN_EXPOSURE_ENDPOINT")
            .ok()
            .filter(|value| !value.trim().is_empty())
    }

    pub fn configured() -> bool {
        Self::endpoint().is_some()
            && std::env::var("RXSCAN_EXPOSURE_TOKEN")
                .ok()
                .is_some_and(|value| !value.trim().is_empty())
    }
}

impl ExposureProvider for HttpApiProvider {
    fn id(&self) -> &'static str {
        "http-api"
    }
    fn accepts(&self, _kind: IdentifierKind) -> bool {
        true
    }
    fn contact_class(&self) -> ContactClass {
        ContactClass::AuthenticatedApi
    }
    fn sends_identifier(&self) -> bool {
        true
    }
    fn requires_auth(&self) -> bool {
        true
    }
    fn describe(&self) -> &'static str {
        "configured threat-intelligence API (env credentials; sends identifier)"
    }
    fn query(
        &self,
        identifier: &str,
        kind: IdentifierKind,
        ctx: &ExposureContext<'_>,
    ) -> Result<(Vec<NormalizedExposure>, usize), ExposureError> {
        if ctx.cancelled.load(Ordering::Acquire) {
            return Err(ExposureError::Cancelled);
        }
        let endpoint = Self::endpoint()
            .ok_or_else(|| ExposureError::Unavailable("credential_not_configured".to_owned()))?;
        // The token is read at request time and never stored in any
        // struct, log, report, or database field.
        let token = std::env::var("RXSCAN_EXPOSURE_TOKEN")
            .map_err(|_| ExposureError::Unavailable("credential_not_configured".to_owned()))?;
        if token.trim().is_empty() {
            return Err(ExposureError::Unavailable(
                "credential_not_configured".to_owned(),
            ));
        }
        let remaining = ctx.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ExposureError::Deadline);
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(remaining.min(Duration::from_secs(10)))
            .no_proxy()
            .build()
            .map_err(|error| ExposureError::Unavailable(error.to_string()))?;
        // Endpoint validation: HTTPS only. The endpoint is operator-configured
        // (explicit `RXSCAN_EXPOSURE_ENDPOINT`); no private/loopback denial
        // is claimed here — the operator trusts the configured host. The
        // identifier is sent as a query parameter only to that configured
        // host, disclosed via `sends_identifier=true` and `--explain`.
        let mut url = url::Url::parse(&endpoint)
            .map_err(|_| ExposureError::Unavailable("invalid endpoint".to_owned()))?;
        if url.scheme() != "https" {
            return Err(ExposureError::Unavailable(
                "endpoint must use HTTPS".to_owned(),
            ));
        }
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("type", kind.as_str());
            pairs.append_pair("q", identifier);
        }
        let response = client
            .get(url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .map_err(|error| ExposureError::Unavailable(error.to_string()))?;
        match response.status().as_u16() {
            401 | 403 => return Err(ExposureError::AuthRequired),
            429 => return Err(ExposureError::RateLimited),
            status if !(200..300).contains(&status) => {
                return Err(ExposureError::Unavailable(format!("HTTP {status}")));
            }
            _ => {}
        }
        let body = response
            .text()
            .map_err(|error| ExposureError::Malformed(error.to_string()))?;
        if body.len() > 256 * 1024 {
            return Err(ExposureError::Malformed(
                "response exceeds 256 KiB".to_owned(),
            ));
        }
        let parsed: serde_json::Value = serde_json::from_str(&body)
            .map_err(|error| ExposureError::Malformed(format!("response is not JSON: {error}")))?;
        let records = parsed
            .get("exposures")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_else(|| vec![parsed]);
        let mut out = Vec::new();
        let mut dropped = 0usize;
        for item in records.into_iter().take(32) {
            let record = normalize_record(&item);
            dropped += record.secrets_dropped;
            let hash = identifier_hash(identifier);
            let source = record
                .safe_fields
                .get("source")
                .cloned()
                .unwrap_or_else(|| self.name.clone());
            out.push(NormalizedExposure {
                id: exposure_entity_id(&source, ExposureType::Breach, &hash),
                exposure_type: ExposureType::Breach,
                source: source.clone(),
                source_name: record.safe_fields.get("breach_name").cloned(),
                identifier_type: kind,
                identifier_hash: hash,
                affected_domain: record.safe_fields.get("affected_domain").cloned(),
                malware_family: record.safe_fields.get("malware_family").cloned(),
                exposed_fields: record.exposed_fields,
                credential_material_exposed: record.credential_material_exposed,
                session_material_exposed: record.session_material_exposed,
                secret_material_retained: false,
                exposure_date: record.safe_fields.get("exposure_date").cloned(),
                confidence: 70,
                timestamp: ctx.now,
                evidence: vec![format!("provider {source} reports exposure")],
            });
        }
        Ok((out, dropped))
    }
}

// ---------------------------------------------------------------------------
// Email context lives in the investigation transform layer, not exposure.
//
// `email_to_mail_infra` (DNS MX/TXT, opt-in) and `search.entity.email_to_username`
// (local-part `UsesUsername` candidate, confidence 60, `Possible`, never a
// verdict) already model derived email context truthfully as `References` /
// `derived` evidence. A local transformation must never become a
// `Breach` exposure, must never claim `DnsQuery` without a query, and must
// never inflate `exposures_found` merely because an email parses.
// No email ExposureProvider ships here by design.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Engine: bounded, exact accounting, secret-free.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureAccounting {
    pub providers_requested: usize,
    pub providers_completed: usize,
    pub providers_skipped: usize,
    pub providers_cancelled: usize,
    pub providers_unscanned: usize,
    pub exposures_found: usize,
    /// Secrets dropped during normalization (informational; always ≥ 0,
    /// never the secrets themselves).
    pub secrets_dropped: usize,
    /// Usable secret values retained. Invariant: always 0.
    pub secrets_retained: usize,
    pub truncated: bool,
}

impl ExposureAccounting {
    pub fn accounted(&self) -> usize {
        self.providers_completed
            + self.providers_skipped
            + self.providers_cancelled
            + self.providers_unscanned
    }

    pub fn check_invariant(&self) -> Result<(), String> {
        if self.providers_requested != self.accounted() {
            return Err(format!(
                "exposure accounting failure: requested {} != accounted {}",
                self.providers_requested,
                self.accounted()
            ));
        }
        if self.secrets_retained != 0 {
            return Err("exposure retained secret material".to_owned());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureObservation {
    pub provider_id: String,
    pub identifier_type: IdentifierKind,
    pub contact_class: ContactClass,
    pub sends_identifier: bool,
    pub status: String,
    pub timestamp: u64,
    #[serde(default)]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureReport {
    pub schema_version: u32,
    pub run_id: String,
    pub identifier_type: IdentifierKind,
    /// SHA-256 of the identifier; raw identifiers never persist.
    pub identifier_hash: String,
    pub exposures: Vec<NormalizedExposure>,
    pub observations: Vec<ExposureObservation>,
    pub accounting: ExposureAccounting,
    pub network_scans: u64,
    pub started_at: u64,
    pub completed_at: u64,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Run exposure lookups across providers with exact accounting. Providers
/// that cannot serve the identifier kind are skipped (counted, never
/// queried). Secret-bearing responses are normalized before return: only
/// [`NormalizedExposure`] (metadata-only) ever leaves this function.
pub fn run_exposure(
    identifier: &str,
    kind: IdentifierKind,
    providers: &[Box<dyn ExposureProvider>],
    deadline: Duration,
    cancelled: &AtomicBool,
) -> ExposureReport {
    let started_at = unix_now();
    // Unique per execution (same rationale as investigation runs:
    // imports upsert by scan id, so colliding ids would overwrite
    // history rather than append it).
    static EXPOSURE_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = EXPOSURE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let run_id = crate::assets::public_entity_id(
        "exposure_run",
        &format!(
            "{}:{}:{}:{}",
            kind.as_str(),
            identifier_hash(identifier),
            std::process::id(),
            sequence
        ),
    );
    let deadline_at = Instant::now() + deadline;
    let mut accounting = ExposureAccounting {
        providers_requested: providers.len(),
        ..ExposureAccounting::default()
    };
    let mut exposures = Vec::new();
    let mut observations = Vec::new();
    for provider in providers {
        if cancelled.load(Ordering::Acquire) {
            accounting.providers_cancelled += 1;
            continue;
        }
        if Instant::now() >= deadline_at {
            accounting.providers_unscanned += 1;
            accounting.truncated = true;
            continue;
        }
        if !provider.accepts(kind) {
            accounting.providers_skipped += 1;
            continue;
        }
        let ctx = ExposureContext {
            deadline: deadline_at,
            cancelled,
            now: unix_now(),
        };
        match provider.query(identifier, kind, &ctx) {
            Ok((found, dropped)) => {
                accounting.providers_completed += 1;
                accounting.secrets_dropped += dropped;
                // Defense in depth: re-assert the constructor invariant on
                // every exposure that crosses the provider boundary.
                for exposure in found.into_iter().take(32) {
                    if exposure.secret_material_retained {
                        accounting.providers_completed =
                            accounting.providers_completed.saturating_sub(1);
                        accounting.providers_skipped += 1;
                        observations.push(ExposureObservation {
                            provider_id: provider.id().to_owned(),
                            identifier_type: kind,
                            contact_class: provider.contact_class(),
                            sends_identifier: provider.sends_identifier(),
                            status: "rejected_secret_retention".to_owned(),
                            timestamp: unix_now(),
                            evidence: vec![
                                "provider returned secret-retaining exposure; dropped".to_owned(),
                            ],
                        });
                        continue;
                    }
                    accounting.exposures_found += 1;
                    observations.push(ExposureObservation {
                        provider_id: provider.id().to_owned(),
                        identifier_type: kind,
                        contact_class: provider.contact_class(),
                        sends_identifier: provider.sends_identifier(),
                        status: "matched".to_owned(),
                        timestamp: unix_now(),
                        evidence: vec![format!(
                            "{} exposure via {}",
                            exposure.exposure_type.as_str(),
                            exposure.source
                        )],
                    });
                    exposures.push(exposure);
                }
            }
            Err(ExposureError::Cancelled) => accounting.providers_cancelled += 1,
            Err(ExposureError::Deadline) => {
                accounting.providers_unscanned += 1;
                accounting.truncated = true;
            }
            Err(error) => {
                accounting.providers_completed += 1;
                let status = match error {
                    ExposureError::AuthRequired => "authentication_required",
                    ExposureError::RateLimited => "rate_limited",
                    ExposureError::Malformed(_) => "malformed",
                    ExposureError::Unavailable(_) => "unavailable",
                    ExposureError::Deadline => "deadline",
                    ExposureError::Cancelled => "cancelled",
                };
                observations.push(ExposureObservation {
                    provider_id: provider.id().to_owned(),
                    identifier_type: kind,
                    contact_class: provider.contact_class(),
                    sends_identifier: provider.sends_identifier(),
                    status: status.to_owned(),
                    timestamp: unix_now(),
                    evidence: vec![error.to_string().chars().take(256).collect()],
                });
            }
        }
    }
    // Providers with no exposure still leave a no-match observation so
    // "checked and clean" is distinguishable from "not checked".
    let matched_providers: BTreeSet<String> = observations
        .iter()
        .filter(|o| o.status == "matched")
        .map(|o| o.provider_id.clone())
        .collect();
    for provider in providers {
        if provider.accepts(kind)
            && !matched_providers.contains(provider.id())
            && !observations.iter().any(|o| o.provider_id == provider.id())
        {
            observations.push(ExposureObservation {
                provider_id: provider.id().to_owned(),
                identifier_type: kind,
                contact_class: provider.contact_class(),
                sends_identifier: provider.sends_identifier(),
                status: "no_match".to_owned(),
                timestamp: unix_now(),
                evidence: vec!["provider reports no exposure for identifier".to_owned()],
            });
        }
    }
    exposures.sort_by(|a, b| a.id.cmp(&b.id));
    observations.sort_by(|a, b| {
        a.provider_id
            .cmp(&b.provider_id)
            .then(a.status.cmp(&b.status))
    });
    ExposureReport {
        schema_version: 1,
        run_id,
        identifier_type: kind,
        identifier_hash: identifier_hash(identifier),
        exposures,
        observations,
        accounting,
        network_scans: 0,
        started_at,
        completed_at: unix_now(),
    }
}

/// Plan-only explanation: which providers would run, what contact they
/// use, and — critically — which ones send the identifier to a third
/// party. No provider contact.
pub fn explain_exposure(kind: IdentifierKind, providers: &[Box<dyn ExposureProvider>]) -> String {
    let mut out = String::from("EXPOSURE INTELLIGENCE\n\n");
    out.push_str(&format!("identifier type   {}\n", kind.as_str()));
    out.push_str("raw storage       disabled\nsecret storage    disabled\n\n");
    for provider in providers {
        out.push_str(&format!(
            "provider        {}\n  contact       {:?}\n  sends         {}\n  auth          {}\n  {}\n",
            provider.id(),
            provider.contact_class(),
            if provider.sends_identifier() {
                format!("{} (third-party query)", kind.as_str())
            } else {
                "nothing (local only)".to_owned()
            },
            if provider.requires_auth() {
                "required (env credentials, never displayed)"
            } else {
                "none"
            },
            provider.describe(),
        ));
    }
    out.push_str("\nsecret material is normalized to boolean metadata, then dropped.\n");
    out
}

// ---------------------------------------------------------------------------
// Rendering: human (semantic terminal styles), JSON, typed JSONL.
// ---------------------------------------------------------------------------

/// Designed human rendering: workflow header, findings, and a summary
/// bar. Styled only when `color` is true; machine output never passes
/// through here. Fixed 80-column layout; see [`render_human_caps`].
pub fn render_human(report: &ExposureReport, color: bool, ascii: bool) -> String {
    render_human_caps(
        report,
        crate::terminal::TerminalCapabilities {
            color,
            ascii,
            width: 80,
            tty: false,
        },
    )
}

/// Capabilities-aware exposure renderer (responsive + styled).
pub fn render_human_caps(
    report: &ExposureReport,
    caps: crate::terminal::TerminalCapabilities,
) -> String {
    use crate::terminal::{
        Style, footer_block, key_value, paint, section_heading, workflow_header,
    };
    let color = caps.color;
    let ascii = caps.ascii;
    let mut out = String::new();
    out.push_str(&workflow_header(
        caps,
        "EXPOSURE",
        Some(crate::terminal::WorkflowMode::Passive),
    ));
    out.push('\n');
    out.push('\n');
    out.push_str(&section_heading(caps, "Findings"));
    out.push('\n');
    if report.exposures.is_empty() {
        out.push('\n');
        out.push_str(&format!(
            "  {}\n",
            paint(
                color,
                Style::Success,
                "no exposures reported by configured providers"
            )
        ));
    } else {
        for exposure in &report.exposures {
            out.push('\n');
            out.push_str(&format!(
                "  {} {}\n",
                paint(
                    color,
                    Style::Warning,
                    &exposure.exposure_type.as_str().to_ascii_uppercase()
                ),
                paint(color, Style::Muted, &format!("via {}", exposure.source)),
            ));
            if let Some(name) = &exposure.source_name {
                out.push_str(&key_value(caps, "Source", name, 11));
                out.push('\n');
            }
            if !exposure.exposed_fields.is_empty() {
                let fields: Vec<&str> = exposure
                    .exposed_fields
                    .iter()
                    .map(|field| field.as_str())
                    .collect();
                let glyph = if ascii { "*" } else { "·" };
                out.push_str(&key_value(
                    caps,
                    "Exposed",
                    &fields.join(&format!(" {glyph} ")),
                    11,
                ));
                out.push('\n');
            }
            if exposure.credential_material_exposed || exposure.session_material_exposed {
                out.push_str(&format!(
                    "  {}\n",
                    paint(color, Style::Error, "! credentials NOT RETAINED")
                ));
            }
            if let Some(family) = &exposure.malware_family {
                out.push_str(&key_value(caps, "Malware", family, 11));
                out.push('\n');
            }
            out.push_str(&key_value(
                caps,
                "Confidence",
                &format!("{}%", exposure.confidence),
                11,
            ));
            out.push('\n');
        }
    }
    out.push('\n');
    let recap = format!(
        "{} checked  ·  {} matched  ·  secrets stored: 0",
        report.accounting.providers_requested, report.accounting.exposures_found,
    );
    out.push_str(&footer_block(caps, &paint(color, Style::Secondary, &recap)));
    out.push('\n');
    out
}

/// Typed JSONL: `exposure_start`, `exposure`, `observation`,
/// `exposure_summary`. Independently parseable lines, no ANSI.
pub fn render_jsonl(report: &ExposureReport) -> String {
    fn envelope(record_type: &'static str, payload: serde_json::Value) -> String {
        serde_json::json!({
            "schema_version": 1,
            "record_type": record_type,
            "payload": payload,
        })
        .to_string()
    }
    let mut out = String::new();
    out.push_str(&envelope(
        "exposure_start",
        serde_json::json!({
            "run_id": report.run_id,
            "identifier_type": report.identifier_type,
            "identifier_hash": report.identifier_hash,
            "network_scans": 0,
            "started_at": report.started_at,
        }),
    ));
    out.push('\n');
    for exposure in &report.exposures {
        out.push_str(&envelope("exposure", serde_json::json!(exposure)));
        out.push('\n');
    }
    for observation in &report.observations {
        out.push_str(&envelope("observation", serde_json::json!(observation)));
        out.push('\n');
    }
    out.push_str(&envelope(
        "exposure_summary",
        serde_json::json!({
            "run_id": report.run_id,
            "exposures": report.exposures.len(),
            "accounting": report.accounting,
            "network_scans": 0,
            "secrets_retained": 0,
            "completed_at": report.completed_at,
        }),
    ));
    out.push('\n');
    out
}

// ---------------------------------------------------------------------------
// Graph integration: exposures as entities, never secrets.
// ---------------------------------------------------------------------------

/// Convert exposures into graph items for investigation enrichment.
/// Returns `(entities, edges)` with full provenance; secret material can
/// never cross this boundary because [`NormalizedExposure`] cannot carry
/// it. `identifier_entity` is the existing graph node (e.g. an
/// `EmailAddress` or `Username` entity) the exposures attach to.
pub fn to_graph_items(
    identifier_entity: &str,
    identifier_kind: EntityKind,
    exposures: &[NormalizedExposure],
    timestamp: u64,
    depth: u8,
) -> (
    Vec<crate::investigate::InvestigationEntity>,
    Vec<crate::investigate::InvestigationRelationship>,
) {
    use crate::investigate::{InvestigationEntity, InvestigationRelationship, TransformProvenance};
    let mut entities = Vec::new();
    let mut edges = Vec::new();
    for exposure in exposures {
        let contact = ContactClass::AuthenticatedApi;
        let provenance = TransformProvenance {
            source_entity: Some(identifier_entity.to_owned()),
            transform_id: "exposure_lookup".to_owned(),
            provider: Some(exposure.source.clone()),
            contact_class: contact,
            timestamp,
            evidence: exposure.evidence.clone(),
            confidence: exposure.confidence.min(95),
            depth,
        };
        let mut attributes = BTreeMap::from([
            ("source".to_owned(), exposure.source.clone()),
            (
                "exposure_type".to_owned(),
                exposure.exposure_type.as_str().to_owned(),
            ),
            (
                "credential_material_exposed".to_owned(),
                exposure.credential_material_exposed.to_string(),
            ),
            (
                "session_material_exposed".to_owned(),
                exposure.session_material_exposed.to_string(),
            ),
            ("secret_material_retained".to_owned(), "false".to_owned()),
        ]);
        if let Some(name) = &exposure.source_name {
            attributes.insert("source_name".to_owned(), name.clone());
        }
        if let Some(family) = &exposure.malware_family {
            attributes.insert("malware_family".to_owned(), family.clone());
        }
        if !exposure.exposed_fields.is_empty() {
            attributes.insert(
                "exposed_fields".to_owned(),
                exposure
                    .exposed_fields
                    .iter()
                    .map(|field| field.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        entities.push(InvestigationEntity {
            id: exposure.id.clone(),
            kind: EntityKind::Exposure,
            label: exposure.label(),
            canonical_value: exposure.id.clone(),
            attributes,
            depth,
            provenance: provenance.clone(),
            observations: 1,
        });
        // Identifier -> exposure: EXPOSED_IN for breach/credential/session/
        // paste, OBSERVED_IN for infostealer/malware observations.
        let relation = match exposure.exposure_type {
            ExposureType::Infostealer | ExposureType::Malware => EdgeRelation::ObservedIn,
            _ => EdgeRelation::ExposedIn,
        };
        edges.push(InvestigationRelationship {
            from: identifier_entity.to_owned(),
            to: exposure.id.clone(),
            relation,
            confidence: exposure.confidence.min(95),
            provenance: provenance.clone(),
            evidence: exposure.evidence.clone(),
            attributes: BTreeMap::from([("observation_class".to_owned(), "observed".to_owned())]),
        });
        // Exposure -> source node.
        let source_id = exposure_source_id(&exposure.source);
        entities.push(InvestigationEntity {
            id: source_id.clone(),
            kind: EntityKind::ExposureSource,
            label: exposure.source.clone(),
            canonical_value: exposure.source.to_ascii_lowercase(),
            attributes: BTreeMap::from([("source".to_owned(), exposure.source.clone())]),
            depth,
            provenance: provenance.clone(),
            observations: 1,
        });
        edges.push(InvestigationRelationship {
            from: exposure.id.clone(),
            to: source_id,
            relation: EdgeRelation::ReportedBy,
            confidence: 95,
            provenance: provenance.clone(),
            evidence: vec![format!("reported by {}", exposure.source)],
            attributes: BTreeMap::new(),
        });
        // Exposure -> affected/targeted domain.
        if let Some(domain) = exposure
            .affected_domain
            .as_deref()
            .filter(|d| crate::investigate::canonical_domain(d).is_some())
        {
            let domain_id = crate::investigate::domain_entity_id(domain);
            let _ = identifier_kind;
            entities.push(InvestigationEntity {
                id: domain_id.clone(),
                kind: EntityKind::Domain,
                label: domain.to_ascii_lowercase(),
                canonical_value: domain.to_ascii_lowercase(),
                attributes: BTreeMap::from([("domain".to_owned(), domain.to_ascii_lowercase())]),
                depth,
                provenance: provenance.clone(),
                observations: 1,
            });
            let relation = match exposure.exposure_type {
                ExposureType::Infostealer | ExposureType::Malware => EdgeRelation::TargetedDomain,
                _ => EdgeRelation::Affects,
            };
            edges.push(InvestigationRelationship {
                from: exposure.id.clone(),
                to: domain_id,
                relation,
                confidence: 70,
                provenance,
                evidence: vec![format!("exposure references {domain}")],
                attributes: BTreeMap::new(),
            });
        }
    }
    (entities, edges)
}

// ---------------------------------------------------------------------------
// Capabilities.
// ---------------------------------------------------------------------------

pub fn capability_entries() -> Vec<(String, bool, String)> {
    let http = HttpApiProvider::configured();
    vec![
        (
            "exposure".to_owned(),
            true,
            "defensive exposure intelligence (opt-in external queries)".to_owned(),
        ),
        (
            "exposure_local_dataset".to_owned(),
            true,
            "operator-supplied local exposure datasets".to_owned(),
        ),
        (
            "exposure_http_api".to_owned(),
            http,
            if http {
                "configured via RXSCAN_EXPOSURE_ENDPOINT".to_owned()
            } else {
                "credential_not_configured: set RXSCAN_EXPOSURE_ENDPOINT and RXSCAN_EXPOSURE_TOKEN"
                    .to_owned()
            },
        ),
        (
            "exposure_secret_retention".to_owned(),
            false,
            "disabled by design: secrets normalize to boolean metadata, then drop".to_owned(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(deadline: Instant) -> (ExposureContext<'static>, &'static AtomicBool) {
        let cancelled: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
        (
            ExposureContext {
                deadline,
                cancelled,
                now: 1_700_000_000,
            },
            cancelled,
        )
    }

    #[test]
    fn secret_keys_classify_then_drop() {
        let record = normalize_record(&serde_json::json!({
            "source": "t",
            "password": "FAKE-PW",
            "session_cookie": "FAKE-SESS",
            "api_key": "FAKE-KEY",
        }));
        assert!(record.credential_material_exposed);
        assert!(record.session_material_exposed);
        assert_eq!(record.secrets_dropped, 3);
        assert!(!record.safe_fields.contains_key("password"));
        assert_eq!(record.safe_fields.get("source").unwrap(), "t");
    }

    #[test]
    fn fixture_matches_and_cleans() {
        let provider = FixtureExposureProvider::default();
        let (context, _) = ctx(Instant::now() + Duration::from_secs(5));
        let (matched, dropped) = provider
            .query(
                "someone-exposed@example.test",
                IdentifierKind::Email,
                &context,
            )
            .unwrap();
        assert_eq!(matched.len(), 2);
        assert!(dropped > 0, "fixture secrets must be counted as dropped");
        for exposure in &matched {
            assert!(!exposure.secret_material_retained);
            assert!(exposure.credential_material_exposed);
        }
        let (clean, _) = provider
            .query("clean-user", IdentifierKind::Username, &context)
            .unwrap();
        assert!(clean.is_empty());
    }

    #[test]
    fn engine_accounting_reconciles_and_retains_nothing() {
        let providers: Vec<Box<dyn ExposureProvider>> =
            vec![Box::new(FixtureExposureProvider::default())];
        let cancelled = AtomicBool::new(false);
        let report = run_exposure(
            "someone-exposed@example.test",
            IdentifierKind::Email,
            &providers,
            Duration::from_secs(5),
            &cancelled,
        );
        report.accounting.check_invariant().unwrap();
        assert_eq!(report.accounting.secrets_retained, 0);
        assert_eq!(report.network_scans, 0);
        let json = serde_json::to_string(&report).unwrap();
        assert_no_secrets(
            &json,
            &[
                "FAKE-SECRET-PW-0000",
                "FAKE-SECRET-HASH-0000",
                "FAKE-SECRET-SESSION-0000",
                "FAKE-SECRET-APIKEY-0000",
            ],
        );
        let jsonl = render_jsonl(&report);
        assert_no_secrets(
            &jsonl,
            &[
                "FAKE-SECRET-PW-0000",
                "FAKE-SECRET-HASH-0000",
                "FAKE-SECRET-SESSION-0000",
                "FAKE-SECRET-APIKEY-0000",
            ],
        );
        assert!(!jsonl.contains('\x1b'));
    }

    #[test]
    fn clean_email_creates_no_breach() {
        // Local email parsing must never become a Breach exposure.
        // Derived context lives in investigation transforms, not exposure.
        let providers: Vec<Box<dyn ExposureProvider>> = Vec::new();
        let cancelled = AtomicBool::new(false);
        let report = run_exposure(
            "user@example.test",
            IdentifierKind::Email,
            &providers,
            Duration::from_secs(5),
            &cancelled,
        );
        assert!(report.exposures.is_empty());
        assert_eq!(report.accounting.exposures_found, 0);
        assert!(report.accounting.check_invariant().is_ok());
    }

    #[test]
    fn exposure_capabilities_claim_no_dns_without_query() {
        // No shipped provider may claim DnsQuery while performing no query,
        // and no email capability may exist in exposure.
        for (id, _, _) in capability_entries() {
            assert_ne!(id, "exposure_email_domain_context");
            assert_ne!(id, "exposure_email_public_reference");
        }
        // Investigation owns derived email context truthfully:
        // email_to_mail_infra does DNS, email local-part is a Possible hint.
        let mail = crate::investigate::EmailToMailInfra;
        use crate::investigate::Transform;
        assert_eq!(mail.contact_class(), crate::search::ContactClass::DnsQuery);
    }
}
