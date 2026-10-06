//! Bounded RDAP intelligence (domain / IP / ASN / prefix).
//!
//! Additive only: existing DNS/search/investigation behavior preserved.
//! Captures only information legitimately returned by RDAP; redaction is
//! respected and never defeated. Every RDAP entity role stays distinct
//! (registrar vs registrant vs technical vs administrative vs allocation
//! holder); strong ownership is never inferred from RDAP alone.
//!
//! Live integration uses configured public RDAP endpoints (default
//! `https://rdap.org/...`, overrideable). Deterministic tests use fixtures
//! or local HTTP servers — never live RDAP.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Normalized RDAP entity reference (role-preserving, redaction-aware).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdapEntityRef {
    pub handle: Option<String>,
    pub roles: Vec<String>,
    /// Public organization / entity name when legitimately present.
    /// `None` when redacted or absent (never fabricated).
    pub public_name: Option<String>,
    pub redacted: bool,
}

/// Normalized RDAP network allocation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RdapNetwork {
    pub start_address: Option<String>,
    pub end_address: Option<String>,
    pub ip_version: Option<String>,
    pub name: Option<String>,
    pub network_type: Option<String>,
    pub country: Option<String>,
}

/// Normalized RDAP summary (timestamps preserved, never replaced by
/// retrieval time).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RdapSummary {
    pub handle: Option<String>,
    pub status: Vec<String>,
    /// eventAction -> eventDate (raw RFC3339 as supplied).
    pub events: BTreeMap<String, String>,
    pub nameservers: Vec<String>,
    pub entities: Vec<RdapEntityRef>,
    pub network: Option<RdapNetwork>,
    pub autnum: Option<u32>,
    pub redacted: bool,
}

fn str_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty() && s.len() <= 512)
}

fn str_list(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty() && s.len() <= 128)
                .take(16)
                .collect()
        })
        .unwrap_or_default()
}

fn is_redacted_marker(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("redacted") || lower.contains("privacy") || lower == "—" || lower == "***"
}

/// Parse an RDAP JSON response (RFC 9083 shape, tolerant).
/// Never errors on missing optional fields; errors only on malformed
/// top-level JSON (non-object) or oversized values.
#[allow(clippy::field_reassign_with_default)]
pub fn parse_rdap(value: &serde_json::Value) -> Result<RdapSummary, String> {
    let obj = value
        .as_object()
        .ok_or_else(|| "RDAP response must be a JSON object".to_owned())?;
    if obj.len() > 256 {
        return Err("RDAP response too large".to_owned());
    }
    let mut summary = RdapSummary::default();
    summary.handle = str_field(value, "handle").filter(|h| !is_redacted_marker(h));
    if value
        .get("handle")
        .and_then(|v| v.as_str())
        .is_some_and(is_redacted_marker)
    {
        summary.redacted = true;
    }
    summary.status = str_list(value, "status");
    // Events: [{eventAction, eventDate}].
    if let Some(events) = value.get("events").and_then(|v| v.as_array()) {
        for event in events.iter().take(32) {
            let action = event
                .get("eventAction")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let date = event
                .get("eventDate")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_owned();
            if action.is_empty() || date.is_empty() || date.len() > 64 {
                continue;
            }
            // First occurrence wins (deterministic, no overwrite games).
            summary.events.entry(action).or_insert(date);
        }
    }
    // Nameservers: [{ldhName}].
    if let Some(servers) = value.get("nameservers").and_then(|v| v.as_array()) {
        for server in servers.iter().take(16) {
            if let Some(name) = server.get("ldhName").and_then(|v| v.as_str()) {
                let clean = name.trim().trim_end_matches('.').to_ascii_lowercase();
                if clean.is_empty() || clean.len() > 253 {
                    continue;
                }
                if crate::search::canonical_hostname_value(&clean).is_some()
                    && !summary.nameservers.contains(&clean)
                {
                    summary.nameservers.push(clean);
                }
            }
        }
    }
    // Entities: [{handle, roles[], vcardArray/publicIds?}].
    if let Some(entities) = value.get("entities").and_then(|v| v.as_array()) {
        for entity in entities.iter().take(32) {
            let handle = entity
                .get("handle")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty() && s.len() <= 128);
            let roles: Vec<String> = entity
                .get("roles")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| s.trim().to_ascii_lowercase())
                        .filter(|s| !s.is_empty() && s.len() <= 32)
                        .take(8)
                        .collect()
                })
                .unwrap_or_default();
            // Public name: vcard fn/org (tolerant), else publicIds.
            let mut public_name: Option<String> = None;
            if let Some(vcard) = entity
                .get("vcardArray")
                .and_then(|v| v.as_array())
                .and_then(|a| a.get(1))
            {
                if let Some(props) = vcard.as_array() {
                    for prop in props.iter().take(32) {
                        let name = prop.get(0).and_then(|v| v.as_str()).unwrap_or("");
                        if name == "fn" || name == "org" {
                            if let Some(text) = prop.get(3).and_then(|v| v.as_str()) {
                                let clean = text.trim().to_owned();
                                if !clean.is_empty()
                                    && clean.len() <= 128
                                    && !is_redacted_marker(&clean)
                                {
                                    public_name = Some(clean);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            let redacted = handle.as_deref().is_some_and(is_redacted_marker)
                || public_name.is_none()
                    && entity
                        .get("redacted")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
            // Never store redacted markers as names.
            if public_name.as_deref().is_some_and(is_redacted_marker) {
                public_name = None;
            }
            if redacted {
                summary.redacted = true;
            }
            summary.entities.push(RdapEntityRef {
                handle: handle.filter(|h| !is_redacted_marker(h)),
                roles,
                public_name,
                redacted,
            });
        }
    }
    // Network allocation (ip query).
    if value.get("startAddress").is_some() || value.get("endAddress").is_some() {
        summary.network = Some(RdapNetwork {
            start_address: str_field(value, "startAddress"),
            end_address: str_field(value, "endAddress"),
            ip_version: str_field(value, "ipVersion"),
            name: str_field(value, "name"),
            network_type: str_field(value, "type"),
            country: str_field(value, "country"),
        });
    }
    // Autnum (asn query): startAutnum/endAutnum or handle.
    if let Some(start) = value.get("startAutnum").and_then(|v| v.as_u64()) {
        if start <= u64::from(u32::MAX) && start > 0 {
            summary.autnum = Some(start as u32);
        }
    }
    // Notices mentioning redaction/privacy mark the whole response.
    if let Some(notices) = value.get("notices").and_then(|v| v.as_array()) {
        for notice in notices.iter().take(16) {
            let text = notice.to_string().to_ascii_lowercase();
            if text.contains("redact") || text.contains("privacy") {
                summary.redacted = true;
                break;
            }
        }
    }
    Ok(summary)
}

/// Deterministic fixture RDAP provider (tests, no network).
#[derive(Debug, Default)]
pub struct FixtureRdapFetcher {
    /// (kind lower, target lower) -> JSON.
    pub responses: HashMap<(String, String), serde_json::Value>,
    /// Targets that must fail with this message.
    pub errors: HashMap<(String, String), String>,
}

impl FixtureRdapFetcher {
    pub fn with_response(mut self, kind: &str, target: &str, value: serde_json::Value) -> Self {
        self.responses.insert(
            (
                kind.trim().to_ascii_lowercase(),
                target.trim().to_ascii_lowercase(),
            ),
            value,
        );
        self
    }

    pub fn with_error(mut self, kind: &str, target: &str, message: &str) -> Self {
        self.errors.insert(
            (
                kind.trim().to_ascii_lowercase(),
                target.trim().to_ascii_lowercase(),
            ),
            message.to_owned(),
        );
        self
    }
}

impl crate::investigate::RdapFetcher for FixtureRdapFetcher {
    fn fetch(
        &self,
        target: &str,
        kind: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<serde_json::Value, String> {
        if cancelled.load(Ordering::Acquire) {
            return Err("cancelled".to_owned());
        }
        if Instant::now() >= deadline {
            return Err("deadline".to_owned());
        }
        let key = (
            kind.trim().to_ascii_lowercase(),
            target.trim().to_ascii_lowercase(),
        );
        if let Some(message) = self.errors.get(&key) {
            return Err(message.clone());
        }
        self.responses
            .get(&key)
            .cloned()
            .ok_or_else(|| "provider unavailable: no fixture for target".to_owned())
    }
}

/// Bounded production RDAP over hardened HTTPS.
///
/// Bases are configurable (default `https://rdap.org/...`). Honors 429 +
/// Retry-After, deadlines, cancellation, bounded body/redirects. Never
/// sends credentials (none required); never defeats redaction.
#[derive(Debug)]
pub struct HttpRdapFetcher {
    pub domain_base: String,
    pub ip_base: String,
    pub asn_base: String,
    pub timeout: Duration,
    pub max_body_bytes: usize,
}

impl Default for HttpRdapFetcher {
    fn default() -> Self {
        Self {
            domain_base: "https://rdap.org/domain/".to_owned(),
            ip_base: "https://rdap.org/ip/".to_owned(),
            asn_base: "https://rdap.org/autnum/".to_owned(),
            timeout: Duration::from_secs(10),
            max_body_bytes: 256 * 1024,
        }
    }
}

impl crate::investigate::RdapFetcher for HttpRdapFetcher {
    fn fetch(
        &self,
        target: &str,
        kind: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<serde_json::Value, String> {
        if cancelled.load(Ordering::Acquire) {
            return Err("cancelled".to_owned());
        }
        if Instant::now() >= deadline {
            return Err("deadline".to_owned());
        }
        let base = match kind.trim().to_ascii_lowercase().as_str() {
            "domain" => &self.domain_base,
            "ip" | "prefix" => &self.ip_base,
            "asn" | "autnum" => &self.asn_base,
            _ => return Err(format!("unsupported RDAP kind {kind}")),
        };
        // Percent-encode the target as a single path segment (no traversal).
        let mut encoded = String::new();
        for byte in target.trim().as_bytes() {
            if byte.is_ascii_alphanumeric()
                || matches!(*byte, b'-' | b'.' | b'_' | b'~' | b':' | b'/')
            {
                // `/` only for prefix CIDR; everything else rejects `/`
                // below via validation in transforms.
                encoded.push(char::from(*byte));
            } else {
                encoded.push_str(&format!("%{byte:02X}"));
            }
        }
        let url_text = format!("{base}{encoded}");
        let url = url::Url::parse(&url_text).map_err(|_| "invalid RDAP URL".to_owned())?;
        if url.scheme() != "https" {
            return Err("RDAP requires HTTPS".to_owned());
        }
        let client = crate::search::SharedHttpClient::new().map_err(|e| e.to_string())?;
        let ctx = crate::search::SearchContext {
            deadline,
            cancelled,
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = self.timeout.min(remaining);
        if timeout.is_zero() {
            return Err("deadline".to_owned());
        }
        let response = client
            .get(&url, timeout, self.max_body_bytes, 2, &ctx)
            .map_err(|e| e.to_string())?;
        if response.status == 429 {
            return Err("rate_limited".to_owned());
        }
        if response.status == 404 {
            return Err("not found".to_owned());
        }
        if response.status == 401 {
            return Err("authentication required".to_owned());
        }
        if response.status == 403 {
            return Err("blocked".to_owned());
        }
        if !(200..300).contains(&response.status) {
            return Err(format!("RDAP HTTP {}", response.status));
        }
        serde_json::from_slice(&response.body).map_err(|_| "malformed RDAP response".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::investigate::RdapFetcher;

    fn sample_domain() -> serde_json::Value {
        serde_json::json!({
            "handle": "EXAMPLE-TEST",
            "status": ["active"],
            "events": [
                {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2024-05-05T00:00:00Z"}
            ],
            "nameservers": [{"ldhName": "ns1.example.test."}, {"ldhName": "ns2.example.test"}],
            "entities": [
                {"handle": "REG-1", "roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]},
                {"handle": "REDACTED", "roles": ["registrant"]}
            ],
            "notices": [{"title": "redacted for privacy"}]
        })
    }

    #[test]
    fn valid_response_preserves_roles_and_redaction() {
        let summary = parse_rdap(&sample_domain()).unwrap();
        assert_eq!(summary.handle.as_deref(), Some("EXAMPLE-TEST"));
        assert!(summary.status.contains(&"active".to_owned()));
        assert_eq!(
            summary.events.get("registration").map(String::as_str),
            Some("2020-01-01T00:00:00Z")
        );
        assert!(summary.nameservers.contains(&"ns1.example.test".to_owned()));
        assert_eq!(summary.entities.len(), 2);
        assert_eq!(summary.entities[0].roles, vec!["registrar".to_owned()]);
        assert_eq!(
            summary.entities[0].public_name.as_deref(),
            Some("Example Registrar")
        );
        assert!(summary.redacted);
        assert!(summary.entities[1].handle.is_none());
    }

    #[test]
    fn missing_optional_fields_are_none_not_error() {
        let summary = parse_rdap(&serde_json::json!({"handle": "X"})).unwrap();
        assert!(summary.nameservers.is_empty());
        assert!(summary.entities.is_empty());
        assert!(summary.events.is_empty());
    }

    #[test]
    fn malformed_top_level_rejected() {
        assert!(parse_rdap(&serde_json::json!([1, 2])).is_err());
    }

    #[test]
    fn ip_and_asn_shapes() {
        let ip = parse_rdap(&serde_json::json!({
            "handle": "NET-1",
            "startAddress": "192.0.2.0",
            "endAddress": "192.0.2.255",
            "ipVersion": "v4",
            "name": "EXAMPLE-NET",
            "type": "ALLOCATED"
        }))
        .unwrap();
        assert_eq!(
            ip.network.as_ref().unwrap().start_address.as_deref(),
            Some("192.0.2.0")
        );
        let asn = parse_rdap(&serde_json::json!({"startAutnum": 64500})).unwrap();
        assert_eq!(asn.autnum, Some(64500));
    }

    #[test]
    fn fixture_fetch_is_deterministic() {
        let fetcher =
            FixtureRdapFetcher::default().with_response("domain", "example.test", sample_domain());
        let deadline = Instant::now() + Duration::from_secs(5);
        let flag = AtomicBool::new(false);
        let value = fetcher
            .fetch("example.test", "domain", deadline, &flag)
            .unwrap();
        assert_eq!(value["handle"], "EXAMPLE-TEST");
        assert!(
            fetcher
                .fetch("other.test", "domain", deadline, &flag)
                .is_err()
        );
    }
}
