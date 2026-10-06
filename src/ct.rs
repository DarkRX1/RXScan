//! Bounded Certificate Transparency intelligence.
//!
//! Additive only. Models `Domain -> Certificate -> Hostname` from public CT
//! indexes (default `https://crt.sh`, overrideable). Normalizes case,
//! trailing dots, duplicates, malformed SANs, wildcards, and IDN/punycode
//! passthrough. Wildcards are observations, never expanded into invented
//! hostnames. A CT hostname proves appearance in certificate material —
//! never that the host exists or is reachable. Historical timestamps are
//! preserved (`not_before`/`not_after`/`entry_timestamp`), never replaced
//! by retrieval time. Third-party observations never masquerade as direct
//! RXScan network observations (`direct_observation=false`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Normalized CT hostname outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedCt {
    /// Lowercase, no trailing dot (`example.test`).
    pub canonical: String,
    pub is_wildcard: bool,
    pub is_ip: bool,
}

/// Normalize one CT SAN value.
/// - trims whitespace, strips one leading `*.` as wildcard (records, never
///   expands);
/// - lowercases, trims trailing dot;
/// - rejects empty, control/whitespace-inside, >253 chars, IP handled
///   separately (returned as `is_ip`);
/// - IDN/punycode passes through lowercased (project policy: no conversion).
pub fn normalize_ct_hostname(raw: &str) -> Option<NormalizedCt> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return None;
    }
    if trimmed.chars().any(char::is_control) {
        return None;
    }
    let (body, is_wildcard) = match trimmed.strip_prefix("*.") {
        Some(rest) => (rest, true),
        None => (trimmed, false),
    };
    if body.is_empty() || body.len() > 253 {
        return None;
    }
    // IP SANs (v4/v6 literals) are valid CT entries; report separately.
    if let Ok(ip) = body.trim_end_matches('.').parse::<std::net::IpAddr>() {
        return Some(NormalizedCt {
            canonical: ip.to_string().to_ascii_lowercase(),
            is_wildcard: false,
            is_ip: true,
        });
    }
    let canonical = body.trim_end_matches('.').to_ascii_lowercase();
    if canonical.is_empty() || canonical.contains(char::is_whitespace) {
        return None;
    }
    // Hostnames must be plausible labels; single-label accepted only when
    // it came from a wildcard base? No — require at least one dot for
    // non-wildcard DNS names (avoids `localhost` noise); wildcards keep
    // their base even if single-label (recorded, not expanded).
    let valid = canonical.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && !label.starts_with('-')
            && !label.ends_with('-')
    });
    if !valid {
        return None;
    }
    if !is_wildcard && !canonical.contains('.') {
        return None;
    }
    Some(NormalizedCt {
        canonical,
        is_wildcard,
        is_ip: false,
    })
}

/// One CT certificate (normalized, timestamped, deduplicated SANs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtCertificate {
    /// Stable identity (`ct:<serial-lower>:<not_before>` or sha256 when
    /// supplied). Deterministic across duplicate log entries.
    pub stable_id: String,
    pub serial: String,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub entry_timestamp: Option<String>,
    pub hostnames: Vec<String>,
    pub wildcards: Vec<String>,
    pub ips: Vec<String>,
}

/// Parse a CT index JSON array (crt.sh shape or generic
/// `[{serial, not_before, not_after, entry_timestamp, name_value}]`).
/// `name_value` may contain newline-separated SANs. Duplicates removed,
/// order deterministic (sorted). Malformed entries skipped, never error.
pub fn parse_ct_response(value: &serde_json::Value) -> Vec<CtCertificate> {
    let arr = match value.as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut seen_ids = BTreeSet::new();
    for entry in arr.iter().take(128) {
        let serial = entry
            .get("serial")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let not_before = entry
            .get("not_before")
            .or_else(|| entry.get("notBefore"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty() && s.len() <= 64);
        let not_after = entry
            .get("not_after")
            .or_else(|| entry.get("notAfter"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty() && s.len() <= 64);
        let entry_timestamp = entry
            .get("entry_timestamp")
            .or_else(|| entry.get("entryTimestamp"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty() && s.len() <= 64);
        // Fingerprint when supplied (some indexes include sha256).
        let sha256 = entry
            .get("sha256")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()));
        let stable_id = if let Some(fp) = sha256 {
            format!("cert:sha256:{fp}")
        } else if !serial.is_empty() {
            format!("ct:{}:{}", serial, not_before.clone().unwrap_or_default())
        } else {
            continue;
        };
        if !seen_ids.insert(stable_id.clone()) {
            continue;
        }
        // SANs: name_value (newline separated) + common_name + dns_names[].
        let mut raw_sans: Vec<String> = Vec::new();
        if let Some(nv) = entry.get("name_value").and_then(|v| v.as_str()) {
            for part in nv.split(['\n', ',']) {
                let p = part.trim().to_owned();
                if !p.is_empty() {
                    raw_sans.push(p);
                }
            }
        }
        if let Some(cn) = entry.get("common_name").and_then(|v| v.as_str()) {
            raw_sans.push(cn.trim().to_owned());
        }
        if let Some(list) = entry.get("dns_names").and_then(|v| v.as_array()) {
            for item in list.iter().take(64) {
                if let Some(s) = item.as_str() {
                    raw_sans.push(s.trim().to_owned());
                }
            }
        }
        let mut hostnames = BTreeSet::new();
        let mut wildcards = BTreeSet::new();
        let mut ips = BTreeSet::new();
        for raw in raw_sans.into_iter().take(128) {
            let Some(norm) = normalize_ct_hostname(&raw) else {
                continue;
            };
            if norm.is_ip {
                ips.insert(norm.canonical);
            } else if norm.is_wildcard {
                wildcards.insert(norm.canonical);
            } else {
                hostnames.insert(norm.canonical);
            }
        }
        out.push(CtCertificate {
            stable_id,
            serial,
            not_before,
            not_after,
            entry_timestamp,
            hostnames: hostnames.into_iter().collect(),
            wildcards: wildcards.into_iter().collect(),
            ips: ips.into_iter().collect(),
        });
        if out.len() >= 32 {
            break;
        }
    }
    out.sort_by(|a, b| a.stable_id.cmp(&b.stable_id));
    out
}

/// Deterministic fixture CT provider (no network).
#[derive(Debug, Default)]
pub struct FixtureCtFetcher {
    pub responses: BTreeMap<String, serde_json::Value>,
    pub errors: BTreeMap<String, String>,
}

impl FixtureCtFetcher {
    pub fn with_response(mut self, domain: &str, value: serde_json::Value) -> Self {
        self.responses
            .insert(domain.trim().to_ascii_lowercase(), value);
        self
    }

    pub fn with_error(mut self, domain: &str, message: &str) -> Self {
        self.errors
            .insert(domain.trim().to_ascii_lowercase(), message.to_owned());
        self
    }
}

impl crate::investigate::CtFetcher for FixtureCtFetcher {
    fn fetch(
        &self,
        domain: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<serde_json::Value, String> {
        if cancelled.load(Ordering::Acquire) {
            return Err("cancelled".to_owned());
        }
        if Instant::now() >= deadline {
            return Err("deadline".to_owned());
        }
        let key = domain.trim().to_ascii_lowercase();
        if let Some(message) = self.errors.get(&key) {
            return Err(message.clone());
        }
        self.responses
            .get(&key)
            .cloned()
            .ok_or_else(|| "provider unavailable: no CT fixture for domain".to_owned())
    }
}

/// Bounded production CT via crt.sh JSON (legitimate public index).
#[derive(Debug, Clone)]
pub struct HttpCtFetcher {
    pub base: String,
    pub timeout: Duration,
    pub max_body_bytes: usize,
}

impl Default for HttpCtFetcher {
    fn default() -> Self {
        Self {
            base: "https://crt.sh/".to_owned(),
            timeout: Duration::from_secs(10),
            max_body_bytes: 512 * 1024,
        }
    }
}

impl crate::investigate::CtFetcher for HttpCtFetcher {
    fn fetch(
        &self,
        domain: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<serde_json::Value, String> {
        if cancelled.load(Ordering::Acquire) {
            return Err("cancelled".to_owned());
        }
        if Instant::now() >= deadline {
            return Err("deadline".to_owned());
        }
        let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if crate::search::canonical_domain_value(&clean).is_none() {
            return Err("invalid domain".to_owned());
        }
        // `%25` = `%` encoded: crt.sh wildcard query `%.example.test`.
        let url_text = format!("{}?q=%25.{}&output=json", self.base, clean);
        let url = url::Url::parse(&url_text).map_err(|_| "invalid CT URL".to_owned())?;
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
            return Ok(serde_json::json!([]));
        }
        if !(200..300).contains(&response.status) {
            return Err(format!("CT HTTP {}", response.status));
        }
        serde_json::from_slice(&response.body).map_err(|_| "malformed CT response".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_and_multiple_sans_normalize() {
        let value = serde_json::json!([
            {"serial": "AB12", "not_before": "2023-01-01T00:00:00Z",
             "name_value": "Example.TEST\napi.example.test\nAPI.EXAMPLE.TEST\n"}
        ]);
        let certs = parse_ct_response(&value);
        assert_eq!(certs.len(), 1);
        assert_eq!(
            certs[0].hostnames,
            vec!["api.example.test".to_owned(), "example.test".to_owned()]
        );
    }

    #[test]
    fn duplicates_case_trailing_dots_collapse() {
        let value = serde_json::json!([
            {"serial": "01", "name_value": "example.test.\nEXAMPLE.test\n example.test "},
            {"serial": "01", "name_value": "example.test"}
        ]);
        let certs = parse_ct_response(&value);
        // Same serial+no-validity duplicates collapse to one cert.
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].hostnames, vec!["example.test".to_owned()]);
    }

    #[test]
    fn wildcards_recorded_never_expanded() {
        let value = serde_json::json!([
            {"serial": "02", "name_value": "*.example.test\nwww.example.test"}
        ]);
        let certs = parse_ct_response(&value);
        assert_eq!(certs[0].wildcards, vec!["example.test".to_owned()]);
        assert_eq!(certs[0].hostnames, vec!["www.example.test".to_owned()]);
        // No invented `foo.example.test`.
        assert!(!certs[0].hostnames.iter().any(|h| h != "www.example.test"));
    }

    #[test]
    fn malformed_values_skipped() {
        let value = serde_json::json!([
            {"serial": "03", "name_value": "\n   \nnot a host!!!\n"}
        ]);
        let certs = parse_ct_response(&value);
        assert!(certs[0].hostnames.is_empty());
        assert!(certs[0].wildcards.is_empty());
    }

    #[test]
    fn historical_timestamps_preserved() {
        let value = serde_json::json!([
            {"serial": "04", "not_before": "2022-01-01T00:00:00Z",
             "not_after": "2023-01-01T00:00:00Z",
             "entry_timestamp": "2022-01-02T00:00:00Z",
             "name_value": "old.example.test"}
        ]);
        let certs = parse_ct_response(&value);
        assert_eq!(certs[0].not_before.as_deref(), Some("2022-01-01T00:00:00Z"));
        assert_eq!(
            certs[0].entry_timestamp.as_deref(),
            Some("2022-01-02T00:00:00Z")
        );
    }

    #[test]
    fn fixture_is_deterministic() {
        use crate::investigate::CtFetcher;
        let fetcher =
            FixtureCtFetcher::default().with_response("example.test", serde_json::json!([]));
        let deadline = Instant::now() + Duration::from_secs(5);
        let flag = AtomicBool::new(false);
        assert!(fetcher.fetch("example.test", deadline, &flag).is_ok());
        assert!(fetcher.fetch("other.test", deadline, &flag).is_err());
    }
}
