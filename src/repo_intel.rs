//! Public repository intelligence (metadata only, never cloned).
//!
//! Entities: repository, organization, public contributor identity, public
//! commit identity, release/package, public signing key, domain/URL
//! references. Relationships use typed vocabulary (`owns_repository`,
//! `contributed_to`, `published_release`, `references_domain`,
//! `references_url`, `uses_package`, `signed_by`). Commit email is never
//! treated as verified real-world identity without supporting evidence.
//! Secrets are never stored: public material that looks like a credential
//! yields safe defensive exposure metadata (`credential_material_exposed`)
//! instead of secret values.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Normalized public repository metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepoMetadata {
    pub owner: String,
    pub name: String,
    pub description: Option<String>,
    pub contributors: Vec<String>,
    pub commit_identities: Vec<String>,
    pub releases: Vec<String>,
    pub packages: Vec<String>,
    pub signing_keys: Vec<String>,
    pub domain_refs: Vec<String>,
    pub url_refs: Vec<String>,
    /// True when public material appears to expose credential-like text.
    /// No secret values are retained anywhere.
    pub credential_material_exposed: bool,
}

fn bounded_names(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control))
                .take(16)
                .collect()
        })
        .unwrap_or_default()
}

/// Heuristic: does public text look like exposed credential material?
/// Conservative substring signals only (never validates secrets).
fn looks_like_secret(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    // `password =`, `api_key =`, PEM headers, `ghp_`/`gho_` prefixes.
    lower.contains("password")
        || lower.contains("api_key")
        || lower.contains("apikey")
        || lower.contains("-----begin private key-----")
        || lower.contains("ghp_")
        || lower.contains("gho_")
}

/// Parse repository metadata JSON (tolerant; missing fields are empty).
/// `description`/`readme`-ish text is scanned for secret-like signals and
/// then dropped (only the boolean survives).
pub fn parse_repo_metadata(owner: &str, name: &str, value: &serde_json::Value) -> RepoMetadata {
    let mut meta = RepoMetadata {
        owner: owner.trim().to_ascii_lowercase(),
        name: name.trim().to_ascii_lowercase(),
        ..RepoMetadata::default()
    };
    if let Some(desc) = value.get("description").and_then(|v| v.as_str()) {
        if looks_like_secret(desc) {
            meta.credential_material_exposed = true;
        } else if !desc.trim().is_empty() {
            meta.description = Some(desc.trim().chars().take(256).collect());
        }
    }
    meta.contributors = bounded_names(value, "contributors");
    meta.commit_identities = bounded_names(value, "commit_identities");
    meta.releases = bounded_names(value, "releases");
    meta.packages = bounded_names(value, "packages");
    meta.signing_keys = bounded_names(value, "signing_keys")
        .into_iter()
        .take(8)
        .collect();
    // Domain/URL refs: keep only http/https URLs and valid domains.
    let mut domains = BTreeSet::new();
    let mut urls = BTreeSet::new();
    if let Some(refs) = value.get("url_refs").and_then(|v| v.as_array()) {
        for item in refs.iter().take(32) {
            if let Some(s) = item.as_str() {
                let clean = s.trim().to_owned();
                if clean.len() > 2048 || clean.chars().any(char::is_control) {
                    continue;
                }
                if let Ok(parsed) = url::Url::parse(&clean) {
                    if parsed.scheme() == "http" || parsed.scheme() == "https" {
                        if let Some(host) = parsed.host_str() {
                            let lower = host.to_ascii_lowercase();
                            if crate::search::canonical_domain_value(&lower).is_some() {
                                domains.insert(lower);
                            }
                        }
                        if looks_like_secret(&clean) {
                            meta.credential_material_exposed = true;
                        }
                        urls.insert(clean);
                    } else if looks_like_secret(&clean) {
                        meta.credential_material_exposed = true;
                    }
                } else if looks_like_secret(&clean) {
                    meta.credential_material_exposed = true;
                }
            }
        }
    }
    // Explicit domain_refs (validated).
    if let Some(refs) = value.get("domain_refs").and_then(|v| v.as_array()) {
        for item in refs.iter().take(32) {
            if let Some(s) = item.as_str() {
                let lower = s.trim().trim_end_matches('.').to_ascii_lowercase();
                if crate::search::canonical_domain_value(&lower).is_some() {
                    domains.insert(lower);
                }
            }
        }
    }
    meta.domain_refs = domains.into_iter().take(16).collect();
    meta.url_refs = urls.into_iter().take(16).collect();
    // Deduplicate identities (case-insensitive).
    for list in [
        &mut meta.contributors,
        &mut meta.commit_identities,
        &mut meta.releases,
        &mut meta.packages,
    ] {
        let mut seen = BTreeSet::new();
        list.retain(|item| seen.insert(item.to_ascii_lowercase()));
        list.sort();
    }
    meta
}

/// Deterministic fixture repository provider (no network, nothing cloned).
#[derive(Debug, Default)]
pub struct FixtureRepoFetcher {
    pub responses: BTreeMap<(String, String), serde_json::Value>,
    pub errors: BTreeMap<(String, String), String>,
}

impl FixtureRepoFetcher {
    pub fn with_response(mut self, owner: &str, name: &str, value: serde_json::Value) -> Self {
        self.responses.insert(
            (
                owner.trim().to_ascii_lowercase(),
                name.trim().to_ascii_lowercase(),
            ),
            value,
        );
        self
    }

    pub fn with_error(mut self, owner: &str, name: &str, message: &str) -> Self {
        self.errors.insert(
            (
                owner.trim().to_ascii_lowercase(),
                name.trim().to_ascii_lowercase(),
            ),
            message.to_owned(),
        );
        self
    }
}

impl crate::investigate::RepoFetcher for FixtureRepoFetcher {
    fn fetch(
        &self,
        owner: &str,
        name: &str,
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
            owner.trim().to_ascii_lowercase(),
            name.trim().to_ascii_lowercase(),
        );
        if let Some(message) = self.errors.get(&key) {
            return Err(message.clone());
        }
        self.responses
            .get(&key)
            .cloned()
            .ok_or_else(|| "provider unavailable: no repo fixture".to_owned())
    }
}

/// Bounded production repository metadata (public forge API, base
/// configurable; default public API with no auth). Nothing cloned.
#[derive(Debug, Clone)]
pub struct HttpRepoFetcher {
    pub base: String,
    pub timeout: Duration,
    pub max_body_bytes: usize,
}

impl Default for HttpRepoFetcher {
    fn default() -> Self {
        Self {
            base: "https://api.github.com/repos/".to_owned(),
            timeout: Duration::from_secs(10),
            max_body_bytes: 256 * 1024,
        }
    }
}

impl crate::investigate::RepoFetcher for HttpRepoFetcher {
    fn fetch(
        &self,
        owner: &str,
        name: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<serde_json::Value, String> {
        if cancelled.load(Ordering::Acquire) {
            return Err("cancelled".to_owned());
        }
        if Instant::now() >= deadline {
            return Err("deadline".to_owned());
        }
        if crate::search::canonical_org_value(owner).is_none() {
            return Err("invalid repository owner".to_owned());
        }
        let url_text = format!("{}{}/{}", self.base, owner.trim(), name.trim());
        let url = url::Url::parse(&url_text).map_err(|_| "invalid repo URL".to_owned())?;
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
        if !(200..300).contains(&response.status) {
            return Err(format!("repo HTTP {}", response.status));
        }
        serde_json::from_slice(&response.body).map_err(|_| "malformed repo response".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalization_and_org_relationship_inputs() {
        let meta = parse_repo_metadata(
            "Example-Org",
            "Example-Project",
            &serde_json::json!({
                "contributors": ["alice", "Alice", "bob"],
                "commit_identities": ["alice@example.test"],
                "domain_refs": ["Example.TEST", "bad..domain"],
                "url_refs": ["https://example.test/x", "file:///etc/passwd"]
            }),
        );
        assert_eq!(meta.owner, "example-org");
        assert_eq!(
            meta.contributors,
            vec!["alice".to_owned(), "bob".to_owned()]
        );
        assert_eq!(meta.domain_refs, vec!["example.test".to_owned()]);
        assert_eq!(meta.url_refs, vec!["https://example.test/x".to_owned()]);
        assert!(!meta.credential_material_exposed);
    }

    #[test]
    fn secret_like_material_yields_metadata_only() {
        let meta = parse_repo_metadata(
            "example-org",
            "example-project",
            &serde_json::json!({"description": "token ghp_abc123 here"}),
        );
        assert!(meta.credential_material_exposed);
        assert!(meta.description.is_none());
    }

    #[test]
    fn missing_fields_and_errors() {
        let meta = parse_repo_metadata("o", "n", &serde_json::json!({}));
        assert!(meta.contributors.is_empty());
        use crate::investigate::RepoFetcher;
        let fetcher = FixtureRepoFetcher::default().with_error(
            "example-org",
            "example-project",
            "rate_limited",
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let flag = AtomicBool::new(false);
        assert_eq!(
            fetcher
                .fetch("example-org", "example-project", deadline, &flag)
                .unwrap_err(),
            "rate_limited"
        );
    }
}
