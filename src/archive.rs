//! Legitimate public archive/index intelligence (historical only).
//!
//! Represents historical URL, snapshot, first/last observed, historical
//! hostname/endpoint/redirect/technology. Historical observations remain
//! historical: an archived 2022 URL is never rendered as a live endpoint
//! unless current evidence independently establishes it. Archive-derived
//! hostnames never trigger active scans (entity creation is not contact).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// One historical snapshot (normalized, bounded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveSnapshot {
    pub url: String,
    pub timestamp: String,
    pub status: Option<String>,
    pub redirect: Option<String>,
    pub tech: Vec<String>,
}

fn bounded_text(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty() && s.len() <= 512)
}

/// Parse an archive index array into snapshots.
/// Accepts `[{url, timestamp, status, redirect, tech[]}]`; duplicates by
/// `(url, timestamp)` collapse; order deterministic (sorted). Malformed
/// entries skipped, never error.
pub fn parse_archive_response(value: &serde_json::Value) -> Vec<ArchiveSnapshot> {
    let arr = match value.as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for entry in arr.iter().take(128) {
        let url = match bounded_text(entry, "url") {
            Some(u) => u,
            None => continue,
        };
        if url.len() > 2048 || url.chars().any(char::is_control) {
            continue;
        }
        // Only http/https historical URLs; file/local schemes rejected.
        let Ok(parsed) = url::Url::parse(&url) else {
            continue;
        };
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            continue;
        }
        if parsed.host_str().is_none() {
            continue;
        }
        let timestamp = match bounded_text(entry, "timestamp") {
            Some(t) => t,
            None => continue,
        };
        if !seen.insert((url.clone(), timestamp.clone())) {
            continue;
        }
        let tech: Vec<String> = entry
            .get("tech")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty() && s.len() <= 64)
                    .take(8)
                    .collect()
            })
            .unwrap_or_default();
        out.push(ArchiveSnapshot {
            url,
            timestamp,
            status: bounded_text(entry, "status"),
            redirect: bounded_text(entry, "redirect"),
            tech,
        });
        if out.len() >= 32 {
            break;
        }
    }
    out.sort_by(|a, b| a.url.cmp(&b.url).then(a.timestamp.cmp(&b.timestamp)));
    out
}

/// First/last observed range over snapshots for one URL.
pub fn snapshot_range(snapshots: &[ArchiveSnapshot], url: &str) -> Option<(String, String)> {
    let mut times: Vec<&String> = snapshots
        .iter()
        .filter(|s| s.url == url)
        .map(|s| &s.timestamp)
        .collect();
    if times.is_empty() {
        return None;
    }
    times.sort();
    Some((
        (*times.first().unwrap()).clone(),
        (*times.last().unwrap()).clone(),
    ))
}

/// Deterministic fixture archive provider (no network).
#[derive(Debug, Default)]
pub struct FixtureArchiveFetcher {
    pub responses: BTreeMap<String, serde_json::Value>,
    pub errors: BTreeMap<String, String>,
}

impl FixtureArchiveFetcher {
    pub fn with_response(mut self, url: &str, value: serde_json::Value) -> Self {
        self.responses.insert(url.trim().to_owned(), value);
        self
    }

    pub fn with_error(mut self, url: &str, message: &str) -> Self {
        self.errors
            .insert(url.trim().to_owned(), message.to_owned());
        self
    }
}

impl crate::investigate::ArchiveFetcher for FixtureArchiveFetcher {
    fn fetch(
        &self,
        url: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<serde_json::Value, String> {
        if cancelled.load(Ordering::Acquire) {
            return Err("cancelled".to_owned());
        }
        if Instant::now() >= deadline {
            return Err("deadline".to_owned());
        }
        if let Some(message) = self.errors.get(url.trim()) {
            return Err(message.clone());
        }
        self.responses
            .get(url.trim())
            .cloned()
            .ok_or_else(|| "provider unavailable: no archive fixture for URL".to_owned())
    }
}

/// Bounded production archive (legitimate index, e.g. Common Crawl index
/// or Wayback CDX — base configurable). Historical only.
#[derive(Debug, Clone)]
pub struct HttpArchiveFetcher {
    pub base: String,
    pub timeout: Duration,
    pub max_body_bytes: usize,
}

impl Default for HttpArchiveFetcher {
    fn default() -> Self {
        Self {
            base: "https://index.commoncrawl.org/".to_owned(),
            timeout: Duration::from_secs(10),
            max_body_bytes: 512 * 1024,
        }
    }
}

impl crate::investigate::ArchiveFetcher for HttpArchiveFetcher {
    fn fetch(
        &self,
        url: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<serde_json::Value, String> {
        if cancelled.load(Ordering::Acquire) {
            return Err("cancelled".to_owned());
        }
        if Instant::now() >= deadline {
            return Err("deadline".to_owned());
        }
        // Validate as http/https URL first (SSRF guard: no file/local).
        let parsed = url::Url::parse(url.trim()).map_err(|_| "invalid URL".to_owned())?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err("archive requires http/https URL".to_owned());
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
        // Base is a configured index endpoint; the URL is sent as a query
        // parameter (never fetched directly here).
        let mut index =
            url::Url::parse(&self.base).map_err(|_| "invalid archive base".to_owned())?;
        index
            .query_pairs_mut()
            .append_pair("url", url.trim())
            .append_pair("output", "json");
        let response = client
            .get(&index, timeout, self.max_body_bytes, 2, &ctx)
            .map_err(|e| e.to_string())?;
        if response.status == 429 {
            return Err("rate_limited".to_owned());
        }
        if !(200..300).contains(&response.status) {
            return Err(format!("archive HTTP {}", response.status));
        }
        serde_json::from_slice(&response.body).map_err(|_| "malformed archive response".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_url_with_multiple_timestamps() {
        let value = serde_json::json!([
            {"url": "https://example.test/", "timestamp": "20220101000000"},
            {"url": "https://example.test/", "timestamp": "20230101000000"},
            {"url": "https://example.test/", "timestamp": "20220101000000"}
        ]);
        let snaps = parse_archive_response(&value);
        assert_eq!(snaps.len(), 2);
        let range = snapshot_range(&snaps, "https://example.test/").unwrap();
        assert_eq!(range.0, "20220101000000");
        assert_eq!(range.1, "20230101000000");
    }

    #[test]
    fn historical_only_endpoint_and_local_schemes_rejected() {
        let value = serde_json::json!([
            {"url": "https://example.test/old", "timestamp": "20200101"},
            {"url": "file:///etc/passwd", "timestamp": "20200101"}
        ]);
        let snaps = parse_archive_response(&value);
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].url, "https://example.test/old");
    }

    #[test]
    fn provider_error_timeout_shapes() {
        use crate::investigate::ArchiveFetcher;
        let fetcher =
            FixtureArchiveFetcher::default().with_error("https://example.test/", "rate_limited");
        let deadline = Instant::now() + Duration::from_secs(5);
        let flag = AtomicBool::new(false);
        assert_eq!(
            fetcher
                .fetch("https://example.test/", deadline, &flag)
                .unwrap_err(),
            "rate_limited"
        );
    }
}
