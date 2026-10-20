//! Breach / leak exposure lookup.
//!
//! Integrates with licensed breach-intelligence providers via their APIs.
//! Raw breach corpora are never downloaded, stored, indexed or redistributed;
//! only breach metadata is returned as evidence.

use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreachError {
    MissingApiKey,
    Timeout,
    RateLimited,
    Http(String),
    InvalidIdentifier(String),
}

impl std::fmt::Display for BreachError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Never include the key or the identifier beyond a generic message.
            Self::MissingApiKey => write!(f, "breach provider API key is not configured"),
            Self::Timeout => write!(f, "breach provider timed out"),
            Self::RateLimited => write!(f, "breach provider rate limited"),
            Self::Http(detail) => write!(f, "breach provider HTTP error: {detail}"),
            Self::InvalidIdentifier(_) => write!(f, "invalid identifier for breach lookup"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreachRecord {
    pub breach_name: String,
    pub disclosure_date: String,
    pub affected_fields: Vec<String>,
    pub record_count: Option<u64>,
    pub provider: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreachLookup {
    pub identifier: String,
    pub records: Vec<BreachRecord>,
    pub provider: String,
    pub uncertainty: bool,
}

/// Pluggable breach-intelligence provider.
pub trait BreachProvider: Send + Sync {
    fn id(&self) -> &str;
    fn lookup(&self, identifier: &str) -> Result<Vec<BreachRecord>, BreachError>;
}

/// A provider that always returns a configured result, for tests and offline use.
pub struct StaticProvider {
    pub id: String,
    pub result: Result<Vec<BreachRecord>, BreachError>,
}

impl StaticProvider {
    pub fn new(id: impl Into<String>, result: Result<Vec<BreachRecord>, BreachError>) -> Self {
        Self {
            id: id.into(),
            result,
        }
    }
}

impl BreachProvider for StaticProvider {
    fn id(&self) -> &str {
        &self.id
    }
    fn lookup(&self, _identifier: &str) -> Result<Vec<BreachRecord>, BreachError> {
        self.result.clone()
    }
}

/// A provider requiring an API key; returns MissingApiKey when absent.
pub struct ApiKeyProvider {
    pub id: String,
    pub api_key: Option<String>,
    pub base_url: String,
}

impl ApiKeyProvider {
    pub fn new(id: impl Into<String>, api_key: Option<String>) -> Self {
        Self {
            id: id.into(),
            api_key,
            base_url: String::new(),
        }
    }
}

impl std::fmt::Debug for ApiKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyProvider")
            .field("id", &self.id)
            .field("api_key", &"[redacted]")
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl BreachProvider for ApiKeyProvider {
    fn id(&self) -> &str {
        &self.id
    }
    fn lookup(&self, _identifier: &str) -> Result<Vec<BreachRecord>, BreachError> {
        if self
            .api_key
            .as_ref()
            .map(|k| k.trim().is_empty())
            .unwrap_or(true)
        {
            return Err(BreachError::MissingApiKey);
        }
        // No network in this stub; real implementation would query here.
        Ok(Vec::new())
    }
}

/// Aggregates multiple providers, preserving disagreement (both results).
pub struct BreachAggregator {
    pub providers: Vec<Box<dyn BreachProvider>>,
    pub deadline: Option<Duration>,
}

impl BreachAggregator {
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
            deadline: None,
        }
    }

    pub fn add_provider(&mut self, provider: Box<dyn BreachProvider>) {
        self.providers.push(provider);
    }

    pub fn lookup_all(&self, identifier: &str) -> Vec<BreachLookup> {
        let mut out = Vec::new();
        for p in &self.providers {
            match p.lookup(identifier) {
                Ok(records) => out.push(BreachLookup {
                    identifier: identifier.to_owned(),
                    records,
                    provider: p.id().to_owned(),
                    uncertainty: false,
                }),
                Err(_) => out.push(BreachLookup {
                    identifier: identifier.to_owned(),
                    records: Vec::new(),
                    provider: p.id().to_owned(),
                    uncertainty: true,
                }),
            }
        }
        out
    }
}

impl Default for BreachAggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a breach record into an evidence-friendly attribute map.
pub fn to_evidence_attrs(record: &BreachRecord) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("breach_name".to_owned(), record.breach_name.clone());
    m.insert("disclosure_date".to_owned(), record.disclosure_date.clone());
    m.insert(
        "affected_fields".to_owned(),
        record.affected_fields.join(","),
    );
    m.insert("provider".to_owned(), record.provider.clone());
    if let Some(c) = record.record_count {
        m.insert("record_count".to_owned(), c.to_string());
    }
    m
}

pub fn is_uncertain(result: &BreachLookup) -> bool {
    result.uncertainty
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_lookup_shape() {
        let rec = BreachRecord {
            breach_name: "ExampleBreach".into(),
            disclosure_date: "2020-01-01".into(),
            affected_fields: vec!["email".into()],
            record_count: Some(100),
            provider: "p1".into(),
        };
        let provider = StaticProvider::new("p1", Ok(vec![rec.clone()]));
        let mut agg = BreachAggregator::new();
        agg.add_provider(Box::new(provider));
        let res = agg.lookup_all("user@example.test");
        assert_eq!(res.len(), 1);
        assert!(!res[0].uncertainty);
        assert_eq!(res[0].records.len(), 1);
    }

    #[test]
    fn timeout_is_uncertainty() {
        let provider = StaticProvider::new("p1", Err(BreachError::Timeout));
        let mut agg = BreachAggregator::new();
        agg.add_provider(Box::new(provider));
        let res = agg.lookup_all("user@example.test");
        assert!(res[0].uncertainty);
        assert!(res[0].records.is_empty());
    }

    #[test]
    fn rate_limit_is_uncertainty() {
        let provider = StaticProvider::new("p1", Err(BreachError::RateLimited));
        let mut agg = BreachAggregator::new();
        agg.add_provider(Box::new(provider));
        let res = agg.lookup_all("user@example.test");
        assert!(res[0].uncertainty);
    }

    #[test]
    fn disagreement_surfaces_both() {
        let r1 = BreachRecord {
            breach_name: "B1".into(),
            disclosure_date: "2020".into(),
            affected_fields: vec![],
            record_count: None,
            provider: "p1".into(),
        };
        let r2 = BreachRecord {
            breach_name: "B2".into(),
            disclosure_date: "2021".into(),
            affected_fields: vec![],
            record_count: None,
            provider: "p2".into(),
        };
        let p1 = StaticProvider::new("p1", Ok(vec![r1]));
        let p2 = StaticProvider::new("p2", Ok(vec![r2]));
        let mut agg = BreachAggregator::new();
        agg.add_provider(Box::new(p1));
        agg.add_provider(Box::new(p2));
        let res = agg.lookup_all("user@example.test");
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].records[0].breach_name, "B1");
        assert_eq!(res[1].records[0].breach_name, "B2");
    }

    #[test]
    fn missing_api_key_clear_error() {
        let provider = ApiKeyProvider::new("p1", None);
        let err = provider.lookup("user@example.test").unwrap_err();
        assert_eq!(err, BreachError::MissingApiKey);
        assert!(!err.to_string().contains("secret"));
    }

    #[test]
    fn key_not_in_output() {
        let provider = ApiKeyProvider::new("p1", Some("supersecret".into()));
        // no panic; result empty
        let _ = provider.lookup("user@example.test");
        let s = format!("{:?}", provider);
        assert!(!s.contains("supersecret"));
    }
}
