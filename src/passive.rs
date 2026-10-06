//! Passive infrastructure connector abstraction.
//!
//! Clean interface for legitimate configured public/passive providers
//! (historical DNS, service observations, certificate observations,
//! hostname observations, infrastructure metadata, reputation/context).
//! No product assumptions in core: providers declare metadata, RXScan
//! enforces scope/budget/policy. Every observation carries provider,
//! source id, `retrieved_at`, optional `observed_at`, observation class,
//! confidence, and `direct_observation=false` — a provider saying "port
//! 443 seen six months ago" never appears as direct RXScan observation.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::search::ContactClass;

/// Provider capabilities (least-privilege, no shell execution).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderCapability {
    PublicHttp,
    Dns,
    ConfiguredApi,
    LocalDataset,
    DirectNetwork,
    FilesystemRead,
}

impl ProviderCapability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicHttp => "public_http",
            Self::Dns => "dns",
            Self::ConfiguredApi => "configured_api",
            Self::LocalDataset => "local_dataset",
            Self::DirectNetwork => "direct_network",
            Self::FilesystemRead => "filesystem_read",
        }
    }
}

/// Static provider descriptor for planning, explain, and capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderDescriptor {
    pub id: String,
    pub supported_kinds: Vec<String>,
    pub requires_credentials: bool,
    pub contact_class: ContactClass,
    pub rate_per_minute: u16,
    pub source_category: String,
    pub capabilities: Vec<ProviderCapability>,
}

impl ProviderDescriptor {
    pub fn fixture(id: &str, kinds: &[&str]) -> Self {
        Self {
            id: id.to_owned(),
            supported_kinds: kinds.iter().map(|s| (*s).to_owned()).collect(),
            requires_credentials: false,
            contact_class: ContactClass::PassivePublic,
            rate_per_minute: 60,
            source_category: "fixture".to_owned(),
            capabilities: vec![ProviderCapability::LocalDataset],
        }
    }
}

/// One passive observation (never a direct RXScan network observation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassiveObservation {
    pub provider: String,
    pub source_id: String,
    pub kind: String,
    pub value: String,
    pub retrieved_at: u64,
    pub observed_at: Option<String>,
    pub contact_class: ContactClass,
    pub confidence: u8,
    pub evidence: Vec<String>,
}

impl PassiveObservation {
    pub fn attributes(&self) -> BTreeMap<String, String> {
        let mut attrs = BTreeMap::from([
            ("provider".to_owned(), self.provider.clone()),
            ("source_id".to_owned(), self.source_id.clone()),
            ("retrieved_at".to_owned(), self.retrieved_at.to_string()),
            (
                "contact_class".to_owned(),
                format!("{:?}", self.contact_class).to_ascii_lowercase(),
            ),
            ("direct_observation".to_owned(), "false".to_owned()),
        ]);
        if let Some(when) = self.observed_at.clone() {
            attrs.insert("observed_at".to_owned(), when);
        }
        attrs
    }
}

/// Passive connector trait (fixture + configured API).
pub trait PassiveConnector: Send + Sync + std::fmt::Debug {
    fn descriptor(&self) -> &ProviderDescriptor;
    fn lookup(
        &self,
        kind: &str,
        value: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Vec<PassiveObservation>, String>;
}

/// Deterministic fixture connector (tests, no network).
#[derive(Debug)]
pub struct FixturePassiveConnector {
    pub descriptor: ProviderDescriptor,
    pub records: BTreeMap<(String, String), Vec<PassiveObservation>>,
    pub errors: BTreeMap<(String, String), String>,
}

impl FixturePassiveConnector {
    pub fn new(id: &str, kinds: &[&str]) -> Self {
        Self {
            descriptor: ProviderDescriptor::fixture(id, kinds),
            records: BTreeMap::new(),
            errors: BTreeMap::new(),
        }
    }

    pub fn with_records(
        mut self,
        kind: &str,
        value: &str,
        observations: Vec<PassiveObservation>,
    ) -> Self {
        self.records.insert(
            (
                kind.trim().to_ascii_lowercase(),
                value.trim().to_ascii_lowercase(),
            ),
            observations,
        );
        self
    }

    pub fn with_error(mut self, kind: &str, value: &str, message: &str) -> Self {
        self.errors.insert(
            (
                kind.trim().to_ascii_lowercase(),
                value.trim().to_ascii_lowercase(),
            ),
            message.to_owned(),
        );
        self
    }
}

impl PassiveConnector for FixturePassiveConnector {
    fn descriptor(&self) -> &ProviderDescriptor {
        &self.descriptor
    }

    fn lookup(
        &self,
        kind: &str,
        value: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Vec<PassiveObservation>, String> {
        if cancelled.load(Ordering::Acquire) {
            return Err("cancelled".to_owned());
        }
        if Instant::now() >= deadline {
            return Err("deadline".to_owned());
        }
        let key = (
            kind.trim().to_ascii_lowercase(),
            value.trim().to_ascii_lowercase(),
        );
        if let Some(message) = self.errors.get(&key) {
            return Err(message.clone());
        }
        Ok(self.records.get(&key).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(value: &str) -> PassiveObservation {
        PassiveObservation {
            provider: "fixture-passive".to_owned(),
            source_id: "src-1".to_owned(),
            kind: "hostname".to_owned(),
            value: value.to_owned(),
            retrieved_at: 1_700_000_000,
            observed_at: Some("2024-01-01T00:00:00Z".to_owned()),
            contact_class: ContactClass::PassivePublic,
            confidence: 70,
            evidence: vec![format!("historical hostname {value}")],
        }
    }

    #[test]
    fn historical_never_masquerades_as_direct() {
        let connector = FixturePassiveConnector::new("fixture-passive", &["hostname"])
            .with_records("hostname", "example.test", vec![obs("api.example.test")]);
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let flag = AtomicBool::new(false);
        let found = connector
            .lookup("hostname", "example.test", deadline, &flag)
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0]
                .attributes()
                .get("direct_observation")
                .map(String::as_str),
            Some("false")
        );
        assert!(found[0].observed_at.is_some());
    }

    #[test]
    fn unavailable_is_distinct_from_not_found() {
        let connector = FixturePassiveConnector::new("fixture-passive", &["hostname"]).with_error(
            "hostname",
            "example.test",
            "provider unavailable",
        );
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let flag = AtomicBool::new(false);
        assert_eq!(
            connector
                .lookup("hostname", "example.test", deadline, &flag)
                .unwrap_err(),
            "provider unavailable"
        );
        // No fixture at all is empty (not found), not error.
        let empty: FixturePassiveConnector =
            FixturePassiveConnector::new("fixture-passive", &["hostname"]);
        assert!(
            empty
                .lookup("hostname", "example.test", deadline, &flag)
                .unwrap()
                .is_empty()
        );
    }
}
