//! Temporal evidence (first-class time, historical vs current).
//!
//! Supports `observed_at`, `retrieved_at`, `first_seen`, `last_seen`,
//! `valid_from`, `valid_until` as bounded string attributes on entities
//! and relationships. Historical timestamps are never replaced by
//! retrieval time: `example.test -> 192.0.2.10` in year A and
//! `example.test -> 198.51.100.20` in year B coexist as timestamped
//! relationships without pretending both are current.

use std::collections::BTreeMap;

/// Bounded timestamp fields (RFC3339 or epoch-seconds strings, <=64 chars).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TemporalMarks {
    pub observed_at: Option<String>,
    pub retrieved_at: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
}

fn bounded_time(raw: &str) -> Option<String> {
    let clean = raw.trim().to_owned();
    if clean.is_empty() || clean.len() > 64 || clean.chars().any(char::is_control) {
        return None;
    }
    Some(clean)
}

impl TemporalMarks {
    pub fn attributes(&self) -> BTreeMap<String, String> {
        let mut attrs = BTreeMap::new();
        if let Some(v) = self.observed_at.clone().and_then(|s| bounded_time(&s)) {
            attrs.insert("observed_at".to_owned(), v);
        }
        if let Some(v) = self.retrieved_at.clone().and_then(|s| bounded_time(&s)) {
            attrs.insert("retrieved_at".to_owned(), v);
        }
        if let Some(v) = self.first_seen.clone().and_then(|s| bounded_time(&s)) {
            attrs.insert("first_seen".to_owned(), v);
        }
        if let Some(v) = self.last_seen.clone().and_then(|s| bounded_time(&s)) {
            attrs.insert("last_seen".to_owned(), v);
        }
        if let Some(v) = self.valid_from.clone().and_then(|s| bounded_time(&s)) {
            attrs.insert("valid_from".to_owned(), v);
        }
        if let Some(v) = self.valid_until.clone().and_then(|s| bounded_time(&s)) {
            attrs.insert("valid_until".to_owned(), v);
        }
        attrs
    }

    /// Merge into existing attributes without overwriting historical values
    /// with retrieval time: existing `observed_at`/`valid_from` win.
    pub fn merge_into(&self, attrs: &mut BTreeMap<String, String>) {
        for (key, value) in self.attributes() {
            attrs.entry(key).or_insert(value);
        }
    }
}

/// True when two timestamped observations describe different periods
/// (neither is necessarily current).
pub fn is_historical(attrs: &BTreeMap<String, String>) -> bool {
    attrs.get("historical").is_some_and(|v| v == "true")
        || attrs.contains_key("valid_from")
        || attrs.contains_key("observed_at")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_and_current_coexist() {
        let old = TemporalMarks {
            observed_at: Some("2022-01-01T00:00:00Z".to_owned()),
            retrieved_at: Some("2024-01-01T00:00:00Z".to_owned()),
            ..TemporalMarks::default()
        };
        let new = TemporalMarks {
            observed_at: Some("2024-06-01T00:00:00Z".to_owned()),
            retrieved_at: Some("2024-06-02T00:00:00Z".to_owned()),
            ..TemporalMarks::default()
        };
        let old_attrs = old.attributes();
        let new_attrs = new.attributes();
        assert_ne!(old_attrs.get("observed_at"), new_attrs.get("observed_at"));
        // Retrieval never overwrites observation.
        let mut merged = old_attrs.clone();
        new.merge_into(&mut merged);
        assert_eq!(
            merged.get("observed_at").map(String::as_str),
            Some("2022-01-01T00:00:00Z")
        );
    }

    #[test]
    fn control_characters_rejected() {
        assert!(bounded_time("bad\x01time").is_none());
    }
}
