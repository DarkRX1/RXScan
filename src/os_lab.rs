//! Offline, privacy-safe measurement fixtures for future OS fingerprints.
//!
//! This module never sends traffic and never writes production packs. A
//! maintainer captures normalized observations from an explicitly targeted
//! `--os` run, records repeat samples, sanitizes the fixture, then reviews
//! the deterministic stable/variable analysis before proposing any rule.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::os_fingerprint::{OsAddressFamily, OsObservation};

pub const OS_LAB_SCHEMA_VERSION: u16 = 1;
pub const MAX_LAB_SAMPLES: usize = 64;
pub const MAX_LAB_OBSERVATIONS_PER_SAMPLE: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabProvenance {
    MeasuredControlled,
    SyntheticFixture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabCapabilitySummary {
    pub backend: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsLabSample {
    pub sample_index: u32,
    pub observations: Vec<OsObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsLabFixture {
    pub schema_version: u16,
    pub fixture_id: String,
    pub expected_os_family: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_os_version: Option<String>,
    pub target: String,
    pub rxscan_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rxscan_commit: Option<String>,
    pub provenance: LabProvenance,
    pub capability: LabCapabilitySummary,
    pub samples: Vec<OsLabSample>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabFeatureSet {
    pub source: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<OsAddressFamily>,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsLabAnalysis {
    pub schema_version: u16,
    pub fixture_id: String,
    pub expected_os_family: String,
    pub sample_count: usize,
    pub stable_features: Vec<LabFeatureSet>,
    pub variable_features: Vec<LabFeatureSet>,
    pub production_pack_modified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabError(pub String);

impl std::fmt::Display for LabError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for LabError {}

impl OsLabFixture {
    pub fn from_json(input: &str) -> Result<Self, LabError> {
        let fixture: Self = serde_json::from_str(input)
            .map_err(|error| LabError(format!("invalid OS lab fixture: {error}")))?;
        fixture.validate()?;
        Ok(fixture)
    }

    pub fn to_pretty_json(&self) -> Result<String, LabError> {
        self.validate()?;
        serde_json::to_string_pretty(self)
            .map_err(|error| LabError(format!("cannot encode OS lab fixture: {error}")))
    }

    pub fn validate(&self) -> Result<(), LabError> {
        if self.schema_version != OS_LAB_SCHEMA_VERSION {
            return Err(LabError(format!(
                "unsupported OS lab schema {}",
                self.schema_version
            )));
        }
        validate_text("fixture_id", &self.fixture_id, 96)?;
        validate_text("expected_os_family", &self.expected_os_family, 64)?;
        validate_text("target", &self.target, 255)?;
        validate_text("rxscan_version", &self.rxscan_version, 32)?;
        validate_text("capability.backend", &self.capability.backend, 64)?;
        validate_text("capability.status", &self.capability.status, 128)?;
        if self.samples.is_empty() || self.samples.len() > MAX_LAB_SAMPLES {
            return Err(LabError(format!(
                "samples must contain 1..={MAX_LAB_SAMPLES} entries"
            )));
        }
        let mut indexes = BTreeSet::new();
        for sample in &self.samples {
            if !indexes.insert(sample.sample_index) {
                return Err(LabError("duplicate sample_index".to_owned()));
            }
            if sample.observations.len() > MAX_LAB_OBSERVATIONS_PER_SAMPLE {
                return Err(LabError(format!(
                    "sample observation count exceeds {MAX_LAB_OBSERVATIONS_PER_SAMPLE}"
                )));
            }
            for observation in &sample.observations {
                validate_text("observation.source", &observation.source, 64)?;
                validate_text("observation.kind", &observation.kind, 64)?;
                validate_text("observation.value", &observation.value, 64)?;
            }
        }
        Ok(())
    }

    /// Produce a repository-safe fixture. Correlation-sensitive live target
    /// addresses are replaced only after capture, timestamps and free-form
    /// details are removed, and semantic observation values are preserved.
    pub fn sanitized(&self) -> Result<Self, LabError> {
        self.validate()?;
        let mut clean = self.clone();
        let v6 = clean
            .samples
            .iter()
            .flat_map(|sample| &sample.observations)
            .any(|observation| observation.family == Some(OsAddressFamily::V6));
        clean.target = if v6 {
            "2001:db8::10".to_owned()
        } else {
            "192.0.2.10".to_owned()
        };
        clean.notes = None;
        for sample in &mut clean.samples {
            for observation in &mut sample.observations {
                observation.timestamp_ms = None;
                observation.detail = None;
            }
            sort_observations(&mut sample.observations);
        }
        clean.samples.sort_by_key(|sample| sample.sample_index);
        Ok(clean)
    }

    pub fn analyze(&self) -> Result<OsLabAnalysis, LabError> {
        self.validate()?;
        type Key = (String, String, Option<String>);
        let mut values: BTreeMap<Key, BTreeSet<String>> = BTreeMap::new();
        let mut occurrences: BTreeMap<Key, usize> = BTreeMap::new();
        for sample in &self.samples {
            let mut seen = BTreeSet::new();
            for observation in &sample.observations {
                let family = observation.family.map(|value| match value {
                    OsAddressFamily::V4 => "v4".to_owned(),
                    OsAddressFamily::V6 => "v6".to_owned(),
                });
                let key = (observation.source.clone(), observation.kind.clone(), family);
                values
                    .entry(key.clone())
                    .or_default()
                    .insert(observation.value.clone());
                seen.insert(key);
            }
            for key in seen {
                *occurrences.entry(key).or_default() += 1;
            }
        }
        let mut stable_features = Vec::new();
        let mut variable_features = Vec::new();
        for ((source, kind, family), feature_values) in values {
            let key = (source.clone(), kind.clone(), family.clone());
            let feature = LabFeatureSet {
                source,
                kind,
                family: family.as_deref().map(|value| {
                    if value == "v6" {
                        OsAddressFamily::V6
                    } else {
                        OsAddressFamily::V4
                    }
                }),
                values: feature_values.into_iter().collect(),
            };
            if occurrences.get(&key) == Some(&self.samples.len()) && feature.values.len() == 1 {
                stable_features.push(feature);
            } else {
                variable_features.push(feature);
            }
        }
        Ok(OsLabAnalysis {
            schema_version: OS_LAB_SCHEMA_VERSION,
            fixture_id: self.fixture_id.clone(),
            expected_os_family: self.expected_os_family.clone(),
            sample_count: self.samples.len(),
            stable_features,
            variable_features,
            production_pack_modified: false,
        })
    }
}

fn validate_text(label: &str, value: &str, max: usize) -> Result<(), LabError> {
    if value.trim().is_empty() || value.chars().count() > max || value.contains('\0') {
        return Err(LabError(format!("invalid {label}")));
    }
    Ok(())
}

fn sort_observations(observations: &mut [OsObservation]) {
    observations.sort_by(|left, right| {
        (&left.probe_id, &left.source, &left.kind, &left.value).cmp(&(
            &right.probe_id,
            &right.source,
            &right.kind,
            &right.value,
        ))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os_fingerprint::{OsProvenance, OsQuality};

    fn observation(kind: &str, value: &str) -> OsObservation {
        OsObservation {
            kind: kind.to_owned(),
            value: value.to_owned(),
            source: "tcp_window".to_owned(),
            family: Some(OsAddressFamily::V4),
            probe_id: Some("tcp-syn-80".to_owned()),
            timestamp_ms: Some(42),
            provenance: OsProvenance::Fixture,
            quality: OsQuality::Medium,
            detail: Some("discard this free-form capture detail".to_owned()),
        }
    }

    fn fixture() -> OsLabFixture {
        OsLabFixture {
            schema_version: OS_LAB_SCHEMA_VERSION,
            fixture_id: "controlled-example-1".to_owned(),
            expected_os_family: "ExampleOS".to_owned(),
            expected_os_version: None,
            target: "router.example.test".to_owned(),
            rxscan_version: "1.0.2".to_owned(),
            rxscan_commit: Some("0123456789abcdef".to_owned()),
            provenance: LabProvenance::SyntheticFixture,
            capability: LabCapabilitySummary {
                backend: "synthetic-test".to_owned(),
                status: "fixture-tested".to_owned(),
            },
            samples: vec![
                OsLabSample {
                    sample_index: 1,
                    observations: vec![observation("window", "1000"), observation("flags", "0x12")],
                },
                OsLabSample {
                    sample_index: 2,
                    observations: vec![observation("flags", "0x12"), observation("window", "2000")],
                },
            ],
            notes: Some("private lab note".to_owned()),
        }
    }

    #[test]
    fn schema_round_trip_and_serialization_are_deterministic() {
        let fixture = fixture().sanitized().unwrap();
        let first = fixture.to_pretty_json().unwrap();
        let decoded = OsLabFixture::from_json(&first).unwrap();
        assert_eq!(decoded, fixture);
        assert_eq!(first, decoded.to_pretty_json().unwrap());
    }

    #[test]
    fn repeat_samples_separate_stable_and_variable_features() {
        let analysis = fixture().analyze().unwrap();
        assert_eq!(analysis.sample_count, 2);
        assert_eq!(analysis.stable_features.len(), 1);
        assert_eq!(analysis.stable_features[0].kind, "flags");
        assert_eq!(analysis.variable_features.len(), 1);
        assert_eq!(analysis.variable_features[0].values, ["1000", "2000"]);
        assert!(!analysis.production_pack_modified);
        assert_eq!(analysis, fixture().analyze().unwrap());
    }

    #[test]
    fn sanitization_removes_capture_identity_and_free_form_fields() {
        let clean = fixture().sanitized().unwrap();
        assert_eq!(clean.target, "192.0.2.10");
        assert!(clean.notes.is_none());
        assert!(
            clean
                .samples
                .iter()
                .flat_map(|sample| &sample.observations)
                .all(|observation| observation.timestamp_ms.is_none()
                    && observation.detail.is_none())
        );
        let json = clean.to_pretty_json().unwrap();
        assert!(!json.contains("router.example.test"));
        assert!(!json.contains("private lab note"));
    }

    #[test]
    fn malformed_and_unsupported_fixtures_are_rejected() {
        assert!(OsLabFixture::from_json("{}").is_err());
        let mut unsupported = fixture();
        unsupported.schema_version = 99;
        assert!(unsupported.validate().is_err());
        let mut duplicate = fixture();
        duplicate.samples[1].sample_index = 1;
        assert!(duplicate.validate().is_err());
    }
}
