//! Threat labeling evidence enforcement.
//!
//! Attribution icons (hacker, threat-group, terrorist, botnet, sanctions,
//! law-enforcement, watchlist) may only be applied from a stored record
//! carrying a named source, confidence > 0, and an evidence reference.

use std::collections::BTreeMap;

pub use crate::graph_icons::ATTRIBUTION_ICONS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatLabelError {
    MissingSource,
    ZeroConfidence,
    MissingEvidence,
    NotAttributionIcon(String),
}

impl std::fmt::Display for ThreatLabelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSource => write!(f, "attribution label requires a named source"),
            Self::ZeroConfidence => write!(f, "attribution label requires confidence > 0"),
            Self::MissingEvidence => write!(f, "attribution label requires an evidence reference"),
            Self::NotAttributionIcon(i) => write!(f, "{i} is not an attribution icon"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributionLabel {
    pub icon: String,
    pub source: String,
    pub confidence: u8,
    pub evidence_ref: String,
}

impl AttributionLabel {
    pub fn new(
        icon: impl Into<String>,
        source: impl Into<String>,
        confidence: u8,
        evidence_ref: impl Into<String>,
    ) -> Self {
        Self {
            icon: icon.into(),
            source: source.into(),
            confidence,
            evidence_ref: evidence_ref.into(),
        }
    }

    pub fn is_attribution_icon(icon: &str) -> bool {
        ATTRIBUTION_ICONS.contains(&icon)
    }

    pub fn validate(&self) -> Result<(), ThreatLabelError> {
        if !Self::is_attribution_icon(&self.icon) {
            return Err(ThreatLabelError::NotAttributionIcon(self.icon.clone()));
        }
        if self.source.trim().is_empty() {
            return Err(ThreatLabelError::MissingSource);
        }
        if self.confidence == 0 {
            return Err(ThreatLabelError::ZeroConfidence);
        }
        if self.evidence_ref.trim().is_empty() {
            return Err(ThreatLabelError::MissingEvidence);
        }
        Ok(())
    }

    pub fn is_allowed(&self) -> bool {
        self.validate().is_ok()
    }
}

pub fn is_attribution_icon(icon: &str) -> bool {
    AttributionLabel::is_attribution_icon(icon)
}

pub fn validate_label(label: &AttributionLabel) -> Result<(), ThreatLabelError> {
    label.validate()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelViolation {
    pub entity_id: String,
    pub icon: String,
    pub reason: String,
}

pub fn audit_labels(entities: &[(String, BTreeMap<String, String>)]) -> Vec<LabelViolation> {
    let mut out = Vec::new();
    for (id, attrs) in entities {
        if let Some(icon) = attrs.get("icon") {
            if is_attribution_icon(icon) {
                let source = attrs.get("attribution_source").cloned().unwrap_or_default();
                let conf: u8 = attrs
                    .get("attribution_confidence")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let ev = attrs
                    .get("attribution_evidence")
                    .cloned()
                    .unwrap_or_default();
                let label = AttributionLabel::new(icon.clone(), source, conf, ev);
                if let Err(e) = label.validate() {
                    out.push(LabelViolation {
                        entity_id: id.clone(),
                        icon: icon.clone(),
                        reason: e.to_string(),
                    });
                }
            }
        }
    }
    out
}

pub fn render_detail(label: &AttributionLabel) -> String {
    format!(
        "listed or attributed by {} (confidence {})",
        label.source, label.confidence
    )
}

pub fn warning_state(label: &AttributionLabel) -> bool {
    !label.is_allowed()
}

#[cfg(test)]
mod tests {

    #[test]
    fn threat_labels_does_not_redefine_attribution_icons() {
        let needle = concat!("pub const ", "ATTRIBUTION_ICONS");
        let src = include_str!("threat_labels.rs");
        assert!(
            !src.contains(needle),
            "ATTRIBUTION_ICONS must be defined only in graph_icons.rs"
        );
    }

    use super::*;

    #[test]
    fn allowed_requires_all() {
        let ok = AttributionLabel::new("hacker", "FBI list", 80, "ev-1");
        assert!(ok.is_allowed());
        let no_src = AttributionLabel::new("hacker", "", 80, "ev-1");
        assert!(!no_src.is_allowed());
        let zero = AttributionLabel::new("hacker", "src", 0, "ev-1");
        assert!(!zero.is_allowed());
        let no_ev = AttributionLabel::new("hacker", "src", 80, "");
        assert!(!no_ev.is_allowed());
    }

    #[test]
    fn non_attribution_not_allowed() {
        let l = AttributionLabel::new("host", "src", 80, "ev-1");
        assert!(l.validate().is_err());
    }

    #[test]
    fn audit_detects_violation() {
        let mut attrs = BTreeMap::new();
        attrs.insert("icon".to_owned(), "terrorist".to_owned());
        let v = audit_labels(&[("e1".to_owned(), attrs)]);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn audit_clean_when_evidence() {
        let mut attrs = BTreeMap::new();
        attrs.insert("icon".to_owned(), "terrorist".to_owned());
        attrs.insert("attribution_source".to_owned(), "OFAC".to_owned());
        attrs.insert("attribution_confidence".to_owned(), "90".to_owned());
        attrs.insert("attribution_evidence".to_owned(), "ev-1".to_owned());
        let v = audit_labels(&[("e1".to_owned(), attrs)]);
        assert!(v.is_empty());
    }

    #[test]
    fn render_detail_format() {
        let l = AttributionLabel::new("hacker", "FBI", 70, "ev");
        assert!(render_detail(&l).contains("listed or attributed by FBI"));
    }
}
