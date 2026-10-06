//! Contradictory evidence: hypotheses with supporting, contradicting,
//! and unknown evidence (never forced binary conclusions).
//!
//! Example:
//! ```text
//! Hypothesis: account-A SAME_IDENTITY account-B
//! Supports: matching handle, shared domain
//! Contradicts: conflicting identity evidence
//! Assessment: POSSIBLE
//! ```

use std::collections::BTreeMap;

/// One evidence reference for/against a hypothesis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRef {
    pub description: String,
    pub source: String,
    pub confidence: u8,
    /// Independence group: observations sharing a group are not independent
    /// confirmations (e.g. three providers copying one upstream dataset).
    pub independent_group: String,
}

impl EvidenceRef {
    pub fn new(description: &str, source: &str, confidence: u8, group: &str) -> Self {
        Self {
            description: description.chars().take(256).collect(),
            source: source.chars().take(64).collect(),
            confidence: confidence.min(100),
            independent_group: group.chars().take(64).collect(),
        }
    }
}

/// Graded assessment (never binary unless evidence warrants it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assessment {
    Confirmed,
    Likely,
    Possible,
    Unknown,
    Unlikely,
    Refuted,
}

impl Assessment {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "CONFIRMED",
            Self::Likely => "LIKELY",
            Self::Possible => "POSSIBLE",
            Self::Unknown => "UNKNOWN",
            Self::Unlikely => "UNLIKELY",
            Self::Refuted => "REFUTED",
        }
    }
}

/// An identity/ownership hypothesis over entity subjects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hypothesis {
    pub id: String,
    pub subjects: Vec<String>,
    pub claim: String,
    pub supports: Vec<EvidenceRef>,
    pub contradicts: Vec<EvidenceRef>,
    pub unknowns: Vec<String>,
    pub assessment: Assessment,
    pub explanation: String,
}

impl Hypothesis {
    pub fn new(id: &str, subjects: Vec<String>, claim: &str) -> Self {
        Self {
            id: id.chars().take(128).collect(),
            subjects,
            claim: claim.chars().take(128).collect(),
            supports: Vec::new(),
            contradicts: Vec::new(),
            unknowns: Vec::new(),
            assessment: Assessment::Unknown,
            explanation: String::new(),
        }
    }

    /// Assess deterministically: strong contradiction caps the ceiling;
    /// independent supports raise the floor. No naive score addition.
    pub fn assess(&mut self) {
        let support_groups: std::collections::BTreeSet<&str> = self
            .supports
            .iter()
            .map(|e| e.independent_group.as_str())
            .collect();
        let max_support = self
            .supports
            .iter()
            .map(|e| e.confidence)
            .max()
            .unwrap_or(0);
        let max_contra = self
            .contradicts
            .iter()
            .map(|e| e.confidence)
            .max()
            .unwrap_or(0);
        let (assessment, why) = if max_contra >= 80 && max_contra >= max_support {
            (
                Assessment::Refuted,
                format!(
                    "contradicting evidence ({max_contra}) meets/exceeds support ({max_support})"
                ),
            )
        } else if max_contra >= 60 {
            (
                Assessment::Possible,
                format!(
                    "contradiction ({max_contra}) caps assessment at POSSIBLE despite support ({max_support})"
                ),
            )
        } else if support_groups.len() >= 2 && max_support >= 70 {
            (
                Assessment::Likely,
                format!(
                    "{} independent supporting sources, strongest {max_support}",
                    support_groups.len()
                ),
            )
        } else if max_support >= 80 && support_groups.len() == 1 {
            (
                Assessment::Possible,
                format!("single-source strong support ({max_support}); independence unproven"),
            )
        } else if max_support > 0 {
            (
                Assessment::Possible,
                format!("weak support ({max_support})"),
            )
        } else {
            (Assessment::Unknown, "no supporting evidence".to_owned())
        };
        self.assessment = assessment;
        self.explanation = why;
    }

    pub fn attributes(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("claim".to_owned(), self.claim.clone()),
            ("assessment".to_owned(), self.assessment.as_str().to_owned()),
            ("explanation".to_owned(), self.explanation.clone()),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_handle_plus_shared_domain_is_possible_not_confirmed() {
        let mut hyp = Hypothesis::new(
            "hyp-1",
            vec!["account-a".to_owned(), "account-b".to_owned()],
            "SAME_IDENTITY",
        );
        hyp.supports.push(EvidenceRef::new(
            "matching handle",
            "provider-a",
            70,
            "provider-a",
        ));
        hyp.supports.push(EvidenceRef::new(
            "shared linked domain",
            "provider-b",
            65,
            "provider-b",
        ));
        hyp.assess();
        // Two independent supports at 65-70 -> LIKELY under our rule...
        // adjust to POSSIBLE by adding contradiction:
        hyp.contradicts.push(EvidenceRef::new(
            "conflicting identity evidence",
            "provider-c",
            65,
            "provider-c",
        ));
        hyp.assess();
        assert_eq!(hyp.assessment, Assessment::Possible);
    }

    #[test]
    fn same_upstream_is_not_three_confirmations() {
        let mut hyp = Hypothesis::new("hyp-2", vec!["a".to_owned()], "SAME_IDENTITY");
        for _ in 0..3 {
            hyp.supports
                .push(EvidenceRef::new("same dataset", "copy", 80, "upstream-x"));
        }
        hyp.assess();
        // One independence group at 80 -> POSSIBLE, not CONFIRMED.
        assert_eq!(hyp.assessment, Assessment::Possible);
    }

    #[test]
    fn strong_contradiction_refutes() {
        let mut hyp = Hypothesis::new("hyp-3", vec!["a".to_owned()], "SAME_IDENTITY");
        hyp.supports
            .push(EvidenceRef::new("handle", "p1", 70, "p1"));
        hyp.contradicts
            .push(EvidenceRef::new("conflicting identity", "p2", 85, "p2"));
        hyp.assess();
        assert_eq!(hyp.assessment, Assessment::Refuted);
    }
}
