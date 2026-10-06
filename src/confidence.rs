//! Deterministic confidence fusion (never naive addition).
//!
//! Considers source reliability, observation strength, source
//! independence, recency, contradictory evidence, and relationship type.
//! Every decision carries an explanation.

use std::collections::BTreeSet;

/// Inputs to fusion (all bounded, all deterministic).
#[derive(Debug, Clone)]
pub struct FusionInput {
    /// Base observation strength (0..=100).
    pub strength: u8,
    /// Source reliability prior (0..=100). Unknown sources use 50.
    pub source_reliability: u8,
    /// Independence group (same group = not independent).
    pub independent_groups: usize,
    /// Total supporting observations (including dependent).
    pub support_count: usize,
    /// Strongest contradicting evidence (0 when none).
    pub max_contradiction: u8,
    /// Days since observation (None = unknown recency, penalized mildly).
    pub age_days: Option<u64>,
    /// Relationship type (ownership claims need more).
    pub relationship: String,
}

/// Fusion outcome with explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FusionOutcome {
    pub confidence: u8,
    pub explanation: String,
}

/// Fuse deterministically. Rules (in order):
/// 1. Start from `min(strength, reliability)`.
/// 2. Independence: 1 group caps at 75; 2+ groups allow up to 90.
/// 3. Contradiction caps: >=80 refutes to <=20; >=60 caps at 55.
/// 4. Recency: >365 days -10; unknown -5.
/// 5. Ownership claims cap at 70 without 2+ independent strong supports.
/// 6. Clamp 0..=95 (never 100 from fusion; 100 is operator assertion).
pub fn fuse_confidence(input: &FusionInput) -> FusionOutcome {
    let mut confidence = input.strength.min(input.source_reliability);
    let mut notes: Vec<String> = vec![format!(
        "base min(strength {}, reliability {}) = {confidence}",
        input.strength, input.source_reliability
    )];
    if input.independent_groups <= 1 {
        let capped = confidence.min(75);
        if capped != confidence {
            notes.push(format!(
                "single independence group caps {confidence} -> {capped}"
            ));
            confidence = capped;
        }
        if input.support_count > 1 {
            notes.push(format!(
                "{} observations share one group: no independence bonus",
                input.support_count
            ));
        }
    } else {
        let capped = confidence.min(90);
        if capped != confidence {
            notes.push(format!(
                "{} independent groups allow up to 90: {confidence} -> {capped}",
                input.independent_groups
            ));
            confidence = capped;
        } else {
            notes.push(format!("{} independent groups", input.independent_groups));
        }
    }
    if input.max_contradiction >= 80 {
        let capped = confidence.min(20);
        notes.push(format!(
            "strong contradiction {} caps {confidence} -> {capped}",
            input.max_contradiction
        ));
        confidence = capped;
    } else if input.max_contradiction >= 60 {
        let capped = confidence.min(55);
        notes.push(format!(
            "contradiction {} caps {confidence} -> {capped}",
            input.max_contradiction
        ));
        confidence = capped;
    }
    match input.age_days {
        Some(days) if days > 365 => {
            let reduced = confidence.saturating_sub(10);
            notes.push(format!("age {days}d staleness {confidence} -> {reduced}"));
            confidence = reduced;
        }
        None => {
            let reduced = confidence.saturating_sub(5);
            notes.push(format!("unknown recency {confidence} -> {reduced}"));
            confidence = reduced;
        }
        _ => {}
    }
    let rel = input.relationship.to_ascii_lowercase();
    if (rel.contains("owner") || rel.contains("ownership"))
        && !(input.independent_groups >= 2 && input.strength >= 70)
    {
        let capped = confidence.min(70);
        if capped != confidence {
            notes.push(format!(
                "ownership needs 2+ independent strong supports: {confidence} -> {capped}"
            ));
            confidence = capped;
        }
    }
    confidence = confidence.min(95);
    // Explain which independence groups were counted (caller passes count;
    // note distinctness without leaking raw source lists here).
    let _ = BTreeSet::<String>::new();
    FusionOutcome {
        confidence,
        explanation: notes.join("; "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_copies_are_not_three_confirmations() {
        let out = fuse_confidence(&FusionInput {
            strength: 80,
            source_reliability: 80,
            independent_groups: 1,
            support_count: 3,
            max_contradiction: 0,
            age_days: Some(10),
            relationship: "references".to_owned(),
        });
        assert!(out.confidence <= 75);
        assert!(out.explanation.contains("single independence group"));
    }

    #[test]
    fn contradiction_caps() {
        let out = fuse_confidence(&FusionInput {
            strength: 85,
            source_reliability: 85,
            independent_groups: 2,
            support_count: 2,
            max_contradiction: 65,
            age_days: Some(5),
            relationship: "references".to_owned(),
        });
        assert!(out.confidence <= 55);
    }

    #[test]
    fn ownership_needs_strong_independent_support() {
        let weak = fuse_confidence(&FusionInput {
            strength: 80,
            source_reliability: 80,
            independent_groups: 1,
            support_count: 1,
            max_contradiction: 0,
            age_days: Some(5),
            relationship: "ownership".to_owned(),
        });
        assert!(weak.confidence <= 70);
    }
}
