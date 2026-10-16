//! OSINT monitoring integration (coverage-aware, no vanity metrics).
//!
//! Compares a baseline investigation/project snapshot against a new one and
//! reports meaningful changes: new hostname, account, domain relationship,
//! repository, certificate, certificate rotation, DNS change, routing
//! change, endpoint, service/tech, exposure, relationship. States stay
//! distinct: `removed` vs `not observed` vs `not checked` vs `provider
//! unavailable` vs `unknown`. Coverage gates removals (a provider blocked
//! in the new run yields `UNKNOWN`, never a fake disappearance).

use std::collections::{BTreeMap, BTreeSet};

/// Coverage-aware change state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorState {
    Added,
    Removed,
    Changed,
    Unchanged,
    NotObserved,
    NotChecked,
    ProviderUnavailable,
    Unknown,
}

impl MonitorState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::Changed => "changed",
            Self::Unchanged => "unchanged",
            Self::NotObserved => "not_observed",
            Self::NotChecked => "not_checked",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::Unknown => "unknown",
        }
    }
}

/// One monitored change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorChange {
    pub entity_id: String,
    pub kind: String,
    pub state: MonitorState,
    pub detail: String,
}

/// Compute coverage-aware changes between baseline (`old_ids`) and new
/// (`new_ids`) entity sets, given per-transform coverage in each run.
///
/// - in new, not old -> `Added`;
/// - in old, not new, and producing transform completed in new -> `Removed`;
/// - in old, not new, but transform did not complete in new -> `Unknown`
///   (truncated/blocked/deadline), never a fake removal;
/// - in both with different fingerprints -> `Changed`.
pub fn monitor_diff(
    old_ids: &BTreeMap<String, String>,
    new_ids: &BTreeMap<String, String>,
    old_fingerprint: &BTreeMap<String, String>,
    new_fingerprint: &BTreeMap<String, String>,
    new_completed_transforms: &BTreeSet<String>,
    entity_to_transform: &BTreeMap<String, String>,
) -> Vec<MonitorChange> {
    let mut out = Vec::new();
    let mut all: BTreeSet<String> = BTreeSet::new();
    all.extend(old_ids.keys().cloned());
    all.extend(new_ids.keys().cloned());
    for id in all {
        let old = old_ids.get(&id);
        let new = new_ids.get(&id);
        let kind = new.or(old).cloned().unwrap_or_else(|| "unknown".to_owned());
        match (old, new) {
            (None, Some(_)) => out.push(MonitorChange {
                entity_id: id.clone(),
                kind,
                state: MonitorState::Added,
                detail: "new entity observed".to_owned(),
            }),
            (Some(_), None) => {
                let transform = entity_to_transform.get(&id).cloned().unwrap_or_default();
                if !transform.is_empty() && new_completed_transforms.contains(&transform) {
                    out.push(MonitorChange {
                        entity_id: id.clone(),
                        kind,
                        state: MonitorState::Removed,
                        detail: format!("covered by {transform}, no longer observed"),
                    });
                } else {
                    out.push(MonitorChange {
                        entity_id: id.clone(),
                        kind,
                        state: MonitorState::Unknown,
                        detail: "producing transform did not complete; cannot confirm removal"
                            .to_owned(),
                    });
                }
            }
            (Some(_), Some(_)) => {
                if old_fingerprint.get(&id) != new_fingerprint.get(&id) {
                    out.push(MonitorChange {
                        entity_id: id.clone(),
                        kind,
                        state: MonitorState::Changed,
                        detail: "entity fingerprint changed".to_owned(),
                    });
                }
            }
            (None, None) => {}
        }
        if out.len() >= 1024 {
            break;
        }
    }
    out.sort_by(|a, b| {
        a.entity_id
            .cmp(&b.entity_id)
            .then(format!("{:?}", a.state).cmp(&format!("{:?}", b.state)))
    });
    out
}

/// Alert thresholds over a checkpoint diff summary (Phase 6 scheduled
/// monitoring). Only *confirmed* transitions alert: inconclusive
/// (not-covered) records are reported for context but can never trigger
/// an alert on their own — absence without coverage is not a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertThresholds {
    /// Minimum confirmed additions (assets + relationships + findings).
    pub min_added: usize,
    /// Minimum confirmed removals (coverage-gated only).
    pub min_removed: usize,
    /// Minimum confirmed modifications.
    pub min_changed: usize,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            min_added: 1,
            min_removed: 1,
            min_changed: 1,
        }
    }
}

/// Evaluate a diff summary against thresholds. Returns human reason
/// lines for each met threshold (empty = no meaningful change, no
/// alert). Inconclusive records never appear here.
pub fn meaningful_changes(
    summary: &crate::diff::DiffSummary,
    thresholds: &AlertThresholds,
) -> Vec<String> {
    let added = summary.assets_added + summary.relationships_added + summary.findings_added;
    let removed = summary.assets_removed_confirmed
        + summary.relationships_removed_confirmed
        + summary.findings_removed_confirmed;
    let changed = summary.assets_modified + summary.findings_modified;
    let mut reasons = Vec::new();
    if thresholds.min_added > 0 && added >= thresholds.min_added {
        reasons.push(format!(
            "{added} confirmed addition(s) (threshold {})",
            thresholds.min_added
        ));
    }
    if thresholds.min_removed > 0 && removed >= thresholds.min_removed {
        reasons.push(format!(
            "{removed} confirmed removal(s) (threshold {})",
            thresholds.min_removed
        ));
    }
    if thresholds.min_changed > 0 && changed >= thresholds.min_changed {
        reasons.push(format!(
            "{changed} confirmed change(s) (threshold {})",
            thresholds.min_changed
        ));
    }
    reasons
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inconclusive_records_never_trigger_alerts() {
        let summary = crate::diff::DiffSummary {
            assets_missing_inconclusive: 9,
            relationships_missing_inconclusive: 4,
            findings_missing_inconclusive: 2,
            ..crate::diff::DiffSummary::default()
        };
        assert!(meaningful_changes(&summary, &AlertThresholds::default()).is_empty());
    }

    #[test]
    fn thresholds_gate_confirmed_changes() {
        let summary = crate::diff::DiffSummary {
            assets_added: 2,
            assets_removed_confirmed: 1,
            ..crate::diff::DiffSummary::default()
        };
        let reasons = meaningful_changes(&summary, &AlertThresholds::default());
        assert_eq!(reasons.len(), 2);
        let strict = AlertThresholds {
            min_added: 5,
            min_removed: 5,
            min_changed: 5,
        };
        assert!(meaningful_changes(&summary, &strict).is_empty());
        let off = AlertThresholds {
            min_added: 0,
            min_removed: 0,
            min_changed: 0,
        };
        assert!(meaningful_changes(&summary, &off).is_empty());
    }

    #[test]
    fn blocked_provider_yields_unknown_not_removed() {
        let mut old = BTreeMap::new();
        old.insert("account:p1:exampleuser".to_owned(), "account".to_owned());
        let new = BTreeMap::new();
        let changes = monitor_diff(
            &old,
            &new,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
            &BTreeMap::from([(
                "account:p1:exampleuser".to_owned(),
                "investigate.username_to_account".to_owned(),
            )]),
        );
        assert_eq!(changes[0].state, MonitorState::Unknown);
    }

    #[test]
    fn covered_absence_is_removed_and_new_is_added() {
        let mut old = BTreeMap::new();
        old.insert("domain:old.example.test".to_owned(), "domain".to_owned());
        let mut new = BTreeMap::new();
        new.insert("domain:new.example.test".to_owned(), "domain".to_owned());
        let mut completed = BTreeSet::new();
        completed.insert("investigate.domain_to_dns".to_owned());
        let changes = monitor_diff(
            &old,
            &new,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &completed,
            &BTreeMap::from([(
                "domain:old.example.test".to_owned(),
                "investigate.domain_to_dns".to_owned(),
            )]),
        );
        assert!(
            changes
                .iter()
                .any(|c| c.state == MonitorState::Added && c.entity_id.contains("new"))
        );
        assert!(
            changes
                .iter()
                .any(|c| c.state == MonitorState::Removed && c.entity_id.contains("old"))
        );
    }
}
