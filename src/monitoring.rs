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

#[cfg(test)]
mod tests {
    use super::*;

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
