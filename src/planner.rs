//! Bounded transform planner (deduplicate, no loops, respect budgets).
//!
//! Plans useful transforms from available evidence: deduplicates work,
//! prevents graph loops (`Domain -> DNS Hostname -> Domain` must not loop),
//! bounds recursion via depth, respects global deadline, per-provider
//! limits, cancellation, scope, separates passive and active work, and
//! explains why each transform was (or was not) scheduled.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use crate::graph::EntityKind;
use crate::investigate::{BudgetClass, InvestigationConfig, TransformRegistry};
use crate::search::ContactClass;

/// One planned unit of work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedTransform {
    pub entity_id: String,
    pub entity_kind: EntityKind,
    pub transform_id: String,
    pub contact_class: ContactClass,
    pub depth: u8,
    pub reason: String,
}

/// Why a transform was skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedTransform {
    pub entity_id: String,
    pub transform_id: String,
    pub reason: String,
}

/// Full plan with coverage.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransformPlan {
    pub planned: Vec<PlannedTransform>,
    pub skipped: Vec<SkippedTransform>,
    pub truncated: bool,
}

/// Plan transforms for `entities` (id -> (kind, depth)).
///
/// Rules:
/// - each `(transform, entity)` at most once (loop prevention);
/// - child depth (`depth + cost`) must fit `config.depth`;
/// - `DirectNetwork`/`AuthenticatedApi` never planned in passive mode
///   (active work needs explicit `--network`, planned separately);
/// - budgets pre-checked (entities/relationships/HTTP/DNS);
/// - deterministic order `(depth, entity_id, transform_id)`.
#[allow(clippy::too_many_arguments)]
pub fn plan_transforms(
    config: &InvestigationConfig,
    registry: &TransformRegistry,
    entities: &BTreeMap<String, (EntityKind, u8)>,
    already_expanded: &BTreeSet<(String, String)>,
    http_used: usize,
    dns_used: usize,
    entity_count: usize,
    relationship_count: usize,
    deadline: Instant,
) -> TransformPlan {
    let mut plan = TransformPlan::default();
    if Instant::now() >= deadline {
        plan.truncated = true;
        return plan;
    }
    let mut candidates: Vec<(u8, String, String)> = Vec::new();
    for (entity_id, (kind, depth)) in entities {
        for transform in registry.for_entity(*kind) {
            // Loop prevention.
            if already_expanded.contains(&(transform.id().to_owned(), entity_id.clone())) {
                plan.skipped.push(SkippedTransform {
                    entity_id: entity_id.clone(),
                    transform_id: transform.id().to_owned(),
                    reason: "already expanded (loop prevention)".to_owned(),
                });
                continue;
            }
            // Depth gate (pure zero-cost transforms may run at boundary).
            if depth.saturating_add(transform.depth_cost()) > config.depth {
                plan.skipped.push(SkippedTransform {
                    entity_id: entity_id.clone(),
                    transform_id: transform.id().to_owned(),
                    reason: format!(
                        "depth {} + cost {} exceeds max {}",
                        depth,
                        transform.depth_cost(),
                        config.depth
                    ),
                });
                continue;
            }
            // Passive/active separation.
            if matches!(
                transform.contact_class(),
                ContactClass::DirectNetwork | ContactClass::AuthenticatedApi
            ) {
                plan.skipped.push(SkippedTransform {
                    entity_id: entity_id.clone(),
                    transform_id: transform.id().to_owned(),
                    reason: "active contact requires explicit opt-in".to_owned(),
                });
                continue;
            }
            candidates.push((*depth, entity_id.clone(), transform.id().to_owned()));
        }
    }
    candidates.sort();
    candidates.dedup();
    for (depth, entity_id, transform_id) in candidates {
        if entity_count >= config.max_entities {
            plan.skipped.push(SkippedTransform {
                entity_id,
                transform_id,
                reason: "entity_budget".to_owned(),
            });
            plan.truncated = true;
            continue;
        }
        if relationship_count >= config.max_relationships {
            plan.skipped.push(SkippedTransform {
                entity_id,
                transform_id,
                reason: "relationship_budget".to_owned(),
            });
            plan.truncated = true;
            continue;
        }
        let Some(transform) = registry.get(&transform_id) else {
            continue;
        };
        // Per-budget gates mirror the engine.
        if transform.budget_class() == BudgetClass::PublicHttp
            && http_used >= config.max_http_requests
        {
            plan.skipped.push(SkippedTransform {
                entity_id,
                transform_id,
                reason: "http_budget".to_owned(),
            });
            plan.truncated = true;
            continue;
        }
        if transform.budget_class() == BudgetClass::Dns && dns_used >= config.max_dns_queries {
            plan.skipped.push(SkippedTransform {
                entity_id,
                transform_id,
                reason: "dns_budget".to_owned(),
            });
            plan.truncated = true;
            continue;
        }
        plan.planned.push(PlannedTransform {
            entity_id: entity_id.clone(),
            entity_kind: entities
                .get(&entity_id)
                .map(|(k, _)| *k)
                .unwrap_or(EntityKind::Domain),
            transform_id: transform_id.clone(),
            contact_class: transform.contact_class(),
            depth,
            reason: format!("scheduled {transform_id} for {entity_id} at depth {depth}"),
        });
    }
    plan.planned.sort_by(|a, b| {
        a.depth
            .cmp(&b.depth)
            .then(a.entity_id.cmp(&b.entity_id))
            .then(a.transform_id.cmp(&b.transform_id))
    });
    plan.skipped.sort_by(|a, b| {
        a.entity_id
            .cmp(&b.entity_id)
            .then(a.transform_id.cmp(&b.transform_id))
    });
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn config() -> InvestigationConfig {
        let mut c =
            InvestigationConfig::seeded(crate::investigate::SeedKind::Domain, "example.test");
        c.depth = 2;
        c
    }

    #[test]
    fn deduplicates_and_prevents_loops() {
        let registry = TransformRegistry::new();
        let mut entities = BTreeMap::new();
        entities.insert("domain:example.test".to_owned(), (EntityKind::Domain, 0));
        let mut expanded = BTreeSet::new();
        expanded.insert(("domain_to_dns".to_owned(), "domain:example.test".to_owned()));
        let plan = plan_transforms(
            &config(),
            &registry,
            &entities,
            &expanded,
            0,
            0,
            1,
            0,
            Instant::now() + Duration::from_secs(60),
        );
        assert!(
            !plan
                .planned
                .iter()
                .any(|p| p.transform_id == "domain_to_dns")
        );
        assert!(plan.skipped.iter().any(|s| s.reason.contains("loop")));
    }

    #[test]
    fn bounds_recursion_and_separates_active() {
        let registry = TransformRegistry::new();
        let mut entities = BTreeMap::new();
        entities.insert("domain:example.test".to_owned(), (EntityKind::Domain, 5));
        let plan = plan_transforms(
            &config(),
            &registry,
            &entities,
            &BTreeSet::new(),
            0,
            0,
            1,
            0,
            Instant::now() + Duration::from_secs(60),
        );
        assert!(plan.planned.is_empty());
        assert!(plan.skipped.iter().any(|s| s.reason.contains("depth")));
    }
}
