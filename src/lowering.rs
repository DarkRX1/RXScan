//! Phase 4 Plan -> Task lowering: pure deterministic translation.
//!
//! `lower_plan_to_tasks` converts a validated [`ScanPlan`] into initial
//! executable [`Task`]s without any network execution. The task graph
//! represents *intended work*, not pretend results.
//!
//! Guarantees:
//! * deterministic ordering (sorted by task ID) and deterministic IDs
//!   (canonical SHA-256 identity in `execution`);
//! * Scope Guard validation per task (fail-closed);
//! * level + goal policy enforcement via [`crate::level`];
//! * module eligibility (only eligible kinds are emitted);
//! * port-selection propagation via deterministic `params`
//!   (`ports=common|explicit|all`, never expanding 65k tasks);
//! * duplicate elimination (same ID emitted once).

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::{
    execution::{
        PolicyScopeGuard, RetryPolicy, SchedulerError, ScopeGuard, SpeedGovernor, Task, TaskKind,
        TaskScopeTarget,
    },
    level::{eligible_task_kinds, priority_for_kind, udp_intent_kind, validate_kind},
    model::{Provenance, Timestamp},
    plan::{ScanPlan, TcpPortSelection},
};

#[derive(Debug, Error)]
pub enum LowerError {
    #[error(transparent)]
    Scheduler(#[from] SchedulerError),
    #[error("task target is outside the current scope")]
    OutOfScope,
    #[error("lowering requires at least one target")]
    NoTargets,
}

const LOWERING_MODULE_VERSION: &str = "4.0.0";
/// Deterministic timestamp for lowered tasks so the same plan always yields
/// the same task graph byte-for-byte. Runtime `SchedulerEvent`s still carry
/// real wall-clock timestamps.
const LOWERING_TIMESTAMP: Timestamp = Timestamp(0);

/// Lower a validated plan into initial executable tasks.
///
/// Pure and deterministic: same `ScanPlan` value always yields the same
/// sorted task vector (by task ID). No I/O, no network.
pub fn lower_plan_to_tasks(plan: &ScanPlan) -> Result<Vec<Task>, LowerError> {
    if plan.targets.is_empty() {
        return Err(LowerError::NoTargets);
    }
    let guard = PolicyScopeGuard::new(plan.scope.clone());
    let governor = SpeedGovernor::new(plan.speed, 1).map_err(LowerError::Scheduler)?;
    let default_timeout = governor.default_timeout();
    let default_retry = governor.default_retry_policy();

    // Eligibility is driven by level+goal+explicit requests. Explicit port
    // selection counts as a ports request even at Level 1.
    let host_requested = plan
        .modules
        .iter()
        .any(|module| matches!(module, crate::plan::PlannedModule::HostDiscovery));
    let udp_requested = plan.udp_requested
        || plan
            .modules
            .iter()
            .any(|module| matches!(module, crate::plan::PlannedModule::UdpDiscovery));
    let ports_requested = !matches!(plan.tcp_ports, TcpPortSelection::Common)
        || plan
            .modules
            .iter()
            .any(|module| matches!(module, crate::plan::PlannedModule::TcpDiscovery));
    let eligible = eligible_task_kinds(
        plan.goal,
        plan.level,
        host_requested,
        udp_requested,
        ports_requested,
    );
    let plan_id = plan.stable_id();

    let mut deduped: BTreeMap<String, Task> = BTreeMap::new();
    for target_index in 0..plan.targets.len() {
        let (scope_target, mut base_params) = scope_target_for_plan_target(plan, target_index);
        // Validate scope fail-closed before emitting any task for this target.
        if !guard.permits(&scope_target) {
            return Err(LowerError::OutOfScope);
        }
        for kind in &eligible {
            // Per-kind params: port selection propagates only to port tasks.
            let mut params = base_params.clone();
            if *kind == TaskKind::PortDiscovery {
                match &plan.tcp_ports {
                    TcpPortSelection::Common => {
                        params.insert("ports".to_owned(), "common".to_owned());
                    }
                    TcpPortSelection::Explicit(ports) => {
                        let rendered = ports
                            .iter()
                            .map(u16::to_string)
                            .collect::<Vec<_>>()
                            .join(",");
                        // Truncate rendered list deterministically if huge;
                        // full list stays out of the ID beyond a bound.
                        let rendered = if rendered.len() > 2048 {
                            format!("{}...(+{} more)", &rendered[..2048], ports.len())
                        } else {
                            rendered
                        };
                        params.insert("ports".to_owned(), format!("explicit:{rendered}"));
                        params.insert("port_count".to_owned(), ports.len().to_string());
                    }
                    TcpPortSelection::All => {
                        // Represent 65k ports as ONE task, never 65k tasks.
                        params.insert("ports".to_owned(), "all".to_owned());
                        params.insert("port_count".to_owned(), 65_535.to_string());
                    }
                }
            }
            if *kind == udp_intent_kind() {
                params.insert("protocol".to_owned(), "udp".to_owned());
            }
            let module_name = module_name_for_kind(kind);
            let provenance = Provenance::new(
                module_name.clone(),
                LOWERING_MODULE_VERSION,
                plan_id.clone(),
                LOWERING_TIMESTAMP,
            )
            .map_err(|_| {
                LowerError::Scheduler(SchedulerError::InvalidTask("provenance required"))
            })?;
            // Per-task timeout/retry: speed-derived defaults. Control
            // validation tasks use a short bounded timeout (they are instant).
            let (timeout, retry): (std::time::Duration, RetryPolicy) = if *kind == validate_kind() {
                (
                    std::time::Duration::from_secs(5),
                    RetryPolicy {
                        max_attempts: 1,
                        base_delay_ms: 0,
                    },
                )
            } else {
                (default_timeout, default_retry.clone())
            };
            let task = Task::new_with_params(
                kind.clone(),
                None,
                Vec::new(),
                None,
                plan_id.clone(),
                priority_for_kind(kind),
                timeout,
                retry,
                module_name,
                provenance,
                scope_target.clone(),
                params,
                &guard,
            )
            .map_err(|error| match error {
                SchedulerError::OutOfScope => LowerError::OutOfScope,
                other => LowerError::Scheduler(other),
            })?;
            // Deduplicate by canonical ID (e.g. repeated identical targets).
            deduped.entry(task.id.0.clone()).or_insert(task);
        }
        // Silence unused warning if base_params mutated pattern changes.
        let _ = &mut base_params;
    }
    let mut tasks: Vec<Task> = deduped.into_values().collect();
    tasks.sort_by(|left, right| left.id.0.cmp(&right.id.0));
    Ok(tasks)
}

/// Derive a scope-checked [`TaskScopeTarget`] plus base params for a target.
///
/// CIDR ranges are represented as ONE task (network address + `cidr` param),
/// never expanded per-address. IPs prefer `Ip`, hostnames/URLs prefer `Host`.
fn scope_target_for_plan_target(
    plan: &ScanPlan,
    target_index: usize,
) -> (TaskScopeTarget, BTreeMap<String, String>) {
    let target = &plan.targets[target_index];
    let mut params = BTreeMap::new();
    params.insert("target".to_owned(), target.original_input.clone());
    if let Some(cidr) = target.cidr {
        params.insert("cidr".to_owned(), cidr.to_string());
        return (TaskScopeTarget::Ip(cidr.network()), params);
    }
    if let Some(address) = target.normalized_addresses.first() {
        if !target.schemes.is_empty() {
            params.insert("scheme".to_owned(), target.schemes.join(","));
        }
        if !target.explicit_ports.is_empty() {
            params.insert(
                "target_ports".to_owned(),
                target
                    .explicit_ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        return (TaskScopeTarget::Ip(*address), params);
    }
    if let Some(hostname) = target.hostnames.first() {
        if !target.schemes.is_empty() {
            params.insert("scheme".to_owned(), target.schemes.join(","));
        }
        if !target.explicit_ports.is_empty() {
            params.insert(
                "target_ports".to_owned(),
                target
                    .explicit_ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        return (TaskScopeTarget::Host(hostname.clone()), params);
    }
    // Fallback preserves determinism; scope guard permits `None` only when
    // the policy has no exclusions blocking it (PolicyScopeGuard maps None
    // to true). Plans always have seeds, so this is unreachable in practice.
    (TaskScopeTarget::None, params)
}

fn module_name_for_kind(kind: &TaskKind) -> String {
    match kind {
        TaskKind::HostDiscovery => "rxscan.host".to_owned(),
        TaskKind::PortDiscovery => "rxscan.port".to_owned(),
        TaskKind::ServiceProbe => "rxscan.service".to_owned(),
        TaskKind::HttpProbe => "rxscan.http".to_owned(),
        TaskKind::TlsProbe => "rxscan.tls".to_owned(),
        TaskKind::DnsProbe => "rxscan.dns".to_owned(),
        TaskKind::Fingerprint => "rxscan.fingerprint".to_owned(),
        TaskKind::Crawl => "rxscan.crawl".to_owned(),
        TaskKind::ContentDiscovery => "rxscan.content".to_owned(),
        TaskKind::Fuzz => "rxscan.fuzz".to_owned(),
        TaskKind::Custom(name) => format!("rxscan.custom.{name}"),
    }
}

/// Distinct task-graph fingerprint (sorted IDs) for determinism tests.
pub fn task_graph_fingerprint(tasks: &[Task]) -> String {
    let mut ids: BTreeSet<&str> = BTreeSet::new();
    for task in tasks {
        ids.insert(task.id.0.as_str());
    }
    ids.into_iter().collect::<Vec<_>>().join("|")
}
