//! Phase 6 Plan -> Task lowering: pure deterministic translation.
//!
//! `lower_plan_to_tasks` converts a validated [`ScanPlan`] into initial
//! executable [`Task`]s without any network execution. The task graph
//! represents *intended work*, not pretend results.
//!
//! Guarantees:
//! * deterministic ordering (sorted by task ID) and deterministic IDs
//!   (canonical SHA-256 identity in `execution`);
//! * Scope Guard validation per task (fail-closed) at lowering; scheduler
//!   admission/dispatch and the module pre-execution check re-enforce it;
//! * level + goal policy enforcement via [`crate::level`];
//! * module eligibility (only eligible kinds are emitted);
//! * port-selection propagation via deterministic `params`
//!   (`ports=common|explicit|all`, never expanding 65k tasks: ONE
//!   `PortDiscovery` task per target carries the full selection; the TCP
//!   module scans internally with a bounded window);
//! * CIDR host expansion is bounded: `HostDiscovery` tasks expand a CIDR to
//!   at most `max_hosts` scope-permitted addresses in deterministic order
//!   (lazy `hosts()` iteration, never materializing massive ranges);
//!   exclusions always win; other kinds keep the single-task `cidr` intent;
//! * duplicate elimination (same ID emitted once).

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::{
    execution::{
        PolicyScopeGuard, RetryPolicy, SchedulerError, ScopeGuard, SpeedGovernor, Task, TaskKind,
        TaskScopeTarget,
    },
    level::{eligible_task_kinds, priority_for_kind, validate_kind},
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

const LOWERING_MODULE_VERSION: &str = "6.0.0";
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
    let max_hosts = usize::try_from(plan.budgets.max_hosts)
        .unwrap_or(usize::MAX)
        .max(1);
    let mut host_budget_remaining = max_hosts;

    let mut deduped: BTreeMap<String, Task> = BTreeMap::new();
    for target_index in 0..plan.targets.len() {
        let target = &plan.targets[target_index];
        // CIDR targets: HostDiscovery expands to bounded per-host tasks;
        // other kinds keep the single-task `cidr` intent (never 65k tasks).
        if let Some(cidr) = target.cidr {
            lower_cidr_target(
                plan,
                &plan_id,
                &guard,
                &eligible,
                target_index,
                cidr,
                &default_timeout,
                &default_retry,
                &mut host_budget_remaining,
                &mut deduped,
            )?;
            continue;
        }
        let (scope_target, base_params) = scope_target_for_plan_target(plan, target_index);
        // Validate scope fail-closed before emitting any task for this target.
        if !guard.permits(&scope_target) {
            return Err(LowerError::OutOfScope);
        }
        for kind in &eligible {
            let params = params_for_kind(plan, kind, &base_params);
            emit_task(
                plan,
                &plan_id,
                &guard,
                kind,
                scope_target.clone(),
                params,
                &default_timeout,
                &default_retry,
                &mut deduped,
            )?;
        }
    }
    let mut tasks: Vec<Task> = deduped.into_values().collect();
    tasks.sort_by(|left, right| left.id.0.cmp(&right.id.0));
    Ok(tasks)
}

/// Lower one CIDR seed: bounded `HostDiscovery` expansion + single-task
/// intents for other kinds. Deterministic, scope-checked, budget-bounded.
#[allow(clippy::too_many_arguments)]
fn lower_cidr_target(
    plan: &ScanPlan,
    plan_id: &crate::model::ScanPlanId,
    guard: &PolicyScopeGuard,
    eligible: &[TaskKind],
    target_index: usize,
    cidr: ipnet::IpNet,
    default_timeout: &std::time::Duration,
    default_retry: &RetryPolicy,
    host_budget_remaining: &mut usize,
    deduped: &mut BTreeMap<String, Task>,
) -> Result<(), LowerError> {
    let target = &plan.targets[target_index];
    // Validate the CIDR seed itself is in scope (fail-closed). The network
    // address represents the range for non-host intents.
    let (seed_scope, seed_params) = scope_target_for_plan_target(plan, target_index);
    if !guard.permits(&seed_scope) {
        // A fully excluded CIDR seed yields zero host tasks rather than an
        // error when the range contains permitted hosts? No: if the seed
        // network address itself is excluded but hosts are permitted (e.g.
        // network .0 excluded, hosts .1+ permitted), expansion may still
        // yield hosts. Only fail when expansion also yields nothing AND the
        // seed is a single address. For ranges, fall through to expansion.
        let is_single = cidr.prefix_len() == 32 || cidr.prefix_len() == 128;
        if is_single {
            return Err(LowerError::OutOfScope);
        }
    }
    let _ = seed_params;
    for kind in eligible {
        if *kind == TaskKind::HostDiscovery {
            // Bounded expansion: first `remaining` permitted hosts in order.
            let remaining = *host_budget_remaining;
            if remaining == 0 {
                continue;
            }
            let hosts = crate::discovery::expand_cidr_bounded(cidr, &plan.scope, remaining);
            *host_budget_remaining = host_budget_remaining.saturating_sub(hosts.len());
            for host in hosts {
                let scope_target = TaskScopeTarget::Ip(host);
                if !guard.permits(&scope_target) {
                    continue;
                }
                let mut params = BTreeMap::new();
                params.insert("target".to_owned(), target.original_input.clone());
                params.insert("cidr".to_owned(), cidr.to_string());
                params.insert("host".to_owned(), host.to_string());
                params.insert(
                    "discovery".to_owned(),
                    plan.discovery_mode.as_str().to_owned(),
                );
                emit_task(
                    plan,
                    plan_id,
                    guard,
                    kind,
                    scope_target,
                    params,
                    default_timeout,
                    default_retry,
                    deduped,
                )?;
            }
        } else {
            // Non-host intents stay single-task (cidr param, network scope).
            let (scope_target, base_params) = scope_target_for_plan_target(plan, target_index);
            // If the seed network is out of scope but hosts exist, still emit
            // non-host intents only when the seed scope permits (fail-closed
            // for intents that cannot enumerate hosts).
            if !guard.permits(&scope_target) {
                continue;
            }
            let params = params_for_kind(plan, kind, &base_params);
            emit_task(
                plan,
                plan_id,
                guard,
                kind,
                scope_target,
                params,
                default_timeout,
                default_retry,
                deduped,
            )?;
        }
    }
    Ok(())
}

/// Per-kind params: port selection only for port tasks; discovery mode for
/// host tasks; UDP marker for the UDP intent.
fn params_for_kind(
    plan: &ScanPlan,
    kind: &TaskKind,
    base: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut params = base.clone();
    if *kind == TaskKind::HostDiscovery {
        params.insert(
            "discovery".to_owned(),
            plan.discovery_mode.as_str().to_owned(),
        );
    }
    if *kind == TaskKind::PortDiscovery {
        match &plan.tcp_ports {
            TcpPortSelection::Common => {
                params.insert("ports".to_owned(), "common".to_owned());
            }
            TcpPortSelection::Explicit(ports) => {
                let rendered = crate::ports::compress_port_list(ports);
                params.insert("ports".to_owned(), format!("explicit:{rendered}"));
                params.insert("port_count".to_owned(), ports.len().to_string());
            }
            TcpPortSelection::All => {
                params.insert("ports".to_owned(), "all".to_owned());
                params.insert("port_count".to_owned(), 65_535.to_string());
            }
        }
    }
    if *kind == TaskKind::UdpDiscovery {
        // Transport-explicit params mirror the TCP shape; the shared
        // operator selection resolves per transport (`common` means
        // udp-common-v1 here, never the TCP set).
        params.insert("transport".to_owned(), "udp".to_owned());
        match &plan.tcp_ports {
            TcpPortSelection::Common => {
                params.insert("ports".to_owned(), "common".to_owned());
            }
            TcpPortSelection::Explicit(ports) => {
                let rendered = crate::ports::compress_port_list(ports);
                params.insert("ports".to_owned(), format!("explicit:{rendered}"));
                params.insert("port_count".to_owned(), ports.len().to_string());
            }
            TcpPortSelection::All => {
                params.insert("ports".to_owned(), "all".to_owned());
                params.insert("port_count".to_owned(), 65_535.to_string());
            }
        }
    }
    params
}

#[allow(clippy::too_many_arguments)]
fn emit_task(
    _plan: &ScanPlan,
    plan_id: &crate::model::ScanPlanId,
    guard: &PolicyScopeGuard,
    kind: &TaskKind,
    scope_target: TaskScopeTarget,
    params: BTreeMap<String, String>,
    default_timeout: &std::time::Duration,
    default_retry: &RetryPolicy,
    deduped: &mut BTreeMap<String, Task>,
) -> Result<(), LowerError> {
    let module_name = module_name_for_kind(kind);
    let provenance = Provenance::new(
        module_name.clone(),
        LOWERING_MODULE_VERSION,
        plan_id.clone(),
        LOWERING_TIMESTAMP,
    )
    .map_err(|_| LowerError::Scheduler(SchedulerError::InvalidTask("provenance required")))?;
    let (timeout, retry): (std::time::Duration, RetryPolicy) = if *kind == validate_kind() {
        (
            std::time::Duration::from_secs(5),
            RetryPolicy {
                max_attempts: 1,
                base_delay_ms: 0,
            },
        )
    } else {
        (*default_timeout, default_retry.clone())
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
        scope_target,
        params,
        guard,
    )
    .map_err(|error| match error {
        SchedulerError::OutOfScope => LowerError::OutOfScope,
        other => LowerError::Scheduler(other),
    })?;
    deduped.entry(task.id.0.clone()).or_insert(task);
    Ok(())
}

/// Derive a scope-checked [`TaskScopeTarget`] plus base params for a target.
///
/// Single (non-CIDR) targets: IPs prefer `Ip`, hostnames/URLs prefer `Host`.
/// CIDR seeds return the network address plus `cidr` param for non-host
/// intents; `HostDiscovery` expansion is handled in `lower_cidr_target`.
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
        TaskKind::UdpDiscovery => "rxscan.udp".to_owned(),
        TaskKind::ServiceProbe => "rxscan.service".to_owned(),
        TaskKind::HttpProbe => "rxscan.http".to_owned(),
        TaskKind::TlsProbe => "rxscan.tls".to_owned(),
        TaskKind::DnsProbe => "rxscan.dns".to_owned(),
        TaskKind::Fingerprint => "rxscan.fingerprint".to_owned(),
        TaskKind::Baseline => "rxscan.baseline".to_owned(),
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
