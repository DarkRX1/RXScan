//! Phase 4 level/goal policy: investigation breadth/depth.
//!
//! `--level` (1-5) is breadth/depth and is independent of `--speed`
//! (execution pressure). This module centralizes task/module eligibility so
//! level checks are not scattered across modules.
//!
//! # v1 policy
//!
//! * Level 1: target validation only (`rxscan.control.validate`).
//! * Level 2: + minimal host-discovery intent.
//! * Level 3: + standard port-discovery intent (+ HTTP intent for web goals).
//! * Level 4: + expanded service/DNS intent (+ TLS for web goals).
//! * Level 5: + deepest eligible modules allowed by the selected goal
//!   (fingerprints, content/fuzz where the goal permits). Crawl is Phase 9
//!   follow-up work only and is never lowered directly from a seed.
//!
//! Because TLS/DNS network modules do not exist yet, Phase 8 only
//! determines eligibility for the remaining intents. `ServiceProbe` and
//! `HttpProbe` tasks execute for real (see `service_probe.rs` and
//! `web_probe.rs`); other network-intent tasks are
//! part of the task graph (intended work) but execute as `Skipped`
//! (`module unavailable`) unless a real module is registered for that kind.
//! No fake discoveries are ever reported.
//!
//! Goal filtering ensures different goals produce different task graphs at
//! the same level (except Level 1, which is intentionally minimal for all
//! goals). Explicit CLI requests (`--discover`, `--ping`, `--udp`,
//! `--ports`/`--all-ports`) add their intent even if the level would not
//! otherwise include it.

use std::collections::BTreeSet;

use crate::{
    execution::TaskKind,
    plan::{PlannedModule, ScanGoal},
};

/// Control validation task kind used at every level.
pub fn validate_kind() -> TaskKind {
    TaskKind::Custom("rxscan.control.validate".to_owned())
}

/// UDP intent kind (no executor in Phase 4; runs as `Skipped`).
pub fn udp_intent_kind() -> TaskKind {
    TaskKind::Custom("rxscan.udp.intent".to_owned())
}

/// Base kinds per level, in deterministic execution order (highest priority first).
fn base_kinds_for_level(level: u8) -> Vec<TaskKind> {
    let validate = validate_kind();
    let host = TaskKind::HostDiscovery;
    let port = TaskKind::PortDiscovery;
    let http = TaskKind::HttpProbe;
    let service = TaskKind::ServiceProbe;
    let dns = TaskKind::DnsProbe;
    let tls = TaskKind::TlsProbe;
    let fingerprint = TaskKind::Fingerprint;
    let content = TaskKind::ContentDiscovery;
    let fuzz = TaskKind::Fuzz;
    match level {
        0 | 1 => vec![validate],
        2 => vec![validate, host],
        3 => vec![validate, host, port, http],
        4 => vec![validate, host, port, http, service, dns, tls],
        _ => vec![
            validate,
            host,
            port,
            http,
            service,
            dns,
            tls,
            fingerprint,
            content,
            fuzz,
        ],
    }
}

/// Goal-allowed kinds (superset filter). Order is irrelevant; base order wins.
fn allowed_kinds_for_goal(goal: ScanGoal) -> BTreeSet<String> {
    let key = |kind: &TaskKind| serde_json::to_string(kind).unwrap_or_default();
    let allowed: Vec<TaskKind> = match goal {
        ScanGoal::Recon => vec![
            validate_kind(),
            TaskKind::HostDiscovery,
            TaskKind::PortDiscovery,
            TaskKind::ServiceProbe,
            TaskKind::DnsProbe,
            TaskKind::Fingerprint,
        ],
        ScanGoal::Discovery => vec![
            validate_kind(),
            TaskKind::HostDiscovery,
            TaskKind::PortDiscovery,
            TaskKind::ServiceProbe,
            TaskKind::DnsProbe,
        ],
        ScanGoal::ServiceMap => vec![
            validate_kind(),
            TaskKind::HostDiscovery,
            TaskKind::PortDiscovery,
            TaskKind::ServiceProbe,
            TaskKind::DnsProbe,
            TaskKind::Fingerprint,
        ],
        ScanGoal::Web => vec![
            validate_kind(),
            TaskKind::HostDiscovery,
            TaskKind::PortDiscovery,
            TaskKind::HttpProbe,
            TaskKind::TlsProbe,
            TaskKind::ContentDiscovery,
            TaskKind::Crawl,
            TaskKind::Fingerprint,
        ],
        ScanGoal::WebDiscovery => vec![
            validate_kind(),
            TaskKind::HostDiscovery,
            TaskKind::PortDiscovery,
            TaskKind::HttpProbe,
            TaskKind::ContentDiscovery,
            TaskKind::Crawl,
            TaskKind::DnsProbe,
        ],
        ScanGoal::Api => vec![
            validate_kind(),
            TaskKind::HostDiscovery,
            TaskKind::PortDiscovery,
            TaskKind::HttpProbe,
            TaskKind::TlsProbe,
            TaskKind::ContentDiscovery,
        ],
        ScanGoal::ApiDiscovery => vec![
            validate_kind(),
            TaskKind::HostDiscovery,
            TaskKind::PortDiscovery,
            TaskKind::HttpProbe,
            TaskKind::ContentDiscovery,
            TaskKind::Crawl,
        ],
        ScanGoal::Content => vec![
            validate_kind(),
            TaskKind::HostDiscovery,
            TaskKind::PortDiscovery,
            TaskKind::HttpProbe,
            TaskKind::ContentDiscovery,
            TaskKind::Crawl,
        ],
        ScanGoal::Fuzz => vec![
            validate_kind(),
            TaskKind::HostDiscovery,
            TaskKind::PortDiscovery,
            TaskKind::HttpProbe,
            TaskKind::ContentDiscovery,
            TaskKind::Crawl,
            TaskKind::Fuzz,
        ],
        ScanGoal::Inventory => vec![
            validate_kind(),
            TaskKind::HostDiscovery,
            TaskKind::PortDiscovery,
            TaskKind::ServiceProbe,
            TaskKind::DnsProbe,
            TaskKind::Fingerprint,
        ],
        ScanGoal::Baseline => vec![
            validate_kind(),
            TaskKind::HostDiscovery,
            TaskKind::PortDiscovery,
            TaskKind::ServiceProbe,
            TaskKind::DnsProbe,
        ],
        ScanGoal::Monitoring => vec![
            validate_kind(),
            TaskKind::HostDiscovery,
            TaskKind::PortDiscovery,
            TaskKind::ServiceProbe,
        ],
        ScanGoal::Research => vec![
            validate_kind(),
            TaskKind::HostDiscovery,
            TaskKind::PortDiscovery,
            TaskKind::ServiceProbe,
            TaskKind::DnsProbe,
            TaskKind::Fingerprint,
            TaskKind::HttpProbe,
            TaskKind::TlsProbe,
        ],
        ScanGoal::Custom => vec![
            validate_kind(),
            TaskKind::HostDiscovery,
            TaskKind::PortDiscovery,
            TaskKind::HttpProbe,
            TaskKind::ServiceProbe,
            TaskKind::DnsProbe,
            TaskKind::TlsProbe,
            TaskKind::Fingerprint,
            TaskKind::ContentDiscovery,
            TaskKind::Crawl,
            TaskKind::Fuzz,
        ],
    };
    allowed.into_iter().map(|kind| key(&kind)).collect()
}

/// Eligible executable task kinds for a goal/level, in deterministic order.
///
/// Explicit requests add intent even if the level would not include it:
/// `host_requested` (`--ping`/`--discover`), `udp_requested` (`--udp`),
/// `ports_requested` (`--ports`/`--all-ports`).
pub fn eligible_task_kinds(
    goal: ScanGoal,
    level: u8,
    host_requested: bool,
    udp_requested: bool,
    ports_requested: bool,
) -> Vec<TaskKind> {
    let level = level.clamp(1, 5);
    let base = base_kinds_for_level(level);
    let allowed = allowed_kinds_for_goal(goal);
    let key = |kind: &TaskKind| serde_json::to_string(kind).unwrap_or_default();
    let mut eligible: Vec<TaskKind> = base
        .into_iter()
        .filter(|kind| allowed.contains(&key(kind)))
        .collect();
    if host_requested && !eligible.contains(&TaskKind::HostDiscovery) {
        // Insert right after validate for deterministic priority ordering.
        let position = usize::from(!eligible.is_empty());
        eligible.insert(position.min(eligible.len()), TaskKind::HostDiscovery);
    }
    if ports_requested && !eligible.contains(&TaskKind::PortDiscovery) {
        let position = eligible
            .iter()
            .position(|kind| *kind == TaskKind::HostDiscovery)
            .map_or(eligible.len(), |index| index + 1);
        eligible.insert(position.min(eligible.len()), TaskKind::PortDiscovery);
    }
    if udp_requested && !eligible.contains(&udp_intent_kind()) {
        eligible.push(udp_intent_kind());
    }
    eligible
}

/// Priority for a task kind (higher runs first). Deterministic.
pub fn priority_for_kind(kind: &TaskKind) -> u8 {
    if *kind == validate_kind() {
        100
    } else {
        match kind {
            TaskKind::HostDiscovery => 80,
            TaskKind::PortDiscovery => 60,
            TaskKind::ServiceProbe => 50,
            TaskKind::DnsProbe => 50,
            TaskKind::HttpProbe => 45,
            TaskKind::TlsProbe => 40,
            TaskKind::Fingerprint => 35,
            TaskKind::ContentDiscovery => 30,
            TaskKind::Crawl => 25,
            TaskKind::Fuzz => 20,
            TaskKind::Custom(_) => 10,
        }
    }
}

/// Map an executable [`TaskKind`] back to its [`PlannedModule`] for
/// `--explain` selected/skipped reporting. `None` for control-only kinds.
pub fn planned_module_for_kind(kind: &TaskKind) -> Option<PlannedModule> {
    match kind {
        TaskKind::HostDiscovery => Some(PlannedModule::HostDiscovery),
        TaskKind::PortDiscovery => Some(PlannedModule::TcpDiscovery),
        TaskKind::Custom(name) if name == "rxscan.udp.intent" => Some(PlannedModule::UdpDiscovery),
        _ => None,
    }
}

/// Select [`PlannedModule`]s for `ScanPlan::compile` from goal/level plus
/// explicit CLI requests. Returns `(modules, selected_reasons, skipped_reasons)`.
pub fn select_planned_modules(
    goal: ScanGoal,
    level: u8,
    host_requested: bool,
    udp_requested: bool,
    ports_requested: bool,
) -> (Vec<PlannedModule>, Vec<String>, Vec<String>) {
    let eligible = eligible_task_kinds(goal, level, host_requested, udp_requested, ports_requested);
    let mut modules = vec![
        PlannedModule::TargetNormalization,
        PlannedModule::ScopeGuard,
        PlannedModule::PlanCompilation,
    ];
    let mut selected = vec![
        "Target normalization, Scope Guard, and plan compilation always run.".to_owned(),
        format!(
            "Level {level} with goal {goal:?} selects: {}.",
            eligible
                .iter()
                .map(|kind| serde_json::to_string(kind).unwrap_or_default())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    ];
    let mut skipped = Vec::new();

    // All possible discovery modules for skipped reporting.
    let all_discovery = [
        PlannedModule::HostDiscovery,
        PlannedModule::TcpDiscovery,
        PlannedModule::UdpDiscovery,
    ];
    let mut included = BTreeSet::new();
    for kind in &eligible {
        if let Some(planned) = planned_module_for_kind(kind) {
            if included.insert(format!("{planned:?}")) {
                modules.push(planned);
            }
        }
    }
    // Ensure explicit UDP request is always represented in the plan even if
    // level/goal filtering would otherwise omit it (explicit wins).
    if udp_requested && !modules.contains(&PlannedModule::UdpDiscovery) {
        modules.push(PlannedModule::UdpDiscovery);
        selected.push("Explicit --udp request adds UDP discovery intent.".to_owned());
    }
    if host_requested && !modules.contains(&PlannedModule::HostDiscovery) {
        if !included.contains("HostDiscovery") {
            modules.push(PlannedModule::HostDiscovery);
        }
        selected.push("Explicit --ping/--discover request adds host discovery.".to_owned());
    }
    if ports_requested && !modules.contains(&PlannedModule::TcpDiscovery) {
        modules.push(PlannedModule::TcpDiscovery);
        selected.push("Explicit port selection adds TCP discovery intent.".to_owned());
    }
    for candidate in all_discovery {
        if !modules.contains(&candidate) {
            skipped.push(format!(
                "{candidate:?} not selected by level {level} + goal {goal:?} (no explicit request)."
            ));
        }
    }
    // Phase 4 honesty: network execution deferred.
    skipped.push(
        "Phase 4 executes only control/host/port scaffold tasks; deeper network intents run as Skipped (module unavailable) without fake results."
            .to_owned(),
    );
    // Deterministic module order: control first, then discovery in enum order.
    modules.sort_by_key(|module| format!("{module:?}"));
    modules.dedup();
    // Restore canonical control-first order.
    let mut ordered = vec![
        PlannedModule::TargetNormalization,
        PlannedModule::ScopeGuard,
        PlannedModule::PlanCompilation,
    ];
    for module in [
        PlannedModule::HostDiscovery,
        PlannedModule::TcpDiscovery,
        PlannedModule::UdpDiscovery,
    ] {
        if modules.contains(&module) {
            ordered.push(module);
        }
    }
    (ordered, selected, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_one_is_minimal_for_all_goals() {
        for goal in [ScanGoal::Recon, ScanGoal::Web, ScanGoal::Fuzz] {
            assert_eq!(
                eligible_task_kinds(goal, 1, false, false, false),
                vec![validate_kind()]
            );
        }
    }

    #[test]
    fn higher_levels_expand_eligibility() {
        let l2 = eligible_task_kinds(ScanGoal::Recon, 2, false, false, false);
        let l3 = eligible_task_kinds(ScanGoal::Recon, 3, false, false, false);
        let l5 = eligible_task_kinds(ScanGoal::Recon, 5, false, false, false);
        assert!(l2.len() < l3.len());
        assert!(l3.len() < l5.len());
    }
}
