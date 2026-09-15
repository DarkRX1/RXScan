//! Level/goal policy: investigation breadth/depth.
//!
//! `--level` (1-5) is breadth/depth and is independent of `--speed`
//! (execution pressure). This module centralizes task/module eligibility so
//! level checks are not scattered across modules.
//!
//! # Canonical workflows
//!
//! Six workflows with distinct execution semantics (historical goal names
//! map to these; see `ScanGoal`):
//! * `Recon` (default): host + port discovery, service identification, and
//!   evidence-driven web/content follow-ups.
//! * `Discover`: host + port discovery and DNS observations, but never
//!   service identification or deeper follow-ups.
//! * `Ports`: port discovery only — no follow-ups beyond the port scan.
//! * `Services`: port discovery + service identification — no
//!   web/content/crawl derivation.
//! * `Web`: web-focused — initial HTTP roots plus web/content follow-ups.
//! * `Full`: broadest bounded reconnaissance, including fuzz follow-ups.
//!
//! # v1 policy
//!
//! * Level 1: target validation only (`rxscan.control.validate`).
//! * Level 2: + minimal host-discovery intent.
//! * Level 3: + standard port-discovery intent (+ HTTP intent for web goals).
//! * Level 4: + expanded service/DNS intent (+ HTTP intent for web goals).
//! * Level 5: + deepest eligible modules allowed by the selected goal.
//!
//! Only task kinds with a registered executor are ever emitted: every
//! emitted task can run. `TlsProbe` and `Fingerprint` have no executor and
//! are never planned (see `describe_unavailable`); `--explain` reports them
//! as unavailable instead of emitting tasks that would predictably `Skip`.
//! `ServiceProbe` and `HttpProbe` tasks execute for real (see
//! `service_probe.rs` and `web_probe.rs`); follow-up-only kinds
//! (`ServiceProbe` per-port context, `Crawl`, `ContentDiscovery`, `Fuzz`)
//! are proposed by the Decision Engine when evidence justifies them.
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

/// Base kinds per level, in deterministic execution order (highest priority first).
///
/// Only executable, seed-meaningful kinds appear here: every kind has a
/// registered scheduler module AND can run from seed params. Kinds without
/// an executor (`TlsProbe`, `Fingerprint`) are never planned (see
/// `describe_unavailable`). Kinds that require evidence context
/// (`Crawl`, `ContentDiscovery`, `Fuzz` need a discovered endpoint/origin)
/// are follow-up-only: lowering one from a seed would predictably fail, so
/// only the Decision Engine proposes them. Level 5 deepens breadth (ports),
/// policy depths, and follow-up caps — not the initial kind set, which
/// saturates at Level 4 by design.
fn base_kinds_for_level(level: u8) -> Vec<TaskKind> {
    let validate = validate_kind();
    let host = TaskKind::HostDiscovery;
    let port = TaskKind::PortDiscovery;
    let http = TaskKind::HttpProbe;
    let service = TaskKind::ServiceProbe;
    let dns = TaskKind::DnsProbe;
    match level {
        0 | 1 => vec![validate],
        2 => vec![validate, host],
        3 => vec![validate, host, port, http],
        _ => vec![validate, host, port, http, service, dns],
    }
}

/// Goal-allowed kinds (superset filter). Order is irrelevant; base order wins.
///
/// Only executable, seed-meaningful kinds are listed: `TlsProbe` and
/// `Fingerprint` have no scheduler module and `Crawl`/`ContentDiscovery`/
/// `Fuzz` need evidence context, so none of them can appear here.
fn allowed_kinds_for_goal(goal: ScanGoal) -> BTreeSet<String> {
    let key = |kind: &TaskKind| serde_json::to_string(kind).unwrap_or_default();
    let allowed: Vec<TaskKind> = match goal {
        ScanGoal::Recon => vec![
            validate_kind(),
            TaskKind::HostDiscovery,
            TaskKind::PortDiscovery,
            TaskKind::ServiceProbe,
            TaskKind::DnsProbe,
        ],
        ScanGoal::Discover => vec![
            validate_kind(),
            TaskKind::HostDiscovery,
            TaskKind::PortDiscovery,
            TaskKind::DnsProbe,
        ],
        ScanGoal::Ports => vec![
            validate_kind(),
            TaskKind::HostDiscovery,
            TaskKind::PortDiscovery,
        ],
        ScanGoal::Services => vec![
            validate_kind(),
            TaskKind::HostDiscovery,
            TaskKind::PortDiscovery,
            TaskKind::ServiceProbe,
            TaskKind::DnsProbe,
        ],
        ScanGoal::Web => vec![
            validate_kind(),
            TaskKind::HostDiscovery,
            TaskKind::PortDiscovery,
            TaskKind::HttpProbe,
            TaskKind::DnsProbe,
        ],
        ScanGoal::Full => vec![
            validate_kind(),
            TaskKind::HostDiscovery,
            TaskKind::PortDiscovery,
            TaskKind::HttpProbe,
            TaskKind::ServiceProbe,
            TaskKind::DnsProbe,
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
    // Explicit `--udp` adds real UDP discovery at every level (explicit
    // wins, mirroring `--ports`): one bounded UdpDiscovery task per target.
    // UDP never joins by level/goal alone; default Recon stays TCP-only.
    if udp_requested && !eligible.contains(&TaskKind::UdpDiscovery) {
        eligible.push(TaskKind::UdpDiscovery);
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
            TaskKind::UdpDiscovery => 55,
            TaskKind::ServiceProbe => 50,
            TaskKind::DnsProbe => 50,
            TaskKind::HttpProbe => 45,
            TaskKind::TlsProbe => 40,
            TaskKind::Fingerprint => 35,
            TaskKind::Baseline => 32,
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
        TaskKind::UdpDiscovery => Some(PlannedModule::UdpDiscovery),
        _ => None,
    }
}

/// Human-readable initial-task list for `--explain`: selected AND
/// executable kinds for this goal/level (explicit requests included).
pub fn describe_initial_tasks(goal: ScanGoal, level: u8) -> String {
    // Recompute with explicit-request flags off; explicit intent is reported
    // separately by select_planned_modules. Pure function of goal/level.
    let kinds = eligible_task_kinds(goal, level, false, false, false);
    if kinds.is_empty() {
        return "  - (none)".to_owned();
    }
    kinds
        .iter()
        .map(|kind| format!("  - {}", serde_json::to_string(kind).unwrap_or_default()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Human-readable evidence-triggered follow-up rules for `--explain`.
/// These never run without justifying evidence; workflow gating decides
/// which rules are live for the selected goal.
pub fn describe_followups(goal: ScanGoal, level: u8) -> String {
    let mut rules = Vec::new();
    let alive = "host discovery concluded -> TCP port discovery";
    rules.push(format!("  - {alive}"));
    if matches!(
        goal,
        ScanGoal::Recon | ScanGoal::Services | ScanGoal::Web | ScanGoal::Full
    ) {
        rules.push("  - open TCP port -> service identification".to_owned());
    }
    if matches!(goal, ScanGoal::Recon | ScanGoal::Web | ScanGoal::Full) {
        rules.push("  - identified HTTP(S) service -> web observation".to_owned());
        rules.push("  - confirmed web endpoint -> crawl / baseline / content discovery".to_owned());
    }
    if matches!(goal, ScanGoal::Full) && level >= 3 {
        rules.push("  - baseline response signature -> bounded query fuzzing".to_owned());
    }
    if !matches!(goal, ScanGoal::Ports) {
        rules.push("  - DNS A/AAAA observation -> host discovery".to_owned());
    }
    if rules.len() <= 1 {
        rules.push("  - (no follow-ups: this workflow stops after initial tasks)".to_owned());
    }
    rules.join("\n")
}

/// Capabilities the planner will never emit as tasks in this build.
///
/// The scheduler has no executor for these, so planning them would only
/// produce predictable `Skipped` (or failed) tasks. `--explain` shows this
/// list instead of advertising them as selected work.
pub fn describe_unavailable() -> String {
    [
        "  - tls-probe tasks (dedicated TLS/cipher enumeration; TLS handshake facts observed via service probing remain available)",
        "  - fingerprint tasks (OS/device fingerprint engine)",
    ]
    .join("\n")
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
            "Level {level} with workflow {goal} selects: {}.",
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
                "{candidate:?} not selected by level {level} + workflow {goal} (no explicit request)."
            ));
        }
    }
    skipped.push(
        "Unsupported selected intents are skipped only when no real module is registered; skipped work is reported without fake discoveries."
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
        for goal in [
            ScanGoal::Recon,
            ScanGoal::Discover,
            ScanGoal::Ports,
            ScanGoal::Services,
            ScanGoal::Web,
            ScanGoal::Full,
        ] {
            assert_eq!(
                eligible_task_kinds(goal, 1, false, false, false),
                vec![validate_kind()]
            );
        }
    }

    #[test]
    fn higher_levels_expand_eligibility_then_saturate_by_design() {
        let l2 = eligible_task_kinds(ScanGoal::Recon, 2, false, false, false);
        let l3 = eligible_task_kinds(ScanGoal::Recon, 3, false, false, false);
        let l4 = eligible_task_kinds(ScanGoal::Recon, 4, false, false, false);
        let l5 = eligible_task_kinds(ScanGoal::Recon, 5, false, false, false);
        assert!(l2.len() < l3.len());
        assert!(l3.len() < l4.len());
        // Initial kinds saturate at L4 by design: L5 deepens breadth
        // (ports), policy depths, and follow-up caps — never the seed set.
        // Follow-up-only kinds (content/crawl/fuzz) and unexecutable kinds
        // (tls/fingerprint) are never lowered from a seed.
        assert_eq!(l4, l5);
        for kind in l5 {
            assert!(!matches!(
                kind,
                TaskKind::TlsProbe
                    | TaskKind::Fingerprint
                    | TaskKind::ContentDiscovery
                    | TaskKind::Crawl
                    | TaskKind::Fuzz
            ));
        }
    }

    #[test]
    fn canonical_workflows_differ_where_promised() {
        use TaskKind::*;
        // L3: web-family adds HTTP roots; port-family stays host+port.
        assert!(eligible_task_kinds(ScanGoal::Web, 3, false, false, false).contains(&HttpProbe));
        assert!(!eligible_task_kinds(ScanGoal::Recon, 3, false, false, false).contains(&HttpProbe));
        // L4: initial service tasks for Recon/Services/Full. Web identifies
        // services purely through evidence-triggered follow-ups (its
        // initial set stays HTTP-roots focused); Discover/Ports never
        // identify services at all.
        for goal in [ScanGoal::Recon, ScanGoal::Services, ScanGoal::Full] {
            assert!(
                eligible_task_kinds(goal, 4, false, false, false).contains(&ServiceProbe),
                "{goal} must select service identification"
            );
        }
        for goal in [ScanGoal::Discover, ScanGoal::Ports, ScanGoal::Web] {
            assert!(
                !eligible_task_kinds(goal, 4, false, false, false).contains(&ServiceProbe),
                "{goal} must not select initial service tasks"
            );
        }
    }
}
