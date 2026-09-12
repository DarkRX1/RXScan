//! Phase 5 runtime bootstrap: Target -> Scope -> ScanPlan -> Tasks ->
//! Reactive Scheduler <-> Speed Governor <-> Budgets <-> Backpressure ->
//! HostDiscovery Module -> Typed Events / Evidence -> Decision Engine
//! boundary -> JSONL Output.
//!
//! Real bounded host-discovery traffic occurs via `HostDiscoveryModule`
//! (native ICMP echo + TCP reachability, no shell `ping`). Deeper intents
//! (port scanning, UDP, HTTP, TLS, DNS, fuzzing) still run as `Skipped`
//! (`module unavailable`). The Decision Engine boundary is preserved
//! (`NoFollowUps` in Phase 5; follow-up port expansion belongs to Phase 6).

use std::sync::Arc;

use thiserror::Error;

use crate::{
    cli::Cli,
    discovery::HostDiscoveryPolicy,
    execution::{
        BudgetLimits, PolicyScopeGuard, Scheduler, SchedulerReport, SpeedGovernor, VecEventSink,
    },
    host_discovery::HostDiscoveryModule,
    lowering::{LowerError, lower_plan_to_tasks},
    modules::{phase5_control_modules, port_intent_module},
    output::{OutputError, create_file_writer},
    plan::{PlanError, ScanPlan},
};

#[derive(Debug, Error)]
pub enum RunError {
    #[error(transparent)]
    Plan(#[from] PlanError),
    #[error("could not lower plan to tasks: {0}")]
    Lower(#[from] LowerError),
    #[error("scheduler error: {0}")]
    Scheduler(#[from] crate::execution::SchedulerError),
    #[error(transparent)]
    Output(#[from] OutputError),
}

impl RunError {
    /// Documented exit statuses: 2 = usage/config, 1 = runtime.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Plan(_) => 2,
            Self::Lower(_) => 2,
            Self::Scheduler(_) => 1,
            Self::Output(_) => 1,
        }
    }
}

/// Result of a successful (non-`--explain`) run.
#[derive(Debug)]
pub struct RunReport {
    pub plan: ScanPlan,
    pub task_count: usize,
    pub scheduler_report: SchedulerReport,
    pub jsonl_bytes: u64,
    pub output_path: Option<String>,
}

/// Execute the full Phase 5 control + discovery plane from CLI.
///
/// Steps: compile plan -> scope guard -> lower tasks (bounded CIDR) -> speed
/// governor -> budgets -> scheduler -> register HostDiscovery + control/port
/// scaffolds -> run -> JSONL output (scheduler events + discovery assets,
/// events, evidence).
pub fn execute(cli: Cli) -> Result<RunReport, RunError> {
    let output_path = cli.output.clone();
    let format = cli.format.clone();
    let plan = ScanPlan::compile(cli)?;
    if plan.explain_requested {
        // --explain never executes; caller prints plan.explain().
        return Ok(RunReport {
            plan,
            task_count: 0,
            scheduler_report: SchedulerReport::default(),
            jsonl_bytes: 0,
            output_path: None,
        });
    }
    let tasks = lower_plan_to_tasks(&plan)?;
    let task_count = tasks.len();
    let budgets: BudgetLimits = plan.budgets.clone();
    budgets.validate()?;
    let governor = SpeedGovernor::new(plan.speed, budgets.max_concurrency)?;
    let queue_capacity = budgets.queue_capacity();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let sink = Arc::new(VecEventSink::default());
    let mut scheduler = Scheduler::new(
        queue_capacity,
        budgets.clone(),
        governor,
        guard.clone(),
        sink.clone(),
    )?;
    // Centralized discovery policy (level breadth + speed pressure).
    let discovery_policy = HostDiscoveryPolicy::for_level(
        plan.level,
        plan.discovery_mode,
        plan.speed,
        plan.discovery_ports.as_deref(),
    );
    scheduler.register_module(Arc::new(HostDiscoveryModule::new(
        discovery_policy,
        guard.clone(),
    )));
    for module in phase5_control_modules() {
        scheduler.register_module(Arc::new(module));
    }
    scheduler.register_module(Arc::new(port_intent_module()));
    for task in tasks {
        // Lowering scope-checks; scheduler admission is the second
        // enforcement point; dispatch + module pre-execution re-check
        // (defense in depth). Duplicates cannot occur (lowering dedupes)
        // unless the DecisionEngine proposes them later (Phase 5 uses
        // NoFollowUps, so none).
        scheduler.add_task(task)?;
    }
    let scheduler_report = scheduler.run()?;
    let events = sink.events();
    let module_outputs = scheduler.module_outputs();

    // JSONL output: file if --output, stdout if --format jsonl without file,
    // otherwise no JSONL (human summary printed by main). Discovery results
    // (assets, events, evidence) flow into the same typed JSONL envelope.
    let mut jsonl_bytes = 0u64;
    if let Some(path) = output_path.as_deref() {
        let mut writer = create_file_writer(path, budgets.max_evidence_bytes)?;
        write_outputs(&mut writer, &events, &module_outputs)?;
        writer.flush()?;
        jsonl_bytes = writer.bytes_written();
    } else if format
        .as_deref()
        .is_some_and(|format| format.eq_ignore_ascii_case("jsonl"))
    {
        let stdout = std::io::stdout();
        let handle = stdout.lock();
        let mut writer = crate::output::JsonlWriter::new(handle, budgets.max_evidence_bytes);
        write_outputs(&mut writer, &events, &module_outputs)?;
        writer.flush()?;
        jsonl_bytes = writer.bytes_written();
    }

    Ok(RunReport {
        plan,
        task_count,
        scheduler_report,
        jsonl_bytes,
        output_path: output_path.map(|path| path.display().to_string()),
    })
}

fn write_outputs<W: std::io::Write>(
    writer: &mut crate::output::JsonlWriter<W>,
    scheduler_events: &[crate::execution::SchedulerEvent],
    module_outputs: &[(crate::execution::TaskId, crate::execution::ModuleOutput)],
) -> Result<(), OutputError> {
    for event in scheduler_events {
        writer.write_scheduler_event(event)?;
    }
    // Deterministic order: sort module outputs by task ID.
    let mut ordered = module_outputs.to_vec();
    ordered.sort_by(|left, right| left.0.0.cmp(&right.0.0));
    for (_, output) in &ordered {
        for asset in &output.assets {
            writer.write_asset(asset)?;
        }
        for event in &output.events {
            writer.write_event(event)?;
        }
        for evidence in &output.evidence {
            writer.write_evidence(evidence)?;
        }
        for finding in &output.findings {
            writer.write_finding(finding)?;
        }
    }
    Ok(())
}

/// Human summary for non-JSONL runs.
pub fn human_summary(report: &RunReport) -> String {
    let scheduler = &report.scheduler_report;
    // Count discovery states from the plan-agnostic scheduler report? The
    // detailed Alive/Unknown/Unreachable breakdown lives in JSONL evidence;
    // the human line stays quiet by design (no noisy per-probe output).
    format!(
        "RXScan Phase 5 run: {} task(s) | completed {} | failed {} | cancelled {} | timed out {} | skipped {} | JSONL bytes {}{}",
        report.task_count,
        scheduler.completed.len(),
        scheduler.failed.len(),
        scheduler.cancelled.len(),
        scheduler.timed_out.len(),
        scheduler.skipped.len(),
        report.jsonl_bytes,
        report
            .output_path
            .as_deref()
            .map_or(String::new(), |path| format!(" | output {path}"))
    )
}
