//! Phase 6 runtime bootstrap: Target -> Scope -> ScanPlan -> Tasks ->
//! Reactive Scheduler <-> Speed Governor <-> Budgets <-> Backpressure ->
//! HostDiscovery + TcpDiscovery Modules -> Typed Events / Evidence / Assets /
//! Findings -> Decision Engine V1 -> JSONL Output + human open-port summary.
//!
//! Real bounded discovery: native ICMP echo + TCP reachability (Phase 5) and
//! native TCP connect port scanning (Phase 6, one task per target with a
//! bounded internal window, no thread per port). Deeper intents (UDP, HTTP,
//! TLS, DNS, fuzzing, service fingerprinting) still run as `Skipped`
//! (`module unavailable`). The Decision Engine boundary is live: host facts
//! propose scoped port tasks admitted via Scope Guard, policy, budgets, and
//! scheduler dedup.

use std::sync::Arc;

use thiserror::Error;

use crate::{
    cli::Cli,
    decision::TcpDecisionEngine,
    discovery::HostDiscoveryPolicy,
    execution::{
        BudgetLimits, PolicyScopeGuard, Scheduler, SchedulerReport, SpeedGovernor, VecEventSink,
    },
    host_discovery::HostDiscoveryModule,
    lowering::{LowerError, lower_plan_to_tasks},
    modules::phase5_control_modules,
    output::{OutputError, create_file_writer},
    plan::{PlanError, ScanPlan},
    tcp_discovery::TcpScanPolicy,
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
    /// Human open-port table (prioritizes opens; empty when none observed).
    /// Kept in the report so the binary prints opens without re-reading JSONL.
    pub open_ports_summary: String,
}

/// Execute the full Phase 6 discovery plane from CLI.
///
/// Steps: compile plan -> scope guard -> lower tasks (bounded CIDR, one port
/// task per target) -> speed governor -> budgets -> scheduler -> register
/// HostDiscovery + TcpDiscovery + control scaffolds -> Decision Engine V1 ->
/// run -> JSONL output (scheduler events + discovery/scan assets, events,
/// evidence, findings) + human open-port summary.
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
            open_ports_summary: String::new(),
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
    // Centralized policies (level breadth + speed pressure).
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
    let tcp_policy = TcpScanPolicy::new(plan.level, plan.goal, plan.tcp_ports.clone(), plan.speed);
    scheduler.register_module(Arc::new(crate::tcp_discovery::TcpDiscoveryModule::new(
        tcp_policy,
        guard.clone(),
    )));
    for module in phase5_control_modules() {
        scheduler.register_module(Arc::new(module));
    }
    // Decision Engine V1: host facts propose scoped port tasks.
    scheduler.set_decision_engine(Arc::new(TcpDecisionEngine::new(
        guard.clone(),
        plan.stable_id(),
        plan.level,
        plan.goal,
        plan.tcp_ports.clone(),
        plan.speed,
    )));
    for task in tasks {
        // Lowering scope-checks; scheduler admission is the second
        // enforcement point; dispatch + module pre-execution re-check
        // (defense in depth). Duplicates cannot occur (lowering dedupes);
        // engine proposals dedup gracefully via best-effort admission.
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
        open_ports_summary: crate::tcp_discovery::human_open_ports_summary(&module_outputs),
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

/// Human summary for non-JSONL runs (prioritizes open ports, stays quiet on
/// closed/filtered detail which lives in JSONL).
pub fn human_summary(report: &RunReport) -> String {
    human_summary_with_opens(report, None)
}

/// Human summary with open-port detail gathered from module outputs.
pub fn human_summary_with_opens(
    report: &RunReport,
    module_outputs: Option<&[(crate::execution::TaskId, crate::execution::ModuleOutput)]>,
) -> String {
    let scheduler = &report.scheduler_report;
    let header = format!(
        "RXScan Phase 6 run: {} task(s) | completed {} | failed {} | cancelled {} | timed out {} | skipped {} | JSONL bytes {}{}",
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
    );
    // Prefer caller-supplied outputs; fall back to the report's own summary
    // (populated by `execute` from scheduler outputs).
    match module_outputs {
        Some(outputs) if !outputs.is_empty() => {
            let table = crate::tcp_discovery::human_open_ports_summary(outputs);
            format!("{header}\n{table}")
        }
        _ if !report.open_ports_summary.is_empty() => {
            format!("{header}\n{}", report.open_ports_summary)
        }
        _ => header,
    }
}
