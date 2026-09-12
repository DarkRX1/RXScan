//! Phase 4 runtime bootstrap: Target -> Scope -> ScanPlan -> Tasks ->
//! Reactive Scheduler <-> Speed Governor <-> Budgets <-> Backpressure ->
//! Module Executor -> Typed Events -> JSONL Output.
//!
//! No network activity. Only Phase-4-safe scaffold modules are registered;
//! deeper network intents run as `Skipped` (`module unavailable`).

use std::sync::Arc;

use thiserror::Error;

use crate::{
    cli::Cli,
    execution::{
        BudgetLimits, PolicyScopeGuard, Scheduler, SchedulerReport, SpeedGovernor, VecEventSink,
    },
    lowering::{LowerError, lower_plan_to_tasks},
    modules::phase4_modules,
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

/// Execute the full Phase 4 control plane from CLI.
///
/// Steps: compile plan -> scope guard -> lower tasks -> speed governor ->
/// budgets -> scheduler -> register Phase-4 modules -> run -> JSONL output.
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
        guard,
        sink.clone(),
    )?;
    for module in phase4_modules() {
        scheduler.register_module(Arc::new(module));
    }
    for task in tasks {
        // Lowering already scope-checks; scheduler admission is the second
        // enforcement point (defense in depth). Duplicates cannot occur
        // (lowering dedupes) unless the DecisionEngine proposes them later
        // (Phase 4 uses NoFollowUps, so none).
        scheduler.add_task(task)?;
    }
    let scheduler_report = scheduler.run()?;
    let events = sink.events();

    // JSONL output: file if --output, stdout if --format jsonl without file,
    // otherwise no JSONL (human summary printed by main).
    let mut jsonl_bytes = 0u64;
    if let Some(path) = output_path.as_deref() {
        let mut writer = create_file_writer(path, budgets.max_evidence_bytes)?;
        for event in &events {
            writer.write_scheduler_event(event)?;
        }
        writer.flush()?;
        jsonl_bytes = writer.bytes_written();
    } else if format
        .as_deref()
        .is_some_and(|format| format.eq_ignore_ascii_case("jsonl"))
    {
        let stdout = std::io::stdout();
        let handle = stdout.lock();
        let mut writer = crate::output::JsonlWriter::new(handle, budgets.max_evidence_bytes);
        for event in &events {
            writer.write_scheduler_event(event)?;
        }
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

/// Human summary for non-JSONL runs.
pub fn human_summary(report: &RunReport) -> String {
    let scheduler = &report.scheduler_report;
    format!(
        "RXScan Phase 4 run: {} task(s) | completed {} | failed {} | cancelled {} | timed out {} | skipped {} | JSONL bytes {}{}",
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
