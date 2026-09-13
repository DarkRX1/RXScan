//! Phase 8 runtime bootstrap: Target -> Scope -> ScanPlan -> Tasks ->
//! Reactive Scheduler <-> Speed Governor <-> Budgets <-> Backpressure ->
//! HostDiscovery + TcpDiscovery + ServiceProbe + WebProbe + Crawl Modules -> Typed
//! Events / Evidence / Assets / Findings -> Decision Engine (host→port,
//! open-port→service, confirmed-service→web→crawl) -> JSONL Output + human service
//! summary.
//!
//! Real bounded discovery: native ICMP echo + TCP reachability (Phase 5),
//! native TCP connect port scanning (Phase 6, one task per target with a
//! bounded internal window, no thread per port), native protocol probing
//! (Phase 7, one task per open port, no authentication), and bounded HTTP/1.1
//! web observations (Phase 8) and deterministic bounded endpoint crawling
//! from confirmed web evidence (Phase 9). Deeper intents (UDP, TLS cipher enumeration,
//! DNS, fuzzing, fingerprint engine) still run as `Skipped`
//! (`module unavailable`). The Decision Engine boundary is live: facts
//! propose scoped follow-ups admitted via Scope Guard, policy, budgets, and
//! scheduler dedup.

use std::sync::Arc;

use thiserror::Error;

use crate::{
    cli::Cli,
    decision::Phase7Engine,
    discovery::HostDiscoveryPolicy,
    execution::{
        BudgetLimits, PolicyScopeGuard, Scheduler, SchedulerReport, SpeedGovernor, VecEventSink,
    },
    host_discovery::HostDiscoveryModule,
    lowering::{LowerError, lower_plan_to_tasks},
    modules::phase5_control_modules,
    output::{OutputError, create_file_writer},
    plan::{PlanError, ScanPlan},
    service_probe::ServicePolicy,
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
    /// Human service table (open ports with service/product columns; falls
    /// back to port-only rows when no service findings exist yet).
    /// Kept in the report so the binary prints services without re-reading JSONL.
    pub open_ports_summary: String,
}

/// Execute the full Phase 9 discovery plane from CLI.
///
/// Steps: compile plan -> scope guard -> lower tasks (bounded CIDR, one port
/// task per target) -> speed governor -> budgets -> scheduler -> register
/// HostDiscovery + TcpDiscovery + ServiceProbe + WebProbe + Crawl + control scaffolds
/// -> Decision Engine (host→port, open-port→service, service→web→crawl) -> run ->
/// JSONL output (scheduler events + discovery/scan/service/web assets,
/// events, evidence, findings) + human service summary.
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
    let service_policy = ServicePolicy::new(plan.level, plan.goal, plan.speed);
    scheduler.register_module(Arc::new(crate::service_probe::ServiceProbeModule::new(
        service_policy,
        guard.clone(),
    )));
    let web_policy = crate::web::WebPolicy::new(plan.level, plan.goal, plan.speed);
    scheduler.register_module(Arc::new(crate::web_probe::WebProbeModule::new(
        web_policy,
        guard.clone(),
    )));
    let contact_registry = crate::contact::ContactRegistry::new();
    let baseline_similarity = crate::baseline::BaselineSimilarityRegistry::new();
    let crawl_policy = crate::crawl::CrawlPolicy::new(plan.level, plan.goal, plan.speed);
    scheduler.register_module(Arc::new(crate::crawl::CrawlModule::with_contact_registry(
        crawl_policy,
        guard.clone(),
        contact_registry.clone(),
    )));
    let baseline_policy = crate::baseline::BaselinePolicy::new(plan.level, plan.goal, plan.speed);
    scheduler.register_module(Arc::new(
        crate::baseline::BaselineModule::with_shared_state(
            baseline_policy,
            guard.clone(),
            contact_registry.clone(),
            baseline_similarity,
        ),
    ));
    let content_policy =
        crate::content::ContentDiscoveryPolicy::new(plan.level, plan.goal, plan.speed);
    scheduler.register_module(Arc::new(
        crate::content::ContentDiscoveryModule::with_contact_registry(
            content_policy,
            guard.clone(),
            contact_registry.clone(),
        ),
    ));
    let fuzz_policy = crate::fuzz::FuzzPolicy::new(plan.level, plan.goal, plan.speed);
    scheduler.register_module(Arc::new(crate::fuzz::FuzzModule::with_contact_registry(
        fuzz_policy,
        guard.clone(),
        contact_registry,
    )));
    for module in phase5_control_modules() {
        scheduler.register_module(Arc::new(module));
    }
    // Decision Engine: host facts propose scoped port tasks, open ports
    // propose scoped service tasks, confirmed web services propose web tasks.
    scheduler.set_decision_engine(Arc::new(Phase7Engine::new_with_content_wordlist(
        guard.clone(),
        plan.stable_id(),
        plan.level,
        plan.goal,
        plan.tcp_ports.clone(),
        plan.speed,
        plan.content_wordlist.clone(),
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
        open_ports_summary: crate::service_probe::human_service_table(&module_outputs),
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

/// Human summary for non-JSONL runs (service table prioritizes classified
/// services with product hints; closed/filtered detail lives in JSONL).
pub fn human_summary(report: &RunReport) -> String {
    human_summary_with_opens(report, None)
}

/// Human summary with service detail gathered from module outputs.
pub fn human_summary_with_opens(
    report: &RunReport,
    module_outputs: Option<&[(crate::execution::TaskId, crate::execution::ModuleOutput)]>,
) -> String {
    let scheduler = &report.scheduler_report;
    let header = format!(
        "RXScan Phase 9 run: {} task(s) | completed {} | failed {} | cancelled {} | timed out {} | skipped {} | JSONL bytes {}{}",
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
            let table = crate::service_probe::human_service_table(outputs);
            format!("{header}\n{table}")
        }
        _ if !report.open_ports_summary.is_empty() => {
            format!("{header}\n{}", report.open_ports_summary)
        }
        _ => header,
    }
}
