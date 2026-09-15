//! Runtime bootstrap: Target -> Scope -> ScanPlan -> Tasks ->
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
    output::{OutputError, create_atomic_file_writer},
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
    #[error(transparent)]
    Persistence(#[from] crate::persistence::PersistenceError),
    #[error("invalid resume invocation: {0}")]
    InvalidResume(String),
}

impl RunError {
    /// Documented exit statuses: 2 = usage/config, 1 = runtime.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Plan(_) => 2,
            Self::Lower(_) => 2,
            Self::Scheduler(_) => 1,
            Self::Output(_) => 1,
            Self::Persistence(_) => 1,
            Self::InvalidResume(_) => 2,
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
    /// Typed TCP totals from the same `PortScanCompleted` events JSONL
    /// serializes. The human summary renders these, so human counts and
    /// machine counts cannot disagree.
    pub tcp_totals: crate::tcp_discovery::TcpScanTotals,
    /// Typed count of `ServiceIdentified` events (same state as JSONL).
    pub services_identified: usize,
    /// Wall-clock execution time in milliseconds (plan lowering through
    /// scheduler completion), rendered as `Duration` in human output.
    pub duration_ms: u64,
}

/// Execute the discovery plane from CLI.
///
/// Default contract (`rxscan TARGET` = workflow `recon`, level 3, balanced
/// speed): normalize target -> enforce scope -> bounded host discovery ->
/// `common-100` TCP discovery -> service identification per open port ->
/// evidence-justified Recon/L3 follow-ups (web, crawl, baseline, content;
/// never fuzz) -> typed JSONL + human summary from the same state.
/// See README "Default contract" for the operator-facing statement.
/// Steps: compile plan -> scope guard -> lower tasks (bounded CIDR, one port
/// task per target) -> speed governor -> budgets -> scheduler -> register
/// HostDiscovery + TcpDiscovery + ServiceProbe + WebProbe + Crawl + control scaffolds
/// -> Decision Engine (host→port, open-port→service, service→web→crawl) -> run ->
/// JSONL output (scheduler events + discovery/scan/service/web assets,
/// events, evidence, findings) + human service summary.
pub fn execute(cli: Cli) -> Result<RunReport, RunError> {
    let output_path = cli.output.clone();
    let format = cli.format.clone();
    let checkpoint_path = cli.checkpoint.clone().or_else(|| cli.resume.clone());
    if cli.resume.is_some() {
        validate_resume_cli(&cli)?;
    }
    let loaded = if let Some(path) = cli.resume.as_deref() {
        Some(crate::persistence::load_checkpoint(path)?)
    } else {
        None
    };
    let mut plan = if let Some(loaded) = &loaded {
        let mut plan = loaded.state.plan.clone();
        if let Some(speed) = cli.speed {
            plan.speed = speed;
        }
        plan
    } else {
        ScanPlan::compile(cli)?
    };
    plan.explain_requested = false;
    if plan.explain_requested {
        // --explain never executes; caller prints plan.explain().
        return Ok(RunReport {
            plan,
            task_count: 0,
            scheduler_report: SchedulerReport::default(),
            jsonl_bytes: 0,
            output_path: None,
            open_ports_summary: String::new(),
            tcp_totals: crate::tcp_discovery::TcpScanTotals::default(),
            services_identified: 0,
            duration_ms: 0,
        });
    }
    let tasks = if loaded.is_none() {
        lower_plan_to_tasks(&plan)?
    } else {
        Vec::new()
    };
    let task_count = loaded
        .as_ref()
        .map_or(tasks.len(), |loaded| loaded.state.tasks.len());
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
    let restored_registries = loaded.as_ref().map(|loaded| &loaded.state.registries);
    let dns_registry = restored_registries
        .map(|registries| registries.restore_dns_registry())
        .transpose()?
        .unwrap_or_default();
    scheduler.register_module(Arc::new(crate::dns::DnsModule::with_registry(
        crate::dns::DnsPolicy::new(plan.level, plan.goal, plan.speed),
        guard.clone(),
        dns_registry.clone(),
    )));
    let web_policy = crate::web::WebPolicy::new(plan.level, plan.goal, plan.speed);
    scheduler.register_module(Arc::new(crate::web_probe::WebProbeModule::new(
        web_policy,
        guard.clone(),
    )));
    let contact_registry = restored_registries
        .map(|registries| registries.restore_contact_registry())
        .transpose()?
        .unwrap_or_default();
    let origin_baselines = restored_registries
        .map(|registries| registries.restore_origin_baselines())
        .transpose()?
        .unwrap_or_default();
    let fuzz_budget = restored_registries
        .map(|registries| registries.restore_fuzz_budget())
        .transpose()?
        .unwrap_or_default();
    let baseline_similarity = crate::baseline::BaselineSimilarityRegistry::new();
    if let Some(loaded) = &loaded {
        let outputs = loaded
            .state
            .outputs
            .iter()
            .map(|output| output.output.clone())
            .collect::<Vec<_>>();
        baseline_similarity.reconstruct_from_outputs(&outputs);
    }
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
        contact_registry.clone(),
    )));
    for module in phase5_control_modules() {
        scheduler.register_module(Arc::new(module));
    }
    // Decision Engine: host facts propose scoped port tasks, open ports
    // propose scoped service tasks, confirmed web services propose web tasks.
    scheduler.set_decision_engine(Arc::new(Phase7Engine::new_with_state(
        guard.clone(),
        plan.stable_id(),
        plan.level,
        plan.goal,
        plan.tcp_ports.clone(),
        plan.speed,
        plan.content_wordlist.clone(),
        origin_baselines.clone(),
        fuzz_budget.clone(),
    )));
    if let Some(loaded) = &loaded {
        crate::persistence::restore_scheduler_state(&mut scheduler, &loaded.state)?;
    } else {
        for task in tasks {
            // Lowering scope-checks; scheduler admission is the second
            // enforcement point; dispatch + module pre-execution re-check
            // (defense in depth). Duplicates cannot occur (lowering dedupes);
            // engine proposals dedup gracefully via best-effort admission.
            scheduler.add_task(task)?;
        }
    }
    let started = std::time::Instant::now();
    let scheduler_report = scheduler.run()?;
    let wall = started.elapsed();
    let events = sink.events();
    let module_outputs = scheduler.module_outputs();

    // JSONL output: file if --output, stdout if --format jsonl without file,
    // otherwise no JSONL (human summary printed by main). Discovery results
    // (assets, events, evidence) flow into the same typed JSONL envelope.
    let mut jsonl_bytes = 0u64;
    if let Some(path) = output_path.as_deref() {
        // Phase 20: atomic file output. A prior valid file is never touched
        // until the full stream completes (SIGINT-safe by rename).
        let mut writer = create_atomic_file_writer(path, budgets.max_evidence_bytes)?;
        write_outputs(writer.writer_mut(), &events, &module_outputs)?;
        jsonl_bytes = writer.finish()?;
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
    if let Some(path) = checkpoint_path.as_deref() {
        let state = crate::persistence::PersistedScanState::from_scheduler(
            plan.clone(),
            &scheduler,
            crate::persistence::PersistedRegistries::from_runtime(
                &contact_registry,
                &origin_baselines,
                &fuzz_budget,
                &dns_registry,
            ),
        );
        crate::persistence::save_checkpoint(path, &state)?;
    }

    Ok(RunReport {
        plan,
        task_count,
        scheduler_report,
        jsonl_bytes,
        output_path: output_path.map(|path| path.display().to_string()),
        open_ports_summary: crate::service_probe::human_service_table(&module_outputs),
        tcp_totals: crate::tcp_discovery::summarize_port_scans(&module_outputs),
        services_identified: crate::service_probe::count_identified_services(&module_outputs),
        duration_ms: wall.as_millis().min(u128::from(u64::MAX)) as u64,
    })
}

fn validate_resume_cli(cli: &Cli) -> Result<(), RunError> {
    let mut rejected = Vec::new();
    if cli.target.is_some() {
        rejected.push("target");
    }
    if cli.targets.is_some() {
        rejected.push("--targets");
    }
    if cli.config.is_some() {
        rejected.push("--config");
    }
    if cli.project_config.is_some() {
        rejected.push("--project-config");
    }
    if cli.goal.is_some() {
        rejected.push("--goal");
    }
    if cli.level.is_some() {
        rejected.push("--level");
    }
    if cli.profile.is_some() {
        rejected.push("--profile");
    }
    if !cli.scope.is_empty() {
        rejected.push("--scope");
    }
    if !cli.exclude.is_empty() {
        rejected.push("--exclude");
    }
    if cli.ports.is_some() || cli.all_ports {
        rejected.push("--ports/--all-ports");
    }
    if cli.ping || cli.discover || cli.udp {
        rejected.push("--ping/--discover/--udp");
    }
    if cli.wordlist.is_some() {
        rejected.push("--wordlist");
    }
    if cli.max_tasks.is_some()
        || cli.max_retries.is_some()
        || cli.max_concurrency.is_some()
        || cli.max_hosts.is_some()
        || cli.max_execution_time.is_some()
        || cli.max_evidence_bytes.is_some()
    {
        rejected.push("budget overrides");
    }
    if rejected.is_empty() {
        Ok(())
    } else {
        Err(RunError::InvalidResume(format!(
            "{} cannot be supplied with --resume; start a fresh scan to change scan semantics",
            rejected.join(", ")
        )))
    }
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
    // Phase 19: sort borrowed references instead of cloning every output
    // (each carries four Vecs) into a temporary owned Vec first.
    let mut ordered: Vec<&(crate::execution::TaskId, crate::execution::ModuleOutput)> =
        module_outputs.iter().collect();
    ordered.sort_by(|left, right| left.0.0.cmp(&right.0.0));
    for (_, output) in ordered {
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
///
/// Scanner work comes first: TCP totals and identified services are rendered
/// from the same typed [`crate::tcp_discovery::TcpScanTotals`] / `ServiceIdentified` state that
/// JSONL serializes, so human counts always equal machine counts.
/// Scheduler task accounting is demoted to a trailing `Diagnostics` block
/// (full task/budget detail remains in `--explain` and JSONL).
pub fn human_summary(report: &RunReport) -> String {
    human_summary_with_opens(report, None)
}

/// Human summary with service detail gathered from module outputs.
pub fn human_summary_with_opens(
    report: &RunReport,
    module_outputs: Option<&[(crate::execution::TaskId, crate::execution::ModuleOutput)]>,
) -> String {
    let scheduler = &report.scheduler_report;
    let summary = match module_outputs {
        Some(outputs) if !outputs.is_empty() => crate::service_probe::human_service_table(outputs),
        _ => report.open_ports_summary.clone(),
    };
    // Scanner-work section derives from typed execution state. When the
    // caller supplies fresher outputs (tests), re-aggregate from those so
    // the numbers still match the table above; otherwise use the report's
    // stored totals (computed from the same outputs at execution time).
    let (tcp_totals, services_identified) = match module_outputs {
        Some(outputs) if !outputs.is_empty() => (
            crate::tcp_discovery::summarize_port_scans(outputs),
            crate::service_probe::count_identified_services(outputs),
        ),
        _ => (report.tcp_totals.clone(), report.services_identified),
    };
    let tcp_line = crate::tcp_discovery::human_tcp_totals_line(&tcp_totals);
    let scan_section = if tcp_line.is_empty() {
        "TCP discovery: not attempted; no ports were scanned.".to_owned()
    } else {
        tcp_line
    };
    let services_line = format!("Services: {services_identified} identified");
    let duration_line = format!("Duration: {}ms", report.duration_ms);
    let header = format!(
        "RXScan\n\nTarget: {}\nWorkflow: {}\nLevel: {}\nSpeed: {}\n\n{}\n\n{scan_section}\n{services_line}\n{duration_line}",
        report
            .plan
            .targets
            .iter()
            .map(|target| target.original_input.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        report.plan.goal,
        report.plan.level,
        report.plan.speed,
        summary
    );
    let footer = format!(
        "\n\nDiagnostics\n  tasks: {} completed, {} failed, {} cancelled, {} timed out, {} skipped\n  jsonl bytes: {}{}",
        scheduler.completed.len(),
        scheduler.failed.len(),
        scheduler.cancelled.len(),
        scheduler.timed_out.len(),
        scheduler.skipped.len(),
        report.jsonl_bytes,
        report
            .output_path
            .as_deref()
            .map_or(String::new(), |path| format!("\n  output: {path}"))
    );
    format!("{header}{footer}")
}
