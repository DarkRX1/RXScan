//! Runtime bootstrap: Target -> Scope -> ScanPlan -> Tasks ->
//! Reactive Scheduler <-> Speed Governor <-> Budgets <-> Backpressure ->
//! HostDiscovery + TcpDiscovery + ServiceProbe + WebProbe + Crawl Modules -> Typed
//! Events / Evidence / Assets / Findings -> Decision Engine (host→port,
//! open-port→service, confirmed-service→web→crawl) -> JSONL Output + human service
//! summary.
//!
//! Real bounded discovery: native ICMP echo + TCP reachability,
//! native TCP connect port scanning (one task per target with a
//! bounded internal window, no thread per port), native protocol probing
//! (one task per open port, no authentication), bounded HTTP/1.1
//! web observations, deterministic bounded endpoint crawling
//! from confirmed web evidence, plus UDP/DNS/content/fuzz modules where
//! evidence and policy permit. Unplannable intents (TLS cipher enumeration,
//! active fingerprint probes) still run as `Skipped`
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
    vuln::VulnerabilityProvider,
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
    #[error("project database error: {0}")]
    ProjectDb(#[from] crate::project_db::ProjectDbError),
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
            Self::ProjectDb(_) => 1,
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
    /// Human UDP table (open UDP ports with transport-explicit state and
    /// grammar-matched service, or empty when no UDP opens exist).
    pub udp_summary: String,
    /// Typed UDP totals from the same `UdpScanCompleted` events JSONL
    /// serializes. Human counts and machine counts cannot disagree.
    pub udp_totals: crate::udp_discovery::UdpScanTotals,
    /// Wall-clock execution time in milliseconds (plan lowering through
    /// scheduler completion), rendered as `Duration` in human output.
    pub duration_ms: u64,
    /// Correlation-engine summary (additive): entities/edges streamed to
    /// JSONL as `graph_entity`/`graph_edge` records after module outputs.
    pub graph_entities: usize,
    pub graph_edges: usize,
    pub graph_truncated: bool,
    /// Certificates observed (distinct global `cert:sha256:` entities) and
    /// reuse groups (certs presented by more than one port).
    pub certificates_observed: usize,
    pub certificate_reuse_groups: usize,
    /// Fingerprint packs loaded once per scan (missing dir → zeros).
    pub fingerprint_packs_loaded: usize,
    pub fingerprint_rules: usize,
    pub fingerprint_files_rejected: usize,
    /// Stable scan id used for project persistence and JSONL records.
    pub scan_id: String,
    /// Optional project import summary (`--project-db`): path plus
    /// entity/observation counts imported this run.
    pub project_import: Option<ProjectImportSummary>,
    /// Change intelligence vs the previous project scan (`--project-db`
    /// only): concise diff plus generated attention. Empty otherwise.
    pub project_changes: Vec<crate::project_db::GraphChange>,
    pub attention: Vec<crate::project_db::AttentionEvent>,
}

/// Summary of one `--project-db` import for human output.
#[derive(Debug, Clone, Default)]
pub struct ProjectImportSummary {
    pub path: String,
    pub entities_upserted: usize,
    pub observations_added: usize,
    pub relationships_upserted: usize,
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
    let project_db_path = cli.project_db.clone();
    let scan_start_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0);
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
    // Stable scan id: plan identity plus start time (unique per run,
    // deterministic inputs). Used for project persistence and JSONL.
    let scan_id = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        plan.stable_id().0.hash(&mut hasher);
        scan_start_ms.hash(&mut hasher);
        format!("scan_{:016x}", hasher.finish())
    };
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
            udp_summary: String::new(),
            udp_totals: crate::udp_discovery::UdpScanTotals::default(),
            duration_ms: 0,
            graph_entities: 0,
            graph_edges: 0,
            graph_truncated: false,
            certificates_observed: 0,
            certificate_reuse_groups: 0,
            fingerprint_packs_loaded: 0,
            fingerprint_rules: 0,
            fingerprint_files_rejected: 0,
            scan_id,
            project_import: None,
            project_changes: Vec::new(),
            attention: Vec::new(),
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
    let udp_policy = crate::udp_discovery::UdpScanPolicy::new(
        plan.level,
        plan.goal,
        plan.tcp_ports.clone(),
        plan.speed,
    );
    scheduler.register_module(Arc::new(crate::udp_discovery::UdpDiscoveryModule::new(
        udp_policy,
        guard.clone(),
    )));
    let service_policy = ServicePolicy::new(plan.level, plan.goal, plan.speed);
    // Fingerprint packs load ONCE per scan into a shared compiled database
    // (never per-port file I/O). Directory defaults to `fingerprints/v1`
    // relative to the working directory and honors RXSCAN_FINGERPRINT_DIR.
    // Missing/unreadable content yields an empty DB: built-in evidence
    // remains authoritative.
    let fingerprint_dir = std::env::var("RXSCAN_FINGERPRINT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("fingerprints/v1"));
    let fingerprint_db = std::sync::Arc::new(crate::fingerprints::FingerprintDb::load_from_dir(
        &fingerprint_dir,
    ));
    scheduler.register_module(Arc::new(
        crate::service_probe::ServiceProbeModule::with_fingerprint_db(
            service_policy,
            guard.clone(),
            fingerprint_db.clone(),
        ),
    ));
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
            //
            // Task-budget exhaustion on initial admission is a normal bounded
            // truncation (P6), not an internal failure: keep the admitted
            // prefix, count the rest as not-admitted, run, and report
            // `termination: task_budget` with partial evidence preserved.
            // Scope/duplicate/dependency errors still fail fast (usage).
            match scheduler.add_task(task) {
                Ok(_) => {}
                Err(crate::execution::SchedulerError::BudgetExhausted(_)) => {
                    // `add_task` already recorded termination + not_admitted.
                    continue;
                }
                Err(error) => return Err(RunError::Scheduler(error)),
            }
        }
    }
    let started = std::time::Instant::now();
    let mut scheduler_report = scheduler.run()?;
    let wall = started.elapsed();
    let events = sink.events();
    let module_outputs = scheduler.module_outputs();

    // Correlation engine (post-scan, pure): build the evidence graph from
    // completed outputs. No network, deterministic task-id order, bounded.
    // SAN/DNS-discovered names are annotated with scope state; contact
    // gating stays with the planner (recorded, never contacted here).
    let mut graph = crate::graph::build_graph(&module_outputs, Some(&plan.scope));
    // Intelligence pass (post-scan, pure, bounded): OS/device
    // classification over collected evidence, software inventory, and
    // offline vulnerability correlation. Fingerprint databases load once
    // per scan; matching is in-memory only.
    let os_dir = std::env::var("RXSCAN_OS_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("fingerprints/os/v1"));
    let os_db = std::sync::Arc::new(crate::os_fingerprint::OsDb::load_from_dir(&os_dir));
    let device_dir = std::env::var("RXSCAN_DEVICE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("fingerprints/device/v1"));
    let device_db = std::sync::Arc::new(crate::device::DeviceDb::load_from_dir(&device_dir));
    let vuln_dir = std::env::var("RXSCAN_VULN_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("vulndb"));
    let vuln_db = load_vuln_db(&vuln_dir);
    let vuln_dataset_version = vuln_db
        .as_ref()
        .map(|db| db.info().dataset_version.clone())
        .unwrap_or_default();
    let intel = collect_intelligence(
        &plan,
        &module_outputs,
        &mut graph,
        &os_db,
        &device_db,
        vuln_db.as_ref(),
    );
    let graph_entities = graph.entity_count();
    let graph_edges = graph.edge_count();
    let graph_truncated = graph.truncated;
    let certificates_observed = graph
        .entities
        .values()
        .filter(|entity| entity.kind == crate::graph::EntityKind::Certificate)
        .count();
    let certificate_reuse_groups = graph.certificate_reuse().len();

    // Project layer (pure builders): coverage from succeeded tasks, rule
    // sources that fired, and the additive JSONL records. Coverage marks
    // truncated scans so diffs never read absence as removal.
    let mut coverage = coverage_from_scheduler(&scheduler, &plan);
    if scheduler_report.termination != crate::execution::TerminationReason::Completed {
        coverage.truncated = true;
    }
    let classifier = classifier_for_scan(
        &module_outputs,
        &fingerprint_db,
        &os_db,
        &device_db,
        vuln_db.as_ref(),
    );
    let wall_ms = wall.as_millis().min(u128::from(u64::MAX)) as u64;
    let project_records = project_records_for_scan(
        &scan_id,
        &plan,
        &scheduler_report,
        &coverage,
        &classifier,
        wall_ms,
    );

    // Optional project persistence (`--project-db`): import the correlation
    // graph, coverage, classifier provenance, and intelligence rows
    // atomically. Then diff against the previous scan and generate
    // attention. Failures here fail the run loudly (explicit operator
    // request, never silent loss).
    let mut project_import = None;
    let mut project_changes = Vec::new();
    let mut attention = Vec::new();
    if let Some(path) = project_db_path.as_deref() {
        use crate::project_db::{
            IntelImport, ScanImport, SoftwareImport, TlsObservationImport, VulnImport,
        };
        let mut project = crate::project_db::ProjectDb::open(path)?;
        let stats = project.import_scan(
            &ScanImport {
                scan_id: scan_id.clone(),
                plan_id: plan.stable_id().0,
                started_at_ms: scan_start_ms,
                finished_at_ms: scan_start_ms.saturating_add(wall_ms),
                scope_json: serde_json::to_string(&plan.scope).unwrap_or_else(|_| "{}".to_owned()),
                workflow: plan.goal.to_string(),
                level: plan.level,
                termination: scheduler_report.termination.to_string(),
                tasks_admitted: scheduler_report.tasks_admitted,
                tasks_completed: scheduler_report.completed.len() as u64,
                coverage,
                classifier,
                retention: crate::project_db::RetentionMode::Standard,
            },
            &graph,
        )?;
        // Intelligence rows: OS/device candidates, software inventory,
        // vulnerability candidates, TLS posture observations.
        let intel_import = IntelImport {
            os: intel
                .os_reports
                .iter()
                .flat_map(|report| {
                    report
                        .candidates
                        .iter()
                        .map(|candidate| (report.host.clone(), candidate.clone()))
                })
                .collect(),
            devices: intel
                .device_reports
                .iter()
                .flat_map(|report| {
                    report
                        .candidates
                        .iter()
                        .map(|candidate| (report.host.clone(), candidate.clone()))
                })
                .collect(),
            software: intel
                .software
                .iter()
                .map(|entry| SoftwareImport {
                    product: entry.identity.product.clone(),
                    vendor: entry.identity.vendor.clone().unwrap_or_default(),
                    version: entry.identity.version.clone().unwrap_or_default(),
                    family: entry.identity.version_family.clone().unwrap_or_default(),
                    cpe: entry.identity.cpe.clone().unwrap_or_default(),
                    confidence: entry.identity.product_confidence,
                    version_confidence: entry.identity.version_confidence,
                    hosts: entry.hosts.clone(),
                    endpoints: entry.endpoints.clone(),
                })
                .collect(),
            vulns: intel
                .vulns
                .iter()
                .map(|record| {
                    let match_type = match record.candidate.match_type {
                        crate::vuln::MatchType::ExactVersion => "exact_version",
                        crate::vuln::MatchType::VersionFamily => "version_family",
                        crate::vuln::MatchType::ProductOnly => "product_only",
                        crate::vuln::MatchType::Indeterminate => "indeterminate",
                    };
                    let outcome = match record.candidate.outcome {
                        crate::vuln::MatchOutcome::Matched => "matched",
                        crate::vuln::MatchOutcome::NotMatched => "not_matched",
                        crate::vuln::MatchOutcome::Indeterminate => "indeterminate",
                    };
                    VulnImport {
                        advisory_id: record.candidate.advisory_id.clone(),
                        provider: record.candidate.provider.clone(),
                        dataset_version: vuln_dataset_version.clone(),
                        product: record.candidate.product.clone(),
                        matched_version: record
                            .candidate
                            .matched_version
                            .clone()
                            .unwrap_or_default(),
                        match_type: match_type.to_owned(),
                        outcome: outcome.to_owned(),
                        confidence: record.candidate.confidence,
                        severity: record.candidate.severity_label.clone().unwrap_or_default(),
                        host: record.host.clone().unwrap_or_default(),
                        endpoint: record.endpoint.clone().unwrap_or_default(),
                        identity_json: serde_json::to_string(&record.identity)
                            .unwrap_or_else(|_| "{}".to_owned()),
                    }
                })
                .collect(),
            tls: intel
                .tls_postures
                .iter()
                .filter_map(|posture| {
                    let (address, port) = posture.endpoint.rsplit_once(':')?;
                    let port: u16 = port.parse().ok()?;
                    Some(TlsObservationImport {
                        port_entity: crate::graph::port_entity_id("tcp", address, port),
                        version: posture
                            .versions_observed
                            .first()
                            .cloned()
                            .unwrap_or_default(),
                        cipher: posture.negotiated_cipher.clone().unwrap_or_default(),
                        alpn: posture.alpn.clone().unwrap_or_default(),
                        cert_id: posture.certificate_id.clone().unwrap_or_default(),
                    })
                })
                .collect(),
        };
        project.import_intelligence(&scan_id, &intel_import)?;
        // Change intelligence vs the previous scan in this project.
        let previous = project.scan_ids()?.into_iter().rfind(|id| *id != scan_id);
        if let Some(previous) = previous {
            let changes = project.diff_scan_runs(&previous, &scan_id)?;
            project.record_changes(&scan_id, &previous, &changes)?;
            project_changes = changes;
        }
        // Attention from this scan (+ changes when available).
        let now_ms = scan_start_ms.saturating_add(wall_ms);
        attention = crate::project_db::generate_attention(
            &project,
            &scan_id,
            project
                .scan_ids()?
                .into_iter()
                .rfind(|id| *id != scan_id)
                .as_deref(),
            now_ms,
            crate::project_db::AttentionThresholds::default(),
        )?;
        project.record_attention(&scan_id, &attention)?;
        // TLS posture observations join their port entities for drift
        // diffing (version/cipher/ALPN changes need per-scan posture).
        let tls_imports: Vec<crate::project_db::TlsObservationImport> = intel
            .tls_postures
            .iter()
            .filter_map(|posture| {
                let (address, port) = posture.endpoint.rsplit_once(':')?;
                let port: u16 = port.parse().ok()?;
                Some(crate::project_db::TlsObservationImport {
                    port_entity: crate::graph::port_entity_id("tcp", address, port),
                    version: posture
                        .versions_observed
                        .first()
                        .cloned()
                        .unwrap_or_default(),
                    cipher: posture.negotiated_cipher.clone().unwrap_or_default(),
                    alpn: posture.alpn.clone().unwrap_or_default(),
                    cert_id: posture.certificate_id.clone().unwrap_or_default(),
                })
            })
            .collect();
        crate::project_db::store_tls_posture(&mut project, &scan_id, &tls_imports)?;
        project_import = Some(ProjectImportSummary {
            path: path.display().to_string(),
            entities_upserted: stats.entities_upserted,
            observations_added: stats.observations_added,
            relationships_upserted: stats.relationships_upserted,
        });
    }
    // JSONL output: file if --output, stdout if --format jsonl without file,
    // otherwise no JSONL (human summary printed by main). Discovery results
    // (assets, events, evidence) flow into the same typed JSONL envelope,
    // followed by additive `graph_entity`/`graph_edge` records.
    //
    // Priority 9: write incrementally with complete records; when the
    // output budget is exhausted stop writing new records, preserve the
    // valid partial file, append a truncation record if the budget permits,
    // and report exact accounting (never delete partial results).
    let mut jsonl_bytes = 0u64;
    if let Some(path) = output_path.as_deref() {
        // Phase 20: atomic file output. A prior valid file is never touched
        // until the full stream completes (SIGINT-safe by rename). On output
        // budget truncation we still finalize the partial file (it holds
        // complete records) instead of deleting it.
        let mut writer = create_atomic_file_writer(path, budgets.max_evidence_bytes)?;
        let output_stats = write_outputs(
            writer.writer_mut(),
            &events,
            &module_outputs,
            &graph,
            &project_records,
            &intel,
            &attention,
            &project_changes,
        )?;
        if output_stats.truncated {
            // Best-effort truncation record within the remaining budget.
            let bytes_so_far = writer.bytes_written();
            let _ = writer.writer_mut().write_termination(
                "output_budget",
                bytes_so_far,
                output_stats.records_written,
            );
            if scheduler_report.termination == crate::execution::TerminationReason::Completed {
                scheduler_report.termination = crate::execution::TerminationReason::OutputBudget;
            }
        }
        jsonl_bytes = writer.finish()?;
    } else if format
        .as_deref()
        .is_some_and(|format| format.eq_ignore_ascii_case("jsonl"))
    {
        let stdout = std::io::stdout();
        let handle = stdout.lock();
        let mut writer = crate::output::JsonlWriter::new(handle, budgets.max_evidence_bytes);
        let output_stats = write_outputs(
            &mut writer,
            &events,
            &module_outputs,
            &graph,
            &project_records,
            &intel,
            &attention,
            &project_changes,
        )?;
        if output_stats.truncated {
            let _ = writer.write_termination(
                "output_budget",
                writer.bytes_written(),
                output_stats.records_written,
            );
            if scheduler_report.termination == crate::execution::TerminationReason::Completed {
                scheduler_report.termination = crate::execution::TerminationReason::OutputBudget;
            }
        }
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
        udp_summary: crate::udp_discovery::human_udp_table(&module_outputs),
        udp_totals: crate::udp_discovery::summarize_udp_scans(&module_outputs),
        duration_ms: wall.as_millis().min(u128::from(u64::MAX)) as u64,
        graph_entities,
        graph_edges,
        graph_truncated,
        certificates_observed,
        certificate_reuse_groups,
        fingerprint_packs_loaded: fingerprint_db.stats().packs_loaded,
        fingerprint_rules: fingerprint_db.stats().rules_accepted,
        fingerprint_files_rejected: fingerprint_db.stats().files_rejected,
        scan_id,
        project_import,
        project_changes,
        attention,
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

struct OutputStats {
    records_written: u64,
    truncated: bool,
}

/// Project-layer records streamed with every scan (additive schema):
/// scan summary, coverage snapshot, and classifier provenance.
pub struct ProjectRecords {
    pub project_scan: serde_json::Value,
    pub coverage: serde_json::Value,
    pub classification_provenance: serde_json::Value,
}

/// Build coverage from succeeded scheduler tasks: only completed work
/// covers anything (attempted-but-unfinished tasks cover nothing).
/// Level-derived selections (`common`) resolve through the plan so the
/// snapshot holds concrete intervals.
pub fn coverage_from_scheduler(
    scheduler: &Scheduler,
    plan: &ScanPlan,
) -> crate::project_db::CoverageSnapshot {
    use crate::execution::{TaskKind, TaskState};
    let mut inputs = Vec::new();
    for task in scheduler.tasks() {
        let succeeded = task.state == TaskState::Succeeded;
        let host = match &task.scope_target {
            crate::execution::TaskScopeTarget::Ip(ip) => Some(ip.to_string()),
            _ => None,
        };
        let hostname = task
            .params
            .get("hostname")
            .or_else(|| task.params.get("target"))
            .cloned();
        let (ports_spec, transport) = match task.kind {
            TaskKind::PortDiscovery | TaskKind::UdpDiscovery => {
                let transport = task
                    .params
                    .get("transport")
                    .cloned()
                    .unwrap_or_else(|| "tcp".to_owned());
                let spec = match task.params.get("ports").map(String::as_str) {
                    Some("all") => Some("all".to_owned()),
                    Some("common") => {
                        let resolved = if transport.eq_ignore_ascii_case("udp") {
                            crate::ports::resolve_udp_ports(&plan.tcp_ports, plan.level).ports
                        } else {
                            crate::ports::resolve_ports(&plan.tcp_ports, plan.level).ports
                        };
                        Some(compress_ports(&resolved))
                    }
                    Some(other) => Some(other.to_owned()),
                    None => None,
                };
                (spec, Some(transport))
            }
            _ => (None, None),
        };
        inputs.push(crate::project_db::TaskCoverageInput {
            kind: format!("{:?}", task.kind),
            host,
            ports_spec,
            transport,
            hostname,
            succeeded,
        });
    }
    // TaskKind debug names are `PortDiscovery`-style; coverage builder
    // matches those exact strings.
    crate::project_db::coverage_from_tasks(&inputs, false)
}

/// Compress a sorted port list into `1-100,200` interval spec.
fn compress_ports(ports: &[u16]) -> String {
    let mut sorted: Vec<u16> = ports.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut parts = Vec::new();
    let mut index = 0;
    while index < sorted.len() {
        let start = sorted[index];
        let mut end = start;
        while index + 1 < sorted.len() && sorted[index + 1] == end.saturating_add(1) {
            index += 1;
            end = sorted[index];
        }
        if start == end {
            parts.push(start.to_string());
        } else {
            parts.push(format!("{start}-{end}"));
        }
        index += 1;
    }
    parts.join(",")
}

/// Classifier provenance for one scan: tool version, loaded packs, and the
/// distinct rule sources that fired (bounded, sorted).
#[allow(clippy::too_many_arguments)]
pub fn classifier_for_scan(
    module_outputs: &[(crate::execution::TaskId, crate::execution::ModuleOutput)],
    fingerprint_db: &crate::fingerprints::FingerprintDb,
    os_db: &crate::os_fingerprint::OsDb,
    device_db: &crate::device::DeviceDb,
    vuln_db: Option<&crate::vuln::LocalVulnDb>,
) -> crate::project_db::ClassifierProvenance {
    use std::collections::BTreeSet;
    let mut rules = BTreeSet::new();
    for (_, output) in module_outputs {
        for event in &output.events {
            for key in ["rule_source", "rule_id"] {
                if let Some(source) = event
                    .details
                    .data
                    .get(key)
                    .and_then(serde_json::Value::as_str)
                {
                    if !source.is_empty() && rules.len() < 256 {
                        rules.insert(source.to_owned());
                    }
                }
            }
        }
        for finding in &output.findings {
            for key in ["rule_source", "matcher"] {
                if let Some(source) = finding
                    .metadata
                    .get(key)
                    .and_then(serde_json::Value::as_str)
                {
                    if !source.is_empty() && rules.len() < 256 {
                        rules.insert(source.to_owned());
                    }
                }
            }
        }
    }
    let mut packs: Vec<crate::project_db::PackProvenance> = fingerprint_db
        .stats()
        .pack_paths
        .iter()
        .map(|path| crate::project_db::PackProvenance {
            path: path.clone(),
            schema_version: crate::fingerprints::FINGERPRINT_SCHEMA_VERSION,
            rule_count: 0,
        })
        .collect();
    for path in os_db.stats().pack_paths.iter() {
        packs.push(crate::project_db::PackProvenance {
            path: format!("os:{path}"),
            schema_version: crate::os_fingerprint::OS_PACK_SCHEMA_VERSION,
            rule_count: 0,
        });
    }
    for path in device_db.stats().pack_paths.iter() {
        packs.push(crate::project_db::PackProvenance {
            path: format!("device:{path}"),
            schema_version: crate::device::DEVICE_PACK_SCHEMA_VERSION,
            rule_count: 0,
        });
    }
    if let Some(vuln) = vuln_db {
        let info = vuln.info();
        packs.push(crate::project_db::PackProvenance {
            path: format!("vuln:{}:{}", info.name, info.dataset_version),
            schema_version: crate::vuln::VULN_DATASET_SCHEMA_VERSION,
            rule_count: info.advisory_count,
        });
        if rules.len() < 256 {
            rules.insert(format!("vuln-provider:{}", info.name));
        }
    }
    packs.sort_by(|a, b| a.path.cmp(&b.path));
    packs.truncate(64);
    crate::project_db::ClassifierProvenance {
        tool_version: crate::project_db::TOOL_VERSION.to_owned(),
        packs,
        rules_used: rules.into_iter().collect(),
    }
}

/// Assemble the additive project-layer JSONL records for one scan.
pub fn project_records_for_scan(
    scan_id: &str,
    plan: &ScanPlan,
    scheduler_report: &SchedulerReport,
    coverage: &crate::project_db::CoverageSnapshot,
    classifier: &crate::project_db::ClassifierProvenance,
    duration_ms: u64,
) -> ProjectRecords {
    // Uniform envelope contract: every JSONL payload carries
    // `provenance.scan_plan_id` starting with `plan_`.
    let provenance = serde_json::json!({
        "scan_plan_id": plan.stable_id().0,
        "module_name": "rxscan.run",
        "module_version": crate::project_db::TOOL_VERSION,
    });
    ProjectRecords {
        project_scan: serde_json::json!({
            "scan_id": scan_id,
            "plan_id": plan.stable_id().0,
            "workflow": plan.goal.to_string(),
            "level": plan.level,
            "tool_version": crate::project_db::TOOL_VERSION,
            "termination": scheduler_report.termination.to_string(),
            "tasks_admitted": scheduler_report.tasks_admitted,
            "tasks_completed": scheduler_report.completed.len(),
            "provenance": provenance,
        }),
        coverage: serde_json::json!({
            "scan_id": scan_id,
            "hosts_attempted": coverage.hosts_attempted,
            "tcp_attempted": coverage.tcp_attempted,
            "udp_attempted": coverage.udp_attempted,
            "dns_queried": coverage.dns_queried,
            "modules_completed": coverage.modules_completed,
            "truncated": coverage.truncated,
            "provenance": provenance,
        }),
        classification_provenance: serde_json::json!({
            "scan_id": scan_id,
            "tool_version": classifier.tool_version,
            "packs": classifier.packs,
            "rules_used": classifier.rules_used,
            "duration_ms": duration_ms,
            "provenance": provenance,
        }),
    }
}

/// Intelligence records collected post-scan for JSONL streaming and
/// project import. All pure/deterministic/bounded; no network.
pub struct IntelBundle {
    pub os_reports: Vec<crate::os_fingerprint::OsHostReport>,
    pub device_reports: Vec<crate::device::DeviceHostReport>,
    pub ssh_keys: Vec<crate::ssh::SshHostKeyRecord>,
    pub tls_postures: Vec<crate::tls::TlsPosture>,
    pub software: Vec<crate::vuln::SoftwareInventoryEntry>,
    pub vulns: Vec<crate::vuln::VulnMatchRecord>,
}

/// Maximum software identities sent to vulnerability correlation per scan.
pub const MAX_VULN_IDENTITIES: usize = 256;

/// Load an offline vulnerability dataset once per scan. Missing or
/// malformed content yields `None`: correlation is skipped, the scan is
/// unaffected (never fatal, never network).
fn load_vuln_db(dir: &std::path::Path) -> Option<crate::vuln::LocalVulnDb> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut advisories = Vec::new();
    let mut files: Vec<_> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    for path in files {
        let text = std::fs::read_to_string(&path).ok()?;
        if text.len() > 16 * 1024 * 1024 {
            continue;
        }
        let dataset: crate::vuln::VulnDataset = serde_json::from_str(&text).ok()?;
        for advisory in dataset.advisories {
            if advisories.len() >= crate::vuln::MAX_ADVISORIES_PER_FILE {
                break;
            }
            advisories.push(advisory);
        }
    }
    if advisories.is_empty() {
        return None;
    }
    crate::vuln::LocalVulnDb::from_dataset(crate::vuln::VulnDataset {
        schema_version: crate::vuln::VULN_DATASET_SCHEMA_VERSION,
        provider: "local".to_owned(),
        dataset_version: dir.display().to_string(),
        advisories,
    })
    .ok()
}

/// Post-scan intelligence: OS/device classification, SSH/TLS record
/// extraction, software inventory, and offline vulnerability correlation.
/// Attaches OS/device entities to the graph; everything else streams or
/// persists from the returned bundle.
#[allow(clippy::too_many_lines)]
fn collect_intelligence(
    plan: &ScanPlan,
    module_outputs: &[(crate::execution::TaskId, crate::execution::ModuleOutput)],
    graph: &mut crate::graph::ScanGraph,
    os_db: &crate::os_fingerprint::OsDb,
    device_db: &crate::device::DeviceDb,
    vuln_db: Option<&crate::vuln::LocalVulnDb>,
) -> IntelBundle {
    use std::collections::{BTreeMap, BTreeSet};
    let now_ms = crate::model::Timestamp::now().0;
    let scan_plan_id = plan.stable_id().0;
    // OS classification per host over passive evidence.
    let host_evidence = crate::os_fingerprint::collect_host_evidence(module_outputs);
    let mut os_reports = Vec::new();
    let mut os_families: BTreeMap<String, String> = BTreeMap::new();
    let mut hosts: Vec<String> = host_evidence.keys().cloned().collect();
    hosts.sort();
    for host in hosts {
        let evidence = &host_evidence[&host];
        let candidates = os_db.classify_host(evidence);
        if candidates.is_empty() {
            continue;
        }
        if let Some(top) = candidates.first() {
            os_families.insert(host.clone(), top.family.clone());
        }
        let provenance = crate::graph::EntityProvenance {
            scan_plan_id: scan_plan_id.clone(),
            module: "rxscan.correlate".to_owned(),
            task_id: None,
            target: Some(host.clone()),
            timestamp: now_ms,
            reason: Some("os evidence classification".to_owned()),
            rule_id: candidates
                .first()
                .and_then(|candidate| candidate.rule_ids.first().cloned()),
        };
        for candidate in &candidates {
            let mut entity_id = format!(
                "os:{}:{}",
                host.to_ascii_lowercase(),
                candidate.family.to_ascii_lowercase()
            );
            if let Some(generation) = candidate.generation.as_deref() {
                entity_id.push(':');
                entity_id.push_str(&generation.to_ascii_lowercase());
            }
            let mut attributes = BTreeMap::from([
                ("family".to_owned(), candidate.family.clone()),
                ("confidence".to_owned(), candidate.confidence.to_string()),
                ("host".to_owned(), host.clone()),
            ]);
            if let Some(generation) = &candidate.generation {
                attributes.insert("generation".to_owned(), generation.clone());
            }
            if let Some(variant) = &candidate.variant {
                attributes.insert("variant".to_owned(), variant.clone());
            }
            graph.upsert_entity(
                entity_id.clone(),
                crate::graph::EntityKind::OsCandidate,
                format!("{} ({})", candidate.family, host),
                attributes,
                &provenance,
            );
            graph.link(
                crate::graph::ip_entity_id(&host),
                entity_id,
                crate::graph::EdgeRelation::IdentifiedBy,
                candidate.confidence,
                &provenance,
                vec![format!("os evidence classifies {}", candidate.family)],
                BTreeMap::new(),
            );
        }
        // Ensure the host IP entity exists for the edge above.
        graph.upsert_entity(
            crate::graph::ip_entity_id(&host),
            crate::graph::EntityKind::IpAddress,
            host.clone(),
            BTreeMap::from([("address".to_owned(), host.clone())]),
            &provenance,
        );
        os_reports.push(crate::os_fingerprint::OsHostReport {
            host: host.clone(),
            candidates,
            evidence_count: host_evidence[&host].len(),
        });
    }
    // Device classification over graph signals + OS families.
    let mut device_reports = Vec::new();
    let signals = crate::device::collect_host_signals(graph, &os_families);
    let mut signal_hosts: Vec<String> = signals.keys().cloned().collect();
    signal_hosts.sort();
    for host in signal_hosts {
        let candidates = device_db.classify_host(&signals[&host]);
        if candidates.is_empty() {
            continue;
        }
        let provenance = crate::graph::EntityProvenance {
            scan_plan_id: scan_plan_id.clone(),
            module: "rxscan.correlate".to_owned(),
            task_id: None,
            target: Some(host.clone()),
            timestamp: now_ms,
            reason: Some("device evidence classification".to_owned()),
            rule_id: candidates
                .first()
                .and_then(|candidate| candidate.rule_ids.first().cloned()),
        };
        for candidate in &candidates {
            let entity_id = format!(
                "device:{}:{}",
                host.to_ascii_lowercase(),
                candidate.role.to_ascii_lowercase()
            );
            let mut attributes = BTreeMap::from([
                ("role".to_owned(), candidate.role.clone()),
                (
                    "role_confidence".to_owned(),
                    candidate.role_confidence.to_string(),
                ),
                ("host".to_owned(), host.clone()),
            ]);
            if let Some(vendor) = &candidate.vendor {
                attributes.insert("vendor".to_owned(), vendor.clone());
            }
            graph.upsert_entity(
                entity_id.clone(),
                crate::graph::EntityKind::DeviceCandidate,
                format!("{} ({})", candidate.role, host),
                attributes,
                &provenance,
            );
            graph.link(
                crate::graph::ip_entity_id(&host),
                entity_id,
                crate::graph::EdgeRelation::Suggests,
                candidate.role_confidence,
                &provenance,
                vec![format!("device evidence suggests {}", candidate.role)],
                BTreeMap::new(),
            );
        }
        graph.upsert_entity(
            crate::graph::ip_entity_id(&host),
            crate::graph::EntityKind::IpAddress,
            host.clone(),
            BTreeMap::from([("address".to_owned(), host.clone())]),
            &provenance,
        );
        device_reports.push(crate::device::DeviceHostReport {
            host: host.clone(),
            candidates,
            signal_kinds: signals[&host].len(),
        });
    }
    // SSH host-key + TLS posture records straight from typed events.
    let mut ssh_keys = Vec::new();
    let mut tls_postures = Vec::new();
    let mut seen_ssh: BTreeSet<String> = BTreeSet::new();
    let mut seen_posture: BTreeSet<String> = BTreeSet::new();
    for (_, output) in module_outputs {
        for event in &output.events {
            let data = &event.details.data;
            match event.kind {
                crate::model::EventKind::SshHostKeyObserved => {
                    let (Some(address), Some(port), Some(sha)) = (
                        data.get("address").and_then(serde_json::Value::as_str),
                        data.get("port").and_then(serde_json::Value::as_u64),
                        data.get("sha256").and_then(serde_json::Value::as_str),
                    ) else {
                        continue;
                    };
                    if !seen_ssh.insert(format!("{address}:{port}:{sha}")) {
                        continue;
                    }
                    let key = crate::ssh::SshHostKeyFacts {
                        key_type: data
                            .get("key_type")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("")
                            .to_owned(),
                        bits: data
                            .get("bits")
                            .and_then(serde_json::Value::as_u64)
                            .unwrap_or(0) as usize,
                        sha256: sha.to_owned(),
                        entity_id: crate::ssh::SshHostKeyFacts::entity_id_for(sha),
                    };
                    let kex = crate::ssh::SshKexFacts {
                        kex_algorithms: str_list(data, "kex_algorithms"),
                        host_key_algorithms: str_list(data, "host_key_algorithms"),
                        ciphers: str_list(data, "ciphers"),
                        macs: str_list(data, "macs"),
                        compression: str_list(data, "compression"),
                        selected_kex: data
                            .get("selected_kex")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned),
                        selected_host_key: data
                            .get("selected_host_key")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned),
                        signature_verified: false,
                    };
                    ssh_keys.push(crate::ssh::SshHostKeyRecord {
                        endpoint: format!("{address}:{port}"),
                        key,
                        kex,
                    });
                }
                crate::model::EventKind::TlsPostureObserved => {
                    let Ok(posture): Result<crate::tls::TlsPosture, _> =
                        serde_json::from_value(data.clone())
                    else {
                        continue;
                    };
                    // TlsPostureObserved details carry exactly the TlsPosture
                    // shape plus target/address/port context keys.
                    if seen_posture.insert(posture.endpoint.clone()) {
                        tls_postures.push(posture);
                    }
                }
                _ => {}
            }
        }
    }
    // Software inventory from service + technology entities.
    let mut software = inventory_from_graph(graph);
    software.sort_by(|a: &crate::vuln::SoftwareInventoryEntry, b| {
        (&a.identity.product, &a.identity.version).cmp(&(&b.identity.product, &b.identity.version))
    });
    software.truncate(512);
    // Offline vulnerability correlation (bounded identities, no network).
    let mut vulns = Vec::new();
    if let Some(db) = vuln_db {
        use crate::vuln::VulnerabilityProvider;
        for entry in software.iter().take(MAX_VULN_IDENTITIES) {
            let host = entry.hosts.first().cloned();
            let endpoint = entry.endpoints.first().cloned();
            for candidate in db.query(&entry.identity) {
                vulns.push(crate::vuln::VulnMatchRecord {
                    host: host.clone(),
                    endpoint: endpoint.clone(),
                    identity: entry.identity.clone(),
                    candidate,
                });
                if vulns.len() >= 512 {
                    break;
                }
            }
            if vulns.len() >= 512 {
                break;
            }
        }
    }
    IntelBundle {
        os_reports,
        device_reports,
        ssh_keys,
        tls_postures,
        software,
        vulns,
    }
}

fn str_list(data: &serde_json::Value, key: &str) -> Vec<String> {
    data.get(key)
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .take(32)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Normalized software inventory from service + technology entities:
/// identities grouped by (product, vendor, version) with observing hosts
/// and endpoints. Deterministic, bounded by graph size.
fn inventory_from_graph(
    graph: &crate::graph::ScanGraph,
) -> Vec<crate::vuln::SoftwareInventoryEntry> {
    use std::collections::BTreeMap;
    // service entity -> hosts/endpoints via port linkage is implicit in the
    // service id (`service:port:<transport>:<ip>:<port>:<label>`).
    let mut grouped: BTreeMap<(String, String, String), crate::vuln::SoftwareInventoryEntry> =
        BTreeMap::new();
    for entity in graph.entities.values() {
        if entity.kind != crate::graph::EntityKind::Service {
            continue;
        }
        let product = entity
            .attributes
            .get("product_hint")
            .cloned()
            .unwrap_or_default();
        if product.trim().is_empty() {
            continue;
        }
        let vendor = entity
            .attributes
            .get("vendor_hint")
            .cloned()
            .unwrap_or_default();
        let version = entity
            .attributes
            .get("version_hint")
            .cloned()
            .unwrap_or_default();
        let key = (product.clone(), vendor.clone(), version.clone());
        let entry = grouped.entry(key).or_insert_with(|| {
            let confidence = entity
                .attributes
                .get("confidence")
                .and_then(|text| text.parse::<u8>().ok())
                .unwrap_or(50);
            let version_confidence = entity
                .attributes
                .get("version_confidence")
                .and_then(|text| text.parse::<u8>().ok())
                .unwrap_or_else(|| confidence.min(70));
            crate::vuln::SoftwareInventoryEntry {
                identity: crate::vuln::SoftwareIdentity {
                    vendor: (!vendor.is_empty()).then(|| vendor.clone()),
                    product: product.clone(),
                    version: (!version.is_empty()).then(|| version.clone()),
                    version_family: entity.attributes.get("version_family").cloned(),
                    cpe: entity.attributes.get("cpe_hint").cloned(),
                    product_confidence: confidence.min(95),
                    version_confidence: version_confidence.min(95),
                    evidence: vec![format!("service {}", entity.id)],
                },
                hosts: Vec::new(),
                endpoints: Vec::new(),
            }
        });
        if let Some(address) = entity.attributes.get("address") {
            if !entry.hosts.contains(address) && entry.hosts.len() < 64 {
                entry.hosts.push(address.clone());
            }
            if let Some(port) = entity.attributes.get("port") {
                let endpoint = format!("{address}:{port}");
                if !entry.endpoints.contains(&endpoint) && entry.endpoints.len() < 64 {
                    entry.endpoints.push(endpoint);
                }
            }
        }
    }
    grouped.into_values().collect()
}

#[allow(clippy::too_many_arguments)]
fn write_outputs<W: std::io::Write>(
    writer: &mut crate::output::JsonlWriter<W>,
    scheduler_events: &[crate::execution::SchedulerEvent],
    module_outputs: &[(crate::execution::TaskId, crate::execution::ModuleOutput)],
    graph: &crate::graph::ScanGraph,
    project_records: &ProjectRecords,
    intel: &IntelBundle,
    attention: &[crate::project_db::AttentionEvent],
    changes: &[crate::project_db::GraphChange],
) -> Result<OutputStats, OutputError> {
    let mut records_written = 0u64;
    let mut truncated = false;
    // Incremental, record-complete writes: on budget exhaustion stop
    // writing new records and preserve the valid partial stream (P9).
    // `BudgetExceeded` is truncation, not a fatal error.
    macro_rules! try_write {
        ($expression:expr) => {
            match $expression {
                Ok(()) => {
                    records_written += 1;
                }
                Err(crate::output::OutputError::BudgetExceeded { .. }) => {
                    truncated = true;
                    return Ok(OutputStats {
                        records_written,
                        truncated,
                    });
                }
                Err(error) => return Err(error),
            }
        };
    }
    for event in scheduler_events {
        try_write!(writer.write_scheduler_event(event));
    }
    // Deterministic order: sort module outputs by task ID.
    // Phase 19: sort borrowed references instead of cloning every output
    // (each carries four Vecs) into a temporary owned Vec first.
    let mut ordered: Vec<&(crate::execution::TaskId, crate::execution::ModuleOutput)> =
        module_outputs.iter().collect();
    ordered.sort_by(|left, right| left.0.0.cmp(&right.0.0));
    for (_, output) in ordered {
        for asset in &output.assets {
            try_write!(writer.write_asset(asset));
        }
        for event in &output.events {
            try_write!(writer.write_event(event));
        }
        for evidence in &output.evidence {
            try_write!(writer.write_evidence(evidence));
        }
        for finding in &output.findings {
            try_write!(writer.write_finding(finding));
        }
    }
    // Correlation graph records stream last (additive schema): entities in
    // stable id order, then edges in build order. Older consumers ignore
    // unknown `record_type` envelopes generically.
    for entity in graph.entities.values() {
        try_write!(writer.write_graph_entity(entity));
    }
    for edge in &graph.edges {
        try_write!(writer.write_graph_edge(edge));
    }
    // Project-layer records: scan summary, coverage, classifier
    // provenance. Additive; diff/change records come from the project API.
    try_write!(writer.write_project_scan(&project_records.project_scan));
    try_write!(writer.write_coverage(&project_records.coverage));
    try_write!(writer.write_classification_provenance(&project_records.classification_provenance));
    // Intelligence records: OS/device candidates, SSH keys, TLS posture,
    // software inventory, vulnerability candidates. Bounded upstream.
    for report in &intel.os_reports {
        try_write!(writer.write_os_candidate(report));
    }
    for report in &intel.device_reports {
        try_write!(writer.write_device_candidate(report));
    }
    for record in &intel.ssh_keys {
        try_write!(writer.write_ssh_host_key(record));
    }
    for posture in &intel.tls_postures {
        try_write!(writer.write_tls_posture(posture));
    }
    for entry in &intel.software {
        try_write!(writer.write_software_identity(entry));
    }
    for record in &intel.vulns {
        try_write!(writer.write_vulnerability_candidate(record));
    }
    // Attention events + computed changes stream when project mode
    // produced them (empty otherwise); same budget rules apply.
    for event in attention {
        try_write!(writer.write_attention_event(event));
    }
    for change in changes {
        try_write!(writer.write_change(change));
    }
    Ok(OutputStats {
        records_written,
        truncated,
    })
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
    // UDP block appears only when the operator requested UDP discovery.
    // Like TCP, its lines require a completed scan; a requested-but-empty
    // ledger states that truthfully instead of implying results.
    let udp_section = if report.plan.udp_requested {
        let (udp_totals, udp_table) = match module_outputs {
            Some(outputs) if !outputs.is_empty() => (
                crate::udp_discovery::summarize_udp_scans(outputs),
                crate::udp_discovery::human_udp_table(outputs),
            ),
            _ => (report.udp_totals.clone(), report.udp_summary.clone()),
        };
        let totals_line = crate::udp_discovery::human_udp_totals_line(&udp_totals);
        if totals_line.is_empty() {
            // Precise accounting instead of a bare "no scan completed"
            // (Priority 4): surface the truncation reason + admission state
            // so a deadline/budget cut is distinguishable from never-queued.
            format!(
                "\n\nUDP discovery: requested but no scan completed (requested: UDP discovery, attempted: {}, remaining: {}, reason: {})",
                udp_totals.ports_attempted, udp_totals.unscanned, scheduler.termination,
            )
        } else if udp_table.is_empty() {
            format!("\n\n{totals_line}\n\nNo open UDP ports observed.")
        } else {
            format!("\n\n{totals_line}\n\n{udp_table}")
        }
    } else {
        String::new()
    };
    let duration_line = format!("Duration: {}ms", report.duration_ms);
    let header = format!(
        "RXScan\n\nTarget: {}\nWorkflow: {}\nLevel: {}\nSpeed: {}\n\n{}\n\n{scan_section}\n{services_line}{udp_section}\n{duration_line}",
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
    // Structured termination (P6): budget/deadline truncation is a normal
    // bounded state with exact accounting, never an internal failure.
    let termination_line = match scheduler.termination {
        crate::execution::TerminationReason::Completed => "Termination: completed".to_owned(),
        ref reason => format!(
            "Termination: {reason} (truncated; partial evidence preserved: {})",
            if report.jsonl_bytes > 0 || !scheduler.completed.is_empty() {
                "yes"
            } else {
                "no completed tasks"
            }
        ),
    };
    let tasks_line = format!(
        "  tasks admitted: {}, completed: {}, failed: {}, cancelled: {}, timed out: {}, skipped: {}, not admitted: {}",
        scheduler.tasks_admitted,
        scheduler.completed.len(),
        scheduler.failed.len(),
        scheduler.cancelled.len(),
        scheduler.timed_out.len(),
        scheduler.skipped.len(),
        scheduler.tasks_not_admitted,
    );
    // Retry accounting (P7): budget configured vs consumed + by module.
    let mut retry_parts = vec![format!(
        "retry budget {}/{}",
        scheduler.retries_consumed, report.plan.budgets.max_retries
    )];
    let mut retry_modules: Vec<_> = scheduler.retries_by_module.iter().collect();
    retry_modules.sort();
    for (module, count) in retry_modules.iter().take(8) {
        retry_parts.push(format!("{module}={count}"));
    }
    let retry_line = format!("  retries: {}", retry_parts.join(", "));
    // Structured errors (P5): categorized counts, aggregate preserved.
    let errors_line = if scheduler.errors_by_category.is_empty() {
        "  errors by category: none".to_owned()
    } else {
        let mut parts: Vec<_> = scheduler.errors_by_category.iter().collect();
        parts.sort();
        format!(
            "  errors by category: {}",
            parts
                .into_iter()
                .map(|(name, count)| format!("{name}={count}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    // Web/module failures (P8): failures by high-level stage.
    let failures_line = if scheduler.failures_by_module.is_empty() {
        String::new()
    } else {
        let mut parts: Vec<_> = scheduler.failures_by_module.iter().collect();
        parts.sort();
        format!(
            "\n  failures by module: {}",
            parts
                .into_iter()
                .map(|(name, count)| format!("{name}={count}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    // Correlation engine summary: fingerprint packs loaded once per scan,
    // graph entities/edges streamed, certificate reuse observed.
    let fingerprint_line = format!(
        "  fingerprints: {} packs, {} rules, {} rejected",
        report.fingerprint_packs_loaded,
        report.fingerprint_rules,
        report.fingerprint_files_rejected,
    );
    let graph_line = format!(
        "  graph: {} entities, {} edges{}; certificates: {} observed, {} reused",
        report.graph_entities,
        report.graph_edges,
        if report.graph_truncated {
            " (truncated)"
        } else {
            ""
        },
        report.certificates_observed,
        report.certificate_reuse_groups,
    );
    let project_line = report
        .project_import
        .as_ref()
        .map_or(String::new(), |import| {
            format!(
                "\n  project: {} ({} entities, {} observations, {} relationships)",
                import.path,
                import.entities_upserted,
                import.observations_added,
                import.relationships_upserted,
            )
        });
    // Change intelligence (project mode only): concise counts plus top
    // attention items. Detail lives in structured records / project CLI.
    let changes_line = if report.project_changes.is_empty() {
        String::new()
    } else {
        format!(
            "\n{}",
            crate::project_db::human_changes_summary(&report.project_changes)
        )
    };
    let attention_line = if report.attention.is_empty() {
        String::new()
    } else {
        use std::collections::BTreeMap;
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for event in &report.attention {
            *counts.entry(event.severity.as_str()).or_default() += 1;
        }
        let mut lines = vec![format!("Attention ({} items):", report.attention.len())];
        for (severity, count) in &counts {
            lines.push(format!("  {severity}: {count}"));
        }
        for event in report.attention.iter().take(5) {
            lines.push(format!(
                "  [{}] {}: {}",
                event.severity.as_str(),
                event.category,
                event.title.chars().take(100).collect::<String>()
            ));
        }
        format!("\n{}", lines.join("\n"))
    };
    let footer = format!(
        "\n\nDiagnostics\n{termination_line}\n{tasks_line}\n{retry_line}\n  evidence bytes: {}/{}\n{errors_line}{failures_line}\n{fingerprint_line}\n{graph_line}{project_line}{changes_line}{attention_line}\n  deadline: {}ms configured, {}ms wall, {}ms overrun, {}ms cleanup\n  jsonl bytes: {}{}",
        scheduler.evidence_bytes,
        report.plan.budgets.max_evidence_bytes,
        scheduler.deadline_ms,
        scheduler.wall_ms,
        scheduler.deadline_overrun_ms,
        scheduler.cleanup_ms,
        report.jsonl_bytes,
        report
            .output_path
            .as_deref()
            .map_or(String::new(), |path| format!("\n  output: {path}"))
    );
    format!("{header}{footer}")
}
