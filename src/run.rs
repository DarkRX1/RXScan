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
    /// Structured service intelligence per open port for findings-first
    /// human output (product/version/banner/endpoint/title/tech/TLS/SSH).
    /// Internal view-model only: derived from the same typed evidence JSONL
    /// serializes, never changes machine schemas, never invented.
    pub port_details: Vec<PortServiceDetail>,
    /// Optional project import summary (`--project-db`): path plus
    /// entity/observation counts imported this run.
    pub project_import: Option<ProjectImportSummary>,
    /// Change intelligence vs the previous project scan (`--project-db`
    /// only): concise diff plus generated attention. Empty otherwise.
    pub project_changes: Vec<crate::project_db::GraphChange>,
    pub attention: Vec<crate::project_db::AttentionEvent>,
    /// OS inference summary per host for findings-first human output (best
    /// candidate only; full evidence streams as `os_candidate` JSONL).
    /// Empty when no host produced OS evidence.
    pub os_hosts: Vec<OsHostSummary>,
}

/// Findings-first OS intelligence for one host.
///
/// Internal presentation view-model: only set from the same typed
/// inference JSONL serializes. Unknown hosts (no defensible evidence)
/// carry `family: "Unknown"` with the explicit reason, never a guess.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct OsHostSummary {
    pub host: String,
    pub family: String,
    pub generation: Option<String>,
    pub confidence: u8,
    /// Explainable band (`high`/`medium`/`low`/`unknown`).
    pub band: String,
    /// Best-candidate coverage 0..=1.
    pub coverage: f32,
    /// Honest limitation note (unsupported probe family, missing raw
    /// capability, unavailable open/closed-port evidence), if any.
    pub limitation: Option<String>,
}

/// Summary of one `--project-db` import for human output.
#[derive(Debug, Clone, Default)]
pub struct ProjectImportSummary {
    pub path: String,
    pub entities_upserted: usize,
    pub observations_added: usize,
    pub relationships_upserted: usize,
}

/// Findings-first service intelligence for one open TCP port.
///
/// Internal presentation view-model: every field is `Option` and only set
/// when the underlying typed evidence actually observed it. The renderer
/// shows a small useful subset (endpoint/product/title/tech/TLS for HTTP,
/// product/version/banner/key for SSH) and never fabricates missing values.
/// Stored evidence and JSON/JSONL are never truncated by human display.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortServiceDetail {
    pub port: u16,
    pub service: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub endpoint: Option<String>,
    pub title: Option<String>,
    pub technologies: Vec<String>,
    pub tls_name: Option<String>,
    pub tls_issuer: Option<String>,
    pub ssh_key: Option<String>,
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
    execute_impl(cli, None)
}

/// Execute a scan with an externally owned cancellation flag.
///
/// Additive web-API path: the CLI always calls [`execute`] (no external
/// flag). When `external_cancel` is set, the scheduler observes it at the
/// top of every iteration through the same machinery as Ctrl+C shutdown:
/// workers stop promptly, already-collected evidence is preserved, and the
/// run reports `UserCancelled` semantics instead of a generic error.
pub fn execute_with_cancellation(
    cli: Cli,
    external_cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> Result<RunReport, RunError> {
    execute_impl(cli, external_cancel)
}

fn execute_impl(
    cli: Cli,
    external_cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> Result<RunReport, RunError> {
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
        // `--os` applies to resumed runs too: active probing is a bounded
        // post-scan phase over replayed outputs, not a lowered task.
        if cli.os {
            plan.os_requested = true;
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
            port_details: Vec::new(),
            project_import: None,
            project_changes: Vec::new(),
            attention: Vec::new(),
            os_hosts: Vec::new(),
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
    if let Some(flag) = external_cancel {
        scheduler.link_external_cancel(flag);
    }
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
    let tcp_policy = TcpScanPolicy::new(plan.level, plan.goal, plan.tcp_ports.clone(), plan.speed)
        .with_scan_mode(
            &plan.scan_mode_requested,
            &plan.scan_mode,
            &plan.scan_mode_fallback,
        );
    if plan.scan_mode == "syn" {
        scheduler.register_module(Arc::new(
            crate::tcp_discovery::TcpDiscoveryModule::with_scanner(
                tcp_policy,
                Arc::new(crate::syn::SynScanner::default()),
                guard.clone(),
            ),
        ));
    } else {
        scheduler.register_module(Arc::new(crate::tcp_discovery::TcpDiscoveryModule::new(
            tcp_policy,
            guard.clone(),
        )));
    }
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
    // Explicit bounded active OS probing (`--os` only): small deterministic
    // plans per in-scope host reusing known ports. Scope, cancellation,
    // deadlines, and capabilities stay authoritative; the phase degrades
    // to passive evidence with explicit notes, never run failure.
    let active_os = collect_active_os_evidence(&plan, &module_outputs, wall);
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
        &active_os,
    );
    // Findings-first OS view-model for human output (best candidate or
    // explicit Unknown per host, derived from the same typed inference
    // JSONL serializes).
    let os_hosts: Vec<OsHostSummary> = intel
        .os_reports
        .iter()
        .map(|report| match report.candidates.first() {
            Some(best) => OsHostSummary {
                host: report.host.clone(),
                family: best.family.clone(),
                generation: best.generation.clone(),
                confidence: best.confidence,
                band: crate::os_fingerprint::confidence_label(best.confidence).to_owned(),
                coverage: report.coverage,
                limitation: os_limitation_note(report),
            },
            None => OsHostSummary {
                host: report.host.clone(),
                family: "Unknown".to_owned(),
                generation: None,
                confidence: 0,
                band: "unknown".to_owned(),
                coverage: 0.0,
                limitation: report.probe_availability.clone(),
            },
        })
        .collect();
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
        port_details: collect_port_details(&module_outputs),
        project_import,
        project_changes,
        attention,
        os_hosts,
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

/// Bounded active OS evidence for one scan (`--os` only): per-host
/// matcher evidence plus one honest availability note per host.
struct ActiveOsEvidence {
    per_host: std::collections::BTreeMap<String, Vec<crate::os_fingerprint::OsEvidence>>,
    notes: std::collections::BTreeMap<String, String>,
}

/// Explicit bounded active OS probing (`--os` only).
///
/// One small deterministic probe plan per in-scope IP host, reusing ports
/// the scan already observed (no hidden scan expansion). Scope is
/// re-checked per host and stays authoritative; process cancellation and
/// the remaining execution deadline bound the phase; the runtime raw
/// capability gates header observations. Unavailable capabilities degrade
/// to passive evidence with an explicit note, never a run failure.
/// Hostnames without a literal address are never resolved here (no extra
/// network); they keep passive inference only.
fn collect_active_os_evidence(
    plan: &ScanPlan,
    module_outputs: &[(crate::execution::TaskId, crate::execution::ModuleOutput)],
    wall: std::time::Duration,
) -> ActiveOsEvidence {
    use std::collections::BTreeMap;
    let mut evidence = ActiveOsEvidence {
        per_host: BTreeMap::new(),
        notes: BTreeMap::new(),
    };
    if !plan.os_requested {
        return evidence;
    }
    let platform = crate::platform::capabilities::detect();
    let cancel = crate::execution::CancellationToken::default();
    let config = crate::os_active::ActiveProbeConfig::default();
    let port_states = crate::os_active::host_tcp_port_states(module_outputs);
    let passive = crate::os_fingerprint::collect_host_evidence(module_outputs);
    let mut hosts: Vec<String> = port_states.keys().cloned().collect();
    for host in passive.keys() {
        if !port_states.contains_key(host) {
            hosts.push(host.clone());
        }
    }
    hosts.sort();
    hosts.dedup();
    // Phase budget: at most 30s total, less when the execution deadline
    // leaves less room. Deadlines stay authoritative: zero remaining time
    // skips every probe with an explicit note.
    let phase_budget_ms: u64 = 30_000;
    let remaining_ms = plan
        .budgets
        .max_execution_time_ms
        .checked_sub(wall.as_millis().min(u128::from(u64::MAX)) as u64);
    let mut budget_ms = phase_budget_ms;
    if let Some(remaining) = remaining_ms {
        budget_ms = budget_ms.min(remaining);
    }
    let phase_start = std::time::Instant::now();
    for host in hosts {
        if crate::platform::process::process_cancelled() || cancel.is_cancelled() {
            evidence.notes.insert(
                host.clone(),
                "active OS probes cancelled; passive evidence retained".to_owned(),
            );
            break;
        }
        if phase_start.elapsed().as_millis() as u64 >= budget_ms {
            evidence.notes.insert(
                host.clone(),
                "active OS probe budget exhausted; passive evidence retained".to_owned(),
            );
            continue;
        }
        let address: std::net::IpAddr = match host.parse() {
            Ok(address) => address,
            Err(_) => {
                evidence.notes.insert(
                    host.clone(),
                    "hostname without literal address: active probes skipped without implicit resolution; passive evidence retained"
                        .to_owned(),
                );
                continue;
            }
        };
        let (open, closed) = port_states.get(&host).cloned().unwrap_or_default();
        let probe_plan = crate::os_active::plan_os_probes(&host, &open, &closed, config.max_probes);
        let outcome = crate::os_active::probe_host_with_scope(
            address,
            &plan.scope,
            &config,
            &cancel,
            &platform,
        );
        if outcome.cancelled {
            evidence.notes.insert(
                host.clone(),
                "active OS probes cancelled; passive evidence retained".to_owned(),
            );
            continue;
        }
        let items = crate::os_active::signals_to_evidence(&outcome.signals);
        if !items.is_empty() {
            evidence.per_host.insert(host.clone(), items);
        }
        let mut notes = probe_plan.missing.clone();
        if let Some(reason) = outcome.unavailable_reason {
            notes.push(reason);
        }
        notes.push(format!(
            "active probe plan: {} probe(s) on port(s) {}",
            probe_plan.probes_planned,
            probe_plan
                .ports
                .iter()
                .map(|port| port.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ));
        evidence.notes.insert(host.clone(), notes.join("; "));
    }
    evidence
}

/// Surface only honest limitation notes in human output: routine plan
/// lines stay in JSONL, while unavailable/skipped/cancelled signals reach
/// the findings view.
fn os_limitation_note(report: &crate::os_fingerprint::OsHostReport) -> Option<String> {
    let note = report.probe_availability.as_deref()?;
    let lowered = note.to_ascii_lowercase();
    let limitation = [
        "unavailable",
        "skipped",
        "cancelled",
        "exhausted",
        "deadline",
        "outside authorized scope",
        "without implicit resolution",
        "passive evidence retained",
        "passive-only",
    ]
    .iter()
    .any(|marker| lowered.contains(marker));
    if limitation {
        Some(note.chars().take(160).collect())
    } else {
        None
    }
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
    active_os: &ActiveOsEvidence,
) -> IntelBundle {
    use std::collections::{BTreeMap, BTreeSet};
    let now_ms = crate::model::Timestamp::now().0;
    let scan_plan_id = plan.stable_id().0;
    // OS classification per host over passive evidence plus bounded
    // active evidence (`--os` only, merged additively). Inference stays
    // deterministic: unknown is an explicit report on explicit runs, never
    // a guessed label.
    let mut host_evidence = crate::os_fingerprint::collect_host_evidence(module_outputs);
    for (host, items) in &active_os.per_host {
        let slot = host_evidence.entry(host.clone()).or_default();
        for item in items.iter().take(16) {
            if slot.len() < 64 {
                slot.push(item.clone());
            }
        }
    }
    let mut os_reports = Vec::new();
    let mut os_families: BTreeMap<String, String> = BTreeMap::new();
    let mut hosts: Vec<String> = host_evidence.keys().cloned().collect();
    hosts.sort();
    for host in hosts {
        let evidence = &host_evidence[&host];
        let inference = os_db.classify_detailed(evidence);
        let candidates = inference.candidates();
        let probe_note = active_os.notes.get(&host).cloned();
        if candidates.is_empty() {
            // Unknown is first-class on explicit runs: record what was
            // observed (or not) instead of dropping the host silently.
            // Passive runs keep the quiet findings-first behavior.
            if plan.os_requested {
                os_reports.push(crate::os_fingerprint::OsHostReport {
                    host: host.clone(),
                    candidates: Vec::new(),
                    evidence_count: host_evidence[&host].len(),
                    coverage: 0.0,
                    unavailable: Vec::new(),
                    probe_availability: probe_note.or_else(|| {
                        inference
                            .unknown_reason
                            .clone()
                            .map(|reason| format!("unknown: {reason}"))
                    }),
                    provenance: Vec::new(),
                });
            }
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
            coverage: inference
                .best
                .as_ref()
                .map(|best| best.coverage)
                .unwrap_or(0.0),
            unavailable: inference
                .best
                .as_ref()
                .map(|best| best.unavailable.clone())
                .unwrap_or_default(),
            probe_availability: probe_note,
            provenance: inference
                .best
                .as_ref()
                .map(|best| best.provenance.clone())
                .unwrap_or_default(),
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
/// Designed interface: `RXSCAN / RECON` header, `TARGET` metadata, `PORTS`
/// table, `SCAN SUMMARY` counts, `DIAGNOSTICS` accounting, and a bottom
/// summary bar. Scanner work comes first: TCP totals and identified
/// services render from the same typed [`crate::tcp_discovery::TcpScanTotals`]
/// / `ServiceIdentified` state that JSONL serializes, so human counts
/// always equal machine counts. Scheduler task accounting is demoted to a
/// trailing `Diagnostics` block (full task/budget detail remains in
/// `--explain` and JSONL).
pub fn human_summary(report: &RunReport) -> String {
    human_summary_with_opens(report, None)
}

/// Human summary with service detail gathered from module outputs.
pub fn human_summary_with_opens(
    report: &RunReport,
    module_outputs: Option<&[(crate::execution::TaskId, crate::execution::ModuleOutput)]>,
) -> String {
    human_summary_caps(
        report,
        crate::terminal::TerminalCapabilities::plain(),
        module_outputs,
    )
}

/// Capabilities-aware scan renderer: styled human output when
/// `caps.color` is set, plain fallback otherwise. Machine output never
/// passes through here.
///
/// Default human output is findings-first and concise: header, `TARGET`,
/// `PORTS`, `SCAN SUMMARY`, concise exceptional warnings, and a footer
/// recap. Legacy diagnostic prose (`Duration:`, `TCP discovery …`,
/// `Services: …`, `DIAGNOSTICS` telemetry) lives only in the explain
/// rendering; see `--explain` and JSONL.
pub fn human_summary_caps(
    report: &RunReport,
    caps: crate::terminal::TerminalCapabilities,
    module_outputs: Option<&[(crate::execution::TaskId, crate::execution::ModuleOutput)]>,
) -> String {
    human_summary_inner(report, caps, module_outputs, false)
}

/// Detailed operational rendering for `--explain`.
///
/// Contains everything default shows plus the engineering detail:
/// termination, task admission, retry/evidence budgets, error categories,
/// fingerprints, graph/certificates, deadlines, wall/overrun/cleanup,
/// JSONL bytes, TCP accounting, services line, legacy `Duration:`, scan
/// modes, fallback reasons, and effective plan. The model is unchanged;
/// only presentation differs.
pub fn human_summary_explain(report: &RunReport) -> String {
    human_summary_with_opens_explain(report, None)
}

/// Detailed rendering with fresh module outputs (tests).
pub fn human_summary_with_opens_explain(
    report: &RunReport,
    module_outputs: Option<&[(crate::execution::TaskId, crate::execution::ModuleOutput)]>,
) -> String {
    human_summary_explain_caps(
        report,
        crate::terminal::TerminalCapabilities::plain(),
        module_outputs,
    )
}

/// Capabilities-aware detailed rendering for `--explain`.
pub fn human_summary_explain_caps(
    report: &RunReport,
    caps: crate::terminal::TerminalCapabilities,
    module_outputs: Option<&[(crate::execution::TaskId, crate::execution::ModuleOutput)]>,
) -> String {
    human_summary_inner(report, caps, module_outputs, true)
}

fn human_summary_inner(
    report: &RunReport,
    caps: crate::terminal::TerminalCapabilities,
    module_outputs: Option<&[(crate::execution::TaskId, crate::execution::ModuleOutput)]>,
    explain: bool,
) -> String {
    use crate::terminal::{
        Align, WorkflowMode, error_block, footer_block, format_count, format_count_u64,
        humanize_duration_ms, key_value, paint, section_heading, style_for_port_state,
        warning_block, workflow_header,
    };
    use crate::terminal::{Style, Theme};
    let color = caps.color;
    let mode = caps.width_mode();
    let scheduler = &report.scheduler_report;
    // Scanner-work state derives from typed execution state. When the
    // caller supplies fresher outputs (tests), re-aggregate from those so
    // the numbers still match the table; otherwise use the report's
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
        tcp_line.clone()
    };
    let services_line = format!("Services: {services_identified} identified");

    let mut out = String::new();
    // Header ------------------------------------------------------------
    out.push_str(&workflow_header(caps, "RECON", None));
    out.push('\n');

    // TARGET ------------------------------------------------------------
    out.push('\n');
    out.push_str(&section_heading(caps, "Target"));
    out.push('\n');
    out.push('\n');
    let hosts = report
        .plan
        .targets
        .iter()
        .map(|target| target.original_input.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let host_display = if hosts.is_empty() {
        "-".to_owned()
    } else {
        hosts
    };
    out.push_str(&key_value(
        caps,
        "Host",
        &paint(color, Style::Identifier, &host_display),
        9,
    ));
    out.push('\n');
    out.push_str(&key_value(
        caps,
        "Profile",
        &format!(
            "Level {} · {}",
            paint(color, Style::Value, &report.plan.level.to_string()),
            report.plan.speed
        ),
        9,
    ));
    out.push('\n');
    out.push_str(&key_value(
        caps,
        "Duration",
        &paint(
            color,
            Style::Value,
            &humanize_duration_ms(report.duration_ms),
        ),
        9,
    ));
    out.push('\n');
    // Duration renders exactly once in the main body (humanized). The
    // footer recap repeats it as compact summary context; the legacy
    // `Duration: <ms>ms` telemetry lives only in `--explain`.
    // (No duplicate duration line here.)

    // PORTS -------------------------------------------------------------
    // Findings-first: each open port shows the useful observed service
    // intelligence underneath it (product/version/endpoint/title/tech/TLS).
    // Only evidence-backed fields render; unknown stays honest.
    out.push('\n');
    out.push_str(&section_heading(caps, "Ports"));
    out.push('\n');
    let port_rows = scan_port_rows(report, module_outputs);
    if port_rows.is_empty() {
        out.push('\n');
        if tcp_totals.completed_tasks > 0 {
            out.push_str(&format!(
                "  {}\n",
                paint(color, Style::Muted, "No open TCP ports observed.")
            ));
        } else {
            out.push_str(&format!(
                "  {}\n",
                paint(
                    color,
                    Style::Muted,
                    "No TCP port discovery was completed; no ports were scanned."
                )
            ));
        }
    } else {
        out.push('\n');
        let details: Vec<PortServiceDetail> = match module_outputs {
            Some(outputs) if !outputs.is_empty() => collect_port_details(outputs),
            _ => report.port_details.clone(),
        };
        let details_map: std::collections::BTreeMap<u16, &PortServiceDetail> =
            details.iter().map(|d| (d.port, d)).collect();
        let _ = mode;
        let _ = Align::Left;
        for row in &port_rows {
            let state_label = row.state.to_ascii_uppercase();
            let service_clean = crate::terminal::sanitize_human_text(&row.service);
            let service_label = if service_clean.is_empty() {
                "unknown".to_owned()
            } else {
                service_clean
            };
            out.push_str(&format!(
                "  {}  {}  {}\n",
                paint(color, Style::Identifier, &row.port_label),
                paint(color, style_for_port_state(&row.state), &state_label),
                paint(color, Style::Value, &service_label),
            ));
            let port_num = row
                .port_label
                .split('/')
                .next()
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(0);
            if let Some(detail) = details_map.get(&port_num) {
                for (label, value, is_url) in port_detail_lines(detail, caps) {
                    let styled_label = paint(color, Style::Secondary, &label);
                    let styled_value = if is_url {
                        paint(color, Style::Identifier, &value)
                    } else {
                        paint(color, Style::Primary, &value)
                    };
                    // Pad label to 10 visible columns for scannability.
                    let pad = 10usize.saturating_sub(label.len());
                    out.push_str(&format!(
                        "    {styled_label}{}  {styled_value}\n",
                        " ".repeat(pad)
                    ));
                }
            } else if row.version.trim() != "-" && !row.version.trim().is_empty() {
                // Fallback from stored summary (product only, no invented
                // version/endpoint/TLS). Honest: shows only what the summary
                // preserved.
                let clean = crate::terminal::truncate_display(
                    &crate::terminal::sanitize_human_text(&row.version),
                    40,
                );
                if !clean.is_empty() && clean != "-" {
                    let styled_label = paint(color, Style::Secondary, "Product");
                    let styled_value = paint(color, Style::Primary, &clean);
                    out.push_str(&format!("    {styled_label}     {styled_value}\n"));
                }
            }
            out.push('\n');
        }
    }

    // OPERATING SYSTEM --------------------------------------------------
    // Findings-first OS inference (best candidate or explicit Unknown per
    // host). High confidence renders confirmed-green; medium/low render
    // uncertain-amber; unknown renders muted-gray with its limitation.
    // Full evidence (matched/conflicting/unavailable/provenance) streams
    // as os_candidate JSONL and persists to project mode.
    if !report.os_hosts.is_empty() {
        out.push('\n');
        out.push_str(&section_heading(caps, "Operating System"));
        out.push('\n');
        out.push('\n');
        for host in &report.os_hosts {
            let label = if host.family == "Unknown" {
                "Unknown".to_owned()
            } else if let Some(generation) = host.generation.as_deref() {
                format!("{} {generation}", host.family)
            } else {
                host.family.clone()
            };
            let (band_label, band_style): (String, Style) = match host.band.as_str() {
                "high" => ("HIGH".to_owned(), Style::Success),
                "medium" | "low" => (host.band.to_ascii_uppercase(), Style::Warning),
                _ => ("UNKNOWN".to_owned(), Style::Muted),
            };
            let clean_label = crate::terminal::truncate_display(
                &crate::terminal::sanitize_human_text(&label),
                48,
            );
            out.push_str(&format!(
                "  {}  {}  {}\n",
                paint(color, Style::Identifier, &host.host),
                paint(color, Style::Primary, &clean_label),
                paint(color, band_style, &band_label),
            ));
            if host.family != "Unknown" {
                out.push_str(&format!(
                    "    {}  {} confidence {} · coverage {}%\n",
                    paint(color, Style::Secondary, "Detail"),
                    paint(color, Style::Primary, &host.band),
                    paint(color, Style::Value, &host.confidence.to_string()),
                    paint(
                        color,
                        Style::Value,
                        &format!("{}", (host.coverage * 100.0).round() as u32)
                    ),
                ));
            }
            if let Some(limitation) = host.limitation.as_deref() {
                let clean = crate::terminal::truncate_display(
                    &crate::terminal::sanitize_human_text(limitation),
                    100,
                );
                out.push_str(&format!(
                    "    {}  {}\n",
                    paint(color, Style::Secondary, "Limits"),
                    paint(color, Style::Muted, &clean),
                ));
            }
        }
    }

    // SCAN SUMMARY ------------------------------------------------------
    out.push('\n');
    out.push_str(&section_heading(caps, "Scan Summary"));
    out.push('\n');
    out.push('\n');
    let attempted = format!(
        "{} / {}",
        format_count_u64(tcp_totals.ports_attempted),
        format_count_u64(tcp_totals.ports_requested)
    );
    out.push_str(&key_value(
        caps,
        "Attempted",
        &paint(color, Style::Value, &attempted),
        10,
    ));
    out.push('\n');
    out.push_str(&key_value(
        caps,
        "Open",
        &paint(color, Style::Success, &format_count_u64(tcp_totals.open)),
        10,
    ));
    out.push('\n');
    out.push_str(&key_value(
        caps,
        "Filtered",
        &paint(
            color,
            Style::Warning,
            &format_count_u64(tcp_totals.filtered_or_timed_out),
        ),
        10,
    ));
    out.push('\n');
    out.push_str(&key_value(
        caps,
        "Errors",
        &paint(color, Style::Error, &format_count_u64(tcp_totals.error)),
        10,
    ));
    out.push('\n');
    out.push_str(&key_value(
        caps,
        "Unscanned",
        &paint(color, Style::Muted, &format_count_u64(tcp_totals.unscanned)),
        10,
    ));
    out.push('\n');
    // Concise UDP state (default): findings only, no telemetry sentence.
    // Detailed UDP accounting lives in `--explain`.
    let (udp_totals, udp_table) = match module_outputs {
        Some(outputs) if !outputs.is_empty() => (
            crate::udp_discovery::summarize_udp_scans(outputs),
            crate::udp_discovery::human_udp_table(outputs),
        ),
        _ => (report.udp_totals.clone(), report.udp_summary.clone()),
    };
    let udp_totals_line = crate::udp_discovery::human_udp_totals_line(&udp_totals);
    if report.plan.udp_requested {
        out.push('\n');
        if udp_totals.completed_tasks == 0 && udp_totals_line.is_empty() {
            out.push_str(&format!(
                "  {}\n",
                paint(
                    color,
                    Style::Muted,
                    "No UDP discovery was completed; no UDP ports were scanned."
                )
            ));
        } else if udp_table.is_empty() {
            out.push_str(&format!(
                "  {}\n",
                paint(color, Style::Muted, "No open UDP ports observed.")
            ));
        } else {
            out.push('\n');
            for line in udp_table.lines() {
                out.push_str(&format!("  {line}\n"));
            }
        }
    }
    // Concise exceptional warnings (default): plain language for
    // first-time users, no scheduler terminology. Detailed accounting
    // lives in `--explain`. Material incompleteness is never hidden.
    if scheduler.termination != crate::execution::TerminationReason::Completed {
        out.push('\n');
        out.push_str(&warning_block(
            caps,
            &human_termination_title(report),
            Some("Partial results are shown below."),
        ));
        out.push('\n');
    }
    if scheduler.tasks_not_admitted > 0 && tcp_totals.unscanned > 0 {
        out.push('\n');
        out.push_str(&warning_block(
            caps,
            &format!(
                "{} ports were not scanned.",
                format_count_u64(tcp_totals.unscanned)
            ),
            Some("Partial results are shown below."),
        ));
        out.push('\n');
    }
    if !scheduler.failed.is_empty() {
        out.push('\n');
        let count = scheduler.failed.len();
        out.push_str(&error_block(
            caps,
            &format!(
                "{count} scan task{} failed.",
                if count == 1 { "" } else { "s" }
            ),
            Some("See --explain for task detail."),
        ));
        out.push('\n');
    }
    // Concise project findings stay visible in default output.
    if report.project_import.is_some()
        || !report.project_changes.is_empty()
        || !report.attention.is_empty()
    {
        out.push('\n');
        out.push_str(&section_heading(caps, "Project"));
        out.push('\n');
        out.push('\n');
        if let Some(import) = &report.project_import {
            out.push_str(&format!(
                "  project: {} ({} entities, {} observations, {} relationships)\n",
                import.path,
                import.entities_upserted,
                import.observations_added,
                import.relationships_upserted,
            ));
        }
        if !report.project_changes.is_empty() {
            out.push_str(&format!(
                "  {}\n",
                crate::project_db::human_changes_summary(&report.project_changes)
            ));
        }
        if !report.attention.is_empty() {
            out.push_str(&format!("  Attention: {} items\n", report.attention.len()));
        }
    }

    // Engineering detail owns `--explain` ---------------------------------
    // Default output stops here (findings + completeness + footer). The
    // full scheduler/evidence/fingerprint/graph/deadline/TCP accounting
    // renders only when `explain` is true.
    if explain {
        out.push('\n');
        out.push_str(&section_heading(caps, "Explain"));
        out.push('\n');
        out.push('\n');
        // Effective plan + scan-mode truth (why this plan).
        out.push_str(&format!(
            "  effective plan: Level {} · {} · {}\n",
            report.plan.level, report.plan.speed, report.plan.goal,
        ));
        if !report.plan.scan_mode_requested.is_empty() || !report.plan.scan_mode.is_empty() {
            let requested = if report.plan.scan_mode_requested.is_empty() {
                "auto"
            } else {
                report.plan.scan_mode_requested.as_str()
            };
            let effective = if report.plan.scan_mode.is_empty() {
                "connect"
            } else {
                report.plan.scan_mode.as_str()
            };
            if report.plan.scan_mode_fallback.is_empty() {
                out.push_str(&format!(
                    "  scan modes: requested {requested}, effective {effective}\n"
                ));
            } else {
                out.push_str(&format!(
                    "  scan modes: requested {requested}, effective {effective} (fallback: {})\n",
                    report.plan.scan_mode_fallback,
                ));
            }
        }
        out.push_str(&format!("  tcp ports: {:?}\n", report.plan.tcp_ports));
        // Legacy scanner-work lines (explain-only).
        out.push_str(&format!("  {scan_section}\n"));
        out.push_str(&format!("  {services_line}\n"));
        if report.plan.udp_requested && !udp_totals_line.is_empty() {
            out.push_str(&format!("  {udp_totals_line}\n"));
        }
        // Legacy duration telemetry (explain-only).
        out.push_str(&format!("  Duration: {}ms\n", report.duration_ms));
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
        out.push_str(&format!("  {termination_line}\n"));
        out.push_str(&format!(
            "  tasks admitted: {}, completed: {}, failed: {}, cancelled: {}, timed out: {}, skipped: {}, not admitted: {}\n",
            scheduler.tasks_admitted,
            scheduler.completed.len(),
            scheduler.failed.len(),
            scheduler.cancelled.len(),
            scheduler.timed_out.len(),
            scheduler.skipped.len(),
            scheduler.tasks_not_admitted,
        ));
        let mut retry_parts = vec![format!(
            "retry budget {}/{}",
            scheduler.retries_consumed, report.plan.budgets.max_retries
        )];
        let mut retry_modules: Vec<_> = scheduler.retries_by_module.iter().collect();
        retry_modules.sort();
        for (module, count) in retry_modules.iter().take(8) {
            retry_parts.push(format!("{module}={count}"));
        }
        out.push_str(&format!("  retries: {}\n", retry_parts.join(", ")));
        out.push_str(&format!(
            "  evidence bytes: {}/{}\n",
            scheduler.evidence_bytes, report.plan.budgets.max_evidence_bytes,
        ));
        if scheduler.errors_by_category.is_empty() {
            out.push_str("  errors by category: none\n");
        } else {
            let mut parts: Vec<_> = scheduler.errors_by_category.iter().collect();
            parts.sort();
            out.push_str(&format!(
                "  errors by category: {}\n",
                parts
                    .into_iter()
                    .map(|(name, count)| format!("{name}={count}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !scheduler.failures_by_module.is_empty() {
            let mut parts: Vec<_> = scheduler.failures_by_module.iter().collect();
            parts.sort();
            out.push_str(&format!(
                "  failures by module: {}\n",
                parts
                    .into_iter()
                    .map(|(name, count)| format!("{name}={count}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        out.push_str(&format!(
            "  fingerprints: {} packs, {} rules, {} rejected\n",
            report.fingerprint_packs_loaded,
            report.fingerprint_rules,
            report.fingerprint_files_rejected,
        ));
        out.push_str(&format!(
            "  graph: {} entities, {} edges{}; certificates: {} observed, {} reused\n",
            report.graph_entities,
            report.graph_edges,
            if report.graph_truncated {
                " (truncated)"
            } else {
                ""
            },
            report.certificates_observed,
            report.certificate_reuse_groups,
        ));
        // Per-task timing proxy: slowest TCP task + scheduler wall/cleanup.
        out.push_str(&format!(
            "  per-task timing: TCP slowest {}ms; scheduler wall {}ms, cleanup {}ms\n",
            tcp_totals.elapsed_ms_max, scheduler.wall_ms, scheduler.cleanup_ms,
        ));
        if let Some(import) = &report.project_import {
            out.push_str(&format!(
                "  project: {} ({} entities, {} observations, {} relationships)\n",
                import.path,
                import.entities_upserted,
                import.observations_added,
                import.relationships_upserted,
            ));
        }
        if !report.project_changes.is_empty() {
            out.push_str(&format!(
                "  {}\n",
                crate::project_db::human_changes_summary(&report.project_changes)
            ));
        }
        if !report.attention.is_empty() {
            use std::collections::BTreeMap;
            let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
            for event in &report.attention {
                *counts.entry(event.severity.as_str()).or_default() += 1;
            }
            out.push_str(&format!(
                "  Attention ({} items):\n",
                report.attention.len()
            ));
            for (severity, count) in &counts {
                out.push_str(&format!("    {severity}: {count}\n"));
            }
            for event in report.attention.iter().take(5) {
                out.push_str(&format!(
                    "    [{}] {}: {}\n",
                    event.severity.as_str(),
                    event.category,
                    event.title.chars().take(100).collect::<String>()
                ));
            }
        }
        out.push_str(&format!(
            "  deadline: {}ms configured, {}ms wall, {}ms overrun, {}ms cleanup\n",
            scheduler.deadline_ms,
            scheduler.wall_ms,
            scheduler.deadline_overrun_ms,
            scheduler.cleanup_ms,
        ));
        out.push_str(&format!("  jsonl bytes: {}", report.jsonl_bytes));
        if let Some(path) = &report.output_path {
            out.push_str(&format!("\n  output: {path}"));
        }
        out.push('\n');
        // Scheduler decisions + plan reasons (why this plan).
        if !report.plan.reasons.is_empty() {
            out.push_str("  scheduler decisions:\n");
            for reason in report.plan.reasons.iter().take(12) {
                let short: String = reason.chars().take(160).collect();
                out.push_str(&format!("    - {short}\n"));
            }
        }
    }

    // Footer summary bar --------------------------------------------------
    out.push('\n');
    let recap = format!(
        "{}  ·  {}  ·  {}",
        paint(
            color,
            Style::Success,
            &format!("{} services", format_count(services_identified)),
        ),
        paint(
            color,
            Style::Secondary,
            &format!(
                "{} ports attempted",
                format_count_u64(tcp_totals.ports_attempted)
            ),
        ),
        paint(
            color,
            Style::Secondary,
            &humanize_duration_ms(report.duration_ms),
        ),
    );
    out.push_str(&footer_block(caps, &recap));
    out.push('\n');
    let _ = (format_count, Theme::DEFAULT, WorkflowMode::Passive);
    out
}

/// Concise human title for a non-completed termination.
///
/// Plain language for first-time users (no scheduler terminology);
/// full accounting lives in `--explain`. Never hides material truncation.
fn human_termination_title(report: &RunReport) -> String {
    use crate::terminal::humanize_duration_ms;
    match report.scheduler_report.termination {
        crate::execution::TerminationReason::Completed => "Completed".to_owned(),
        crate::execution::TerminationReason::GlobalDeadline => {
            let basis = if report.scheduler_report.deadline_ms > 0 {
                report.scheduler_report.deadline_ms
            } else {
                report.duration_ms
            };
            format!(
                "Scan stopped after reaching the {} time limit.",
                humanize_duration_ms(basis)
            )
        }
        crate::execution::TerminationReason::UserCancelled => "Scan was cancelled.".to_owned(),
        crate::execution::TerminationReason::TaskBudget => {
            "Scan stopped: task limit reached.".to_owned()
        }
        crate::execution::TerminationReason::RetryBudget => {
            "Scan stopped: retry limit reached.".to_owned()
        }
        crate::execution::TerminationReason::EvidenceBudget => {
            "Scan stopped: evidence limit reached.".to_owned()
        }
        crate::execution::TerminationReason::OutputBudget => {
            "Scan stopped: output limit reached.".to_owned()
        }
        crate::execution::TerminationReason::InternalFailure => {
            "Scan stopped: internal error.".to_owned()
        }
    }
}

/// One open-port row for the styled `PORTS` table.
struct ScanPortRow {
    port_label: String,
    state: String,
    service: String,
    version: String,
}

/// Build open-port rows from typed findings when available, else by
/// parsing the stored service summary. Rows are always `open`; filtered
/// and closed counts live in `SCAN SUMMARY` and JSONL.
fn scan_port_rows(
    report: &RunReport,
    module_outputs: Option<&[(crate::execution::TaskId, crate::execution::ModuleOutput)]>,
) -> Vec<ScanPortRow> {
    if let Some(outputs) = module_outputs {
        if !outputs.is_empty() {
            return scan_port_rows_from_outputs(outputs);
        }
    }
    scan_port_rows_from_summary(&report.open_ports_summary)
}

/// Extract open ports + service/product from module findings.
fn scan_port_rows_from_outputs(
    outputs: &[(crate::execution::TaskId, crate::execution::ModuleOutput)],
) -> Vec<ScanPortRow> {
    use std::collections::BTreeMap;
    let mut ports: BTreeMap<(String, u16), ()> = BTreeMap::new();
    let mut services: BTreeMap<(String, u16), (String, String)> = BTreeMap::new();
    for (_, output) in outputs {
        for finding in &output.findings {
            if finding.title.starts_with("Open TCP port") {
                let address = finding
                    .metadata
                    .get("address")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned();
                let port = finding
                    .metadata
                    .get("port")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0) as u16;
                if port > 0 {
                    ports.insert((address, port), ());
                }
            } else if finding.title.ends_with("service on port")
                || finding.title.contains(" service on port ")
            {
                let address = finding
                    .metadata
                    .get("address")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned();
                let port = finding
                    .metadata
                    .get("port")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0) as u16;
                let service = finding
                    .metadata
                    .get("service")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned();
                let product = finding
                    .metadata
                    .get("product")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("-")
                    .to_owned();
                if port > 0 {
                    ports.insert((address.clone(), port), ());
                    services.insert((address, port), (service, product));
                }
            }
        }
    }
    let mut rows = Vec::new();
    let mut keys: Vec<(String, u16)> = ports.into_keys().collect();
    keys.sort();
    for (host, port) in keys {
        let _ = host;
        let (service, version) = services
            .get(&(host.clone(), port))
            .cloned()
            .unwrap_or_else(|| ("unknown".to_owned(), "-".to_owned()));
        rows.push(ScanPortRow {
            port_label: format!("{port}/tcp"),
            state: "open".to_owned(),
            service,
            version,
        });
    }
    rows
}

/// Collect findings-first service intelligence per open port.
///
/// Only values actually observed in typed findings/events/evidence are kept;
/// missing stays `None` and the renderer omits it. Never invents products,
/// versions, URLs, titles, TLS names, banners, or technologies.
pub fn collect_port_details(
    outputs: &[(crate::execution::TaskId, crate::execution::ModuleOutput)],
) -> Vec<PortServiceDetail> {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<u16, PortServiceDetail> = BTreeMap::new();
    fn ensure_detail(
        map: &mut BTreeMap<u16, PortServiceDetail>,
        port: u16,
    ) -> &mut PortServiceDetail {
        map.entry(port).or_insert_with(|| PortServiceDetail {
            port,
            service: "unknown".to_owned(),
            ..Default::default()
        })
    }
    fn set_if_empty(slot: &mut Option<String>, value: Option<String>) {
        if slot.is_none() {
            if let Some(v) = value {
                let t = v.trim().to_owned();
                if !t.is_empty() && t != "-" {
                    *slot = Some(t);
                }
            }
        }
    }
    for (_, output) in outputs {
        // Findings: authoritative service/product/version + HTTP endpoints.
        for finding in &output.findings {
            let port = finding
                .metadata
                .get("port")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u16;
            if finding.title.starts_with("Open TCP port") {
                if port > 0 {
                    ensure_detail(&mut map, port);
                }
                continue;
            }
            let is_service = finding.title.ends_with("service on port")
                || finding.title.contains(" service on port ");
            let is_http = finding.title.starts_with("HTTP ");
            if is_service && port > 0 {
                let entry = ensure_detail(&mut map, port);
                if let Some(svc) = finding
                    .metadata
                    .get("service")
                    .and_then(serde_json::Value::as_str)
                {
                    if !svc.trim().is_empty() && entry.service == "unknown" {
                        entry.service = svc.trim().to_owned();
                    }
                }
                let product = finding
                    .metadata
                    .get("product")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
                set_if_empty(&mut entry.product, product);
                let version = finding
                    .metadata
                    .get("version")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
                set_if_empty(&mut entry.version, version);
                let ssh_key = finding
                    .metadata
                    .get("ssh_host_key_sha256")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
                set_if_empty(&mut entry.ssh_key, ssh_key);
            } else if is_http {
                // HTTP finding carries url but not always port; derive port
                // from URL when metadata lacks it, else match via evidence.
                let url = finding
                    .metadata
                    .get("url")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let derived_port = if port > 0 {
                    port
                } else {
                    url_port(&url).unwrap_or(0)
                };
                if derived_port > 0 && !url.trim().is_empty() {
                    let entry = ensure_detail(&mut map, derived_port);
                    if entry.service == "unknown" {
                        if let Some(svc) = finding
                            .metadata
                            .get("service")
                            .and_then(serde_json::Value::as_str)
                        {
                            if !svc.trim().is_empty() {
                                entry.service = svc.trim().to_owned();
                            }
                        }
                    }
                    if entry.endpoint.is_none() && !url.trim().is_empty() {
                        entry.endpoint = Some(url.trim().to_owned());
                    }
                }
            }
        }
        // Events: banners, service identity, TLS, SSH keys, endpoints.
        for event in &output.events {
            let data = &event.details.data;
            let port = data
                .get("port")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u16;
            match event.kind {
                crate::model::EventKind::BannerObserved => {
                    if port > 0 {
                        let banner = data
                            .get("banner")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned);
                        let entry = ensure_detail(&mut map, port);
                        set_if_empty(&mut entry.banner, banner);
                    }
                }
                crate::model::EventKind::ServiceIdentified => {
                    if port > 0 {
                        let entry = ensure_detail(&mut map, port);
                        if let Some(svc) = data.get("service").and_then(serde_json::Value::as_str) {
                            if !svc.trim().is_empty() && entry.service == "unknown" {
                                entry.service = svc.trim().to_owned();
                            }
                        }
                        let product = data
                            .get("product_hint")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned);
                        set_if_empty(&mut entry.product, product);
                        let version = data
                            .get("version_hint")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned);
                        set_if_empty(&mut entry.version, version);
                    }
                }
                crate::model::EventKind::SshHostKeyObserved => {
                    if port > 0 {
                        let fp = data
                            .get("sha256")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned);
                        let entry = ensure_detail(&mut map, port);
                        set_if_empty(&mut entry.ssh_key, fp);
                    }
                }
                crate::model::EventKind::EndpointObserved => {
                    let url = data
                        .get("url")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_owned();
                    let title = data
                        .get("title")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                    let p = if port > 0 {
                        port
                    } else {
                        url_port(&url).unwrap_or(0)
                    };
                    if p > 0 && !url.trim().is_empty() {
                        let entry = ensure_detail(&mut map, p);
                        if entry.endpoint.is_none() {
                            entry.endpoint = Some(url.trim().to_owned());
                        }
                        set_if_empty(&mut entry.title, title);
                    }
                }
                crate::model::EventKind::TlsObserved => {
                    // Both service-probe (sni) and web-probe (subject/issuer).
                    let subject = data
                        .get("subject")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                    let issuer = data
                        .get("issuer")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                    let sni = data
                        .get("sni")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                    // Attach to matching port when known; otherwise attach to
                    // TLS-ish ports already open (443/8443) only if exactly
                    // one such port exists (avoids misattribution).
                    let mut targets: Vec<u16> = Vec::new();
                    if port > 0 {
                        targets.push(port);
                    } else if let Some(url) = data.get("url").and_then(serde_json::Value::as_str) {
                        if let Some(p) = url_port(url) {
                            targets.push(p);
                        }
                    }
                    if targets.is_empty() {
                        let tls_ports: Vec<u16> = map
                            .iter()
                            .filter(|(_, d)| {
                                d.service.eq_ignore_ascii_case("https")
                                    || d.service.eq_ignore_ascii_case("tls")
                                    || d.service.eq_ignore_ascii_case("smtps")
                            })
                            .map(|(p, _)| *p)
                            .collect();
                        if tls_ports.len() == 1 {
                            targets.push(tls_ports[0]);
                        }
                    }
                    for p in targets {
                        let entry = ensure_detail(&mut map, p);
                        if entry.tls_name.is_none() {
                            if let Some(s) = subject.clone() {
                                if !s.trim().is_empty() {
                                    entry.tls_name = Some(s.trim().to_owned());
                                }
                            }
                        }
                        if entry.tls_name.is_none() {
                            set_if_empty(&mut entry.tls_name, sni.clone());
                        }
                        set_if_empty(&mut entry.tls_issuer, issuer.clone());
                    }
                }
                crate::model::EventKind::HttpObserved if port > 0 => {
                    let product = data
                        .get("product_hint")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                    let entry = ensure_detail(&mut map, port);
                    set_if_empty(&mut entry.product, product);
                }
                _ => {}
            }
        }
        // Evidence: full observations (service + web + cert).
        for evidence in &output.evidence {
            let data = &evidence.details.data;
            let port = data
                .get("port")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u16;
            // ServiceObservation shape.
            if (data.get("service_label").is_some() || data.get("product_hint").is_some())
                && port > 0
            {
                let entry = ensure_detail(&mut map, port);
                if let Some(svc) = data
                    .get("service_label")
                    .and_then(serde_json::Value::as_str)
                {
                    if !svc.trim().is_empty() && entry.service == "unknown" {
                        entry.service = svc.trim().to_owned();
                    }
                }
                let product = data
                    .get("product_hint")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
                set_if_empty(&mut entry.product, product);
                let version = data
                    .get("version_hint")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
                set_if_empty(&mut entry.version, version);
                let banner = data
                    .get("banner")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
                set_if_empty(&mut entry.banner, banner);
            }
            // WebProbe shape: url/title/server/technologies/tls.
            if let Some(url) = data.get("url").and_then(serde_json::Value::as_str) {
                if !url.trim().is_empty()
                    && (data.get("title").is_some()
                        || data.get("technologies").is_some()
                        || data.get("server").is_some()
                        || data.get("status").is_some())
                {
                    let p = if port > 0 {
                        port
                    } else {
                        url_port(url).unwrap_or(0)
                    };
                    if p > 0 {
                        let entry = ensure_detail(&mut map, p);
                        if entry.endpoint.is_none() {
                            entry.endpoint = Some(url.trim().to_owned());
                        }
                        let title = data
                            .get("title")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned);
                        set_if_empty(&mut entry.title, title);
                        // Server header as product fallback (observed).
                        if entry.product.is_none() {
                            let server = data
                                .get("server")
                                .and_then(serde_json::Value::as_str)
                                .map(|s| s.split('/').next().unwrap_or(s).trim().to_owned());
                            set_if_empty(&mut entry.product, server);
                        }
                        // Technologies: first two names only, scannable.
                        if entry.technologies.is_empty() {
                            if let Some(arr) = data.get("technologies").and_then(|v| v.as_array()) {
                                for tech in arr.iter().take(2) {
                                    let name = if let Some(s) = tech.as_str() {
                                        s.trim().to_owned()
                                    } else {
                                        tech.get("name")
                                            .and_then(serde_json::Value::as_str)
                                            .unwrap_or("")
                                            .trim()
                                            .to_owned()
                                    };
                                    if !name.is_empty()
                                        && !entry.technologies.contains(&name)
                                        && entry.technologies.len() < 2
                                    {
                                        entry.technologies.push(name);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Certificate shape: subject/issuer/san_dns.
            if data.get("subject").is_some() && data.get("fingerprint_sha256").is_some()
                || (data.get("subject").is_some() && data.get("issuer").is_some())
            {
                let mut targets: Vec<u16> = Vec::new();
                if port > 0 {
                    targets.push(port);
                } else if let Some(url) = data.get("url").and_then(serde_json::Value::as_str) {
                    if let Some(p) = url_port(url) {
                        targets.push(p);
                    }
                }
                if targets.is_empty() {
                    let tls_ports: Vec<u16> = map
                        .iter()
                        .filter(|(_, d)| {
                            d.service.eq_ignore_ascii_case("https")
                                || d.service.eq_ignore_ascii_case("tls")
                        })
                        .map(|(p, _)| *p)
                        .collect();
                    if tls_ports.len() == 1 {
                        targets.push(tls_ports[0]);
                    }
                }
                for p in targets {
                    let entry = ensure_detail(&mut map, p);
                    if entry.tls_name.is_none() {
                        // Prefer first SAN DNS (useful identifier) over raw DN.
                        if let Some(sans) = data.get("san_dns").and_then(|v| v.as_array()) {
                            if let Some(first) = sans.iter().filter_map(|v| v.as_str()).next() {
                                if !first.trim().is_empty() {
                                    entry.tls_name = Some(first.trim().to_owned());
                                }
                            }
                        }
                    }
                    if entry.tls_name.is_none() {
                        let subject = data
                            .get("subject")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned);
                        set_if_empty(&mut entry.tls_name, subject);
                    }
                    let issuer = data
                        .get("issuer")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                    set_if_empty(&mut entry.tls_issuer, issuer);
                }
            }
        }
    }
    map.into_values().collect()
}

fn url_port(url: &str) -> Option<u16> {
    let parsed = url::Url::parse(url.trim()).ok()?;
    parsed.port_or_known_default()
}

/// Fallback parser for the stored plain service summary
/// (`HOST … / PORT SERVICE PRODUCT / 22/tcp ssh …`).
fn scan_port_rows_from_summary(summary: &str) -> Vec<ScanPortRow> {
    let mut rows = Vec::new();
    for line in summary.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("HOST")
            || trimmed.starts_with("PORT")
            || trimmed.starts_with("No ")
        {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let Some(port_token) = parts.next() else {
            continue;
        };
        if !port_token.contains("/tcp") {
            continue;
        }
        let service = parts.next().unwrap_or("unknown").to_owned();
        let version = {
            let rest: Vec<&str> = parts.collect();
            if rest.is_empty() {
                "-".to_owned()
            } else {
                rest.join(" ")
            }
        };
        rows.push(ScanPortRow {
            port_label: port_token.to_owned(),
            state: "open".to_owned(),
            service,
            version,
        });
    }
    rows
}

/// Ordered, bounded detail lines for one open port.
///
/// Returns `(label, value, is_url)` triples. Priority follows the finding
/// type (HTTP: endpoint/product/title/tech/TLS; SSH: product/version/banner
/// /key; TLS: name/issuer; generic: product/version/banner). At most 4
/// lines keep output scannable; detailed provenance stays in `--explain`
/// and JSON/JSONL. All values are sanitized and width-bounded; stored
/// evidence is never modified.
fn port_detail_lines(
    detail: &PortServiceDetail,
    caps: crate::terminal::TerminalCapabilities,
) -> Vec<(String, String, bool)> {
    use crate::terminal::{sanitize_human_text, sanitize_url_for_display, truncate_display};
    let max_text = caps.width.saturating_sub(18).clamp(20, 80);
    let max_url = caps.width.saturating_sub(18).clamp(20, 120);
    let clean_opt = |v: &Option<String>, max: usize| -> Option<String> {
        v.as_ref().and_then(|raw| {
            let clean = sanitize_human_text(raw);
            if clean.is_empty() || clean == "-" {
                return None;
            }
            let shown = truncate_display(&clean, max);
            if shown.is_empty() || shown == "-" {
                None
            } else {
                Some(shown)
            }
        })
    };
    let clean_url = |v: &Option<String>| -> Option<String> {
        v.as_ref().and_then(|raw| {
            let clean = sanitize_url_for_display(raw);
            if clean.is_empty() {
                return None;
            }
            Some(truncate_display(&clean, max_url))
        })
    };
    fn push_line(
        lines: &mut Vec<(String, String, bool)>,
        label: &str,
        value: Option<String>,
        is_url: bool,
    ) {
        if lines.len() >= 4 {
            return;
        }
        if let Some(v) = value {
            lines.push((label.to_owned(), v, is_url));
        }
    }
    let service = detail.service.to_ascii_lowercase();
    let mut lines: Vec<(String, String, bool)> = Vec::new();
    if service == "http" || service == "https" {
        push_line(&mut lines, "Endpoint", clean_url(&detail.endpoint), true);
        push_line(
            &mut lines,
            "Product",
            clean_opt(&detail.product, max_text),
            false,
        );
        push_line(
            &mut lines,
            "Title",
            clean_opt(&detail.title, max_text),
            false,
        );
        if !detail.technologies.is_empty() && lines.len() < 4 {
            let techs: Vec<String> = detail
                .technologies
                .iter()
                .map(|t| sanitize_human_text(t))
                .filter(|t| !t.is_empty())
                .take(2)
                .collect();
            if !techs.is_empty() {
                let joined = truncate_display(&techs.join(", "), max_text);
                lines.push(("Technology".to_owned(), joined, false));
            }
        }
        push_line(
            &mut lines,
            "TLS name",
            clean_opt(&detail.tls_name, max_text),
            true,
        );
        // Version/banner only if room remains (priority lower for HTTP).
        if lines.len() < 4 {
            push_line(
                &mut lines,
                "Version",
                clean_opt(&detail.version, max_text),
                false,
            );
        }
        if lines.len() < 4 {
            push_line(
                &mut lines,
                "Banner",
                clean_opt(&detail.banner, max_text),
                false,
            );
        }
    } else if service == "ssh" {
        push_line(
            &mut lines,
            "Product",
            clean_opt(&detail.product, max_text),
            false,
        );
        push_line(
            &mut lines,
            "Version",
            clean_opt(&detail.version, max_text),
            false,
        );
        push_line(
            &mut lines,
            "Banner",
            clean_opt(&detail.banner, max_text),
            false,
        );
        if lines.len() < 4 {
            if let Some(key) = clean_opt(&detail.ssh_key, max_text) {
                lines.push(("SSH key".to_owned(), key, false));
            }
        }
    } else if service == "tls" || service == "smtps" {
        push_line(
            &mut lines,
            "TLS name",
            clean_opt(&detail.tls_name, max_text),
            true,
        );
        push_line(
            &mut lines,
            "Issuer",
            clean_opt(&detail.tls_issuer, max_text),
            false,
        );
        push_line(&mut lines, "Endpoint", clean_url(&detail.endpoint), true);
        push_line(
            &mut lines,
            "Product",
            clean_opt(&detail.product, max_text),
            false,
        );
    } else {
        push_line(
            &mut lines,
            "Product",
            clean_opt(&detail.product, max_text),
            false,
        );
        push_line(
            &mut lines,
            "Version",
            clean_opt(&detail.version, max_text),
            false,
        );
        push_line(
            &mut lines,
            "Banner",
            clean_opt(&detail.banner, max_text),
            false,
        );
        if lines.len() < 4 {
            push_line(&mut lines, "Endpoint", clean_url(&detail.endpoint), true);
        }
        if lines.len() < 4 {
            push_line(
                &mut lines,
                "TLS name",
                clean_opt(&detail.tls_name, max_text),
                true,
            );
        }
    }
    lines
}
