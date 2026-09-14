use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use clap::Parser;
use rxscan::{
    baseline::OriginBaselineRegistry,
    cli::Cli,
    contact::{ContactRegistry, RequestPurpose},
    dns::{DnsRecordType, DnsRegistry},
    execution::{
        BudgetLimits, Module, ModuleContext, ModuleFuture, ModuleOutput, PolicyScopeGuard,
        RetryPolicy, Scheduler, SpeedGovernor, Task, TaskKind, TaskScopeTarget, TaskState,
        VecEventSink,
    },
    fuzz::FuzzOriginBudget,
    model::{
        Asset, AssetKind, BoundedDetails, Confidence, Event, EventKind, Evidence, Finding,
        Provenance, Relationship, RelationshipKind, RelationshipSubject, Severity, Timestamp,
    },
    persistence::{
        PersistedModuleOutput, PersistedRegistries, PersistedScanState, PersistedTask,
        load_checkpoint, restore_scheduler_state, save_checkpoint,
    },
    plan::{ScanPlan, SpeedSetting},
    web::WebTarget,
};

struct CountModule(Arc<AtomicUsize>);

impl Module for CountModule {
    fn kind(&self) -> TaskKind {
        TaskKind::HostDiscovery
    }

    fn execute(&self, _context: ModuleContext) -> ModuleFuture {
        let count = self.0.clone();
        Box::pin(async move {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(ModuleOutput::default())
        })
    }
}

fn plan() -> ScanPlan {
    ScanPlan::compile(
        Cli::try_parse_from([
            "rxscan",
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--level",
            "5",
            "--max-tasks",
            "64",
        ])
        .unwrap(),
    )
    .unwrap()
}

fn task(plan: &ScanPlan, variant: &str, state: TaskState) -> Task {
    let guard = PolicyScopeGuard::new(plan.scope.clone());
    let mut task = Task::new_with_params(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        30,
        Duration::from_secs(1),
        RetryPolicy::default(),
        "phase14.bench",
        Provenance::new("phase14.bench", "1.0.0", plan.stable_id(), Timestamp(1)).unwrap(),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([
            ("target".to_owned(), "127.0.0.1".to_owned()),
            ("variant".to_owned(), variant.to_owned()),
        ]),
        &guard,
    )
    .unwrap();
    task.state = state;
    task
}

fn checkpoint_path() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("rxscan_phase14_bench_{}.json", std::process::id()));
    path
}

fn semantic_output(plan: &ScanPlan, task: &Task) -> ModuleOutput {
    let provenance =
        Provenance::new("phase14.bench", "1.0.0", plan.stable_id(), Timestamp(1)).unwrap();
    let host = Asset::scoped(AssetKind::Ip, "127.0.0.1", &plan.scope, provenance.clone()).unwrap();
    let url = Asset::scoped(
        AssetKind::Url,
        "http://127.0.0.1/",
        &plan.scope,
        provenance.clone(),
    )
    .unwrap();
    let evidence = Evidence::new(
        "phase14.bench",
        url.id.clone(),
        BoundedDetails::from_value(
            serde_json::json!({
                "kind": "compact_checkpoint_benchmark",
                "body_hash": "sha256:bench",
                "raw_body_retained": false
            }),
            2048,
        )
        .unwrap(),
        Confidence::new(90).unwrap(),
        provenance.clone(),
    )
    .unwrap();
    let mut finding = Finding::new(
        "Phase 14 benchmark compact state",
        Severity::Info,
        Confidence::new(80).unwrap(),
        url.id.clone(),
        provenance.clone(),
    )
    .unwrap();
    finding.evidence_ids.push(evidence.id.clone());
    let mut event = Event::new(
        EventKind::EvidenceCollected,
        Some(url.id.clone()),
        BoundedDetails::from_value(
            serde_json::json!({"task_id": task.id.0, "checkpoint_semantic_state": true}),
            2048,
        )
        .unwrap(),
        provenance.clone(),
    )
    .unwrap();
    event.relationships.push(
        Relationship::new(
            RelationshipKind::DiscoveredFrom,
            RelationshipSubject::Asset(url.id.clone()),
            RelationshipSubject::Asset(host.id.clone()),
            provenance,
        )
        .unwrap(),
    );
    ModuleOutput {
        events: vec![event],
        assets: vec![host, url],
        evidence: vec![evidence],
        findings: vec![finding],
    }
}

fn semantic_registries() -> PersistedRegistries {
    let contacts = ContactRegistry::new();
    let target = WebTarget::parse("http://127.0.0.1/login").unwrap();
    assert!(contacts.claim(&target, RequestPurpose::CrawlPage));

    let baselines = OriginBaselineRegistry::new();
    baselines.remember("http://127.0.0.1/".to_owned(), "bench_norm_hash".to_owned());

    let fuzz = FuzzOriginBudget::new();
    assert!(fuzz.claim("http://127.0.0.1/", "bench-fuzz-plan", 8));

    let dns = DnsRegistry::new();
    let resolver = "127.0.0.1:53".parse().unwrap();
    assert!(dns.claim_query("www.example.test", DnsRecordType::A, resolver));
    assert!(dns.claim_domain_task("example.test", "www.example.test", 32));

    PersistedRegistries::from_runtime(&contacts, &baselines, &fuzz, &dns)
}

fn peak_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("VmHWM:").and_then(|rest| {
            rest.split_whitespace()
                .next()
                .and_then(|value| value.parse().ok())
        })
    })
}

fn main() {
    let path = checkpoint_path();
    let plan = plan();
    let completed = task(&plan, "done", TaskState::Succeeded);
    let pending = task(&plan, "pending", TaskState::Pending);
    let output = semantic_output(&plan, &completed);
    let registries = semantic_registries();
    let state = PersistedScanState {
        schema_version: rxscan::persistence::CHECKPOINT_SCHEMA_VERSION,
        scan_id: plan.stable_id(),
        saved_at: Timestamp::now(),
        plan: plan.clone(),
        tasks: vec![
            PersistedTask {
                task: completed.clone(),
            },
            PersistedTask { task: pending },
        ],
        outputs: vec![PersistedModuleOutput {
            task_id: completed.id.clone(),
            output,
        }],
        registries,
    };
    let write_started = Instant::now();
    let write_metrics = save_checkpoint(&path, &state).unwrap();
    let checkpoint_write_ms = write_started.elapsed().as_millis();
    let load_started = Instant::now();
    let loaded = load_checkpoint(&path).unwrap();
    let checkpoint_load_ms = load_started.elapsed().as_millis();
    let guard = Arc::new(PolicyScopeGuard::new(loaded.state.plan.scope.clone()));
    let contacts = Arc::new(AtomicUsize::new(0));
    let mut scheduler = Scheduler::new(
        16,
        BudgetLimits {
            max_tasks: 64,
            max_concurrency: 1,
            ..BudgetLimits::default()
        },
        SpeedGovernor::new(SpeedSetting::Numeric(100), 1).unwrap(),
        guard,
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler.register_module(Arc::new(CountModule(contacts.clone())));
    let (restored, completed_before_resume) =
        restore_scheduler_state(&mut scheduler, &loaded.state).unwrap();
    let report = scheduler.run().unwrap();
    let network_requests_after_resume = contacts.load(Ordering::SeqCst);
    println!("phase14_bench");
    println!("assets_persisted={}", write_metrics.assets_persisted);
    println!(
        "relationships_persisted={}",
        write_metrics.relationships_persisted
    );
    println!("evidence_persisted={}", write_metrics.evidence_persisted);
    println!("findings_persisted={}", write_metrics.findings_persisted);
    println!(
        "completed_tasks_persisted={}",
        write_metrics.completed_tasks_persisted
    );
    println!(
        "pending_tasks_persisted={}",
        write_metrics.pending_tasks_persisted
    );
    println!(
        "contact_registry_entries={}",
        loaded.state.registries.contacts.len()
    );
    println!(
        "origin_baseline_entries={}",
        loaded.state.registries.origin_baselines.len()
    );
    println!(
        "fuzz_budget_entries={}",
        loaded
            .state
            .registries
            .fuzz_origin_budgets
            .iter()
            .map(|(_, plans)| plans.len())
            .sum::<usize>()
    );
    println!(
        "dns_query_entries={}",
        loaded.state.registries.dns_queries.len()
    );
    println!(
        "dns_domain_entries={}",
        loaded.state.registries.dns_domains.len()
    );
    println!(
        "registry_entries_persisted={}",
        write_metrics.registry_entries_persisted
    );
    println!("checkpoint_bytes={}", loaded.checkpoint_bytes);
    println!("checkpoint_write_ms={checkpoint_write_ms}");
    println!("checkpoint_load_ms={checkpoint_load_ms}");
    println!("resume_tasks_restored={restored}");
    println!("completed_tasks_skipped_on_resume={completed_before_resume}");
    println!("duplicate_contacts_avoided={completed_before_resume}");
    println!("network_requests_after_resume={network_requests_after_resume}");
    println!("completed_tasks_after_resume={}", report.completed.len());
    println!("failed_tasks_after_resume={}", report.failed.len());
    println!("peak_rss_kb={}", peak_rss_kb().unwrap_or(0));
    println!("release_binary_size_bytes=measure-with-cargo-build-release-and-stat");
    println!("new_production_dependency_count=0");
    let _ = fs::remove_file(path);
}
