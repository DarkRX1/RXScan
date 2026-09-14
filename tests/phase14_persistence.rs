use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use clap::Parser;
use rxscan::{
    baseline::{
        BASELINE_MODULE_NAME, BaselineModule, BaselinePolicy, BaselineSimilarityRegistry,
        ResponseSignature, baseline_task_params,
    },
    cli::Cli,
    contact::{ContactRegistry, RequestPurpose},
    decision::Phase7Engine,
    dns::{DnsRecordType, DnsRegistry},
    execution::{
        BudgetLimits, DecisionEngine, Module, ModuleContext, ModuleFuture, ModuleOutput,
        PolicyScopeGuard, RetryPolicy, Scheduler, ScopeGuard, SpeedGovernor, Task, TaskKind,
        TaskScopeTarget, TaskState, VecEventSink,
    },
    fuzz::FuzzOriginBudget,
    model::{
        Asset, AssetId, AssetKind, BoundedDetails, Event, EventKind, Provenance, Relationship,
        RelationshipKind, RelationshipSubject, Timestamp,
    },
    output::JsonlWriter,
    persistence::{
        CHECKPOINT_SCHEMA_VERSION, MAX_CHECKPOINT_BYTES, PersistedCollectionCounts,
        PersistedModuleOutput, PersistedRegistries, PersistedScanState, PersistedTask,
        load_checkpoint, restore_scheduler_state, save_checkpoint,
        validate_persisted_collection_counts,
    },
    plan::{ScanGoal, ScanPlan, SpeedSetting},
    run,
    web::{WebTarget, endpoint_asset_id},
};

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

fn temp_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "rxscan_phase14_{}_{}_{}.json",
        name,
        std::process::id(),
        Timestamp::now().0
    ));
    path
}

fn task(plan: &ScanPlan, state: TaskState, module: &str) -> Task {
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
        module,
        Provenance::new("test", "14.0.0", plan.stable_id(), Timestamp(1)).unwrap(),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([("target".to_owned(), "127.0.0.1".to_owned())]),
        &guard,
    )
    .unwrap();
    task.state = state;
    task
}

fn state_with_tasks(tasks: Vec<Task>) -> PersistedScanState {
    let plan = plan();
    PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: plan.stable_id(),
        saved_at: Timestamp(2),
        plan,
        tasks: tasks
            .into_iter()
            .map(|task| PersistedTask { task })
            .collect(),
        outputs: Vec::new(),
        registries: PersistedRegistries::default(),
    }
}

struct HttpFixture {
    port: u16,
    requests: Arc<std::sync::Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl HttpFixture {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let requests_clone = requests.clone();
        let stop_clone = stop.clone();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(20);
            while !stop_clone.load(Ordering::SeqCst) && Instant::now() < deadline {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => break,
                };
                let requests = requests_clone.clone();
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                    let mut raw = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while let Ok(count) = stream.read(&mut chunk) {
                        if count == 0 {
                            break;
                        }
                        raw.extend_from_slice(&chunk[..count]);
                        if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let path = String::from_utf8_lossy(&raw)
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_owned();
                    requests.lock().unwrap().push(path.clone());
                    let body = if path.starts_with("/__rxscan_baseline_") {
                        format!("<html><title>missing</title><body>missing {path}</body></html>")
                    } else {
                        "<html><title>real</title><body>real endpoint</body></html>".to_owned()
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes());
                });
            }
        });
        Self {
            port,
            requests,
            stop,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn baseline_request_count(&self) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|path| path.starts_with("/__rxscan_baseline_"))
            .count()
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn baseline_task_for(plan: &ScanPlan, target: &WebTarget, origin_baseline: bool) -> Task {
    let guard = PolicyScopeGuard::new(plan.scope.clone());
    let endpoint = endpoint_asset_id(target);
    Task::new_with_params(
        TaskKind::Baseline,
        None,
        Vec::new(),
        Some(AssetId(endpoint.clone())),
        plan.stable_id(),
        32,
        Duration::from_secs(3),
        RetryPolicy::default(),
        BASELINE_MODULE_NAME,
        Provenance::new("test", "14.0.0", plan.stable_id(), Timestamp(1)).unwrap(),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        baseline_task_params(target, &endpoint, origin_baseline),
        &guard,
    )
    .unwrap()
}

#[test]
fn checkpoint_schema_round_trip_and_deterministic_bytes() {
    let state = state_with_tasks(vec![task(&plan(), TaskState::Pending, "rxscan.test")]);
    let a = serde_json::to_vec_pretty(&state).unwrap();
    let b = serde_json::to_vec_pretty(&state).unwrap();
    assert_eq!(a, b);
    let parsed: PersistedScanState = serde_json::from_slice(&a).unwrap();
    parsed.validate().unwrap();
    assert_eq!(parsed.schema_version, CHECKPOINT_SCHEMA_VERSION);
    assert_eq!(parsed.scan_id, parsed.plan.stable_id());
}

#[test]
fn corrupt_unsupported_truncated_and_oversized_checkpoints_fail_cleanly() {
    let path = temp_path("bad");
    fs::write(&path, b"not json").unwrap();
    assert!(load_checkpoint(&path).is_err());
    fs::write(&path, b"{\"schema_version\":1").unwrap();
    assert!(load_checkpoint(&path).is_err());
    let mut state = state_with_tasks(Vec::new());
    state.schema_version = CHECKPOINT_SCHEMA_VERSION + 1;
    fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(load_checkpoint(&path).is_err());
    fs::write(&path, vec![b'x'; (MAX_CHECKPOINT_BYTES as usize) + 1]).unwrap();
    assert!(load_checkpoint(&path).is_err());
    let _ = fs::remove_file(path);
}

#[test]
fn atomic_save_preserves_old_valid_checkpoint_on_failed_replacement() {
    let path = temp_path("atomic");
    let valid = state_with_tasks(Vec::new());
    save_checkpoint(&path, &valid).unwrap();
    let before = fs::read(&path).unwrap();
    let mut invalid = valid.clone();
    invalid.schema_version += 1;
    assert!(save_checkpoint(&path, &invalid).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    let _ = fs::remove_file(path);
}

#[test]
fn atomic_save_filesystem_failure_preserves_prior_checkpoint() {
    let path = temp_path("atomic_fs");
    let valid = state_with_tasks(Vec::new());
    save_checkpoint(&path, &valid).unwrap();
    let before = fs::read(&path).unwrap();
    let conflict_dir = temp_path("atomic_fs_conflict");
    fs::create_dir_all(&conflict_dir).unwrap();
    let result = save_checkpoint(&conflict_dir, &valid);
    assert!(result.is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    load_checkpoint(&path).unwrap();
    let _ = fs::remove_file(path);
    let _ = fs::remove_dir_all(conflict_dir);
}

#[test]
fn scope_widening_and_dangling_graph_are_rejected_before_resume() {
    let mut state = state_with_tasks(vec![task(&plan(), TaskState::Pending, "rxscan.test")]);
    state.plan.scope.allowed.clear();
    assert!(state.validate().is_err());

    let mut state = state_with_tasks(vec![task(&plan(), TaskState::Succeeded, "rxscan.test")]);
    let provenance =
        Provenance::new("test", "14.0.0", state.scan_id.clone(), Timestamp(1)).unwrap();
    let asset = Asset::scoped(
        AssetKind::Ip,
        "127.0.0.1",
        &state.plan.scope,
        provenance.clone(),
    )
    .unwrap();
    let missing = rxscan::model::AssetId("asset_missing".to_owned());
    let mut event = Event::new(
        EventKind::DnsRecordObserved,
        Some(asset.id.clone()),
        BoundedDetails::from_value(serde_json::json!({"x": 1}), 1024).unwrap(),
        provenance.clone(),
    )
    .unwrap();
    event.relationships.push(
        Relationship::new(
            RelationshipKind::HostnameResolvesToIp,
            RelationshipSubject::Asset(asset.id.clone()),
            RelationshipSubject::Asset(missing),
            provenance,
        )
        .unwrap(),
    );
    state.outputs.push(PersistedModuleOutput {
        task_id: state.tasks[0].task.id.clone(),
        output: ModuleOutput {
            events: vec![event],
            assets: vec![asset],
            ..Default::default()
        },
    });
    assert!(state.validate().is_err());
}

#[test]
fn invalid_checkpoint_matrix_has_zero_network_contacts() {
    let cases = {
        let base = state_with_tasks(vec![task(&plan(), TaskState::Pending, "rxscan.test")]);
        let mut unsupported = base.clone();
        unsupported.schema_version = CHECKPOINT_SCHEMA_VERSION + 1;

        let mut tampered = base.clone();
        tampered.tasks[0]
            .task
            .params
            .insert("target".to_owned(), "127.0.0.2".to_owned());

        let mut widened = base.clone();
        widened.plan.scope.allowed.clear();

        let malicious = {
            let mut state = state_with_tasks(Vec::new());
            let malicious_plan = ScanPlan::compile(
                Cli::try_parse_from(["rxscan", "127.0.0.2", "--scope", "127.0.0.2"]).unwrap(),
            )
            .unwrap();
            let malicious_guard = PolicyScopeGuard::new(malicious_plan.scope.clone());
            let mut malicious_task = Task::new_with_params(
                TaskKind::HostDiscovery,
                None,
                Vec::new(),
                None,
                malicious_plan.stable_id(),
                30,
                Duration::from_secs(1),
                RetryPolicy::default(),
                "rxscan.test",
                Provenance::new("test", "14.0.0", malicious_plan.stable_id(), Timestamp(1))
                    .unwrap(),
                TaskScopeTarget::Ip("127.0.0.2".parse().unwrap()),
                BTreeMap::from([("target".to_owned(), "127.0.0.2".to_owned())]),
                &malicious_guard,
            )
            .unwrap();
            malicious_task.scan_plan_id = state.scan_id.clone();
            malicious_task.id = malicious_task.canonical_identity();
            state.tasks.push(PersistedTask {
                task: malicious_task,
            });
            state
        };

        let dangling = {
            let mut state =
                state_with_tasks(vec![task(&plan(), TaskState::Succeeded, "rxscan.test")]);
            let provenance =
                Provenance::new("test", "14.0.0", state.scan_id.clone(), Timestamp(1)).unwrap();
            let asset = Asset::scoped(
                AssetKind::Ip,
                "127.0.0.1",
                &state.plan.scope,
                provenance.clone(),
            )
            .unwrap();
            let mut event = Event::new(
                EventKind::DnsRecordObserved,
                Some(asset.id.clone()),
                BoundedDetails::from_value(serde_json::json!({"x": 1}), 1024).unwrap(),
                provenance.clone(),
            )
            .unwrap();
            event.relationships.push(
                Relationship::new(
                    RelationshipKind::HostnameResolvesToIp,
                    RelationshipSubject::Asset(asset.id.clone()),
                    RelationshipSubject::Asset(AssetId("asset_missing".to_owned())),
                    provenance,
                )
                .unwrap(),
            );
            state.outputs.push(PersistedModuleOutput {
                task_id: state.tasks[0].task.id.clone(),
                output: ModuleOutput {
                    assets: vec![asset],
                    events: vec![event],
                    ..Default::default()
                },
            });
            state
        };

        let invalid_asset_ref = {
            let mut state =
                state_with_tasks(vec![task(&plan(), TaskState::Succeeded, "rxscan.test")]);
            let provenance =
                Provenance::new("test", "14.0.0", state.scan_id.clone(), Timestamp(1)).unwrap();
            let event = Event::new(
                EventKind::EvidenceCollected,
                Some(AssetId("asset_missing".to_owned())),
                BoundedDetails::from_value(serde_json::json!({"x": 1}), 1024).unwrap(),
                provenance,
            )
            .unwrap();
            state.outputs.push(PersistedModuleOutput {
                task_id: state.tasks[0].task.id.clone(),
                output: ModuleOutput {
                    events: vec![event],
                    ..Default::default()
                },
            });
            state
        };

        let over_limit_registry = {
            let mut state = base.clone();
            state.registries.contacts = (0..=rxscan::contact::MAX_CONTACT_REGISTRY_ENTRIES)
                .map(|index| rxscan::contact::ContactRegistryEntry {
                    method: "GET".to_owned(),
                    url: format!("http://127.0.0.1/{index}"),
                    purpose: RequestPurpose::CrawlPage,
                })
                .collect();
            state
        };

        vec![
            (
                "unsupported_schema",
                serde_json::to_vec(&unsupported).unwrap(),
            ),
            ("task_tampering", serde_json::to_vec(&tampered).unwrap()),
            ("widened_scope", serde_json::to_vec(&widened).unwrap()),
            (
                "malicious_out_of_scope_task",
                serde_json::to_vec(&malicious).unwrap(),
            ),
            (
                "dangling_relationship",
                serde_json::to_vec(&dangling).unwrap(),
            ),
            (
                "invalid_asset_reference",
                serde_json::to_vec(&invalid_asset_ref).unwrap(),
            ),
            (
                "over_limit_registry",
                serde_json::to_vec(&over_limit_registry).unwrap(),
            ),
        ]
    };
    let mut bytes_cases = vec![
        ("malformed_json", b"not json".to_vec()),
        ("oversized", vec![b'x'; (MAX_CHECKPOINT_BYTES as usize) + 1]),
    ];
    bytes_cases.extend(cases);

    for (name, bytes) in bytes_cases {
        let path = temp_path(name);
        fs::write(&path, bytes).unwrap();
        let contacts = Arc::new(AtomicUsize::new(0));
        if let Ok(loaded) = load_checkpoint(&path) {
            let guard = Arc::new(PolicyScopeGuard::new(loaded.state.plan.scope.clone()));
            let mut scheduler = Scheduler::new(
                16,
                BudgetLimits {
                    max_tasks: 16,
                    max_concurrency: 1,
                    ..BudgetLimits::default()
                },
                SpeedGovernor::new(SpeedSetting::Numeric(100), 1).unwrap(),
                guard,
                Arc::new(VecEventSink::default()),
            )
            .unwrap();
            scheduler.register_module(Arc::new(CountModule(contacts.clone())));
            if restore_scheduler_state(&mut scheduler, &loaded.state).is_ok() {
                let _ = scheduler.run();
            }
        }
        assert_eq!(contacts.load(Ordering::SeqCst), 0, "{name}");
        let _ = fs::remove_file(path);
    }
}

#[test]
fn registries_round_trip_preserve_contact_dns_fuzz_and_origin_budget_state() {
    let contacts = ContactRegistry::new();
    let target = WebTarget::parse("http://127.0.0.1/login#frag").unwrap();
    assert!(contacts.claim(&target, RequestPurpose::CrawlPage));
    let baselines = rxscan::baseline::OriginBaselineRegistry::new();
    baselines.remember("http://127.0.0.1/".to_owned(), "abc".to_owned());
    let fuzz = FuzzOriginBudget::new();
    assert!(fuzz.claim("http://127.0.0.1/", "plan-a", 8));
    let dns = DnsRegistry::new();
    let resolver = "127.0.0.1:53".parse().unwrap();
    assert!(dns.claim_query("www.example.test", DnsRecordType::A, resolver));
    assert!(dns.claim_domain_task("example.test", "www.example.test", 32));

    let snapshot = PersistedRegistries::from_runtime(&contacts, &baselines, &fuzz, &dns);
    let restored_contacts = snapshot.restore_contact_registry().unwrap();
    assert!(!restored_contacts.claim(&target, RequestPurpose::CrawlPage));
    assert_eq!(
        snapshot
            .restore_origin_baselines()
            .unwrap()
            .get_hashes("http://127.0.0.1/")
            .as_deref(),
        Some("abc")
    );
    assert_eq!(
        snapshot
            .restore_fuzz_budget()
            .unwrap()
            .count_for_origin("http://127.0.0.1/"),
        1
    );
    let restored_dns = snapshot.restore_dns_registry().unwrap();
    assert!(!restored_dns.claim_query("www.example.test", DnsRecordType::A, resolver));
    assert_eq!(restored_dns.tracked_names_for_domain("example.test"), 1);
}

fn endpoint_observed_output(plan: &ScanPlan, target: &WebTarget) -> ModuleOutput {
    let provenance = Provenance::new("test", "14.0.0", plan.stable_id(), Timestamp(1)).unwrap();
    ModuleOutput {
        events: vec![Event::new(
            EventKind::EndpointObserved,
            Some(AssetId(endpoint_asset_id(target))),
            BoundedDetails::from_value(
                serde_json::json!({"url": target.canonical(), "target": target.host, "status": 200}),
                4096,
            )
            .unwrap(),
            provenance,
        )
        .unwrap()],
        ..Default::default()
    }
}

#[test]
fn origin_baseline_is_reused_after_checkpoint_without_reacquiring_synthetic_samples() {
    let fixture = HttpFixture::spawn();
    let root = WebTarget::parse(&fixture.url("/real")).unwrap();
    let plan = plan();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let baselines = rxscan::baseline::OriginBaselineRegistry::new();
    let engine = Phase7Engine::new_with_state(
        guard.clone(),
        plan.stable_id(),
        5,
        ScanGoal::Recon,
        plan.tcp_ports.clone(),
        SpeedSetting::Numeric(100),
        None,
        baselines.clone(),
        FuzzOriginBudget::new(),
    );

    let baseline_task = baseline_task_for(&plan, &root, true);
    let mut scheduler = Scheduler::new(
        16,
        BudgetLimits {
            max_tasks: 8,
            max_concurrency: 1,
            ..BudgetLimits::default()
        },
        SpeedGovernor::new(SpeedSetting::Numeric(100), 1).unwrap(),
        guard.clone(),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler.register_module(Arc::new(BaselineModule::new(
        BaselinePolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    )));
    scheduler.add_task(baseline_task.clone()).unwrap();
    scheduler.run().unwrap();
    let baseline_output = scheduler
        .module_outputs()
        .into_iter()
        .find(|(id, _)| *id == baseline_task.id)
        .unwrap()
        .1;
    let _ = engine.follow_up_tasks(&baseline_task, &baseline_output);
    let baseline_requests_before_checkpoint = fixture.baseline_request_count();
    assert!(baseline_requests_before_checkpoint > 0);

    let checkpoint = PersistedScanState {
        registries: PersistedRegistries::from_runtime(
            &ContactRegistry::new(),
            &baselines,
            &FuzzOriginBudget::new(),
            &DnsRegistry::new(),
        ),
        ..state_with_tasks(Vec::new())
    };
    let path = temp_path("origin_baseline_reuse");
    save_checkpoint(&path, &checkpoint).unwrap();
    let restored_baselines = load_checkpoint(&path)
        .unwrap()
        .state
        .registries
        .restore_origin_baselines()
        .unwrap();
    let restored_engine = Phase7Engine::new_with_state(
        guard.clone(),
        plan.stable_id(),
        5,
        ScanGoal::Recon,
        plan.tcp_ports.clone(),
        SpeedSetting::Numeric(100),
        None,
        restored_baselines,
        FuzzOriginBudget::new(),
    );
    let after = WebTarget::parse(&fixture.url("/after")).unwrap();
    let seed = task(&plan, TaskState::Succeeded, "phase14.seed");
    let proposals =
        restored_engine.follow_up_tasks(&seed, &endpoint_observed_output(&plan, &after));
    let reuse_tasks = proposals
        .iter()
        .filter(|task| {
            task.kind == TaskKind::Baseline && !task.params.contains_key("origin_baseline")
        })
        .count();
    assert_eq!(reuse_tasks, 1);
    let resumed_baseline = proposals
        .into_iter()
        .find(|task| task.kind == TaskKind::Baseline)
        .unwrap();

    let mut scheduler = Scheduler::new(
        16,
        BudgetLimits {
            max_tasks: 8,
            max_concurrency: 1,
            ..BudgetLimits::default()
        },
        SpeedGovernor::new(SpeedSetting::Numeric(100), 1).unwrap(),
        guard.clone(),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler.register_module(Arc::new(BaselineModule::new(
        BaselinePolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard,
    )));
    scheduler.add_task(resumed_baseline).unwrap();
    scheduler.run().unwrap();
    let baseline_requests_after_resume = fixture.baseline_request_count();
    assert_eq!(
        baseline_requests_after_resume,
        baseline_requests_before_checkpoint
    );
    assert_eq!(
        baseline_requests_after_resume - baseline_requests_before_checkpoint,
        0
    );
    assert_eq!(reuse_tasks, 1);
    let _ = fs::remove_file(path);
}

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

#[test]
fn scheduler_resume_restores_pending_and_skips_completed_work() {
    let plan = plan();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let completed = task(&plan, TaskState::Succeeded, "rxscan.test");
    let mut pending = task(&plan, TaskState::Running, "rxscan.test");
    pending
        .params
        .insert("variant".to_owned(), "pending".to_owned());
    pending.id = Task::new_with_params(
        pending.kind.clone(),
        pending.parent_task_id.clone(),
        pending.dependencies.clone(),
        pending.associated_asset_id.clone(),
        pending.scan_plan_id.clone(),
        pending.priority,
        Duration::from_millis(pending.timeout_ms),
        pending.retry_policy.clone(),
        pending.module_name.clone(),
        pending.provenance.clone(),
        pending.scope_target.clone(),
        pending.params.clone(),
        guard.as_ref(),
    )
    .unwrap()
    .id;
    let state = PersistedScanState {
        outputs: vec![PersistedModuleOutput {
            task_id: completed.id.clone(),
            output: ModuleOutput::default(),
        }],
        ..state_with_tasks(vec![completed, pending])
    };
    state.validate().unwrap();
    let mut scheduler = Scheduler::new(
        16,
        BudgetLimits {
            max_tasks: 4,
            max_concurrency: 1,
            ..BudgetLimits::default()
        },
        SpeedGovernor::new(SpeedSetting::Numeric(100), 1).unwrap(),
        guard,
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    let contacts = Arc::new(AtomicUsize::new(0));
    scheduler.register_module(Arc::new(CountModule(contacts.clone())));
    let (restored, completed_count) = restore_scheduler_state(&mut scheduler, &state).unwrap();
    assert_eq!(restored, 2);
    assert_eq!(completed_count, 1);
    scheduler.run().unwrap();
    assert_eq!(contacts.load(Ordering::SeqCst), 1);
}

#[test]
fn checkpoint_bytes_exclude_sensitive_raw_markers_and_jsonl_round_trips() {
    let path = temp_path("sensitive");
    let state = state_with_tasks(vec![task(&plan(), TaskState::Pending, "rxscan.test")]);
    save_checkpoint(&path, &state).unwrap();
    let bytes = fs::read(&path).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("password=secret"));
    let loaded = load_checkpoint(&path).unwrap();
    assert_eq!(loaded.state.scan_id, state.scan_id);
    let mut out = Vec::new();
    let mut writer = JsonlWriter::new(&mut out, 1024 * 1024);
    for persisted in loaded.state.outputs {
        for event in persisted.output.events {
            writer.write_event(&event).unwrap();
        }
    }
    writer.flush().unwrap();

    let mut rejected = state_with_tasks(vec![task(&plan(), TaskState::Pending, "rxscan.test")]);
    rejected.tasks[0].task.params.insert(
        "header".to_owned(),
        "Authorization: Bearer phase14_secret".to_owned(),
    );
    rejected.tasks[0].task.id = rejected.tasks[0].task.canonical_identity();
    assert!(save_checkpoint(&path, &rejected).is_err());
    let bytes_after_reject = fs::read(&path).unwrap();
    assert!(!String::from_utf8_lossy(&bytes_after_reject).contains("phase14_secret"));

    let mut rejected_output =
        state_with_tasks(vec![task(&plan(), TaskState::Succeeded, "rxscan.test")]);
    let provenance = Provenance::new(
        "test",
        "14.0.0",
        rejected_output.scan_id.clone(),
        Timestamp(1),
    )
    .unwrap();
    let asset = Asset::scoped(
        AssetKind::Url,
        "http://127.0.0.1/",
        &rejected_output.plan.scope,
        provenance.clone(),
    )
    .unwrap();
    let evidence = rxscan::model::Evidence::new(
        "test",
        asset.id.clone(),
        BoundedDetails::from_value(
            serde_json::json!({"body": "raw_http_body_marker phase14_secret"}),
            1024,
        )
        .unwrap(),
        rxscan::model::Confidence::new(80).unwrap(),
        provenance,
    )
    .unwrap();
    rejected_output.outputs.push(PersistedModuleOutput {
        task_id: rejected_output.tasks[0].task.id.clone(),
        output: ModuleOutput {
            assets: vec![asset],
            evidence: vec![evidence],
            ..Default::default()
        },
    });
    assert!(save_checkpoint(&path, &rejected_output).is_err());
    let _ = fs::remove_file(path);
}

#[test]
fn task_identity_tampering_and_malicious_pending_target_are_rejected() {
    let plan = plan();
    let mut tampered = task(&plan, TaskState::Pending, "rxscan.test");
    tampered
        .params
        .insert("target".to_owned(), "127.0.0.2".to_owned());
    let state = state_with_tasks(vec![tampered]);
    assert!(state.validate().is_err());

    let guard = PolicyScopeGuard::new(plan.scope.clone());
    let malicious = Task::new_with_params(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        30,
        Duration::from_secs(1),
        RetryPolicy::default(),
        "rxscan.test",
        Provenance::new("test", "14.0.0", plan.stable_id(), Timestamp(1)).unwrap(),
        TaskScopeTarget::Ip("127.0.0.2".parse().unwrap()),
        BTreeMap::from([("target".to_owned(), "127.0.0.2".to_owned())]),
        &PolicyScopeGuard::new(
            ScanPlan::compile(
                Cli::try_parse_from(["rxscan", "127.0.0.2", "--scope", "127.0.0.2"]).unwrap(),
            )
            .unwrap()
            .scope,
        ),
    )
    .unwrap();
    assert!(!guard.permits(&malicious.scope_target));
    let state = state_with_tasks(vec![malicious]);
    assert!(state.validate().is_err());
}

#[test]
fn resume_cli_rejects_semantic_overrides_and_allows_speed_only() {
    let path = temp_path("cli");
    save_checkpoint(&path, &state_with_tasks(Vec::new())).unwrap();
    assert!(
        run::execute(
            Cli::try_parse_from([
                "rxscan",
                "--resume",
                path.to_str().unwrap(),
                "--speed",
                "100"
            ])
            .unwrap()
        )
        .is_ok()
    );
    for args in [
        vec!["rxscan", "--resume", path.to_str().unwrap(), "127.0.0.1"],
        vec!["rxscan", "--resume", path.to_str().unwrap(), "--level", "4"],
        vec![
            "rxscan",
            "--resume",
            path.to_str().unwrap(),
            "--goal",
            "web",
        ],
        vec![
            "rxscan",
            "--resume",
            path.to_str().unwrap(),
            "--scope",
            "127.0.0.2",
        ],
        vec![
            "rxscan",
            "--resume",
            path.to_str().unwrap(),
            "--max-tasks",
            "128",
        ],
    ] {
        assert!(matches!(
            run::execute(Cli::try_parse_from(args).unwrap()),
            Err(run::RunError::InvalidResume(_))
        ));
    }
    let _ = fs::remove_file(path);
}

#[test]
fn fuzz_and_dns_budget_continuity_survives_repeated_restore() {
    let contacts = ContactRegistry::new();
    let baselines = rxscan::baseline::OriginBaselineRegistry::new();
    let fuzz = FuzzOriginBudget::new();
    for index in 0..5 {
        assert!(fuzz.claim("http://127.0.0.1/", &format!("plan-{index}"), 8));
    }
    let dns = DnsRegistry::new();
    for index in 0..5 {
        assert!(dns.claim_domain_task("example.test", &format!("h{index}.example.test"), 8));
    }
    let snapshot = PersistedRegistries::from_runtime(&contacts, &baselines, &fuzz, &dns);
    let restored = snapshot.restore_fuzz_budget().unwrap();
    assert!(restored.claim("http://127.0.0.1/", "plan-5", 8));
    assert!(restored.claim("http://127.0.0.1/", "plan-6", 8));
    assert!(restored.claim("http://127.0.0.1/", "plan-7", 8));
    assert!(!restored.claim("http://127.0.0.1/", "plan-8", 8));
    assert!(restored.claim("http://127.0.0.2/", "plan-a", 8));

    let snapshot = PersistedRegistries {
        fuzz_origin_budgets: restored.snapshot(),
        ..PersistedRegistries::default()
    };
    assert!(
        !snapshot
            .restore_fuzz_budget()
            .unwrap()
            .claim("http://127.0.0.1/", "plan-8", 8)
    );

    let restored_dns = PersistedRegistries::from_runtime(&contacts, &baselines, &fuzz, &dns)
        .restore_dns_registry()
        .unwrap();
    assert!(restored_dns.claim_domain_task("example.test", "h5.example.test", 8));
    assert!(restored_dns.claim_domain_task("example.test", "h6.example.test", 8));
    assert!(restored_dns.claim_domain_task("example.test", "h7.example.test", 8));
    assert!(!restored_dns.claim_domain_task("example.test", "h8.example.test", 8));
    assert!(restored_dns.claim_domain_task("other.test", "h.other.test", 8));
}

fn signature(raw: &str, normalized: &str) -> ResponseSignature {
    ResponseSignature {
        status: 200,
        content_type: "text/html".to_owned(),
        content_length: None,
        observed_body_len: 32,
        body_len_bucket: "small".to_owned(),
        raw_sha256: raw.to_owned(),
        normalized_sha256: normalized.to_owned(),
        title_hash: Some("title".to_owned()),
        header_hash: "headers".to_owned(),
        html_structure_hash: Some("html".to_owned()),
        truncated: false,
    }
}

#[test]
fn baseline_similarity_reconstructs_from_persisted_signature_events() {
    let plan = plan();
    let provenance = Provenance::new("test", "14.0.0", plan.stable_id(), Timestamp(1)).unwrap();
    let asset = Asset::scoped(
        AssetKind::Url,
        "http://127.0.0.1/a",
        &plan.scope,
        provenance.clone(),
    )
    .unwrap();
    let event = Event::new(
        EventKind::ResponseSignatureObserved,
        Some(asset.id.clone()),
        BoundedDetails::from_value(
            serde_json::json!({"url": "http://127.0.0.1/a", "signature": signature("raw-a", "norm-a")}),
            4096,
        )
        .unwrap(),
        provenance.clone(),
    )
    .unwrap();
    let output = ModuleOutput {
        events: vec![event],
        assets: vec![asset.clone()],
        ..Default::default()
    };
    let registry = BaselineSimilarityRegistry::new();
    registry.reconstruct_from_outputs(&[output]);
    let asset_b = Asset::scoped(
        AssetKind::Url,
        "http://127.0.0.1/b",
        &plan.scope,
        provenance.clone(),
    )
    .unwrap();
    let events = registry.observe(
        "http://127.0.0.1/b",
        &asset_b.id,
        &signature("raw-b", "norm-a"),
        &provenance,
    );
    assert!(events.iter().any(|event| {
        event
            .relationships
            .iter()
            .any(|rel| rel.kind == RelationshipKind::DuplicateOf)
    }));
}

#[test]
fn fresh_vs_resumed_scheduler_semantics_match_without_repeating_completed_work() {
    let plan = plan();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let first = task(&plan, TaskState::Pending, "rxscan.test");
    let mut second = task(&plan, TaskState::Pending, "rxscan.test");
    second
        .params
        .insert("variant".to_owned(), "second".to_owned());
    second.id = second.canonical_identity();

    let run_pair = |tasks: Vec<Task>| {
        let mut scheduler = Scheduler::new(
            16,
            BudgetLimits {
                max_tasks: 8,
                max_concurrency: 1,
                ..BudgetLimits::default()
            },
            SpeedGovernor::new(SpeedSetting::Numeric(100), 1).unwrap(),
            guard.clone(),
            Arc::new(VecEventSink::default()),
        )
        .unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        scheduler.register_module(Arc::new(CountModule(counter.clone())));
        for task in tasks {
            scheduler.add_task(task).unwrap();
        }
        scheduler.run().unwrap();
        (
            scheduler
                .tasks()
                .map(|task| task.id.clone())
                .collect::<Vec<_>>(),
            counter.load(Ordering::SeqCst),
        )
    };
    let (fresh_ids, fresh_count) = run_pair(vec![first.clone(), second.clone()]);

    let mut completed = first;
    completed.state = TaskState::Succeeded;
    let resumed_state = state_with_tasks(vec![completed, second]);
    let mut scheduler = Scheduler::new(
        16,
        BudgetLimits {
            max_tasks: 8,
            max_concurrency: 1,
            ..BudgetLimits::default()
        },
        SpeedGovernor::new(SpeedSetting::Numeric(100), 1).unwrap(),
        guard,
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    let counter = Arc::new(AtomicUsize::new(0));
    scheduler.register_module(Arc::new(CountModule(counter.clone())));
    restore_scheduler_state(&mut scheduler, &resumed_state).unwrap();
    scheduler.run().unwrap();
    let resumed_ids = scheduler
        .tasks()
        .map(|task| task.id.clone())
        .collect::<Vec<_>>();
    assert_eq!(fresh_ids, resumed_ids);
    assert_eq!(fresh_count, 2);
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[test]
fn duplicate_task_proposal_after_resume_is_rejected_by_scheduler_dedup() {
    let plan = plan();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let pending = task(&plan, TaskState::Pending, "rxscan.test");
    let state = state_with_tasks(vec![pending.clone()]);
    let mut scheduler = Scheduler::new(
        16,
        BudgetLimits {
            max_tasks: 8,
            max_concurrency: 1,
            ..BudgetLimits::default()
        },
        SpeedGovernor::new(SpeedSetting::Numeric(100), 1).unwrap(),
        guard,
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    let counter = Arc::new(AtomicUsize::new(0));
    scheduler.register_module(Arc::new(CountModule(counter.clone())));
    restore_scheduler_state(&mut scheduler, &state).unwrap();
    assert!(matches!(
        scheduler.add_task(pending),
        Err(rxscan::execution::SchedulerError::DuplicateTask)
    ));
    scheduler.run().unwrap();
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[test]
fn task_state_resume_mapping_is_explicit() {
    let plan = plan();
    for state in [
        TaskState::Pending,
        TaskState::Ready,
        TaskState::Running,
        TaskState::Succeeded,
        TaskState::Failed,
        TaskState::Cancelled,
        TaskState::TimedOut,
        TaskState::Skipped,
    ] {
        let checkpoint = PersistedScanState::from_scheduler(
            plan.clone(),
            &{
                let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
                let mut scheduler = Scheduler::new(
                    4,
                    BudgetLimits {
                        max_tasks: 4,
                        max_concurrency: 1,
                        ..BudgetLimits::default()
                    },
                    SpeedGovernor::new(SpeedSetting::Numeric(100), 1).unwrap(),
                    guard,
                    Arc::new(VecEventSink::default()),
                )
                .unwrap();
                scheduler
                    .restore_task(task(&plan, state, &format!("rxscan.test.{state:?}")), None)
                    .unwrap();
                scheduler
            },
            PersistedRegistries::default(),
        );
        let restored = &checkpoint.tasks[0].task;
        if matches!(state, TaskState::Ready | TaskState::Running) {
            assert_eq!(restored.state, TaskState::Pending);
        }
    }
}

#[test]
fn repeated_resume_keeps_identity_and_checkpoint_size_bounded() {
    let path = temp_path("repeat");
    let mut state = state_with_tasks(vec![task(&plan(), TaskState::Pending, "rxscan.test")]);
    let mut sizes = Vec::new();
    for _ in 0..3 {
        save_checkpoint(&path, &state).unwrap();
        let loaded = load_checkpoint(&path).unwrap();
        sizes.push(loaded.checkpoint_bytes);
        assert_eq!(loaded.state.scan_id, state.scan_id);
        assert_eq!(loaded.state.tasks[0].task.id, state.tasks[0].task.id);
        state = loaded.state;
    }
    assert!(sizes.windows(2).all(|pair| pair[0] == pair[1]));
    let _ = fs::remove_file(path);
}

#[test]
fn checkpoint_relocation_does_not_change_scan_or_task_identity() {
    let state = state_with_tasks(vec![task(&plan(), TaskState::Pending, "rxscan.test")]);
    let a = temp_path("relocate_a");
    let b = temp_path("relocate_b");
    save_checkpoint(&a, &state).unwrap();
    save_checkpoint(&b, &state).unwrap();
    let loaded_a = load_checkpoint(&a).unwrap();
    let loaded_b = load_checkpoint(&b).unwrap();
    assert_eq!(loaded_a.state.scan_id, loaded_b.state.scan_id);
    assert_eq!(
        loaded_a.state.tasks[0].task.id,
        loaded_b.state.tasks[0].task.id
    );
    assert_eq!(
        loaded_a.state.plan.stable_id(),
        loaded_b.state.plan.stable_id()
    );
    assert_eq!(loaded_a.state.registries, loaded_b.state.registries);
    let _ = fs::remove_file(a);
    let _ = fs::remove_file(b);
}

#[test]
fn ipv6_persistence_round_trip_preserves_identity_and_scope() {
    let plan = ScanPlan::compile(
        Cli::try_parse_from(["rxscan", "::1", "--scope", "::1", "--level", "5"]).unwrap(),
    )
    .unwrap();
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
        "rxscan.test",
        Provenance::new("test", "14.0.0", plan.stable_id(), Timestamp(1)).unwrap(),
        TaskScopeTarget::Ip("::1".parse().unwrap()),
        BTreeMap::from([("target".to_owned(), "::1".to_owned())]),
        &guard,
    )
    .unwrap();
    task.state = TaskState::Pending;
    let provenance = Provenance::new("test", "14.0.0", plan.stable_id(), Timestamp(1)).unwrap();
    let asset = Asset::scoped(AssetKind::Ip, "::1", &plan.scope, provenance).unwrap();
    let state = PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: plan.stable_id(),
        saved_at: Timestamp(2),
        plan: plan.clone(),
        tasks: vec![PersistedTask { task: task.clone() }],
        outputs: vec![PersistedModuleOutput {
            task_id: task.id.clone(),
            output: ModuleOutput {
                assets: vec![asset.clone()],
                ..Default::default()
            },
        }],
        registries: PersistedRegistries::default(),
    };
    let path = temp_path("ipv6");
    save_checkpoint(&path, &state).unwrap();
    let loaded = load_checkpoint(&path).unwrap();
    assert_eq!(loaded.state.scan_id, state.scan_id);
    assert_eq!(loaded.state.tasks[0].task.id, task.id);
    assert_eq!(loaded.state.outputs[0].output.assets[0].id, asset.id);
    assert!(
        PolicyScopeGuard::new(loaded.state.plan.scope)
            .permits(&TaskScopeTarget::Ip("::1".parse().unwrap()))
    );
    let _ = fs::remove_file(path);
}

#[test]
fn large_collection_limits_reject_one_over_and_allow_bounded_state() {
    let mut state = state_with_tasks(Vec::new());
    for index in 0..128 {
        let mut item = task(
            &state.plan,
            TaskState::Pending,
            &format!("rxscan.test.{index}"),
        );
        item.params.insert("i".to_owned(), index.to_string());
        item.id = item.canonical_identity();
        state.tasks.push(PersistedTask { task: item });
    }
    state.validate().unwrap();
    let bytes = serde_json::to_vec(&state).unwrap();
    assert!((bytes.len() as u64) < MAX_CHECKPOINT_BYTES);

    let mut too_many_contacts = state.clone();
    too_many_contacts.registries.contacts = (0..=rxscan::contact::MAX_CONTACT_REGISTRY_ENTRIES)
        .map(|index| rxscan::contact::ContactRegistryEntry {
            method: "GET".to_owned(),
            url: format!("http://127.0.0.1/{index}"),
            purpose: RequestPurpose::CrawlPage,
        })
        .collect();
    assert!(too_many_contacts.validate().is_err());
}

#[test]
fn advertised_collection_limits_accept_exact_limit_and_reject_one_over() {
    let exact = PersistedCollectionCounts {
        tasks: rxscan::persistence::MAX_PERSISTED_TASKS,
        outputs: rxscan::persistence::MAX_PERSISTED_OUTPUTS,
        assets: rxscan::persistence::MAX_PERSISTED_ASSETS,
        relationships: rxscan::persistence::MAX_PERSISTED_RELATIONSHIPS,
        events: rxscan::persistence::MAX_PERSISTED_EVENTS,
        evidence: rxscan::persistence::MAX_PERSISTED_EVIDENCE,
        findings: rxscan::persistence::MAX_PERSISTED_FINDINGS,
    };
    validate_persisted_collection_counts(exact).unwrap();
    for (label, counts) in [
        (
            "tasks",
            PersistedCollectionCounts {
                tasks: rxscan::persistence::MAX_PERSISTED_TASKS + 1,
                ..PersistedCollectionCounts::default()
            },
        ),
        (
            "outputs",
            PersistedCollectionCounts {
                outputs: rxscan::persistence::MAX_PERSISTED_OUTPUTS + 1,
                ..PersistedCollectionCounts::default()
            },
        ),
        (
            "assets",
            PersistedCollectionCounts {
                assets: rxscan::persistence::MAX_PERSISTED_ASSETS + 1,
                ..PersistedCollectionCounts::default()
            },
        ),
        (
            "relationships",
            PersistedCollectionCounts {
                relationships: rxscan::persistence::MAX_PERSISTED_RELATIONSHIPS + 1,
                ..PersistedCollectionCounts::default()
            },
        ),
        (
            "events",
            PersistedCollectionCounts {
                events: rxscan::persistence::MAX_PERSISTED_EVENTS + 1,
                ..PersistedCollectionCounts::default()
            },
        ),
        (
            "evidence",
            PersistedCollectionCounts {
                evidence: rxscan::persistence::MAX_PERSISTED_EVIDENCE + 1,
                ..PersistedCollectionCounts::default()
            },
        ),
        (
            "findings",
            PersistedCollectionCounts {
                findings: rxscan::persistence::MAX_PERSISTED_FINDINGS + 1,
                ..PersistedCollectionCounts::default()
            },
        ),
    ] {
        assert!(
            validate_persisted_collection_counts(counts).is_err(),
            "{label}"
        );
    }
}
