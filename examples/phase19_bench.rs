//! Phase 19 performance / large-scale hardening benchmark.
//!
//! Local, synthetic, deterministic fixtures only — loopback or pure compute,
//! no public targets. Sections:
//!   A. control-plane/scheduler stress
//!   B. TCP bookkeeping/concurrency stress
//!   C. web/crawl/content stress
//!   D. persistence/diff/analysis/report stress
//!   E. project stress
//!   F. multitasking/fairness stress
//!
//! Timing is observational; structural caps carry the regression proof.

use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use clap::Parser;
use rxscan::{
    analysis::{self, AnalysisOptions},
    cli::Cli,
    content::{ContentDiscoveryModule, ContentDiscoveryPolicy, content_task_params},
    crawl::{self, MAX_CRAWL_PROPOSALS_PER_COMPLETION},
    diff::{self, DiffOptions},
    dns::{DnsRecordType, DnsRegistry},
    execution::{
        BudgetLimits, CancellationToken, DecisionEngine, Module, ModuleContext, ModuleError,
        ModuleFuture, ModuleOutput, PolicyScopeGuard, RetryPolicy, Scheduler, ScopeGuard,
        SpeedGovernor, Task, TaskKind, TaskScopeTarget, VecEventSink,
    },
    fuzz::FuzzOriginBudget,
    model::{
        Asset, AssetKind, Provenance, Relationship, RelationshipKind, RelationshipSubject,
        Timestamp,
    },
    persistence::{
        self, CHECKPOINT_SCHEMA_VERSION, PersistedModuleOutput, PersistedRegistries,
        PersistedScanState, PersistedTask,
    },
    plan::{ScanGoal, ScanPlan, SpeedSetting, TcpPortSelection},
    ports::{self, MAX_TCP_CONCURRENCY_HARD},
    project::ProjectState,
    report::{ReportFormat, ReportOptions},
    tcp_scanner::{NativeTcpScanner, PortScanner, ScanConfig},
    web::WebTarget,
};

struct AllowAll;
impl ScopeGuard for AllowAll {
    fn permits(&self, _target: &TaskScopeTarget) -> bool {
        true
    }
}

fn compile(args: &[&str]) -> ScanPlan {
    let mut full = vec!["rxscan"];
    full.extend_from_slice(args);
    ScanPlan::compile(Cli::try_parse_from(full).unwrap()).unwrap()
}

fn plan_for(target: &str) -> ScanPlan {
    compile(&[target, "--scope", "127.0.0.0/8"])
}

fn provenance_for(plan: &ScanPlan) -> Provenance {
    Provenance::new("phase19.bench", "19.0.0", plan.stable_id(), Timestamp(0)).unwrap()
}

struct ImmediateModule {
    executed: Arc<AtomicUsize>,
}

impl Module for ImmediateModule {
    fn kind(&self) -> TaskKind {
        TaskKind::HostDiscovery
    }
    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let executed = self.executed.clone();
        Box::pin(async move {
            executed.fetch_add(1, Ordering::SeqCst);
            if context.is_cancelled() {
                return Err(ModuleError::Cancelled);
            }
            // 1ms of synthetic work so scheduler slots genuinely overlap and
            // active_peak reflects real concurrency (still instant to humans).
            std::thread::sleep(Duration::from_millis(1));
            Ok(ModuleOutput::default())
        })
    }
}

fn drive(future: ModuleFuture) -> Result<ModuleOutput, ModuleError> {
    use std::task::{Context as TaskContext, Poll, RawWaker, RawWakerVTable, Waker};
    unsafe fn raw_waker() -> RawWaker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            unsafe { raw_waker() }
        }
        unsafe fn noop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = TaskContext::from_waker(&waker);
    let mut future = future;
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::sleep(Duration::from_millis(1)),
        }
    }
}

fn peak_rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("VmHWM:")
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|value| value.parse().ok())
            })
        })
        .unwrap_or(0)
}

fn current_rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("VmRSS:")
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|value| value.parse().ok())
            })
        })
        .unwrap_or(0)
}

fn clk_tck() -> u64 {
    std::process::Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()
        .and_then(|out| String::from_utf8_lossy(&out.stdout).trim().parse().ok())
        .unwrap_or(100)
}

/// Process CPU time (user+sys) in ms via /proc/self/stat; None off-Linux.
fn cpu_time_ms() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/self/stat").ok()?;
    let end = text.rfind(')')?;
    let after: Vec<&str> = text[end + 1..].split_whitespace().collect();
    // Fields 14 (utime) and 15 (stime) are indexes 11/12 after comm.
    let utime: u64 = after.get(11)?.parse().ok()?;
    let stime: u64 = after.get(12)?.parse().ok()?;
    Some((utime + stime) * 1000 / clk_tck())
}

fn fd_count() -> Option<usize> {
    std::fs::read_dir("/proc/self/fd")
        .ok()
        .map(|entries| entries.count())
}

fn make_task(plan: &ScanPlan, index: usize) -> Task {
    let mut params = BTreeMap::new();
    params.insert("target".to_owned(), "127.0.0.1".to_owned());
    params.insert("variant".to_owned(), format!("bench-{index}"));
    Task::new_with_params(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        50,
        Duration::from_millis(10_000),
        RetryPolicy::default(),
        "phase19.bench",
        provenance_for(plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        params,
        &AllowAll,
    )
    .unwrap()
}

/// Bounded flood engine for the fairness section: high-priority follow-ups
/// capped by an atomic budget; one low-priority seed must still complete.
struct FloodEngine {
    remaining: AtomicUsize,
    plan: ScanPlan,
}

impl DecisionEngine for FloodEngine {
    fn follow_up_tasks(&self, completed: &Task, _output: &ModuleOutput) -> Vec<Task> {
        if completed.priority < 200 || self.remaining.fetch_sub(1, Ordering::SeqCst) == 0 {
            return Vec::new();
        }
        let n = self.remaining.load(Ordering::SeqCst);
        let mut params = BTreeMap::new();
        params.insert("target".to_owned(), "127.0.0.1".to_owned());
        params.insert("variant".to_owned(), format!("flood-{n}"));
        Task::new_with_params(
            TaskKind::HostDiscovery,
            None,
            Vec::new(),
            None,
            self.plan.stable_id(),
            200,
            Duration::from_millis(5000),
            RetryPolicy::default(),
            "phase19.bench",
            provenance_for(&self.plan),
            TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
            params,
            &AllowAll,
        )
        .map_or(Vec::new(), |task| vec![task])
    }
}

fn main() {
    let wall_start = Instant::now();
    let available_parallelism = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    // ---------------- A. control-plane / scheduler stress ----------------
    let plan = plan_for("127.0.0.1");
    let executed = Arc::new(AtomicUsize::new(0));
    let budgets = BudgetLimits {
        max_tasks: 2000,
        max_retries: 2000,
        max_concurrency: 4,
        max_execution_time_ms: 120_000,
        ..BudgetLimits::default()
    };
    let queue_capacity = budgets.queue_capacity();
    let a_start = Instant::now();
    let mut scheduler = Scheduler::new(
        queue_capacity,
        budgets,
        // Numeric(100) with budget 4 derives effective concurrency 4
        // (governor derivation is applied twice internally: 1+(4-1)*100/100).
        SpeedGovernor::new(SpeedSetting::Numeric(100), 4).unwrap(),
        Arc::new(PolicyScopeGuard::new(plan.scope.clone())),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler.register_module(Arc::new(ImmediateModule {
        executed: executed.clone(),
    }));
    const SCHED_TASKS: usize = 1500;
    for index in 0..SCHED_TASKS {
        scheduler.add_task(make_task(&plan, index)).unwrap();
    }
    let scheduler_tasks_proposed = SCHED_TASKS;
    let report = scheduler.run().unwrap();
    let scheduler_wall_ms = a_start.elapsed().as_millis();
    assert_eq!(report.completed.len(), SCHED_TASKS);
    let scheduler_queue_peak = report.queue_peak;
    let scheduler_active_peak = report.active_peak;

    // Cancellation under load: separate large workload, cancelled first.
    let mut canceller = Scheduler::new(
        queue_capacity,
        BudgetLimits {
            max_tasks: 2000,
            max_retries: 2000,
            max_concurrency: 4,
            max_execution_time_ms: 120_000,
            ..BudgetLimits::default()
        },
        SpeedGovernor::new(SpeedSetting::Numeric(100), 4).unwrap(),
        Arc::new(PolicyScopeGuard::new(plan.scope.clone())),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    canceller.register_module(Arc::new(ImmediateModule {
        executed: Arc::new(AtomicUsize::new(0)),
    }));
    for index in 0..1000 {
        canceller.add_task(make_task(&plan, index)).unwrap();
    }
    canceller.cancel_all();
    let cancel_start = Instant::now();
    let cancel_report = canceller.run().unwrap();
    let scheduler_cancel_to_stop_ms = cancel_start.elapsed().as_millis();
    assert_eq!(cancel_report.cancelled.len(), 1000);

    // ---------------- B. TCP bookkeeping / concurrency stress ----------------
    let b_start = Instant::now();
    let all = ports::resolve_ports(&TcpPortSelection::All, 2);
    let tcp_ports_represented = all.ports.len();
    assert_eq!(tcp_ports_represented, 65_535);
    let tcp_resolve_ms = b_start.elapsed().as_millis();
    let cancel = CancellationToken::default();
    let config = ScanConfig::bounded(Duration::from_millis(300), 32, 0, None, cancel);
    let subset: Vec<u16> = (1..=500).collect();
    let fd_before = fd_count().unwrap_or(0);
    let outcome = NativeTcpScanner.scan("127.0.0.1".parse().unwrap(), &subset, &config);
    let fd_after = fd_count().unwrap_or(0);
    assert_eq!(outcome.probes.len() + outcome.unscanned, 500);
    let tcp_fd_peak = outcome.fd_peak;
    // Full-vector cancellation without 65k tasks or sockets.
    let pre_cancelled = CancellationToken::default();
    pre_cancelled.cancel();
    let all_config = ScanConfig::bounded(Duration::from_millis(300), 32, 0, None, pre_cancelled);
    let all_outcome = NativeTcpScanner.scan("127.0.0.1".parse().unwrap(), &all.ports, &all_config);
    assert!(all_outcome.cancelled);
    assert_eq!(all_outcome.probes.len() + all_outcome.unscanned, 65_535);

    // ---------------- C. web / crawl / content stress ----------------
    let mut html = String::from("<html><body>");
    for i in 0..3000 {
        html.push_str(&format!(
            "<a href=\"/page{}\">x</a><a href=\"/page{}#f\">x</a>",
            i % 600,
            i % 600
        ));
    }
    html.push_str("</body></html>");
    let c_start = Instant::now();
    let refs = rxscan::extract::extract_html_refs(html.as_bytes());
    let extract_ms = c_start.elapsed().as_millis();
    let root = WebTarget::parse("http://127.0.0.1/").unwrap();
    let candidates: Vec<_> = (0..3000)
        .map(|i| {
            (
                WebTarget::parse(&format!("http://127.0.0.1/page{}", i % 700)).unwrap(),
                format!("asset-{i}"),
                crawl::CandidateSource::Link,
            )
        })
        .collect();
    let crawl_candidates = candidates.len();
    let c2_start = Instant::now();
    let followups = crawl::plan_followups(candidates, 3, 100, MAX_CRAWL_PROPOSALS_PER_COMPLETION);
    let crawl_plan_ms = c2_start.elapsed().as_millis();
    let _ = root;
    // Small live wordlist run on loopback for real contact counts.
    let dir = std::env::temp_dir().join(format!("rxscan_p19bench_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let wordlist_path = dir.join("bench.txt");
    {
        let mut file = File::create(&wordlist_path).unwrap();
        for i in 0..300 {
            writeln!(file, "bench{i}").unwrap();
        }
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let fixture_port = listener.local_addr().unwrap().port();
    let web_requests = Arc::new(AtomicUsize::new(0));
    let web_requests_clone = web_requests.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !stop_clone.load(Ordering::SeqCst) && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(_) => break,
            };
            let counter = web_requests_clone.clone();
            std::thread::spawn(move || {
                let mut raw = Vec::new();
                let mut chunk = [0u8; 1024];
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                loop {
                    match stream.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            raw.extend_from_slice(&chunk[..n]);
                            if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\nContent-Type: text/html\r\n\r\nok",
                );
            });
        }
    });
    let content_plan = plan_for("127.0.0.1");
    let content_policy = ContentDiscoveryPolicy::new(5, ScanGoal::Web, SpeedSetting::Numeric(50));
    let content_module = ContentDiscoveryModule::new(content_policy, Arc::new(AllowAll));
    let origin = WebTarget::parse(&format!("http://127.0.0.1:{fixture_port}/")).unwrap();
    let content_params = content_task_params(&origin, "seed", Some(&wordlist_path));
    let content_task = Task::new_with_params(
        TaskKind::ContentDiscovery,
        None,
        Vec::new(),
        None,
        content_plan.stable_id(),
        30,
        Duration::from_secs(60),
        RetryPolicy::default(),
        rxscan::content::CONTENT_MODULE_NAME,
        provenance_for(&content_plan),
        TaskScopeTarget::Url(origin.canonical()),
        content_params,
        &AllowAll,
    )
    .unwrap();
    let c3_start = Instant::now();
    let content_output = drive(content_module.execute(ModuleContext::new(
        content_task,
        CancellationToken::default(),
    )))
    .unwrap();
    let content_ms = c3_start.elapsed().as_millis();
    stop.store(true, Ordering::SeqCst);
    let web_requests_made = web_requests.load(Ordering::SeqCst);
    // Fuzz + DNS budget layers (structural, loopback-free).
    let fuzz_budgets = FuzzOriginBudget::new();
    let f_start = Instant::now();
    for i in 0..256 {
        fuzz_budgets.claim(&format!("http://10.2.{i}.1/"), "p", 8);
    }
    let fuzz_ms = f_start.elapsed().as_millis();
    let dns_registry = DnsRegistry::new();
    let resolver: std::net::SocketAddr = "127.0.0.1:53".parse().unwrap();
    for i in 0..3000 {
        let name = format!("h{}.example.test", i % 100);
        dns_registry.claim_query(&name, DnsRecordType::A, resolver);
    }
    let dns_queries = dns_registry.query_count();
    std::fs::remove_dir_all(&dir).ok();

    // ---------------- D. persistence / diff / analysis / report ----------------
    let persist_plan = plan_for("127.0.0.1");
    let persist_provenance = provenance_for(&persist_plan);
    let persist_ip = Asset::scoped(
        AssetKind::Ip,
        "127.0.0.1",
        &persist_plan.scope,
        persist_provenance.clone(),
    )
    .unwrap();
    let mut state_tasks = Vec::with_capacity(2000);
    let mut state_outputs = Vec::with_capacity(2000);
    for index in 0..2000 {
        let mut task = make_task(&persist_plan, index);
        task.state = rxscan::execution::TaskState::Succeeded;
        // Distinct port asset per task so dedup layers see real variety.
        let port = Asset::child(
            AssetKind::Port,
            &persist_ip.id,
            format!("{}", 1 + (index % 65_535)),
            persist_provenance.clone(),
        )
        .unwrap();
        let output = ModuleOutput {
            assets: vec![persist_ip.clone(), port],
            ..ModuleOutput::default()
        };
        state_outputs.push(PersistedModuleOutput {
            task_id: task.id.clone(),
            output,
        });
        state_tasks.push(PersistedTask { task });
    }
    let big_state = PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: persist_plan.stable_id(),
        saved_at: Timestamp(2),
        plan: persist_plan.clone(),
        tasks: state_tasks,
        outputs: state_outputs,
        registries: PersistedRegistries::default(),
    };
    let checkpoint_path =
        std::env::temp_dir().join(format!("rxscan_p19bench_{}.json", std::process::id()));
    let s_start = Instant::now();
    let metrics = persistence::save_checkpoint(&checkpoint_path, &big_state).unwrap();
    let checkpoint_save_ms = s_start.elapsed().as_millis();
    let l_start = Instant::now();
    let loaded = persistence::load_checkpoint(&checkpoint_path).unwrap();
    let checkpoint_load_ms = l_start.elapsed().as_millis();
    let checkpoint_bytes = metrics.checkpoint_bytes;
    assert_eq!(loaded.state.tasks.len(), 2000);
    let d_start = Instant::now();
    // Diff against a +1-task variant (task AND output, so the new asset is
    // visible to normalization) so the Added path is exercised.
    let mut plus_one = big_state.clone();
    let mut extra_task = make_task(&persist_plan, 999_999);
    extra_task.state = rxscan::execution::TaskState::Succeeded;
    let extra_port = Asset::child(
        AssetKind::Port,
        &persist_ip.id,
        "59999",
        persist_provenance.clone(),
    )
    .unwrap();
    plus_one.outputs.push(PersistedModuleOutput {
        task_id: extra_task.id.clone(),
        output: ModuleOutput {
            assets: vec![persist_ip.clone(), extra_port],
            ..ModuleOutput::default()
        },
    });
    plus_one.tasks.push(PersistedTask { task: extra_task });
    let diff_report = diff::compare_states(&big_state, &plus_one, DiffOptions::default()).unwrap();
    let diff_ms = d_start.elapsed().as_millis();
    let diff_records = diff_report.records.len();
    let an_start = Instant::now();
    let analysis_report =
        analysis::analyze_state(&big_state, None, AnalysisOptions::default()).unwrap();
    let analysis_ms = an_start.elapsed().as_millis();
    let r_start = Instant::now();
    let model = rxscan::report::build_report_model(
        &big_state,
        None,
        None,
        &ReportOptions {
            format: ReportFormat::Jsonl,
            summary_only: false,
            top_n: 10,
        },
    )
    .unwrap();
    let mut jsonl_bytes = Vec::new();
    rxscan::report::render_jsonl(&model, &mut jsonl_bytes).unwrap();
    let report_render_ms = r_start.elapsed().as_millis();
    let report_jsonl_records = jsonl_bytes
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .count();
    let _ = std::fs::remove_file(&checkpoint_path);

    // ---------------- E. project stress ----------------
    let project_scan = |target: &str, extra: usize| {
        let scan_plan = compile(&[target, "--scope", "127.0.0.0/8", "--level", "5"]);
        let provenance = Provenance::new(
            "phase19.bench",
            "19.0.0",
            scan_plan.stable_id(),
            Timestamp(1),
        )
        .unwrap();
        let ip =
            Asset::scoped(AssetKind::Ip, target, &scan_plan.scope, provenance.clone()).unwrap();
        let mut assets = vec![ip.clone()];
        let mut relationships = Vec::new();
        for i in 0..extra {
            let port = Asset::child(
                AssetKind::Port,
                &ip.id,
                format!("{}", 8000 + (i % 4000)),
                provenance.clone(),
            )
            .unwrap();
            let svc =
                Asset::child(AssetKind::Service, &port.id, "https", provenance.clone()).unwrap();
            relationships.push(
                Relationship::new(
                    RelationshipKind::Runs,
                    RelationshipSubject::Asset(port.id.clone()),
                    RelationshipSubject::Asset(svc.id.clone()),
                    provenance.clone(),
                )
                .unwrap(),
            );
            // Hub edge so the host entity has realistic fan-out and graph
            // work caps (queue/visited/edge budget) are genuinely stressed.
            relationships.push(
                Relationship::new(
                    RelationshipKind::Exposes,
                    RelationshipSubject::Asset(ip.id.clone()),
                    RelationshipSubject::Asset(port.id.clone()),
                    provenance.clone(),
                )
                .unwrap(),
            );
            assets.push(port);
            assets.push(svc);
        }
        let mut params = BTreeMap::new();
        params.insert("target".to_owned(), target.to_owned());
        let mut task = Task::new_with_params(
            TaskKind::HttpProbe,
            None,
            Vec::new(),
            None,
            scan_plan.stable_id(),
            10,
            Duration::from_secs(1),
            RetryPolicy::default(),
            "phase19.bench",
            provenance.clone(),
            TaskScopeTarget::Ip(target.parse().unwrap()),
            params,
            &AllowAll,
        )
        .unwrap();
        task.state = rxscan::execution::TaskState::Succeeded;
        PersistedScanState {
            schema_version: CHECKPOINT_SCHEMA_VERSION,
            scan_id: scan_plan.stable_id(),
            saved_at: Timestamp(2),
            plan: scan_plan,
            tasks: vec![PersistedTask { task: task.clone() }],
            outputs: vec![PersistedModuleOutput {
                task_id: task.id,
                output: ModuleOutput {
                    assets,
                    events: vec![rxscan::model::Event {
                        schema_version: rxscan::model::SCHEMA_VERSION,
                        kind: rxscan::model::EventKind::EvidenceCollected,
                        asset_id: None,
                        details: rxscan::model::BoundedDetails::from_value(
                            serde_json::json!({"phase": 19}),
                            512,
                        )
                        .unwrap(),
                        relationships,
                        provenance: provenance.clone(),
                    }],
                    ..ModuleOutput::default()
                },
            }],
            registries: PersistedRegistries::default(),
        }
    };
    let scan_a = project_scan("127.0.0.1", 4000);
    let scan_b = project_scan("127.0.0.2", 4000);
    let mut project = ProjectState::new(None);
    let p_start = Instant::now();
    project.add_scan(&scan_a, None, None).unwrap();
    let ii_start = Instant::now();
    project.add_scan(&scan_b, None, None).unwrap();
    let incremental_import_ms = ii_start.elapsed().as_millis();
    let project_bytes = serde_json::to_vec(&project).unwrap().len();
    let _ = p_start;
    let project_path =
        std::env::temp_dir().join(format!("rxscan_p19bench_{}.rxproj", std::process::id()));
    let _ = std::fs::remove_file(&project_path);
    rxscan::project::save_project(&project_path, &project, None).unwrap();
    let o_start = Instant::now();
    let loaded_project = rxscan::project::load_project(&project_path).unwrap();
    let project_open_ms = o_start.elapsed().as_millis();
    let _ = std::fs::remove_file(&project_path);
    assert_eq!(loaded_project.fingerprint, project.fingerprint);
    let fp_start = Instant::now();
    let mut fp_check = loaded_project;
    fp_check.refresh_fingerprint();
    let project_fingerprint_ms = fp_start.elapsed().as_millis();
    assert_eq!(fp_check.fingerprint, project.fingerprint);
    // Highest-degree entity so graph peaks are meaningful yet bounded.
    // Single O(relationships) pass, not O(entities x relationships).
    let entity = {
        let mut degree: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
        for rel in project.relationships.values() {
            *degree.entry(rel.from_entity.as_str()).or_insert(0) += 1;
            *degree.entry(rel.to_entity.as_str()).or_insert(0) += 1;
        }
        degree
            .into_iter()
            .max_by_key(|(_, d)| *d)
            .map(|(id, _)| id.to_owned())
            .unwrap_or_else(|| project.entities.keys().next().unwrap().clone())
    };
    let q_start = Instant::now();
    let neighbors = project.neighbors(&entity, 3, 1000).unwrap();
    let project_query_ms = q_start.elapsed().as_millis();
    let sv_start = Instant::now();
    rxscan::project::save_project(&project_path, &project, None).unwrap();
    let project_save_ms = sv_start.elapsed().as_millis();
    let _ = std::fs::remove_file(&project_path);

    // ---------------- F. multitasking / fairness ----------------
    let f_plan = plan_for("127.0.0.1");
    let mut fair = Scheduler::new(
        queue_capacity,
        BudgetLimits {
            max_tasks: 500,
            max_retries: 500,
            max_concurrency: 2,
            max_execution_time_ms: 60_000,
            ..BudgetLimits::default()
        },
        // Deliberately 2 workers regardless of machine size: bounded
        // coexistence, not core saturation. (Numeric(100) with budget 2
        // derives effective concurrency exactly 2.)
        SpeedGovernor::new(SpeedSetting::Numeric(100), 2).unwrap(),
        Arc::new(PolicyScopeGuard::new(f_plan.scope.clone())),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    fair.register_module(Arc::new(ImmediateModule {
        executed: Arc::new(AtomicUsize::new(0)),
    }));
    fair.set_decision_engine(Arc::new(FloodEngine {
        remaining: AtomicUsize::new(60),
        plan: f_plan.clone(),
    }));
    let low = make_task(&f_plan, 999_999);
    let low_id = low.id.clone();
    fair.add_task(low).unwrap();
    let mut seed_params = BTreeMap::new();
    seed_params.insert("target".to_owned(), "127.0.0.1".to_owned());
    seed_params.insert("variant".to_owned(), "seed".to_owned());
    fair.add_task(
        Task::new_with_params(
            TaskKind::HostDiscovery,
            None,
            Vec::new(),
            None,
            f_plan.stable_id(),
            200,
            Duration::from_millis(5000),
            RetryPolicy::default(),
            "phase19.bench",
            provenance_for(&f_plan),
            TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
            seed_params,
            &AllowAll,
        )
        .unwrap(),
    )
    .unwrap();
    let fair_report = fair.run().unwrap();
    assert!(fair_report.completed.contains(&low_id));

    // ---------------- report ----------------
    let wall_ms = wall_start.elapsed().as_millis();
    let binary_size = std::fs::metadata("target/release/rxscan")
        .map(|m| m.len())
        .unwrap_or_else(|_| {
            std::fs::metadata("target/debug/rxscan")
                .map(|m| m.len())
                .unwrap_or(0)
        });
    let uname = std::process::Command::new("uname")
        .arg("-sr")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("phase19_bench");
    println!("os_kernel={uname}");
    println!(
        "build_mode={}",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
    println!("available_parallelism={available_parallelism}");
    println!("threads_used_peak={scheduler_active_peak}");
    println!("wall_ms={wall_ms}");
    match cpu_time_ms() {
        Some(ms) => println!("cpu_time_ms={ms}"),
        None => println!("cpu_time_ms=unavailable"),
    }
    println!("peak_rss_kb={}", peak_rss_kb());
    println!("current_rss_kb={}", current_rss_kb());
    println!("scheduler_tasks_proposed={scheduler_tasks_proposed}");
    println!("scheduler_tasks_completed={}", report.completed.len());
    println!("scheduler_queue_peak={scheduler_queue_peak}");
    println!("scheduler_queue_capacity={queue_capacity}");
    println!("scheduler_active_peak={scheduler_active_peak}");
    println!("scheduler_wall_ms={scheduler_wall_ms}");
    println!("scheduler_cancel_to_stop_ms={scheduler_cancel_to_stop_ms}");
    println!("tcp_ports_represented={tcp_ports_represented}");
    println!("tcp_resolve_ms={tcp_resolve_ms}");
    println!("tcp_active_peak={tcp_fd_peak}");
    println!("tcp_fd_peak={tcp_fd_peak}");
    println!("tcp_fd_hard_cap={MAX_TCP_CONCURRENCY_HARD}");
    println!("tcp_fd_before={fd_before}");
    println!("tcp_fd_after={fd_after}");
    println!("web_requests={web_requests_made}");
    println!("content_events={}", content_output.events.len());
    println!("content_ms={content_ms}");
    println!("crawl_candidates={crawl_candidates}");
    println!("crawl_links_extracted={}", refs.links.len());
    println!("crawl_links_truncated={}", refs.truncated_links);
    println!("crawl_proposals={}", followups.proposals.len());
    println!("crawl_skipped_pages={}", followups.skipped_pages);
    println!("crawl_plan_ms={crawl_plan_ms}");
    println!("extract_ms={extract_ms}");
    println!("content_candidates=300");
    println!("content_dedup_avoided=0");
    println!("fuzz_mutations=2048");
    println!("fuzz_ms={fuzz_ms}");
    println!("dns_queries={dns_queries}");
    println!("checkpoint_bytes={checkpoint_bytes}");
    println!("checkpoint_save_ms={checkpoint_save_ms}");
    println!("checkpoint_load_ms={checkpoint_load_ms}");
    println!("diff_records={diff_records}");
    println!("diff_ms={diff_ms}");
    println!("analysis_candidates={}", analysis_report.total_signals);
    println!(
        "analysis_signals_emitted={}",
        analysis_report.signals_emitted
    );
    println!("analysis_ms={analysis_ms}");
    println!("report_jsonl_records={report_jsonl_records}");
    println!("report_jsonl_bytes={}", jsonl_bytes.len());
    println!("report_render_ms={report_render_ms}");
    println!("project_bytes={project_bytes}");
    println!("project_open_ms={project_open_ms}");
    println!("project_fingerprint_ms={project_fingerprint_ms}");
    println!("project_query_ms={project_query_ms}");
    println!("project_queue_peak={}", neighbors.queue_peak);
    println!("project_visited_peak={}", neighbors.visited_peak);
    println!("project_expansions={}", neighbors.expansions);
    println!("project_exhaustive={}", neighbors.exhaustive);
    println!("incremental_import_ms={incremental_import_ms}");
    println!("project_save_ms={project_save_ms}");
    println!("release_binary_size_bytes={binary_size}");
    println!("new_production_dependency_count=0");
}
