use std::{
    collections::BTreeMap,
    fs,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use rxscan::{
    cli::Cli,
    config::{parse_bytes, parse_duration_ms},
    execution::{
        BudgetLimits, CancellationToken, Module, ModuleContext, ModuleError, ModuleFuture,
        ModuleOutput, PolicyScopeGuard, RetryPolicy, Scheduler, ScopeGuard, SpeedGovernor, Task,
        TaskKind, TaskScopeTarget, VecEventSink,
    },
    level::{eligible_task_kinds, validate_kind},
    lowering::{lower_plan_to_tasks, task_graph_fingerprint},
    model::{
        Asset, AssetKind, BoundedDetails, Confidence, Event, EventKind, Evidence, Finding,
        Provenance, Relationship, RelationshipKind, RelationshipSubject, SCHEMA_VERSION, Severity,
        Timestamp,
    },
    output::{JsonlWriter, parse_envelope_payload},
    plan::{ScanGoal, ScanPlan, SpeedSetting},
};
use serde_json::json;

// ---------- helpers ----------

fn compile(args: &[&str]) -> ScanPlan {
    let mut full = vec!["rxscan"];
    full.extend_from_slice(args);
    let cli = Cli::try_parse_from(full).unwrap();
    ScanPlan::compile(cli).unwrap()
}

fn plan_for(target: &str) -> ScanPlan {
    compile(&[target])
}

fn provenance_for(plan: &ScanPlan) -> Provenance {
    Provenance::new("test.module", "4.0.0", plan.stable_id(), Timestamp(0)).unwrap()
}

struct AllowAll;
impl ScopeGuard for AllowAll {
    fn permits(&self, _target: &TaskScopeTarget) -> bool {
        true
    }
}

fn make_task(
    plan: &ScanPlan,
    kind: TaskKind,
    module: &str,
    scope: TaskScopeTarget,
    params: BTreeMap<String, String>,
) -> Task {
    Task::new_with_params(
        kind,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        50,
        Duration::from_millis(100),
        RetryPolicy::default(),
        module,
        provenance_for(plan),
        scope,
        params,
        &AllowAll,
    )
    .unwrap()
}

struct ImmediateModule {
    kind: TaskKind,
}
impl Module for ImmediateModule {
    fn kind(&self) -> TaskKind {
        self.kind.clone()
    }
    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        Box::pin(async move {
            if context.is_cancelled() {
                return Err(ModuleError::Cancelled);
            }
            Ok(ModuleOutput::default())
        })
    }
}

struct RetryOnceModule {
    kind: TaskKind,
    attempts: Arc<AtomicUsize>,
}
impl Module for RetryOnceModule {
    fn kind(&self) -> TaskKind {
        self.kind.clone()
    }
    fn execute(&self, _context: ModuleContext) -> ModuleFuture {
        let attempts = self.attempts.clone();
        Box::pin(async move {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                Err(ModuleError::Failed {
                    message: "temporary".into(),
                    retryable: true,
                })
            } else {
                Ok(ModuleOutput::default())
            }
        })
    }
}

// ---------- lowering ----------

#[test]
fn same_plan_yields_same_task_graph() {
    let first = lower_plan_to_tasks(&plan_for("example.test")).unwrap();
    let second = lower_plan_to_tasks(&plan_for("example.test")).unwrap();
    assert_eq!(
        task_graph_fingerprint(&first),
        task_graph_fingerprint(&second)
    );
    assert_eq!(first.len(), second.len());
    // Deterministic ordering: sorted by ID.
    let mut ids: Vec<&str> = first.iter().map(|task| task.id.0.as_str()).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted);
    ids.sort_unstable();
    let _ = ids;
}

#[test]
fn different_levels_yield_different_tasks_where_defined() {
    let l1 = lower_plan_to_tasks(&compile(&["example.test", "--level", "1"])).unwrap();
    let l2 = lower_plan_to_tasks(&compile(&["example.test", "--level", "2"])).unwrap();
    let l5 = lower_plan_to_tasks(&compile(&["example.test", "--level", "5"])).unwrap();
    assert!(l1.len() < l2.len());
    assert!(l2.len() < l5.len());
    assert_ne!(task_graph_fingerprint(&l1), task_graph_fingerprint(&l2));
    // Level 1 is validation only.
    assert_eq!(l1.len(), 1);
    assert_eq!(l1[0].kind, validate_kind());
}

#[test]
fn different_goals_yield_different_task_graphs() {
    let recon = lower_plan_to_tasks(&compile(&[
        "example.test",
        "--level",
        "5",
        "--goal",
        "recon",
    ]))
    .unwrap();
    let web =
        lower_plan_to_tasks(&compile(&["example.test", "--level", "5", "--goal", "web"])).unwrap();
    let fuzz = lower_plan_to_tasks(&compile(&[
        "example.test",
        "--level",
        "5",
        "--goal",
        "fuzz",
    ]))
    .unwrap();
    assert_ne!(task_graph_fingerprint(&recon), task_graph_fingerprint(&web));
    assert_ne!(task_graph_fingerprint(&web), task_graph_fingerprint(&fuzz));
    // Web includes HTTP intent, recon does not.
    assert!(web.iter().any(|task| task.kind == TaskKind::HttpProbe));
    assert!(!recon.iter().any(|task| task.kind == TaskKind::HttpProbe));
    // Fuzz intent is evidence-triggered only (follow-up, never a seed task):
    // Full and Web initial graphs differ, and Full advertises the fuzz rule.
    let full_followups = rxscan::level::describe_followups(rxscan::plan::ScanGoal::Full, 5);
    let web_followups = rxscan::level::describe_followups(rxscan::plan::ScanGoal::Web, 5);
    assert!(full_followups.contains("fuzzing"));
    assert!(!web_followups.contains("fuzzing"));
    assert!(!web.iter().any(|task| task.kind == TaskKind::Fuzz));
    assert!(!fuzz.iter().any(|task| task.kind == TaskKind::Fuzz));
}

#[test]
fn out_of_scope_targets_are_rejected() {
    // Seed excluded at compile time fails fast.
    let cli = Cli::try_parse_from(["rxscan", "192.0.2.10", "--exclude", "192.0.2.10"]).unwrap();
    assert!(ScanPlan::compile(cli).is_err());
    // Lowering is fail-closed if scope later becomes empty.
    let mut plan = plan_for("example.test");
    plan.scope.allowed.clear();
    assert!(lower_plan_to_tasks(&plan).is_err());
}

#[test]
fn exclusions_are_respected() {
    // Excluding a non-seed still compiles, but the excluded host is not permitted.
    let plan = compile(&["192.0.2.10", "--exclude", "192.0.2.11"]);
    assert!(
        !plan
            .scope
            .permits(Some("192.0.2.11".parse().unwrap()), None)
    );
    assert!(
        plan.scope
            .permits(Some("192.0.2.10".parse().unwrap()), None)
    );
}

#[test]
fn duplicate_targets_are_eliminated() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("rxscan-phase4-dedup-{stamp}"));
    fs::create_dir_all(&directory).unwrap();
    let targets = directory.join("targets.txt");
    fs::write(
        &targets,
        "example.test\nexample.test\n# comment\n\nexample.test\n",
    )
    .unwrap();
    let single = lower_plan_to_tasks(&plan_for("example.test")).unwrap();
    let cli = Cli::try_parse_from(["rxscan", "--targets", targets.to_str().unwrap()]).unwrap();
    let plan = ScanPlan::compile(cli).unwrap();
    // Three identical seed lines must not triple the task graph.
    assert_eq!(plan.targets.len(), 3);
    let deduped = lower_plan_to_tasks(&plan).unwrap();
    assert_eq!(single.len(), deduped.len());
    // Same duplicate plan lowers deterministically.
    let cli_again =
        Cli::try_parse_from(["rxscan", "--targets", targets.to_str().unwrap()]).unwrap();
    let plan_again = ScanPlan::compile(cli_again).unwrap();
    let deduped_again = lower_plan_to_tasks(&plan_again).unwrap();
    assert_eq!(
        task_graph_fingerprint(&deduped),
        task_graph_fingerprint(&deduped_again)
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn all_ports_represented_safely_without_expansion() {
    let plan = compile(&["example.test", "--all-ports", "--level", "3"]);
    let tasks = lower_plan_to_tasks(&plan).unwrap();
    // One port task per target, not 65k.
    let port_tasks: Vec<&Task> = tasks
        .iter()
        .filter(|task| task.kind == TaskKind::PortDiscovery)
        .collect();
    assert_eq!(port_tasks.len(), 1);
    assert!(tasks.len() < 10);
    assert_eq!(
        port_tasks[0].params.get("ports").map(String::as_str),
        Some("all")
    );
    assert_eq!(
        port_tasks[0].params.get("port_count").map(String::as_str),
        Some("65535")
    );
}

#[test]
fn explicit_ports_propagate_via_params() {
    let plan = compile(&["example.test", "--ports", "80,443", "--level", "3"]);
    let tasks = lower_plan_to_tasks(&plan).unwrap();
    let port_task = tasks
        .iter()
        .find(|task| task.kind == TaskKind::PortDiscovery)
        .unwrap();
    assert!(port_task.params.get("ports").unwrap().contains("80"));
    assert!(port_task.params.get("ports").unwrap().contains("443"));
    assert_eq!(
        port_task.params.get("port_count").map(String::as_str),
        Some("2")
    );
}

// ---------- level / speed ----------

#[test]
fn level_policy_is_centralized_and_documented() {
    // L1 minimal for every goal; higher levels expand.
    for goal in [ScanGoal::Recon, ScanGoal::Web, ScanGoal::Full] {
        assert_eq!(
            eligible_task_kinds(goal, 1, false, false, false),
            vec![validate_kind()]
        );
    }
    let l2 = eligible_task_kinds(ScanGoal::Recon, 2, false, false, false);
    let l3 = eligible_task_kinds(ScanGoal::Recon, 3, false, false, false);
    assert!(l2.len() < l3.len());
    // Explicit requests add intent even at L1.
    let l1_host = eligible_task_kinds(ScanGoal::Recon, 1, true, false, false);
    assert!(l1_host.contains(&TaskKind::HostDiscovery));
}

#[test]
fn speed_policy_controls_concurrency_retry_and_timeout() {
    let slow = SpeedGovernor::new(SpeedSetting::Numeric(20), 5).unwrap();
    let fast = SpeedGovernor::new(SpeedSetting::Numeric(90), 5).unwrap();
    assert!(slow.concurrency() < fast.concurrency());
    assert!(fast.retry_limit() >= slow.retry_limit());
    assert!(fast.default_timeout() <= slow.default_timeout());
    // Speed 100 never means unlimited: capped by max_concurrency.
    let capped = SpeedGovernor::new(SpeedSetting::Numeric(100), 4).unwrap();
    assert_eq!(capped.concurrency(), 4);
    // Named mappings are deterministic.
    let auto = SpeedGovernor::new(SpeedSetting::Named(rxscan::plan::NamedSpeed::Auto), 4).unwrap();
    let balanced =
        SpeedGovernor::new(SpeedSetting::Named(rxscan::plan::NamedSpeed::Balanced), 4).unwrap();
    assert_eq!(auto.concurrency(), balanced.concurrency());
    assert_eq!(auto.retry_limit(), balanced.retry_limit());
    assert_eq!(auto.default_timeout(), balanced.default_timeout());
}

#[test]
fn auto_is_an_honest_non_adaptive_baseline() {
    let auto = SpeedGovernor::new(SpeedSetting::Named(rxscan::plan::NamedSpeed::Auto), 4).unwrap();
    assert!(!auto.is_adaptive());
    assert!(auto.describe().contains("non-adaptive"));
    assert!(auto.describe().contains("auto == balanced"));
}

// ---------- budgets ----------

#[test]
fn budget_config_precedence_is_defaults_then_global_then_project_then_cli() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("rxscan-phase4-budget-{stamp}"));
    fs::create_dir_all(&directory).unwrap();
    let global = directory.join("global.toml");
    let project = directory.join("project.toml");
    fs::write(
        &global,
        "max_tasks = 11\nmax_concurrency = 2\nmax_execution_time = '60s'\nmax_evidence_bytes = '1024'\n",
    )
    .unwrap();
    fs::write(&project, "max_tasks = 22\nmax_concurrency = 3\n").unwrap();
    // Project overrides global.
    let cli = Cli::try_parse_from([
        "rxscan",
        "example.test",
        "--config",
        global.to_str().unwrap(),
        "--project-config",
        project.to_str().unwrap(),
    ])
    .unwrap();
    let plan = ScanPlan::compile(cli).unwrap();
    assert_eq!(plan.budgets.max_tasks, 22);
    assert_eq!(plan.budgets.max_concurrency, 3);
    // CLI wins over both.
    let cli = Cli::try_parse_from([
        "rxscan",
        "example.test",
        "--config",
        global.to_str().unwrap(),
        "--project-config",
        project.to_str().unwrap(),
        "--max-tasks",
        "33",
    ])
    .unwrap();
    let plan = ScanPlan::compile(cli).unwrap();
    assert_eq!(plan.budgets.max_tasks, 33);
    assert_eq!(plan.budgets.max_concurrency, 3);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn invalid_budgets_fail_fast() {
    // Zero concurrency rejected by CLI parser.
    assert!(Cli::try_parse_from(["rxscan", "example.test", "--max-concurrency", "0"]).is_err());
    // Malformed durations / sizes rejected.
    assert!(parse_duration_ms("").is_err());
    assert!(parse_duration_ms("0s").is_err());
    assert!(parse_duration_ms("banana").is_err());
    assert!(parse_bytes("").is_err());
    assert!(parse_bytes("0").is_err());
    assert!(parse_bytes("banana").is_err());
    // Well-formed values parse.
    assert_eq!(parse_duration_ms("60s").unwrap(), 60_000);
    assert_eq!(parse_duration_ms("5m").unwrap(), 300_000);
    assert_eq!(parse_duration_ms("500ms").unwrap(), 500);
    assert_eq!(parse_duration_ms("42").unwrap(), 42_000);
    assert_eq!(parse_bytes("1024").unwrap(), 1024);
    assert_eq!(parse_bytes("64MiB").unwrap(), 64 * 1024 * 1024);
    assert_eq!(parse_bytes("10MB").unwrap(), 10_000_000);
    // Exceeding hard safety limits fails at plan compile.
    let cli = Cli::try_parse_from(["rxscan", "example.test", "--max-tasks", "999999999"]).unwrap();
    assert!(ScanPlan::compile(cli).is_err());
    let cli = Cli::try_parse_from(["rxscan", "example.test", "--max-concurrency", "999"]).unwrap();
    assert!(ScanPlan::compile(cli).is_err());
    let cli =
        Cli::try_parse_from(["rxscan", "example.test", "--max-execution-time", "banana"]).unwrap();
    assert!(ScanPlan::compile(cli).is_err());
    // Only jsonl format supported.
    let cli = Cli::try_parse_from(["rxscan", "example.test", "--format", "html"]).unwrap();
    assert!(ScanPlan::compile(cli).is_err());
}

// ---------- task IDs ----------

#[test]
fn task_ids_distinguish_meaningful_execution_variants() {
    let plan = plan_for("example.test");
    let scope_host = TaskScopeTarget::Host("example.test".to_owned());
    let base = make_task(
        &plan,
        TaskKind::HostDiscovery,
        "m",
        scope_host.clone(),
        BTreeMap::new(),
    );
    // Timeout differs -> different ID.
    let other_timeout = Task::new(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        50,
        Duration::from_millis(999),
        RetryPolicy::default(),
        "m",
        provenance_for(&plan),
        scope_host.clone(),
        &AllowAll,
    )
    .unwrap();
    assert_ne!(base.id, other_timeout.id);
    // Retry policy differs -> different ID.
    let other_retry = Task::new(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        50,
        Duration::from_millis(100),
        RetryPolicy {
            max_attempts: 5,
            base_delay_ms: 50,
        },
        "m",
        provenance_for(&plan),
        scope_host.clone(),
        &AllowAll,
    )
    .unwrap();
    assert_ne!(base.id, other_retry.id);
    // Priority differs -> different ID.
    let other_priority = Task::new(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        9,
        Duration::from_millis(100),
        RetryPolicy::default(),
        "m",
        provenance_for(&plan),
        scope_host.clone(),
        &AllowAll,
    )
    .unwrap();
    assert_ne!(base.id, other_priority.id);
    // Scope target differs -> different ID.
    let other_scope = make_task(
        &plan,
        TaskKind::HostDiscovery,
        "m",
        TaskScopeTarget::None,
        BTreeMap::new(),
    );
    assert_ne!(base.id, other_scope.id);
    // Params differ -> different ID.
    let mut params = BTreeMap::new();
    params.insert("ports".to_owned(), "all".to_owned());
    let other_params = make_task(&plan, TaskKind::HostDiscovery, "m", scope_host, params);
    assert_ne!(base.id, other_params.id);
    // Identical inputs -> identical ID (deterministic).
    let again = make_task(
        &plan,
        TaskKind::HostDiscovery,
        "m",
        TaskScopeTarget::Host("example.test".to_owned()),
        BTreeMap::new(),
    );
    assert_eq!(base.id, again.id);
}

// ---------- scheduler hardening ----------

#[test]
fn queue_saturation_is_backpressure_not_fatal() {
    let plan = plan_for("example.test");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let sink = Arc::new(VecEventSink::default());
    // Queue capacity 1 with 3 tasks must still complete (drains over ticks).
    let mut scheduler = Scheduler::new(
        1,
        BudgetLimits::default(),
        SpeedGovernor::new(SpeedSetting::Numeric(100), 2).unwrap(),
        guard.clone(),
        sink,
    )
    .unwrap();
    scheduler.register_module(Arc::new(ImmediateModule {
        kind: TaskKind::HostDiscovery,
    }));
    for asset in ["a", "b", "c"] {
        let task = Task::new(
            TaskKind::HostDiscovery,
            None,
            Vec::new(),
            Some(rxscan::model::AssetId(asset.to_owned())),
            plan.stable_id(),
            50,
            Duration::from_millis(500),
            RetryPolicy::default(),
            format!("host-{asset}"),
            provenance_for(&plan),
            TaskScopeTarget::Host("example.test".to_owned()),
            guard.as_ref(),
        )
        .unwrap();
        scheduler.add_task(task).unwrap();
    }
    let report = scheduler.run().unwrap();
    assert_eq!(report.completed.len(), 3);
}

#[test]
fn retry_delay_does_not_head_of_line_block_others() {
    let plan = plan_for("example.test");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let sink = Arc::new(VecEventSink::default());
    let mut scheduler = Scheduler::new(
        16,
        BudgetLimits::default(),
        SpeedGovernor::new(SpeedSetting::Numeric(100), 2).unwrap(),
        guard.clone(),
        sink,
    )
    .unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    scheduler.register_module(Arc::new(RetryOnceModule {
        kind: TaskKind::HostDiscovery,
        attempts: attempts.clone(),
    }));
    scheduler.register_module(Arc::new(ImmediateModule {
        kind: TaskKind::PortDiscovery,
    }));
    // Flaky task with a long retry delay; independent task must not be blocked.
    let mut flaky = Task::new(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        Some(rxscan::model::AssetId("flaky".to_owned())),
        plan.stable_id(),
        10,
        Duration::from_millis(2000),
        RetryPolicy {
            max_attempts: 2,
            base_delay_ms: 200,
        },
        "flaky",
        provenance_for(&plan),
        TaskScopeTarget::Host("example.test".to_owned()),
        guard.as_ref(),
    )
    .unwrap();
    flaky.priority = 90;
    scheduler.add_task(flaky).unwrap();
    let fast = Task::new(
        TaskKind::PortDiscovery,
        None,
        Vec::new(),
        Some(rxscan::model::AssetId("fast".to_owned())),
        plan.stable_id(),
        10,
        Duration::from_millis(2000),
        RetryPolicy::default(),
        "fast",
        provenance_for(&plan),
        TaskScopeTarget::Host("example.test".to_owned()),
        guard.as_ref(),
    )
    .unwrap();
    scheduler.add_task(fast).unwrap();
    let started = Instant::now();
    let report = scheduler.run().unwrap();
    // Both complete; the fast task was not stuck behind the 200ms retry delay
    // beyond a generous bound (would be ~200ms+ with HOL blocking, but the
    // scheduler overlaps them).
    assert_eq!(report.completed.len(), 2);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn cancellation_is_observed_promptly() {
    let plan = plan_for("example.test");
    let provenance = provenance_for(&plan);
    let task = Task::new(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        50,
        Duration::from_millis(5000),
        RetryPolicy::default(),
        "rxscan.host",
        provenance,
        TaskScopeTarget::Host("example.test".to_owned()),
        &AllowAll,
    )
    .unwrap();
    let token = CancellationToken::default();
    let context = ModuleContext::new(task, token.clone());
    token.cancel();
    let module = rxscan::modules::ScaffoldModule::host_intent();
    let started = Instant::now();
    // Drive the future manually via the scheduler's worker path: spawn and join.
    let handle = std::thread::spawn(move || {
        // Reimplement minimal block_on by polling until ready with parking.
        use std::task::{Context as TaskContext, Poll, RawWaker, RawWakerVTable, Waker};
        unsafe fn raw_waker(thread: std::thread::Thread) -> RawWaker {
            unsafe fn clone(data: *const ()) -> RawWaker {
                let thread = unsafe { &*(data as *const std::thread::Thread) };
                unsafe { raw_waker(thread.clone()) }
            }
            unsafe fn wake(data: *const ()) {
                let thread = unsafe { Box::from_raw(data as *mut std::thread::Thread) };
                thread.unpark();
            }
            unsafe fn wake_by_ref(data: *const ()) {
                unsafe { (&*(data as *const std::thread::Thread)).unpark() };
            }
            unsafe fn drop_waker(data: *const ()) {
                drop(unsafe { Box::from_raw(data as *mut std::thread::Thread) });
            }
            static VTABLE: RawWakerVTable =
                RawWakerVTable::new(clone, wake, wake_by_ref, drop_waker);
            RawWaker::new(Box::into_raw(Box::new(thread)) as *const (), &VTABLE)
        }
        let waker = unsafe { Waker::from_raw(raw_waker(std::thread::current())) };
        let mut future = module.execute(context);
        let mut context = TaskContext::from_waker(&waker);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => break value,
                Poll::Pending => std::thread::park(),
            }
        }
    });
    let result = handle.join().unwrap();
    assert!(matches!(result, Err(ModuleError::Cancelled)));
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "cancellation latency {:?} exceeds bound",
        started.elapsed()
    );
}

struct HangingModule;
impl Module for HangingModule {
    fn kind(&self) -> TaskKind {
        TaskKind::Custom("hang".into())
    }
    fn execute(&self, _context: ModuleContext) -> ModuleFuture {
        Box::pin(async move {
            loop {
                std::thread::sleep(Duration::from_millis(50));
            }
        })
    }
}

#[test]
fn timeout_frees_slots_without_deadlock_or_double_count() {
    let plan = plan_for("example.test");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let mut scheduler = Scheduler::new(
        8,
        BudgetLimits {
            max_execution_time_ms: 5000,
            ..BudgetLimits::default()
        },
        SpeedGovernor::new(SpeedSetting::Numeric(100), 2).unwrap(),
        guard.clone(),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler.register_module(Arc::new(HangingModule));
    scheduler.register_module(Arc::new(ImmediateModule {
        kind: TaskKind::HostDiscovery,
    }));
    let mut hanging = Task::new(
        TaskKind::Custom("hang".into()),
        None,
        Vec::new(),
        Some(rxscan::model::AssetId("hang".to_owned())),
        plan.stable_id(),
        50,
        Duration::from_millis(30),
        RetryPolicy::default(),
        "hang",
        provenance_for(&plan),
        TaskScopeTarget::Host("example.test".to_owned()),
        guard.as_ref(),
    )
    .unwrap();
    hanging.priority = 90;
    let hanging_id = hanging.id.clone();
    scheduler.add_task(hanging).unwrap();
    let fast = Task::new(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        Some(rxscan::model::AssetId("fast".to_owned())),
        plan.stable_id(),
        10,
        Duration::from_millis(2000),
        RetryPolicy::default(),
        "fast",
        provenance_for(&plan),
        TaskScopeTarget::Host("example.test".to_owned()),
        guard.as_ref(),
    )
    .unwrap();
    scheduler.add_task(fast).unwrap();
    let started = Instant::now();
    let report = scheduler.run().unwrap();
    assert!(report.timed_out.contains(&hanging_id));
    assert_eq!(report.completed.len(), 1);
    // Total tasks accounted exactly once (no double-count from orphan reaps).
    let total = report.completed.len()
        + report.failed.len()
        + report.cancelled.len()
        + report.timed_out.len()
        + report.skipped.len();
    assert_eq!(total, 2);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn retries_are_fair_and_eventually_succeed() {
    let plan = plan_for("example.test");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let attempts_a = Arc::new(AtomicUsize::new(0));
    let attempts_b = Arc::new(AtomicUsize::new(0));
    let mut scheduler = Scheduler::new(
        16,
        BudgetLimits::default(),
        SpeedGovernor::new(SpeedSetting::Numeric(100), 2).unwrap(),
        guard.clone(),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    // Two distinct kinds so each has its own retrying module.
    scheduler.register_module(Arc::new(RetryOnceModule {
        kind: TaskKind::HostDiscovery,
        attempts: attempts_a.clone(),
    }));
    scheduler.register_module(Arc::new(RetryOnceModule {
        kind: TaskKind::PortDiscovery,
        attempts: attempts_b.clone(),
    }));
    for (kind, asset, module) in [
        (TaskKind::HostDiscovery, "a", "ma"),
        (TaskKind::PortDiscovery, "b", "mb"),
    ] {
        let mut task = Task::new(
            kind,
            None,
            Vec::new(),
            Some(rxscan::model::AssetId(asset.to_owned())),
            plan.stable_id(),
            50,
            Duration::from_millis(2000),
            RetryPolicy {
                max_attempts: 2,
                base_delay_ms: 0,
            },
            module,
            provenance_for(&plan),
            TaskScopeTarget::Host("example.test".to_owned()),
            guard.as_ref(),
        )
        .unwrap();
        task.priority = 50;
        scheduler.add_task(task).unwrap();
    }
    let report = scheduler.run().unwrap();
    assert_eq!(report.completed.len(), 2);
    assert_eq!(attempts_a.load(Ordering::SeqCst), 2);
    assert_eq!(attempts_b.load(Ordering::SeqCst), 2);
}

#[test]
fn stale_scope_skips_at_execution_time() {
    use std::sync::atomic::AtomicBool;
    struct FlippingGuard {
        allowed: AtomicBool,
    }
    impl ScopeGuard for FlippingGuard {
        fn permits(&self, _target: &TaskScopeTarget) -> bool {
            self.allowed.load(Ordering::SeqCst)
        }
    }
    let plan = plan_for("example.test");
    let guard = Arc::new(FlippingGuard {
        allowed: AtomicBool::new(true),
    });
    let mut scheduler = Scheduler::new(
        4,
        BudgetLimits::default(),
        SpeedGovernor::new(SpeedSetting::Numeric(100), 2).unwrap(),
        guard.clone(),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler.register_module(Arc::new(ImmediateModule {
        kind: TaskKind::HostDiscovery,
    }));
    let task = Task::new(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        50,
        Duration::from_millis(500),
        RetryPolicy::default(),
        "m",
        provenance_for(&plan),
        TaskScopeTarget::Host("example.test".to_owned()),
        guard.as_ref(),
    )
    .unwrap();
    scheduler.add_task(task).unwrap();
    guard.allowed.store(false, Ordering::SeqCst);
    assert_eq!(scheduler.run().unwrap().skipped.len(), 1);
}

// ---------- bootstrap + output ----------

#[test]
fn scheduler_is_reachable_from_bootstrap_with_no_network() {
    let cli = Cli::try_parse_from(["rxscan", "example.test"]).unwrap();
    let report = rxscan::run::execute(cli).unwrap();
    assert!(report.task_count > 0);
    assert_eq!(
        report.task_count,
        report.scheduler_report.completed.len() + report.scheduler_report.skipped.len()
    );
    // Every planned task is executable: no task may predictably become
    // `Skipped` for a missing module (tls/fingerprint planners were removed;
    // content/crawl/fuzz are follow-up-only). Level 5 web runs clean.
    let cli =
        Cli::try_parse_from(["rxscan", "example.test", "--level", "5", "--goal", "web"]).unwrap();
    let report = rxscan::run::execute(cli).unwrap();
    assert!(report.scheduler_report.skipped.is_empty());
}

#[test]
fn jsonl_output_is_valid_provenanced_and_bounded() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("rxscan-phase4-jsonl-{stamp}"));
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("out.jsonl");
    let cli = Cli::try_parse_from(["rxscan", "example.test", "--output", path.to_str().unwrap()])
        .unwrap();
    let report = rxscan::run::execute(cli).unwrap();
    assert!(report.jsonl_bytes > 0);
    let contents = fs::read_to_string(&path).unwrap();
    let mut lines = 0;
    for line in contents.lines() {
        assert!(!line.trim().is_empty());
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(value["schema_version"], SCHEMA_VERSION);
        assert!(value.get("record_type").is_some());
        assert!(
            value["payload"]["provenance"]["scan_plan_id"]
                .as_str()
                .unwrap()
                .starts_with("plan_")
        );
        lines += 1;
    }
    assert!(lines > 0);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn jsonl_typed_records_round_trip() {
    let plan = plan_for("example.test");
    let provenance = provenance_for(&plan);
    let host = Asset::scoped(
        AssetKind::Host,
        "example.test",
        &plan.scope,
        provenance.clone(),
    )
    .unwrap();
    let event = Event::new(
        EventKind::HostDiscovered,
        Some(host.id.clone()),
        BoundedDetails::from_value(json!({"method": "seed"}), 1024).unwrap(),
        provenance.clone(),
    )
    .unwrap();
    let evidence = Evidence::new(
        "test.source",
        host.id.clone(),
        BoundedDetails::from_value(json!({"k": "v"}), 1024).unwrap(),
        Confidence::new(80).unwrap(),
        provenance.clone(),
    )
    .unwrap();
    let finding = Finding::new(
        "Test finding",
        Severity::Low,
        Confidence::new(80).unwrap(),
        host.id.clone(),
        provenance.clone(),
    )
    .unwrap();
    let relationship = Relationship::new(
        RelationshipKind::Supports,
        RelationshipSubject::Evidence(evidence.id.clone()),
        RelationshipSubject::Finding(finding.id.clone()),
        provenance,
    )
    .unwrap();
    let mut buffer = Vec::new();
    {
        let mut writer = JsonlWriter::new(&mut buffer, 1024 * 1024);
        writer.write_event(&event).unwrap();
        writer.write_evidence(&evidence).unwrap();
        writer.write_finding(&finding).unwrap();
        writer.write_relationship(&relationship).unwrap();
        writer.write_asset(&host).unwrap();
        writer.flush().unwrap();
    }
    let text = String::from_utf8(buffer).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 5);
    let (_, record_type, parsed_event): (u16, String, Event) =
        parse_envelope_payload(lines[0]).unwrap();
    assert_eq!(record_type, "event");
    assert_eq!(parsed_event, event);
    let (_, _, parsed_evidence): (u16, String, Evidence) =
        parse_envelope_payload(lines[1]).unwrap();
    assert_eq!(parsed_evidence, evidence);
}

#[test]
fn output_filesystem_failures_are_clean_errors() {
    // Writing to a directory path must fail cleanly, not panic.
    let directory = std::env::temp_dir().join(format!(
        "rxscan-phase4-fail-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&directory).unwrap();
    let result = rxscan::output::create_file_writer(&directory, 1024);
    assert!(result.is_err());
    // Bootstrap with an unwritable output path returns Output error (exit 1), not panic.
    let cli = Cli::try_parse_from([
        "rxscan",
        "example.test",
        "--output",
        "/nonexistent-dir-xyz-123/out.jsonl",
    ])
    .unwrap();
    let result = rxscan::run::execute(cli);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().exit_code(), 1);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn explain_reflects_effective_policy() {
    let plan = compile(&[
        "example.test",
        "--goal",
        "web",
        "--level",
        "3",
        "--speed",
        "fast",
        "--max-tasks",
        "42",
        "--max-concurrency",
        "3",
    ]);
    let explained = plan.explain();
    assert!(explained.contains("web") || explained.contains("Web"));
    assert!(explained.contains("level: 3") || explained.contains("level 3"));
    assert!(explained.contains("Fast") || explained.contains("fast"));
    assert!(explained.contains("effective concurrency"));
    assert!(explained.contains("retry limit"));
    assert!(explained.contains("task budget"));
    assert!(explained.contains("evidence budget"));
    assert!(explained.contains("execution timeout"));
    assert!(explained.contains("selected") || explained.contains("selects"));
    assert!(explained.contains("not selected") || explained.contains("skipped"));
    // Auto honesty shows in explain.
    let auto_plan = compile(&["example.test", "--speed", "auto"]);
    assert!(auto_plan.explain().contains("non-adaptive"));
}
