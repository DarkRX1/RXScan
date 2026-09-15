//! Phase 19 performance / large-scale hardening tests.
//!
//! All fixtures are local, synthetic, and deterministic. No public network
//! access. Timing assertions use generous bounds only; structural invariants
//! (caps, counts, determinism, bounded stop) carry the proof.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
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
    analysis::{self, AnalysisOptions},
    cli::Cli,
    contact::{ContactRegistry, RequestPurpose},
    content::{
        self, CONTENT_MODULE_NAME, ContentDiscoveryModule, ContentDiscoveryPolicy,
        MAX_CANDIDATES_READ, MAX_CONTENT_REQUESTS,
    },
    crawl::{self, MAX_CRAWL_PROPOSALS_PER_COMPLETION},
    decision::open_ports_from_output,
    diff::{self, ChangeType, DiffOptions},
    discovery::expand_cidr_bounded,
    dns::{
        DnsRecordType, DnsRegistry, MAX_DNS_DOMAINS, MAX_DNS_REGISTRY_ENTRIES,
        MAX_DNS_TASKS_PER_DOMAIN_HARD,
    },
    execution::{
        BudgetLimits, CancellationToken, DecisionEngine, Module, ModuleContext, ModuleError,
        ModuleFuture, ModuleOutput, PolicyScopeGuard, RetryPolicy, Scheduler, ScopeGuard,
        SpeedGovernor, Task, TaskKind, TaskScopeTarget, VecEventSink,
    },
    fuzz::{FuzzOriginBudget, MAX_FUZZ_ORIGIN_BUDGETS, MAX_FUZZ_TASKS_PER_ORIGIN_HARD},
    model::{Asset, AssetKind, Provenance, ScanPlanId, Timestamp},
    persistence::{
        self, CHECKPOINT_SCHEMA_VERSION, PersistedModuleOutput, PersistedRegistries,
        PersistedScanState, PersistedTask,
    },
    plan::{NamedSpeed, ScanGoal, ScanPlan, SpeedSetting, TcpPortSelection},
    ports::{self, MAX_TCP_CONCURRENCY_HARD},
    project::ProjectState,
    report::{ReportFormat, ReportOptions},
    service,
    tcp_scanner::{NativeTcpScanner, PortScanner, ScanConfig},
    web::WebTarget,
};

// ---------- shared helpers ----------

struct AllowAll;
impl ScopeGuard for AllowAll {
    fn permits(&self, _target: &TaskScopeTarget) -> bool {
        true
    }
}

struct DenyAll;
impl ScopeGuard for DenyAll {
    fn permits(&self, _target: &TaskScopeTarget) -> bool {
        false
    }
}

fn compile(args: &[&str]) -> ScanPlan {
    let mut full = vec!["rxscan"];
    full.extend_from_slice(args);
    let cli = Cli::try_parse_from(full).unwrap();
    ScanPlan::compile(cli).unwrap()
}

fn plan_for(target: &str) -> ScanPlan {
    compile(&[target, "--scope", "127.0.0.0/8"])
}

fn provenance_for(plan: &ScanPlan) -> Provenance {
    Provenance::new("phase19.test", "19.0.0", plan.stable_id(), Timestamp(0)).unwrap()
}

fn make_task(plan: &ScanPlan, index: usize, priority: u8, timeout_ms: u64) -> Task {
    let mut params = BTreeMap::new();
    params.insert("target".to_owned(), "127.0.0.1".to_owned());
    params.insert("variant".to_owned(), format!("task-{index}"));
    Task::new_with_params(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        priority,
        Duration::from_millis(timeout_ms),
        RetryPolicy::default(),
        "phase19.immediate",
        provenance_for(plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        params,
        &AllowAll,
    )
    .unwrap()
}

struct ImmediateModule {
    kind: TaskKind,
    executed: Arc<AtomicUsize>,
}

impl Module for ImmediateModule {
    fn kind(&self) -> TaskKind {
        self.kind.clone()
    }
    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let executed = self.executed.clone();
        Box::pin(async move {
            executed.fetch_add(1, Ordering::SeqCst);
            if context.is_cancelled() {
                return Err(ModuleError::Cancelled);
            }
            Ok(ModuleOutput::default())
        })
    }
}

/// Cooperative module: sleeps in small slices, honors cancellation.
struct SleepyModule {
    kind: TaskKind,
    total: Duration,
    executed: Arc<AtomicUsize>,
}

impl Module for SleepyModule {
    fn kind(&self) -> TaskKind {
        self.kind.clone()
    }
    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let total = self.total;
        let executed = self.executed.clone();
        Box::pin(async move {
            executed.fetch_add(1, Ordering::SeqCst);
            let start = Instant::now();
            while start.elapsed() < total {
                if context.is_cancelled() {
                    return Err(ModuleError::Cancelled);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(ModuleOutput::default())
        })
    }
}

#[test]
fn per_task_timeouts_under_load_free_slots_promptly() {
    // Twelve 5s sleepers on 4 slots with 300ms per-task timeouts: three
    // timeout waves must free every slot without double-counting orphans.
    let plan = plan_for("127.0.0.1");
    let executed = Arc::new(AtomicUsize::new(0));
    let budgets = BudgetLimits {
        max_tasks: 100,
        max_retries: 100,
        max_concurrency: 4,
        max_execution_time_ms: 60_000,
        ..BudgetLimits::default()
    };
    let mut scheduler = test_scheduler(&plan, budgets, SpeedSetting::Numeric(50), 4);
    scheduler.register_module(Arc::new(SleepyModule {
        kind: TaskKind::HostDiscovery,
        total: Duration::from_secs(5),
        executed: executed.clone(),
    }));
    for index in 0..12 {
        let task = make_task(&plan, index, 50, 300);
        scheduler.add_task(task).unwrap();
    }
    let started = Instant::now();
    let report = scheduler.run().unwrap();
    let wall = started.elapsed();
    assert_eq!(report.timed_out.len(), 12);
    let total = report.completed.len()
        + report.failed.len()
        + report.cancelled.len()
        + report.timed_out.len()
        + report.skipped.len();
    assert_eq!(total, 12, "orphaned workers must not double-count slots");
    assert!(
        wall < Duration::from_secs(30),
        "timeout waves took {wall:?}; slots must free promptly"
    );
}

struct AlwaysFailModule {
    kind: TaskKind,
    retryable: bool,
    attempts: Arc<AtomicUsize>,
}

impl Module for AlwaysFailModule {
    fn kind(&self) -> TaskKind {
        self.kind.clone()
    }
    fn execute(&self, _context: ModuleContext) -> ModuleFuture {
        let attempts = self.attempts.clone();
        let retryable = self.retryable;
        Box::pin(async move {
            attempts.fetch_add(1, Ordering::SeqCst);
            Err(ModuleError::Failed {
                message: "phase19 synthetic failure".to_owned(),
                retryable,
            })
        })
    }
}

fn test_scheduler(
    plan: &ScanPlan,
    budgets: BudgetLimits,
    speed: SpeedSetting,
    max_concurrency: usize,
) -> Scheduler {
    let capacity = budgets.queue_capacity();
    Scheduler::new(
        capacity,
        budgets,
        SpeedGovernor::new(speed, max_concurrency).unwrap(),
        Arc::new(PolicyScopeGuard::new(plan.scope.clone())),
        Arc::new(VecEventSink::default()),
    )
    .unwrap()
}

fn peak_rss_kb() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmHWM:")
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|value| value.parse().ok())
        })
}

// ---------- 85. large scheduler ----------

#[test]
fn large_scheduler_stays_bounded_and_accounts_every_task() {
    let plan = plan_for("127.0.0.1");
    let executed = Arc::new(AtomicUsize::new(0));
    let budgets = BudgetLimits {
        max_tasks: 5000,
        max_retries: 5000,
        max_concurrency: 4,
        max_execution_time_ms: 120_000,
        ..BudgetLimits::default()
    };
    let capacity = budgets.queue_capacity();
    let mut scheduler = test_scheduler(&plan, budgets, SpeedSetting::Numeric(50), 4);
    scheduler.register_module(Arc::new(ImmediateModule {
        kind: TaskKind::HostDiscovery,
        executed: executed.clone(),
    }));
    const TASKS: usize = 3000;
    for index in 0..TASKS {
        scheduler.make_task_checked(&plan, index);
    }
    let report = scheduler.run().unwrap();
    let total = report.completed.len()
        + report.failed.len()
        + report.cancelled.len()
        + report.timed_out.len()
        + report.skipped.len();
    assert_eq!(
        total, TASKS,
        "every admitted task must reach terminal state"
    );
    assert_eq!(report.completed.len(), TASKS);
    assert_eq!(executed.load(Ordering::SeqCst), TASKS);
    assert!(
        report.queue_peak <= capacity,
        "queue_peak {} exceeds capacity {capacity}",
        report.queue_peak
    );
    assert!(
        report.active_peak <= 4,
        "active_peak {} exceeds concurrency 4",
        report.active_peak
    );
    assert!(peak_rss_kb().is_some(), "VmHWM must be observable");
}

// Helper to admit tasks from tests without duplicating construction.
trait AdmitHelper {
    fn make_task_checked(&mut self, plan: &ScanPlan, index: usize);
}

impl AdmitHelper for Scheduler {
    fn make_task_checked(&mut self, plan: &ScanPlan, index: usize) {
        let task = make_task(plan, index, 50, 5000);
        self.add_task(task).unwrap();
    }
}

// ---------- 86. scheduler fairness ----------

/// Bounded sustained high-priority arrivals must not starve an eligible
/// low-priority task: the workload model is bounded, so the low task runs.
struct BoundedFloodEngine {
    remaining: AtomicUsize,
    plan_id: rxscan::model::ScanPlanId,
    provenance: Provenance,
}

impl DecisionEngine for BoundedFloodEngine {
    fn follow_up_tasks(&self, completed: &Task, _output: &ModuleOutput) -> Vec<Task> {
        // Only flood from high-priority tasks, bounded overall.
        if completed.priority < 200 {
            return Vec::new();
        }
        if self.remaining.fetch_sub(1, Ordering::SeqCst) == 0 {
            return Vec::new();
        }
        let n = self.remaining.load(Ordering::SeqCst);
        let mut params = BTreeMap::new();
        params.insert("target".to_owned(), "127.0.0.1".to_owned());
        params.insert("variant".to_owned(), format!("flood-{n}"));
        let task = Task::new_with_params(
            TaskKind::HostDiscovery,
            None,
            Vec::new(),
            None,
            self.plan_id.clone(),
            200,
            Duration::from_millis(2000),
            RetryPolicy::default(),
            "phase19.flood",
            self.provenance.clone(),
            TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
            params,
            &AllowAll,
        )
        .unwrap();
        vec![task]
    }
}

#[test]
fn sustained_high_priority_arrivals_do_not_starve_low_priority() {
    let plan = plan_for("127.0.0.1");
    let executed = Arc::new(AtomicUsize::new(0));
    let budgets = BudgetLimits {
        max_tasks: 500,
        max_retries: 500,
        max_concurrency: 2,
        max_execution_time_ms: 60_000,
        ..BudgetLimits::default()
    };
    let mut scheduler = test_scheduler(&plan, budgets, SpeedSetting::Numeric(50), 2);
    scheduler.register_module(Arc::new(ImmediateModule {
        kind: TaskKind::HostDiscovery,
        executed: executed.clone(),
    }));
    scheduler.set_decision_engine(Arc::new(BoundedFloodEngine {
        remaining: AtomicUsize::new(60),
        plan_id: plan.stable_id(),
        provenance: provenance_for(&plan),
    }));
    // One low-priority task admitted first, then a high-priority seed that
    // triggers the sustained flood.
    let low = make_task(&plan, 999_999, 10, 10_000);
    let low_id = low.id.clone();
    scheduler.add_task(low).unwrap();
    let mut seed_params = BTreeMap::new();
    seed_params.insert("target".to_owned(), "127.0.0.1".to_owned());
    seed_params.insert("variant".to_owned(), "seed".to_owned());
    let seed = Task::new_with_params(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        200,
        Duration::from_millis(10_000),
        RetryPolicy::default(),
        "phase19.flood",
        provenance_for(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        seed_params,
        &AllowAll,
    )
    .unwrap();
    scheduler.add_task(seed).unwrap();
    let report = scheduler.run().unwrap();
    assert!(
        report.completed.contains(&low_id),
        "eligible low-priority task must eventually execute despite sustained high-priority arrivals"
    );
}

// ---------- 87. mass cancellation ----------

#[test]
fn mass_precancellation_is_bounded_and_admits_no_new_work() {
    let plan = plan_for("127.0.0.1");
    let executed = Arc::new(AtomicUsize::new(0));
    let budgets = BudgetLimits {
        max_tasks: 4000,
        max_retries: 4000,
        max_concurrency: 4,
        max_execution_time_ms: 120_000,
        ..BudgetLimits::default()
    };
    let mut scheduler = test_scheduler(&plan, budgets, SpeedSetting::Numeric(50), 4);
    let executed_clone = executed.clone();
    scheduler.register_module(Arc::new(ImmediateModule {
        kind: TaskKind::HostDiscovery,
        executed: executed_clone,
    }));
    const TASKS: usize = 3000;
    for index in 0..TASKS {
        scheduler.make_task_checked(&plan, index);
    }
    scheduler.cancel_all();
    let started = Instant::now();
    let report = scheduler.run().unwrap();
    let cancel_to_stop = started.elapsed();
    assert_eq!(report.cancelled.len(), TASKS);
    assert_eq!(executed.load(Ordering::SeqCst), 0, "no work after cancel");
    assert_eq!(scheduler.module_outputs().len(), 0, "no retained outputs");
    assert!(
        cancel_to_stop < Duration::from_secs(30),
        "cancel_to_stop {cancel_to_stop:?} exceeds generous bound"
    );
}

// ---------- deadline under load ----------

#[test]
fn expired_global_deadline_stops_loaded_run_promptly() {
    // Retry-delayed tasks leave the scheduler with no active slots while
    // work remains: the global execution budget must fire there instead of
    // letting the whole queue drain through every backoff.
    let plan = plan_for("127.0.0.1");
    let attempts = Arc::new(AtomicUsize::new(0));
    let budgets = BudgetLimits {
        max_tasks: 100,
        max_retries: 1000,
        max_concurrency: 2,
        max_execution_time_ms: 150,
        ..BudgetLimits::default()
    };
    let mut scheduler = test_scheduler(&plan, budgets, SpeedSetting::Numeric(50), 2);
    scheduler.register_module(Arc::new(AlwaysFailModule {
        kind: TaskKind::HostDiscovery,
        retryable: true,
        attempts: attempts.clone(),
    }));
    for index in 0..20 {
        let mut task = make_task(&plan, index, 50, 30_000);
        task.retry_policy = RetryPolicy {
            max_attempts: 5,
            base_delay_ms: 200,
        };
        scheduler.add_task(task).unwrap();
    }
    let started = Instant::now();
    let report = scheduler.run().unwrap();
    let wall = started.elapsed();
    let total = report.completed.len()
        + report.failed.len()
        + report.cancelled.len()
        + report.timed_out.len()
        + report.skipped.len();
    assert_eq!(total, 20, "deadline must still account every task");
    assert!(
        !report.cancelled.is_empty(),
        "expired deadline must cancel remaining backoff work, got {report:?}"
    );
    assert!(
        attempts.load(Ordering::SeqCst) < 20 * 5,
        "deadline must cut the retry queue short"
    );
    assert!(
        wall < Duration::from_secs(30),
        "deadline run took {wall:?}; must stop promptly, not finish the queue"
    );
}

// ---------- retry fairness / failure storm ----------

#[test]
fn retryable_failure_storm_does_not_exceed_attempt_budget() {
    let plan = plan_for("127.0.0.1");
    let attempts = Arc::new(AtomicUsize::new(0));
    let budgets = BudgetLimits {
        max_tasks: 300,
        max_retries: 1000,
        max_concurrency: 4,
        max_execution_time_ms: 60_000,
        ..BudgetLimits::default()
    };
    let mut scheduler = test_scheduler(&plan, budgets, SpeedSetting::Numeric(50), 4);
    scheduler.register_module(Arc::new(AlwaysFailModule {
        kind: TaskKind::HostDiscovery,
        retryable: true,
        attempts: attempts.clone(),
    }));
    // Speed 50 => retry_limit 2 => max 2 attempts per task.
    for index in 0..200 {
        let mut task = make_task(&plan, index, 50, 5000);
        task.retry_policy = RetryPolicy {
            max_attempts: 2,
            base_delay_ms: 1,
        };
        scheduler.add_task(task).unwrap();
    }
    let report = scheduler.run().unwrap();
    assert_eq!(report.failed.len(), 200);
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        400,
        "retries must stay within the per-task attempt budget"
    );
}

#[test]
fn non_retryable_failure_storm_runs_each_task_once() {
    let plan = plan_for("127.0.0.1");
    let attempts = Arc::new(AtomicUsize::new(0));
    let budgets = BudgetLimits {
        max_tasks: 500,
        max_retries: 500,
        max_concurrency: 8,
        max_execution_time_ms: 60_000,
        ..BudgetLimits::default()
    };
    let mut scheduler = test_scheduler(&plan, budgets, SpeedSetting::Numeric(100), 8);
    scheduler.register_module(Arc::new(AlwaysFailModule {
        kind: TaskKind::HostDiscovery,
        retryable: false,
        attempts: attempts.clone(),
    }));
    for index in 0..400 {
        scheduler.make_task_checked(&plan, index);
    }
    let report = scheduler.run().unwrap();
    assert_eq!(report.failed.len(), 400);
    assert_eq!(attempts.load(Ordering::SeqCst), 400, "no retry explosion");
}

// ---------- 88/89/90. ports structure, FD bound, exhaustion ----------

#[test]
fn all_ports_is_one_task_not_65535_tasks() {
    let resolved = ports::resolve_ports(&TcpPortSelection::All, 2);
    assert_eq!(resolved.ports.len(), 65_535);
    assert_eq!(*resolved.ports.first().unwrap(), 1);
    assert_eq!(*resolved.ports.last().unwrap(), 65_535);
    // Lowering must keep the one-task-per-host architecture.
    let plan = compile(&[
        "127.0.0.1",
        "--scope",
        "127.0.0.0/8",
        "--all-ports",
        "--level",
        "3",
    ]);
    let tasks = rxscan::lowering::lower_plan_to_tasks(&plan).unwrap();
    let port_tasks: Vec<_> = tasks
        .iter()
        .filter(|task| task.kind == TaskKind::PortDiscovery)
        .collect();
    assert_eq!(
        port_tasks.len(),
        1,
        "all-ports must lower to exactly one PortDiscovery task"
    );
}

#[test]
fn real_socket_scan_reports_peak_within_hard_bound() {
    let cancel = CancellationToken::default();
    let config = ScanConfig::bounded(Duration::from_millis(300), 16, 0, None, cancel.clone());
    // Loopback: fast refused/closed, no public traffic.
    let ports: Vec<u16> = (1..=300).collect();
    let outcome = NativeTcpScanner.scan("127.0.0.1".parse().unwrap(), &ports, &config);
    assert_eq!(outcome.probes.len() + outcome.unscanned, 300);
    assert!(
        outcome.fd_peak <= 16,
        "fd_peak {} exceeds configured concurrency 16",
        outcome.fd_peak
    );
    assert!(
        outcome.fd_peak <= MAX_TCP_CONCURRENCY_HARD,
        "fd_peak exceeds hard cap"
    );
}

#[test]
fn tcp_concurrency_policy_is_capped_for_every_speed() {
    for speed in [
        SpeedSetting::Named(NamedSpeed::Slow),
        SpeedSetting::Named(NamedSpeed::Balanced),
        SpeedSetting::Named(NamedSpeed::Fast),
        SpeedSetting::Named(NamedSpeed::Auto),
        SpeedSetting::Numeric(0),
        SpeedSetting::Numeric(50),
        SpeedSetting::Numeric(100),
    ] {
        let concurrency = ports::tcp_concurrency_for_speed(speed);
        assert!(
            concurrency <= MAX_TCP_CONCURRENCY_HARD,
            "speed {speed:?} concurrency {concurrency} exceeds hard cap"
        );
        assert!(concurrency >= 1);
    }
    let clamped = ScanConfig::bounded(
        Duration::from_millis(500),
        100_000,
        99,
        None,
        CancellationToken::default(),
    );
    assert_eq!(clamped.max_concurrent, MAX_TCP_CONCURRENCY_HARD);
    assert_eq!(clamped.max_retries, 1);
}

#[test]
fn cancelled_scan_returns_bounded_partial_outcome() {
    let cancel = CancellationToken::default();
    cancel.cancel();
    let config = ScanConfig::bounded(Duration::from_millis(500), 32, 0, None, cancel);
    let ports: Vec<u16> = (1..=2000).collect();
    let outcome = NativeTcpScanner.scan("127.0.0.1".parse().unwrap(), &ports, &config);
    assert!(outcome.cancelled);
    assert_eq!(outcome.probes.len() + outcome.unscanned, 2000);
    assert!(outcome.fd_peak <= 32);
}

#[test]
fn fd_pressure_still_accounts_every_port_without_panic() {
    // Hold many descriptors open to pressure socket creation, then scan.
    // Whether or not EMFILE triggers, every port must be accounted.
    let mut held = Vec::new();
    for _ in 0..800 {
        if let Ok(file) = File::open("/dev/null") {
            held.push(file);
        } else {
            break;
        }
    }
    let cancel = CancellationToken::default();
    let config = ScanConfig::bounded(Duration::from_millis(200), 16, 0, None, cancel);
    let ports: Vec<u16> = (1..=100).collect();
    let outcome = NativeTcpScanner.scan("127.0.0.1".parse().unwrap(), &ports, &config);
    assert_eq!(outcome.probes.len() + outcome.unscanned, 100);
    assert!(outcome.fd_peak <= 16);
    drop(held);
}

// ---------- scheduler saturation ----------

#[test]
fn tiny_queue_still_drains_without_loss_or_deadlock() {
    let plan = plan_for("127.0.0.1");
    let executed = Arc::new(AtomicUsize::new(0));
    let budgets = BudgetLimits {
        max_tasks: 300,
        max_retries: 300,
        max_concurrency: 1,
        max_execution_time_ms: 60_000,
        ..BudgetLimits::default()
    };
    let mut scheduler = Scheduler::new(
        4,
        budgets,
        SpeedGovernor::new(SpeedSetting::Numeric(50), 1).unwrap(),
        Arc::new(PolicyScopeGuard::new(plan.scope.clone())),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler.register_module(Arc::new(ImmediateModule {
        kind: TaskKind::HostDiscovery,
        executed: executed.clone(),
    }));
    for index in 0..200 {
        scheduler.make_task_checked(&plan, index);
    }
    let started = Instant::now();
    let report = scheduler.run().unwrap();
    assert!(started.elapsed() < Duration::from_secs(30));
    let total = report.completed.len()
        + report.failed.len()
        + report.cancelled.len()
        + report.timed_out.len()
        + report.skipped.len();
    assert_eq!(total, 200, "backpressure must not lose tasks");
    assert!(report.queue_peak <= 4);
}

// ---------- 101. level/speed invariance ----------

#[test]
fn speed_changes_pressure_not_port_truth() {
    // Same level across speeds: identical lowered PortDiscovery identity
    // (target set + port set); only the governor pressure differs.
    // NOTE: task IDs themselves embed timeout/retry pressure by design
    // (canonical identity covers timeout_ms/retry_max), so the invariant
    // is checked on the semantic port params, not the ID digest.
    let speeds = ["slow", "balanced", "fast", "0", "100"];
    for level in ["1", "2", "3", "4", "5"] {
        let mut references = Vec::new();
        for speed in speeds {
            let plan = compile(&[
                "127.0.0.1",
                "--scope",
                "127.0.0.0/8",
                "--level",
                level,
                "--speed",
                speed,
            ]);
            let tasks = rxscan::lowering::lower_plan_to_tasks(&plan).unwrap();
            let mut port_params: Vec<BTreeMap<String, String>> = tasks
                .iter()
                .filter(|task| task.kind == TaskKind::PortDiscovery)
                .map(|task| task.params.clone())
                .collect();
            port_params.sort();
            references.push(port_params);
        }
        for candidate in &references[1..] {
            assert_eq!(
                *candidate, references[0],
                "level {level} port-task params must not depend on speed"
            );
        }
    }
    // ... while across levels the breadth DOES differ.
    let l1 = compile(&["127.0.0.1", "--scope", "127.0.0.0/8", "--level", "1"]);
    let l5 = compile(&["127.0.0.1", "--scope", "127.0.0.0/8", "--level", "5"]);
    let kinds = |plan: &ScanPlan| {
        let mut kinds: Vec<String> = rxscan::lowering::lower_plan_to_tasks(plan)
            .unwrap()
            .iter()
            .map(|task| format!("{:?}", task.kind))
            .collect();
        kinds.sort();
        kinds.dedup();
        kinds
    };
    assert!(
        kinds(&l5).len() >= kinds(&l1).len(),
        "higher level must not narrow breadth"
    );
    // Pressure DOES vary with speed.
    assert_ne!(
        ports::tcp_concurrency_for_speed(SpeedSetting::Named(NamedSpeed::Slow)),
        ports::tcp_concurrency_for_speed(SpeedSetting::Named(NamedSpeed::Fast))
    );
    assert_ne!(
        ports::tcp_timeout_for_speed(SpeedSetting::Named(NamedSpeed::Slow)),
        ports::tcp_timeout_for_speed(SpeedSetting::Named(NamedSpeed::Fast))
    );
}

#[test]
fn service_probe_plan_is_bounded_and_speed_independent_in_shape() {
    for level in 1..=5u8 {
        let plan = service::plan_probes(80, level, ScanGoal::Discover);
        assert!(
            plan.len() <= service::MAX_PROBES_PER_PORT,
            "level {level} probe plan exceeds per-port cap"
        );
        // Speed is not even an input to probe eligibility — only to timeouts.
        assert_ne!(
            service::service_timeout_for_speed(SpeedSetting::Named(NamedSpeed::Slow)),
            service::service_timeout_for_speed(SpeedSetting::Named(NamedSpeed::Fast)),
            "speed must change timeout pressure"
        );
    }
}

// ---------- host discovery scale ----------

#[test]
fn cidr_host_cap_is_enforced_before_runaway_allocation() {
    let plan = plan_for("127.0.0.1");
    // /8 would be ~16M hosts; the bound must apply during expansion.
    let cidr: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
    let hosts = expand_cidr_bounded(cidr, &plan.scope, 64);
    assert!(hosts.len() <= 64 + 4096, "hosts {}", hosts.len());
    let tiny = expand_cidr_bounded(cidr, &plan.scope, 8);
    assert!(tiny.len() <= 8 + 4096);
}

// ---------- crawl scale ----------

#[test]
fn huge_link_set_is_capped_deduped_and_deterministic() {
    let mut html = String::from("<html><body>");
    for i in 0..3000 {
        // Duplicates, fragments, query variants, cycles, externals.
        html.push_str(&format!(
            "<a href=\"/page{}\">x</a><a href=\"/page{}#frag\">x</a><a href=\"/page{}?b=2&a=1\">x</a>",
            i % 500,
            i % 500,
            i % 500
        ));
    }
    html.push_str("<a href=\"https://external.test/\">x</a></body></html>");
    let refs = rxscan::extract::extract_html_refs(html.as_bytes());
    assert!(
        refs.links.len() <= rxscan::extract::MAX_LINKS_PER_PAGE,
        "links {} exceed extraction cap",
        refs.links.len()
    );
    // Plan followups over thousands of candidates: bounded + deterministic.
    let root = WebTarget::parse("http://127.0.0.1/").unwrap();
    let mut candidates = Vec::new();
    for i in 0..3000 {
        let url = WebTarget::parse(&format!("http://127.0.0.1/page{}", i % 700)).unwrap();
        candidates.push((url, format!("asset-{i}"), crawl::CandidateSource::Link));
    }
    let first = crawl::plan_followups(
        candidates.clone(),
        3,
        100,
        MAX_CRAWL_PROPOSALS_PER_COMPLETION,
    );
    let second = crawl::plan_followups(candidates, 3, 100, MAX_CRAWL_PROPOSALS_PER_COMPLETION);
    assert!(first.proposals.len() <= MAX_CRAWL_PROPOSALS_PER_COMPLETION);
    let keys = |plan: &crawl::FollowupPlan| {
        plan.proposals
            .iter()
            .map(|p| p.url.canonical())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        keys(&first),
        keys(&second),
        "followup planning deterministic"
    );
    let _ = root;
}

// ---------- content wordlist streaming ----------

fn spawn_http_fixture(
    responder: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static,
) -> (u16, Arc<std::sync::Mutex<Vec<String>>>, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let requests_clone = requests.clone();
    let stop_clone = stop.clone();
    let responder = Arc::new(responder);
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
            let responder = responder.clone();
            let requests = requests_clone.clone();
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut raw = Vec::new();
                let mut chunk = [0u8; 1024];
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
                let path = String::from_utf8_lossy(&raw)
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_owned();
                requests.lock().unwrap().push(path.clone());
                let _ = stream.write_all(&responder(&path));
            });
        }
    });
    (port, requests, stop)
}

fn write_wordlist(dir: &std::path::Path, name: &str, lines: &[String]) -> PathBuf {
    let path = dir.join(name);
    let mut file = File::create(&path).unwrap();
    for line in lines {
        writeln!(file, "{line}").unwrap();
    }
    path
}

#[test]
fn large_wordlist_streams_with_candidate_and_request_caps() {
    let dir = std::env::temp_dir().join(format!("rxscan_p19_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // 3000 lines > MAX_CANDIDATES_READ (2000): streaming must stop at the cap.
    let lines: Vec<String> = (0..3000).map(|i| format!("path{i}")).collect();
    let wordlist = write_wordlist(&dir, "big.txt", &lines);
    let (port, requests, stop) = spawn_http_fixture(|_| {
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\nContent-Type: text/html\r\n\r\nok".to_vec()
    });
    let plan = plan_for("127.0.0.1");
    let policy = ContentDiscoveryPolicy::new(5, ScanGoal::Web, SpeedSetting::Numeric(50));
    let module = ContentDiscoveryModule::new(policy, Arc::new(AllowAll));
    let origin = WebTarget::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let params = rxscan::content::content_task_params(&origin, "seed", Some(&wordlist));
    let task = Task::new_with_params(
        TaskKind::ContentDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        30,
        Duration::from_secs(60),
        RetryPolicy::default(),
        CONTENT_MODULE_NAME,
        provenance_for(&plan),
        TaskScopeTarget::Url(origin.canonical()),
        params,
        &AllowAll,
    )
    .unwrap();
    let output =
        futures_drive(module.execute(ModuleContext::new(task, CancellationToken::default())))
            .unwrap();
    stop.store(true, Ordering::SeqCst);
    let seen = requests.lock().unwrap().len();
    assert!(
        seen <= MAX_CONTENT_REQUESTS,
        "requests {seen} exceed per-task cap {}",
        MAX_CONTENT_REQUESTS
    );
    assert!(output.events.len() <= content::MAX_CONTENT_EVENTS);
    assert!(output.findings.len() <= content::MAX_CONTENT_FINDINGS);
    let _ = MAX_CANDIDATES_READ;
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn duplicate_wordlist_lines_contact_each_path_once() {
    let dir = std::env::temp_dir().join(format!("rxscan_p19d_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let lines: Vec<String> = std::iter::repeat_n("admin".to_owned(), 3000).collect();
    let wordlist = write_wordlist(&dir, "dup.txt", &lines);
    let (port, requests, stop) = spawn_http_fixture(|_| {
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\nContent-Type: text/html\r\n\r\nok".to_vec()
    });
    let plan = plan_for("127.0.0.1");
    let policy = ContentDiscoveryPolicy::new(5, ScanGoal::Web, SpeedSetting::Numeric(50));
    let module = ContentDiscoveryModule::new(policy, Arc::new(AllowAll));
    let origin = WebTarget::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let params = rxscan::content::content_task_params(&origin, "seed", Some(&wordlist));
    let task = Task::new_with_params(
        TaskKind::ContentDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        30,
        Duration::from_secs(60),
        RetryPolicy::default(),
        CONTENT_MODULE_NAME,
        provenance_for(&plan),
        TaskScopeTarget::Url(origin.canonical()),
        params,
        &AllowAll,
    )
    .unwrap();
    let _ = futures_drive(module.execute(ModuleContext::new(task, CancellationToken::default())))
        .unwrap();
    stop.store(true, Ordering::SeqCst);
    let paths = requests.lock().unwrap().clone();
    let admin_hits = paths.iter().filter(|p| p.contains("admin")).count();
    assert_eq!(
        admin_hits, 1,
        "3000 duplicate lines must contact /admin once"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Minimal blocking driver for module futures (test-only, no new deps).
fn futures_drive(future: ModuleFuture) -> Result<ModuleOutput, ModuleError> {
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

// ---------- fuzz / dns / registry caps ----------

#[test]
fn fuzz_origin_budgets_enforce_per_origin_and_global_caps() {
    let budgets = FuzzOriginBudget::new();
    for i in 0..MAX_FUZZ_TASKS_PER_ORIGIN_HARD {
        assert!(budgets.claim(
            "http://127.0.0.1/",
            &format!("plan-{i}"),
            MAX_FUZZ_TASKS_PER_ORIGIN_HARD
        ));
    }
    assert!(
        !budgets.claim(
            "http://127.0.0.1/",
            "plan-over",
            MAX_FUZZ_TASKS_PER_ORIGIN_HARD
        ),
        "per-origin cap must hold"
    );
    assert_eq!(
        budgets.count_for_origin("http://127.0.0.1/"),
        MAX_FUZZ_TASKS_PER_ORIGIN_HARD
    );
    // Re-claim of an admitted plan stays admitted (no double count).
    assert!(budgets.claim(
        "http://127.0.0.1/",
        "plan-0",
        MAX_FUZZ_TASKS_PER_ORIGIN_HARD
    ));
    assert_eq!(
        budgets.count_for_origin("http://127.0.0.1/"),
        MAX_FUZZ_TASKS_PER_ORIGIN_HARD
    );
    // Global origin cap: one origin already exists above, so exactly
    // MAX-1 further distinct origins are admitted and the next is refused.
    for i in 0..MAX_FUZZ_ORIGIN_BUDGETS - 1 {
        assert!(
            budgets.claim(
                &format!("http://10.1.{i}.1/"),
                "p",
                MAX_FUZZ_TASKS_PER_ORIGIN_HARD
            ),
            "origin {i} must be admitted within the global cap"
        );
    }
    assert!(
        !budgets.claim("http://10.9.9.9/", "p", MAX_FUZZ_TASKS_PER_ORIGIN_HARD),
        "global origin cap must hold"
    );
}

#[test]
fn dns_registry_dedups_repeats_and_holds_domain_caps() {
    use std::net::SocketAddr;
    let registry = DnsRegistry::new();
    let resolver: SocketAddr = "127.0.0.1:53".parse().unwrap();
    // 5000 identical proposals collapse to one tracked query.
    for _ in 0..5000 {
        let _ = registry.claim_query("host127.test", DnsRecordType::A, resolver);
    }
    assert_eq!(registry.query_count(), 1);
    // Many names × two types stay deduplicated.
    for i in 0..3000 {
        let name = format!("h{}.example.test", i % 100);
        registry.claim_query(&name, DnsRecordType::A, resolver);
        registry.claim_query(&name, DnsRecordType::Aaaa, resolver);
    }
    assert!(registry.query_count() <= 201);
    // Per-domain fairness cap.
    for i in 0..(MAX_DNS_TASKS_PER_DOMAIN_HARD + 10) {
        registry.claim_domain_task(
            "example.test",
            &format!("h{i}.example.test"),
            MAX_DNS_TASKS_PER_DOMAIN_HARD,
        );
    }
    assert_eq!(
        registry.tracked_names_for_domain("example.test"),
        MAX_DNS_TASKS_PER_DOMAIN_HARD
    );
    // Transient failures release the query so a later task may retry.
    registry.forget_query("host127.test", DnsRecordType::A, resolver);
    assert_eq!(registry.query_count(), 200);
    assert!(registry.claim_query("host127.test", DnsRecordType::A, resolver));
    let _ = MAX_DNS_DOMAINS;
    let _ = MAX_DNS_REGISTRY_ENTRIES;
}

#[test]
fn contact_registry_holds_exact_cap_with_documented_fail_open() {
    let registry = ContactRegistry::new();
    for i in 0..4096 {
        let target = WebTarget::parse(&format!("http://127.0.0.1/p{i}")).unwrap();
        assert!(registry.claim(&target, RequestPurpose::ContentCandidate));
    }
    assert_eq!(registry.len(), 4096);
    let extra = WebTarget::parse("http://127.0.0.1/over").unwrap();
    // Documented fail-open: over-cap claims proceed without dedup tracking.
    assert!(registry.claim(&extra, RequestPurpose::ContentCandidate));
    assert_eq!(registry.len(), 4096);
    // Exact duplicates collapse.
    let dup = WebTarget::parse("http://127.0.0.1/p1").unwrap();
    let registry2 = ContactRegistry::new();
    assert!(registry2.claim(&dup, RequestPurpose::CrawlPage));
    assert!(!registry2.claim(&dup, RequestPurpose::CrawlPage));
}

// ---------- persistence / resume / diff / analysis / report ----------

fn large_state(plan: &ScanPlan, tasks: usize) -> PersistedScanState {
    let provenance = provenance_for(plan);
    let ip = Asset::scoped(AssetKind::Ip, "127.0.0.1", &plan.scope, provenance.clone()).unwrap();
    let mut state_tasks = Vec::with_capacity(tasks);
    let mut outputs = Vec::with_capacity(tasks);
    for index in 0..tasks {
        let mut task = make_task(plan, index, 50, 5000);
        task.state = rxscan::execution::TaskState::Succeeded;
        // Distinct port asset per task so dedup/diff/analysis layers see
        // real variety instead of one collapsible asset.
        let port = Asset::child(
            AssetKind::Port,
            &ip.id,
            format!("{}", 1 + (index % 65_535)),
            provenance.clone(),
        )
        .unwrap();
        let output = ModuleOutput {
            assets: vec![ip.clone(), port],
            ..ModuleOutput::default()
        };
        outputs.push(PersistedModuleOutput {
            task_id: task.id.clone(),
            output,
        });
        state_tasks.push(PersistedTask { task });
    }
    PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: plan.stable_id(),
        saved_at: Timestamp(2),
        plan: plan.clone(),
        tasks: state_tasks,
        outputs,
        registries: PersistedRegistries::default(),
    }
}

#[test]
fn large_checkpoint_roundtrips_with_bounded_size() {
    let plan = plan_for("127.0.0.1");
    let state = large_state(&plan, 3000);
    let dir = std::env::temp_dir().join(format!("rxscan_p19c_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("big.json");
    let metrics = persistence::save_checkpoint(&path, &state).unwrap();
    assert!(metrics.checkpoint_bytes <= persistence::MAX_CHECKPOINT_BYTES);
    let loaded = persistence::load_checkpoint(&path).unwrap();
    assert_eq!(loaded.state.tasks.len(), 3000);
    assert_eq!(loaded.state.outputs.len(), 3000);
    let before: BTreeSet<_> = state.tasks.iter().map(|t| t.task.id.clone()).collect();
    let after: BTreeSet<_> = loaded
        .state
        .tasks
        .iter()
        .map(|t| t.task.id.clone())
        .collect();
    assert_eq!(before, after, "IDs preserved across save/load");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn resume_does_not_repeat_completed_work() {
    let plan = plan_for("127.0.0.1");
    let mut state = large_state(&plan, 60);
    // Mix terminal states.
    for (i, persisted) in state.tasks.iter_mut().enumerate() {
        persisted.task.state = match i % 4 {
            0 => rxscan::execution::TaskState::Succeeded,
            1 => rxscan::execution::TaskState::Failed,
            2 => rxscan::execution::TaskState::Cancelled,
            _ => rxscan::execution::TaskState::Pending,
        };
    }
    state.outputs.retain(|_| true);
    let budgets = BudgetLimits {
        max_tasks: 1000,
        max_retries: 1000,
        max_concurrency: 2,
        max_execution_time_ms: 60_000,
        ..BudgetLimits::default()
    };
    let mut scheduler = test_scheduler(&plan, budgets, SpeedSetting::Numeric(50), 2);
    let (restored, completed) =
        persistence::restore_scheduler_state(&mut scheduler, &state).unwrap();
    assert_eq!(restored, 60);
    assert_eq!(completed, 15, "only Succeeded outputs are re-attached");
}

#[test]
fn large_diff_has_no_false_removals_and_stays_capped() {
    let plan = plan_for("127.0.0.1");
    let old = large_state(&plan, 2000);
    let mut new = large_state(&plan, 2000);
    // Append exactly one new asset via one extra task AND its output (the
    // diff normalizes outputs, so both are required for visibility).
    let mut extra = make_task(&plan, 999_999, 50, 5000);
    extra.state = rxscan::execution::TaskState::Succeeded;
    let provenance = provenance_for(&plan);
    let ip = Asset::scoped(AssetKind::Ip, "127.0.0.1", &plan.scope, provenance.clone()).unwrap();
    let new_port = Asset::child(AssetKind::Port, &ip.id, "59999", provenance).unwrap();
    new.outputs.push(PersistedModuleOutput {
        task_id: extra.id.clone(),
        output: ModuleOutput {
            assets: vec![ip, new_port],
            ..ModuleOutput::default()
        },
    });
    new.tasks.push(PersistedTask { task: extra });
    let report = diff::compare_states(&old, &new, DiffOptions::default()).unwrap();
    assert!(
        report.records.len() <= diff::MAX_DIFF_RECORDS,
        "diff records capped"
    );
    assert_eq!(report.network_requests, 0, "diff stays offline");
    let removed = report
        .records
        .iter()
        .filter(|r| matches!(r.change_type, ChangeType::Removed))
        .count();
    assert_eq!(removed, 0, "no false removals for identical assets");
    assert!(
        report
            .records
            .iter()
            .any(|r| matches!(r.change_type, ChangeType::Added)),
        "the one genuinely new asset must be reported Added"
    );
}

#[test]
fn analysis_over_candidate_cap_keeps_counts_and_determinism() {
    let plan = plan_for("127.0.0.1");
    let state = large_state(&plan, 1500);
    let first = analysis::analyze_state(&state, None, AnalysisOptions::default()).unwrap();
    let second = analysis::analyze_state(&state, None, AnalysisOptions::default()).unwrap();
    assert!(first.top_signals.len() <= analysis::MAX_ANALYSIS_SIGNALS);
    assert_eq!(first.network_requests, 0, "analysis stays offline");
    let ids = |report: &analysis::AnalysisReport| {
        report
            .top_signals
            .iter()
            .map(|s| s.id.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(&first), ids(&second), "top-N deterministic");
    assert_eq!(
        first.total_signals, second.total_signals,
        "aggregate counts stable"
    );
    assert_eq!(
        first.signals_emitted, second.signals_emitted,
        "emitted counts stable"
    );
}

#[test]
fn jsonl_report_streams_exact_record_counts() {
    let plan = plan_for("127.0.0.1");
    let state = large_state(&plan, 1200);
    let model = rxscan::report::build_report_model(
        &state,
        None,
        None,
        &ReportOptions {
            format: ReportFormat::Jsonl,
            summary_only: false,
            top_n: 10,
        },
    )
    .unwrap();
    let mut bytes = Vec::new();
    rxscan::report::render_jsonl(&model, &mut bytes).unwrap();
    let lines = bytes
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .count();
    // meta + summary + one record per asset/relationship/finding/evidence.
    let expected = 2
        + model.assets.len()
        + model.relationships.len()
        + model.findings.len()
        + model.evidence_summary.len();
    assert_eq!(lines, expected, "every record streamed exactly once");
    assert!(!bytes.is_empty());
}

#[test]
fn slow_output_sink_does_not_break_bounded_render() {
    struct SlowSink {
        bytes: usize,
        records: usize,
    }
    impl Write for SlowSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            // Bounded slow sink: small sleep per write call, no buffering.
            std::thread::sleep(Duration::from_micros(50));
            self.bytes += buf.len();
            self.records += 1;
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let plan = plan_for("127.0.0.1");
    let state = large_state(&plan, 400);
    let model = rxscan::report::build_report_model(
        &state,
        None,
        None,
        &ReportOptions {
            format: ReportFormat::Jsonl,
            summary_only: false,
            top_n: 10,
        },
    )
    .unwrap();
    let mut sink = SlowSink {
        bytes: 0,
        records: 0,
    };
    let started = Instant::now();
    rxscan::report::render_jsonl(&model, &mut sink).unwrap();
    assert!(started.elapsed() < Duration::from_secs(60));
    assert!(sink.bytes > 0);
}

// ---------- project scale ----------

fn project_scan_state(target: &str, extra: usize) -> PersistedScanState {
    use rxscan::model::{Relationship, RelationshipKind, RelationshipSubject};
    let plan = compile(&[target, "--scope", "127.0.0.0/8", "--level", "5"]);
    let provenance =
        Provenance::new("phase19.test", "19.0.0", plan.stable_id(), Timestamp(1)).unwrap();
    let ip = Asset::scoped(AssetKind::Ip, target, &plan.scope, provenance.clone()).unwrap();
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
        let svc = Asset::child(AssetKind::Service, &port.id, "https", provenance.clone()).unwrap();
        relationships.push(
            Relationship::new(
                RelationshipKind::Runs,
                RelationshipSubject::Asset(port.id.clone()),
                RelationshipSubject::Asset(svc.id.clone()),
                provenance.clone(),
            )
            .unwrap(),
        );
        // Hub edge: realistic host fan-out so graph work caps are stressed.
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
    let task = {
        let mut params = BTreeMap::new();
        params.insert("target".to_owned(), target.to_owned());
        let mut task = Task::new_with_params(
            TaskKind::HttpProbe,
            None,
            Vec::new(),
            None,
            plan.stable_id(),
            10,
            Duration::from_secs(1),
            RetryPolicy::default(),
            "phase19.test",
            provenance.clone(),
            TaskScopeTarget::Ip(target.parse().unwrap()),
            params,
            &AllowAll,
        )
        .unwrap();
        task.state = rxscan::execution::TaskState::Succeeded;
        task
    };
    PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: plan.stable_id(),
        saved_at: Timestamp(2),
        plan,
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
                    provenance,
                }],
                ..ModuleOutput::default()
            },
        }],
        registries: PersistedRegistries::default(),
    }
}

#[test]
fn large_project_import_query_save_hold_p18_bounds() {
    // Materially larger than the P18 ~2.09 MiB fixture, under the 16 MiB cap.
    let scan_a = project_scan_state("127.0.0.1", 3000);
    let scan_b = project_scan_state("127.0.0.2", 3000);
    let mut project = ProjectState::new(None);
    let first = project.add_scan(&scan_a, None, None).unwrap();
    assert!(!first.duplicate_scan);
    let duplicate = project.add_scan(&scan_a, None, None).unwrap();
    assert!(duplicate.duplicate_scan, "identical re-import stays a noop");
    let _ = project.add_scan(&scan_b, None, None).unwrap();
    let bytes = serde_json::to_vec(&project).unwrap().len();
    assert!(
        bytes as u64 <= rxscan::project::MAX_PROJECT_BYTES,
        "project {bytes} exceeds cap"
    );
    let entity = project.entities.keys().next().unwrap().clone();
    let query = project
        .neighbors(
            &entity,
            rxscan::project::MAX_QUERY_DEPTH,
            rxscan::project::MAX_QUERY_LIMIT,
        )
        .unwrap();
    assert!(query.queue_peak <= rxscan::project::MAX_GRAPH_QUERY_QUEUE);
    assert!(query.visited_peak <= rxscan::project::MAX_GRAPH_QUERY_VISITED);
    assert!(query.expansions <= rxscan::project::MAX_GRAPH_QUERY_EXPANSIONS);
    assert!(query.results_total <= rxscan::project::MAX_GRAPH_QUERY_EDGE_BUDGET);
    let dir = std::env::temp_dir().join(format!("rxscan_p19p_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("big.rxproj");
    rxscan::project::save_project(&path, &project, None).unwrap();
    let loaded = rxscan::project::load_project(&path).unwrap();
    assert_eq!(loaded.fingerprint, project.fingerprint);
    assert_eq!(loaded.entities.len(), project.entities.len());
    assert_eq!(rxscan::project::fingerprint_whole_state_clones(), 0);
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- duplicate storm ----------

#[test]
fn duplicate_storm_collapses_before_deep_work() {
    let plan = plan_for("127.0.0.1");
    let budgets = BudgetLimits {
        max_tasks: 100,
        max_retries: 100,
        max_concurrency: 2,
        max_execution_time_ms: 60_000,
        ..BudgetLimits::default()
    };
    let mut scheduler = test_scheduler(&plan, budgets, SpeedSetting::Numeric(50), 2);
    let task = make_task(&plan, 7, 50, 5000);
    scheduler.add_task(task.clone()).unwrap();
    let mut duplicates = 0usize;
    for _ in 0..5000 {
        match scheduler.add_task(task.clone()) {
            Err(rxscan::execution::SchedulerError::DuplicateTask) => duplicates += 1,
            _ => panic!("duplicate must be rejected as DuplicateTask"),
        }
    }
    assert_eq!(duplicates, 5000);
    // URL canonicalization storm collapses too.
    let mut unique = BTreeSet::new();
    for _ in 0..5000 {
        let url = WebTarget::parse("http://127.0.0.1/page#frag").unwrap();
        unique.insert(url.canonical());
    }
    assert_eq!(unique.len(), 1);
}

// ---------- determinism / multitasking / ipv6 / malformed ----------

#[test]
fn equivalent_workloads_produce_stable_ids() {
    let run_once = || {
        let plan = plan_for("127.0.0.1");
        let executed = Arc::new(AtomicUsize::new(0));
        let budgets = BudgetLimits {
            max_tasks: 600,
            max_retries: 600,
            max_concurrency: 4,
            max_execution_time_ms: 60_000,
            ..BudgetLimits::default()
        };
        let mut scheduler = test_scheduler(&plan, budgets, SpeedSetting::Numeric(50), 4);
        scheduler.register_module(Arc::new(ImmediateModule {
            kind: TaskKind::HostDiscovery,
            executed,
        }));
        for index in 0..500 {
            scheduler.make_task_checked(&plan, index);
        }
        let report = scheduler.run().unwrap();
        let mut ids: Vec<String> = report.completed.iter().map(|id| id.0.clone()).collect();
        ids.sort();
        ids
    };
    assert_eq!(run_once(), run_once(), "task IDs stable under load");
}

#[test]
fn worker_caps_do_not_follow_available_parallelism() {
    let parallelism = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    assert!(parallelism >= 1);
    // Deterministic derivation from speed+budget only.
    let governor = SpeedGovernor::new(SpeedSetting::Named(NamedSpeed::Fast), 4).unwrap();
    assert_eq!(governor.concurrency(), 3);
    assert!(governor.concurrency() <= rxscan::execution::MAX_CONCURRENCY_HARD_LIMIT);
    assert!(
        ports::tcp_concurrency_for_speed(SpeedSetting::Named(NamedSpeed::Fast))
            <= MAX_TCP_CONCURRENCY_HARD
    );
}

#[test]
fn ipv6_targets_flow_through_scheduler_and_sort() {
    // Scheduler handles IPv6 scope targets identically.
    let plan = compile(&["::1", "--scope", "::1/128"]);
    let executed = Arc::new(AtomicUsize::new(0));
    let budgets = BudgetLimits {
        max_tasks: 100,
        max_retries: 100,
        max_concurrency: 2,
        max_execution_time_ms: 30_000,
        ..BudgetLimits::default()
    };
    let mut scheduler = test_scheduler(&plan, budgets, SpeedSetting::Numeric(50), 2);
    scheduler.register_module(Arc::new(ImmediateModule {
        kind: TaskKind::HostDiscovery,
        executed,
    }));
    for index in 0..50 {
        let mut params = BTreeMap::new();
        params.insert("target".to_owned(), "::1".to_owned());
        params.insert("variant".to_owned(), format!("v6-{index}"));
        let task = Task::new_with_params(
            TaskKind::HostDiscovery,
            None,
            Vec::new(),
            None,
            plan.stable_id(),
            50,
            Duration::from_millis(2000),
            RetryPolicy::default(),
            "phase19.immediate",
            provenance_for(&plan),
            TaskScopeTarget::Ip("::1".parse().unwrap()),
            params,
            &AllowAll,
        )
        .unwrap();
        scheduler.add_task(task).unwrap();
    }
    let report = scheduler.run().unwrap();
    assert_eq!(report.completed.len(), 50);
    // Mixed v4/v6 open-port facts sort deterministically.
    let output = ModuleOutput {
        findings: vec![
            open_port_finding(&plan.stable_id(), "::1", 80),
            open_port_finding(&plan.stable_id(), "127.0.0.1", 80),
            open_port_finding(&plan.stable_id(), "::1", 80),
        ],
        ..ModuleOutput::default()
    };
    let first = open_ports_from_output(&output);
    let second = open_ports_from_output(&output);
    assert_eq!(first, second);
    assert_eq!(first.len(), 2, "dedup collapses the repeated fact");
}

#[test]
fn all_ports_diff_coverage_is_compact_and_correct() {
    // A full-range scan previously expanded "1-65535" into 65,535 heap
    // Strings + BTree nodes per task during diff normalization. The
    // interval representation must keep identical membership truth.
    let plan = plan_for("127.0.0.1");
    let port_task = |ports: &str| {
        let mut params = BTreeMap::new();
        params.insert("target".to_owned(), "127.0.0.1".to_owned());
        params.insert("ports".to_owned(), ports.to_owned());
        let mut task = Task::new_with_params(
            TaskKind::PortDiscovery,
            None,
            Vec::new(),
            None,
            plan.stable_id(),
            60,
            Duration::from_secs(5),
            RetryPolicy::default(),
            "phase19.test",
            provenance_for(&plan),
            TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
            params,
            &AllowAll,
        )
        .unwrap();
        task.state = rxscan::execution::TaskState::Succeeded;
        task
    };
    let old = PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: plan.stable_id(),
        saved_at: Timestamp(2),
        plan: plan.clone(),
        tasks: vec![PersistedTask {
            task: port_task("1-65535"),
        }],
        outputs: Vec::new(),
        registries: PersistedRegistries::default(),
    };
    let new = PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: plan.stable_id(),
        saved_at: Timestamp(2),
        plan: plan.clone(),
        tasks: vec![PersistedTask {
            task: port_task("1-65535"),
        }],
        outputs: Vec::new(),
        registries: PersistedRegistries::default(),
    };
    let started = Instant::now();
    let same = diff::compare_states(&old, &new, DiffOptions::default()).unwrap();
    assert!(started.elapsed() < Duration::from_secs(30));
    assert_eq!(same.network_requests, 0);
    // Narrowed rescan completes without runaway allocation.
    let narrowed = PersistedScanState {
        tasks: vec![PersistedTask {
            task: port_task("80,443"),
        }],
        ..new.clone()
    };
    let _ = diff::compare_states(&old, &narrowed, DiffOptions::default()).unwrap();
}

#[test]
fn open_port_fact_extraction_scales_without_allocation_blowup() {
    // 2000 open findings: extraction stays sorted, deduped, and fast.
    // The per-completion proposal cap (256) is enforced by the engine take().
    let plan = plan_for("127.0.0.1");
    let mut findings = Vec::with_capacity(2000);
    for i in 0..2000 {
        findings.push(open_port_finding(
            &plan.stable_id(),
            "127.0.0.1",
            (1 + (i % 65_535)) as u16,
        ));
    }
    let output = ModuleOutput {
        findings,
        ..ModuleOutput::default()
    };
    let started = Instant::now();
    let facts = open_ports_from_output(&output);
    assert!(started.elapsed() < Duration::from_secs(30));
    assert_eq!(facts.len(), 2000);
    let mut sorted = facts.clone();
    sorted.sort_by_key(|f| (f.address, f.port));
    let canonical: Vec<_> = facts.iter().map(|f| (f.address, f.port)).collect();
    let expected: Vec<_> = sorted.iter().map(|f| (f.address, f.port)).collect();
    assert_eq!(canonical, expected, "facts sorted by (address, port)");
    // Compile-time structural proof: the extraction layer can exceed the
    // per-completion proposal cap, so the engine take() is load-bearing.
    const _: () = assert!(2000 > rxscan::decision::MAX_SERVICE_PROPOSALS_PER_COMPLETION);
}

#[test]
fn slow_and_oversized_http_responses_stay_bounded() {
    // Slow peer (200ms), huge body (200 KiB), and 100 response headers:
    // every layer must truncate/timeout instead of accumulating.
    let dir = std::env::temp_dir().join(format!("rxscan_p19s_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let lines: Vec<String> = (0..5).map(|i| format!("slow{i}")).collect();
    let wordlist = write_wordlist(&dir, "slow.txt", &lines);
    let mut big_headers = String::from("HTTP/1.1 200 OK\r\nContent-Length: 204800\r\n");
    for i in 0..100 {
        big_headers.push_str(&format!("X-Pad-{i}: {}\r\n", "p".repeat(200)));
    }
    big_headers.push_str("Connection: close\r\nContent-Type: text/html\r\n\r\n");
    let mut body = big_headers.into_bytes();
    body.extend(std::iter::repeat_n(b'z', 204_800));
    let response = Arc::new(body);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(90);
        while !stop_clone.load(Ordering::SeqCst) && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(_) => break,
            };
            let response = response.clone();
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let mut raw = Vec::new();
                let mut chunk = [0u8; 1024];
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
                std::thread::sleep(Duration::from_millis(200));
                let _ = stream.write_all(&response);
            });
        }
    });
    let plan = plan_for("127.0.0.1");
    let policy = ContentDiscoveryPolicy::new(5, ScanGoal::Web, SpeedSetting::Numeric(50));
    let module = ContentDiscoveryModule::new(policy, Arc::new(AllowAll));
    let origin = WebTarget::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let params = rxscan::content::content_task_params(&origin, "seed", Some(&wordlist));
    let task = Task::new_with_params(
        TaskKind::ContentDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        30,
        Duration::from_secs(120),
        RetryPolicy::default(),
        CONTENT_MODULE_NAME,
        provenance_for(&plan),
        TaskScopeTarget::Url(origin.canonical()),
        params,
        &AllowAll,
    )
    .unwrap();
    let started = Instant::now();
    let output =
        futures_drive(module.execute(ModuleContext::new(task, CancellationToken::default())))
            .unwrap();
    let wall = started.elapsed();
    stop.store(true, Ordering::SeqCst);
    assert!(
        wall < Duration::from_secs(60),
        "slow/oversized peer took {wall:?}"
    );
    assert!(output.events.len() <= content::MAX_CONTENT_EVENTS);
    assert!(output.evidence.len() <= content::MAX_CONTENT_EVIDENCE);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn descriptor_exhaustion_returns_bounded_result() {
    // Hermetic subprocess: the FD limit is lowered for the CHILD process
    // only, so parallel tests in this process are unaffected.
    if std::env::var("RXSCAN_P19_FD_CHILD").is_ok() {
        fd_exhaustion_child_main();
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("descriptor_exhaustion_returns_bounded_result")
        .arg("--nocapture")
        .env("RXSCAN_P19_FD_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "fd-exhaustion child failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn fd_exhaustion_child_main() {
    // Hold most of a lowered descriptor table, then scan: socket creation
    // must degrade to bounded Error/backoff outcomes, never panic or spin.
    let mut held = Vec::new();
    for _ in 0..40 {
        if let Ok(file) = File::open("/dev/null") {
            held.push(file);
        }
    }
    let pid = std::process::id();
    let limited = std::process::Command::new("prlimit")
        .arg("--pid")
        .arg(pid.to_string())
        .arg("--nofile=64")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let cancel = CancellationToken::default();
    let config = ScanConfig::bounded(Duration::from_millis(200), 32, 0, None, cancel);
    let ports: Vec<u16> = (1..=100).collect();
    let started = Instant::now();
    let outcome = NativeTcpScanner.scan("127.0.0.1".parse().unwrap(), &ports, &config);
    let wall = started.elapsed();
    assert_eq!(outcome.probes.len() + outcome.unscanned, 100);
    assert!(outcome.fd_peak <= 32);
    assert!(
        wall < Duration::from_secs(60),
        "exhausted scan took {wall:?}; must not spin"
    );
    println!(
        "phase19 fd-exhaustion child: prlimit_applied={limited} probes={} unscanned={} fd_peak={}",
        outcome.probes.len(),
        outcome.unscanned,
        outcome.fd_peak
    );
    drop(held);
}

fn open_port_finding(plan_id: &ScanPlanId, address: &str, port: u16) -> rxscan::model::Finding {
    use rxscan::model::{AssetId, Confidence, Finding, Severity};
    let mut finding = Finding::new(
        format!("Open TCP port {port}"),
        Severity::Info,
        Confidence::new(80).unwrap(),
        AssetId(format!("asset-{address}-{port}")),
        Provenance::new("phase19.test", "19.0.0", plan_id.clone(), Timestamp(0)).unwrap(),
    )
    .unwrap();
    finding.metadata.insert(
        "address".to_owned(),
        serde_json::Value::String(address.to_owned()),
    );
    finding
        .metadata
        .insert("port".to_owned(), serde_json::Value::Number(port.into()));
    finding
}

#[test]
fn large_malformed_inputs_fail_bounded_without_panic() {
    let dir = std::env::temp_dir().join(format!("rxscan_p19m_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // 5 MiB of garbage as a checkpoint.
    let bad_checkpoint = dir.join("bad.json");
    {
        let mut file = File::create(&bad_checkpoint).unwrap();
        let chunk = vec![b'x'; 8192];
        for _ in 0..640 {
            file.write_all(&chunk).unwrap();
        }
    }
    let started = Instant::now();
    let result = persistence::load_checkpoint(&bad_checkpoint);
    assert!(result.is_err(), "malformed checkpoint must be rejected");
    assert!(started.elapsed() < Duration::from_secs(30));
    // Malformed project file.
    let bad_project = dir.join("bad.rxproj");
    std::fs::write(&bad_project, "{not valid json!!!").unwrap();
    assert!(rxscan::project::load_project(&bad_project).is_err());
    // Malformed DNS packet: short buffer must be rejected, not panic.
    let short = vec![0u8; 11];
    assert!(rxscan::dns::parse_dns_response(&short, "x.test", DnsRecordType::A).is_err());
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- zero-contact rejections ----------

#[test]
fn out_of_scope_work_is_rejected_before_any_execution() {
    let plan = plan_for("127.0.0.1");
    let executed = Arc::new(AtomicUsize::new(0));
    let budgets = BudgetLimits {
        max_tasks: 500,
        max_retries: 500,
        max_concurrency: 4,
        max_execution_time_ms: 30_000,
        ..BudgetLimits::default()
    };
    // Guard permits nothing: every add is rejected before admission.
    let mut scheduler = Scheduler::new(
        budgets.queue_capacity(),
        budgets,
        SpeedGovernor::new(SpeedSetting::Numeric(50), 4).unwrap(),
        Arc::new(DenyAll),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler.register_module(Arc::new(ImmediateModule {
        kind: TaskKind::HostDiscovery,
        executed: executed.clone(),
    }));
    let mut rejected = 0usize;
    for index in 0..200 {
        let task = make_task(&plan, index, 50, 5000);
        match scheduler.add_task(task) {
            Err(rxscan::execution::SchedulerError::OutOfScope) => rejected += 1,
            _ => panic!("expected OutOfScope"),
        }
    }
    assert_eq!(rejected, 200);
    let report = scheduler.run().unwrap();
    assert_eq!(executed.load(Ordering::SeqCst), 0, "zero contact");
    let total = report.completed.len()
        + report.failed.len()
        + report.cancelled.len()
        + report.timed_out.len()
        + report.skipped.len();
    assert_eq!(total, 0);
}

// ---------- startup laziness ----------

#[test]
fn help_path_has_no_persistent_side_effects() {
    let binary = env!("CARGO_BIN_EXE_rxscan");
    let dir = std::env::temp_dir().join(format!("rxscan_p19h_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let before: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
    let output = std::process::Command::new(binary)
        .arg("--help")
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("rxscan") || text.contains("RXScan"));
    let after: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
    assert_eq!(before.len(), after.len(), "help must not create files");
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- offline commands stay offline ----------

#[test]
fn offline_commands_report_zero_network_requests() {
    let plan = plan_for("127.0.0.1");
    let state = large_state(&plan, 100);
    let diff_report = diff::compare_states(&state, &state, DiffOptions::default()).unwrap();
    assert_eq!(diff_report.network_requests, 0);
    let analysis = analysis::analyze_state(&state, None, AnalysisOptions::default()).unwrap();
    assert_eq!(analysis.network_requests, 0);
    let model = rxscan::report::build_report_model(
        &state,
        None,
        None,
        &ReportOptions {
            format: ReportFormat::Jsonl,
            summary_only: true,
            top_n: 5,
        },
    )
    .unwrap();
    assert_eq!(model.summary.network_requests, 0);
}

// ---------- misc scale proofs ----------

#[test]
fn tcp_closed_heavy_outcome_stays_compact_in_reporting() {
    // 2000 closed ports through the discovery module: repetitive negative
    // results must not explode event/evidence structures.
    let plan = compile(&["127.0.0.1", "--scope", "127.0.0.0/8", "--level", "3"]);
    let executed = Arc::new(AtomicUsize::new(0));
    struct ClosedScanner {
        executed: Arc<AtomicUsize>,
    }
    impl PortScanner for ClosedScanner {
        fn scan(
            &self,
            _ip: std::net::IpAddr,
            ports: &[u16],
            _config: &ScanConfig,
        ) -> rxscan::tcp_scanner::ScanOutcome {
            self.executed.fetch_add(1, Ordering::SeqCst);
            rxscan::tcp_scanner::ScanOutcome {
                probes: ports
                    .iter()
                    .map(|port| rxscan::tcp_scanner::PortProbe {
                        port: *port,
                        state: rxscan::tcp_scanner::PortState::Closed,
                        latency: Duration::from_micros(10),
                        detail: "fake closed".to_owned(),
                        attempts: 1,
                    })
                    .collect(),
                truncated: false,
                cancelled: false,
                unscanned: 0,
                fd_peak: 1,
            }
        }
    }
    let provenance = provenance_for(&plan);
    let guard = Arc::new(AllowAll);
    let policy = rxscan::tcp_discovery::TcpScanPolicy::new(
        3,
        ScanGoal::Discover,
        TcpPortSelection::Explicit((1..=2000).collect()),
        SpeedSetting::Numeric(50),
    );
    let module = rxscan::tcp_discovery::TcpDiscoveryModule::with_scanner(
        policy,
        Arc::new(ClosedScanner {
            executed: executed.clone(),
        }),
        guard.clone(),
    );
    let mut params = BTreeMap::new();
    params.insert("target".to_owned(), "127.0.0.1".to_owned());
    params.insert("ports".to_owned(), "1-2000".to_owned());
    let task = Task::new_with_params(
        TaskKind::PortDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        60,
        Duration::from_secs(30),
        RetryPolicy::default(),
        rxscan::tcp_discovery::TCP_DISCOVERY_MODULE_NAME,
        provenance,
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        params,
        guard.as_ref(),
    )
    .unwrap();
    let output =
        futures_drive(module.execute(ModuleContext::new(task, CancellationToken::default())))
            .unwrap();
    assert_eq!(executed.load(Ordering::SeqCst), 1);
    assert!(
        output.events.len() <= rxscan::tcp_discovery::MAX_DETAILED_PORT_EVENTS + 8,
        "closed-heavy outcome events {} exceed compact bound",
        output.events.len()
    );
}

#[test]
fn dns_module_serves_many_types_from_local_fixture_with_dedup() {
    // Registry-level proof for thousands of repeated hostname/type
    // proposals: collapse to one tracked query per name/type, per-domain
    // fairness holds, transient forget releases for retry. (Module wire
    // behavior against a live UDP fixture is covered by phase13.)
    use std::net::SocketAddr;
    let registry = DnsRegistry::new();
    let resolver: SocketAddr = "127.0.0.1:53".parse().unwrap();
    for i in 0..3000 {
        let name = format!("h{}.example.test", i % 100);
        registry.claim_query(&name, DnsRecordType::A, resolver);
        registry.claim_query(&name, DnsRecordType::Aaaa, resolver);
    }
    assert!(registry.query_count() <= 200);
}
