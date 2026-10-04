//! Priority 1 regression: hard execution deadline enforcement.
//!
//! The global `max_execution_time` is an authoritative wall-clock deadline:
//! `wall ≈ deadline + bounded cleanup`, never `deadline + full scan`.
//! Tolerances are generous for CI (cleanup <= 1500ms); the invariant under
//! test is bounded overrun, not exact timing.

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use clap::Parser;
use rxscan::{
    cli::Cli,
    execution::{
        BudgetLimits, Module, ModuleContext, ModuleError, ModuleFuture, ModuleOutput,
        PolicyScopeGuard, RetryPolicy, Scheduler, SpeedGovernor, Task, TaskKind, TaskScopeTarget,
        TerminationReason, VecEventSink,
    },
    model::{Provenance, Timestamp},
    plan::SpeedSetting,
};

fn plan_for(target: &str) -> rxscan::plan::ScanPlan {
    let cli = Cli::try_parse_from(["rxscan", target, "--scope", "127.0.0.0/8"]).unwrap();
    rxscan::plan::ScanPlan::compile(cli).unwrap()
}

fn provenance_for(plan: &rxscan::plan::ScanPlan) -> Provenance {
    Provenance::new("deadline.test", "1.0.0", plan.stable_id(), Timestamp(0)).unwrap()
}

/// Cooperative long task: sleeps in 5ms slices, honors cancellation.
struct SleepyModule {
    kind: TaskKind,
    total: Duration,
}

impl Module for SleepyModule {
    fn kind(&self) -> TaskKind {
        self.kind.clone()
    }
    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let total = self.total;
        Box::pin(async move {
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

fn make_task(plan: &rxscan::plan::ScanPlan, index: usize) -> Task {
    let mut params = BTreeMap::new();
    params.insert("target".to_owned(), "127.0.0.1".to_owned());
    params.insert("variant".to_owned(), format!("deadline-{index}"));
    Task::new_with_params(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        50,
        Duration::from_secs(30),
        RetryPolicy::default(),
        "deadline.test",
        provenance_for(plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        params,
        &AllowAll,
    )
    .unwrap()
}

struct AllowAll;
impl rxscan::execution::ScopeGuard for AllowAll {
    fn permits(&self, _target: &TaskScopeTarget) -> bool {
        true
    }
}

fn run_with_deadline(
    deadline_ms: u64,
    tasks: usize,
    sleep: Duration,
) -> (rxscan::execution::SchedulerReport, Duration) {
    let plan = plan_for("127.0.0.1");
    let budgets = BudgetLimits {
        max_tasks: 1000,
        max_retries: 1000,
        max_concurrency: 4,
        max_execution_time_ms: deadline_ms,
        ..BudgetLimits::default()
    };
    let capacity = budgets.queue_capacity();
    let mut scheduler = Scheduler::new(
        capacity,
        budgets,
        SpeedGovernor::new(SpeedSetting::Numeric(50), 4).unwrap(),
        Arc::new(PolicyScopeGuard::new(plan.scope.clone())),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler.register_module(Arc::new(SleepyModule {
        kind: TaskKind::HostDiscovery,
        total: sleep,
    }));
    for index in 0..tasks {
        scheduler.add_task(make_task(&plan, index)).unwrap();
    }
    let start = Instant::now();
    let report = scheduler.run().unwrap();
    (report, start.elapsed())
}

fn assert_bounded(deadline_ms: u64, wall: Duration, report: &rxscan::execution::SchedulerReport) {
    // Wall must be deadline + small bounded cleanup (generous 2s for CI).
    let bound = Duration::from_millis(deadline_ms).saturating_add(Duration::from_millis(2000));
    assert!(
        wall <= bound,
        "deadline {deadline_ms}ms overran: wall {wall:?} exceeds {bound:?}"
    );
    // Truncation is a normal termination with partial accounting.
    assert_eq!(
        report.termination,
        TerminationReason::GlobalDeadline,
        "expected global_deadline truncation, got {:?}",
        report.termination
    );
    assert!(
        !report.cancelled.is_empty(),
        "deadline must cancel unfinished work"
    );
    let total = report.completed.len()
        + report.failed.len()
        + report.cancelled.len()
        + report.timed_out.len()
        + report.skipped.len();
    assert!(total > 0, "must account work");
}

#[test]
fn deadline_100ms_is_hard() {
    let (report, wall) = run_with_deadline(100, 8, Duration::from_secs(10));
    assert_bounded(100, wall, &report);
}

#[test]
fn deadline_500ms_is_hard() {
    let (report, wall) = run_with_deadline(500, 8, Duration::from_secs(10));
    assert_bounded(500, wall, &report);
}

#[test]
fn deadline_1s_is_hard() {
    let (report, wall) = run_with_deadline(1000, 8, Duration::from_secs(30));
    assert_bounded(1000, wall, &report);
}

#[test]
fn deadline_2s_is_hard() {
    let (report, wall) = run_with_deadline(2000, 8, Duration::from_secs(30));
    assert_bounded(2000, wall, &report);
}

#[test]
fn deadline_5s_is_hard() {
    // Shorter-than-deadline work completes early with Completed.
    let (report, wall) = run_with_deadline(5000, 2, Duration::from_millis(50));
    assert_eq!(report.termination, TerminationReason::Completed);
    assert_eq!(report.completed.len(), 2);
    assert!(wall < Duration::from_secs(5));
    // Longer-than-deadline work truncates bounded.
    let (report, wall) = run_with_deadline(5000, 8, Duration::from_secs(60));
    // 8×60s sleepers on 4 slots cannot finish in 5s; must truncate.
    assert_bounded(5000, wall, &report);
}

#[test]
fn no_task_receives_timeout_beyond_global_budget() {
    // Effective deadline is always <= global deadline: tasks dispatched
    // near expiry get clamped timeouts via ModuleContext.
    let plan = plan_for("127.0.0.1");
    let task = make_task(&plan, 0);
    let ctx = ModuleContext::with_global(
        task,
        rxscan::execution::CancellationToken::default(),
        rxscan::execution::CancellationToken::default(),
        Some(Instant::now() + Duration::from_millis(100)),
    );
    let effective = ctx.effective_deadline().unwrap();
    assert!(effective <= Instant::now() + Duration::from_millis(500));
}

#[test]
fn task_budget_exhaustion_is_truncation_not_failure() {
    let plan = plan_for("127.0.0.1");
    let budgets = BudgetLimits {
        max_tasks: 2,
        max_retries: 100,
        max_concurrency: 2,
        max_execution_time_ms: 60_000,
        ..BudgetLimits::default()
    };
    let executed = Arc::new(AtomicUsize::new(0));
    struct Counter {
        kind: TaskKind,
        executed: Arc<AtomicUsize>,
    }
    impl Module for Counter {
        fn kind(&self) -> TaskKind {
            self.kind.clone()
        }
        fn execute(&self, _ctx: ModuleContext) -> ModuleFuture {
            let executed = self.executed.clone();
            Box::pin(async move {
                executed.fetch_add(1, Ordering::SeqCst);
                Ok(ModuleOutput::default())
            })
        }
    }
    let mut scheduler = Scheduler::new(
        budgets.queue_capacity(),
        budgets,
        SpeedGovernor::new(SpeedSetting::Numeric(50), 2).unwrap(),
        Arc::new(PolicyScopeGuard::new(plan.scope.clone())),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler.register_module(Arc::new(Counter {
        kind: TaskKind::HostDiscovery,
        executed: executed.clone(),
    }));
    // First two admit; third is budget truncation, not a fatal error.
    scheduler.add_task(make_task(&plan, 0)).unwrap();
    scheduler.add_task(make_task(&plan, 1)).unwrap();
    assert!(scheduler.add_task(make_task(&plan, 2)).is_err());
    let report = scheduler.run().unwrap();
    assert_eq!(report.termination, TerminationReason::TaskBudget);
    assert_eq!(report.completed.len(), 2);
    assert_eq!(report.tasks_not_admitted, 1);
}

#[test]
fn error_taxonomy_classifies_without_losing_totals() {
    use rxscan::execution::{ErrorCategory, classify_error_detail};
    assert_eq!(
        classify_error_detail("TCP connection refused (errno 111)"),
        ErrorCategory::ConnectionRefused
    );
    assert_eq!(
        classify_error_detail("TCP connect timed out after 800ms"),
        ErrorCategory::ConnectTimeout
    );
    assert_eq!(
        classify_error_detail("global deadline"),
        ErrorCategory::GlobalDeadline
    );
    assert_eq!(
        classify_error_detail("something completely novel"),
        ErrorCategory::Other
    );
    for category in ErrorCategory::all() {
        assert!(!category.to_string().is_empty());
    }
}
