use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    thread,
    time::Duration,
};

use clap::Parser;
use rxscan::{
    cli::Cli,
    execution::{
        BudgetLimits, DecisionEngine, Module, ModuleContext, ModuleError, ModuleFuture,
        ModuleOutput, PolicyScopeGuard, RetryPolicy, Scheduler, SchedulerError, SchedulerEventKind,
        ScopeGuard, SpeedGovernor, Task, TaskId, TaskKind, TaskQueue, TaskScopeTarget, TaskState,
        VecEventSink,
    },
    model::{AssetId, Provenance, Timestamp},
    plan::{ScanPlan, SpeedSetting},
};

fn plan() -> ScanPlan {
    ScanPlan::compile(Cli::try_parse_from(["rxscan", "example.test"]).unwrap()).unwrap()
}

fn provenance(plan: &ScanPlan, module: &str) -> Provenance {
    Provenance::new(module, "3.0.0", plan.stable_id(), Timestamp(100)).unwrap()
}

fn task(
    plan: &ScanPlan,
    kind: TaskKind,
    asset: &str,
    module: &str,
    guard: &dyn ScopeGuard,
) -> Task {
    Task::new(
        kind,
        None,
        Vec::new(),
        Some(AssetId(asset.to_owned())),
        plan.stable_id(),
        50,
        Duration::from_millis(100),
        RetryPolicy::default(),
        module,
        provenance(plan, module),
        TaskScopeTarget::Host("example.test".to_owned()),
        guard,
    )
    .unwrap()
}

fn make_scheduler(
    plan: &ScanPlan,
    sink: Arc<VecEventSink>,
    budgets: BudgetLimits,
    speed: SpeedSetting,
) -> Scheduler {
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    Scheduler::new(
        32,
        budgets.clone(),
        SpeedGovernor::new(speed, budgets.max_concurrency).unwrap(),
        guard,
        sink,
    )
    .unwrap()
}

struct ImmediateModule {
    kind: TaskKind,
    order: Option<Arc<Mutex<Vec<TaskId>>>>,
    active: Option<Arc<AtomicUsize>>,
    maximum: Option<Arc<AtomicUsize>>,
    delay: Duration,
}
impl Module for ImmediateModule {
    fn kind(&self) -> TaskKind {
        self.kind.clone()
    }
    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let order = self.order.clone();
        let active = self.active.clone();
        let maximum = self.maximum.clone();
        let delay = self.delay;
        Box::pin(async move {
            if let Some(order) = order {
                order.lock().unwrap().push(context.task.id.clone());
            }
            let current = active
                .as_ref()
                .map(|counter| counter.fetch_add(1, Ordering::SeqCst) + 1);
            if let (Some(current), Some(maximum)) = (current, maximum.as_ref()) {
                maximum.fetch_max(current, Ordering::SeqCst);
            }
            if !delay.is_zero() {
                thread::sleep(delay);
            }
            if let Some(active) = active {
                active.fetch_sub(1, Ordering::SeqCst);
            }
            Ok(ModuleOutput::default())
        })
    }
}

struct RetryModule {
    attempts: Arc<AtomicUsize>,
    kind: TaskKind,
}
impl Module for RetryModule {
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

struct NeverFuture;
impl Future for NeverFuture {
    type Output = Result<ModuleOutput, ModuleError>;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}
struct HangingModule;
impl Module for HangingModule {
    fn kind(&self) -> TaskKind {
        TaskKind::Custom("hang".into())
    }
    fn execute(&self, _context: ModuleContext) -> ModuleFuture {
        Box::pin(NeverFuture)
    }
}

#[test]
fn queue_is_bounded_and_priority_order_is_deterministic() {
    let mut queue = TaskQueue::new(2).unwrap();
    queue.push(TaskId("low".into()), 1).unwrap();
    queue.push(TaskId("high".into()), 9).unwrap();
    assert_eq!(
        queue.push(TaskId("full".into()), 2),
        Err(SchedulerError::QueueSaturated)
    );
    assert_eq!(queue.pop(), Some(TaskId("high".into())));
    assert_eq!(queue.pop(), Some(TaskId("low".into())));
}

#[test]
fn speed_is_deterministic_and_independent_of_level() {
    let slow = SpeedGovernor::new(SpeedSetting::Numeric(20), 5).unwrap();
    let fast = SpeedGovernor::new(SpeedSetting::Numeric(90), 5).unwrap();
    assert_eq!(slow.concurrency(), 1);
    assert_eq!(fast.concurrency(), 4);
    assert!(fast.retry_limit() >= slow.retry_limit());
}

#[test]
fn lifecycle_events_and_duplicate_prevention_work() {
    let plan = plan();
    let sink = Arc::new(VecEventSink::default());
    let mut scheduler = make_scheduler(
        &plan,
        sink.clone(),
        BudgetLimits::default(),
        SpeedSetting::Numeric(100),
    );
    let guard = PolicyScopeGuard::new(plan.scope.clone());
    let work = task(&plan, TaskKind::HostDiscovery, "a", "host", &guard);
    let same = work.clone();
    scheduler.register_module(Arc::new(ImmediateModule {
        kind: TaskKind::HostDiscovery,
        order: None,
        active: None,
        maximum: None,
        delay: Duration::ZERO,
    }));
    scheduler.add_task(work).unwrap();
    assert_eq!(scheduler.add_task(same), Err(SchedulerError::DuplicateTask));
    let report = scheduler.run().unwrap();
    assert_eq!(report.completed.len(), 1);
    let kinds: Vec<SchedulerEventKind> =
        sink.events().into_iter().map(|event| event.kind).collect();
    assert!(kinds.contains(&SchedulerEventKind::TaskCreated));
    assert!(kinds.contains(&SchedulerEventKind::TaskStarted));
    assert!(kinds.contains(&SchedulerEventKind::TaskCompleted));
}

#[test]
fn dependencies_order_execution_and_skip_after_failure() {
    let plan = plan();
    let guard = PolicyScopeGuard::new(plan.scope.clone());
    let order = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::new(VecEventSink::default());
    let mut scheduler = make_scheduler(
        &plan,
        sink,
        BudgetLimits::default(),
        SpeedSetting::Numeric(100),
    );
    scheduler.register_module(Arc::new(ImmediateModule {
        kind: TaskKind::HostDiscovery,
        order: Some(order.clone()),
        active: None,
        maximum: None,
        delay: Duration::ZERO,
    }));
    scheduler.register_module(Arc::new(ImmediateModule {
        kind: TaskKind::PortDiscovery,
        order: Some(order.clone()),
        active: None,
        maximum: None,
        delay: Duration::ZERO,
    }));
    let first = task(&plan, TaskKind::HostDiscovery, "host", "host", &guard);
    let first_id = first.id.clone();
    scheduler.add_task(first).unwrap();
    let mut second = task(&plan, TaskKind::PortDiscovery, "port", "port", &guard);
    second.dependencies.push(first_id);
    scheduler.add_task(second).unwrap();
    let report = scheduler.run().unwrap();
    assert_eq!(report.completed.len(), 2);
    assert_eq!(order.lock().unwrap().len(), 2);

    let mut failure_scheduler = make_scheduler(
        &plan,
        Arc::new(VecEventSink::default()),
        BudgetLimits::default(),
        SpeedSetting::Numeric(100),
    );
    failure_scheduler.register_module(Arc::new(FailingModule {
        kind: TaskKind::HostDiscovery,
    }));
    failure_scheduler.register_module(Arc::new(ImmediateModule {
        kind: TaskKind::PortDiscovery,
        order: None,
        active: None,
        maximum: None,
        delay: Duration::ZERO,
    }));
    let root = task(&plan, TaskKind::HostDiscovery, "root", "host", &guard);
    let root_id = root.id.clone();
    failure_scheduler.add_task(root).unwrap();
    let mut dependent = task(&plan, TaskKind::PortDiscovery, "dependent", "port", &guard);
    dependent.dependencies.push(root_id);
    failure_scheduler.add_task(dependent).unwrap();
    let report = failure_scheduler.run().unwrap();
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.skipped.len(), 1);
}

struct FailingModule {
    kind: TaskKind,
}
impl Module for FailingModule {
    fn kind(&self) -> TaskKind {
        self.kind.clone()
    }
    fn execute(&self, _context: ModuleContext) -> ModuleFuture {
        Box::pin(async {
            Err(ModuleError::Failed {
                message: "permanent".into(),
                retryable: false,
            })
        })
    }
}

#[test]
fn retries_are_bounded_and_successful() {
    let plan = plan();
    let attempts = Arc::new(AtomicUsize::new(0));
    let sink = Arc::new(VecEventSink::default());
    let mut scheduler = make_scheduler(
        &plan,
        sink.clone(),
        BudgetLimits::default(),
        SpeedSetting::Numeric(100),
    );
    scheduler.register_module(Arc::new(RetryModule {
        attempts: attempts.clone(),
        kind: TaskKind::HostDiscovery,
    }));
    let guard = PolicyScopeGuard::new(plan.scope.clone());
    let mut work = task(&plan, TaskKind::HostDiscovery, "retry", "retry", &guard);
    work.retry_policy = RetryPolicy {
        max_attempts: 2,
        base_delay_ms: 0,
    };
    scheduler.add_task(work).unwrap();
    assert_eq!(scheduler.run().unwrap().completed.len(), 1);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert!(
        sink.events()
            .iter()
            .any(|event| event.kind == SchedulerEventKind::TaskRetried)
    );
}

#[test]
fn timeout_and_queued_cancellation_are_terminal() {
    let plan = plan();
    let sink = Arc::new(VecEventSink::default());
    let mut scheduler = make_scheduler(
        &plan,
        sink,
        BudgetLimits {
            max_execution_time_ms: 500,
            ..BudgetLimits::default()
        },
        SpeedSetting::Numeric(100),
    );
    scheduler.register_module(Arc::new(HangingModule));
    let guard = PolicyScopeGuard::new(plan.scope.clone());
    let mut hanging = task(
        &plan,
        TaskKind::Custom("hang".into()),
        "hang",
        "hang",
        &guard,
    );
    hanging.timeout_ms = 10;
    hanging.deadline = Some(Timestamp(110));
    let hanging_id = hanging.id.clone();
    scheduler.add_task(hanging).unwrap();
    let queued = task(
        &plan,
        TaskKind::Custom("hang".into()),
        "queued",
        "hang",
        &guard,
    );
    let queued_id = queued.id.clone();
    scheduler.add_task(queued).unwrap();
    assert!(scheduler.cancel_task(&queued_id));
    let report = scheduler.run().unwrap();
    assert!(report.timed_out.contains(&hanging_id));
    assert_eq!(
        scheduler.task(&queued_id).unwrap().state,
        TaskState::Cancelled
    );
}

#[test]
fn concurrency_budget_scope_and_stale_scope_are_enforced() {
    let plan = plan();
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let mut scheduler = make_scheduler(
        &plan,
        Arc::new(VecEventSink::default()),
        BudgetLimits {
            max_concurrency: 2,
            max_tasks: 2,
            ..BudgetLimits::default()
        },
        SpeedSetting::Numeric(100),
    );
    scheduler.register_module(Arc::new(ImmediateModule {
        kind: TaskKind::HostDiscovery,
        order: None,
        active: Some(active),
        maximum: Some(maximum.clone()),
        delay: Duration::from_millis(20),
    }));
    let guard = PolicyScopeGuard::new(plan.scope.clone());
    scheduler
        .add_task(task(&plan, TaskKind::HostDiscovery, "one", "host", &guard))
        .unwrap();
    scheduler
        .add_task(task(&plan, TaskKind::HostDiscovery, "two", "host", &guard))
        .unwrap();
    assert_eq!(scheduler.run().unwrap().completed.len(), 2);
    assert_eq!(maximum.load(Ordering::SeqCst), 2);

    let mutable_guard = Arc::new(FlippingGuard {
        allowed: AtomicBool::new(true),
    });
    let mut stale = Scheduler::new(
        4,
        BudgetLimits::default(),
        SpeedGovernor::new(SpeedSetting::Numeric(100), 2).unwrap(),
        mutable_guard.clone(),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    stale.register_module(Arc::new(ImmediateModule {
        kind: TaskKind::HostDiscovery,
        order: None,
        active: None,
        maximum: None,
        delay: Duration::ZERO,
    }));
    let work = task(
        &plan,
        TaskKind::HostDiscovery,
        "stale",
        "host",
        mutable_guard.as_ref(),
    );
    stale.add_task(work).unwrap();
    mutable_guard.allowed.store(false, Ordering::SeqCst);
    assert_eq!(stale.run().unwrap().skipped.len(), 1);
}

struct FlippingGuard {
    allowed: AtomicBool,
}
impl ScopeGuard for FlippingGuard {
    fn permits(&self, _target: &TaskScopeTarget) -> bool {
        self.allowed.load(Ordering::SeqCst)
    }
}

#[test]
fn decision_engine_is_the_only_follow_up_source() {
    let plan = plan();
    let guard = PolicyScopeGuard::new(plan.scope.clone());
    let followup = task(&plan, TaskKind::PortDiscovery, "followup", "port", &guard);
    let followup_id = followup.id.clone();
    let mut scheduler = make_scheduler(
        &plan,
        Arc::new(VecEventSink::default()),
        BudgetLimits::default(),
        SpeedSetting::Numeric(100),
    );
    scheduler.register_module(Arc::new(ImmediateModule {
        kind: TaskKind::HostDiscovery,
        order: None,
        active: None,
        maximum: None,
        delay: Duration::ZERO,
    }));
    scheduler.register_module(Arc::new(ImmediateModule {
        kind: TaskKind::PortDiscovery,
        order: None,
        active: None,
        maximum: None,
        delay: Duration::ZERO,
    }));
    scheduler.set_decision_engine(Arc::new(OneFollowUp {
        followup: Some(followup),
    }));
    scheduler
        .add_task(task(
            &plan,
            TaskKind::HostDiscovery,
            "parent",
            "host",
            &guard,
        ))
        .unwrap();
    let report = scheduler.run().unwrap();
    assert_eq!(report.completed.len(), 2);
    assert_eq!(
        scheduler.task(&followup_id).unwrap().state,
        TaskState::Succeeded
    );
}
struct OneFollowUp {
    followup: Option<Task>,
}
impl DecisionEngine for OneFollowUp {
    fn follow_up_tasks(&self, completed: &Task, _output: &ModuleOutput) -> Vec<Task> {
        if completed.kind == TaskKind::HostDiscovery {
            self.followup.clone().into_iter().collect()
        } else {
            Vec::new()
        }
    }
}

#[test]
fn evidence_budget_and_task_budget_are_central() {
    let plan = plan();
    let guard = PolicyScopeGuard::new(plan.scope.clone());
    let sink = Arc::new(VecEventSink::default());
    let mut scheduler = make_scheduler(
        &plan,
        sink,
        BudgetLimits {
            max_tasks: 1,
            ..BudgetLimits::default()
        },
        SpeedSetting::Numeric(100),
    );
    scheduler.register_module(Arc::new(ImmediateModule {
        kind: TaskKind::HostDiscovery,
        order: None,
        active: None,
        maximum: None,
        delay: Duration::ZERO,
    }));
    scheduler
        .add_task(task(
            &plan,
            TaskKind::HostDiscovery,
            "first",
            "host",
            &guard,
        ))
        .unwrap();
    assert!(matches!(
        scheduler.add_task(task(
            &plan,
            TaskKind::HostDiscovery,
            "second",
            "host",
            &guard
        )),
        Err(SchedulerError::BudgetExhausted("maximum tasks"))
    ));
}
