//! Phase 3 execution control plane.
//!
//! This module deliberately contains no network or process execution. Modules
//! supply bounded futures; the scheduler owns admission, ordering, limits,
//! cancellation, retries, dependencies, and follow-up-task validation.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BinaryHeap},
    future::Future,
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering as AtomicOrdering},
        mpsc::{self, RecvTimeoutError, Sender},
    },
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    model::{AssetId, Event, Evidence, Finding, Provenance, ScanPlanId, Timestamp},
    plan::SpeedSetting,
    scope::ScopePolicy,
};

pub type ModuleFuture = Pin<Box<dyn Future<Output = Result<ModuleOutput, ModuleError>> + Send>>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    HostDiscovery,
    PortDiscovery,
    ServiceProbe,
    HttpProbe,
    TlsProbe,
    DnsProbe,
    Fingerprint,
    Crawl,
    ContentDiscovery,
    Fuzz,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TaskId(pub String);
impl std::fmt::Display for TaskId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Pending,
    Ready,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    Skipped,
}
impl TaskState {
    fn terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::TimedOut | Self::Skipped
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "target_type", content = "value")]
pub enum TaskScopeTarget {
    Host(String),
    Ip(IpAddr),
    Url(String),
    None,
}

pub trait ScopeGuard: Send + Sync {
    fn permits(&self, target: &TaskScopeTarget) -> bool;
}

#[derive(Debug, Clone)]
pub struct PolicyScopeGuard {
    policy: ScopePolicy,
}
impl PolicyScopeGuard {
    pub fn new(policy: ScopePolicy) -> Self {
        Self { policy }
    }
}
impl ScopeGuard for PolicyScopeGuard {
    fn permits(&self, target: &TaskScopeTarget) -> bool {
        match target {
            TaskScopeTarget::Host(host) => self.policy.permits(None, Some(host)),
            TaskScopeTarget::Ip(ip) => self.policy.permits(Some(*ip), None),
            TaskScopeTarget::Url(url) => url::Url::parse(url)
                .ok()
                .and_then(|parsed| parsed.host_str().map(str::to_owned))
                .is_some_and(|host| match host.parse::<IpAddr>() {
                    Ok(ip) => self.policy.permits(Some(ip), None),
                    Err(_) => self.policy.permits(None, Some(&host)),
                }),
            TaskScopeTarget::None => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base_delay_ms: u64,
}
impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 1,
            base_delay_ms: 0,
        }
    }
}
impl RetryPolicy {
    pub fn delay_for_retry(&self, attempt: u32) -> Duration {
        Duration::from_millis(self.base_delay_ms.saturating_mul(attempt as u64))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetAccount {
    pub task_cost: u64,
    pub evidence_bytes: u64,
}
impl Default for BudgetAccount {
    fn default() -> Self {
        Self {
            task_cost: 1,
            evidence_bytes: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    pub id: TaskId,
    pub kind: TaskKind,
    pub parent_task_id: Option<TaskId>,
    pub dependencies: Vec<TaskId>,
    pub associated_asset_id: Option<AssetId>,
    pub scan_plan_id: ScanPlanId,
    pub priority: u8,
    pub state: TaskState,
    pub created_at: Timestamp,
    pub timeout_ms: u64,
    pub deadline: Option<Timestamp>,
    pub retry_policy: RetryPolicy,
    pub attempt: u32,
    pub retry_count: u32,
    pub cancel_requested: bool,
    pub module_name: String,
    pub provenance: Provenance,
    pub budget: BudgetAccount,
    pub scope_target: TaskScopeTarget,
}
impl Task {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: TaskKind,
        parent_task_id: Option<TaskId>,
        dependencies: Vec<TaskId>,
        associated_asset_id: Option<AssetId>,
        scan_plan_id: ScanPlanId,
        priority: u8,
        timeout: Duration,
        retry_policy: RetryPolicy,
        module_name: impl Into<String>,
        provenance: Provenance,
        scope_target: TaskScopeTarget,
        scope_guard: &dyn ScopeGuard,
    ) -> Result<Self, SchedulerError> {
        let module_name = module_name.into();
        if module_name.trim().is_empty() || scan_plan_id.0.trim().is_empty() {
            return Err(SchedulerError::InvalidTask(
                "module and plan identity are required",
            ));
        }
        if retry_policy.max_attempts == 0 || timeout.is_zero() {
            return Err(SchedulerError::InvalidTask(
                "timeout and maximum attempts must be positive",
            ));
        }
        if !scope_guard.permits(&scope_target) {
            return Err(SchedulerError::OutOfScope);
        }
        let created_at = provenance.timestamp;
        let deadline = Some(Timestamp(
            created_at.0.saturating_add(timeout.as_millis() as u64),
        ));
        let identity = format!(
            "{}|{}|{}|{}|{}",
            scan_plan_id.0,
            module_name,
            kind_key(&kind),
            associated_asset_id.as_ref().map_or("", |id| id.0.as_str()),
            dependencies
                .iter()
                .map(|id| id.0.as_str())
                .collect::<Vec<_>>()
                .join(",")
        );
        Ok(Self {
            id: TaskId(format!("task_{}", stable_hash(identity.as_bytes()))),
            kind,
            parent_task_id,
            dependencies,
            associated_asset_id,
            scan_plan_id,
            priority,
            state: TaskState::Pending,
            created_at,
            timeout_ms: timeout.as_millis().min(u64::MAX as u128) as u64,
            deadline,
            retry_policy,
            attempt: 0,
            retry_count: 0,
            cancel_requested: false,
            module_name,
            provenance,
            budget: BudgetAccount::default(),
            scope_target,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueueEntry {
    priority: u8,
    sequence: u64,
    task_id: TaskId,
}
impl Ord for QueueEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority
            .cmp(&other.priority)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}
impl PartialOrd for QueueEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone)]
pub struct TaskQueue {
    capacity: usize,
    sequence: u64,
    entries: BinaryHeap<QueueEntry>,
}
impl TaskQueue {
    pub fn new(capacity: usize) -> Result<Self, SchedulerError> {
        if capacity == 0 {
            return Err(SchedulerError::InvalidConfiguration(
                "queue capacity must be positive",
            ));
        }
        Ok(Self {
            capacity,
            sequence: 0,
            entries: BinaryHeap::new(),
        })
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn push(&mut self, task_id: TaskId, priority: u8) -> Result<(), SchedulerError> {
        if self.len() >= self.capacity {
            return Err(SchedulerError::QueueSaturated);
        }
        let sequence = self.sequence;
        self.sequence = self.sequence.saturating_add(1);
        self.entries.push(QueueEntry {
            priority,
            sequence,
            task_id,
        });
        Ok(())
    }
    pub fn pop(&mut self) -> Option<TaskId> {
        self.entries.pop().map(|entry| entry.task_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleBudget {
    pub max_tasks: u64,
    pub max_retries: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetLimits {
    pub max_tasks: u64,
    pub max_retries: u64,
    pub max_concurrency: usize,
    pub max_execution_time_ms: u64,
    pub max_evidence_bytes: u64,
    #[serde(default)]
    pub per_module: BTreeMap<String, ModuleBudget>,
}
impl Default for BudgetLimits {
    fn default() -> Self {
        Self {
            max_tasks: 1_000,
            max_retries: 1_000,
            max_concurrency: 4,
            max_execution_time_ms: 60_000,
            max_evidence_bytes: 64 * 1024 * 1024,
            per_module: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct BudgetLedger {
    accepted_tasks: u64,
    retries: u64,
    evidence_bytes: u64,
    module_tasks: BTreeMap<String, u64>,
    module_retries: BTreeMap<String, u64>,
}
impl BudgetLedger {
    fn admit(
        &mut self,
        task: &Task,
        limits: &BudgetLimits,
        is_retry: bool,
    ) -> Result<(), SchedulerError> {
        if !is_retry && self.accepted_tasks >= limits.max_tasks {
            return Err(SchedulerError::BudgetExhausted("maximum tasks"));
        }
        if is_retry && self.retries >= limits.max_retries {
            return Err(SchedulerError::BudgetExhausted("maximum retries"));
        }
        let module_limit = limits.per_module.get(&task.module_name);
        if !is_retry {
            let used = self
                .module_tasks
                .get(&task.module_name)
                .copied()
                .unwrap_or(0);
            if module_limit.is_some_and(|limit| used >= limit.max_tasks) {
                return Err(SchedulerError::BudgetExhausted("per-module tasks"));
            }
        } else {
            let used = self
                .module_retries
                .get(&task.module_name)
                .copied()
                .unwrap_or(0);
            if module_limit.is_some_and(|limit| used >= limit.max_retries) {
                return Err(SchedulerError::BudgetExhausted("per-module retries"));
            }
        }
        if is_retry {
            self.retries += 1;
            *self
                .module_retries
                .entry(task.module_name.clone())
                .or_default() += 1;
        } else {
            self.accepted_tasks += 1;
            *self
                .module_tasks
                .entry(task.module_name.clone())
                .or_default() += 1;
        }
        Ok(())
    }
    fn add_evidence(&mut self, bytes: u64, limits: &BudgetLimits) -> Result<(), SchedulerError> {
        let next = self.evidence_bytes.saturating_add(bytes);
        if next > limits.max_evidence_bytes {
            return Err(SchedulerError::BudgetExhausted("evidence volume"));
        }
        self.evidence_bytes = next;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeedGovernor {
    setting: SpeedSetting,
    max_concurrency: usize,
}
impl SpeedGovernor {
    pub fn new(setting: SpeedSetting, max_concurrency: usize) -> Result<Self, SchedulerError> {
        if max_concurrency == 0 {
            return Err(SchedulerError::InvalidConfiguration(
                "maximum concurrency must be positive",
            ));
        }
        Ok(Self {
            setting,
            max_concurrency,
        })
    }
    pub fn concurrency(&self) -> usize {
        let pressure = match self.setting {
            SpeedSetting::Numeric(value) => value,
            SpeedSetting::Named(crate::plan::NamedSpeed::Slow) => 20,
            SpeedSetting::Named(crate::plan::NamedSpeed::Balanced) => 50,
            SpeedSetting::Named(crate::plan::NamedSpeed::Fast) => 80,
            SpeedSetting::Named(crate::plan::NamedSpeed::Auto) => 50,
        } as usize;
        (1 + ((self.max_concurrency.saturating_sub(1) * pressure) / 100)).min(self.max_concurrency)
    }
    pub fn retry_limit(&self) -> u32 {
        match self.setting {
            SpeedSetting::Numeric(value) => (value / 25).max(1) as u32,
            SpeedSetting::Named(crate::plan::NamedSpeed::Slow) => 1,
            SpeedSetting::Named(crate::plan::NamedSpeed::Balanced) => 2,
            SpeedSetting::Named(crate::plan::NamedSpeed::Fast) => 3,
            SpeedSetting::Named(crate::plan::NamedSpeed::Auto) => 2,
        }
    }
    pub fn setting(&self) -> SpeedSetting {
        self.setting
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerEventKind {
    TaskCreated,
    TaskQueued,
    TaskStarted,
    TaskCompleted,
    TaskFailed,
    TaskRetried,
    TaskCancelled,
    TaskTimedOut,
    TaskSkipped,
    BudgetExhausted,
    QueueSaturated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerEvent {
    pub kind: SchedulerEventKind,
    pub task_id: TaskId,
    pub state: TaskState,
    pub timestamp: Timestamp,
    pub provenance: Provenance,
    pub reason: Option<String>,
}

pub trait EventSink: Send + Sync {
    fn emit(&self, event: SchedulerEvent);
}

#[derive(Debug, Default)]
pub struct VecEventSink {
    events: std::sync::Mutex<Vec<SchedulerEvent>>,
}
impl VecEventSink {
    pub fn events(&self) -> Vec<SchedulerEvent> {
        self.events
            .lock()
            .expect("event sink lock poisoned")
            .clone()
    }
}
impl EventSink for VecEventSink {
    fn emit(&self, event: SchedulerEvent) {
        self.events
            .lock()
            .expect("event sink lock poisoned")
            .push(event);
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ModuleOutput {
    pub events: Vec<Event>,
    pub evidence: Vec<Evidence>,
    pub findings: Vec<Finding>,
}
impl ModuleOutput {
    fn evidence_bytes(&self) -> u64 {
        self.evidence
            .iter()
            .map(|item| item.details.captured_bytes as u64)
            .chain(
                self.events
                    .iter()
                    .map(|item| item.details.captured_bytes as u64),
            )
            .sum()
    }
}

#[derive(Debug, Clone)]
pub struct ModuleContext {
    pub task: Task,
    cancellation: CancellationToken,
}
impl ModuleContext {
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }
}

pub trait Module: Send + Sync {
    fn kind(&self) -> TaskKind;
    fn execute(&self, context: ModuleContext) -> ModuleFuture;
}

#[derive(Debug, Clone)]
pub struct CancellationToken(Arc<AtomicBool>);
impl Default for CancellationToken {
    fn default() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }
}
impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, AtomicOrdering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(AtomicOrdering::Acquire)
    }
}

pub trait DecisionEngine: Send + Sync {
    fn follow_up_tasks(&self, completed: &Task, output: &ModuleOutput) -> Vec<Task>;
}

#[derive(Debug, Default, Clone)]
pub struct NoFollowUps;
impl DecisionEngine for NoFollowUps {
    fn follow_up_tasks(&self, _completed: &Task, _output: &ModuleOutput) -> Vec<Task> {
        Vec::new()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SchedulerReport {
    pub completed: Vec<TaskId>,
    pub failed: Vec<TaskId>,
    pub cancelled: Vec<TaskId>,
    pub timed_out: Vec<TaskId>,
    pub skipped: Vec<TaskId>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ModuleError {
    #[error("module failure: {message} (retryable: {retryable})")]
    Failed { message: String, retryable: bool },
    #[error("module cancelled")]
    Cancelled,
}
impl ModuleError {
    fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Failed {
                retryable: true,
                ..
            }
        )
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SchedulerError {
    #[error("task is outside the current scope")]
    OutOfScope,
    #[error("duplicate task ID")]
    DuplicateTask,
    #[error("task dependency is unknown: {0}")]
    UnknownDependency(TaskId),
    #[error("task queue is saturated")]
    QueueSaturated,
    #[error("budget exhausted: {0}")]
    BudgetExhausted(&'static str),
    #[error("invalid task: {0}")]
    InvalidTask(&'static str),
    #[error("invalid scheduler configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("module is not registered for task kind")]
    MissingModule,
    #[error("scheduler worker channel closed")]
    WorkerChannelClosed,
}

struct TaskRecord {
    task: Task,
    cancellation: CancellationToken,
    queued: bool,
    ready_at: Instant,
    execution_started: Option<Instant>,
}

struct WorkerResult {
    task_id: TaskId,
    attempt: u32,
    result: Result<ModuleOutput, ModuleError>,
}

pub struct Scheduler {
    queue: TaskQueue,
    tasks: BTreeMap<TaskId, TaskRecord>,
    modules: BTreeMap<TaskKind, Arc<dyn Module>>,
    scope_guard: Arc<dyn ScopeGuard>,
    decision_engine: Arc<dyn DecisionEngine>,
    event_sink: Arc<dyn EventSink>,
    budgets: BudgetLimits,
    ledger: BudgetLedger,
    governor: SpeedGovernor,
    started_at: Instant,
}
impl Scheduler {
    pub fn new(
        queue_capacity: usize,
        budgets: BudgetLimits,
        governor: SpeedGovernor,
        scope_guard: Arc<dyn ScopeGuard>,
        event_sink: Arc<dyn EventSink>,
    ) -> Result<Self, SchedulerError> {
        if budgets.max_concurrency == 0 || budgets.max_execution_time_ms == 0 {
            return Err(SchedulerError::InvalidConfiguration(
                "concurrency and execution time must be positive",
            ));
        }
        let max_concurrency = governor.concurrency().min(budgets.max_concurrency);
        let governor = SpeedGovernor::new(governor.setting(), max_concurrency)?;
        Ok(Self {
            queue: TaskQueue::new(queue_capacity)?,
            tasks: BTreeMap::new(),
            modules: BTreeMap::new(),
            scope_guard,
            decision_engine: Arc::new(NoFollowUps),
            event_sink,
            budgets,
            ledger: BudgetLedger::default(),
            governor,
            started_at: Instant::now(),
        })
    }
    pub fn register_module(&mut self, module: Arc<dyn Module>) {
        self.modules.insert(module.kind(), module);
    }
    pub fn set_decision_engine(&mut self, engine: Arc<dyn DecisionEngine>) {
        self.decision_engine = engine;
    }
    pub fn add_task(&mut self, mut task: Task) -> Result<TaskId, SchedulerError> {
        if !self.scope_guard.permits(&task.scope_target) {
            return Err(SchedulerError::OutOfScope);
        }
        if self.tasks.contains_key(&task.id) {
            return Err(SchedulerError::DuplicateTask);
        }
        for dependency in &task.dependencies {
            if !self.tasks.contains_key(dependency) {
                return Err(SchedulerError::UnknownDependency(dependency.clone()));
            }
        }
        self.ledger.admit(&task, &self.budgets, false)?;
        task.state = TaskState::Pending;
        let id = task.id.clone();
        let provenance = task.provenance.clone();
        self.tasks.insert(
            id.clone(),
            TaskRecord {
                task,
                cancellation: CancellationToken::default(),
                queued: false,
                ready_at: Instant::now(),
                execution_started: None,
            },
        );
        self.emit(
            &id,
            TaskState::Pending,
            SchedulerEventKind::TaskCreated,
            None,
            provenance,
        );
        Ok(id)
    }
    pub fn cancel_task(&mut self, task_id: &TaskId) -> bool {
        let Some(record) = self.tasks.get_mut(task_id) else {
            return false;
        };
        record.task.cancel_requested = true;
        record.cancellation.cancel();
        if !record.task.state.terminal() && record.task.state != TaskState::Running {
            record.task.state = TaskState::Cancelled;
            self.emit_task(task_id, SchedulerEventKind::TaskCancelled, None);
        }
        true
    }
    pub fn cancel_all(&mut self) {
        let ids: Vec<TaskId> = self.tasks.keys().cloned().collect();
        for id in ids {
            self.cancel_task(&id);
        }
    }
    pub fn drain_pending(&mut self) -> Vec<TaskId> {
        let ids: Vec<TaskId> = self
            .tasks
            .iter()
            .filter(|(_, record)| {
                !record.task.state.terminal() && record.task.state != TaskState::Running
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in &ids {
            self.cancel_task(id);
        }
        ids
    }
    pub fn task(&self, task_id: &TaskId) -> Option<&Task> {
        self.tasks.get(task_id).map(|record| &record.task)
    }
    pub fn tasks(&self) -> impl Iterator<Item = &Task> {
        self.tasks.values().map(|record| &record.task)
    }
    pub fn run(&mut self) -> Result<SchedulerReport, SchedulerError> {
        let (sender, receiver) = mpsc::channel();
        let mut active = 0usize;
        let mut report = SchedulerReport::default();
        loop {
            self.promote_ready_tasks()?;
            while active < self.governor.concurrency() {
                let Some(task_id) = self.queue.pop() else {
                    break;
                };
                let Some(record) = self.tasks.get_mut(&task_id) else {
                    continue;
                };
                record.queued = false;
                if record.task.state.terminal() || record.task.cancel_requested {
                    continue;
                }
                if !self.scope_guard.permits(&record.task.scope_target) {
                    record.task.state = TaskState::Skipped;
                    report.skipped.push(task_id.clone());
                    self.emit_task(
                        &task_id,
                        SchedulerEventKind::TaskSkipped,
                        Some("scope changed"),
                    );
                    continue;
                }
                if record.ready_at > Instant::now() {
                    record.queued = true;
                    self.queue.push(task_id, record.task.priority)?;
                    break;
                }
                let Some(module) = self.modules.get(&record.task.kind).cloned() else {
                    record.task.state = TaskState::Skipped;
                    report.skipped.push(task_id.clone());
                    self.emit_task(
                        &task_id,
                        SchedulerEventKind::TaskSkipped,
                        Some("module unavailable"),
                    );
                    continue;
                };
                record.task.state = TaskState::Running;
                record.task.attempt = record.task.attempt.saturating_add(1);
                record.execution_started = Some(Instant::now());
                let attempt = record.task.attempt;
                let context = ModuleContext {
                    task: record.task.clone(),
                    cancellation: record.cancellation.clone(),
                };
                let task_id_for_worker = task_id.clone();
                self.emit_task(&task_id, SchedulerEventKind::TaskStarted, None);
                spawn_worker(module, context, sender.clone(), task_id_for_worker, attempt);
                active += 1;
            }

            if active == 0 {
                if self.all_terminal() {
                    break;
                }
                if self.started_at.elapsed().as_millis() as u64
                    >= self.budgets.max_execution_time_ms
                {
                    self.cancel_all();
                    continue;
                }
                thread::sleep(Duration::from_millis(1));
                continue;
            }

            let timeout = self.next_wait_timeout();
            match receiver.recv_timeout(timeout) {
                Ok(result) => {
                    active = active.saturating_sub(1);
                    self.handle_worker_result(result, &mut report)?;
                }
                Err(RecvTimeoutError::Timeout) => {
                    let now = Instant::now();
                    let timed_out: Vec<TaskId> = self
                        .tasks
                        .iter()
                        .filter(|(_, record)| {
                            record.task.state == TaskState::Running
                                && record.task.timeout_ms.checked_add(0).is_some_and(|_| {
                                    record.execution_started.is_some_and(|started| {
                                        now.duration_since(started).as_millis() as u64
                                            >= record.task.timeout_ms
                                    })
                                })
                        })
                        .map(|(id, _)| id.clone())
                        .take(1)
                        .collect();
                    if let Some(task_id) = timed_out.first() {
                        if let Some(record) = self.tasks.get_mut(task_id) {
                            record.task.state = TaskState::TimedOut;
                            record.cancellation.cancel();
                            report.timed_out.push(task_id.clone());
                            self.emit_task(task_id, SchedulerEventKind::TaskTimedOut, None);
                            active = active.saturating_sub(1);
                        }
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(SchedulerError::WorkerChannelClosed);
                }
            }
        }
        for (task_id, record) in &self.tasks {
            match record.task.state {
                TaskState::Failed if !report.failed.contains(task_id) => {
                    report.failed.push(task_id.clone())
                }
                TaskState::Cancelled if !report.cancelled.contains(task_id) => {
                    report.cancelled.push(task_id.clone())
                }
                TaskState::TimedOut if !report.timed_out.contains(task_id) => {
                    report.timed_out.push(task_id.clone())
                }
                TaskState::Skipped if !report.skipped.contains(task_id) => {
                    report.skipped.push(task_id.clone())
                }
                TaskState::Succeeded if !report.completed.contains(task_id) => {
                    report.completed.push(task_id.clone())
                }
                _ => {}
            }
        }
        Ok(report)
    }
    fn promote_ready_tasks(&mut self) -> Result<(), SchedulerError> {
        let candidates: Vec<TaskId> = self
            .tasks
            .iter()
            .filter(|(_, record)| record.task.state == TaskState::Pending && !record.queued)
            .map(|(id, _)| id.clone())
            .collect();
        for task_id in candidates {
            let (dependencies, priority, provenance) = {
                let record = self.tasks.get(&task_id).expect("candidate exists");
                (
                    record.task.dependencies.clone(),
                    record.task.priority,
                    record.task.provenance.clone(),
                )
            };
            let dependency_states: Vec<TaskState> = dependencies
                .iter()
                .filter_map(|id| self.tasks.get(id).map(|record| record.task.state))
                .collect();
            if dependency_states.iter().any(|state| {
                matches!(
                    state,
                    TaskState::Failed
                        | TaskState::Cancelled
                        | TaskState::TimedOut
                        | TaskState::Skipped
                )
            }) {
                let record = self.tasks.get_mut(&task_id).expect("candidate exists");
                record.task.state = TaskState::Skipped;
                self.emit(
                    &task_id,
                    TaskState::Skipped,
                    SchedulerEventKind::TaskSkipped,
                    Some("dependency failed"),
                    provenance,
                );
                continue;
            }
            if dependency_states.len() != dependencies.len()
                || dependency_states
                    .iter()
                    .any(|state| *state != TaskState::Succeeded)
            {
                continue;
            }
            if !self
                .scope_guard
                .permits(&self.tasks[&task_id].task.scope_target)
            {
                self.tasks
                    .get_mut(&task_id)
                    .expect("candidate exists")
                    .task
                    .state = TaskState::Skipped;
                self.emit_task(
                    &task_id,
                    SchedulerEventKind::TaskSkipped,
                    Some("scope changed"),
                );
                continue;
            }
            let record = self.tasks.get_mut(&task_id).expect("candidate exists");
            record.task.state = TaskState::Ready;
            record.queued = true;
            self.queue
                .push(task_id.clone(), priority)
                .inspect_err(|_| {
                    self.emit(
                        &task_id,
                        TaskState::Ready,
                        SchedulerEventKind::QueueSaturated,
                        None,
                        provenance.clone(),
                    );
                })?;
            self.emit(
                &task_id,
                TaskState::Ready,
                SchedulerEventKind::TaskQueued,
                None,
                provenance,
            );
        }
        Ok(())
    }
    fn handle_worker_result(
        &mut self,
        result: WorkerResult,
        report: &mut SchedulerReport,
    ) -> Result<(), SchedulerError> {
        let Some(record) = self.tasks.get_mut(&result.task_id) else {
            return Ok(());
        };
        if record.task.state != TaskState::Running || record.task.attempt != result.attempt {
            return Ok(());
        }
        let task_snapshot = record.task.clone();
        match result.result {
            Ok(output) => {
                self.ledger
                    .add_evidence(output.evidence_bytes(), &self.budgets)?;
                record.task.state = TaskState::Succeeded;
                record.execution_started = None;
                report.completed.push(result.task_id.clone());
                self.emit_task(&result.task_id, SchedulerEventKind::TaskCompleted, None);
                let followups = self
                    .decision_engine
                    .follow_up_tasks(&task_snapshot, &output);
                for task in followups {
                    self.add_task(task)?;
                }
            }
            Err(ModuleError::Cancelled) => {
                record.task.state = TaskState::Cancelled;
                record.execution_started = None;
                report.cancelled.push(result.task_id.clone());
                self.emit_task(&result.task_id, SchedulerEventKind::TaskCancelled, None);
            }
            Err(error)
                if error.retryable()
                    && record.task.attempt < record.task.retry_policy.max_attempts =>
            {
                self.ledger.admit(&record.task, &self.budgets, true)?;
                record.task.retry_count = record.task.retry_count.saturating_add(1);
                record.task.state = TaskState::Pending;
                record.execution_started = None;
                record.queued = false;
                record.ready_at = Instant::now()
                    + record
                        .task
                        .retry_policy
                        .delay_for_retry(record.task.retry_count);
                self.emit_task(
                    &result.task_id,
                    SchedulerEventKind::TaskRetried,
                    Some("retryable module failure"),
                );
            }
            Err(error) => {
                record.task.state = TaskState::Failed;
                record.execution_started = None;
                report.failed.push(result.task_id.clone());
                self.emit_task(
                    &result.task_id,
                    SchedulerEventKind::TaskFailed,
                    Some(&error.to_string()),
                );
            }
        }
        Ok(())
    }
    fn all_terminal(&self) -> bool {
        self.tasks
            .values()
            .all(|record| record.task.state.terminal())
    }
    fn next_wait_timeout(&self) -> Duration {
        let global_remaining = Duration::from_millis(self.budgets.max_execution_time_ms)
            .saturating_sub(self.started_at.elapsed());
        self.tasks
            .values()
            .filter(|record| record.task.state == TaskState::Running)
            .filter_map(|record| {
                record.execution_started.map(|started| {
                    Duration::from_millis(record.task.timeout_ms).saturating_sub(started.elapsed())
                })
            })
            .min()
            .unwrap_or(global_remaining)
            .min(global_remaining)
            .max(Duration::from_millis(1))
    }
    fn emit_task(&self, task_id: &TaskId, kind: SchedulerEventKind, reason: Option<&str>) {
        if let Some(record) = self.tasks.get(task_id) {
            self.emit(
                task_id,
                record.task.state,
                kind,
                reason,
                record.task.provenance.clone(),
            );
        }
    }
    fn emit(
        &self,
        task_id: &TaskId,
        state: TaskState,
        kind: SchedulerEventKind,
        reason: Option<&str>,
        provenance: Provenance,
    ) {
        self.event_sink.emit(SchedulerEvent {
            kind,
            task_id: task_id.clone(),
            state,
            timestamp: Timestamp::now(),
            provenance,
            reason: reason.map(str::to_owned),
        });
    }
}

fn spawn_worker(
    module: Arc<dyn Module>,
    context: ModuleContext,
    sender: Sender<WorkerResult>,
    task_id: TaskId,
    attempt: u32,
) {
    thread::spawn(move || {
        let result = block_on(module.execute(context));
        let _ = sender.send(WorkerResult {
            task_id,
            attempt,
            result,
        });
    });
}

fn block_on<F: Future>(future: F) -> F::Output {
    let thread = thread::current();
    let waker = unsafe { Waker::from_raw(raw_waker(thread)) };
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(&waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => thread::park(),
        }
    }
}

unsafe fn raw_waker(thread: thread::Thread) -> RawWaker {
    RawWaker::new(
        Box::into_raw(Box::new(thread)) as *const (),
        &RAW_WAKER_VTABLE,
    )
}
unsafe fn clone_waker(data: *const ()) -> RawWaker {
    let thread = unsafe { &*(data as *const thread::Thread) };
    unsafe { raw_waker(thread.clone()) }
}
unsafe fn wake_waker(data: *const ()) {
    let thread = unsafe { Box::from_raw(data as *mut thread::Thread) };
    thread.unpark();
}
unsafe fn wake_by_ref_waker(data: *const ()) {
    unsafe { (&*(data as *const thread::Thread)).unpark() };
}
unsafe fn drop_waker(data: *const ()) {
    drop(unsafe { Box::from_raw(data as *mut thread::Thread) });
}
static RAW_WAKER_VTABLE: RawWakerVTable =
    RawWakerVTable::new(clone_waker, wake_waker, wake_by_ref_waker, drop_waker);

fn kind_key(kind: &TaskKind) -> String {
    serde_json::to_string(kind).expect("TaskKind serializes")
}
fn stable_hash(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}
