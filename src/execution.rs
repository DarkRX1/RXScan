//! Phase 3 execution control plane (hardened in Phase 4).
//!
//! This module deliberately contains no network or process execution. Modules
//! supply bounded futures; the scheduler owns admission, ordering, limits,
//! cancellation, retries, dependencies, and follow-up-task validation.
//!
//! # Phase 4 contracts
//!
//! * Task identity is canonical and deterministic (SHA-256 over all
//!   execution-relevant fields). Two tasks that differ in kind, module,
//!   scope target, params, priority, timeout, retry policy, asset,
//!   parent, or dependencies MUST have different IDs.
//! * Modules MUST observe [`ModuleContext::is_cancelled`] frequently
//!   (at least every few milliseconds), use bounded I/O timeouts, and
//!   return [`ModuleError::Cancelled`] promptly when cancellation is
//!   requested. A timed-out task frees its scheduler slot immediately but
//!   the orphaned worker thread remains bounded by the task budget; late
//!   results from orphaned workers are discarded without double-counting.
//! * The hand-rolled `block_on` executor is a cooperative parking executor
//!   for Phase 4 stub/control modules only. Future real I/O modules must
//!   not block a worker thread indefinitely; they must use bounded timeouts
//!   and prompt cancellation checks.
//! * Retry-delayed tasks never head-of-line block other ready tasks.
//! * Queue saturation never aborts a run; excess tasks stay `Pending` until
//!   the queue drains.

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
    model::{AssetId, Event, Evidence, Finding, Provenance, SCHEMA_VERSION, ScanPlanId, Timestamp},
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
    Baseline,
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
    /// Deterministic task-specific parameters (e.g. `ports=all`,
    /// `cidr=192.0.2.0/24`, `target=example.test`). Part of task identity.
    #[serde(default)]
    pub params: BTreeMap<String, String>,
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
        Self::new_with_params(
            kind,
            parent_task_id,
            dependencies,
            associated_asset_id,
            scan_plan_id,
            priority,
            timeout,
            retry_policy,
            module_name,
            provenance,
            scope_target,
            BTreeMap::new(),
            scope_guard,
        )
    }

    /// Full constructor including deterministic `params`.
    ///
    /// NOTE: mutating `dependencies`, `params`, `priority`, `timeout`,
    /// `retry_policy`, `scope_target`, `kind`, `module_name`,
    /// `associated_asset_id`, or `parent_task_id` after construction
    /// invalidates the canonical ID. Prefer constructing tasks with their
    /// final values (as `lower_plan_to_tasks` does).
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_params(
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
        params: BTreeMap<String, String>,
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
        for (key, value) in &params {
            if key.trim().is_empty() || key.contains('\0') || value.contains('\0') {
                return Err(SchedulerError::InvalidTask("invalid task params"));
            }
        }
        if !scope_guard.permits(&scope_target) {
            return Err(SchedulerError::OutOfScope);
        }
        let created_at = provenance.timestamp;
        let timeout_ms = timeout.as_millis().min(u64::MAX as u128) as u64;
        let deadline = Some(Timestamp(created_at.0.saturating_add(timeout_ms)));
        let id = canonical_task_id(
            &scan_plan_id,
            &module_name,
            &kind,
            &associated_asset_id,
            &parent_task_id,
            &dependencies,
            priority,
            timeout_ms,
            &retry_policy,
            &scope_target,
            &params,
        );
        Ok(Self {
            id,
            kind,
            parent_task_id,
            dependencies,
            associated_asset_id,
            scan_plan_id,
            priority,
            state: TaskState::Pending,
            created_at,
            timeout_ms,
            deadline,
            retry_policy,
            attempt: 0,
            retry_count: 0,
            cancel_requested: false,
            module_name,
            provenance,
            budget: BudgetAccount::default(),
            scope_target,
            params,
        })
    }

    pub fn canonical_identity(&self) -> TaskId {
        canonical_task_id(
            &self.scan_plan_id,
            &self.module_name,
            &self.kind,
            &self.associated_asset_id,
            &self.parent_task_id,
            &self.dependencies,
            self.priority,
            self.timeout_ms,
            &self.retry_policy,
            &self.scope_target,
            &self.params,
        )
    }

    pub fn identity_is_valid(&self) -> bool {
        self.id == self.canonical_identity()
    }
}

/// Canonical deterministic task identity.
///
/// All execution-relevant fields participate: plan, module, kind,
/// asset, parent, dependencies (sorted), priority, timeout, retry
/// policy, scope target, and params (BTreeMap order). Runtime-mutable
/// fields (state, attempt counts, timestamps, budgets) do NOT
/// participate so the same logical task keeps one ID across retries.
///
/// Serialization uses `serde_json` over a fixed-field struct with
/// `BTreeMap` params, so it is independent of `HashMap` iteration
/// order. The digest is SHA-256 (hex, `task_` prefixed), which is
/// collision-resistant for untrusted inputs.
#[allow(clippy::too_many_arguments)]
fn canonical_task_id(
    scan_plan_id: &ScanPlanId,
    module_name: &str,
    kind: &TaskKind,
    associated_asset_id: &Option<AssetId>,
    parent_task_id: &Option<TaskId>,
    dependencies: &[TaskId],
    priority: u8,
    timeout_ms: u64,
    retry_policy: &RetryPolicy,
    scope_target: &TaskScopeTarget,
    params: &BTreeMap<String, String>,
) -> TaskId {
    let mut sorted_deps: Vec<&str> = dependencies.iter().map(|id| id.0.as_str()).collect();
    sorted_deps.sort_unstable();
    let identity = serde_json::json!({
        "plan": scan_plan_id.0,
        "module": module_name,
        "kind": kind_key(kind),
        "asset": associated_asset_id.as_ref().map_or("", |id| id.0.as_str()),
        "parent": parent_task_id.as_ref().map_or("", |id| id.0.as_str()),
        "deps": sorted_deps,
        "priority": priority,
        "timeout_ms": timeout_ms,
        "retry_max": retry_policy.max_attempts,
        "retry_delay_ms": retry_policy.base_delay_ms,
        "scope": serde_json::to_string(scope_target).unwrap_or_default(),
        "params": params,
    });
    let bytes = serde_json::to_vec(&identity).expect("task identity serializes");
    TaskId(format!("task_{}", sha256_hex(&bytes)))
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
    pub fn capacity(&self) -> usize {
        self.capacity
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

/// Hard safety ceilings for Phase 4 configurable budgets.
/// Values above these limits are rejected fail-fast.
pub const MAX_TASKS_HARD_LIMIT: u64 = 100_000;
pub const MAX_RETRIES_HARD_LIMIT: u64 = 100_000;
pub const MAX_CONCURRENCY_HARD_LIMIT: usize = 64;
pub const MAX_EXECUTION_TIME_MS_HARD_LIMIT: u64 = 3_600_000;
pub const MAX_EVIDENCE_BYTES_HARD_LIMIT: u64 = 1024 * 1024 * 1024;
/// Phase 5 host-discovery bound: at most this many hosts may be generated
/// from explicit CIDR targets. Large scopes stay bounded; Level 5 never
/// means unbounded.
pub const MAX_HOSTS_HARD_LIMIT: u64 = 100_000;
/// Default host bound: one /24 worth of hosts. Larger ranges are truncated
/// deterministically (first `max_hosts` permitted addresses in order).
pub const DEFAULT_MAX_HOSTS: u64 = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetLimits {
    pub max_tasks: u64,
    pub max_retries: u64,
    pub max_concurrency: usize,
    pub max_execution_time_ms: u64,
    pub max_evidence_bytes: u64,
    /// Phase 5: cap on hosts generated from CIDR targets (1..=100000).
    /// Defaults to 256 (one /24). Enforced during plan lowering.
    #[serde(default = "default_max_hosts")]
    pub max_hosts: u64,
    #[serde(default)]
    pub per_module: BTreeMap<String, ModuleBudget>,
}
fn default_max_hosts() -> u64 {
    DEFAULT_MAX_HOSTS
}
impl Default for BudgetLimits {
    fn default() -> Self {
        Self {
            max_tasks: 1_000,
            max_retries: 1_000,
            max_concurrency: 4,
            max_execution_time_ms: 60_000,
            max_evidence_bytes: 64 * 1024 * 1024,
            max_hosts: DEFAULT_MAX_HOSTS,
            per_module: BTreeMap::new(),
        }
    }
}
impl BudgetLimits {
    /// Fail-fast validation for user-supplied budgets.
    pub fn validate(&self) -> Result<(), SchedulerError> {
        if self.max_tasks == 0
            || self.max_retries == 0
            || self.max_concurrency == 0
            || self.max_execution_time_ms == 0
            || self.max_evidence_bytes == 0
            || self.max_hosts == 0
        {
            return Err(SchedulerError::InvalidConfiguration(
                "budgets must be positive (max tasks, retries, concurrency, execution time, evidence bytes, hosts)",
            ));
        }
        if self.max_tasks > MAX_TASKS_HARD_LIMIT
            || self.max_retries > MAX_RETRIES_HARD_LIMIT
            || self.max_concurrency > MAX_CONCURRENCY_HARD_LIMIT
            || self.max_execution_time_ms > MAX_EXECUTION_TIME_MS_HARD_LIMIT
            || self.max_evidence_bytes > MAX_EVIDENCE_BYTES_HARD_LIMIT
            || self.max_hosts > MAX_HOSTS_HARD_LIMIT
        {
            return Err(SchedulerError::InvalidConfiguration(
                "budget exceeds hard safety limit",
            ));
        }
        Ok(())
    }

    /// Deterministic bounded queue capacity derived from budgets.
    /// Keeps the queue bounded without requiring another CLI flag.
    pub fn queue_capacity(&self) -> usize {
        // At least enough to keep workers fed, at most max_tasks, and
        // always bounded by the hard task limit.
        (self.max_concurrency.saturating_mul(16))
            .max(self.max_concurrency.saturating_add(4))
            .min(self.max_tasks.min(MAX_TASKS_HARD_LIMIT) as usize)
            .max(1)
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

/// Phase 4 speed policy: `--speed` is execution pressure, independent of `--level`.
///
/// * `slow`/`balanced`/`fast` map to deterministic pressure values.
/// * Numeric `0-100` interpolates pressure directly; 100 is still capped by
///   `max_concurrency` and never means unlimited.
/// * `auto` v1 is a conservative deterministic baseline identical to
///   `balanced`. It is NOT adaptive in Phase 4; adaptive feedback based on
///   runtime scheduler metrics is deferred to Phase 4.1+. `--explain`
///   reports this honestly.
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
    /// Default per-task timeout derived from speed. Faster pressure fails
    /// faster; slower pressure waits longer. All values are bounded.
    pub fn default_timeout(&self) -> Duration {
        let millis = match self.setting {
            SpeedSetting::Named(crate::plan::NamedSpeed::Slow) => 30_000,
            SpeedSetting::Named(crate::plan::NamedSpeed::Balanced) => 15_000,
            SpeedSetting::Named(crate::plan::NamedSpeed::Fast) => 10_000,
            SpeedSetting::Named(crate::plan::NamedSpeed::Auto) => 15_000,
            SpeedSetting::Numeric(value) => {
                // 0 -> 30s, 100 -> 5s, linear interpolation, always bounded.
                30_000u64.saturating_sub((25_000u64 * u64::from(value)) / 100)
            }
        };
        Duration::from_millis(millis.max(1_000))
    }
    /// Default retry policy derived from speed.
    pub fn default_retry_policy(&self) -> RetryPolicy {
        RetryPolicy {
            max_attempts: self.retry_limit().max(1),
            base_delay_ms: match self.setting {
                SpeedSetting::Named(crate::plan::NamedSpeed::Slow) => 200,
                SpeedSetting::Named(crate::plan::NamedSpeed::Balanced) => 100,
                SpeedSetting::Named(crate::plan::NamedSpeed::Fast) => 50,
                SpeedSetting::Named(crate::plan::NamedSpeed::Auto) => 100,
                SpeedSetting::Numeric(value) if value < 25 => 200,
                SpeedSetting::Numeric(value) if value < 75 => 100,
                SpeedSetting::Numeric(_) => 50,
            },
        }
    }
    pub fn setting(&self) -> SpeedSetting {
        self.setting
    }
    /// Phase 4 auto is intentionally non-adaptive.
    pub fn is_adaptive(&self) -> bool {
        false
    }
    pub fn describe(&self) -> String {
        let adaptive = if self.is_adaptive() {
            "adaptive"
        } else {
            "deterministic baseline (non-adaptive in Phase 4; auto == balanced)"
        };
        format!(
            "speed {} -> concurrency {}, retry_limit {}, default_timeout_ms {}, {}",
            self.setting,
            self.concurrency(),
            self.retry_limit(),
            self.default_timeout().as_millis(),
            adaptive
        )
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
    #[serde(default = "default_schema_version")]
    pub schema_version: u16,
    pub kind: SchedulerEventKind,
    pub task_id: TaskId,
    pub state: TaskState,
    pub timestamp: Timestamp,
    pub provenance: Provenance,
    pub reason: Option<String>,
}

fn default_schema_version() -> u16 {
    SCHEMA_VERSION
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

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ModuleOutput {
    pub events: Vec<Event>,
    pub evidence: Vec<Evidence>,
    pub findings: Vec<Finding>,
    /// Phase 5: assets observed by the module (e.g. discovered hosts).
    /// Recording an observation never grants scheduling authority.
    pub assets: Vec<crate::model::Asset>,
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
    pub fn new(task: Task, cancellation: CancellationToken) -> Self {
        Self { task, cancellation }
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }
}

/// A unit of executable work.
///
/// # Cancellation contract (mandatory for all future network modules)
///
/// * Check [`ModuleContext::is_cancelled`] at least every few milliseconds
///   and after every bounded I/O wait.
/// * Use bounded I/O timeouts (never block indefinitely on a socket/read).
/// * On observed cancellation, return [`ModuleError::Cancelled`] promptly
///   and drop/close sockets and other resources immediately.
/// * Never spawn unbounded threads, processes, or follow-up tasks;
///   follow-ups belong to the [`DecisionEngine`] and scheduler admission.
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
    /// Phase 5: completed module outputs retained for JSONL output.
    /// Keyed by task ID; only `Succeeded` tasks populate this map.
    completed_outputs: BTreeMap<TaskId, ModuleOutput>,
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
            completed_outputs: BTreeMap::new(),
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

    pub fn restore_task(
        &mut self,
        mut task: Task,
        output: Option<ModuleOutput>,
    ) -> Result<TaskId, SchedulerError> {
        if !self.scope_guard.permits(&task.scope_target) {
            return Err(SchedulerError::OutOfScope);
        }
        if self.tasks.contains_key(&task.id) {
            return Err(SchedulerError::DuplicateTask);
        }
        self.ledger.admit(&task, &self.budgets, false)?;
        if matches!(task.state, TaskState::Running | TaskState::Ready) {
            task.state = TaskState::Pending;
            task.attempt = 0;
            task.cancel_requested = false;
        }
        let queued = false;
        let ready_at = Instant::now();
        let id = task.id.clone();
        if matches!(task.state, TaskState::Succeeded) {
            if let Some(output) = output {
                self.completed_outputs.insert(id.clone(), output);
            }
        }
        self.tasks.insert(
            id.clone(),
            TaskRecord {
                task,
                cancellation: CancellationToken::default(),
                queued,
                ready_at,
                execution_started: None,
            },
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
        // `active` counts scheduler slots in use (Running tasks not yet
        // reaped as terminal). A timed-out task frees its slot immediately;
        // its orphaned worker thread (if any) is bounded by the task budget
        // and its late result is discarded without touching `active`.
        let mut active = 0usize;
        let mut report = SchedulerReport::default();
        loop {
            self.promote_ready_tasks()?;
            // Dispatch loop: never let a retry-delayed task head-of-line
            // block other ready tasks. Not-ready pops are stashed aside and
            // requeued after the dispatch window.
            let mut deferred: Vec<(TaskId, u8)> = Vec::new();
            while active < self.governor.concurrency() {
                let Some(task_id) = self.queue.pop() else {
                    break;
                };
                let now = Instant::now();
                let should_defer = self.tasks.get(&task_id).is_some_and(|record| {
                    !record.task.state.terminal()
                        && !record.task.cancel_requested
                        && record.ready_at > now
                });
                if should_defer {
                    let priority = self.tasks.get(&task_id).map_or(0, |r| r.task.priority);
                    // Mark as not-queued while stashed; requeue below.
                    if let Some(record) = self.tasks.get_mut(&task_id) {
                        record.queued = false;
                    }
                    deferred.push((task_id, priority));
                    continue;
                }
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
            // Requeue deferred (not-yet-ready) tasks without blocking others.
            // Queue has free slots (we just popped), so push should succeed;
            // if saturated anyway, leave them Pending for the next loop.
            for (task_id, priority) in deferred {
                let is_ready = self
                    .tasks
                    .get(&task_id)
                    .is_some_and(|record| record.task.state == TaskState::Ready);
                if !is_ready {
                    continue;
                }
                match self.queue.push(task_id.clone(), priority) {
                    Ok(()) => {
                        if let Some(record) = self.tasks.get_mut(&task_id) {
                            record.queued = true;
                        }
                    }
                    Err(SchedulerError::QueueSaturated) => {
                        let provenance = self
                            .tasks
                            .get(&task_id)
                            .map(|record| record.task.provenance.clone());
                        if let Some(record) = self.tasks.get_mut(&task_id) {
                            record.task.state = TaskState::Pending;
                            record.queued = false;
                        }
                        if let Some(provenance) = provenance {
                            self.emit(
                                &task_id,
                                TaskState::Pending,
                                SchedulerEventKind::QueueSaturated,
                                Some("queue saturated; retrying when drained"),
                                provenance,
                            );
                        }
                    }
                    Err(error) => return Err(error),
                }
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
                    // Only consume a slot for a genuinely Running attempt.
                    // Stale/orphaned results (already TimedOut/Cancelled or
                    // attempt mismatch) were already freed; discard silently.
                    let is_live = self.tasks.get(&result.task_id).is_some_and(|record| {
                        record.task.state == TaskState::Running
                            && record.task.attempt == result.attempt
                    });
                    if is_live {
                        active = active.saturating_sub(1);
                        self.handle_worker_result(result, &mut report)?;
                    } else {
                        // Orphaned worker reaped; slot was already freed at
                        // timeout/cancel time. Discard without double-count.
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    // Reap ALL expired Running tasks per timeout tick, not
                    // just one, so concurrent timeouts all become terminal.
                    let now = Instant::now();
                    let timed_out: Vec<TaskId> = self
                        .tasks
                        .iter()
                        .filter(|(_, record)| {
                            record.task.state == TaskState::Running
                                && record.execution_started.is_some_and(|started| {
                                    now.duration_since(started).as_millis() as u64
                                        >= record.task.timeout_ms
                                })
                        })
                        .map(|(id, _)| id.clone())
                        .collect();
                    for task_id in timed_out {
                        if let Some(record) = self.tasks.get_mut(&task_id) {
                            if record.task.state != TaskState::Running {
                                continue;
                            }
                            record.task.state = TaskState::TimedOut;
                            record.execution_started = None;
                            record.cancellation.cancel();
                            report.timed_out.push(task_id.clone());
                            self.emit_task(&task_id, SchedulerEventKind::TaskTimedOut, None);
                            // Free the slot immediately; the orphaned worker
                            // (if non-cooperative) stays bounded by max_tasks.
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
        let now = Instant::now();
        let candidates: Vec<TaskId> = self
            .tasks
            .iter()
            .filter(|(_, record)| {
                record.task.state == TaskState::Pending && !record.queued && record.ready_at <= now
            })
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
            // Queue saturation is backpressure, not a fatal error: leave
            // the task Pending so it is retried once the queue drains.
            match self.queue.push(task_id.clone(), priority) {
                Ok(()) => {
                    let record = self.tasks.get_mut(&task_id).expect("candidate exists");
                    record.task.state = TaskState::Ready;
                    record.queued = true;
                    self.emit(
                        &task_id,
                        TaskState::Ready,
                        SchedulerEventKind::TaskQueued,
                        None,
                        provenance,
                    );
                }
                Err(SchedulerError::QueueSaturated) => {
                    self.emit(
                        &task_id,
                        TaskState::Pending,
                        SchedulerEventKind::QueueSaturated,
                        Some("queue saturated; retrying when drained"),
                        provenance,
                    );
                    // Stop promoting this tick; remaining candidates stay
                    // Pending and will be retried next loop iteration.
                    break;
                }
                Err(error) => return Err(error),
            }
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
                self.completed_outputs
                    .insert(result.task_id.clone(), output.clone());
                self.emit_task(&result.task_id, SchedulerEventKind::TaskCompleted, None);
                let followups = self
                    .decision_engine
                    .follow_up_tasks(&task_snapshot, &output);
                // Phase 6: follow-up admission is best-effort and bounded.
                // Duplicates (same canonical ID as an initial task),
                // out-of-scope proposals, and budget-exhausted proposals are
                // skipped without aborting the run; initial tasks still fail
                // fast via `add_task` in `run.rs`. This gives duplicate
                // proposal prevention and scope/budget enforcement for free.
                for task in followups {
                    match self.add_task(task) {
                        Ok(_) => {}
                        Err(
                            SchedulerError::DuplicateTask
                            | SchedulerError::OutOfScope
                            | SchedulerError::BudgetExhausted(_)
                            | SchedulerError::UnknownDependency(_)
                            | SchedulerError::QueueSaturated,
                        ) => {}
                        Err(error) => return Err(error),
                    }
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
    /// Effective concurrency after capping the governor by budgets.
    pub fn effective_concurrency(&self) -> usize {
        self.governor.concurrency()
    }
    pub fn governor(&self) -> &SpeedGovernor {
        &self.governor
    }
    pub fn budgets(&self) -> &BudgetLimits {
        &self.budgets
    }
    /// Completed module outputs for JSONL output (Phase 5 discovery results).
    pub fn module_outputs(&self) -> Vec<(TaskId, ModuleOutput)> {
        self.completed_outputs
            .iter()
            .map(|(id, output)| (id.clone(), output.clone()))
            .collect()
    }
    pub fn queue_depth(&self) -> usize {
        self.queue.len()
    }
    pub fn queue_capacity(&self) -> usize {
        self.queue.capacity()
    }
    pub fn task_count(&self) -> usize {
        self.tasks.len()
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
            schema_version: SCHEMA_VERSION,
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
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Legacy FNV-1a helper retained for stable asset/model IDs in `model.rs`.
/// Task IDs use [`sha256_hex`] (collision-resistant for untrusted inputs).
#[allow(dead_code)]
fn stable_hash(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}
