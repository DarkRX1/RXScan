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
    collections::{BTreeMap, BinaryHeap, HashSet},
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
    UdpDiscovery,
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
    /// NOTE: mutating `dependencies`, `params` (except the explanatory
    /// `reason` key and the discovery-lineage keys `discovery_depth`,
    /// `discovery_path`, `parent_evidence_id`, `originating_seed`,
    /// `truncated_expansions`, all stripped from the identity hash),
    /// `priority`, `timeout`, `retry_policy`, `scope_target`, `kind`,
    /// `module_name`, `associated_asset_id`, or `parent_task_id` after
    /// construction invalidates the canonical ID. Prefer constructing tasks
    /// with their final values (as `lower_plan_to_tasks` does).
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
/// The explanatory `reason` param (evidence-driven follow-up rationale,
/// Phase 17) is stripped before hashing: it documents WHY a task exists
/// without changing WHAT it is, so engine proposals dedup against
/// identically-shaped lowering tasks instead of rescanning.
///
/// Discovery-lineage params (`discovery_depth`, `discovery_path`,
/// `parent_evidence_id`, `originating_seed`, `truncated_expansions`) are
/// likewise stripped: they describe HOW a target was found, not what work
/// the task performs. Two proposals for the same target therefore share
/// one ID however deep their discovery chains, so repeated evidence never
/// produces unbounded duplicate tasks.
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
    let identity_params: BTreeMap<&str, &str> = params
        .iter()
        .filter(|(key, _)| {
            !matches!(
                key.as_str(),
                "reason"
                    | "discovery_depth"
                    | "discovery_path"
                    | "parent_evidence_id"
                    | "originating_seed"
                    | "truncated_expansions"
            )
        })
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
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
        "params": identity_params,
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
    pub fn retries_consumed(&self) -> u64 {
        self.retries
    }
    pub fn retries_by_module(&self) -> BTreeMap<String, u64> {
        self.module_retries.clone()
    }
    pub fn tasks_by_module(&self) -> BTreeMap<String, u64> {
        self.module_tasks.clone()
    }
    pub fn evidence_bytes(&self) -> u64 {
        self.evidence_bytes
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
    /// Explicit concurrency budget this governor was built with. Exposed so
    /// [`Scheduler::new`] can combine caller and scheduler budgets by taking
    /// the minimum *before* deriving pressure (Phase 20 governor fix).
    pub fn budget(&self) -> usize {
        self.max_concurrency
    }
    /// Auto is currently a deterministic, non-adaptive baseline.
    pub fn is_adaptive(&self) -> bool {
        false
    }
    pub fn describe(&self) -> String {
        let adaptive = if self.is_adaptive() {
            "adaptive"
        } else {
            "deterministic baseline (non-adaptive; auto == balanced)"
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
    global_cancellation: CancellationToken,
    /// Authoritative absolute wall-clock deadline for the whole scan.
    /// `None` means no global bound (tests / unbounded contexts).
    /// Every subsystem must derive remaining budget as
    /// `global_deadline - now` and never exceed it.
    global_deadline: Option<Instant>,
}
impl ModuleContext {
    pub fn new(task: Task, cancellation: CancellationToken) -> Self {
        Self {
            task,
            cancellation,
            global_cancellation: CancellationToken::default(),
            global_deadline: None,
        }
    }
    /// Scheduler path: attach the authoritative global deadline + cancel.
    pub fn with_global(
        task: Task,
        cancellation: CancellationToken,
        global_cancellation: CancellationToken,
        global_deadline: Option<Instant>,
    ) -> Self {
        Self {
            task,
            cancellation,
            global_cancellation,
            global_deadline,
        }
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled() || self.global_cancellation.is_cancelled()
    }
    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }
    pub fn global_cancellation(&self) -> CancellationToken {
        self.global_cancellation.clone()
    }
    pub fn global_deadline(&self) -> Option<Instant> {
        self.global_deadline
    }
    /// Remaining global budget (`global_deadline - now`), if any.
    pub fn global_remaining(&self) -> Option<Duration> {
        self.global_deadline.map(|deadline| {
            let now = Instant::now();
            if now >= deadline {
                Duration::ZERO
            } else {
                deadline.duration_since(now)
            }
        })
    }
    /// Effective absolute deadline for this task: the earlier of the
    /// per-task timeout and the global wall-clock deadline. No task may
    /// receive a timeout exceeding the remaining global budget.
    pub fn effective_deadline(&self) -> Option<Instant> {
        let task_deadline =
            Instant::now().checked_add(Duration::from_millis(self.task.timeout_ms.max(1)));
        match (task_deadline, self.global_deadline) {
            (Some(task), Some(global)) => Some(task.min(global)),
            (Some(task), None) => Some(task),
            (None, Some(global)) => Some(global),
            (None, None) => None,
        }
    }
    /// Remaining time before the effective (task ∩ global) deadline.
    pub fn effective_remaining(&self) -> Option<Duration> {
        self.effective_deadline().map(|deadline| {
            let now = Instant::now();
            if now >= deadline {
                Duration::ZERO
            } else {
                deadline.duration_since(now)
            }
        })
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationReason {
    #[default]
    Completed,
    GlobalDeadline,
    TaskBudget,
    RetryBudget,
    EvidenceBudget,
    OutputBudget,
    UserCancelled,
    InternalFailure,
}

impl std::fmt::Display for TerminationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Completed => write!(f, "completed"),
            Self::GlobalDeadline => write!(f, "global_deadline"),
            Self::TaskBudget => write!(f, "task_budget"),
            Self::RetryBudget => write!(f, "retry_budget"),
            Self::EvidenceBudget => write!(f, "evidence_budget"),
            Self::OutputBudget => write!(f, "output_budget"),
            Self::UserCancelled => write!(f, "user_cancelled"),
            Self::InternalFailure => write!(f, "internal_failure"),
        }
    }
}

/// Structured network/error taxonomy (Priority 5).
///
/// The scheduler keeps aggregate totals for compatibility but every
/// generic failure is also classified into one of these buckets so
/// large-scale runs stay actionable instead of producing hundreds of
/// thousands of undifferentiated `errors`. Classification is
/// best-effort from OS errno / message text; unknown cases map to
/// `Other` and never lose the aggregate count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    ConnectionRefused,
    ConnectTimeout,
    HostUnreachable,
    NetworkUnreachable,
    PermissionDenied,
    SocketCreationFailure,
    FdExhaustion,
    QueueRejected,
    TaskDeadline,
    GlobalDeadline,
    Cancelled,
    IcmpUnreachable,
    ProtocolError,
    ResourceExhaustion,
    InternalError,
    Other,
}

impl std::fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::ConnectionRefused => "connection_refused",
            Self::ConnectTimeout => "connect_timeout",
            Self::HostUnreachable => "host_unreachable",
            Self::NetworkUnreachable => "network_unreachable",
            Self::PermissionDenied => "permission_denied",
            Self::SocketCreationFailure => "socket_creation_failure",
            Self::FdExhaustion => "fd_exhaustion",
            Self::QueueRejected => "queue_rejected",
            Self::TaskDeadline => "task_deadline",
            Self::GlobalDeadline => "global_deadline",
            Self::Cancelled => "cancelled",
            Self::IcmpUnreachable => "icmp_unreachable",
            Self::ProtocolError => "protocol_error",
            Self::ResourceExhaustion => "resource_exhaustion",
            Self::InternalError => "internal_error",
            Self::Other => "other",
        };
        f.write_str(name)
    }
}

impl ErrorCategory {
    pub fn all() -> &'static [Self] {
        &[
            Self::ConnectionRefused,
            Self::ConnectTimeout,
            Self::HostUnreachable,
            Self::NetworkUnreachable,
            Self::PermissionDenied,
            Self::SocketCreationFailure,
            Self::FdExhaustion,
            Self::QueueRejected,
            Self::TaskDeadline,
            Self::GlobalDeadline,
            Self::Cancelled,
            Self::IcmpUnreachable,
            Self::ProtocolError,
            Self::ResourceExhaustion,
            Self::InternalError,
            Self::Other,
        ]
    }
}

/// Classify a free-form probe/module detail string into a structured
/// error bucket. Never panics; unknown text maps to `Other`.
pub fn classify_error_detail(detail: &str) -> ErrorCategory {
    let lower = detail.to_ascii_lowercase();
    if lower.contains("cancelled") || lower.contains("canceled") {
        return ErrorCategory::Cancelled;
    }
    if lower.contains("global deadline") || lower.contains("global_deadline") {
        return ErrorCategory::GlobalDeadline;
    }
    if lower.contains("task deadline")
        || lower.contains("task_deadline")
        || lower.contains("timed out after")
        || lower.contains("timed out")
    {
        // Distinguish connect timeouts from generic task deadlines by
        // context: explicit connect/timeout wording wins.
        if lower.contains("connect") || lower.contains("timed out") {
            return ErrorCategory::ConnectTimeout;
        }
        return ErrorCategory::TaskDeadline;
    }
    if lower.contains("refused") || lower.contains("rst") || lower.contains("errno 111") {
        return ErrorCategory::ConnectionRefused;
    }
    if lower.contains("host unreachable")
        || lower.contains("ehostunreach")
        || lower.contains("errno 113")
    {
        return ErrorCategory::HostUnreachable;
    }
    if lower.contains("network unreachable")
        || lower.contains("enetunreach")
        || lower.contains("errno 101")
    {
        return ErrorCategory::NetworkUnreachable;
    }
    if lower.contains("permission") || lower.contains("errno 13") || lower.contains("errno 1") {
        return ErrorCategory::PermissionDenied;
    }
    if lower.contains("socket creation failed") {
        return ErrorCategory::SocketCreationFailure;
    }
    if lower.contains("emfile")
        || lower.contains("enfile")
        || lower.contains("enomem")
        || lower.contains("errno 24")
        || lower.contains("errno 23")
        || lower.contains("errno 12")
        || lower.contains("fd") && lower.contains("exhaust")
    {
        return ErrorCategory::FdExhaustion;
    }
    if lower.contains("queue") {
        return ErrorCategory::QueueRejected;
    }
    if lower.contains("unreachable") && lower.contains("icmp") {
        return ErrorCategory::IcmpUnreachable;
    }
    if lower.contains("unreachable") {
        return ErrorCategory::HostUnreachable;
    }
    if lower.contains("protocol") || lower.contains("grammar") || lower.contains("handshake") {
        return ErrorCategory::ProtocolError;
    }
    if lower.contains("resource") || lower.contains("memory") || lower.contains("budget") {
        return ErrorCategory::ResourceExhaustion;
    }
    if lower.contains("internal") {
        return ErrorCategory::InternalError;
    }
    ErrorCategory::Other
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SchedulerReport {
    pub completed: Vec<TaskId>,
    pub failed: Vec<TaskId>,
    pub cancelled: Vec<TaskId>,
    pub timed_out: Vec<TaskId>,
    pub skipped: Vec<TaskId>,
    /// Peak scheduler-queue occupancy observed during the run.
    ///
    /// Phase 19 observability: proves the bounded queue stayed within
    /// `queue_capacity()` without changing admission or ordering truth.
    pub queue_peak: usize,
    /// Peak simultaneously active worker slots observed during the run.
    ///
    /// Always `<= effective_concurrency() <= MAX_CONCURRENCY_HARD_LIMIT`.
    pub active_peak: usize,
    /// Structured termination state (Priority 6). `Completed` when every
    /// admitted task reached a terminal state within budgets and the
    /// global deadline. Any budget/deadline truncation is a normal bounded
    /// termination here, never an internal scheduler failure.
    pub termination: TerminationReason,
    /// Tasks admitted vs never admitted (budget/deadline-truncated).
    /// `admitted + not_admitted` covers every task the plan produced.
    pub tasks_admitted: u64,
    pub tasks_not_admitted: u64,
    /// Bounded-execution accounting for diagnostics (Priorities 7/10).
    pub evidence_bytes: u64,
    pub retries_consumed: u64,
    /// Per-module retry consumption (module -> retries).
    pub retries_by_module: BTreeMap<String, u64>,
    /// Structured error counts by category (Priority 5). Aggregate
    /// `failed + timed_out + cancelled` still holds; this map explains it.
    pub errors_by_category: BTreeMap<String, u64>,
    /// Wall-clock runtime + cleanup overhead (Priority 10).
    pub wall_ms: u64,
    pub cleanup_ms: u64,
    /// Configured global deadline + observed overrun, if any.
    pub deadline_ms: u64,
    pub deadline_overrun_ms: u64,
    /// Failures by high-level module/stage (Priority 8). Keys are module
    /// names (`rxscan.port`, `rxscan.http`, ...); values are failure counts.
    pub failures_by_module: BTreeMap<String, u64>,
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
    /// Phase 20: effective worker-slot concurrency, derived EXACTLY ONCE in
    /// [`Scheduler::new`] from the speed setting and the tighter of the
    /// caller and scheduler concurrency budgets. Previously the *derived*
    /// value was fed back as the new maximum, applying the pressure formula
    /// a second time and collapsing e.g. `Numeric(50)` + budget 4 from 2
    /// slots to 1. Budget combination is idempotent now: rebuilding changes
    /// nothing. Dispatch uses only this field.
    effective_concurrency: usize,
    started_at: Instant,
    /// Authoritative absolute wall-clock deadline for the whole run
    /// (`started_at + max_execution_time_ms`, reset at each `run()`).
    /// Every subsystem derives remaining budget as `deadline - now`.
    global_deadline: Instant,
    /// Global cancellation broadcast to every active module via
    /// `ModuleContext::is_cancelled`. Fired exactly once when the
    /// deadline expires or `request_shutdown()` (Ctrl+C) is called.
    global_cancel: CancellationToken,
    /// Structured termination + truncation accounting (P6/P10).
    termination: TerminationReason,
    tasks_not_admitted: u64,
    errors_by_category: BTreeMap<String, u64>,
    failures_by_module: BTreeMap<String, u64>,
    /// Phase 10 diagnostics: per-kind dispatch counts for fairness proofs.
    dispatch_by_kind: BTreeMap<String, u64>,
    /// Phase 10 diagnostics: peak queue depth is in the report; this
    /// tracks admission rejections by reason for the final report.
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
        // Phase 20: derive pressure exactly once. Combine the caller and
        // scheduler budgets by taking the minimum FIRST, then derive once
        // with that budget. Feeding the derived value back as a maximum
        // re-applies the pressure formula and collapses concurrency (P19
        // finding: Numeric(50)+4 collapsed 2 -> 1); budget combination is
        // idempotent and keeps the explicit budget an upper bound.
        let budget = governor.budget().min(budgets.max_concurrency).max(1);
        let governor = SpeedGovernor::new(governor.setting(), budget)?;
        let effective_concurrency = governor.concurrency();
        let started_at = Instant::now();
        let global_deadline = started_at
            .checked_add(Duration::from_millis(budgets.max_execution_time_ms.max(1)))
            .unwrap_or(started_at + Duration::from_secs(3600));
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
            effective_concurrency,
            started_at,
            global_deadline,
            global_cancel: CancellationToken::default(),
            termination: TerminationReason::Completed,
            tasks_not_admitted: 0,
            errors_by_category: BTreeMap::new(),
            failures_by_module: BTreeMap::new(),
            dispatch_by_kind: BTreeMap::new(),
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
        // Hard deadline is also an admission gate: once expired, no new
        // tasks are admitted (counted as not-admitted for the report).
        if self.is_global_expired() {
            self.tasks_not_admitted += 1;
            if self.termination == TerminationReason::Completed {
                self.termination = TerminationReason::GlobalDeadline;
            }
            return Err(SchedulerError::BudgetExhausted("global deadline"));
        }
        if let Err(error) = self.ledger.admit(&task, &self.budgets, false) {
            self.tasks_not_admitted += 1;
            // Task-budget exhaustion is a normal bounded termination, not
            // an internal failure. Record it once; `run()` preserves the
            // first truncation reason.
            if matches!(error, SchedulerError::BudgetExhausted(_))
                && self.termination == TerminationReason::Completed
            {
                self.termination = TerminationReason::TaskBudget;
            }
            return Err(error);
        }
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
        let had_pending = ids.iter().any(|id| {
            self.tasks
                .get(id)
                .is_some_and(|record| !record.task.state.terminal())
        });
        for id in ids {
            self.cancel_task(&id);
        }
        // User-initiated cancellation is a normal truncation (P6/P13).
        if had_pending && self.termination == TerminationReason::Completed {
            self.termination = TerminationReason::UserCancelled;
        }
        self.global_cancel.cancel();
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
    /// Remaining global budget (`global_deadline - now`).
    pub fn global_remaining(&self) -> Duration {
        let now = Instant::now();
        if now >= self.global_deadline {
            Duration::ZERO
        } else {
            self.global_deadline.duration_since(now)
        }
    }
    pub fn global_deadline(&self) -> Instant {
        self.global_deadline
    }
    pub fn is_global_expired(&self) -> bool {
        Instant::now() >= self.global_deadline || self.global_cancel.is_cancelled()
    }
    /// External shutdown (Ctrl+C / SIGINT path): stop admitting new tasks,
    /// broadcast cancellation to every active module, and let `run()` drain
    /// with a bounded cleanup allowance. Safe to call multiple times.
    pub fn request_shutdown(&mut self) {
        self.global_cancel.cancel();
        if self.termination == TerminationReason::Completed {
            self.termination = TerminationReason::UserCancelled;
        }
        // Signal per-task tokens too so modules polling only the task
        // token still observe shutdown promptly.
        for record in self.tasks.values() {
            record.cancellation.cancel();
        }
    }
    pub fn termination(&self) -> TerminationReason {
        self.termination
    }
    pub fn tasks_not_admitted(&self) -> u64 {
        self.tasks_not_admitted
    }
    pub fn retries_consumed(&self) -> u64 {
        self.ledger.retries_consumed()
    }
    pub fn retries_by_module(&self) -> BTreeMap<String, u64> {
        self.ledger.retries_by_module()
    }
    pub fn tasks_by_module(&self) -> BTreeMap<String, u64> {
        self.ledger.tasks_by_module()
    }
    pub fn evidence_bytes_used(&self) -> u64 {
        self.ledger.evidence_bytes()
    }
    pub fn dispatch_by_kind(&self) -> BTreeMap<String, u64> {
        self.dispatch_by_kind.clone()
    }
    /// Per-kind concurrent slot cap (separate concurrency domains).
    ///
    /// Prevents one scan class from monopolizing every worker slot and
    /// exploding total socket pressure (e.g. 32 port tasks × 64 sockets).
    /// Each cap is bounded by the global effective concurrency; the global
    /// cap always wins. Host discovery gets the widest cap (lightweight
    /// probes); port/UDP scans are narrower (sustained socket pressure).
    fn kind_concurrency_cap(&self, kind: &TaskKind) -> usize {
        let total = self.effective_concurrency.max(1);
        let cap = match kind {
            TaskKind::HostDiscovery => total.clamp(1, 32),
            TaskKind::PortDiscovery => total.clamp(1, 8),
            TaskKind::UdpDiscovery => total.clamp(1, 4),
            TaskKind::ServiceProbe | TaskKind::HttpProbe | TaskKind::DnsProbe => total.clamp(1, 8),
            _ => total,
        };
        cap.min(total)
    }
    fn active_count_for_kind(&self, kind: &TaskKind) -> usize {
        self.tasks
            .values()
            .filter(|record| record.task.state == TaskState::Running && &record.task.kind == kind)
            .count()
    }
    fn record_error(&mut self, category: ErrorCategory) {
        *self
            .errors_by_category
            .entry(category.to_string())
            .or_default() += 1;
    }
    fn record_module_failure(&mut self, module: &str) {
        *self
            .failures_by_module
            .entry(module.to_owned())
            .or_default() += 1;
    }
    /// Deadline shutdown: (1) stop admitting new tasks, (2) broadcast
    /// cancellation to every active module so outstanding network I/O
    /// closes promptly, (3) mark every non-terminal queued task Cancelled
    /// so it is reported as truncated/unscanned rather than silently
    /// dropped. Already-collected evidence is preserved; `run()` drains
    /// briefly afterwards within its bounded cleanup allowance.
    fn shutdown_for_deadline(&mut self, report: &mut SchedulerReport, _active: &mut usize) {
        if self.termination == TerminationReason::Completed {
            // Preserve an explicit user-cancel reason over the deadline.
            self.termination =
                if self.global_cancel.is_cancelled() && Instant::now() < self.global_deadline {
                    TerminationReason::UserCancelled
                } else {
                    TerminationReason::GlobalDeadline
                };
        } else if self.termination == TerminationReason::UserCancelled {
            // Keep user-cancelled sticky.
        }
        // Broadcast first so active workers observe it within milliseconds.
        self.global_cancel.cancel();
        // Per-task tokens as well (modules polling only the task token).
        for record in self.tasks.values() {
            record.cancellation.cancel();
        }
        // Mark every non-running, non-terminal task Cancelled immediately.
        // Running tasks are reaped by the bounded drain (or force-marked).
        let pending: Vec<TaskId> = self
            .tasks
            .iter()
            .filter(|(_, record)| {
                !record.task.state.terminal() && record.task.state != TaskState::Running
            })
            .map(|(id, _)| id.clone())
            .collect();
        for task_id in pending {
            let should_emit = if let Some(record) = self.tasks.get_mut(&task_id) {
                if record.task.state.terminal() || record.task.state == TaskState::Running {
                    false
                } else {
                    record.task.state = TaskState::Cancelled;
                    record.task.cancel_requested = true;
                    true
                }
            } else {
                false
            };
            if should_emit {
                if !report.cancelled.contains(&task_id) {
                    report.cancelled.push(task_id.clone());
                }
                self.record_error(ErrorCategory::GlobalDeadline);
                self.emit_task(
                    &task_id,
                    SchedulerEventKind::TaskCancelled,
                    Some("global deadline"),
                );
            }
        }
        // Drain the scheduler queue so no new dispatches happen after this
        // point (dispatch loop also checks `is_global_expired`).
        while self.queue.pop().is_some() {}
    }
    pub fn run(&mut self) -> Result<SchedulerReport, SchedulerError> {
        // Authoritative absolute execution deadline near the root of the
        // scan execution (Priority 1). Every subsystem derives its
        // remaining budget as `global_deadline - now`; no task receives a
        // timeout exceeding the remaining global budget (enforced via
        // `ModuleContext::effective_deadline` + clamped scheduler waits).
        //
        // Reset here (not only at construction) so queueing/lowering time
        // does not eat the execution budget, and so resumed schedulers get
        // a fresh wall-clock window from their configured budget.
        let wall_start = Instant::now();
        self.started_at = wall_start;
        // Preserve an externally requested shutdown (Ctrl+C before run):
        // keep the cancelled token but still refresh the deadline window.
        let shutdown_requested = self.global_cancel.is_cancelled();
        self.global_deadline = wall_start
            .checked_add(Duration::from_millis(
                self.budgets.max_execution_time_ms.max(1),
            ))
            .unwrap_or(wall_start + Duration::from_secs(3600));
        if shutdown_requested {
            self.global_cancel.cancel();
            if self.termination == TerminationReason::Completed {
                self.termination = TerminationReason::UserCancelled;
            }
        }
        // Bounded cleanup allowance after the deadline expires: workers
        // are signalled promptly via the global token; we then drain at
        // most this long before force-marking stragglers Cancelled.
        const CLEANUP_ALLOWANCE: Duration = Duration::from_millis(500);
        let (sender, receiver): (Sender<WorkerResult>, _) = mpsc::channel();
        // `active` counts scheduler slots in use (Running tasks not yet
        // reaped as terminal). A timed-out task frees its slot immediately;
        // its orphaned worker thread (if any) is bounded by the task budget
        // and its late result is discarded without touching `active`.
        let mut active = 0usize;
        let mut report = SchedulerReport {
            deadline_ms: self.budgets.max_execution_time_ms,
            ..SchedulerReport::default()
        };
        // Phase 19 peak observability: O(1) counters, no semantic effect.
        let mut queue_peak = 0usize;
        let mut active_peak = 0usize;
        loop {
            // Hard deadline gate at the TOP of every iteration: when the
            // deadline expires we (1) stop admitting, (2) broadcast
            // cancellation, (3) drain quickly, (4) report truncation.
            // This runs even when workers are active (the old code only
            // checked the deadline when `active == 0`, letting long scans
            // overrun 1s budgets by 8+ seconds).
            if self.is_global_expired() {
                self.shutdown_for_deadline(&mut report, &mut active);
                // Bounded drain: collect any workers that exit promptly,
                // then force-mark the rest Cancelled and break.
                let cleanup_start = Instant::now();
                while active > 0 && cleanup_start.elapsed() < CLEANUP_ALLOWANCE {
                    match receiver.recv_timeout(Duration::from_millis(25)) {
                        Ok(result) => {
                            let is_live = self.tasks.get(&result.task_id).is_some_and(|record| {
                                record.task.state == TaskState::Running
                                    && record.task.attempt == result.attempt
                            });
                            if is_live {
                                active = active.saturating_sub(1);
                                // Preserve already-collected evidence even
                                // on the deadline path.
                                let _ = self.handle_worker_result(result, &mut report);
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => {
                            // Re-check: workers may have observed the
                            // cancellation and exited; loop to reap them.
                        }
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
                // Force-mark any stragglers (non-cooperative workers leave
                // orphaned threads bounded by the task budget; their late
                // results are discarded).
                let stragglers: Vec<TaskId> = self
                    .tasks
                    .iter()
                    .filter(|(_, record)| record.task.state == TaskState::Running)
                    .map(|(id, _)| id.clone())
                    .collect();
                for task_id in stragglers {
                    if let Some(record) = self.tasks.get_mut(&task_id) {
                        if record.task.state == TaskState::Running {
                            record.task.state = TaskState::Cancelled;
                            record.execution_started = None;
                            record.cancellation.cancel();
                            if !report.cancelled.contains(&task_id) {
                                report.cancelled.push(task_id.clone());
                            }
                            self.record_error(ErrorCategory::GlobalDeadline);
                            self.emit_task(
                                &task_id,
                                SchedulerEventKind::TaskCancelled,
                                Some("global deadline"),
                            );
                            active = active.saturating_sub(1);
                        }
                    }
                }
                report.cleanup_ms = cleanup_start
                    .elapsed()
                    .as_millis()
                    .min(u128::from(u64::MAX)) as u64;
                break;
            }
            self.promote_ready_tasks()?;
            queue_peak = queue_peak.max(self.queue.len());
            // Dispatch loop: never let a retry-delayed task head-of-line
            // block other ready tasks. Not-ready pops are stashed aside and
            // requeued after the dispatch window. Per-kind caps give each
            // scan class a separate bounded concurrency domain so one class
            // cannot monopolize every slot or explode total socket pressure.
            let mut deferred: Vec<(TaskId, u8)> = Vec::new();
            // Fairness: when several scan classes are queued, avoid draining
            // one class for every slot while another waits. We pop in
            // priority order but defer same-kind pops once that kind has
            // taken more than its fair share this window.
            let mut window_dispatched: BTreeMap<String, usize> = BTreeMap::new();
            while active < self.effective_concurrency {
                // Stop admitting the moment the deadline expires (queue
                // admission gate). The top-of-loop gate will drive shutdown.
                if self.is_global_expired() {
                    break;
                }
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
                // Peek kind for fairness + per-kind cap before mutating.
                let kind_name = self
                    .tasks
                    .get(&task_id)
                    .map(|record| kind_key(&record.task.kind))
                    .unwrap_or_default();
                let kind_for_cap = self
                    .tasks
                    .get(&task_id)
                    .map(|record| record.task.kind.clone());
                if let Some(kind) = &kind_for_cap {
                    let cap = self.kind_concurrency_cap(kind);
                    if self.active_count_for_kind(kind) >= cap {
                        let priority = self.tasks.get(&task_id).map_or(0, |r| r.task.priority);
                        if let Some(record) = self.tasks.get_mut(&task_id) {
                            record.queued = false;
                        }
                        deferred.push((task_id, priority));
                        continue;
                    }
                    // Fairness: if this window already dispatched 2 of this
                    // kind and another kind is waiting in the stashed set or
                    // still queued, defer this one to let the other class in.
                    // (Deterministic, bounded: deferred tasks requeue below.)
                    let dispatched = window_dispatched.get(&kind_name).copied().unwrap_or(0);
                    if dispatched >= 2 {
                        // Check whether a different kind is actually waiting.
                        let other_waiting = deferred.iter().any(|(id, _)| {
                            self.tasks
                                .get(id)
                                .is_some_and(|record| kind_key(&record.task.kind) != kind_name)
                        }) || !self.queue.is_empty();
                        // Only defer for fairness when we have spare slots
                        // pressure: with 1 slot total, priority order wins.
                        if other_waiting && self.effective_concurrency > 1 {
                            let priority = self.tasks.get(&task_id).map_or(0, |r| r.task.priority);
                            if let Some(record) = self.tasks.get_mut(&task_id) {
                                record.queued = false;
                            }
                            deferred.push((task_id, priority));
                            continue;
                        }
                    }
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
                // No task receives a timeout exceeding the remaining global
                // budget: the effective deadline travels in the context and
                // every network worker clamps poll slices + per-probe
                // timeouts to it (see ModuleContext::effective_deadline).
                let context = ModuleContext::with_global(
                    record.task.clone(),
                    record.cancellation.clone(),
                    self.global_cancel.clone(),
                    Some(self.global_deadline),
                );
                *window_dispatched.entry(kind_name.clone()).or_default() += 1;
                *self.dispatch_by_kind.entry(kind_name).or_default() += 1;
                let task_id_for_worker = task_id.clone();
                self.emit_task(&task_id, SchedulerEventKind::TaskStarted, None);
                spawn_worker(module, context, sender.clone(), task_id_for_worker, attempt);
                active += 1;
                active_peak = active_peak.max(active);
            }
            queue_peak = queue_peak.max(self.queue.len());
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
                // Deadline expiry here is already handled at the top of the
                // next loop iteration (bounded shutdown + drain). Sleeping
                // 1ms keeps retry-delayed queues moving without spinning.
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
                        // Budget exhaustion inside is a normal truncation,
                        // never a fatal scheduler error (P6).
                        if let Err(error) = self.handle_worker_result(result, &mut report) {
                            self.termination = TerminationReason::InternalFailure;
                            self.record_error(ErrorCategory::InternalError);
                            let _ = error;
                        }
                    } else {
                        // Orphaned worker reaped; slot was already freed at
                        // timeout/cancel time. Discard without double-count.
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    // Global expiry races the wait: the top-of-loop gate
                    // owns shutdown; here we only reap per-task timeouts.
                    if self.is_global_expired() {
                        continue;
                    }
                    // Reap ALL expired Running tasks per timeout tick, not
                    // just one, so concurrent timeouts all become terminal.
                    // Per-task timeouts are additionally clamped by the
                    // remaining global budget at dispatch (effective
                    // deadline), so a task never outlives the global window.
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
                            self.record_error(ErrorCategory::TaskDeadline);
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
        // Final sweep: reconcile tasks that reached a terminal state without
        // passing through the incremental report paths (e.g. tasks restored
        // as already-terminal). Phase 19: HashSet membership keeps this
        // linear instead of quadratic in task count; emission order is
        // unchanged (BTreeMap task order, missing entries appended).
        let completed: HashSet<TaskId> = report.completed.iter().cloned().collect();
        let failed: HashSet<TaskId> = report.failed.iter().cloned().collect();
        let cancelled: HashSet<TaskId> = report.cancelled.iter().cloned().collect();
        let timed_out: HashSet<TaskId> = report.timed_out.iter().cloned().collect();
        let skipped: HashSet<TaskId> = report.skipped.iter().cloned().collect();
        for (task_id, record) in &self.tasks {
            match record.task.state {
                TaskState::Failed if !failed.contains(task_id) => {
                    report.failed.push(task_id.clone())
                }
                TaskState::Cancelled if !cancelled.contains(task_id) => {
                    report.cancelled.push(task_id.clone())
                }
                TaskState::TimedOut if !timed_out.contains(task_id) => {
                    report.timed_out.push(task_id.clone())
                }
                TaskState::Skipped if !skipped.contains(task_id) => {
                    report.skipped.push(task_id.clone())
                }
                TaskState::Succeeded if !completed.contains(task_id) => {
                    report.completed.push(task_id.clone())
                }
                _ => {}
            }
        }
        report.queue_peak = queue_peak;
        report.active_peak = active_peak;
        report.termination = self.termination;
        report.tasks_admitted = self.tasks.len() as u64;
        report.tasks_not_admitted = self.tasks_not_admitted;
        report.evidence_bytes = self.ledger.evidence_bytes();
        report.retries_consumed = self.ledger.retries_consumed();
        report.retries_by_module = self.ledger.retries_by_module();
        report.errors_by_category = self.errors_by_category.clone();
        report.failures_by_module = self.failures_by_module.clone();
        report.wall_ms = wall_start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        // Overrun: wall beyond the configured budget (0 when within).
        report.deadline_overrun_ms = report
            .wall_ms
            .saturating_sub(self.budgets.max_execution_time_ms);
        // If we broke out via the deadline path but termination somehow
        // stayed Completed (e.g. all work finished exactly at expiry),
        // keep Completed; otherwise the shutdown path already set it.
        // A run that exhausted a budget but still completed every admitted
        // task keeps its budget termination (truncated, not completed).
        Ok(report)
    }
    fn promote_ready_tasks(&mut self) -> Result<(), SchedulerError> {
        // Queue admission gate: once the global deadline expires, stop
        // promoting Pending -> Ready. Existing Ready tasks are drained by
        // the shutdown path, not dispatched.
        if self.is_global_expired() {
            return Ok(());
        }
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
        // Child/follow-up creation and retry scheduling both derive from
        // the remaining global budget: when the deadline has expired we
        // finish the current task but admit nothing further.
        let deadline_expired = self.is_global_expired();
        let global_remaining_snapshot = self.global_remaining();
        let Some(record) = self.tasks.get_mut(&result.task_id) else {
            return Ok(());
        };
        if record.task.state != TaskState::Running || record.task.attempt != result.attempt {
            return Ok(());
        }
        let task_snapshot = record.task.clone();
        match result.result {
            Ok(output) => {
                // Evidence budget is a normal truncation (P6/P9), never a
                // fatal error: preserve already-collected outputs, drop the
                // overflowing record, and stop further admission.
                if let Err(SchedulerError::BudgetExhausted(_)) = self
                    .ledger
                    .add_evidence(output.evidence_bytes(), &self.budgets)
                {
                    if self.termination == TerminationReason::Completed {
                        self.termination = TerminationReason::EvidenceBudget;
                    }
                    self.tasks_not_admitted += 1;
                    record.task.state = TaskState::Succeeded;
                    record.execution_started = None;
                    report.completed.push(result.task_id.clone());
                    // Retain events/findings but drop evidence bytes to stay
                    // within budget: keep a truncated output shell.
                    let mut truncated = output.clone();
                    truncated.evidence.clear();
                    self.completed_outputs
                        .insert(result.task_id.clone(), truncated);
                    self.record_error(ErrorCategory::ResourceExhaustion);
                    self.emit_task(
                        &result.task_id,
                        SchedulerEventKind::TaskCompleted,
                        Some("evidence budget exhausted; output truncated"),
                    );
                    return Ok(());
                }
                record.task.state = TaskState::Succeeded;
                record.execution_started = None;
                report.completed.push(result.task_id.clone());
                self.completed_outputs
                    .insert(result.task_id.clone(), output.clone());
                self.emit_task(&result.task_id, SchedulerEventKind::TaskCompleted, None);
                if deadline_expired {
                    // No follow-ups past the deadline (queue admission gate).
                    if self.termination == TerminationReason::Completed {
                        self.termination = TerminationReason::GlobalDeadline;
                    }
                    return Ok(());
                }
                let followups = self
                    .decision_engine
                    .follow_up_tasks(&task_snapshot, &output);
                // Phase 6: follow-up admission is best-effort and bounded.
                // Duplicates, out-of-scope, budget-exhausted, and
                // deadline-gated proposals are skipped without aborting;
                // initial tasks still fail fast via `add_task` in `run.rs`.
                // Retry scheduling below clamps delays to the global window.
                for task in followups {
                    // Retry scheduling and child creation never exceed the
                    // remaining global budget: skip admission when expired.
                    if self.is_global_expired() {
                        self.tasks_not_admitted += 1;
                        if self.termination == TerminationReason::Completed {
                            self.termination = TerminationReason::GlobalDeadline;
                        }
                        break;
                    }
                    match self.add_task(task) {
                        Ok(_) => {}
                        Err(SchedulerError::BudgetExhausted(reason)) => {
                            // add_task already recorded termination for
                            // task-budget vs global-deadline; retry-budget
                            // overflow from follow-ups is also truncation.
                            if (reason == "maximum retries" || reason == "per-module retries")
                                && self.termination == TerminationReason::Completed
                            {
                                self.termination = TerminationReason::RetryBudget;
                            }
                        }
                        Err(
                            SchedulerError::DuplicateTask
                            | SchedulerError::OutOfScope
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
                // Distinguish global-deadline cancels from user cancels for
                // actionable diagnostics (P5).
                if self.is_global_expired() {
                    self.record_error(ErrorCategory::GlobalDeadline);
                    self.emit_task(
                        &result.task_id,
                        SchedulerEventKind::TaskCancelled,
                        Some("global deadline"),
                    );
                } else {
                    self.record_error(ErrorCategory::Cancelled);
                    self.emit_task(&result.task_id, SchedulerEventKind::TaskCancelled, None);
                }
            }
            Err(error)
                if error.retryable()
                    && record.task.attempt < record.task.retry_policy.max_attempts =>
            {
                // Retry scheduling derives from the remaining global budget:
                // never schedule a retry past the deadline (P1).
                if deadline_expired {
                    record.task.state = TaskState::Cancelled;
                    record.execution_started = None;
                    report.cancelled.push(result.task_id.clone());
                    self.record_error(ErrorCategory::GlobalDeadline);
                    self.emit_task(
                        &result.task_id,
                        SchedulerEventKind::TaskCancelled,
                        Some("global deadline; retry not scheduled"),
                    );
                    if self.termination == TerminationReason::Completed {
                        self.termination = TerminationReason::GlobalDeadline;
                    }
                    return Ok(());
                }
                let retry_delay = record
                    .task
                    .retry_policy
                    .delay_for_retry(record.task.retry_count.saturating_add(1));
                if global_remaining_snapshot < retry_delay + Duration::from_millis(50) {
                    record.task.state = TaskState::Cancelled;
                    record.execution_started = None;
                    report.cancelled.push(result.task_id.clone());
                    self.record_error(ErrorCategory::GlobalDeadline);
                    self.emit_task(
                        &result.task_id,
                        SchedulerEventKind::TaskCancelled,
                        Some("global deadline; retry not scheduled"),
                    );
                    if self.termination == TerminationReason::Completed {
                        self.termination = TerminationReason::GlobalDeadline;
                    }
                    return Ok(());
                }
                match self.ledger.admit(&record.task, &self.budgets, true) {
                    Ok(()) => {
                        record.task.retry_count = record.task.retry_count.saturating_add(1);
                        record.task.state = TaskState::Pending;
                        record.execution_started = None;
                        record.queued = false;
                        record.ready_at = Instant::now() + retry_delay;
                        self.emit_task(
                            &result.task_id,
                            SchedulerEventKind::TaskRetried,
                            Some("retryable module failure"),
                        );
                    }
                    Err(SchedulerError::BudgetExhausted(_)) => {
                        // Retry budget is truncation, not failure (P6/P7).
                        if self.termination == TerminationReason::Completed {
                            self.termination = TerminationReason::RetryBudget;
                        }
                        record.task.state = TaskState::Failed;
                        record.execution_started = None;
                        report.failed.push(result.task_id.clone());
                        self.record_error(ErrorCategory::ResourceExhaustion);
                        self.record_module_failure(&task_snapshot.module_name);
                        self.emit_task(
                            &result.task_id,
                            SchedulerEventKind::TaskFailed,
                            Some("retry budget exhausted"),
                        );
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) => {
                record.task.state = TaskState::Failed;
                record.execution_started = None;
                report.failed.push(result.task_id.clone());
                self.record_error(classify_error_detail(&error.to_string()));
                self.record_module_failure(&task_snapshot.module_name);
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
        // Scheduler waits derive from the remaining global budget: never
        // sleep past the deadline (P1). Wakes promptly for shutdown.
        let global_remaining = self.global_remaining();
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
            .clamp(Duration::from_millis(1), Duration::from_millis(50))
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
    /// Derived exactly once at construction; the explicit budget is an upper
    /// bound and never triggers re-derivation (Phase 20 governor fix).
    pub fn effective_concurrency(&self) -> usize {
        self.effective_concurrency
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
