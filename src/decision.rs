//! Phase 6 Decision Engine V1 (+ Phase 7 service rule): facts → proposals.
//!
//! Boundary (modules never self-schedule):
//! * `HostDiscovery result -> Decision Engine -> proposed TcpDiscovery task`
//! * `Open Port Finding -> Decision Engine -> proposed ServiceProbe task`
//!   each gated by `Scope Guard -> Policy/Budget validation -> Scheduler`.
//!
//! Host policy (explicit, documented):
//! * `Alive` → propose `PortDiscovery` when port-eligible.
//! * `Unknown` → propose when the operator explicitly chose ports/`--all-ports`
//!   (explicit intent wins) or when `level >= 3` (standard+ scans assume ICMP
//!   may be blocked; never assume ICMP failure means stop).
//! * `Unreachable` → normally skip (no proposal).
//!
//! Service policy: every open TCP port yields at most one `ServiceProbe`
//! proposal (bounded per completion, deterministic order). Port hints select
//! probe *order* inside the task — never identity. The engine pre-validates
//! scope; the scheduler re-validates admission, budgets, and duplicates.
//! Proposals mirror lowering shapes so single-host duplicates share task IDs
//! and are ignored gracefully instead of rescanning.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use crate::discovery::HostState;
use crate::execution::{ModuleOutput, ScopeGuard, Task, TaskKind, TaskScopeTarget};
use crate::level::priority_for_kind;
use crate::model::{ScanPlanId, Timestamp};
use crate::plan::{ScanGoal, TcpPortSelection};

/// Deterministic V1 engine: host → TCP proposals only.
#[derive(Clone)]
pub struct TcpDecisionEngine {
    scope_guard: Arc<dyn ScopeGuard>,
    plan_id: ScanPlanId,
    level: u8,
    goal: ScanGoal,
    tcp_selection: TcpPortSelection,
    speed: crate::plan::SpeedSetting,
}

impl TcpDecisionEngine {
    pub fn new(
        scope_guard: Arc<dyn ScopeGuard>,
        plan_id: ScanPlanId,
        level: u8,
        goal: ScanGoal,
        tcp_selection: TcpPortSelection,
        speed: crate::plan::SpeedSetting,
    ) -> Self {
        Self {
            scope_guard,
            plan_id,
            level: level.clamp(1, 5),
            goal,
            tcp_selection,
            speed,
        }
    }

    fn explicit_ports(&self) -> bool {
        !matches!(self.tcp_selection, TcpPortSelection::Common)
    }

    fn port_eligible(&self) -> bool {
        crate::ports::port_eligible_for_plan(self.goal, self.level, self.explicit_ports())
    }

    /// Build the deterministic per-host port task (same shape as lowering so
    /// single-host duplicates share IDs and are skipped, not rescanned).
    fn port_task_for_host(&self, host: std::net::IpAddr, target_label: &str) -> Option<Task> {
        let scope_target = TaskScopeTarget::Ip(host);
        if !self.scope_guard.permits(&scope_target) {
            return None;
        }
        let mut params = BTreeMap::new();
        params.insert("target".to_owned(), target_label.to_owned());
        match &self.tcp_selection {
            TcpPortSelection::Common => {
                params.insert("ports".to_owned(), "common".to_owned());
            }
            TcpPortSelection::Explicit(ports) => {
                let rendered = ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                let rendered = if rendered.len() > 2048 {
                    format!("{}...(+{} more)", &rendered[..2048], ports.len())
                } else {
                    rendered
                };
                params.insert("ports".to_owned(), format!("explicit:{rendered}"));
                params.insert("port_count".to_owned(), ports.len().to_string());
            }
            TcpPortSelection::All => {
                params.insert("ports".to_owned(), "all".to_owned());
                params.insert("port_count".to_owned(), 65_535.to_string());
            }
        }
        let governor = crate::execution::SpeedGovernor::new(self.speed, 1).ok()?;
        let timeout = governor.default_timeout();
        let retry = governor.default_retry_policy();
        let provenance = crate::model::Provenance::new(
            "rxscan.decision",
            "6.0.0",
            self.plan_id.clone(),
            Timestamp::now(),
        )
        .ok()?;
        Task::new_with_params(
            TaskKind::PortDiscovery,
            None,
            Vec::new(),
            None,
            self.plan_id.clone(),
            priority_for_kind(&TaskKind::PortDiscovery),
            timeout,
            retry,
            "rxscan.port",
            provenance,
            scope_target,
            params,
            self.scope_guard.as_ref(),
        )
        .ok()
    }
}

/// Extract `(HostState, target label, address)` from a host module output.
/// Reads the `HostStateConcluded` event or host evidence details; `None`
/// when the output carries no host conclusion (e.g. empty scaffolds).
pub fn host_conclusion_from_output(
    output: &ModuleOutput,
) -> Option<(HostState, String, Option<std::net::IpAddr>)> {
    for event in &output.events {
        if matches!(event.kind, crate::model::EventKind::HostStateConcluded) {
            let data = &event.details.data;
            let state = match data.get("state")?.as_str()? {
                "alive" => HostState::Alive,
                "unreachable" => HostState::Unreachable,
                _ => HostState::Unknown,
            };
            let target = data
                .get("target")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_owned();
            let address = data
                .get("address")
                .and_then(serde_json::Value::as_str)
                .and_then(|text| text.parse().ok());
            return Some((state, target, address));
        }
    }
    for evidence in &output.evidence {
        let data = &evidence.details.data;
        let state_text = data.get("state")?.as_str()?;
        if !matches!(state_text, "alive" | "unreachable" | "unknown") {
            continue;
        }
        let state = match state_text {
            "alive" => HostState::Alive,
            "unreachable" => HostState::Unreachable,
            _ => HostState::Unknown,
        };
        let target = data
            .get("target")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned();
        let address = data
            .get("address")
            .and_then(serde_json::Value::as_str)
            .and_then(|text| text.parse().ok());
        return Some((state, target, address));
    }
    None
}

impl crate::execution::DecisionEngine for TcpDecisionEngine {
    fn follow_up_tasks(&self, completed: &Task, output: &ModuleOutput) -> Vec<Task> {
        // Only host completions propose; port tasks never chain further.
        if completed.kind != TaskKind::HostDiscovery {
            return Vec::new();
        }
        if !self.port_eligible() {
            return Vec::new();
        }
        let Some((state, target_label, address)) = host_conclusion_from_output(output) else {
            return Vec::new();
        };
        // Fall back to the host task's own scope when output lacks an address.
        let host_ip = address.or(match &completed.scope_target {
            TaskScopeTarget::Ip(ip) => Some(*ip),
            _ => None,
        });
        let Some(host_ip) = host_ip else {
            return Vec::new();
        };
        let target = if target_label.is_empty() {
            completed
                .params
                .get("target")
                .cloned()
                .unwrap_or_else(|| host_ip.to_string())
        } else {
            target_label
        };
        match state {
            HostState::Alive => self
                .port_task_for_host(host_ip, &target)
                .into_iter()
                .collect(),
            HostState::Unknown => {
                // Explicit operator intent wins; otherwise standard+ levels
                // assume ICMP may be blocked and still scan.
                if self.explicit_ports() || self.level >= 3 {
                    self.port_task_for_host(host_ip, &target)
                        .into_iter()
                        .collect()
                } else {
                    Vec::new()
                }
            }
            HostState::Unreachable => Vec::new(),
        }
    }
}

/// Timeout helper for tests (kept here to avoid duplicating governor logic).
#[allow(dead_code)]
pub fn default_task_timeout(speed: crate::plan::SpeedSetting) -> Duration {
    crate::execution::SpeedGovernor::new(speed, 1)
        .map(|governor| governor.default_timeout())
        .unwrap_or_else(|_| Duration::from_secs(15))
}

/// One open port parsed from a `PortDiscovery` output (finding-first,
/// evidence-backed). Engine input only — identity always comes from probes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPortFact {
    pub address: std::net::IpAddr,
    pub port: u16,
    pub port_asset_id: String,
    pub target_label: String,
}

/// Extract open-port facts from a port-scan output, sorted by
/// (address, port) for deterministic proposals.
pub fn open_ports_from_output(output: &ModuleOutput) -> Vec<OpenPortFact> {
    let mut facts = Vec::new();
    for finding in &output.findings {
        if !finding.title.starts_with("Open TCP port") {
            continue;
        }
        let (Some(address_text), Some(port_number)) = (
            finding
                .metadata
                .get("address")
                .and_then(serde_json::Value::as_str),
            finding
                .metadata
                .get("port")
                .and_then(serde_json::Value::as_u64),
        ) else {
            continue;
        };
        let (Ok(address), Ok(port)) = (
            address_text.parse::<std::net::IpAddr>(),
            u16::try_from(port_number),
        ) else {
            continue;
        };
        if port == 0 {
            continue;
        }
        facts.push(OpenPortFact {
            address,
            port,
            port_asset_id: finding.affected_asset_id.0.clone(),
            target_label: address_text.to_owned(),
        });
    }
    // Backstop: findings are authoritative, but port-open events carry the
    // same shape if a future module emits events without findings.
    if facts.is_empty() {
        for event in &output.events {
            if !matches!(event.kind, crate::model::EventKind::PortOpen) {
                continue;
            }
            let data = &event.details.data;
            let (Some(address_text), Some(port_number)) = (
                data.get("address").and_then(serde_json::Value::as_str),
                data.get("port").and_then(serde_json::Value::as_u64),
            ) else {
                continue;
            };
            let (Ok(address), Ok(port)) = (
                address_text.parse::<std::net::IpAddr>(),
                u16::try_from(port_number),
            ) else {
                continue;
            };
            if port == 0 {
                continue;
            }
            let port_asset_id = event
                .asset_id
                .as_ref()
                .map(|id| id.0.clone())
                .unwrap_or_default();
            facts.push(OpenPortFact {
                address,
                port,
                port_asset_id,
                target_label: data
                    .get("target")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(address_text)
                    .to_owned(),
            });
        }
    }
    facts.sort_by(|left, right| {
        left.address
            .to_string()
            .cmp(&right.address.to_string())
            .then(left.port.cmp(&right.port))
    });
    facts.dedup();
    facts
}

/// Deterministic V1+V2 engine: open ports → `ServiceProbe` proposals.
///
/// One task per open port (bounded per completion), carrying the planner's
/// probe order in `probes` params so IDs stay deterministic. Scope is
/// pre-validated; budgets/duplicates fall to best-effort scheduler admission.
#[derive(Clone)]
pub struct ServiceDecisionEngine {
    scope_guard: Arc<dyn ScopeGuard>,
    plan_id: ScanPlanId,
    level: u8,
    goal: ScanGoal,
    speed: crate::plan::SpeedSetting,
}

/// Cap on service proposals per single port-task completion (deterministic
/// first-N by address/port). Realistic scans never approach it; pathological
/// full-open hosts stay bounded instead of flooding `max_tasks`.
pub const MAX_SERVICE_PROPOSALS_PER_COMPLETION: usize = 256;

impl ServiceDecisionEngine {
    pub fn new(
        scope_guard: Arc<dyn ScopeGuard>,
        plan_id: ScanPlanId,
        level: u8,
        goal: ScanGoal,
        speed: crate::plan::SpeedSetting,
    ) -> Self {
        Self {
            scope_guard,
            plan_id,
            level: level.clamp(1, 5),
            goal,
            speed,
        }
    }

    fn service_task_for_open_port(&self, fact: &OpenPortFact) -> Option<Task> {
        let scope_target = TaskScopeTarget::Ip(fact.address);
        if !self.scope_guard.permits(&scope_target) {
            return None;
        }
        let probes = crate::service::plan_probes(fact.port, self.level, self.goal);
        let mut params = BTreeMap::new();
        params.insert("target".to_owned(), fact.target_label.clone());
        params.insert("address".to_owned(), fact.address.to_string());
        params.insert("port".to_owned(), fact.port.to_string());
        params.insert("transport".to_owned(), "tcp".to_owned());
        params.insert("parent_asset".to_owned(), fact.port_asset_id.clone());
        params.insert("probes".to_owned(), probes.join(","));
        let governor = crate::execution::SpeedGovernor::new(self.speed, 1).ok()?;
        let provenance = crate::model::Provenance::new(
            "rxscan.decision",
            "7.0.0",
            self.plan_id.clone(),
            Timestamp::now(),
        )
        .ok()?;
        Task::new_with_params(
            TaskKind::ServiceProbe,
            None,
            Vec::new(),
            None,
            self.plan_id.clone(),
            priority_for_kind(&TaskKind::ServiceProbe),
            governor.default_timeout(),
            governor.default_retry_policy(),
            "rxscan.service",
            provenance,
            scope_target,
            params,
            self.scope_guard.as_ref(),
        )
        .ok()
    }
}

impl crate::execution::DecisionEngine for ServiceDecisionEngine {
    fn follow_up_tasks(&self, completed: &Task, output: &ModuleOutput) -> Vec<Task> {
        if completed.kind != TaskKind::PortDiscovery {
            return Vec::new();
        }
        open_ports_from_output(output)
            .into_iter()
            .take(MAX_SERVICE_PROPOSALS_PER_COMPLETION)
            .filter_map(|fact| self.service_task_for_open_port(&fact))
            .collect()
    }
}

/// Combined Phase 7 engine: host→port (V1) plus open-port→service (V2).
/// Dispatches purely on the completed task kind; each sub-engine owns its
/// rule. Modules still never self-schedule.
#[derive(Clone)]
pub struct Phase7Engine {
    tcp: TcpDecisionEngine,
    service: ServiceDecisionEngine,
}

impl Phase7Engine {
    pub fn new(
        scope_guard: Arc<dyn ScopeGuard>,
        plan_id: ScanPlanId,
        level: u8,
        goal: ScanGoal,
        tcp_selection: TcpPortSelection,
        speed: crate::plan::SpeedSetting,
    ) -> Self {
        Self {
            tcp: TcpDecisionEngine::new(
                scope_guard.clone(),
                plan_id.clone(),
                level,
                goal,
                tcp_selection,
                speed,
            ),
            service: ServiceDecisionEngine::new(scope_guard, plan_id, level, goal, speed),
        }
    }
}

impl crate::execution::DecisionEngine for Phase7Engine {
    fn follow_up_tasks(&self, completed: &Task, output: &ModuleOutput) -> Vec<Task> {
        match completed.kind {
            TaskKind::HostDiscovery => self.tcp.follow_up_tasks(completed, output),
            TaskKind::PortDiscovery => self.service.follow_up_tasks(completed, output),
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::{DecisionEngine, PolicyScopeGuard, RetryPolicy};
    use crate::model::{BoundedDetails, Event, Provenance};
    use std::time::Duration;

    fn test_plan_id() -> ScanPlanId {
        ScanPlanId("plan_test".to_owned())
    }

    fn host_output_with_state(state: &str, target: &str, address: &str) -> ModuleOutput {
        let provenance =
            Provenance::new("rxscan.host", "5.0.0", test_plan_id(), Timestamp(1)).unwrap();
        let event = Event::new(
            crate::model::EventKind::HostStateConcluded,
            None,
            BoundedDetails::from_value(
                serde_json::json!({"state": state, "target": target, "address": address}),
                4096,
            )
            .unwrap(),
            provenance,
        )
        .unwrap();
        ModuleOutput {
            events: vec![event],
            evidence: Vec::new(),
            findings: Vec::new(),
            assets: Vec::new(),
        }
    }

    fn host_task(scope: TaskScopeTarget, guard: &dyn ScopeGuard) -> Task {
        let provenance =
            Provenance::new("rxscan.host", "5.0.0", test_plan_id(), Timestamp(1)).unwrap();
        Task::new_with_params(
            TaskKind::HostDiscovery,
            None,
            Vec::new(),
            None,
            test_plan_id(),
            80,
            Duration::from_millis(1000),
            RetryPolicy::default(),
            "rxscan.host",
            provenance,
            scope,
            BTreeMap::from([("target".to_owned(), "127.0.0.1".to_owned())]),
            guard,
        )
        .unwrap()
    }

    #[test]
    fn alive_proposes_unknown_policy_gates_and_unreachable_skips() {
        use crate::scope::ScopePolicy;
        use crate::target::TargetSpec;
        let target = TargetSpec::parse("127.0.0.1").unwrap();
        let policy = ScopePolicy::from_targets(&[target], &[], &[]).unwrap();
        let guard = Arc::new(PolicyScopeGuard::new(policy));
        let engine = TcpDecisionEngine::new(
            guard.clone(),
            test_plan_id(),
            3,
            ScanGoal::Recon,
            TcpPortSelection::Common,
            crate::plan::SpeedSetting::default(),
        );
        let task = host_task(
            TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
            guard.as_ref(),
        );
        let alive = host_output_with_state("alive", "127.0.0.1", "127.0.0.1");
        assert_eq!(engine.follow_up_tasks(&task, &alive).len(), 1);
        let unknown = host_output_with_state("unknown", "127.0.0.1", "127.0.0.1");
        assert_eq!(engine.follow_up_tasks(&task, &unknown).len(), 1);
        let unreachable = host_output_with_state("unreachable", "127.0.0.1", "127.0.0.1");
        assert!(engine.follow_up_tasks(&task, &unreachable).is_empty());
        // L1 without explicit ports: Unknown skipped.
        let strict = TcpDecisionEngine::new(
            guard.clone(),
            test_plan_id(),
            1,
            ScanGoal::Recon,
            TcpPortSelection::Common,
            crate::plan::SpeedSetting::default(),
        );
        assert!(strict.follow_up_tasks(&task, &unknown).is_empty());
        // L1 with explicit ports: Unknown proceeds (explicit wins).
        let explicit = TcpDecisionEngine::new(
            guard.clone(),
            test_plan_id(),
            1,
            ScanGoal::Recon,
            TcpPortSelection::Explicit(vec![80]),
            crate::plan::SpeedSetting::default(),
        );
        assert_eq!(explicit.follow_up_tasks(&task, &unknown).len(), 1);
    }
}
