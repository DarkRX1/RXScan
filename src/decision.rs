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

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::discovery::HostState;
use crate::execution::{ModuleOutput, ScopeGuard, Task, TaskId, TaskKind, TaskScopeTarget};
use crate::level::priority_for_kind;
use crate::model::{AssetId, ScanPlanId, Timestamp};
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
                let rendered = crate::ports::compress_port_list(ports);
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
    // Phase 19: cache the string key once per fact. Ordering is unchanged
    // (address rendered as text, then port); the previous comparator
    // re-rendered both addresses on every comparison (O(n log n) heap
    // allocations for large open sets).
    facts.sort_by_cached_key(|fact| (fact.address.to_string(), fact.port));
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
        // Workflow gating: Discover finds hosts/ports without identifying
        // services; Ports stops after the port scan itself.
        if !matches!(
            self.goal,
            ScanGoal::Recon | ScanGoal::Services | ScanGoal::Web | ScanGoal::Full
        ) {
            return Vec::new();
        }
        open_ports_from_output(output)
            .into_iter()
            .take(MAX_SERVICE_PROPOSALS_PER_COMPLETION)
            .filter_map(|fact| self.service_task_for_open_port(&fact))
            .collect()
    }
}

/// Combined Phase 7+ engine: host→port (V1), open-port→service (V2),
/// confirmed-service→web (Phase 8), and confirmed endpoint/discovery→crawl
/// (Phase 9) rules. Dispatches purely on the completed task kind; each
/// sub-engine owns its rule. Modules still never self-schedule.
#[derive(Clone)]
pub struct Phase7Engine {
    tcp: TcpDecisionEngine,
    service: ServiceDecisionEngine,
    web: WebDecisionEngine,
    crawl: CrawlDecisionEngine,
    baseline: BaselineDecisionEngine,
    content: ContentDecisionEngine,
    fuzz: FuzzDecisionEngine,
    dns: DnsDecisionEngine,
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
        Self::new_with_content_wordlist(
            scope_guard,
            plan_id,
            level,
            goal,
            tcp_selection,
            speed,
            None,
        )
    }

    pub fn new_with_content_wordlist(
        scope_guard: Arc<dyn ScopeGuard>,
        plan_id: ScanPlanId,
        level: u8,
        goal: ScanGoal,
        tcp_selection: TcpPortSelection,
        speed: crate::plan::SpeedSetting,
        content_wordlist: Option<PathBuf>,
    ) -> Self {
        let origin_baselines = crate::baseline::OriginBaselineRegistry::new();
        let fuzz_budget = crate::fuzz::FuzzOriginBudget::new();
        Self::new_with_state(
            scope_guard,
            plan_id,
            level,
            goal,
            tcp_selection,
            speed,
            content_wordlist,
            origin_baselines,
            fuzz_budget,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_state(
        scope_guard: Arc<dyn ScopeGuard>,
        plan_id: ScanPlanId,
        level: u8,
        goal: ScanGoal,
        tcp_selection: TcpPortSelection,
        speed: crate::plan::SpeedSetting,
        content_wordlist: Option<PathBuf>,
        origin_baselines: crate::baseline::OriginBaselineRegistry,
        fuzz_budget: crate::fuzz::FuzzOriginBudget,
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
            service: ServiceDecisionEngine::new(
                scope_guard.clone(),
                plan_id.clone(),
                level,
                goal,
                speed,
            ),
            web: WebDecisionEngine::new(scope_guard.clone(), plan_id.clone(), goal, speed),
            crawl: CrawlDecisionEngine::new(
                scope_guard.clone(),
                plan_id.clone(),
                level,
                goal,
                speed,
            ),
            baseline: BaselineDecisionEngine::new(
                scope_guard.clone(),
                plan_id.clone(),
                level,
                goal,
                speed,
                origin_baselines.clone(),
            ),
            content: ContentDecisionEngine::new(
                scope_guard.clone(),
                plan_id.clone(),
                level,
                goal,
                speed,
                content_wordlist,
                origin_baselines,
            ),
            fuzz: FuzzDecisionEngine::with_origin_budget(
                scope_guard.clone(),
                plan_id.clone(),
                level,
                goal,
                speed,
                fuzz_budget,
            ),
            dns: DnsDecisionEngine::new(scope_guard, plan_id, level, goal, speed),
        }
    }
}

impl crate::execution::DecisionEngine for Phase7Engine {
    fn follow_up_tasks(&self, completed: &Task, output: &ModuleOutput) -> Vec<Task> {
        match completed.kind {
            TaskKind::HostDiscovery => self.tcp.follow_up_tasks(completed, output),
            TaskKind::PortDiscovery => self.service.follow_up_tasks(completed, output),
            TaskKind::ServiceProbe => self.web.follow_up_tasks(completed, output),
            TaskKind::HttpProbe | TaskKind::Crawl => self.crawl.follow_up_tasks(completed, output),
            TaskKind::Baseline => Vec::new(),
            // Wave 1 proposes no UDP follow-ups: an open UDP port is
            // reported with grammar evidence for a future rule to consume.
            TaskKind::UdpDiscovery => Vec::new(),
            _ => Vec::new(),
        }
        .into_iter()
        .chain(self.baseline.follow_up_tasks(completed, output))
        .chain(self.content.follow_up_tasks(completed, output))
        .chain(self.fuzz.follow_up_tasks(completed, output))
        .chain(self.dns.follow_up_tasks(completed, output))
        .collect()
    }
}

/// Deterministic Phase 8 rule: confirmed HTTP/HTTPS services → bounded
/// `HttpProbe` (WebProbe) proposals, one per service finding.
///
/// Port hints played no role here either: only findings whose metadata
/// carries `service: http|https` (protocol evidence from Phase 7) propose.
/// Level breadth lives inside the web task itself (HEAD vs GET, redirect
/// cap), so every confirmed web service proposes at every level; speed and
/// budgets flow through the standard governor/admission path. Proposals
/// carry the canonical URL plus address/port/service context so task IDs
/// stay deterministic; scope is pre-validated and duplicates fall to
/// best-effort scheduler admission.
#[derive(Clone)]
pub struct WebDecisionEngine {
    scope_guard: Arc<dyn ScopeGuard>,
    plan_id: ScanPlanId,
    goal: ScanGoal,
    speed: crate::plan::SpeedSetting,
}

/// Cap on web proposals per single service-task completion (deterministic
/// first-N by URL). Service tasks normally yield ≤1 finding each.
pub const MAX_WEB_PROPOSALS_PER_COMPLETION: usize = 64;

impl WebDecisionEngine {
    pub fn new(
        scope_guard: Arc<dyn ScopeGuard>,
        plan_id: ScanPlanId,
        goal: ScanGoal,
        speed: crate::plan::SpeedSetting,
    ) -> Self {
        Self {
            scope_guard,
            plan_id,
            goal,
            speed,
        }
    }

    fn web_task_for_service(
        &self,
        address: &str,
        port: u16,
        service: &str,
        parent_service_asset: &str,
        target_label: &str,
    ) -> Option<Task> {
        if service != "http" && service != "https" {
            return None;
        }
        let scheme = if service == "https" { "https" } else { "http" };
        let url_text = format!("{scheme}://{address}:{port}/");
        let target = crate::web::WebTarget::parse(&url_text).ok()?;
        // Scope pre-check on the URL host before proposing.
        let scope_target = match target.ip_literal() {
            Some(ip) => TaskScopeTarget::Ip(ip),
            None => TaskScopeTarget::Host(target.host.clone()),
        };
        if !self.scope_guard.permits(&scope_target) {
            return None;
        }
        let mut params = BTreeMap::new();
        params.insert("target".to_owned(), target_label.to_owned());
        params.insert("url".to_owned(), target.canonical());
        params.insert("address".to_owned(), address.to_owned());
        params.insert("port".to_owned(), port.to_string());
        params.insert("scheme".to_owned(), scheme.to_owned());
        params.insert("parent_service".to_owned(), parent_service_asset.to_owned());
        let governor = crate::execution::SpeedGovernor::new(self.speed, 1).ok()?;
        let provenance = crate::model::Provenance::new(
            "rxscan.decision",
            "8.0.0",
            self.plan_id.clone(),
            Timestamp::now(),
        )
        .ok()?;
        Task::new_with_params(
            TaskKind::HttpProbe,
            None,
            Vec::new(),
            None,
            self.plan_id.clone(),
            priority_for_kind(&TaskKind::HttpProbe),
            governor.default_timeout(),
            governor.default_retry_policy(),
            "rxscan.http",
            provenance,
            scope_target,
            params,
            self.scope_guard.as_ref(),
        )
        .ok()
    }
}

impl crate::execution::DecisionEngine for WebDecisionEngine {
    fn follow_up_tasks(&self, completed: &Task, output: &ModuleOutput) -> Vec<Task> {
        if completed.kind != TaskKind::ServiceProbe {
            return Vec::new();
        }
        // Workflow gating: only Recon, Web, and Full derive web work from
        // identified services. Services stops at identification; Discover
        // and Ports never identify services at all.
        if !matches!(self.goal, ScanGoal::Recon | ScanGoal::Web | ScanGoal::Full) {
            return Vec::new();
        }
        let mut proposals = Vec::new();
        let mut seen: BTreeSet<(String, u16, String)> = BTreeSet::new();
        for finding in &output.findings {
            if !(finding.title.contains("service on port")) {
                continue;
            }
            let (Some(service), Some(port_number), Some(address)) = (
                finding
                    .metadata
                    .get("service")
                    .and_then(serde_json::Value::as_str),
                finding
                    .metadata
                    .get("port")
                    .and_then(serde_json::Value::as_u64),
                finding
                    .metadata
                    .get("address")
                    .and_then(serde_json::Value::as_str),
            ) else {
                continue;
            };
            if service != "http" && service != "https" {
                continue;
            }
            let Ok(port) = u16::try_from(port_number) else {
                continue;
            };
            if port == 0
                || !seen.insert((address.to_owned(), port, service.to_owned()))
                || proposals.len() >= MAX_WEB_PROPOSALS_PER_COMPLETION
            {
                continue;
            }
            let target_label = completed
                .params
                .get("target")
                .cloned()
                .unwrap_or_else(|| address.to_owned());
            if let Some(task) = self.web_task_for_service(
                address,
                port,
                service,
                &finding.affected_asset_id.0,
                &target_label,
            ) {
                proposals.push(task);
            }
        }
        proposals
    }
}

/// Phase 9 rule: only confirmed HTTP/HTTPS endpoint observations and
/// evidence-backed crawl discoveries may create `Crawl` tasks. The crawler
/// itself emits events only; recursive work returns through this engine.
#[derive(Clone)]
pub struct CrawlDecisionEngine {
    scope_guard: Arc<dyn ScopeGuard>,
    plan_id: ScanPlanId,
    level: u8,
    goal: ScanGoal,
    speed: crate::plan::SpeedSetting,
}

impl CrawlDecisionEngine {
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

    #[allow(clippy::too_many_arguments)]
    fn crawl_task(
        &self,
        url: &crate::web::WebTarget,
        root: &crate::web::WebTarget,
        parent_endpoint: &str,
        target_label: &str,
        depth: u8,
        pages_left: u32,
        is_root: bool,
        visited: &str,
    ) -> Option<Task> {
        let scope_target = crate::web_probe::scope_target_for_web_target(url);
        if !self.scope_guard.permits(&scope_target) {
            return None;
        }
        let mut params = crate::crawl::crawl_task_params(
            url,
            root,
            depth,
            pages_left,
            parent_endpoint,
            target_label,
            is_root,
        );
        if !visited.is_empty() {
            params.insert("visited".to_owned(), visited.to_owned());
        }
        let governor = crate::execution::SpeedGovernor::new(self.speed, 1).ok()?;
        let provenance = crate::model::Provenance::new(
            "rxscan.decision",
            "9.0.0",
            self.plan_id.clone(),
            Timestamp::now(),
        )
        .ok()?;
        Task::new_with_params(
            TaskKind::Crawl,
            None,
            Vec::new(),
            Some(crate::model::AssetId(parent_endpoint.to_owned())),
            self.plan_id.clone(),
            priority_for_kind(&TaskKind::Crawl),
            governor.default_timeout(),
            governor.default_retry_policy(),
            crate::crawl::CRAWL_MODULE_NAME,
            provenance,
            scope_target,
            params,
            self.scope_guard.as_ref(),
        )
        .ok()
    }
}

impl crate::execution::DecisionEngine for CrawlDecisionEngine {
    fn follow_up_tasks(&self, completed: &Task, output: &ModuleOutput) -> Vec<Task> {
        // Workflow gating: crawl derivation only for Recon, Web, Full.
        if !matches!(self.goal, ScanGoal::Recon | ScanGoal::Web | ScanGoal::Full) {
            return Vec::new();
        }
        let policy = crate::crawl::CrawlPolicy::new(self.level, self.goal, self.speed);
        if completed.kind == TaskKind::HttpProbe {
            let mut proposals = Vec::new();
            let mut seen = BTreeSet::new();
            for event in &output.events {
                if !matches!(event.kind, crate::model::EventKind::EndpointObserved) {
                    continue;
                }
                let Some(url_text) = event
                    .details
                    .data
                    .get("url")
                    .and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                let Ok(url) = crate::web::WebTarget::parse(url_text) else {
                    continue;
                };
                if !seen.insert(url.canonical()) {
                    continue;
                }
                let parent = event
                    .asset_id
                    .as_ref()
                    .map(|id| id.0.as_str())
                    .unwrap_or("");
                if parent.is_empty() {
                    continue;
                }
                let target_label = event
                    .details
                    .data
                    .get("target")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(url.host.as_str());
                if let Some(task) = self.crawl_task(
                    &url,
                    &url,
                    parent,
                    target_label,
                    policy.max_depth(),
                    policy.max_pages_per_root(),
                    true,
                    "",
                ) {
                    proposals.push(task);
                }
                if proposals.len() >= crate::crawl::MAX_CRAWL_PROPOSALS_PER_COMPLETION {
                    break;
                }
            }
            return proposals;
        }

        if completed.kind != TaskKind::Crawl {
            return Vec::new();
        }
        let depth = completed
            .params
            .get("depth")
            .and_then(|value| value.parse::<u8>().ok())
            .unwrap_or(0);
        let pages_left = completed
            .params
            .get("pages_left")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0);
        let root = completed
            .params
            .get("root")
            .and_then(|value| crate::web::WebTarget::parse(value).ok())
            .or_else(|| {
                completed
                    .params
                    .get("url")
                    .and_then(|value| crate::web::WebTarget::parse(value).ok())
            });
        let Some(root) = root else {
            return Vec::new();
        };
        let target_label = completed
            .params
            .get("target")
            .map(String::as_str)
            .unwrap_or(root.host.as_str());
        let mut visited: BTreeSet<String> = completed
            .params
            .get("visited")
            .map(|value| value.split('\n').map(str::to_owned).collect())
            .unwrap_or_default();
        if let Some(current) = completed.params.get("url") {
            visited.insert(current.clone());
        }
        let visited_param = visited.iter().cloned().collect::<Vec<_>>().join("\n");
        let mut candidates = Vec::new();
        for event in &output.events {
            if !matches!(event.kind, crate::model::EventKind::EndpointDiscovered) {
                continue;
            }
            let data = &event.details.data;
            if !data
                .get("scope_permitted")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
                || !data
                    .get("crawl_eligible")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
            {
                continue;
            }
            let Some(url_text) = data.get("url").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let Ok(url) = crate::web::WebTarget::parse(url_text) else {
                continue;
            };
            if url.scheme != root.scheme || url.host != root.host || url.port != root.port {
                continue;
            }
            if visited.contains(&url.canonical()) {
                continue;
            }
            let parent = data
                .get("parent_asset_id")
                .and_then(serde_json::Value::as_str)
                .or_else(|| event.asset_id.as_ref().map(|id| id.0.as_str()))
                .unwrap_or("");
            if parent.is_empty() {
                continue;
            }
            let source = match data.get("source").and_then(serde_json::Value::as_str) {
                Some("link") => crate::crawl::CandidateSource::Link,
                Some("canonical") => crate::crawl::CandidateSource::Canonical,
                Some("stylesheet") => crate::crawl::CandidateSource::Stylesheet,
                Some("robots-path") => crate::crawl::CandidateSource::RobotsPath,
                Some("sitemap-url") => crate::crawl::CandidateSource::SitemapUrl,
                Some("sitemap-index") => crate::crawl::CandidateSource::SitemapIndex,
                _ => continue,
            };
            candidates.push((url, parent.to_owned(), source));
        }
        let plan = crate::crawl::plan_followups(
            candidates,
            depth,
            pages_left,
            crate::crawl::MAX_CRAWL_PROPOSALS_PER_COMPLETION,
        );
        plan.proposals
            .into_iter()
            .filter_map(|proposal| {
                self.crawl_task(
                    &proposal.url,
                    &root,
                    &proposal.parent_asset_id,
                    target_label,
                    proposal.child_depth,
                    proposal.child_pages_left,
                    false,
                    &visited_param,
                )
            })
            .collect()
    }
}

#[derive(Clone)]
pub struct BaselineDecisionEngine {
    scope_guard: Arc<dyn ScopeGuard>,
    plan_id: ScanPlanId,
    level: u8,
    goal: ScanGoal,
    speed: crate::plan::SpeedSetting,
    origin_baselines: crate::baseline::OriginBaselineRegistry,
}

impl BaselineDecisionEngine {
    pub fn new(
        scope_guard: Arc<dyn ScopeGuard>,
        plan_id: ScanPlanId,
        level: u8,
        goal: ScanGoal,
        speed: crate::plan::SpeedSetting,
        origin_baselines: crate::baseline::OriginBaselineRegistry,
    ) -> Self {
        Self {
            scope_guard,
            plan_id,
            level: level.clamp(1, 5),
            goal,
            speed,
            origin_baselines,
        }
    }

    fn baseline_task(
        &self,
        url: &crate::web::WebTarget,
        source_endpoint: &str,
        source: &str,
        origin_baseline: bool,
    ) -> Option<Task> {
        let scope_target = crate::web_probe::scope_target_for_web_target(url);
        if !self.scope_guard.permits(&scope_target) {
            return None;
        }
        let mut params =
            crate::baseline::baseline_task_params(url, source_endpoint, origin_baseline);
        params.insert("source".to_owned(), source.to_owned());
        let governor = crate::execution::SpeedGovernor::new(self.speed, 1).ok()?;
        let provenance = crate::model::Provenance::new(
            "rxscan.decision",
            "10.0.0",
            self.plan_id.clone(),
            Timestamp::now(),
        )
        .ok()?;
        Task::new_with_params(
            TaskKind::Baseline,
            None,
            Vec::new(),
            Some(crate::model::AssetId(source_endpoint.to_owned())),
            self.plan_id.clone(),
            priority_for_kind(&TaskKind::Baseline),
            governor.default_timeout(),
            governor.default_retry_policy(),
            crate::baseline::BASELINE_MODULE_NAME,
            provenance,
            scope_target,
            params,
            self.scope_guard.as_ref(),
        )
        .ok()
    }
}

impl crate::execution::DecisionEngine for BaselineDecisionEngine {
    fn follow_up_tasks(&self, completed: &Task, output: &ModuleOutput) -> Vec<Task> {
        if self.level == 0 {
            return Vec::new();
        }
        // Workflow gating: baseline checks feed content/fuzz derivation,
        // which only Recon, Web, and Full consume.
        if !matches!(self.goal, ScanGoal::Recon | ScanGoal::Web | ScanGoal::Full) {
            return Vec::new();
        }
        if completed.kind == TaskKind::Baseline {
            remember_origin_baselines(&self.origin_baselines, output);
            return Vec::new();
        }
        let mut proposals = Vec::new();
        let mut origins = BTreeSet::new();
        for event in &output.events {
            let source = match event.kind {
                crate::model::EventKind::EndpointObserved => "confirmed-endpoint",
                crate::model::EventKind::EndpointDiscovered => "crawl-discovery",
                _ => continue,
            };
            if matches!(event.kind, crate::model::EventKind::EndpointDiscovered)
                && !event
                    .details
                    .data
                    .get("scope_permitted")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
            {
                continue;
            }
            let Some(url_text) = event
                .details
                .data
                .get("url")
                .and_then(serde_json::Value::as_str)
            else {
                continue;
            };
            let Ok(url) = crate::web::WebTarget::parse(url_text) else {
                continue;
            };
            let origin = crate::baseline::origin_root(&url).canonical();
            let origin_baseline =
                origins.insert(origin.clone()) && !self.origin_baselines.has(&origin);
            let source_endpoint = event
                .asset_id
                .as_ref()
                .map(|id| id.0.as_str())
                .unwrap_or("");
            if source_endpoint.is_empty() {
                continue;
            }
            if let Some(task) = self.baseline_task(&url, source_endpoint, source, origin_baseline) {
                proposals.push(task);
            }
            if proposals.len() >= crate::baseline::MAX_ENDPOINT_COMPARISONS {
                break;
            }
        }
        proposals
    }
}

fn remember_origin_baselines(
    registry: &crate::baseline::OriginBaselineRegistry,
    output: &ModuleOutput,
) {
    for event in &output.events {
        if !matches!(event.kind, crate::model::EventKind::OriginBaselineObserved) {
            continue;
        }
        let Some(origin) = event
            .details
            .data
            .get("origin")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let hashes = event
            .details
            .data
            .get("normalized_sha256")
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        registry.remember(origin.to_owned(), hashes);
    }
}

#[derive(Clone)]
pub struct ContentDecisionEngine {
    scope_guard: Arc<dyn ScopeGuard>,
    plan_id: ScanPlanId,
    level: u8,
    goal: ScanGoal,
    speed: crate::plan::SpeedSetting,
    wordlist: Option<PathBuf>,
    origin_baselines: crate::baseline::OriginBaselineRegistry,
}

impl ContentDecisionEngine {
    pub fn new(
        scope_guard: Arc<dyn ScopeGuard>,
        plan_id: ScanPlanId,
        level: u8,
        goal: ScanGoal,
        speed: crate::plan::SpeedSetting,
        wordlist: Option<PathBuf>,
        origin_baselines: crate::baseline::OriginBaselineRegistry,
    ) -> Self {
        Self {
            scope_guard,
            plan_id,
            level: level.clamp(1, 5),
            goal,
            speed,
            wordlist,
            origin_baselines,
        }
    }

    fn content_task(
        &self,
        url: &crate::web::WebTarget,
        _source_endpoint: &str,
        baseline_hashes: Option<&str>,
    ) -> Option<Task> {
        let policy = crate::content::ContentDiscoveryPolicy::new(self.level, self.goal, self.speed);
        if !policy.enabled() {
            return None;
        }
        let root = crate::baseline::origin_root(url);
        let scope_target = crate::web_probe::scope_target_for_web_target(&root);
        if !self.scope_guard.permits(&scope_target) {
            return None;
        }
        let origin_endpoint = crate::web::endpoint_asset_id(&root);
        let mut params =
            crate::content::content_task_params(&root, &origin_endpoint, self.wordlist.as_deref());
        let stored_hashes = self.origin_baselines.get_hashes(&root.canonical());
        let baseline_hashes = baseline_hashes
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .or(stored_hashes);
        if let Some(hash) = baseline_hashes.filter(|value| !value.is_empty()) {
            params.insert("baseline_normalized_sha256".to_owned(), hash.to_owned());
        }
        let governor = crate::execution::SpeedGovernor::new(self.speed, 1).ok()?;
        let provenance = crate::model::Provenance::new(
            "rxscan.decision",
            "11.0.0",
            self.plan_id.clone(),
            Timestamp::now(),
        )
        .ok()?;
        Task::new_with_params(
            TaskKind::ContentDiscovery,
            None,
            Vec::new(),
            Some(crate::model::AssetId(origin_endpoint)),
            self.plan_id.clone(),
            priority_for_kind(&TaskKind::ContentDiscovery),
            governor.default_timeout(),
            governor.default_retry_policy(),
            crate::content::CONTENT_MODULE_NAME,
            provenance,
            scope_target,
            params,
            self.scope_guard.as_ref(),
        )
        .ok()
    }
}

impl crate::execution::DecisionEngine for ContentDecisionEngine {
    fn follow_up_tasks(&self, completed: &Task, output: &ModuleOutput) -> Vec<Task> {
        if self.level < 2 {
            return Vec::new();
        }
        // Workflow gating: content derivation only for Recon, Web, Full.
        if !matches!(self.goal, ScanGoal::Recon | ScanGoal::Web | ScanGoal::Full) {
            return Vec::new();
        }
        let mut proposals = Vec::new();
        let mut origins = BTreeSet::new();
        if completed.kind == TaskKind::Baseline {
            remember_origin_baselines(&self.origin_baselines, output);
            let mut baseline_by_origin: BTreeMap<String, String> = BTreeMap::new();
            for event in &output.events {
                if !matches!(event.kind, crate::model::EventKind::OriginBaselineObserved) {
                    continue;
                }
                let Some(origin) = event
                    .details
                    .data
                    .get("origin")
                    .and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                let hashes = event
                    .details
                    .data
                    .get("normalized_sha256")
                    .and_then(serde_json::Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(serde_json::Value::as_str)
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                baseline_by_origin.insert(origin.to_owned(), hashes);
            }
            for event in &output.events {
                if !matches!(event.kind, crate::model::EventKind::BaselineCompleted) {
                    continue;
                }
                let Some(url_text) = event
                    .details
                    .data
                    .get("url")
                    .and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                let Ok(url) = crate::web::WebTarget::parse(url_text) else {
                    continue;
                };
                let origin = crate::baseline::origin_root(&url).canonical();
                if !origins.insert(origin.clone()) {
                    continue;
                }
                if !baseline_by_origin.contains_key(&origin) {
                    continue;
                }
                let source_endpoint = completed
                    .associated_asset_id
                    .as_ref()
                    .map(|id| id.0.as_str())
                    .unwrap_or("");
                if source_endpoint.is_empty() {
                    continue;
                }
                if let Some(task) = self.content_task(
                    &url,
                    source_endpoint,
                    baseline_by_origin.get(&origin).map(String::as_str),
                ) {
                    proposals.push(task);
                }
            }
        } else if self.level == 2 && matches!(completed.kind, TaskKind::HttpProbe | TaskKind::Crawl)
        {
            for event in &output.events {
                let source_event = matches!(
                    event.kind,
                    crate::model::EventKind::EndpointObserved
                        | crate::model::EventKind::EndpointDiscovered
                );
                if !source_event {
                    continue;
                }
                if matches!(event.kind, crate::model::EventKind::EndpointDiscovered)
                    && !event
                        .details
                        .data
                        .get("scope_permitted")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false)
                {
                    continue;
                }
                let Some(url_text) = event
                    .details
                    .data
                    .get("url")
                    .and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                let Ok(url) = crate::web::WebTarget::parse(url_text) else {
                    continue;
                };
                let origin = crate::baseline::origin_root(&url).canonical();
                if !origins.insert(origin) {
                    continue;
                }
                let source_endpoint = event
                    .asset_id
                    .as_ref()
                    .map(|id| id.0.as_str())
                    .unwrap_or("");
                if source_endpoint.is_empty() {
                    continue;
                }
                if let Some(task) = self.content_task(&url, source_endpoint, None) {
                    proposals.push(task);
                }
            }
        }
        proposals
    }
}

#[derive(Clone)]
pub struct FuzzDecisionEngine {
    scope_guard: Arc<dyn ScopeGuard>,
    plan_id: ScanPlanId,
    level: u8,
    goal: ScanGoal,
    speed: crate::plan::SpeedSetting,
    origin_budget: crate::fuzz::FuzzOriginBudget,
}

impl FuzzDecisionEngine {
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
            origin_budget: crate::fuzz::FuzzOriginBudget::new(),
        }
    }

    pub fn with_origin_budget(
        scope_guard: Arc<dyn ScopeGuard>,
        plan_id: ScanPlanId,
        level: u8,
        goal: ScanGoal,
        speed: crate::plan::SpeedSetting,
        origin_budget: crate::fuzz::FuzzOriginBudget,
    ) -> Self {
        Self {
            scope_guard,
            plan_id,
            level: level.clamp(1, 5),
            goal,
            speed,
            origin_budget,
        }
    }

    fn fuzz_task(
        &self,
        url: &crate::web::WebTarget,
        source_endpoint: &str,
        param: &str,
        signature: &crate::baseline::ResponseSignature,
    ) -> Option<Task> {
        let policy = crate::fuzz::FuzzPolicy::new(self.level, self.goal, self.speed);
        if !policy.enabled() || crate::fuzz::is_sensitive_name(param) {
            return None;
        }
        let scope_target = crate::web_probe::scope_target_for_web_target(url);
        if !self.scope_guard.permits(&scope_target) {
            return None;
        }
        let governor = crate::execution::SpeedGovernor::new(self.speed, 1).ok()?;
        let provenance = crate::model::Provenance::new(
            "rxscan.decision",
            "12.0.0",
            self.plan_id.clone(),
            Timestamp::now(),
        )
        .ok()?;
        let mut task = Task::new_with_params(
            TaskKind::Fuzz,
            None,
            Vec::new(),
            Some(crate::model::AssetId(source_endpoint.to_owned())),
            self.plan_id.clone(),
            priority_for_kind(&TaskKind::Fuzz),
            governor.default_timeout(),
            governor.default_retry_policy(),
            crate::fuzz::FUZZ_MODULE_NAME,
            provenance,
            scope_target,
            crate::fuzz::fuzz_task_params(url, source_endpoint, param, Some(signature)),
            self.scope_guard.as_ref(),
        )
        .ok()?;
        task.id = fuzz_plan_task_id(&self.plan_id, url, source_endpoint, param, signature);
        Some(task)
    }
}

fn fuzz_plan_task_id(
    plan_id: &ScanPlanId,
    url: &crate::web::WebTarget,
    source_endpoint: &str,
    param: &str,
    signature: &crate::baseline::ResponseSignature,
) -> TaskId {
    let identity = serde_json::json!({
        "plan": plan_id.0,
        "module": crate::fuzz::FUZZ_MODULE_NAME,
        "kind": "fuzz",
        "source_endpoint": source_endpoint,
        "url": url.canonical(),
        "param": param,
        "baseline_raw_sha256": signature.raw_sha256,
        "baseline_normalized_sha256": signature.normalized_sha256,
    });
    let bytes = serde_json::to_vec(&identity).expect("fuzz identity serializes");
    let digest = Sha256::digest(&bytes);
    TaskId(format!(
        "task_{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

impl crate::execution::DecisionEngine for FuzzDecisionEngine {
    fn follow_up_tasks(&self, completed: &Task, output: &ModuleOutput) -> Vec<Task> {
        if completed.kind != TaskKind::Baseline
            || self.level < 3
            || !matches!(self.goal, ScanGoal::Full)
        {
            return Vec::new();
        }
        let mut proposals = Vec::new();
        let mut seen = BTreeSet::new();
        for event in &output.events {
            if !matches!(
                event.kind,
                crate::model::EventKind::ResponseSignatureObserved
            ) {
                continue;
            }
            let Some(url_text) = event
                .details
                .data
                .get("url")
                .and_then(serde_json::Value::as_str)
            else {
                continue;
            };
            let Ok(url) = crate::web::WebTarget::parse(url_text) else {
                continue;
            };
            let Some(query) = url.query.as_deref() else {
                continue;
            };
            let Some(signature_value) = event.details.data.get("signature") else {
                continue;
            };
            let Ok(signature) = serde_json::from_value::<crate::baseline::ResponseSignature>(
                signature_value.clone(),
            ) else {
                continue;
            };
            let source_endpoint = event
                .asset_id
                .as_ref()
                .map(|id| id.0.as_str())
                .unwrap_or("");
            if source_endpoint.is_empty() {
                continue;
            }
            for (name, _) in url::form_urlencoded::parse(query.as_bytes())
                .take(crate::fuzz::MAX_FUZZ_PARAMS_PER_ENDPOINT)
            {
                if name.is_empty() || crate::fuzz::is_sensitive_name(&name) {
                    continue;
                }
                let key = format!("{}#{name}", url.canonical());
                if !seen.insert(key) {
                    continue;
                }
                let origin = crate::fuzz::origin_key(&url);
                let plan_key = format!("{}#{name}", url.canonical());
                let policy = crate::fuzz::FuzzPolicy::new(self.level, self.goal, self.speed);
                if !self
                    .origin_budget
                    .claim(&origin, &plan_key, policy.tasks_per_origin_limit())
                {
                    continue;
                }
                if let Some(task) = self.fuzz_task(&url, source_endpoint, &name, &signature) {
                    proposals.push(task);
                }
                if proposals.len() >= crate::fuzz::MAX_FUZZ_PARAMS_PER_ENDPOINT {
                    return proposals;
                }
            }
        }
        proposals
    }
}

#[derive(Clone)]
pub struct DnsDecisionEngine {
    scope_guard: Arc<dyn ScopeGuard>,
    plan_id: ScanPlanId,
    level: u8,
    goal: ScanGoal,
    speed: crate::plan::SpeedSetting,
}

impl DnsDecisionEngine {
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

    fn host_task(&self, ip: IpAddr, source_asset: Option<AssetId>) -> Option<Task> {
        let scope_target = TaskScopeTarget::Ip(ip);
        if !self.scope_guard.permits(&scope_target) {
            return None;
        }
        let governor = crate::execution::SpeedGovernor::new(self.speed, 1).ok()?;
        let provenance = crate::model::Provenance::new(
            "rxscan.decision",
            "13.0.0",
            self.plan_id.clone(),
            Timestamp::now(),
        )
        .ok()?;
        Task::new_with_params(
            TaskKind::HostDiscovery,
            None,
            Vec::new(),
            source_asset,
            self.plan_id.clone(),
            priority_for_kind(&TaskKind::HostDiscovery),
            governor.default_timeout(),
            governor.default_retry_policy(),
            crate::host_discovery::HOST_DISCOVERY_MODULE_NAME,
            provenance,
            scope_target,
            BTreeMap::from([
                ("target".to_owned(), ip.to_string()),
                ("source".to_owned(), "dns".to_owned()),
            ]),
            self.scope_guard.as_ref(),
        )
        .ok()
    }
}

impl crate::execution::DecisionEngine for DnsDecisionEngine {
    fn follow_up_tasks(&self, completed: &Task, output: &ModuleOutput) -> Vec<Task> {
        if completed.kind != TaskKind::DnsProbe || self.level == 0 {
            return Vec::new();
        }
        // Workflow gating: Ports stops after the port scan; every other
        // workflow may expand DNS observations into host discovery.
        if !matches!(
            self.goal,
            ScanGoal::Recon
                | ScanGoal::Discover
                | ScanGoal::Services
                | ScanGoal::Web
                | ScanGoal::Full
        ) {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        for event in &output.events {
            if !matches!(event.kind, crate::model::EventKind::DnsRecordObserved) {
                continue;
            }
            let record_type = event
                .details
                .data
                .get("record_type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            if record_type != "A" && record_type != "AAAA" {
                continue;
            }
            let Some(value) = event
                .details
                .data
                .get("value")
                .and_then(serde_json::Value::as_str)
            else {
                continue;
            };
            let Ok(ip) = value.parse::<IpAddr>() else {
                continue;
            };
            if !seen.insert(ip) {
                continue;
            }
            if let Some(task) = self.host_task(ip, event.asset_id.clone()) {
                out.push(task);
            }
            if out.len() >= 16 {
                break;
            }
        }
        out
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
