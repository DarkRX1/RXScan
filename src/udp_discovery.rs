//! Native UDP port-discovery scheduler module (P23).
//!
//! Control path (never bypassed):
//! `Target -> Scope Guard -> ScanPlan -> Scheduler <-> Speed Governor /
//! Budgets / Backpressure -> UdpDiscoveryModule (bounded internal scan) ->
//! Typed Events / Evidence / Assets / Findings -> JSONL Output`.
//!
//! The module emits facts only. Wave 1 proposes no follow-up tasks;
//! DNS-grammar recognition is reported as evidence (service/protocol on
//! the finding metadata) for a future DecisionEngine rule to consume.
//!
//! Task representation mirrors TCP: ONE `UdpDiscovery` scheduler task per
//! target carries the full selection in deterministic `params`
//! (`transport=udp`, `ports=common|explicit|all`). The shared operator
//! selection resolves per transport: `Common` means `udp-common-v1`
//! (never the TCP set), `Explicit` reuses the operator list,
//! `All` means `1..=65535`.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::discovery::AddressFamily;
use crate::execution::{
    CancellationToken, Module, ModuleContext, ModuleError, ModuleFuture, ModuleOutput, ScopeGuard,
    TaskKind, TaskScopeTarget,
};
use crate::model::{
    Asset, AssetId, AssetKind, BoundedDetails, Confidence, Event, EventKind, Evidence, Finding,
    MAX_EVENT_DETAILS_BYTES, Provenance, Severity, Timestamp,
};
use crate::plan::{ScanGoal, SpeedSetting, TcpPortSelection};
use crate::ports::{
    PortSource, ResolvedPorts, parse_port_selection, resolve_udp_ports, udp_concurrency_for_speed,
};
use crate::udp_probes::Wave1UdpProbes;
use crate::udp_scanner::{NativeUdpScanner, UdpPortState, UdpScanConfig, UdpScanner};

pub const UDP_DISCOVERY_MODULE_NAME: &str = "rxscan.udp";
pub const UDP_DISCOVERY_MODULE_VERSION: &str = "1.0.0";

/// Per-port events flood JSONL on huge scans; emit per-port outcome events
/// only up to this many ports, otherwise opens + summary.
pub const MAX_DETAILED_UDP_EVENTS: usize = 256;

/// Max IPs scanned per hostname task (scope-filtered, deterministic).
pub const MAX_IPS_PER_UDP_TASK: usize = 4;

/// Centralized UDP policy template (level breadth + speed pressure).
#[derive(Debug, Clone)]
pub struct UdpScanPolicy {
    pub level: u8,
    pub goal: ScanGoal,
    pub selection: TcpPortSelection,
    pub speed: SpeedSetting,
}

impl UdpScanPolicy {
    pub fn new(
        level: u8,
        goal: ScanGoal,
        selection: TcpPortSelection,
        speed: SpeedSetting,
    ) -> Self {
        Self {
            level: level.clamp(1, 5),
            goal,
            selection,
            speed,
        }
    }

    /// Concrete port list for one task. Explicit/`all` in task params win;
    /// otherwise the plan-level selection resolved for UDP (`Common` means
    /// `udp-common-v1`). Always sorted, deduped, port 0 excluded.
    pub fn ports_for_task(&self, task_ports_param: Option<&str>) -> ResolvedPorts {
        if let Some(param) = task_ports_param {
            if param == "all" {
                return ResolvedPorts {
                    ports: (1..=65_535).collect(),
                    source: PortSource::All,
                };
            }
            if let Some(rest) = param.strip_prefix("explicit:") {
                let ports = parse_port_selection(rest).unwrap_or_default();
                return ResolvedPorts {
                    ports,
                    source: PortSource::Explicit,
                };
            }
            if param == "common" {
                return resolve_udp_ports(&TcpPortSelection::Common, self.level);
            }
        }
        resolve_udp_ports(&self.selection, self.level)
    }

    pub fn per_attempt_timeout(&self) -> Duration {
        crate::ports::udp_timeout_for_speed(self.speed)
    }

    pub fn window(&self) -> usize {
        udp_concurrency_for_speed(self.speed)
    }

    /// Bounded retries: silence gets one retry at L3+ when the speed
    /// policy allows it; closed/answered/error never retry.
    pub fn max_retries(&self) -> u32 {
        crate::ports::udp_max_retries_for_level(self.level)
    }

    pub fn describe(&self) -> String {
        let resolved = resolve_udp_ports(&self.selection, self.level);
        let preview = if resolved.ports.len() <= 12 {
            resolved
                .ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        } else {
            format!(
                "{} ports ({}..{} …)",
                resolved.ports.len(),
                resolved.ports.first().unwrap_or(&0),
                resolved.ports.last().unwrap_or(&0)
            )
        };
        format!(
            "udp {} level {} ({:?}): {} [{}], timeout {}ms, window {}, retries {}",
            resolved.source,
            self.level,
            self.goal,
            preview,
            crate::ports::UDP_PROFILE_VERSION,
            self.per_attempt_timeout().as_millis(),
            self.window(),
            self.max_retries(),
        )
    }
}

/// One open UDP port preserved as evidence/JSONL.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenUdpRecord {
    pub target: String,
    pub address: String,
    pub address_family: AddressFamily,
    pub parent_asset_id: String,
    pub asset_id: String,
    pub transport: String,
    pub port: u16,
    pub state: String,
    /// Grammar-matched protocol (`dns`/`ntp`/`ssdp`), if any. `None`
    /// means responsive with unrecognized payload (Open + unknown).
    pub service: Option<String>,
    pub latency_ms: u64,
    pub timestamp: u64,
}

/// Typed UDP totals aggregated from `UdpScanCompleted` events: the SAME
/// state JSONL serializes, rendered by human output so the two agree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UdpScanTotals {
    pub completed_tasks: usize,
    pub ports_requested: u64,
    pub ports_attempted: u64,
    pub open: u64,
    pub closed: u64,
    pub open_or_filtered: u64,
    pub error: u64,
    pub unscanned: u64,
    pub truncated: bool,
    pub port_sources: Vec<String>,
    pub elapsed_ms_max: u64,
    pub fd_peak_max: usize,
    pub datagrams_sent: u64,
    pub datagrams_received: u64,
    pub retries: u64,
}

/// Aggregate `UdpScanCompleted` events across succeeded module outputs.
pub fn summarize_udp_scans(
    module_outputs: &[(crate::execution::TaskId, ModuleOutput)],
) -> UdpScanTotals {
    let mut totals = UdpScanTotals::default();
    let mut sources: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (_, output) in module_outputs {
        for event in &output.events {
            if !matches!(event.kind, EventKind::UdpScanCompleted) {
                continue;
            }
            totals.completed_tasks += 1;
            let data = &event.details.data;
            let count = |key: &str| {
                data.get("counts")
                    .and_then(|c| c.get(key))
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0)
            };
            totals.open += count("open");
            totals.closed += count("closed");
            totals.open_or_filtered += count("open_or_filtered");
            totals.error += count("error");
            let requested = data
                .get("ports_requested")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let unscanned = data
                .get("unscanned")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            totals.ports_requested += requested;
            totals.unscanned += unscanned;
            totals.ports_attempted += requested.saturating_sub(unscanned);
            if data
                .get("truncated")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                totals.truncated = true;
            }
            if let Some(source) = data.get("port_source").and_then(serde_json::Value::as_str) {
                sources.insert(source.to_owned());
            }
            if let Some(elapsed) = data.get("elapsed_ms").and_then(serde_json::Value::as_u64) {
                totals.elapsed_ms_max = totals.elapsed_ms_max.max(elapsed);
            }
            if let Some(peak) = data.get("fd_peak").and_then(serde_json::Value::as_u64) {
                totals.fd_peak_max = totals.fd_peak_max.max(usize::try_from(peak).unwrap_or(0));
            }
            for (key, slot) in [
                ("datagrams_sent", &mut totals.datagrams_sent),
                ("datagrams_received", &mut totals.datagrams_received),
                ("retries", &mut totals.retries),
            ] {
                if let Some(value) = data.get(key).and_then(serde_json::Value::as_u64) {
                    *slot += value;
                }
            }
        }
    }
    totals.port_sources = sources.into_iter().collect();
    totals
}

/// Whether any completed UDP discovery exists in these outputs.
///
/// Execution truth: UDP human lines require a `UdpScanCompleted` event.
/// Absence of open ports alone proves nothing (no UDP task may have run).
pub fn udp_scan_completed(
    module_outputs: &[(crate::execution::TaskId, crate::execution::ModuleOutput)],
) -> bool {
    module_outputs
        .iter()
        .flat_map(|(_, output)| &output.events)
        .any(|event| matches!(event.kind, EventKind::UdpScanCompleted))
}

/// One-line UDP scanner-work summary. Empty when no UDP discovery
/// completed (caller prints the truthful no-discovery message instead).
pub fn human_udp_totals_line(totals: &UdpScanTotals) -> String {
    if totals.completed_tasks == 0 {
        return String::new();
    }
    let sources = if totals.port_sources.is_empty() {
        "unknown".to_owned()
    } else {
        totals.port_sources.join("+")
    };
    let mut line = format!(
        "UDP discovery ({sources}): {} requested, {} attempted, {} open, {} closed, {} open|filtered, {} errors, {} unscanned",
        totals.ports_requested,
        totals.ports_attempted,
        totals.open,
        totals.closed,
        totals.open_or_filtered,
        totals.error,
        totals.unscanned,
    );
    if totals.truncated {
        line.push_str(" (truncated: global deadline cut the scan short)");
    }
    line.push_str(&format!(
        " [UDP scan time: {}ms max per task, {} datagrams sent/{} received, {} retries]",
        totals.elapsed_ms_max, totals.datagrams_sent, totals.datagrams_received, totals.retries,
    ));
    line
}

/// Human UDP table: one row per open UDP port with transport-explicit
/// state and grammar-matched service (or `-` for unknown).
///
/// Silence is never shown as open: only `Open`-state findings produce rows.
/// Empty string when no UDP opens exist (caller selects the truthful
/// completed-vs-never-ran message instead).
pub fn human_udp_table(
    module_outputs: &[(crate::execution::TaskId, crate::execution::ModuleOutput)],
) -> String {
    use std::collections::BTreeMap;
    let mut rows: BTreeMap<(String, u16), String> = BTreeMap::new();
    for (_, output) in module_outputs {
        for finding in &output.findings {
            if !finding.title.starts_with("Open UDP port") {
                continue;
            }
            let address = finding
                .metadata
                .get("address")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_owned();
            let port = finding
                .metadata
                .get("port")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u16;
            if port == 0 {
                continue;
            }
            let service = finding
                .metadata
                .get("service")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-")
                .to_owned();
            rows.insert((address, port), service);
        }
    }
    if rows.is_empty() {
        return String::new();
    }
    let mut by_host: BTreeMap<String, Vec<(u16, String)>> = BTreeMap::new();
    for ((host, port), service) in rows {
        by_host.entry(host).or_default().push((port, service));
    }
    let mut lines = Vec::new();
    for (host, mut host_ports) in by_host {
        host_ports.sort();
        lines.push(format!("HOST {host}"));
        lines.push("PORT      STATE           SERVICE".to_owned());
        for (port, service) in host_ports {
            lines.push(format!("{port}/udp    open            {service}"));
        }
    }
    lines.join("\n")
}

/// Stable FNV-1a helpers mirroring TCP asset-ID stability.
fn fnv_hex(input: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

pub fn parent_asset_id_for_ip(ip: &IpAddr) -> String {
    format!("asset_ip_{}", fnv_hex(&format!("ip:{ip}")))
}

/// Stable child port-asset ID. Transport-partitioned: `53/tcp` and
/// `53/udp` never collide (diff/report treat them as distinct).
pub fn udp_port_asset_id(parent_asset_id: &str, transport: &str, port: u16) -> String {
    // Reuse the TCP asset-ID construction exactly (same hash inputs mean
    // the same stable ID for the same parent/transport/port).
    crate::tcp_discovery::port_asset_id(parent_asset_id, transport, port)
}

fn port_asset_identity(parent_asset_id: &str, transport: &str, port: u16) -> String {
    format!("{parent_asset_id}:{transport}/{port}")
}

/// Real scheduler module for `TaskKind::UdpDiscovery`.
pub struct UdpDiscoveryModule {
    policy: UdpScanPolicy,
    scanner: Arc<dyn UdpScanner>,
    source: Arc<dyn crate::udp_scanner::UdpProbeSource>,
    scope_guard: Arc<dyn ScopeGuard>,
}

impl UdpDiscoveryModule {
    pub fn new(policy: UdpScanPolicy, scope_guard: Arc<dyn ScopeGuard>) -> Self {
        Self {
            policy,
            scanner: Arc::new(NativeUdpScanner),
            source: Arc::new(Wave1UdpProbes),
            scope_guard,
        }
    }

    pub fn with_scanner(
        policy: UdpScanPolicy,
        scanner: Arc<dyn UdpScanner>,
        scope_guard: Arc<dyn ScopeGuard>,
    ) -> Self {
        Self {
            policy,
            scanner,
            source: Arc::new(Wave1UdpProbes),
            scope_guard,
        }
    }

    /// Test seam: deterministic probe source (production always uses
    /// [`Wave1UdpProbes`]). Lets tests prove grammar recognition on
    /// ephemeral ports without privileged low-port binds.
    pub fn with_probes(
        policy: UdpScanPolicy,
        scanner: Arc<dyn UdpScanner>,
        source: Arc<dyn crate::udp_scanner::UdpProbeSource>,
        scope_guard: Arc<dyn ScopeGuard>,
    ) -> Self {
        Self {
            policy,
            scanner,
            source,
            scope_guard,
        }
    }

    pub fn policy(&self) -> &UdpScanPolicy {
        &self.policy
    }
}

impl Module for UdpDiscoveryModule {
    fn kind(&self) -> TaskKind {
        TaskKind::UdpDiscovery
    }

    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let policy = self.policy.clone();
        let scanner = self.scanner.clone();
        let source = self.source.clone();
        let guard = self.scope_guard.clone();
        Box::pin(async move {
            execute_udp_scan(
                &policy,
                scanner.as_ref(),
                source.as_ref(),
                guard.as_ref(),
                context,
            )
        })
    }
}

enum Candidates {
    Ips {
        ips: Vec<IpAddr>,
        target_label: String,
        parent_ids: Vec<String>,
    },
    Empty {
        target_label: String,
        reason: String,
    },
    Cancelled,
    StaleScope(String),
}

fn resolve_scan_candidates(
    scope_target: &TaskScopeTarget,
    params: &BTreeMap<String, String>,
    guard: &dyn ScopeGuard,
    cancel: &CancellationToken,
) -> Result<Candidates, ModuleError> {
    if cancel.is_cancelled() {
        return Ok(Candidates::Cancelled);
    }
    let target_label = params
        .get("target")
        .cloned()
        .unwrap_or_else(|| match scope_target {
            TaskScopeTarget::Ip(ip) => ip.to_string(),
            TaskScopeTarget::Host(host) => host.clone(),
            TaskScopeTarget::Url(url) => url.clone(),
            TaskScopeTarget::None => "unknown".to_owned(),
        });
    match scope_target {
        TaskScopeTarget::Ip(ip) => {
            if !guard.permits(&TaskScopeTarget::Ip(*ip)) {
                return Ok(Candidates::StaleScope(
                    "stale scope rejected immediately before network execution".to_owned(),
                ));
            }
            Ok(Candidates::Ips {
                ips: vec![*ip],
                target_label,
                parent_ids: vec![parent_asset_id_for_ip(ip)],
            })
        }
        TaskScopeTarget::Host(host) => {
            if !guard.permits(&TaskScopeTarget::Host(host.clone())) {
                return Ok(Candidates::StaleScope(
                    "stale scope rejected immediately before network execution".to_owned(),
                ));
            }
            if let Ok(ip) = host.parse::<IpAddr>() {
                if !guard.permits(&TaskScopeTarget::Ip(ip)) {
                    return Ok(Candidates::Empty {
                        target_label,
                        reason: format!(
                            "derived address {ip} is outside scope; skipped without probing."
                        ),
                    });
                }
                return Ok(Candidates::Ips {
                    ips: vec![ip],
                    target_label,
                    parent_ids: vec![parent_asset_id_for_ip(&ip)],
                });
            }
            match crate::host_discovery::resolve_hostname_bounded(
                host,
                Duration::from_millis(2000),
                cancel,
            ) {
                Ok(addresses) => {
                    let permitted: Vec<IpAddr> = addresses
                        .into_iter()
                        .filter(|ip| guard.permits(&TaskScopeTarget::Ip(*ip)))
                        .take(MAX_IPS_PER_UDP_TASK)
                        .collect();
                    if permitted.is_empty() {
                        Ok(Candidates::Empty {
                            target_label,
                            reason: format!(
                                "hostname '{host}' resolved only to out-of-scope addresses or nothing; skipped without probing."
                            ),
                        })
                    } else {
                        let parent_ids = permitted.iter().map(parent_asset_id_for_ip).collect();
                        Ok(Candidates::Ips {
                            ips: permitted,
                            target_label,
                            parent_ids,
                        })
                    }
                }
                Err(reason) if reason == "cancelled" => Ok(Candidates::Cancelled),
                Err(reason) => Ok(Candidates::Empty {
                    target_label,
                    reason: format!("hostname '{host}' resolution failed ({reason})."),
                }),
            }
        }
        TaskScopeTarget::Url(url) => {
            let host = url::Url::parse(url)
                .ok()
                .and_then(|parsed| parsed.host_str().map(str::to_owned));
            match host {
                Some(host) => {
                    let nested = TaskScopeTarget::Host(host);
                    let mut nested_params = params.clone();
                    nested_params
                        .entry("target".to_owned())
                        .or_insert_with(|| url.clone());
                    resolve_scan_candidates(&nested, &nested_params, guard, cancel)
                }
                None => Ok(Candidates::Empty {
                    target_label,
                    reason: format!("URL '{url}' has no resolvable host."),
                }),
            }
        }
        TaskScopeTarget::None => Ok(Candidates::Empty {
            target_label,
            reason: "task has no network target.".to_owned(),
        }),
    }
}

#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
fn execute_udp_scan(
    policy: &UdpScanPolicy,
    scanner: &dyn UdpScanner,
    source: &dyn crate::udp_scanner::UdpProbeSource,
    guard: &dyn ScopeGuard,
    context: ModuleContext,
) -> Result<ModuleOutput, ModuleError> {
    let task = context.task.clone();
    let cancel = context.cancellation();
    if !guard.permits(&task.scope_target) {
        return Err(ModuleError::Failed {
            message: "stale scope rejected immediately before network execution".to_owned(),
            retryable: false,
        });
    }
    if cancel.is_cancelled() {
        return Err(ModuleError::Cancelled);
    }
    let started_at = Timestamp::now();
    let start_instant = Instant::now();
    let task_deadline = Instant::now()
        .checked_add(Duration::from_millis(task.timeout_ms.max(1)))
        .unwrap_or_else(|| Instant::now() + Duration::from_secs(60));
    let provenance = Provenance::new(
        UDP_DISCOVERY_MODULE_NAME,
        UDP_DISCOVERY_MODULE_VERSION,
        task.scan_plan_id.clone(),
        started_at,
    )
    .map_err(|_| ModuleError::Failed {
        message: "invalid provenance".to_owned(),
        retryable: false,
    })?;

    let mut events: Vec<Event> = Vec::new();
    let mut evidence_items: Vec<Evidence> = Vec::new();
    let mut assets: Vec<Asset> = Vec::new();
    let mut findings: Vec<Finding> = Vec::new();

    // Resolve ports BEFORE candidates so invalid selection fails fast.
    let ports_param = task.params.get("ports").map(String::as_str);
    let resolved = policy.ports_for_task(ports_param);
    let candidates = resolve_scan_candidates(&task.scope_target, &task.params, guard, &cancel)
        .map_err(|_| ModuleError::Failed {
            message: "candidate resolution failed".to_owned(),
            retryable: false,
        })?;
    let (ips, target_label, parent_ids) = match candidates {
        Candidates::Cancelled => return Err(ModuleError::Cancelled),
        Candidates::StaleScope(message) => {
            return Err(ModuleError::Failed {
                message,
                retryable: false,
            });
        }
        Candidates::Empty {
            target_label,
            reason,
        } => {
            return finish_empty_scan(
                &target_label,
                &reason,
                &resolved,
                policy,
                events,
                &provenance,
                start_instant,
            );
        }
        Candidates::Ips {
            ips,
            target_label,
            parent_ids,
        } => (ips, target_label, parent_ids),
    };

    push_event(
        &mut events,
        EventKind::UdpScanStarted,
        None,
        serde_json::json!({
            "target": target_label,
            "policy": policy.describe(),
            "port_source": resolved.source.to_string(),
            "port_count": resolved.ports.len(),
            "addresses": ips.iter().map(IpAddr::to_string).collect::<Vec<_>>(),
        }),
        &provenance,
    )?;

    let detailed = resolved.ports.len() <= MAX_DETAILED_UDP_EVENTS;
    let scan_config = UdpScanConfig::bounded_detailed(
        policy.per_attempt_timeout(),
        policy.window(),
        policy.max_retries(),
        detailed,
        Some(task_deadline),
        cancel.clone(),
    );
    let detailed = resolved.ports.len() <= MAX_DETAILED_UDP_EVENTS;
    let mut open_records: Vec<OpenUdpRecord> = Vec::new();
    let mut counts = BTreeMap::from([
        ("open", 0u64),
        ("closed", 0u64),
        ("open_or_filtered", 0u64),
        ("error", 0u64),
    ]);
    let mut truncated_any = false;
    let mut unscanned_total = 0usize;
    let mut fd_peak_max = 0usize;
    let mut sent_total = 0u64;
    let mut received_total = 0u64;
    let mut retries_total = 0u64;

    for (ip, parent_id) in ips.iter().zip(parent_ids.iter()) {
        if cancel.is_cancelled() {
            return Err(ModuleError::Cancelled);
        }
        // Per-derived-address scope check: discovery must never expand scope.
        if !guard.permits(&TaskScopeTarget::Ip(*ip)) {
            continue;
        }
        let remaining = task_deadline.saturating_duration_since(Instant::now());
        if remaining < Duration::from_millis(50) {
            truncated_any = true;
            unscanned_total += resolved.ports.len();
            break;
        }
        let outcome = scanner.scan(*ip, &resolved.ports, source, &scan_config);
        if outcome.cancelled || cancel.is_cancelled() {
            return Err(ModuleError::Cancelled);
        }
        truncated_any |= outcome.truncated;
        unscanned_total += outcome.unscanned;
        fd_peak_max = fd_peak_max.max(outcome.fd_peak);
        *counts.get_mut("open").unwrap() += outcome.open_count;
        *counts.get_mut("closed").unwrap() += outcome.closed_count;
        *counts.get_mut("open_or_filtered").unwrap() += outcome.filtered_count;
        *counts.get_mut("error").unwrap() += outcome.error_count;
        sent_total += outcome.datagrams_sent;
        received_total += outcome.datagrams_received;
        retries_total += outcome.retries;
        for probe in &outcome.probes {
            // Scope re-check per probed port is unnecessary (same address
            // checked above); the address itself was permitted.
            match probe.state {
                UdpPortState::Open => {
                    let family = AddressFamily::of(ip);
                    let asset_id = udp_port_asset_id(parent_id, "udp", probe.port);
                    let record = OpenUdpRecord {
                        target: target_label.clone(),
                        address: ip.to_string(),
                        address_family: family,
                        parent_asset_id: parent_id.clone(),
                        asset_id: asset_id.clone(),
                        transport: "udp".to_owned(),
                        port: probe.port,
                        state: "open".to_owned(),
                        service: probe.protocol.clone(),
                        latency_ms: probe.latency.as_millis() as u64,
                        timestamp: started_at.0,
                    };
                    assets.push(Asset {
                        schema_version: crate::model::SCHEMA_VERSION,
                        id: AssetId(asset_id.clone()),
                        kind: AssetKind::Port,
                        identity: port_asset_identity(parent_id, "udp", probe.port),
                        attributes: BTreeMap::from([
                            ("transport".to_owned(), "udp".to_owned()),
                            ("port".to_owned(), probe.port.to_string()),
                            ("state".to_owned(), "open".to_owned()),
                            ("address".to_owned(), ip.to_string()),
                            ("target".to_owned(), target_label.clone()),
                            (
                                "latency_ms".to_owned(),
                                (probe.latency.as_millis() as u64).to_string(),
                            ),
                        ]),
                        first_seen: started_at,
                        last_seen: started_at,
                        provenance: provenance.clone(),
                    });
                    let mut open_data = serde_json::json!({
                        "target": target_label,
                        "address": ip.to_string(),
                        "transport": "udp",
                        "port": probe.port,
                        "state": "open",
                        "latency_ms": probe.latency.as_millis() as u64,
                        "attempts": probe.attempts,
                    });
                    if let Some(service) = &probe.protocol {
                        open_data["service"] = serde_json::Value::String(service.clone());
                    }
                    push_event(
                        &mut events,
                        EventKind::UdpPortOpen,
                        Some(AssetId(asset_id.clone())),
                        open_data,
                        &provenance,
                    )?;
                    let confidence = Confidence::new(90).map_err(|_| ModuleError::Failed {
                        message: "invalid confidence".to_owned(),
                        retryable: false,
                    })?;
                    let details = BoundedDetails::from_value(
                        serde_json::json!({
                            "target": record.target,
                            "address": record.address,
                            "address_family": family,
                            "parent_asset_id": record.parent_asset_id,
                            "transport": record.transport,
                            "port": record.port,
                            "state": record.state,
                            "service": record.service,
                            "latency_ms": record.latency_ms,
                            "timestamp": record.timestamp,
                        }),
                        crate::model::MAX_EVIDENCE_DETAILS_BYTES,
                    )
                    .map_err(|_| ModuleError::Failed {
                        message: "evidence details too large".to_owned(),
                        retryable: false,
                    })?;
                    let evidence = Evidence::new(
                        UDP_DISCOVERY_MODULE_NAME,
                        AssetId(asset_id.clone()),
                        details,
                        confidence,
                        provenance.clone(),
                    )
                    .map_err(|_| ModuleError::Failed {
                        message: "invalid evidence".to_owned(),
                        retryable: false,
                    })?;
                    let evidence_id = evidence.id.clone();
                    evidence_items.push(evidence);
                    let mut finding = Finding::new(
                        format!("Open UDP port {}", probe.port),
                        Severity::Info,
                        confidence,
                        AssetId(asset_id),
                        provenance.clone(),
                    )
                    .map_err(|_| ModuleError::Failed {
                        message: "invalid finding".to_owned(),
                        retryable: false,
                    })?;
                    finding.evidence_ids.push(evidence_id);
                    finding.metadata.insert(
                        "transport".to_owned(),
                        serde_json::Value::String("udp".to_owned()),
                    );
                    finding
                        .metadata
                        .insert("port".to_owned(), serde_json::Value::from(probe.port));
                    finding.metadata.insert(
                        "address".to_owned(),
                        serde_json::Value::String(ip.to_string()),
                    );
                    // Grammar-matched protocol only; never invented.
                    // Unknown stays absent (human renders `-`).
                    if let Some(service) = &probe.protocol {
                        finding.metadata.insert(
                            "service".to_owned(),
                            serde_json::Value::String(service.clone()),
                        );
                    }
                    findings.push(finding);
                    open_records.push(record);
                }
                UdpPortState::Closed => {
                    if detailed {
                        push_udp_state_asset(
                            &mut assets,
                            parent_id,
                            ip,
                            &target_label,
                            probe.port,
                            "closed",
                            probe.latency,
                            started_at,
                            &provenance,
                        );
                        push_event(
                            &mut events,
                            EventKind::UdpPortClosed,
                            Some(AssetId(udp_port_asset_id(parent_id, "udp", probe.port))),
                            serde_json::json!({
                                "target": target_label,
                                "address": ip.to_string(),
                                "transport": "udp",
                                "port": probe.port,
                                "state": "closed",
                                "latency_ms": probe.latency.as_millis() as u64,
                            }),
                            &provenance,
                        )?;
                    }
                }
                UdpPortState::OpenOrFiltered => {
                    if detailed {
                        push_udp_state_asset(
                            &mut assets,
                            parent_id,
                            ip,
                            &target_label,
                            probe.port,
                            "open_or_filtered",
                            probe.latency,
                            started_at,
                            &provenance,
                        );
                        push_event(
                            &mut events,
                            EventKind::UdpPortFiltered,
                            Some(AssetId(udp_port_asset_id(parent_id, "udp", probe.port))),
                            serde_json::json!({
                                "target": target_label,
                                "address": ip.to_string(),
                                "transport": "udp",
                                "port": probe.port,
                                "state": "open_or_filtered",
                                "attempts": probe.attempts,
                            }),
                            &provenance,
                        )?;
                    }
                }
                UdpPortState::Error => {
                    if detailed {
                        push_udp_state_asset(
                            &mut assets,
                            parent_id,
                            ip,
                            &target_label,
                            probe.port,
                            "error",
                            probe.latency,
                            started_at,
                            &provenance,
                        );
                        push_event(
                            &mut events,
                            EventKind::UdpProbeError,
                            Some(AssetId(udp_port_asset_id(parent_id, "udp", probe.port))),
                            serde_json::json!({
                                "target": target_label,
                                "address": ip.to_string(),
                                "transport": "udp",
                                "port": probe.port,
                                "state": "error",
                                "detail": probe.detail,
                            }),
                            &provenance,
                        )?;
                    }
                }
            }
        }
        if cancel.is_cancelled() {
            return Err(ModuleError::Cancelled);
        }
    }

    open_records.sort_by_key(|record| (record.address.clone(), record.port));
    let elapsed_ms = start_instant.elapsed().as_millis() as u64;
    // Attempted ports: exactly the probed set, recovered from the typed
    // per-port outcome events (detailed mode). Huge scans omit per-port
    // events; there the counts + unscanned invariant proves coverage.
    let attempted_ports: Vec<u16> = {
        let mut seen = std::collections::BTreeSet::new();
        for event in events.iter().filter(|event| {
            matches!(
                event.kind,
                EventKind::UdpPortOpen | EventKind::UdpPortClosed | EventKind::UdpPortFiltered
            )
        }) {
            // Detailed mode only: huge scans omit per-port events, and
            // attempted coverage is proven by counts + unscanned instead.
            if let Some(port) = event
                .details
                .data
                .get("port")
                .and_then(serde_json::Value::as_u64)
            {
                if let Ok(port) = u16::try_from(port) {
                    seen.insert(port);
                }
            }
        }
        // UdpProbeError outcomes also count as attempted.
        for event in events
            .iter()
            .filter(|event| matches!(event.kind, EventKind::UdpProbeError))
        {
            if let Some(port) = event
                .details
                .data
                .get("port")
                .and_then(serde_json::Value::as_u64)
            {
                if let Ok(port) = u16::try_from(port) {
                    seen.insert(port);
                }
            }
        }
        seen.into_iter().collect()
    };
    let open_services: Vec<serde_json::Value> = open_records
        .iter()
        .map(|record| serde_json::json!({"port": record.port, "service": record.service}))
        .collect();
    push_event(
        &mut events,
        EventKind::UdpScanCompleted,
        None,
        serde_json::json!({
            "target": target_label,
            "port_source": resolved.source.to_string(),
            "ports_requested": resolved.ports.len(),
            "requested_ports": if detailed { Some(resolved.ports.clone()) } else { None },
            "attempted_ports": if detailed { Some(attempted_ports) } else { None },
            "counts": counts,
            "open_ports": open_records.iter().map(|record| record.port).collect::<Vec<_>>(),
            "open_services": open_services,
            "truncated": truncated_any,
            "unscanned": unscanned_total,
            "fd_peak": fd_peak_max,
            "datagrams_sent": sent_total,
            "datagrams_received": received_total,
            "retries": retries_total,
            "elapsed_ms": elapsed_ms,
        }),
        &provenance,
    )?;
    // Summary evidence anchored to the first owned asset (same rule as TCP:
    // never dangle, never collide). Without assets the completed event
    // already preserves the ledger.
    let confidence = Confidence::new(90).map_err(|_| ModuleError::Failed {
        message: "invalid confidence".to_owned(),
        retryable: false,
    })?;
    if let Some(anchor) = assets.first() {
        let summary_asset = anchor.id.clone();
        let summary_details = BoundedDetails::from_value(
            serde_json::json!({
                "target": target_label,
                "port_source": resolved.source.to_string(),
                "ports_requested": resolved.ports.len(),
                "counts": counts,
                "open": open_records,
                "truncated": truncated_any,
                "unscanned": unscanned_total,
                "fd_peak": fd_peak_max,
                "datagrams_sent": sent_total,
                "datagrams_received": received_total,
                "retries": retries_total,
                "elapsed_ms": elapsed_ms,
            }),
            crate::model::MAX_EVIDENCE_DETAILS_BYTES,
        )
        .map_err(|_| ModuleError::Failed {
            message: "evidence details too large".to_owned(),
            retryable: false,
        })?;
        evidence_items.push(
            Evidence::new(
                UDP_DISCOVERY_MODULE_NAME,
                summary_asset,
                summary_details,
                confidence,
                provenance,
            )
            .map_err(|_| ModuleError::Failed {
                message: "invalid evidence".to_owned(),
                retryable: false,
            })?,
        );
    }

    Ok(ModuleOutput {
        events,
        evidence: evidence_items,
        findings,
        assets,
    })
}

#[allow(clippy::too_many_arguments)]
fn finish_empty_scan(
    target_label: &str,
    reason: &str,
    resolved: &ResolvedPorts,
    policy: &UdpScanPolicy,
    mut events: Vec<Event>,
    provenance: &Provenance,
    start_instant: Instant,
) -> Result<ModuleOutput, ModuleError> {
    push_event(
        &mut events,
        EventKind::UdpScanCompleted,
        None,
        serde_json::json!({
            "target": target_label,
            "port_source": resolved.source.to_string(),
            "ports_requested": resolved.ports.len(),
            "counts": {"open": 0, "closed": 0, "open_or_filtered": 0, "error": 0},
            "open_ports": [],
            "open_services": [],
            "truncated": false,
            "unscanned": 0,
            "fd_peak": 0,
            "datagrams_sent": 0,
            "datagrams_received": 0,
            "retries": 0,
            "elapsed_ms": start_instant.elapsed().as_millis() as u64,
            "note": reason,
            "policy": policy.describe(),
        }),
        provenance,
    )?;
    Ok(ModuleOutput {
        events,
        evidence: Vec::new(),
        findings: Vec::new(),
        assets: Vec::new(),
    })
}

#[allow(clippy::too_many_arguments)]
fn push_udp_state_asset(
    assets: &mut Vec<Asset>,
    parent_id: &str,
    ip: &IpAddr,
    target_label: &str,
    port: u16,
    state: &str,
    latency: Duration,
    started_at: Timestamp,
    provenance: &Provenance,
) {
    let asset_id = udp_port_asset_id(parent_id, "udp", port);
    assets.push(Asset {
        schema_version: crate::model::SCHEMA_VERSION,
        id: AssetId(asset_id),
        kind: AssetKind::Port,
        identity: port_asset_identity(parent_id, "udp", port),
        attributes: BTreeMap::from([
            ("transport".to_owned(), "udp".to_owned()),
            ("port".to_owned(), port.to_string()),
            ("state".to_owned(), state.to_owned()),
            ("address".to_owned(), ip.to_string()),
            ("target".to_owned(), target_label.to_owned()),
            (
                "latency_ms".to_owned(),
                (latency.as_millis() as u64).to_string(),
            ),
        ]),
        first_seen: started_at,
        last_seen: started_at,
        provenance: provenance.clone(),
    });
}

fn push_event(
    events: &mut Vec<Event>,
    kind: EventKind,
    asset_id: Option<AssetId>,
    data: serde_json::Value,
    provenance: &Provenance,
) -> Result<(), ModuleError> {
    let details = BoundedDetails::from_value(data, MAX_EVENT_DETAILS_BYTES).map_err(|_| {
        ModuleError::Failed {
            message: "event details too large".to_owned(),
            retryable: false,
        }
    })?;
    let event = Event::new(kind, asset_id, details, provenance.clone()).map_err(|_| {
        ModuleError::Failed {
            message: "invalid event".to_owned(),
            retryable: false,
        }
    })?;
    events.push(event);
    Ok(())
}
