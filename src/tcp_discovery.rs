//! Phase 6 native TCP port-discovery scheduler module.
//!
//! Control path (never bypassed):
//! `Target -> Scope Guard -> ScanPlan -> Scheduler <-> Speed Governor /
//! Budgets / Backpressure -> TcpDiscoveryModule (bounded internal scan) ->
//! Typed Events / Evidence / Assets / Findings -> Decision Engine boundary
//! -> JSONL Output`.
//!
//! The module emits facts only. It never schedules `ServiceProbe`/HTTP/SSH
//! tasks; only the Decision Engine may propose follow-ups, admitted via
//! Scope Guard, policy, budget, and scheduler checks.
//!
//! Task representation is bounded: ONE `PortDiscovery` scheduler task per
//! target carries the full port selection in deterministic `params`
//! (`ports=common|explicit|all`, never 65k tasks). The module scans the
//! resolved list internally with a strictly bounded non-blocking window
//! (see `tcp_scanner.rs`), sorted output, and truncated per-port detail for
//! huge scans so JSONL stays meaningful.

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
use crate::ports::{PortSource, ResolvedPorts, resolve_ports, tcp_concurrency_for_speed};
use crate::tcp_scanner::{NativeTcpScanner, PortScanner, PortState, ScanConfig};

pub const TCP_DISCOVERY_MODULE_NAME: &str = "rxscan.port";
pub const TCP_DISCOVERY_MODULE_VERSION: &str = "6.0.0";

/// Per-port events flood JSONL on huge scans; emit per-port outcome events
/// only up to this many ports, otherwise opens + summary.
pub const MAX_DETAILED_PORT_EVENTS: usize = 256;

/// Max IPs scanned per hostname task (scope-filtered, deterministic).
pub const MAX_IPS_PER_PORT_TASK: usize = 4;

/// Centralized Phase 6 TCP policy template (level breadth + speed pressure).
#[derive(Debug, Clone)]
pub struct TcpScanPolicy {
    pub level: u8,
    pub goal: ScanGoal,
    pub selection: TcpPortSelection,
    pub speed: SpeedSetting,
}

impl TcpScanPolicy {
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
    /// otherwise the plan-level selection resolved against this policy level.
    /// Always sorted, deduped, port 0 excluded.
    pub fn ports_for_task(&self, task_ports_param: Option<&str>) -> ResolvedPorts {
        if let Some(param) = task_ports_param {
            if param == "all" {
                return ResolvedPorts {
                    ports: (1..=65_535).collect(),
                    source: PortSource::All,
                };
            }
            if let Some(rest) = param.strip_prefix("explicit:") {
                let mut ports: Vec<u16> = rest
                    .split(',')
                    .filter_map(|item| item.trim().parse::<u16>().ok())
                    .filter(|port| *port > 0)
                    .collect();
                ports.sort_unstable();
                ports.dedup();
                // `port_count` param guards truncation collisions in IDs, but
                // the module scans the rendered prefix only when the full list
                // was truncated at lowering (documented limitation for giant
                // explicit lists; `--all-ports` is the canonical huge scan).
                return ResolvedPorts {
                    ports,
                    source: PortSource::Explicit,
                };
            }
            if param == "common" {
                return resolve_ports(&TcpPortSelection::Common, self.level);
            }
        }
        resolve_ports(&self.selection, self.level)
    }

    pub fn per_port_timeout(&self) -> Duration {
        crate::ports::tcp_timeout_for_speed(self.speed)
    }

    pub fn concurrency(&self) -> usize {
        tcp_concurrency_for_speed(self.speed)
    }

    /// Bounded retries: filtered/timeout gets one retry when the speed
    /// policy allows ≥2 attempts; refused/open/error never retry.
    pub fn max_retries(&self) -> u32 {
        let retry_limit = crate::execution::SpeedGovernor::new(self.speed, 4)
            .map(|governor| governor.retry_limit())
            .unwrap_or(2);
        u32::from(retry_limit >= 2).min(1)
    }

    pub fn describe(&self) -> String {
        let resolved = resolve_ports(&self.selection, self.level);
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
            "tcp {} level {} ({:?}): {} [{}], timeout {}ms, concurrency {}, retries {}",
            resolved.source,
            self.level,
            self.goal,
            preview,
            crate::ports::COMMON_PROFILE_VERSION,
            self.per_port_timeout().as_millis(),
            self.concurrency(),
            self.max_retries(),
        )
    }
}

/// One open port preserved as evidence/JSONL.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenPortRecord {
    pub target: String,
    pub address: String,
    pub address_family: AddressFamily,
    pub parent_asset_id: String,
    pub asset_id: String,
    pub transport: String,
    pub port: u16,
    pub state: String,
    pub latency_ms: u64,
    pub evidence: String,
    pub timestamp: u64,
}

/// Stable FNV-1a helpers mirroring Phase 5 asset-ID stability.
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

/// Stable child port-asset ID: parent + protocol + port. Never collides
/// across parents (`10.0.0.1:80` vs `10.0.0.2:80`) or protocols
/// (`tcp/80` vs future `udp/80`).
pub fn port_asset_id(parent_asset_id: &str, transport: &str, port: u16) -> String {
    format!(
        "asset_port_{}",
        fnv_hex(&format!("port:{parent_asset_id}:{transport}/{port}"))
    )
}

fn port_asset_identity(parent_asset_id: &str, transport: &str, port: u16) -> String {
    format!("{parent_asset_id}:{transport}/{port}")
}

/// Real scheduler module for `TaskKind::PortDiscovery`.
pub struct TcpDiscoveryModule {
    policy: TcpScanPolicy,
    scanner: Arc<dyn PortScanner>,
    scope_guard: Arc<dyn ScopeGuard>,
}

impl TcpDiscoveryModule {
    pub fn new(policy: TcpScanPolicy, scope_guard: Arc<dyn ScopeGuard>) -> Self {
        Self {
            policy,
            scanner: Arc::new(NativeTcpScanner),
            scope_guard,
        }
    }

    pub fn with_scanner(
        policy: TcpScanPolicy,
        scanner: Arc<dyn PortScanner>,
        scope_guard: Arc<dyn ScopeGuard>,
    ) -> Self {
        Self {
            policy,
            scanner,
            scope_guard,
        }
    }

    pub fn policy(&self) -> &TcpScanPolicy {
        &self.policy
    }
}

impl Module for TcpDiscoveryModule {
    fn kind(&self) -> TaskKind {
        TaskKind::PortDiscovery
    }

    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let policy = self.policy.clone();
        let scanner = self.scanner.clone();
        let guard = self.scope_guard.clone();
        Box::pin(
            async move { execute_port_scan(&policy, scanner.as_ref(), guard.as_ref(), context) },
        )
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
                        .take(MAX_IPS_PER_PORT_TASK)
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
fn execute_port_scan(
    policy: &TcpScanPolicy,
    scanner: &dyn PortScanner,
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
        TCP_DISCOVERY_MODULE_NAME,
        TCP_DISCOVERY_MODULE_VERSION,
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
    let mut findings: Vec<crate::model::Finding> = Vec::new();

    // Resolve ports BEFORE candidates so invalid selection fails fast.
    let ports_param = task.params.get("ports").map(String::as_str);
    let resolved = policy.ports_for_task(ports_param);
    // `explicit:` params only carry a rendered prefix for giant lists; the
    // full count rides in `port_count`. Scanning the prefix alone would
    // silently under-scan, so refuse giant explicit renders and direct the
    // operator to `--all-ports` (canonical huge scan).
    if task
        .params
        .get("ports")
        .is_some_and(|value| value.contains("...(+"))
    {
        return Err(ModuleError::Failed {
            message: "explicit port list truncated in task params; use --all-ports for huge scans"
                .to_owned(),
            retryable: false,
        });
    }

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
                &task,
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
        EventKind::PortScanStarted,
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

    let scan_config = ScanConfig::bounded(
        policy.per_port_timeout(),
        policy.concurrency(),
        policy.max_retries(),
        Some(task_deadline),
        cancel.clone(),
    );
    let detailed = resolved.ports.len() <= MAX_DETAILED_PORT_EVENTS;
    let mut open_records: Vec<OpenPortRecord> = Vec::new();
    let mut counts = BTreeMap::from([
        ("open", 0u64),
        ("closed", 0u64),
        ("filtered_or_timed_out", 0u64),
        ("error", 0u64),
    ]);
    let mut first_open_ms: Option<u64> = None;
    let mut truncated_any = false;
    let mut unscanned_total = 0usize;

    for (ip, parent_id) in ips.iter().zip(parent_ids.iter()) {
        if cancel.is_cancelled() {
            return Err(ModuleError::Cancelled);
        }
        if !guard.permits(&TaskScopeTarget::Ip(*ip)) {
            continue;
        }
        let remaining = task_deadline.saturating_duration_since(Instant::now());
        if remaining < Duration::from_millis(50) {
            truncated_any = true;
            unscanned_total += resolved.ports.len();
            break;
        }
        let outcome = scanner.scan(*ip, &resolved.ports, &scan_config);
        if outcome.cancelled || cancel.is_cancelled() {
            return Err(ModuleError::Cancelled);
        }
        truncated_any |= outcome.truncated;
        unscanned_total += outcome.unscanned;
        for probe in &outcome.probes {
            match probe.state {
                PortState::Open => {
                    *counts.get_mut("open").unwrap() += 1;
                    if first_open_ms.is_none() {
                        first_open_ms = Some(start_instant.elapsed().as_millis() as u64);
                    }
                    let family = AddressFamily::of(ip);
                    let asset_id = port_asset_id(parent_id, "tcp", probe.port);
                    let record = OpenPortRecord {
                        target: target_label.clone(),
                        address: ip.to_string(),
                        address_family: family,
                        parent_asset_id: parent_id.clone(),
                        asset_id: asset_id.clone(),
                        transport: "tcp".to_owned(),
                        port: probe.port,
                        state: "open".to_owned(),
                        latency_ms: probe.latency.as_millis() as u64,
                        evidence: probe.detail.clone(),
                        timestamp: started_at.0,
                    };
                    // Port asset (stable child identity incl. proto).
                    assets.push(Asset {
                        schema_version: crate::model::SCHEMA_VERSION,
                        id: AssetId(asset_id.clone()),
                        kind: AssetKind::Port,
                        identity: port_asset_identity(parent_id, "tcp", probe.port),
                        attributes: BTreeMap::from([
                            ("transport".to_owned(), "tcp".to_owned()),
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
                    push_event(
                        &mut events,
                        EventKind::PortOpen,
                        Some(AssetId(asset_id.clone())),
                        serde_json::json!({
                            "target": target_label,
                            "address": ip.to_string(),
                            "transport": "tcp",
                            "port": probe.port,
                            "state": "open",
                            "latency_ms": probe.latency.as_millis() as u64,
                            "attempts": probe.attempts,
                        }),
                        &provenance,
                    )?;
                    // Evidence + Finding per open port (closed/filtered stay
                    // in the summary to avoid giant output files).
                    let confidence = Confidence::new(95).map_err(|_| ModuleError::Failed {
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
                            "latency_ms": record.latency_ms,
                            "evidence": record.evidence,
                            "timestamp": record.timestamp,
                        }),
                        crate::model::MAX_EVIDENCE_DETAILS_BYTES,
                    )
                    .map_err(|_| ModuleError::Failed {
                        message: "evidence details too large".to_owned(),
                        retryable: false,
                    })?;
                    let evidence = Evidence::new(
                        TCP_DISCOVERY_MODULE_NAME,
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
                        format!("Open TCP port {}", probe.port),
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
                        serde_json::Value::String("tcp".to_owned()),
                    );
                    finding
                        .metadata
                        .insert("port".to_owned(), serde_json::Value::from(probe.port));
                    finding.metadata.insert(
                        "address".to_owned(),
                        serde_json::Value::String(ip.to_string()),
                    );
                    findings.push(finding);
                    open_records.push(record);
                }
                PortState::Closed => {
                    *counts.get_mut("closed").unwrap() += 1;
                    if detailed {
                        push_port_state_asset(
                            &mut assets,
                            parent_id,
                            ip,
                            &target_label,
                            probe,
                            "closed",
                            started_at,
                            &provenance,
                        );
                        push_event(
                            &mut events,
                            EventKind::PortClosed,
                            Some(AssetId(port_asset_id(parent_id, "tcp", probe.port))),
                            serde_json::json!({
                                "target": target_label,
                                "address": ip.to_string(),
                                "transport": "tcp",
                                "port": probe.port,
                                "state": "closed",
                                "latency_ms": probe.latency.as_millis() as u64,
                            }),
                            &provenance,
                        )?;
                    }
                }
                PortState::FilteredOrTimedOut => {
                    *counts.get_mut("filtered_or_timed_out").unwrap() += 1;
                    if detailed {
                        push_port_state_asset(
                            &mut assets,
                            parent_id,
                            ip,
                            &target_label,
                            probe,
                            "filtered_or_timed_out",
                            started_at,
                            &provenance,
                        );
                        push_event(
                            &mut events,
                            EventKind::PortTimedOut,
                            Some(AssetId(port_asset_id(parent_id, "tcp", probe.port))),
                            serde_json::json!({
                                "target": target_label,
                                "address": ip.to_string(),
                                "transport": "tcp",
                                "port": probe.port,
                                "state": "filtered_or_timed_out",
                                "attempts": probe.attempts,
                            }),
                            &provenance,
                        )?;
                    }
                }
                PortState::Error => {
                    *counts.get_mut("error").unwrap() += 1;
                    if detailed {
                        push_port_state_asset(
                            &mut assets,
                            parent_id,
                            ip,
                            &target_label,
                            probe,
                            "error",
                            started_at,
                            &provenance,
                        );
                        push_event(
                            &mut events,
                            EventKind::PortProbeError,
                            Some(AssetId(port_asset_id(parent_id, "tcp", probe.port))),
                            serde_json::json!({
                                "target": target_label,
                                "address": ip.to_string(),
                                "transport": "tcp",
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
    push_event(
        &mut events,
        EventKind::PortScanCompleted,
        None,
        serde_json::json!({
            "target": target_label,
            "port_source": resolved.source.to_string(),
            "ports_requested": resolved.ports.len(),
            "counts": counts,
            "open_ports": open_records.iter().map(|record| record.port).collect::<Vec<_>>(),
            "truncated": truncated_any,
            "unscanned": unscanned_total,
            "elapsed_ms": elapsed_ms,
            "time_to_first_open_ms": first_open_ms,
        }),
        &provenance,
    )?;
    // Summary evidence (always when an anchor exists) so JSONL preserves
    // counts even when per-port detail was truncated for huge scans.
    //
    // Phase 20: the anchor must be an asset this output owns. Anchoring to
    // the parent host asset dangled whenever no host asset existed anywhere
    // (e.g. level-1 port-only scans: `--checkpoint` then failed validation
    // on the scan's own state), and emitting the parent here would collide
    // with the host module's copy. The first port asset is deterministic
    // (outputs are port-ordered); when the output holds no assets at all
    // the evidence is skipped because the always-emitted PortScanCompleted
    // event already preserves counts/open_ports/truncated/unscanned.
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
                TCP_DISCOVERY_MODULE_NAME,
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
    policy: &TcpScanPolicy,
    mut events: Vec<Event>,
    provenance: &Provenance,
    _task: &crate::execution::Task,
    start_instant: Instant,
) -> Result<ModuleOutput, ModuleError> {
    push_event(
        &mut events,
        EventKind::PortScanCompleted,
        None,
        serde_json::json!({
            "target": target_label,
            "port_source": resolved.source.to_string(),
            "ports_requested": resolved.ports.len(),
            "counts": {"open": 0, "closed": 0, "filtered_or_timed_out": 0, "error": 0},
            "open_ports": [],
            "truncated": false,
            "unscanned": 0,
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

/// Phase 20: typed Port asset for a detailed non-open observation.
///
/// Detailed closed/filtered/error events carry this asset's stable ID, so
/// the asset must exist: checkpoint validation (and the JSONL asset model)
/// requires every event `asset_id` to resolve. Bounded by the same
/// `detailed` gate as the events (ports <= 256), with no evidence or
/// findings — repetitive negative results stay compact by design.
#[allow(clippy::too_many_arguments)]
fn push_port_state_asset(
    assets: &mut Vec<Asset>,
    parent_id: &str,
    ip: &IpAddr,
    target_label: &str,
    probe: &crate::tcp_scanner::PortProbe,
    state: &str,
    started_at: Timestamp,
    provenance: &Provenance,
) {
    let asset_id = port_asset_id(parent_id, "tcp", probe.port);
    assets.push(Asset {
        schema_version: crate::model::SCHEMA_VERSION,
        id: AssetId(asset_id),
        kind: AssetKind::Port,
        identity: port_asset_identity(parent_id, "tcp", probe.port),
        attributes: BTreeMap::from([
            ("transport".to_owned(), "tcp".to_owned()),
            ("port".to_owned(), probe.port.to_string()),
            ("state".to_owned(), state.to_owned()),
            ("address".to_owned(), ip.to_string()),
            ("target".to_owned(), target_label.to_owned()),
            (
                "latency_ms".to_owned(),
                (probe.latency.as_millis() as u64).to_string(),
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

/// Human open-port summary across module outputs (prioritizes opens).
pub fn human_open_ports_summary(
    module_outputs: &[(crate::execution::TaskId, ModuleOutput)],
) -> String {
    let mut opens: Vec<(String, u16)> = Vec::new();
    for (_, output) in module_outputs {
        for finding in &output.findings {
            if finding.title.starts_with("Open TCP port") {
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
                if port > 0 {
                    opens.push((address, port));
                }
            }
        }
    }
    if opens.is_empty() {
        return "No open TCP ports observed.".to_owned();
    }
    opens.sort();
    opens.dedup();
    // Group by host for the table.
    let mut by_host: BTreeMap<String, Vec<u16>> = BTreeMap::new();
    for (host, port) in opens {
        by_host.entry(host).or_default().push(port);
    }
    let mut lines = Vec::new();
    for (host, mut ports) in by_host {
        ports.sort_unstable();
        lines.push(format!("HOST {host}"));
        lines.push("PORT      STATE".to_owned());
        for port in ports {
            lines.push(format!("{port}/tcp    open"));
        }
    }
    lines.join("\n")
}
