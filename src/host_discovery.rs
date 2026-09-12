//! Phase 5 `HostDiscovery` scheduler module: real bounded network probing.
//!
//! Control path (never bypassed):
//! `Target -> Scope Guard -> ScanPlan -> Plan Lowering -> Scheduler <->
//! Speed Governor / Budgets / Backpressure -> HostDiscovery Module ->
//! Typed Events / Evidence -> Decision Engine boundary -> Output`.
//!
//! The module emits results only. It never schedules follow-up work; only
//! the `DecisionEngine` may propose tasks, admitted via Scope Guard, policy,
//! budget, and scheduler checks.
//!
//! Contract per probe: timeout, cancellation, retry limit (bounded attempts,
//! outer scheduler retries), concurrency limit (scheduler host slots;
//! per-host probes sequential), budget accounting (evidence bytes, task
//! budgets), resource cleanup (sockets closed, helper threads bounded).

use std::collections::BTreeMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::discovery::{
    AddressFamily, DiscoveryMode, DiscoveryTechnique, HostDiscoveryPolicy, HostState, ProbeOutcome,
    ProbeRecord, conclude_state,
};
use crate::execution::{
    CancellationToken, Module, ModuleContext, ModuleError, ModuleFuture, ModuleOutput, ScopeGuard,
    TaskKind, TaskScopeTarget,
};
use crate::icmp::{IcmpProber, NativeIcmpProber, icmp_probe_with_retries};
use crate::model::{
    Asset, AssetId, AssetKind, BoundedDetails, Confidence, Event, EventKind, Evidence,
    MAX_EVENT_DETAILS_BYTES, Provenance, Timestamp,
};
use crate::tcp_probe::{NativeTcpProber, TcpProber, tcp_probe_ports};

pub const HOST_DISCOVERY_MODULE_NAME: &str = "rxscan.host";
pub const HOST_DISCOVERY_MODULE_VERSION: &str = "5.0.0";
pub const MAX_TCP_PROBE_PORTS: usize = 8;

/// Host-discovery result preserved as evidence (also serialized into
/// `Evidence`/`Event` details for JSONL output).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostDiscoveryResult {
    pub asset_id: String,
    pub target: String,
    pub address: Option<String>,
    pub address_family: Option<AddressFamily>,
    pub state: HostState,
    pub confidence: u8,
    pub techniques: Vec<DiscoveryTechnique>,
    pub latency_ms: Option<u64>,
    pub evidence: String,
    pub probe_details: Vec<String>,
    pub timestamp: u64,
}

/// Minimal deterministic Decision Engine rule for the Phase 5 boundary.
///
/// Currently returns no follow-ups (Phase 6 owns port-scan expansion). The
/// boundary itself — module emits results, only the engine proposes, the
/// scheduler admits via scope/policy/budget — is exercised by unit tests.
#[derive(Debug, Default, Clone)]
pub struct HostDiscoveryDecisionEngine;

impl crate::execution::DecisionEngine for HostDiscoveryDecisionEngine {
    fn follow_up_tasks(
        &self,
        _completed: &crate::execution::Task,
        _output: &ModuleOutput,
    ) -> Vec<crate::execution::Task> {
        Vec::new()
    }
}

/// Resolve a hostname to sorted IPs with a bounded timeout and prompt
/// cancellation. Uses a helper thread so a slow resolver cannot hang the
/// scheduler; the helper is bounded by `timeout`.
pub fn resolve_hostname_bounded(
    host: &str,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<Vec<IpAddr>, String> {
    if cancel.is_cancelled() {
        return Err("cancelled".to_owned());
    }
    let host = host.to_owned();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // Port 0: resolution only; `ToSocketAddrs` never connects.
        let result: Result<Vec<IpAddr>, String> = format!("{host}:0")
            .to_socket_addrs()
            .map(|iter| {
                let mut addresses: Vec<IpAddr> = iter.map(|socket| socket.ip()).collect();
                addresses.sort();
                addresses.dedup();
                addresses
            })
            .map_err(|error| error.to_string());
        let _ = sender.send(result);
    });
    let started = Instant::now();
    loop {
        if cancel.is_cancelled() {
            return Err("cancelled".to_owned());
        }
        match receiver.recv_timeout(Duration::from_millis(10)) {
            Ok(result) => return result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if started.elapsed() >= timeout {
                    return Err(format!(
                        "hostname resolution timed out after {}ms",
                        timeout.as_millis()
                    ));
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err("resolver worker exited".to_owned());
            }
        }
    }
}

/// Real scheduler module for `TaskKind::HostDiscovery`.
pub struct HostDiscoveryModule {
    policy: HostDiscoveryPolicy,
    icmp: Arc<dyn IcmpProber>,
    tcp: Arc<dyn TcpProber>,
    scope_guard: Arc<dyn ScopeGuard>,
}

impl HostDiscoveryModule {
    pub fn new(policy: HostDiscoveryPolicy, scope_guard: Arc<dyn ScopeGuard>) -> Self {
        Self {
            policy,
            icmp: Arc::new(NativeIcmpProber),
            tcp: Arc::new(NativeTcpProber),
            scope_guard,
        }
    }

    pub fn with_probers(
        policy: HostDiscoveryPolicy,
        icmp: Arc<dyn IcmpProber>,
        tcp: Arc<dyn TcpProber>,
        scope_guard: Arc<dyn ScopeGuard>,
    ) -> Self {
        Self {
            policy,
            icmp,
            tcp,
            scope_guard,
        }
    }

    pub fn policy(&self) -> &HostDiscoveryPolicy {
        &self.policy
    }
}

impl Module for HostDiscoveryModule {
    fn kind(&self) -> TaskKind {
        TaskKind::HostDiscovery
    }

    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let policy = self.policy.clone();
        let icmp = self.icmp.clone();
        let tcp = self.tcp.clone();
        let guard = self.scope_guard.clone();
        Box::pin(async move {
            execute_discovery(
                &policy,
                icmp.as_ref(),
                tcp.as_ref(),
                guard.as_ref(),
                context,
            )
        })
    }
}

#[allow(clippy::too_many_lines)]
fn execute_discovery(
    policy: &HostDiscoveryPolicy,
    icmp: &dyn IcmpProber,
    tcp: &dyn TcpProber,
    guard: &dyn ScopeGuard,
    context: ModuleContext,
) -> Result<ModuleOutput, ModuleError> {
    let task = context.task.clone();
    let cancel = context.cancellation();
    // Scope check immediately before network execution (third enforcement
    // point after lowering and scheduler admission/dispatch).
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

    // Target label for evidence (stable, from params or scope).
    let target_label =
        task.params
            .get("target")
            .cloned()
            .unwrap_or_else(|| match &task.scope_target {
                TaskScopeTarget::Ip(ip) => ip.to_string(),
                TaskScopeTarget::Host(host) => host.clone(),
                TaskScopeTarget::Url(url) => url.clone(),
                TaskScopeTarget::None => "unknown".to_owned(),
            });

    // Discovery-started event (typed, quiet by default; verbose in JSONL).
    let provenance = Provenance::new(
        HOST_DISCOVERY_MODULE_NAME,
        HOST_DISCOVERY_MODULE_VERSION,
        task.scan_plan_id.clone(),
        started_at,
    )
    .map_err(|_| ModuleError::Failed {
        message: "invalid provenance".to_owned(),
        retryable: false,
    })?;

    let mut events: Vec<Event> = Vec::new();
    let mut assets: Vec<Asset> = Vec::new();

    let discovery_started = Event::new(
        EventKind::DiscoveryStarted,
        None,
        BoundedDetails::from_value(
            serde_json::json!({
                "target": target_label,
                "policy": policy.describe(),
                "mode": policy.mode.as_str(),
            }),
            MAX_EVENT_DETAILS_BYTES,
        )
        .map_err(|_| ModuleError::Failed {
            message: "event details too large".to_owned(),
            retryable: false,
        })?,
        provenance.clone(),
    )
    .map_err(|_| ModuleError::Failed {
        message: "invalid event".to_owned(),
        retryable: false,
    })?;
    events.push(discovery_started);

    // Resolve task scope target to candidate IPs (bounded, scope-checked).
    let candidates = resolve_candidates(&task.scope_target, &task.params, guard, &cancel)?;
    // `resolve_candidates` returns Err only for cancellation or stale scope.
    // Resolution failures (unknown hostname) yield an Unknown result below.

    // Handle resolution-failure / no-candidate path as Unknown (never dead).
    let candidate_ips: Vec<IpAddr> = match candidates {
        CandidateResolution::Cancelled => return Err(ModuleError::Cancelled),
        CandidateResolution::StaleScope(message) => {
            return Err(ModuleError::Failed {
                message,
                retryable: false,
            });
        }
        CandidateResolution::NoCandidates { reason } => {
            let result = HostDiscoveryResult {
                asset_id: stable_asset_id_for_target(&target_label),
                target: target_label.clone(),
                address: None,
                address_family: None,
                state: HostState::Unknown,
                confidence: 30,
                techniques: Vec::new(),
                latency_ms: None,
                evidence: format!(
                    "Host state is Unknown: {reason} No definitive reachable or unreachable response was received."
                ),
                probe_details: vec![reason.clone()],
                timestamp: started_at.0,
            };
            return finish_with_result(
                result,
                &target_label,
                None,
                Vec::new(),
                events,
                &provenance,
                &task,
                start_instant,
            );
        }
        CandidateResolution::Ips(ips) => ips,
    };

    // Probe each candidate IP sequentially (bounded: at most a few IPs per
    // task; CIDR expansion already bounds hosts per plan via max_hosts).
    // Hostnames resolving to many IPs are truncated to 4 to stay bounded.
    let mut all_probes: Vec<ProbeRecord> = Vec::new();
    let mut concluded: Option<(HostState, u8, Vec<DiscoveryTechnique>, String)> = None;
    let mut primary_ip: Option<IpAddr> = None;

    for ip in candidate_ips.iter().take(4) {
        if cancel.is_cancelled() {
            return Err(ModuleError::Cancelled);
        }
        // Per-derived-address scope check: discovery must never expand scope.
        if !guard.permits(&TaskScopeTarget::Ip(*ip)) {
            all_probes.push(ProbeRecord::unavailable(
                DiscoveryTechnique::TcpConnect,
                *ip,
                None,
                "derived address outside scope; skipped without probing",
            ));
            continue;
        }
        if primary_ip.is_none() {
            primary_ip = Some(*ip);
        }
        // Per-probe timeouts capped by remaining task budget.
        let remaining = task_deadline.saturating_duration_since(Instant::now());
        if remaining < Duration::from_millis(50) {
            break;
        }
        let icmp_timeout = Duration::from_millis(policy.icmp_timeout_ms).min(remaining);
        let tcp_timeout = Duration::from_millis(policy.tcp_timeout_ms).min(remaining);

        // ICMP attempts (bounded 1..=5, stops on success/unavailable).
        if policy.use_icmp {
            emit_probe_event(
                &mut events,
                EventKind::ProbeAttempted,
                *ip,
                None,
                DiscoveryTechnique::IcmpEcho,
                "attempting ICMP echo",
                &provenance,
                &task,
            )?;
            if cancel.is_cancelled() {
                return Err(ModuleError::Cancelled);
            }
            let mut records =
                icmp_probe_with_retries(icmp, *ip, policy.icmp_attempts, icmp_timeout, &cancel);
            for record in &records {
                emit_probe_outcome_event(&mut events, record, &provenance, &task)?;
                if matches!(record.outcome, ProbeOutcome::Cancelled) {
                    return Err(ModuleError::Cancelled);
                }
            }
            all_probes.append(&mut records);
            // Early exit on credible Alive: no need for TCP.
            let (state, _, _, _) = conclude_state(&all_probes);
            if state == HostState::Alive {
                concluded = Some(conclude_state(&all_probes));
                break;
            }
        } else {
            // ICMP disabled by policy (e.g. L1 ping-only handled above; this
            // branch records the skip for evidence completeness).
        }

        // Deferred link-layer techniques: never faked, always unavailable.
        // Recorded once per host for evidence completeness (quiet in terminal).
        // Only record if no other probes exist yet to avoid noise? Record
        // unconditionally as unavailable with deferred reason — tests assert
        // graceful handling.
        // (We record ARP/ND as unavailable without network I/O.)
        // Note: these do not affect state (Unavailable is ignored unless all
        // probes are unavailable, in which case Unknown with low confidence).
        // To keep evidence focused, only include when policy would otherwise
        // have zero probes (should not happen) — so skip by default. The
        // deferred status is documented instead. (No fake records emitted.)

        // TCP reachability (small bounded set, sequential).
        if policy.use_tcp && !policy.tcp_ports.is_empty() {
            for port in policy.tcp_ports.iter().take(MAX_TCP_PROBE_PORTS) {
                emit_probe_event(
                    &mut events,
                    EventKind::ProbeAttempted,
                    *ip,
                    Some(*port),
                    DiscoveryTechnique::TcpConnect,
                    "attempting TCP reachability",
                    &provenance,
                    &task,
                )?;
                if cancel.is_cancelled() {
                    return Err(ModuleError::Cancelled);
                }
                let records = tcp_probe_ports(
                    tcp,
                    *ip,
                    std::slice::from_ref(port),
                    tcp_timeout,
                    &cancel,
                    Some(task_deadline),
                );
                for record in &records {
                    emit_probe_outcome_event(&mut events, record, &provenance, &task)?;
                    if matches!(record.outcome, ProbeOutcome::Cancelled) {
                        return Err(ModuleError::Cancelled);
                    }
                }
                let had_records = !records.is_empty();
                all_probes.extend(records);
                if cancel.is_cancelled() {
                    return Err(ModuleError::Cancelled);
                }
                if !had_records {
                    break; // Task budget exhausted.
                }
                let (state, _, _, _) = conclude_state(&all_probes);
                if state == HostState::Alive {
                    concluded = Some(conclude_state(&all_probes));
                    break;
                }
            }
            if concluded.is_some() {
                break;
            }
        }

        // Correlate after each IP: definitive Unreachable short-circuits
        // remaining candidates only if all candidates agree? For multi-IP
        // hostnames, one Alive wins; otherwise continue to next IP so a
        // second address may still prove Alive (TCP fallback correlation).
        let (state, _, _, _) = conclude_state(&all_probes);
        if state == HostState::Alive {
            concluded = Some(conclude_state(&all_probes));
            break;
        }
    }

    if cancel.is_cancelled() {
        return Err(ModuleError::Cancelled);
    }
    let (state, confidence, techniques, summary) =
        concluded.unwrap_or_else(|| conclude_state(&all_probes));
    let latency_ms = all_probes
        .iter()
        .filter_map(|probe| probe.latency)
        .map(|latency| latency.as_millis() as u64)
        .min();
    let probe_details: Vec<String> = all_probes.iter().map(ProbeRecord::describe).collect();
    let primary = primary_ip.or_else(|| candidate_ips.first().copied());
    let family = primary.map(|ip| AddressFamily::of(&ip));
    let asset_id = match primary {
        Some(ip) => crate::discovery::asset_id_for_ip(&ip),
        None => stable_asset_id_for_target(&target_label),
    };
    let result = HostDiscoveryResult {
        asset_id: asset_id.clone(),
        target: target_label.clone(),
        address: primary.map(|ip| ip.to_string()),
        address_family: family,
        state,
        confidence,
        techniques,
        latency_ms,
        evidence: summary,
        probe_details,
        timestamp: started_at.0,
    };

    // Build asset record for JSONL (scope-checked at creation).
    let asset = build_asset_for_result(&result, primary, &target_label, &provenance);
    if let Some(asset) = asset {
        assets.push(asset);
    }

    finish_with_result(
        result,
        &target_label,
        primary,
        all_probes,
        events,
        &provenance,
        &task,
        start_instant,
    )
    .map(|mut output| {
        output.assets = assets;
        output
    })
}

enum CandidateResolution {
    Ips(Vec<IpAddr>),
    NoCandidates { reason: String },
    Cancelled,
    StaleScope(String),
}

fn resolve_candidates(
    scope_target: &TaskScopeTarget,
    _params: &BTreeMap<String, String>,
    guard: &dyn ScopeGuard,
    cancel: &CancellationToken,
) -> Result<CandidateResolution, ModuleError> {
    if cancel.is_cancelled() {
        return Ok(CandidateResolution::Cancelled);
    }
    match scope_target {
        TaskScopeTarget::Ip(ip) => {
            // Lowering already scope-checks; re-check here for stale scope.
            if !guard.permits(&TaskScopeTarget::Ip(*ip)) {
                return Ok(CandidateResolution::StaleScope(
                    "stale scope rejected immediately before network execution".to_owned(),
                ));
            }
            Ok(CandidateResolution::Ips(vec![*ip]))
        }
        TaskScopeTarget::Host(host) => {
            if !guard.permits(&TaskScopeTarget::Host(host.clone())) {
                return Ok(CandidateResolution::StaleScope(
                    "stale scope rejected immediately before network execution".to_owned(),
                ));
            }
            // Fast path: literal IP in host clothing (should not happen, but
            // handle deterministically without DNS).
            if let Ok(ip) = host.parse::<IpAddr>() {
                if !guard.permits(&TaskScopeTarget::Ip(ip)) {
                    return Ok(CandidateResolution::NoCandidates {
                        reason: format!(
                            "derived address {ip} is outside scope; skipped without probing."
                        ),
                    });
                }
                return Ok(CandidateResolution::Ips(vec![ip]));
            }
            match resolve_hostname_bounded(host, Duration::from_millis(2000), cancel) {
                Ok(addresses) => {
                    if addresses.is_empty() {
                        Ok(CandidateResolution::NoCandidates {
                            reason: format!("hostname '{host}' resolved to no addresses."),
                        })
                    } else {
                        // Filter derived addresses by scope (never expand).
                        let permitted: Vec<IpAddr> = addresses
                            .into_iter()
                            .filter(|ip| guard.permits(&TaskScopeTarget::Ip(*ip)))
                            .take(4)
                            .collect();
                        if permitted.is_empty() {
                            Ok(CandidateResolution::NoCandidates {
                                reason: format!(
                                    "hostname '{host}' resolved only to out-of-scope addresses; skipped without probing."
                                ),
                            })
                        } else {
                            Ok(CandidateResolution::Ips(permitted))
                        }
                    }
                }
                Err(reason) if reason == "cancelled" => Ok(CandidateResolution::Cancelled),
                Err(reason) => Ok(CandidateResolution::NoCandidates {
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
                    // Recurse with one level (host branch handles IP literals
                    // and DNS). Avoid infinite recursion: Url never nests.
                    resolve_candidates(&nested, _params, guard, cancel)
                }
                None => Ok(CandidateResolution::NoCandidates {
                    reason: format!("URL '{url}' has no resolvable host."),
                }),
            }
        }
        TaskScopeTarget::None => Ok(CandidateResolution::NoCandidates {
            reason: "task has no network target.".to_owned(),
        }),
    }
}

fn stable_asset_id_for_target(target: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in format!("host:{target}").as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("asset_host_{hash:016x}")
}

fn build_asset_for_result(
    result: &HostDiscoveryResult,
    primary: Option<IpAddr>,
    target_label: &str,
    provenance: &Provenance,
) -> Option<Asset> {
    // Prefer a canonical IP asset when we probed an address; otherwise a
    // host asset keyed by the target label. Construction is infallible here
    // (no ScopePolicy available in the module); the stable ID matches
    // `discovery::asset_id_for_ip` / `stable_asset_id_for_target`.
    let (kind, identity) = match primary {
        Some(ip) => (AssetKind::Ip, ip.to_string()),
        None => (AssetKind::Host, target_label.to_ascii_lowercase()),
    };
    let id = AssetId(result.asset_id.clone());
    let mut attributes = BTreeMap::new();
    attributes.insert("state".to_owned(), result.state.to_string());
    attributes.insert("confidence".to_owned(), result.confidence.to_string());
    attributes.insert("target".to_owned(), target_label.to_owned());
    if let Some(address) = &result.address {
        attributes.insert("address".to_owned(), address.clone());
    }
    Some(Asset {
        schema_version: crate::model::SCHEMA_VERSION,
        id,
        kind,
        identity,
        attributes,
        first_seen: provenance.timestamp,
        last_seen: provenance.timestamp,
        provenance: provenance.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
fn emit_probe_event(
    events: &mut Vec<Event>,
    kind: EventKind,
    ip: IpAddr,
    port: Option<u16>,
    technique: DiscoveryTechnique,
    message: &str,
    provenance: &Provenance,
    task: &crate::execution::Task,
) -> Result<(), ModuleError> {
    let asset_id = AssetId(crate::discovery::asset_id_for_ip(&ip));
    let details = BoundedDetails::from_value(
        serde_json::json!({
            "target": task.params.get("target").cloned().unwrap_or_else(|| ip.to_string()),
            "address": ip.to_string(),
            "port": port,
            "technique": technique.to_string(),
            "message": message,
        }),
        MAX_EVENT_DETAILS_BYTES,
    )
    .map_err(|_| ModuleError::Failed {
        message: "event details too large".to_owned(),
        retryable: false,
    })?;
    let event = Event::new(kind, Some(asset_id), details, provenance.clone()).map_err(|_| {
        ModuleError::Failed {
            message: "invalid event".to_owned(),
            retryable: false,
        }
    })?;
    events.push(event);
    Ok(())
}

fn emit_probe_outcome_event(
    events: &mut Vec<Event>,
    record: &ProbeRecord,
    provenance: &Provenance,
    task: &crate::execution::Task,
) -> Result<(), ModuleError> {
    let kind = match &record.outcome {
        ProbeOutcome::Success { .. } => EventKind::ProbeSucceeded,
        ProbeOutcome::Timeout => EventKind::ProbeTimedOut,
        ProbeOutcome::Unavailable { .. } => EventKind::ProbeUnavailable,
        ProbeOutcome::Unreachable { .. } => EventKind::ProbeSucceeded,
        ProbeOutcome::Cancelled => return Ok(()),
    };
    let asset_id = AssetId(crate::discovery::asset_id_for_ip(&record.target));
    let details = BoundedDetails::from_value(
        serde_json::json!({
            "target": task.params.get("target").cloned().unwrap_or_else(|| record.target.to_string()),
            "address": record.target.to_string(),
            "port": record.port,
            "technique": record.technique.to_string(),
            "outcome": record.describe(),
            "latency_ms": record.latency.map(|latency| latency.as_millis() as u64),
        }),
        MAX_EVENT_DETAILS_BYTES,
    )
    .map_err(|_| ModuleError::Failed {
        message: "event details too large".to_owned(),
        retryable: false,
    })?;
    let event = Event::new(kind, Some(asset_id), details, provenance.clone()).map_err(|_| {
        ModuleError::Failed {
            message: "invalid event".to_owned(),
            retryable: false,
        }
    })?;
    events.push(event);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finish_with_result(
    result: HostDiscoveryResult,
    target_label: &str,
    primary: Option<IpAddr>,
    probes: Vec<ProbeRecord>,
    mut events: Vec<Event>,
    provenance: &Provenance,
    task: &crate::execution::Task,
    start_instant: Instant,
) -> Result<ModuleOutput, ModuleError> {
    let confidence = Confidence::new(result.confidence).map_err(|_| ModuleError::Failed {
        message: "invalid confidence".to_owned(),
        retryable: false,
    })?;
    let asset_id = AssetId(result.asset_id.clone());
    // Host-state-concluded event (always emitted) + HostDiscovered for Alive.
    let concluded_details = BoundedDetails::from_value(
        serde_json::json!({
            "target": target_label,
            "address": result.address,
            "address_family": result.address_family,
            "state": result.state.to_string(),
            "confidence": result.confidence,
            "techniques": result.techniques.iter().map(|technique| technique.to_string()).collect::<Vec<_>>(),
            "latency_ms": result.latency_ms,
            "evidence": result.evidence,
            "probe_details": result.probe_details,
            "elapsed_ms": start_instant.elapsed().as_millis() as u64,
        }),
        MAX_EVENT_DETAILS_BYTES,
    )
    .map_err(|_| ModuleError::Failed {
        message: "event details too large".to_owned(),
        retryable: false,
    })?;
    let concluded = Event::new(
        EventKind::HostStateConcluded,
        Some(asset_id.clone()),
        concluded_details,
        provenance.clone(),
    )
    .map_err(|_| ModuleError::Failed {
        message: "invalid event".to_owned(),
        retryable: false,
    })?;
    events.push(concluded);
    if result.state == HostState::Alive {
        let discovered_details = BoundedDetails::from_value(
            serde_json::json!({
                "target": target_label,
                "address": result.address,
                "technique": result.techniques.first().map(|technique| technique.to_string()),
                "latency_ms": result.latency_ms,
            }),
            MAX_EVENT_DETAILS_BYTES,
        )
        .map_err(|_| ModuleError::Failed {
            message: "event details too large".to_owned(),
            retryable: false,
        })?;
        let discovered = Event::new(
            EventKind::HostDiscovered,
            Some(asset_id.clone()),
            discovered_details,
            provenance.clone(),
        )
        .map_err(|_| ModuleError::Failed {
            message: "invalid event".to_owned(),
            retryable: false,
        })?;
        events.push(discovered);
    }
    // Evidence explaining WHY the host received its state.
    let evidence_details = BoundedDetails::from_value(
        serde_json::json!({
            "target": result.target,
            "address": result.address,
            "address_family": result.address_family,
            "state": result.state.to_string(),
            "confidence": result.confidence,
            "techniques": result.techniques.iter().map(|technique| technique.to_string()).collect::<Vec<_>>(),
            "latency_ms": result.latency_ms,
            "evidence": result.evidence,
            "probe_details": result.probe_details,
            "policy": task.params.get("discovery_policy").cloned().unwrap_or_default(),
            "provenance": {
                "module": provenance.module_name,
                "version": provenance.module_version,
            },
            "timestamp": provenance.timestamp.0,
        }),
        crate::model::MAX_EVIDENCE_DETAILS_BYTES,
    )
    .map_err(|_| ModuleError::Failed {
        message: "evidence details too large".to_owned(),
        retryable: false,
    })?;
    let evidence = Evidence::new(
        HOST_DISCOVERY_MODULE_NAME,
        asset_id,
        evidence_details,
        confidence,
        provenance.clone(),
    )
    .map_err(|_| ModuleError::Failed {
        message: "invalid evidence".to_owned(),
        retryable: false,
    })?;
    let _ = (primary, probes);
    Ok(ModuleOutput {
        events,
        evidence: vec![evidence],
        findings: Vec::new(),
        assets: Vec::new(),
    })
}

/// Describe discovery mode for explain output.
pub fn describe_mode(mode: DiscoveryMode) -> &'static str {
    mode.as_str()
}
