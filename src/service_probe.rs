//! Phase 7 `ServiceProbe` scheduler module: native protocol identification.
//!
//! Control path (never bypassed):
//! `Open Port Finding -> Decision Engine -> ServiceProbe proposal ->
//! Scope Guard -> Scheduler <-> Speed / Budgets / Backpressure ->
//! Protocol Probe Module -> Typed Events / Evidence / Service Assets ->
//! Decision Engine boundary`.
//!
//! The module emits facts only. One task probes ONE open port with a small
//! ordered probe plan (sequential fresh connections, first classification
//! wins, TLS compositions reuse the session). Initial lowering tasks carry
//! no port context and complete empty with an explanatory event — the
//! Decision Engine owns real per-port proposals.
//!
//! Contract: per-probe wall budget (speed-derived) plus task-deadline
//! truncation with partial results, prompt cancellation, no retries inner
//! (timeouts become evidence), bounded reads/writes, immediate socket
//! cleanup, zero authentication bytes.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::discovery::AddressFamily;
use crate::execution::{
    CancellationToken, Module, ModuleContext, ModuleError, ModuleFuture, ModuleOutput, ScopeGuard,
    TaskKind, TaskScopeTarget,
};
use crate::model::{
    Asset, AssetId, AssetKind, BoundedDetails, Confidence, Event, EventKind, Evidence, Finding,
    MAX_EVENT_DETAILS_BYTES, Provenance, Relationship, RelationshipKind, RelationshipSubject,
    Severity, Timestamp,
};
use crate::plan::{ScanGoal, SpeedSetting};
use crate::probes::{
    CertFacts, ProbeAttempt, ProbeCtx, match_ssh_identification, parse_cert_facts, probe_ftp,
    probe_generic, probe_http, probe_http_inner, probe_mysql, probe_postgres, probe_redis,
    probe_smtp, probe_smtp_inner, probe_ssh, probe_tls, split_220_greeting,
};
use crate::service::{
    MAX_PROBES_PER_PORT, PROBE_HTTP, PROBE_SMTP, ServiceObservation, plan_probes, service_asset_id,
    service_asset_identity, service_timeout_for_speed,
};

pub const SERVICE_MODULE_NAME: &str = "rxscan.service";
pub const SERVICE_MODULE_VERSION: &str = "7.0.0";

/// Stop planning new probes when less than this remains on the task clock;
/// partial results return with `truncated: true`.
const PROBE_PLANNING_FLOOR: Duration = Duration::from_millis(500);

/// Centralized Phase 7 service policy (level breadth + speed pressure).
#[derive(Debug, Clone)]
pub struct ServicePolicy {
    pub level: u8,
    pub goal: ScanGoal,
    pub speed: SpeedSetting,
}

impl ServicePolicy {
    pub fn new(level: u8, goal: ScanGoal, speed: SpeedSetting) -> Self {
        Self {
            level: level.clamp(1, 5),
            goal,
            speed,
        }
    }

    pub fn probe_budget(&self) -> Duration {
        service_timeout_for_speed(self.speed)
    }

    pub fn describe(&self) -> String {
        format!(
            "service level {} ({}): planner ≤{} probes/port, probe budget {}ms, passive window {}ms, speculative redis/postgres {}ms; unknown-port actives by level: L1 none, L2 http, L3 +redis, L4 +tls, L5 +postgres,smtp(220-gated); known ports append pivots at L4(+http)/L5(+redis,+tls)",
            self.level,
            self.goal,
            MAX_PROBES_PER_PORT,
            self.probe_budget().as_millis(),
            PASSIVE_WINDOW_MS,
            SHORT_SPECULATIVE_MS,
        )
    }
}

/// Real scheduler module for `TaskKind::ServiceProbe`.
pub struct ServiceProbeModule {
    policy: ServicePolicy,
    scope_guard: Arc<dyn ScopeGuard>,
}

impl ServiceProbeModule {
    pub fn new(policy: ServicePolicy, scope_guard: Arc<dyn ScopeGuard>) -> Self {
        Self {
            policy,
            scope_guard,
        }
    }

    pub fn policy(&self) -> &ServicePolicy {
        &self.policy
    }
}

impl Module for ServiceProbeModule {
    fn kind(&self) -> TaskKind {
        TaskKind::ServiceProbe
    }

    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let policy = self.policy.clone();
        let guard = self.scope_guard.clone();
        Box::pin(async move { execute_service_probe(&policy, guard.as_ref(), context) })
    }
}

/// Parsed ServiceProbe task identity (engine proposals carry all fields).
struct ServiceTarget {
    address: IpAddr,
    port: u16,
    target_label: String,
    parent_port_asset_id: String,
    planned_probes: Vec<String>,
}

fn parse_service_target(
    task: &crate::execution::Task,
    guard: &dyn ScopeGuard,
    cancel: &CancellationToken,
) -> Result<Result<ServiceTarget, String>, ModuleError> {
    if cancel.is_cancelled() {
        return Err(ModuleError::Cancelled);
    }
    if !guard.permits(&task.scope_target) {
        return Err(ModuleError::Failed {
            message: "stale scope rejected immediately before network execution".to_owned(),
            retryable: false,
        });
    }
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
    let (Some(address_text), Some(port_text)) =
        (task.params.get("address"), task.params.get("port"))
    else {
        // Initial lowering tasks carry no port context: honest empty
        // completion; the Decision Engine owns per-port proposals.
        return Ok(Err(target_label));
    };
    let address: IpAddr = address_text.parse().map_err(|_| ModuleError::Failed {
        message: format!("invalid service address '{address_text}'"),
        retryable: false,
    })?;
    let port: u16 = port_text.parse().map_err(|_| ModuleError::Failed {
        message: format!("invalid service port '{port_text}'"),
        retryable: false,
    })?;
    if port == 0 {
        return Err(ModuleError::Failed {
            message: "invalid service port 0".to_owned(),
            retryable: false,
        });
    }
    if !guard.permits(&TaskScopeTarget::Ip(address)) {
        return Err(ModuleError::Failed {
            message: "derived service address outside scope; skipped without probing".to_owned(),
            retryable: false,
        });
    }
    let parent_port_asset_id = task.params.get("parent_asset").cloned().unwrap_or_else(|| {
        crate::tcp_discovery::port_asset_id(
            &crate::tcp_discovery::parent_asset_id_for_ip(&address),
            "tcp",
            port,
        )
    });
    let planned: Vec<String> = task
        .params
        .get("probes")
        .map(|csv| {
            csv.split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Ok(Ok(ServiceTarget {
        address,
        port,
        target_label,
        parent_port_asset_id,
        planned_probes: planned,
    }))
}

#[allow(clippy::too_many_lines)]
fn execute_service_probe(
    policy: &ServicePolicy,
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
        SERVICE_MODULE_NAME,
        SERVICE_MODULE_VERSION,
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
    let findings: Vec<Finding> = Vec::new();

    let target = match parse_service_target(&task, guard, &cancel)? {
        Ok(target) => target,
        Err(target_label) => {
            push_event(
                &mut events,
                EventKind::ServiceProbeCompleted,
                None,
                serde_json::json!({
                    "target": target_label,
                    "ports_probed": 0,
                    "note": "no port context in task params; awaiting Decision Engine per-port proposals",
                    "policy": policy.describe(),
                    "elapsed_ms": start_instant.elapsed().as_millis() as u64,
                }),
                &provenance,
            )?;
            return Ok(ModuleOutput {
                events,
                evidence: evidence_items,
                findings,
                assets,
            });
        }
    };

    // Probe plan: engine-recorded order wins (deterministic task ID input);
    // otherwise derive from the centralized planner for parity.
    let plan: Vec<String> = if target.planned_probes.is_empty() {
        plan_probes(target.port, policy.level, policy.goal)
            .into_iter()
            .map(str::to_owned)
            .collect()
    } else {
        target
            .planned_probes
            .clone()
            .into_iter()
            .take(MAX_PROBES_PER_PORT)
            .collect()
    };
    push_event(
        &mut events,
        EventKind::ServiceProbeStarted,
        Some(AssetId(target.parent_port_asset_id.clone())),
        serde_json::json!({
            "target": target.target_label,
            "address": target.address.to_string(),
            "transport": "tcp",
            "port": target.port,
            "probes": plan,
            "policy": policy.describe(),
        }),
        &provenance,
    )?;

    let family = AddressFamily::of(&target.address);
    let probe_budget = policy.probe_budget();
    let connections = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut attempt_log: Vec<String> = Vec::new();
    let mut classified: Option<ProbeAttempt> = None;
    // Best unclassified result: the first attempt carrying a banner becomes
    // the observation (unknown + preserved banner), so generic evidence is
    // never silently dropped. Fully silent runs keep the default below.
    let mut fallback: Option<ProbeAttempt> = None;
    let mut cert_facts: Option<CertFacts> = None;
    let mut tls_observation: Option<crate::tls::TlsObservation> = None;
    let mut truncated = false;
    // Every executed probe evaluation (network or passive-covered) lands
    // here in order: first classification wins, first banner seeds the
    // unknown fallback, and byte/write sums stay exact.
    let mut attempts_made: Vec<ProbeAttempt> = Vec::new();

    // Step 0: shared passive observation (one connection) when the plan
    // contains the generic consumer. The SAME bytes feed every passive
    // matcher — no separate passive connection per matcher. Pure-active
    // plans (e.g. L1 `[tls]`) skip it, preserving minimal behavior.
    let wants_passive = plan.iter().any(|probe| probe.as_str() == "generic");
    let passive = if wants_passive {
        Some(observe_passive(
            &target,
            probe_budget,
            task_deadline,
            &cancel,
            connections.clone(),
        ))
    } else {
        None
    };
    let mut passive_verdict = passive.as_ref().map(evaluate_passive);
    // A passive classification stops everything: strong server-first
    // identity from a single connection.
    if let Some(PassiveVerdict::Classified(attempt)) = passive_verdict.take() {
        attempt_log.push(format!(
            "passive: classified {} (1 connection, {} bytes)",
            attempt.protocol, attempt.bytes_in
        ));
        emit_attempt_event(&mut events, &attempt, &target, &provenance)?;
        attempts_made.push((*attempt).clone());
        classified = Some(*attempt);
    }

    // Deferred speculative actives, in plan order. Declared outside the
    // sequential phase so Phase B can consume it afterwards.
    let mut wave: Vec<String> = Vec::new();
    // Full-budget context shared by sequential inline probes and the TLS
    // composition step (speculative shorts are derived per wave item).
    let ctx = ProbeCtx {
        ip: target.address,
        port: target.port,
        host_label: &target.target_label,
        timeout: probe_budget,
        deadline: task_deadline,
        cancel: &cancel,
        connections: connections.clone(),
    };
    if classified.is_none() {
        // Deferred speculative actives for Phase B, in plan order.
        for probe_id in &plan {
            if cancel.is_cancelled() {
                return Err(ModuleError::Cancelled);
            }
            if task_deadline.saturating_duration_since(Instant::now()) < PROBE_PLANNING_FLOOR {
                truncated = true;
                attempt_log.push(format!("{probe_id}: skipped (task budget exhausted)"));
                break;
            }
            // Passive-covered probes never reconnect: ssh/mysql/generic
            // were already evaluated on the shared observation (a miss
            // there is evidence, not an excuse for another connection).
            // FTP/SMTP run the disambiguation exchange unless passive
            // bytes refute mail outright.
            match probe_id.as_str() {
                "generic" => {
                    // Passive-covered: evaluate on shared bytes without
                    // reconnecting. Without a passive observation (defensive;
                    // unreachable for planner-built plans) run it fresh.
                    let attempt = match passive.as_ref() {
                        Some(_) => passive_generic_attempt(passive.as_ref()),
                        None => probe_generic(&ctx),
                    };
                    attempts_made.push(attempt.clone());
                    emit_attempt_event(&mut events, &attempt, &target, &provenance)?;
                    attempt_log.push(format!(
                        "generic: {}",
                        attempt
                            .evidence
                            .first()
                            .cloned()
                            .unwrap_or_else(|| "miss".to_owned())
                    ));
                    if attempt.classified() {
                        classified = Some(attempt);
                        break;
                    }
                    if fallback.is_none() && attempt.banner.is_some() {
                        fallback = Some(attempt);
                    }
                    continue;
                }
                "ssh" | "mysql" => {
                    // Passive-covered when observed (a miss there is
                    // evidence, not an excuse for another connection);
                    // dedicated fresh read only without passive (L1 plans).
                    let attempt = match passive.as_ref() {
                        Some(_) => passive_refuted_attempt(probe_id, passive.as_ref()),
                        None => run_plain_probe(probe_id, &ctx),
                    };
                    attempts_made.push(attempt.clone());
                    emit_attempt_event(&mut events, &attempt, &target, &provenance)?;
                    attempt_log.push(format!(
                        "{probe_id}: {}",
                        attempt
                            .evidence
                            .first()
                            .cloned()
                            .unwrap_or_else(|| "miss".to_owned())
                    ));
                    if fallback.is_none() && attempt.banner.is_some() {
                        fallback = Some(attempt);
                    }
                    continue;
                }
                "ftp" | "smtp" => {
                    if !mail_probe_justified(passive.as_ref()) {
                        let attempt = passive_refuted_attempt(probe_id, passive.as_ref());
                        attempts_made.push(attempt.clone());
                        emit_attempt_event(&mut events, &attempt, &target, &provenance)?;
                        attempt_log.push(format!(
                            "{probe_id}: skipped (passive observation refutes mail)"
                        ));
                        if fallback.is_none() && attempt.banner.is_some() {
                            fallback = Some(attempt);
                        }
                        continue;
                    }
                    // Justified: shared disambiguation exchange (own bounded
                    // connection; identity from grammar, never the port).
                    let attempt = run_plain_probe(probe_id, &ctx);
                    if cancel.is_cancelled() {
                        return Err(ModuleError::Cancelled);
                    }
                    attempts_made.push(attempt.clone());
                    emit_attempt_event(&mut events, &attempt, &target, &provenance)?;
                    attempt_log.push(format!(
                        "{probe_id}: {}",
                        if attempt.classified() {
                            format!("classified {}", attempt.protocol)
                        } else {
                            attempt
                                .evidence
                                .first()
                                .cloned()
                                .unwrap_or_else(|| "miss".to_owned())
                        }
                    ));
                    if attempt.classified() {
                        classified = Some(attempt);
                        break;
                    }
                    if fallback.is_none() && attempt.banner.is_some() {
                        fallback = Some(attempt);
                    }
                    continue;
                }
                _ => {}
            }
            // Remaining kinds are speculative actives (http/tls/redis/
            // postgres or an unlisted id): defer to the bounded parallel
            // wave below. Each gets its own bounded connection; results
            // merge back in plan order so output stays deterministic.
            wave.push(probe_id.clone());
            continue;
        }
    } // end Phase A: sequential evaluations + evidence-priority probes

    // Phase B: bounded parallel wave over deferred speculative actives.
    // Independent probes overlap their I/O waits instead of summing
    // sequential read timeouts on quiet ports. Width is naturally bounded
    // (at most the plan's active count, ≤5 given MAX_PROBES_PER_PORT).
    // Replay below is two-step — materialize every result in plan order,
    // then decide — so a plan-first classification wins exactly as if
    // sequential, while every executed probe stays counted and logged.
    if !wave.is_empty() && classified.is_none() {
        if cancel.is_cancelled() {
            return Err(ModuleError::Cancelled);
        }
        let wave_results = run_wave(
            &wave,
            &target,
            probe_budget,
            task_deadline,
            &cancel,
            connections.clone(),
        );
        // Step 1: materialize. TLS sessions stay live for a possible
        // composition; everything else becomes a plain attempt record.
        struct Replayed {
            probe_id: String,
            attempt: ProbeAttempt,
            tls_session: Option<(
                Box<crate::tls::EstablishedTls>,
                crate::tls::TlsObservation,
                Option<Vec<u8>>,
            )>,
        }
        let mut replay: Vec<Replayed> = Vec::with_capacity(wave_results.len());
        for (probe_id, out) in wave_results {
            if cancel.is_cancelled() {
                return Err(ModuleError::Cancelled);
            }
            match out {
                WaveOut::TlsCancelled => return Err(ModuleError::Cancelled),
                WaveOut::Attempt(attempt) => replay.push(Replayed {
                    probe_id,
                    attempt: *attempt,
                    tls_session: None,
                }),
                WaveOut::TlsEstablished {
                    session,
                    observation,
                    leaf_der,
                } => {
                    let facts = leaf_der
                        .as_deref()
                        .and_then(|der| parse_cert_facts(der, &target.target_label));
                    let bare = bare_tls_attempt(&observation, facts.clone());
                    replay.push(Replayed {
                        probe_id,
                        attempt: bare,
                        tls_session: Some((session, observation, leaf_der)),
                    });
                    if cert_facts.is_none() {
                        cert_facts = facts;
                    }
                }
            }
        }
        // Step 2: winner first (plan order, as if sequential), so later
        // composition/fallback logic sees the same decision point.
        let winner = replay.iter().position(|item| item.attempt.classified());
        // Step 3: emit and log every result in plan order. TLS sessions
        // record their bare conclusion like any other executed probe
        // (superseded or not, the handshake happened); composition runs
        // in step 4 only for a TLS winner.
        let mut tls_record_pos: Option<usize> = None;
        for item in &replay {
            // TLS sessions log their handshake line (as sequential code
            // did); every other result logs the standard one-liner.
            if item.probe_id == "tls" {
                if let Some((_, observation, _)) = item.tls_session.as_ref() {
                    emit_tls_observed(&mut events, observation, &target, &provenance)?;
                    attempt_log.push(format!(
                        "tls: handshake {} {} ({}ms)",
                        observation.negotiated_version,
                        observation.cipher_suite,
                        observation.latency.as_millis()
                    ));
                    tls_record_pos = Some(attempts_made.len());
                } else {
                    attempt_log.push(format!(
                        "{}: {}",
                        item.probe_id,
                        item.attempt
                            .evidence
                            .first()
                            .cloned()
                            .unwrap_or_else(|| "miss".to_owned())
                    ));
                }
            } else {
                attempt_log.push(format!(
                    "{}: {}",
                    item.probe_id,
                    if item.attempt.classified() {
                        format!("classified {}", item.attempt.protocol)
                    } else {
                        item.attempt
                            .evidence
                            .first()
                            .cloned()
                            .unwrap_or_else(|| "miss".to_owned())
                    }
                ));
            }
            attempts_made.push(item.attempt.clone());
            emit_attempt_event(&mut events, &item.attempt, &target, &provenance)?;
            attempt_log.push(format!(
                "{}: {}",
                item.probe_id,
                if item.attempt.classified() {
                    format!("classified {}", item.attempt.protocol)
                } else {
                    item.attempt
                        .evidence
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "miss".to_owned())
                }
            ));
            if fallback.is_none() && item.attempt.banner.is_some() {
                fallback = Some(item.attempt.clone());
            }
        }
        // Step 4: TLS composition runs only when the TLS result is the
        // plan-first winner (sequential-equivalent: composition never runs
        // for a probe sequential execution would not have reached).
        // Certificate records attach only in that case too.
        if let Some(index) = winner {
            let is_tls_winner =
                replay[index].probe_id == "tls" && replay[index].tls_session.is_some();
            if is_tls_winner {
                let item = &mut replay[index];
                let (session, observation, _) = item.tls_session.as_mut().unwrap();
                if let Some(facts) = cert_facts.clone() {
                    emit_cert_records(
                        &mut assets,
                        &mut events,
                        &mut evidence_items,
                        &facts,
                        &target,
                        &provenance,
                    )?;
                }
                // Composition: HTTP or SMTP inside the same session when
                // the port is TLS-likely for it or the plan includes
                // the probe (planner-driven, never guessed).
                let (composed, composition_notes) = compose_over_tls(
                    session,
                    observation,
                    &target,
                    &ctx,
                    &plan,
                    &mut events,
                    &provenance,
                )?;
                attempt_log.extend(composition_notes);
                tls_observation = Some(observation.clone());
                if let Some(hit) = composed {
                    // The composed application protocol supersedes bare TLS
                    // (same decision sequential execution reaches): swap the
                    // bare record for the composed one, keeping counts exact.
                    if let Some(pos) = tls_record_pos {
                        if let Some(slot) = attempts_made.get_mut(pos) {
                            *slot = hit.clone();
                        }
                    }
                    classified = Some(hit);
                } else {
                    classified = Some(item.attempt.clone());
                }
            } else {
                let winner_attempt = replay[index].attempt.clone();
                classified = Some(winner_attempt);
            }
        }
    }

    if cancel.is_cancelled() {
        return Err(ModuleError::Cancelled);
    }
    if task_deadline.saturating_duration_since(Instant::now()) < Duration::from_millis(50) {
        truncated = true;
    }
    // Hard accounting from the shared connection counter and attempt
    // records: exact connections, executed probes, probe-level writes,
    // and byte totals. Surfaced in ServiceProbeCompleted details.
    let connections_opened = connections.load(std::sync::atomic::Ordering::Relaxed) as u64;
    let probes_executed = attempts_made.len() as u32;
    let bytes_read: u64 = attempts_made.iter().map(|a| a.bytes_in as u64).sum();
    let bytes_written: u64 = attempts_made.iter().map(|a| a.bytes_out as u64).sum();
    let writes: u64 = attempts_made.iter().map(|a| u64::from(a.writes)).sum();
    // A banner-bearing unknown result still becomes the observation; only a
    // fully silent run falls back to the default below.
    let result = classified.or(fallback);
    let matched_by = result.as_ref().and_then(|attempt| {
        if attempt.classified() {
            Some(attempt.probe_id.to_owned())
        } else {
            None
        }
    });
    let unknown_fingerprint = match &result {
        // Fingerprint the richest bounded observation available: the shared
        // passive bytes when present, else the preserved banner text.
        // Silence fingerprints nothing.
        Some(attempt) if !attempt.classified() => {
            let banner_bytes;
            let (bytes, spoke_first, truncated_fp) = match passive
                .as_ref()
                .filter(|observation| !observation.bytes.is_empty())
            {
                Some(observation) => (
                    observation.bytes.as_slice(),
                    observation.spoke_first,
                    observation.truncated,
                ),
                None => {
                    banner_bytes = attempt.banner.clone().unwrap_or_default().into_bytes();
                    (banner_bytes.as_slice(), false, attempt.truncated)
                }
            };
            crate::service::UnknownFingerprint::compute(
                bytes,
                spoke_first,
                attempt.probe_id,
                truncated_fp,
            )
        }
        _ => None,
    };
    finish_observation(
        result,
        cert_facts,
        tls_observation,
        attempt_log,
        truncated,
        matched_by,
        unknown_fingerprint,
        connections_opened,
        probes_executed,
        bytes_written,
        bytes_read,
        writes,
        &target,
        family,
        policy,
        events,
        &provenance,
        started_at,
        start_instant,
    )
    .map(|(events, evidence, findings, assets)| ModuleOutput {
        events,
        evidence,
        findings,
        assets,
    })
    .map(|mut output| {
        output.evidence.extend(evidence_items);
        output.findings.extend(findings);
        output.assets.extend(assets);
        output
    })
}

fn run_plain_probe(probe_id: &str, ctx: &ProbeCtx) -> ProbeAttempt {
    match probe_id {
        "ssh" => probe_ssh(ctx),
        "http" => probe_http(ctx),
        "ftp" => probe_ftp(ctx),
        "smtp" => probe_smtp(ctx),
        "redis" => probe_redis(ctx),
        "mysql" => probe_mysql(ctx),
        "postgres" => probe_postgres(ctx),
        _ => probe_generic(ctx),
    }
}

/// Registry probe identity (static) for runtime plan ids. Unknown ids
/// fall back to generic (passive read, never classifies blindly).
fn static_probe_id(name: &str) -> &'static str {
    match name {
        "ssh" => "ssh",
        "http" => "http",
        "ftp" => "ftp",
        "smtp" => "smtp",
        "redis" => "redis",
        "mysql" => "mysql",
        "postgres" => "postgres",
        "tls" => "tls",
        _ => "generic",
    }
}

/// One deferred speculative probe's network result, collected by the
/// parallel wave and replayed in plan order by the caller.
enum WaveOut {
    Attempt(Box<ProbeAttempt>),
    TlsEstablished {
        session: Box<crate::tls::EstablishedTls>,
        observation: crate::tls::TlsObservation,
        leaf_der: Option<Vec<u8>>,
    },
    TlsCancelled,
}

/// Bounded parallel wave over deferred speculative actives.
///
/// Independent probes overlap their I/O waits instead of summing sequential
/// read timeouts on quiet ports. Results return in plan order with the
/// probe id attached; the caller replays them sequentially (first
/// classification wins), so observable output matches sequential
/// execution. Width is the eligible active count (≤5). A panicking probe
/// thread becomes a miss with explicit evidence rather than stalling the
/// task: parsers are bounded, but a scanner must never hang on them.
#[allow(clippy::too_many_arguments)]
fn run_wave(
    wave: &[String],
    target: &ServiceTarget,
    probe_budget: Duration,
    task_deadline: Instant,
    cancel: &CancellationToken,
    connections: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> Vec<(String, WaveOut)> {
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(wave.len());
        for probe_id in wave.iter() {
            let short = matches!(probe_id.as_str(), "redis" | "postgres");
            // Redis/PostgreSQL grammars need ≤256 bytes: a short sub-budget
            // keeps silence cheap. Pivots (HTTP/TLS) keep the full budget.
            let budget = if short {
                probe_budget.min(Duration::from_millis(SHORT_SPECULATIVE_MS))
            } else {
                probe_budget
            };
            let owned_id = probe_id.clone();
            let conns = connections.clone();
            handles.push((
                probe_id.clone(),
                scope.spawn(move || {
                    let probe_ctx = ProbeCtx {
                        ip: target.address,
                        port: target.port,
                        host_label: &target.target_label,
                        timeout: budget,
                        deadline: task_deadline.min(Instant::now() + budget),
                        cancel,
                        connections: conns,
                    };
                    run_wave_probe(&owned_id, &probe_ctx)
                }),
            ));
        }
        handles
            .into_iter()
            .map(|(probe_id, handle)| {
                let out = match handle.join() {
                    Ok(out) => out,
                    Err(_) => WaveOut::Attempt(Box::new(ProbeAttempt::miss(
                        static_probe_id(&probe_id),
                        format!("{probe_id}: probe thread failed"),
                    ))),
                };
                (probe_id, out)
            })
            .collect()
    })
}

/// Execute one deferred probe inside the wave (own bounded connection).
fn run_wave_probe(probe_id: &str, ctx: &ProbeCtx) -> WaveOut {
    if probe_id == "tls" {
        // probe_tls builds its own socket inside tls::connect_tls (exactly
        // one TCP connection per call, handshake or not), bypassing
        // ProbeCtx::connect: count it here so accounting stays exact.
        ctx.connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return match probe_tls(ctx) {
            crate::probes::TlsProbeOutcome::Cancelled => WaveOut::TlsCancelled,
            crate::probes::TlsProbeOutcome::Miss(attempt) => WaveOut::Attempt(attempt),
            crate::probes::TlsProbeOutcome::Established(session, observation, leaf_der) => {
                WaveOut::TlsEstablished {
                    session,
                    observation,
                    leaf_der,
                }
            }
        };
    }
    WaveOut::Attempt(Box::new(run_plain_probe(static_probe_id(probe_id), ctx)))
}

/// Small bounded server-first observation window (passive reads only).
/// Shorter than a full probe budget: banners arrive in milliseconds;
/// silence must fail fast so quiet ports stay cheap.
pub const PASSIVE_WINDOW_MS: u64 = 1000;
/// Short sub-budget for speculative grammars that need few bytes
/// (Redis single line, PostgreSQL single byte). Pivots (HTTP/TLS) keep the
/// full probe budget.
pub const SHORT_SPECULATIVE_MS: u64 = 800;
/// Cap on bytes retained from the shared passive observation.
pub const PASSIVE_MAX_BYTES: usize = 2048;

/// One shared server-first observation feeding every passive matcher.
#[derive(Debug, Clone, Default)]
pub struct PassiveObservation {
    /// Bounded raw bytes (up to [`PASSIVE_MAX_BYTES`]).
    pub bytes: Vec<u8>,
    /// Whether the server spoke first (non-empty before the window ended).
    pub spoke_first: bool,
    /// Whether the first line terminated (needed for line grammars).
    pub saw_newline: bool,
    /// Whether the reader hit the byte budget.
    pub truncated: bool,
    pub elapsed_ms: u64,
}

/// Collect one bounded server-first observation on a fresh connection.
/// Sends nothing. Silent servers cost at most the window, never more.
fn observe_passive(
    target: &ServiceTarget,
    probe_budget: Duration,
    task_deadline: Instant,
    cancel: &CancellationToken,
    connections: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> PassiveObservation {
    let started = Instant::now();
    let window = probe_budget.min(Duration::from_millis(PASSIVE_WINDOW_MS));
    let ctx = ProbeCtx {
        ip: target.address,
        port: target.port,
        host_label: &target.target_label,
        timeout: window,
        deadline: task_deadline.min(started + window),
        cancel,
        connections,
    };
    // Reuse the bounded TCP prober for a pure read: connect, then read
    // without writing. Any connect failure yields an empty observation.
    let mut observation = PassiveObservation::default();
    let Ok(mut stream) = ctx.connect() else {
        observation.elapsed_ms = started.elapsed().as_millis() as u64;
        return observation;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
    use std::io::Read as _;
    let mut first_newline = false;
    let deadline = ctx.deadline;
    while observation.bytes.len() < PASSIVE_MAX_BYTES {
        if cancel.is_cancelled() || Instant::now() >= deadline || started.elapsed() >= window {
            break;
        }
        let mut chunk = [0u8; 1024];
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                let room = PASSIVE_MAX_BYTES.saturating_sub(observation.bytes.len());
                observation
                    .bytes
                    .extend_from_slice(&chunk[..count.min(room)]);
                if !first_newline && observation.bytes.contains(&b'\n') {
                    first_newline = true;
                    // One line suffices for line grammars, but keep reading
                    // briefly: binary framings (MySQL) have no newlines.
                    // Binary data arrives immediately or not at all; a short
                    // grace covers segmentation without funding silence.
                    std::thread::sleep(Duration::from_millis(50));
                    // Drain whatever arrived during the grace period.
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(60)));
                    loop {
                        let mut extra = [0u8; 1024];
                        match stream.read(&mut extra) {
                            Ok(0) => break,
                            Ok(n) => {
                                let room =
                                    PASSIVE_MAX_BYTES.saturating_sub(observation.bytes.len());
                                if room == 0 {
                                    observation.truncated = true;
                                    break;
                                }
                                observation.bytes.extend_from_slice(&extra[..n.min(room)]);
                                if observation.bytes.len() >= PASSIVE_MAX_BYTES {
                                    observation.truncated = true;
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    break;
                }
                if observation.bytes.len() >= PASSIVE_MAX_BYTES {
                    observation.truncated = true;
                    break;
                }
                // Binary-first protocols send everything up front: stop
                // early once a MySQL-shaped framing is complete or 512
                // bytes arrived with no newline in sight.
                if !observation.bytes.contains(&b'\n') && observation.bytes.len() >= 512 {
                    break;
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(_) => break,
        }
    }
    observation.saw_newline = first_newline;
    observation.spoke_first = !observation.bytes.is_empty();
    observation.elapsed_ms = started.elapsed().as_millis() as u64;
    observation
}

/// Fan-out verdict over shared passive bytes. Only complete grammars
/// classify; everything else stays material for later steps.
enum PassiveVerdict {
    /// A passive grammar fully proved identity (ssh/mysql). Boxed: the
    /// other verdicts carry no data and the attempt is large.
    Classified(Box<ProbeAttempt>),
    /// A `220`-led greeting: mail disambiguation is justified, nothing more.
    MailGated,
    /// No classification; generic material (banner or silence).
    Open,
}

/// Evaluate passive matchers over shared bytes (no I/O, no port identity).
fn evaluate_passive(observation: &PassiveObservation) -> PassiveVerdict {
    if observation.bytes.is_empty() {
        return PassiveVerdict::Open;
    }
    let text = String::from_utf8_lossy(&observation.bytes);
    let first_line = text.lines().next().unwrap_or("").trim().to_owned();
    // SSH: strict line grammar only (same matcher as dedicated probes).
    if observation.saw_newline && first_line.starts_with("SSH-") {
        if let Some((proto, product, version)) = match_ssh_identification(&first_line) {
            let mut attempt = ProbeAttempt::miss("passive", String::new());
            attempt.bytes_in = observation.bytes.len();
            attempt.truncated = observation.truncated;
            attempt.protocol = "ssh".to_owned();
            attempt.protocol_version = Some(proto);
            if let Some(product) = product {
                attempt.product_hint = Some(product);
            }
            attempt.version_hint = version;
            attempt.banner = Some(first_line.chars().take(200).collect());
            attempt.confidence = if attempt.product_hint.is_some() {
                crate::service::confidence::CONFIRMED
            } else {
                crate::service::confidence::CHARACTERISTIC
            };
            attempt.evidence = vec![
                format!("passive: SSH identification string {first_line:?}"),
                "passive: banner satisfies the SSH identification-string grammar".to_owned(),
            ];
            return PassiveVerdict::Classified(Box::new(attempt));
        }
    }
    // 220-led greeting: gate mail disambiguation, classify nothing yet.
    // (A lone 220 never identifies; truncated mid-line greetings still
    // gate, since the mail probe re-reads the greeting directly.)
    if split_220_greeting(&first_line).is_some() {
        return PassiveVerdict::MailGated;
    }
    // MySQL: complete packet framing required (inconclusive, never a
    // refutation, when the buffer holds only a prefix).
    if let Ok((protocol, version, _)) = crate::probes::parse_mysql_handshake(&observation.bytes) {
        let (product, detected) = crate::service::product_from_greeting(&version);
        let mut attempt = ProbeAttempt::miss("passive", String::new());
        attempt.bytes_in = observation.bytes.len();
        attempt.truncated = observation.truncated;
        attempt.protocol = "mysql".to_owned();
        attempt.protocol_version = Some(format!("handshake-{protocol}"));
        attempt.product_hint = product;
        attempt.version_hint = detected.or(Some(version.clone()));
        attempt.banner = Some(version.chars().take(120).collect());
        attempt.confidence = crate::service::confidence::STRONG;
        attempt.evidence = vec![format!(
            "passive: MySQL handshake protocol {protocol} version {version:?}"
        )];
        return PassiveVerdict::Classified(Box::new(attempt));
    }
    PassiveVerdict::Open
}

/// Generic material from passive bytes without reconnecting: SSH already
/// handled by the fan-out; anything else is unknown-banner or silence.
fn passive_generic_attempt(passive: Option<&PassiveObservation>) -> ProbeAttempt {
    let Some(observation) = passive else {
        return ProbeAttempt::miss("generic", "generic: no passive observation".to_owned());
    };
    let mut attempt = ProbeAttempt::miss("generic", String::new());
    attempt.bytes_in = observation.bytes.len();
    attempt.truncated = observation.truncated;
    if observation.bytes.is_empty() {
        attempt.confidence = 0;
        attempt.evidence = vec!["generic: silent service, no banner received".to_owned()];
        return attempt;
    }
    let text = String::from_utf8_lossy(&observation.bytes);
    let first_line = text.lines().next().unwrap_or("").trim().to_owned();
    attempt.protocol = "unknown".to_owned();
    attempt.confidence = crate::service::confidence::BANNER;
    attempt.banner = Some(first_line.chars().take(200).collect());
    let mut lines = vec![format!(
        "generic: unknown TCP service, banner preserved ({} bytes)",
        observation.bytes.len()
    )];
    if observation.truncated {
        lines.push("generic: banner truncated at byte budget".to_owned());
    }
    attempt.evidence = lines;
    attempt
}

/// Refutation material for passive-nature probes (ssh/mysql) already
/// evaluated on shared bytes: no reconnect, evidence preserved.
fn passive_refuted_attempt(probe_id: &str, passive: Option<&PassiveObservation>) -> ProbeAttempt {
    // Registry probe identity (static): passive-covered ids only.
    let static_id = match probe_id {
        "ssh" => "ssh",
        "mysql" => "mysql",
        "ftp" => "ftp",
        "smtp" => "smtp",
        _ => "generic",
    };
    let Some(observation) = passive else {
        return ProbeAttempt::miss(static_id, format!("{static_id}: no passive observation"));
    };
    let mut attempt = ProbeAttempt::miss(static_id, String::new());
    attempt.bytes_in = observation.bytes.len();
    attempt.truncated = observation.truncated;
    if observation.bytes.is_empty() {
        attempt.evidence = vec![format!("{static_id}: silent service (passive observation)")];
        return attempt;
    }
    let text = String::from_utf8_lossy(&observation.bytes);
    let first_line = text.lines().next().unwrap_or("").trim().to_owned();
    attempt.banner = Some(first_line.chars().take(120).collect());
    attempt.evidence = vec![format!(
        "{static_id}: passive observation does not satisfy {static_id} grammar"
    )];
    attempt
}

/// Whether running FTP/SMTP disambiguation is justified: the passive
/// observation is absent (dedicated likely-port probe), `220`-led, or
/// lacks a complete first line — anything a complete non-220 first line
/// would refute stays skipped. Silence refutes mail outright: unlike
/// HTTP/Redis/PostgreSQL/TLS (client-first, silent until spoken to),
/// FTP and SMTP servers greet first by protocol, so a silent socket
/// cannot be either and earns no extra connection.
fn mail_probe_justified(passive: Option<&PassiveObservation>) -> bool {
    let Some(observation) = passive else {
        return true;
    };
    if observation.bytes.is_empty() {
        return false;
    }
    let text = String::from_utf8_lossy(&observation.bytes);
    let first_line = text.lines().next().unwrap_or("").trim().to_owned();
    if split_220_greeting(&first_line).is_some() {
        return true;
    }
    // No complete first line: inconclusive (truncated mid-greeting), so the
    // mail probe re-reads the greeting directly instead of trusting bytes.
    !observation.saw_newline
}

/// HTTP-inside-TLS (or SMTP-inside-TLS) composition on an established
/// session. Returns the classified attempt (if any) plus a note describing
/// what the composition step observed — including negative outcomes, so a
/// bare-TLS conclusion still explains why no application layer was claimed.
#[allow(clippy::too_many_arguments)]
fn compose_over_tls(
    session: &mut crate::tls::EstablishedTls,
    observation: &crate::tls::TlsObservation,
    target: &ServiceTarget,
    ctx: &ProbeCtx,
    planned: &[String],
    events: &mut Vec<Event>,
    provenance: &Provenance,
) -> Result<(Option<ProbeAttempt>, Vec<String>), ModuleError> {
    let mut notes = Vec::new();
    let wants_http = planned.iter().any(|probe| probe == PROBE_HTTP);
    let wants_smtp = planned.iter().any(|probe| probe == PROBE_SMTP);
    let http_likely = crate::service::PROBE_REGISTRY
        .iter()
        .find(|spec| spec.id == PROBE_HTTP)
        .is_some_and(|spec| spec.likely_ports.contains(&target.port))
        || target.port == 443
        || target.port == 8443;
    let smtp_likely = [25u16, 465, 587].contains(&target.port);
    if http_likely || wants_http {
        let budget = ctx
            .timeout
            .min(ctx.deadline.saturating_duration_since(Instant::now()));
        match session.http_get(
            ctx.host_label,
            crate::service::MAX_HTTP_HEADER_BYTES + crate::service::MAX_HTTP_BODY_BYTES,
            budget,
            ctx.cancel,
        ) {
            Ok(body) if !body.is_empty() => {
                let mut attempt = probe_http_inner(ctx, Some(body));
                attempt.tls = true;
                attempt.confidence = attempt.confidence.clamp(85, 95);
                attempt.evidence.insert(
                    0,
                    format!(
                        "https: TLS {} handshake then HTTP inside TLS ({}ms)",
                        observation.negotiated_version,
                        observation.latency.as_millis()
                    ),
                );
                emit_attempt_event(events, &attempt, target, provenance)?;
                if attempt.classified() {
                    return Ok((Some(attempt), notes));
                }
                notes.push(
                    "https: HTTP inside TLS returned no valid HTTP response; staying bare TLS"
                        .to_owned(),
                );
            }
            Ok(_) => {
                notes.push("https: empty HTTP response inside TLS; staying bare TLS".to_owned());
            }
            Err(reason) => {
                notes.push(format!(
                    "https: HTTP inside TLS failed ({reason}); staying bare TLS"
                ));
                push_event(
                    events,
                    EventKind::ServiceProbeError,
                    None,
                    serde_json::json!({
                        "target": target.target_label,
                        "probe": "https",
                        "detail": format!("HTTP inside TLS failed: {reason}"),
                    }),
                    provenance,
                )?;
            }
        }
    } else if smtp_likely || wants_smtp {
        let budget = ctx
            .timeout
            .min(ctx.deadline.saturating_duration_since(Instant::now()));
        match session.exchange_lines(
            b"EHLO rxscan.local\r\n",
            crate::service::MAX_SMTP_REPLY_BYTES,
            budget,
            ctx.cancel,
        ) {
            Ok(body) if !body.is_empty() => {
                let mut attempt = probe_smtp_inner(ctx, Some(body));
                attempt.tls = true;
                attempt.confidence = attempt.confidence.clamp(80, 90);
                attempt.evidence.insert(
                    0,
                    format!(
                        "smtps: TLS {} handshake then SMTP inside TLS",
                        observation.negotiated_version
                    ),
                );
                emit_attempt_event(events, &attempt, target, provenance)?;
                if attempt.classified() {
                    return Ok((Some(attempt), notes));
                }
                notes.push(
                    "smtps: SMTP inside TLS returned no valid SMTP greeting; staying bare TLS"
                        .to_owned(),
                );
            }
            Ok(_) => {
                notes.push("smtps: empty SMTP response inside TLS; staying bare TLS".to_owned());
            }
            Err(reason) => {
                notes.push(format!(
                    "smtps: SMTP inside TLS failed ({reason}); staying bare TLS"
                ));
                push_event(
                    events,
                    EventKind::ServiceProbeError,
                    None,
                    serde_json::json!({
                        "target": target.target_label,
                        "probe": "smtps",
                        "detail": format!("SMTP inside TLS failed: {reason}"),
                    }),
                    provenance,
                )?;
            }
        }
    }
    Ok((None, notes))
}

fn bare_tls_attempt(
    observation: &crate::tls::TlsObservation,
    cert_facts: Option<CertFacts>,
) -> ProbeAttempt {
    let confidence = if cert_facts.is_some() {
        crate::service::confidence::CONFIRMED
    } else {
        crate::service::confidence::CHARACTERISTIC
    };
    let mut lines = vec![format!(
        "tls: handshake {} {} completed; peer certificate observed ({})",
        observation.negotiated_version,
        observation.cipher_suite,
        observation.peer_certs_der.len()
    )];
    if let Some(facts) = &cert_facts {
        lines.push(format!(
            "tls: certificate subject {:?} issuer {:?}",
            facts.subject, facts.issuer
        ));
    }
    ProbeAttempt {
        probe_id: "tls",
        protocol: "tls".to_owned(),
        tls: true,
        protocol_version: Some(observation.negotiated_version.clone()),
        product_hint: None,
        version_hint: None,
        banner: None,
        capabilities: Vec::new(),
        cert: cert_facts,
        confidence,
        evidence: lines,
        bytes_in: 0,
        // The handshake write happened inside the TLS session; exact
        // handshake bytes are untracked, the single write is counted.
        bytes_out: 0,
        writes: 1,
        truncated: false,
    }
}

/// Combined output bundles returned by observation finalization.
type ServiceOut = (Vec<Event>, Vec<Evidence>, Vec<Finding>, Vec<Asset>);

#[allow(clippy::too_many_arguments)]
fn finish_observation(
    classified: Option<ProbeAttempt>,
    cert_facts: Option<CertFacts>,
    tls_observation: Option<crate::tls::TlsObservation>,
    attempt_log: Vec<String>,
    truncated: bool,
    matched_by: Option<String>,
    unknown_fingerprint: Option<crate::service::UnknownFingerprint>,
    connections_opened: u64,
    probes_executed: u32,
    bytes_written: u64,
    bytes_read: u64,
    writes: u64,
    target: &ServiceTarget,
    family: AddressFamily,
    policy: &ServicePolicy,
    mut events: Vec<Event>,
    provenance: &Provenance,
    started_at: Timestamp,
    start_instant: Instant,
) -> Result<ServiceOut, ModuleError> {
    let mut evidence_items = Vec::new();
    let mut findings = Vec::new();
    let mut assets = Vec::new();
    // Best banner seen across attempts (generic/unknown evidence).
    let (
        protocol,
        tls,
        confidence,
        product,
        version,
        proto_version,
        banner,
        capabilities,
        rawevidence,
    ) = match classified {
        Some(attempt) => (
            attempt.protocol,
            attempt.tls,
            attempt.confidence,
            attempt.product_hint,
            attempt.version_hint,
            attempt.protocol_version,
            attempt.banner,
            attempt.capabilities,
            attempt.evidence,
        ),
        None => (
            "unknown".to_owned(),
            false,
            20u8,
            None,
            None,
            None,
            None,
            Vec::new(),
            vec!["service: no probe classified the service".to_owned()],
        ),
    };
    let label = if tls && protocol == "http" {
        "https".to_owned()
    } else if tls && protocol == "smtp" {
        "smtps".to_owned()
    } else {
        protocol.clone()
    };
    let asset_id = service_asset_id(&target.parent_port_asset_id, &protocol, tls);
    let observation = ServiceObservation {
        target: target.target_label.clone(),
        address: target.address.to_string(),
        address_family: family,
        port: target.port,
        transport: "tcp".to_owned(),
        parent_port_asset_id: target.parent_port_asset_id.clone(),
        asset_id: asset_id.clone(),
        protocol: protocol.clone(),
        tls,
        service_label: label.clone(),
        protocol_version: proto_version,
        product_hint: product.clone(),
        version_hint: version.clone(),
        banner: banner.clone(),
        capabilities: capabilities.clone(),
        confidence,
        evidence_lines: rawevidence.clone(),
        timestamp: started_at.0,
        matched_by: matched_by.clone(),
        unknown_fingerprint: unknown_fingerprint.clone(),
    };
    assets.push(Asset {
        schema_version: crate::model::SCHEMA_VERSION,
        id: AssetId(asset_id.clone()),
        kind: AssetKind::Service,
        identity: service_asset_identity(&target.parent_port_asset_id, &protocol, tls),
        attributes: BTreeMap::from([
            ("protocol".to_owned(), protocol.clone()),
            ("service".to_owned(), label.clone()),
            ("transport".to_owned(), "tcp".to_owned()),
            ("port".to_owned(), target.port.to_string()),
            ("address".to_owned(), target.address.to_string()),
            ("confidence".to_owned(), confidence.to_string()),
        ]),
        first_seen: started_at,
        last_seen: started_at,
        provenance: provenance.clone(),
    });
    if let Some(banner_text) = &banner {
        push_event(
            &mut events,
            EventKind::BannerObserved,
            Some(AssetId(asset_id.clone())),
            serde_json::json!({
                "target": target.target_label,
                "address": target.address.to_string(),
                "port": target.port,
                "protocol": protocol,
                "banner": banner_text,
            }),
            provenance,
        )?;
    }
    if protocol != "unknown" {
        let mut identified = Event::new(
            EventKind::ServiceIdentified,
            Some(AssetId(asset_id.clone())),
            BoundedDetails::from_value(
                serde_json::json!({
                    "target": target.target_label,
                    "address": target.address.to_string(),
                    "port": target.port,
                    "protocol": protocol,
                    "service": label,
                    "tls": tls,
                    "product_hint": product,
                    "version_hint": version,
                    "confidence": confidence,
                    "matcher": matched_by,
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
        identified.relationships.push(
            Relationship::new(
                RelationshipKind::Runs,
                RelationshipSubject::Asset(AssetId(target.parent_port_asset_id.clone())),
                RelationshipSubject::Asset(AssetId(asset_id.clone())),
                provenance.clone(),
            )
            .map_err(|_| ModuleError::Failed {
                message: "invalid relationship".to_owned(),
                retryable: false,
            })?,
        );
        events.push(identified);
        if tls {
            push_event(
                &mut events,
                EventKind::TlsObserved,
                Some(AssetId(asset_id.clone())),
                serde_json::json!({
                    "target": target.target_label,
                    "service": label,
                    "version": tls_observation.as_ref().map(|observation| observation.negotiated_version.clone()),
                    "cipher": tls_observation.as_ref().map(|observation| observation.cipher_suite.clone()),
                }),
                provenance,
            )?;
        }
        if protocol == "http" {
            push_event(
                &mut events,
                EventKind::HttpObserved,
                Some(AssetId(asset_id.clone())),
                serde_json::json!({
                    "target": target.target_label,
                    "service": label,
                    "product_hint": product,
                }),
                provenance,
            )?;
        }
    }
    // Observation evidence (always — unknowns included, silence noted).
    let confidence_checked = Confidence::new(confidence).map_err(|_| ModuleError::Failed {
        message: "invalid confidence".to_owned(),
        retryable: false,
    })?;
    let details = BoundedDetails::from_value(
        serde_json::json!(&observation),
        crate::model::MAX_EVIDENCE_DETAILS_BYTES,
    )
    .map_err(|_| ModuleError::Failed {
        message: "evidence details too large".to_owned(),
        retryable: false,
    })?;
    let evidence = Evidence::new(
        SERVICE_MODULE_NAME,
        AssetId(asset_id.clone()),
        details,
        confidence_checked,
        provenance.clone(),
    )
    .map_err(|_| ModuleError::Failed {
        message: "invalid evidence".to_owned(),
        retryable: false,
    })?;
    let evidence_id = evidence.id.clone();
    evidence_items.push(evidence);
    if protocol != "unknown" {
        let mut finding = Finding::new(
            format!("{label} service on port {}", target.port),
            Severity::Info,
            confidence_checked,
            AssetId(asset_id.clone()),
            provenance.clone(),
        )
        .map_err(|_| ModuleError::Failed {
            message: "invalid finding".to_owned(),
            retryable: false,
        })?;
        finding.evidence_ids.push(evidence_id);
        finding.metadata.insert(
            "protocol".to_owned(),
            serde_json::Value::String(protocol.clone()),
        );
        finding.metadata.insert(
            "service".to_owned(),
            serde_json::Value::String(label.clone()),
        );
        finding
            .metadata
            .insert("port".to_owned(), serde_json::Value::from(target.port));
        finding.metadata.insert(
            "address".to_owned(),
            serde_json::Value::String(target.address.to_string()),
        );
        if let Some(matcher) = matched_by.as_deref() {
            finding.metadata.insert(
                "matcher".to_owned(),
                serde_json::Value::String(matcher.to_owned()),
            );
        }
        if let Some(product) = product {
            finding
                .metadata
                .insert("product".to_owned(), serde_json::Value::String(product));
        }
        findings.push(finding);
    }
    let _ = cert_facts;
    push_event(
        &mut events,
        EventKind::ServiceProbeCompleted,
        Some(AssetId(asset_id)),
        serde_json::json!({
            "target": target.target_label,
            "address": target.address.to_string(),
            "port": target.port,
            "protocol": protocol,
            "service": label,
            "confidence": confidence,
            "matcher": matched_by,
            "attempts": attempt_log,
            "truncated": truncated,
            "connections_opened": connections_opened,
            "probes_attempted": probes_executed,
            "writes": writes,
            "bytes_written": bytes_written,
            "bytes_read": bytes_read,
            "policy": policy.describe(),
            "elapsed_ms": start_instant.elapsed().as_millis() as u64,
        }),
        provenance,
    )?;
    Ok((events, evidence_items, findings, assets))
}

fn emit_attempt_event(
    events: &mut Vec<Event>,
    attempt: &ProbeAttempt,
    target: &ServiceTarget,
    provenance: &Provenance,
) -> Result<(), ModuleError> {
    let kind = if attempt.classified() {
        EventKind::ProtocolDetected
    } else if attempt
        .evidence
        .iter()
        .any(|line| line.contains("timed out"))
    {
        EventKind::ServiceProbeTimedOut
    } else {
        EventKind::ServiceProbeUnavailable
    };
    push_event(
        events,
        kind,
        Some(AssetId(target.parent_port_asset_id.clone())),
        serde_json::json!({
            "target": target.target_label,
            "address": target.address.to_string(),
            "port": target.port,
            "probe": attempt.probe_id,
            "protocol": attempt.protocol,
            "confidence": attempt.confidence,
            "evidence": attempt.evidence,
        }),
        provenance,
    )
}

fn emit_tls_observed(
    events: &mut Vec<Event>,
    observation: &crate::tls::TlsObservation,
    target: &ServiceTarget,
    provenance: &Provenance,
) -> Result<(), ModuleError> {
    push_event(
        events,
        EventKind::TlsObserved,
        Some(AssetId(target.parent_port_asset_id.clone())),
        serde_json::json!({
            "target": target.target_label,
            "address": target.address.to_string(),
            "port": target.port,
            "version": observation.negotiated_version,
            "cipher": observation.cipher_suite,
            "chain_len": observation.peer_certs_der.len(),
            "latency_ms": observation.latency.as_millis() as u64,
        }),
        provenance,
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_cert_records(
    assets: &mut Vec<Asset>,
    events: &mut Vec<Event>,
    evidence_items: &mut Vec<Evidence>,
    facts: &CertFacts,
    target: &ServiceTarget,
    provenance: &Provenance,
) -> Result<(), ModuleError> {
    let cert_asset = Asset::child(
        AssetKind::Certificate,
        &AssetId(target.parent_port_asset_id.clone()),
        &facts.fingerprint_sha256,
        provenance.clone(),
    )
    .map_err(|_| ModuleError::Failed {
        message: "invalid certificate asset".to_owned(),
        retryable: false,
    })?;
    let cert_id = cert_asset.id.clone();
    assets.push(cert_asset);
    push_event(
        events,
        EventKind::TlsObserved,
        Some(cert_id.clone()),
        serde_json::json!({
            "target": target.target_label,
            "subject": facts.subject,
            "issuer": facts.issuer,
            "san_dns": facts.san_dns,
            "san_ip": facts.san_ip,
            "not_before": facts.not_before,
            "not_after": facts.not_after,
            "fingerprint_sha256": facts.fingerprint_sha256,
            "hostname_match": facts.hostname_match,
            "hostname_detail": facts.hostname_detail,
        }),
        provenance,
    )?;
    let confidence = Confidence::new(90).map_err(|_| ModuleError::Failed {
        message: "invalid confidence".to_owned(),
        retryable: false,
    })?;
    let details = BoundedDetails::from_value(
        serde_json::json!({
            "target": target.target_label,
            "address": target.address.to_string(),
            "port": target.port,
            "subject": facts.subject,
            "issuer": facts.issuer,
            "san_dns": facts.san_dns,
            "san_ip": facts.san_ip,
            "not_before": facts.not_before,
            "not_after": facts.not_after,
            "fingerprint_sha256": facts.fingerprint_sha256,
            "hostname_match": facts.hostname_match,
            "hostname_detail": facts.hostname_detail,
        }),
        crate::model::MAX_EVIDENCE_DETAILS_BYTES,
    )
    .map_err(|_| ModuleError::Failed {
        message: "evidence details too large".to_owned(),
        retryable: false,
    })?;
    evidence_items.push(
        Evidence::new(
            SERVICE_MODULE_NAME,
            cert_id,
            details,
            confidence,
            provenance.clone(),
        )
        .map_err(|_| ModuleError::Failed {
            message: "invalid evidence".to_owned(),
            retryable: false,
        })?,
    );
    Ok(())
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

/// Count `ServiceIdentified` events across succeeded module outputs.
///
/// Same typed state JSONL serializes; the human summary renders this count
/// so it cannot disagree with machine output.
pub fn count_identified_services(
    module_outputs: &[(crate::execution::TaskId, crate::execution::ModuleOutput)],
) -> usize {
    module_outputs
        .iter()
        .flat_map(|(_, output)| &output.events)
        .filter(|event| matches!(event.kind, crate::model::EventKind::ServiceIdentified))
        .count()
}

/// Whether any completed TCP discovery exists in these outputs.
///
/// Execution truth: "No open TCP ports observed" is only valid after a
/// `PortScanCompleted` event proves meaningful port discovery was actually
/// attempted. Absence of `PortOpen` evidence alone proves nothing (Level 1
/// runs no port tasks at all; failed/skipped tasks leave no completion).
pub fn tcp_scan_completed(
    module_outputs: &[(crate::execution::TaskId, crate::execution::ModuleOutput)],
) -> bool {
    module_outputs
        .iter()
        .flat_map(|(_, output)| &output.events)
        .any(|event| matches!(event.kind, crate::model::EventKind::PortScanCompleted))
}

/// Service-aware human table (ports + service/product columns).
/// Falls back to port-only rows when no service findings exist yet.
///
/// When no open ports exist the message distinguishes a completed scan
/// ("No open TCP ports observed.") from no scan at all (truthful
/// no-discovery message that never implies ports were scanned).
pub fn human_service_table(
    module_outputs: &[(crate::execution::TaskId, crate::execution::ModuleOutput)],
) -> String {
    use std::collections::BTreeMap;
    let mut ports: BTreeMap<(String, u16), ()> = BTreeMap::new();
    let mut services: BTreeMap<(String, u16), (String, String)> = BTreeMap::new();
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
                    ports.insert((address, port), ());
                }
            } else if finding.title.ends_with("service on port")
                || finding.title.contains(" service on port ")
            {
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
                let service = finding
                    .metadata
                    .get("service")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned();
                let product = finding
                    .metadata
                    .get("product")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("-")
                    .to_owned();
                if port > 0 {
                    ports.insert((address.clone(), port), ());
                    services.insert((address, port), (service, product));
                }
            }
        }
    }
    if ports.is_empty() {
        if tcp_scan_completed(module_outputs) {
            return "No open TCP ports observed.".to_owned();
        }
        return "No TCP port discovery was completed; no ports were scanned.".to_owned();
    }
    let mut by_host: BTreeMap<String, Vec<u16>> = BTreeMap::new();
    for (host, port) in ports.keys() {
        by_host.entry(host.clone()).or_default().push(*port);
    }
    let mut lines = Vec::new();
    for (host, mut host_ports) in by_host {
        host_ports.sort_unstable();
        lines.push(format!("HOST {host}"));
        lines.push("PORT      SERVICE     PRODUCT".to_owned());
        for port in host_ports {
            let (service, product) = services
                .get(&(host.clone(), port))
                .cloned()
                .unwrap_or_else(|| ("unknown".to_owned(), "-".to_owned()));
            lines.push(format!("{port}/tcp    {service}    {product}"));
        }
    }
    lines.join("\n")
}
