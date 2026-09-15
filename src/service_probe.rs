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
    CertFacts, ProbeAttempt, ProbeCtx, parse_cert_facts, probe_ftp, probe_generic, probe_http,
    probe_http_inner, probe_mysql, probe_postgres, probe_redis, probe_smtp, probe_smtp_inner,
    probe_ssh, probe_tls,
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
            "service level {} ({:?}): planner ≤{} probes/port, probe budget {}ms",
            self.level,
            self.goal,
            MAX_PROBES_PER_PORT,
            self.probe_budget().as_millis(),
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
    let mut attempt_log: Vec<String> = Vec::new();
    let mut classified: Option<ProbeAttempt> = None;
    // Best unclassified result: the first attempt carrying a banner becomes
    // the observation (unknown + preserved banner), so generic evidence is
    // never silently dropped. Fully silent runs keep the default below.
    let mut fallback: Option<ProbeAttempt> = None;
    let mut cert_facts: Option<CertFacts> = None;
    let mut tls_observation: Option<crate::tls::TlsObservation> = None;
    let mut truncated = false;

    for probe_id in &plan {
        if cancel.is_cancelled() {
            return Err(ModuleError::Cancelled);
        }
        if task_deadline.saturating_duration_since(Instant::now()) < PROBE_PLANNING_FLOOR {
            truncated = true;
            attempt_log.push(format!("{probe_id}: skipped (task budget exhausted)"));
            break;
        }
        let ctx = ProbeCtx {
            ip: target.address,
            port: target.port,
            host_label: &target.target_label,
            timeout: probe_budget,
            deadline: task_deadline,
            cancel: &cancel,
        };
        match probe_id.as_str() {
            "tls" => {
                match probe_tls(&ctx) {
                    crate::probes::TlsProbeOutcome::Cancelled => {
                        return Err(ModuleError::Cancelled);
                    }
                    crate::probes::TlsProbeOutcome::Miss(attempt) => {
                        emit_attempt_event(&mut events, &attempt, &target, &provenance)?;
                        attempt_log.push(format!(
                            "tls: miss ({})",
                            attempt.evidence.first().cloned().unwrap_or_default()
                        ));
                    }
                    crate::probes::TlsProbeOutcome::Established(
                        mut session,
                        observation,
                        leaf_der,
                    ) => {
                        emit_tls_observed(&mut events, &observation, &target, &provenance)?;
                        attempt_log.push(format!(
                            "tls: handshake {} {} ({}ms)",
                            observation.negotiated_version,
                            observation.cipher_suite,
                            observation.latency.as_millis()
                        ));
                        let facts = leaf_der
                            .as_deref()
                            .and_then(|der| parse_cert_facts(der, &target.target_label));
                        if let Some(facts) = facts {
                            emit_cert_records(
                                &mut assets,
                                &mut events,
                                &mut evidence_items,
                                &facts,
                                &target,
                                &provenance,
                            )?;
                            cert_facts = Some(facts);
                        }
                        // Composition: HTTP or SMTP inside the same session when
                        // the port is TLS-likely for it or the plan includes
                        // the probe (planner-driven, never guessed).
                        let (composed, composition_notes) = compose_over_tls(
                            &mut session,
                            &observation,
                            &target,
                            &ctx,
                            &plan,
                            &mut events,
                            &provenance,
                        )?;
                        attempt_log.extend(composition_notes);
                        tls_observation = Some(observation);
                        if let Some(hit) = composed {
                            classified = Some(hit);
                            break;
                        }
                        // Bare TLS stands as the classification.
                        classified = Some(bare_tls_attempt(
                            &tls_observation.clone().unwrap(),
                            cert_facts.clone(),
                        ));
                        break;
                    }
                }
            }
            other => {
                let attempt = run_plain_probe(other, &ctx);
                if cancel.is_cancelled() {
                    return Err(ModuleError::Cancelled);
                }
                emit_attempt_event(&mut events, &attempt, &target, &provenance)?;
                attempt_log.push(format!(
                    "{other}: {}",
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
            }
        }
    }

    if cancel.is_cancelled() {
        return Err(ModuleError::Cancelled);
    }
    if task_deadline.saturating_duration_since(Instant::now()) < Duration::from_millis(50) {
        truncated = true;
    }
    // A banner-bearing unknown result still becomes the observation; only a
    // fully silent run falls back to the default below.
    let result = classified.or(fallback);
    finish_observation(
        result,
        cert_facts,
        tls_observation,
        attempt_log,
        truncated,
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
    let confidence = if cert_facts.is_some() { 90 } else { 75 };
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
        bytes_out: 0,
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
            "attempts": attempt_log,
            "truncated": truncated,
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
