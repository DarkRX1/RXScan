//! Phase 8 `HttpProbe` scheduler module: bounded web observations.
//!
//! Control path (never bypassed):
//! `Confirmed HTTP/HTTPS Service -> Decision Engine -> WebProbe proposal ->
//! Scope Guard -> Scheduler <-> Speed / Budgets / Backpressure ->
//! Web Probe Module -> Typed Events / Evidence / Web Assets ->
//! Decision Engine boundary (no crawling follow-ups)`.
//!
//! The module records what single request/response exchanges prove —
//! status, headers, cookies (bounded), title, bounded body metadata/sample,
//! redirect chains, TLS/certificate facts — and nothing more. No link
//! following, robots/sitemap traversal, directory discovery, endpoint
//! enumeration, fuzzing, wordlists, or vulnerability scanning.
//!
//! One task carries either an explicit `url` (Decision Engine path) or a
//! bare target (initial lowering path: up to two default roots, plus
//! explicit `target_ports` when the operator named them).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::execution::{
    CancellationToken, Module, ModuleContext, ModuleError, ModuleFuture, ModuleOutput, ScopeGuard,
    TaskKind, TaskScopeTarget,
};
use crate::model::{
    Asset, AssetId, AssetKind, BoundedDetails, Confidence, Event, EventKind, Evidence, Finding,
    MAX_EVENT_DETAILS_BYTES, Provenance, Severity, Timestamp,
};
use crate::probes::parse_cert_facts;
use crate::web::{Scheme, WebPolicy, WebTarget, endpoint_asset_id, endpoint_local_identity};

pub const WEB_MODULE_NAME: &str = "rxscan.http";
pub const WEB_MODULE_VERSION: &str = "8.0.0";

/// Stop starting new work when less than this remains on the task clock.
const WEB_PLANNING_FLOOR: Duration = Duration::from_millis(500);
/// Maximum start URLs per task (explicit URL or default roots).
const MAX_START_URLS: usize = 4;
/// Maximum findings per task (one per distinct HTTP-valid URL).
const MAX_FINDINGS_PER_TASK: usize = 8;
/// Maximum addresses tried per hostname (sorted, deterministic).
const MAX_DIAL_ADDRESSES: usize = 4;

/// Real scheduler module for `TaskKind::HttpProbe`.
pub struct WebProbeModule {
    policy: WebPolicy,
    scope_guard: Arc<dyn ScopeGuard>,
}

impl WebProbeModule {
    pub fn new(policy: WebPolicy, scope_guard: Arc<dyn ScopeGuard>) -> Self {
        Self {
            policy,
            scope_guard,
        }
    }

    pub fn policy(&self) -> &WebPolicy {
        &self.policy
    }
}

impl Module for WebProbeModule {
    fn kind(&self) -> TaskKind {
        TaskKind::HttpProbe
    }

    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let policy = self.policy.clone();
        let guard = self.scope_guard.clone();
        Box::pin(async move { execute_web_probe(&policy, guard.as_ref(), context) })
    }
}

/// Planned start URL with its scope story (for evidence).
#[derive(Debug, Clone)]
pub(crate) struct PlannedStart {
    pub(crate) target: WebTarget,
    pub(crate) origin: String,
}

pub(crate) fn plan_start_urls(
    task: &crate::execution::Task,
    guard: &dyn ScopeGuard,
) -> Result<Vec<PlannedStart>, ModuleError> {
    if let Some(url_text) = task.params.get("url") {
        let target = WebTarget::parse(url_text).map_err(|reason| ModuleError::Failed {
            message: format!("invalid web URL param: {reason}"),
            retryable: false,
        })?;
        return Ok(vec![PlannedStart {
            target,
            origin: "decision-engine proposal".to_owned(),
        }]);
    }
    // Initial lowering path: default roots for the task scope. Explicit
    // operator ports (from `target_ports` params) replace the 80/443
    // defaults so custom-port targets are honored, still bounded.
    let mut starts = Vec::new();
    let explicit_ports: Vec<u16> = task
        .params
        .get("target_ports")
        .map(|list| {
            list.split(',')
                .filter_map(|item| item.trim().parse::<u16>().ok())
                .filter(|port| *port > 0)
                .take(MAX_START_URLS)
                .collect()
        })
        .unwrap_or_default();
    let mut push_roots = |host: String| {
        if explicit_ports.is_empty() {
            for (scheme, port) in [(Scheme::Http, 80u16), (Scheme::Https, 443u16)] {
                if starts.len() >= MAX_START_URLS {
                    break;
                }
                starts.push(PlannedStart {
                    target: WebTarget {
                        scheme,
                        host: host.clone(),
                        port,
                        path: "/".to_owned(),
                        query: None,
                    },
                    origin: "default roots (no explicit URL context)".to_owned(),
                });
            }
        } else {
            for port in &explicit_ports {
                if starts.len() >= MAX_START_URLS {
                    break;
                }
                // Scheme is unknown for a bare port: try plain HTTP; the
                // response (or TLS alert bytes) decides — never the port.
                starts.push(PlannedStart {
                    target: WebTarget {
                        scheme: Scheme::Http,
                        host: host.clone(),
                        port: *port,
                        path: "/".to_owned(),
                        query: None,
                    },
                    origin: "operator explicit port".to_owned(),
                });
            }
        }
    };
    match &task.scope_target {
        TaskScopeTarget::Ip(ip) => push_roots(ip.to_string()),
        TaskScopeTarget::Host(host) => {
            if !guard.permits(&TaskScopeTarget::Host(host.clone())) {
                return Err(ModuleError::Failed {
                    message: "stale scope rejected immediately before network execution".to_owned(),
                    retryable: false,
                });
            }
            push_roots(host.clone());
        }
        TaskScopeTarget::Url(url) => {
            let target = WebTarget::parse(url).map_err(|reason| ModuleError::Failed {
                message: format!("invalid web URL scope: {reason}"),
                retryable: false,
            })?;
            starts.push(PlannedStart {
                target,
                origin: "URL scope target".to_owned(),
            });
        }
        TaskScopeTarget::None => {
            return Err(ModuleError::Failed {
                message: "web task has no network target".to_owned(),
                retryable: false,
            });
        }
    }
    Ok(starts)
}

pub(crate) fn scope_target_for_web_target(target: &WebTarget) -> TaskScopeTarget {
    match target.ip_literal() {
        Some(ip) => TaskScopeTarget::Ip(ip),
        None => TaskScopeTarget::Host(target.host.clone()),
    }
}

#[allow(clippy::too_many_lines)]
fn execute_web_probe(
    policy: &WebPolicy,
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
        WEB_MODULE_NAME,
        WEB_MODULE_VERSION,
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
    let parent_service_asset = task.params.get("parent_service").cloned();

    push_event(
        &mut events,
        EventKind::WebProbeStarted,
        None,
        serde_json::json!({
            "target": target_label,
            "policy": policy.describe(),
        }),
        &provenance,
    )?;

    let starts = plan_start_urls(&task, guard)?;
    let mut observed: Vec<UrlObservation> = Vec::new();
    let mut chain_notes: Vec<String> = Vec::new();
    let mut truncated_any = false;

    for start in starts {
        if cancel.is_cancelled() {
            return Err(ModuleError::Cancelled);
        }
        if task_deadline.saturating_duration_since(Instant::now()) < WEB_PLANNING_FLOOR {
            truncated_any = true;
            chain_notes.push(format!(
                "{}: skipped (task budget exhausted)",
                start.target.canonical()
            ));
            break;
        }
        // Scope gate per start URL, before any byte is sent.
        if !guard.permits(&scope_target_for_web_target(&start.target)) {
            chain_notes.push(format!(
                "{}: out of scope, never contacted ({})",
                start.target.canonical(),
                start.origin
            ));
            push_event(
                &mut events,
                EventKind::RedirectObserved,
                None,
                serde_json::json!({
                    "target": target_label,
                    "url": start.target.canonical(),
                    "followed": false,
                    "reason": "out-of-scope start URL; recorded, never contacted",
                }),
                &provenance,
            )?;
            continue;
        }
        let (mut steps, done_truncated) = fetch_chain(
            &start.target,
            policy,
            guard,
            &target_label,
            &cancel,
            task_deadline,
            &mut events,
            &provenance,
        )?;
        truncated_any |= done_truncated;
        for step in steps.drain(..) {
            chain_notes.push(format!(
                "{} -> {} {}",
                step.url,
                step.status,
                step.location
                    .as_deref()
                    .map(|location| format!("Location: {location}"))
                    .unwrap_or_default()
            ));
            chain_notes.extend(step.notes);
            if step.observation.is_some() && observed.len() >= MAX_FINDINGS_PER_TASK {
                truncated_any = true;
            }
            if let Some(observation) = step.observation {
                observed.push(observation);
            }
        }
        if cancel.is_cancelled() {
            return Err(ModuleError::Cancelled);
        }
    }

    // Materialize assets/evidence/findings for distinct observed URLs.
    let mut seen_urls = BTreeSet::new();
    for observation in &observed {
        if !seen_urls.insert(observation.url.clone()) {
            continue;
        }
        let target = WebTarget::parse(&observation.url).map_err(|_| ModuleError::Failed {
            message: "internal URL re-parse failed".to_owned(),
            retryable: false,
        })?;
        let parent_id = parent_service_asset.clone().unwrap_or_else(|| {
            observation.port_asset_fallback.clone().unwrap_or_else(|| {
                format!(
                    "asset_orphan_{}",
                    observation.address.replace(['.', ':'], "_")
                )
            })
        });
        let (local_identity, identity_truncated) = endpoint_local_identity(&target);
        let endpoint_id = endpoint_asset_id(&target);
        let mut attributes = BTreeMap::from([
            ("url".to_owned(), observation.url.clone()),
            ("scheme".to_owned(), target.scheme.as_str().to_owned()),
            ("status".to_owned(), observation.status.to_string()),
            ("transport".to_owned(), "tcp".to_owned()),
        ]);
        if identity_truncated {
            attributes.insert("identity_truncated".to_owned(), "true".to_owned());
        }
        assets.push(Asset {
            schema_version: crate::model::SCHEMA_VERSION,
            id: AssetId(endpoint_id.clone()),
            kind: AssetKind::Endpoint,
            identity: format!("{parent_id}:{local_identity}"),
            attributes,
            first_seen: started_at,
            last_seen: started_at,
            provenance: provenance.clone(),
        });
        push_event(
            &mut events,
            EventKind::EndpointObserved,
            Some(AssetId(endpoint_id.clone())),
            serde_json::json!({
                "target": target_label,
                "url": observation.url,
                "status": observation.status,
                "service": observation.service,
                "title": observation.title,
            }),
            &provenance,
        )?;
        let confidence = Confidence::new(85).map_err(|_| ModuleError::Failed {
            message: "invalid confidence".to_owned(),
            retryable: false,
        })?;
        let details = BoundedDetails::from_value(
            serde_json::json!({
                "target": target_label,
                "url": observation.url,
                "address": observation.address,
                "port": observation.port,
                "service": observation.service,
                "status": observation.status,
                "reason": observation.reason,
                "server": observation.server,
                "content_type": observation.content_type,
                "location": observation.location,
                "cookies": observation.cookies,
                "title": observation.title,
                "body_bytes": observation.body_bytes,
                "body_truncated": observation.body_truncated,
                "tls": observation.tls_summary,
                "parent_asset_id": parent_id,
                "timestamp": started_at.0,
            }),
            crate::model::MAX_EVIDENCE_DETAILS_BYTES,
        )
        .map_err(|_| ModuleError::Failed {
            message: "evidence details too large".to_owned(),
            retryable: false,
        })?;
        let evidence = Evidence::new(
            WEB_MODULE_NAME,
            AssetId(endpoint_id.clone()),
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
        if findings.len() < MAX_FINDINGS_PER_TASK {
            let mut finding = Finding::new(
                format!("HTTP {} at {}", observation.status, observation.url),
                Severity::Info,
                confidence,
                AssetId(endpoint_id),
                provenance.clone(),
            )
            .map_err(|_| ModuleError::Failed {
                message: "invalid finding".to_owned(),
                retryable: false,
            })?;
            finding.evidence_ids.push(evidence_id);
            finding.metadata.insert(
                "url".to_owned(),
                serde_json::Value::String(observation.url.clone()),
            );
            finding.metadata.insert(
                "status".to_owned(),
                serde_json::Value::from(observation.status),
            );
            finding.metadata.insert(
                "service".to_owned(),
                serde_json::Value::String(observation.service.clone()),
            );
            findings.push(finding);
        }
        // TLS certificate asset for HTTPS observations (parented under the
        // endpoint for per-URL evidence locality).
        if let Some(cert) = &observation.cert {
            let cert_asset = Asset::child(
                AssetKind::Certificate,
                &AssetId(
                    assets
                        .last()
                        .map(|asset| asset.id.0.clone())
                        .unwrap_or_default(),
                ),
                &cert.fingerprint_sha256,
                provenance.clone(),
            )
            .map_err(|_| ModuleError::Failed {
                message: "invalid certificate asset".to_owned(),
                retryable: false,
            })?;
            let cert_id = cert_asset.id.clone();
            assets.push(cert_asset);
            push_event(
                &mut events,
                EventKind::TlsObserved,
                Some(cert_id.clone()),
                serde_json::json!({
                    "target": target_label,
                    "url": observation.url,
                    "subject": cert.subject,
                    "issuer": cert.issuer,
                    "fingerprint_sha256": cert.fingerprint_sha256,
                    "hostname_match": cert.hostname_match,
                }),
                &provenance,
            )?;
            let cert_details = BoundedDetails::from_value(
                serde_json::json!({
                    "target": target_label,
                    "url": observation.url,
                    "subject": cert.subject,
                    "issuer": cert.issuer,
                    "san_dns": cert.san_dns,
                    "san_ip": cert.san_ip,
                    "not_before": cert.not_before,
                    "not_after": cert.not_after,
                    "fingerprint_sha256": cert.fingerprint_sha256,
                    "hostname_match": cert.hostname_match,
                    "hostname_detail": cert.hostname_detail,
                }),
                crate::model::MAX_EVIDENCE_DETAILS_BYTES,
            )
            .map_err(|_| ModuleError::Failed {
                message: "evidence details too large".to_owned(),
                retryable: false,
            })?;
            evidence_items.push(
                Evidence::new(
                    WEB_MODULE_NAME,
                    cert_id,
                    cert_details,
                    confidence,
                    provenance.clone(),
                )
                .map_err(|_| ModuleError::Failed {
                    message: "invalid evidence".to_owned(),
                    retryable: false,
                })?,
            );
        }
    }

    push_event(
        &mut events,
        EventKind::WebProbeCompleted,
        None,
        serde_json::json!({
            "target": target_label,
            "policy": policy.describe(),
            "observations": observed.len(),
            "chain": chain_notes,
            "truncated": truncated_any,
            "elapsed_ms": start_instant.elapsed().as_millis() as u64,
        }),
        &provenance,
    )?;
    Ok(ModuleOutput {
        events,
        evidence: evidence_items,
        findings,
        assets,
    })
}

/// One fetched step: URL, optional classified observation, redirect signal,
/// and human-readable notes for steps that produced no observation.
struct ChainStep {
    url: String,
    status: u16,
    location: Option<String>,
    observation: Option<UrlObservation>,
    notes: Vec<String>,
}

/// Classified per-URL observation (HTTP-valid responses only).
#[derive(Debug, Clone)]
struct UrlObservation {
    url: String,
    address: String,
    port: u16,
    service: String,
    status: u16,
    reason: String,
    server: Option<String>,
    content_type: Option<String>,
    location: Option<String>,
    cookies: Vec<crate::web::ObservedCookie>,
    title: Option<String>,
    body_bytes: usize,
    body_truncated: bool,
    tls_summary: Option<serde_json::Value>,
    cert: Option<crate::probes::CertFacts>,
    port_asset_fallback: Option<String>,
}

/// Follow one start URL through its bounded redirect chain. Every hop is
/// scope-checked before contact; visited URLs stop loops; malformed
/// destinations, exhausted caps, and out-of-scope hops stop with notes.
/// Never panics.
#[allow(clippy::too_many_arguments)]
fn fetch_chain(
    start: &WebTarget,
    policy: &WebPolicy,
    guard: &dyn ScopeGuard,
    target_label: &str,
    cancel: &CancellationToken,
    task_deadline: Instant,
    events: &mut Vec<Event>,
    provenance: &Provenance,
) -> Result<(Vec<ChainStep>, bool), ModuleError> {
    let mut steps = Vec::new();
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut current = start.clone();
    let mut truncated = false;
    let max_redirects = usize::from(policy.max_redirects());
    loop {
        if cancel.is_cancelled() {
            return Err(ModuleError::Cancelled);
        }
        if task_deadline.saturating_duration_since(Instant::now()) < Duration::from_millis(500) {
            truncated = true;
            break;
        }
        let canonical = current.canonical();
        if !visited.insert(canonical.clone()) {
            push_event(
                events,
                EventKind::RedirectObserved,
                None,
                serde_json::json!({
                    "target": target_label,
                    "url": canonical,
                    "followed": false,
                    "reason": "redirect loop detected (URL already visited)",
                }),
                provenance,
            )?;
            break;
        }
        // Scope gate before every connection.
        if !guard.permits(&scope_target_for_web_target(&current)) {
            push_event(
                events,
                EventKind::RedirectObserved,
                None,
                serde_json::json!({
                    "target": target_label,
                    "url": canonical,
                    "followed": false,
                    "reason": "out-of-scope redirect destination; recorded, never contacted",
                }),
                provenance,
            )?;
            break;
        }
        let step = fetch_single(&current, policy, guard, cancel, task_deadline)?;
        let mut next: Option<WebTarget> = None;
        if let Some(location) = step.location.clone().filter(|_| step.observation.is_some()) {
            if steps.len() >= max_redirects {
                push_event(
                    events,
                    EventKind::RedirectObserved,
                    None,
                    serde_json::json!({
                        "target": target_label,
                        "url": canonical,
                        "location": location,
                        "followed": false,
                        "reason": format!(
                            "redirect cap reached (policy allows {max_redirects}); recorded, not followed"
                        ),
                    }),
                    provenance,
                )?;
            } else {
                match current.resolve_location(&location) {
                    Ok(destination) => {
                        let destination_canonical = destination.canonical();
                        if visited.contains(&destination_canonical) {
                            push_event(
                                events,
                                EventKind::RedirectObserved,
                                None,
                                serde_json::json!({
                                    "target": target_label,
                                    "url": canonical,
                                    "location": location,
                                    "followed": false,
                                    "reason": "redirect loop detected (destination already visited)",
                                }),
                                provenance,
                            )?;
                        } else if !guard.permits(&scope_target_for_web_target(&destination)) {
                            push_event(
                                events,
                                EventKind::RedirectObserved,
                                None,
                                serde_json::json!({
                                    "target": target_label,
                                    "url": canonical,
                                    "location": location,
                                    "destination": destination_canonical,
                                    "followed": false,
                                    "reason": "out-of-scope redirect destination; recorded, never contacted",
                                }),
                                provenance,
                            )?;
                        } else {
                            push_event(
                                events,
                                EventKind::RedirectObserved,
                                None,
                                serde_json::json!({
                                    "target": target_label,
                                    "url": canonical,
                                    "location": location,
                                    "destination": destination_canonical,
                                    "followed": true,
                                    "reason": "in-scope redirect within policy cap",
                                }),
                                provenance,
                            )?;
                            next = Some(destination);
                        }
                    }
                    Err(reason) => {
                        push_event(
                            events,
                            EventKind::RedirectObserved,
                            None,
                            serde_json::json!({
                                "target": target_label,
                                "url": canonical,
                                "location": location,
                                "followed": false,
                                "reason": format!("malformed redirect destination ({reason}); not followed"),
                            }),
                            provenance,
                        )?;
                    }
                }
            }
        }
        steps.push(step);
        if let Some(destination) = next {
            current = destination;
            continue;
        }
        break;
    }
    Ok((steps, truncated))
}

/// Fetch a single URL (no redirect following): resolve, connect, exchange,
/// classify. Malformed responses and connection failures become step notes,
/// never panics, never guesses.
#[allow(clippy::too_many_arguments)]
fn fetch_single(
    target: &WebTarget,
    policy: &WebPolicy,
    guard: &dyn ScopeGuard,
    cancel: &CancellationToken,
    task_deadline: Instant,
) -> Result<ChainStep, ModuleError> {
    let unobserved = |status: u16, location: Option<String>, notes: Vec<String>| ChainStep {
        url: target.canonical(),
        status,
        location,
        observation: None,
        notes,
    };
    // Resolve (scope-filtered); IP literals skip resolution entirely.
    let addresses: Vec<IpAddr> = if let Some(ip) = target.ip_literal() {
        if !guard.permits(&TaskScopeTarget::Ip(ip)) {
            return Ok(unobserved(
                0,
                None,
                vec!["out-of-scope address; never contacted".to_owned()],
            ));
        }
        vec![ip]
    } else {
        let permit = |ip: IpAddr| guard.permits(&TaskScopeTarget::Ip(ip));
        match crate::web::resolve_web_addresses(
            target,
            &permit,
            Duration::from_millis(2000),
            cancel,
        ) {
            Ok(mut addresses) => {
                addresses.truncate(MAX_DIAL_ADDRESSES);
                if addresses.is_empty() {
                    return Ok(unobserved(
                        0,
                        None,
                        vec![
                            "no scannable address (resolution failed or all filtered by scope)"
                                .to_owned(),
                        ],
                    ));
                }
                addresses
            }
            Err(reason) if reason == "cancelled" => return Err(ModuleError::Cancelled),
            Err(reason) => {
                return Ok(unobserved(
                    0,
                    None,
                    vec![format!("address resolution failed ({reason})")],
                ));
            }
        }
    };
    let method = policy.method();
    let read_body = policy.wants_body();
    let connect_timeout = policy.connect_timeout();
    let response_timeout = policy.response_timeout();
    for ip in addresses {
        if cancel.is_cancelled() {
            return Err(ModuleError::Cancelled);
        }
        if Instant::now() >= task_deadline {
            break;
        }
        let started = Instant::now();
        enum Fetched {
            Plain(Vec<u8>),
            Tls(Vec<u8>, crate::tls::TlsObservation, Option<Vec<u8>>),
        }
        let fetched = match target.scheme {
            Scheme::Http => {
                match crate::web::fetch_plain(
                    ip,
                    target,
                    method,
                    read_body,
                    crate::web::MAX_WEB_BODY_BYTES,
                    connect_timeout,
                    response_timeout,
                    cancel,
                    task_deadline,
                ) {
                    Ok(fetch) => {
                        let mut raw = fetch.head;
                        raw.extend_from_slice(&fetch.body);
                        Fetched::Plain(raw)
                    }
                    Err(crate::web::FetchFailure::Cancelled) => return Err(ModuleError::Cancelled),
                    Err(_) => continue,
                }
            }
            Scheme::Https => {
                let server_name = (!target.is_ip_literal()).then_some(target.host.as_str());
                match crate::web::fetch_tls(
                    ip,
                    target,
                    server_name,
                    method,
                    read_body,
                    crate::web::MAX_WEB_BODY_BYTES,
                    connect_timeout,
                    response_timeout,
                    cancel,
                    task_deadline,
                ) {
                    Ok(fetch) => {
                        let mut raw = fetch.head;
                        raw.extend_from_slice(&fetch.body);
                        let leaf = fetch.tls_leaf_der.clone();
                        let observation = fetch.tls.expect("tls fetch carries TLS facts");
                        Fetched::Tls(raw, observation, leaf)
                    }
                    Err(crate::web::FetchFailure::Cancelled) => return Err(ModuleError::Cancelled),
                    Err(_) => continue,
                }
            }
        };
        if cancel.is_cancelled() {
            return Err(ModuleError::Cancelled);
        }
        let latency_ms = started.elapsed().as_millis() as u64;
        let (raw, tls_facts) = match fetched {
            Fetched::Plain(raw) => (raw, None),
            Fetched::Tls(raw, observation, leaf) => {
                let cert = leaf
                    .as_deref()
                    .and_then(|der| parse_cert_facts(der, &target.host));
                (raw, Some((observation, cert)))
            }
        };
        let Some(response) = crate::web::parse_response(&raw, latency_ms) else {
            return Ok(unobserved(
                0,
                None,
                vec![format!(
                    "response from {} is not valid HTTP; recorded, not classified ({} bytes)",
                    target.canonical(),
                    raw.len()
                )],
            ));
        };
        let service = if target.scheme == Scheme::Https {
            "https"
        } else {
            "http"
        }
        .to_owned();
        let (tls_summary, cert) = match tls_facts {
            Some((observation, cert)) => (
                Some(serde_json::json!({
                    "version": observation.negotiated_version,
                    "cipher": observation.cipher_suite,
                    "chain_len": observation.peer_certs_der.len(),
                    "latency_ms": observation.latency.as_millis() as u64,
                })),
                cert,
            ),
            None => (None, None),
        };
        return Ok(ChainStep {
            url: target.canonical(),
            status: response.status,
            location: response.location.clone(),
            observation: Some(UrlObservation {
                url: target.canonical(),
                address: ip.to_string(),
                port: target.port,
                service,
                status: response.status,
                reason: response.reason.clone(),
                server: response.server.clone(),
                content_type: response.content_type.clone(),
                location: response.location.clone(),
                cookies: response.cookies.clone(),
                title: response.title.clone(),
                body_bytes: response.body_bytes,
                body_truncated: response.body_truncated,
                tls_summary,
                cert,
                port_asset_fallback: Some(crate::tcp_discovery::port_asset_id(
                    &crate::tcp_discovery::parent_asset_id_for_ip(&ip),
                    "tcp",
                    target.port,
                )),
            }),
            notes: Vec::new(),
        });
    }
    // Every address failed to connect: connection failure is evidence of
    // unreachability for this URL, not a task failure.
    Ok(unobserved(
        0,
        None,
        vec![format!(
            "connection failed for {} (refused, timeout, or unreachable)",
            target.canonical()
        )],
    ))
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
