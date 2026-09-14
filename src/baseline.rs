//! Phase 10 baseline web intelligence.
//!
//! This module characterizes confirmed web endpoints and origins with
//! bounded response signatures, conservative normalization, soft-404 /
//! wildcard observations, endpoint classes, parameter inventory, and a small
//! deterministic interestingness score. It does not discover paths from
//! dictionaries, fuzz parameters, submit forms, execute JavaScript, or infer
//! vulnerabilities.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
use crate::web::{Scheme, WebPolicy, WebTarget};

pub const BASELINE_MODULE_NAME: &str = "rxscan.baseline";
pub const BASELINE_MODULE_VERSION: &str = "10.0.0";
pub const MAX_BASELINE_BODY_BYTES: usize = 64 * 1024;
pub const MAX_SYNTHETIC_REQUESTS_PER_ORIGIN: usize = 2;
pub const MAX_ENDPOINT_COMPARISONS: usize = 128;
pub const MAX_DUPLICATE_RELATIONSHIPS: usize = 32;
pub const MAX_PARAMETER_RECORDS: usize = 32;
pub const MAX_BASELINE_FINDINGS: usize = 8;
pub const MAX_ORIGIN_BASELINES: usize = 512;
pub const MAX_BASELINE_SIGNATURE_INDEX: usize = 1024;
pub const MAX_SIMILAR_BUCKET: usize = 8;
const BASELINE_PLANNING_FLOOR: Duration = Duration::from_millis(500);

#[derive(Debug, Clone)]
pub struct BaselinePolicy {
    pub level: u8,
    pub goal: ScanGoal,
    pub speed: SpeedSetting,
}

impl BaselinePolicy {
    pub fn new(level: u8, goal: ScanGoal, speed: SpeedSetting) -> Self {
        Self {
            level: level.clamp(1, 5),
            goal,
            speed,
        }
    }

    pub fn synthetic_samples(&self) -> usize {
        match self.level {
            0..=2 => 0,
            3 => 2,
            _ => 2,
        }
        .min(MAX_SYNTHETIC_REQUESTS_PER_ORIGIN)
    }

    pub fn normalized_signatures(&self) -> bool {
        self.level >= 3
    }

    pub fn similarity(&self) -> bool {
        self.level >= 4
    }

    pub fn interestingness(&self) -> bool {
        self.level >= 5
    }

    pub fn connect_timeout(&self) -> Duration {
        crate::ports::tcp_timeout_for_speed(self.speed)
    }

    pub fn response_timeout(&self) -> Duration {
        crate::service::service_timeout_for_speed(self.speed)
    }

    pub fn web_policy(&self) -> WebPolicy {
        WebPolicy::new(self.level, self.goal, self.speed)
    }

    pub fn describe(&self) -> String {
        format!(
            "baseline level {} ({:?}): synthetic {}, normalized {}, similarity {}, interestingness {}, body cap {}",
            self.level,
            self.goal,
            self.synthetic_samples(),
            self.normalized_signatures(),
            self.similarity(),
            self.interestingness(),
            MAX_BASELINE_BODY_BYTES,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointClass {
    HtmlPage,
    Redirect,
    StaticAsset,
    Script,
    JsonResponse,
    Xml,
    PlainText,
    Binary,
    ErrorPage,
    Soft404Like,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimilarityClass {
    Exact,
    NearDuplicate,
    SimilarTemplate,
    Different,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseSignature {
    pub status: u16,
    pub content_type: String,
    pub content_length: Option<String>,
    pub observed_body_len: usize,
    pub body_len_bucket: String,
    pub raw_sha256: String,
    pub normalized_sha256: String,
    pub title_hash: Option<String>,
    pub header_hash: String,
    pub html_structure_hash: Option<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Soft404Class {
    HardNotFound,
    SoftNotFound,
    WildcardLike,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterRecord {
    pub name: String,
    pub source: String,
    pub method: String,
    pub value_class: String,
}

#[derive(Debug, Clone)]
pub struct OriginBaselineRecord {
    pub origin: String,
    pub normalized_sha256: String,
}

#[derive(Debug, Default)]
struct OriginBaselineState {
    records: BTreeMap<String, OriginBaselineRecord>,
    full: bool,
}

#[derive(Debug, Clone, Default)]
pub struct OriginBaselineRegistry {
    state: Arc<Mutex<OriginBaselineState>>,
}

impl OriginBaselineRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn has(&self, origin: &str) -> bool {
        self.state.lock().unwrap().records.contains_key(origin)
    }

    pub fn get_hashes(&self, origin: &str) -> Option<String> {
        self.state
            .lock()
            .unwrap()
            .records
            .get(origin)
            .map(|record| record.normalized_sha256.clone())
    }

    pub fn remember(&self, origin: String, normalized_sha256: String) {
        let mut state = self.state.lock().unwrap();
        if state.records.contains_key(&origin) {
            state.records.insert(
                origin.clone(),
                OriginBaselineRecord {
                    origin,
                    normalized_sha256,
                },
            );
            return;
        }
        if state.full {
            return;
        }
        state.records.insert(
            origin.clone(),
            OriginBaselineRecord {
                origin,
                normalized_sha256,
            },
        );
        if state.records.len() >= MAX_ORIGIN_BASELINES {
            state.full = true;
        }
    }

    pub fn snapshot(&self) -> Vec<(String, String)> {
        self.state
            .lock()
            .unwrap()
            .records
            .iter()
            .take(MAX_ORIGIN_BASELINES)
            .map(|(origin, record)| (origin.clone(), record.normalized_sha256.clone()))
            .collect()
    }

    pub fn restore(records: &[(String, String)]) -> Result<Self, String> {
        if records.len() > MAX_ORIGIN_BASELINES {
            return Err("too many origin baselines".to_owned());
        }
        let registry = Self::new();
        for (origin, hash) in records {
            if origin.len() > 4096 || hash.len() > 4096 {
                return Err("invalid origin baseline".to_owned());
            }
            registry.remember(origin.clone(), hash.clone());
        }
        Ok(registry)
    }
}

#[derive(Debug, Clone)]
struct SignatureRepresentative {
    url: String,
    asset: AssetId,
    signature: ResponseSignature,
}

#[derive(Debug, Default)]
struct SimilarityRegistryState {
    by_raw: BTreeMap<String, SignatureRepresentative>,
    by_normalized: BTreeMap<String, SignatureRepresentative>,
    by_bucket: BTreeMap<String, Vec<SignatureRepresentative>>,
    inserted: usize,
    full: bool,
}

#[derive(Debug, Clone, Default)]
pub struct BaselineSimilarityRegistry {
    state: Arc<Mutex<SimilarityRegistryState>>,
}

impl BaselineSimilarityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(
        &self,
        url: &str,
        asset: &AssetId,
        signature: &ResponseSignature,
        provenance: &Provenance,
    ) -> Vec<Event> {
        let mut state = self.state.lock().unwrap();
        let mut events = Vec::new();
        let current = SignatureRepresentative {
            url: url.to_owned(),
            asset: asset.clone(),
            signature: signature.clone(),
        };
        if let Some(representative) = state.by_raw.get(&signature.raw_sha256) {
            if representative.url != url {
                if let Some(event) = duplicate_event(
                    url,
                    asset,
                    representative,
                    SimilarityClass::Exact,
                    100,
                    provenance,
                ) {
                    events.push(event);
                }
            }
        } else if let Some(representative) = state.by_normalized.get(&signature.normalized_sha256) {
            if representative.url != url {
                if let Some(event) = duplicate_event(
                    url,
                    asset,
                    representative,
                    SimilarityClass::NearDuplicate,
                    92,
                    provenance,
                ) {
                    events.push(event);
                }
            }
        } else if let Some(bucket) = state.by_bucket.get(&similarity_bucket(signature)) {
            for representative in bucket.iter().take(MAX_SIMILAR_BUCKET) {
                if representative.url == url {
                    continue;
                }
                let (class, confidence) = similarity(signature, &representative.signature);
                if class == SimilarityClass::SimilarTemplate {
                    if let Some(event) =
                        similar_event(url, asset, representative, confidence, provenance)
                    {
                        events.push(event);
                    }
                    break;
                }
            }
        }
        if state.full {
            return events;
        }
        state
            .by_raw
            .entry(signature.raw_sha256.clone())
            .or_insert_with(|| current.clone());
        state
            .by_normalized
            .entry(signature.normalized_sha256.clone())
            .or_insert_with(|| current.clone());
        let bucket = state
            .by_bucket
            .entry(similarity_bucket(signature))
            .or_default();
        if bucket.len() < MAX_SIMILAR_BUCKET && !bucket.iter().any(|entry| entry.url == url) {
            bucket.push(current);
            state.inserted += 1;
        }
        if state.inserted >= MAX_BASELINE_SIGNATURE_INDEX {
            state.full = true;
        }
        events
    }

    pub fn reconstruct_from_outputs(&self, outputs: &[crate::execution::ModuleOutput]) {
        for output in outputs {
            for event in &output.events {
                if !matches!(
                    event.kind,
                    crate::model::EventKind::ResponseSignatureObserved
                ) {
                    continue;
                }
                let Some(url) = event
                    .details
                    .data
                    .get("url")
                    .and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                let Some(signature_value) = event.details.data.get("signature") else {
                    continue;
                };
                let Ok(signature) =
                    serde_json::from_value::<ResponseSignature>(signature_value.clone())
                else {
                    continue;
                };
                let Some(asset) = event.asset_id.as_ref() else {
                    continue;
                };
                let _ = self.observe(url, asset, &signature, &event.provenance);
            }
        }
    }
}

pub fn baseline_task_params(
    url: &WebTarget,
    source_endpoint: &str,
    origin_baseline: bool,
) -> BTreeMap<String, String> {
    let mut params = BTreeMap::new();
    params.insert("url".to_owned(), url.canonical());
    params.insert("target".to_owned(), url.host.clone());
    params.insert("source_endpoint".to_owned(), source_endpoint.to_owned());
    params.insert(
        "origin".to_owned(),
        format!(
            "{}://{}:{}",
            url.scheme.as_str(),
            host_for_url(url),
            url.port
        ),
    );
    if origin_baseline {
        params.insert("origin_baseline".to_owned(), "true".to_owned());
    }
    params
}

fn host_for_url(url: &WebTarget) -> String {
    if url.host.contains(':') && !url.host.starts_with('[') {
        format!("[{}]", url.host)
    } else {
        url.host.clone()
    }
}

pub fn origin_root(url: &WebTarget) -> WebTarget {
    WebTarget {
        scheme: url.scheme,
        host: url.host.clone(),
        port: url.port,
        path: "/".to_owned(),
        query: None,
    }
}

pub fn signature_for_response(
    response: &crate::web::HttpResponse,
    body: &[u8],
) -> ResponseSignature {
    let body = &body[..body.len().min(MAX_BASELINE_BODY_BYTES)];
    let normalized = normalize_body(body);
    let headers = selected_header_fingerprint_input(&response.headers);
    ResponseSignature {
        status: response.status,
        content_type: response.content_type.clone().unwrap_or_default(),
        content_length: response.content_length.clone(),
        observed_body_len: body.len(),
        body_len_bucket: length_bucket(body.len()),
        raw_sha256: sha256_hex(body),
        normalized_sha256: sha256_hex(normalized.as_bytes()),
        title_hash: response
            .title
            .as_deref()
            .map(|title| sha256_hex(title.as_bytes())),
        header_hash: sha256_hex(headers.as_bytes()),
        html_structure_hash: html_structure(body).map(|structure| sha256_hex(structure.as_bytes())),
        truncated: response.body_truncated || body.len() >= MAX_BASELINE_BODY_BYTES,
    }
}

pub fn normalize_body(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body).to_ascii_lowercase();
    let mut out = String::with_capacity(text.len().min(MAX_BASELINE_BODY_BYTES));
    let mut chars = text.chars().peekable();
    let mut last_space = false;
    while let Some(ch) = chars.next() {
        if ch.is_ascii_digit() {
            let mut digits = 1usize;
            while chars.peek().is_some_and(|next| next.is_ascii_digit()) {
                chars.next();
                digits += 1;
            }
            if digits >= 4 {
                out.push_str("<num>");
                last_space = false;
            } else {
                for _ in 0..digits {
                    out.push('0');
                }
                last_space = false;
            }
            continue;
        }
        if ch.is_whitespace() {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
            continue;
        }
        out.push(ch);
        last_space = false;
    }
    let mut normalized = out.trim().to_owned();
    while normalized.contains("> ") || normalized.contains(" <") {
        normalized = normalized.replace("> ", ">").replace(" <", "<");
    }
    normalized
}

pub fn similarity(left: &ResponseSignature, right: &ResponseSignature) -> (SimilarityClass, u8) {
    if left.status != right.status
        || mime_family(&left.content_type) != mime_family(&right.content_type)
    {
        return (SimilarityClass::Different, 90);
    }
    if left.raw_sha256 == right.raw_sha256 {
        return (SimilarityClass::Exact, 100);
    }
    if left.normalized_sha256 == right.normalized_sha256 {
        return (SimilarityClass::NearDuplicate, 92);
    }
    let ratio = len_ratio(left.observed_body_len, right.observed_body_len);
    if ratio >= 85
        && left.observed_body_len.min(right.observed_body_len) >= 256
        && left.body_len_bucket == right.body_len_bucket
        && left.title_hash.is_some()
        && left.title_hash == right.title_hash
        && left.html_structure_hash.is_some()
        && left.html_structure_hash == right.html_structure_hash
    {
        return (SimilarityClass::SimilarTemplate, 78);
    }
    if left.observed_body_len == 0 || right.observed_body_len == 0 {
        return (SimilarityClass::Unknown, 30);
    }
    (SimilarityClass::Different, 80)
}

pub fn classify_endpoint(
    target: &WebTarget,
    response: &crate::web::HttpResponse,
    body: &[u8],
    soft404: bool,
) -> EndpointClass {
    if soft404 {
        return EndpointClass::Soft404Like;
    }
    if (300..400).contains(&response.status) {
        return EndpointClass::Redirect;
    }
    if response.status >= 400 {
        return EndpointClass::ErrorPage;
    }
    let content_type = response
        .content_type
        .clone()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if content_type.contains("json") || looks_json(body) {
        return EndpointClass::JsonResponse;
    }
    if content_type.contains("xml") || looks_xml(body) {
        return EndpointClass::Xml;
    }
    if content_type.contains("javascript") || target.path.ends_with(".js") {
        return EndpointClass::Script;
    }
    if content_type.starts_with("text/plain") {
        return EndpointClass::PlainText;
    }
    if content_type.contains("html") || looks_html(body) {
        return EndpointClass::HtmlPage;
    }
    if content_type.starts_with("image/")
        || content_type.starts_with("font/")
        || content_type.starts_with("application/octet-stream")
    {
        return EndpointClass::Binary;
    }
    if target.path.ends_with(".css")
        || target.path.ends_with(".png")
        || target.path.ends_with(".jpg")
        || target.path.ends_with(".svg")
    {
        return EndpointClass::StaticAsset;
    }
    EndpointClass::Unknown
}

pub fn query_parameters(target: &WebTarget) -> Vec<ParameterRecord> {
    let mut out = Vec::new();
    let Some(query) = &target.query else {
        return out;
    };
    for (name, value) in url::form_urlencoded::parse(query.as_bytes()).take(MAX_PARAMETER_RECORDS) {
        if name.is_empty() {
            continue;
        }
        out.push(ParameterRecord {
            name: name.into_owned(),
            source: "query".to_owned(),
            method: "GET".to_owned(),
            value_class: value_class(&value),
        });
    }
    out
}

pub fn value_class(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    if value.is_empty() {
        "empty".to_owned()
    } else if lower == "true" || lower == "false" || lower == "yes" || lower == "no" {
        "boolean_like".to_owned()
    } else if value.chars().all(|ch| ch.is_ascii_digit()) {
        "numeric".to_owned()
    } else if is_uuid_like(value) {
        "uuid_like".to_owned()
    } else if lower.starts_with("http://") || lower.starts_with("https://") {
        "url_like".to_owned()
    } else if value.contains('/') {
        "path_like".to_owned()
    } else if value.len() <= 32 {
        "short_string".to_owned()
    } else {
        "string".to_owned()
    }
}

pub fn interestingness(
    class: &EndpointClass,
    signature: &ResponseSignature,
    params: &[ParameterRecord],
    source: &str,
) -> (u8, Vec<String>) {
    let mut score = 10u8;
    let mut factors = Vec::new();
    match class {
        EndpointClass::JsonResponse | EndpointClass::Xml => {
            score = score.saturating_add(25);
            factors.push("structured-response".to_owned());
        }
        EndpointClass::Redirect => {
            score = score.saturating_add(8);
            factors.push("redirect".to_owned());
        }
        EndpointClass::ErrorPage | EndpointClass::Soft404Like => {
            score = score.saturating_add(5);
            factors.push("missing-resource-behavior".to_owned());
        }
        EndpointClass::Script => {
            score = score.saturating_add(12);
            factors.push("script".to_owned());
        }
        _ => {}
    }
    if !params.is_empty() {
        score = score.saturating_add(15);
        factors.push("parameters".to_owned());
    }
    if source == "script-literal" {
        score = score.saturating_add(15);
        factors.push("script-referenced".to_owned());
    }
    if signature.observed_body_len > 0 && signature.body_len_bucket != "tiny" {
        score = score.saturating_add(5);
        factors.push("non-empty-content".to_owned());
    }
    (score.min(100), factors)
}

#[derive(Debug)]
struct BaselineFetch {
    target: WebTarget,
    response: crate::web::HttpResponse,
    body: Vec<u8>,
    redirect_out_of_scope: bool,
}

pub struct BaselineModule {
    policy: BaselinePolicy,
    scope_guard: Arc<dyn ScopeGuard>,
    contacts: crate::contact::ContactRegistry,
    similarity: BaselineSimilarityRegistry,
}

impl BaselineModule {
    pub fn new(policy: BaselinePolicy, scope_guard: Arc<dyn ScopeGuard>) -> Self {
        Self {
            policy,
            scope_guard,
            contacts: crate::contact::ContactRegistry::new(),
            similarity: BaselineSimilarityRegistry::new(),
        }
    }

    pub fn with_shared_state(
        policy: BaselinePolicy,
        scope_guard: Arc<dyn ScopeGuard>,
        contacts: crate::contact::ContactRegistry,
        similarity: BaselineSimilarityRegistry,
    ) -> Self {
        Self {
            policy,
            scope_guard,
            contacts,
            similarity,
        }
    }
}

impl Module for BaselineModule {
    fn kind(&self) -> TaskKind {
        TaskKind::Baseline
    }

    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let policy = self.policy.clone();
        let guard = self.scope_guard.clone();
        let contacts = self.contacts.clone();
        let similarity = self.similarity.clone();
        Box::pin(async move {
            execute_baseline(&policy, guard.as_ref(), &contacts, &similarity, context)
        })
    }
}

fn scope_target_for_url(url: &WebTarget) -> TaskScopeTarget {
    match url.ip_literal() {
        Some(ip) => TaskScopeTarget::Ip(ip),
        None => TaskScopeTarget::Host(url.host.clone()),
    }
}

fn execute_baseline(
    policy: &BaselinePolicy,
    guard: &dyn ScopeGuard,
    contacts: &crate::contact::ContactRegistry,
    similarity_registry: &BaselineSimilarityRegistry,
    context: ModuleContext,
) -> Result<ModuleOutput, ModuleError> {
    let task = context.task.clone();
    let cancel = context.cancellation();
    if cancel.is_cancelled() {
        return Err(ModuleError::Cancelled);
    }
    if !guard.permits(&task.scope_target) {
        return Err(ModuleError::Failed {
            message: "stale scope rejected immediately before baseline execution".to_owned(),
            retryable: false,
        });
    }
    let started_at = Timestamp::now();
    let started = Instant::now();
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(task.timeout_ms.max(1)))
        .unwrap_or_else(|| Instant::now() + Duration::from_secs(60));
    let provenance = Provenance::new(
        BASELINE_MODULE_NAME,
        BASELINE_MODULE_VERSION,
        task.scan_plan_id.clone(),
        started_at,
    )
    .map_err(|_| ModuleError::Failed {
        message: "invalid provenance".to_owned(),
        retryable: false,
    })?;
    let url_text = task.params.get("url").ok_or_else(|| ModuleError::Failed {
        message: "baseline task missing url".to_owned(),
        retryable: false,
    })?;
    let target = WebTarget::parse(url_text).map_err(|reason| ModuleError::Failed {
        message: format!("invalid baseline URL: {reason}"),
        retryable: false,
    })?;
    if !guard.permits(&scope_target_for_url(&target)) {
        return Err(ModuleError::Failed {
            message: "baseline target outside scope".to_owned(),
            retryable: false,
        });
    }

    let mut output = ModuleOutput {
        events: Vec::new(),
        evidence: Vec::new(),
        findings: Vec::new(),
        assets: Vec::new(),
    };
    push_event(
        &mut output.events,
        EventKind::BaselineStarted,
        None,
        serde_json::json!({"url": target.canonical(), "policy": policy.describe()}),
        &provenance,
    )?;

    let endpoint_asset = ensure_endpoint_asset(&mut output.assets, &target, &provenance)?;
    let primary = fetch_baseline(
        &target,
        policy,
        guard,
        contacts,
        crate::contact::RequestPurpose::BaselinePrimary,
        &cancel,
        deadline,
    )?;
    let mut primary_signature = None;
    if let Some(fetch) = primary {
        let signature = signature_for_response(&fetch.response, &fetch.body);
        let mut soft404_like = false;
        emit_signature(
            &mut output,
            &endpoint_asset,
            &fetch.target,
            &signature,
            &provenance,
        )?;
        let params = query_parameters(&fetch.target);
        for record in params.iter().take(MAX_PARAMETER_RECORDS) {
            emit_parameter(&mut output, &endpoint_asset, record, &provenance)?;
        }

        let mut synthetic_signatures = Vec::new();
        let origin_baseline = task
            .params
            .get("origin_baseline")
            .is_some_and(|value| value == "true");
        let synthetic_samples = if origin_baseline {
            policy.synthetic_samples()
        } else {
            0
        };
        for index in 0..synthetic_samples {
            if deadline.saturating_duration_since(Instant::now()) < BASELINE_PLANNING_FLOOR {
                push_event(
                    &mut output.events,
                    EventKind::BaselineBudgetExhausted,
                    None,
                    serde_json::json!({"reason": "task-deadline", "url": target.canonical()}),
                    &provenance,
                )?;
                break;
            }
            let synthetic = synthetic_target(&target, &task.id.0, index);
            if !guard.permits(&scope_target_for_url(&synthetic)) {
                continue;
            }
            if let Some(sample) = fetch_baseline(
                &synthetic,
                policy,
                guard,
                contacts,
                crate::contact::RequestPurpose::BaselineSynthetic,
                &cancel,
                deadline,
            )? {
                let sample_sig = signature_for_response(&sample.response, &sample.body);
                synthetic_signatures.push((sample, sample_sig));
            }
        }
        if !synthetic_signatures.is_empty() {
            let soft = classify_soft404(&signature, &synthetic_signatures);
            soft404_like = matches!(
                soft,
                Soft404Class::SoftNotFound | Soft404Class::WildcardLike
            );
            push_event(
                &mut output.events,
                EventKind::OriginBaselineObserved,
                Some(endpoint_asset.clone()),
                serde_json::json!({
                    "origin": origin_root(&target).canonical(),
                    "samples": synthetic_signatures.len(),
                    "normalized_sha256": synthetic_signatures
                        .iter()
                        .map(|(_, signature)| signature.normalized_sha256.as_str())
                        .collect::<Vec<_>>(),
                    "statuses": synthetic_signatures
                        .iter()
                        .map(|(_, signature)| signature.status)
                        .collect::<Vec<_>>(),
                }),
                &provenance,
            )?;
            push_event(
                &mut output.events,
                EventKind::Soft404Observed,
                Some(endpoint_asset.clone()),
                serde_json::json!({
                    "url": target.canonical(),
                    "classification": soft,
                    "samples": synthetic_signatures.len(),
                }),
                &provenance,
            )?;
            if synthetic_signatures.len() >= 2
                && synthetic_signatures
                    .windows(2)
                    .all(|pair| similarity(&pair[0].1, &pair[1].1).0 != SimilarityClass::Different)
            {
                push_event(
                    &mut output.events,
                    EventKind::WildcardBehaviorObserved,
                    Some(endpoint_asset.clone()),
                    serde_json::json!({"origin": origin_root(&target).canonical(), "kind": "uniform_missing_path"}),
                    &provenance,
                )?;
            }
        }
        let final_class =
            classify_endpoint(&fetch.target, &fetch.response, &fetch.body, soft404_like);
        let (score, factors) = if policy.interestingness() {
            interestingness(
                &final_class,
                &signature,
                &params,
                task.params
                    .get("source")
                    .map(String::as_str)
                    .unwrap_or("endpoint"),
            )
        } else {
            (0, Vec::new())
        };
        push_event(
            &mut output.events,
            EventKind::EndpointClassified,
            Some(endpoint_asset.clone()),
            serde_json::json!({
                "url": target.canonical(),
                "class": final_class,
                "interestingness": score,
                "factors": factors,
            }),
            &provenance,
        )?;
        for event in similarity_registry
            .observe(
                &target.canonical(),
                &endpoint_asset,
                &signature,
                &provenance,
            )
            .into_iter()
            .take(MAX_DUPLICATE_RELATIONSHIPS)
        {
            output.events.push(event);
        }
        let evidence = Evidence::new(
            BASELINE_MODULE_NAME,
            endpoint_asset.clone(),
            BoundedDetails::from_value(
                serde_json::json!({
                    "url": target.canonical(),
                    "signature": signature,
                    "class": final_class,
                    "parameters": params,
                    "redirect_out_of_scope": fetch.redirect_out_of_scope,
                }),
                crate::model::MAX_EVIDENCE_DETAILS_BYTES,
            )
            .map_err(|_| ModuleError::Failed {
                message: "baseline evidence too large".to_owned(),
                retryable: false,
            })?,
            Confidence::new(80).map_err(|_| ModuleError::Failed {
                message: "invalid confidence".to_owned(),
                retryable: false,
            })?,
            provenance.clone(),
        )
        .map_err(|_| ModuleError::Failed {
            message: "invalid evidence".to_owned(),
            retryable: false,
        })?;
        output.evidence.push(evidence);
        primary_signature = Some(signature);
        if output.findings.len() < MAX_BASELINE_FINDINGS {
            output.findings.push(
                Finding::new(
                    format!("Baseline intelligence for {}", target.canonical()),
                    Severity::Info,
                    Confidence::new(70).unwrap(),
                    endpoint_asset.clone(),
                    provenance.clone(),
                )
                .map_err(|_| ModuleError::Failed {
                    message: "invalid finding".to_owned(),
                    retryable: false,
                })?,
            );
        }
    }
    push_event(
        &mut output.events,
        EventKind::BaselineCompleted,
        None,
        serde_json::json!({
            "url": target.canonical(),
            "elapsed_ms": started.elapsed().as_millis() as u64,
            "has_signature": primary_signature.is_some(),
        }),
        &provenance,
    )?;
    Ok(output)
}

fn classify_soft404(
    primary: &ResponseSignature,
    synthetic: &[(BaselineFetch, ResponseSignature)],
) -> Soft404Class {
    if synthetic
        .iter()
        .all(|(_, sig)| sig.status == 404 || sig.status == 410)
    {
        return Soft404Class::HardNotFound;
    }
    if synthetic.len() < 2 {
        return Soft404Class::Inconclusive;
    }
    let uniform_missing = synthetic
        .windows(2)
        .all(|pair| similarity(&pair[0].1, &pair[1].1).0 != SimilarityClass::Different);
    if !uniform_missing {
        return Soft404Class::Inconclusive;
    }
    if synthetic
        .iter()
        .all(|(_, sig)| (300..400).contains(&sig.status))
    {
        return Soft404Class::WildcardLike;
    }
    if synthetic.iter().all(|(_, sig)| sig.status == 200) {
        let similar_to_primary = synthetic
            .iter()
            .any(|(_, sig)| similarity(primary, sig).0 != SimilarityClass::Different);
        return if similar_to_primary {
            Soft404Class::SoftNotFound
        } else {
            Soft404Class::WildcardLike
        };
    }
    Soft404Class::Inconclusive
}

fn synthetic_target(root: &WebTarget, task_id: &str, index: usize) -> WebTarget {
    let token = sha256_hex(format!("{task_id}:{index}:rxscan-baseline").as_bytes());
    WebTarget {
        scheme: root.scheme,
        host: root.host.clone(),
        port: root.port,
        path: format!("/__rxscan_baseline_{}__", &token[..16]),
        query: None,
    }
}

fn fetch_baseline(
    start: &WebTarget,
    policy: &BaselinePolicy,
    guard: &dyn ScopeGuard,
    contacts: &crate::contact::ContactRegistry,
    purpose: crate::contact::RequestPurpose,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<Option<BaselineFetch>, ModuleError> {
    let mut current = start.clone();
    let mut visited = BTreeSet::new();
    let mut redirect_out_of_scope = false;
    for _ in 0..=policy.web_policy().max_redirects() {
        if cancel.is_cancelled() {
            return Err(ModuleError::Cancelled);
        }
        if !guard.permits(&scope_target_for_url(&current)) {
            return Ok(None);
        }
        if !visited.insert(current.canonical()) {
            return Ok(None);
        }
        let hop_purpose = if visited.len() == 1 {
            purpose
        } else {
            crate::contact::RequestPurpose::RedirectFollow
        };
        if !contacts.claim(&current, hop_purpose) {
            return Ok(None);
        }
        let addresses = resolve_addresses(&current, guard, cancel)?;
        let mut fetched = None;
        for ip in addresses {
            let remaining = deadline
                .saturating_duration_since(Instant::now())
                .min(policy.response_timeout());
            let result = match current.scheme {
                Scheme::Http => crate::web::fetch_plain(
                    ip,
                    &current,
                    "GET",
                    true,
                    MAX_BASELINE_BODY_BYTES,
                    policy.connect_timeout(),
                    remaining,
                    cancel,
                    deadline,
                ),
                Scheme::Https => crate::web::fetch_tls(
                    ip,
                    &current,
                    (!current.is_ip_literal()).then_some(current.host.as_str()),
                    "GET",
                    true,
                    MAX_BASELINE_BODY_BYTES,
                    policy.connect_timeout(),
                    remaining,
                    cancel,
                    deadline,
                ),
            };
            match result {
                Ok(raw) => {
                    fetched = Some(raw);
                    break;
                }
                Err(crate::web::FetchFailure::Cancelled) => return Err(ModuleError::Cancelled),
                Err(_) => continue,
            }
        }
        let Some(raw_fetch) = fetched else {
            return Ok(None);
        };
        let mut raw = raw_fetch.head.clone();
        raw.extend_from_slice(&raw_fetch.body);
        let Some(response) = crate::web::parse_response(&raw, raw_fetch.latency_ms) else {
            return Ok(None);
        };
        if response.is_redirect() {
            if let Some(location) = response.location.as_deref() {
                let Ok(next) = current.resolve_location(location) else {
                    return Ok(Some(BaselineFetch {
                        target: current,
                        response,
                        body: raw_fetch.body,
                        redirect_out_of_scope,
                    }));
                };
                if !guard.permits(&scope_target_for_url(&next)) {
                    redirect_out_of_scope = true;
                    return Ok(Some(BaselineFetch {
                        target: current,
                        response,
                        body: raw_fetch.body,
                        redirect_out_of_scope,
                    }));
                }
                current = next;
                continue;
            }
        }
        return Ok(Some(BaselineFetch {
            target: current,
            response,
            body: raw_fetch.body,
            redirect_out_of_scope,
        }));
    }
    Ok(None)
}

fn resolve_addresses(
    target: &WebTarget,
    guard: &dyn ScopeGuard,
    cancel: &CancellationToken,
) -> Result<Vec<IpAddr>, ModuleError> {
    if let Some(ip) = target.ip_literal() {
        return Ok(if guard.permits(&TaskScopeTarget::Ip(ip)) {
            vec![ip]
        } else {
            Vec::new()
        });
    }
    let permit = |ip: IpAddr| guard.permits(&TaskScopeTarget::Ip(ip));
    crate::web::resolve_web_addresses(target, &permit, Duration::from_secs(2), cancel).map_err(
        |reason| {
            if reason == "cancelled" {
                ModuleError::Cancelled
            } else {
                ModuleError::Failed {
                    message: reason,
                    retryable: true,
                }
            }
        },
    )
}

fn ensure_endpoint_asset(
    assets: &mut Vec<Asset>,
    url: &WebTarget,
    provenance: &Provenance,
) -> Result<AssetId, ModuleError> {
    let id = AssetId(crate::web::endpoint_asset_id(url));
    if !assets.iter().any(|asset| asset.id == id) {
        let (identity, truncated) = crate::web::endpoint_local_identity(url);
        let mut attributes = BTreeMap::from([("url".to_owned(), url.canonical())]);
        if truncated {
            attributes.insert("identity_truncated".to_owned(), "true".to_owned());
        }
        assets.push(Asset {
            schema_version: crate::model::SCHEMA_VERSION,
            id: id.clone(),
            kind: AssetKind::Endpoint,
            identity,
            attributes,
            first_seen: provenance.timestamp,
            last_seen: provenance.timestamp,
            provenance: provenance.clone(),
        });
    }
    Ok(id)
}

fn emit_signature(
    output: &mut ModuleOutput,
    asset: &AssetId,
    url: &WebTarget,
    signature: &ResponseSignature,
    provenance: &Provenance,
) -> Result<(), ModuleError> {
    push_event(
        &mut output.events,
        EventKind::ResponseSignatureObserved,
        Some(asset.clone()),
        serde_json::json!({"url": url.canonical(), "signature": signature}),
        provenance,
    )
}

fn emit_parameter(
    output: &mut ModuleOutput,
    asset: &AssetId,
    record: &ParameterRecord,
    provenance: &Provenance,
) -> Result<(), ModuleError> {
    let mut event = Event::new(
        EventKind::ParameterObserved,
        Some(asset.clone()),
        BoundedDetails::from_value(serde_json::json!(record), MAX_EVENT_DETAILS_BYTES).map_err(
            |_| ModuleError::Failed {
                message: "parameter event too large".to_owned(),
                retryable: false,
            },
        )?,
        provenance.clone(),
    )
    .map_err(|_| ModuleError::Failed {
        message: "invalid parameter event".to_owned(),
        retryable: false,
    })?;
    event.relationships.push(
        Relationship::new(
            RelationshipKind::ParameterOf,
            RelationshipSubject::Asset(AssetId(format!(
                "asset_param_{}",
                sha256_hex(record.name.as_bytes())
            ))),
            RelationshipSubject::Asset(asset.clone()),
            provenance.clone(),
        )
        .map_err(|_| ModuleError::Failed {
            message: "invalid parameter relationship".to_owned(),
            retryable: false,
        })?,
    );
    output.events.push(event);
    Ok(())
}

fn similarity_bucket(signature: &ResponseSignature) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        signature.status,
        mime_family(&signature.content_type),
        signature.body_len_bucket,
        signature.title_hash.as_deref().unwrap_or(""),
        signature.html_structure_hash.as_deref().unwrap_or("")
    )
}

fn duplicate_event(
    url: &str,
    asset: &AssetId,
    representative: &SignatureRepresentative,
    class: SimilarityClass,
    confidence: u8,
    provenance: &Provenance,
) -> Option<Event> {
    let mut event = Event::new(
        EventKind::DuplicateObserved,
        Some(asset.clone()),
        BoundedDetails::from_value(
            serde_json::json!({
                "url": url,
                "representative_url": representative.url,
                "class": class,
                "confidence": confidence,
            }),
            MAX_EVENT_DETAILS_BYTES,
        )
        .ok()?,
        provenance.clone(),
    )
    .ok()?;
    event.relationships.push(
        Relationship::new(
            RelationshipKind::DuplicateOf,
            RelationshipSubject::Asset(asset.clone()),
            RelationshipSubject::Asset(representative.asset.clone()),
            provenance.clone(),
        )
        .ok()?,
    );
    Some(event)
}

fn similar_event(
    url: &str,
    asset: &AssetId,
    representative: &SignatureRepresentative,
    confidence: u8,
    provenance: &Provenance,
) -> Option<Event> {
    let mut event = Event::new(
        EventKind::SimilarResponseObserved,
        Some(asset.clone()),
        BoundedDetails::from_value(
            serde_json::json!({
                "url": url,
                "representative_url": representative.url,
                "class": SimilarityClass::SimilarTemplate,
                "confidence": confidence,
            }),
            MAX_EVENT_DETAILS_BYTES,
        )
        .ok()?,
        provenance.clone(),
    )
    .ok()?;
    event.relationships.push(
        Relationship::new(
            RelationshipKind::SimilarTo,
            RelationshipSubject::Asset(asset.clone()),
            RelationshipSubject::Asset(representative.asset.clone()),
            provenance.clone(),
        )
        .ok()?,
    );
    Some(event)
}

fn push_event(
    events: &mut Vec<Event>,
    kind: EventKind,
    asset_id: Option<AssetId>,
    data: serde_json::Value,
    provenance: &Provenance,
) -> Result<(), ModuleError> {
    events.push(
        Event::new(
            kind,
            asset_id,
            BoundedDetails::from_value(data, MAX_EVENT_DETAILS_BYTES).map_err(|_| {
                ModuleError::Failed {
                    message: "event details too large".to_owned(),
                    retryable: false,
                }
            })?,
            provenance.clone(),
        )
        .map_err(|_| ModuleError::Failed {
            message: "invalid event".to_owned(),
            retryable: false,
        })?,
    );
    Ok(())
}

fn selected_header_fingerprint_input(headers: &[(String, String)]) -> String {
    let mut selected = headers
        .iter()
        .filter(|(name, _)| {
            matches!(
                name.to_ascii_lowercase().as_str(),
                "content-type" | "location" | "server" | "x-powered-by"
            )
        })
        .map(|(name, value)| format!("{}:{}", name.to_ascii_lowercase(), value.trim()))
        .collect::<Vec<_>>();
    selected.sort();
    selected.join("\n")
}

fn html_structure(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body).to_ascii_lowercase();
    if !text.contains('<') {
        return None;
    }
    let mut tags = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() && tags.len() < 128 {
        if bytes[index] != b'<' {
            index += 1;
            continue;
        }
        index += 1;
        if index < bytes.len() && bytes[index] == b'/' {
            index += 1;
        }
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_alphanumeric() {
            index += 1;
        }
        if index > start {
            tags.push(&text[start..index]);
        }
    }
    (!tags.is_empty()).then(|| tags.join(">"))
}

fn length_bucket(len: usize) -> String {
    match len {
        0 => "empty",
        1..=255 => "tiny",
        256..=2047 => "small",
        2048..=16383 => "medium",
        _ => "large",
    }
    .to_owned()
}

fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn mime_family(content_type: &str) -> &str {
    content_type.split(';').next().unwrap_or("").trim()
}

fn len_ratio(left: usize, right: usize) -> u8 {
    if left == 0 && right == 0 {
        return 100;
    }
    let min = left.min(right) as f64;
    let max = left.max(right) as f64;
    ((min / max) * 100.0) as u8
}

fn looks_html(body: &[u8]) -> bool {
    String::from_utf8_lossy(&body[..body.len().min(256)])
        .to_ascii_lowercase()
        .contains("<html")
}

fn looks_json(body: &[u8]) -> bool {
    let text = String::from_utf8_lossy(&body[..body.len().min(128)]);
    let trimmed = text.trim_start();
    trimmed.starts_with('{') || trimmed.starts_with('[')
}

fn looks_xml(body: &[u8]) -> bool {
    let text = String::from_utf8_lossy(&body[..body.len().min(128)]);
    let trimmed = text.trim_start();
    trimmed.starts_with("<?xml") || trimmed.starts_with('<') && !looks_html(body)
}

fn is_uuid_like(value: &str) -> bool {
    let parts = value.split('-').map(str::len).collect::<Vec<_>>();
    parts == [8, 4, 4, 4, 12] && value.chars().all(|ch| ch == '-' || ch.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response_for(status: u16, content_type: &str, body: &[u8]) -> crate::web::HttpResponse {
        crate::web::parse_response(
            format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                String::from_utf8_lossy(body)
            )
            .as_bytes(),
            1,
        )
        .unwrap()
    }

    #[test]
    fn signatures_are_deterministic_and_normalize_conservatively() {
        let a = response_for(200, "text/html", b"<html>  ID 12345 </html>");
        let b = response_for(200, "text/html", b"<html>ID 99999</html>");
        let sig_a = signature_for_response(&a, b"<html>  ID 12345 </html>");
        let sig_b = signature_for_response(&b, b"<html>ID 99999</html>");
        assert_ne!(sig_a.raw_sha256, sig_b.raw_sha256);
        assert_eq!(sig_a.normalized_sha256, sig_b.normalized_sha256);
        assert_eq!(
            sig_a,
            signature_for_response(&a, b"<html>  ID 12345 </html>")
        );
    }

    #[test]
    fn similarity_thresholds_are_stable() {
        let a = signature_for_response(&response_for(200, "text/html", b"same"), b"same");
        let b = signature_for_response(&response_for(200, "text/html", b"same"), b"same");
        let c = signature_for_response(&response_for(200, "text/html", b"different"), b"different");
        assert_eq!(similarity(&a, &b).0, SimilarityClass::Exact);
        assert_eq!(similarity(&a, &c).0, SimilarityClass::Different);
    }

    #[test]
    fn template_similarity_requires_enough_body_material() {
        let left_body = format!(
            "<html><title>Catalog</title><main>{}</main></html>",
            "product alpha ".repeat(32)
        );
        let right_body = format!(
            "<html><title>Catalog</title><main>{}</main></html>",
            "product beta ".repeat(32)
        );
        let left = signature_for_response(
            &response_for(200, "text/html", left_body.as_bytes()),
            left_body.as_bytes(),
        );
        let right = signature_for_response(
            &response_for(200, "text/html", right_body.as_bytes()),
            right_body.as_bytes(),
        );
        assert_eq!(
            similarity(&left, &right).0,
            SimilarityClass::SimilarTemplate
        );
    }

    #[test]
    fn endpoint_classification_uses_evidence_not_path_only() {
        let json = response_for(200, "application/json", br#"{"ok":true}"#);
        let html = response_for(200, "text/html", b"<html><title>x</title></html>");
        let js = response_for(200, "application/javascript", b"console.log(1)");
        let target = WebTarget::parse("http://example.test:80/api").unwrap();
        assert_eq!(
            classify_endpoint(&target, &json, br#"{"ok":true}"#, false),
            EndpointClass::JsonResponse
        );
        assert_eq!(
            classify_endpoint(&target, &html, b"<html></html>", false),
            EndpointClass::HtmlPage
        );
        assert_eq!(
            classify_endpoint(&target, &js, b"console.log(1)", false),
            EndpointClass::Script
        );
    }

    #[test]
    fn parameter_values_are_classified_without_mutation() {
        let target =
            WebTarget::parse("http://example.test:80/a?id=123&on=true&next=%2Fhome").unwrap();
        let params = query_parameters(&target);
        assert_eq!(params[0].value_class, "numeric");
        assert_eq!(params[1].value_class, "boolean_like");
        assert_eq!(params[2].value_class, "path_like");
    }
}
