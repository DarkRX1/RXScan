//! Phase 12 contextual fuzzing.
//!
//! This module mutates only already-observed safe GET query parameters. It is
//! behavioral reconnaissance, not exploit fuzzing: no payload banks, POST
//! submission, credential attacks, traversal, injection strings, or recursive
//! self-scheduling.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    baseline::{ResponseSignature, SimilarityClass, signature_for_response, similarity},
    execution::{
        CancellationToken, Module, ModuleContext, ModuleError, ModuleFuture, ModuleOutput,
        ScopeGuard, TaskKind, TaskScopeTarget,
    },
    model::{
        Asset, AssetId, AssetKind, BoundedDetails, Confidence, Event, EventKind, Evidence, Finding,
        MAX_EVENT_DETAILS_BYTES, Provenance, Relationship, RelationshipKind, RelationshipSubject,
        Severity, Timestamp,
    },
    plan::{ScanGoal, SpeedSetting},
    web::{Scheme, WebPolicy, WebTarget},
};

pub const FUZZ_MODULE_NAME: &str = "rxscan.fuzz";
pub const FUZZ_MODULE_VERSION: &str = "12.0.0";
pub const MAX_FUZZ_PARAMS_PER_ENDPOINT: usize = 4;
pub const MAX_MUTATIONS_PER_PARAM: usize = 4;
pub const MAX_MUTATIONS_PER_TASK: usize = 8;
pub const MAX_FUZZ_REQUESTS_PER_TASK: usize = 8;
pub const MAX_FUZZ_RESPONSE_BYTES: usize = 64 * 1024;
pub const MAX_FUZZ_EVENTS: usize = 64;
pub const MAX_FUZZ_EVIDENCE: usize = 16;
pub const MAX_FUZZ_FINDINGS: usize = 4;
pub const MAX_MUTATION_VALUE_BYTES: usize = 32;
pub const MAX_FUZZ_DEDUP_ENTRIES: usize = 64;
pub const MAX_FUZZ_ORIGIN_BUDGETS: usize = 256;
pub const MAX_FUZZ_TASKS_PER_ORIGIN_HARD: usize = 8;

#[derive(Debug, Clone)]
pub struct FuzzPolicy {
    pub level: u8,
    pub goal: ScanGoal,
    pub speed: SpeedSetting,
}

impl FuzzPolicy {
    pub fn new(level: u8, goal: ScanGoal, speed: SpeedSetting) -> Self {
        Self {
            level: level.clamp(1, 5),
            goal,
            speed,
        }
    }

    pub fn enabled(&self) -> bool {
        self.level >= 3
    }

    pub fn max_params(&self) -> usize {
        match self.level {
            0..=2 => 0,
            3 => 1,
            4 => 3,
            _ => MAX_FUZZ_PARAMS_PER_ENDPOINT,
        }
    }

    pub fn max_mutations_per_param(&self) -> usize {
        match self.level {
            0..=2 => 0,
            3 => 2,
            4 => 3,
            _ => MAX_MUTATIONS_PER_PARAM,
        }
    }

    pub fn request_limit(&self) -> usize {
        match self.level {
            0..=2 => 0,
            3 => 2,
            4 => 6,
            _ => MAX_FUZZ_REQUESTS_PER_TASK,
        }
    }

    pub fn tasks_per_origin_limit(&self) -> usize {
        match self.level {
            0..=2 => 0,
            3 => 2,
            4 => 4,
            _ => MAX_FUZZ_TASKS_PER_ORIGIN_HARD,
        }
    }

    pub fn web_policy(&self) -> WebPolicy {
        WebPolicy::new(self.level, self.goal, self.speed)
    }

    pub fn connect_timeout(&self) -> Duration {
        crate::ports::tcp_timeout_for_speed(self.speed)
    }

    pub fn response_timeout(&self) -> Duration {
        crate::service::service_timeout_for_speed(self.speed)
    }

    pub fn describe(&self) -> String {
        format!(
            "contextual fuzz level {} ({:?}): params {}, mutations/param {}, requests {}, body cap {}",
            self.level,
            self.goal,
            self.max_params(),
            self.max_mutations_per_param(),
            self.request_limit(),
            MAX_FUZZ_RESPONSE_BYTES,
        )
    }
}

#[derive(Debug, Default)]
struct OriginBudgetState {
    plans_by_origin: BTreeMap<String, BTreeSet<String>>,
    full: bool,
}

#[derive(Debug, Clone, Default)]
pub struct FuzzOriginBudget {
    state: Arc<Mutex<OriginBudgetState>>,
}

impl FuzzOriginBudget {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn claim(&self, origin: &str, plan_key: &str, per_origin_limit: usize) -> bool {
        if per_origin_limit == 0 {
            return false;
        }
        let mut state = self.state.lock().unwrap();
        if let Some(plans) = state.plans_by_origin.get_mut(origin) {
            if plans.contains(plan_key) {
                return true;
            }
            if plans.len() >= per_origin_limit {
                return false;
            }
            plans.insert(plan_key.to_owned());
            return true;
        }
        if state.full || state.plans_by_origin.len() >= MAX_FUZZ_ORIGIN_BUDGETS {
            state.full = true;
            return false;
        }
        let mut plans = BTreeSet::new();
        plans.insert(plan_key.to_owned());
        state.plans_by_origin.insert(origin.to_owned(), plans);
        true
    }

    pub fn count_for_origin(&self, origin: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .plans_by_origin
            .get(origin)
            .map(BTreeSet::len)
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueKind {
    Empty,
    Integer,
    Boolean,
    ShortText,
    TokenLike,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationClass {
    EmptyValue,
    OmittedValue,
    AlternateBenignScalar,
    AlternateNumericBoundary,
    AlternateBoolean,
    ShortRandomToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzOutcome {
    NoMeaningfulChange,
    StatusChanged,
    RedirectChanged,
    ContentTypeChanged,
    LengthChanged,
    BodyChanged,
    TemplateChanged,
    InputReflected,
    ErrorBehaviorChanged,
    Inconclusive,
    RequestError,
}

#[derive(Debug, Clone)]
struct Mutation {
    class: MutationClass,
    value: Option<String>,
}

#[derive(Debug)]
struct FuzzFetch {
    target: WebTarget,
    response: crate::web::HttpResponse,
    body: Vec<u8>,
    redirect_out_of_scope: bool,
}

pub struct FuzzModule {
    policy: FuzzPolicy,
    scope_guard: Arc<dyn ScopeGuard>,
    contacts: crate::contact::ContactRegistry,
}

impl FuzzModule {
    pub fn new(policy: FuzzPolicy, scope_guard: Arc<dyn ScopeGuard>) -> Self {
        Self {
            policy,
            scope_guard,
            contacts: crate::contact::ContactRegistry::new(),
        }
    }

    pub fn with_contact_registry(
        policy: FuzzPolicy,
        scope_guard: Arc<dyn ScopeGuard>,
        contacts: crate::contact::ContactRegistry,
    ) -> Self {
        Self {
            policy,
            scope_guard,
            contacts,
        }
    }
}

impl Module for FuzzModule {
    fn kind(&self) -> TaskKind {
        TaskKind::Fuzz
    }

    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let policy = self.policy.clone();
        let guard = self.scope_guard.clone();
        let contacts = self.contacts.clone();
        Box::pin(async move { execute_fuzz(&policy, guard.as_ref(), &contacts, context) })
    }
}

pub fn fuzz_task_params(
    url: &WebTarget,
    source_endpoint: &str,
    param_name: &str,
    baseline_signature: Option<&ResponseSignature>,
) -> BTreeMap<String, String> {
    let mut params = BTreeMap::new();
    params.insert("url".to_owned(), url.canonical());
    params.insert("target".to_owned(), url.host.clone());
    params.insert("source_endpoint".to_owned(), source_endpoint.to_owned());
    params.insert("param".to_owned(), param_name.to_owned());
    if let Some(signature) = baseline_signature {
        if let Ok(serialized) = serde_json::to_string(signature) {
            params.insert("baseline_signature".to_owned(), serialized);
        }
    }
    params
}

pub fn infer_value_kind(value: &str) -> ValueKind {
    let lower = value.to_ascii_lowercase();
    if value.is_empty() {
        ValueKind::Empty
    } else if lower == "true" || lower == "false" || value == "0" || value == "1" {
        ValueKind::Boolean
    } else if value.parse::<i64>().is_ok() {
        ValueKind::Integer
    } else if value.len() <= 24
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
    {
        ValueKind::TokenLike
    } else if value.len() <= 32 && value.chars().all(|ch| ch.is_ascii_graphic()) {
        ValueKind::ShortText
    } else {
        ValueKind::Unknown
    }
}

pub fn is_sensitive_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "password", "passwd", "token", "csrf", "secret", "otp", "auth", "session",
    ]
    .iter()
    .any(|part| lower.contains(part))
}

pub fn origin_key(url: &WebTarget) -> String {
    let root = crate::baseline::origin_root(url);
    root.canonical()
}

fn execute_fuzz(
    policy: &FuzzPolicy,
    guard: &dyn ScopeGuard,
    contacts: &crate::contact::ContactRegistry,
    context: ModuleContext,
) -> Result<ModuleOutput, ModuleError> {
    let task = context.task.clone();
    let cancel = context.cancellation();
    if cancel.is_cancelled() {
        return Err(ModuleError::Cancelled);
    }
    if !policy.enabled() {
        return Ok(ModuleOutput::default());
    }
    if !guard.permits(&task.scope_target) {
        return Err(ModuleError::Failed {
            message: "stale scope rejected immediately before contextual fuzzing".to_owned(),
            retryable: false,
        });
    }
    let started_at = Timestamp::now();
    let started = Instant::now();
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(task.timeout_ms.max(1)))
        .unwrap_or_else(|| Instant::now() + Duration::from_secs(60));
    let provenance = Provenance::new(
        FUZZ_MODULE_NAME,
        FUZZ_MODULE_VERSION,
        task.scan_plan_id.clone(),
        started_at,
    )
    .map_err(|_| ModuleError::Failed {
        message: "invalid fuzz provenance".to_owned(),
        retryable: false,
    })?;
    let url_text = task.params.get("url").ok_or_else(|| ModuleError::Failed {
        message: "fuzz task missing url".to_owned(),
        retryable: false,
    })?;
    let target = WebTarget::parse(url_text).map_err(|reason| ModuleError::Failed {
        message: format!("invalid fuzz URL: {reason}"),
        retryable: false,
    })?;
    if !guard.permits(&scope_target_for_url(&target)) {
        return Err(ModuleError::Failed {
            message: "fuzz target outside scope".to_owned(),
            retryable: false,
        });
    }
    let param = task.params.get("param").cloned().unwrap_or_default();
    let baseline_signature = task
        .params
        .get("baseline_signature")
        .and_then(|value| serde_json::from_str::<ResponseSignature>(value).ok());
    let original = query_value(&target, &param);
    let mut output = ModuleOutput::default();
    push_event(
        &mut output.events,
        EventKind::ContextualFuzzStarted,
        None,
        serde_json::json!({"url": target.canonical(), "policy": policy.describe()}),
        &provenance,
    )?;
    let endpoint_asset = ensure_endpoint_asset(&mut output.assets, &target, &provenance)?;
    if param.is_empty() || original.is_none() {
        push_event(
            &mut output.events,
            EventKind::FuzzBudgetExhausted,
            Some(endpoint_asset),
            serde_json::json!({"url": target.canonical(), "reason": "no-observed-query-parameter"}),
            &provenance,
        )?;
        return complete(output, &target, started, 0, 0, &provenance);
    }
    if is_sensitive_name(&param) {
        push_event(
            &mut output.events,
            EventKind::FuzzSkippedSensitiveInput,
            Some(endpoint_asset),
            serde_json::json!({"url": target.canonical(), "param": param, "reason": "sensitive-name"}),
            &provenance,
        )?;
        return complete(output, &target, started, 0, 0, &provenance);
    }
    let original = original.unwrap_or_default();
    let value_kind = infer_value_kind(&original);
    push_event(
        &mut output.events,
        EventKind::FuzzInputSelected,
        Some(endpoint_asset.clone()),
        serde_json::json!({
            "url": target.canonical(),
            "param": param,
            "value_kind": value_kind,
            "method": "GET",
        }),
        &provenance,
    )?;
    let mutations = mutation_plan(&param, &original, &value_kind, policy);
    let mut attempted = 0usize;
    let mut deltas = 0usize;
    let mut dedup = BTreeSet::new();
    for mutation in mutations {
        if cancel.is_cancelled() {
            return Err(ModuleError::Cancelled);
        }
        if attempted >= policy.request_limit() || attempted >= MAX_MUTATIONS_PER_TASK {
            push_event(
                &mut output.events,
                EventKind::FuzzBudgetExhausted,
                Some(endpoint_asset.clone()),
                serde_json::json!({"url": target.canonical(), "reason": "requests"}),
                &provenance,
            )?;
            break;
        }
        let mutated = mutate_query(&target, &param, &mutation)?;
        if !guard.permits(&scope_target_for_url(&mutated)) {
            continue;
        }
        let canonical = mutated.canonical();
        if dedup.len() >= MAX_FUZZ_DEDUP_ENTRIES {
            push_event(
                &mut output.events,
                EventKind::FuzzBudgetExhausted,
                Some(endpoint_asset.clone()),
                serde_json::json!({"url": target.canonical(), "reason": "dedup"}),
                &provenance,
            )?;
            break;
        }
        if !dedup.insert(canonical.clone()) {
            continue;
        }
        if !contacts.claim(&mutated, crate::contact::RequestPurpose::FuzzMutation) {
            continue;
        }
        attempted += 1;
        push_event(
            &mut output.events,
            EventKind::FuzzMutationAttempted,
            Some(endpoint_asset.clone()),
            serde_json::json!({
                "url": mutated.canonical(),
                "param": param,
                "mutation_class": mutation.class,
            }),
            &provenance,
        )?;
        let Some(fetch) = fetch_fuzz(&mutated, policy, guard, contacts, &cancel, deadline)? else {
            emit_delta(
                &mut output,
                &endpoint_asset,
                &target,
                &mutated,
                &param,
                &mutation,
                FuzzOutcome::RequestError,
                0,
                Vec::new(),
                None,
                &baseline_signature,
                &provenance,
            )?;
            continue;
        };
        let signature = signature_for_response(&fetch.response, &fetch.body);
        let (outcome, score, factors) = classify_delta(
            &baseline_signature,
            &signature,
            &fetch,
            mutation.value.as_deref(),
        );
        if outcome != FuzzOutcome::NoMeaningfulChange {
            deltas += 1;
        }
        emit_delta(
            &mut output,
            &endpoint_asset,
            &target,
            &fetch.target,
            &param,
            &mutation,
            outcome.clone(),
            score,
            factors,
            Some(&signature),
            &baseline_signature,
            &provenance,
        )?;
        if outcome == FuzzOutcome::InputReflected {
            push_event(
                &mut output.events,
                EventKind::FuzzInputReflected,
                Some(endpoint_asset.clone()),
                serde_json::json!({"url": fetch.target.canonical(), "param": param, "mutation_class": mutation.class}),
                &provenance,
            )?;
        }
    }
    complete(output, &target, started, attempted, deltas, &provenance)
}

fn mutation_plan(
    param: &str,
    original: &str,
    value_kind: &ValueKind,
    policy: &FuzzPolicy,
) -> Vec<Mutation> {
    let token = format!(
        "rxscan_{}",
        &sha256_hex(format!("{param}:{original}").as_bytes())[..8]
    );
    let mut mutations = Vec::new();
    mutations.push(Mutation {
        class: MutationClass::OmittedValue,
        value: None,
    });
    mutations.push(Mutation {
        class: MutationClass::EmptyValue,
        value: Some(String::new()),
    });
    match value_kind {
        ValueKind::Integer => {
            if let Ok(value) = original.parse::<i64>() {
                for next in [0, 1, value.saturating_sub(1), value.saturating_add(1)] {
                    mutations.push(Mutation {
                        class: MutationClass::AlternateNumericBoundary,
                        value: Some(next.to_string()),
                    });
                }
            }
        }
        ValueKind::Boolean => {
            let next = match original.to_ascii_lowercase().as_str() {
                "true" => "false",
                "false" => "true",
                "1" => "0",
                "0" => "1",
                _ => "false",
            };
            mutations.push(Mutation {
                class: MutationClass::AlternateBoolean,
                value: Some(next.to_owned()),
            });
        }
        ValueKind::ShortText | ValueKind::TokenLike => {
            mutations.push(Mutation {
                class: MutationClass::ShortRandomToken,
                value: Some(token),
            });
            mutations.push(Mutation {
                class: MutationClass::AlternateBenignScalar,
                value: Some("rxscan".to_owned()),
            });
        }
        ValueKind::Empty | ValueKind::Unknown => {}
    }
    let mut seen = BTreeSet::new();
    mutations
        .into_iter()
        .filter(|mutation| {
            mutation
                .value
                .as_ref()
                .is_none_or(|value| value.len() <= MAX_MUTATION_VALUE_BYTES)
        })
        .filter(|mutation| seen.insert((mutation.class, mutation.value.clone())))
        .take(policy.max_mutations_per_param())
        .collect()
}

fn query_value(target: &WebTarget, param: &str) -> Option<String> {
    target.query.as_ref().and_then(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .find(|(name, _)| name == param)
            .map(|(_, value)| value.into_owned())
    })
}

fn mutate_query(
    target: &WebTarget,
    param: &str,
    mutation: &Mutation,
) -> Result<WebTarget, ModuleError> {
    let mut pairs: Vec<(String, String)> = target
        .query
        .as_deref()
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect()
        })
        .unwrap_or_default();
    let mut changed = false;
    pairs.retain(|(name, _)| {
        if name == param && mutation.value.is_none() {
            changed = true;
            false
        } else {
            true
        }
    });
    if let Some(value) = &mutation.value {
        for (name, current) in &mut pairs {
            if name == param {
                *current = value.clone();
                changed = true;
                break;
            }
        }
    }
    if !changed {
        return Err(ModuleError::Failed {
            message: "mutation target parameter missing".to_owned(),
            retryable: false,
        });
    }
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        serializer.append_pair(&name, &value);
    }
    Ok(WebTarget {
        scheme: target.scheme,
        host: target.host.clone(),
        port: target.port,
        path: target.path.clone(),
        query: {
            let query = serializer.finish();
            (!query.is_empty()).then_some(query)
        },
    })
}

fn classify_delta(
    baseline: &Option<ResponseSignature>,
    mutated: &ResponseSignature,
    fetch: &FuzzFetch,
    mutation_value: Option<&str>,
) -> (FuzzOutcome, u8, Vec<String>) {
    let mut factors = Vec::new();
    let Some(base) = baseline else {
        return (
            FuzzOutcome::Inconclusive,
            10,
            vec!["missing-baseline-signature".to_owned()],
        );
    };
    if mutation_value.is_some_and(|value| !value.is_empty() && contains_token(&fetch.body, value)) {
        return (
            FuzzOutcome::InputReflected,
            70,
            vec!["inert-token-reflected".to_owned()],
        );
    }
    if fetch.redirect_out_of_scope
        || (300..400).contains(&mutated.status) != (300..400).contains(&base.status)
    {
        return (
            FuzzOutcome::RedirectChanged,
            55,
            vec!["redirect".to_owned()],
        );
    }
    if base.status != mutated.status {
        factors.push("status".to_owned());
        if mutated.status >= 500 || (base.status < 400 && mutated.status >= 400) {
            return (FuzzOutcome::ErrorBehaviorChanged, 65, factors);
        }
        return (FuzzOutcome::StatusChanged, 55, factors);
    }
    if mime_family(&base.content_type) != mime_family(&mutated.content_type) {
        return (
            FuzzOutcome::ContentTypeChanged,
            50,
            vec!["content-type".to_owned()],
        );
    }
    let (class, _) = similarity(base, mutated);
    match class {
        SimilarityClass::Exact | SimilarityClass::NearDuplicate => {
            (FuzzOutcome::NoMeaningfulChange, 0, Vec::new())
        }
        SimilarityClass::SimilarTemplate => (
            FuzzOutcome::TemplateChanged,
            35,
            vec!["template".to_owned()],
        ),
        SimilarityClass::Different => {
            let delta = base.observed_body_len.abs_diff(mutated.observed_body_len);
            if delta > base.observed_body_len.max(1) / 5 {
                (FuzzOutcome::LengthChanged, 30, vec!["length".to_owned()])
            } else {
                (FuzzOutcome::BodyChanged, 25, vec!["body".to_owned()])
            }
        }
        SimilarityClass::Unknown => (
            FuzzOutcome::Inconclusive,
            10,
            vec!["unknown-similarity".to_owned()],
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_delta(
    output: &mut ModuleOutput,
    endpoint_asset: &AssetId,
    original: &WebTarget,
    mutated: &WebTarget,
    param: &str,
    mutation: &Mutation,
    outcome: FuzzOutcome,
    score: u8,
    factors: Vec<String>,
    mutated_signature: Option<&ResponseSignature>,
    baseline_signature: &Option<ResponseSignature>,
    provenance: &Provenance,
) -> Result<(), ModuleError> {
    if output.events.len() < MAX_FUZZ_EVENTS {
        let mut event = Event::new(
            EventKind::FuzzBehaviorDeltaObserved,
            Some(endpoint_asset.clone()),
            BoundedDetails::from_value(
                serde_json::json!({
                    "original_url": original.canonical(),
                    "mutated_url": mutated.canonical(),
                    "param": param,
                    "mutation_class": mutation.class,
                    "outcome": outcome,
                    "behavior_delta_score": score,
                    "factors": factors,
                    "baseline_signature": baseline_signature,
                    "mutated_signature": mutated_signature,
                }),
                MAX_EVENT_DETAILS_BYTES,
            )
            .map_err(|_| ModuleError::Failed {
                message: "fuzz event too large".to_owned(),
                retryable: false,
            })?,
            provenance.clone(),
        )
        .map_err(|_| ModuleError::Failed {
            message: "invalid fuzz event".to_owned(),
            retryable: false,
        })?;
        let relationship_kind = if outcome == FuzzOutcome::InputReflected {
            RelationshipKind::ReflectsInput
        } else {
            RelationshipKind::BehaviorDiffersFrom
        };
        event.relationships.push(
            Relationship::new(
                relationship_kind,
                RelationshipSubject::Asset(endpoint_asset.clone()),
                RelationshipSubject::Evidence(crate::model::EvidenceId(format!(
                    "evidence_fuzz_{}",
                    sha256_hex(mutated.canonical().as_bytes())
                ))),
                provenance.clone(),
            )
            .map_err(|_| ModuleError::Failed {
                message: "invalid fuzz relationship".to_owned(),
                retryable: false,
            })?,
        );
        output.events.push(event);
    }
    if output.evidence.len() < MAX_FUZZ_EVIDENCE {
        output.evidence.push(
            Evidence::new(
                FUZZ_MODULE_NAME,
                endpoint_asset.clone(),
                BoundedDetails::from_value(
                    serde_json::json!({
                        "original_url": original.canonical(),
                        "mutated_url": mutated.canonical(),
                        "param": param,
                        "mutation_class": mutation.class,
                        "outcome": outcome,
                        "behavior_delta_score": score,
                        "factors": factors,
                    }),
                    crate::model::MAX_EVIDENCE_DETAILS_BYTES,
                )
                .map_err(|_| ModuleError::Failed {
                    message: "fuzz evidence too large".to_owned(),
                    retryable: false,
                })?,
                Confidence::new(65).unwrap(),
                provenance.clone(),
            )
            .map_err(|_| ModuleError::Failed {
                message: "invalid fuzz evidence".to_owned(),
                retryable: false,
            })?,
        );
    }
    if score >= 50 && output.findings.len() < MAX_FUZZ_FINDINGS {
        output.findings.push(
            Finding::new(
                format!("Behavioral difference observed at {}", original.canonical()),
                Severity::Info,
                Confidence::new(55).unwrap(),
                endpoint_asset.clone(),
                provenance.clone(),
            )
            .map_err(|_| ModuleError::Failed {
                message: "invalid fuzz finding".to_owned(),
                retryable: false,
            })?,
        );
    }
    Ok(())
}

fn complete(
    mut output: ModuleOutput,
    target: &WebTarget,
    started: Instant,
    mutations_attempted: usize,
    behavior_deltas: usize,
    provenance: &Provenance,
) -> Result<ModuleOutput, ModuleError> {
    push_event(
        &mut output.events,
        EventKind::ContextualFuzzCompleted,
        None,
        serde_json::json!({
            "url": target.canonical(),
            "elapsed_ms": started.elapsed().as_millis() as u64,
            "mutations_attempted": mutations_attempted,
            "behavior_deltas": behavior_deltas,
        }),
        provenance,
    )?;
    Ok(output)
}

fn fetch_fuzz(
    start: &WebTarget,
    policy: &FuzzPolicy,
    guard: &dyn ScopeGuard,
    contacts: &crate::contact::ContactRegistry,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<Option<FuzzFetch>, ModuleError> {
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
        if visited.len() > 1
            && !contacts.claim(&current, crate::contact::RequestPurpose::RedirectFollow)
        {
            return Ok(None);
        }
        let addresses = resolve_addresses(&current, guard, cancel)?;
        let mut fetched = None;
        for ip in addresses {
            if cancel.is_cancelled() {
                return Err(ModuleError::Cancelled);
            }
            let remaining = deadline
                .saturating_duration_since(Instant::now())
                .min(policy.response_timeout());
            let result = match current.scheme {
                Scheme::Http => crate::web::fetch_plain(
                    ip,
                    &current,
                    "GET",
                    true,
                    MAX_FUZZ_RESPONSE_BYTES,
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
                    MAX_FUZZ_RESPONSE_BYTES,
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
                    return Ok(Some(FuzzFetch {
                        target: current,
                        response,
                        body: raw_fetch.body,
                        redirect_out_of_scope,
                    }));
                };
                if !guard.permits(&scope_target_for_url(&next)) {
                    redirect_out_of_scope = true;
                    return Ok(Some(FuzzFetch {
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
        return Ok(Some(FuzzFetch {
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

fn scope_target_for_url(url: &WebTarget) -> TaskScopeTarget {
    match url.ip_literal() {
        Some(ip) => TaskScopeTarget::Ip(ip),
        None => TaskScopeTarget::Host(url.host.clone()),
    }
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

fn push_event(
    events: &mut Vec<Event>,
    kind: EventKind,
    asset_id: Option<AssetId>,
    data: serde_json::Value,
    provenance: &Provenance,
) -> Result<(), ModuleError> {
    if events.len() >= MAX_FUZZ_EVENTS {
        return Ok(());
    }
    events.push(
        Event::new(
            kind,
            asset_id,
            BoundedDetails::from_value(data, MAX_EVENT_DETAILS_BYTES).map_err(|_| {
                ModuleError::Failed {
                    message: "fuzz event details too large".to_owned(),
                    retryable: false,
                }
            })?,
            provenance.clone(),
        )
        .map_err(|_| ModuleError::Failed {
            message: "invalid fuzz event".to_owned(),
            retryable: false,
        })?,
    );
    Ok(())
}

fn contains_token(body: &[u8], token: &str) -> bool {
    if token.len() > MAX_MUTATION_VALUE_BYTES {
        return false;
    }
    String::from_utf8_lossy(&body[..body.len().min(MAX_FUZZ_RESPONSE_BYTES)]).contains(token)
}

fn mime_family(value: &str) -> &str {
    value.split(';').next().unwrap_or("").trim()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_inference_and_sensitive_filter_are_conservative() {
        assert_eq!(infer_value_kind(""), ValueKind::Empty);
        assert_eq!(infer_value_kind("42"), ValueKind::Integer);
        assert_eq!(infer_value_kind("true"), ValueKind::Boolean);
        assert_eq!(infer_value_kind("alice"), ValueKind::TokenLike);
        assert!(is_sensitive_name("csrf_token"));
        assert!(!is_sensitive_name("query"));
    }
}
