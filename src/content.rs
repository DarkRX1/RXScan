//! Phase 11 managed content discovery.
//!
//! This module attempts a small, explicitly managed set of resource paths
//! against a confirmed in-scope web origin. It is not fuzzing: no placeholder
//! substitution, form submission, parameter mutation, method enumeration,
//! traversal payloads, injection strings, or exploit probes are generated.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufRead, BufReader},
    net::IpAddr,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

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

pub const CONTENT_MODULE_NAME: &str = "rxscan.content";
pub const CONTENT_MODULE_VERSION: &str = "11.0.0";
pub const MAX_CANDIDATE_LINE_BYTES: usize = 512;
pub const MAX_CANDIDATES_READ: usize = 2_000;
pub const MAX_CANDIDATES_ADMITTED: usize = 512;
pub const MAX_CONTENT_REQUESTS: usize = 128;
pub const MAX_CONTENT_RESPONSE_BYTES: usize = 64 * 1024;
pub const MAX_DISCOVERED_ENDPOINTS: usize = 64;
pub const MAX_CONTENT_EVENTS: usize = 256;
pub const MAX_CONTENT_EVIDENCE: usize = 128;
pub const MAX_CONTENT_FINDINGS: usize = 16;
pub const MAX_DEDUP_ENTRIES: usize = 1_024;
pub const MAX_DERIVED_CANDIDATES: usize = 32;
const BUILTIN_CANDIDATES: &[&str] = &[
    "/",
    "/index.html",
    "/robots.txt",
    "/sitemap.xml",
    "/login",
    "/docs/",
    "/api/",
    "/status",
    "/health",
    "/assets/",
    "/static/",
    "/app.js",
];

#[derive(Debug, Clone)]
pub struct ContentDiscoveryPolicy {
    pub level: u8,
    pub goal: ScanGoal,
    pub speed: SpeedSetting,
}

impl ContentDiscoveryPolicy {
    pub fn new(level: u8, goal: ScanGoal, speed: SpeedSetting) -> Self {
        Self {
            level: level.clamp(1, 5),
            goal,
            speed,
        }
    }

    pub fn enabled(&self) -> bool {
        self.level >= 2
    }

    pub fn builtin_limit(&self) -> usize {
        match self.level {
            0 | 1 => 0,
            2 => 4,
            3 => 8,
            _ => BUILTIN_CANDIDATES.len(),
        }
    }

    pub fn user_file_enabled(&self) -> bool {
        self.level >= 4
    }

    pub fn request_limit(&self) -> usize {
        match self.level {
            0 | 1 => 0,
            2 => 8,
            3 => 32,
            4 => 64,
            _ => MAX_CONTENT_REQUESTS,
        }
        .min(MAX_CONTENT_REQUESTS)
    }

    pub fn candidate_limit(&self) -> usize {
        match self.level {
            0 | 1 => 0,
            2 => 16,
            3 => 64,
            4 => 256,
            _ => MAX_CANDIDATES_ADMITTED,
        }
        .min(MAX_CANDIDATES_ADMITTED)
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
            "content discovery level {} ({:?}): builtin {}, user-file {}, request cap {}, candidate cap {}, body cap {}",
            self.level,
            self.goal,
            self.builtin_limit(),
            self.user_file_enabled(),
            self.request_limit(),
            self.candidate_limit(),
            MAX_CONTENT_RESPONSE_BYTES,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateSourceKind {
    BuiltIn,
    UserFile,
    Derived,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentDiscoveryState {
    Found,
    Redirect,
    Forbidden,
    Unauthorized,
    NotFound,
    SoftNotFound,
    WildcardLike,
    Inconclusive,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub path: String,
    pub source: CandidateSourceKind,
    pub source_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateReject {
    Empty,
    Comment,
    TooLong,
    Control,
    Backslash,
    SchemeOrAuthority,
    PathTraversal,
    Malformed,
}

pub fn builtin_candidates() -> &'static [&'static str] {
    BUILTIN_CANDIDATES
}

pub fn content_task_params(
    origin: &WebTarget,
    source_endpoint: &str,
    wordlist: Option<&Path>,
) -> BTreeMap<String, String> {
    let mut params = BTreeMap::new();
    params.insert(
        "origin".to_owned(),
        crate::baseline::origin_root(origin).canonical(),
    );
    params.insert("target".to_owned(), origin.host.clone());
    params.insert("source_endpoint".to_owned(), source_endpoint.to_owned());
    if let Some(path) = wordlist {
        params.insert("wordlist".to_owned(), path.display().to_string());
    }
    params
}

pub fn normalize_candidate(line: &str) -> Result<Option<String>, CandidateReject> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.starts_with('#') {
        return Ok(None);
    }
    if trimmed.len() > MAX_CANDIDATE_LINE_BYTES {
        return Err(CandidateReject::TooLong);
    }
    if trimmed.chars().any(char::is_control) {
        return Err(CandidateReject::Control);
    }
    if trimmed.contains('\\') {
        return Err(CandidateReject::Backslash);
    }
    if trimmed.starts_with("//") || trimmed.contains("://") {
        return Err(CandidateReject::SchemeOrAuthority);
    }
    let without_fragment = trimmed.split('#').next().unwrap_or("");
    if without_fragment
        .split(['/', '?'])
        .any(|part| matches!(part, "." | ".." | "%2e" | "%2E" | "%2e%2e" | "%2E%2E"))
    {
        return Err(CandidateReject::PathTraversal);
    }
    let collapsed = collapse_slashes(without_fragment);
    let with_slash = if collapsed.starts_with('/') {
        collapsed
    } else {
        format!("/{collapsed}")
    };
    let parsed = url::Url::parse(&format!("http://rxscan.local{with_slash}"))
        .map_err(|_| CandidateReject::Malformed)?;
    if parsed.path_segments().is_none_or(|segments| {
        segments
            .filter(|segment| !segment.is_empty())
            .any(|segment| segment == "." || segment == ".." || segment.eq_ignore_ascii_case("%2e"))
    }) {
        return Err(CandidateReject::PathTraversal);
    }
    let path = parsed.path().to_owned();
    let query = parsed
        .query()
        .map(|query| format!("?{query}"))
        .unwrap_or_default();
    Ok(Some(format!("{path}{query}")))
}

fn collapse_slashes(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut last_slash = false;
    for ch in value.chars() {
        if ch == '/' {
            if !last_slash {
                out.push(ch);
            }
            last_slash = true;
        } else {
            out.push(ch);
            last_slash = false;
        }
    }
    out
}

pub struct ContentDiscoveryModule {
    policy: ContentDiscoveryPolicy,
    scope_guard: Arc<dyn ScopeGuard>,
    contacts: crate::contact::ContactRegistry,
}

impl ContentDiscoveryModule {
    pub fn new(policy: ContentDiscoveryPolicy, scope_guard: Arc<dyn ScopeGuard>) -> Self {
        Self {
            policy,
            scope_guard,
            contacts: crate::contact::ContactRegistry::new(),
        }
    }

    pub fn with_contact_registry(
        policy: ContentDiscoveryPolicy,
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

impl Module for ContentDiscoveryModule {
    fn kind(&self) -> TaskKind {
        TaskKind::ContentDiscovery
    }

    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let policy = self.policy.clone();
        let guard = self.scope_guard.clone();
        let contacts = self.contacts.clone();
        Box::pin(
            async move { execute_content_discovery(&policy, guard.as_ref(), &contacts, context) },
        )
    }
}

fn execute_content_discovery(
    policy: &ContentDiscoveryPolicy,
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
            message: "stale scope rejected immediately before content discovery".to_owned(),
            retryable: false,
        });
    }
    let started_at = Timestamp::now();
    let started = Instant::now();
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(task.timeout_ms.max(1)))
        .unwrap_or_else(|| Instant::now() + Duration::from_secs(60));
    let provenance = Provenance::new(
        CONTENT_MODULE_NAME,
        CONTENT_MODULE_VERSION,
        task.scan_plan_id.clone(),
        started_at,
    )
    .map_err(|_| ModuleError::Failed {
        message: "invalid provenance".to_owned(),
        retryable: false,
    })?;
    let origin_text = task
        .params
        .get("origin")
        .ok_or_else(|| ModuleError::Failed {
            message: "content discovery task missing origin".to_owned(),
            retryable: false,
        })?;
    let origin = WebTarget::parse(origin_text).map_err(|reason| ModuleError::Failed {
        message: format!("invalid content discovery origin: {reason}"),
        retryable: false,
    })?;
    if !guard.permits(&scope_target_for_url(&origin)) {
        return Err(ModuleError::Failed {
            message: "content discovery origin outside scope".to_owned(),
            retryable: false,
        });
    }

    let mut output = ModuleOutput::default();
    push_event(
        &mut output.events,
        EventKind::ContentDiscoveryStarted,
        None,
        serde_json::json!({
            "origin": origin.canonical(),
            "builtin_candidates": policy.builtin_limit(),
            "request_limit": policy.request_limit(),
            "candidate_limit": policy.candidate_limit(),
        }),
        &provenance,
    )?;

    let mut state = ContentRunState {
        policy,
        guard,
        cancel: &cancel,
        deadline,
        provenance: &provenance,
        origin: &origin,
        output: &mut output,
        read: 0,
        admitted: 0,
        rejected: 0,
        requests: 0,
        discovered: 0,
        baseline_rejected: 0,
        dedup_avoided: 0,
        dedup: BTreeSet::new(),
        baseline_signatures: baseline_signatures_from_params(&task.params),
        contacts,
    };

    for candidate in builtin_candidates()
        .iter()
        .take(policy.builtin_limit())
        .map(|path| Candidate {
            path: (*path).to_owned(),
            source: CandidateSourceKind::BuiltIn,
            source_label: "builtin-small-v1".to_owned(),
        })
    {
        state.process_candidate_line(candidate)?;
    }
    if let Some(wordlist) = task
        .params
        .get("wordlist")
        .filter(|_| policy.user_file_enabled())
    {
        stream_user_wordlist(wordlist, &mut state)?;
    }

    push_event(
        &mut state.output.events,
        EventKind::ContentDiscoveryCompleted,
        None,
        serde_json::json!({
            "origin": origin.canonical(),
            "elapsed_ms": started.elapsed().as_millis() as u64,
            "candidates_read": state.read,
            "candidates_admitted": state.admitted,
            "candidates_rejected": state.rejected,
            "requests": state.requests,
            "discovered": state.discovered,
            "baseline_rejected": state.baseline_rejected,
            "dedup_avoided_requests": state.dedup_avoided,
        }),
        &provenance,
    )?;
    Ok(output)
}

fn stream_user_wordlist(path: &str, state: &mut ContentRunState<'_>) -> Result<(), ModuleError> {
    let file = File::open(path).map_err(|source| ModuleError::Failed {
        message: format!("could not read content candidate file: {source}"),
        retryable: false,
    })?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    loop {
        line.clear();
        let bytes = reader
            .read_line(&mut line)
            .map_err(|source| ModuleError::Failed {
                message: format!("could not read content candidate line: {source}"),
                retryable: false,
            })?;
        if bytes == 0 {
            break;
        }
        if bytes > MAX_CANDIDATE_LINE_BYTES + 1 {
            state.rejected += 1;
            continue;
        }
        state.process_candidate_line(Candidate {
            path: line.clone(),
            source: CandidateSourceKind::UserFile,
            source_label: "user-file".to_owned(),
        })?;
    }
    Ok(())
}

struct ContentRunState<'a> {
    policy: &'a ContentDiscoveryPolicy,
    guard: &'a dyn ScopeGuard,
    cancel: &'a CancellationToken,
    deadline: Instant,
    provenance: &'a Provenance,
    origin: &'a WebTarget,
    output: &'a mut ModuleOutput,
    read: usize,
    admitted: usize,
    rejected: usize,
    requests: usize,
    discovered: usize,
    baseline_rejected: usize,
    dedup_avoided: usize,
    dedup: BTreeSet<String>,
    baseline_signatures: Vec<ResponseSignature>,
    contacts: &'a crate::contact::ContactRegistry,
}

impl ContentRunState<'_> {
    fn process_candidate_line(&mut self, candidate: Candidate) -> Result<(), ModuleError> {
        if self.cancel.is_cancelled() {
            return Err(ModuleError::Cancelled);
        }
        if self.read >= MAX_CANDIDATES_READ {
            self.note_budget("candidates-read")?;
            return Ok(());
        }
        self.read += 1;
        let Some(normalized) = (match normalize_candidate(&candidate.path) {
            Ok(value) => value,
            Err(_) => {
                self.rejected += 1;
                return Ok(());
            }
        }) else {
            return Ok(());
        };
        if self.admitted >= self.policy.candidate_limit() {
            self.note_budget("candidates-admitted")?;
            return Ok(());
        }
        let target = join_origin_path(self.origin, &normalized)?;
        if !self.guard.permits(&scope_target_for_url(&target)) {
            self.rejected += 1;
            return Ok(());
        }
        let canonical = target.canonical();
        if self.dedup.len() >= MAX_DEDUP_ENTRIES {
            self.note_budget("dedup")?;
            return Ok(());
        }
        if !self.dedup.insert(canonical.clone()) {
            self.dedup_avoided += 1;
            return Ok(());
        }
        if self.requests >= self.policy.request_limit() {
            self.note_budget("requests")?;
            return Ok(());
        }
        if !self
            .contacts
            .claim(&target, crate::contact::RequestPurpose::ContentCandidate)
        {
            self.dedup_avoided += 1;
            return Ok(());
        }
        self.admitted += 1;
        self.emit_attempt(&target, &candidate)?;
        let Some(fetch) = fetch_content(
            &target,
            self.policy,
            self.guard,
            self.contacts,
            self.cancel,
            self.deadline,
        )?
        else {
            return Ok(());
        };
        self.requests += 1;
        let signature = signature_for_response(&fetch.response, &fetch.body);
        let state = classify_discovery(&fetch, &signature, &self.baseline_signatures);
        match state {
            ContentDiscoveryState::Found
            | ContentDiscoveryState::Redirect
            | ContentDiscoveryState::Forbidden
            | ContentDiscoveryState::Unauthorized => {
                self.discovered += 1;
                self.emit_discovery(&fetch, &candidate, &signature, state)?;
            }
            ContentDiscoveryState::SoftNotFound | ContentDiscoveryState::WildcardLike => {
                self.baseline_rejected += 1;
                self.emit_rejected(&fetch, &candidate, &signature, state)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn note_budget(&mut self, reason: &str) -> Result<(), ModuleError> {
        push_event(
            &mut self.output.events,
            EventKind::ContentDiscoveryBudgetExhausted,
            None,
            serde_json::json!({"origin": self.origin.canonical(), "reason": reason}),
            self.provenance,
        )
    }

    fn emit_attempt(
        &mut self,
        target: &WebTarget,
        candidate: &Candidate,
    ) -> Result<(), ModuleError> {
        if self.output.events.len() >= MAX_CONTENT_EVENTS {
            return Ok(());
        }
        push_event(
            &mut self.output.events,
            EventKind::CandidateAttempted,
            None,
            serde_json::json!({
                "url": target.canonical(),
                "source": candidate.source,
                "source_label": candidate.source_label,
            }),
            self.provenance,
        )
    }

    fn emit_discovery(
        &mut self,
        fetch: &ContentFetch,
        candidate: &Candidate,
        signature: &ResponseSignature,
        state: ContentDiscoveryState,
    ) -> Result<(), ModuleError> {
        if self.discovered > MAX_DISCOVERED_ENDPOINTS {
            self.note_budget("discovered-endpoints")?;
            return Ok(());
        }
        let asset = ensure_endpoint_asset(&mut self.output.assets, &fetch.target, self.provenance)?;
        let mut event = Event::new(
            if state == ContentDiscoveryState::Redirect {
                EventKind::ContentRedirectObserved
            } else {
                EventKind::ContentDiscovered
            },
            Some(asset.clone()),
            BoundedDetails::from_value(
                serde_json::json!({
                    "url": fetch.target.canonical(),
                    "state": state,
                    "status": fetch.response.status,
                    "content_type": fetch.response.content_type,
                    "observed_body_len": signature.observed_body_len,
                    "candidate_source": candidate.source,
                    "candidate_source_label": candidate.source_label,
                    "redirect_out_of_scope": fetch.redirect_out_of_scope,
                    "signature": signature,
                }),
                MAX_EVENT_DETAILS_BYTES,
            )
            .map_err(|_| ModuleError::Failed {
                message: "content discovery event too large".to_owned(),
                retryable: false,
            })?,
            self.provenance.clone(),
        )
        .map_err(|_| ModuleError::Failed {
            message: "invalid content discovery event".to_owned(),
            retryable: false,
        })?;
        // Phase 20: reference the origin's real endpoint asset ID (the same
        // function http/crawl use), never a mangled URL string: checkpoint
        // validation requires every relationship endpoint to resolve to a
        // persisted asset. The origin asset is ensured in this output so the
        // edge resolves even when no other module assetized the origin; the
        // persistence merge collapses identical IDs deterministically.
        // A discovery whose target IS the origin carries no edge (self-links
        // are rejected); the event itself still records it.
        let origin_asset = AssetId(crate::web::endpoint_asset_id(self.origin));
        if asset != origin_asset {
            let provenance = self.provenance.clone();
            ensure_endpoint_asset(&mut self.output.assets, self.origin, &provenance)?;
            event.relationships.push(
                Relationship::new(
                    RelationshipKind::DiscoveredByContentProbe,
                    RelationshipSubject::Asset(asset.clone()),
                    RelationshipSubject::Asset(origin_asset),
                    self.provenance.clone(),
                )
                .map_err(|_| ModuleError::Failed {
                    message: "invalid content relationship".to_owned(),
                    retryable: false,
                })?,
            );
        }
        self.output.events.push(event);
        push_event(
            &mut self.output.events,
            EventKind::EndpointDiscovered,
            Some(asset.clone()),
            serde_json::json!({
                "url": fetch.target.canonical(),
                "parent_asset_id": self.origin.canonical(),
                "source": "content-discovery",
                "scope_permitted": true,
                "crawl_eligible": matches!(state, ContentDiscoveryState::Found | ContentDiscoveryState::Redirect),
            }),
            self.provenance,
        )?;
        if self.output.evidence.len() < MAX_CONTENT_EVIDENCE {
            self.output.evidence.push(
                Evidence::new(
                    CONTENT_MODULE_NAME,
                    asset.clone(),
                    BoundedDetails::from_value(
                        serde_json::json!({
                            "url": fetch.target.canonical(),
                            "state": state,
                            "status": fetch.response.status,
                            "signature": signature,
                            "candidate_source": candidate.source,
                        }),
                        crate::model::MAX_EVIDENCE_DETAILS_BYTES,
                    )
                    .map_err(|_| ModuleError::Failed {
                        message: "content evidence too large".to_owned(),
                        retryable: false,
                    })?,
                    Confidence::new(75).unwrap(),
                    self.provenance.clone(),
                )
                .map_err(|_| ModuleError::Failed {
                    message: "invalid content evidence".to_owned(),
                    retryable: false,
                })?,
            );
        }
        if self.output.findings.len() < MAX_CONTENT_FINDINGS {
            self.output.findings.push(
                Finding::new(
                    format!("Content discovered at {}", fetch.target.canonical()),
                    Severity::Info,
                    Confidence::new(65).unwrap(),
                    asset,
                    self.provenance.clone(),
                )
                .map_err(|_| ModuleError::Failed {
                    message: "invalid content finding".to_owned(),
                    retryable: false,
                })?,
            );
        }
        Ok(())
    }

    fn emit_rejected(
        &mut self,
        fetch: &ContentFetch,
        candidate: &Candidate,
        signature: &ResponseSignature,
        state: ContentDiscoveryState,
    ) -> Result<(), ModuleError> {
        if self.output.events.len() >= MAX_CONTENT_EVENTS {
            return Ok(());
        }
        push_event(
            &mut self.output.events,
            EventKind::ContentRejectedByBaseline,
            None,
            serde_json::json!({
                "url": fetch.target.canonical(),
                "state": state,
                "status": fetch.response.status,
                "candidate_source": candidate.source,
                "signature": signature,
            }),
            self.provenance,
        )
    }
}

fn join_origin_path(origin: &WebTarget, normalized: &str) -> Result<WebTarget, ModuleError> {
    WebTarget::parse(&format!(
        "{}://{}:{}{}",
        origin.scheme.as_str(),
        host_for_url(origin),
        origin.port,
        normalized
    ))
    .map_err(|reason| ModuleError::Failed {
        message: format!("invalid normalized content candidate: {reason}"),
        retryable: false,
    })
}

fn host_for_url(url: &WebTarget) -> String {
    if url.host.contains(':') && !url.host.starts_with('[') {
        format!("[{}]", url.host)
    } else {
        url.host.clone()
    }
}

fn baseline_signatures_from_params(params: &BTreeMap<String, String>) -> Vec<ResponseSignature> {
    params
        .get("baseline_normalized_sha256")
        .map(|value| {
            value
                .split(',')
                .filter(|part| !part.is_empty())
                .map(|hash| ResponseSignature {
                    status: 200,
                    content_type: "text/html".to_owned(),
                    content_length: None,
                    observed_body_len: 0,
                    body_len_bucket: "unknown".to_owned(),
                    raw_sha256: String::new(),
                    normalized_sha256: hash.to_owned(),
                    title_hash: None,
                    header_hash: String::new(),
                    html_structure_hash: None,
                    truncated: false,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn classify_discovery(
    fetch: &ContentFetch,
    signature: &ResponseSignature,
    baseline: &[ResponseSignature],
) -> ContentDiscoveryState {
    match fetch.response.status {
        401 => return ContentDiscoveryState::Unauthorized,
        403 => return ContentDiscoveryState::Forbidden,
        404 | 410 => return ContentDiscoveryState::NotFound,
        status if (300..400).contains(&status) => return ContentDiscoveryState::Redirect,
        200..=299 => {}
        _ => return ContentDiscoveryState::Error,
    }
    if baseline
        .iter()
        .any(|base| base.normalized_sha256 == signature.normalized_sha256)
    {
        return ContentDiscoveryState::SoftNotFound;
    }
    if baseline.iter().any(|base| {
        matches!(
            similarity(base, signature).0,
            SimilarityClass::Exact
                | SimilarityClass::NearDuplicate
                | SimilarityClass::SimilarTemplate
        )
    }) {
        return ContentDiscoveryState::WildcardLike;
    }
    if baseline.is_empty() && signature.observed_body_len == 0 {
        ContentDiscoveryState::Inconclusive
    } else {
        ContentDiscoveryState::Found
    }
}

#[derive(Debug)]
struct ContentFetch {
    target: WebTarget,
    response: crate::web::HttpResponse,
    body: Vec<u8>,
    redirect_out_of_scope: bool,
}

fn fetch_content(
    start: &WebTarget,
    policy: &ContentDiscoveryPolicy,
    guard: &dyn ScopeGuard,
    contacts: &crate::contact::ContactRegistry,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<Option<ContentFetch>, ModuleError> {
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
                    MAX_CONTENT_RESPONSE_BYTES,
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
                    MAX_CONTENT_RESPONSE_BYTES,
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
                    return Ok(Some(ContentFetch {
                        target: current,
                        response,
                        body: raw_fetch.body,
                        redirect_out_of_scope,
                    }));
                };
                if !guard.permits(&scope_target_for_url(&next)) {
                    redirect_out_of_scope = true;
                    return Ok(Some(ContentFetch {
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
        return Ok(Some(ContentFetch {
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
    if events.len() >= MAX_CONTENT_EVENTS {
        return Ok(());
    }
    events.push(
        Event::new(
            kind,
            asset_id,
            BoundedDetails::from_value(data, MAX_EVENT_DETAILS_BYTES).map_err(|_| {
                ModuleError::Failed {
                    message: "content discovery event too large".to_owned(),
                    retryable: false,
                }
            })?,
            provenance.clone(),
        )
        .map_err(|_| ModuleError::Failed {
            message: "invalid content discovery event".to_owned(),
            retryable: false,
        })?,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_set_is_small_and_reviewable() {
        assert_eq!(builtin_candidates().len(), 12);
        assert!(
            builtin_candidates()
                .iter()
                .all(|candidate| candidate.starts_with('/'))
        );
    }

    #[test]
    fn candidate_normalization_is_safe_and_deterministic() {
        assert_eq!(
            normalize_candidate(" admin#x ").unwrap(),
            Some("/admin".to_owned())
        );
        assert_eq!(
            normalize_candidate("//evil.test/admin").unwrap_err(),
            CandidateReject::SchemeOrAuthority
        );
        assert_eq!(
            normalize_candidate("../admin").unwrap_err(),
            CandidateReject::PathTraversal
        );
        assert_eq!(
            normalize_candidate("/a//b?q=1#frag").unwrap(),
            Some("/a/b?q=1".to_owned())
        );
        assert_eq!(normalize_candidate("#comment").unwrap(), None);
    }
}
