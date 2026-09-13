//! Phase 9 bounded web crawler: endpoints from evidence, never guesses.
//!
//! Pipeline: confirmed HTTP/HTTPS endpoint → Decision Engine → Crawl task →
//! bounded fetch/extraction → canonical candidates → scope/policy/budget
//! validation → endpoint assets + relationships + evidence → bounded crawl
//! follow-ups through the Decision Engine → Scheduler.
//!
//! This phase discovers endpoints from response evidence already obtained
//! from web applications. It is NOT content brute forcing, fuzzing,
//! vulnerability scanning, or exploitation: no wordlists, no path guessing,
//! no parameter mutation, no form submission, no authentication attempts, no
//! JavaScript execution.
//!
//! # Budget model
//!
//! * Per-task caps (module-enforced): links/forms/scripts/images extracted
//!   per page, scripts fetched, JS bytes, HTML bytes, sitemap entries and
//!   files, robots size, redirect hops, findings.
//! * Subtree caps (engine-enforced via task params): `depth` counts remaining
//!   levels below a task; `pages_left` counts remaining crawl tasks in the
//!   subtree *including* the task itself. The pure [`plan_followups`]
//!   function distributes one allowance deterministically so the total can
//!   never exceed the root allowance — the same function marks eligibility
//!   reasons in module events and gates engine proposals, so budget stops
//!   are always visible, never silent.
//! * Global caps (scheduler-enforced): `max_tasks` bounds every crawl task
//!   like any other; follow-up admission is best-effort.
//!
//! # Scope model
//!
//! Every URL is scope-checked before admission (engine), before execution,
//! before each connection (including every redirect hop, script fetch, and
//! robots/sitemap fetch), and after resolution. Out-of-scope candidates are
//! recorded as observations with `scope_permitted: false` and never
//! contacted — proven by canary tests.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

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

pub const CRAWL_MODULE_NAME: &str = "rxscan.crawl";
pub const CRAWL_MODULE_VERSION: &str = "9.0.0";

/// Hard safety ceilings: configuration and levels can never exceed these.
pub const MAX_DEPTH_HARD: u8 = 6;
pub const MAX_PAGES_PER_ROOT_HARD: u32 = 200;
pub const MAX_LINKS_PER_PAGE_HARD: usize = crate::extract::MAX_LINKS_PER_PAGE;
pub const MAX_SITEMAP_FILES_PER_ROOT: usize = 3;
/// Maximum fetched HTML bytes per page for extraction (larger than the web
/// observation cap: link extraction needs more context than a sample).
pub const CRAWL_MAX_HTML_BYTES: usize = 128 * 1024;
/// Maximum crawl follow-up proposals admitted from one completion.
pub const MAX_CRAWL_PROPOSALS_PER_COMPLETION: usize = 64;
/// Maximum start page URLs per crawl task (engine path always carries one).
pub const MAX_CRAWL_STARTS: usize = 2;
/// Maximum findings per crawl task.
pub const MAX_CRAWL_FINDINGS: usize = 8;
/// Stop starting new work when less than this remains on the task clock.
const CRAWL_PLANNING_FLOOR: Duration = Duration::from_millis(500);

/// Centralized Phase 9 crawl policy. Level sets breadth; speed sets pressure
/// only and never changes what identical content means.
#[derive(Debug, Clone)]
pub struct CrawlPolicy {
    pub level: u8,
    pub goal: ScanGoal,
    pub speed: SpeedSetting,
}

impl CrawlPolicy {
    pub fn new(level: u8, goal: ScanGoal, speed: SpeedSetting) -> Self {
        Self {
            level: level.clamp(1, 5),
            goal,
            speed,
        }
    }

    /// Remaining crawl levels below a root task. L1 performs root-only
    /// extraction (depth 0: the root is fetched, nothing is followed).
    pub fn max_depth(&self) -> u8 {
        match self.level {
            1 => 0,
            2 => 1,
            3 => 2,
            4 => 3,
            _ => 4,
        }
        .min(MAX_DEPTH_HARD)
    }

    /// Maximum crawl tasks in one root's subtree, including the root task.
    pub fn max_pages_per_root(&self) -> u32 {
        match self.level {
            1 => 1,
            2 => 5,
            3 => 15,
            4 => 40,
            _ => 100,
        }
        .min(MAX_PAGES_PER_ROOT_HARD)
    }

    /// robots.txt is fetched for root tasks from L3 up.
    pub fn fetch_robots(&self) -> bool {
        self.level >= 3
    }

    /// Sitemap files are fetched for root tasks from L4 up.
    pub fn fetch_sitemap(&self) -> bool {
        self.level >= 4
    }

    /// Discovered script bodies are fetched and mined from L4 up. Below L4,
    /// script `src` values are recorded as relationships without fetching.
    pub fn fetch_js(&self) -> bool {
        self.level >= 4
    }

    /// Links extracted per page (bounded by the extractor hard cap).
    pub fn max_links_per_page(&self) -> usize {
        match self.level {
            1 => 20,
            2 => 50,
            _ => 100,
        }
        .min(MAX_LINKS_PER_PAGE_HARD)
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
            "crawl level {} ({:?}): depth ≤{}, pages/root ≤{}, links/page ≤{}, robots {}, sitemap {}, js-fetch {}, connect {}ms, response {}ms",
            self.level,
            self.goal,
            self.max_depth(),
            self.max_pages_per_root(),
            self.max_links_per_page(),
            flag(self.fetch_robots()),
            flag(self.fetch_sitemap()),
            flag(self.fetch_js()),
            self.connect_timeout().as_millis(),
            self.response_timeout().as_millis(),
        )
    }
}

fn flag(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

/// Where a candidate came from. The discovery technique is part of every
/// candidate's evidence — consumers never infer it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateSource {
    Link,
    FormAction,
    ScriptSrc,
    ScriptLiteral,
    Stylesheet,
    Image,
    Frame,
    Canonical,
    RobotsPath,
    SitemapUrl,
    SitemapIndex,
}

impl CandidateSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::FormAction => "form-action",
            Self::ScriptSrc => "script-src",
            Self::ScriptLiteral => "script-literal",
            Self::Stylesheet => "stylesheet",
            Self::Image => "image",
            Self::Frame => "frame",
            Self::Canonical => "canonical",
            Self::RobotsPath => "robots-path",
            Self::SitemapUrl => "sitemap-url",
            Self::SitemapIndex => "sitemap-index",
        }
    }

    /// Relationship naming the discovery mechanism for this source.
    pub fn relationship(self) -> RelationshipKind {
        match self {
            Self::Link | Self::Canonical => RelationshipKind::LinksTo,
            Self::FormAction => RelationshipKind::SubmitsTo,
            Self::ScriptSrc => RelationshipKind::LoadsScript,
            Self::Stylesheet | Self::Image | Self::Frame => RelationshipKind::ReferencesEndpoint,
            Self::ScriptLiteral => RelationshipKind::ReferencesEndpoint,
            Self::RobotsPath => RelationshipKind::ReferencesEndpoint,
            Self::SitemapUrl => RelationshipKind::ListsEndpoint,
            Self::SitemapIndex => RelationshipKind::ReferencesSitemap,
        }
    }

    /// Only page-like candidates may seed deeper crawls. Scripts are mined
    /// inline by their parent; images/frames are recorded, never fetched;
    /// form actions are evidence only (forms are never submitted).
    pub fn crawl_eligible(self) -> bool {
        matches!(
            self,
            Self::Link
                | Self::Canonical
                | Self::Stylesheet
                | Self::SitemapUrl
                | Self::SitemapIndex
                | Self::RobotsPath
        )
    }
}

/// One normalized discovery candidate, pre-scope-check.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub url: WebTarget,
    pub source: CandidateSource,
    pub detail: String,
}

/// Inputs to the follow-up planner: sorted, deduped candidates from one
/// completed crawl task plus that task's remaining budgets.
pub struct FollowupPlan {
    pub proposals: Vec<FollowupProposal>,
    pub skipped_depth: usize,
    pub skipped_pages: usize,
}

/// One engine proposal with fully determined child budgets.
#[derive(Debug, Clone)]
pub struct FollowupProposal {
    pub url: WebTarget,
    pub parent_asset_id: String,
    pub source: CandidateSource,
    pub child_depth: u8,
    pub child_pages_left: u32,
}

/// Deterministic budget distribution shared by module (eligibility reasons)
/// and engine (proposal construction): sorted candidates, first-N within
/// the remaining allowance, equal integer shares. The sum of child
/// allowances never exceeds `pages_left - 1`, so any subtree does at most
/// `pages_left` fetches including its root — by induction from the root
/// allowance. Returns proposals plus counts of depth/pages skips so budget
/// stops stay observable.
pub fn plan_followups(
    mut candidates: Vec<(WebTarget, String, CandidateSource)>,
    parent_depth: u8,
    parent_pages_left: u32,
    max_proposals: usize,
) -> FollowupPlan {
    candidates.sort_by(|left, right| {
        left.0
            .canonical()
            .cmp(&right.0.canonical())
            .then_with(|| left.1.cmp(&right.1))
    });
    candidates
        .dedup_by(|right, left| right.0.canonical() == left.0.canonical() && right.1 == left.1);
    let mut plan = FollowupPlan {
        proposals: Vec::new(),
        skipped_depth: 0,
        skipped_pages: 0,
    };
    if parent_depth == 0 {
        plan.skipped_depth = candidates.len();
        return plan;
    }
    let remaining = parent_pages_left.saturating_sub(1);
    if remaining == 0 {
        plan.skipped_pages = candidates.len();
        return plan;
    }
    let take = candidates.len().min(remaining as usize).min(max_proposals);
    if take == 0 {
        plan.skipped_pages = candidates.len();
        return plan;
    }
    let share = remaining / take as u32;
    if share == 0 {
        plan.skipped_pages = candidates.len();
        return plan;
    }
    for (index, (url, parent_asset_id, source)) in candidates.into_iter().enumerate() {
        if index >= take {
            plan.skipped_pages += 1;
            continue;
        }
        plan.proposals.push(FollowupProposal {
            url,
            parent_asset_id,
            source,
            child_depth: parent_depth - 1,
            child_pages_left: share,
        });
    }
    plan
}

/// Stable crawl-task identity helper: the engine and module agree on these
/// params so identical proposals share task IDs and dedupe gracefully.
pub fn crawl_task_params(
    url: &WebTarget,
    root: &WebTarget,
    depth: u8,
    pages_left: u32,
    parent_endpoint: &str,
    target_label: &str,
    is_root: bool,
) -> BTreeMap<String, String> {
    let mut params = BTreeMap::new();
    params.insert("target".to_owned(), target_label.to_owned());
    params.insert("url".to_owned(), url.canonical());
    params.insert("root".to_owned(), root.canonical());
    params.insert("depth".to_owned(), depth.to_string());
    params.insert("pages_left".to_owned(), pages_left.to_string());
    params.insert("parent_endpoint".to_owned(), parent_endpoint.to_owned());
    if is_root {
        params.insert("is_root".to_owned(), "true".to_owned());
    }
    params
}

/// Real scheduler module for `TaskKind::Crawl`.
pub struct CrawlModule {
    policy: CrawlPolicy,
    scope_guard: Arc<dyn ScopeGuard>,
    contacts: crate::contact::ContactRegistry,
}

impl CrawlModule {
    pub fn new(policy: CrawlPolicy, scope_guard: Arc<dyn ScopeGuard>) -> Self {
        Self {
            policy,
            scope_guard,
            contacts: crate::contact::ContactRegistry::new(),
        }
    }

    pub fn with_contact_registry(
        policy: CrawlPolicy,
        scope_guard: Arc<dyn ScopeGuard>,
        contacts: crate::contact::ContactRegistry,
    ) -> Self {
        Self {
            policy,
            scope_guard,
            contacts,
        }
    }

    pub fn policy(&self) -> &CrawlPolicy {
        &self.policy
    }
}

impl Module for CrawlModule {
    fn kind(&self) -> TaskKind {
        TaskKind::Crawl
    }

    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let policy = self.policy.clone();
        let guard = self.scope_guard.clone();
        let contacts = self.contacts.clone();
        Box::pin(async move { execute_crawl(&policy, guard.as_ref(), &contacts, context) })
    }
}

/// One page this task will fetch, with root context.
#[derive(Debug, Clone)]
struct PagePlan {
    url: WebTarget,
    is_root: bool,
}

/// Parsed crawl-task identity: engine proposals carry everything; initial
/// lowering tasks derive roots from scope with policy-maximum budgets.
struct CrawlTarget {
    pages: Vec<PagePlan>,
    depth: u8,
    pages_left: u32,
    root: WebTarget,
    parent_endpoint: String,
    target_label: String,
}

fn parse_task_target(
    task: &crate::execution::Task,
    guard: &dyn ScopeGuard,
    policy: &CrawlPolicy,
    cancel: &CancellationToken,
) -> Result<Option<CrawlTarget>, ModuleError> {
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
    if let Some(url_text) = task.params.get("url") {
        let url = WebTarget::parse(url_text).map_err(|reason| ModuleError::Failed {
            message: format!("invalid crawl URL param: {reason}"),
            retryable: false,
        })?;
        let root = task
            .params
            .get("root")
            .and_then(|text| WebTarget::parse(text).ok())
            .unwrap_or_else(|| url.clone());
        return Ok(Some(CrawlTarget {
            pages: vec![PagePlan {
                url,
                is_root: task
                    .params
                    .get("is_root")
                    .is_some_and(|value| value == "true"),
            }],
            depth: task
                .params
                .get("depth")
                .and_then(|value| value.parse::<u8>().ok())
                .unwrap_or_else(|| policy.max_depth()),
            pages_left: task
                .params
                .get("pages_left")
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or_else(|| policy.max_pages_per_root()),
            root,
            parent_endpoint: task
                .params
                .get("parent_endpoint")
                .cloned()
                .unwrap_or_default(),
            target_label,
        }));
    }
    // Initial lowering path: derive roots from scope (http + https, or the
    // operator's explicit ports), each a root with maximum budgets.
    let explicit_ports: Vec<u16> = task
        .params
        .get("target_ports")
        .map(|list| {
            list.split(',')
                .filter_map(|item| item.trim().parse::<u16>().ok())
                .filter(|port| *port > 0)
                .take(MAX_CRAWL_STARTS)
                .collect()
        })
        .unwrap_or_default();
    let mut roots: Vec<String> = Vec::new();
    let mut push_roots = |host: String| {
        if explicit_ports.is_empty() {
            for (scheme, port) in [(Scheme::Http, 80u16), (Scheme::Https, 443u16)] {
                if roots.len() >= MAX_CRAWL_STARTS {
                    break;
                }
                roots.push(format!(
                    "{}://{}:{}/",
                    scheme.as_str(),
                    bracketed(&host),
                    port
                ));
            }
        } else {
            for port in &explicit_ports {
                if roots.len() >= MAX_CRAWL_STARTS {
                    break;
                }
                roots.push(format!("http://{}:{}/", bracketed(&host), port));
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
            roots.push(url.clone());
            roots.truncate(MAX_CRAWL_STARTS);
        }
        TaskScopeTarget::None => {
            return Err(ModuleError::Failed {
                message: "crawl task has no network target".to_owned(),
                retryable: false,
            });
        }
    }
    let mut pages = Vec::new();
    for root_text in &roots {
        if let Ok(url) = WebTarget::parse(root_text) {
            pages.push(PagePlan { url, is_root: true });
        }
    }
    if pages.is_empty() {
        return Ok(None);
    }
    let root = pages[0].url.clone();
    Ok(Some(CrawlTarget {
        pages,
        depth: policy.max_depth(),
        pages_left: policy.max_pages_per_root(),
        root,
        parent_endpoint: String::new(),
        target_label,
    }))
}

fn bracketed(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

fn scope_target_for_url(url: &WebTarget) -> TaskScopeTarget {
    match url.ip_literal() {
        Some(ip) => TaskScopeTarget::Ip(ip),
        None => TaskScopeTarget::Host(url.host.clone()),
    }
}

/// One fetched document with transport facts.
struct FetchedDocument {
    url: WebTarget,
    status: u16,
    content_type: String,
    body: Vec<u8>,
    body_truncated: bool,
    latency_ms: u64,
    tls_version: Option<String>,
    hops: usize,
}

/// Document Dispatch kind: classifies fetched content for the crawler's
/// extraction dispatch. Each variant represents a content type the crawler
/// knows how to process.
#[derive(Debug, Clone)]
enum DocumentDispatch {
    Html,
    Xml { is_index: bool },
    Js,
    Robots,
    TextList,
    Skip { reason: String },
}

/// Classify a fetched document into a dispatch kind based on its content type.
fn classify_for_crawl(url: &WebTarget, content_type: &str, body: &[u8]) -> DocumentDispatch {
    let lower = content_type.to_ascii_lowercase();
    if url.path.ends_with("/robots.txt") {
        return DocumentDispatch::Robots;
    }
    if lower.contains("text/html") || lower.contains("text/xhtml") {
        return DocumentDispatch::Html;
    }
    if lower.contains("application/xml") || lower.contains("text/xml") || lower.ends_with("+xml") {
        return DocumentDispatch::Xml {
            is_index: url.path.ends_with("/sitemap.xml") || url.path.ends_with("/sitemap"),
        };
    }
    if lower.contains("application/javascript") || lower.contains("text/javascript") {
        return DocumentDispatch::Js;
    }
    if lower.contains("text/plain")
        || lower.contains("application/json")
        || lower.contains("application/xml")
    {
        return DocumentDispatch::TextList;
    }
    if lower.contains("robots") || lower.contains("txt") {
        return DocumentDispatch::Robots;
    }
    if content_type.is_empty() {
        let prefix = String::from_utf8_lossy(&body[..body.len().min(256)]).to_ascii_lowercase();
        if prefix.contains("<html") || prefix.contains("<!doctype html") {
            return DocumentDispatch::Html;
        }
        if prefix.contains("<urlset") || prefix.contains("<sitemapindex") {
            return DocumentDispatch::Xml {
                is_index: prefix.contains("<sitemapindex"),
            };
        }
    }
    DocumentDispatch::Skip {
        reason: "unrecognized content type".to_owned(),
    }
}

/// Fetch one page with crawl bounds and a bounded redirect walk. Every hop
/// is scope-checked before contact; loop/cap/malformed stops return notes.
/// Returns the final document (if any), hop count, and notes.
#[allow(clippy::too_many_arguments)]
fn fetch_document(
    start: &WebTarget,
    policy: &CrawlPolicy,
    guard: &dyn ScopeGuard,
    contacts: &crate::contact::ContactRegistry,
    cancel: &CancellationToken,
    task_deadline: Instant,
    requests_made: &mut usize,
    max_bytes: usize,
) -> Result<(Option<FetchedDocument>, Vec<String>, usize), ModuleError> {
    let mut notes = Vec::new();
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut current = start.clone();
    let max_redirects = usize::from(policy.web_policy().max_redirects());
    let mut hops = 0usize;
    loop {
        if cancel.is_cancelled() {
            return Err(ModuleError::Cancelled);
        }
        if task_deadline.saturating_duration_since(Instant::now()) < Duration::from_millis(500) {
            notes.push("task budget exhausted mid-chain".to_owned());
            return Ok((None, notes, hops));
        }
        let canonical = current.canonical();
        if !visited.insert(canonical.clone()) {
            notes.push(format!("redirect loop detected at {canonical}; stopped"));
            return Ok((None, notes, 0));
        }
        if !guard.permits(&scope_target_for_url(&current)) {
            notes.push(format!(
                "out-of-scope redirect destination {canonical}; recorded, never contacted"
            ));
            return Ok((None, notes, 0));
        }
        // Resolve (scope-filtered, deterministic first addresses).
        let addresses: Vec<IpAddr> = if let Some(ip) = current.ip_literal() {
            if !guard.permits(&TaskScopeTarget::Ip(ip)) {
                notes.push(format!("out-of-scope address {ip}; never contacted"));
                return Ok((None, notes, 0));
            }
            vec![ip]
        } else {
            let permit = |ip: IpAddr| guard.permits(&TaskScopeTarget::Ip(ip));
            match crate::web::resolve_web_addresses(
                &current,
                &permit,
                Duration::from_millis(2000),
                cancel,
            ) {
                Ok(mut addresses) => {
                    addresses.truncate(4);
                    if addresses.is_empty() {
                        notes.push(format!(
                            "no scannable address for {} (resolution failed or filtered)",
                            current.canonical()
                        ));
                        return Ok((None, notes, 0));
                    }
                    addresses
                }
                Err(reason) if reason == "cancelled" => return Err(ModuleError::Cancelled),
                Err(reason) => {
                    notes.push(format!("address resolution failed ({reason})"));
                    return Ok((None, notes, 0));
                }
            }
        };
        let purpose = if hops == 0 {
            crate::contact::RequestPurpose::CrawlPage
        } else {
            crate::contact::RequestPurpose::RedirectFollow
        };
        if !contacts.claim(&current, purpose) {
            notes.push(format!(
                "request for {} skipped because it was already contacted in this scan",
                current.canonical()
            ));
            return Ok((None, notes, hops));
        }
        let remaining = task_deadline
            .saturating_duration_since(Instant::now())
            .min(policy.response_timeout());
        let mut fetched: Option<crate::web::RawFetch> = None;
        for ip in addresses {
            if cancel.is_cancelled() {
                return Err(ModuleError::Cancelled);
            }
            if Instant::now() >= task_deadline {
                break;
            }
            let attempt = match current.scheme {
                Scheme::Http => crate::web::fetch_plain(
                    ip,
                    &current,
                    "GET",
                    true,
                    max_bytes,
                    policy.connect_timeout(),
                    remaining,
                    cancel,
                    task_deadline,
                ),
                Scheme::Https => crate::web::fetch_tls(
                    ip,
                    &current,
                    (!current.is_ip_literal()).then_some(current.host.as_str()),
                    "GET",
                    true,
                    max_bytes,
                    policy.connect_timeout(),
                    remaining,
                    cancel,
                    task_deadline,
                ),
            };
            *requests_made += 1;
            match attempt {
                Ok(value) => {
                    fetched = Some(value);
                    break;
                }
                Err(crate::web::FetchFailure::Cancelled) => return Err(ModuleError::Cancelled),
                Err(_) => continue,
            }
        }
        let Some(raw_fetch) = fetched else {
            notes.push(format!(
                "connection failed for {} (refused, timeout, or unreachable)",
                current.canonical()
            ));
            return Ok((None, notes, 0));
        };
        let mut raw = raw_fetch.head.clone();
        raw.extend_from_slice(&raw_fetch.body);
        let latency_ms = raw_fetch.latency_ms;
        let Some(response) = crate::web::parse_response(&raw, latency_ms) else {
            notes.push(format!(
                "response from {} is not valid HTTP; recorded, not classified",
                current.canonical()
            ));
            return Ok((None, notes, 0));
        };
        if (300..400).contains(&response.status) {
            if let Some(location) = response.location.clone() {
                if hops >= max_redirects {
                    notes.push(format!(
                        "redirect cap reached at {} (policy allows {max_redirects}); recorded, not followed",
                        current.canonical()
                    ));
                    return Ok((None, notes, 0));
                }
                match current.resolve_location(&location) {
                    Ok(destination) => {
                        if visited.contains(&destination.canonical()) {
                            notes.push(format!(
                                "redirect loop detected ({} already visited)",
                                destination.canonical()
                            ));
                            return Ok((None, notes, 0));
                        }
                        if !guard.permits(&scope_target_for_url(&destination)) {
                            notes.push(format!(
                                "out-of-scope redirect destination {}; recorded, never contacted",
                                destination.canonical()
                            ));
                            return Ok((None, notes, 0));
                        }
                        hops += 1;
                        current = destination;
                        continue;
                    }
                    Err(reason) => {
                        notes.push(format!(
                            "malformed redirect destination ({reason}); not followed"
                        ));
                        return Ok((None, notes, 0));
                    }
                }
            }
        }
        return Ok((
            Some(FetchedDocument {
                url: current.clone(),
                status: response.status,
                content_type: response.content_type.clone().unwrap_or_default(),
                body: raw_fetch.body,
                body_truncated: raw_fetch.body_truncated,
                latency_ms,
                tls_version: raw_fetch
                    .tls
                    .as_ref()
                    .map(|observation| observation.negotiated_version.clone()),
                hops,
            }),
            notes,
            hops,
        ));
    }
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

fn push_relationship(
    event: &mut Event,
    kind: RelationshipKind,
    from: AssetId,
    to: AssetId,
    provenance: &Provenance,
) -> Result<(), ModuleError> {
    if from == to {
        return Ok(());
    }
    event.relationships.push(
        Relationship::new(
            kind,
            RelationshipSubject::Asset(from),
            RelationshipSubject::Asset(to),
            provenance.clone(),
        )
        .map_err(|_| ModuleError::Failed {
            message: "invalid relationship".to_owned(),
            retryable: false,
        })?,
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn execute_crawl(
    policy: &CrawlPolicy,
    guard: &dyn ScopeGuard,
    contacts: &crate::contact::ContactRegistry,
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
        CRAWL_MODULE_NAME,
        CRAWL_MODULE_VERSION,
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
    let Some(crawl_target) = parse_task_target(&task, guard, policy, &cancel)? else {
        return Ok(ModuleOutput {
            events,
            evidence: evidence_items,
            findings,
            assets,
        });
    };

    push_event(
        &mut events,
        EventKind::CrawlStarted,
        None,
        serde_json::json!({
            "target": target_label,
            "policy": policy.describe(),
            "root": crawl_target.root.canonical(),
            "depth": crawl_target.depth,
            "pages_left": crawl_target.pages_left,
        }),
        &provenance,
    )?;

    let mut state = CrawlRunState {
        policy,
        guard,
        contacts,
        cancel: &cancel,
        task_deadline,
        target_label: target_label.clone(),
        provenance: provenance.clone(),
        events: std::mem::take(&mut events),
        evidence_items: std::mem::take(&mut evidence_items),
        assets: std::mem::take(&mut assets),
        findings: std::mem::take(&mut findings),
        requests_made: 0,
        pages_fetched: 0,
        budget_notes: Vec::new(),
    };

    for page in &crawl_target.pages {
        if cancel.is_cancelled() {
            return Err(ModuleError::Cancelled);
        }
        if task_deadline.saturating_duration_since(Instant::now()) < CRAWL_PLANNING_FLOOR {
            state.note_budget("task-deadline");
            state.emit_budget_exhausted("task-deadline")?;
            break;
        }
        if let Err(ModuleError::Cancelled) = state.crawl_page(page, &crawl_target) {
            return Err(ModuleError::Cancelled);
        }
    }

    let elapsed_ms = start_instant.elapsed().as_millis() as u64;
    push_event(
        &mut state.events,
        EventKind::CrawlCompleted,
        None,
        serde_json::json!({
            "target": target_label,
            "policy": policy.describe(),
            "pages_fetched": state.pages_fetched,
            "requests_made": state.requests_made,
            "budget_notes": state.budget_notes,
            "elapsed_ms": elapsed_ms,
        }),
        &provenance,
    )?;
    Ok(ModuleOutput {
        events: state.events,
        evidence: state.evidence_items,
        findings: state.findings,
        assets: state.assets,
    })
}

struct CrawlRunState<'a> {
    policy: &'a CrawlPolicy,
    guard: &'a dyn ScopeGuard,
    contacts: &'a crate::contact::ContactRegistry,
    cancel: &'a CancellationToken,
    task_deadline: Instant,
    target_label: String,
    provenance: Provenance,
    events: Vec<Event>,
    evidence_items: Vec<Evidence>,
    assets: Vec<Asset>,
    findings: Vec<Finding>,
    requests_made: usize,
    pages_fetched: usize,
    budget_notes: Vec<String>,
}

impl CrawlRunState<'_> {
    fn note_budget(&mut self, reason: &str) {
        if !self.budget_notes.iter().any(|note| note == reason) {
            self.budget_notes.push(reason.to_owned());
        }
    }

    fn emit_budget_exhausted(&mut self, reason: &str) -> Result<(), ModuleError> {
        self.note_budget(reason);
        push_event(
            &mut self.events,
            EventKind::CrawlBudgetExhausted,
            None,
            serde_json::json!({
                "target": self.target_label,
                "reason": reason,
                "pages_fetched": self.pages_fetched,
                "requests_made": self.requests_made,
            }),
            &self.provenance,
        )
    }

    /// Ensure an endpoint asset exists (idempotent by stable ID) and return
    /// its ID. Identity namespaces by discoverer parent; the ID is the
    /// cross-phase join key.
    fn ensure_endpoint_asset(
        &mut self,
        url: &WebTarget,
        parent_asset_id: &str,
        resource: Option<&str>,
    ) -> Result<AssetId, ModuleError> {
        let (local_identity, identity_truncated) = crate::web::endpoint_local_identity(url);
        let endpoint_id = crate::web::endpoint_asset_id(url);
        if !self.assets.iter().any(|asset| asset.id.0 == endpoint_id) {
            let mut attributes = BTreeMap::from([("url".to_owned(), url.canonical())]);
            if let Some(resource) = resource {
                attributes.insert("resource".to_owned(), resource.to_owned());
            }
            if identity_truncated {
                attributes.insert("identity_truncated".to_owned(), "true".to_owned());
            }
            self.assets.push(Asset {
                schema_version: crate::model::SCHEMA_VERSION,
                id: AssetId(endpoint_id.clone()),
                kind: AssetKind::Endpoint,
                identity: format!("{parent_asset_id}:{local_identity}"),
                attributes,
                first_seen: self.provenance.timestamp,
                last_seen: self.provenance.timestamp,
                provenance: self.provenance.clone(),
            });
        }
        Ok(AssetId(endpoint_id))
    }

    /// Emit one candidate: endpoint asset (in-scope only) + EndpointDiscovered
    /// event with the discovery relationship, or a scope-denied observation
    /// with no asset and no contact. Returns the endpoint asset ID when
    /// created, for follow-up correlation.
    #[allow(clippy::too_many_arguments)]
    fn emit_candidate(
        &mut self,
        url: &WebTarget,
        source: crate::crawl::CandidateSource,
        parent_asset_id: &str,
        page_url: &str,
        eligible: bool,
        reason: &str,
        resource: Option<&str>,
    ) -> Result<Option<AssetId>, ModuleError> {
        use crate::crawl::CandidateSource as Source;
        let in_scope = self.guard.permits(&scope_target_for_url(url));
        if !in_scope {
            let mut event = Event::new(
                EventKind::EndpointDiscovered,
                None,
                BoundedDetails::from_value(
                    serde_json::json!({
                        "target": self.target_label,
                        "url": url.canonical(),
                        "source": source.as_str(),
                        "parent_asset_id": parent_asset_id,
                        "page_url": page_url,
                        "scope_permitted": false,
                        "crawl_eligible": false,
                        "reason": "out-of-scope candidate; recorded, never contacted",
                    }),
                    MAX_EVENT_DETAILS_BYTES,
                )
                .map_err(|_| ModuleError::Failed {
                    message: "event details too large".to_owned(),
                    retryable: false,
                })?,
                self.provenance.clone(),
            )
            .map_err(|_| ModuleError::Failed {
                message: "invalid event".to_owned(),
                retryable: false,
            })?;
            push_relationship(
                &mut event,
                source.relationship(),
                AssetId(parent_asset_id.to_owned()),
                AssetId(crate::web::endpoint_asset_id(url)),
                &self.provenance,
            )?;
            self.events.push(event);
            return Ok(None);
        }
        let endpoint_id = self.ensure_endpoint_asset(url, parent_asset_id, resource)?;
        let mut event = Event::new(
            EventKind::EndpointDiscovered,
            Some(endpoint_id.clone()),
            BoundedDetails::from_value(
                serde_json::json!({
                    "target": self.target_label,
                    "url": url.canonical(),
                    "source": source.as_str(),
                    "parent_asset_id": parent_asset_id,
                    "page_url": page_url,
                    "scope_permitted": true,
                    "crawl_eligible": eligible && matches!(source,
                        Source::Link | Source::Canonical | Source::Stylesheet
                        | Source::SitemapUrl | Source::SitemapIndex | Source::RobotsPath),
                    "reason": reason,
                }),
                MAX_EVENT_DETAILS_BYTES,
            )
            .map_err(|_| ModuleError::Failed {
                message: "event details too large".to_owned(),
                retryable: false,
            })?,
            self.provenance.clone(),
        )
        .map_err(|_| ModuleError::Failed {
            message: "invalid event".to_owned(),
            retryable: false,
        })?;
        push_relationship(
            &mut event,
            source.relationship(),
            AssetId(parent_asset_id.to_owned()),
            endpoint_id.clone(),
            &self.provenance,
        )?;
        self.events.push(event);
        // Per-source typed observations share the endpoint record.
        let source_event = match source {
            Source::Link | Source::Canonical | Source::Stylesheet => Some(EventKind::LinkObserved),
            Source::FormAction => Some(EventKind::FormObserved),
            Source::ScriptSrc | Source::ScriptLiteral => Some(EventKind::ScriptObserved),
            _ => None,
        };
        if let Some(kind) = source_event {
            push_event(
                &mut self.events,
                kind,
                Some(endpoint_id.clone()),
                serde_json::json!({
                    "target": self.target_label,
                    "url": url.canonical(),
                    "source": source.as_str(),
                    "page_url": page_url,
                }),
                &self.provenance,
            )?;
        }
        Ok(Some(endpoint_id))
    }

    /// Crawl one page: fetch, dispatch by content, extract, emit. All
    /// candidates flow through `emit_candidate`; follow-up scheduling belongs
    /// to the Decision Engine, never here.
    fn crawl_page(&mut self, page: &PagePlan, target: &CrawlTarget) -> Result<(), ModuleError> {
        if !self.guard.permits(&scope_target_for_url(&page.url)) {
            return Ok(());
        }
        let (document, notes, _hops) = fetch_document(
            &page.url,
            self.policy,
            self.guard,
            self.contacts,
            self.cancel,
            self.task_deadline,
            &mut self.requests_made,
            CRAWL_MAX_HTML_BYTES,
        )?;
        for note in notes {
            self.note_budget(&note);
        }
        let Some(document) = document else {
            return Ok(());
        };
        self.pages_fetched += 1;
        let parent_id = if target.parent_endpoint.is_empty() {
            target.target_label.as_str()
        } else {
            target.parent_endpoint.as_str()
        };
        let page_asset_id = self.ensure_endpoint_asset(&document.url, parent_id, None)?;
        let _ = page_asset_id;
        // Re-resolve the page asset ID deterministically for relationships.
        let page_asset = AssetId(crate::web::endpoint_asset_id(&document.url));
        self.crawl_document(&document, &page_asset, page.is_root)?;
        Ok(())
    }

    /// Extract from one fetched document and emit candidates + evidence.
    fn crawl_document(
        &mut self,
        document: &FetchedDocument,
        page_asset: &AssetId,
        is_root: bool,
    ) -> Result<(), ModuleError> {
        let kind = classify_for_crawl(&document.url, &document.content_type, &document.body);
        let page_url = document.url.canonical();
        let mut counts = BTreeMap::from([
            ("links", 0usize),
            ("forms", 0usize),
            ("scripts", 0usize),
            ("images", 0usize),
            ("sitemap_urls", 0usize),
            ("js_literals", 0usize),
        ]);
        let mut truncated_flags: Vec<String> = Vec::new();
        match kind {
            DocumentDispatch::Html => {
                let refs = crate::extract::extract_html_refs(&document.body);
                // Effective base: <base href> resolved against the page URL,
                // else the page URL itself.
                let base = refs
                    .base_href
                    .as_deref()
                    .and_then(|href| document.url.resolve_location(href).ok())
                    .unwrap_or_else(|| document.url.clone());
                let max_links = self.policy.max_links_per_page();
                let mut link_candidates: Vec<(WebTarget, String)> = Vec::new();
                for raw in refs
                    .links
                    .iter()
                    .chain(refs.stylesheets.iter())
                    .chain(refs.frames.iter())
                {
                    let Some(value) = crate::extract::classify_reference(&raw.value) else {
                        continue;
                    };
                    let Ok(resolved) = base.resolve_location(value) else {
                        continue;
                    };
                    link_candidates.push((resolved, page_asset.0.clone()));
                }
                if refs.truncated_links || link_candidates.len() > max_links {
                    truncated_flags.push("links-capped".to_owned());
                    self.note_budget("links-per-page-cap");
                    self.emit_budget_exhausted("links-per-page-cap")?;
                }
                link_candidates.truncate(max_links);
                for (url, parent) in link_candidates {
                    *counts.get_mut("links").unwrap() += 1;
                    self.emit_candidate(
                        &url,
                        CandidateSource::Link,
                        &parent,
                        &page_url,
                        true,
                        "anchor/stylesheet/frame reference",
                        None,
                    )?;
                }
                if let Some(canonical) = refs.canonical.as_deref() {
                    if let Some(value) = crate::extract::classify_reference(canonical) {
                        if let Ok(resolved) = base.resolve_location(value) {
                            *counts.get_mut("links").unwrap() += 1;
                            self.emit_candidate(
                                &resolved,
                                CandidateSource::Canonical,
                                &page_asset.0,
                                &page_url,
                                true,
                                "canonical link observation",
                                None,
                            )?;
                        }
                    }
                }
                for form in &refs.forms {
                    self.emit_form(form, &page_asset.0, &page_url, &base)?;
                    *counts.get_mut("forms").unwrap() += 1;
                }
                if refs.truncated_forms {
                    truncated_flags.push("forms-capped".to_owned());
                    self.note_budget("forms-per-page-cap");
                    self.emit_budget_exhausted("forms-per-page-cap")?;
                }
                let mut scripts = refs.scripts.clone();
                if scripts.len() > crate::extract::MAX_SCRIPTS_PER_PAGE {
                    scripts.truncate(crate::extract::MAX_SCRIPTS_PER_PAGE);
                    truncated_flags.push("scripts-capped".to_owned());
                    self.note_budget("scripts-per-page-cap");
                    self.emit_budget_exhausted("scripts-per-page-cap")?;
                }
                for raw in &scripts {
                    let Some(value) = crate::extract::classify_reference(&raw.value) else {
                        continue;
                    };
                    let Ok(resolved) = base.resolve_location(value) else {
                        continue;
                    };
                    *counts.get_mut("scripts").unwrap() += 1;
                    let script_asset = self.emit_candidate(
                        &resolved,
                        CandidateSource::ScriptSrc,
                        &page_asset.0,
                        &page_url,
                        false,
                        "script reference recorded; body fetched inline at L4+ only",
                        Some("script"),
                    )?;
                    if self.policy.fetch_js() {
                        if let Some(asset) = script_asset {
                            self.mine_script(&resolved, &asset, &page_url)?;
                        }
                    }
                }
                if refs.truncated_scripts {
                    truncated_flags.push("scripts-capped".to_owned());
                    self.note_budget("scripts-per-page-cap");
                    self.emit_budget_exhausted("scripts-per-page-cap")?;
                }
                for raw in &refs.images {
                    let Some(value) = crate::extract::classify_reference(&raw.value) else {
                        continue;
                    };
                    let Ok(resolved) = base.resolve_location(value) else {
                        continue;
                    };
                    if self.guard.permits(&scope_target_for_url(&resolved)) {
                        *counts.get_mut("images").unwrap() += 1;
                        self.emit_candidate(
                            &resolved,
                            CandidateSource::Image,
                            &page_asset.0,
                            &page_url,
                            false,
                            "static resource recorded without fetching",
                            Some("image"),
                        )?;
                    } else {
                        self.emit_candidate(
                            &resolved,
                            CandidateSource::Image,
                            &page_asset.0,
                            &page_url,
                            false,
                            "out-of-scope static reference; recorded, never contacted",
                            Some("image"),
                        )?;
                    }
                    if *counts.get("images").unwrap_or(&0) >= crate::extract::MAX_IMAGES_PER_PAGE {
                        truncated_flags.push("images-capped".to_owned());
                        self.note_budget("images-per-page-cap");
                        self.emit_budget_exhausted("images-per-page-cap")?;
                        break;
                    }
                }
                if refs.truncated_images
                    && !truncated_flags.iter().any(|flag| flag == "images-capped")
                {
                    truncated_flags.push("images-capped".to_owned());
                    self.note_budget("images-per-page-cap");
                    self.emit_budget_exhausted("images-per-page-cap")?;
                }
            }
            DocumentDispatch::Xml { is_index } => {
                let (locations, _, entries_truncated) =
                    crate::extract::extract_sitemap_locs(&document.body);
                if entries_truncated {
                    truncated_flags.push("sitemap-entries-capped".to_owned());
                    self.note_budget("sitemap-entries-cap");
                }
                push_event(
                    &mut self.events,
                    EventKind::SitemapObserved,
                    Some(page_asset.clone()),
                    serde_json::json!({
                        "target": self.target_label,
                        "url": page_url,
                        "is_index": is_index,
                        "entries": locations.len(),
                        "truncated": entries_truncated,
                    }),
                    &self.provenance,
                )?;
                for location in locations {
                    let Ok(resolved) = document.url.resolve_location(&location) else {
                        continue;
                    };
                    let source = if is_index {
                        CandidateSource::SitemapIndex
                    } else {
                        CandidateSource::SitemapUrl
                    };
                    *counts.get_mut("sitemap_urls").unwrap() += 1;
                    self.emit_candidate(
                        &resolved,
                        source,
                        &page_asset.0,
                        &page_url,
                        true,
                        if is_index {
                            "sitemap-index entry"
                        } else {
                            "sitemap-listed URL"
                        },
                        None,
                    )?;
                }
            }
            DocumentDispatch::Js => {
                let literals = crate::extract::extract_js_urls(
                    &document.body,
                    crate::extract::MAX_JS_LITERALS,
                );
                *counts.get_mut("js_literals").unwrap() = literals.len();
                push_event(
                    &mut self.events,
                    EventKind::ScriptObserved,
                    Some(page_asset.clone()),
                    serde_json::json!({
                        "target": self.target_label,
                        "url": page_url,
                        "literals": literals.len(),
                    }),
                    &self.provenance,
                )?;
                for literal in literals {
                    let Ok(resolved) = document.url.resolve_location(&literal) else {
                        continue;
                    };
                    self.emit_candidate(
                        &resolved,
                        CandidateSource::ScriptLiteral,
                        &page_asset.0,
                        &page_url,
                        true,
                        "conservative JS literal reference",
                        None,
                    )?;
                }
            }
            DocumentDispatch::Robots => {
                self.crawl_robots_document(document, page_asset, &page_url, is_root)?;
            }
            DocumentDispatch::TextList => {
                let text = String::from_utf8_lossy(&document.body);
                for line in text.lines().take(crate::extract::MAX_SITEMAP_ENTRIES) {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let Ok(resolved) = document.url.resolve_location(line) else {
                        continue;
                    };
                    // Absolute http(s) URLs only (enforced by resolve +
                    // scheme check below); anything else is not a target.
                    if !matches!(resolved.scheme, Scheme::Http | Scheme::Https) {
                        continue;
                    }
                    *counts.get_mut("sitemap_urls").unwrap() += 1;
                    self.emit_candidate(
                        &resolved,
                        CandidateSource::SitemapUrl,
                        &page_asset.0,
                        &page_url,
                        true,
                        "plain-text sitemap entry",
                        None,
                    )?;
                }
            }
            DocumentDispatch::Skip { reason } => {
                self.note_budget(&format!("unparsed-content:{reason}"));
            }
        }
        // Robots + sitemap discovery inputs for roots, per level policy.
        if is_root {
            if self.policy.fetch_robots() {
                self.crawl_robots_manifest(&document.url, page_asset, &page_url)?;
            }
            if self.policy.fetch_sitemap() {
                // Sitemap locations advertised by robots are fetched inline
                // (bounded file count); their entries become candidates.
                // (Inline fetch happens inside crawl_robots_manifest when the
                // manifest itself was fetched; direct /sitemap.xml probing is
                // intentionally NOT done — no guessing paths.)
            }
        }
        self.emit_page_evidence(document, page_asset, &page_url, &counts, &truncated_flags)?;
        if self.findings.len() < MAX_CRAWL_FINDINGS {
            let mut finding = Finding::new(
                format!("Crawled endpoint {}", document.url.canonical()),
                Severity::Info,
                Confidence::new(70).map_err(|_| ModuleError::Failed {
                    message: "invalid confidence".to_owned(),
                    retryable: false,
                })?,
                page_asset.clone(),
                self.provenance.clone(),
            )
            .map_err(|_| ModuleError::Failed {
                message: "invalid finding".to_owned(),
                retryable: false,
            })?;
            finding.metadata.insert(
                "url".to_owned(),
                serde_json::Value::String(document.url.canonical()),
            );
            finding.metadata.insert(
                "status".to_owned(),
                serde_json::Value::from(document.status),
            );
            self.findings.push(finding);
        } else {
            self.note_budget("findings-cap");
            self.emit_budget_exhausted("findings-cap")?;
        }
        Ok(())
    }

    /// Emit one form: bounded field metadata, SubmitsTo relationship, and a
    /// FormObserved event. The action is evidence only — never submitted.
    fn emit_form(
        &mut self,
        form: &crate::extract::FormRef,
        parent_asset_id: &str,
        page_url: &str,
        base: &WebTarget,
    ) -> Result<(), ModuleError> {
        let Some(action) = form
            .action
            .as_deref()
            .and_then(crate::extract::classify_reference)
        else {
            push_event(
                &mut self.events,
                EventKind::FormObserved,
                None,
                serde_json::json!({
                    "target": self.target_label,
                    "page_url": page_url,
                    "method": form.method,
                    "inputs": form.inputs.iter().map(|(name, kind)| serde_json::json!({"name": name, "type": kind})).collect::<Vec<_>>(),
                    "note": "form without resolvable action; recorded, never submitted",
                }),
                &self.provenance,
            )?;
            return Ok(());
        };
        let Ok(resolved) = base.resolve_location(action) else {
            return Ok(());
        };
        self.emit_candidate(
            &resolved,
            CandidateSource::FormAction,
            parent_asset_id,
            page_url,
            false,
            "form action recorded; forms are never submitted",
            None,
        )?;
        push_event(
            &mut self.events,
            EventKind::FormObserved,
            None,
            serde_json::json!({
                "target": self.target_label,
                "page_url": page_url,
                "action": resolved.canonical(),
                "method": form.method,
                "inputs": form.inputs.iter().map(|(name, kind)| serde_json::json!({"name": name, "type": kind})).collect::<Vec<_>>(),
                "inputs_truncated": form.inputs_truncated,
            }),
            &self.provenance,
        )?;
        Ok(())
    }

    /// Fetch one discovered script (scope-checked, byte-capped) and mine
    /// conservative URL literals from its body.
    fn mine_script(
        &mut self,
        url: &WebTarget,
        script_asset: &AssetId,
        page_url: &str,
    ) -> Result<(), ModuleError> {
        if !self.guard.permits(&scope_target_for_url(url)) {
            return Ok(());
        }
        if self.task_deadline_reached() {
            self.note_budget("task-deadline");
            return Ok(());
        }
        let (document, notes, _) = fetch_document(
            url,
            self.policy,
            self.guard,
            self.contacts,
            self.cancel,
            self.task_deadline,
            &mut self.requests_made,
            crate::extract::MAX_JS_BYTES,
        )?;
        for note in notes {
            self.note_budget(&note);
        }
        let Some(document) = document else {
            return Ok(());
        };
        let literals =
            crate::extract::extract_js_urls(&document.body, crate::extract::MAX_JS_LITERALS);
        push_event(
            &mut self.events,
            EventKind::ScriptObserved,
            Some(script_asset.clone()),
            serde_json::json!({
                "target": self.target_label,
                "url": url.canonical(),
                "literals": literals.len(),
                "status": document.status,
            }),
            &self.provenance,
        )?;
        for literal in literals {
            let Ok(resolved) = url.resolve_location(&literal) else {
                continue;
            };
            if !matches!(resolved.scheme, Scheme::Http | Scheme::Https) {
                continue;
            }
            self.emit_candidate(
                &resolved,
                CandidateSource::ScriptLiteral,
                &script_asset.0,
                page_url,
                true,
                "conservative JS literal reference",
                None,
            )?;
        }
        Ok(())
    }

    /// Crawl the robots manifest + advertised sitemaps for a root page.
    fn crawl_robots_manifest(
        &mut self,
        page_url: &WebTarget,
        page_asset: &AssetId,
        root_page_url: &str,
    ) -> Result<(), ModuleError> {
        let origin = WebTarget {
            scheme: page_url.scheme,
            host: page_url.host.clone(),
            port: page_url.port,
            path: "/robots.txt".to_owned(),
            query: None,
        };
        if !self.guard.permits(&scope_target_for_url(&origin)) {
            return Ok(());
        }
        if self.task_deadline_reached() {
            self.note_budget("task-deadline");
            return Ok(());
        }
        let (document, notes, _) = fetch_document(
            &origin,
            self.policy,
            self.guard,
            self.contacts,
            self.cancel,
            self.task_deadline,
            &mut self.requests_made,
            crate::extract::MAX_ROBOTS_BYTES,
        )?;
        for note in notes {
            self.note_budget(&note);
        }
        let Some(document) = document else {
            return Ok(());
        };
        if document.status != 200 {
            return Ok(());
        }
        let text = String::from_utf8_lossy(&document.body).into_owned();
        let robots = crate::extract::parse_robots_txt(&text);
        if robots.truncated {
            self.note_budget("robots-truncated");
        }
        push_event(
            &mut self.events,
            EventKind::RobotsObserved,
            Some(page_asset.clone()),
            serde_json::json!({
                "target": self.target_label,
                "url": origin.canonical(),
                "allows": robots.allows.len(),
                "disallows": robots.disallows.len(),
                "sitemaps": robots.sitemaps,
                "truncated": robots.truncated,
            }),
            &self.provenance,
        )?;
        self.emit_page_evidence_raw(
            &origin.canonical(),
            &page_asset.0,
            "robots",
            &serde_json::json!({
                "allows": robots.allows,
                "disallows": robots.disallows,
                "sitemaps": robots.sitemaps,
            }),
        )?;
        let base = &document.url;
        for entry in robots.allows.iter().chain(robots.disallows.iter()) {
            let Ok(resolved) = base.resolve_location(entry) else {
                continue;
            };
            if !matches!(resolved.scheme, Scheme::Http | Scheme::Https) {
                continue;
            }
            self.emit_candidate(
                &resolved,
                CandidateSource::RobotsPath,
                &page_asset.0,
                root_page_url,
                true,
                "robots.txt-listed path (discovery input, not authorization)",
                None,
            )?;
        }
        if !self.policy.fetch_sitemap() {
            return Ok(());
        }
        let mut files = 0usize;
        for sitemap in &robots.sitemaps {
            if files >= MAX_SITEMAP_FILES_PER_ROOT {
                self.note_budget("sitemap-files-cap");
                self.emit_budget_exhausted("sitemap-files-cap")?;
                break;
            }
            // Sitemap URLs are usually absolute; resolve defensively anyway.
            let Ok(location) = base
                .resolve_location(sitemap)
                .or_else(|_| WebTarget::parse(sitemap))
            else {
                continue;
            };
            if !matches!(location.scheme, Scheme::Http | Scheme::Https) {
                continue;
            }
            if !self.guard.permits(&scope_target_for_url(&location)) {
                self.emit_candidate(
                    &location,
                    CandidateSource::SitemapIndex,
                    &page_asset.0,
                    root_page_url,
                    false,
                    "out-of-scope sitemap reference; recorded, never contacted",
                    None,
                )?;
                continue;
            }
            files += 1;
            self.crawl_sitemap_file(&location, &page_asset.0, root_page_url)?;
        }
        Ok(())
    }

    /// Fetch one sitemap document and emit its entries as candidates.
    fn crawl_sitemap_file(
        &mut self,
        url: &WebTarget,
        parent_asset_id: &str,
        root_page_url: &str,
    ) -> Result<(), ModuleError> {
        if self.task_deadline_reached() {
            self.note_budget("task-deadline");
            return Ok(());
        }
        let (document, notes, _) = fetch_document(
            url,
            self.policy,
            self.guard,
            self.contacts,
            self.cancel,
            self.task_deadline,
            &mut self.requests_made,
            CRAWL_MAX_HTML_BYTES,
        )?;
        for note in notes {
            self.note_budget(&note);
        }
        let Some(document) = document else {
            return Ok(());
        };
        if document.status != 200 {
            return Ok(());
        }
        let (locations, is_index, entries_truncated) =
            crate::extract::extract_sitemap_locs(&document.body);
        if entries_truncated {
            self.note_budget("sitemap-entries-cap");
            self.emit_budget_exhausted("sitemap-entries-cap")?;
        }
        push_event(
            &mut self.events,
            EventKind::SitemapObserved,
            Some(AssetId(parent_asset_id.to_owned())),
            serde_json::json!({
                "target": self.target_label,
                "url": url.canonical(),
                "is_index": is_index,
                "entries": locations.len(),
                "truncated": entries_truncated,
            }),
            &self.provenance,
        )?;
        for location in locations {
            let Ok(resolved) = document
                .url
                .resolve_location(&location)
                .or_else(|_| WebTarget::parse(&location))
            else {
                continue;
            };
            if !matches!(resolved.scheme, Scheme::Http | Scheme::Https) {
                continue;
            }
            let source = if is_index {
                CandidateSource::SitemapIndex
            } else {
                CandidateSource::SitemapUrl
            };
            self.emit_candidate(
                &resolved,
                source,
                parent_asset_id,
                root_page_url,
                true,
                if is_index {
                    "sitemap-index entry"
                } else {
                    "sitemap-listed URL"
                },
                None,
            )?;
        }
        Ok(())
    }

    /// Handle a robots.txt document reached as a crawl target (e.g. a
    /// sitemap-index entry or an explicitly proposed robots URL).
    fn crawl_robots_document(
        &mut self,
        document: &FetchedDocument,
        page_asset: &AssetId,
        page_url: &str,
        _is_root: bool,
    ) -> Result<(), ModuleError> {
        let text = String::from_utf8_lossy(&document.body).into_owned();
        let robots = crate::extract::parse_robots_txt(&text);
        if robots.truncated {
            self.note_budget("robots-truncated");
        }
        push_event(
            &mut self.events,
            EventKind::RobotsObserved,
            Some(page_asset.clone()),
            serde_json::json!({
                "target": self.target_label,
                "url": page_url,
                "allows": robots.allows.len(),
                "disallows": robots.disallows.len(),
                "sitemaps": robots.sitemaps,
                "truncated": robots.truncated,
            }),
            &self.provenance,
        )?;
        for entry in robots.allows.iter().chain(robots.disallows.iter()) {
            let Ok(resolved) = document.url.resolve_location(entry) else {
                continue;
            };
            if !matches!(resolved.scheme, Scheme::Http | Scheme::Https) {
                continue;
            }
            self.emit_candidate(
                &resolved,
                CandidateSource::RobotsPath,
                &page_asset.0,
                page_url,
                true,
                "robots.txt-listed path (discovery input, not authorization)",
                None,
            )?;
        }
        Ok(())
    }

    /// Per-page evidence: counts, truncation flags, transport facts.
    #[allow(clippy::too_many_arguments)]
    fn emit_page_evidence(
        &mut self,
        document: &FetchedDocument,
        page_asset: &AssetId,
        page_url: &str,
        counts: &BTreeMap<&str, usize>,
        truncated_flags: &[String],
    ) -> Result<(), ModuleError> {
        let details = BoundedDetails::from_value(
            serde_json::json!({
                "target": self.target_label,
                "url": page_url,
                "status": document.status,
                "content_type": document.content_type,
                "tls_version": document.tls_version,
                "body_bytes": document.body.len(),
                "body_truncated": document.body_truncated,
                "redirect_hops": document.hops,
                "counts": counts,
                "truncated": truncated_flags,
                "latency_ms": document.latency_ms,
            }),
            crate::model::MAX_EVIDENCE_DETAILS_BYTES,
        )
        .map_err(|_| ModuleError::Failed {
            message: "evidence details too large".to_owned(),
            retryable: false,
        })?;
        let confidence = Confidence::new(75).map_err(|_| ModuleError::Failed {
            message: "invalid confidence".to_owned(),
            retryable: false,
        })?;
        self.evidence_items.push(
            Evidence::new(
                CRAWL_MODULE_NAME,
                page_asset.clone(),
                details,
                confidence,
                self.provenance.clone(),
            )
            .map_err(|_| ModuleError::Failed {
                message: "invalid evidence".to_owned(),
                retryable: false,
            })?,
        );
        Ok(())
    }

    fn emit_page_evidence_raw(
        &mut self,
        url: &str,
        parent_asset_id: &str,
        kind: &str,
        data: &serde_json::Value,
    ) -> Result<(), ModuleError> {
        let endpoint = WebTarget::parse(url).map_err(|_| ModuleError::Failed {
            message: "internal URL re-parse failed".to_owned(),
            retryable: false,
        })?;
        let asset_id = self.ensure_endpoint_asset(&endpoint, parent_asset_id, Some(kind))?;
        let mut payload = serde_json::json!({
            "target": self.target_label,
            "url": url,
            "kind": kind,
        });
        if let Some(object) = payload.as_object_mut() {
            if let Some(data) = data.as_object() {
                for (key, value) in data {
                    object.insert(key.clone(), value.clone());
                }
            }
        }
        let details = BoundedDetails::from_value(payload, crate::model::MAX_EVIDENCE_DETAILS_BYTES)
            .map_err(|_| ModuleError::Failed {
                message: "evidence details too large".to_owned(),
                retryable: false,
            })?;
        let confidence = Confidence::new(75).map_err(|_| ModuleError::Failed {
            message: "invalid confidence".to_owned(),
            retryable: false,
        })?;
        self.evidence_items.push(
            Evidence::new(
                CRAWL_MODULE_NAME,
                asset_id,
                details,
                confidence,
                self.provenance.clone(),
            )
            .map_err(|_| ModuleError::Failed {
                message: "invalid evidence".to_owned(),
                retryable: false,
            })?,
        );
        Ok(())
    }

    fn task_deadline_reached(&self) -> bool {
        self.cancel.is_cancelled()
            || self.task_deadline.saturating_duration_since(Instant::now()) < CRAWL_PLANNING_FLOOR
    }
}
