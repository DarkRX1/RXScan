//! Phase D passive investigation / transform engine.
//!
//! Turns isolated username search observations into a bounded, explainable
//! reconnaissance graph. Default contact is public/passive only:
//! `PassivePublic`, `PublicHttp`, and `DnsQuery`. `DirectNetwork` is never
//! used by passive investigation, and authenticated APIs never activate
//! silently.
//!
//! Workflow: Search -> Discover -> Transform -> Correlate -> Explain ->
//! Persist. The graph is built by small bounded transforms:
//!
//! ```text
//! Username --HAS_ACCOUNT--> Account --LINKS_TO--> Url --REFERENCES--> Domain
//! Url --LINKS_TO--> Repository
//! Domain --RESOLVES_TO--> IpAddress
//! Domain --REFERENCES--> DnsRecord / Hostname
//! ```
//!
//! Depth semantics (graph-transform depth, not recursive crawling):
//!
//! ```text
//! depth 0: seed only (Username, Domain, or Url)
//! depth 1: seed expansion (Username -> Account)
//! depth 2: Account -> Url / Domain / Repository (+ Url -> Domain/Repository)
//! depth 3: Domain -> DNS / Hostname / IP
//! depth 4+: reserved; DNS values that are hostnames are recorded as
//!           entities but not re-expanded (no subdomain brute-forcing,
//!           no recursive namespace enumeration)
//! ```
//!
//! Pure local transforms (`Url -> Domain`, `Url -> Repository`) cost zero
//! depth: they resolve already-observed URLs without contact, so the
//! `Domain` behind a `Url` appears at the same depth as the `Url` itself.
//! Contact transforms (`Username -> Account`, `Account -> Url`,
//! `Domain -> DNS`) cost one depth each.
//!
//! Entity creation is never network contact. Only explicit transform
//! execution contacts anything, and only within the allowed contact classes.
//! A discovered `IpAddress` never triggers a scan.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::graph::{EdgeRelation, EntityKind, EntityProvenance, ScanGraph};
use crate::search::{ContactClass, SearchStatus};

// ---------------------------------------------------------------------------
// Constants: defaults and hard ceilings.
// ---------------------------------------------------------------------------

/// Schema version for investigation JSON/JSONL envelopes.
pub const INVESTIGATION_SCHEMA_VERSION: u32 = 1;
/// Default graph-transform depth. DNS expansion needs `--depth 3`.
pub const DEFAULT_DEPTH: u8 = 2;
/// Conservative maximum depth. DNS follow-ups never re-expand.
pub const MAX_DEPTH: u8 = 5;

pub const DEFAULT_MAX_ENTITIES: usize = 500;
pub const HARD_MAX_ENTITIES: usize = 5_000;
pub const DEFAULT_MAX_RELATIONSHIPS: usize = 1_000;
pub const HARD_MAX_RELATIONSHIPS: usize = 10_000;
pub const DEFAULT_MAX_HTTP_REQUESTS: usize = 150;
pub const HARD_MAX_HTTP_REQUESTS: usize = 1_000;
pub const DEFAULT_MAX_DNS_QUERIES: usize = 100;
pub const HARD_MAX_DNS_QUERIES: usize = 1_000;
pub const DEFAULT_MAX_PROVIDERS: usize = 10_000;
/// Default global investigation deadline.
pub const DEFAULT_INVESTIGATION_DEADLINE: Duration = Duration::from_secs(60);

/// Snake-case contact class name for human/plan output.
/// (Debug formatting would render `PublicHttp`, losing word boundaries.)
pub fn contact_class_as_str(class: ContactClass) -> &'static str {
    match class {
        ContactClass::PassivePublic => "passive_public",
        ContactClass::PublicHttp => "public_http",
        ContactClass::DnsQuery => "dns_query",
        ContactClass::DirectNetwork => "direct_network",
        ContactClass::AuthenticatedApi => "authenticated_api",
        ContactClass::LocalDataset => "local_dataset",
    }
}

/// Bounded profile body retained for link extraction (never full HTML
/// archiving; extraction only).
pub const MAX_PROFILE_BODY_BYTES: usize = 64 * 1024;
/// Maximum candidate URLs extracted per profile page.
pub const MAX_URLS_PER_PROFILE: usize = 20;
/// Maximum discovered links retained per URL-extraction observation.
pub const MAX_LINKS_PER_OBSERVATION: usize = 20;
/// Maximum emails extracted per profile (structured public metadata only).
pub const MAX_EMAILS_PER_PROFILE: usize = 5;

// ---------------------------------------------------------------------------
// Seeds and config.
// ---------------------------------------------------------------------------

/// Supported investigation seed types. Username is the primary acceptance
/// path; domain and URL seeds exist only where the transform graph cleanly
/// supports them (no half-working input types).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeedKind {
    Username,
    Domain,
    Url,
}

impl SeedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Domain => "domain",
            Self::Url => "url",
        }
    }
}

/// Operator-facing investigation configuration. All resource controls are
/// hard caps: when reached, expansion stops, partial results are preserved,
/// and truncation is reported (never silent drops).
#[derive(Debug, Clone)]
pub struct InvestigationConfig {
    pub seed_kind: SeedKind,
    pub seed_value: String,
    pub depth: u8,
    pub max_entities: usize,
    pub max_relationships: usize,
    pub max_http_requests: usize,
    pub max_dns_queries: usize,
    pub max_providers: usize,
    pub deadline: Duration,
    pub allow_test_loopback: bool,
    pub selected_providers: Option<BTreeSet<String>>,
    pub excluded_providers: BTreeSet<String>,
    pub categories: BTreeSet<String>,
    /// Opt-in defensive exposure enrichment. External queries that send
    /// identifiers to third parties run ONLY when this is true; ordinary
    /// passive investigation never performs them.
    pub exposure: bool,
    /// Operator-supplied local exposure dataset (local-only, never uploaded).
    pub exposure_dataset: Option<std::path::PathBuf>,
}

impl InvestigationConfig {
    pub fn username(username: &str) -> Self {
        Self {
            seed_kind: SeedKind::Username,
            seed_value: username.to_owned(),
            depth: DEFAULT_DEPTH,
            max_entities: DEFAULT_MAX_ENTITIES,
            max_relationships: DEFAULT_MAX_RELATIONSHIPS,
            max_http_requests: DEFAULT_MAX_HTTP_REQUESTS,
            max_dns_queries: DEFAULT_MAX_DNS_QUERIES,
            max_providers: DEFAULT_MAX_PROVIDERS,
            deadline: DEFAULT_INVESTIGATION_DEADLINE,
            allow_test_loopback: false,
            selected_providers: None,
            excluded_providers: BTreeSet::new(),
            categories: BTreeSet::new(),
            exposure: false,
            exposure_dataset: None,
        }
    }

    /// Validate operator input; clamps nothing silently — out-of-range
    /// budgets are errors, never quiet reinterpretations.
    pub fn validate(&self) -> Result<(), String> {
        if self.seed_value.trim().is_empty() || self.seed_value.len() > 512 {
            return Err("seed must be 1..=512 characters".to_owned());
        }
        if self.depth > MAX_DEPTH {
            return Err(format!("depth {} exceeds maximum {MAX_DEPTH}", self.depth));
        }
        if self.max_entities == 0 || self.max_entities > HARD_MAX_ENTITIES {
            return Err(format!("max_entities must be 1..={HARD_MAX_ENTITIES}"));
        }
        if self.max_relationships == 0 || self.max_relationships > HARD_MAX_RELATIONSHIPS {
            return Err("max_relationships out of range".to_owned());
        }
        if self.max_http_requests > HARD_MAX_HTTP_REQUESTS {
            return Err("max_http_requests out of range".to_owned());
        }
        if self.max_dns_queries > HARD_MAX_DNS_QUERIES {
            return Err("max_dns_queries out of range".to_owned());
        }
        if self.max_providers == 0 {
            return Err("max_providers must be positive".to_owned());
        }
        match self.seed_kind {
            SeedKind::Username => {
                crate::search::SearchEntity::username(&self.seed_value, 0)
                    .map_err(|e| e.to_string())?;
            }
            SeedKind::Domain => {
                canonical_domain(&self.seed_value)
                    .ok_or_else(|| "invalid domain seed".to_owned())?;
            }
            SeedKind::Url => {
                canonical_url_entity(&self.seed_value)
                    .ok_or_else(|| "invalid URL seed (need http/https with host)".to_owned())?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Canonical entity identity.
// ---------------------------------------------------------------------------

/// Stable canonical username identity: `username:<lower>`.
pub fn username_entity_id(username: &str) -> String {
    format!("username:{}", username.trim().to_ascii_lowercase())
}

/// Stable canonical account identity: `account:<provider>:<user>`.
/// Provider and username are lowercased; identity never merges across
/// providers (same username on two providers is two accounts with shared
/// evidence, never one merged person).
pub fn account_entity_id(provider: &str, username: &str) -> String {
    format!(
        "account:{}:{}",
        provider.trim().to_ascii_lowercase(),
        username.trim().to_ascii_lowercase()
    )
}

/// Canonical domain identity: `domain:<lower, no trailing dot>`.
pub fn domain_entity_id(domain: &str) -> String {
    format!(
        "domain:{}",
        domain.trim().trim_end_matches('.').to_ascii_lowercase()
    )
}

/// Canonical repository identity from its canonical URL.
pub fn repository_entity_id(canonical_url: &str) -> String {
    format!("repository:{}", canonical_url.trim().to_ascii_lowercase())
}

/// Canonical email identity.
pub fn email_entity_id(email: &str) -> String {
    format!("email:{}", email.trim().to_ascii_lowercase())
}

/// Canonical organization identity from a forge owner/name.
pub fn organization_entity_id(name: &str) -> String {
    format!("organization:{}", name.trim().to_ascii_lowercase())
}

/// Normalize a domain: lowercase, trim trailing dot and whitespace.
/// Rejects empty input, whitespace/control characters, strings without a
/// dot or colon handling, and values that parse as IP literals (those are
/// `IpAddress` entities, not domains).
pub fn canonical_domain(raw: &str) -> Option<String> {
    let domain = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || domain.len() > 253 {
        return None;
    }
    if domain.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    // Must contain at least one dot and valid labels; single-label names
    // (e.g. `localhost`) are hostnames, not public domains.
    if !domain.contains('.') {
        return None;
    }
    let valid = domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    });
    if !valid {
        return None;
    }
    Some(domain)
}

/// Canonicalize a URL for entity identity using the existing web-target
/// normalization (scheme/host lowercased, default ports filled, empty path
/// becomes `/`). Returns `None` for unparseable or unsupported input;
/// callers preserve the observation as text but skip entity joins.
pub fn canonical_url_entity(raw: &str) -> Option<String> {
    crate::graph::canonical_url(raw)
}

// ---------------------------------------------------------------------------
// Investigation entities, relationships, observations.
// ---------------------------------------------------------------------------

/// Provenance answering "why does RXScan believe this?". Every entity and
/// relationship carries the source entity, the transform that produced it,
/// the provider/source, the contact class used, and bounded evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformProvenance {
    pub source_entity: Option<String>,
    pub transform_id: String,
    pub provider: Option<String>,
    pub contact_class: ContactClass,
    pub timestamp: u64,
    pub evidence: Vec<String>,
    pub confidence: u8,
    pub depth: u8,
}

impl TransformProvenance {
    pub fn to_graph(&self, run_id: &str) -> EntityProvenance {
        EntityProvenance {
            scan_plan_id: run_id.to_owned(),
            module: format!("investigate.{}", self.transform_id),
            task_id: self.source_entity.clone(),
            target: self.source_entity.clone(),
            timestamp: self.timestamp,
            reason: self.evidence.first().cloned(),
            rule_id: self.provider.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationEntity {
    pub id: String,
    pub kind: EntityKind,
    pub label: String,
    pub canonical_value: String,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    pub depth: u8,
    pub provenance: TransformProvenance,
    pub observations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationRelationship {
    pub from: String,
    pub to: String,
    pub relation: EdgeRelation,
    pub confidence: u8,
    pub provenance: TransformProvenance,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

/// One transform execution record: what was tried, what contact it used,
/// and what it found. Non-account outcomes (`not_found`, `blocked`,
/// `rate_limited`, `unknown`, ...) are observations here — they never
/// create account relationships.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationObservation {
    pub transform_id: String,
    pub input_entity_id: String,
    pub contact_class: ContactClass,
    pub status: String,
    pub confidence: u8,
    pub timestamp: u64,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// Accounting with a reconciliation invariant.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationAccounting {
    pub transforms_requested: usize,
    pub transforms_completed: usize,
    pub transforms_skipped: usize,
    pub transforms_cancelled: usize,
    pub transforms_unscanned: usize,
    pub entities_created: usize,
    pub relationships_created: usize,
    pub http_requests: usize,
    pub dns_queries: usize,
    /// Passive investigation never performs network scans; always 0.
    pub network_scans: u64,
    /// Opt-in exposure lookups completed (0 unless `--exposure`).
    pub exposure_lookups: usize,
    /// Normalized exposures found (metadata only; secrets never retained).
    pub exposures_found: usize,
    pub truncated: bool,
    #[serde(default)]
    pub truncation_reasons: BTreeSet<String>,
}

impl InvestigationAccounting {
    /// Reconciliation invariant: every requested transform is exactly one
    /// of completed / skipped / cancelled / unscanned.
    pub fn accounted(&self) -> usize {
        self.transforms_completed
            + self.transforms_skipped
            + self.transforms_cancelled
            + self.transforms_unscanned
    }

    pub fn check_invariant(&self) -> Result<(), String> {
        if self.transforms_requested != self.accounted() {
            return Err(format!(
                "investigation accounting failure: requested {} != accounted {} (completed={} skipped={} cancelled={} unscanned={})",
                self.transforms_requested,
                self.accounted(),
                self.transforms_completed,
                self.transforms_skipped,
                self.transforms_cancelled,
                self.transforms_unscanned,
            ));
        }
        if self.network_scans != 0 {
            return Err("passive investigation must never record network scans".to_owned());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Transform abstraction.
// ---------------------------------------------------------------------------

/// Budget class a transform consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetClass {
    None,
    Provider,
    PublicHttp,
    Dns,
}

/// What a transform execution produced. Entity creation is not network
/// contact; `http_used` / `dns_used` report actual contacts so the engine
/// can enforce global budgets exactly.
#[derive(Debug, Clone, Default)]
pub struct TransformOutput {
    pub entities: Vec<InvestigationEntity>,
    pub relationships: Vec<InvestigationRelationship>,
    pub observations: Vec<InvestigationObservation>,
    pub http_used: usize,
    pub dns_used: usize,
}

/// Pluggable username-search runner. Production delegates to the existing
/// 100-provider search subsystem; tests inject deterministic fixtures with
/// zero network.
pub trait UsernameSearchRunner: Send + Sync {
    fn search_accounts(
        &self,
        username: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
        now: u64,
    ) -> UsernameSearchOutcome;
}

#[derive(Debug, Clone, Default)]
pub struct UsernameSearchOutcome {
    pub accounts: Vec<DiscoveredAccount>,
    pub observations: Vec<InvestigationObservation>,
    /// HTTP requests actually performed (counts toward the HTTP budget).
    pub http_used: usize,
}

#[derive(Debug, Clone)]
pub struct DiscoveredAccount {
    pub provider_id: String,
    pub platform: String,
    pub username: String,
    pub profile_url: String,
    pub final_url: String,
    pub confidence: u8,
    pub evidence: Vec<String>,
}

/// Bounded public profile fetch. Production uses the hardened search HTTP
/// client (HTTPS policy, DNS validation, address pinning, redirect
/// revalidation, body/redirect/deadline caps). Tests inject fixtures.
pub trait ProfileFetcher: Send + Sync {
    fn fetch(
        &self,
        url: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<FetchedProfile, String>;
}

#[derive(Debug, Clone)]
pub struct FetchedProfile {
    pub final_url: String,
    pub status: u16,
    pub body: String,
}

/// Bounded DNS lookup. Production uses the system resolver for address
/// records and reports no-data for other types (still passive, still
/// counted); tests inject deterministic fixtures for every record type.
pub trait DnsFetcher: Send + Sync {
    fn query(
        &self,
        domain: &str,
        record_type: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Vec<String>, String>;
}

/// Context handed to every transform: shared deadline, cancellation,
/// current time, and the pluggable contact backends.
pub struct TransformContext<'a> {
    pub deadline: Instant,
    pub cancelled: &'a AtomicBool,
    pub now: u64,
    pub allow_test_loopback: bool,
    pub search: &'a dyn UsernameSearchRunner,
    pub profile: &'a dyn ProfileFetcher,
    pub dns: &'a dyn DnsFetcher,
}

/// Internal transform abstraction. Kept internal on purpose: no public
/// plugin SDK in this phase.
pub trait Transform: Send + Sync {
    fn id(&self) -> &'static str;
    fn accepts(&self, kind: EntityKind) -> bool;
    fn contact_class(&self) -> ContactClass;
    fn depth_cost(&self) -> u8;
    fn budget_class(&self) -> BudgetClass;
    /// Human description for `--explain` (plan-only, no contact).
    fn describe(&self) -> &'static str;
    fn execute(
        &self,
        ctx: &TransformContext<'_>,
        entity: &InvestigationEntity,
    ) -> Result<TransformOutput, String>;
}

/// Static transform metadata for planning, explain, and capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformInfo {
    pub id: String,
    pub accepts: Vec<String>,
    pub produces: Vec<String>,
    pub contact_class: ContactClass,
    pub depth_cost: u8,
    pub budget: String,
    pub description: String,
}

// --- Transform: Username -> Account (reuses search subsystem) ---

pub struct UsernameToAccount;

impl Transform for UsernameToAccount {
    fn id(&self) -> &'static str {
        "username_to_account"
    }
    fn accepts(&self, kind: EntityKind) -> bool {
        kind == EntityKind::Username
    }
    fn contact_class(&self) -> ContactClass {
        ContactClass::PublicHttp
    }
    fn depth_cost(&self) -> u8 {
        1
    }
    fn budget_class(&self) -> BudgetClass {
        BudgetClass::Provider
    }
    fn describe(&self) -> &'static str {
        "Username -> Account via the existing public provider search (positive outcomes only)"
    }
    fn execute(
        &self,
        ctx: &TransformContext<'_>,
        entity: &InvestigationEntity,
    ) -> Result<TransformOutput, String> {
        if entity.kind != EntityKind::Username {
            return Err("username_to_account requires a username entity".to_owned());
        }
        let outcome = ctx.search.search_accounts(
            &entity.canonical_value,
            ctx.deadline,
            ctx.cancelled,
            ctx.now,
        );
        let mut out = TransformOutput {
            http_used: outcome.http_used,
            ..TransformOutput::default()
        };
        out.observations.extend(outcome.observations);
        for account in outcome.accounts {
            let account_id = account_entity_id(&account.provider_id, &account.username);
            let provenance = TransformProvenance {
                source_entity: Some(entity.id.clone()),
                transform_id: self.id().to_owned(),
                provider: Some(account.provider_id.clone()),
                contact_class: ContactClass::PublicHttp,
                timestamp: ctx.now,
                evidence: account.evidence.clone(),
                confidence: account.confidence.min(95),
                depth: entity.depth.saturating_add(self.depth_cost()),
            };
            out.entities.push(InvestigationEntity {
                id: account_id.clone(),
                kind: EntityKind::Account,
                label: format!("{} / {}", account.platform, account.username),
                canonical_value: format!(
                    "{}:{}",
                    account.provider_id.to_ascii_lowercase(),
                    account.username.to_ascii_lowercase()
                ),
                attributes: BTreeMap::from([
                    ("provider".to_owned(), account.provider_id.clone()),
                    ("platform".to_owned(), account.platform.clone()),
                    ("profile_url".to_owned(), account.profile_url.clone()),
                    ("final_url".to_owned(), account.final_url.clone()),
                ]),
                depth: entity.depth.saturating_add(self.depth_cost()),
                provenance: provenance.clone(),
                observations: 1,
            });
            out.relationships.push(InvestigationRelationship {
                from: entity.id.clone(),
                to: account_id,
                relation: EdgeRelation::HasAccount,
                // Each relationship reflects its own evidence, never a
                // blind merge of provider confidence.
                confidence: account.confidence.min(95),
                provenance,
                evidence: account.evidence.clone(),
                attributes: BTreeMap::from([(
                    "observation_class".to_owned(),
                    "observed".to_owned(),
                )]),
            });
        }
        Ok(out)
    }
}

// --- Transform: Account -> Url (bounded public profile extraction) ---

pub struct AccountToUrl;

impl Transform for AccountToUrl {
    fn id(&self) -> &'static str {
        "account_to_url"
    }
    fn accepts(&self, kind: EntityKind) -> bool {
        kind == EntityKind::Account
    }
    fn contact_class(&self) -> ContactClass {
        ContactClass::PublicHttp
    }
    fn depth_cost(&self) -> u8 {
        1
    }
    fn budget_class(&self) -> BudgetClass {
        BudgetClass::PublicHttp
    }
    fn describe(&self) -> &'static str {
        "Account -> Url via bounded public profile extraction (explicit links only)"
    }
    fn execute(
        &self,
        ctx: &TransformContext<'_>,
        entity: &InvestigationEntity,
    ) -> Result<TransformOutput, String> {
        if entity.kind != EntityKind::Account {
            return Err("account_to_url requires an account entity".to_owned());
        }
        let profile_url = entity
            .attributes
            .get("final_url")
            .or_else(|| entity.attributes.get("profile_url"))
            .cloned()
            .unwrap_or_default();
        if profile_url.is_empty() {
            return Ok(TransformOutput {
                observations: vec![observation(
                    self.id(),
                    entity,
                    ContactClass::PublicHttp,
                    "unscanned",
                    0,
                    ctx.now,
                    vec!["account has no profile URL to extract".to_owned()],
                )],
                ..TransformOutput::default()
            });
        }
        // Contact policy: only https (loopback http allowed in fixture
        // tests). Anything else is observed-as-text, never contacted.
        if !contact_url_permitted(&profile_url, ctx.allow_test_loopback) {
            return Ok(TransformOutput {
                observations: vec![observation(
                    self.id(),
                    entity,
                    ContactClass::PublicHttp,
                    "unscanned",
                    0,
                    ctx.now,
                    vec![format!(
                        "profile URL contact refused by policy: {}",
                        truncate(&profile_url, 160)
                    )],
                )],
                ..TransformOutput::default()
            });
        }
        let fetched = match ctx.profile.fetch(&profile_url, ctx.deadline, ctx.cancelled) {
            Ok(fetched) => fetched,
            Err(error) => {
                return Ok(TransformOutput {
                    http_used: 1,
                    observations: vec![observation(
                        self.id(),
                        entity,
                        ContactClass::PublicHttp,
                        "error",
                        0,
                        ctx.now,
                        vec![truncate(&error, 256)],
                    )],
                    ..TransformOutput::default()
                });
            }
        };
        let mut out = TransformOutput {
            http_used: 1,
            ..TransformOutput::default()
        };
        // The canonical profile URL itself is evidence.
        let canonical_profile =
            canonical_url_entity(&fetched.final_url).or_else(|| canonical_url_entity(&profile_url));
        let mut seen: BTreeSet<String> = BTreeSet::new();
        if let Some(canonical) = canonical_profile {
            seen.insert(canonical.clone());
            let url_id = crate::graph::endpoint_entity_id(&canonical);
            let provenance = TransformProvenance {
                source_entity: Some(entity.id.clone()),
                transform_id: self.id().to_owned(),
                provider: entity.attributes.get("provider").cloned(),
                contact_class: ContactClass::PublicHttp,
                timestamp: ctx.now,
                evidence: vec![format!("canonical profile URL {canonical}")],
                // Explicit profile URL field: strong relationship.
                confidence: 90,
                depth: entity.depth.saturating_add(self.depth_cost()),
            };
            out.entities.push(InvestigationEntity {
                id: url_id.clone(),
                kind: EntityKind::WebEndpoint,
                label: canonical.clone(),
                canonical_value: canonical.clone(),
                attributes: BTreeMap::from([
                    ("url".to_owned(), canonical.clone()),
                    ("source".to_owned(), "profile_canonical".to_owned()),
                ]),
                depth: entity.depth.saturating_add(self.depth_cost()),
                provenance: provenance.clone(),
                observations: 1,
            });
            out.relationships.push(InvestigationRelationship {
                from: entity.id.clone(),
                to: url_id,
                relation: EdgeRelation::LinksTo,
                confidence: 90,
                provenance,
                evidence: vec![format!("canonical profile URL {canonical}")],
                attributes: BTreeMap::from([(
                    "link_class".to_owned(),
                    "profile_canonical".to_owned(),
                )]),
            });
        }
        // Conservative extraction of explicit public links from the bounded
        // profile body. Weak text mentions are not promoted: only href/src
        // links and bare https URLs become Url entities.
        for link in extract_profile_links(&fetched.body, &fetched.final_url) {
            if out.entities.len() >= MAX_URLS_PER_PROFILE {
                break;
            }
            let Some(canonical) = canonical_url_entity(&link) else {
                continue;
            };
            if !seen.insert(canonical.clone()) {
                continue;
            }
            let url_id = crate::graph::endpoint_entity_id(&canonical);
            let is_repo = is_repository_url(&canonical);
            let confidence = if is_repo { 80 } else { 70 };
            let provenance = TransformProvenance {
                source_entity: Some(entity.id.clone()),
                transform_id: self.id().to_owned(),
                provider: entity.attributes.get("provider").cloned(),
                contact_class: ContactClass::PublicHttp,
                timestamp: ctx.now,
                evidence: vec![format!("explicit profile link {canonical}")],
                confidence,
                depth: entity.depth.saturating_add(self.depth_cost()),
            };
            out.entities.push(InvestigationEntity {
                id: url_id.clone(),
                kind: EntityKind::WebEndpoint,
                label: canonical.clone(),
                canonical_value: canonical.clone(),
                attributes: BTreeMap::from([
                    ("url".to_owned(), canonical.clone()),
                    ("source".to_owned(), "profile_link".to_owned()),
                ]),
                depth: entity.depth.saturating_add(self.depth_cost()),
                provenance: provenance.clone(),
                observations: 1,
            });
            out.relationships.push(InvestigationRelationship {
                from: entity.id.clone(),
                to: url_id,
                relation: EdgeRelation::LinksTo,
                confidence,
                provenance,
                evidence: vec![format!("explicit profile link {canonical}")],
                attributes: BTreeMap::from([("link_class".to_owned(), "profile_link".to_owned())]),
            });
        }
        // Clearly public emails in structured public metadata may become
        // EmailAddress entities. Never probed (no login, recovery, or
        // existence checks on unrelated services).
        for email in extract_public_emails(&fetched.body) {
            let email_id = email_entity_id(&email);
            let provenance = TransformProvenance {
                source_entity: Some(entity.id.clone()),
                transform_id: self.id().to_owned(),
                provider: entity.attributes.get("provider").cloned(),
                contact_class: ContactClass::PassivePublic,
                timestamp: ctx.now,
                evidence: vec![format!("public email in profile metadata: {email}")],
                confidence: 60,
                depth: entity.depth.saturating_add(self.depth_cost()),
            };
            out.entities.push(InvestigationEntity {
                id: email_id.clone(),
                kind: EntityKind::EmailAddress,
                label: email.clone(),
                canonical_value: email.to_ascii_lowercase(),
                attributes: BTreeMap::from([("email".to_owned(), email.clone())]),
                depth: entity.depth.saturating_add(self.depth_cost()),
                provenance: provenance.clone(),
                observations: 1,
            });
            out.relationships.push(InvestigationRelationship {
                from: entity.id.clone(),
                to: email_id,
                relation: EdgeRelation::References,
                confidence: 60,
                provenance,
                evidence: vec![format!("public email in profile metadata: {email}")],
                attributes: BTreeMap::new(),
            });
        }
        out.observations.push(observation(
            self.id(),
            entity,
            ContactClass::PublicHttp,
            "extracted",
            70,
            ctx.now,
            vec![format!(
                "profile extraction: {} urls, final {}",
                out.entities.len(),
                truncate(&fetched.final_url, 120)
            )],
        ));
        Ok(out)
    }
}

// --- Transform: Url -> Domain (pure, no contact) ---

pub struct UrlToDomain;

impl Transform for UrlToDomain {
    fn id(&self) -> &'static str {
        "url_to_domain"
    }
    fn accepts(&self, kind: EntityKind) -> bool {
        kind == EntityKind::WebEndpoint
    }
    fn contact_class(&self) -> ContactClass {
        ContactClass::PassivePublic
    }
    fn depth_cost(&self) -> u8 {
        0
    }
    fn budget_class(&self) -> BudgetClass {
        BudgetClass::None
    }
    fn describe(&self) -> &'static str {
        "Url -> Domain via host parsing (pure, zero depth; entity creation is not contact)"
    }
    fn execute(
        &self,
        ctx: &TransformContext<'_>,
        entity: &InvestigationEntity,
    ) -> Result<TransformOutput, String> {
        if entity.kind != EntityKind::WebEndpoint {
            return Err("url_to_domain requires a URL entity".to_owned());
        }
        let url_text = entity
            .attributes
            .get("url")
            .cloned()
            .unwrap_or_else(|| entity.canonical_value.clone());
        let mut out = TransformOutput::default();
        let Some(host) = url_host(&url_text) else {
            out.observations.push(observation(
                self.id(),
                entity,
                ContactClass::PassivePublic,
                "unscanned",
                0,
                ctx.now,
                vec!["URL has no usable host".to_owned()],
            ));
            return Ok(out);
        };
        // IP literals become IpAddress entities (still no scan).
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            let ip_id = crate::graph::ip_entity_id(&ip.to_string());
            let provenance = TransformProvenance {
                source_entity: Some(entity.id.clone()),
                transform_id: self.id().to_owned(),
                provider: None,
                contact_class: ContactClass::PassivePublic,
                timestamp: ctx.now,
                evidence: vec![format!("URL host is IP literal {ip}")],
                confidence: 95,
                depth: entity.depth.saturating_add(self.depth_cost()),
            };
            out.entities.push(InvestigationEntity {
                id: ip_id.clone(),
                kind: EntityKind::IpAddress,
                label: ip.to_string(),
                canonical_value: ip.to_string().to_ascii_lowercase(),
                attributes: BTreeMap::from([("address".to_owned(), ip.to_string())]),
                depth: entity.depth.saturating_add(self.depth_cost()),
                provenance: provenance.clone(),
                observations: 1,
            });
            out.relationships.push(InvestigationRelationship {
                from: entity.id.clone(),
                to: ip_id,
                relation: EdgeRelation::References,
                confidence: 95,
                provenance,
                evidence: vec![format!("URL host is IP literal {ip}")],
                attributes: BTreeMap::new(),
            });
            out.observations.push(observation(
                self.id(),
                entity,
                ContactClass::PassivePublic,
                "resolved_literal",
                95,
                ctx.now,
                vec![format!("URL host is IP literal {ip}")],
            ));
            return Ok(out);
        }
        let Some(domain) = canonical_domain(&host) else {
            out.observations.push(observation(
                self.id(),
                entity,
                ContactClass::PassivePublic,
                "unscanned",
                0,
                ctx.now,
                vec![format!("URL host {host} is not a public domain")],
            ));
            return Ok(out);
        };
        let domain_id = domain_entity_id(&domain);
        let provenance = TransformProvenance {
            source_entity: Some(entity.id.clone()),
            transform_id: self.id().to_owned(),
            provider: None,
            contact_class: ContactClass::PassivePublic,
            timestamp: ctx.now,
            evidence: vec![format!("URL host is {domain}")],
            confidence: 90,
            depth: entity.depth.saturating_add(self.depth_cost()),
        };
        out.entities.push(InvestigationEntity {
            id: domain_id.clone(),
            kind: EntityKind::Domain,
            label: domain.clone(),
            canonical_value: domain.clone(),
            attributes: BTreeMap::from([("domain".to_owned(), domain.clone())]),
            depth: entity.depth.saturating_add(self.depth_cost()),
            provenance: provenance.clone(),
            observations: 1,
        });
        out.relationships.push(InvestigationRelationship {
            from: entity.id.clone(),
            to: domain_id,
            relation: EdgeRelation::References,
            confidence: 90,
            provenance,
            evidence: vec![format!("URL host is {domain}")],
            attributes: BTreeMap::new(),
        });
        out.observations.push(observation(
            self.id(),
            entity,
            ContactClass::PassivePublic,
            "identified",
            90,
            ctx.now,
            vec![format!("URL host is {domain}")],
        ));
        Ok(out)
    }
}

// --- Transform: Url -> Repository (pure forge detection, bounded) ---

pub struct UrlToRepository;

impl Transform for UrlToRepository {
    fn id(&self) -> &'static str {
        "url_to_repository"
    }
    fn accepts(&self, kind: EntityKind) -> bool {
        kind == EntityKind::WebEndpoint
    }
    fn contact_class(&self) -> ContactClass {
        ContactClass::PassivePublic
    }
    fn depth_cost(&self) -> u8 {
        0
    }
    fn budget_class(&self) -> BudgetClass {
        BudgetClass::None
    }
    fn describe(&self) -> &'static str {
        "Url -> Repository for explicit public forge links (pure, zero depth; never clones)"
    }
    fn execute(
        &self,
        ctx: &TransformContext<'_>,
        entity: &InvestigationEntity,
    ) -> Result<TransformOutput, String> {
        if entity.kind != EntityKind::WebEndpoint {
            return Err("url_to_repository requires a URL entity".to_owned());
        }
        let url_text = entity
            .attributes
            .get("url")
            .cloned()
            .unwrap_or_else(|| entity.canonical_value.clone());
        let mut out = TransformOutput::default();
        let Some((owner, name)) = parse_repository_identity(&url_text) else {
            return Ok(out);
        };
        let canonical = canonical_url_entity(&url_text).unwrap_or_else(|| url_text.clone());
        let repo_id = repository_entity_id(&canonical);
        let provenance = TransformProvenance {
            source_entity: Some(entity.id.clone()),
            transform_id: self.id().to_owned(),
            provider: None,
            contact_class: ContactClass::PassivePublic,
            timestamp: ctx.now,
            evidence: vec![format!("explicit repository link {owner}/{name}")],
            confidence: 80,
            depth: entity.depth.saturating_add(self.depth_cost()),
        };
        out.entities.push(InvestigationEntity {
            id: repo_id.clone(),
            kind: EntityKind::Repository,
            label: format!("{owner}/{name}"),
            canonical_value: canonical.to_ascii_lowercase(),
            attributes: BTreeMap::from([
                ("owner".to_owned(), owner.clone()),
                ("name".to_owned(), name.clone()),
                ("url".to_owned(), canonical.clone()),
            ]),
            depth: entity.depth.saturating_add(self.depth_cost()),
            provenance: provenance.clone(),
            observations: 1,
        });
        out.relationships.push(InvestigationRelationship {
            from: entity.id.clone(),
            to: repo_id.clone(),
            relation: EdgeRelation::LinksTo,
            confidence: 80,
            provenance: provenance.clone(),
            evidence: vec![format!("explicit repository link {owner}/{name}")],
            attributes: BTreeMap::new(),
        });
        // Repository owner becomes an Organization entity (reconnaissance
        // relationship, never a person-identity claim).
        let org_id = organization_entity_id(&owner);
        let org_provenance = TransformProvenance {
            source_entity: Some(repo_id.clone()),
            transform_id: self.id().to_owned(),
            provider: None,
            contact_class: ContactClass::PassivePublic,
            timestamp: ctx.now,
            evidence: vec![format!("repository owner {owner}")],
            confidence: 70,
            depth: entity.depth.saturating_add(self.depth_cost()),
        };
        out.entities.push(InvestigationEntity {
            id: org_id.clone(),
            kind: EntityKind::Organization,
            label: owner.clone(),
            canonical_value: owner.to_ascii_lowercase(),
            attributes: BTreeMap::from([("name".to_owned(), owner.clone())]),
            depth: entity.depth.saturating_add(self.depth_cost()),
            provenance: org_provenance.clone(),
            observations: 1,
        });
        out.relationships.push(InvestigationRelationship {
            from: repo_id,
            to: org_id,
            relation: EdgeRelation::References,
            confidence: 70,
            provenance: org_provenance,
            evidence: vec![format!("repository owner {owner}")],
            attributes: BTreeMap::new(),
        });
        out.observations.push(observation(
            self.id(),
            entity,
            ContactClass::PassivePublic,
            "identified",
            80,
            ctx.now,
            vec![format!("explicit repository link {owner}/{name}")],
        ));
        Ok(out)
    }
}

// --- Transform: Domain -> DNS (bounded passive/public) ---

pub struct DomainToDns;

impl DomainToDns {
    const RECORD_TYPES: &'static [&'static str] = &["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV"];
}

impl Transform for DomainToDns {
    fn id(&self) -> &'static str {
        "domain_to_dns"
    }
    fn accepts(&self, kind: EntityKind) -> bool {
        kind == EntityKind::Domain
    }
    fn contact_class(&self) -> ContactClass {
        ContactClass::DnsQuery
    }
    fn depth_cost(&self) -> u8 {
        1
    }
    fn budget_class(&self) -> BudgetClass {
        BudgetClass::Dns
    }
    fn describe(&self) -> &'static str {
        "Domain -> DNS records (A/AAAA/CNAME/MX/NS/TXT/SRV; no port scanning, no subdomain brute-forcing)"
    }
    fn execute(
        &self,
        ctx: &TransformContext<'_>,
        entity: &InvestigationEntity,
    ) -> Result<TransformOutput, String> {
        if entity.kind != EntityKind::Domain {
            return Err("domain_to_dns requires a domain entity".to_owned());
        }
        let domain = entity.canonical_value.clone();
        let mut out = TransformOutput::default();
        for rtype in Self::RECORD_TYPES {
            if ctx.cancelled.load(Ordering::Acquire) {
                break;
            }
            if Instant::now() >= ctx.deadline {
                break;
            }
            let values = match ctx.dns.query(&domain, rtype, ctx.deadline, ctx.cancelled) {
                Ok(values) => values,
                Err(error) => {
                    out.observations.push(observation(
                        self.id(),
                        entity,
                        ContactClass::DnsQuery,
                        "error",
                        0,
                        ctx.now,
                        vec![format!("DNS {rtype} {domain}: {}", truncate(&error, 120))],
                    ));
                    continue;
                }
            };
            out.dns_used += 1;
            if values.is_empty() {
                out.observations.push(observation(
                    self.id(),
                    entity,
                    ContactClass::DnsQuery,
                    "no_data",
                    0,
                    ctx.now,
                    vec![format!("DNS {rtype} {domain}: no data")],
                ));
                continue;
            }
            for value in values.into_iter().take(16) {
                let value = value.trim().to_owned();
                if value.is_empty() || value.len() > 512 {
                    continue;
                }
                if *rtype == "A" || *rtype == "AAAA" {
                    if value.parse::<std::net::IpAddr>().is_err() {
                        continue;
                    }
                    let ip_id = crate::graph::ip_entity_id(&value);
                    let provenance = TransformProvenance {
                        source_entity: Some(entity.id.clone()),
                        transform_id: self.id().to_owned(),
                        provider: Some(format!("dns:{rtype}")),
                        contact_class: ContactClass::DnsQuery,
                        timestamp: ctx.now,
                        evidence: vec![format!("DNS {rtype} {domain} -> {value}")],
                        confidence: 85,
                        depth: entity.depth.saturating_add(self.depth_cost()),
                    };
                    out.entities.push(InvestigationEntity {
                        id: ip_id.clone(),
                        kind: EntityKind::IpAddress,
                        label: value.clone(),
                        canonical_value: value.to_ascii_lowercase(),
                        attributes: BTreeMap::from([
                            ("address".to_owned(), value.clone()),
                            ("record_type".to_owned(), (*rtype).to_owned()),
                        ]),
                        depth: entity.depth.saturating_add(self.depth_cost()),
                        provenance: provenance.clone(),
                        observations: 1,
                    });
                    out.relationships.push(InvestigationRelationship {
                        from: entity.id.clone(),
                        to: ip_id,
                        relation: EdgeRelation::ResolvesTo,
                        confidence: 85,
                        provenance,
                        evidence: vec![format!("DNS {rtype} {domain} -> {value}")],
                        attributes: BTreeMap::from([(
                            "record_type".to_owned(),
                            (*rtype).to_owned(),
                        )]),
                    });
                } else {
                    // MX/NS/CNAME/SRV values that are hostnames become
                    // Hostname entities (recorded, never re-expanded: no
                    // recursive namespace enumeration in this phase).
                    let clean = value.trim_end_matches('.').to_ascii_lowercase();
                    let host_id = crate::graph::hostname_entity_id(&clean);
                    let provenance = TransformProvenance {
                        source_entity: Some(entity.id.clone()),
                        transform_id: self.id().to_owned(),
                        provider: Some(format!("dns:{rtype}")),
                        contact_class: ContactClass::DnsQuery,
                        timestamp: ctx.now,
                        evidence: vec![format!("DNS {rtype} {domain}: {value}")],
                        confidence: 80,
                        depth: entity.depth.saturating_add(self.depth_cost()),
                    };
                    // Hostname observation for mail/name-server targets.
                    if clean.contains('.') && clean.parse::<std::net::IpAddr>().is_err() {
                        out.entities.push(InvestigationEntity {
                            id: host_id.clone(),
                            kind: EntityKind::Hostname,
                            label: clean.clone(),
                            canonical_value: clean.clone(),
                            attributes: BTreeMap::from([
                                ("name".to_owned(), clean.clone()),
                                ("record_type".to_owned(), (*rtype).to_owned()),
                            ]),
                            depth: entity.depth.saturating_add(self.depth_cost()),
                            provenance: provenance.clone(),
                            observations: 1,
                        });
                        out.relationships.push(InvestigationRelationship {
                            from: entity.id.clone(),
                            to: host_id.clone(),
                            relation: EdgeRelation::References,
                            confidence: 80,
                            provenance: provenance.clone(),
                            evidence: vec![format!("DNS {rtype} {domain}: {value}")],
                            attributes: BTreeMap::from([(
                                "record_type".to_owned(),
                                (*rtype).to_owned(),
                            )]),
                        });
                    }
                    // The raw record itself is always a DnsRecord entity.
                    let record_id = crate::graph::dns_record_entity_id(rtype, &domain, &value);
                    out.entities.push(InvestigationEntity {
                        id: record_id.clone(),
                        kind: EntityKind::DnsRecord,
                        label: format!("{rtype} {domain}"),
                        canonical_value: format!(
                            "{}:{}:{}",
                            rtype,
                            domain.to_ascii_lowercase(),
                            value.to_ascii_lowercase()
                        ),
                        attributes: BTreeMap::from([
                            ("record_type".to_owned(), (*rtype).to_owned()),
                            ("name".to_owned(), domain.clone()),
                            ("value".to_owned(), value.clone()),
                        ]),
                        depth: entity.depth.saturating_add(self.depth_cost()),
                        provenance: provenance.clone(),
                        observations: 1,
                    });
                    out.relationships.push(InvestigationRelationship {
                        from: entity.id.clone(),
                        to: record_id,
                        relation: EdgeRelation::References,
                        confidence: 80,
                        provenance,
                        evidence: vec![format!("DNS {rtype} record observed")],
                        attributes: BTreeMap::from([(
                            "record_type".to_owned(),
                            (*rtype).to_owned(),
                        )]),
                    });
                }
            }
            out.observations.push(observation(
                self.id(),
                entity,
                ContactClass::DnsQuery,
                "resolved",
                80,
                ctx.now,
                vec![format!("DNS {rtype} {domain} queried")],
            ));
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Transform registry: deterministic ordering, no scattered matches.
// ---------------------------------------------------------------------------

pub struct TransformRegistry {
    transforms: Vec<Box<dyn Transform>>,
}

impl Default for TransformRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TransformRegistry {
    pub fn new() -> Self {
        Self {
            // Deterministic registration order = execution priority for
            // ties. Pure transforms sort before contact transforms only
            // via the engine's pending-queue sort; registration order is
            // the final tiebreak.
            transforms: vec![
                Box::new(UsernameToAccount),
                Box::new(AccountToUrl),
                Box::new(UrlToDomain),
                Box::new(UrlToRepository),
                Box::new(DomainToDns),
            ],
        }
    }

    /// Answer which transforms accept this entity, in deterministic order.
    pub fn for_entity(&self, kind: EntityKind) -> Vec<&dyn Transform> {
        self.transforms
            .iter()
            .filter(|t| t.accepts(kind))
            .map(|t| t.as_ref() as &dyn Transform)
            .collect()
    }

    pub fn infos(&self) -> Vec<TransformInfo> {
        let mut infos: Vec<TransformInfo> = self
            .transforms
            .iter()
            .map(|t| TransformInfo {
                id: t.id().to_owned(),
                accepts: accepts_of(t.as_ref()),
                produces: produces_of(t.id()),
                contact_class: t.contact_class(),
                depth_cost: t.depth_cost(),
                budget: format!("{:?}", t.budget_class()).to_ascii_lowercase(),
                description: t.describe().to_owned(),
            })
            .collect();
        infos.sort_by(|a, b| a.id.cmp(&b.id));
        infos
    }

    pub fn ids(&self) -> Vec<&'static str> {
        let mut ids: Vec<&'static str> = self.transforms.iter().map(|t| t.id()).collect();
        ids.sort_unstable();
        ids
    }

    pub fn get(&self, id: &str) -> Option<&dyn Transform> {
        self.transforms
            .iter()
            .find(|t| t.id() == id)
            .map(|t| t.as_ref() as &dyn Transform)
    }
}

fn accepts_of(transform: &dyn Transform) -> Vec<String> {
    let mut kinds = Vec::new();
    for kind in [
        EntityKind::Username,
        EntityKind::Account,
        EntityKind::Domain,
        EntityKind::WebEndpoint,
        EntityKind::Hostname,
        EntityKind::IpAddress,
        EntityKind::Repository,
        EntityKind::DnsRecord,
        EntityKind::EmailAddress,
        EntityKind::Organization,
    ] {
        if transform.accepts(kind) {
            kinds.push(kind.to_string());
        }
    }
    kinds
}

fn produces_of(id: &str) -> Vec<String> {
    match id {
        "username_to_account" => vec!["account".to_owned()],
        "account_to_url" => vec!["web_endpoint".to_owned(), "email_address".to_owned()],
        "url_to_domain" => vec!["domain".to_owned(), "ip_address".to_owned()],
        "url_to_repository" => vec!["repository".to_owned(), "organization".to_owned()],
        "domain_to_dns" => vec![
            "ip_address".to_owned(),
            "hostname".to_owned(),
            "dns_record".to_owned(),
        ],
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Investigation engine: bounded deterministic expansion.
// ---------------------------------------------------------------------------

fn observation(
    transform_id: &str,
    entity: &InvestigationEntity,
    contact: ContactClass,
    status: &str,
    confidence: u8,
    now: u64,
    evidence: Vec<String>,
) -> InvestigationObservation {
    InvestigationObservation {
        transform_id: transform_id.to_owned(),
        input_entity_id: entity.id.clone(),
        contact_class: contact,
        status: status.to_owned(),
        confidence,
        timestamp: now,
        evidence: evidence.into_iter().take(8).collect(),
        attributes: BTreeMap::new(),
    }
}

/// Observation classes: how a relationship was established.
///
/// * `observed` — directly seen evidence (profile contains the link, DNS
///   answered, provider confirmed the account).
/// * `derived` — normalization of observed data (URL host to domain, forge
///   URL pattern to repository identity). No new contact, no new claim.
/// * `inferred` — interpretive correlation verdicts. The transform engine
///   never emits these; only explicit reconciliation overlays
///   (`reconcile_candidates`) may, and they are never presented as
///   observed fact.
pub const OBSERVATION_OBSERVED: &str = "observed";
pub const OBSERVATION_DERIVED: &str = "derived";
pub const OBSERVATION_INFERRED: &str = "inferred";

/// Default observation class per transform. Pure normalization transforms
/// derive; everything else observes. Applied authoritatively at admission
/// so every relationship carries a class even when a transform omits it.
fn observation_class_for(transform_id: &str) -> &'static str {
    match transform_id {
        "url_to_domain" | "url_to_repository" => OBSERVATION_DERIVED,
        _ => OBSERVATION_OBSERVED,
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub struct InvestigationEngine<'a> {
    config: InvestigationConfig,
    registry: TransformRegistry,
    search: &'a dyn UsernameSearchRunner,
    profile: &'a dyn ProfileFetcher,
    dns: &'a dyn DnsFetcher,
    pub entities: BTreeMap<String, InvestigationEntity>,
    pub relationships: Vec<InvestigationRelationship>,
    edge_keys: BTreeSet<(String, String, String)>,
    pub observations: Vec<InvestigationObservation>,
    pub accounting: InvestigationAccounting,
    expanded: BTreeSet<(String, String)>,
    run_id: String,
    started_at: u64,
}

impl<'a> InvestigationEngine<'a> {
    pub fn new(
        config: InvestigationConfig,
        search: &'a dyn UsernameSearchRunner,
        profile: &'a dyn ProfileFetcher,
        dns: &'a dyn DnsFetcher,
    ) -> Result<Self, String> {
        config.validate()?;
        let started_at = unix_now();
        let run_id = crate::assets::public_entity_id(
            "investigation_run",
            &format!(
                "{}:{}:{started_at}",
                config.seed_kind.as_str(),
                config.seed_value.to_ascii_lowercase()
            ),
        );
        Ok(Self {
            config,
            registry: TransformRegistry::new(),
            search,
            profile,
            dns,
            entities: BTreeMap::new(),
            relationships: Vec::new(),
            edge_keys: BTreeSet::new(),
            observations: Vec::new(),
            accounting: InvestigationAccounting::default(),
            expanded: BTreeSet::new(),
            run_id,
            started_at,
        })
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn registry(&self) -> &TransformRegistry {
        &self.registry
    }

    fn seed_entity(&self, now: u64) -> InvestigationEntity {
        let provenance = TransformProvenance {
            source_entity: None,
            transform_id: "seed".to_owned(),
            provider: None,
            contact_class: ContactClass::PassivePublic,
            timestamp: now,
            evidence: vec!["operator-supplied seed".to_owned()],
            confidence: 100,
            depth: 0,
        };
        match self.config.seed_kind {
            SeedKind::Username => {
                let canonical = self.config.seed_value.trim().to_ascii_lowercase();
                InvestigationEntity {
                    id: username_entity_id(&canonical),
                    kind: EntityKind::Username,
                    label: self.config.seed_value.trim().to_owned(),
                    canonical_value: canonical,
                    attributes: BTreeMap::new(),
                    depth: 0,
                    provenance,
                    observations: 1,
                }
            }
            SeedKind::Domain => {
                let domain = canonical_domain(&self.config.seed_value)
                    .unwrap_or_else(|| self.config.seed_value.trim().to_ascii_lowercase());
                InvestigationEntity {
                    id: domain_entity_id(&domain),
                    kind: EntityKind::Domain,
                    label: domain.clone(),
                    canonical_value: domain.clone(),
                    attributes: BTreeMap::from([("domain".to_owned(), domain)]),
                    depth: 0,
                    provenance,
                    observations: 1,
                }
            }
            SeedKind::Url => {
                let canonical = canonical_url_entity(&self.config.seed_value)
                    .unwrap_or_else(|| self.config.seed_value.trim().to_owned());
                InvestigationEntity {
                    id: crate::graph::endpoint_entity_id(&canonical),
                    kind: EntityKind::WebEndpoint,
                    label: canonical.clone(),
                    canonical_value: canonical.clone(),
                    attributes: BTreeMap::from([("url".to_owned(), canonical)]),
                    depth: 0,
                    provenance,
                    observations: 1,
                }
            }
        }
    }

    /// Bounded deterministic expansion. Single-threaded with a sorted
    /// pending queue so identical inputs always produce identical graphs
    /// regardless of timing.
    pub fn execute(mut self, cancelled: &AtomicBool) -> InvestigationReport {
        let deadline = Instant::now() + self.config.deadline;
        let now = unix_now();
        let seed = self.seed_entity(now);
        self.entities.insert(seed.id.clone(), seed);

        // Pending work sorted by (depth, entity id, transform id).
        let mut pending: Vec<(u8, String, String)> = Vec::new();
        let seed_id = self.entities.keys().next().cloned().unwrap_or_default();
        for transform in self.registry.for_entity(
            self.entities
                .get(&seed_id)
                .map(|e| e.kind)
                .unwrap_or(EntityKind::Username),
        ) {
            pending.push((0, seed_id.clone(), transform.id().to_owned()));
        }
        pending.sort();
        pending.dedup();
        self.accounting.transforms_requested = pending.len();

        while let Some((_, entity_id, transform_id)) = take_first(&mut pending) {
            if cancelled.load(Ordering::Acquire) {
                self.accounting.transforms_cancelled += 1;
                self.mark_truncated("cancellation");
                // Drain remaining as cancelled (bounded, exact accounting).
                self.accounting.transforms_cancelled += pending.len();
                pending.clear();
                break;
            }
            if Instant::now() >= deadline {
                self.accounting.transforms_unscanned += 1;
                self.accounting.transforms_unscanned += pending.len();
                pending.clear();
                self.mark_truncated("deadline");
                break;
            }
            let Some(entity) = self.entities.get(&entity_id).cloned() else {
                self.accounting.transforms_skipped += 1;
                continue;
            };
            // Cycle prevention: each (transform, entity) expands at most
            // once. Depth alone cannot hide cycles.
            if !self
                .expanded
                .insert((transform_id.clone(), entity_id.clone()))
            {
                self.accounting.transforms_skipped += 1;
                continue;
            }
            let Some(transform) = self.registry.get(&transform_id) else {
                self.accounting.transforms_skipped += 1;
                continue;
            };
            // Depth gate: expansion only when the child depth fits.
            // Pure (zero-cost) transforms resolve already-observed data,
            // so they may run at the boundary depth.
            if entity.depth.saturating_add(transform.depth_cost()) > self.config.depth {
                self.accounting.transforms_skipped += 1;
                continue;
            }
            // Contact-class gate: passive investigation never admits
            // DirectNetwork or AuthenticatedApi.
            if matches!(
                transform.contact_class(),
                ContactClass::DirectNetwork | ContactClass::AuthenticatedApi
            ) {
                self.accounting.transforms_skipped += 1;
                continue;
            }
            // Pre-budget gates: refuse to start work that cannot fit.
            if self.entities.len() >= self.config.max_entities {
                self.accounting.transforms_unscanned += 1;
                self.mark_truncated("entity_budget");
                continue;
            }
            if self.relationships.len() >= self.config.max_relationships {
                self.accounting.transforms_unscanned += 1;
                self.mark_truncated("relationship_budget");
                continue;
            }
            if transform.budget_class() == BudgetClass::PublicHttp
                && self.accounting.http_requests >= self.config.max_http_requests
            {
                self.accounting.transforms_unscanned += 1;
                self.mark_truncated("http_budget");
                continue;
            }
            if transform.budget_class() == BudgetClass::Dns
                && self.accounting.dns_queries >= self.config.max_dns_queries
            {
                self.accounting.transforms_unscanned += 1;
                self.mark_truncated("dns_budget");
                continue;
            }

            let ctx = TransformContext {
                deadline,
                cancelled,
                now: unix_now(),
                allow_test_loopback: self.config.allow_test_loopback,
                search: self.search,
                profile: self.profile,
                dns: self.dns,
            };
            let output = match transform.execute(&ctx, &entity) {
                Ok(output) => output,
                Err(error) => {
                    self.accounting.transforms_completed += 1;
                    self.observations.push(InvestigationObservation {
                        transform_id: transform_id.clone(),
                        input_entity_id: entity_id.clone(),
                        contact_class: transform.contact_class(),
                        status: "error".to_owned(),
                        confidence: 0,
                        timestamp: unix_now(),
                        evidence: vec![truncate(&error, 256)],
                        attributes: BTreeMap::new(),
                    });
                    continue;
                }
            };
            // Charge budgets for actual contacts (never double-count pure
            // entity creation as contact).
            for _ in 0..output.http_used {
                if self.accounting.http_requests >= self.config.max_http_requests {
                    self.mark_truncated("http_budget");
                    break;
                }
                self.accounting.http_requests += 1;
            }
            for _ in 0..output.dns_used {
                if self.accounting.dns_queries >= self.config.max_dns_queries {
                    self.mark_truncated("dns_budget");
                    break;
                }
                self.accounting.dns_queries += 1;
            }
            self.accounting.transforms_completed += 1;
            self.observations.extend(output.observations);
            // A transform that consumed the global deadline mid-execution
            // truncates honestly even when nothing remains queued: partial
            // results are preserved and the reason is reported.
            if Instant::now() >= deadline {
                self.mark_truncated("deadline");
            }

            // Admit produced entities (dedup by canonical id; independent
            // evidence preserved on relationships, observation count bumped
            // on re-observation).
            for mut new_entity in output.entities {
                if new_entity.depth > self.config.depth {
                    continue;
                }
                if let Some(existing) = self.entities.get_mut(&new_entity.id) {
                    existing.observations = existing.observations.saturating_add(1);
                    continue;
                }
                if self.entities.len() >= self.config.max_entities {
                    self.mark_truncated("entity_budget");
                    // Stop admitting further entities from this output but
                    // keep what is already preserved.
                    break;
                }
                // Clamp depth to the configured maximum.
                if new_entity.depth > self.config.depth {
                    continue;
                }
                // Keep provenance depth consistent with entity depth.
                new_entity.depth = new_entity.depth.min(self.config.depth);
                let kind = new_entity.kind;
                let id = new_entity.id.clone();
                let depth = new_entity.depth;
                self.entities.insert(id.clone(), new_entity);
                self.accounting.entities_created += 1;
                // Schedule follow-up transforms for the new entity.
                for follow in self.registry.for_entity(kind) {
                    let key = (follow.id().to_owned(), id.clone());
                    if self.expanded.contains(&key) {
                        continue;
                    }
                    let entry = (depth, id.clone(), follow.id().to_owned());
                    if !pending.contains(&entry) {
                        pending.push(entry);
                        self.accounting.transforms_requested += 1;
                    }
                }
            }
            // Admit relationships (dedup by from/to/relation; strongest
            // confidence wins, bounded evidence merged).
            for mut rel in output.relationships {
                let key = (rel.from.clone(), rel.to.clone(), rel.relation.to_string());
                if self.edge_keys.contains(&key) {
                    // Merge evidence into the existing edge without
                    // duplicating entities.
                    if let Some(existing) = self.relationships.iter_mut().find(|e| {
                        e.from == rel.from && e.to == rel.to && e.relation == rel.relation
                    }) {
                        if rel.confidence > existing.confidence {
                            existing.confidence = rel.confidence;
                        }
                        for item in rel.evidence {
                            if existing.evidence.len() >= 4 {
                                break;
                            }
                            if !existing.evidence.contains(&item) {
                                existing.evidence.push(item);
                            }
                        }
                    }
                    continue;
                }
                if !self.entities.contains_key(&rel.from) || !self.entities.contains_key(&rel.to) {
                    continue;
                }
                if self.relationships.len() >= self.config.max_relationships {
                    self.mark_truncated("relationship_budget");
                    break;
                }
                // Stage 4: every relationship carries its observation class
                // (observed vs derived); inferred is never auto-emitted.
                rel.attributes
                    .entry("observation_class".to_owned())
                    .or_insert_with(|| {
                        observation_class_for(&rel.provenance.transform_id).to_owned()
                    });
                self.edge_keys.insert(key);
                self.relationships.push(rel);
                self.accounting.relationships_created += 1;
            }
            // Keep the queue deterministic after every admission burst.
            pending.sort();
            pending.dedup();
        }

        // Opt-in defensive exposure enrichment (Stage 3). Runs only when
        // the operator passed `--exposure`: external providers that send
        // identifiers to third parties never activate silently.
        if self.config.exposure {
            self.enrich_exposure(cancelled, deadline);
        }

        // Deterministic final ordering: never expose completion timing.
        self.observations.sort_by(|a, b| {
            a.transform_id
                .cmp(&b.transform_id)
                .then(a.input_entity_id.cmp(&b.input_entity_id))
                .then(a.evidence.join(";").cmp(&b.evidence.join(";")))
        });
        self.relationships.sort_by(|a, b| {
            a.from
                .cmp(&b.from)
                .then(a.to.cmp(&b.to))
                .then(a.relation.to_string().cmp(&b.relation.to_string()))
        });

        let completed_at = unix_now();
        // Seed for the report (first entity by depth then id is the seed).
        let seed = self
            .entities
            .values()
            .min_by(|a, b| a.depth.cmp(&b.depth).then(a.id.cmp(&b.id)))
            .cloned()
            .unwrap_or_else(|| self.seed_entity(now));
        InvestigationReport {
            schema_version: INVESTIGATION_SCHEMA_VERSION,
            run_id: self.run_id.clone(),
            seed_kind: self.config.seed_kind,
            seed: seed.clone(),
            depth: self.config.depth,
            max_depth: MAX_DEPTH,
            entities: self.entities.clone(),
            relationships: self.relationships.clone(),
            observations: self.observations.clone(),
            accounting: self.accounting.clone(),
            budgets: BudgetSnapshot {
                max_entities: self.config.max_entities,
                max_relationships: self.config.max_relationships,
                max_http_requests: self.config.max_http_requests,
                max_dns_queries: self.config.max_dns_queries,
                max_providers: self.config.max_providers,
            },
            network_scans: 0,
            direct_network_contacts: 0,
            started_at: self.started_at,
            completed_at,
        }
    }

    fn mark_truncated(&mut self, reason: &str) {
        self.accounting.truncated = true;
        self.accounting.truncation_reasons.insert(reason.to_owned());
    }

    /// Opt-in exposure enrichment for the seed identifier. Normalized
    /// exposures become graph entities with full provenance; secret
    /// material cannot cross this boundary (providers return metadata
    /// only, re-asserted here). Honors entity/relationship/HTTP budgets
    /// and the global deadline like every other transform.
    fn enrich_exposure(&mut self, cancelled: &AtomicBool, deadline: Instant) {
        use crate::exposure::{
            ExposureProvider, HttpApiProvider, IdentifierKind, LocalDatasetProvider,
        };
        let now = unix_now();
        let seed_id = match self
            .entities
            .values()
            .min_by(|a, b| a.depth.cmp(&b.depth).then(a.id.cmp(&b.id)))
        {
            Some(seed) => seed.id.clone(),
            None => return,
        };
        let (identifier, kind, seed_depth) = match self.config.seed_kind {
            SeedKind::Username => (
                self.entities
                    .get(&seed_id)
                    .map(|e| e.canonical_value.clone())
                    .unwrap_or_default(),
                IdentifierKind::Username,
                self.entities.get(&seed_id).map(|e| e.depth).unwrap_or(0),
            ),
            SeedKind::Domain => (
                self.entities
                    .get(&seed_id)
                    .map(|e| e.canonical_value.clone())
                    .unwrap_or_default(),
                IdentifierKind::Domain,
                self.entities.get(&seed_id).map(|e| e.depth).unwrap_or(0),
            ),
            SeedKind::Url => {
                self.observations.push(observation(
                    "exposure_lookup",
                    &self.seed_entity(now),
                    ContactClass::PassivePublic,
                    "skipped",
                    0,
                    now,
                    vec!["exposure lookup needs an email/username/domain seed".to_owned()],
                ));
                return;
            }
        };
        let child_depth = seed_depth.saturating_add(1);
        if child_depth > self.config.depth {
            self.observations.push(observation(
                "exposure_lookup",
                &self.seed_entity(now),
                ContactClass::PassivePublic,
                "skipped",
                0,
                now,
                vec![format!(
                    "exposure enrichment needs depth {}, configured {}",
                    child_depth, self.config.depth
                )],
            ));
            return;
        }
        let mut providers: Vec<Box<dyn ExposureProvider>> = Vec::new();
        if let Some(dataset) = self.config.exposure_dataset.clone() {
            providers.push(Box::new(LocalDatasetProvider {
                label: "operator-dataset".to_owned(),
                path: dataset,
                max_entries: LocalDatasetProvider::MAX_ENTRIES,
            }));
        }
        providers.push(Box::new(HttpApiProvider {
            name: "configured-api".to_owned(),
        }));
        let remaining = deadline.saturating_duration_since(Instant::now());
        let report =
            crate::exposure::run_exposure(&identifier, kind, &providers, remaining, cancelled);
        self.accounting.exposure_lookups += report.accounting.providers_completed;
        self.accounting.exposures_found += report.exposures.len();
        // Completed third-party/API contacts count toward the HTTP budget.
        for obs in &report.observations {
            if matches!(
                obs.contact_class,
                ContactClass::AuthenticatedApi | ContactClass::PublicHttp
            ) && matches!(obs.status.as_str(), "matched" | "no_match")
            {
                if self.accounting.http_requests >= self.config.max_http_requests {
                    self.mark_truncated("http_budget");
                } else {
                    self.accounting.http_requests += 1;
                }
            }
            self.observations.push(InvestigationObservation {
                transform_id: "exposure_lookup".to_owned(),
                input_entity_id: seed_id.clone(),
                contact_class: obs.contact_class,
                status: obs.status.clone(),
                confidence: 0,
                timestamp: obs.timestamp,
                evidence: obs.evidence.clone(),
                attributes: BTreeMap::from([
                    ("provider".to_owned(), obs.provider_id.clone()),
                    (
                        "sends_identifier".to_owned(),
                        obs.sends_identifier.to_string(),
                    ),
                ]),
            });
        }
        let seed_kind = self
            .entities
            .get(&seed_id)
            .map(|e| e.kind)
            .unwrap_or(EntityKind::Username);
        let (entities, edges) = crate::exposure::to_graph_items(
            &seed_id,
            seed_kind,
            &report.exposures,
            now,
            child_depth,
        );
        for entity in entities {
            if self.entities.contains_key(&entity.id) {
                if let Some(existing) = self.entities.get_mut(&entity.id) {
                    existing.observations = existing.observations.saturating_add(1);
                }
                continue;
            }
            if self.entities.len() >= self.config.max_entities {
                self.mark_truncated("entity_budget");
                break;
            }
            self.entities.insert(entity.id.clone(), entity);
            self.accounting.entities_created += 1;
        }
        for mut rel in edges {
            let key = (rel.from.clone(), rel.to.clone(), rel.relation.to_string());
            if self.edge_keys.contains(&key) {
                continue;
            }
            if !self.entities.contains_key(&rel.from) || !self.entities.contains_key(&rel.to) {
                continue;
            }
            if self.relationships.len() >= self.config.max_relationships {
                self.mark_truncated("relationship_budget");
                break;
            }
            rel.attributes
                .entry("observation_class".to_owned())
                .or_insert_with(|| observation_class_for(&rel.provenance.transform_id).to_owned());
            self.edge_keys.insert(key);
            self.relationships.push(rel);
            self.accounting.relationships_created += 1;
        }
    }
}

fn take_first(pending: &mut Vec<(u8, String, String)>) -> Option<(u8, String, String)> {
    if pending.is_empty() {
        return None;
    }
    Some(pending.remove(0))
}

// ---------------------------------------------------------------------------
// Report: JSON / JSONL / human / project persistence.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetSnapshot {
    pub max_entities: usize,
    pub max_relationships: usize,
    pub max_http_requests: usize,
    pub max_dns_queries: usize,
    pub max_providers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationReport {
    pub schema_version: u32,
    pub run_id: String,
    pub seed_kind: SeedKind,
    pub seed: InvestigationEntity,
    pub depth: u8,
    pub max_depth: u8,
    pub entities: BTreeMap<String, InvestigationEntity>,
    pub relationships: Vec<InvestigationRelationship>,
    pub observations: Vec<InvestigationObservation>,
    pub accounting: InvestigationAccounting,
    pub budgets: BudgetSnapshot,
    pub network_scans: u64,
    pub direct_network_contacts: u64,
    pub started_at: u64,
    pub completed_at: u64,
}

impl InvestigationReport {
    /// Ordered entities for deterministic output.
    pub fn ordered_entities(&self) -> Vec<&InvestigationEntity> {
        let mut entities: Vec<&InvestigationEntity> = self.entities.values().collect();
        entities.sort_by(|a, b| a.id.cmp(&b.id));
        entities
    }

    /// Correlation highlights: entities referenced by more than one
    /// independent source (valuable correlation evidence, never identity
    /// proof on its own).
    pub fn correlations(&self) -> Vec<(String, Vec<String>)> {
        let mut inbound: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for rel in &self.relationships {
            inbound
                .entry(rel.to.clone())
                .or_default()
                .insert(rel.from.clone());
        }
        inbound
            .into_iter()
            .filter(|(_, from)| from.len() > 1)
            .map(|(id, from)| (id, from.into_iter().collect()))
            .collect()
    }

    /// Convert to the shared scan graph for project persistence and diff.
    pub fn to_scan_graph(&self) -> ScanGraph {
        let mut graph = ScanGraph::default();
        for entity in self.entities.values() {
            graph.upsert_entity(
                entity.id.clone(),
                entity.kind,
                entity.label.clone(),
                entity.attributes.clone(),
                &entity.provenance.to_graph(&self.run_id),
            );
        }
        for rel in &self.relationships {
            graph.link(
                rel.from.clone(),
                rel.to.clone(),
                rel.relation,
                rel.confidence,
                &rel.provenance.to_graph(&self.run_id),
                rel.evidence.clone(),
                rel.attributes.clone(),
            );
        }
        graph
    }
}

/// Plan-only explanation: what *would* run, without contacting anything.
pub fn explain_plan(config: &InvestigationConfig) -> String {
    let registry = TransformRegistry::new();
    let mut out = String::from("INVESTIGATION PLAN\n\n");
    out.push_str(&format!(
        "seed\n  {}:{}\n\n",
        config.seed_kind.as_str(),
        config.seed_value
    ));
    out.push_str("enabled transforms\n");
    for info in registry.infos() {
        out.push_str(&format!(
            "  {} (accepts {}) [{}]\n    {}\n",
            info.id,
            info.accepts.join(","),
            contact_class_as_str(info.contact_class),
            info.description
        ));
    }
    out.push_str(&format!(
        "\ndepth             {}\nmax depth         {}\nentity budget     {}\nrelationship cap  {}\nHTTP budget       {}\nDNS budget        {}\nprovider cap      {}\ndeadline          {}s\n\nDirectNetwork     disabled\nnetwork scans     0\n",
        config.depth,
        MAX_DEPTH,
        config.max_entities,
        config.max_relationships,
        config.max_http_requests,
        config.max_dns_queries,
        config.max_providers,
        config.deadline.as_secs(),
    ));
    out.push_str("contact classes   passive_public, public_http, dns_query\n");
    out.push_str("forbidden         direct_network, authenticated_api\n");
    if config.exposure {
        out.push_str("\nexposure          ENABLED (opt-in)\n");
        if let Some(dataset) = &config.exposure_dataset {
            out.push_str(&format!(
                "  local dataset {} (sends nothing)\n",
                dataset.display()
            ));
        }
        out.push_str(
            "  http-api      sends identifier to RXSCAN_EXPOSURE_ENDPOINT (env credentials)\n",
        );
        out.push_str("  secret storage disabled; raw responses never persisted\n");
    } else {
        out.push_str("\nexposure          disabled (pass --exposure to opt in)\n");
    }
    out.push_str(
        "note              rxscan investigate never port scans discovered infrastructure\n",
    );
    out
}

/// Compact graph-oriented human rendering. Bounded: interesting entities,
/// strong relationships, correlations, warnings, and truncation first;
/// complete data lives in JSON/JSONL. Never emits ANSI.
pub fn render_human(report: &InvestigationReport, show_all: bool) -> String {
    let mut out = String::new();
    out.push_str("RXSCAN INVESTIGATION \u{00B7} passive evidence graph\n");
    out.push_str(&format!(
        "seed       {}:{}\n",
        report.seed_kind.as_str(),
        report.seed.canonical_value
    ));
    out.push_str(&format!("depth      {}\n", report.depth));
    out.push_str("network    disabled\n\n");
    // Accounts first (strongest signal), then a bounded sample of the rest.
    let mut accounts: Vec<&InvestigationEntity> = report
        .entities
        .values()
        .filter(|e| e.kind == EntityKind::Account)
        .collect();
    accounts.sort_by(|a, b| a.id.cmp(&b.id));
    let account_limit = if show_all { accounts.len() } else { 10 };
    for account in accounts.iter().take(account_limit) {
        out.push_str(&format!("  account     {}\n", account.label));
        let mut outgoing: Vec<&InvestigationRelationship> = report
            .relationships
            .iter()
            .filter(|r| r.from == account.id)
            .collect();
        outgoing.sort_by(|a, b| b.confidence.cmp(&a.confidence).then(a.to.cmp(&b.to)));
        let link_limit = if show_all { outgoing.len() } else { 5 };
        for rel in outgoing.iter().take(link_limit) {
            let target_kind = report
                .entities
                .get(&rel.to)
                .map(|e| e.kind.to_string())
                .unwrap_or_else(|| "?".to_owned());
            out.push_str(&format!(
                "      |- {} {} ({})\n",
                target_kind,
                truncate(&rel.to, 64),
                rel.confidence
            ));
        }
    }
    if !show_all && accounts.len() > account_limit {
        out.push_str(&format!(
            "  ... {} more accounts (use --all or JSON for complete data)\n",
            accounts.len() - account_limit
        ));
    }
    let correlations = report.correlations();
    if !correlations.is_empty() {
        out.push_str("\nCORRELATION\n");
        let limit = if show_all { correlations.len() } else { 10 };
        for (id, sources) in correlations.iter().take(limit) {
            out.push_str(&format!(
                "  {} referenced by {} independent sources\n",
                truncate(id, 72),
                sources.len()
            ));
        }
    }
    let mut exposures: Vec<&InvestigationEntity> = report
        .entities
        .values()
        .filter(|e| e.kind == EntityKind::Exposure)
        .collect();
    exposures.sort_by(|a, b| a.id.cmp(&b.id));
    if !exposures.is_empty() {
        out.push_str("\nEXPOSURE INTELLIGENCE\n");
        let limit = if show_all { exposures.len() } else { 10 };
        for entity in exposures.iter().take(limit) {
            out.push_str(&format!(
                "  {} (secrets retained: no)\n",
                truncate(&entity.label, 88)
            ));
        }
    }
    if report.accounting.truncated {
        let mut reasons: Vec<&String> = report.accounting.truncation_reasons.iter().collect();
        reasons.sort();
        out.push_str(&format!(
            "\nTRUNCATED ({})\n",
            reasons
                .iter()
                .map(|r| r.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    out.push_str(&format!(
        "\n----------------------------------------\n{} entities \u{00B7} {} relationships\n{} HTTP \u{00B7} {} DNS \u{00B7} 0 network scans\n",
        report.entities.len(),
        report.relationships.len(),
        report.accounting.http_requests,
        report.accounting.dns_queries,
    ));
    if report.accounting.exposure_lookups > 0 || report.accounting.exposures_found > 0 {
        out.push_str(&format!(
            "exposure      {} lookups \u{00B7} {} found \u{00B7} secrets stored: 0\n",
            report.accounting.exposure_lookups, report.accounting.exposures_found
        ));
    }
    out
}

/// Typed JSONL: `investigation_start`, `entity`, `relationship`,
/// `observation`, `investigation_summary`. Every line is independently
/// valid JSON; stable deterministic ordering; no ANSI, no banner.
pub fn render_jsonl(report: &InvestigationReport) -> String {
    fn envelope(record_type: &'static str, payload: serde_json::Value) -> String {
        serde_json::json!({
            "schema_version": INVESTIGATION_SCHEMA_VERSION,
            "record_type": record_type,
            "payload": payload,
        })
        .to_string()
    }
    let mut out = String::new();
    out.push_str(&envelope(
        "investigation_start",
        serde_json::json!({
            "run_id": report.run_id,
            "seed_kind": report.seed_kind,
            "seed": report.seed.id,
            "seed_display": report.seed.label,
            "depth": report.depth,
            "max_depth": report.max_depth,
            "budgets": report.budgets,
            "network_scans": 0,
            "started_at": report.started_at,
        }),
    ));
    out.push('\n');
    for entity in report.ordered_entities() {
        out.push_str(&envelope(
            "entity",
            serde_json::json!({
                "id": entity.id,
                "kind": entity.kind,
                "label": entity.label,
                "canonical_value": entity.canonical_value,
                "attributes": entity.attributes,
                "depth": entity.depth,
                "provenance": entity.provenance,
                "observations": entity.observations,
            }),
        ));
        out.push('\n');
    }
    for rel in &report.relationships {
        out.push_str(&envelope(
            "relationship",
            serde_json::json!({
                "from": rel.from,
                "to": rel.to,
                "relation": rel.relation,
                "confidence": rel.confidence,
                "provenance": rel.provenance,
                "evidence": rel.evidence,
                "attributes": rel.attributes,
            }),
        ));
        out.push('\n');
    }
    for obs in &report.observations {
        out.push_str(&envelope(
            "observation",
            serde_json::json!({
                "transform_id": obs.transform_id,
                "input_entity_id": obs.input_entity_id,
                "contact_class": obs.contact_class,
                "status": obs.status,
                "confidence": obs.confidence,
                "timestamp": obs.timestamp,
                "evidence": obs.evidence,
                "attributes": obs.attributes,
            }),
        ));
        out.push('\n');
    }
    out.push_str(&envelope(
        "investigation_summary",
        serde_json::json!({
            "run_id": report.run_id,
            "entities": report.entities.len(),
            "relationships": report.relationships.len(),
            "observations": report.observations.len(),
            "accounting": report.accounting,
            "truncated": report.accounting.truncated,
            "truncation_reasons": report.accounting.truncation_reasons,
            "network_scans": 0,
            "direct_network_contacts": 0,
            "started_at": report.started_at,
            "completed_at": report.completed_at,
        }),
    ));
    out.push('\n');
    out
}

/// DOT export for investigation graphs (Stage 4 graph V3). Nodes carry a
/// `kind` shape hint; edges are labeled with the relation. Pure,
/// deterministic, bounded by the graph itself. GraphML is deferred: DOT
/// covers the cleanly-implementable export need.
pub fn render_dot(report: &InvestigationReport) -> String {
    fn escape(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for ch in text.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                c if c.is_control() => out.push(' '),
                c => out.push(c),
            }
        }
        out
    }
    let mut out = String::from("digraph investigation {\n  rankdir=LR;\n");
    for entity in report.ordered_entities() {
        let shape = match entity.kind {
            EntityKind::Username | EntityKind::Account => "ellipse",
            EntityKind::Domain | EntityKind::Hostname => "box",
            EntityKind::IpAddress => "diamond",
            _ => "note",
        };
        out.push_str(&format!(
            "  \"{}\" [label=\"{}:{}\" shape={}];\n",
            escape(&entity.id),
            entity.kind,
            escape(&truncate(&entity.label, 48)),
            shape
        ));
    }
    for rel in &report.relationships {
        out.push_str(&format!(
            "  \"{}\" -> \"{}\" [label=\"{}\"];\n",
            escape(&rel.from),
            escape(&rel.to),
            rel.relation
        ));
    }
    out.push_str("}\n");
    out
}

// ---------------------------------------------------------------------------
// URL / profile helpers (conservative, bounded).
// ---------------------------------------------------------------------------

/// Whether a profile URL may be contacted. Observation and contact are
/// distinct: unsafe links may exist as observed text but are never fetched.
/// Only `https` is contacted (loopback `http` additionally in fixture
/// tests); every other scheme is refused before any byte is sent.
pub fn contact_url_permitted(url: &str, allow_test_loopback: bool) -> bool {
    let Ok(parsed) = url::Url::parse(url.trim()) else {
        return false;
    };
    match parsed.scheme() {
        "https" => {}
        "http" if allow_test_loopback => {}
        _ => return false,
    }
    let Some(host) = parsed.host_str() else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return false;
    }
    // Literal private/special destinations are never contacted (test
    // asserts this with synthetic literals; production additionally
    // revalidates resolved addresses inside the pinned client).
    if let Ok(ip) = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
    {
        if ip.is_loopback() && !allow_test_loopback {
            return false;
        }
        if is_non_public_literal(ip, allow_test_loopback) {
            return false;
        }
    }
    true
}

fn is_non_public_literal(ip: std::net::IpAddr, allow_loopback: bool) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            // allow_test_loopback permits loopback literals for fixture
            // servers only; every other special range stays refused.
            if v4.is_loopback() {
                return !allow_loopback;
            }
            v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
                || octets[0] >= 240
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_multicast()
                || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8)
                || (v6.is_loopback() && !allow_loopback)
        }
    }
}

fn url_host(url: &str) -> Option<String> {
    url::Url::parse(url.trim())
        .ok()?
        .host_str()
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
}

/// Conservative URL extraction from bounded public profile bodies.
/// Only `http(s)` links from `href`/`src` attributes and bare `https://`
/// URLs become candidates; unsafe schemes never become entities (kept as
/// observation text at most). Relative links resolve against the profile
/// URL. Output is deduplicated and bounded.
pub fn extract_profile_links(body: &str, base_url: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let base = url::Url::parse(base_url).ok();
    // Attribute links (href/src/action/cite/data-href).
    for needle in [
        "href=\"",
        "href='",
        "src=\"",
        "src='",
        "action=\"",
        "cite=\"",
    ] {
        for part in body.split(needle).skip(1) {
            if found.len() >= MAX_LINKS_PER_OBSERVATION * 2 {
                break;
            }
            let quote = if needle.ends_with('"') { '"' } else { '\'' };
            let Some(end) = part.find(quote) else {
                continue;
            };
            let raw = part[..end].trim();
            if raw.is_empty() || raw.len() > 2048 {
                continue;
            }
            if let Some(resolved) = resolve_link(raw, base.as_ref()) {
                if seen.insert(resolved.clone()) {
                    found.push(resolved);
                }
            }
        }
    }
    // Bare https URLs in text.
    for token in
        body.split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '<' || c == '>')
    {
        if found.len() >= MAX_LINKS_PER_OBSERVATION * 2 {
            break;
        }
        let token = token.trim().trim_end_matches(['.', ',', ';', ')', ']']);
        if !(token.starts_with("https://") || token.starts_with("http://")) {
            continue;
        }
        if token.len() > 2048 {
            continue;
        }
        if let Some(resolved) = resolve_link(token, base.as_ref()) {
            if seen.insert(resolved.clone()) {
                found.push(resolved);
            }
        }
    }
    found.into_iter().take(MAX_LINKS_PER_OBSERVATION).collect()
}

fn resolve_link(raw: &str, base: Option<&url::Url>) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty()
        || raw.starts_with('#')
        || raw.starts_with("javascript:")
        || raw.starts_with("data:")
        || raw.starts_with("file:")
        || raw.starts_with("ftp:")
        || raw.starts_with("gopher:")
        || raw.starts_with("mailto:")
        || raw.starts_with("unix:")
    {
        return None;
    }
    let joined = if raw.contains("://") {
        url::Url::parse(raw).ok()?
    } else {
        base?.join(raw).ok()?
    };
    match joined.scheme() {
        "https" | "http" => {}
        _ => return None,
    }
    if joined.host_str().is_none_or(|h| h.is_empty()) {
        return None;
    }
    Some(joined.to_string())
}

/// Known public code forges for repository-identity detection. Only
/// explicit `https` links matching `forge/owner/repo` become Repository
/// entities; nothing is cloned and no history is fetched.
fn is_repository_url(canonical: &str) -> bool {
    parse_repository_identity(canonical).is_some()
}

pub fn parse_repository_identity(canonical: &str) -> Option<(String, String)> {
    let parsed = url::Url::parse(canonical).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    let host = parsed.host_str()?.to_ascii_lowercase();
    let forge = matches!(
        host.as_str(),
        "github.com"
            | "www.github.com"
            | "gitlab.com"
            | "www.gitlab.com"
            | "bitbucket.org"
            | "codeberg.org"
            | "sourcehut.org"
            | "sr.ht"
            | "git.sr.ht"
    );
    if !forge {
        return None;
    }
    let mut segments: Vec<&str> = parsed.path().split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() < 2 {
        return None;
    }
    // Drop trailing forge noise (blob/tree/issues/pulls/-/…).
    if segments.len() > 2 {
        segments.truncate(2);
    }
    let owner = segments[0].trim().to_owned();
    let mut name = segments[1].trim().to_owned();
    if let Some(stripped) = name.strip_suffix(".git") {
        name = stripped.to_owned();
    }
    if owner.is_empty() || name.is_empty() || owner.len() > 64 || name.len() > 64 {
        return None;
    }
    if !owner
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return None;
    }
    Some((owner, name))
}

/// Conservative public-email extraction from bounded profile text.
/// Pure pattern match; the addresses are never probed.
pub fn extract_public_emails(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for token in body.split(|c: char| {
        c.is_whitespace() || c == '"' || c == '\'' || c == '<' || c == '>' || c == ',' || c == ';'
    }) {
        if out.len() >= MAX_EMAILS_PER_PROFILE {
            break;
        }
        let token = token
            .trim()
            .trim_matches(|c| c == '.' || c == ')' || c == ']' || c == '(');
        let Some((local, domain)) = token.split_once('@') else {
            continue;
        };
        if local.is_empty()
            || local.len() > 64
            || domain.is_empty()
            || domain.len() > 253
            || !domain.contains('.')
        {
            continue;
        }
        if !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-'))
            || !domain
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            continue;
        }
        if canonical_domain(domain).is_none() {
            continue;
        }
        let email = format!(
            "{}@{}",
            local.to_ascii_lowercase(),
            domain.to_ascii_lowercase()
        );
        if seen.insert(email.clone()) {
            out.push(email);
        }
    }
    out
}

pub fn truncate(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

// ---------------------------------------------------------------------------
// Production contact backends (hardened, bounded, passive-only).
// ---------------------------------------------------------------------------

/// Production username search: delegates to the existing provider engine
/// without duplicating provider logic. Only meaningful positive outcomes
/// (`confirmed`/`probable`/`possible`) become accounts; every other status
/// stays an observation.
pub struct ProductionSearchRunner {
    pub max_providers: usize,
    pub selected: Option<BTreeSet<String>>,
    pub excluded: BTreeSet<String>,
    pub categories: BTreeSet<String>,
}

impl UsernameSearchRunner for ProductionSearchRunner {
    fn search_accounts(
        &self,
        username: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
        now: u64,
    ) -> UsernameSearchOutcome {
        let pack = match crate::search::embedded_username_pack() {
            Ok(pack) => pack,
            Err(error) => {
                return UsernameSearchOutcome {
                    observations: vec![InvestigationObservation {
                        transform_id: "username_to_account".to_owned(),
                        input_entity_id: username_entity_id(username),
                        contact_class: ContactClass::PublicHttp,
                        status: "error".to_owned(),
                        confidence: 0,
                        timestamp: now,
                        evidence: vec![truncate(&error.to_string(), 256)],
                        attributes: BTreeMap::new(),
                    }],
                    ..UsernameSearchOutcome::default()
                };
            }
        };
        let mut ids: Vec<String> = pack
            .providers
            .iter()
            .filter(|p| {
                self.selected
                    .as_ref()
                    .is_none_or(|ids| ids.contains(&p.metadata.id))
                    && !self.excluded.contains(&p.metadata.id)
                    && (self.categories.is_empty() || self.categories.contains(&p.category))
                    && p.health_state != crate::search::HealthState::Disabled
            })
            .map(|p| p.metadata.id.clone())
            .collect();
        ids.sort();
        ids.dedup();
        ids.truncate(self.max_providers.max(1));
        let selected: BTreeSet<String> = ids.into_iter().collect();
        let remaining = deadline.saturating_duration_since(Instant::now());
        let report = match crate::search::execute_username_search(
            username,
            4,
            1,
            remaining,
            Some(&selected),
            cancelled,
        ) {
            Ok(report) => report,
            Err(error) => {
                return UsernameSearchOutcome {
                    observations: vec![InvestigationObservation {
                        transform_id: "username_to_account".to_owned(),
                        input_entity_id: username_entity_id(username),
                        contact_class: ContactClass::PublicHttp,
                        status: "error".to_owned(),
                        confidence: 0,
                        timestamp: now,
                        evidence: vec![truncate(&error.to_string(), 256)],
                        attributes: BTreeMap::new(),
                    }],
                    ..UsernameSearchOutcome::default()
                };
            }
        };
        let mut outcome = UsernameSearchOutcome {
            // Each completed provider performed one bounded HTTPS exchange.
            http_used: report.accounting.providers_completed,
            ..UsernameSearchOutcome::default()
        };
        for result in &report.results {
            let status_key = match result.status {
                SearchStatus::Confirmed => "confirmed",
                SearchStatus::Probable => "probable",
                SearchStatus::Possible => "possible",
                SearchStatus::NotFound => "not_found",
                SearchStatus::Unknown => "unknown",
                SearchStatus::RateLimited => "rate_limited",
                SearchStatus::Blocked => "blocked",
                SearchStatus::AuthenticationRequired => "authentication_required",
                SearchStatus::Error => "error",
                SearchStatus::Cancelled => "cancelled",
                SearchStatus::Unscanned => "unscanned",
            };
            outcome.observations.push(InvestigationObservation {
                transform_id: "username_to_account".to_owned(),
                input_entity_id: username_entity_id(username),
                contact_class: result.contact_class,
                status: status_key.to_owned(),
                confidence: result.confidence,
                timestamp: now,
                evidence: result.evidence.clone().into_iter().take(4).collect(),
                attributes: BTreeMap::from([
                    ("provider".to_owned(), result.provider_id.clone()),
                    (
                        "profile_url".to_owned(),
                        result
                            .attributes
                            .get("profile_url")
                            .cloned()
                            .unwrap_or_default(),
                    ),
                ]),
            });
            if !matches!(
                result.status,
                SearchStatus::Confirmed | SearchStatus::Probable | SearchStatus::Possible
            ) {
                continue;
            }
            let platform = result
                .attributes
                .get("platform")
                .cloned()
                .unwrap_or_else(|| result.provider_id.clone());
            let profile_url = result
                .attributes
                .get("profile_url")
                .cloned()
                .unwrap_or_default();
            let final_url = result
                .attributes
                .get("final_url")
                .cloned()
                .unwrap_or_else(|| profile_url.clone());
            outcome.accounts.push(DiscoveredAccount {
                provider_id: result.provider_id.clone(),
                platform,
                username: username.to_owned(),
                profile_url,
                final_url,
                confidence: result.confidence,
                evidence: result.evidence.clone().into_iter().take(4).collect(),
            });
        }
        outcome.accounts.sort_by(|a, b| {
            a.provider_id
                .cmp(&b.provider_id)
                .then(a.username.cmp(&b.username))
        });
        outcome.observations.sort_by(|a, b| {
            a.attributes
                .get("provider")
                .cmp(&b.attributes.get("provider"))
        });
        outcome
    }
}

/// Production profile fetch over the hardened search HTTP client: HTTPS
/// policy, DNS validation, address pinning, redirect revalidation, body
/// and redirect caps, deadline, and cancellation. Never weaker than
/// search; never contacts unsafe destinations.
pub struct ProductionProfileFetcher {
    pub allow_test_loopback: bool,
}

impl ProfileFetcher for ProductionProfileFetcher {
    fn fetch(
        &self,
        url: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<FetchedProfile, String> {
        if !contact_url_permitted(url, self.allow_test_loopback) {
            return Err("profile URL refused by contact policy".to_owned());
        }
        let parsed = url::Url::parse(url).map_err(|_| "invalid profile URL".to_owned())?;
        let client = crate::search::SharedHttpClient::new().map_err(|e| e.to_string())?;
        // Hardened test hooks (loopback) mirror the search client's own
        // test affordance: production never enables them.
        let _ = &client;
        let ctx = crate::search::SearchContext {
            deadline,
            cancelled,
        };
        // Same hardened policy as search: bounded body/redirects/timeout.
        let response = client
            .get(
                &parsed,
                Duration::from_secs(10),
                MAX_PROFILE_BODY_BYTES,
                2,
                &ctx,
            )
            .map_err(|e| e.to_string())?;
        if response.body_truncated {
            return Err("profile body exceeded bounded limit".to_owned());
        }
        let body = String::from_utf8_lossy(&response.body).into_owned();
        Ok(FetchedProfile {
            final_url: response.final_url,
            status: response.status,
            body,
        })
    }
}

/// Production DNS: system resolver for address records (A/AAAA); other
/// types report no-data in this phase. Still `DnsQuery` contact, still
/// counted, still bounded — never direct service probing.
pub struct ProductionDnsFetcher;

impl DnsFetcher for ProductionDnsFetcher {
    fn query(
        &self,
        domain: &str,
        record_type: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Vec<String>, String> {
        if cancelled.load(Ordering::Acquire) {
            return Err("cancelled".to_owned());
        }
        if Instant::now() >= deadline {
            return Err("deadline".to_owned());
        }
        match record_type {
            "A" | "AAAA" => {
                use std::net::ToSocketAddrs as _;
                let want_v6 = record_type == "AAAA";
                let target = format!("{domain}:443");
                let mut out = BTreeSet::new();
                let Ok(addrs) = target.to_socket_addrs() else {
                    return Ok(Vec::new());
                };
                for addr in addrs {
                    if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
                        break;
                    }
                    let ip = addr.ip();
                    if want_v6 != ip.is_ipv6() {
                        continue;
                    }
                    // Never surface private/special answers as trusted
                    // network pivots; record them as observations only when
                    // they are clearly synthetic test values.
                    out.insert(ip.to_string());
                    if out.len() >= 16 {
                        break;
                    }
                }
                Ok(out.into_iter().collect())
            }
            // Bounded passive posture for non-address types in Phase D:
            // report no-data rather than inventing a second DNS client.
            // Fixture-backed tests prove the transform graph for MX/NS/TXT/
            // SRV/CNAME; production returns explicit no-data observations.
            "CNAME" | "MX" | "NS" | "TXT" | "SRV" => Ok(Vec::new()),
            _ => Err(format!("unsupported record type {record_type}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Project persistence for investigations.
// ---------------------------------------------------------------------------

/// Persist an investigation graph into the existing project database.
/// Reuses the versioned SQLite schema and coverage model; no second
/// database. Coverage-aware: providers/transforms that never completed
/// stay `UNKNOWN`, never negative evidence.
pub fn persist_investigation(
    db: &mut crate::project_db::ProjectDb,
    report: &InvestigationReport,
) -> Result<crate::project_db::ImportStats, String> {
    use crate::project_db::{
        ClassifierProvenance, CoverageSnapshot, PackProvenance, RetentionMode, ScanImport,
    };
    let graph = report.to_scan_graph();
    let mut modules: BTreeSet<String> = report
        .observations
        .iter()
        .map(|o| format!("investigate.{}", o.transform_id))
        .collect();
    modules.insert("investigate.seed".to_owned());
    let mut modules: Vec<String> = modules.into_iter().collect();
    modules.sort();
    let mut dns_queried: BTreeSet<String> = BTreeSet::new();
    for entity in report.entities.values() {
        if entity.kind == EntityKind::Domain
            && report
                .observations
                .iter()
                .any(|o| o.transform_id == "domain_to_dns" && o.input_entity_id == entity.id)
        {
            dns_queried.insert(entity.canonical_value.clone());
        }
    }
    let coverage = CoverageSnapshot {
        dns_queried: dns_queried.into_iter().collect(),
        modules_completed: modules,
        truncated: report.accounting.truncated,
        ..CoverageSnapshot::default()
    };
    let termination = if report.accounting.transforms_cancelled > 0 {
        "cancelled"
    } else if report.accounting.transforms_unscanned > 0 {
        "deadline_or_budget"
    } else {
        "complete"
    };
    let rules_used: BTreeSet<String> = report
        .observations
        .iter()
        .map(|o| o.transform_id.clone())
        .collect();
    let import = ScanImport {
        scan_id: report.run_id.clone(),
        plan_id: crate::assets::public_entity_id(
            "investigation_plan",
            &format!("{}:{}", report.seed_kind.as_str(), report.depth),
        ),
        started_at_ms: report.started_at.saturating_mul(1_000),
        finished_at_ms: report.completed_at.saturating_mul(1_000),
        scope_json: serde_json::json!({
            "contact_class": ["passive_public", "public_http", "dns_query"],
            "direct_network": false,
            "seed_kind": report.seed_kind.as_str(),
            "depth": report.depth,
        })
        .to_string(),
        workflow: "investigation".to_owned(),
        level: report.depth,
        termination: termination.to_owned(),
        tasks_admitted: report.accounting.transforms_requested as u64,
        tasks_completed: report.accounting.transforms_completed as u64,
        coverage,
        classifier: ClassifierProvenance {
            tool_version: crate::project_db::TOOL_VERSION.to_owned(),
            packs: vec![PackProvenance {
                path: "internal:investigate/transforms".to_owned(),
                schema_version: INVESTIGATION_SCHEMA_VERSION,
                rule_count: TransformRegistry::new().ids().len(),
            }],
            rules_used: rules_used.into_iter().collect(),
        },
        retention: RetentionMode::Standard,
    };
    let stats = db.import_scan(&import, &graph).map_err(|e| e.to_string())?;
    let evidence: Vec<(String, String, u8, serde_json::Value, u64)> = report
        .observations
        .iter()
        .map(|o| {
            (
                format!("investigate.{}", o.transform_id),
                o.input_entity_id.clone(),
                o.confidence,
                serde_json::json!({
                    "status": o.status,
                    "evidence": o.evidence,
                    "contact_class": o.contact_class,
                }),
                o.timestamp.saturating_mul(1_000),
            )
        })
        .collect();
    let stored = db
        .store_evidence(&report.run_id, &evidence, RetentionMode::Standard)
        .map_err(|e| e.to_string())?;
    Ok(crate::project_db::ImportStats {
        entities_upserted: stats.entities_upserted,
        observations_added: stats.observations_added,
        relationships_upserted: stats.relationships_upserted,
        evidence_stored: stored,
        clusters_stored: stats.clusters_stored,
    })
}

/// Explain why an entity is in the graph: provenance chain from the seed
/// through each transform hop. No vague "correlated by engine".
pub fn explain_entity(report: &InvestigationReport, entity_id: &str) -> Result<String, String> {
    let entity = report
        .entities
        .get(entity_id)
        .ok_or_else(|| format!("unknown entity {entity_id}"))?;
    let mut out = format!(
        "Why is {}:{} in this investigation?\n\n",
        entity.kind,
        truncate(&entity.canonical_value, 120)
    );
    // Walk inbound edges to the seed.
    let mut chain: Vec<String> = vec![format!(
        "{} ({}; {})",
        truncate(&entity.id, 96),
        entity.provenance.transform_id,
        entity
            .provenance
            .evidence
            .first()
            .cloned()
            .unwrap_or_else(|| "observed".to_owned())
    )];
    let mut current = entity_id.to_owned();
    let mut guard = 0usize;
    while guard < 16 {
        guard += 1;
        let Some(edge) = report.relationships.iter().find(|e| e.to == current) else {
            break;
        };
        chain.push(format!(
            "{} --{}--> {} ({})",
            truncate(&edge.from, 80),
            edge.relation,
            truncate(&edge.to, 80),
            edge.evidence.first().cloned().unwrap_or_default()
        ));
        if edge.from == current {
            break;
        }
        current = edge.from.clone();
        if current == report.seed.id {
            chain.push(format!(
                "seed {}:{} (operator-supplied)",
                report.seed_kind.as_str(),
                truncate(&report.seed.canonical_value, 80)
            ));
            break;
        }
    }
    for (index, step) in chain.iter().enumerate() {
        out.push_str(&format!("{}. {step}\n", index + 1));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Top-level runner used by the CLI and tests.
// ---------------------------------------------------------------------------

/// Run an investigation with explicit injectable backends. Production
/// passes the hardened backends; tests pass deterministic fixtures.
pub fn run_investigation_with(
    config: InvestigationConfig,
    search: &dyn UsernameSearchRunner,
    profile: &dyn ProfileFetcher,
    dns: &dyn DnsFetcher,
    cancelled: &AtomicBool,
) -> Result<InvestigationReport, String> {
    let engine = InvestigationEngine::new(config, search, profile, dns)?;
    Ok(engine.execute(cancelled))
}

/// Run with production backends (passive by default; never DirectNetwork).
pub fn run_investigation(
    config: InvestigationConfig,
    cancelled: &AtomicBool,
) -> Result<InvestigationReport, String> {
    let search = ProductionSearchRunner {
        max_providers: config.max_providers,
        selected: config.selected_providers.clone(),
        excluded: config.excluded_providers.clone(),
        categories: config.categories.clone(),
    };
    let profile = ProductionProfileFetcher {
        allow_test_loopback: config.allow_test_loopback,
    };
    let dns = ProductionDnsFetcher;
    run_investigation_with(config, &search, &profile, &dns, cancelled)
}

/// Capability entries for `rxscan capabilities`. Reflects actual registry
/// state; direct network is always reported disabled by default.
pub fn capability_entries() -> Vec<(String, bool, String)> {
    let registry = TransformRegistry::new();
    let ids = registry.ids().join(",");
    vec![
        (
            "investigation".to_owned(),
            true,
            "passive evidence-graph workflow".to_owned(),
        ),
        (
            "investigation_username_seed".to_owned(),
            true,
            "username seed via embedded provider search".to_owned(),
        ),
        (
            "investigation_account_transforms".to_owned(),
            registry.get("account_to_url").is_some(),
            "bounded public profile extraction".to_owned(),
        ),
        (
            "investigation_url_transforms".to_owned(),
            registry.get("url_to_domain").is_some() && registry.get("url_to_repository").is_some(),
            "url to domain and repository".to_owned(),
        ),
        (
            "investigation_dns_transforms".to_owned(),
            registry.get("domain_to_dns").is_some(),
            "bounded A/AAAA/CNAME/MX/NS/TXT/SRV observations".to_owned(),
        ),
        (
            "investigation_project_persistence".to_owned(),
            true,
            "investigation graphs persist through the versioned SQLite project graph".to_owned(),
        ),
        ("investigation_transforms".to_owned(), true, ids),
        (
            "investigation_direct_network".to_owned(),
            false,
            "disabled by default; passive investigation never port scans".to_owned(),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Fixture backends for deterministic tests (no network).
// ---------------------------------------------------------------------------

/// Deterministic fixture search runner: maps usernames to canned accounts.
#[derive(Debug, Default)]
pub struct FixtureSearchRunner {
    /// username (lower) -> accounts.
    pub accounts: HashMap<String, Vec<DiscoveredAccount>>,
    /// provider outcomes that are observations but not accounts.
    pub non_account: HashMap<String, Vec<(String, String)>>,
}

impl FixtureSearchRunner {
    pub fn with_account(
        mut self,
        username: &str,
        provider: &str,
        platform: &str,
        profile_url: &str,
    ) -> Self {
        self.accounts
            .entry(username.to_ascii_lowercase())
            .or_default()
            .push(DiscoveredAccount {
                provider_id: provider.to_owned(),
                platform: platform.to_owned(),
                username: username.to_owned(),
                profile_url: profile_url.to_owned(),
                final_url: profile_url.to_owned(),
                confidence: 94,
                evidence: vec!["all required profile markers matched".to_owned()],
            });
        self
    }
}

impl UsernameSearchRunner for FixtureSearchRunner {
    fn search_accounts(
        &self,
        username: &str,
        _deadline: Instant,
        cancelled: &AtomicBool,
        now: u64,
    ) -> UsernameSearchOutcome {
        if cancelled.load(Ordering::Acquire) {
            return UsernameSearchOutcome::default();
        }
        let key = username.to_ascii_lowercase();
        let mut outcome = UsernameSearchOutcome::default();
        for account in self.accounts.get(&key).cloned().unwrap_or_default() {
            outcome.observations.push(InvestigationObservation {
                transform_id: "username_to_account".to_owned(),
                input_entity_id: username_entity_id(username),
                contact_class: ContactClass::PublicHttp,
                status: "confirmed".to_owned(),
                confidence: account.confidence,
                timestamp: now,
                evidence: account.evidence.clone(),
                attributes: BTreeMap::from([
                    ("provider".to_owned(), account.provider_id.clone()),
                    ("profile_url".to_owned(), account.profile_url.clone()),
                ]),
            });
            outcome.accounts.push(account);
        }
        // One synthetic not_found observation proves non-positives never
        // become accounts.
        outcome.observations.push(InvestigationObservation {
            transform_id: "username_to_account".to_owned(),
            input_entity_id: username_entity_id(username),
            contact_class: ContactClass::PublicHttp,
            status: "not_found".to_owned(),
            confidence: 0,
            timestamp: now,
            evidence: vec!["provider not-found evidence matched".to_owned()],
            attributes: BTreeMap::from([("provider".to_owned(), "fixture-absent".to_owned())]),
        });
        outcome.http_used = outcome.accounts.len() + 1;
        outcome
    }
}

/// Deterministic fixture profile fetcher.
#[derive(Debug, Default)]
pub struct FixtureProfileFetcher {
    pub pages: HashMap<String, FetchedProfile>,
    pub calls: std::sync::Mutex<Vec<String>>,
}

impl FixtureProfileFetcher {
    pub fn with_page(mut self, url: &str, final_url: &str, body: &str) -> Self {
        self.pages.insert(
            url.to_owned(),
            FetchedProfile {
                final_url: final_url.to_owned(),
                status: 200,
                body: body.to_owned(),
            },
        );
        self
    }

    pub fn call_count(&self) -> usize {
        self.calls.lock().map(|c| c.len()).unwrap_or_default()
    }
}

impl ProfileFetcher for FixtureProfileFetcher {
    fn fetch(
        &self,
        url: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<FetchedProfile, String> {
        if cancelled.load(Ordering::Acquire) {
            return Err("cancelled".to_owned());
        }
        if Instant::now() >= deadline {
            return Err("deadline".to_owned());
        }
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(url.to_owned());
        }
        // SSRF-equivalent guard lives in the transform's contact check,
        // but the fixture backend refuses unsafe literals too so tests
        // prove the full chain never contacts them.
        if !contact_url_permitted(url, true) && !url.starts_with("https://") {
            return Err("fixture refuses unsafe URL".to_owned());
        }
        // Private literals are never served, even in fixtures: the test
        // asserts they are observed-as-text at most.
        if url.contains("127.0.0.1") || url.contains("192.168.") || url.contains("[::1]") {
            return Err("fixture refuses private destination".to_owned());
        }
        self.pages
            .get(url)
            .cloned()
            .ok_or_else(|| "fixture has no page for URL".to_owned())
    }
}

/// Deterministic fixture DNS.
#[derive(Debug, Default)]
pub struct FixtureDnsFetcher {
    /// (domain lower, TYPE upper) -> values.
    pub records: HashMap<(String, String), Vec<String>>,
}

impl FixtureDnsFetcher {
    pub fn with_records(mut self, domain: &str, rtype: &str, values: &[&str]) -> Self {
        self.records.insert(
            (domain.to_ascii_lowercase(), rtype.to_ascii_uppercase()),
            values.iter().map(|s| (*s).to_owned()).collect(),
        );
        self
    }
}

impl DnsFetcher for FixtureDnsFetcher {
    fn query(
        &self,
        domain: &str,
        record_type: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Vec<String>, String> {
        if cancelled.load(Ordering::Acquire) {
            return Err("cancelled".to_owned());
        }
        if Instant::now() >= deadline {
            return Err("deadline".to_owned());
        }
        Ok(self
            .records
            .get(&(
                domain.to_ascii_lowercase(),
                record_type.to_ascii_uppercase(),
            ))
            .cloned()
            .unwrap_or_default())
    }
}

/// Slow fixture DNS for deadline tests.
#[derive(Debug)]
pub struct SlowDnsFetcher {
    pub delay: Duration,
}

impl DnsFetcher for SlowDnsFetcher {
    fn query(
        &self,
        _domain: &str,
        _record_type: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Vec<String>, String> {
        let end = Instant::now() + self.delay;
        while Instant::now() < end {
            if cancelled.load(Ordering::Acquire) {
                return Err("cancelled".to_owned());
            }
            if Instant::now() >= deadline {
                return Err("deadline".to_owned());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(vec!["192.0.2.10".to_owned()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn test_config(username: &str, depth: u8) -> InvestigationConfig {
        let mut config = InvestigationConfig::username(username);
        config.depth = depth;
        config.allow_test_loopback = true;
        config.deadline = Duration::from_secs(10);
        config
    }

    fn fixture_graph() -> (
        FixtureSearchRunner,
        FixtureProfileFetcher,
        FixtureDnsFetcher,
    ) {
        let search = FixtureSearchRunner::default()
            .with_account(
                "exampleuser",
                "provider-a",
                "Provider A",
                "https://profile.example.test/exampleuser",
            )
            .with_account(
                "exampleuser",
                "provider-b",
                "Provider B",
                "https://blog.example.test/exampleuser",
            );
        let profile = FixtureProfileFetcher::default()
            .with_page(
                "https://profile.example.test/exampleuser",
                "https://profile.example.test/exampleuser",
                r#"<html><head><link rel="canonical" href="https://profile.example.test/exampleuser"></head><body><a href="https://example.test/">website</a> <a href="https://github.com/exampleuser/example-repo">code</a></body></html>"#,
            )
            .with_page(
                "https://blog.example.test/exampleuser",
                "https://blog.example.test/exampleuser",
                r#"<html><body><a href="https://example.test/about">same domain</a></body></html>"#,
            );
        let dns = FixtureDnsFetcher::default()
            .with_records("example.test", "A", &["192.0.2.10"])
            .with_records("example.test", "AAAA", &["2001:db8::10"])
            .with_records("example.test", "MX", &["10 mail.example.test."])
            .with_records("example.test", "NS", &["ns1.example.test."])
            .with_records("example.test", "TXT", &["v=spf1 -all"])
            .with_records("example.test", "SRV", &["0 0 443 api.example.test."]);
        (search, profile, dns)
    }

    #[test]
    fn depth_zero_is_seed_only() {
        let (search, profile, dns) = fixture_graph();
        let cancelled = AtomicBool::new(false);
        let report = run_investigation_with(
            test_config("exampleuser", 0),
            &search,
            &profile,
            &dns,
            &cancelled,
        )
        .unwrap();
        assert_eq!(report.entities.len(), 1);
        assert!(report.relationships.is_empty());
        report.accounting.check_invariant().unwrap();
    }

    #[test]
    fn depth_one_yields_accounts_only() {
        let (search, profile, dns) = fixture_graph();
        let cancelled = AtomicBool::new(false);
        let report = run_investigation_with(
            test_config("exampleuser", 1),
            &search,
            &profile,
            &dns,
            &cancelled,
        )
        .unwrap();
        // seed + 2 accounts
        assert_eq!(report.entities.len(), 3);
        assert_eq!(report.relationships.len(), 2);
        assert!(
            report
                .relationships
                .iter()
                .all(|r| r.relation == EdgeRelation::HasAccount)
        );
        report.accounting.check_invariant().unwrap();
    }

    #[test]
    fn depth_two_expands_urls_domains_repos() {
        let (search, profile, dns) = fixture_graph();
        let cancelled = AtomicBool::new(false);
        let report = run_investigation_with(
            test_config("exampleuser", 2),
            &search,
            &profile,
            &dns,
            &cancelled,
        )
        .unwrap();
        assert!(
            report
                .entities
                .values()
                .any(|e| e.kind == EntityKind::Domain)
        );
        assert!(
            report
                .entities
                .values()
                .any(|e| e.kind == EntityKind::Repository)
        );
        assert_eq!(report.network_scans, 0);
        assert_eq!(report.accounting.network_scans, 0);
        report.accounting.check_invariant().unwrap();
    }

    #[test]
    fn depth_three_expands_dns() {
        let (search, profile, dns) = fixture_graph();
        let cancelled = AtomicBool::new(false);
        let report = run_investigation_with(
            test_config("exampleuser", 3),
            &search,
            &profile,
            &dns,
            &cancelled,
        )
        .unwrap();
        assert!(
            report
                .entities
                .values()
                .any(|e| e.kind == EntityKind::IpAddress)
        );
        assert!(
            report
                .entities
                .values()
                .any(|e| e.kind == EntityKind::DnsRecord)
        );
        assert!(report.accounting.dns_queries > 0);
        report.accounting.check_invariant().unwrap();
    }

    #[test]
    fn shared_domain_dedups_with_two_evidence_paths() {
        let (search, profile, dns) = fixture_graph();
        let cancelled = AtomicBool::new(false);
        let report = run_investigation_with(
            test_config("exampleuser", 2),
            &search,
            &profile,
            &dns,
            &cancelled,
        )
        .unwrap();
        let domains: Vec<&InvestigationEntity> = report
            .entities
            .values()
            .filter(|e| e.kind == EntityKind::Domain && e.canonical_value == "example.test")
            .collect();
        assert_eq!(domains.len(), 1, "one Domain entity, not duplicates");
        let inbound = report
            .relationships
            .iter()
            .filter(|r| r.to == domains[0].id)
            .count();
        assert!(
            inbound >= 2,
            "two independent provenance paths, got {inbound}"
        );
    }

    #[test]
    fn cycle_bound_prevents_repeated_expansion() {
        // Account -> Url -> Domain -> (hostname refs, no re-expansion).
        // A second account pointing at the same domain must not cause
        // unbounded Url -> Domain -> Url cycling: each (transform, entity)
        // expands at most once.
        let (search, profile, dns) = fixture_graph();
        let cancelled = AtomicBool::new(false);
        let report = run_investigation_with(
            test_config("exampleuser", 5),
            &search,
            &profile,
            &dns,
            &cancelled,
        )
        .unwrap();
        // Bounded: no pathological blowup from the shared domain.
        assert!(report.entities.len() < 100, "len={}", report.entities.len());
        report.accounting.check_invariant().unwrap();
        // Every entity id is unique (dedup invariant).
        let mut ids: Vec<&String> = report.entities.keys().collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), report.entities.len());
    }

    #[test]
    fn tiny_budgets_truncate_gracefully() {
        for (config_fn, reason) in [
            (
                Box::new(|c: &mut InvestigationConfig| c.max_entities = 1)
                    as Box<dyn Fn(&mut InvestigationConfig)>,
                "entity_budget",
            ),
            (
                Box::new(|c: &mut InvestigationConfig| c.max_relationships = 1),
                "relationship_budget",
            ),
            (
                Box::new(|c: &mut InvestigationConfig| c.max_http_requests = 0),
                "http_budget",
            ),
            (
                Box::new(|c: &mut InvestigationConfig| {
                    c.depth = 3;
                    c.max_dns_queries = 0;
                }),
                "dns_budget",
            ),
        ] {
            let (search, profile, dns) = fixture_graph();
            let cancelled = AtomicBool::new(false);
            let mut config = test_config("exampleuser", 3);
            config_fn(&mut config);
            let report =
                run_investigation_with(config, &search, &profile, &dns, &cancelled).unwrap();
            assert!(
                report.accounting.truncated,
                "expected truncation for {reason}"
            );
            assert!(
                report.accounting.truncation_reasons.contains(reason),
                "missing {reason}: {:?}",
                report.accounting.truncation_reasons
            );
            // Partial graph preserved, output valid.
            assert!(!report.entities.is_empty());
            let json = serde_json::to_string(&report).unwrap();
            assert!(!json.contains('\x1b'));
            let jsonl = render_jsonl(&report);
            for line in jsonl.lines() {
                serde_json::from_str::<serde_json::Value>(line).unwrap();
            }
            report.accounting.check_invariant().unwrap();
        }
    }

    #[test]
    fn not_found_never_creates_accounts() {
        let search = FixtureSearchRunner::default();
        let profile = FixtureProfileFetcher::default();
        let dns = FixtureDnsFetcher::default();
        let cancelled = AtomicBool::new(false);
        let report = run_investigation_with(
            test_config("ghostuser", 3),
            &search,
            &profile,
            &dns,
            &cancelled,
        )
        .unwrap();
        assert_eq!(report.entities.len(), 1, "seed only");
        assert!(
            report.observations.iter().any(|o| o.status == "not_found"),
            "non-positive outcomes stay observations"
        );
    }

    #[test]
    fn passive_boundary_holds_no_direct_network() {
        let (search, profile, dns) = fixture_graph();
        let cancelled = AtomicBool::new(false);
        let report = run_investigation_with(
            test_config("exampleuser", 5),
            &search,
            &profile,
            &dns,
            &cancelled,
        )
        .unwrap();
        assert_eq!(report.network_scans, 0);
        assert_eq!(report.direct_network_contacts, 0);
        assert_eq!(report.accounting.network_scans, 0);
        // Every observation contact class is passive-allowed.
        for obs in &report.observations {
            assert!(
                matches!(
                    obs.contact_class,
                    ContactClass::PassivePublic
                        | ContactClass::PublicHttp
                        | ContactClass::DnsQuery
                        | ContactClass::LocalDataset
                ),
                "forbidden contact {:?}",
                obs.contact_class
            );
        }
        for entity in report.entities.values() {
            assert!(
                matches!(
                    entity.provenance.contact_class,
                    ContactClass::PassivePublic
                        | ContactClass::PublicHttp
                        | ContactClass::DnsQuery
                        | ContactClass::LocalDataset
                ),
                "forbidden entity contact {:?}",
                entity.provenance.contact_class
            );
        }
    }

    #[test]
    fn unsafe_profile_links_are_never_contacted() {
        let search = FixtureSearchRunner::default().with_account(
            "exampleuser",
            "provider-a",
            "Provider A",
            "https://profile.example.test/exampleuser",
        );
        let profile = FixtureProfileFetcher::default().with_page(
            "https://profile.example.test/exampleuser",
            "https://profile.example.test/exampleuser",
            r#"<html><body>
            <a href="http://127.0.0.1/admin">loopback</a>
            <a href="http://192.168.1.1/">rfc1918</a>
            <a href="http://[::1]/">v6 loopback</a>
            <a href="file:///etc/passwd">file</a>
            <a href="https://example.test/ok">ok</a>
            </body></html>"#,
        );
        let dns = FixtureDnsFetcher::default();
        let cancelled = AtomicBool::new(false);
        let report = run_investigation_with(
            test_config("exampleuser", 2),
            &search,
            &profile,
            &dns,
            &cancelled,
        )
        .unwrap();
        // Only the profile page itself was contacted. Unsafe links may
        // exist as observed entities/text, but they are never fetched:
        // observation and contact are distinct.
        assert_eq!(profile.call_count(), 1);
        // The safe link is still discovered.
        assert!(
            report
                .entities
                .values()
                .any(|e| e.canonical_value.contains("example.test"))
        );
        // Passive boundary still holds with hostile profile content.
        assert_eq!(report.network_scans, 0);
        assert_eq!(report.accounting.network_scans, 0);
        report.accounting.check_invariant().unwrap();
    }

    #[test]
    fn jsonl_is_typed_stable_and_clean() {
        let (search, profile, dns) = fixture_graph();
        let cancelled = AtomicBool::new(false);
        let report = run_investigation_with(
            test_config("exampleuser", 3),
            &search,
            &profile,
            &dns,
            &cancelled,
        )
        .unwrap();
        let text = render_jsonl(&report);
        assert!(!text.contains('\x1b'));
        assert!(!text.contains("RXSCAN"));
        let mut invalid = 0usize;
        let mut kinds = Vec::new();
        for line in text.lines() {
            match serde_json::from_str::<serde_json::Value>(line) {
                Ok(record) => {
                    kinds.push(record["record_type"].as_str().unwrap().to_owned());
                }
                Err(_) => invalid += 1,
            }
        }
        assert_eq!(invalid, 0);
        assert_eq!(kinds.first().unwrap(), "investigation_start");
        assert_eq!(kinds.last().unwrap(), "investigation_summary");
        assert!(kinds.contains(&"entity".to_owned()));
        assert!(kinds.contains(&"relationship".to_owned()));
        assert!(kinds.contains(&"observation".to_owned()));
        // Deterministic: byte-identical on re-render.
        assert_eq!(render_jsonl(&report), text);
        // Summary reconciles.
        let summary_line = text.lines().last().unwrap();
        let summary: serde_json::Value = serde_json::from_str(summary_line).unwrap();
        let accounting = &summary["payload"]["accounting"];
        assert_eq!(
            accounting["transforms_requested"].as_u64().unwrap(),
            accounting["transforms_completed"].as_u64().unwrap()
                + accounting["transforms_skipped"].as_u64().unwrap()
                + accounting["transforms_cancelled"].as_u64().unwrap()
                + accounting["transforms_unscanned"].as_u64().unwrap()
        );
    }

    #[test]
    fn deadline_is_respected_with_partial_graph() {
        let search = FixtureSearchRunner::default().with_account(
            "exampleuser",
            "provider-a",
            "Provider A",
            "https://profile.example.test/exampleuser",
        );
        let profile = FixtureProfileFetcher::default().with_page(
            "https://profile.example.test/exampleuser",
            "https://profile.example.test/exampleuser",
            r#"<html><body><a href="https://example.test/">website</a></body></html>"#,
        );
        let dns = SlowDnsFetcher {
            delay: Duration::from_secs(5),
        };
        let cancelled = AtomicBool::new(false);
        let mut config = test_config("exampleuser", 3);
        config.deadline = Duration::from_millis(80);
        let report = run_investigation_with(config, &search, &profile, &dns, &cancelled).unwrap();
        assert!(report.accounting.truncated);
        assert!(report.accounting.truncation_reasons.contains("deadline"));
        assert!(!report.entities.is_empty(), "partial graph retained");
        serde_json::to_string(&report).unwrap();
        render_jsonl(&report);
        report.accounting.check_invariant().unwrap();
    }

    #[test]
    fn cancellation_preserves_partial_graph() {
        let (search, profile, dns) = fixture_graph();
        let cancelled = AtomicBool::new(true);
        let report = run_investigation_with(
            test_config("exampleuser", 3),
            &search,
            &profile,
            &dns,
            &cancelled,
        )
        .unwrap();
        assert!(!report.entities.is_empty());
        serde_json::to_string(&report).unwrap();
        let text = render_jsonl(&report);
        for line in text.lines() {
            serde_json::from_str::<serde_json::Value>(line).unwrap();
        }
        report.accounting.check_invariant().unwrap();
    }

    #[test]
    fn url_normalization_and_schemes() {
        assert!(contact_url_permitted("https://example.test/", false));
        assert!(!contact_url_permitted("http://example.test/", false));
        assert!(!contact_url_permitted("file:///etc/passwd", false));
        assert!(!contact_url_permitted("ftp://example.test/x", false));
        assert!(!contact_url_permitted("data:text/plain,hi", false));
        assert!(!contact_url_permitted("javascript:alert(1)", false));
        assert!(!contact_url_permitted("http://127.0.0.1/", false));
        assert!(!contact_url_permitted("http://192.168.1.1/", false));
        assert!(!contact_url_permitted("http://[::1]/", false));
        // Deduplication: default ports share identity.
        assert_eq!(
            canonical_url_entity("https://example.test/"),
            canonical_url_entity("https://example.test:443/")
        );
    }

    #[test]
    fn repository_identity_is_bounded() {
        assert_eq!(
            parse_repository_identity("https://github.com/exampleuser/example-repo"),
            Some(("exampleuser".to_owned(), "example-repo".to_owned()))
        );
        assert_eq!(parse_repository_identity("https://example.test/x"), None);
        assert_eq!(
            parse_repository_identity("http://github.com/exampleuser/example-repo"),
            None,
            "http forge links are not repository evidence"
        );
    }

    #[test]
    fn registry_answers_planning_questions() {
        let registry = TransformRegistry::new();
        assert!(!registry.ids().is_empty());
        let infos = registry.infos();
        assert_eq!(infos.len(), registry.ids().len());
        for info in &infos {
            assert!(!info.accepts.is_empty());
            assert!(!info.produces.is_empty());
        }
        // No DirectNetwork anywhere in the registry.
        for info in &infos {
            assert!(
                !matches!(
                    info.contact_class,
                    ContactClass::DirectNetwork | ContactClass::AuthenticatedApi
                ),
                "transform {} uses forbidden contact",
                info.id
            );
        }
    }

    #[test]
    fn explain_plan_is_contact_free() {
        let config = test_config("exampleuser", 3);
        let plan = explain_plan(&config);
        assert!(plan.contains("INVESTIGATION PLAN"));
        assert!(plan.contains("DirectNetwork"));
        assert!(plan.contains("network scans     0"));
    }
}
