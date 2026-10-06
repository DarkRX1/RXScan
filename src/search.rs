use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROVIDER_SCHEMA_VERSION: u32 = 1;
// NOTE: there is deliberately NO maximum registry size. Registry size and
// execution concurrency are separate concepts: thousands of registered
// vectors are fine; only a bounded number ever runs concurrently (see
// `SearchScheduler.max_concurrency`). Pack transport stays bounded by
// `MAX_PROVIDER_PACK_BYTES` so a corrupt/huge file cannot OOM the loader.
// Never reintroduce an arbitrary provider/vector count cap here.
pub const MAX_PROVIDER_PACK_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_SEARCH_EVIDENCE: usize = 8;
pub const MAX_SEARCH_BODY_BYTES: usize = 256 * 1024;
pub const MAX_SEARCH_HEADERS: usize = 32;
/// Default username-search fan-out shared by CLI and Web so both entry
/// points schedule the same plan. Registry size and concurrency stay
/// separate concepts: thousands of vectors are fine, only this many run
/// concurrently (plus at most one in flight per provider).
pub const DEFAULT_SEARCH_CONCURRENCY: usize = 4;
pub const MAX_SEARCH_PER_HOST: usize = 1;
pub const SEARCH_USER_AGENT: &str = "RXScan/0.1 public-search";
pub const USERNAME_PROVIDER_CATEGORIES: &[&str] = &[
    // Legacy corpus categories (stable, still valid for existing providers).
    "commerce",
    "creative",
    "developer",
    "forum",
    "gaming",
    "media",
    "misc",
    "professional",
    "security",
    "social",
    // Shared forward-looking category vocabulary (stable machine IDs).
    // Categories with zero configured providers are valid selection targets
    // but honestly report zero scheduled; they are never hardcoded with fake
    // counts. `adult` and `intelligence` exist as explicit classes so such
    // providers are never hidden inside `other`/`misc`.
    "community",
    "creator",
    "shopping",
    "finance",
    "music",
    "education",
    "news-media",
    "messaging",
    "archives",
    "adult",
    "other",
    "intelligence",
];

/// Human label for a machine category ID.
///
/// Stable mapping shared by CLI and web: the registry owns the IDs, this
/// owns the presentation labels. Unknown IDs fall back to the raw ID so
/// future registry categories never break presentation.
pub fn category_label(category: &str) -> &str {
    match category {
        "social" => "Social",
        "developer" => "Developer",
        "community" => "Community",
        "gaming" => "Gaming",
        "creator" => "Creator",
        "creative" => "Creator",
        "shopping" => "Shopping",
        "commerce" => "Shopping",
        "finance" => "Finance",
        "music" => "Music",
        "media" => "News / Media",
        "news-media" => "News / Media",
        "messaging" => "Messaging",
        "archives" => "Archives",
        "adult" => "Adult / NSFW",
        "professional" => "Professional",
        "education" => "Education",
        "forum" => "Community",
        "security" => "Security",
        "misc" => "Other",
        "other" => "Other",
        "intelligence" => "Intelligence",
        _ => category,
    }
}

/// Canonical known categories (registry vocabulary, sorted, deduped).
/// Used by both CLI and web to validate `--category` / category selection:
/// unknown IDs are rejected, known-but-empty IDs honestly schedule zero.
pub fn known_username_categories() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = USERNAME_PROVIDER_CATEGORIES.to_vec();
    out.sort_unstable();
    out.dedup();
    out
}

/// Discovery state for one provider definition.
///
/// Shared by CLI (`search providers`) and the web API: a single definition
/// of usable vs review-queue vs never-scheduled.
pub fn provider_state(definition: &UsernameProviderDefinition) -> &'static str {
    match definition.health_state {
        HealthState::Disabled => "disabled",
        HealthState::NeedsReview => "unavailable",
        HealthState::FixtureVerified | HealthState::LiveVerified => "usable",
    }
}

/// Per-category registry summary. Counts come from the loaded pack only.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProviderCategorySummary {
    pub category: String,
    pub label: String,
    pub configured: usize,
    pub usable: usize,
    pub unavailable: usize,
    pub disabled: usize,
}

/// Category discovery from the real provider registry (no hardcoded counts).
pub fn username_category_summary(pack: &UsernameProviderPack) -> Vec<ProviderCategorySummary> {
    let mut by_category: BTreeMap<String, Vec<&UsernameProviderDefinition>> = BTreeMap::new();
    for provider in &pack.providers {
        by_category
            .entry(provider.category.clone())
            .or_default()
            .push(provider);
    }
    let mut out = Vec::new();
    for (category, providers) in by_category {
        let mut usable = 0usize;
        let mut unavailable = 0usize;
        let mut disabled = 0usize;
        for provider in providers.iter() {
            match provider_state(provider) {
                "usable" => usable += 1,
                "unavailable" => unavailable += 1,
                _ => disabled += 1,
            }
        }
        out.push(ProviderCategorySummary {
            label: category_label(&category).to_owned(),
            category: category.clone(),
            configured: providers.len(),
            usable,
            unavailable,
            disabled,
        });
    }
    out.sort_by(|a, b| a.category.cmp(&b.category));
    out
}

/// Provider vs search vector.
///
/// Do NOT assume one website == one search vector. A provider may expose
/// several genuinely different lookup/detection paths (e.g. a username
/// vector, a public-profile vector, a metadata vector). Every vector must
/// represent a different lookup path — never duplicate vectors to inflate a
/// count, and never advertise "N sites" when the implementation holds fewer
/// sites with multiple vectors.
///
/// Today each username definition registers exactly one vector whose stable
/// ID equals the provider ID. The model below keeps provider and vector
/// counts distinct so multi-vector providers can land later without
/// double-counting sites, and so every frontend reports both numbers
/// honestly from the same registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchVectorRef {
    /// Stable vector ID (`provider-id` today; `provider-id/vector-name`
    /// for future multi-vector providers).
    pub vector_id: String,
    pub provider_id: String,
    pub provider_name: String,
    pub category: String,
    pub category_label: String,
    /// Entity kind this vector accepts (`username` today).
    pub entity_kind: &'static str,
    /// Discovery state of the owning provider (`usable`/`unavailable`/`disabled`).
    pub state: &'static str,
}

/// All registered username search vectors, sorted by stable vector ID.
///
/// Derived from the loaded pack only — never hardcoded, never inflated.
pub fn username_search_vectors(pack: &UsernameProviderPack) -> Vec<SearchVectorRef> {
    let mut out: Vec<SearchVectorRef> = pack
        .providers
        .iter()
        .map(|definition| SearchVectorRef {
            vector_id: definition.metadata.id.clone(),
            provider_id: definition.metadata.id.clone(),
            provider_name: definition.platform.clone(),
            category: definition.category.clone(),
            category_label: category_label(&definition.category).to_owned(),
            entity_kind: "username",
            state: provider_state(definition),
        })
        .collect();
    out.sort_by(|a, b| a.vector_id.cmp(&b.vector_id));
    out
}

/// Honest registry counts shared by CLI, API, GUI, and machine output.
///
/// Definitions (spec section "configured / enabled / usable / scheduled /
/// completed / remaining"):
///
/// * `providers_configured` — definitions in the registry.
/// * `vectors_registered` — registered lookup paths (1:1 with definitions
///   today; larger only when providers genuinely expose more paths).
/// * `enabled` — configured minus `disabled` (never scheduled).
/// * `usable` — enabled with verified detection (`fixture_verified` or
///   `live_verified`); `needs_review` stays `unavailable`, never usable.
/// * `scheduled` is per-run (the effective plan), NOT part of this struct:
///   see [`plan_username_providers`] and progress denominators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryCounts {
    pub providers_configured: usize,
    pub vectors_registered: usize,
    pub enabled: usize,
    pub usable: usize,
    pub unavailable: usize,
    pub disabled: usize,
}

/// Registry counts for the username corpus. All values derive from the
/// loaded pack; report exactly what RXScan has, never a target number.
pub fn username_registry_counts(pack: &UsernameProviderPack) -> RegistryCounts {
    let vectors = username_search_vectors(pack);
    let mut enabled = 0usize;
    let mut usable = 0usize;
    let mut unavailable = 0usize;
    let mut disabled = 0usize;
    for vector in &vectors {
        match vector.state {
            "usable" => {
                usable += 1;
                enabled += 1;
            }
            "unavailable" => {
                unavailable += 1;
                enabled += 1;
            }
            _ => disabled += 1,
        }
    }
    let mut provider_ids = BTreeSet::new();
    for vector in &vectors {
        provider_ids.insert(vector.provider_id.as_str());
    }
    RegistryCounts {
        providers_configured: provider_ids.len(),
        vectors_registered: vectors.len(),
        enabled,
        usable,
        unavailable,
        disabled,
    }
}

/// Email search-vector registry.
///
/// The email vector registry is defined but currently unpopulated: email
/// search stays passive local canonicalization until real email lookup
/// vectors (stable ID, target construction, positive + absence rules,
/// fixtures, provenance, review status) land under the same quality bar.
/// Reporting `0` honestly beats advertising vectors RXScan does not have.
pub fn email_registry_counts() -> RegistryCounts {
    RegistryCounts {
        providers_configured: 0,
        vectors_registered: 0,
        enabled: 0,
        usable: 0,
        unavailable: 0,
        disabled: 0,
    }
}

/// Shared execution-plan selection for username search.
///
/// Both the terminal CLI and the web API call this: given the loaded pack
/// plus operator-selected provider IDs, excluded IDs, and categories, it
/// validates unknown entries and returns the exact provider ID set the
/// scheduler will run. Category/provider selection affects the REAL plan
/// (never post-filters after contacting every provider).
pub fn plan_username_providers(
    pack: &UsernameProviderPack,
    selected: Option<&BTreeSet<String>>,
    excluded: &BTreeSet<String>,
    categories: &BTreeSet<String>,
) -> Result<BTreeSet<String>, String> {
    let available: BTreeSet<&str> = pack
        .providers
        .iter()
        .map(|provider| provider.metadata.id.as_str())
        .collect();
    for requested in selected
        .iter()
        .flat_map(|ids| ids.iter())
        .chain(excluded.iter())
    {
        if !available.contains(requested.as_str()) {
            return Err(format!("unknown provider: {requested}"));
        }
    }
    let known: BTreeSet<&str> = known_username_categories().into_iter().collect();
    let mut unknown_categories = Vec::new();
    for category in categories {
        if !known.contains(category.as_str()) {
            unknown_categories.push(category.clone());
        }
    }
    if !unknown_categories.is_empty() {
        unknown_categories.sort();
        let label = if unknown_categories.len() == 1 {
            "unknown category"
        } else {
            "unknown categories"
        };
        return Err(format!(
            "{label}: {} (known: {})",
            unknown_categories.join(", "),
            known.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    let effective: BTreeSet<String> = pack
        .providers
        .iter()
        .filter(|provider| {
            selected
                .as_ref()
                .is_none_or(|ids| ids.contains(&provider.metadata.id))
                && !excluded.contains(&provider.metadata.id)
                && (categories.is_empty() || categories.contains(&provider.category))
        })
        .map(|provider| provider.metadata.id.clone())
        .collect();
    Ok(effective)
}

/// Per-category coverage derived from the real plan + real results.
///
/// `effective` is the exact scheduled set from [`plan_username_providers`];
/// `results` are completed observations; `provider_to_category` maps every
/// scheduled provider to its registry category. Scheduled counts come from
/// the plan, complete counts from observations — never invented.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UsernameCategoryCoverage {
    pub category: String,
    pub label: String,
    pub scheduled: usize,
    pub complete: usize,
    pub remaining: usize,
}

pub fn coverage_by_category(
    effective: &BTreeSet<String>,
    provider_to_category: &BTreeMap<String, String>,
    results: &[SearchObservation],
) -> Vec<UsernameCategoryCoverage> {
    let mut scheduled: BTreeMap<String, usize> = BTreeMap::new();
    for provider in effective {
        let category = provider_to_category
            .get(provider)
            .cloned()
            .unwrap_or_else(|| "other".to_owned());
        *scheduled.entry(category).or_default() += 1;
    }
    let mut complete: BTreeMap<String, usize> = BTreeMap::new();
    for result in results {
        if let Some(category) = provider_to_category.get(&result.provider_id) {
            *complete.entry(category.clone()).or_default() += 1;
        }
    }
    let mut out = Vec::new();
    for (category, scheduled_count) in scheduled {
        let complete_count = complete
            .get(&category)
            .copied()
            .unwrap_or(0)
            .min(scheduled_count);
        out.push(UsernameCategoryCoverage {
            label: category_label(&category).to_owned(),
            category: category.clone(),
            scheduled: scheduled_count,
            complete: complete_count,
            remaining: scheduled_count.saturating_sub(complete_count),
        });
    }
    out.sort_by(|a, b| a.category.cmp(&b.category));
    out
}

/// Core URL-kind semantics shared by CLI, web, and machine output.
///
/// Mirrors the terminal presentation honesty (`Profile` vs `Resource` vs
/// `Candidate` vs `ProviderEndpoint`) without any presentation styling:
/// the same inputs always yield the same kind in every frontend.
pub fn core_url_kind(url: &str, username: &str, observed: bool) -> &'static str {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return "none";
    }
    let user = username.trim().to_ascii_lowercase();
    let lower = trimmed.to_ascii_lowercase();
    let identity = if user.is_empty() {
        false
    } else if lower.contains(&user) {
        true
    } else {
        // Percent-encoded username form (provider templates encode).
        let mut encoded = String::with_capacity(user.len());
        for byte in username.trim().as_bytes() {
            if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
                encoded.push(char::from(*byte).to_ascii_lowercase());
            } else {
                encoded.push('%');
                encoded.push(
                    char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]).to_ascii_lowercase(),
                );
                encoded.push(
                    char::from(b"0123456789ABCDEF"[(byte & 15) as usize]).to_ascii_lowercase(),
                );
            }
        }
        encoded != user && lower.contains(&encoded)
    };
    if !identity {
        return "provider_endpoint";
    }
    if observed {
        // API/resource shape detection (same heuristic as terminal).
        let host = lower
            .split("://")
            .nth(1)
            .unwrap_or(&lower)
            .split('/')
            .next()
            .unwrap_or("")
            .split('?')
            .next()
            .unwrap_or("")
            .split('#')
            .next()
            .unwrap_or("");
        let path = lower.split("://").nth(1).unwrap_or(&lower);
        let is_api = host.starts_with("api.")
            || host.contains(".api.")
            || path.contains("/api/")
            || path.contains("/xrpc/")
            || path.contains("/v1/users/")
            || path.contains("/v2/users/")
            || path.contains("/v1/user/")
            || path.contains("about.json")
            || path.contains("lookup.json")
            || path.trim_end_matches('/').ends_with(".json");
        if is_api {
            "observed_resource"
        } else {
            "observed_profile"
        }
    } else {
        "candidate"
    }
}

/// Bounded public-metadata prioritization shared by CLI and web.
///
/// Deterministic order, visible hidden-count: the default renderer shows
/// only a useful subset; `--all`/`--explain` (or web expand) may show more.
/// A provider returning 100 keys never destroys readability.
pub fn prioritized_public_metadata(
    attributes: &BTreeMap<String, String>,
    limit: usize,
) -> (Vec<(String, String)>, usize) {
    const PRIORITY: &[&str] = &[
        "username",
        "display_name",
        "displayname",
        "name",
        "joined",
        "created",
        "created_at",
        "followers",
        "following",
        "website",
        "url",
        "bio",
        "location",
        "account_type",
        "platform",
        "profile_url",
        "final_url",
        "http_status",
        "provider_health",
        "elapsed_ms",
    ];
    let mut ordered: Vec<(String, String)> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for key in PRIORITY {
        if let Some(value) = attributes.get(*key) {
            let value = value.trim();
            if !value.is_empty() {
                ordered.push(((*key).to_owned(), value.to_owned()));
                seen.insert((*key).to_owned());
            }
        }
    }
    let mut rest: Vec<(String, String)> = attributes
        .iter()
        .filter(|(key, value)| !seen.contains(*key) && !value.trim().is_empty())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    rest.sort_by(|a, b| a.0.cmp(&b.0));
    // Technical hashes stay last; they prove observation but rarely help.
    ordered.extend(rest);
    if ordered.len() <= limit {
        (ordered, 0)
    } else {
        let hidden = ordered.len() - limit;
        ordered.truncate(limit);
        (ordered, hidden)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundedHttpResponse {
    pub status: u16,
    pub final_url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub redirect_count: u8,
    pub elapsed_ms: u64,
    pub body_truncated: bool,
}

#[derive(Clone)]
pub struct SharedHttpClient {
    clients: Arc<Mutex<BTreeMap<String, reqwest::blocking::Client>>>,
    resolver: Arc<dyn SearchResolver>,
    allow_nonpublic: bool,
}

trait SearchResolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, SearchError>;
}

struct SystemResolver;

impl SearchResolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, SearchError> {
        (host, port)
            .to_socket_addrs()
            .map(|addresses| addresses.collect())
            .map_err(|error| SearchError::Http(format!("could not resolve '{host}': {error}")))
    }
}

impl SharedHttpClient {
    pub fn new() -> Result<Self, SearchError> {
        Ok(Self {
            clients: Arc::new(Mutex::new(BTreeMap::new())),
            resolver: Arc::new(SystemResolver),
            allow_nonpublic: false,
        })
    }

    fn client_for(&self, url: &url::Url) -> Result<reqwest::blocking::Client, SearchError> {
        let host = url
            .host_str()
            .ok_or_else(|| SearchError::UnsafeUrl("URL has no host".to_owned()))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| SearchError::UnsafeUrl("URL has no usable port".to_owned()))?;
        let key = format!("{}:{port}", host.to_ascii_lowercase());
        if let Some(client) = self
            .clients
            .lock()
            .map_err(|_| SearchError::Http("HTTP client cache is poisoned".to_owned()))?
            .get(&key)
            .cloned()
        {
            return Ok(client);
        }
        let mut addresses = self.resolver.resolve(host, port)?;
        addresses.sort();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(SearchError::Http(format!(
                "provider host '{host}' resolved to no addresses"
            )));
        }
        for address in &addresses {
            if !public_search_address_allowed(address.ip(), self.allow_nonpublic) {
                return Err(SearchError::UnsafeUrl(format!(
                    "provider host '{host}' resolved to prohibited address {}",
                    address.ip()
                )));
            }
        }
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(SEARCH_USER_AGENT)
            .pool_max_idle_per_host(2)
            .connect_timeout(std::time::Duration::from_secs(5))
            .no_proxy()
            .resolve_to_addrs(host, &addresses)
            .build()
            .map_err(|error| SearchError::Http(format!("could not create HTTP client: {error}")))?;
        self.clients
            .lock()
            .map_err(|_| SearchError::Http("HTTP client cache is poisoned".to_owned()))?
            .insert(key, client.clone());
        Ok(client)
    }

    pub fn get(
        &self,
        initial_url: &url::Url,
        timeout: std::time::Duration,
        body_limit: usize,
        redirect_limit: u8,
        context: &SearchContext<'_>,
    ) -> Result<BoundedHttpResponse, SearchError> {
        validate_public_url(initial_url, self.allow_nonpublic)?;
        let started = Instant::now();
        let mut current = initial_url.clone();
        let mut redirects = 0u8;
        loop {
            if context.cancelled.load(Ordering::Acquire) {
                return Err(SearchError::Cancelled);
            }
            let remaining = context.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SearchError::Deadline);
            }
            let request_timeout = timeout.min(remaining);
            let deadline_limited = request_timeout == remaining;
            let response = self
                .client_for(&current)?
                .get(current.clone())
                .timeout(request_timeout)
                .header(reqwest::header::ACCEPT_ENCODING, "identity")
                .send()
                .map_err(|error| {
                    if error.is_timeout() && deadline_limited {
                        SearchError::Deadline
                    } else if error.is_timeout() {
                        SearchError::Http(format!(
                            "request timed out after {}ms",
                            request_timeout.as_millis()
                        ))
                    } else {
                        SearchError::Http(error.to_string())
                    }
                })?;
            if context.cancelled.load(Ordering::Acquire) {
                return Err(SearchError::Cancelled);
            }
            let status = response.status();
            if status.is_redirection() {
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| {
                        SearchError::MalformedRedirect("redirect has no valid Location".to_owned())
                    })?;
                let next = current.join(location).map_err(|error| {
                    SearchError::MalformedRedirect(format!("invalid redirect target: {error}"))
                })?;
                if next.scheme() != "https" && !(self.allow_nonpublic && next.scheme() == "http") {
                    return Err(SearchError::UnsupportedRedirectScheme(
                        "unsupported scheme".to_owned(),
                    ));
                }
                let host = next.host_str().ok_or_else(|| {
                    SearchError::MalformedRedirect("redirect has no host".to_owned())
                })?;
                if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
                    return Err(SearchError::UnsafeRedirectDestination(
                        "loopback hostname is not public".to_owned(),
                    ));
                }
                if let Ok(ip) = host.parse::<IpAddr>() {
                    if !public_search_address_allowed(ip, self.allow_nonpublic) {
                        let dest_msg = format!("non-public destination '{host}'");
                        return Err(SearchError::UnsafeRedirectDestination(dest_msg));
                    }
                }
                if redirects >= redirect_limit {
                    return Err(SearchError::RedirectLimitExceeded);
                }
                current = next;
                redirects += 1;
                continue;
            }
            let mut headers = BTreeMap::new();
            for (name, value) in response
                .headers()
                .iter()
                .filter(|(name, _)| {
                    matches!(name.as_str(), "content-type" | "location" | "retry-after")
                })
                .take(MAX_SEARCH_HEADERS)
            {
                if let Ok(value) = value.to_str() {
                    headers.insert(name.as_str().to_owned(), value.chars().take(512).collect());
                }
            }
            let mut body = Vec::with_capacity(body_limit.min(16 * 1024) + 1);
            let mut bounded = response.take((body_limit + 1) as u64);
            bounded
                .read_to_end(&mut body)
                .map_err(|error| SearchError::Http(format!("response read failed: {error}")))?;
            let body_truncated = body.len() > body_limit;
            if body_truncated {
                body.truncate(body_limit);
            }
            return Ok(BoundedHttpResponse {
                status: status.as_u16(),
                final_url: current.to_string(),
                headers,
                body,
                redirect_count: redirects,
                elapsed_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                body_truncated,
            });
        }
    }
}

fn public_search_address_allowed(ip: IpAddr, allow_test_loopback: bool) -> bool {
    if allow_test_loopback && ip.is_loopback() {
        return true;
    }
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            let special = octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
                || octets[0] >= 240;
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_multicast()
                || special)
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
                || documentation)
        }
    }
}

fn validate_public_url(url: &url::Url, allow_test_loopback: bool) -> Result<(), SearchError> {
    if url.scheme() != "https" && !(allow_test_loopback && url.scheme() == "http") {
        return Err(SearchError::UnsafeUrl(format!(
            "unsupported scheme '{}'",
            url.scheme()
        )));
    }
    let host = url
        .host_str()
        .ok_or_else(|| SearchError::UnsafeUrl("URL has no host".to_owned()))?;
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return Err(SearchError::UnsafeUrl(
            "loopback hostname is not public".to_owned(),
        ));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !public_search_address_allowed(ip, allow_test_loopback) {
            return Err(SearchError::UnsafeUrl(format!(
                "non-public destination '{host}'"
            )));
        }
    }
    Ok(())
}

fn validate_definition_url(url: &url::Url) -> Result<(), SearchError> {
    if url.scheme() != "https" {
        return Err(SearchError::UnsafeUrl(
            "provider URL must use HTTPS".to_owned(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| SearchError::UnsafeUrl("URL has no host".to_owned()))?;
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return Err(SearchError::UnsafeUrl(
            "loopback hostname is not public".to_owned(),
        ));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !public_search_address_allowed(ip, false) {
            return Err(SearchError::UnsafeUrl(format!(
                "non-public destination '{host}'"
            )));
        }
    }
    Ok(())
}

pub fn provider_url(
    definition: &UsernameProviderDefinition,
    username: &str,
    allow_test_loopback: bool,
) -> Result<url::Url, SearchError> {
    if username.is_empty() || username.len() > 128 || username.chars().any(char::is_control) {
        return Err(SearchError::InvalidEntity(
            "username must be 1..=128 printable characters".to_owned(),
        ));
    }
    let mut encoded = String::with_capacity(username.len());
    for byte in username.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    let rendered = definition.profile_url.replace("{username}", &encoded);
    let url = url::Url::parse(&rendered)
        .map_err(|error| SearchError::UnsafeUrl(format!("invalid provider URL: {error}")))?;
    validate_public_url(&url, allow_test_loopback)?;
    Ok(url)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsernameProviderPack {
    pub schema_version: u32,
    pub pack_version: String,
    #[serde(default)]
    pub providers: Vec<UsernameProviderDefinition>,
}

pub fn parse_provider_pack(json: &str, source: &str) -> Result<UsernameProviderPack, SearchError> {
    if json.len() > MAX_PROVIDER_PACK_BYTES {
        return Err(SearchError::InvalidProvider(format!(
            "provider pack '{source}' exceeds 32 MiB"
        )));
    }
    let pack: UsernameProviderPack = serde_json::from_str(json).map_err(|error| {
        SearchError::InvalidProvider(format!("provider pack '{source}' is malformed: {error}"))
    })?;
    if pack.schema_version != PROVIDER_SCHEMA_VERSION {
        return Err(SearchError::InvalidProvider(format!(
            "provider pack '{source}' uses schema {}, expected {PROVIDER_SCHEMA_VERSION}",
            pack.schema_version
        )));
    }
    if pack.pack_version.trim().is_empty() || pack.pack_version.len() > 64 {
        return Err(SearchError::InvalidProvider(format!(
            "provider pack '{source}' has an invalid pack version"
        )));
    }
    validate_definitions(&pack.providers)?;
    Ok(pack)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchEntityKind {
    Username,
    EmailAddress,
    Domain,
    Hostname,
    IpAddress,
    Url,
    Account,
    Organization,
    NetworkEndpoint,
    Service,
    WebEndpoint,
    Certificate,
    SshHostKey,
    SoftwareIdentity,
    Technology,
    Asn,
    DnsRecord,
    Repository,
    // Ultimate OSINT expansion (additive).
    NetworkPrefix,
    Package,
    Document,
    ArchiveSnapshot,
    PublicKey,
    ExposureEvent,
    Provider,
    Route,
    IdentityHypothesis,
    Software,
}

impl SearchEntityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::EmailAddress => "email_address",
            Self::Domain => "domain",
            Self::Hostname => "hostname",
            Self::IpAddress => "ip_address",
            Self::Url => "url",
            Self::Account => "account",
            Self::Organization => "organization",
            Self::NetworkEndpoint => "network_endpoint",
            Self::Service => "service",
            Self::WebEndpoint => "web_endpoint",
            Self::Certificate => "certificate",
            Self::SshHostKey => "ssh_host_key",
            Self::SoftwareIdentity => "software_identity",
            Self::Technology => "technology",
            Self::Asn => "asn",
            Self::DnsRecord => "dns_record",
            Self::Repository => "repository",
            Self::NetworkPrefix => "network_prefix",
            Self::Package => "package",
            Self::Document => "document",
            Self::ArchiveSnapshot => "archive_snapshot",
            Self::PublicKey => "public_key",
            Self::ExposureEvent => "exposure_event",
            Self::Provider => "provider",
            Self::Route => "route",
            Self::IdentityHypothesis => "identity_hypothesis",
            Self::Software => "software",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchEntity {
    pub id: String,
    pub kind: SearchEntityKind,
    pub canonical_value: String,
    pub display_value: String,
    pub first_observed: u64,
    pub last_observed: u64,
    pub confidence: Option<u8>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

impl SearchEntity {
    pub fn username(value: &str, timestamp: u64) -> Result<Self, SearchError> {
        let display = value.trim();
        if display.is_empty() || display.len() > 128 || display.chars().any(char::is_control) {
            return Err(SearchError::InvalidEntity(
                "username must be 1..=128 printable characters".to_owned(),
            ));
        }
        let canonical = display.to_lowercase();
        Ok(Self {
            id: crate::assets::public_entity_id("username", &canonical),
            kind: SearchEntityKind::Username,
            canonical_value: canonical,
            display_value: display.to_owned(),
            first_observed: timestamp,
            last_observed: timestamp,
            confidence: None,
            attributes: BTreeMap::new(),
        })
    }

    /// Canonical email identity: `email:<lower>`.
    ///
    /// Additive Phase-1 constructor. Local part 1..=64, total 1..=254,
    /// single `@`, domain must satisfy [`canonical_domain_value`].
    pub fn email(value: &str, timestamp: u64) -> Result<Self, SearchError> {
        let display = value.trim();
        if display.is_empty() || display.len() > 254 || display.chars().any(char::is_control) {
            return Err(SearchError::InvalidEntity(
                "email must be 1..=254 printable characters".to_owned(),
            ));
        }
        let (local, domain) = display.split_once('@').ok_or_else(|| {
            SearchError::InvalidEntity("email must contain a single '@'".to_owned())
        })?;
        if local.is_empty() || local.len() > 64 || domain.is_empty() {
            return Err(SearchError::InvalidEntity(
                "email has an invalid local part or domain".to_owned(),
            ));
        }
        if local.contains(char::is_whitespace) || domain.contains(char::is_whitespace) {
            return Err(SearchError::InvalidEntity(
                "email must not contain whitespace".to_owned(),
            ));
        }
        if display.chars().filter(|c| *c == '@').count() != 1 {
            return Err(SearchError::InvalidEntity(
                "email must contain a single '@'".to_owned(),
            ));
        }
        let domain_canon = canonical_domain_value(domain).ok_or_else(|| {
            SearchError::InvalidEntity("email domain is not a valid domain".to_owned())
        })?;
        let canonical = format!("{}@{domain_canon}", local.to_ascii_lowercase());
        let mut attributes = BTreeMap::new();
        attributes.insert("local_part".to_owned(), local.to_owned());
        attributes.insert("domain".to_owned(), domain_canon);
        Ok(Self {
            id: crate::assets::public_entity_id("email_address", &canonical),
            kind: SearchEntityKind::EmailAddress,
            canonical_value: canonical,
            display_value: display.to_owned(),
            first_observed: timestamp,
            last_observed: timestamp,
            confidence: None,
            attributes,
        })
    }

    /// Canonical domain identity: `domain:<lower, no trailing dot>`.
    pub fn domain(value: &str, timestamp: u64) -> Result<Self, SearchError> {
        let canonical = canonical_domain_value(value)
            .ok_or_else(|| SearchError::InvalidEntity("invalid domain".to_owned()))?;
        Ok(Self {
            id: crate::assets::public_entity_id("domain", &canonical),
            kind: SearchEntityKind::Domain,
            canonical_value: canonical.clone(),
            display_value: value.trim().to_owned(),
            first_observed: timestamp,
            last_observed: timestamp,
            confidence: None,
            attributes: BTreeMap::from([("domain".to_owned(), canonical)]),
        })
    }

    /// Canonical hostname identity. Single-label names (e.g. `localhost`)
    /// are accepted here; bare IP literals are rejected (those are
    /// `IpAddress` entities, not hostnames).
    pub fn hostname(value: &str, timestamp: u64) -> Result<Self, SearchError> {
        let canonical = canonical_hostname_value(value)
            .ok_or_else(|| SearchError::InvalidEntity("invalid hostname".to_owned()))?;
        Ok(Self {
            id: crate::assets::public_entity_id("hostname", &canonical),
            kind: SearchEntityKind::Hostname,
            canonical_value: canonical.clone(),
            display_value: value.trim().to_owned(),
            first_observed: timestamp,
            last_observed: timestamp,
            confidence: None,
            attributes: BTreeMap::from([("hostname".to_owned(), canonical)]),
        })
    }

    /// Canonical IP identity (v4 or v6, normalized via [`std::net::IpAddr`]).
    pub fn ip_address(value: &str, timestamp: u64) -> Result<Self, SearchError> {
        let display = value.trim();
        let ip: std::net::IpAddr = display
            .parse()
            .map_err(|_| SearchError::InvalidEntity("invalid IP address".to_owned()))?;
        let canonical = ip.to_string().to_ascii_lowercase();
        Ok(Self {
            id: crate::assets::public_entity_id("ip_address", &canonical),
            kind: SearchEntityKind::IpAddress,
            canonical_value: canonical.clone(),
            display_value: display.to_owned(),
            first_observed: timestamp,
            last_observed: timestamp,
            confidence: None,
            attributes: BTreeMap::from([("address".to_owned(), canonical)]),
        })
    }

    /// Canonical ASN identity: `AS<number>` (1..=4294967295).
    ///
    /// Accepts `AS64500`, `as64500`, or bare `64500`.
    pub fn asn(value: &str, timestamp: u64) -> Result<Self, SearchError> {
        let canonical = canonical_asn_value(value).ok_or_else(|| {
            SearchError::InvalidEntity("invalid ASN (want AS<number>)".to_owned())
        })?;
        Ok(Self {
            id: crate::assets::public_entity_id("asn", &canonical),
            kind: SearchEntityKind::Asn,
            canonical_value: canonical.clone(),
            display_value: value.trim().to_owned(),
            first_observed: timestamp,
            last_observed: timestamp,
            confidence: None,
            attributes: BTreeMap::from([("asn".to_owned(), canonical)]),
        })
    }

    /// Canonical URL identity via the shared [`crate::graph::canonical_url`]
    /// normalization (scheme/host lowercased, default ports filled).
    pub fn url(value: &str, timestamp: u64) -> Result<Self, SearchError> {
        let display = value.trim();
        if display.is_empty() || display.len() > 2048 {
            return Err(SearchError::InvalidEntity(
                "url must be 1..=2048 characters".to_owned(),
            ));
        }
        let canonical = crate::graph::canonical_url(display).ok_or_else(|| {
            SearchError::InvalidEntity("invalid URL (need http/https with host)".to_owned())
        })?;
        Ok(Self {
            id: crate::assets::public_entity_id("url", &canonical.to_ascii_lowercase()),
            kind: SearchEntityKind::Url,
            canonical_value: canonical.to_ascii_lowercase(),
            display_value: display.to_owned(),
            first_observed: timestamp,
            last_observed: timestamp,
            confidence: None,
            attributes: BTreeMap::from([("url".to_owned(), canonical)]),
        })
    }

    /// Canonical repository identity: `owner/name` (lowercased).
    ///
    /// Accepts `owner/name` or an `https://` forge URL containing
    /// `owner/name`; nothing is cloned and no history is fetched.
    pub fn repository(value: &str, timestamp: u64) -> Result<Self, SearchError> {
        let (owner, name) = canonical_repo_parts(value).ok_or_else(|| {
            SearchError::InvalidEntity("invalid repository (want owner/name)".to_owned())
        })?;
        let canonical = format!("{owner}/{name}");
        Ok(Self {
            id: crate::assets::public_entity_id("repository", &canonical),
            kind: SearchEntityKind::Repository,
            canonical_value: canonical.clone(),
            display_value: value.trim().to_owned(),
            first_observed: timestamp,
            last_observed: timestamp,
            confidence: None,
            attributes: BTreeMap::from([
                ("owner".to_owned(), owner),
                ("name".to_owned(), name),
                ("repository".to_owned(), canonical),
            ]),
        })
    }

    /// Canonical organization identity (forge owner / org name).
    pub fn organization(value: &str, timestamp: u64) -> Result<Self, SearchError> {
        let canonical = canonical_org_value(value)
            .ok_or_else(|| SearchError::InvalidEntity("invalid organization name".to_owned()))?;
        Ok(Self {
            id: crate::assets::public_entity_id("organization", &canonical),
            kind: SearchEntityKind::Organization,
            canonical_value: canonical.clone(),
            display_value: value.trim().to_owned(),
            first_observed: timestamp,
            last_observed: timestamp,
            confidence: None,
            attributes: BTreeMap::from([("name".to_owned(), canonical)]),
        })
    }

    /// Canonical network-prefix identity (`192.0.2.0/24`, `2001:db8::/32`).
    /// Validated via `ipnet`; host bits must be zero (no `192.0.2.1/24`).
    pub fn network_prefix(value: &str, timestamp: u64) -> Result<Self, SearchError> {
        let prefix: ipnet::IpNet = value
            .trim()
            .parse()
            .map_err(|_| SearchError::InvalidEntity("invalid network prefix".to_owned()))?;
        // Require canonical form: host bits zero, otherwise callers could
        // create duplicate identities for the same prefix.
        let canonical = prefix.to_string().to_ascii_lowercase();
        let reparsed: ipnet::IpNet = canonical
            .parse()
            .map_err(|_| SearchError::InvalidEntity("invalid network prefix".to_owned()))?;
        if reparsed != prefix || !canonical.contains('/') {
            return Err(SearchError::InvalidEntity(
                "invalid network prefix".to_owned(),
            ));
        }
        // `ipnet` normalizes host bits; reject non-canonical input by
        // comparing against the trimmed lowercased input.
        if value.trim().to_ascii_lowercase() != canonical {
            return Err(SearchError::InvalidEntity(
                "prefix must be canonical (host bits zero)".to_owned(),
            ));
        }
        Ok(Self {
            id: crate::assets::public_entity_id("network_prefix", &canonical),
            kind: SearchEntityKind::NetworkPrefix,
            canonical_value: canonical.clone(),
            display_value: value.trim().to_owned(),
            first_observed: timestamp,
            last_observed: timestamp,
            confidence: None,
            attributes: BTreeMap::from([("prefix".to_owned(), canonical)]),
        })
    }

    /// Canonical package identity (`name`, lowercased, bounded charset).
    pub fn package(value: &str, timestamp: u64) -> Result<Self, SearchError> {
        let canonical = value.trim().to_ascii_lowercase();
        if canonical.is_empty()
            || canonical.len() > 128
            || canonical
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
            || !canonical
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        {
            return Err(SearchError::InvalidEntity(
                "invalid package name".to_owned(),
            ));
        }
        Ok(Self {
            id: crate::assets::public_entity_id("package", &canonical),
            kind: SearchEntityKind::Package,
            canonical_value: canonical.clone(),
            display_value: value.trim().to_owned(),
            first_observed: timestamp,
            last_observed: timestamp,
            confidence: None,
            attributes: BTreeMap::from([("package".to_owned(), canonical)]),
        })
    }

    /// Generic canonical constructor for document / provider / route /
    /// hypothesis / software kinds where identity is an opaque bounded
    /// token (hash, name, or `a+b` subject list). Validation is
    /// conservative: non-empty, bounded, no control characters.
    pub fn opaque(
        kind: SearchEntityKind,
        value: &str,
        timestamp: u64,
    ) -> Result<Self, SearchError> {
        match kind {
            SearchEntityKind::Document
            | SearchEntityKind::ArchiveSnapshot
            | SearchEntityKind::PublicKey
            | SearchEntityKind::ExposureEvent
            | SearchEntityKind::Provider
            | SearchEntityKind::Route
            | SearchEntityKind::IdentityHypothesis
            | SearchEntityKind::Software => {}
            _ => {
                return Err(SearchError::InvalidEntity(
                    "opaque constructor only for extended kinds".to_owned(),
                ));
            }
        }
        let display = value.trim();
        if display.is_empty() || display.len() > 512 || display.chars().any(char::is_control) {
            return Err(SearchError::InvalidEntity(
                "extended entity value must be 1..=512 printable characters".to_owned(),
            ));
        }
        let canonical = display.to_ascii_lowercase();
        Ok(Self {
            id: crate::assets::public_entity_id(kind.as_str(), &canonical),
            kind,
            canonical_value: canonical,
            display_value: display.to_owned(),
            first_observed: timestamp,
            last_observed: timestamp,
            confidence: None,
            attributes: BTreeMap::new(),
        })
    }
}

/// Shared domain normalization for passive entity constructors.
///
/// Lowercase, no trailing dot, 1..=253 chars, at least one dot, valid
/// labels (1..=63, alnum/hyphen, no leading/trailing hyphen). IP literals
/// are rejected (those are `IpAddress` entities).
pub fn canonical_domain_value(raw: &str) -> Option<String> {
    let domain = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
        return None;
    }
    if domain.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    if domain.parse::<std::net::IpAddr>().is_ok() {
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
    valid.then_some(domain)
}

/// Hostname normalization: like [`canonical_domain_value`] but single-label
/// names are accepted (e.g. `localhost` in fixtures). IP literals rejected.
pub fn canonical_hostname_value(raw: &str) -> Option<String> {
    let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    if host.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let valid = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    });
    valid.then_some(host)
}

/// Canonical `AS<number>` value (uppercase prefix).
pub fn canonical_asn_value(raw: &str) -> Option<String> {
    let text = raw.trim();
    if text.is_empty() || text.len() > 12 {
        return None;
    }
    let digits = text
        .strip_prefix("AS")
        .or_else(|| text.strip_prefix("as"))
        .or_else(|| text.strip_prefix("As"))
        .or_else(|| text.strip_prefix("aS"))
        .unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // No leading-zero games change identity, but `AS0` is reserved.
    let number: u32 = digits.parse().ok()?;
    if number == 0 {
        return None;
    }
    Some(format!("AS{number}"))
}

fn repo_part_valid(part: &str) -> bool {
    !part.is_empty()
        && part.len() <= 64
        && part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        && part.bytes().any(|b| b.is_ascii_alphanumeric())
}

fn canonical_repo_parts(raw: &str) -> Option<(String, String)> {
    let text = raw.trim();
    if text.is_empty() || text.len() > 256 || text.chars().any(char::is_control) {
        return None;
    }
    // Forge URL form: extract the first two path segments.
    if text.contains("://") {
        let url = url::Url::parse(text).ok()?;
        if url.scheme() != "http" && url.scheme() != "https" {
            return None;
        }
        let mut segments = url.path_segments()?.filter(|s| !s.is_empty());
        let owner = segments.next()?.trim().to_ascii_lowercase();
        let mut name = segments.next()?.trim().to_ascii_lowercase();
        // Strip a trailing `.git` for identity stability.
        if let Some(stripped) = name.strip_suffix(".git") {
            if !stripped.is_empty() {
                name = stripped.to_owned();
            }
        }
        if !repo_part_valid(&owner) || !repo_part_valid(&name) {
            return None;
        }
        return Some((owner, name));
    }
    let (owner_raw, name_raw) = text.split_once('/')?;
    // Exactly one slash: `a/b/c` is rejected.
    if name_raw.contains('/') {
        return None;
    }
    let owner = owner_raw.trim().to_ascii_lowercase();
    let mut name = name_raw.trim().to_ascii_lowercase();
    if let Some(stripped) = name.strip_suffix(".git") {
        if !stripped.is_empty() {
            name = stripped.to_owned();
        }
    }
    if !repo_part_valid(&owner) || !repo_part_valid(&name) {
        return None;
    }
    Some((owner, name))
}

/// Organization / owner name normalization.
pub fn canonical_org_value(raw: &str) -> Option<String> {
    let name = raw.trim().to_ascii_lowercase();
    if name.is_empty() || name.len() > 64 || name.contains('/') {
        return None;
    }
    if name.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return None;
    }
    if !name.bytes().any(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    Some(name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactClass {
    PassivePublic,
    PublicHttp,
    DnsQuery,
    DirectNetwork,
    AuthenticatedApi,
    LocalDataset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchStatus {
    Confirmed,
    Probable,
    Possible,
    NotFound,
    Unknown,
    RateLimited,
    Blocked,
    AuthenticationRequired,
    Error,
    Cancelled,
    Unscanned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderMetadata {
    pub id: String,
    pub version: String,
    pub accepts: Vec<SearchEntityKind>,
    pub produces: Vec<SearchEntityKind>,
    pub contact_class: ContactClass,
    pub timeout_ms: u64,
    pub requests_per_minute: u16,
    pub weight: u16,
    pub source_category: String,
    pub requires_authentication: bool,
}

pub trait SearchProvider: Send + Sync {
    fn metadata(&self) -> &ProviderMetadata;
    fn accepts(&self, entity: &SearchEntity) -> bool {
        self.metadata().accepts.contains(&entity.kind)
    }
    fn host_key(&self) -> String {
        self.metadata().id.clone()
    }
    fn search(
        &self,
        context: &SearchContext,
        entity: &SearchEntity,
    ) -> Result<SearchObservation, SearchError>;
}

#[derive(Debug, Clone, Copy)]
pub struct SearchContext<'a> {
    pub deadline: Instant,
    pub cancelled: &'a AtomicBool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchObservation {
    pub provider_id: String,
    pub provider_version: String,
    pub task_id: String,
    pub input_entity_id: String,
    pub contact_class: ContactClass,
    pub status: SearchStatus,
    pub confidence: u8,
    pub timestamp: u64,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

pub fn task_id(provider: &ProviderMetadata, entity: &SearchEntity) -> String {
    crate::assets::public_entity_id(
        "search_task",
        &format!("{}:{}:search", provider.id, entity.id),
    )
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarkerPolicy {
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub any: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsernameProviderDefinition {
    pub metadata: ProviderMetadata,
    pub platform: String,
    pub category: String,
    pub profile_url: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub success_status: Vec<u16>,
    #[serde(default)]
    pub not_found_status: Vec<u16>,
    #[serde(default)]
    pub success: MarkerPolicy,
    #[serde(default)]
    pub not_found: MarkerPolicy,
    #[serde(default)]
    pub blocked_markers: Vec<String>,
    #[serde(default)]
    pub authentication_url_markers: Vec<String>,
    #[serde(default = "default_redirects")]
    pub max_redirects: u8,
    #[serde(default = "default_body_limit")]
    pub max_body_bytes: usize,
    #[serde(default = "default_health_state")]
    pub health_state: HealthState,
    /// Declarative username validity constraints. `None` means no
    /// provider-specific constraints: the username is queried rather than
    /// skipped. Rules stay conservative; an uncertain provider leaves this
    /// unset instead of risking a false skip.
    #[serde(default)]
    pub username_rules: Option<UsernameRules>,
    /// Final-URL substrings that deterministically mean "no such public
    /// account" for this provider (e.g. a login-wall the provider routes
    /// unknown usernames to). Checked before authentication-redirect
    /// handling. Must only be set when verified live; an entry here that
    /// also fires for genuine auth walls would hide existing accounts.
    #[serde(default)]
    pub absence_redirect_markers: Vec<String>,
    /// Date (`YYYY-MM-DD`) of the last successful live verification.
    /// Required when `health_state` is `live_verified`; never set it
    /// without actually checking live behavior.
    #[serde(default)]
    pub verified_at: Option<String>,
    /// How live verification was performed (e.g. `live-probe`). No test
    /// usernames, machine names, or operator data belong here.
    #[serde(default)]
    pub verification_method: Option<String>,
    /// Maintainer notes: basis for markers/rules, known quirks, why a
    /// provider is `needs_review` or `disabled`. Public-safe text only.
    #[serde(default)]
    pub source_notes: Option<String>,
}

/// Declarative per-provider username validity constraints.
///
/// Before any request is made, a username that cannot be valid on a
/// provider skips that provider with an explicit reason instead of
/// generating a doomed request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsernameRules {
    #[serde(default = "default_username_min_length")]
    pub min_length: u8,
    #[serde(default = "default_username_max_length")]
    pub max_length: u16,
    #[serde(default)]
    pub charset: UsernameCharset,
}

/// Character classes a provider username may use.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsernameCharset {
    /// No character restriction beyond printable, non-control text.
    #[default]
    Any,
    /// ASCII letters, digits, hyphen, underscore, and dot.
    AlnumDotHyphenUnderscore,
    /// ASCII letters, digits, and hyphen.
    AlnumHyphen,
    /// ASCII letters, digits, and underscore.
    AlnumUnderscore,
}

impl UsernameRules {
    /// Conservative default: accept anything [`SearchEntity::username`]
    /// accepts. Providers opt into tighter rules only where justified.
    pub fn permissive() -> Self {
        Self {
            min_length: 1,
            max_length: 128,
            charset: UsernameCharset::Any,
        }
    }

    /// Returns `Ok(())` when the username may be valid, or `Err(reason)`
    /// with an explicit skip reason when it cannot be valid.
    pub fn check(&self, username: &str) -> Result<(), String> {
        let length = username.chars().count();
        if length < usize::from(self.min_length) {
            return Err(format!(
                "username is shorter than the provider minimum of {}",
                self.min_length
            ));
        }
        if length > usize::from(self.max_length) {
            return Err(format!(
                "username exceeds the provider maximum of {}",
                self.max_length
            ));
        }
        let charset_ok = match self.charset {
            UsernameCharset::Any => true,
            UsernameCharset::AlnumDotHyphenUnderscore => username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.'),
            UsernameCharset::AlnumHyphen => username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            UsernameCharset::AlnumUnderscore => username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        };
        if !charset_ok {
            return Err("username uses characters the provider does not allow".to_owned());
        }
        Ok(())
    }
}

/// Explicit skip reason for a provider/username pair, or `None` when the
/// provider should be queried. Disabled providers are never queried.
pub fn username_skip_reason(
    definition: &UsernameProviderDefinition,
    username: &str,
) -> Option<String> {
    if definition.health_state == HealthState::Disabled {
        return Some("provider is disabled".to_owned());
    }
    match &definition.username_rules {
        Some(rules) => rules.check(username).err(),
        None => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    FixtureVerified,
    LiveVerified,
    NeedsReview,
    Disabled,
}

impl HealthState {
    pub fn as_str(&self) -> &'static str {
        match self {
            HealthState::FixtureVerified => "fixture_verified",
            HealthState::LiveVerified => "live_verified",
            HealthState::NeedsReview => "needs_review",
            HealthState::Disabled => "disabled",
        }
    }
}

fn default_health_state() -> HealthState {
    HealthState::FixtureVerified
}

fn default_username_min_length() -> u8 {
    1
}

fn default_username_max_length() -> u16 {
    128
}

fn default_method() -> String {
    "GET".to_owned()
}
fn default_redirects() -> u8 {
    2
}
fn default_body_limit() -> usize {
    64 * 1024
}

impl UsernameProviderDefinition {
    pub fn validate(&self) -> Result<(), SearchError> {
        let id = self.metadata.id.as_str();
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(SearchError::InvalidProvider(format!(
                "provider id '{id}' must use lowercase ASCII letters, digits, or hyphens"
            )));
        }
        if !self.metadata.accepts.contains(&SearchEntityKind::Username)
            || !self.metadata.produces.contains(&SearchEntityKind::Account)
        {
            return Err(SearchError::InvalidProvider(format!(
                "provider '{id}' must transform username to account"
            )));
        }
        if self.metadata.contact_class != ContactClass::PublicHttp {
            return Err(SearchError::InvalidProvider(format!(
                "provider '{id}' username definitions must use public_http"
            )));
        }
        if !USERNAME_PROVIDER_CATEGORIES.contains(&self.category.as_str()) {
            return Err(SearchError::InvalidProvider(format!(
                "provider '{id}' has unsupported category '{}'",
                self.category
            )));
        }
        if !self.profile_url.starts_with("https://") || !self.profile_url.contains("{username}") {
            return Err(SearchError::InvalidProvider(format!(
                "provider '{id}' requires an HTTPS profile_url containing {{username}}"
            )));
        }
        let validation_url = url::Url::parse(&self.profile_url.replace("{username}", "rx"))
            .map_err(|error| {
                SearchError::InvalidProvider(format!(
                    "provider '{id}' has an invalid profile URL: {error}"
                ))
            })?;
        validate_definition_url(&validation_url)
            .map_err(|error| SearchError::InvalidProvider(format!("provider '{id}': {error}")))?;
        if self.method != "GET" {
            return Err(SearchError::InvalidProvider(format!(
                "provider '{id}' method must be GET"
            )));
        }
        if self.max_redirects > 5
            || self.max_body_bytes == 0
            || self.max_body_bytes > MAX_SEARCH_BODY_BYTES
        {
            return Err(SearchError::InvalidProvider(format!(
                "provider '{id}' exceeds redirect/body limits"
            )));
        }
        if self.metadata.timeout_ms == 0
            || self.metadata.timeout_ms > 30_000
            || self.metadata.requests_per_minute == 0
        {
            return Err(SearchError::InvalidProvider(format!(
                "provider '{id}' has invalid timeout or rate limit"
            )));
        }
        if self.success.required.is_empty() {
            return Err(SearchError::InvalidProvider(format!(
                "provider '{id}' requires a strong success marker; HTTP status alone is insufficient"
            )));
        }
        if let Some(rules) = &self.username_rules {
            if rules.min_length == 0
                || usize::from(rules.min_length) > usize::from(rules.max_length)
                || usize::from(rules.max_length) > 128
            {
                return Err(SearchError::InvalidProvider(format!(
                    "provider '{id}' has impossible username rules"
                )));
            }
        }
        if self.health_state == HealthState::LiveVerified
            && self
                .verified_at
                .as_ref()
                .is_none_or(|date| date.trim().is_empty())
        {
            return Err(SearchError::InvalidProvider(format!(
                "provider '{id}' claims live_verified without verification metadata"
            )));
        }
        // Verification metadata must be minimal, well-formed, and consistent:
        // dates are YYYY-MM-DD, a method never appears without a date, and a
        // date never appears on a non-live provider.
        if let Some(date) = self.verified_at.as_deref() {
            if !is_verification_date(date) {
                return Err(SearchError::InvalidProvider(format!(
                    "provider '{id}' has invalid verification date {date:?}"
                )));
            }
            if self.health_state != HealthState::LiveVerified {
                return Err(SearchError::InvalidProvider(format!(
                    "provider '{id}' carries verification metadata without live_verified health"
                )));
            }
        }
        if self.verification_method.is_some() && self.verified_at.is_none() {
            return Err(SearchError::InvalidProvider(format!(
                "provider '{id}' carries a verification method without a verification date"
            )));
        }
        // A live_verified claim must not be contradicted by its own notes.
        // Provisional/awaiting-verification language means the provider was
        // never actually verified and must stay in needs_review.
        if self.health_state == HealthState::LiveVerified
            && verification_notes_contradict_live(self.source_notes.as_deref())
        {
            return Err(SearchError::InvalidProvider(format!(
                "provider '{id}' claims live_verified with provisional/unverified source notes"
            )));
        }
        if let Some(method) = self.verification_method.as_deref() {
            if method.trim().is_empty() || method.len() > 64 {
                return Err(SearchError::InvalidProvider(format!(
                    "provider '{id}' has invalid verification metadata"
                )));
            }
        }
        // Top-level category and metadata source_category must agree; drift
        // here means a miscategorized provider or a bad merge.
        if self.metadata.source_category != self.category {
            return Err(SearchError::InvalidProvider(format!(
                "provider '{id}' has inconsistent categories '{}' vs '{}'",
                self.metadata.source_category, self.category
            )));
        }
        if self.platform.trim().is_empty() || self.platform.len() > 64 {
            return Err(SearchError::InvalidProvider(format!(
                "provider '{id}' has an invalid display name"
            )));
        }
        // Body/redirect budgets stay bounded: zero, unbounded, or over-global
        // values are rejected rather than silently clamped.
        if self.max_body_bytes == 0 || self.max_body_bytes > MAX_SEARCH_BODY_BYTES {
            return Err(SearchError::InvalidProvider(format!(
                "provider '{id}' has an unbounded body budget"
            )));
        }
        if self.max_redirects > 5 {
            return Err(SearchError::InvalidProvider(format!(
                "provider '{id}' has an unbounded redirect policy"
            )));
        }
        Ok(())
    }

    pub fn classify(&self, response: &ProviderResponse, username: &str) -> SearchClassification {
        if response.status == 429 {
            return SearchClassification::new(SearchStatus::RateLimited, 0, "HTTP 429");
        }
        if response.status == 401 {
            return SearchClassification::new(
                SearchStatus::AuthenticationRequired,
                0,
                "provider requires authentication",
            );
        }
        if response.status == 403 {
            return SearchClassification::new(SearchStatus::Blocked, 0, "provider denied access");
        }
        let body = response.body.to_lowercase();
        if self
            .blocked_markers
            .iter()
            .any(|m| body.contains(&m.to_lowercase()))
        {
            return SearchClassification::new(
                SearchStatus::Blocked,
                0,
                "provider block marker matched",
            );
        }
        if self.not_found_status.contains(&response.status)
            || marker_matches(&body, &self.not_found, username)
        {
            return SearchClassification::new(
                SearchStatus::NotFound,
                0,
                "provider not-found evidence matched",
            );
        }
        if !self.success_status.contains(&response.status) {
            return SearchClassification::new(
                SearchStatus::Unknown,
                0,
                "HTTP status is not classified",
            );
        }
        let required = marker_matches_required(&body, &self.success.required, username);
        let optional = self
            .success
            .any
            .iter()
            .any(|m| marker(&m.to_lowercase(), username, &body));
        if required {
            let mut evidence = vec!["all required profile markers matched".to_owned()];
            if optional {
                evidence.push("additional profile marker matched".to_owned());
            }
            SearchClassification {
                status: SearchStatus::Confirmed,
                confidence: if optional { 94 } else { 88 },
                evidence,
            }
        } else {
            SearchClassification::new(
                SearchStatus::Possible,
                25,
                "HTTP success without required identity evidence",
            )
        }
    }
}

pub struct DefinitionProvider {
    definition: UsernameProviderDefinition,
    client: Arc<SharedHttpClient>,
}

impl DefinitionProvider {
    pub fn new(
        definition: UsernameProviderDefinition,
        client: Arc<SharedHttpClient>,
    ) -> Result<Self, SearchError> {
        definition.validate()?;
        Ok(Self { definition, client })
    }
}

impl SearchProvider for DefinitionProvider {
    fn metadata(&self) -> &ProviderMetadata {
        &self.definition.metadata
    }

    fn accepts(&self, entity: &SearchEntity) -> bool {
        if !self.definition.metadata.accepts.contains(&entity.kind) {
            return false;
        }
        // Disabled providers and usernames that cannot be valid on this
        // provider are skipped (counted, never queried).
        username_skip_reason(&self.definition, &entity.display_value).is_none()
    }

    fn host_key(&self) -> String {
        url::Url::parse(&self.definition.profile_url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
            .unwrap_or_else(|| self.definition.metadata.id.clone())
    }

    fn search(
        &self,
        context: &SearchContext<'_>,
        entity: &SearchEntity,
    ) -> Result<SearchObservation, SearchError> {
        if entity.kind != SearchEntityKind::Username {
            return Err(SearchError::InvalidEntity(format!(
                "provider '{}' requires a username",
                self.definition.metadata.id
            )));
        }
        let url = provider_url(
            &self.definition,
            &entity.display_value,
            self.client.allow_nonpublic,
        )?;
        let response = self.client.get(
            &url,
            std::time::Duration::from_millis(self.definition.metadata.timeout_ms),
            self.definition.max_body_bytes,
            self.definition.max_redirects,
            context,
        )?;
        let body_hash = {
            use sha2::Digest as _;
            format!("{:x}", sha2::Sha256::digest(&response.body))
        };
        let mut attributes = BTreeMap::from([
            ("platform".to_owned(), self.definition.platform.clone()),
            ("category".to_owned(), self.definition.category.clone()),
            (
                "category_label".to_owned(),
                category_label(&self.definition.category).to_owned(),
            ),
            ("username".to_owned(), entity.display_value.clone()),
            ("profile_url".to_owned(), url.to_string()),
            ("final_url".to_owned(), response.final_url.clone()),
            (
                "provider_health".to_owned(),
                self.definition.health_state.as_str().to_owned(),
            ),
            (
                "provider_state".to_owned(),
                provider_state(&self.definition).to_owned(),
            ),
            ("body_sha256".to_owned(), body_hash),
            ("http_status".to_owned(), response.status.to_string()),
            (
                "redirect_count".to_owned(),
                response.redirect_count.to_string(),
            ),
            ("elapsed_ms".to_owned(), response.elapsed_ms.to_string()),
        ]);
        let final_url = response.final_url.to_ascii_lowercase();
        let classification = if response.body_truncated {
            SearchClassification::new(
                SearchStatus::Unknown,
                0,
                "response exceeded configured body limit",
            )
        } else if self
            .definition
            .absence_redirect_markers
            .iter()
            .any(|marker| final_url.contains(&marker.to_ascii_lowercase()))
        {
            // Verified provider-specific behavior: unknown usernames land
            // on this destination instead of a usable profile page.
            SearchClassification::new(
                SearchStatus::NotFound,
                0,
                "provider redirected to a known absence destination",
            )
        } else if self
            .definition
            .authentication_url_markers
            .iter()
            .any(|marker| final_url.contains(&marker.to_ascii_lowercase()))
        {
            SearchClassification::new(
                SearchStatus::AuthenticationRequired,
                0,
                "provider redirected to an authentication page",
            )
        } else {
            self.definition.classify(
                &ProviderResponse {
                    status: response.status,
                    body: String::from_utf8_lossy(&response.body).into_owned(),
                },
                &entity.display_value,
            )
        };
        if let Some(retry_after) = response.headers.get("retry-after") {
            attributes.insert("retry_after".to_owned(), retry_after.clone());
        }
        Ok(SearchObservation {
            provider_id: self.definition.metadata.id.clone(),
            provider_version: self.definition.metadata.version.clone(),
            task_id: task_id(&self.definition.metadata, entity),
            input_entity_id: entity.id.clone(),
            contact_class: ContactClass::PublicHttp,
            status: classification.status,
            confidence: classification.confidence.min(95),
            timestamp: entity.last_observed,
            evidence: classification
                .evidence
                .into_iter()
                .take(MAX_SEARCH_EVIDENCE)
                .collect(),
            attributes,
        })
    }
}

fn marker_matches(body: &str, policy: &MarkerPolicy, username: &str) -> bool {
    marker_matches_required(body, &policy.required, username)
        || policy
            .any
            .iter()
            .any(|m| marker(&m.to_lowercase(), username, body))
}

fn marker_matches_required(body: &str, markers: &[String], username: &str) -> bool {
    !markers.is_empty()
        && markers
            .iter()
            .all(|m| marker(&m.to_lowercase(), username, body))
}

fn marker(pattern: &str, username: &str, body: &str) -> bool {
    body.contains(&pattern.replace("{username}", &username.to_lowercase()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderResponse {
    pub status: u16,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchClassification {
    pub status: SearchStatus,
    pub confidence: u8,
    pub evidence: Vec<String>,
}

impl SearchClassification {
    fn new(status: SearchStatus, confidence: u8, evidence: &str) -> Self {
        Self {
            status,
            confidence,
            evidence: vec![evidence.to_owned()],
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchAccounting {
    pub providers_requested: usize,
    pub providers_completed: usize,
    pub skipped: usize,
    pub cancelled: usize,
    pub unscanned: usize,
    pub counts: BTreeMap<SearchStatus, usize>,
    pub truncated: bool,
}

impl SearchAccounting {
    pub fn accounted(&self) -> usize {
        self.providers_completed + self.skipped + self.cancelled + self.unscanned
    }

    /// Work still outstanding: scheduled but neither completed nor skipped.
    /// Progress denominators elsewhere MUST use scheduled (`requested`) and
    /// this remainder — never the registry size.
    pub fn remaining(&self) -> usize {
        self.cancelled + self.unscanned
    }

    /// Scheduled work for this run. `providers_requested` IS the scheduled
    /// set: planning already applied category/provider selection, so the
    /// denominator is real scheduled vectors, never the registry total.
    pub fn scheduled(&self) -> usize {
        self.providers_requested
    }
}

/// Simple rate limiter that honors `requests_per_minute` per provider.
/// The limiter is scoped to a single search run; state is not persisted.
struct RateLimiter {
    /// Maps provider id to the instant of its last request
    last_request: BTreeMap<String, Instant>,
    /// Minimum interval between requests for any provider (ms)
    interval_ms: u64,
}

impl RateLimiter {
    fn new(requests_per_minute: u16) -> Self {
        let interval_ms = if requests_per_minute > 0 {
            60_000u64.saturating_div(requests_per_minute.into())
        } else {
            0
        };
        Self {
            last_request: BTreeMap::new(),
            interval_ms,
        }
    }

    /// Check if a provider can execute a request respecting its rate limit.
    /// Returns true if the provider can execute now (no side effects).
    /// Does NOT increment request count, reset last-request time, or consume a permit
    /// unless it actually grants a permit.
    fn can_execute(&self, provider_id: &str) -> bool {
        let Some(&last) = self.last_request.get(provider_id) else {
            return true; // first request from this provider, always allowed
        };
        last.elapsed().as_millis() as u64 >= self.interval_ms
    }

    /// Record a completed request for rate-limit accounting.
    /// Should be called after a successful request execution.
    fn record_request(&mut self, provider_id: &str) {
        self.last_request
            .entry(provider_id.to_owned())
            .or_insert(Instant::now());
    }
}

/// Bounded execution over an unbounded registry.
///
/// The scheduler admits up to `max_providers` vectors and runs at most
/// `max_concurrency` at once: 2,391 scheduled vectors with 4 concurrent
/// means ~598 sequential waves, NOT 2,391 simultaneous requests. Registry
/// growth never changes the concurrency profile; raise the registry, keep
/// the waves bounded. Admission is O(scheduled); per-wave thread count is
/// O(concurrency), independent of registry size.
#[allow(private_interfaces)]
pub struct SearchScheduler {
    pub max_providers: usize,
    pub max_concurrency: usize,
    pub max_per_host: usize,
    pub deadline: Instant,
    pub(crate) rate_limiter: RateLimiter,
}

impl SearchScheduler {
    /// Bounded execution over any registry size: `max_providers` caps
    /// admission, `max_concurrency` caps simultaneous requests. A 2,500
    /// registry with concurrency 20 runs ~125 sequential waves — registry
    /// growth never widens the concurrency profile.
    pub fn new(
        max_providers: usize,
        max_concurrency: usize,
        max_per_host: usize,
        deadline: Instant,
    ) -> Self {
        Self {
            max_providers,
            max_concurrency,
            max_per_host,
            deadline,
            rate_limiter: RateLimiter::new(0),
        }
    }

    pub fn run(
        &mut self,
        providers: &[Box<dyn SearchProvider>],
        entity: &SearchEntity,
        cancelled: &AtomicBool,
    ) -> (Vec<SearchObservation>, SearchAccounting) {
        self.run_with_progress(providers, entity, cancelled, &|_, _| {})
    }

    /// Scheduler with a real progress hook `(completed, total)`.
    ///
    /// The hook fires after each wave with honest counts (completed providers
    /// vs requested). Frontends use it for restrained TTY progress or SSE;
    /// the hook never affects scheduling, evidence, or accounting.
    pub fn run_with_progress(
        &mut self,
        providers: &[Box<dyn SearchProvider>],
        entity: &SearchEntity,
        cancelled: &AtomicBool,
        progress: &dyn Fn(usize, usize),
    ) -> (Vec<SearchObservation>, SearchAccounting) {
        let mut accounting = SearchAccounting {
            providers_requested: providers.len(),
            ..SearchAccounting::default()
        };
        let mut observations = Vec::new();
        let admitted = providers.len().min(self.max_providers);
        accounting.unscanned = providers.len() - admitted;
        accounting.truncated = accounting.unscanned > 0;
        let context = SearchContext {
            deadline: self.deadline,
            cancelled,
        };
        let mut pending: Vec<usize> = (0..admitted).collect();
        while !pending.is_empty() {
            if cancelled.load(Ordering::Acquire) {
                accounting.cancelled += pending.len();
                break;
            }
            if Instant::now() >= self.deadline {
                accounting.unscanned += pending.len();
                accounting.truncated = true;
                break;
            }
            let mut hosts = BTreeMap::<String, usize>::new();
            let mut wave = Vec::new();
            let mut deferred = Vec::new();
            for index in pending {
                let provider = &providers[index];
                if !provider.accepts(entity) {
                    accounting.skipped += 1;
                    continue;
                }
                // Rate limit check: defer instead of skip
                if !self.rate_limiter.can_execute(&provider.host_key()) {
                    deferred.push(index);
                    continue;
                }
                let host = provider.host_key();
                let count = hosts.entry(host).or_default();
                if wave.len() < self.max_concurrency.max(1) && *count < self.max_per_host.max(1) {
                    *count += 1;
                    wave.push(index);
                } else {
                    deferred.push(index);
                }
            }
            let completed = std::thread::scope(|scope| {
                let handles: Vec<_> = wave
                    .into_iter()
                    .map(|index| {
                        let provider = &providers[index];
                        (
                            index,
                            scope.spawn(move || provider.search(&context, entity)),
                        )
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|(index, handle)| (index, handle.join()))
                    .collect::<Vec<_>>()
            });
            for (index, completed) in completed {
                let result = match completed {
                    Ok(result) => result,
                    Err(_) => Err(SearchError::Provider(
                        "provider panicked during execution".to_owned(),
                    )),
                };
                let provider = &providers[index];
                let observation = match result {
                    Ok(value) => value,
                    Err(SearchError::Cancelled) => {
                        accounting.cancelled += 1;
                        continue;
                    }
                    Err(SearchError::Deadline) => {
                        accounting.unscanned += 1;
                        accounting.truncated = true;
                        continue;
                    }
                    Err(error) => SearchObservation {
                        provider_id: provider.metadata().id.clone(),
                        provider_version: provider.metadata().version.clone(),
                        task_id: task_id(provider.metadata(), entity),
                        input_entity_id: entity.id.clone(),
                        contact_class: provider.metadata().contact_class,
                        status: SearchStatus::Error,
                        confidence: 0,
                        timestamp: entity.last_observed,
                        evidence: vec![error.to_string()],
                        attributes: BTreeMap::new(),
                    },
                };
                accounting.providers_completed += 1;
                *accounting.counts.entry(observation.status).or_default() += 1;
                observations.push(observation);
                // Record rate limit request after successful/completed execution
                self.rate_limiter.record_request(&provider.host_key());
            }
            pending = deferred;
            // Real progress: completed vs requested after each wave.
            progress(
                accounting.providers_completed,
                accounting.providers_requested,
            );
        }
        observations.sort_by(|a, b| {
            a.provider_id
                .cmp(&b.provider_id)
                .then(a.input_entity_id.cmp(&b.input_entity_id))
        });
        debug_assert_eq!(accounting.providers_requested, accounting.accounted());
        (observations, accounting)
    }
}

#[derive(Debug, Error)]
pub enum SearchError {
    #[error("invalid search entity: {0}")]
    InvalidEntity(String),
    #[error("invalid search provider: {0}")]
    InvalidProvider(String),
    #[error("search provider failed: {0}")]
    Provider(String),
    #[error("search HTTP error: {0}")]
    Http(String),
    #[error("unsafe provider URL: {0}")]
    UnsafeUrl(String),
    #[error("search deadline expired")]
    Deadline,
    #[error("search cancelled")]
    Cancelled,
    #[error("redirect limit exceeded")]
    RedirectLimitExceeded,
    #[error("unsupported redirect scheme")]
    UnsupportedRedirectScheme(String),
    #[error("malformed redirect: {0}")]
    MalformedRedirect(String),
    #[error("unsafe redirect destination: {0}")]
    UnsafeRedirectDestination(String),
    #[error(transparent)]
    ProjectDb(#[from] crate::project_db::ProjectDbError),
}

pub fn validate_definitions(definitions: &[UsernameProviderDefinition]) -> Result<(), SearchError> {
    // No count limit: the registry is designed for thousands of vectors.
    // Safety comes from the pack byte cap plus per-definition validation.
    let mut ids = BTreeSet::new();
    for definition in definitions {
        definition.validate()?;
        if !ids.insert(definition.metadata.id.as_str()) {
            return Err(SearchError::InvalidProvider(format!(
                "duplicate provider id '{}'",
                definition.metadata.id
            )));
        }
    }
    Ok(())
}

/// Convert days since the Unix epoch to a civil (year, month, day) date.
/// Integer-only Howard Hinnant algorithm; no calendar dependency needed.
pub fn days_to_civil(days: i64) -> (i32, u32, u32) {
    let shifted = days + 719468;
    let era = shifted.div_euclid(146097);
    let day_of_era = shifted.rem_euclid(146097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;
    (
        (if month <= 2 { year + 1 } else { year }) as i32,
        month,
        day,
    )
}

/// Cutoff date string (`YYYY-MM-DD`) `days` before today, from the system
/// clock. Used to derive verification staleness without storing it.
pub fn stale_cutoff(days_back: u64) -> String {
    let now_days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() / 86400)
        .unwrap_or(0) as i64;
    let (year, month, day) = days_to_civil(now_days.saturating_sub(days_back as i64));
    format!("{year:04}-{month:02}-{day:02}")
}

/// A verification date is `YYYY-MM-DD` with a real calendar date.
/// Lexicographic compare stays chronological for this format, which is what
/// staleness derivation relies on.
pub fn is_verification_date(date: &str) -> bool {
    let bytes = date.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        if index == 4 || index == 7 {
            continue;
        }
        if !byte.is_ascii_digit() {
            return false;
        }
    }
    let year: u32 = date[0..4].parse().unwrap_or(0);
    let month: u32 = date[5..7].parse().unwrap_or(0);
    let day: u32 = date[8..10].parse().unwrap_or(0);
    if year == 0 || !(1..=12).contains(&month) || day == 0 {
        return false;
    }
    // Calendar-valid day: reject impossible dates such as 2026-02-31 that
    // pass a naive month/day-range check.
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    day <= max_day
}

/// `source_notes` that explicitly describe a provisional/unverified state
/// contradict a `live_verified` health claim. The note text — not a
/// separate boolean — is the historical source of the contradiction, so
/// lint treats this as an error rather than trusting the health flag.
pub fn verification_notes_contradict_live(notes: Option<&str>) -> bool {
    let Some(text) = notes else {
        return false;
    };
    let lowered = text.to_ascii_lowercase();
    lowered.contains("provisional")
        || lowered.contains("needs_review")
        || lowered.contains("needs review")
        || lowered.contains("await live verification")
        || lowered.contains("awaiting live verification")
        || lowered.contains("awaiting verification")
        || lowered.contains("unverified")
        || lowered.contains("not yet verified")
}

/// Derived staleness: a `live_verified` provider whose `verified_at` is
/// older than `cutoff` (`YYYY-MM-DD`, lexicographic compare is chronological
/// for ISO dates). Anything else is never "stale": other states are their
/// own review queues.
pub fn verification_stale(health: &HealthState, verified_at: Option<&str>, cutoff: &str) -> bool {
    *health == HealthState::LiveVerified && verified_at.is_some_and(|date| date < cutoff)
}

/// A provider has meaningful absence handling when at least one of these
/// holds: a not-found status code, a not-found body marker, or a verified
/// absence redirect destination. Status codes alone never confirm, but for
/// absence a stable provider status (e.g. 404) is legitimate evidence.
pub fn has_absence_handling(definition: &UsernameProviderDefinition) -> bool {
    !definition.not_found_status.is_empty()
        || !definition.not_found.required.is_empty()
        || !definition.not_found.any.is_empty()
        || !definition.absence_redirect_markers.is_empty()
}

/// Maintainer-facing corpus lint report. Errors fail the gate; warnings do
/// not. Everything is deterministic and offline: lint never performs
/// network requests.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusLintReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub providers_checked: usize,
    pub files_checked: usize,
    pub fixture_complete: usize,
    /// Registered search vectors checked (1:1 with providers today; kept
    /// distinct so multi-vector providers never inflate either number).
    #[serde(default)]
    pub vectors_checked: usize,
    /// Distinct provider IDs seen.
    #[serde(default)]
    pub providers_count: usize,
    #[serde(default)]
    pub disabled_count: usize,
    #[serde(default)]
    pub needs_review_count: usize,
    /// `live_verified` definitions older than the 180-day review window.
    #[serde(default)]
    pub stale_count: usize,
}

impl CorpusLintReport {
    pub fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Normalize a profile URL template for suspicious-equivalence checks:
/// lowercase host, drop a single trailing slash, keep the `{username}`
/// placeholder verbatim. Two templates that normalize identically resolve
/// to the same identity endpoint even when they differ in casing or a
/// trailing slash.
fn normalized_template(template: &str) -> String {
    let lowered = template.to_ascii_lowercase();
    lowered.strip_suffix('/').unwrap_or(&lowered).to_owned()
}

/// Definition-level checks shared by file lint and the embedded fallback.
///
/// Scales with the registry: all checks are O(definitions) hash joins, so
/// thousands of vectors lint as fast as dozens. Every check names the
/// offending vector — at 2,500 vectors a bare count is unactionable.
pub fn lint_definitions(definitions: &[UsernameProviderDefinition], report: &mut CorpusLintReport) {
    if let Err(error) = validate_definitions(definitions) {
        report.errors.push(format!("definitions: {error}"));
    }
    let stale_cutoff = stale_cutoff(180);
    let mut templates = BTreeMap::new();
    let mut normalized = BTreeMap::new();
    let mut vector_ids = BTreeSet::new();
    let mut provider_ids = BTreeSet::new();
    let mut disabled_count = 0usize;
    let mut needs_review_count = 0usize;
    let mut stale_count = 0usize;
    for definition in definitions {
        let id = definition.metadata.id.as_str();
        provider_ids.insert(id);
        // Explicit vector-identity check: vector IDs must be unique even
        // when several vectors later share one provider.
        if !vector_ids.insert(id) {
            report.errors.push(format!(
                "duplicate search vector '{id}' (vector IDs must be unique)"
            ));
        }
        match definition.health_state {
            HealthState::Disabled => disabled_count += 1,
            HealthState::NeedsReview => needs_review_count += 1,
            HealthState::LiveVerified => {
                if verification_stale(
                    &definition.health_state,
                    definition.verified_at.as_deref(),
                    &stale_cutoff,
                ) {
                    stale_count += 1;
                }
            }
            HealthState::FixtureVerified => {}
        }
        if definition.category.trim().is_empty() {
            report.errors.push(format!(
                "provider '{id}' has a missing category (every vector needs one)"
            ));
        } else if !USERNAME_PROVIDER_CATEGORIES.contains(&definition.category.as_str()) {
            report.errors.push(format!(
                "provider '{id}' has unsupported category '{}'",
                definition.category
            ));
        }
        if definition.metadata.weight == 0 {
            report.warnings.push(format!(
                "provider '{id}' has zero weight (scheduling priority misconfiguration)"
            ));
        }
        // Conflicting rules: a marker cannot prove presence AND absence.
        {
            let success_markers: BTreeSet<&str> = definition
                .success
                .required
                .iter()
                .chain(definition.success.any.iter())
                .map(String::as_str)
                .collect();
            let absence_markers: BTreeSet<&str> = definition
                .not_found
                .required
                .iter()
                .chain(definition.not_found.any.iter())
                .map(String::as_str)
                .collect();
            let conflicting: Vec<&&str> = success_markers.intersection(&absence_markers).collect();
            if !conflicting.is_empty() {
                report.errors.push(format!(
                    "provider '{id}' has conflicting rules (marker proves presence and absence: {:?})",
                    conflicting
                        .into_iter()
                        .take(3)
                        .collect::<Vec<_>>()
                ));
            }
        }
        if !has_absence_handling(definition) {
            report.errors.push(format!(
                "provider '{id}' has no absence handling (no not-found status, marker, or redirect)"
            ));
        }
        if definition.health_state == HealthState::LiveVerified && definition.verified_at.is_none()
        {
            report.errors.push(format!(
                "provider '{id}' claims live_verified without verification metadata"
            ));
        }
        if let Some(date) = definition.verified_at.as_deref() {
            if !is_verification_date(date) {
                report.errors.push(format!(
                    "provider '{id}' has invalid verification date {date:?}"
                ));
            }
        }
        if definition.verification_method.is_some() && definition.verified_at.is_none() {
            report.errors.push(format!(
                "provider '{id}' carries a verification method without a verification date"
            ));
        }
        if definition.verified_at.is_some() && definition.health_state != HealthState::LiveVerified
        {
            report.errors.push(format!(
                "provider '{id}' carries verification metadata without live_verified health"
            ));
        }
        if definition.health_state == HealthState::LiveVerified
            && verification_notes_contradict_live(definition.source_notes.as_deref())
        {
            report.errors.push(format!(
                "provider '{id}' claims live_verified with provisional/unverified source notes"
            ));
        }
        if definition.metadata.source_category != definition.category {
            report.errors.push(format!(
                "provider '{id}' has inconsistent categories '{}' vs '{}'",
                definition.metadata.source_category, definition.category
            ));
        }
        // Unsafe schemes/destinations are validated, but surface a dedicated
        // lint error so corpus maintenance can distinguish them from generic
        // validation failures.
        if !definition.profile_url.starts_with("https://") {
            report.errors.push(format!(
                "provider '{id}' uses an unsafe URL scheme (must be https)"
            ));
        }
        if definition.max_body_bytes == 0 || definition.max_body_bytes > MAX_SEARCH_BODY_BYTES {
            report
                .errors
                .push(format!("provider '{id}' has an unbounded body budget"));
        }
        if definition.max_redirects > 5 {
            report
                .errors
                .push(format!("provider '{id}' has an unbounded redirect policy"));
        }
        if let Some(rules) = &definition.username_rules {
            if rules.min_length == 0
                || usize::from(rules.min_length) > usize::from(rules.max_length)
                || usize::from(rules.max_length) > 128
            {
                report
                    .errors
                    .push(format!("provider '{id}' has invalid username rules"));
            }
        }
        lint_classifier_markers(definition, report);
        if let Some(other) = templates.insert(definition.profile_url.as_str(), id) {
            report.errors.push(format!(
                "duplicate profile_url template shared by '{other}' and '{id}'"
            ));
        } else {
            let key = normalized_template(&definition.profile_url);
            if let Some(other) = normalized.insert(key, id) {
                report.errors.push(format!(
                    "suspiciously equivalent profile_url template shared by '{other}' and '{id}'"
                ));
            }
        }
    }
    report.providers_checked = definitions.len();
    report.vectors_checked = vector_ids.len();
    report.providers_count = provider_ids.len();
    report.disabled_count = disabled_count;
    report.needs_review_count = needs_review_count;
    report.stale_count = stale_count;
}

fn lint_expected_status(name: &str) -> Option<SearchStatus> {
    match name {
        "found" => Some(SearchStatus::Confirmed),
        "not-found" => Some(SearchStatus::NotFound),
        "generic-200" => Some(SearchStatus::Possible),
        "blocked" => Some(SearchStatus::Blocked),
        _ => None,
    }
}

/// Single-token block markers so generic they match ordinary page content
/// (scripts, footers, bundles). The `captcha` singleton once converted
/// every live confirmation on eight providers into `Blocked`.
const BROAD_BLOCK_MARKERS: &[&str] = &[
    "captcha",
    "blocked",
    "denied",
    "forbidden",
    "unauthorized",
    "error",
    "limit",
    "sorry",
    "oops",
    "robot",
    "robots",
    "bot",
    "bots",
    "challenge",
    "verify",
    "human",
    "suspicious",
    "unusual",
    "restricted",
];

/// Statically detectable classifier weaknesses: identity-free required
/// markers, username-echo-only markers (a bare `{username}` reflection
/// confirms any page that echoes the probe), and overly broad block
/// markers.
fn lint_classifier_markers(definition: &UsernameProviderDefinition, report: &mut CorpusLintReport) {
    let id = definition.metadata.id.as_str();
    for marker in &definition.success.required {
        if !marker.contains("{username}") {
            report.errors.push(format!(
                "provider '{id}' has a required success marker without identity binding: {marker:?}"
            ));
            continue;
        }
        // A required marker that is only the echoed username confirms
        // reflection, not identity. Short-but-bound markers (a tag plus a
        // username, e.g. `~user<` on SourceHut where `~user` is canonical)
        // stay warnings: they cannot confirm without the probe username
        // present, so they are weak rather than FP factories. Only a bare
        // echo is an error.
        let structural: String = marker
            .replace("{username}", "")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if structural.is_empty() {
            report.errors.push(format!(
                "provider '{id}' has an overly broad success marker (username echo without structure): {marker:?}"
            ));
        } else if structural.len() < 12 {
            report.warnings.push(format!(
                "provider '{id}' has a short success marker that relies on minimal structure: {marker:?}"
            ));
        }
    }
    for marker in definition
        .success
        .any
        .iter()
        .chain(definition.not_found.required.iter())
        .chain(definition.not_found.any.iter())
    {
        if marker.trim().is_empty() {
            report
                .errors
                .push(format!("provider '{id}' has an empty classifier marker"));
        }
    }
    for marker in &definition.blocked_markers {
        if BROAD_BLOCK_MARKERS.contains(&marker.to_ascii_lowercase().as_str())
            || marker.trim().len() < 4
        {
            report.errors.push(format!(
                "provider '{id}' has an overly broad block marker: {marker:?}"
            ));
        } else if !marker.contains(' ') && !marker.contains('-') && !marker.contains('_') {
            report.warnings.push(format!(
                "provider '{id}' has a single-token block marker that may match page content: {marker:?}"
            ));
        }
    }
}

/// Check stored fixtures for every definition. Fixture bodies are
/// classified with the fixed probe username `Rx`, mirroring the unit-test
/// matrix. A `generic-200` fixture that classifies as `Confirmed` is
/// always an error, never a warning.
fn lint_fixtures(
    definitions: &[UsernameProviderDefinition],
    fixture_root: &std::path::Path,
    report: &mut CorpusLintReport,
) {
    let mut complete = 0usize;
    for definition in definitions {
        let id = definition.metadata.id.as_str();
        let cases_path = fixture_root.join(id).join("cases.json");
        let text = match std::fs::read_to_string(&cases_path) {
            Ok(text) => text,
            Err(_) => {
                report.errors.push(format!(
                    "provider '{id}' is missing fixture {}",
                    cases_path.display()
                ));
                continue;
            }
        };
        let cases: serde_json::Value = match serde_json::from_str(&text) {
            Ok(cases) => cases,
            Err(error) => {
                report
                    .errors
                    .push(format!("provider '{id}' has malformed fixtures: {error}"));
                continue;
            }
        };
        if cases.get("provider").and_then(serde_json::Value::as_str) != Some(id) {
            report.errors.push(format!(
                "provider '{id}' fixture provider field does not match its directory"
            ));
            continue;
        }
        let empty = Vec::new();
        let listed = cases
            .get("cases")
            .and_then(serde_json::Value::as_array)
            .unwrap_or(&empty);
        let mut names = BTreeSet::new();
        let mut provider_ok = true;
        for case in listed {
            let name = case.get("name").and_then(serde_json::Value::as_str);
            let expected = case.get("expected").and_then(serde_json::Value::as_str);
            let (Some(name), Some(expected)) = (name, expected) else {
                report.errors.push(format!(
                    "provider '{id}' has a fixture case without name/expected"
                ));
                provider_ok = false;
                continue;
            };
            names.insert(name.to_owned());
            // Canonical cases pin their expectation by name; any other
            // case (e.g. `captcha-noise`) is verified by its `expected`
            // field exactly like the unit-test matrix does.
            if let Some(canonical_want) = lint_expected_status(name) {
                let canonical = match canonical_want {
                    SearchStatus::Confirmed => "confirmed",
                    SearchStatus::NotFound => "not_found",
                    SearchStatus::Possible => "possible",
                    SearchStatus::Blocked => "blocked",
                    _ => "",
                };
                if expected != canonical {
                    report.errors.push(format!(
                        "provider '{id}' fixture '{name}' claims '{expected}', want '{canonical}'"
                    ));
                    provider_ok = false;
                    continue;
                }
            }
            let want = match expected {
                "confirmed" => SearchStatus::Confirmed,
                "not_found" => SearchStatus::NotFound,
                "possible" => SearchStatus::Possible,
                "blocked" => SearchStatus::Blocked,
                _ => {
                    report.errors.push(format!(
                        "provider '{id}' fixture '{name}' has unknown expectation '{expected}'"
                    ));
                    provider_ok = false;
                    continue;
                }
            };
            let status = case.get("status").and_then(serde_json::Value::as_u64);
            let body = case.get("body").and_then(serde_json::Value::as_str);
            let (Some(status), Some(body)) = (status, body) else {
                report.errors.push(format!(
                    "provider '{id}' fixture '{name}' lacks status/body"
                ));
                provider_ok = false;
                continue;
            };
            let got = definition
                .classify(
                    &ProviderResponse {
                        status: status as u16,
                        body: body.to_owned(),
                    },
                    "Rx",
                )
                .status;
            if got != want {
                // Any non-confirming fixture that confirms is a
                // false-positive factory: error, never warning.
                if want != SearchStatus::Confirmed && got == SearchStatus::Confirmed {
                    report.errors.push(format!(
                        "provider '{id}' fixture '{name}' classifies as confirmed"
                    ));
                } else {
                    report.errors.push(format!(
                        "provider '{id}' fixture '{name}' classifies as {got:?}, want {want:?}"
                    ));
                }
                provider_ok = false;
            }
        }
        for required in ["found", "not-found", "generic-200", "blocked"] {
            if !names.contains(required) {
                report.errors.push(format!(
                    "provider '{id}' is missing the '{required}' fixture"
                ));
                provider_ok = false;
            }
        }
        if provider_ok {
            complete += 1;
        }
    }
    report.fixture_complete = complete;
    let fixture_dirs = std::fs::read_dir(fixture_root)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.path().is_dir())
                .filter_map(|entry| entry.file_name().into_string().ok())
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    for dir in fixture_dirs {
        if !definitions
            .iter()
            .any(|definition| definition.metadata.id == dir)
        {
            // Unknown fixture provider: the directory has no definition.
            // Report the declared provider field when it differs, so a typo
            // in either place is visible without failing the gate on a
            // stray directory alone.
            let declared = std::fs::read_to_string(fixture_root.join(&dir).join("cases.json"))
                .ok()
                .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
                .and_then(|value| {
                    value
                        .get("provider")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                });
            match declared {
                Some(provider) if provider != dir => {
                    report.warnings.push(format!(
                        "orphaned fixture directory '{dir}' has no provider definition (declares provider '{provider}')"
                    ));
                }
                _ => {
                    report.warnings.push(format!(
                        "orphaned fixture directory '{dir}' has no provider definition"
                    ));
                }
            }
        }
    }
}

/// Lint a corpus checkout: `corpus_dir` holds per-category pack files and
/// `fixture_root` holds per-provider fixture directories.
pub fn lint_corpus_files(
    corpus_dir: &std::path::Path,
    fixture_root: &std::path::Path,
) -> CorpusLintReport {
    let mut report = CorpusLintReport::default();
    let entries = match std::fs::read_dir(corpus_dir) {
        Ok(entries) => entries,
        Err(error) => {
            report.errors.push(format!(
                "cannot read corpus directory {}: {error}",
                corpus_dir.display()
            ));
            return report;
        }
    };
    let mut files: Vec<std::path::PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    if files.is_empty() {
        report
            .errors
            .push(format!("no provider files in {}", corpus_dir.display()));
        return report;
    }
    report.files_checked = files.len();
    let mut schema_version: Option<u64> = None;
    let mut pack_version: Option<String> = None;
    let mut definitions: Vec<UsernameProviderDefinition> = Vec::new();
    let mut ids: BTreeSet<String> = BTreeSet::new();
    for file in &files {
        let name = file
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let text = match std::fs::read_to_string(file) {
            Ok(text) => text,
            Err(error) => {
                report
                    .errors
                    .push(format!("cannot read provider file '{name}': {error}"));
                continue;
            }
        };
        let fragment: serde_json::Value = match serde_json::from_str(&text) {
            Ok(fragment) => fragment,
            Err(error) => {
                report
                    .errors
                    .push(format!("provider file '{name}' is malformed: {error}"));
                continue;
            }
        };
        match (
            fragment
                .get("schema_version")
                .and_then(serde_json::Value::as_u64),
            fragment
                .get("pack_version")
                .and_then(serde_json::Value::as_str),
        ) {
            (Some(schema), Some(version)) => {
                if schema != u64::from(PROVIDER_SCHEMA_VERSION) {
                    report.errors.push(format!(
                        "provider file '{name}' uses invalid schema_version {schema}"
                    ));
                }
                if version.trim().is_empty() || version.len() > 64 {
                    report.errors.push(format!(
                        "provider file '{name}' has an invalid pack version"
                    ));
                }
                if schema_version.is_some_and(|expected| expected != schema)
                    || pack_version
                        .as_deref()
                        .is_some_and(|expected| expected != version)
                {
                    report.errors.push(format!(
                        "provider file '{name}' disagrees on schema/pack version"
                    ));
                }
                schema_version = Some(schema);
                pack_version = Some(version.to_owned());
            }
            _ => {
                report.errors.push(format!(
                    "provider file '{name}' lacks schema_version/pack_version"
                ));
                continue;
            }
        }
        let providers = fragment
            .get("providers")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        // Category files must stay consistent: `developer.json` holds
        // `developer` providers. A mismatch is a miscategorization or a bad
        // merge, reported as an error rather than silently accepted.
        let expected_category = name.strip_suffix(".json").unwrap_or(&name).to_owned();
        let category_known = USERNAME_PROVIDER_CATEGORIES.contains(&expected_category.as_str());
        for (index, raw) in providers.iter().enumerate() {
            match serde_json::from_value::<UsernameProviderDefinition>(raw.clone()) {
                Ok(definition) => {
                    if !ids.insert(definition.metadata.id.clone()) {
                        report.errors.push(format!(
                            "duplicate provider id '{}' (also in '{name}')",
                            definition.metadata.id
                        ));
                    }
                    if category_known && definition.category != expected_category {
                        report.errors.push(format!(
                            "provider '{}' in '{name}' has inconsistent category '{}'",
                            definition.metadata.id, definition.category
                        ));
                    }
                    definitions.push(definition);
                }
                Err(error) => {
                    report.errors.push(format!(
                        "provider file '{name}' entry {index} is invalid (unsupported classifier primitive or schema drift): {error}"
                    ));
                }
            }
        }
    }
    if definitions.is_empty() {
        report
            .errors
            .push("merged corpus contains no providers".to_owned());
    }
    lint_definitions(&definitions, &mut report);
    lint_fixtures(&definitions, fixture_root, &mut report);
    report
}

/// Lint the embedded pack (definition-level checks). Fixture directories
/// are not embedded, so fixture checks are skipped with a warning.
pub fn lint_embedded_pack() -> CorpusLintReport {
    let mut report = CorpusLintReport::default();
    match embedded_username_pack() {
        Ok(pack) => {
            lint_definitions(&pack.providers, &mut report);
            report.warnings.push(
                "fixture checks skipped: no corpus checkout; run from the repository root for full lint"
                    .to_owned(),
            );
        }
        Err(error) => {
            report
                .errors
                .push(format!("embedded pack is invalid: {error}"));
        }
    }
    report
}

pub fn add_username_observation_to_graph(
    graph: &mut crate::graph::ScanGraph,
    input: &SearchEntity,
    observation: &SearchObservation,
) -> Option<String> {
    if input.kind != SearchEntityKind::Username
        || !matches!(
            observation.status,
            SearchStatus::Confirmed | SearchStatus::Probable | SearchStatus::Possible
        )
    {
        return None;
    }
    let platform = observation.attributes.get("platform")?;
    let account_value = format!(
        "{}:{}",
        platform.to_ascii_lowercase(),
        input.canonical_value
    );
    let account_id = crate::assets::public_entity_id("account", &account_value);
    let provenance = crate::graph::EntityProvenance {
        scan_plan_id: "search".to_owned(),
        module: format!("search.provider.{}", observation.provider_id),
        task_id: Some(observation.task_id.clone()),
        target: Some(input.id.clone()),
        timestamp: observation.timestamp,
        reason: Some(format!("provider outcome: {:?}", observation.status).to_ascii_lowercase()),
        rule_id: Some(format!(
            "{}@{}",
            observation.provider_id, observation.provider_version
        )),
    };
    let mut username_attributes = input.attributes.clone();
    username_attributes.insert("canonical_value".to_owned(), input.canonical_value.clone());
    graph.upsert_entity(
        input.id.clone(),
        crate::graph::EntityKind::Username,
        input.display_value.clone(),
        username_attributes,
        &provenance,
    );
    let mut account_attributes = observation.attributes.clone();
    account_attributes.insert(
        "contact_class".to_owned(),
        format!("{:?}", observation.contact_class).to_ascii_lowercase(),
    );
    account_attributes.insert(
        "status".to_owned(),
        format!("{:?}", observation.status).to_ascii_lowercase(),
    );
    graph.upsert_entity(
        account_id.clone(),
        crate::graph::EntityKind::Account,
        format!("{} / {}", platform, input.display_value),
        account_attributes,
        &provenance,
    );
    graph.link(
        input.id.clone(),
        account_id.clone(),
        crate::graph::EdgeRelation::HasAccount,
        observation.confidence.min(95),
        &provenance,
        observation
            .evidence
            .iter()
            .take(MAX_SEARCH_EVIDENCE)
            .cloned()
            .collect(),
        BTreeMap::from([("observation_class".to_owned(), "observed".to_owned())]),
    );
    Some(account_id)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernameSearchReport {
    pub schema_version: u32,
    pub run_id: String,
    pub seed: SearchEntity,
    pub provider_pack_version: String,
    pub accounting: SearchAccounting,
    pub results: Vec<SearchObservation>,
    pub graph: crate::graph::ScanGraph,
    pub network_scans: u64,
    pub started_at: u64,
    pub completed_at: u64,
}

pub fn embedded_username_pack() -> Result<UsernameProviderPack, SearchError> {
    parse_provider_pack(
        include_str!(concat!(env!("OUT_DIR"), "/username_pack.json")),
        "embedded username providers",
    )
}

pub fn execute_username_search(
    username: &str,
    max_concurrency: usize,
    max_per_host: usize,
    deadline: std::time::Duration,
    selected: Option<&BTreeSet<String>>,
    cancelled: &AtomicBool,
) -> Result<UsernameSearchReport, SearchError> {
    execute_username_search_full(
        username,
        max_concurrency,
        max_per_host,
        deadline,
        selected,
        &BTreeSet::new(),
        &BTreeSet::new(),
        cancelled,
        None,
    )
}

/// Full core entry point with category/provider selection.
///
/// `selected` (explicit provider IDs), `excluded`, and `categories` form the
/// REAL execution plan via [`plan_username_providers`]: providers outside
/// the plan are never contacted (no post-filtering). Both CLI and web call
/// this so the same query yields the same plan. `progress` is an optional
/// real progress hook `(completed, total)` invoked after each scheduler wave;
/// frontends use it for restrained TTY progress or SSE, never faked.
#[allow(clippy::too_many_arguments)]
pub fn execute_username_search_full(
    username: &str,
    max_concurrency: usize,
    max_per_host: usize,
    deadline: std::time::Duration,
    selected: Option<&BTreeSet<String>>,
    excluded: &BTreeSet<String>,
    categories: &BTreeSet<String>,
    cancelled: &AtomicBool,
    progress: Option<&dyn Fn(usize, usize)>,
) -> Result<UsernameSearchReport, SearchError> {
    let started_at = unix_timestamp();
    let seed = SearchEntity::username(username, started_at)?;
    let pack = embedded_username_pack()?;
    let pack_version = pack.pack_version.clone();
    // Shared planning: identical validation + effective set for CLI and web.
    let effective = plan_username_providers(&pack, selected, excluded, categories)
        .map_err(SearchError::InvalidProvider)?;
    let client = Arc::new(SharedHttpClient::new()?);
    let mut providers: Vec<Box<dyn SearchProvider>> = Vec::new();
    for definition in pack.providers {
        if !effective.contains(&definition.metadata.id) {
            continue;
        }
        providers.push(Box::new(DefinitionProvider::new(
            definition,
            client.clone(),
        )?));
    }
    providers.sort_by(|a, b| a.metadata().id.cmp(&b.metadata().id));
    let rate_limiter = RateLimiter::new(0);
    let mut scheduler = SearchScheduler {
        max_providers: providers.len(),
        max_concurrency: max_concurrency.clamp(1, 16),
        max_per_host: max_per_host.clamp(1, 4),
        deadline: Instant::now() + deadline,
        rate_limiter,
    };
    let (results, accounting) = if let Some(hook) = progress {
        scheduler.run_with_progress(&providers, &seed, cancelled, hook)
    } else {
        scheduler.run(&providers, &seed, cancelled)
    };
    let mut graph = crate::graph::ScanGraph::default();
    graph.upsert_entity(
        seed.id.clone(),
        crate::graph::EntityKind::Username,
        seed.display_value.clone(),
        BTreeMap::from([("canonical_value".to_owned(), seed.canonical_value.clone())]),
        &crate::graph::EntityProvenance {
            scan_plan_id: "search".to_owned(),
            module: "search.seed".to_owned(),
            task_id: None,
            target: Some(seed.id.clone()),
            timestamp: seed.last_observed,
            reason: Some("operator-supplied username seed".to_owned()),
            rule_id: None,
        },
    );
    for observation in &results {
        add_username_observation_to_graph(&mut graph, &seed, observation);
    }
    let completed_at = unix_timestamp();
    Ok(UsernameSearchReport {
        schema_version: 1,
        run_id: crate::assets::public_entity_id(
            "search_run",
            &format!("{}:{started_at}:{pack_version}", seed.id),
        ),
        seed,
        provider_pack_version: pack_version,
        accounting,
        results,
        graph,
        network_scans: 0,
        started_at,
        completed_at,
    })
}

pub fn persist_username_report(
    db: &mut crate::project_db::ProjectDb,
    report: &UsernameSearchReport,
) -> Result<crate::project_db::ImportStats, SearchError> {
    use crate::project_db::{
        ClassifierProvenance, CoverageSnapshot, PackProvenance, RetentionMode, ScanImport,
    };

    let mut coverage = CoverageSnapshot {
        truncated: report.accounting.truncated,
        ..CoverageSnapshot::default()
    };
    coverage.modules_completed = report
        .results
        .iter()
        .map(|result| {
            format!(
                "search.provider.{}.{}",
                result.provider_id,
                format!("{:?}", result.status).to_ascii_lowercase()
            )
        })
        .collect();
    coverage.modules_completed.sort();
    coverage.modules_completed.dedup();
    let termination = if report.accounting.cancelled > 0 {
        "cancelled"
    } else if report.accounting.unscanned > 0 {
        "deadline_or_budget"
    } else {
        "complete"
    };
    let import = ScanImport {
        scan_id: report.run_id.clone(),
        plan_id: crate::assets::public_entity_id(
            "search_plan",
            &format!("username:{}", report.provider_pack_version),
        ),
        started_at_ms: report.started_at.saturating_mul(1_000),
        finished_at_ms: report.completed_at.saturating_mul(1_000),
        scope_json: serde_json::json!({
            "contact_class": "public_http",
            "direct_network": false,
            "seed_kind": "username"
        })
        .to_string(),
        workflow: "username_search".to_owned(),
        level: 0,
        termination: termination.to_owned(),
        tasks_admitted: report
            .accounting
            .providers_requested
            .saturating_sub(report.accounting.unscanned) as u64,
        tasks_completed: report.accounting.providers_completed as u64,
        coverage,
        classifier: ClassifierProvenance {
            tool_version: crate::project_db::TOOL_VERSION.to_owned(),
            packs: vec![PackProvenance {
                path: "embedded:search/providers/v1/username/".to_owned(),
                schema_version: PROVIDER_SCHEMA_VERSION,
                rule_count: report.accounting.providers_requested,
            }],
            rules_used: report
                .results
                .iter()
                .map(|result| format!("{}@{}", result.provider_id, result.provider_version))
                .collect(),
        },
        retention: RetentionMode::Standard,
    };
    let stats = db.import_scan(&import, &report.graph)?;
    let evidence = report
        .results
        .iter()
        .map(|result| {
            (
                format!("search.provider.{}", result.provider_id),
                report.seed.id.clone(),
                result.confidence,
                serde_json::json!({
                    "provider": result.provider_id,
                    "provider_version": result.provider_version,
                    "status": result.status,
                    "evidence": result.evidence,
                    "attributes": result.attributes,
                    "contact_class": result.contact_class,
                    "task_id": result.task_id
                }),
                result.timestamp.saturating_mul(1_000),
            )
        })
        .collect::<Vec<_>>();
    db.store_evidence(
        &report.run_id,
        &evidence,
        crate::project_db::RetentionMode::Standard,
    )?;
    Ok(stats)
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn render_username_human(report: &UsernameSearchReport, show_all: bool) -> String {
    let mut output = format!("Username search: {}\n", report.seed.display_value);
    for status in [
        SearchStatus::Confirmed,
        SearchStatus::Probable,
        SearchStatus::Possible,
    ] {
        let matching: Vec<&SearchObservation> = report
            .results
            .iter()
            .filter(|result| result.status == status)
            .collect();
        if matching.is_empty() {
            continue;
        }
        output.push_str(&format!("\n{:?}\n", status));
        for result in matching {
            output.push_str(&format!(
                "  {} confidence={} profile={}\n",
                result.provider_id,
                result.confidence,
                result
                    .attributes
                    .get("final_url")
                    .map(String::as_str)
                    .unwrap_or("unknown")
            ));
            for evidence in &result.evidence {
                output.push_str(&format!("    evidence: {evidence}\n"));
            }
        }
    }
    if show_all {
        output.push_str("\nAll provider outcomes\n");
        for result in &report.results {
            output.push_str(&format!(
                "  {} {:?} confidence={}\n",
                result.provider_id, result.status, result.confidence
            ));
        }
    }
    output.push_str(&format!(
        "\nSummary\n  providers requested: {}\n  completed: {}\n  skipped: {}\n  cancelled: {}\n  unscanned: {}\n  confirmed: {}\n  probable: {}\n  possible: {}\n  not found: {}\n  rate limited: {}\n  blocked: {}\n  errors: {}\n  network scans: 0\n  truncated: {}\n",
        report.accounting.providers_requested,
        report.accounting.providers_completed,
        report.accounting.skipped,
        report.accounting.cancelled,
        report.accounting.unscanned,
        count_status(&report.accounting, SearchStatus::Confirmed),
        count_status(&report.accounting, SearchStatus::Probable),
        count_status(&report.accounting, SearchStatus::Possible),
        count_status(&report.accounting, SearchStatus::NotFound),
        count_status(&report.accounting, SearchStatus::RateLimited),
        count_status(&report.accounting, SearchStatus::Blocked),
        count_status(&report.accounting, SearchStatus::Error),
        report.accounting.truncated,
    ));
    output
}

fn count_status(accounting: &SearchAccounting, status: SearchStatus) -> usize {
    accounting.counts.get(&status).copied().unwrap_or_default()
}

/// Typed JSONL rendering of a username search report.
///
/// Every emitted line is one independently valid JSON object using the
/// codebase `record_type` envelope convention; nothing here can emit ANSI,
/// banners, or human prose. Record stream:
///
/// * `search_start` — run identity, seed, pack version, requested count.
/// * `observation` — one per completed provider result, in the report's
///   deterministic order, with provenance for future transforms.
/// * `search_summary` — exact accounting plus per-status counts.
///
/// Providers without an observation (skipped, cancelled, unscanned) appear
/// only in the summary: no observation object exists for them, and the
/// renderer does not invent one.
pub fn render_username_jsonl(report: &UsernameSearchReport) -> String {
    fn envelope(record_type: &'static str, payload: serde_json::Value) -> String {
        serde_json::json!({
            "schema_version": 1,
            "record_type": record_type,
            "payload": payload,
        })
        .to_string()
    }

    let mut output = String::new();
    output.push_str(&envelope(
        "search_start",
        serde_json::json!({
            "run_id": report.run_id,
            "entity": report.seed.id,
            "seed_kind": "username",
            "seed_display": report.seed.display_value,
            "provider_pack_version": report.provider_pack_version,
            "providers_requested": report.accounting.providers_requested,
            "scheduled": report.accounting.scheduled(),
            "network_scans": report.network_scans,
            "started_at": report.started_at,
        }),
    ));
    output.push('\n');
    for result in &report.results {
        let attribute = |key: &str| result.attributes.get(key).cloned().unwrap_or_default();
        // Core URL-kind semantics (same as CLI/web presentation, no ANSI).
        let profile = attribute("profile_url");
        let final_url = attribute("final_url");
        let observed = matches!(
            result.status,
            SearchStatus::Confirmed | SearchStatus::Probable
        );
        // Prefer final URL when identity-specific, else profile template.
        let kind_url = if !final_url.trim().is_empty() {
            final_url.clone()
        } else {
            profile.clone()
        };
        let url_kind = core_url_kind(
            &kind_url,
            &report.seed.display_value,
            observed && !kind_url.trim().is_empty(),
        );
        output.push_str(&envelope(
            "observation",
            serde_json::json!({
                "entity": result.input_entity_id,
                "provider_id": result.provider_id,
                "definition_version": result.provider_version,
                "provider_health": attribute("provider_health"),
                "provider_state": attribute("provider_state"),
                "categories": [attribute("category")],
                "category": attribute("category"),
                "category_label": attribute("category_label"),
                "status": result.status,
                "confidence": result.confidence,
                "profile_url": attribute("profile_url"),
                "final_url": attribute("final_url"),
                "url": if !final_url.is_empty() { final_url.clone() } else { profile.clone() },
                "url_kind": url_kind,
                "metadata": result.attributes,
                "evidence": result.evidence,
                "provenance": {
                    "provider_id": result.provider_id,
                    "provider_version": result.provider_version,
                    "task_id": result.task_id,
                    "input_entity_id": result.input_entity_id,
                    "contact_class": result.contact_class,
                    "scan_plan_id": "search",
                    "module": format!("search.provider.{}", result.provider_id),
                },
                "contact_class": result.contact_class,
                "task_id": result.task_id,
                "timestamp": result.timestamp,
                "started_at": report.started_at,
                "observed_at": result.timestamp,
            }),
        ));
        output.push('\n');
    }
    let mut counts = serde_json::Map::new();
    for status in [
        SearchStatus::Confirmed,
        SearchStatus::Probable,
        SearchStatus::Possible,
        SearchStatus::NotFound,
        SearchStatus::Unknown,
        SearchStatus::RateLimited,
        SearchStatus::Blocked,
        SearchStatus::AuthenticationRequired,
        SearchStatus::Error,
        SearchStatus::Cancelled,
        SearchStatus::Unscanned,
    ] {
        // Serde snake_case keeps word boundaries (`rate_limited`), unlike
        // lowercase Debug (`ratelimited`).
        let key = match serde_json::to_value(status) {
            Ok(serde_json::Value::String(key)) => key,
            _ => format!("{status:?}").to_ascii_lowercase(),
        };
        counts.insert(
            key,
            serde_json::Value::from(count_status(&report.accounting, status)),
        );
    }
    output.push_str(&envelope(
        "search_summary",
        serde_json::json!({
            "run_id": report.run_id,
            "providers_requested": report.accounting.providers_requested,
            // Explicit scheduled/remaining aliases: the denominator is the
            // real scheduled set for this run, never the registry size.
            "scheduled": report.accounting.scheduled(),
            "remaining": report.accounting.remaining(),
            "providers_completed": report.accounting.providers_completed,
            "skipped": report.accounting.skipped,
            "cancelled": report.accounting.cancelled,
            "unscanned": report.accounting.unscanned,
            "truncated": report.accounting.truncated,
            "status_counts": counts,
            "network_scans": report.network_scans,
            "started_at": report.started_at,
            "completed_at": report.completed_at,
        }),
    ));
    output.push('\n');
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::time::Duration;

    fn fixture_http(response: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);
            stream.write_all(&response).unwrap();
        });
        (format!("http://{address}/{{username}}"), handle)
    }

    fn local_test_client() -> SharedHttpClient {
        SharedHttpClient {
            clients: Arc::new(Mutex::new(BTreeMap::new())),
            resolver: Arc::new(SystemResolver),
            allow_nonpublic: true,
        }
    }

    fn definition() -> UsernameProviderDefinition {
        UsernameProviderDefinition {
            metadata: ProviderMetadata {
                id: "fixture-dev".to_owned(),
                version: "1".to_owned(),
                accepts: vec![SearchEntityKind::Username],
                produces: vec![SearchEntityKind::Account],
                contact_class: ContactClass::PublicHttp,
                timeout_ms: 2_000,
                requests_per_minute: 30,
                weight: 1,
                source_category: "developer".to_owned(),
                requires_authentication: false,
            },
            platform: "Fixture Dev".to_owned(),
            category: "developer".to_owned(),
            profile_url: "https://example.test/{username}".to_owned(),
            method: "GET".to_owned(),
            success_status: vec![200],
            not_found_status: vec![404],
            success: MarkerPolicy {
                required: vec!["data-profile=\"{username}\"".to_owned()],
                any: vec!["rel=\"canonical\"".to_owned()],
            },
            not_found: MarkerPolicy {
                required: vec![],
                any: vec!["profile not found".to_owned()],
            },
            blocked_markers: vec!["captcha challenge".to_owned()],
            authentication_url_markers: vec!["/login".to_owned()],
            max_redirects: 2,
            max_body_bytes: 64 * 1024,
            health_state: HealthState::FixtureVerified,
            username_rules: None,
            absence_redirect_markers: Vec::new(),
            verified_at: None,
            verification_method: None,
            source_notes: None,
        }
    }

    #[test]
    fn username_identity_is_stable_and_display_is_preserved() {
        let first = SearchEntity::username("Rx", 10).unwrap();
        let second = SearchEntity::username("rx", 20).unwrap();
        assert_eq!(first.id, second.id);
        assert_eq!(first.display_value, "Rx");
        assert_eq!(first.canonical_value, "rx");
    }

    #[test]
    fn status_alone_never_confirms_account() {
        let result = definition().classify(
            &ProviderResponse {
                status: 200,
                body: "generic page".to_owned(),
            },
            "Rx",
        );
        assert_eq!(result.status, SearchStatus::Possible);
        assert!(result.confidence < 40);
    }

    #[test]
    fn strong_marker_confirms_and_generic_echo_does_not() {
        let provider = definition();
        let confirmed = provider.classify(
            &ProviderResponse {
                status: 200,
                body: "<meta data-profile=\"rx\" rel=\"canonical\">".to_owned(),
            },
            "Rx",
        );
        assert_eq!(confirmed.status, SearchStatus::Confirmed);
        assert_eq!(confirmed.confidence, 94);
        let echo = provider.classify(
            &ProviderResponse {
                status: 200,
                body: "Search results for Rx".to_owned(),
            },
            "Rx",
        );
        assert_eq!(echo.status, SearchStatus::Possible);
    }

    #[test]
    fn absence_rate_limit_and_block_are_distinct() {
        let provider = definition();
        assert_eq!(
            provider
                .classify(
                    &ProviderResponse {
                        status: 404,
                        body: String::new()
                    },
                    "rx"
                )
                .status,
            SearchStatus::NotFound
        );
        assert_eq!(
            provider
                .classify(
                    &ProviderResponse {
                        status: 429,
                        body: String::new()
                    },
                    "rx"
                )
                .status,
            SearchStatus::RateLimited
        );
        assert_eq!(
            provider
                .classify(
                    &ProviderResponse {
                        status: 200,
                        body: "captcha challenge".to_owned()
                    },
                    "rx"
                )
                .status,
            SearchStatus::Blocked
        );
    }

    #[test]
    fn definitions_reject_status_only_and_duplicates() {
        let mut weak = definition();
        weak.success.required.clear();
        assert!(weak.validate().is_err());
        let item = definition();
        assert!(validate_definitions(&[item.clone(), item]).is_err());
    }

    #[test]
    fn username_rules_skip_with_explicit_reason() {
        let permissive = UsernameRules::permissive();
        assert!(permissive.check("exampleuser").is_ok());
        // Absent rules never skip.
        assert!(username_skip_reason(&definition(), "exampleuser").is_none());

        let mut constrained = definition();
        constrained.username_rules = Some(UsernameRules {
            min_length: 3,
            max_length: 8,
            charset: UsernameCharset::AlnumHyphen,
        });
        assert!(username_skip_reason(&constrained, "rx").is_some());
        assert!(username_skip_reason(&constrained, "toolongusername").is_some());
        assert!(username_skip_reason(&constrained, "bad_name!").is_some());
        assert!(username_skip_reason(&constrained, "ok-name").is_none());

        // Disabled providers are always skipped with a reason.
        let mut disabled = definition();
        disabled.health_state = HealthState::Disabled;
        assert_eq!(
            username_skip_reason(&disabled, "exampleuser").as_deref(),
            Some("provider is disabled")
        );

        // Impossible rules are rejected at validation time.
        let mut impossible = definition();
        impossible.username_rules = Some(UsernameRules {
            min_length: 9,
            max_length: 8,
            charset: UsernameCharset::Any,
        });
        assert!(impossible.validate().is_err());
        let mut unbounded = definition();
        unbounded.username_rules = Some(UsernameRules {
            min_length: 1,
            max_length: 500,
            charset: UsernameCharset::Any,
        });
        assert!(unbounded.validate().is_err());
    }

    #[test]
    fn corpus_lint_catches_duplicates_missing_fixtures_and_orphans() {
        let root =
            std::env::temp_dir().join(format!("rxscan_lint_{}_{}", std::process::id(), "dupcase"));
        let corpus = root.join("search/providers/v1/username");
        let fixtures = root.join("search/fixtures/username");
        std::fs::create_dir_all(&corpus).unwrap();
        std::fs::create_dir_all(fixtures.join("lonely")).unwrap();
        let mut first = definition();
        first.metadata.id = "lint-a".to_owned();
        let mut second = definition();
        second.metadata.id = "lint-a".to_owned();
        let fragment = serde_json::json!({
            "schema_version": 1,
            "pack_version": "lint-v1",
            "providers": [first, second],
        });
        std::fs::write(corpus.join("developer.json"), fragment.to_string()).unwrap();
        let report = lint_corpus_files(&corpus, &fixtures);
        assert!(!report.is_clean());
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("duplicate provider id"))
        );
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("missing fixture"))
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("lonely"))
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn corpus_lint_rejects_generic200_confirming_fixture() {
        let root =
            std::env::temp_dir().join(format!("rxscan_lint_{}_{}", std::process::id(), "fp200"));
        let corpus = root.join("search/providers/v1/username");
        let fixtures = root.join("search/fixtures/username");
        std::fs::create_dir_all(&corpus).unwrap();
        std::fs::create_dir_all(fixtures.join("lint-b")).unwrap();
        let mut only = definition();
        only.metadata.id = "lint-b".to_owned();
        let fragment = serde_json::json!({
            "schema_version": 1,
            "pack_version": "lint-v1",
            "providers": [only],
        });
        std::fs::write(corpus.join("developer.json"), fragment.to_string()).unwrap();
        // The generic-200 body carries the required marker: must be caught.
        let cases = serde_json::json!({
            "provider": "lint-b",
            "cases": [
                {"name": "found", "status": 200, "body": "data-profile=\"rx\" rel=\"canonical\"", "expected": "confirmed"},
                {"name": "not-found", "status": 404, "body": "profile not found", "expected": "not_found"},
                {"name": "generic-200", "status": 200, "body": "data-profile=\"rx\" rel=\"canonical\"", "expected": "possible"},
                {"name": "blocked", "status": 200, "body": "captcha challenge", "expected": "blocked"},
            ],
        });
        std::fs::write(fixtures.join("lint-b/cases.json"), cases.to_string()).unwrap();
        let report = lint_corpus_files(&corpus, &fixtures);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("generic-200") && error.contains("confirmed")),
            "unexpected report: {report:?}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn embedded_corpus_passes_lint_definitions() {
        let report = lint_embedded_pack();
        let definition_errors: Vec<&String> = report
            .errors
            .iter()
            .filter(|error| !error.contains("fixture"))
            .collect();
        assert!(
            definition_errors.is_empty(),
            "embedded definition lint errors: {definition_errors:?}"
        );
    }

    fn jsonl_report() -> UsernameSearchReport {
        let seed = SearchEntity::username("ExampleUser", 1_700_000_000).unwrap();
        let observation =
            |provider: &str, status: SearchStatus, confidence: u8| SearchObservation {
                provider_id: provider.to_owned(),
                provider_version: "1".to_owned(),
                task_id: format!("task-{provider}"),
                input_entity_id: seed.id.clone(),
                contact_class: ContactClass::PublicHttp,
                status,
                confidence,
                timestamp: 1_700_000_000,
                evidence: vec!["synthetic evidence".to_owned()],
                attributes: BTreeMap::from([
                    ("platform".to_owned(), provider.to_owned()),
                    (
                        "profile_url".to_owned(),
                        format!("https://example.test/{provider}/exampleuser"),
                    ),
                    (
                        "final_url".to_owned(),
                        format!("https://example.test/{provider}/exampleuser"),
                    ),
                    ("provider_health".to_owned(), "needs_review".to_owned()),
                ]),
            };
        let results = vec![
            observation("zeta", SearchStatus::Confirmed, 94),
            observation("alpha", SearchStatus::Blocked, 0),
        ];
        let mut counts = BTreeMap::new();
        counts.insert(SearchStatus::Confirmed, 1);
        counts.insert(SearchStatus::Blocked, 1);
        UsernameSearchReport {
            schema_version: 1,
            run_id: "search_run_fixture".to_owned(),
            seed,
            provider_pack_version: "fixture-v1".to_owned(),
            accounting: SearchAccounting {
                providers_requested: 3,
                providers_completed: 2,
                skipped: 1,
                cancelled: 0,
                unscanned: 0,
                counts,
                truncated: false,
            },
            results,
            graph: crate::graph::ScanGraph::default(),
            network_scans: 0,
            started_at: 1_700_000_000,
            completed_at: 1_700_000_001,
        }
    }

    #[test]
    fn username_jsonl_lines_parse_independently_and_reconcile() {
        let report = jsonl_report();
        let text = render_username_jsonl(&report);
        assert!(!text.contains('\x1b'), "JSONL must never contain ANSI");
        assert!(!text.contains("RXSCAN"));
        assert!(!text.contains("Username search"));
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "start + 2 observations + summary");
        let records: Vec<serde_json::Value> = lines
            .iter()
            .map(|line| serde_json::from_str(line).expect("every line parses"))
            .collect();
        let kinds: Vec<&str> = records
            .iter()
            .map(|record| record["record_type"].as_str().unwrap())
            .collect();
        assert_eq!(
            kinds,
            [
                "search_start",
                "observation",
                "observation",
                "search_summary"
            ]
        );
        for record in &records {
            assert_eq!(record["schema_version"], 1);
        }
        // Observation provenance for future transforms.
        let first = &records[1]["payload"];
        for field in [
            "entity",
            "provider_id",
            "provider_health",
            "status",
            "confidence",
            "profile_url",
            "contact_class",
            "evidence",
            "definition_version",
            "timestamp",
        ] {
            assert!(first.get(field).is_some(), "missing {field}");
        }
        assert_eq!(first["provider_health"], "needs_review");
        // Deterministic ordering: report order preserved, render stable.
        assert_eq!(records[1]["payload"]["provider_id"], "zeta");
        assert_eq!(records[2]["payload"]["provider_id"], "alpha");
        assert_eq!(render_username_jsonl(&report), text);
        // Summary accounting reconciles exactly.
        let summary = &records[3]["payload"];
        assert_eq!(
            summary["providers_requested"].as_u64().unwrap(),
            summary["providers_completed"].as_u64().unwrap()
                + summary["skipped"].as_u64().unwrap()
                + summary["cancelled"].as_u64().unwrap()
                + summary["unscanned"].as_u64().unwrap()
        );
        assert_eq!(summary["network_scans"], 0);
        let status_counts = summary["status_counts"].as_object().unwrap();
        let counted: u64 = status_counts.values().map(|v| v.as_u64().unwrap()).sum();
        assert_eq!(counted, summary["providers_completed"].as_u64().unwrap());
    }

    #[test]
    fn username_jsonl_has_no_machine_output_pollution() {
        // Phase C3 gate: every stdout line in JSONL mode is independently
        // valid JSON; no ANSI, no banner, no human headings/tables, no
        // decorative separators. Stderr diagnostics never mix into stdout
        // (the renderer returns a pure string; the CLI writes diagnostics
        // to stderr).
        let report = jsonl_report();
        let text = render_username_jsonl(&report);
        let ansi_count = text.matches('\x1b').count();
        assert_eq!(ansi_count, 0, "ANSI count must be 0");
        let banner_count = text.matches("RXSCAN").count() + text.matches("RxScan").count();
        assert_eq!(banner_count, 0, "banner count must be 0");
        for heading in [
            "Username search",
            "All provider outcomes",
            "Summary",
            "providers requested",
            "───",
            "---",
            "===",
            "TABLE",
        ] {
            assert!(
                !text.contains(heading),
                "human heading {heading:?} must not appear in JSONL"
            );
        }
        // Every line parses independently with serde_json.
        let mut invalid = 0usize;
        for line in text.lines() {
            if serde_json::from_str::<serde_json::Value>(line).is_err() {
                invalid += 1;
            }
        }
        assert_eq!(invalid, 0, "invalid JSONL lines must be 0");
        assert!(!text.is_empty() && text.ends_with('\n'));
    }

    #[test]
    fn username_jsonl_ordering_is_deterministic() {
        // Rendering the same report twice yields byte-identical output, and
        // observation order follows the report's deterministic provider
        // order (the scheduler sorts by provider_id).
        let report = jsonl_report();
        assert_eq!(
            render_username_jsonl(&report),
            render_username_jsonl(&report)
        );
        let text = render_username_jsonl(&report);
        let lines: Vec<&str> = text.lines().collect();
        let ids: Vec<String> = lines[1..lines.len() - 1]
            .iter()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["payload"]["provider_id"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        // jsonl_report uses insertion order [zeta, alpha]; rendering
        // preserves report order byte-for-byte (scheduler order is enforced
        // at schedule time, not re-sorted at render time).
        assert_eq!(ids, ["zeta", "alpha"]);
    }

    #[test]
    fn verification_dates_are_validated() {
        assert!(is_verification_date("2026-10-05"));
        assert!(!is_verification_date("2026-13-01"));
        assert!(!is_verification_date("2026-00-10"));
        assert!(!is_verification_date("2026-02-31"));
        assert!(!is_verification_date("2026-02-29"));
        assert!(is_verification_date("2024-02-29"));
        assert!(!is_verification_date("not-a-date"));
        assert!(!is_verification_date("2026/10/05"));
        assert!(!is_verification_date(""));
        let mut dated = definition();
        dated.health_state = HealthState::LiveVerified;
        dated.verified_at = Some("2026-13-40".to_owned());
        assert!(dated.validate().is_err());
        let mut stray = definition();
        stray.verified_at = Some("2026-10-05".to_owned());
        assert!(stray.validate().is_err());
        let mut method_only = definition();
        method_only.verification_method = Some("live-probe".to_owned());
        assert!(method_only.validate().is_err());
        // A live_verified claim contradicted by its own notes is an error.
        let mut contradicted = definition();
        contradicted.health_state = HealthState::LiveVerified;
        contradicted.verified_at = Some("2026-10-05".to_owned());
        contradicted.verification_method = Some("live-probe".to_owned());
        contradicted.source_notes =
            Some("Provisional definition (needs_review): await live verification.".to_owned());
        assert!(contradicted.validate().is_err());
        let mut report = CorpusLintReport::default();
        lint_definitions(&[contradicted], &mut report);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("provisional/unverified")),
            "lint must flag live_verified with provisional notes"
        );
    }

    #[test]
    fn corpus_rejects_suspicious_url_equivalence_and_category_drift() {
        let mut first = definition();
        first.metadata.id = "lint-x".to_owned();
        first.profile_url = "https://example.test/{username}".to_owned();
        let mut second = definition();
        second.metadata.id = "lint-y".to_owned();
        second.profile_url = "https://EXAMPLE.test/{username}/".to_owned();
        let mut report = CorpusLintReport::default();
        lint_definitions(&[first, second], &mut report);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("suspiciously equivalent")),
            "expected equivalence error, got {report:?}"
        );
        let mut drifted = definition();
        drifted.metadata.id = "lint-z".to_owned();
        drifted.category = "social".to_owned();
        drifted.metadata.source_category = "developer".to_owned();
        assert!(drifted.validate().is_err());
    }

    #[test]
    fn scheduler_scales_to_thousand_mock_providers_with_exact_accounting() {
        // 1000 in-memory providers (no network): proves provider count never
        // equals concurrency, ordering stays stable, and accounting is exact.
        let base = definition().metadata;
        for count in [100usize, 250, 500, 1000] {
            let providers: Vec<Box<dyn SearchProvider>> = (0..count)
                .map(|index| {
                    Box::new(FixtureProvider {
                        metadata: ProviderMetadata {
                            id: format!("scale-{index:04}"),
                            ..base.clone()
                        },
                        status: if index % 10 == 0 {
                            SearchStatus::Confirmed
                        } else {
                            SearchStatus::NotFound
                        },
                    }) as Box<dyn SearchProvider>
                })
                .collect();
            let entity = SearchEntity::username("Rx", 1).unwrap();
            let mut scheduler = SearchScheduler {
                max_providers: count,
                max_concurrency: 8,
                max_per_host: 2,
                deadline: Instant::now() + Duration::from_secs(30),
                rate_limiter: RateLimiter::new(0),
            };
            let started = Instant::now();
            let (results, accounting) = scheduler.run(&providers, &entity, &AtomicBool::new(false));
            let wall = started.elapsed();
            assert_eq!(accounting.providers_requested, count);
            assert_eq!(
                accounting.accounted(),
                count,
                "accounting must reconcile at {count}"
            );
            assert_eq!(accounting.providers_completed, count);
            assert!(
                results
                    .windows(2)
                    .all(|pair| pair[0].provider_id <= pair[1].provider_id),
                "ordering must stay deterministic at {count}"
            );
            eprintln!("scale: providers={count} wall={wall:?}");
            assert!(
                wall < Duration::from_secs(30),
                "scheduler stalled at {count}"
            );
        }
    }

    #[test]
    fn short_deadline_preserves_partial_results_at_scale() {
        // A deliberately expired deadline contacts nothing but still
        // accounts exactly; a zero-remaining deadline never drains providers.
        let base = definition().metadata;
        let providers: Vec<Box<dyn SearchProvider>> = (0..200)
            .map(|index| {
                Box::new(FixtureProvider {
                    metadata: ProviderMetadata {
                        id: format!("deadline-{index:03}"),
                        ..base.clone()
                    },
                    status: SearchStatus::Confirmed,
                }) as Box<dyn SearchProvider>
            })
            .collect();
        let entity = SearchEntity::username("Rx", 1).unwrap();
        let mut scheduler = SearchScheduler {
            max_providers: 200,
            max_concurrency: 8,
            max_per_host: 2,
            deadline: Instant::now(),
            rate_limiter: RateLimiter::new(0),
        };
        let (results, accounting) = scheduler.run(&providers, &entity, &AtomicBool::new(false));
        assert!(results.is_empty());
        assert_eq!(accounting.accounted(), 200);
        assert!(accounting.truncated);
    }

    #[test]
    fn cancelled_mass_search_retains_completed_work() {
        let base = definition().metadata;
        let providers: Vec<Box<dyn SearchProvider>> = (0..100)
            .map(|index| {
                Box::new(FixtureProvider {
                    metadata: ProviderMetadata {
                        id: format!("cancel-{index:03}"),
                        ..base.clone()
                    },
                    status: SearchStatus::NotFound,
                }) as Box<dyn SearchProvider>
            })
            .collect();
        let entity = SearchEntity::username("Rx", 1).unwrap();
        let cancelled = AtomicBool::new(true);
        let mut scheduler = SearchScheduler {
            max_providers: 100,
            max_concurrency: 8,
            max_per_host: 2,
            deadline: Instant::now() + Duration::from_secs(30),
            rate_limiter: RateLimiter::new(0),
        };
        let (results, accounting) = scheduler.run(&providers, &entity, &cancelled);
        assert!(results.is_empty());
        assert_eq!(accounting.cancelled, 100);
        assert_eq!(accounting.accounted(), 100);
    }

    #[test]
    fn captcha_noise_in_page_content_never_blocks() {
        // Regression: the bare `captcha` block marker once matched ordinary
        // script/bundle tokens (e.g. `octocaptcha_*` on GitHub) and turned
        // every live confirmation into `Blocked`. Innocent captcha-adjacent
        // content must stay unblocked on all providers.
        let pack = embedded_username_pack().unwrap();
        let noise = "asset octocaptcha_origin_optimization bundle captchaToken verified";
        for provider in &pack.providers {
            let status = provider
                .classify(
                    &ProviderResponse {
                        status: 200,
                        body: noise.to_owned(),
                    },
                    "exampleuser",
                )
                .status;
            assert_ne!(
                status,
                SearchStatus::Blocked,
                "{} treats captcha noise as a block page",
                provider.metadata.id
            );
        }
    }

    #[test]
    fn civil_date_math_and_staleness_are_derived() {
        assert_eq!(days_to_civil(0), (1970, 1, 1));
        assert_eq!(days_to_civil(20361), (2025, 9, 30));
        assert_eq!(days_to_civil(20366), (2025, 10, 5));
        assert_eq!(days_to_civil(-1), (1969, 12, 31));
        assert!(verification_stale(
            &HealthState::LiveVerified,
            Some("2025-01-01"),
            "2025-10-05"
        ));
        assert!(!verification_stale(
            &HealthState::LiveVerified,
            Some("2025-10-05"),
            "2025-10-05"
        ));
        assert!(!verification_stale(
            &HealthState::NeedsReview,
            None,
            "2025-10-05"
        ));
        assert!(!verification_stale(
            &HealthState::LiveVerified,
            None,
            "2025-10-05"
        ));
        let cutoff = stale_cutoff(180);
        assert_eq!(cutoff.len(), 10);
        assert!(cutoff < stale_cutoff(0));
    }

    #[test]
    fn provider_pack_parser_is_versioned_and_bounded() {
        let json = serde_json::json!({
            "schema_version": 1,
            "pack_version": "fixture-v1",
            "providers": [definition()]
        });
        assert_eq!(
            parse_provider_pack(&json.to_string(), "fixture")
                .unwrap()
                .providers
                .len(),
            1
        );
        let mut future = json;
        future["schema_version"] = 2.into();
        assert!(parse_provider_pack(&future.to_string(), "future").is_err());
        assert!(parse_provider_pack("{", "broken").is_err());
    }

    #[test]
    fn every_embedded_provider_has_stored_positive_negative_generic_and_block_fixtures() {
        #[derive(Deserialize)]
        struct FixtureFile {
            provider: String,
            cases: Vec<FixtureCase>,
        }
        #[derive(Deserialize)]
        struct FixtureCase {
            name: String,
            status: u16,
            body: String,
            expected: String,
        }
        let pack = embedded_username_pack().unwrap();
        assert!(
            !pack.providers.is_empty(),
            "registry must hold real providers"
        );
        for provider in pack.providers {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("search/fixtures/username")
                .join(&provider.metadata.id)
                .join("cases.json");
            let fixtures: FixtureFile =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            assert_eq!(fixtures.provider, provider.metadata.id);
            let names = fixtures
                .cases
                .iter()
                .map(|case| case.name.as_str())
                .collect::<BTreeSet<_>>();
            for required in ["found", "not-found", "generic-200", "blocked"] {
                assert!(
                    names.contains(required),
                    "{} lacks {required}",
                    fixtures.provider
                );
            }
            for case in fixtures.cases {
                let expected = match case.expected.as_str() {
                    "confirmed" => SearchStatus::Confirmed,
                    "not_found" => SearchStatus::NotFound,
                    "possible" => SearchStatus::Possible,
                    "blocked" => SearchStatus::Blocked,
                    other => panic!("unsupported fixture expectation {other}"),
                };
                assert_eq!(
                    provider
                        .classify(
                            &ProviderResponse {
                                status: case.status,
                                body: case.body,
                            },
                            "Rx",
                        )
                        .status,
                    expected,
                    "{} fixture {}",
                    provider.metadata.id,
                    case.name
                );
            }
        }
    }

    #[test]
    fn username_substitution_is_encoded_and_case_preserving() {
        let provider = definition();
        let url = provider_url(&provider, "R x/雪", false).unwrap();
        assert_eq!(url.as_str(), "https://example.test/R%20x%2F%E9%9B%AA");
        assert!(provider_url(&provider, &"x".repeat(129), false).is_err());
        let mut unsafe_provider = provider;
        unsafe_provider.profile_url = "https://127.0.0.1/{username}".to_owned();
        assert!(unsafe_provider.validate().is_err());
        assert!(
            validate_public_url(&url::Url::parse("file:///etc/passwd").unwrap(), false).is_err()
        );
    }

    #[test]
    fn shared_client_and_executor_confirm_only_with_identity_evidence() {
        let body = b"<meta data-profile=\"rx\" rel=\"canonical\">";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        )
        .into_bytes();
        let (url, server) = fixture_http(response);
        let mut definition = definition();
        definition.profile_url = url;
        let provider = DefinitionProvider {
            definition,
            client: Arc::new(local_test_client()),
        };
        let seed = SearchEntity::username("Rx", 1).unwrap();
        let cancelled = AtomicBool::new(false);
        let observation = provider
            .search(
                &SearchContext {
                    deadline: Instant::now() + Duration::from_secs(2),
                    cancelled: &cancelled,
                },
                &seed,
            )
            .unwrap();
        server.join().unwrap();
        assert_eq!(observation.status, SearchStatus::Confirmed);
        assert_eq!(observation.contact_class, ContactClass::PublicHttp);
        assert_eq!(observation.attributes["redirect_count"], "0");
    }

    #[test]
    fn shared_client_stops_reading_after_the_body_limit() {
        let body = "x".repeat(33);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes();
        let (url, server) = fixture_http(response);
        let url = provider_url(
            &UsernameProviderDefinition {
                profile_url: url,
                ..definition()
            },
            "Rx",
            true,
        )
        .unwrap();
        let cancelled = AtomicBool::new(false);
        let response = local_test_client()
            .get(
                &url,
                Duration::from_secs(2),
                32,
                0,
                &SearchContext {
                    deadline: Instant::now() + Duration::from_secs(2),
                    cancelled: &cancelled,
                },
            )
            .unwrap();
        server.join().unwrap();
        assert!(response.body_truncated);
        assert_eq!(response.body.len(), 32);
    }

    struct FixedResolver(Vec<SocketAddr>);

    impl SearchResolver for FixedResolver {
        fn resolve(&self, _: &str, _: u16) -> Result<Vec<SocketAddr>, SearchError> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn resolved_nonpublic_addresses_are_rejected_before_connection() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "2001:db8::1",
            "fe80::1",
        ] {
            let address = SocketAddr::new(ip.parse().unwrap(), 443);
            let client = SharedHttpClient {
                clients: Arc::new(Mutex::new(BTreeMap::new())),
                resolver: Arc::new(FixedResolver(vec![address])),
                allow_nonpublic: false,
            };
            let error = client
                .client_for(&url::Url::parse("https://profiles.example/Rx").unwrap())
                .unwrap_err();
            assert!(matches!(error, SearchError::UnsafeUrl(_)), "{ip}");
        }
    }

    #[test]
    fn every_resolved_address_must_be_public() {
        let client = SharedHttpClient {
            clients: Arc::new(Mutex::new(BTreeMap::new())),
            resolver: Arc::new(FixedResolver(vec![
                "93.184.216.34:443".parse().unwrap(),
                "127.0.0.1:443".parse().unwrap(),
            ])),
            allow_nonpublic: false,
        };
        assert!(matches!(
            client.client_for(&url::Url::parse("https://profiles.example/Rx").unwrap()),
            Err(SearchError::UnsafeUrl(_))
        ));
    }

    fn redirect_fixture(
        location: &str,
        limit: u8,
        accepts: usize,
    ) -> Result<BoundedHttpResponse, SearchError> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let location = location.replace("{authority}", &address.to_string());
        let handle = std::thread::spawn(move || {
            for _ in 0..accepts {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 2048];
                let _ = stream.read(&mut request);
                write!(
                    stream,
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
            }
        });
        let cancelled = AtomicBool::new(false);
        let result = local_test_client().get(
            &url::Url::parse(&format!("http://{address}/start")).unwrap(),
            Duration::from_secs(2),
            32,
            limit,
            &SearchContext {
                deadline: Instant::now() + Duration::from_secs(2),
                cancelled: &cancelled,
            },
        );
        handle.join().unwrap();
        result
    }

    /// Serve one canned response per connection on loopback.
    fn serve_many(
        responses: Vec<Vec<u8>>,
        connections: usize,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<usize>) {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut served = 0usize;
            for _ in 0..connections {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request);
                let body = &responses[served % responses.len()];
                if stream.write_all(body).is_err() {
                    break;
                }
                served += 1;
            }
            served
        });
        (address, handle)
    }

    #[test]
    fn absence_redirect_beats_auth_wall_with_evidence() {
        // Chain: profile URL 302s to a login wall that matches BOTH the
        // absence and the authentication markers. Absence must win.
        use std::io::{Read as _, Write as _};
        let wall = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let wall_address = wall.local_addr().unwrap();
        let wall_handle = std::thread::spawn(move || {
            let (mut stream, _) = wall.accept().unwrap();
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);
            let body = b"sign in to continue";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                String::from_utf8_lossy(body)
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        let gate = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let gate_address = gate.local_addr().unwrap();
        let gate_handle = std::thread::spawn(move || {
            let (mut stream, _) = gate.accept().unwrap();
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{wall_address}/signin-wall\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        let mut definition = definition();
        definition.profile_url = format!("http://{gate_address}/{{username}}");
        definition.absence_redirect_markers = vec!["/signin-wall".to_owned()];
        definition.authentication_url_markers = vec!["/signin-wall".to_owned()];
        let provider = DefinitionProvider {
            definition,
            client: Arc::new(local_test_client()),
        };
        let seed = SearchEntity::username("Rx", 1).unwrap();
        let cancelled = AtomicBool::new(false);
        let observation = provider
            .search(
                &SearchContext {
                    deadline: Instant::now() + Duration::from_secs(5),
                    cancelled: &cancelled,
                },
                &seed,
            )
            .unwrap();
        gate_handle.join().unwrap();
        wall_handle.join().unwrap();
        assert_eq!(observation.status, SearchStatus::NotFound);
        assert!(
            observation
                .evidence
                .iter()
                .any(|evidence| evidence.contains("absence destination")),
            "evidence: {:?}",
            observation.evidence
        );
    }

    #[test]
    fn retry_after_survives_rate_limit_classification() {
        let body = b"slow down";
        let response = format!(
            "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        )
        .into_bytes();
        let (url, server) = fixture_http(response);
        let mut definition = definition();
        definition.profile_url = url;
        let provider = DefinitionProvider {
            definition,
            client: Arc::new(local_test_client()),
        };
        let seed = SearchEntity::username("Rx", 1).unwrap();
        let cancelled = AtomicBool::new(false);
        let observation = provider
            .search(
                &SearchContext {
                    deadline: Instant::now() + Duration::from_secs(5),
                    cancelled: &cancelled,
                },
                &seed,
            )
            .unwrap();
        server.join().unwrap();
        assert_eq!(observation.status, SearchStatus::RateLimited);
        assert_eq!(
            observation
                .attributes
                .get("retry_after")
                .map(String::as_str),
            Some("120")
        );
    }

    #[test]
    fn cancelled_in_flight_search_counts_cancelled() {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);
            std::thread::sleep(Duration::from_millis(400));
            let body = b"too late";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                String::from_utf8_lossy(body)
            );
            let _ = stream.write_all(response.as_bytes());
        });
        let mut definition = definition();
        definition.profile_url = format!("http://{address}/{{username}}");
        let provider = DefinitionProvider {
            definition,
            client: Arc::new(local_test_client()),
        };
        let seed = SearchEntity::username("Rx", 1).unwrap();
        let cancelled = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                provider.search(
                    &SearchContext {
                        deadline: Instant::now() + Duration::from_secs(10),
                        cancelled: &cancelled,
                    },
                    &seed,
                )
            });
            std::thread::sleep(Duration::from_millis(50));
            cancelled.store(true, Ordering::Release);
            assert!(matches!(
                handle.join().unwrap(),
                Err(SearchError::Cancelled)
            ));
        });
        server.join().unwrap();
    }

    #[test]
    fn connection_failure_is_error_never_absence() {
        // Nothing listens here: refused connections must error, never read
        // as "account does not exist".
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = probe.local_addr().unwrap();
        drop(probe);
        let mut definition = definition();
        definition.profile_url = format!("http://{address}/{{username}}");
        let provider = DefinitionProvider {
            definition,
            client: Arc::new(local_test_client()),
        };
        let seed = SearchEntity::username("Rx", 1).unwrap();
        let cancelled = AtomicBool::new(false);
        assert!(matches!(
            provider.search(
                &SearchContext {
                    deadline: Instant::now() + Duration::from_secs(5),
                    cancelled: &cancelled,
                },
                &seed,
            ),
            Err(SearchError::Http(_))
        ));
    }

    /// Deterministic local benchmark at scale `count`: one loopback
    /// request per mock provider. Returns wall time and served request
    /// count. No public network involved.
    fn bench_mock_search(count: usize) -> (std::time::Duration, usize) {
        let found = b"<meta data-profile=\"rx\" rel=\"canonical\">";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            found.len(),
            String::from_utf8_lossy(found)
        )
        .into_bytes();
        // Every mock provider points at a shared loopback server. The
        // response carries the shared fixture markers, so all confirm.
        let client = Arc::new(local_test_client());
        let (address, server) = serve_many(vec![response], count);
        let entity = SearchEntity::username("Rx", 1).unwrap();
        let started = Instant::now();
        let mut scheduler = SearchScheduler {
            max_providers: count,
            max_concurrency: 8,
            max_per_host: 2,
            deadline: Instant::now() + Duration::from_secs(60),
            rate_limiter: RateLimiter::new(0),
        };
        let base = definition();
        let pointed: Vec<Box<dyn SearchProvider>> = (0..count)
            .map(|index| {
                let mut item = base.clone();
                item.metadata.id = format!("bench-{index:04}");
                item.profile_url = format!("http://{address}/bench-{index:04}/{{username}}");
                Box::new(DefinitionProvider {
                    definition: item,
                    client: client.clone(),
                }) as Box<dyn SearchProvider>
            })
            .collect();
        let (results, accounting) = scheduler.run(&pointed, &entity, &AtomicBool::new(false));
        let wall = started.elapsed();
        let served = server.join().unwrap();
        assert_eq!(served, pointed.len(), "one request per provider");
        assert_eq!(accounting.providers_requested, pointed.len());
        assert_eq!(accounting.accounted(), pointed.len());
        assert_eq!(accounting.providers_completed, pointed.len());
        assert!(
            results
                .windows(2)
                .all(|pair| pair[0].provider_id <= pair[1].provider_id),
            "result ordering stays deterministic under concurrency"
        );
        (wall, served)
    }

    #[test]
    fn mock_scale_benchmark_matrix() {
        // Scheduler/concurrency scale at milestone sizes against loopback.
        for count in [50, 100] {
            let (wall, served) = bench_mock_search(count);
            assert!(
                wall < Duration::from_secs(60),
                "{count} loopback providers took {wall:?}"
            );
            eprintln!("bench: mock{count}_wall={wall:?} mock{count}_requests={served}");
        }

        let pack_started = Instant::now();
        let pack = embedded_username_pack().unwrap();
        let pack_elapsed = pack_started.elapsed();
        let validate_started = Instant::now();
        validate_definitions(&pack.providers).unwrap();
        let validate_elapsed = validate_started.elapsed();
        let classify_started = Instant::now();
        let mut classified = 0usize;
        for provider in &pack.providers {
            for body in [
                format!(
                    "{} {}",
                    provider.success.required.join(" "),
                    provider.success.any.join(" ")
                ),
                "generic directory listing".to_owned(),
            ] {
                let _ = provider.classify(&ProviderResponse { status: 200, body }, "exampleuser");
                classified += 1;
            }
        }
        let classify_elapsed = classify_started.elapsed();
        eprintln!(
            "bench: pack_load={pack_elapsed:?} validate={validate_elapsed:?} classify_all={classify_elapsed:?}({classified} cases)"
        );
    }

    #[test]
    fn redirect_limits_and_destinations_are_revalidated() {
        assert!(matches!(
            redirect_fixture("http://{authority}/loop", 1, 2),
            Err(SearchError::RedirectLimitExceeded)
        ));
        assert!(matches!(
            redirect_fixture("file:///etc/passwd", 0, 1),
            Err(SearchError::UnsupportedRedirectScheme(_))
        ));
        assert!(matches!(
            redirect_fixture("file:///etc/passwd", 1, 1),
            Err(SearchError::UnsupportedRedirectScheme(_))
        ));
        assert!(matches!(
            redirect_fixture("http://[invalid", 1, 1),
            Err(SearchError::MalformedRedirect(_))
        ));
    }

    #[test]
    fn response_status_matrix_stays_non_boolean() {
        let provider = definition();
        for (status, expected) in [
            (401, SearchStatus::AuthenticationRequired),
            (403, SearchStatus::Blocked),
            (404, SearchStatus::NotFound),
            (410, SearchStatus::Unknown),
            (429, SearchStatus::RateLimited),
            (500, SearchStatus::Unknown),
            (503, SearchStatus::Unknown),
        ] {
            assert_eq!(
                provider
                    .classify(
                        &ProviderResponse {
                            status,
                            body: Vec::from([0xff, 0xfe])
                                .into_iter()
                                .map(char::from)
                                .collect(),
                        },
                        "Rx",
                    )
                    .status,
                expected
            );
        }
    }

    #[test]
    fn username_report_persists_graph_coverage_and_provider_provenance() {
        let seed = SearchEntity::username("Rx", 10).unwrap();
        let observation = SearchObservation {
            provider_id: "fixture-dev".to_owned(),
            provider_version: "1".to_owned(),
            task_id: "search-task-fixture".to_owned(),
            input_entity_id: seed.id.clone(),
            contact_class: ContactClass::PublicHttp,
            status: SearchStatus::Confirmed,
            confidence: 94,
            timestamp: 10,
            evidence: vec!["canonical username matched".to_owned()],
            attributes: BTreeMap::from([
                ("platform".to_owned(), "Fixture Dev".to_owned()),
                ("final_url".to_owned(), "https://example.test/Rx".to_owned()),
            ]),
        };
        let mut graph = crate::graph::ScanGraph::default();
        add_username_observation_to_graph(&mut graph, &seed, &observation).unwrap();
        let report = UsernameSearchReport {
            schema_version: 1,
            run_id: "search-run-fixture".to_owned(),
            seed,
            provider_pack_version: "fixture-v1".to_owned(),
            accounting: SearchAccounting {
                providers_requested: 1,
                providers_completed: 1,
                counts: BTreeMap::from([(SearchStatus::Confirmed, 1)]),
                ..SearchAccounting::default()
            },
            results: vec![observation],
            graph,
            network_scans: 0,
            started_at: 10,
            completed_at: 11,
        };
        let mut db = crate::project_db::ProjectDb::open_in_memory().unwrap();
        let stats = persist_username_report(&mut db, &report).unwrap();
        assert_eq!(db.scan_ids().unwrap(), vec!["search-run-fixture"]);
        assert_eq!(stats.relationships_upserted, 1);
        let coverage = db.coverage_of("search-run-fixture").unwrap();
        assert_eq!(
            coverage.modules_completed,
            vec!["search.provider.fixture-dev.confirmed"]
        );
    }

    struct FixtureProvider {
        metadata: ProviderMetadata,
        status: SearchStatus,
    }
    impl SearchProvider for FixtureProvider {
        fn metadata(&self) -> &ProviderMetadata {
            &self.metadata
        }
        fn search(
            &self,
            _: &SearchContext<'_>,
            entity: &SearchEntity,
        ) -> Result<SearchObservation, SearchError> {
            Ok(SearchObservation {
                provider_id: self.metadata.id.clone(),
                provider_version: self.metadata.version.clone(),
                task_id: task_id(&self.metadata, entity),
                input_entity_id: entity.id.clone(),
                contact_class: self.metadata.contact_class,
                status: self.status,
                confidence: 0,
                timestamp: entity.last_observed,
                evidence: vec![],
                attributes: BTreeMap::new(),
            })
        }
    }

    #[test]
    fn scheduler_accounting_is_exact_and_budgeted() {
        let base = definition().metadata;
        let providers: Vec<Box<dyn SearchProvider>> = (0..3)
            .map(|index| {
                Box::new(FixtureProvider {
                    metadata: ProviderMetadata {
                        id: format!("fixture-{index}"),
                        ..base.clone()
                    },
                    status: SearchStatus::NotFound,
                }) as Box<dyn SearchProvider>
            })
            .collect();
        let entity = SearchEntity::username("Rx", 1).unwrap();
        let mut scheduler = SearchScheduler {
            max_providers: 2,
            max_concurrency: 2,
            max_per_host: 1,
            deadline: Instant::now() + Duration::from_secs(1),
            rate_limiter: RateLimiter::new(0),
        };
        let (results, accounting) = scheduler.run(&providers, &entity, &AtomicBool::new(false));
        assert_eq!(results.len(), 2);
        assert_eq!(accounting.providers_requested, 3);
        assert_eq!(accounting.accounted(), 3);
        assert_eq!(accounting.unscanned, 1);
        assert!(accounting.truncated);
    }

    #[test]
    fn expired_deadline_contacts_nothing() {
        let provider: Box<dyn SearchProvider> = Box::new(FixtureProvider {
            metadata: definition().metadata,
            status: SearchStatus::Confirmed,
        });
        let entity = SearchEntity::username("Rx", 1).unwrap();
        let mut scheduler = SearchScheduler {
            max_providers: 1,
            max_concurrency: 1,
            max_per_host: 1,
            deadline: Instant::now() - Duration::from_millis(1),
            rate_limiter: RateLimiter::new(0),
        };
        let (results, accounting) = scheduler.run(&[provider], &entity, &AtomicBool::new(false));
        assert!(results.is_empty());
        assert_eq!(accounting.unscanned, 1);
        assert_eq!(accounting.accounted(), 1);
    }

    #[test]
    fn account_observation_enters_graph_without_identity_merge() {
        let input = SearchEntity::username("Rx", 10).unwrap();
        let mut attributes = BTreeMap::new();
        attributes.insert("platform".to_owned(), "Fixture Dev".to_owned());
        attributes.insert(
            "profile_url".to_owned(),
            "https://example.test/Rx".to_owned(),
        );
        let observation = SearchObservation {
            provider_id: "fixture-dev".to_owned(),
            provider_version: "1".to_owned(),
            task_id: "task".to_owned(),
            input_entity_id: input.id.clone(),
            contact_class: ContactClass::PublicHttp,
            status: SearchStatus::Confirmed,
            confidence: 94,
            timestamp: 10,
            evidence: vec!["canonical username matched".to_owned()],
            attributes,
        };
        let mut graph = crate::graph::ScanGraph::default();
        let account = add_username_observation_to_graph(&mut graph, &input, &observation).unwrap();
        assert_ne!(account, input.id);
        assert_eq!(graph.entity_count(), 2);
        assert_eq!(graph.edge_count(), 1);
        assert_eq!(
            graph.edges[0].relation,
            crate::graph::EdgeRelation::HasAccount
        );
        assert_eq!(graph.edges[0].confidence, 94);
    }
}
