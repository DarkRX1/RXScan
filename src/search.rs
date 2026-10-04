use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROVIDER_SCHEMA_VERSION: u32 = 1;
pub const MAX_PROVIDER_DEFINITIONS: usize = 2_000;
pub const MAX_SEARCH_EVIDENCE: usize = 8;
pub const MAX_SEARCH_BODY_BYTES: usize = 256 * 1024;
pub const MAX_SEARCH_HEADERS: usize = 32;
pub const SEARCH_USER_AGENT: &str = "RXScan/0.1 public-search";
pub const USERNAME_PROVIDER_CATEGORIES: &[&str] = &[
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
];

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
    if json.len() > 4 * 1024 * 1024 {
        return Err(SearchError::InvalidProvider(format!(
            "provider pack '{source}' exceeds 4 MiB"
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
pub struct MarkerPolicy {
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub any: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
            ("profile_url".to_owned(), url.to_string()),
            ("final_url".to_owned(), response.final_url.clone()),
            ("body_sha256".to_owned(), body_hash),
            ("http_status".to_owned(), response.status.to_string()),
            (
                "redirect_count".to_owned(),
                response.redirect_count.to_string(),
            ),
            ("elapsed_ms".to_owned(), response.elapsed_ms.to_string()),
        ]);
        let classification = if response.body_truncated {
            SearchClassification::new(
                SearchStatus::Unknown,
                0,
                "response exceeded configured body limit",
            )
        } else if self
            .definition
            .authentication_url_markers
            .iter()
            .any(|marker| {
                response
                    .final_url
                    .to_ascii_lowercase()
                    .contains(&marker.to_ascii_lowercase())
            })
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

#[allow(private_interfaces)]
pub struct SearchScheduler {
    pub max_providers: usize,
    pub max_concurrency: usize,
    pub max_per_host: usize,
    pub deadline: Instant,
    pub(crate) rate_limiter: RateLimiter,
}

impl SearchScheduler {
    pub fn run(
        &mut self,
        providers: &[Box<dyn SearchProvider>],
        entity: &SearchEntity,
        cancelled: &AtomicBool,
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
    if definitions.len() > MAX_PROVIDER_DEFINITIONS {
        return Err(SearchError::InvalidProvider(
            "provider pack exceeds definition limit".to_owned(),
        ));
    }
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
        include_str!("../search/providers/v1/username.json"),
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
    let started_at = unix_timestamp();
    let seed = SearchEntity::username(username, started_at)?;
    let pack = embedded_username_pack()?;
    let pack_version = pack.pack_version.clone();
    let client = Arc::new(SharedHttpClient::new()?);
    let mut providers: Vec<Box<dyn SearchProvider>> = Vec::new();
    for definition in pack.providers {
        if selected.is_some_and(|ids| !ids.contains(&definition.metadata.id)) {
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
    let (results, accounting) = scheduler.run(&providers, &seed, cancelled);
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
                path: "embedded:search/providers/v1/username.json".to_owned(),
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
        assert_eq!(pack.providers.len(), 10);
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
            (429, SearchStatus::RateLimited),
            (500, SearchStatus::Unknown),
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
