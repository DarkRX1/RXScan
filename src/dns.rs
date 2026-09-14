//! Phase 13 DNS / asset intelligence.
//!
//! Native bounded UDP DNS queries for A/AAAA/CNAME plus lightweight MX/NS/TXT
//! and PTR observations at higher levels. This is asset intelligence only:
//! no brute-force subdomain enumeration, no zone transfers, and no active
//! follow-up outside the Decision Engine.

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use crate::{
    execution::{
        CancellationToken, Module, ModuleContext, ModuleError, ModuleFuture, ModuleOutput,
        ScopeGuard, TaskKind, TaskScopeTarget,
    },
    model::{
        Asset, AssetId, AssetKind, BoundedDetails, Confidence, Event, EventKind, Evidence,
        MAX_EVENT_DETAILS_BYTES, Provenance, Relationship, RelationshipKind, RelationshipSubject,
        Timestamp,
    },
    plan::{ScanGoal, SpeedSetting},
};

pub const DNS_MODULE_NAME: &str = "rxscan.dns";
pub const DNS_MODULE_VERSION: &str = "13.0.0";
pub const MAX_DNS_PACKET_BYTES: usize = 512;
pub const MAX_DNS_RECORDS_PER_RESPONSE: usize = 16;
pub const MAX_DNS_RECORDS_PER_TASK: usize = 48;
pub const MAX_DNS_EVENTS_PER_TASK: usize = 64;
pub const MAX_DNS_EVIDENCE_PER_TASK: usize = 32;
pub const MAX_CNAME_HOPS: usize = 8;
pub const MAX_TXT_RECORD_BYTES: usize = 256;
pub const MAX_TXT_TOTAL_BYTES: usize = 1024;
pub const MAX_DNS_REGISTRY_ENTRIES: usize = 4096;
pub const MAX_DNS_DOMAINS: usize = 256;
pub const MAX_DNS_TASKS_PER_DOMAIN_HARD: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Txt,
    Ptr,
}

impl DnsRecordType {
    pub fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Ptr => 12,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Aaaa => 28,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Mx => "MX",
            Self::Ns => "NS",
            Self::Txt => "TXT",
            Self::Ptr => "PTR",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsOutcome {
    Resolved,
    NoData,
    NxDomain,
    Truncated,
    Timeout,
    ServFail,
    Refused,
    MalformedResponse,
    TransportError,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: DnsRecordType,
    pub value: String,
    pub ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preference: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct DnsPolicy {
    pub level: u8,
    pub goal: ScanGoal,
    pub speed: SpeedSetting,
}

impl DnsPolicy {
    pub fn new(level: u8, goal: ScanGoal, speed: SpeedSetting) -> Self {
        Self {
            level: level.clamp(1, 5),
            goal,
            speed,
        }
    }

    pub fn record_types(&self) -> Vec<DnsRecordType> {
        match self.level {
            0..=2 => vec![DnsRecordType::A, DnsRecordType::Aaaa, DnsRecordType::Cname],
            3 => vec![
                DnsRecordType::A,
                DnsRecordType::Aaaa,
                DnsRecordType::Cname,
                DnsRecordType::Mx,
                DnsRecordType::Ns,
            ],
            _ => vec![
                DnsRecordType::A,
                DnsRecordType::Aaaa,
                DnsRecordType::Cname,
                DnsRecordType::Mx,
                DnsRecordType::Ns,
                DnsRecordType::Txt,
                DnsRecordType::Ptr,
            ],
        }
    }

    pub fn per_domain_limit(&self) -> usize {
        match self.level {
            0 | 1 => 4,
            2 => 8,
            3 => 16,
            _ => MAX_DNS_TASKS_PER_DOMAIN_HARD,
        }
    }

    pub fn timeout(&self) -> Duration {
        crate::service::service_timeout_for_speed(self.speed).min(Duration::from_secs(3))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DnsQueryKey {
    name: String,
    record_type: DnsRecordType,
    resolver: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQueryRegistryEntry {
    pub name: String,
    pub record_type: DnsRecordType,
    pub resolver: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsDomainRegistryEntry {
    pub domain: String,
    pub names: Vec<String>,
}

#[derive(Debug, Default)]
struct DnsRegistryState {
    queries: BTreeSet<DnsQueryKey>,
    domains: BTreeMap<String, BTreeSet<String>>,
    query_full: bool,
    domain_full: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DnsRegistry {
    state: Arc<Mutex<DnsRegistryState>>,
}

impl DnsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn claim_query(
        &self,
        name: &str,
        record_type: DnsRecordType,
        resolver: SocketAddr,
    ) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.query_full {
            return true;
        }
        let inserted = state.queries.insert(DnsQueryKey {
            name: name.to_owned(),
            record_type,
            resolver,
        });
        if state.queries.len() >= MAX_DNS_REGISTRY_ENTRIES {
            state.query_full = true;
        }
        inserted
    }

    pub fn forget_query(&self, name: &str, record_type: DnsRecordType, resolver: SocketAddr) {
        let mut state = self.state.lock().unwrap();
        state.queries.remove(&DnsQueryKey {
            name: name.to_owned(),
            record_type,
            resolver,
        });
    }

    pub fn query_count(&self) -> usize {
        self.state.lock().unwrap().queries.len()
    }

    pub fn domain_count(&self) -> usize {
        self.state.lock().unwrap().domains.len()
    }

    pub fn tracked_names_for_domain(&self, domain: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .domains
            .get(domain)
            .map(|names| names.len())
            .unwrap_or(0)
    }

    pub fn claim_domain_task(&self, domain: &str, name: &str, per_domain_limit: usize) -> bool {
        let mut state = self.state.lock().unwrap();
        if let Some(names) = state.domains.get_mut(domain) {
            if names.contains(name) {
                return true;
            }
            if names.len() >= per_domain_limit {
                return false;
            }
            names.insert(name.to_owned());
            return true;
        }
        if state.domain_full || state.domains.len() >= MAX_DNS_DOMAINS {
            state.domain_full = true;
            return false;
        }
        let mut names = BTreeSet::new();
        names.insert(name.to_owned());
        state.domains.insert(domain.to_owned(), names);
        true
    }

    pub fn snapshot_queries(&self) -> Vec<DnsQueryRegistryEntry> {
        self.state
            .lock()
            .unwrap()
            .queries
            .iter()
            .take(MAX_DNS_REGISTRY_ENTRIES)
            .map(|key| DnsQueryRegistryEntry {
                name: key.name.clone(),
                record_type: key.record_type,
                resolver: key.resolver,
            })
            .collect()
    }

    pub fn snapshot_domains(&self) -> Vec<DnsDomainRegistryEntry> {
        self.state
            .lock()
            .unwrap()
            .domains
            .iter()
            .take(MAX_DNS_DOMAINS)
            .map(|(domain, names)| DnsDomainRegistryEntry {
                domain: domain.clone(),
                names: names
                    .iter()
                    .take(MAX_DNS_TASKS_PER_DOMAIN_HARD)
                    .cloned()
                    .collect(),
            })
            .collect()
    }

    pub fn restore(
        queries: &[DnsQueryRegistryEntry],
        domains: &[DnsDomainRegistryEntry],
    ) -> Result<Self, String> {
        if queries.len() > MAX_DNS_REGISTRY_ENTRIES || domains.len() > MAX_DNS_DOMAINS {
            return Err("too many DNS registry entries".to_owned());
        }
        let registry = Self::new();
        for query in queries {
            if canonical_hostname(&query.name).is_err() {
                return Err("invalid DNS query name".to_owned());
            }
            registry.claim_query(&query.name, query.record_type, query.resolver);
        }
        for domain in domains {
            if domain.names.len() > MAX_DNS_TASKS_PER_DOMAIN_HARD
                || canonical_hostname(&domain.domain).is_err()
            {
                return Err("invalid DNS domain budget".to_owned());
            }
            for name in &domain.names {
                if !registry.claim_domain_task(&domain.domain, name, MAX_DNS_TASKS_PER_DOMAIN_HARD)
                {
                    return Err("invalid DNS domain budget".to_owned());
                }
            }
        }
        Ok(registry)
    }
}

pub fn canonical_hostname(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    let rooted = trimmed.strip_suffix('.').unwrap_or(trimmed);
    let host = rooted.to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 || host.contains('\0') || host.contains('/') {
        return Err("invalid hostname".to_owned());
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("invalid hostname label".to_owned());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("invalid hostname label".to_owned());
        }
        if !label
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        {
            return Err("invalid hostname character".to_owned());
        }
    }
    Ok(host)
}

pub fn domain_key(name: &str) -> String {
    let mut parts: Vec<&str> = name.split('.').collect();
    if parts.len() > 2 {
        parts = parts.split_off(parts.len() - 2);
    }
    parts.join(".")
}

pub struct DnsModule {
    policy: DnsPolicy,
    scope_guard: Arc<dyn ScopeGuard>,
    registry: DnsRegistry,
}

impl DnsModule {
    pub fn new(policy: DnsPolicy, scope_guard: Arc<dyn ScopeGuard>) -> Self {
        Self {
            policy,
            scope_guard,
            registry: DnsRegistry::new(),
        }
    }

    pub fn with_registry(
        policy: DnsPolicy,
        scope_guard: Arc<dyn ScopeGuard>,
        registry: DnsRegistry,
    ) -> Self {
        Self {
            policy,
            scope_guard,
            registry,
        }
    }
}

impl Module for DnsModule {
    fn kind(&self) -> TaskKind {
        TaskKind::DnsProbe
    }

    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let policy = self.policy.clone();
        let guard = self.scope_guard.clone();
        let registry = self.registry.clone();
        Box::pin(async move { execute_dns(&policy, guard.as_ref(), &registry, context) })
    }
}

fn execute_dns(
    policy: &DnsPolicy,
    guard: &dyn ScopeGuard,
    registry: &DnsRegistry,
    context: ModuleContext,
) -> Result<ModuleOutput, ModuleError> {
    let task = context.task.clone();
    let cancel = context.cancellation();
    if cancel.is_cancelled() {
        return Err(ModuleError::Cancelled);
    }
    if !guard.permits(&task.scope_target) {
        return Err(ModuleError::Failed {
            message: "stale scope rejected before DNS resolution".to_owned(),
            retryable: false,
        });
    }
    let started = Instant::now();
    let provenance = Provenance::new(
        DNS_MODULE_NAME,
        DNS_MODULE_VERSION,
        task.scan_plan_id.clone(),
        Timestamp::now(),
    )
    .map_err(|_| ModuleError::Failed {
        message: "invalid DNS provenance".to_owned(),
        retryable: false,
    })?;
    let hostname = match task
        .params
        .get("hostname")
        .or_else(|| task.params.get("target"))
    {
        Some(value) => canonical_hostname(value).map_err(|reason| ModuleError::Failed {
            message: reason,
            retryable: false,
        })?,
        None => match &task.scope_target {
            TaskScopeTarget::Host(host) => {
                canonical_hostname(host).map_err(|reason| ModuleError::Failed {
                    message: reason,
                    retryable: false,
                })?
            }
            TaskScopeTarget::Ip(ip) => ptr_query_name(*ip),
            _ => {
                return Err(ModuleError::Failed {
                    message: "DNS task missing hostname".to_owned(),
                    retryable: false,
                });
            }
        },
    };
    let resolver = resolver_from_params(&task.params).map_err(|message| ModuleError::Failed {
        message,
        retryable: false,
    })?;
    let requested = record_types_from_params(&task.params).unwrap_or_else(|| {
        if matches!(task.scope_target, TaskScopeTarget::Ip(_)) {
            vec![DnsRecordType::Ptr]
        } else {
            policy.record_types()
        }
    });
    let mut output = ModuleOutput::default();
    push_event(
        &mut output.events,
        EventKind::DnsResolutionStarted,
        None,
        serde_json::json!({"hostname": hostname, "resolver": resolver.to_string(), "record_types": requested.iter().map(|kind| kind.as_str()).collect::<Vec<_>>()}),
        &provenance,
    )?;
    let host_asset = ensure_asset(&mut output.assets, AssetKind::Host, &hostname, &provenance);
    let domain = domain_key(&hostname);
    if !registry.claim_domain_task(&domain, &hostname, policy.per_domain_limit()) {
        push_event(
            &mut output.events,
            EventKind::DnsBudgetExhausted,
            Some(host_asset.clone()),
            serde_json::json!({"hostname": hostname, "domain": domain, "reason": "per-domain-task-budget"}),
            &provenance,
        )?;
        push_event(
            &mut output.events,
            EventKind::DnsResolutionCompleted,
            Some(host_asset),
            serde_json::json!({"hostname": hostname, "records_retained": 0, "elapsed_ms": started.elapsed().as_millis() as u64}),
            &provenance,
        )?;
        return Ok(output);
    }
    let mut retained = 0usize;
    let mut txt_bytes = 0usize;
    for record_type in requested {
        if cancel.is_cancelled() {
            return Err(ModuleError::Cancelled);
        }
        if retained >= MAX_DNS_RECORDS_PER_TASK {
            push_event(
                &mut output.events,
                EventKind::DnsBudgetExhausted,
                Some(host_asset.clone()),
                serde_json::json!({"hostname": hostname, "reason": "records"}),
                &provenance,
            )?;
            break;
        }
        let mut current_name = hostname.clone();
        let mut cname_seen = BTreeSet::new();
        for hop in 0..MAX_CNAME_HOPS {
            if !registry.claim_query(&current_name, record_type, resolver) {
                break;
            }
            let response = query_udp(
                &current_name,
                record_type,
                resolver,
                policy.timeout(),
                &cancel,
            );
            let parsed = match response {
                Ok(packet) => match parse_dns_response(&packet, &current_name, record_type) {
                    Ok(parsed) => parsed,
                    Err(_) => {
                        registry.forget_query(&current_name, record_type, resolver);
                        push_query_failed(
                            &mut output,
                            &host_asset,
                            &current_name,
                            record_type,
                            DnsOutcome::MalformedResponse,
                            &provenance,
                        )?;
                        break;
                    }
                },
                Err(DnsOutcome::Cancelled) => return Err(ModuleError::Cancelled),
                Err(outcome) => {
                    if matches!(outcome, DnsOutcome::Timeout | DnsOutcome::TransportError) {
                        registry.forget_query(&current_name, record_type, resolver);
                    }
                    push_query_failed(
                        &mut output,
                        &host_asset,
                        &current_name,
                        record_type,
                        outcome,
                        &provenance,
                    )?;
                    break;
                }
            };
            if parsed.outcome != DnsOutcome::Resolved {
                push_query_failed(
                    &mut output,
                    &host_asset,
                    &current_name,
                    record_type,
                    parsed.outcome,
                    &provenance,
                )?;
                break;
            }
            let mut next_cname = None;
            let mut terminal = false;
            for record in parsed
                .records
                .into_iter()
                .take(MAX_DNS_RECORDS_PER_RESPONSE)
            {
                if retained >= MAX_DNS_RECORDS_PER_TASK {
                    break;
                }
                if record.record_type == DnsRecordType::Txt {
                    txt_bytes = txt_bytes.saturating_add(record.value.len());
                    if txt_bytes > MAX_TXT_TOTAL_BYTES {
                        break;
                    }
                }
                if record.record_type == DnsRecordType::Cname {
                    next_cname = Some(record.value.clone());
                }
                if matches!(record.record_type, DnsRecordType::A | DnsRecordType::Aaaa)
                    || record.record_type == record_type
                {
                    terminal = true;
                }
                retain_record(&mut output, &host_asset, &record, &provenance)?;
                retained += 1;
            }
            if !matches!(record_type, DnsRecordType::A | DnsRecordType::Aaaa) || terminal {
                break;
            }
            let Some(next) = next_cname else {
                break;
            };
            if !cname_seen.insert(next.clone()) {
                push_event(
                    &mut output.events,
                    EventKind::DnsBudgetExhausted,
                    Some(host_asset.clone()),
                    serde_json::json!({"hostname": hostname, "reason": "cname-loop"}),
                    &provenance,
                )?;
                break;
            }
            if hop + 1 >= MAX_CNAME_HOPS {
                push_event(
                    &mut output.events,
                    EventKind::DnsBudgetExhausted,
                    Some(host_asset.clone()),
                    serde_json::json!({"hostname": hostname, "reason": "cname-depth", "max_hops": MAX_CNAME_HOPS}),
                    &provenance,
                )?;
                break;
            }
            current_name = next;
        }
    }
    push_event(
        &mut output.events,
        EventKind::DnsResolutionCompleted,
        Some(host_asset),
        serde_json::json!({"hostname": hostname, "records_retained": retained, "elapsed_ms": started.elapsed().as_millis() as u64}),
        &provenance,
    )?;
    Ok(output)
}

fn retain_record(
    output: &mut ModuleOutput,
    host_asset: &AssetId,
    record: &DnsRecord,
    provenance: &Provenance,
) -> Result<(), ModuleError> {
    if record.record_type == DnsRecordType::Txt {
        let event = Event::new(
            EventKind::DnsRecordObserved,
            Some(host_asset.clone()),
            BoundedDetails::from_value(
                serde_json::json!({"name": record.name, "record_type": record.record_type, "value": record.value, "ttl": record.ttl, "preference": record.preference, "informational": true}),
                MAX_EVENT_DETAILS_BYTES,
            )
            .map_err(|_| ModuleError::Failed {
                message: "DNS event too large".to_owned(),
                retryable: false,
            })?,
            provenance.clone(),
        )
        .map_err(|_| ModuleError::Failed {
            message: "invalid DNS event".to_owned(),
            retryable: false,
        })?;
        if output.events.len() < MAX_DNS_EVENTS_PER_TASK {
            output.events.push(event);
        }
        if output.evidence.len() < MAX_DNS_EVIDENCE_PER_TASK {
            output.evidence.push(
                Evidence::new(
                    DNS_MODULE_NAME,
                    host_asset.clone(),
                    BoundedDetails::from_value(
                        serde_json::json!({"dns_record": record, "informational": true}),
                        crate::model::MAX_EVIDENCE_DETAILS_BYTES,
                    )
                    .map_err(|_| ModuleError::Failed {
                        message: "DNS evidence too large".to_owned(),
                        retryable: false,
                    })?,
                    Confidence::new(70).unwrap(),
                    provenance.clone(),
                )
                .map_err(|_| ModuleError::Failed {
                    message: "invalid DNS evidence".to_owned(),
                    retryable: false,
                })?,
            );
        }
        return Ok(());
    }
    let value_asset = match record.record_type {
        DnsRecordType::A | DnsRecordType::Aaaa => {
            ensure_asset(&mut output.assets, AssetKind::Ip, &record.value, provenance)
        }
        _ => ensure_asset(
            &mut output.assets,
            AssetKind::Host,
            &record.value,
            provenance,
        ),
    };
    let kind = match record.record_type {
        DnsRecordType::A | DnsRecordType::Aaaa => RelationshipKind::HostnameResolvesToIp,
        DnsRecordType::Cname => RelationshipKind::HostnameAliasesTo,
        DnsRecordType::Mx => RelationshipKind::MailExchangeFor,
        DnsRecordType::Ns => RelationshipKind::NameServerFor,
        DnsRecordType::Ptr => RelationshipKind::ReverseResolvesTo,
        DnsRecordType::Txt => unreachable!("TXT is handled as informational evidence"),
    };
    let mut event = Event::new(
        if record.record_type == DnsRecordType::Cname {
            EventKind::DnsAliasObserved
        } else if record.record_type == DnsRecordType::Ptr {
            EventKind::DnsReverseObserved
        } else {
            EventKind::DnsRecordObserved
        },
        Some(host_asset.clone()),
        BoundedDetails::from_value(
            serde_json::json!({"name": record.name, "record_type": record.record_type, "value": record.value, "ttl": record.ttl, "preference": record.preference}),
            MAX_EVENT_DETAILS_BYTES,
        )
        .map_err(|_| ModuleError::Failed {
            message: "DNS event too large".to_owned(),
            retryable: false,
        })?,
        provenance.clone(),
    )
    .map_err(|_| ModuleError::Failed {
        message: "invalid DNS event".to_owned(),
        retryable: false,
    })?;
    event.relationships.push(
        Relationship::new(
            kind,
            RelationshipSubject::Asset(host_asset.clone()),
            RelationshipSubject::Asset(value_asset),
            provenance.clone(),
        )
        .map_err(|_| ModuleError::Failed {
            message: "invalid DNS relationship".to_owned(),
            retryable: false,
        })?,
    );
    if output.events.len() < MAX_DNS_EVENTS_PER_TASK {
        output.events.push(event);
    }
    if output.evidence.len() < MAX_DNS_EVIDENCE_PER_TASK {
        output.evidence.push(
            Evidence::new(
                DNS_MODULE_NAME,
                host_asset.clone(),
                BoundedDetails::from_value(
                    serde_json::json!({"dns_record": record}),
                    crate::model::MAX_EVIDENCE_DETAILS_BYTES,
                )
                .map_err(|_| ModuleError::Failed {
                    message: "DNS evidence too large".to_owned(),
                    retryable: false,
                })?,
                Confidence::new(80).unwrap(),
                provenance.clone(),
            )
            .map_err(|_| ModuleError::Failed {
                message: "invalid DNS evidence".to_owned(),
                retryable: false,
            })?,
        );
    }
    Ok(())
}

fn ensure_asset(
    assets: &mut Vec<Asset>,
    kind: AssetKind,
    identity: &str,
    provenance: &Provenance,
) -> AssetId {
    let id = AssetId(format!(
        "asset_dns_{}_{}",
        match kind {
            AssetKind::Ip => "ip",
            _ => "host",
        },
        fnv_hex(identity)
    ));
    if !assets.iter().any(|asset| asset.id == id) {
        assets.push(Asset {
            schema_version: crate::model::SCHEMA_VERSION,
            id: id.clone(),
            kind,
            identity: identity.to_owned(),
            attributes: BTreeMap::new(),
            first_seen: provenance.timestamp,
            last_seen: provenance.timestamp,
            provenance: provenance.clone(),
        });
    }
    id
}

fn push_event(
    events: &mut Vec<Event>,
    kind: EventKind,
    asset_id: Option<AssetId>,
    data: serde_json::Value,
    provenance: &Provenance,
) -> Result<(), ModuleError> {
    if events.len() >= MAX_DNS_EVENTS_PER_TASK {
        return Ok(());
    }
    events.push(
        Event::new(
            kind,
            asset_id,
            BoundedDetails::from_value(data, MAX_EVENT_DETAILS_BYTES).map_err(|_| {
                ModuleError::Failed {
                    message: "DNS event too large".to_owned(),
                    retryable: false,
                }
            })?,
            provenance.clone(),
        )
        .map_err(|_| ModuleError::Failed {
            message: "invalid DNS event".to_owned(),
            retryable: false,
        })?,
    );
    Ok(())
}

fn push_query_failed(
    output: &mut ModuleOutput,
    asset_id: &AssetId,
    hostname: &str,
    record_type: DnsRecordType,
    outcome: DnsOutcome,
    provenance: &Provenance,
) -> Result<(), ModuleError> {
    push_event(
        &mut output.events,
        EventKind::DnsQueryFailed,
        Some(asset_id.clone()),
        serde_json::json!({"hostname": hostname, "record_type": record_type, "outcome": outcome}),
        provenance,
    )
}

fn resolver_from_params(params: &BTreeMap<String, String>) -> Result<SocketAddr, String> {
    if let Some(value) = params.get("resolver") {
        return value.parse().map_err(|_| "invalid resolver".to_owned());
    }
    let text = std::fs::read_to_string("/etc/resolv.conf").map_err(|e| e.to_string())?;
    resolver_from_resolv_conf(&text)
}

pub fn resolver_from_resolv_conf(text: &str) -> Result<SocketAddr, String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("nameserver") {
            if let Some(addr) = rest.split_whitespace().next() {
                let socket = if addr.contains(':') {
                    format!("[{addr}]:53")
                } else {
                    format!("{addr}:53")
                };
                if let Ok(parsed) = socket.parse() {
                    return Ok(parsed);
                }
            }
        }
    }
    Err("no resolver configured".to_owned())
}

fn record_types_from_params(params: &BTreeMap<String, String>) -> Option<Vec<DnsRecordType>> {
    params.get("record_types").map(|value| {
        value
            .split(',')
            .filter_map(|part| match part.trim().to_ascii_uppercase().as_str() {
                "A" => Some(DnsRecordType::A),
                "AAAA" => Some(DnsRecordType::Aaaa),
                "CNAME" => Some(DnsRecordType::Cname),
                "MX" => Some(DnsRecordType::Mx),
                "NS" => Some(DnsRecordType::Ns),
                "TXT" => Some(DnsRecordType::Txt),
                "PTR" => Some(DnsRecordType::Ptr),
                _ => None,
            })
            .take(8)
            .collect()
    })
}

fn query_udp(
    name: &str,
    record_type: DnsRecordType,
    resolver: SocketAddr,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<Vec<u8>, DnsOutcome> {
    if cancel.is_cancelled() {
        return Err(DnsOutcome::Cancelled);
    }
    let request = build_query(name, record_type)?;
    let bind = if resolver.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind).map_err(|_| DnsOutcome::TransportError)?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|_| DnsOutcome::TransportError)?;
    socket
        .set_write_timeout(Some(timeout))
        .map_err(|_| DnsOutcome::TransportError)?;
    socket
        .send_to(&request, resolver)
        .map_err(|_| DnsOutcome::TransportError)?;
    let started = Instant::now();
    let mut buf = [0u8; MAX_DNS_PACKET_BYTES];
    loop {
        if cancel.is_cancelled() {
            return Err(DnsOutcome::Cancelled);
        }
        match socket.recv_from(&mut buf) {
            Ok((len, _)) => return Ok(buf[..len].to_vec()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if started.elapsed() >= timeout {
                    return Err(DnsOutcome::Timeout);
                }
            }
            Err(_) => return Err(DnsOutcome::TransportError),
        }
    }
}

fn build_query(name: &str, record_type: DnsRecordType) -> Result<Vec<u8>, DnsOutcome> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&0x5258u16.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    encode_name(name, &mut out).map_err(|_| DnsOutcome::TransportError)?;
    out.extend_from_slice(&record_type.code().to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    Ok(out)
}

fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), String> {
    for label in name.trim_end_matches('.').split('.') {
        if label.len() > 63 {
            return Err("label too long".to_owned());
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

#[derive(Debug)]
pub struct ParsedDns {
    pub outcome: DnsOutcome,
    pub records: Vec<DnsRecord>,
}

pub fn parse_dns_response(
    packet: &[u8],
    question_name: &str,
    question_type: DnsRecordType,
) -> Result<ParsedDns, String> {
    if packet.len() < 12 {
        return Err("short DNS packet".to_owned());
    }
    if u16_at(packet, 0)? != 0x5258 {
        return Err("unexpected transaction id".to_owned());
    }
    let flags = u16_at(packet, 2)?;
    if flags & 0x0200 != 0 {
        return Ok(ParsedDns {
            outcome: DnsOutcome::Truncated,
            records: Vec::new(),
        });
    }
    let rcode = flags & 0x000f;
    let qd = u16_at(packet, 4)? as usize;
    let an = u16_at(packet, 6)? as usize;
    if qd != 1 {
        return Err("unexpected question count".to_owned());
    }
    let mut offset = 12usize;
    let parsed_q = read_name(packet, &mut offset)?;
    if parsed_q != question_name {
        return Err("wrong question".to_owned());
    }
    let qtype = u16_at(packet, offset)?;
    offset += 4;
    if qtype != question_type.code() {
        return Err("wrong question type".to_owned());
    }
    let outcome = match rcode {
        0 => {
            if an == 0 {
                DnsOutcome::NoData
            } else {
                DnsOutcome::Resolved
            }
        }
        3 => DnsOutcome::NxDomain,
        2 => DnsOutcome::ServFail,
        5 => DnsOutcome::Refused,
        _ => DnsOutcome::MalformedResponse,
    };
    if outcome != DnsOutcome::Resolved {
        return Ok(ParsedDns {
            outcome,
            records: Vec::new(),
        });
    }
    let mut records = Vec::new();
    for _ in 0..an.min(MAX_DNS_RECORDS_PER_RESPONSE) {
        let name = read_name(packet, &mut offset)?;
        let typ = u16_at(packet, offset)?;
        offset += 2;
        let class = u16_at(packet, offset)?;
        offset += 2;
        let ttl = u32_at(packet, offset)?;
        offset += 4;
        let rdlen = u16_at(packet, offset)? as usize;
        offset += 2;
        let end = offset.checked_add(rdlen).ok_or("overflow")?;
        if class != 1 || end > packet.len() {
            return Err("malformed rdata".to_owned());
        }
        let record = match typ {
            1 if rdlen == 4 => Some(DnsRecord {
                name,
                record_type: DnsRecordType::A,
                value: Ipv4Addr::new(
                    packet[offset],
                    packet[offset + 1],
                    packet[offset + 2],
                    packet[offset + 3],
                )
                .to_string(),
                ttl,
                preference: None,
            }),
            28 if rdlen == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&packet[offset..end]);
                Some(DnsRecord {
                    name,
                    record_type: DnsRecordType::Aaaa,
                    value: Ipv6Addr::from(octets).to_string(),
                    ttl,
                    preference: None,
                })
            }
            5 | 2 | 12 => {
                let mut name_offset = offset;
                let value = read_name(packet, &mut name_offset)?;
                Some(DnsRecord {
                    name,
                    record_type: if typ == 5 {
                        DnsRecordType::Cname
                    } else if typ == 2 {
                        DnsRecordType::Ns
                    } else {
                        DnsRecordType::Ptr
                    },
                    value,
                    ttl,
                    preference: None,
                })
            }
            15 if rdlen >= 3 => {
                let pref = u16_at(packet, offset)?;
                let mut name_offset = offset + 2;
                let value = read_name(packet, &mut name_offset)?;
                Some(DnsRecord {
                    name,
                    record_type: DnsRecordType::Mx,
                    value,
                    ttl,
                    preference: Some(pref),
                })
            }
            16 => {
                let mut pos = offset;
                let mut txt = String::new();
                while pos < end && txt.len() < MAX_TXT_RECORD_BYTES {
                    let len = packet[pos] as usize;
                    pos += 1;
                    if pos + len > end {
                        return Err("malformed txt".to_owned());
                    }
                    txt.push_str(&String::from_utf8_lossy(&packet[pos..pos + len]));
                    pos += len;
                }
                Some(DnsRecord {
                    name,
                    record_type: DnsRecordType::Txt,
                    value: txt.chars().take(MAX_TXT_RECORD_BYTES).collect(),
                    ttl,
                    preference: None,
                })
            }
            _ => None,
        };
        if let Some(record) = record {
            records.push(record);
        }
        offset = end;
    }
    Ok(ParsedDns {
        outcome: DnsOutcome::Resolved,
        records,
    })
}

fn read_name(packet: &[u8], offset: &mut usize) -> Result<String, String> {
    let mut labels = Vec::new();
    let mut pos = *offset;
    let mut jumped = false;
    let mut seen = BTreeSet::new();
    for _ in 0..32 {
        if pos >= packet.len() {
            return Err("name out of bounds".to_owned());
        }
        let len = packet[pos];
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= packet.len() {
                return Err("pointer out of bounds".to_owned());
            }
            let ptr = (((len & 0x3f) as usize) << 8) | packet[pos + 1] as usize;
            if !seen.insert(ptr) {
                return Err("compression loop".to_owned());
            }
            if !jumped {
                *offset = pos + 2;
                jumped = true;
            }
            pos = ptr;
            continue;
        }
        if len == 0 {
            if !jumped {
                *offset = pos + 1;
            }
            return canonical_hostname(&labels.join("."));
        }
        if len > 63 {
            return Err("invalid label length".to_owned());
        }
        pos += 1;
        let end = pos + len as usize;
        if end > packet.len() {
            return Err("label out of bounds".to_owned());
        }
        let label = std::str::from_utf8(&packet[pos..end]).map_err(|_| "label utf8".to_owned())?;
        labels.push(label.to_owned());
        pos = end;
    }
    Err("name too deep".to_owned())
}

fn u16_at(packet: &[u8], offset: usize) -> Result<u16, String> {
    let bytes = packet.get(offset..offset + 2).ok_or("short u16")?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn u32_at(packet: &[u8], offset: usize) -> Result<u32, String> {
    let bytes = packet.get(offset..offset + 4).ok_or("short u32")?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub fn ptr_query_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            v4.octets()
                .iter()
                .rev()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(".")
                + ".in-addr.arpa"
        }
        IpAddr::V6(v6) => {
            let mut nibbles = Vec::new();
            for byte in v6.octets().iter().rev() {
                nibbles.push(format!("{:x}", byte & 0x0f));
                nibbles.push(format!("{:x}", byte >> 4));
            }
            nibbles.join(".") + ".ip6.arpa"
        }
    }
}

fn fnv_hex(input: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}
