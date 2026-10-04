//! Evidence graph core (correlation engine).
//!
//! Post-scan correlation over already-collected module outputs: no network,
//! no new tasks, deterministic, bounded. Entities are content-addressed
//! (stable across scans for future diffing); every edge carries provenance
//! answering "why does RXScan believe this?".
//!
//! Scope philosophy: graph entities are *observations*, not contact
//! authorizations. SAN/DNS-discovered names become entities with
//! `contacted: false`; only the planner/decision engine may create
//! scope-checked follow-ups (recorded, never contacted here).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::execution::TaskId;
use crate::scope::ScopePolicy;

/// Maximum entities retained (bounded correlation).
pub const MAX_GRAPH_ENTITIES: usize = 8192;
/// Maximum edges retained (bounded correlation).
pub const MAX_GRAPH_EDGES: usize = 16384;
/// Maximum evidence excerpts per edge (bounded output).
pub const MAX_EDGE_EVIDENCE: usize = 4;

/// Graph node types. OS/device candidates exist as kinds for future
/// engines; current builders emit the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Host,
    IpAddress,
    Hostname,
    Port,
    Service,
    Certificate,
    SshHostKey,
    DnsRecord,
    WebEndpoint,
    Technology,
    Fingerprint,
    OsCandidate,
    DeviceCandidate,
}

impl std::fmt::Display for EntityKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Host => "host",
            Self::IpAddress => "ip_address",
            Self::Hostname => "hostname",
            Self::Port => "port",
            Self::Service => "service",
            Self::Certificate => "certificate",
            Self::SshHostKey => "ssh_host_key",
            Self::DnsRecord => "dns_record",
            Self::WebEndpoint => "web_endpoint",
            Self::Technology => "technology",
            Self::Fingerprint => "fingerprint",
            Self::OsCandidate => "os_candidate",
            Self::DeviceCandidate => "device_candidate",
        };
        f.write_str(name)
    }
}

impl EntityKind {
    /// Strict parse for untrusted (database) input: unknown kinds are
    /// rejected, never defaulted.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "host" => Some(Self::Host),
            "ip_address" => Some(Self::IpAddress),
            "hostname" => Some(Self::Hostname),
            "port" => Some(Self::Port),
            "service" => Some(Self::Service),
            "certificate" => Some(Self::Certificate),
            "ssh_host_key" => Some(Self::SshHostKey),
            "dns_record" => Some(Self::DnsRecord),
            "web_endpoint" => Some(Self::WebEndpoint),
            "technology" => Some(Self::Technology),
            "fingerprint" => Some(Self::Fingerprint),
            "os_candidate" => Some(Self::OsCandidate),
            "device_candidate" => Some(Self::DeviceCandidate),
            _ => None,
        }
    }
}

/// Edge relations. Sharing a certificate relates observations; it never
/// merges host identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeRelation {
    HasAddress,
    ResolvesTo,
    ListensOn,
    RunsService,
    PresentsCertificate,
    PresentsSshHostKey,
    HasSan,
    RedirectsTo,
    IdentifiedBy,
    DiscoveredFrom,
    ObservedAt,
    Suggests,
    References,
    /// WebEndpoint is served by a classified service instance on a port.
    ServedBy,
    /// WebEndpoint (IP-literal or DNS-resolved host) maps to a network
    /// endpoint (`port:<transport>:<ip>:<port>`). The port entity doubles
    /// as the network endpoint: no parallel entity universe is created.
    ResolvesToEndpoint,
}

impl std::fmt::Display for EdgeRelation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::HasAddress => "has_address",
            Self::ResolvesTo => "resolves_to",
            Self::ListensOn => "listens_on",
            Self::RunsService => "runs_service",
            Self::PresentsCertificate => "presents_certificate",
            Self::PresentsSshHostKey => "presents_ssh_host_key",
            Self::HasSan => "has_san",
            Self::RedirectsTo => "redirects_to",
            Self::IdentifiedBy => "identified_by",
            Self::DiscoveredFrom => "discovered_from",
            Self::ObservedAt => "observed_at",
            Self::Suggests => "suggests",
            Self::References => "references",
            Self::ServedBy => "served_by",
            Self::ResolvesToEndpoint => "resolves_to_endpoint",
        };
        f.write_str(name)
    }
}

impl EdgeRelation {
    /// Strict parse for untrusted (database) input.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "has_address" => Some(Self::HasAddress),
            "resolves_to" => Some(Self::ResolvesTo),
            "listens_on" => Some(Self::ListensOn),
            "runs_service" => Some(Self::RunsService),
            "presents_certificate" => Some(Self::PresentsCertificate),
            "presents_ssh_host_key" => Some(Self::PresentsSshHostKey),
            "has_san" => Some(Self::HasSan),
            "redirects_to" => Some(Self::RedirectsTo),
            "identified_by" => Some(Self::IdentifiedBy),
            "discovered_from" => Some(Self::DiscoveredFrom),
            "observed_at" => Some(Self::ObservedAt),
            "suggests" => Some(Self::Suggests),
            "references" => Some(Self::References),
            "served_by" => Some(Self::ServedBy),
            "resolves_to_endpoint" => Some(Self::ResolvesToEndpoint),
            _ => None,
        }
    }
}

/// Provenance answering "why does RXScan believe this?".
/// Carries `scan_plan_id` in the same shape as record provenance so every
/// JSONL line — including graph records — satisfies the uniform
/// `payload.provenance.scan_plan_id` envelope contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityProvenance {
    pub scan_plan_id: String,
    pub module: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub timestamp: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
}

/// One graph node: stable content-derived id, kind, human label, bounded
/// string attributes, provenance of first observation, observation count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphEntity {
    pub id: String,
    pub kind: EntityKind,
    pub label: String,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    pub provenance: EntityProvenance,
    pub observations: u32,
}

/// One directed relationship with confidence, provenance, and bounded
/// supporting evidence excerpts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub relation: EdgeRelation,
    pub confidence: u8,
    pub provenance: EntityProvenance,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

/// Bounded, deduplicated evidence graph.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanGraph {
    #[serde(default)]
    pub entities: BTreeMap<String, GraphEntity>,
    #[serde(default)]
    pub edges: Vec<GraphEdge>,
    #[serde(default)]
    pub truncated: bool,
}

impl ScanGraph {
    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Certificates presented by more than one port: reuse correlation.
    /// Returns `(cert_entity_id, presenter_entity_ids)` sorted by cert id.
    pub fn certificate_reuse(&self) -> Vec<(String, Vec<String>)> {
        self.reuse_for(EdgeRelation::PresentsCertificate)
    }

    /// SSH host keys presented by more than one endpoint: reuse
    /// correlation. Shared keys relate observations; they never merge
    /// host identity (NAT/cloning/appliance templates exist).
    pub fn ssh_key_reuse(&self) -> Vec<(String, Vec<String>)> {
        self.reuse_for(EdgeRelation::PresentsSshHostKey)
    }

    fn reuse_for(&self, relation: EdgeRelation) -> Vec<(String, Vec<String>)> {
        let mut presenters: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for edge in &self.edges {
            if edge.relation == relation {
                presenters
                    .entry(edge.to.clone())
                    .or_default()
                    .insert(edge.from.clone());
            }
        }
        presenters
            .into_iter()
            .filter(|(_, from)| from.len() > 1)
            .map(|(cert, from)| (cert, from.into_iter().collect()))
            .collect()
    }

    /// Public entity upsert for post-scan classification passes (OS/device
    /// candidates computed after the event sweep). Same bounds and dedup
    /// as the internal path.
    pub fn upsert_entity(
        &mut self,
        id: String,
        kind: EntityKind,
        label: String,
        attributes: BTreeMap<String, String>,
        provenance: &EntityProvenance,
    ) {
        self.ensure_entity(id, kind, label, attributes, provenance);
    }

    /// Public edge insertion for post-scan classification passes. Same
    /// bounds, dedup, and confidence ceiling as the internal path.
    #[allow(clippy::too_many_arguments)]
    pub fn link(
        &mut self,
        from: String,
        to: String,
        relation: EdgeRelation,
        confidence: u8,
        provenance: &EntityProvenance,
        evidence: Vec<String>,
        attributes: BTreeMap<String, String>,
    ) {
        self.add_edge(
            from, to, relation, confidence, provenance, evidence, attributes,
        );
    }

    fn ensure_entity(
        &mut self,
        id: String,
        kind: EntityKind,
        label: String,
        attributes: BTreeMap<String, String>,
        provenance: &EntityProvenance,
    ) {
        if let Some(existing) = self.entities.get_mut(&id) {
            existing.observations = existing.observations.saturating_add(1);
            return;
        }
        if self.entities.len() >= MAX_GRAPH_ENTITIES {
            self.truncated = true;
            return;
        }
        self.entities.insert(
            id.clone(),
            GraphEntity {
                id,
                kind,
                label,
                attributes,
                provenance: provenance.clone(),
                observations: 1,
            },
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn add_edge(
        &mut self,
        from: String,
        to: String,
        relation: EdgeRelation,
        confidence: u8,
        provenance: &EntityProvenance,
        evidence: Vec<String>,
        attributes: BTreeMap<String, String>,
    ) {
        if from == to {
            return;
        }
        if !self.entities.contains_key(&from) || !self.entities.contains_key(&to) {
            return;
        }
        if let Some(existing) = self
            .edges
            .iter_mut()
            .find(|edge| edge.from == from && edge.to == to && edge.relation == relation)
        {
            // Dedup: keep the strongest confidence, merge bounded evidence.
            if confidence > existing.confidence {
                existing.confidence = confidence;
            }
            for item in evidence {
                if existing.evidence.len() >= MAX_EDGE_EVIDENCE {
                    break;
                }
                if !existing.evidence.contains(&item) {
                    existing.evidence.push(item);
                }
            }
            return;
        }
        if self.edges.len() >= MAX_GRAPH_EDGES {
            self.truncated = true;
            return;
        }
        let mut bounded_evidence = Vec::new();
        for item in evidence {
            if bounded_evidence.len() >= MAX_EDGE_EVIDENCE {
                break;
            }
            bounded_evidence.push(truncate_attr(&item, 256));
        }
        self.edges.push(GraphEdge {
            from,
            to,
            relation,
            confidence: confidence.min(95),
            provenance: provenance.clone(),
            evidence: bounded_evidence,
            attributes,
        });
    }
}

fn truncate_attr(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

fn bounded_attrs(pairs: Vec<(String, String)>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (key, value) in pairs.into_iter().take(12) {
        out.insert(truncate_attr(&key, 64), truncate_attr(&value, 256));
    }
    out
}

// ---------------- stable entity ids (diff foundation) ----------------

pub fn ip_entity_id(ip: &str) -> String {
    format!("ip:{}", ip.trim().to_ascii_lowercase())
}

pub fn hostname_entity_id(name: &str) -> String {
    format!(
        "host:{}",
        name.trim().trim_end_matches('.').to_ascii_lowercase()
    )
}

pub fn port_entity_id(transport: &str, ip: &str, port: u16) -> String {
    format!(
        "port:{}:{}:{}",
        transport.trim().to_ascii_lowercase(),
        ip.trim(),
        port
    )
}

pub fn service_entity_id(port_entity: &str, label: &str) -> String {
    format!(
        "service:{}:{}",
        port_entity,
        label.trim().to_ascii_lowercase()
    )
}

pub fn cert_entity_id(sha256_hex: &str) -> String {
    format!("cert:sha256:{}", sha256_hex.trim().to_ascii_lowercase())
}

pub fn ssh_key_entity_id(sha256_hex: &str) -> String {
    format!("sshkey:sha256:{}", sha256_hex.trim().to_ascii_lowercase())
}

pub fn endpoint_entity_id(url: &str) -> String {
    format!("endpoint:{}", url.trim())
}

/// Canonicalize a URL for entity identity (`http://h/` and `http://h:80/`
/// share one entity). Returns `None` for unparseable/unsupported input;
/// callers fall back to raw text (observation preserved, joins skipped).
pub fn canonical_url(url: &str) -> Option<String> {
    crate::web::WebTarget::parse(url)
        .ok()
        .map(|target| target.canonical())
}

pub fn technology_entity_id(product: &str) -> String {
    format!("tech:{}", product.trim().to_ascii_lowercase())
}

pub fn fingerprint_entity_id(rule_source: &str) -> String {
    format!("fp:rule:{}", rule_source.trim())
}

pub fn dns_record_entity_id(record_type: &str, name: &str, value: &str) -> String {
    format!(
        "dns:{}:{}:{}",
        record_type.trim().to_ascii_uppercase(),
        name.trim().trim_end_matches('.').to_ascii_lowercase(),
        value.trim().to_ascii_lowercase()
    )
}

// ---------------- builder ----------------

/// Build a correlation graph from completed module outputs. Pure:
/// deterministic over sorted task ids, no network, bounded output.
/// `scope` annotates SAN/DNS-discovered names with in-scope state;
/// `None` annotates `scope-unknown` (observation only either way).
pub fn build_graph(
    module_outputs: &[(TaskId, crate::execution::ModuleOutput)],
    scope: Option<&ScopePolicy>,
) -> ScanGraph {
    let mut graph = ScanGraph::default();
    let mut ordered: Vec<&(TaskId, crate::execution::ModuleOutput)> =
        module_outputs.iter().collect();
    ordered.sort_by(|left, right| left.0.0.cmp(&right.0.0));
    for (task_id, output) in ordered {
        for event in &output.events {
            let provenance = EntityProvenance {
                scan_plan_id: event.provenance.scan_plan_id.0.clone(),
                module: event.provenance.module_name.clone(),
                task_id: Some(task_id.0.clone()),
                target: event
                    .details
                    .data
                    .get("target")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                timestamp: event.provenance.timestamp.0,
                reason: event
                    .details
                    .data
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                rule_id: event
                    .details
                    .data
                    .get("rule_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| {
                        event
                            .details
                            .data
                            .get("rule_source")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned)
                    }),
            };
            ingest_event(&mut graph, event, &provenance, scope);
        }
    }
    // Join pass: connect web endpoints to the network endpoints (port
    // entities) and services they were observed on. Runs after all events
    // so task ordering never affects joins. Only joins to entities with
    // direct evidence — never fabricates port/service entities.
    join_endpoints(&mut graph);
    graph
}

/// Join web endpoints to canonical network endpoints.
///
/// `http://192.168.0.1`, `http://192.168.0.1:80/`, and the discovered
/// `192.168.0.1:80` port all resolve to `port:tcp:192.168.0.1:80` (the
/// port entity doubles as the network endpoint; no parallel universe).
/// Hostname URLs join through observed `resolves_to` mappings; virtual
/// hosts on one socket each link to the same port entity. Joins are
/// derived (confidence 85), never new observations.
fn join_endpoints(graph: &mut ScanGraph) {
    let endpoints: Vec<(String, EntityProvenance)> = graph
        .entities
        .iter()
        .filter(|(_, entity)| entity.kind == EntityKind::WebEndpoint)
        .map(|(id, entity)| (id.clone(), entity.provenance.clone()))
        .collect();
    let mut resolves: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for edge in &graph.edges {
        if edge.relation == EdgeRelation::ResolvesTo {
            resolves
                .entry(edge.from.clone())
                .or_default()
                .push(edge.to.clone());
        }
    }
    // Service entities indexed by port-entity prefix.
    let services: Vec<(String, String)> = graph
        .entities
        .iter()
        .filter(|(_, entity)| entity.kind == EntityKind::Service)
        .map(|(id, _)| {
            let port_prefix = id
                .strip_prefix("service:")
                .and_then(|rest| rest.rsplit_once(':').map(|(port, _)| port.to_owned()))
                .unwrap_or_default();
            (port_prefix, id.clone())
        })
        .collect();
    for (endpoint_id, provenance) in endpoints {
        let Some(url) = endpoint_id.strip_prefix("endpoint:") else {
            continue;
        };
        let Ok(target) = crate::web::WebTarget::parse(url) else {
            continue;
        };
        if target.scheme.as_str() != "http" && target.scheme.as_str() != "https" {
            continue;
        }
        // Candidate network endpoints for this URL.
        let mut port_ids: Vec<String> = Vec::new();
        if target.is_ip_literal() {
            let ip = target.host.trim_start_matches('[').trim_end_matches(']');
            port_ids.push(port_entity_id("tcp", ip, target.port));
        } else if let Some(ips) = resolves.get(&hostname_entity_id(&target.host)) {
            for ip_id in ips {
                if let Some(ip) = ip_id.strip_prefix("ip:") {
                    port_ids.push(port_entity_id("tcp", ip, target.port));
                }
            }
        }
        for port_id in port_ids {
            if !graph.entities.contains_key(&port_id) {
                continue;
            }
            graph.add_edge(
                endpoint_id.clone(),
                port_id.clone(),
                EdgeRelation::ResolvesToEndpoint,
                85,
                &provenance,
                vec!["endpoint maps to observed network endpoint".to_owned()],
                BTreeMap::new(),
            );
            for (prefix, service_id) in &services {
                if *prefix == port_id {
                    graph.add_edge(
                        endpoint_id.clone(),
                        service_id.clone(),
                        EdgeRelation::ServedBy,
                        85,
                        &provenance,
                        vec!["endpoint served by classified service".to_owned()],
                        BTreeMap::new(),
                    );
                }
            }
        }
    }
}

fn event_str(data: &serde_json::Value, key: &str) -> Option<String> {
    data.get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

fn event_u64(data: &serde_json::Value, key: &str) -> Option<u64> {
    data.get(key).and_then(serde_json::Value::as_u64)
}

fn ingest_event(
    graph: &mut ScanGraph,
    event: &crate::model::Event,
    provenance: &EntityProvenance,
    scope: Option<&ScopePolicy>,
) {
    use crate::model::EventKind;
    let data = &event.details.data;
    match event.kind {
        EventKind::PortOpen => {
            let (Some(address), Some(port)) = (
                event_str(data, "address"),
                event_u64(data, "port").and_then(|port| u16::try_from(port).ok()),
            ) else {
                return;
            };
            let transport = event_str(data, "transport").unwrap_or_else(|| "tcp".to_owned());
            let ip_id = ip_entity_id(&address);
            let port_id = port_entity_id(&transport, &address, port);
            graph.ensure_entity(
                ip_id.clone(),
                EntityKind::IpAddress,
                address.clone(),
                bounded_attrs(vec![("address".to_owned(), address.clone())]),
                provenance,
            );
            graph.ensure_entity(
                port_id.clone(),
                EntityKind::Port,
                format!("{address}:{port}/{transport}"),
                bounded_attrs(vec![
                    ("address".to_owned(), address.clone()),
                    ("transport".to_owned(), transport.clone()),
                    ("port".to_owned(), port.to_string()),
                ]),
                provenance,
            );
            graph.add_edge(
                ip_id,
                port_id,
                EdgeRelation::ListensOn,
                90,
                provenance,
                vec![format!("{transport} connect to {address}:{port} succeeded")],
                BTreeMap::new(),
            );
        }
        EventKind::ServiceIdentified => {
            let (Some(address), Some(port)) = (
                event_str(data, "address"),
                event_u64(data, "port").and_then(|port| u16::try_from(port).ok()),
            ) else {
                return;
            };
            let protocol = event_str(data, "protocol").unwrap_or_else(|| "unknown".to_owned());
            let service = event_str(data, "service").unwrap_or_else(|| protocol.clone());
            let confidence = event_u64(data, "confidence").unwrap_or(80).min(95) as u8;
            // ServiceIdentified observations are TCP-only in this build.
            let transport = "tcp".to_owned();
            let port_id = port_entity_id(&transport, &address, port);
            let service_id = service_entity_id(&port_id, &service);
            // Port entity may be absent for huge scans (per-port events
            // truncated); ensure both ends from event content.
            graph.ensure_entity(
                port_id.clone(),
                EntityKind::Port,
                format!("{address}:{port}/{transport}"),
                bounded_attrs(vec![
                    ("address".to_owned(), address.clone()),
                    ("transport".to_owned(), transport.clone()),
                    ("port".to_owned(), port.to_string()),
                ]),
                provenance,
            );
            // Service properties (product/version/…) ride on the entity so
            // cross-scan diffs read version changes off stable service ids.
            // Identity stays endpoint+protocol; these are properties.
            let mut service_attrs = vec![
                ("protocol".to_owned(), protocol.clone()),
                ("service".to_owned(), service.clone()),
                ("address".to_owned(), address.clone()),
                ("port".to_owned(), port.to_string()),
            ];
            for key in [
                "product_hint",
                "version_hint",
                "version_family",
                "vendor_hint",
                "cpe_hint",
                "confidence",
            ] {
                if let Some(value) = event_str(data, key) {
                    service_attrs.push((key.to_owned(), value));
                }
            }
            // Per-field certainty for inventory/vuln consumers.
            if let Some(fields) = data.get("field_confidence") {
                for key in ["product", "version", "vendor"] {
                    if let Some(value) = fields.get(key).and_then(serde_json::Value::as_u64) {
                        service_attrs
                            .push((format!("{key}_confidence"), value.min(100).to_string()));
                    }
                }
            }
            // Per-field certainty rides along for inventory/vuln consumers.
            if let Some(fields) = data.get("field_confidence") {
                for key in ["product", "version", "vendor"] {
                    if let Some(value) = fields.get(key).and_then(serde_json::Value::as_u64) {
                        service_attrs
                            .push((format!("{key}_confidence"), value.min(100).to_string()));
                    }
                }
            }
            graph.ensure_entity(
                service_id.clone(),
                EntityKind::Service,
                format!("{service} on {address}:{port}"),
                bounded_attrs(service_attrs),
                provenance,
            );
            graph.add_edge(
                port_id.clone(),
                service_id.clone(),
                EdgeRelation::RunsService,
                confidence,
                provenance,
                vec![format!("service identified as {service} ({protocol})")],
                BTreeMap::new(),
            );
            if let Some(product) = event_str(data, "product_hint").filter(|p| !p.is_empty()) {
                let tech_id = technology_entity_id(&product);
                graph.ensure_entity(
                    tech_id.clone(),
                    EntityKind::Technology,
                    product.clone(),
                    bounded_attrs(vec![("product".to_owned(), product.clone())]),
                    provenance,
                );
                graph.add_edge(
                    service_id.clone(),
                    tech_id,
                    EdgeRelation::Suggests,
                    confidence.min(90),
                    provenance,
                    vec![format!("product evidence: {product}")],
                    BTreeMap::new(),
                );
            }
            let rule = event_str(data, "rule_source")
                .or_else(|| event_str(data, "matcher"))
                .unwrap_or_else(|| "builtin:unknown".to_owned());
            let fp_id = fingerprint_entity_id(&rule);
            graph.ensure_entity(
                fp_id.clone(),
                EntityKind::Fingerprint,
                rule.clone(),
                bounded_attrs(vec![("rule".to_owned(), rule.clone())]),
                provenance,
            );
            graph.add_edge(
                service_id,
                fp_id,
                EdgeRelation::IdentifiedBy,
                confidence,
                provenance,
                vec![format!("classified via {rule}")],
                BTreeMap::new(),
            );
        }
        EventKind::TlsObserved => {
            let Some(fingerprint) = event_str(data, "fingerprint_sha256")
                .filter(|fp| fp.len() == 64 && fp.bytes().all(|byte| byte.is_ascii_hexdigit()))
            else {
                return;
            };
            let address = event_str(data, "address").unwrap_or_default();
            let port = event_u64(data, "port")
                .and_then(|port| u16::try_from(port).ok())
                .unwrap_or(443);
            let port_id = if address.is_empty() {
                None
            } else {
                Some(port_entity_id("tcp", &address, port))
            };
            let cert_id = cert_entity_id(&fingerprint);
            let mut cert_attrs = vec![("sha256".to_owned(), fingerprint.clone())];
            for key in [
                "subject",
                "issuer",
                "serial_hex",
                "public_key_algorithm",
                "public_key_bits_nominal",
                "signature_algorithm",
                "chain_len",
                "self_signed",
                "not_before",
                "not_after",
                "not_before_epoch",
                "not_after_epoch",
            ] {
                if let Some(value) = match event_str(data, key) {
                    Some(text) => Some(text),
                    None => data
                        .get(key)
                        .and_then(|value| value.as_i64())
                        .map(|epoch| epoch.to_string()),
                } {
                    cert_attrs.push((key.to_owned(), value));
                }
            }
            graph.ensure_entity(
                cert_id.clone(),
                EntityKind::Certificate,
                format!("cert:sha256:{}", &fingerprint[..12.min(fingerprint.len())]),
                bounded_attrs(cert_attrs),
                provenance,
            );
            if let Some(port_id) = port_id {
                graph.ensure_entity(
                    port_id.clone(),
                    EntityKind::Port,
                    format!("{address}:{port}/tcp"),
                    bounded_attrs(vec![
                        ("address".to_owned(), address.clone()),
                        ("transport".to_owned(), "tcp".to_owned()),
                        ("port".to_owned(), port.to_string()),
                    ]),
                    provenance,
                );
                graph.add_edge(
                    port_id,
                    cert_id.clone(),
                    EdgeRelation::PresentsCertificate,
                    90,
                    provenance,
                    vec!["tls handshake presented certificate".to_owned()],
                    BTreeMap::new(),
                );
            }
            // SAN correlation: entities with scope annotation; contact
            // gating stays with the planner (recorded, never contacted).
            let mut sans: Vec<(String, bool)> = Vec::new();
            if let Some(list) = data.get("san_dns").and_then(serde_json::Value::as_array) {
                for name in list.iter().filter_map(serde_json::Value::as_str).take(64) {
                    if !name.trim().is_empty() {
                        sans.push((name.to_owned(), false));
                    }
                }
            }
            if let Some(list) = data.get("san_ip").and_then(serde_json::Value::as_array) {
                for ip in list.iter().filter_map(serde_json::Value::as_str).take(64) {
                    if !ip.trim().is_empty() {
                        sans.push((ip.to_owned(), true));
                    }
                }
            }
            for (name, is_ip) in sans {
                let (entity_id, kind, label) = if is_ip {
                    (ip_entity_id(&name), EntityKind::IpAddress, name.clone())
                } else {
                    (
                        hostname_entity_id(&name),
                        EntityKind::Hostname,
                        name.to_ascii_lowercase(),
                    )
                };
                graph.ensure_entity(
                    entity_id.clone(),
                    kind,
                    label,
                    bounded_attrs(vec![("name".to_owned(), name.clone())]),
                    provenance,
                );
                let scope_state = match scope {
                    None => "scope-unknown",
                    Some(policy) => {
                        let in_scope = if is_ip {
                            name.parse::<std::net::IpAddr>()
                                .map(|ip| policy.permits(Some(ip), None))
                                .unwrap_or(false)
                        } else {
                            policy.permits(None, Some(&name))
                        };
                        if in_scope {
                            "in-scope-uncontacted"
                        } else {
                            "outside-scope"
                        }
                    }
                };
                graph.add_edge(
                    cert_id.clone(),
                    entity_id,
                    EdgeRelation::HasSan,
                    95,
                    provenance,
                    vec![format!("certificate SAN lists {name}")],
                    BTreeMap::from([
                        ("contacted".to_owned(), "false".to_owned()),
                        ("scope".to_owned(), scope_state.to_owned()),
                    ]),
                );
            }
        }
        EventKind::SshHostKeyObserved => {
            let Some(fingerprint) = event_str(data, "sha256")
                .filter(|fp| fp.len() == 64 && fp.bytes().all(|byte| byte.is_ascii_hexdigit()))
            else {
                return;
            };
            let address = event_str(data, "address").unwrap_or_default();
            let port = event_u64(data, "port")
                .and_then(|port| u16::try_from(port).ok())
                .unwrap_or(22);
            let port_id = if address.is_empty() {
                None
            } else {
                Some(port_entity_id("tcp", &address, port))
            };
            let key_id = ssh_key_entity_id(&fingerprint);
            let mut key_attrs = vec![("sha256".to_owned(), fingerprint.clone())];
            for key in ["key_type", "bits", "selected_kex", "selected_host_key"] {
                if let Some(value) = event_str(data, key) {
                    key_attrs.push((key.to_owned(), value));
                }
            }
            graph.ensure_entity(
                key_id.clone(),
                EntityKind::SshHostKey,
                format!(
                    "sshkey:sha256:{}",
                    &fingerprint[..12.min(fingerprint.len())]
                ),
                bounded_attrs(key_attrs),
                provenance,
            );
            if let Some(port_id) = port_id {
                graph.ensure_entity(
                    port_id.clone(),
                    EntityKind::Port,
                    format!("{address}:{port}/tcp"),
                    bounded_attrs(vec![
                        ("address".to_owned(), address.clone()),
                        ("transport".to_owned(), "tcp".to_owned()),
                        ("port".to_owned(), port.to_string()),
                    ]),
                    provenance,
                );
                graph.add_edge(
                    port_id,
                    key_id,
                    EdgeRelation::PresentsSshHostKey,
                    90,
                    provenance,
                    vec!["ssh handshake presented host key (signature unverified)".to_owned()],
                    BTreeMap::new(),
                );
            }
        }
        EventKind::DnsRecordObserved | EventKind::DnsReverseObserved => {
            let (Some(name), Some(record_type), Some(value)) = (
                event_str(data, "name"),
                event_str(data, "record_type"),
                event_str(data, "value"),
            ) else {
                return;
            };
            if name.is_empty() || value.is_empty() {
                return;
            }
            let host_id = hostname_entity_id(&name);
            graph.ensure_entity(
                host_id.clone(),
                EntityKind::Hostname,
                name.to_ascii_lowercase(),
                bounded_attrs(vec![("name".to_owned(), name.clone())]),
                provenance,
            );
            if (record_type == "A" || record_type == "AAAA")
                && value.parse::<std::net::IpAddr>().is_ok()
            {
                let ip_id = ip_entity_id(&value);
                graph.ensure_entity(
                    ip_id.clone(),
                    EntityKind::IpAddress,
                    value.clone(),
                    bounded_attrs(vec![("address".to_owned(), value.clone())]),
                    provenance,
                );
                graph.add_edge(
                    host_id,
                    ip_id,
                    EdgeRelation::ResolvesTo,
                    85,
                    provenance,
                    vec![format!("DNS {record_type} {name} → {value}")],
                    BTreeMap::from([("record_type".to_owned(), record_type)]),
                );
            } else {
                let record_id = dns_record_entity_id(&record_type, &name, &value);
                graph.ensure_entity(
                    record_id.clone(),
                    EntityKind::DnsRecord,
                    format!("{record_type} {name}"),
                    bounded_attrs(vec![
                        ("record_type".to_owned(), record_type.clone()),
                        ("name".to_owned(), name.clone()),
                        ("value".to_owned(), value.clone()),
                    ]),
                    provenance,
                );
                graph.add_edge(
                    host_id,
                    record_id,
                    EdgeRelation::References,
                    80,
                    provenance,
                    vec![format!("DNS {record_type} record observed")],
                    BTreeMap::from([("record_type".to_owned(), record_type)]),
                );
            }
        }
        EventKind::EndpointObserved | EventKind::EndpointDiscovered => {
            let Some(url) = event_str(data, "url").filter(|url| !url.is_empty()) else {
                return;
            };
            if url.len() > 2048 {
                return;
            }
            let canonical = canonical_url(&url).unwrap_or_else(|| url.clone());
            let endpoint_id = endpoint_entity_id(&canonical);
            graph.ensure_entity(
                endpoint_id.clone(),
                EntityKind::WebEndpoint,
                canonical.clone(),
                bounded_attrs(vec![("url".to_owned(), canonical.clone())]),
                provenance,
            );
            // Crawl discoveries name their discovering page: link them.
            if let Some(page_url) = event_str(data, "page_url")
                .filter(|page| !page.is_empty() && page.len() <= 2048 && *page != url)
            {
                let canonical_page = canonical_url(&page_url).unwrap_or_else(|| page_url.clone());
                let page_id = endpoint_entity_id(&canonical_page);
                graph.ensure_entity(
                    page_id.clone(),
                    EntityKind::WebEndpoint,
                    page_url.clone(),
                    bounded_attrs(vec![("url".to_owned(), page_url.clone())]),
                    provenance,
                );
                let source = event_str(data, "source").unwrap_or_else(|| "crawl".to_owned());
                graph.add_edge(
                    endpoint_id,
                    page_id,
                    EdgeRelation::DiscoveredFrom,
                    90,
                    provenance,
                    vec![format!("endpoint discovered from page ({source})")],
                    BTreeMap::from([("source".to_owned(), source)]),
                );
            }
        }
        EventKind::RedirectObserved => {
            let Some(url) = event_str(data, "url") else {
                return;
            };
            if url.is_empty() || url.len() > 2048 {
                return;
            }
            // The redirect source is always recorded; only absolute
            // targets become edges (relative locations cannot form
            // stable entity ids without base resolution here).
            let canonical = canonical_url(&url).unwrap_or_else(|| url.clone());
            let from_id = endpoint_entity_id(&canonical);
            graph.ensure_entity(
                from_id.clone(),
                EntityKind::WebEndpoint,
                canonical.clone(),
                bounded_attrs(vec![("url".to_owned(), canonical.clone())]),
                provenance,
            );
            let Some(location) = event_str(data, "location") else {
                return;
            };
            if location.contains("://") && location.len() <= 2048 {
                let canonical_to = canonical_url(&location).unwrap_or_else(|| location.clone());
                let to_id = endpoint_entity_id(&canonical_to);
                graph.ensure_entity(
                    to_id.clone(),
                    EntityKind::WebEndpoint,
                    canonical_to.clone(),
                    bounded_attrs(vec![("url".to_owned(), canonical_to)]),
                    provenance,
                );
                graph.add_edge(
                    from_id,
                    to_id,
                    EdgeRelation::RedirectsTo,
                    90,
                    provenance,
                    vec![format!("HTTP redirect → {location}")],
                    BTreeMap::new(),
                );
            }
        }
        _ => {}
    }
}

// ---------------- identity reconciliation ----------------
//
// Raw entities are never merged automatically. Reconciliation produces
// graded cluster CANDIDATES with explicit verdicts: SAME_IDENTITY needs
// strong same-observation evidence (same observed IP literal within one
// scan); everything else — shared certificates, shared hostnames, shared
// DNS — is RELATED_TO. Certificate reuse alone never implies same machine.

/// Identity verdict for a cluster candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityVerdict {
    SameIdentity,
    Related,
}

/// A proposed asset grouping with confidence and human-readable reasons.
/// Raw entities stay available; clusters are interpretive overlays.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetClusterCandidate {
    pub members: Vec<String>,
    pub verdict: IdentityVerdict,
    pub confidence: u8,
    pub reasons: Vec<String>,
}

/// Maximum cluster candidates per graph (bounded).
pub const MAX_CLUSTERS: usize = 1024;

/// Derive reconciliation candidates from a built graph. Deterministic
/// (sorted member and candidate order), bounded, pure.
pub fn reconcile_candidates(graph: &ScanGraph) -> Vec<AssetClusterCandidate> {
    let mut out = Vec::new();
    // Ports grouped by exact IP-literal suffix: same observed address in
    // one scan is same probed target (scan-scoped identity, not a
    // cross-scan physical claim).
    let mut by_ip: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (id, entity) in &graph.entities {
        if entity.kind != EntityKind::Port {
            continue;
        }
        if let Some(ip) = port_ip_literal(id) {
            by_ip.entry(ip).or_default().push(id.clone());
        }
    }
    for (ip, mut members) in by_ip {
        if members.len() < 2 {
            continue;
        }
        members.sort();
        members.insert(0, ip_entity_id(&ip));
        out.push(AssetClusterCandidate {
            members,
            verdict: IdentityVerdict::SameIdentity,
            confidence: 80,
            reasons: vec!["same observed IP literal within one scan (scan-scoped)".to_owned()],
        });
        if out.len() >= MAX_CLUSTERS {
            return sorted_clusters(out);
        }
    }
    // Certificate reuse across distinct ports: RELATED_TO only.
    for (cert, mut presenters) in graph.certificate_reuse() {
        presenters.sort();
        presenters.insert(0, cert.clone());
        out.push(AssetClusterCandidate {
            members: presenters,
            verdict: IdentityVerdict::Related,
            confidence: 70,
            reasons: vec![format!(
                "shared certificate {cert} relates observations; reuse never merges host identity"
            )],
        });
        if out.len() >= MAX_CLUSTERS {
            return sorted_clusters(out);
        }
    }
    // SSH host-key reuse across distinct endpoints: RELATED_TO only.
    // Strong identity evidence (exact key match) but never an automatic
    // merge: NAT, cloning, and appliance templates reuse keys legitimately.
    for (key, mut presenters) in graph.ssh_key_reuse() {
        presenters.sort();
        presenters.insert(0, key.clone());
        out.push(AssetClusterCandidate {
            members: presenters,
            verdict: IdentityVerdict::Related,
            confidence: 85,
            reasons: vec![format!(
                "shared SSH host key {key} relates endpoints; reuse never merges host identity"
            )],
        });
        if out.len() >= MAX_CLUSTERS {
            return sorted_clusters(out);
        }
    }
    // Hostname → IP resolution: RELATED_TO (DNS observed fact).
    for edge in &graph.edges {
        if edge.relation != EdgeRelation::ResolvesTo {
            continue;
        }
        out.push(AssetClusterCandidate {
            members: vec![edge.from.clone(), edge.to.clone()],
            verdict: IdentityVerdict::Related,
            confidence: 85,
            reasons: vec!["DNS resolution relates name to address".to_owned()],
        });
        if out.len() >= MAX_CLUSTERS {
            return sorted_clusters(out);
        }
    }
    sorted_clusters(out)
}

fn sorted_clusters(mut clusters: Vec<AssetClusterCandidate>) -> Vec<AssetClusterCandidate> {
    clusters.sort_by(|a, b| {
        format!("{:?}", a.verdict)
            .cmp(&format!("{:?}", b.verdict))
            .then_with(|| a.members.cmp(&b.members))
    });
    clusters
}

/// Extract the IP literal from a `port:<transport>:<ip>:<port>` entity id.
/// IPv6 literals contain colons: split from the left (transport) and right
/// (port) instead of naively splitting on every colon.
fn port_ip_literal(port_entity_id: &str) -> Option<String> {
    let rest = port_entity_id.strip_prefix("port:")?;
    let (_, after_transport) = rest.split_once(':')?;
    let (ip, _port) = after_transport.rsplit_once(':')?;
    if ip.trim().is_empty() {
        return None;
    }
    Some(ip.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance() -> EntityProvenance {
        EntityProvenance {
            scan_plan_id: "plan_test".to_owned(),
            module: "test".to_owned(),
            task_id: Some("task_x".to_owned()),
            target: Some("127.0.0.1".to_owned()),
            timestamp: 1,
            reason: Some("unit".to_owned()),
            rule_id: None,
        }
    }

    #[test]
    fn entity_ids_are_stable_and_scoped() {
        assert_eq!(ip_entity_id("127.0.0.1"), "ip:127.0.0.1");
        assert_eq!(
            hostname_entity_id("API.Example.TEST."),
            "host:api.example.test"
        );
        assert_eq!(
            port_entity_id("TCP", "10.0.0.1", 443),
            "port:tcp:10.0.0.1:443"
        );
        assert_eq!(
            cert_entity_id(&"ab".repeat(32)),
            format!("cert:sha256:{}", "ab".repeat(32))
        );
    }

    #[test]
    fn edges_dedup_keep_strongest_with_provenance() {
        let mut graph = ScanGraph::default();
        let proof = provenance();
        graph.ensure_entity(
            "ip:1.1.1.1".to_owned(),
            EntityKind::IpAddress,
            "1.1.1.1".to_owned(),
            BTreeMap::new(),
            &proof,
        );
        graph.ensure_entity(
            "port:tcp:1.1.1.1:80".to_owned(),
            EntityKind::Port,
            "x".to_owned(),
            BTreeMap::new(),
            &proof,
        );
        graph.add_edge(
            "ip:1.1.1.1".to_owned(),
            "port:tcp:1.1.1.1:80".to_owned(),
            EdgeRelation::ListensOn,
            80,
            &proof,
            vec!["a".to_owned()],
            BTreeMap::new(),
        );
        graph.add_edge(
            "ip:1.1.1.1".to_owned(),
            "port:tcp:1.1.1.1:80".to_owned(),
            EdgeRelation::ListensOn,
            90,
            &proof,
            vec!["b".to_owned()],
            BTreeMap::new(),
        );
        assert_eq!(graph.edge_count(), 1);
        assert_eq!(graph.edges[0].confidence, 90);
        assert_eq!(graph.edges[0].evidence.len(), 2);
        // Self-edges never form.
        graph.add_edge(
            "ip:1.1.1.1".to_owned(),
            "ip:1.1.1.1".to_owned(),
            EdgeRelation::References,
            50,
            &proof,
            vec![],
            BTreeMap::new(),
        );
        assert_eq!(graph.edge_count(), 1);
    }

    #[test]
    fn bounds_hold_under_flood() {
        let mut graph = ScanGraph::default();
        let proof = provenance();
        for index in 0..(MAX_GRAPH_ENTITIES + 500) {
            graph.ensure_entity(
                format!("ip:10.9.{}.{}", index / 250, index % 250),
                EntityKind::IpAddress,
                index.to_string(),
                BTreeMap::new(),
                &proof,
            );
        }
        assert!(graph.entity_count() <= MAX_GRAPH_ENTITIES);
        assert!(graph.truncated);
    }
}
