//! Passive local entity intelligence (Phase 1 of the Ultimate Expansion).
//!
//! Additive only: the existing username provider search is untouched.
//! This module answers "what is this identifier, canonically, and what
//! does it directly imply without any network contact?" for:
//!
//! ```text
//! email, domain, hostname, IP, ASN, URL, repository, organization
//! ```
//!
//! Guarantees:
//!
//! * Zero network contact. Pure canonicalization + local derivation.
//!   DNS enrichment, RDAP, CT, archive, and repository fetching live in
//!   `investigate` transforms, never here.
//! * Stable identity via [`crate::assets::public_entity_id`].
//! * Provenance + confidence + timestamps on every entity/relationship.
//! * `network_scans` is always 0.
//! * Reserved/synthetic examples only in docs/tests.
//!
//! Future phases add certificate / SSH-key / software-identity / document
//! constructors without changing this module's schemas.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::graph::{EdgeRelation, EntityKind, EntityProvenance, ScanGraph};
use crate::search::{
    ContactClass, SearchEntity, SearchEntityKind, SearchError, SearchObservation, SearchStatus,
};

/// Schema version for passive entity search envelopes.
pub const ENTITY_SEARCH_SCHEMA_VERSION: u32 = 1;

/// Passive entity search report. JSON-serializable, versioned, deterministic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySearchReport {
    pub schema_version: u32,
    pub run_id: String,
    pub seed: SearchEntity,
    pub observations: Vec<SearchObservation>,
    pub graph: ScanGraph,
    pub network_scans: u64,
    pub started_at: u64,
    pub completed_at: u64,
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn seed_provenance(seed: &SearchEntity) -> EntityProvenance {
    EntityProvenance {
        scan_plan_id: "search".to_owned(),
        module: "search.seed".to_owned(),
        task_id: None,
        target: Some(seed.id.clone()),
        timestamp: seed.last_observed,
        reason: Some("operator-supplied entity seed".to_owned()),
        rule_id: None,
    }
}

fn derived_provenance(seed: &SearchEntity, module: &str, reason: &str) -> EntityProvenance {
    EntityProvenance {
        scan_plan_id: "search".to_owned(),
        module: module.to_owned(),
        task_id: None,
        target: Some(seed.id.clone()),
        timestamp: seed.last_observed,
        reason: Some(reason.to_owned()),
        rule_id: None,
    }
}

fn observation(
    seed: &SearchEntity,
    status: SearchStatus,
    confidence: u8,
    evidence: Vec<String>,
    mut attributes: BTreeMap<String, String>,
) -> SearchObservation {
    attributes.insert("seed_kind".to_owned(), seed.kind.as_str().to_owned());
    SearchObservation {
        provider_id: "local".to_owned(),
        provider_version: "1".to_owned(),
        task_id: crate::assets::public_entity_id(
            "search_task",
            &format!("local:{}:search", seed.id),
        ),
        input_entity_id: seed.id.clone(),
        contact_class: ContactClass::PassivePublic,
        status,
        confidence: confidence.min(95),
        timestamp: seed.last_observed,
        evidence,
        attributes,
    }
}

fn graph_kind(kind: SearchEntityKind) -> EntityKind {
    match kind {
        SearchEntityKind::Username => EntityKind::Username,
        SearchEntityKind::EmailAddress => EntityKind::EmailAddress,
        SearchEntityKind::Domain => EntityKind::Domain,
        SearchEntityKind::Hostname => EntityKind::Hostname,
        SearchEntityKind::IpAddress => EntityKind::IpAddress,
        SearchEntityKind::Url => EntityKind::WebEndpoint,
        SearchEntityKind::Account => EntityKind::Account,
        SearchEntityKind::Organization => EntityKind::Organization,
        SearchEntityKind::NetworkEndpoint => EntityKind::NetworkEndpoint,
        SearchEntityKind::Service => EntityKind::Service,
        SearchEntityKind::WebEndpoint => EntityKind::WebEndpoint,
        SearchEntityKind::Certificate => EntityKind::Certificate,
        SearchEntityKind::SshHostKey => EntityKind::SshHostKey,
        SearchEntityKind::SoftwareIdentity => EntityKind::Technology,
        SearchEntityKind::Technology => EntityKind::Technology,
        SearchEntityKind::Asn => EntityKind::Asn,
        SearchEntityKind::DnsRecord => EntityKind::DnsRecord,
        SearchEntityKind::Repository => EntityKind::Repository,
        SearchEntityKind::NetworkPrefix => EntityKind::NetworkPrefix,
        SearchEntityKind::Package => EntityKind::Package,
        SearchEntityKind::Document => EntityKind::Document,
        SearchEntityKind::ArchiveSnapshot => EntityKind::ArchiveSnapshot,
        SearchEntityKind::PublicKey => EntityKind::PublicKey,
        SearchEntityKind::ExposureEvent => EntityKind::Exposure,
        SearchEntityKind::Provider => EntityKind::Provider,
        SearchEntityKind::Route => EntityKind::Route,
        SearchEntityKind::IdentityHypothesis => EntityKind::IdentityHypothesis,
        SearchEntityKind::Software => EntityKind::Software,
    }
}

/// Build the seed graph node plus zero-network derived nodes.
///
/// Derivation is conservative and local-only:
/// * email -> domain (`references`, 95, derived) + local-part username
///   (`uses_username`, 60, derived) when the local part is username-shaped.
/// * url -> host domain or IP literal (`references`, 90, derived).
/// * repository -> organization owner (`references`, 70, derived).
/// * everything else -> seed only (enrichment lives in `investigate`).
fn build_graph(seed: &SearchEntity) -> (ScanGraph, Vec<SearchObservation>) {
    let mut graph = ScanGraph::default();
    let seed_prov = seed_provenance(seed);
    let mut seed_attrs = seed.attributes.clone();
    seed_attrs.insert("canonical_value".to_owned(), seed.canonical_value.clone());
    graph.upsert_entity(
        seed.id.clone(),
        graph_kind(seed.kind),
        seed.display_value.clone(),
        seed_attrs,
        &seed_prov,
    );

    let mut observations = vec![observation(
        seed,
        SearchStatus::Confirmed,
        95,
        vec![format!(
            "canonical {} seed {}",
            seed.kind.as_str(),
            seed.canonical_value
        )],
        BTreeMap::new(),
    )];

    match seed.kind {
        SearchEntityKind::EmailAddress => {
            if let Some(domain) = seed.attributes.get("domain").cloned() {
                let domain_id = crate::assets::public_entity_id("domain", &domain);
                let prov = derived_provenance(
                    seed,
                    "search.entity.email_to_domain",
                    &format!("email domain is {domain}"),
                );
                graph.upsert_entity(
                    domain_id.clone(),
                    EntityKind::Domain,
                    domain.clone(),
                    BTreeMap::from([("domain".to_owned(), domain.clone())]),
                    &prov,
                );
                graph.link(
                    seed.id.clone(),
                    domain_id.clone(),
                    EdgeRelation::References,
                    95,
                    &prov,
                    vec![format!("email domain is {domain}")],
                    BTreeMap::from([("observation_class".to_owned(), "derived".to_owned())]),
                );
                observations.push(observation(
                    seed,
                    SearchStatus::Confirmed,
                    95,
                    vec![format!("email domain is {domain}")],
                    BTreeMap::from([
                        ("derived_entity".to_owned(), domain_id),
                        ("derived_kind".to_owned(), "domain".to_owned()),
                    ]),
                ));
            }
            // Local-part username hint: evidence of reuse, never identity.
            if let Some(local) = seed.attributes.get("local_part").cloned() {
                let candidate = local.trim();
                if !candidate.is_empty()
                    && candidate.len() <= 128
                    && !candidate.chars().any(char::is_control)
                    && !candidate.contains(char::is_whitespace)
                {
                    let canonical = candidate.to_ascii_lowercase();
                    let username_id = crate::assets::public_entity_id("username", &canonical);
                    let prov = derived_provenance(
                        seed,
                        "search.entity.email_to_username",
                        &format!("email local part is {candidate}"),
                    );
                    graph.upsert_entity(
                        username_id.clone(),
                        EntityKind::Username,
                        candidate.to_owned(),
                        BTreeMap::from([("canonical_value".to_owned(), canonical)]),
                        &prov,
                    );
                    graph.link(
                        seed.id.clone(),
                        username_id.clone(),
                        EdgeRelation::UsesUsername,
                        60,
                        &prov,
                        vec![format!("email local part is {candidate}")],
                        BTreeMap::from([("observation_class".to_owned(), "derived".to_owned())]),
                    );
                    observations.push(observation(
                        seed,
                        SearchStatus::Possible,
                        60,
                        vec![format!(
                            "email local part {candidate} may indicate a username (weak reuse hint)"
                        )],
                        BTreeMap::from([
                            ("derived_entity".to_owned(), username_id),
                            ("derived_kind".to_owned(), "username".to_owned()),
                        ]),
                    ));
                }
            }
        }
        SearchEntityKind::Url => {
            let url_text = seed
                .attributes
                .get("url")
                .cloned()
                .unwrap_or_else(|| seed.canonical_value.clone());
            if let Ok(parsed) = url::Url::parse(&url_text) {
                if let Some(host) = parsed.host_str() {
                    let host_lower = host.to_ascii_lowercase();
                    if let Ok(ip) = host_lower.parse::<std::net::IpAddr>() {
                        let ip_id = crate::assets::public_entity_id(
                            "ip_address",
                            &ip.to_string().to_ascii_lowercase(),
                        );
                        let prov = derived_provenance(
                            seed,
                            "search.entity.url_to_ip",
                            &format!("URL host is IP literal {ip}"),
                        );
                        graph.upsert_entity(
                            ip_id.clone(),
                            EntityKind::IpAddress,
                            ip.to_string(),
                            BTreeMap::from([("address".to_owned(), ip.to_string())]),
                            &prov,
                        );
                        graph.link(
                            seed.id.clone(),
                            ip_id.clone(),
                            EdgeRelation::References,
                            90,
                            &prov,
                            vec![format!("URL host is IP literal {ip}")],
                            BTreeMap::from([(
                                "observation_class".to_owned(),
                                "derived".to_owned(),
                            )]),
                        );
                        observations.push(observation(
                            seed,
                            SearchStatus::Confirmed,
                            90,
                            vec![format!("URL host is IP literal {ip}")],
                            BTreeMap::from([
                                ("derived_entity".to_owned(), ip_id),
                                ("derived_kind".to_owned(), "ip_address".to_owned()),
                            ]),
                        ));
                    } else if let Some(domain) = crate::search::canonical_domain_value(&host_lower)
                    {
                        let domain_id = crate::assets::public_entity_id("domain", &domain);
                        let prov = derived_provenance(
                            seed,
                            "search.entity.url_to_domain",
                            &format!("URL host is {domain}"),
                        );
                        graph.upsert_entity(
                            domain_id.clone(),
                            EntityKind::Domain,
                            domain.clone(),
                            BTreeMap::from([("domain".to_owned(), domain.clone())]),
                            &prov,
                        );
                        graph.link(
                            seed.id.clone(),
                            domain_id.clone(),
                            EdgeRelation::References,
                            90,
                            &prov,
                            vec![format!("URL host is {domain}")],
                            BTreeMap::from([(
                                "observation_class".to_owned(),
                                "derived".to_owned(),
                            )]),
                        );
                        observations.push(observation(
                            seed,
                            SearchStatus::Confirmed,
                            90,
                            vec![format!("URL host is {domain}")],
                            BTreeMap::from([
                                ("derived_entity".to_owned(), domain_id),
                                ("derived_kind".to_owned(), "domain".to_owned()),
                            ]),
                        ));
                    }
                }
            }
        }
        SearchEntityKind::Repository => {
            if let Some(owner) = seed.attributes.get("owner").cloned() {
                let org_id = crate::assets::public_entity_id("organization", &owner);
                let prov = derived_provenance(
                    seed,
                    "search.entity.repository_to_org",
                    &format!("repository owner is {owner}"),
                );
                graph.upsert_entity(
                    org_id.clone(),
                    EntityKind::Organization,
                    owner.clone(),
                    BTreeMap::from([("name".to_owned(), owner.clone())]),
                    &prov,
                );
                graph.link(
                    seed.id.clone(),
                    org_id.clone(),
                    EdgeRelation::References,
                    70,
                    &prov,
                    vec![format!("repository owner is {owner}")],
                    BTreeMap::from([("observation_class".to_owned(), "derived".to_owned())]),
                );
                observations.push(observation(
                    seed,
                    SearchStatus::Confirmed,
                    70,
                    vec![format!("repository owner is {owner}")],
                    BTreeMap::from([
                        ("derived_entity".to_owned(), org_id),
                        ("derived_kind".to_owned(), "organization".to_owned()),
                    ]),
                ));
            }
        }
        _ => {}
    }

    (graph, observations)
}

/// Execute a zero-network passive search for one entity value.
///
/// `kind` selects the constructor; `value` is operator input. No DNS, no
/// HTTP, no raw sockets. Deterministic over the input plus timestamps.
pub fn execute_entity_search(
    kind: SearchEntityKind,
    value: &str,
) -> Result<EntitySearchReport, SearchError> {
    let started_at = unix_timestamp();
    let seed = match kind {
        SearchEntityKind::EmailAddress => SearchEntity::email(value, started_at)?,
        SearchEntityKind::Domain => SearchEntity::domain(value, started_at)?,
        SearchEntityKind::Hostname => SearchEntity::hostname(value, started_at)?,
        SearchEntityKind::IpAddress => SearchEntity::ip_address(value, started_at)?,
        SearchEntityKind::Asn => SearchEntity::asn(value, started_at)?,
        SearchEntityKind::Url => SearchEntity::url(value, started_at)?,
        SearchEntityKind::Repository => SearchEntity::repository(value, started_at)?,
        SearchEntityKind::Organization => SearchEntity::organization(value, started_at)?,
        // Username keeps its dedicated provider-search path; route it
        // through the same local canonicalization here only for `--explain`
        // style planning without provider contact.
        SearchEntityKind::Username => SearchEntity::username(value, started_at)?,
        other => {
            return Err(SearchError::InvalidEntity(format!(
                "passive search does not yet support {} (see `rxscan investigate transforms`)",
                other.as_str()
            )));
        }
    };
    let (graph, observations) = build_graph(&seed);
    let completed_at = unix_timestamp();
    Ok(EntitySearchReport {
        schema_version: ENTITY_SEARCH_SCHEMA_VERSION,
        run_id: crate::assets::public_entity_id("search_run", &format!("{}:{started_at}", seed.id)),
        seed,
        observations,
        graph,
        network_scans: 0,
        started_at,
        completed_at,
    })
}

/// Plan-only explanation: no contact, no persistence.
pub fn explain_entity_plan(kind: SearchEntityKind, value: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Entity search plan\nseed kind: {}\n",
        kind.as_str()
    ));
    out.push_str(&format!("seed input: {value}\n"));
    out.push_str("contact class: passive_public\n");
    out.push_str("network contact: none (local canonicalization only)\n");
    out.push_str("network scans: 0\n");
    out.push_str("enrichment: rxscan investigate (DNS/profile transforms)\n");
    out
}

/// Bounded human rendering (no ANSI; caller adds workflow header).
pub fn render_entity_human(report: &EntitySearchReport, show_all: bool) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Entity search: {} ({})\n",
        report.seed.display_value,
        report.seed.kind.as_str()
    ));
    out.push_str(&format!("canonical: {}\n", report.seed.canonical_value));
    out.push_str(&format!("entity id: {}\n", report.seed.id));
    out.push('\n');
    out.push_str("Observations\n");
    for obs in &report.observations {
        out.push_str(&format!(
            "  {:?} confidence={} {}\n",
            obs.status,
            obs.confidence,
            obs.evidence.first().cloned().unwrap_or_default()
        ));
    }
    if show_all || report.graph.entities.len() <= 8 {
        out.push_str("\nGraph\n");
        let mut ids: Vec<&String> = report.graph.entities.keys().collect();
        ids.sort();
        for id in ids {
            if let Some(entity) = report.graph.entities.get(id) {
                out.push_str(&format!(
                    "  {} {:?} {}\n",
                    entity.id, entity.kind, entity.label
                ));
            }
        }
        for edge in &report.graph.edges {
            out.push_str(&format!(
                "  {} --{}--> {} confidence={}\n",
                edge.from, edge.relation, edge.to, edge.confidence
            ));
        }
    } else {
        out.push_str(&format!(
            "\nGraph: {} entities, {} relationships (use --all or --json for complete data)\n",
            report.graph.entities.len(),
            report.graph.edges.len()
        ));
    }
    out.push_str(&format!(
        "\nSummary\n  observations: {}\n  entities: {}\n  relationships: {}\n  network scans: 0\n",
        report.observations.len(),
        report.graph.entities.len(),
        report.graph.edges.len()
    ));
    out
}

/// Typed JSONL: `search_start`, one `observation` per local finding,
/// `entity` / `relationship` graph records, then `search_summary`.
/// Pure JSON, one object per line, deterministic order, no ANSI.
pub fn render_entity_jsonl(report: &EntitySearchReport) -> String {
    fn envelope(record_type: &'static str, payload: serde_json::Value) -> String {
        serde_json::json!({
            "schema_version": 1,
            "record_type": record_type,
            "payload": payload,
        })
        .to_string()
    }
    let mut out = String::new();
    out.push_str(&envelope(
        "search_start",
        serde_json::json!({
            "run_id": report.run_id,
            "entity": report.seed.id,
            "seed_kind": report.seed.kind.as_str(),
            "seed_display": report.seed.display_value,
            "seed_canonical": report.seed.canonical_value,
            "network_scans": report.network_scans,
            "started_at": report.started_at,
        }),
    ));
    out.push('\n');
    for obs in &report.observations {
        out.push_str(&envelope(
            "observation",
            serde_json::json!({
                "entity": obs.input_entity_id,
                "provider_id": obs.provider_id,
                "definition_version": obs.provider_version,
                "status": obs.status,
                "confidence": obs.confidence,
                "contact_class": obs.contact_class,
                "evidence": obs.evidence,
                "attributes": obs.attributes,
                "task_id": obs.task_id,
                "timestamp": obs.timestamp,
            }),
        ));
        out.push('\n');
    }
    let mut ids: Vec<&String> = report.graph.entities.keys().collect();
    ids.sort();
    for id in ids {
        if let Some(entity) = report.graph.entities.get(id) {
            out.push_str(&envelope(
                "entity",
                serde_json::json!({
                    "id": entity.id,
                    "kind": entity.kind.to_string(),
                    "label": entity.label,
                    "attributes": entity.attributes,
                    "observations": entity.observations,
                }),
            ));
            out.push('\n');
        }
    }
    for edge in &report.graph.edges {
        out.push_str(&envelope(
            "relationship",
            serde_json::json!({
                "from": edge.from,
                "to": edge.to,
                "relation": edge.relation.to_string(),
                "confidence": edge.confidence,
                "evidence": edge.evidence,
                "attributes": edge.attributes,
            }),
        ));
        out.push('\n');
    }
    out.push_str(&envelope(
        "search_summary",
        serde_json::json!({
            "run_id": report.run_id,
            "observations": report.observations.len(),
            "entities": report.graph.entities.len(),
            "relationships": report.graph.edges.len(),
            "network_scans": report.network_scans,
            "started_at": report.started_at,
            "completed_at": report.completed_at,
        }),
    ));
    out.push('\n');
    out
}

/// Persist a passive entity report into the existing SQLite project graph.
///
/// Reuses the scan-import path (no second database, no second schema).
/// Evidence is stored without secrets; this module never handles secrets.
pub fn persist_entity_report(
    db: &mut crate::project_db::ProjectDb,
    report: &EntitySearchReport,
) -> Result<crate::project_db::ImportStats, SearchError> {
    use crate::project_db::{
        ClassifierProvenance, CoverageSnapshot, PackProvenance, RetentionMode, ScanImport,
    };
    let coverage = CoverageSnapshot {
        modules_completed: vec![format!("search.entity.{}", report.seed.kind.as_str())],
        ..CoverageSnapshot::default()
    };
    let import = ScanImport {
        scan_id: report.run_id.clone(),
        plan_id: crate::assets::public_entity_id(
            "search_plan",
            &format!("entity:{}", report.seed.kind.as_str()),
        ),
        started_at_ms: report.started_at.saturating_mul(1_000),
        finished_at_ms: report.completed_at.saturating_mul(1_000),
        scope_json: serde_json::json!({
            "contact_class": "passive_public",
            "direct_network": false,
            "seed_kind": report.seed.kind.as_str(),
        })
        .to_string(),
        workflow: "entity_search".to_owned(),
        level: 0,
        termination: "complete".to_owned(),
        tasks_admitted: report.observations.len() as u64,
        tasks_completed: report.observations.len() as u64,
        coverage,
        classifier: ClassifierProvenance {
            tool_version: crate::project_db::TOOL_VERSION.to_owned(),
            packs: vec![PackProvenance {
                path: "local:entity_search/v1".to_owned(),
                schema_version: 1,
                rule_count: 1,
            }],
            rules_used: vec!["local@v1".to_owned()],
        },
        retention: RetentionMode::Standard,
    };
    let stats = db.import_scan(&import, &report.graph)?;
    let evidence: Vec<(String, String, u8, serde_json::Value, u64)> = report
        .observations
        .iter()
        .map(|obs| {
            (
                "search.entity.local".to_owned(),
                obs.input_entity_id.clone(),
                obs.confidence,
                serde_json::json!({
                    "provider": obs.provider_id,
                    "status": obs.status,
                    "evidence": obs.evidence,
                    "attributes": obs.attributes,
                    "contact_class": obs.contact_class,
                    "task_id": obs.task_id,
                }),
                obs.timestamp.saturating_mul(1_000),
            )
        })
        .collect();
    db.store_evidence(&report.run_id, &evidence, RetentionMode::Standard)?;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_canonical_and_derived_domain() {
        let report =
            execute_entity_search(SearchEntityKind::EmailAddress, "User@Example.test").unwrap();
        assert_eq!(report.seed.canonical_value, "user@example.test");
        assert_eq!(report.network_scans, 0);
        // Seed + domain + username hint.
        assert!(report.graph.entities.len() >= 2);
        let domain_id = crate::assets::public_entity_id("domain", "example.test");
        assert!(report.graph.entities.contains_key(&domain_id));
    }

    #[test]
    fn domain_identity_is_stable() {
        let a = execute_entity_search(SearchEntityKind::Domain, "Example.TEST.").unwrap();
        let b = execute_entity_search(SearchEntityKind::Domain, "example.test").unwrap();
        assert_eq!(a.seed.id, b.seed.id);
        assert_eq!(a.seed.canonical_value, "example.test");
    }

    #[test]
    fn ip_and_asn_canonicalize() {
        let ip = execute_entity_search(SearchEntityKind::IpAddress, "192.0.2.10").unwrap();
        assert_eq!(ip.seed.canonical_value, "192.0.2.10");
        let asn = execute_entity_search(SearchEntityKind::Asn, "as64500").unwrap();
        assert_eq!(asn.seed.canonical_value, "AS64500");
        let asn2 = execute_entity_search(SearchEntityKind::Asn, "AS64500").unwrap();
        assert_eq!(asn.seed.id, asn2.seed.id);
    }

    #[test]
    fn url_derives_domain_locally() {
        let report =
            execute_entity_search(SearchEntityKind::Url, "https://api.example.test/path").unwrap();
        let domain_id = crate::assets::public_entity_id("domain", "api.example.test");
        assert!(report.graph.entities.contains_key(&domain_id));
        assert_eq!(report.network_scans, 0);
    }

    #[test]
    fn repo_derives_org() {
        let report =
            execute_entity_search(SearchEntityKind::Repository, "Example-Org/Example-Project")
                .unwrap();
        assert_eq!(report.seed.canonical_value, "example-org/example-project");
        let org_id = crate::assets::public_entity_id("organization", "example-org");
        assert!(report.graph.entities.contains_key(&org_id));
    }

    #[test]
    fn invalid_entities_rejected_without_network() {
        assert!(execute_entity_search(SearchEntityKind::EmailAddress, "not-an-email").is_err());
        assert!(execute_entity_search(SearchEntityKind::Domain, "localhost").is_err());
        assert!(execute_entity_search(SearchEntityKind::IpAddress, "999.1.1.1").is_err());
        assert!(execute_entity_search(SearchEntityKind::Asn, "AS0").is_err());
        assert!(execute_entity_search(SearchEntityKind::Url, "gopher://example.test").is_err());
        assert!(execute_entity_search(SearchEntityKind::Repository, "onlyowner").is_err());
    }

    #[test]
    fn jsonl_is_typed_and_zero_network() {
        let report = execute_entity_search(SearchEntityKind::Domain, "example.test").unwrap();
        let jsonl = render_entity_jsonl(&report);
        assert!(jsonl.contains("\"record_type\":\"search_start\""));
        assert!(jsonl.contains("\"record_type\":\"search_summary\""));
        assert!(jsonl.contains("\"network_scans\":0"));
        for line in jsonl.lines() {
            assert!(serde_json::from_str::<serde_json::Value>(line).is_ok());
        }
    }
}
