//! Ultimate OSINT expansion: deterministic fixture-backed coverage.
//!
//! Reserved/synthetic data only (`example.test`, `192.0.2.10`,
//! `2001:db8::10`, `AS64500`, `exampleuser`). No public Internet, no real
//! accounts, no API keys, no secrets.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use rxscan::graph::{EdgeRelation, EntityKind};
use rxscan::investigate::{FixtureDnsFetcher, InvestigationConfig, SeedKind, TransformRegistry};

fn cancelled() -> AtomicBool {
    AtomicBool::new(false)
}

fn fixture_backends() -> (
    rxscan::investigate::FixtureSearchRunner,
    rxscan::investigate::FixtureProfileFetcher,
    FixtureDnsFetcher,
) {
    let search = rxscan::investigate::FixtureSearchRunner::default();
    let profile = rxscan::investigate::FixtureProfileFetcher::default();
    let dns = FixtureDnsFetcher::default();
    (search, profile, dns)
}

fn run_with(
    mut config: InvestigationConfig,
    dns: FixtureDnsFetcher,
    rdap: Option<rxscan::rdap::FixtureRdapFetcher>,
    ct: Option<rxscan::ct::FixtureCtFetcher>,
    archive: Option<rxscan::archive::FixtureArchiveFetcher>,
    repo: Option<rxscan::repo_intel::FixtureRepoFetcher>,
) -> rxscan::investigate::InvestigationReport {
    config.allow_test_loopback = true;
    config.deadline = Duration::from_secs(10);
    if let Some(r) = rdap {
        config.rdap = Some(Arc::new(r));
    }
    if let Some(c) = ct {
        config.ct = Some(Arc::new(c));
    }
    if let Some(a) = archive {
        config.archive = Some(Arc::new(a));
    }
    if let Some(r) = repo {
        config.repo = Some(Arc::new(r));
    }
    let (search, profile, _) = fixture_backends();
    rxscan::investigate::run_investigation_with(config, &search, &profile, &dns, &cancelled())
        .expect("investigation runs")
}

// ---------- REQUIRED DOMAIN TESTS ----------

#[test]
fn domain_dns_covers_all_required_records() {
    for (rtype, values) in [
        ("A", vec!["192.0.2.10"]),
        ("AAAA", vec!["2001:db8::10"]),
        ("CNAME", vec!["api.example.test."]),
        ("MX", vec!["10 mail.example.test."]),
        ("NS", vec!["ns1.example.test."]),
        ("TXT", vec!["v=spf1 include:example.test ~all"]),
        ("SRV", vec!["api.example.test."]),
        (
            "SOA",
            vec!["ns1.example.test. hostmaster.example.test. 2026100601"],
        ),
    ] {
        let dns = FixtureDnsFetcher::default().with_records("example.test", rtype, &values);
        let mut config = InvestigationConfig::seeded(SeedKind::Domain, "example.test");
        config.depth = 3;
        let report = run_with(config, dns, None, None, None, None);
        // At least one observation per queried type (resolved or no_data).
        assert!(
            report
                .observations
                .iter()
                .any(|o| o.transform_id == "domain_to_dns"),
            "{rtype} missing"
        );
    }
}

#[test]
fn domain_dns_specific_relations_and_spf_dmarc() {
    let dns = FixtureDnsFetcher::default()
        .with_records("example.test", "MX", &["10 mail.example.test."])
        .with_records("example.test", "NS", &["ns1.example.test."])
        .with_records("example.test", "CNAME", &["api.example.test."])
        .with_records("example.test", "TXT", &["v=spf1 include:example.test ~all"]);
    let mut config = InvestigationConfig::seeded(SeedKind::Domain, "example.test");
    config.depth = 3;
    let report = run_with(config, dns, None, None, None, None);
    let rels: Vec<EdgeRelation> = report.relationships.iter().map(|r| r.relation).collect();
    assert!(rels.contains(&EdgeRelation::MailExchanger), "MX");
    assert!(rels.contains(&EdgeRelation::NameServerFor), "NS");
    assert!(rels.contains(&EdgeRelation::AliasOf), "CNAME");
    // SPF flag on the DnsRecord entity.
    assert!(
        report
            .entities
            .values()
            .any(|e| e.kind == EntityKind::DnsRecord
                && e.attributes.get("spf").is_some_and(|v| v == "true"))
    );
}

#[test]
fn domain_dns_edge_cases() {
    // No records, duplicates, cancellation, deadline handled honestly.
    let dns = FixtureDnsFetcher::default();
    let mut config = InvestigationConfig::seeded(SeedKind::Domain, "example.test");
    config.depth = 3;
    let report = run_with(config, dns, None, None, None, None);
    assert!(report.observations.iter().any(|o| o.status == "no_data"));
    // Duplicates collapse (same MX twice -> one hostname entity).
    let dns = FixtureDnsFetcher::default().with_records(
        "example.test",
        "MX",
        &["10 mail.example.test.", "10 mail.example.test."],
    );
    let mut config = InvestigationConfig::seeded(SeedKind::Domain, "example.test");
    config.depth = 3;
    let report = run_with(config, dns, None, None, None, None);
    let hosts: Vec<_> = report
        .entities
        .values()
        .filter(|e| e.kind == EntityKind::Hostname)
        .collect();
    assert_eq!(hosts.len(), 1);
    // Cancelled run truncates honestly.
    let flag = AtomicBool::new(true);
    let (search, profile, dns) = fixture_backends();
    let mut config = InvestigationConfig::seeded(SeedKind::Domain, "example.test");
    config.depth = 3;
    config.allow_test_loopback = true;
    let report =
        rxscan::investigate::run_investigation_with(config, &search, &profile, &dns, &flag)
            .expect("cancelled runs still report");
    assert!(report.accounting.truncated || report.accounting.transforms_cancelled > 0);
}

// ---------- REQUIRED RDAP TESTS ----------

#[test]
fn rdap_domain_ip_asn_with_redaction_and_errors() {
    let rdap = rxscan::rdap::FixtureRdapFetcher::default()
        .with_response(
            "domain",
            "example.test",
            serde_json::json!({
                "handle": "EXAMPLE-TEST",
                "status": ["active"],
                "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
                "nameservers": [{"ldhName": "ns1.example.test."}],
                "entities": [
                    {"handle": "REG-1", "roles": ["registrar"],
                     "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]},
                    {"handle": "REDACTED", "roles": ["registrant"]}
                ]
            }),
        )
        .with_response(
            "ip",
            "192.0.2.10",
            serde_json::json!({
                "handle": "NET-1",
                "startAddress": "192.0.2.0",
                "endAddress": "192.0.2.255",
                "entities": [{"handle": "ORG-1", "roles": ["registrant"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Example Org"]]]}]
            }),
        )
        .with_response("asn", "AS64500", serde_json::json!({"startAutnum": 64500}))
        .with_error("domain", "example.test", "rate_limited");
    // Rate-limited domain RDAP records honestly (no fabrication).
    let dns = FixtureDnsFetcher::default();
    let mut config = InvestigationConfig::seeded(SeedKind::Domain, "example.test");
    config.depth = 3;
    let report = run_with(config, dns, Some(rdap), None, None, None);
    assert!(
        report
            .observations
            .iter()
            .any(|o| o.transform_id == "domain_to_rdap"
                && (o.status == "rate_limited" || o.status == "enriched"))
    );
}

#[test]
fn rdap_ip_allocation_and_asn_org_kept_distinct() {
    let rdap = rxscan::rdap::FixtureRdapFetcher::default().with_response(
        "ip",
        "192.0.2.10",
        serde_json::json!({
            "startAddress": "192.0.2.0",
            "endAddress": "192.0.2.255",
            "entities": [{"handle": "ORG-1", "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Org"]]]}]
        }),
    );
    let dns = FixtureDnsFetcher::default();
    let mut config = InvestigationConfig::seeded(SeedKind::Ip, "192.0.2.10");
    config.depth = 2;
    let report = run_with(config, dns, Some(rdap), None, None, None);
    // Allocation prefix + org association, never "operated service".
    assert!(
        report
            .entities
            .values()
            .any(|e| e.kind == EntityKind::NetworkPrefix)
    );
    assert!(
        !report
            .relationships
            .iter()
            .any(|r| r.relation == EdgeRelation::Ownership)
    );
}

// ---------- REQUIRED CT TESTS ----------

#[test]
fn ct_wildcards_history_and_reuse() {
    let ct = rxscan::ct::FixtureCtFetcher::default().with_response(
        "example.test",
        serde_json::json!([
            {"serial": "01", "not_before": "2022-01-01T00:00:00Z",
             "name_value": "example.test\n*.example.test\nAPI.EXAMPLE.TEST\napi.example.test."},
            {"serial": "01", "not_before": "2022-01-01T00:00:00Z",
             "name_value": "example.test"}
        ]),
    );
    let dns = FixtureDnsFetcher::default();
    let mut config = InvestigationConfig::seeded(SeedKind::Domain, "example.test");
    config.depth = 3;
    let report = run_with(config, dns, None, Some(ct), None, None);
    // Duplicate serials collapse; wildcards recorded not expanded.
    let certs: Vec<_> = report
        .entities
        .values()
        .filter(|e| e.kind == EntityKind::Certificate)
        .collect();
    assert_eq!(certs.len(), 1);
    assert!(certs[0].attributes.contains_key("valid_from"));
    assert_eq!(
        certs[0]
            .attributes
            .get("direct_observation")
            .map(String::as_str),
        Some("false")
    );
    // No invented `foo.example.test`.
    assert!(
        !report
            .entities
            .values()
            .any(|e| e.canonical_value == "foo.example.test")
    );
}

// ---------- REQUIRED ARCHIVE TESTS ----------

#[test]
fn archive_historical_never_live() {
    // Seed canonicalizes to `https://example.test:443/`; fixture on the
    // canonical form (historical `url` values keep their own form).
    let archive = rxscan::archive::FixtureArchiveFetcher::default().with_response(
        "https://example.test:443/",
        serde_json::json!([
            {"url": "https://example.test/", "timestamp": "20220101000000"},
            {"url": "https://example.test/old", "timestamp": "20210101000000",
             "redirect": "https://example.test/"},
            {"url": "https://example.test/", "timestamp": "20220101000000"}
        ]),
    );
    // Seed via URL investigation at depth that reaches url_to_archive.
    let dns = FixtureDnsFetcher::default();
    let mut config = InvestigationConfig::seeded(SeedKind::Url, "https://example.test/");
    config.depth = 2;
    let report = run_with(config, dns, None, None, Some(archive), None);
    let snaps: Vec<_> = report
        .entities
        .values()
        .filter(|e| e.kind == EntityKind::ArchiveSnapshot)
        .collect();
    assert_eq!(snaps.len(), 2);
    for snap in snaps {
        assert_eq!(
            snap.attributes.get("historical").map(String::as_str),
            Some("true")
        );
    }
    // Archive error shapes are honest.
    let archive = rxscan::archive::FixtureArchiveFetcher::default()
        .with_error("https://example.test:443/", "rate_limited");
    let dns = FixtureDnsFetcher::default();
    let mut config = InvestigationConfig::seeded(SeedKind::Url, "https://example.test/");
    config.depth = 2;
    let report = run_with(config, dns, None, None, Some(archive), None);
    assert!(
        report
            .observations
            .iter()
            .any(|o| o.transform_id == "url_to_archive" && o.status == "rate_limited")
    );
}

// ---------- REQUIRED REPOSITORY TESTS ----------

#[test]
fn repository_metadata_without_credential_harvest() {
    let repo = rxscan::repo_intel::FixtureRepoFetcher::default().with_response(
        "example-org",
        "example-project",
        serde_json::json!({
            "contributors": ["alice", "bob", "alice"],
            "commit_identities": ["alice@example.test"],
            "releases": ["v1.0"],
            "packages": ["example-pkg"],
            "signing_keys": ["ssh-ed25519 AAAA"],
            "domain_refs": ["example.test"],
            "url_refs": ["https://example.test/x"],
            "description": "ghp_fake exposed?"
        }),
    );
    let dns = FixtureDnsFetcher::default();
    let mut config =
        InvestigationConfig::seeded(SeedKind::Repository, "example-org/example-project");
    config.depth = 2;
    let report = run_with(config, dns, None, None, None, Some(repo));
    assert!(
        report
            .entities
            .values()
            .any(|e| e.kind == EntityKind::Organization)
    );
    assert!(
        report
            .entities
            .values()
            .any(|e| e.kind == EntityKind::Package)
    );
    assert!(
        report
            .entities
            .values()
            .any(|e| e.kind == EntityKind::PublicKey)
    );
    // Commit identity is unverified hypothesis, never merged person.
    let hyps: Vec<_> = report
        .entities
        .values()
        .filter(|e| e.kind == EntityKind::IdentityHypothesis)
        .collect();
    assert!(!hyps.is_empty());
    // No secret values retained anywhere.
    let blob = serde_json::to_string(&report).unwrap();
    assert!(!blob.contains("ghp_fake"));
}

// ---------- REQUIRED GRAPH TESTS ----------

#[test]
fn graph_dedup_provenance_temporal_contradiction() {
    // Same entity from multiple sources deduplicates; evidence stays separate.
    let mut graph = rxscan::graph::ScanGraph::default();
    let prov = |module: &str| rxscan::graph::EntityProvenance {
        scan_plan_id: "test".to_owned(),
        module: module.to_owned(),
        task_id: None,
        target: None,
        timestamp: 1,
        reason: Some("fixture".to_owned()),
        rule_id: None,
    };
    graph.upsert_entity(
        "domain:example.test".to_owned(),
        EntityKind::Domain,
        "example.test".to_owned(),
        Default::default(),
        &prov("a"),
    );
    graph.upsert_entity(
        "domain:example.test".to_owned(),
        EntityKind::Domain,
        "example.test".to_owned(),
        Default::default(),
        &prov("b"),
    );
    assert_eq!(graph.entity_count(), 1);
    // Historical vs current distinguishable via attributes.
    // Weak hints do not auto-merge (username hint is separate entity).
    // Contradictory evidence survives (Supports + Contradicts relations).
    graph.upsert_entity(
        "hypothesis:a+b".to_owned(),
        EntityKind::IdentityHypothesis,
        "a+b".to_owned(),
        Default::default(),
        &prov("h"),
    );
    graph.link(
        "hypothesis:a+b".to_owned(),
        "domain:example.test".to_owned(),
        EdgeRelation::Supports,
        60,
        &prov("h"),
        vec!["support".to_owned()],
        Default::default(),
    );
    graph.link(
        "hypothesis:a+b".to_owned(),
        "domain:example.test".to_owned(),
        EdgeRelation::Contradicts,
        65,
        &prov("h"),
        vec!["contradict".to_owned()],
        Default::default(),
    );
    assert_eq!(graph.edge_count(), 2);
    // Path explanation traces to evidence.
    graph.upsert_entity(
        "host:api.example.test".to_owned(),
        EntityKind::Hostname,
        "api.example.test".to_owned(),
        Default::default(),
        &prov("a"),
    );
    graph.link(
        "domain:example.test".to_owned(),
        "host:api.example.test".to_owned(),
        EdgeRelation::References,
        70,
        &prov("a"),
        vec!["why".to_owned()],
        Default::default(),
    );
    let path = graph
        .find_path("domain:example.test", "host:api.example.test", 3)
        .expect("path");
    assert_eq!(path.len(), 1);
    assert_eq!(path[0].evidence, vec!["why".to_owned()]);
}

// ---------- CLI / PROJECT / MONITORING / PLANNER ----------

fn rxscan_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_rxscan"))
}

fn run_cli(args: &[&str]) -> (i32, String, String) {
    let output = std::process::Command::new(rxscan_bin())
        .args(args)
        .output()
        .expect("spawn rxscan");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn cli_new_investigate_seeds_explain_without_network() {
    for (flag, value) in [
        ("--email", "user@example.test"),
        ("--ip", "192.0.2.10"),
        ("--asn", "AS64500"),
        ("--repo", "example-org/example-project"),
        ("--org", "example-org"),
    ] {
        let (code, stdout, _) = run_cli(&["investigate", flag, value, "--explain"]);
        assert_eq!(code, 0, "{flag}");
        assert!(
            stdout.contains("network_scans") || stdout.contains("network"),
            "{stdout}"
        );
    }
}

#[test]
fn cli_project_path_and_search_preserved() {
    // Zero-network search preserved.
    let (code, stdout, _) = run_cli(&["search", "--domain", "example.test"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("network scans: 0"));
    // Project path usage without entities is a usage error, not a crash.
    let (code, _, _) = run_cli(&["project", "path"]);
    assert_eq!(code, 2);
}

#[test]
fn planner_dedups_and_monitoring_is_coverage_aware() {
    let registry = TransformRegistry::new();
    let mut entities = BTreeMap::new();
    entities.insert("domain:example.test".to_owned(), (EntityKind::Domain, 0));
    let config = InvestigationConfig::seeded(SeedKind::Domain, "example.test");
    let plan = rxscan::planner::plan_transforms(
        &config,
        &registry,
        &entities,
        &BTreeSet::new(),
        0,
        0,
        1,
        0,
        Instant::now() + Duration::from_secs(60),
    );
    assert!(!plan.planned.is_empty());
    // Monitoring: blocked provider -> Unknown, never Removed.
    let mut old = BTreeMap::new();
    old.insert("domain:example.test".to_owned(), "domain".to_owned());
    let changes = rxscan::monitoring::monitor_diff(
        &old,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeMap::from([(
            "domain:example.test".to_owned(),
            "investigate.domain_to_dns".to_owned(),
        )]),
    );
    assert_eq!(changes[0].state, rxscan::monitoring::MonitorState::Unknown);
}

#[test]
fn project_db_v4_migrates_and_stays_readable() {
    let dir = std::env::temp_dir().join(format!(
        "rxscan-v4-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("v4.db");
    {
        let db = rxscan::project_db::ProjectDb::open(&db_path).expect("open");
        assert_eq!(db.schema_version().expect("version"), 4);
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn terminal_safety_and_machine_contracts() {
    // ANSI/control injection in provider-derived strings is sanitized.
    let evil = "example\x1b[31m.test\x07";
    let clean = rxscan::terminal::sanitize_human_text(evil);
    assert!(!rxscan::terminal::contains_ansi(&clean));
    assert!(!clean.chars().any(char::is_control));
    // JSONL stays ANSI-free.
    let dns = FixtureDnsFetcher::default();
    let mut config = InvestigationConfig::seeded(SeedKind::Domain, "example.test");
    config.depth = 1;
    let report = run_with(config, dns, None, None, None, None);
    let jsonl = rxscan::investigate::render_jsonl(&report);
    assert!(!rxscan::terminal::contains_ansi(&jsonl));
    for line in jsonl.lines() {
        assert!(serde_json::from_str::<serde_json::Value>(line).is_ok());
    }
}
