//! Stage 4 evidence-graph V3 tests: observation classes, conflict
//! preservation, correlation without merging, DOT export, and new
//! exposure kind/relation round-trips. Synthetic fixtures only.

use std::collections::BTreeSet;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use rxscan::graph::{EdgeRelation, EntityKind, ScanGraph};
use rxscan::investigate::{
    self, FixtureDnsFetcher, FixtureProfileFetcher, FixtureSearchRunner, InvestigationConfig,
};

fn depth_fixture(depth: u8) -> investigate::InvestigationReport {
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
            "<html><body><a href=\"https://example.test/\">site</a> \
             <a href=\"https://github.com/exampleuser/example-repo\">code</a></body></html>",
        )
        .with_page(
            "https://blog.example.test/exampleuser",
            "https://blog.example.test/exampleuser",
            "<html><body><a href=\"https://example.test/about\">same</a> \
             <a href=\"https://github.com/exampleuser/example-repo\">same code</a></body></html>",
        );
    let dns = FixtureDnsFetcher::default()
        .with_records("example.test", "A", &["192.0.2.10"])
        .with_records("example.test", "MX", &["10 mail.example.test."]);
    let cancelled = AtomicBool::new(false);
    let mut config = InvestigationConfig::username("exampleuser");
    config.depth = depth;
    config.allow_test_loopback = true;
    config.deadline = Duration::from_secs(10);
    investigate::run_investigation_with(config, &search, &profile, &dns, &cancelled).unwrap()
}

#[test]
fn every_relationship_carries_observation_class() {
    let report = depth_fixture(3);
    assert!(!report.relationships.is_empty());
    for rel in &report.relationships {
        let class = rel
            .attributes
            .get("observation_class")
            .expect("every relationship carries observation_class");
        assert!(
            matches!(class.as_str(), "observed" | "derived",),
            "unexpected class {class} on {}",
            rel.relation
        );
        // Inferred verdicts are never auto-emitted by transforms.
        assert_ne!(class, "inferred");
        assert_eq!(
            class,
            match rel.provenance.transform_id.as_str() {
                "url_to_domain" | "url_to_repository" => "derived",
                _ => "observed",
            },
            "wrong class for {}",
            rel.provenance.transform_id
        );
    }
}

#[test]
fn conflicting_provider_outcomes_are_both_preserved() {
    // Fixture search always emits a confirmed set plus a not_found
    // observation; both must survive as independent evidence.
    let report = depth_fixture(1);
    let statuses: BTreeSet<&str> = report
        .observations
        .iter()
        .map(|o| o.status.as_str())
        .collect();
    assert!(statuses.contains("confirmed"), "{statuses:?}");
    assert!(statuses.contains("not_found"), "{statuses:?}");
    // Only positives became relationships.
    assert!(
        report
            .relationships
            .iter()
            .all(|r| r.relation == EdgeRelation::HasAccount)
    );
}

#[test]
fn shared_repository_correlates_without_merging() {
    let report = depth_fixture(2);
    let repos: Vec<_> = report
        .entities
        .values()
        .filter(|e| e.kind == EntityKind::Repository)
        .collect();
    assert_eq!(repos.len(), 1, "one repository, not duplicates");
    // The identical forge URL from two profiles is one Url entity with two
    // independent account paths; the repository derives from it once.
    // Correlation evidence lives on the shared URL (2 inbound account
    // edges) and the shared domain; accounts are never merged.
    let correlations = report.correlations();
    assert!(
        correlations
            .iter()
            .any(|(id, sources)| id == "domain:example.test" && sources.len() >= 2),
        "shared domain must correlate across independent paths"
    );
    let repo_urls: Vec<_> = report
        .relationships
        .iter()
        .filter(|r| r.to == repos[0].id)
        .collect();
    assert_eq!(repo_urls.len(), 1);
    let shared_url = &repo_urls[0].from;
    let inbound = report
        .relationships
        .iter()
        .filter(|r| r.to == *shared_url)
        .count();
    assert!(
        inbound >= 2,
        "shared forge URL keeps both provenance paths, got {inbound}"
    );
    // Repository owner becomes an organization (reconnaissance relation,
    // never a person-identity claim).
    assert!(
        report
            .entities
            .values()
            .any(|e| e.kind == EntityKind::Organization),
        "repository owner must appear as an organization"
    );
    let accounts: Vec<_> = report
        .entities
        .values()
        .filter(|e| e.kind == EntityKind::Account)
        .collect();
    assert_eq!(accounts.len(), 2);
}

#[test]
fn dot_export_is_structured_and_deterministic() {
    let report = depth_fixture(2);
    let first = investigate::render_dot(&report);
    assert!(first.starts_with("digraph investigation {"));
    assert!(first.ends_with("}\n"));
    assert!(!first.contains('\x1b'));
    let node_lines = first
        .lines()
        .filter(|l| l.contains("[label=") && !l.contains("->"))
        .count();
    let edge_lines = first.lines().filter(|l| l.contains("->")).count();
    assert_eq!(node_lines, report.entities.len());
    assert_eq!(edge_lines, report.relationships.len());
    assert_eq!(first, investigate::render_dot(&report));
}

#[test]
fn new_kinds_and_relations_round_trip() {
    for kind in ["exposure", "exposure_source"] {
        let parsed = EntityKind::parse(kind).unwrap_or_else(|| panic!("{kind} parses"));
        assert_eq!(parsed.to_string(), kind);
    }
    for relation in [
        "exposed_in",
        "observed_in",
        "affects",
        "reported_by",
        "targeted_domain",
    ] {
        let parsed = EdgeRelation::parse(relation).unwrap_or_else(|| panic!("{relation} parses"));
        assert_eq!(parsed.to_string(), relation);
    }
    assert!(EntityKind::parse("person").is_none());
    assert!(EdgeRelation::parse("related_to").is_none());
    // Persisted through the versioned project graph.
    let mut graph = ScanGraph::default();
    let proof = rxscan::graph::EntityProvenance {
        scan_plan_id: "test".to_owned(),
        module: "test".to_owned(),
        task_id: None,
        target: None,
        timestamp: 1,
        reason: None,
        rule_id: None,
    };
    graph.upsert_entity(
        "exposure:t:abcd".to_owned(),
        EntityKind::Exposure,
        "breach exposure via t".to_owned(),
        Default::default(),
        &proof,
    );
    graph.upsert_entity(
        "email:user@example.test".to_owned(),
        EntityKind::EmailAddress,
        "user@example.test".to_owned(),
        Default::default(),
        &proof,
    );
    graph.link(
        "email:user@example.test".to_owned(),
        "exposure:t:abcd".to_owned(),
        EdgeRelation::ExposedIn,
        85,
        &proof,
        vec!["test".to_owned()],
        Default::default(),
    );
    let mut db = rxscan::project_db::ProjectDb::open_in_memory().unwrap();
    let import = rxscan::project_db::ScanImport {
        scan_id: "graph-v3-test".to_owned(),
        plan_id: "plan".to_owned(),
        started_at_ms: 1,
        finished_at_ms: 2,
        scope_json: "{}".to_owned(),
        workflow: "test".to_owned(),
        level: 0,
        termination: "complete".to_owned(),
        tasks_admitted: 1,
        tasks_completed: 1,
        coverage: rxscan::project_db::CoverageSnapshot::default(),
        classifier: rxscan::project_db::ClassifierProvenance::default(),
        retention: rxscan::project_db::RetentionMode::Standard,
    };
    let stats = db.import_scan(&import, &graph).unwrap();
    assert_eq!(stats.entities_upserted, 2);
    assert_eq!(stats.relationships_upserted, 1);
}
