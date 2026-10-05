//! Stage 3 defensive exposure-intelligence tests.
//!
//! Synthetic fixtures only. Secret-bearing fixtures use unmistakably fake
//! placeholder values and assert they never appear in the graph, JSON,
//! JSONL, project DB, or terminal output.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use rxscan::exposure::{self, ExposureProvider, FixtureExposureProvider, IdentifierKind};

fn rxscan_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rxscan"))
}

fn run_cli(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(rxscan_bin())
        .args(args)
        .output()
        .expect("spawn rxscan");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn write_dataset(name: &str, content: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("rxscan-exp-{name}-{}", std::process::id()));
    std::fs::write(&path, content).unwrap();
    path
}

const FAKE_SECRETS: &[&str] = &[
    "FAKE-SECRET-PW-0000",
    "FAKE-SECRET-HASH-0000",
    "FAKE-SECRET-SESSION-0000",
    "FAKE-SECRET-APIKEY-0000",
];

fn assert_clean(text: &str) {
    for secret in FAKE_SECRETS {
        assert!(!text.contains(secret), "secret material leaked");
    }
    assert!(
        !text.contains('\x1b'),
        "machine output must never contain ANSI"
    );
}

// ---------------------------------------------------------------------------
// CLI: plan-only and validation paths (offline, no network).
// ---------------------------------------------------------------------------

#[test]
fn exposure_explain_discloses_identifier_sending() {
    let (code, stdout, _) = run_cli(&["exposure", "--email", "user@example.test", "--explain"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("sends"));
    assert!(stdout.contains("secret storage    disabled"));
    assert!(stdout.contains("raw storage       disabled"));
}

#[test]
fn exposure_rejects_bad_input() {
    let (code, _, stderr) = run_cli(&["exposure", "--explain"]);
    assert_eq!(code, 2, "{stderr}");
    let (code, _, _) = run_cli(&[
        "exposure",
        "--email",
        "a@example.test",
        "--username",
        "b",
        "--explain",
    ]);
    assert_eq!(code, 2);
    let (code, _, _) = run_cli(&["exposure", "--email", "not-an-email", "--explain"]);
    assert_eq!(code, 2);
    let (code, _, _) = run_cli(&["exposure", "--email", "a@example.test", "--json", "--jsonl"]);
    assert_eq!(code, 2);
}

#[test]
fn exposure_without_credentials_reports_unavailable() {
    // No RXSCAN_EXPOSURE_* env in test: the HTTP provider must degrade to
    // an explicit unavailable observation, never a silent skip.
    let (code, stdout, _) = run_cli(&["exposure", "--email", "user@example.test", "--json"]);
    assert_eq!(code, 0);
    assert_clean(&stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["network_scans"], 0);
    let statuses: Vec<&str> = report["observations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["status"].as_str().unwrap())
        .collect();
    assert!(
        statuses.contains(&"unavailable") || statuses.contains(&"no_match"),
        "unexpected statuses: {statuses:?}"
    );
}

// ---------------------------------------------------------------------------
// Local dataset: match, no-match, malformed, secret redaction.
// ---------------------------------------------------------------------------

#[test]
fn dataset_match_normalizes_and_drops_secrets() {
    let path = write_dataset(
        "match",
        r#"{"exposures": [
          {"identifier_type": "email", "identifier": "user@example.test",
           "source": "op-list", "source_name": "OpBreach",
           "exposure_type": "breach", "affected_domain": "example.test",
           "confidence": 80,
           "record": {"password": "FAKE-SECRET-PW-0000",
                      "session_cookie": "FAKE-SECRET-SESSION-0000"}}
        ]}"#,
    );
    let (code, stdout, _) = run_cli(&[
        "exposure",
        "--email",
        "user@example.test",
        "--dataset",
        path.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(code, 0);
    assert_clean(&stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["exposures"].as_array().unwrap().len(), 1);
    let exposure = &report["exposures"][0];
    assert_eq!(exposure["secret_material_retained"], false);
    assert_eq!(exposure["credential_material_exposed"], true);
    assert_eq!(exposure["session_material_exposed"], true);
    assert_eq!(report["accounting"]["secrets_retained"], 0);
    assert!(report["accounting"]["secrets_dropped"].as_u64().unwrap() >= 2);
    std::fs::remove_file(&path).ok();
}

#[test]
fn dataset_no_match_is_distinct_from_not_checked() {
    let path = write_dataset(
        "nomatch",
        r#"{"exposures": [
          {"identifier_type": "email", "identifier": "other@example.test",
           "source": "op-list", "exposure_type": "breach"}
        ]}"#,
    );
    let (code, stdout, _) = run_cli(&[
        "exposure",
        "--email",
        "user@example.test",
        "--dataset",
        path.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(code, 0);
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["exposures"].as_array().unwrap().len(), 0);
    let statuses: Vec<&str> = report["observations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["status"].as_str().unwrap())
        .collect();
    assert!(statuses.contains(&"no_match"), "{statuses:?}");
    std::fs::remove_file(&path).ok();
}

#[test]
fn dataset_malformed_is_an_observation_not_a_panic() {
    let path = write_dataset("bad", "not json at all {{{");
    let (code, stdout, _) = run_cli(&[
        "exposure",
        "--email",
        "user@example.test",
        "--dataset",
        path.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(code, 0);
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let statuses: Vec<&str> = report["observations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["status"].as_str().unwrap())
        .collect();
    assert!(statuses.contains(&"malformed"), "{statuses:?}");
    report["accounting"].get("providers_completed").unwrap();
    std::fs::remove_file(&path).ok();
}

#[test]
fn exposure_jsonl_is_typed_and_clean() {
    let path = write_dataset(
        "jsonl",
        r#"{"exposures": [
          {"identifier_type": "username", "identifier": "exampleuser",
           "source": "op-list", "exposure_type": "paste"}
        ]}"#,
    );
    let (code, stdout, _) = run_cli(&[
        "exposure",
        "--username",
        "exampleuser",
        "--dataset",
        path.to_str().unwrap(),
        "--jsonl",
    ]);
    assert_eq!(code, 0);
    assert_clean(&stdout);
    let mut kinds = Vec::new();
    for line in stdout.lines() {
        let record: serde_json::Value = serde_json::from_str(line).expect("every line parses");
        kinds.push(record["record_type"].as_str().unwrap().to_owned());
    }
    assert_eq!(kinds.first().unwrap(), "exposure_start");
    assert_eq!(kinds.last().unwrap(), "exposure_summary");
    assert!(kinds.contains(&"exposure".to_owned()));
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// Library: secret redaction across graph, DB, and terminal.
// ---------------------------------------------------------------------------

#[test]
fn secrets_never_reach_graph_db_or_terminal() {
    let providers: Vec<Box<dyn ExposureProvider>> =
        vec![Box::new(FixtureExposureProvider::default())];
    let cancelled = AtomicBool::new(false);
    let report = exposure::run_exposure(
        "someone-exposed@example.test",
        IdentifierKind::Email,
        &providers,
        Duration::from_secs(5),
        &cancelled,
    );
    report.accounting.check_invariant().unwrap();
    assert_eq!(report.accounting.secrets_retained, 0);
    assert!(report.accounting.secrets_dropped >= 4);
    // Graph items carry metadata only.
    let (entities, edges) = exposure::to_graph_items(
        "email:someone-exposed@example.test",
        rxscan::graph::EntityKind::EmailAddress,
        &report.exposures,
        1_700_000_000,
        1,
    );
    assert!(!entities.is_empty() && !edges.is_empty());
    let graph_text = serde_json::to_string(&(&entities, &edges)).unwrap();
    assert_clean(&graph_text);
    // Project DB persistence stays secret-free.
    let mut graph = rxscan::graph::ScanGraph::default();
    let proof = rxscan::graph::EntityProvenance {
        scan_plan_id: "test".to_owned(),
        module: "exposure.test".to_owned(),
        task_id: None,
        target: None,
        timestamp: 1,
        reason: None,
        rule_id: None,
    };
    for entity in &entities {
        graph.upsert_entity(
            entity.id.clone(),
            entity.kind,
            entity.label.clone(),
            entity.attributes.clone(),
            &proof,
        );
    }
    for edge in &edges {
        graph.link(
            edge.from.clone(),
            edge.to.clone(),
            edge.relation,
            edge.confidence,
            &proof,
            edge.evidence.clone(),
            edge.attributes.clone(),
        );
    }
    let mut db = rxscan::project_db::ProjectDb::open_in_memory().unwrap();
    let import = rxscan::project_db::ScanImport {
        scan_id: "exposure-test".to_owned(),
        plan_id: "plan".to_owned(),
        started_at_ms: 1,
        finished_at_ms: 2,
        scope_json: "{}".to_owned(),
        workflow: "exposure".to_owned(),
        level: 0,
        termination: "complete".to_owned(),
        tasks_admitted: 1,
        tasks_completed: 1,
        coverage: rxscan::project_db::CoverageSnapshot::default(),
        classifier: rxscan::project_db::ClassifierProvenance::default(),
        retention: rxscan::project_db::RetentionMode::Standard,
    };
    db.import_scan(&import, &graph).unwrap();
    let rows = db.conn_query_for_test("SELECT entity_id FROM entities");
    assert!(!rows.is_empty());
    // Terminal output stays secret-free. Unstyled output carries no
    // ANSI; styled output may (TTY-only styling, never machine output).
    assert_clean(&exposure::render_human(&report, false, true));
    assert_clean(&exposure::render_human(&report, false, false));
    for secret in FAKE_SECRETS {
        assert!(!exposure::render_human(&report, true, true).contains(secret));
    }
    assert_clean(&exposure::render_jsonl(&report));
}

// ---------------------------------------------------------------------------
// Investigation integration: opt-in only, budgeted, secret-free.
// ---------------------------------------------------------------------------

#[test]
fn investigation_without_exposure_sends_nothing() {
    let search = rxscan::investigate::FixtureSearchRunner::default();
    let profile = rxscan::investigate::FixtureProfileFetcher::default();
    let dns = rxscan::investigate::FixtureDnsFetcher::default();
    let cancelled = AtomicBool::new(false);
    let mut config = rxscan::investigate::InvestigationConfig::username("exampleuser");
    config.depth = 2;
    config.allow_test_loopback = true;
    let report =
        rxscan::investigate::run_investigation_with(config, &search, &profile, &dns, &cancelled)
            .unwrap();
    assert_eq!(report.accounting.exposure_lookups, 0);
    assert_eq!(report.accounting.exposures_found, 0);
    assert!(
        !report
            .entities
            .values()
            .any(|e| e.kind == rxscan::graph::EntityKind::Exposure),
        "no exposure entities without opt-in"
    );
}

#[test]
fn investigation_with_dataset_enriches_seed_secret_free() {
    let path = write_dataset(
        "invest",
        r#"{"exposures": [
          {"identifier_type": "username", "identifier": "exampleuser",
           "source": "op-list", "exposure_type": "breach",
           "confidence": 80,
           "record": {"password_hash": "FAKE-SECRET-HASH-0000"}}
        ]}"#,
    );
    let search = rxscan::investigate::FixtureSearchRunner::default();
    let profile = rxscan::investigate::FixtureProfileFetcher::default();
    let dns = rxscan::investigate::FixtureDnsFetcher::default();
    let cancelled = AtomicBool::new(false);
    let mut config = rxscan::investigate::InvestigationConfig::username("exampleuser");
    config.depth = 2;
    config.allow_test_loopback = true;
    config.exposure = true;
    config.exposure_dataset = Some(path.clone());
    let report =
        rxscan::investigate::run_investigation_with(config, &search, &profile, &dns, &cancelled)
            .unwrap();
    report.accounting.check_invariant().unwrap();
    assert!(report.accounting.exposure_lookups >= 1);
    assert_eq!(report.accounting.exposures_found, 1);
    assert!(
        report
            .entities
            .values()
            .any(|e| e.kind == rxscan::graph::EntityKind::Exposure)
    );
    assert_clean(&serde_json::to_string(&report).unwrap());
    assert_clean(&rxscan::investigate::render_jsonl(&report));
    assert_eq!(report.network_scans, 0);
    std::fs::remove_file(&path).ok();
}

#[test]
fn investigate_exposure_explain_is_plan_only() {
    let (code, stdout, _) = run_cli(&[
        "investigate",
        "--username",
        "exampleuser",
        "--exposure",
        "--explain",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("exposure          ENABLED"));
    assert!(stdout.contains("sends identifier"));
    let (code, stdout, _) = run_cli(&["investigate", "--username", "exampleuser", "--explain"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("exposure          disabled"));
}
