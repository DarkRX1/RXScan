//! Stage 5 project-history tests: consecutive investigation persists,
//! coverage-aware diffing, and persisted provenance explanation.
//! Synthetic fixtures only.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use rxscan::investigate::{
    self, FixtureDnsFetcher, FixtureProfileFetcher, FixtureSearchRunner, InvestigationConfig,
};

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

fn account_page(account: &str, link: &str) -> String {
    format!("<html><body><a href=\"{link}\">site</a> {account}</body></html>")
}

fn run_fixture(providers: &[(&str, &str, &str)], depth: u8) -> investigate::InvestigationReport {
    let mut search = FixtureSearchRunner::default();
    let mut profile = FixtureProfileFetcher::default();
    for (provider, platform, host) in providers {
        let page = format!("https://{host}/{provider}");
        search = search.with_account("historyuser", provider, platform, &page);
        profile = profile.with_page(
            &page,
            &page,
            &account_page(provider, "https://example.test/"),
        );
    }
    let dns = FixtureDnsFetcher::default().with_records("example.test", "A", &["192.0.2.10"]);
    let cancelled = AtomicBool::new(false);
    let mut config = InvestigationConfig::username("historyuser");
    config.depth = depth;
    config.allow_test_loopback = true;
    config.deadline = Duration::from_secs(10);
    investigate::run_investigation_with(config, &search, &profile, &dns, &cancelled).unwrap()
}

#[test]
fn consecutive_persists_diff_new_and_removed() {
    // Run A sees two accounts; run B sees one. The diff must surface the
    // removal as a disappeared/removed change, and re-adding must show
    // the account again (no phantom persistence, no silent loss).
    let first = run_fixture(
        &[
            ("provider-a", "Provider A", "a.example.test"),
            ("provider-b", "Provider B", "b.example.test"),
        ],
        1,
    );
    let second = run_fixture(&[("provider-a", "Provider A", "a.example.test")], 1);
    assert_ne!(first.run_id, second.run_id);
    let mut db = rxscan::project_db::ProjectDb::open_in_memory().unwrap();
    investigate::persist_investigation(&mut db, &first).unwrap();
    investigate::persist_investigation(&mut db, &second).unwrap();
    let changes = db.diff_scan_runs(&first.run_id, &second.run_id).unwrap();
    assert!(!changes.is_empty(), "account removal must surface");
    let removed_b = changes.iter().any(|change| {
        change.entity_id.contains("provider-b")
            && matches!(
                change.change_type,
                rxscan::project_db::ChangeType::Disappeared
                    | rxscan::project_db::ChangeType::Removed
            )
    });
    assert!(
        removed_b,
        "provider-b account must read as disappeared/removed"
    );
    // Coverage of both runs is recorded with completed modules.
    for run in [&first.run_id, &second.run_id] {
        let coverage = db.coverage_of(run).unwrap();
        assert!(
            coverage
                .modules_completed
                .iter()
                .any(|m| m.contains("investigate")),
            "coverage must record investigate modules"
        );
    }
}

#[test]
fn truncated_run_records_coverage_not_negative_evidence() {
    // A tiny entity budget truncates run B: coverage must say truncated so
    // later readers treat missing evidence as UNKNOWN, never removed.
    let mut full = run_fixture(
        &[
            ("provider-a", "Provider A", "a.example.test"),
            ("provider-b", "Provider B", "b.example.test"),
        ],
        2,
    );
    assert!(!full.accounting.truncated);
    let mut db = rxscan::project_db::ProjectDb::open_in_memory().unwrap();
    investigate::persist_investigation(&mut db, &full).unwrap();
    // Re-run with an entity budget of 1: only the seed persists.
    let search = FixtureSearchRunner::default().with_account(
        "historyuser",
        "provider-a",
        "Provider A",
        "https://a.example.test/x",
    );
    let profile = FixtureProfileFetcher::default();
    let dns = FixtureDnsFetcher::default();
    let cancelled = AtomicBool::new(false);
    let mut config = InvestigationConfig::username("historyuser");
    config.depth = 2;
    config.allow_test_loopback = true;
    config.max_entities = 1;
    let partial =
        investigate::run_investigation_with(config, &search, &profile, &dns, &cancelled).unwrap();
    assert!(partial.accounting.truncated);
    investigate::persist_investigation(&mut db, &partial).unwrap();
    let coverage = db.coverage_of(&partial.run_id).unwrap();
    assert!(coverage.truncated, "truncation must persist in coverage");
    assert_eq!(
        db.scan_termination(&partial.run_id).unwrap(),
        "deadline_or_budget"
    );
    let _ = &mut full;
}

#[test]
fn project_db_explain_shows_persisted_chain() {
    let report = run_fixture(&[("provider-a", "Provider A", "a.example.test")], 2);
    let db_path = std::env::temp_dir().join(format!("rxscan-hist-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&db_path);
    let db_path_str = db_path.to_str().unwrap().to_owned();
    let mut db = rxscan::project_db::ProjectDb::open(&db_path).unwrap();
    investigate::persist_investigation(&mut db, &report).unwrap();
    drop(db);
    let (code, stdout, _) = run_cli(&[
        "project-db",
        "explain",
        "--db",
        &db_path_str,
        "domain:example.test",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Why is domain:example.test present?"));
    assert!(stdout.contains("url_to_domain") || stdout.contains("references"));
    let (code, stdout, _) = run_cli(&[
        "project-db",
        "explain",
        "--db",
        &db_path_str,
        "domain:example.test",
        "--json",
    ]);
    assert_eq!(code, 0);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(!parsed["chain"].as_array().unwrap().is_empty());
    let (code, _, _) = run_cli(&[
        "project-db",
        "explain",
        "--db",
        &db_path_str,
        "domain:nonexistent-xyz.test",
    ]);
    assert_eq!(code, 1);
    std::fs::remove_file(&db_path).ok();
}

#[test]
fn diff_check_exit_codes_serve_automation() {
    // Identical consecutive persists agree (exit 0); a changed run
    // reports exit 3 under --check. Default output is unaffected.
    let same = run_fixture(&[("provider-a", "Provider A", "a.example.test")], 1);
    let changed = run_fixture(
        &[
            ("provider-a", "Provider A", "a.example.test"),
            ("provider-b", "Provider B", "b.example.test"),
        ],
        1,
    );
    let db_path = std::env::temp_dir().join(format!("rxscan-check-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&db_path);
    let db_str = db_path.to_str().unwrap().to_owned();
    let mut db = rxscan::project_db::ProjectDb::open(&db_path).unwrap();
    investigate::persist_investigation(&mut db, &same).unwrap();
    investigate::persist_investigation(&mut db, &changed).unwrap();
    drop(db);
    let (code, _, _) = run_cli(&[
        "project-db",
        "diff",
        "--db",
        &db_str,
        &same.run_id,
        &same.run_id,
        "--check",
    ]);
    assert_eq!(code, 0, "identical runs agree");
    let (code, _, _) = run_cli(&[
        "project-db",
        "diff",
        "--db",
        &db_str,
        &same.run_id,
        &changed.run_id,
        "--check",
    ]);
    assert_eq!(code, 3, "changed runs report exit 3");
    let (code, _, _) = run_cli(&[
        "project-db",
        "diff",
        "--db",
        &db_str,
        &same.run_id,
        &changed.run_id,
    ]);
    assert_eq!(code, 0, "default diff keeps exit 0");
    std::fs::remove_file(&db_path).ok();
}
