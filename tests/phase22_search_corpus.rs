//! Phase C search-corpus CLI tests.
//!
//! Covers the first-class `search` workflows (`username`, `providers`,
//! `stats`), the `scan` alias, `--color` validation, and the machine-output
//! contract (JSON never contains ANSI escape codes). All cases are offline:
//! `--explain` and `--json` never touch the network.

use std::path::PathBuf;
use std::process::Command;

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

#[test]
fn search_stats_counts_reconcile_and_stay_machine_clean() {
    let (code, stdout, _) = run_cli(&["search", "stats", "--json"]);
    assert_eq!(code, 0);
    assert!(!stdout.contains('\x1b'), "JSON must never contain ANSI");
    let stats: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let loaded = stats["providers_loaded"].as_u64().unwrap();
    let enabled = stats["enabled"].as_u64().unwrap();
    let disabled = stats["disabled"].as_u64().unwrap();
    assert_eq!(loaded, enabled + disabled);
    let accounted = stats["fixture_verified"].as_u64().unwrap()
        + stats["live_verified"].as_u64().unwrap()
        + stats["needs_review"].as_u64().unwrap()
        + disabled;
    assert_eq!(loaded, accounted);
    // Registry size is historical state, never a design target: assert
    // reconciliation against the live registry, never an exact total.
    assert!(loaded >= 1, "registry must not be empty");
    // Provider vs vector counts stay distinct and honest (1:1 today).
    assert_eq!(
        stats["username_vectors"].as_u64().unwrap(),
        loaded,
        "vectors derive from the registry"
    );
    assert_eq!(
        stats["username_providers"].as_u64().unwrap(),
        loaded,
        "providers derive from the registry"
    );
    // Email vector registry is defined but honestly unpopulated.
    assert_eq!(stats["email_vectors"].as_u64().unwrap(), 0);
    assert_eq!(stats["email_providers"].as_u64().unwrap(), 0);
    let categories = stats["categories"].as_object().unwrap();
    let category_total: u64 = categories.values().map(|v| v.as_u64().unwrap()).sum();
    assert_eq!(category_total, loaded);
}

#[test]
fn search_stats_human_is_generated_not_hardcoded() {
    let (code, stdout, _) = run_cli(&["search", "stats"]);
    assert_eq!(code, 0);
    assert!(
        !stdout.contains('\x1b'),
        "piped output defaults to plain text"
    );
    assert!(stdout.contains("SEARCH CORPUS"));
    assert!(stdout.contains("Providers loaded"));
    // Provider vs vector lines report the live registry (never hardcoded).
    assert!(stdout.contains("Username vectors"));
    assert!(stdout.contains("Username providers"));
    assert!(stdout.contains("Email vectors"));
    assert!(stdout.contains("Live verified"));
    assert!(stdout.contains("Disabled"));
}

#[test]
fn search_providers_json_exposes_health_states() {
    let (code, stdout, _) = run_cli(&["search", "providers", "--json"]);
    assert_eq!(code, 0);
    assert!(!stdout.contains('\x1b'), "JSON must never contain ANSI");
    let payload: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let providers = payload["providers"].as_array().unwrap();
    assert!(
        !providers.is_empty(),
        "registry must list its real providers"
    );
    let mut ids = std::collections::BTreeSet::new();
    for provider in providers {
        let id = provider["id"].as_str().unwrap();
        assert!(ids.insert(id.to_owned()), "duplicate provider id {id}");
        let health = provider["health_state"].as_str().unwrap();
        assert!(
            matches!(
                health,
                "fixture_verified" | "live_verified" | "needs_review" | "disabled"
            ),
            "invalid health state {health}"
        );
    }
    let needs_review = providers
        .iter()
        .filter(|p| p["health_state"] == "needs_review")
        .count();
    let live_verified = providers
        .iter()
        .filter(|p| p["health_state"] == "live_verified")
        .count();
    // Health buckets reconcile with the listing instead of pinning history.
    assert_eq!(
        needs_review
            + live_verified
            + providers
                .iter()
                .filter(|p| p["health_state"] == "fixture_verified")
                .count()
            + providers
                .iter()
                .filter(|p| p["health_state"] == "disabled")
                .count(),
        providers.len()
    );
    assert!(live_verified >= 1, "some providers must be verified");
    let disabled = providers
        .iter()
        .filter(|p| p["health_state"] == "disabled")
        .count();
    assert!(
        providers
            .iter()
            .any(|p| p["id"] == "pinterest" && p["health_state"] == "disabled"),
        "pinterest stays disabled (verified false-confirm); disabled total: {disabled}"
    );
}

#[test]
fn search_providers_filters_serve_review_queues() {
    let (code, stdout, _) = run_cli(&["search", "providers", "--health", "disabled"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("pinterest"));
    assert!(!stdout.contains("github"));
    let (code, stdout, _) =
        run_cli(&["search", "providers", "--health", "live_verified", "--json"]);
    assert_eq!(code, 0);
    let payload: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let shown = payload["providers"].as_array().unwrap().len() as u64;
    assert!(shown >= 1, "live_verified queue must not be empty");
    assert_eq!(payload["active_providers"], shown);
    assert!(payload["total_providers"].as_u64().unwrap() >= shown);
    let (code, stdout, _) = run_cli(&["search", "providers", "--stale"]);
    assert_eq!(code, 0, "stale queue is empty but valid");
    assert!(stdout.contains("ID\tNAME"));
    let (code, _, stderr) = run_cli(&["search", "providers", "--health", "bogus"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown health state"));
    let (code, _, stderr) = run_cli(&["search", "providers", "--category", "bogus"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown category"));
}

#[test]
fn search_username_positional_matches_flag_form() {
    let (code_flag, stdout_flag, _) =
        run_cli(&["search", "--username", "exampleuser", "--explain"]);
    let (code_pos, stdout_pos, _) = run_cli(&["search", "username", "exampleuser", "--explain"]);
    assert_eq!((code_flag, code_pos), (0, 0));
    assert_eq!(stdout_flag, stdout_pos);
    assert!(stdout_pos.contains("providers selected: "));
    assert!(stdout_pos.contains("network scans: 0"));
}

#[test]
fn search_rejects_bad_color_and_unknown_selection() {
    let (code, _, stderr) = run_cli(&["search", "stats", "--color=bogus"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("--color"));
    let (code, _, stderr) = run_cli(&[
        "search",
        "--username",
        "exampleuser",
        "--providers",
        "no-such-provider",
        "--explain",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown provider"));
}

#[test]
fn scan_alias_forwards_to_network_recon() {
    let (code, stdout, _) = run_cli(&["scan", "127.0.0.1", "--explain"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("RXScan plan"));
}

#[test]
fn search_lint_passes_embedded_corpus_with_machine_output() {
    // No corpus checkout under an empty root: definition checks only.
    let empty = std::env::temp_dir().join(format!("rxscan_cli_lint_empty_{}", std::process::id()));
    std::fs::create_dir_all(&empty).unwrap();
    let (code, stdout, _) = run_cli(&[
        "search",
        "lint",
        "--json",
        "--corpus-root",
        empty.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    assert!(!stdout.contains('\x1b'), "JSON must never contain ANSI");
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        report["errors"].as_array().unwrap().is_empty(),
        "lint errors: {}",
        stdout
    );
    assert!(report["providers_checked"].as_u64().unwrap() >= 1);
    assert_eq!(report["fixture_complete"].as_u64().unwrap(), 0);
    assert!(!report["warnings"].as_array().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&empty);
}

#[test]
fn search_lint_checks_files_and_fixtures_from_checkout() {
    let root = std::env::current_dir().unwrap();
    let (code, stdout, _) = run_cli(&["search", "lint", "--corpus-root", root.to_str().unwrap()]);
    assert_eq!(code, 0, "stdout: {stdout}");
    assert!(stdout.contains("errors               0"));
    // Fixture coverage is complete when every registered vector has fixtures.
    assert!(stdout.contains("fixture complete"));
    assert!(stdout.contains("vectors checked"));
}

#[test]
fn search_lint_fails_on_broken_corpus_copy() {
    let dir = std::env::temp_dir().join(format!("rxscan_cli_lint_{}", std::process::id()));
    let corpus = dir.join("search/providers/v1/username");
    let fixtures = dir.join("search/fixtures/username");
    std::fs::create_dir_all(&corpus).unwrap();
    std::fs::create_dir_all(&fixtures).unwrap();
    std::fs::write(
        corpus.join("developer.json"),
        r#"{"schema_version":1,"pack_version":"t","providers":[]}"#,
    )
    .unwrap();
    let (code, _, _) = run_cli(&[
        "search",
        "lint",
        "--corpus-root",
        dir.to_str().unwrap(),
        "--json",
    ]);
    assert_ne!(code, 0, "empty corpus must fail lint");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn machine_output_survives_broken_pipe() {
    use std::process::Stdio;
    let mut child = Command::new(rxscan_bin())
        .args(["search", "stats", "--json"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn rxscan");
    let mut stdout = child.stdout.take().unwrap();
    use std::io::Read as _;
    let mut buf = [0u8; 10];
    let _ = stdout.read_exact(&mut buf);
    drop(stdout);
    let status = child.wait().expect("wait rxscan");
    assert!(
        status.success(),
        "early-closed pipe must exit 0, got {status}"
    );
}

#[test]
fn search_help_advertises_jsonl_mode() {
    let (code, stdout, _) = run_cli(&["search", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--jsonl"));
}

#[test]
fn search_explain_stays_plain_diagnostic() {
    let (code, stdout, _) = run_cli(&["search", "--username", "exampleuser", "--explain"]);
    assert_eq!(code, 0);
    assert!(!stdout.contains("RXSCAN"), "explain stays diagnostic");
    assert!(stdout.contains("network scans: 0"));
}

#[test]
fn forced_color_shows_startup_mark_while_json_stays_clean() {
    let (code, stdout, _) = run_cli(&["search", "stats", "--color", "always"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("RXSCAN"));
    assert!(stdout.contains('\x1b'), "forced color must emit ANSI");
    // Piped human output keeps its workflow header structurally but stays
    // plain (no ANSI) without `--color always`.
    let (code, stdout, _) = run_cli(&["search", "providers"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("RXSCAN"),
        "workflow header stays structural"
    );
    assert!(!stdout.contains('\x1b'));
}

#[test]
fn search_jsonl_stdout_is_pure_typed_jsonl() {
    // Phase C3 gate: `--jsonl` stdout is only typed JSONL. Each line parses
    // independently; no ANSI, no banner, no human headings; accounting
    // reconciles; ordering is deterministic; network scans stay 0.
    // A 1ms deadline keeps the test offline-deterministic: providers go
    // unscanned, but the JSONL envelope and accounting must still hold.
    let (code, stdout, stderr) = run_cli(&[
        "search",
        "--username",
        "exampleuser",
        "--providers",
        "github",
        "--jsonl",
        "--deadline",
        "1ms",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(!stdout.contains('\x1b'), "ANSI count must be 0");
    assert!(!stdout.contains("RXSCAN"), "banner count must be 0");
    for heading in [
        "Username search",
        "All provider outcomes",
        "providers requested:",
    ] {
        assert!(
            !stdout.contains(heading),
            "human heading {heading:?} in JSONL"
        );
    }
    assert!(
        !stderr.contains("RXSCAN"),
        "banner must not leak to stderr either"
    );
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(!lines.is_empty());
    let mut invalid = 0usize;
    let mut kinds = Vec::new();
    for line in &lines {
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(record) => {
                kinds.push(record["record_type"].as_str().unwrap().to_owned());
                assert_eq!(record["schema_version"], 1);
            }
            Err(_) => invalid += 1,
        }
    }
    assert_eq!(invalid, 0, "invalid JSONL lines must be 0");
    assert_eq!(kinds.first().map(String::as_str), Some("search_start"));
    assert_eq!(kinds.last().map(String::as_str), Some("search_summary"));
    let summary: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    let payload = &summary["payload"];
    let requested = payload["providers_requested"].as_u64().unwrap();
    let reconciled = payload["providers_completed"].as_u64().unwrap()
        + payload["skipped"].as_u64().unwrap()
        + payload["cancelled"].as_u64().unwrap()
        + payload["unscanned"].as_u64().unwrap();
    assert_eq!(requested, reconciled, "accounting must reconcile");
    assert_eq!(requested, 1);
    assert_eq!(payload["network_scans"], 0);
    // Deterministic: same offline run twice yields identical JSONL except
    // for wall-clock timestamps (run_id/started_at may vary), so compare
    // record kinds and accounting, not raw bytes.
    let (code2, stdout2, _) = run_cli(&[
        "search",
        "--username",
        "exampleuser",
        "--providers",
        "github",
        "--jsonl",
        "--deadline",
        "1ms",
    ]);
    assert_eq!(code2, 0);
    let kinds2: Vec<String> = stdout2
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).unwrap()["record_type"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(kinds, kinds2, "record ordering must be deterministic");
}

#[test]
fn search_jsonl_survives_broken_pipe() {
    use std::io::Read as _;
    use std::process::Stdio;
    let mut child = std::process::Command::new(rxscan_bin())
        .args([
            "search",
            "--username",
            "exampleuser",
            "--providers",
            "github",
            "--jsonl",
            "--deadline",
            "1ms",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn rxscan");
    let mut stdout = child.stdout.take().unwrap();
    let mut buf = [0u8; 10];
    let _ = stdout.read_exact(&mut buf);
    drop(stdout);
    let status = child.wait().expect("wait rxscan");
    assert!(
        status.success(),
        "early-closed JSONL pipe must exit 0, got {status}"
    );
}

#[test]
fn search_stats_reports_maintainer_signals() {
    // Review tooling is generated, never hard-coded: counts reconcile and
    // the new maintenance signals exist.
    let (code, stdout, _) = run_cli(&["search", "stats", "--json"]);
    assert_eq!(code, 0);
    let stats: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let loaded = stats["providers_loaded"].as_u64().unwrap();
    for field in [
        "username_vectors",
        "username_providers",
        "email_vectors",
        "email_providers",
        "username_rules_curated",
        "username_rules_missing",
        "blocking_susceptible",
        "confirmation_ceilings",
        "api_backed",
        "html_backed",
    ] {
        assert!(stats.get(field).is_some(), "stats missing {field}");
    }
    assert_eq!(
        stats["username_rules_curated"].as_u64().unwrap()
            + stats["username_rules_missing"].as_u64().unwrap(),
        loaded
    );
    assert_eq!(
        stats["api_backed"].as_u64().unwrap() + stats["html_backed"].as_u64().unwrap(),
        loaded
    );
}
