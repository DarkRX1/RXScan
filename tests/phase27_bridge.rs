//! Stage 6 authorized network-bridge tests.
//!
//! The pivot backend is always a deterministic fixture here: no test
//! performs real network contact. Scope strings use reserved documentation
//! addresses; loopback/private literals appear only as rejected-scope or
//! refused-destination cases.

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, atomic::AtomicBool};
use std::time::Duration;

use rxscan::investigate::{
    self, FixtureDnsFetcher, FixturePivot, FixtureProfileFetcher, FixtureSearchRunner,
    InvestigationConfig,
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

/// Two accounts linking two distinct domains with distinct DNS answers.
fn two_domain_backends() -> (
    FixtureSearchRunner,
    FixtureProfileFetcher,
    FixtureDnsFetcher,
) {
    let search = FixtureSearchRunner::default()
        .with_account(
            "bridgeuser",
            "provider-a",
            "Provider A",
            "https://page-a.example.test/provider-a",
        )
        .with_account(
            "bridgeuser",
            "provider-b",
            "Provider B",
            "https://page-b.example.test/provider-b",
        );
    let profile = FixtureProfileFetcher::default()
        .with_page(
            "https://page-a.example.test/provider-a",
            "https://page-a.example.test/provider-a",
            "<html><body><a href=\"https://example.test/\">one</a></body></html>",
        )
        .with_page(
            "https://page-b.example.test/provider-b",
            "https://page-b.example.test/provider-b",
            "<html><body><a href=\"https://other.test/\">two</a></body></html>",
        );
    let dns = FixtureDnsFetcher::default()
        .with_records("example.test", "A", &["192.0.2.10"])
        .with_records("other.test", "A", &["198.51.100.20"]);
    (search, profile, dns)
}

fn bridge_config(
    pivot: Arc<FixturePivot>,
    scopes: &[&str],
    max_pivots: usize,
) -> InvestigationConfig {
    let mut config = InvestigationConfig::username("bridgeuser");
    config.depth = 3;
    config.allow_test_loopback = true;
    config.deadline = Duration::from_secs(10);
    config.network = true;
    config.scopes = scopes.iter().map(|s| (*s).to_owned()).collect();
    config.max_network_pivots = max_pivots;
    config.pivot = Some(pivot);
    config
}

#[test]
fn network_without_scope_is_rejected() {
    let pivot = Arc::new(FixturePivot::default());
    let (search, profile, dns) = two_domain_backends();
    let cancelled = AtomicBool::new(false);
    let mut config = InvestigationConfig::username("bridgeuser");
    config.network = true;
    config.pivot = Some(pivot);
    assert!(
        investigate::run_investigation_with(config, &search, &profile, &dns, &cancelled).is_err()
    );
    // CLI likewise, fully offline.
    let (code, _, _) = run_cli(&[
        "investigate",
        "--username",
        "bridgeuser",
        "--network",
        "--explain",
    ]);
    assert_eq!(code, 2);
    let (code, _, _) = run_cli(&[
        "investigate",
        "--username",
        "bridgeuser",
        "--network",
        "--scope",
        "not a scope !!!",
        "--explain",
    ]);
    assert_eq!(code, 2);
}

#[test]
fn passive_mode_never_contacts_even_with_scope_set() {
    let pivot = Arc::new(FixturePivot::default().with_open("192.0.2.10", 80));
    let (search, profile, dns) = two_domain_backends();
    let cancelled = AtomicBool::new(false);
    let mut config = InvestigationConfig::username("bridgeuser");
    config.depth = 3;
    config.allow_test_loopback = true;
    config.scopes = vec!["192.0.2.0/24".to_owned()];
    config.pivot = Some(pivot.clone());
    let report =
        investigate::run_investigation_with(config, &search, &profile, &dns, &cancelled).unwrap();
    assert!(pivot.contacted().is_empty(), "passive runs never probe");
    assert_eq!(report.accounting.network_scans, 0);
    assert_eq!(report.network_scans, 0);
    assert!(!report.network_enabled);
    for obs in &report.observations {
        assert_ne!(
            obs.contact_class,
            rxscan::search::ContactClass::DirectNetwork,
            "passive observation used DirectNetwork"
        );
    }
    report.accounting.check_invariant().unwrap();
}

#[test]
fn scope_guard_allows_and_rejects_per_ip() {
    let pivot = Arc::new(FixturePivot::default().with_open("192.0.2.10", 80));
    let (search, profile, dns) = two_domain_backends();
    let cancelled = AtomicBool::new(false);
    let report = investigate::run_investigation_with(
        bridge_config(pivot.clone(), &["192.0.2.10"], 10),
        &search,
        &profile,
        &dns,
        &cancelled,
    )
    .unwrap();
    // Only the in-scope IP was contacted.
    assert_eq!(pivot.contacted(), vec!["192.0.2.10".to_owned()]);
    assert_eq!(report.accounting.network_scans, 1);
    assert_eq!(report.direct_network_contacts, 1);
    assert!(report.network_enabled);
    // Out-of-scope address: entity allowed, never contacted.
    let rejected = report
        .observations
        .iter()
        .any(|o| o.status == "rejected_by_scope" && o.input_entity_id == "ip:198.51.100.20");
    assert!(rejected, "out-of-scope IP must be recorded as rejected");
    let other = report.entities.get("ip:198.51.100.20").unwrap();
    assert_eq!(
        other.attributes.get("pivot_authorized").map(String::as_str),
        Some("false")
    );
    // Open port from the authorized pivot feeds the graph.
    assert!(report.entities.contains_key("port:tcp:192.0.2.10:80"));
    assert!(
        report
            .relationships
            .iter()
            .any(|r| r.from == "ip:192.0.2.10"
                && r.to == "port:tcp:192.0.2.10:80"
                && r.relation == rxscan::graph::EdgeRelation::ListensOn)
    );
    // No port entity for the rejected IP.
    assert!(
        !report
            .entities
            .keys()
            .any(|id| id.starts_with("port:tcp:198.51.100.20")),
        "rejected IPs gain no port entities"
    );
    report.accounting.check_invariant().unwrap();
}

#[test]
fn pivot_budget_exhausts_with_partial_results() {
    let pivot = Arc::new(FixturePivot::default());
    let (search, profile, dns) = two_domain_backends();
    let cancelled = AtomicBool::new(false);
    let report = investigate::run_investigation_with(
        bridge_config(pivot.clone(), &["192.0.2.0/24", "198.51.100.0/24"], 1),
        &search,
        &profile,
        &dns,
        &cancelled,
    )
    .unwrap();
    assert_eq!(pivot.contacted().len(), 1);
    assert_eq!(report.accounting.network_scans, 1);
    assert!(report.accounting.truncated);
    assert!(
        report
            .accounting
            .truncation_reasons
            .contains("network_pivot_budget"),
        "{:?}",
        report.accounting.truncation_reasons
    );
    assert!(!report.entities.is_empty(), "partial graph preserved");
    report.accounting.check_invariant().unwrap();
}

#[test]
fn bridge_output_is_deterministic_and_structured() {
    let run_once = || {
        let pivot = Arc::new(FixturePivot::default().with_open("192.0.2.10", 443));
        let (search, profile, dns) = two_domain_backends();
        let cancelled = AtomicBool::new(false);
        investigate::run_investigation_with(
            bridge_config(pivot, &["192.0.2.0/24"], 10),
            &search,
            &profile,
            &dns,
            &cancelled,
        )
        .unwrap()
    };
    let first = run_once();
    let second = run_once();
    // Stable graph shape (run ids and timestamps legitimately differ).
    let shape = |report: &investigate::InvestigationReport| {
        let mut entities: Vec<(String, String)> = report
            .entities
            .iter()
            .map(|(id, e)| (id.clone(), e.kind.to_string()))
            .collect();
        entities.sort();
        let mut rels: Vec<(String, String, String)> = report
            .relationships
            .iter()
            .map(|r| (r.from.clone(), r.to.clone(), r.relation.to_string()))
            .collect();
        rels.sort();
        (entities, rels)
    };
    assert_eq!(shape(&first), shape(&second));
    let jsonl = investigate::render_jsonl(&first);
    for line in jsonl.lines() {
        serde_json::from_str::<serde_json::Value>(line).unwrap();
    }
    assert!(!jsonl.contains('\x1b'));
    let human = investigate::render_human(&first, false, false, true);
    assert!(human.contains("AUTHORIZED"));
    assert!(!human.contains('\x1b'));
}

#[test]
fn bridge_explain_is_plan_only() {
    let (code, stdout, _) = run_cli(&[
        "investigate",
        "--username",
        "bridgeuser",
        "--network",
        "--scope",
        "192.0.2.0/24",
        "--explain",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("NETWORK BRIDGE"));
    assert!(stdout.contains("192.0.2.0/24"));
    assert!(stdout.contains("network budget"));
}
