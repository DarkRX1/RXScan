//! Phase D passive-investigation CLI and engine tests.
//!
//! All cases are offline and deterministic: `--explain`, `transforms`,
//! `--help`, usage errors, and capabilities never touch the network.
//! Library-level graph behavior uses synthetic fixtures only
//! (`example.test` domain family, TEST-NET addresses).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

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

// ---------------------------------------------------------------------------
// CLI: plan-only paths never contact the network.
// ---------------------------------------------------------------------------

#[test]
fn investigate_explain_is_plan_only_and_machine_clean() {
    let (code, stdout, _) = run_cli(&["investigate", "--username", "exampleuser", "--explain"]);
    assert_eq!(code, 0);
    assert!(!stdout.contains('\x1b'), "explain must never contain ANSI");
    for marker in [
        "INVESTIGATION PLAN",
        "username:exampleuser",
        "username_to_account",
        "account_to_url",
        "url_to_domain",
        "domain_to_dns",
        "DirectNetwork",
        "network scans     0",
    ] {
        assert!(stdout.contains(marker), "explain missing {marker:?}");
    }
}

#[test]
fn investigate_explain_json_is_structured() {
    let (code, stdout, _) = run_cli(&[
        "investigate",
        "--username",
        "exampleuser",
        "--explain",
        "--json",
    ]);
    assert_eq!(code, 0);
    assert!(!stdout.contains('\x1b'));
    let plan: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(plan["seed"], "exampleuser");
    assert_eq!(plan["direct_network"], false);
    assert_eq!(plan["network_scans"], 0);
    let transforms = plan["transforms"].as_array().unwrap();
    assert!(transforms.len() >= 5);
}

#[test]
fn investigate_domain_and_url_seeds_explain_offline() {
    let (code, stdout, _) = run_cli(&["investigate", "--domain", "example.test", "--explain"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("domain:example.test"));
    let (code, stdout, _) =
        run_cli(&["investigate", "--url", "https://example.test/", "--explain"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("https://example.test/"));
}

#[test]
fn investigate_depth_is_bounded_and_exclusive_seeds() {
    let (code, _, stderr) = run_cli(&[
        "investigate",
        "--username",
        "exampleuser",
        "--depth",
        "99",
        "--explain",
    ]);
    assert_eq!(code, 2, "depth beyond max must fail: {stderr}");
    let (code, _, stderr) = run_cli(&[
        "investigate",
        "--username",
        "a",
        "--domain",
        "example.test",
        "--explain",
    ]);
    assert_eq!(code, 2, "two seeds must fail: {stderr}");
    let (code, _, stderr) = run_cli(&["investigate", "--explain"]);
    assert_eq!(code, 2, "missing seed must fail: {stderr}");
    let (code, _, stderr) = run_cli(&[
        "investigate",
        "--username",
        "exampleuser",
        "--json",
        "--jsonl",
        "--explain",
    ]);
    assert_eq!(code, 2, "conflicting formats must fail: {stderr}");
}

#[test]
fn investigate_transforms_listing_is_deterministic() {
    let (code, human, _) = run_cli(&["investigate", "transforms"]);
    assert_eq!(code, 0);
    assert!(human.contains("username_to_account"));
    assert!(human.contains("DirectNetwork: disabled"));
    let (code, json, _) = run_cli(&["investigate", "transforms", "--json"]);
    assert_eq!(code, 0);
    assert!(!json.contains('\x1b'));
    let infos: serde_json::Value = serde_json::from_str(&json).unwrap();
    let ids: Vec<&str> = infos
        .as_array()
        .unwrap()
        .iter()
        .map(|info| info["id"].as_str().unwrap())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "transform listing must be deterministic");
    // No transform may admit forbidden contact classes.
    for info in infos.as_array().unwrap() {
        let contact = info["contact_class"].as_str().unwrap_or("");
        assert!(
            !matches!(contact, "direct_network" | "authenticated_api"),
            "transform {} uses forbidden contact {contact}",
            info["id"]
        );
    }
}

#[test]
fn investigate_help_and_capabilities_stay_consistent() {
    let (code, stdout, _) = run_cli(&["investigate", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--username"));
    assert!(stdout.contains("--depth"));
    assert!(stdout.contains("--project-db"));
    let (code, stdout, _) = run_cli(&["capabilities", "--json"]);
    assert_eq!(code, 0);
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let names: Vec<&str> = report["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["name"].as_str().unwrap())
        .collect();
    for required in [
        "investigation",
        "investigation_username_seed",
        "investigation_account_transforms",
        "investigation_url_transforms",
        "investigation_dns_transforms",
        "investigation_project_persistence",
        "investigation_direct_network",
    ] {
        assert!(names.contains(&required), "capabilities missing {required}");
    }
    let direct = report["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "investigation_direct_network")
        .unwrap();
    assert_eq!(direct["available"], false);
}

// ---------------------------------------------------------------------------
// Library: deterministic fixture investigation end to end.
// ---------------------------------------------------------------------------

fn fixture_backends() -> (
    FixtureSearchRunner,
    FixtureProfileFetcher,
    FixtureDnsFetcher,
) {
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
            "<html><body><a href=\"https://example.test/about\">same domain</a></body></html>",
        );
    let dns = FixtureDnsFetcher::default()
        .with_records("example.test", "A", &["192.0.2.10"])
        .with_records("example.test", "AAAA", &["2001:db8::10"])
        .with_records("example.test", "MX", &["10 mail.example.test."])
        .with_records("example.test", "NS", &["ns1.example.test."])
        .with_records("example.test", "TXT", &["v=spf1 -all"])
        .with_records("example.test", "SRV", &["0 0 443 api.example.test."]);
    (search, profile, dns)
}

fn depth_config(depth: u8) -> InvestigationConfig {
    let mut config = InvestigationConfig::username("exampleuser");
    config.depth = depth;
    config.allow_test_loopback = true;
    config.deadline = Duration::from_secs(10);
    config
}

#[test]
fn investigation_depth_ladder_is_exact() {
    let cancelled = AtomicBool::new(false);
    // depth 0: seed only.
    let (search, profile, dns) = fixture_backends();
    let report =
        investigate::run_investigation_with(depth_config(0), &search, &profile, &dns, &cancelled)
            .unwrap();
    assert_eq!(report.entities.len(), 1);
    assert!(report.relationships.is_empty());
    // depth 1: accounts appear, nothing deeper.
    let (search, profile, dns) = fixture_backends();
    let report =
        investigate::run_investigation_with(depth_config(1), &search, &profile, &dns, &cancelled)
            .unwrap();
    assert_eq!(report.entities.len(), 3);
    // depth 2: urls, shared domain (deduped), repository.
    let (search, profile, dns) = fixture_backends();
    let report =
        investigate::run_investigation_with(depth_config(2), &search, &profile, &dns, &cancelled)
            .unwrap();
    let domains: Vec<_> = report
        .entities
        .values()
        .filter(|e| {
            e.kind == rxscan::graph::EntityKind::Domain && e.canonical_value == "example.test"
        })
        .collect();
    assert_eq!(domains.len(), 1);
    assert!(
        report
            .entities
            .values()
            .any(|e| e.kind == rxscan::graph::EntityKind::Repository),
        "depth 2 must include repository entities"
    );
    // depth 3: DNS expansion, still zero network scans.
    let (search, profile, dns) = fixture_backends();
    let report =
        investigate::run_investigation_with(depth_config(3), &search, &profile, &dns, &cancelled)
            .unwrap();
    assert!(
        report
            .entities
            .values()
            .any(|e| e.kind == rxscan::graph::EntityKind::IpAddress),
        "depth 3 must include resolved addresses"
    );
    assert!(
        report
            .entities
            .values()
            .any(|e| e.kind == rxscan::graph::EntityKind::DnsRecord),
        "depth 3 must include DNS records"
    );
    assert_eq!(report.network_scans, 0);
    assert_eq!(report.direct_network_contacts, 0);
    report.accounting.check_invariant().unwrap();
}

#[test]
fn investigation_structured_output_is_clean_and_reconciles() {
    let cancelled = AtomicBool::new(false);
    let (search, profile, dns) = fixture_backends();
    let report =
        investigate::run_investigation_with(depth_config(3), &search, &profile, &dns, &cancelled)
            .unwrap();
    // JSON: no ANSI, parses, carries budgets and provenance.
    let json = serde_json::to_string_pretty(&report).unwrap();
    assert!(!json.contains('\x1b'));
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["network_scans"], 0);
    assert_eq!(parsed["direct_network_contacts"], 0);
    // JSONL: every line parses independently, stable record envelope.
    let jsonl = investigate::render_jsonl(&report);
    assert!(!jsonl.contains('\x1b'));
    assert!(!jsonl.contains("RXSCAN INVESTIGATION"));
    let mut kinds = Vec::new();
    for line in jsonl.lines() {
        let record: serde_json::Value =
            serde_json::from_str(line).expect("every JSONL line parses");
        assert_eq!(record["schema_version"], 1);
        kinds.push(record["record_type"].as_str().unwrap().to_owned());
    }
    assert_eq!(kinds.first().unwrap(), "investigation_start");
    assert_eq!(kinds.last().unwrap(), "investigation_summary");
    assert_eq!(investigate::render_jsonl(&report), jsonl);
    // Human: bounded, no ANSI, truncation surfaced when present.
    let human = investigate::render_human(&report, false, false, true);
    assert!(!human.contains('\x1b'));
    assert!(human.contains("0 network scans"));
}

#[test]
fn investigation_persists_to_project_db_with_coverage() {
    let cancelled = AtomicBool::new(false);
    let (search, profile, dns) = fixture_backends();
    let report =
        investigate::run_investigation_with(depth_config(3), &search, &profile, &dns, &cancelled)
            .unwrap();
    let mut db = rxscan::project_db::ProjectDb::open_in_memory().unwrap();
    let stats = investigate::persist_investigation(&mut db, &report).unwrap();
    assert!(stats.entities_upserted > 0);
    assert!(stats.relationships_upserted > 0);
    let scans = db.scan_ids().unwrap_or_default();
    assert!(scans.contains(&report.run_id), "run must be queryable");
    // Provenance explanation names the transform chain, not the engine.
    let explanation = investigate::explain_entity(&report, "domain:example.test").unwrap();
    assert!(explanation.contains("url_to_domain") || explanation.contains("account_to_url"));
}

#[test]
fn investigation_rejects_ssrf_destinations_end_to_end() {
    // Profile links to loopback, RFC1918, IPv6 loopback, and file: must
    // never be contacted; production fetch refuses them by policy.
    for unsafe_url in [
        "http://127.0.0.1/",
        "http://192.168.1.1/",
        "http://[::1]/",
        "file:///etc/passwd",
        "ftp://example.test/x",
    ] {
        assert!(
            !investigate::contact_url_permitted(unsafe_url, false),
            "{unsafe_url} must be refused"
        );
    }
    assert!(investigate::contact_url_permitted(
        "https://example.test/",
        false
    ));
}

// ---------------------------------------------------------------------------
// Deterministic local benchmarks (no Internet timings).
// ---------------------------------------------------------------------------

#[test]
fn benchmark_typical_investigation_is_bounded() {
    // 1 username, 10 positive accounts, ~20 urls, ~10 domains, ~20 records.
    let mut search = FixtureSearchRunner::default();
    let mut profile = FixtureProfileFetcher::default();
    let mut dns = FixtureDnsFetcher::default();
    for index in 0..10 {
        let provider = format!("provider-{index:02}");
        let page = format!("https://profile{index}.example.test/exampleuser");
        search = search.with_account("benchuser", &provider, &provider, &page);
        let body = format!(
            "<html><body><a href=\"https://target{index}.example.test/\">t</a> \
             <a href=\"https://shared.example.test/\">shared</a></body></html>"
        );
        profile = profile.with_page(&page, &page, &body);
        dns = dns.with_records(&format!("target{index}.example.test"), "A", &["192.0.2.10"]);
    }
    dns = dns.with_records("shared.example.test", "A", &["198.51.100.20"]);
    let cancelled = AtomicBool::new(false);
    let mut config = InvestigationConfig::username("benchuser");
    config.depth = 3;
    config.allow_test_loopback = true;
    config.deadline = Duration::from_secs(30);
    let started = Instant::now();
    let report =
        investigate::run_investigation_with(config, &search, &profile, &dns, &cancelled).unwrap();
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(10), "took {elapsed:?}");
    assert!(report.entities.len() >= 20, "len={}", report.entities.len());
    assert_eq!(report.network_scans, 0);
    report.accounting.check_invariant().unwrap();
    // Structured serialization stays fast and deterministic.
    let started = Instant::now();
    let first = serde_json::to_string(&report).unwrap();
    let jsonl_first = investigate::render_jsonl(&report);
    assert!(Instant::now().duration_since(started) < Duration::from_secs(10));
    let second = serde_json::to_string(&report).unwrap();
    assert_eq!(first, second);
    assert_eq!(jsonl_first, investigate::render_jsonl(&report));
}

#[test]
fn benchmark_large_graph_insertion_and_serialization() {
    // Synthetic ~1000 entities / ~2500 relationships: bounded memory,
    // deterministic completion, no pathological blowup.
    use rxscan::graph::{EdgeRelation, EntityKind, EntityProvenance};
    let proof = EntityProvenance {
        scan_plan_id: "bench".to_owned(),
        module: "investigate.bench".to_owned(),
        task_id: None,
        target: None,
        timestamp: 1,
        reason: Some("synthetic benchmark".to_owned()),
        rule_id: None,
    };
    let started = Instant::now();
    let mut graph = rxscan::graph::ScanGraph::default();
    for index in 0..1000 {
        graph.upsert_entity(
            format!("domain:bench{index}.example.test"),
            EntityKind::Domain,
            format!("bench{index}.example.test"),
            BTreeMap::from([("domain".to_owned(), format!("bench{index}.example.test"))]),
            &proof,
        );
    }
    for index in 0..2500 {
        let from = format!("domain:bench{}.example.test", index % 1000);
        let to = format!("domain:bench{}.example.test", (index * 7 + 1) % 1000);
        if from == to {
            continue;
        }
        graph.link(
            from,
            to,
            EdgeRelation::References,
            70,
            &proof,
            vec!["synthetic".to_owned()],
            BTreeMap::new(),
        );
    }
    assert!(started.elapsed() < Duration::from_secs(15));
    assert!(graph.entity_count() <= 1000);
    let started = Instant::now();
    let first = serde_json::to_string(&graph).unwrap();
    assert!(Instant::now().duration_since(started) < Duration::from_secs(15));
    assert_eq!(first, serde_json::to_string(&graph).unwrap());
    // Human rendering of a large investigation stays bounded.
    let cancelled = AtomicBool::new(false);
    let (search, profile, dns) = fixture_backends();
    let report =
        investigate::run_investigation_with(depth_config(3), &search, &profile, &dns, &cancelled)
            .unwrap();
    let human = investigate::render_human(&report, false, false, true);
    assert!(human.lines().count() < 200, "renderer must stay bounded");
}
