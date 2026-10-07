//! Stage I — evidence-backed investigation pivots.
//!
//! A pivot answers "what can I investigate next, and why?" Every pivot
//! cites observed evidence (reason + source + state). Passive pivots
//! never authorize contact; IP pivots are scan *candidates* requiring
//! explicit `--network --scope`, and RXScan never active-scans them
//! on its own. Reserved/synthetic data only. No network.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use rxscan::investigate::{
    FixtureDnsFetcher, InvestigationConfig, SeedKind, render_human, suggest_pivots,
};

fn cancelled() -> AtomicBool {
    AtomicBool::new(false)
}

fn run_with(
    mut config: InvestigationConfig,
    dns: FixtureDnsFetcher,
    ct: Option<rxscan::ct::FixtureCtFetcher>,
    rdap: Option<rxscan::rdap::FixtureRdapFetcher>,
) -> rxscan::investigate::InvestigationReport {
    config.allow_test_loopback = true;
    config.deadline = Duration::from_secs(10);
    if let Some(c) = ct {
        config.ct = Some(Arc::new(c));
    }
    if let Some(r) = rdap {
        config.rdap = Some(Arc::new(r));
    }
    let search = rxscan::investigate::FixtureSearchRunner::default();
    let profile = rxscan::investigate::FixtureProfileFetcher::default();
    rxscan::investigate::run_investigation_with(config, &search, &profile, &dns, &cancelled())
        .expect("investigation runs")
}

fn domain_report() -> rxscan::investigate::InvestigationReport {
    let dns = FixtureDnsFetcher::default()
        .with_records("example.test", "A", &["192.0.2.10"])
        .with_records("example.test", "MX", &["10 mail.example.test."]);
    let ct = rxscan::ct::FixtureCtFetcher::default().with_response(
        "example.test",
        serde_json::json!([
            {"serial": "A1", "not_before": "2023-01-01T00:00:00Z",
             "name_value": "example.test\napi.example.test"}
        ]),
    );
    let mut config = InvestigationConfig::seeded(SeedKind::Domain, "example.test");
    config.depth = 1;
    run_with(config, dns, Some(ct), None)
}

#[test]
fn ct_san_hostname_becomes_explained_domain_pivot() {
    let report = domain_report();
    let pivot = report
        .pivots
        .iter()
        .find(|p| p.target_kind == "domain" && p.target_value == "api.example.test")
        .expect("CT SAN hostname must be suggested");
    assert_eq!(pivot.reason, "observed certificate SAN");
    assert_eq!(pivot.source, "certificate transparency");
    assert!(
        pivot.state.contains("historical"),
        "CT evidence stays historical, got {}",
        pivot.state
    );
    assert_eq!(pivot.action, "investigate");
    assert!(!pivot.network_candidate);
    assert!(!pivot.evidence.is_empty());
    assert!(pivot.confidence > 0);
}

#[test]
fn dns_ip_pivot_is_candidate_never_authorized() {
    let report = domain_report();
    let pivot = report
        .pivots
        .iter()
        .find(|p| p.target_kind == "ip" && p.target_value == "192.0.2.10")
        .expect("resolved IP must be suggested");
    assert_eq!(pivot.reason, "domain resolves to IP");
    assert_eq!(pivot.source, "dns:A");
    assert!(pivot.network_candidate);
    assert!(
        pivot.action.contains("--network --scope"),
        "IP action must name the explicit authorization, got {}",
        pivot.action
    );
    // Discovery is not authorization: nothing was contacted.
    assert_eq!(report.network_scans, 0);
    assert!(
        !report.pivots.iter().any(|p| p.action == "scan"),
        "no pivot may present itself as an authorized scan"
    );
}

#[test]
fn every_pivot_carries_why_and_where() {
    let report = domain_report();
    assert!(!report.pivots.is_empty());
    for pivot in &report.pivots {
        assert!(!pivot.target_kind.trim().is_empty());
        assert!(!pivot.target_value.trim().is_empty());
        assert!(!pivot.reason.trim().is_empty(), "pivot needs a reason");
        assert!(!pivot.source.trim().is_empty(), "pivot needs a source");
        assert!(!pivot.state.trim().is_empty(), "pivot needs a state");
        assert!(
            !pivot.action.trim().is_empty(),
            "pivot needs an action boundary"
        );
        assert!(!pivot.evidence.is_empty(), "pivot needs cited evidence");
    }
}

#[test]
fn seed_and_expanded_entities_are_never_pivots() {
    let report = domain_report();
    // The seed was investigated; suggesting it again is noise.
    assert!(
        !report
            .pivots
            .iter()
            .any(|p| p.target_value == "example.test"),
        "seed must not be suggested"
    );
    // Entities already used as transform inputs were looked at.
    let expanded: std::collections::BTreeSet<&str> = report
        .observations
        .iter()
        .map(|o| o.input_entity_id.as_str())
        .collect();
    for pivot in &report.pivots {
        let entity = report.entities.values().find(|e| {
            e.canonical_value == pivot.target_value
                || e.attributes
                    .get("url")
                    .is_some_and(|u| *u == pivot.target_value)
        });
        if let Some(entity) = entity {
            assert!(
                !expanded.contains(entity.id.as_str()),
                "expanded entity {} must not be re-suggested",
                entity.id
            );
        }
    }
}

#[test]
fn pivots_bounded_sorted_deterministic() {
    // 40 exchanges: only the bound survives, in sorted order.
    let exchanges: Vec<String> = (0..40)
        .map(|i| format!("10 mail{i:02}.example.test."))
        .collect();
    let refs: Vec<&str> = exchanges.iter().map(String::as_str).collect();
    let dns = FixtureDnsFetcher::default().with_records("example.test", "MX", &refs);
    let mut config = InvestigationConfig::seeded(SeedKind::Domain, "example.test");
    config.depth = 1;
    let report = run_with(config, dns, None, None);
    assert!(
        report.pivots.len() <= rxscan::investigate::MAX_INVESTIGATE_PIVOTS,
        "pivots must be bounded, got {}",
        report.pivots.len()
    );
    let mut sorted = report.pivots.clone();
    sorted.sort_by(|a, b| {
        a.target_kind
            .cmp(&b.target_kind)
            .then(a.target_value.cmp(&b.target_value))
    });
    assert_eq!(
        report.pivots, sorted,
        "pivots must be deterministically ordered"
    );
    // Pure recomputation matches the stored field (reload-stability).
    assert_eq!(suggest_pivots(&report), report.pivots);
}

#[test]
fn pivots_survive_machine_round_trip() {
    let report = domain_report();
    let value = serde_json::to_value(&report).expect("report serializes");
    let pivots = value
        .get("pivots")
        .and_then(|v| v.as_array())
        .expect("machine output must carry pivots");
    assert!(!pivots.is_empty());
    for pivot in pivots {
        for key in [
            "target_kind",
            "target_value",
            "reason",
            "source",
            "state",
            "action",
        ] {
            assert!(
                pivot
                    .get(key)
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty()),
                "pivot missing {key}"
            );
        }
    }
    // Older machine output without pivots still loads (additive contract).
    let mut legacy = value.clone();
    legacy.as_object_mut().unwrap().remove("pivots");
    let reloaded: rxscan::investigate::InvestigationReport =
        serde_json::from_value(legacy).expect("legacy report loads");
    assert!(reloaded.pivots.is_empty());
    assert_eq!(suggest_pivots(&reloaded), report.pivots);
}

#[test]
fn human_output_lists_pivots_without_ansi() {
    let report = domain_report();
    let text = render_human(&report, false, false, true);
    assert!(
        text.contains("PIVOT"),
        "human output must name the pivot section"
    );
    assert!(text.contains("api.example.test"));
    assert!(text.contains("192.0.2.10"));
    assert!(
        !text.contains('\u{1b}'),
        "non-color human output must stay ANSI-free"
    );
}

#[test]
fn rdap_asn_becomes_explained_pivot() {
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
    let dns = FixtureDnsFetcher::default().with_records("example.test", "A", &["192.0.2.10"]);
    let mut config = InvestigationConfig::seeded(SeedKind::Domain, "example.test");
    config.depth = 3;
    let report = run_with(config, dns, None, Some(rdap));
    // Registration-derived pivots (ASN/org/prefix) must cite RDAP, and
    // org labels must not be presented as confirmed ownership.
    for pivot in &report.pivots {
        if pivot.source.contains("RDAP") {
            assert!(
                !pivot.reason.to_ascii_lowercase().contains("owner")
                    || pivot.reason.contains("association")
                    || pivot.reason.contains("mapped")
                    || pivot.reason.contains("allocation"),
                "registration pivots must not claim ownership: {}",
                pivot.reason
            );
        }
    }
    report.accounting.check_invariant().unwrap();
}
