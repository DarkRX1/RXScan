//! Findings-first presentation: show the useful thing RXScan already found.
//!
//! Synthetic fixtures only (`exampleuser`, `example.test`, `192.0.2.10`,
//! ...). No network, no real provider data.

use rxscan::terminal::{RowTier, SearchRow, SearchSummary, TerminalCapabilities};

fn caps_plain() -> TerminalCapabilities {
    TerminalCapabilities::plain()
}

fn confirmed_row(provider: &str, url: &str) -> SearchRow {
    SearchRow {
        status: "confirmed",
        provider: provider.to_owned(),
        confidence: 94,
        detail: "public profile".to_owned(),
        tier: RowTier::Positive,
        url: url.to_owned(),
        url_observed: true,
    }
}

fn possible_row(provider: &str, url: &str) -> SearchRow {
    SearchRow {
        status: "possible",
        provider: provider.to_owned(),
        confidence: 25,
        detail: "weak evidence".to_owned(),
        tier: RowTier::Positive,
        url: url.to_owned(),
        url_observed: false,
    }
}

fn summary_for(total: usize) -> SearchSummary {
    SearchSummary {
        requested: total,
        completed: total,
        skipped: 0,
        cancelled: 0,
        unscanned: 0,
        truncated: false,
    }
}

fn render_default(rows: &[SearchRow], summary: &SearchSummary) -> String {
    rxscan::terminal::render_search_report_caps(
        "exampleuser",
        summary.requested,
        rows,
        summary,
        false,
        caps_plain(),
    )
}

// --- SEARCH ---------------------------------------------------------------

#[test]
fn confirmed_finding_includes_observed_profile_url() {
    let rows = vec![
        confirmed_row("github", "https://example.test/github/exampleuser"),
        confirmed_row("gitlab", "https://example.test/gitlab/exampleuser"),
    ];
    let text = render_default(&rows, &summary_for(2));
    assert!(
        text.contains("https://example.test/github/exampleuser"),
        "github URL visible: {text}"
    );
    assert!(
        text.contains("https://example.test/gitlab/exampleuser"),
        "gitlab URL visible: {text}"
    );
    assert!(text.contains("github"), "{text}");
    assert!(text.contains("94%"), "confidence visible: {text}");
    assert!(text.contains("high"), "confidence label: {text}");
    assert!(text.contains("public profile"), "evidence type: {text}");
}

#[test]
fn possible_finding_uses_cautious_wording() {
    let rows = vec![possible_row(
        "example-site",
        "https://example.test/u/exampleuser",
    )];
    let text = render_default(&rows, &summary_for(1));
    assert!(
        text.contains("https://example.test/u/exampleuser"),
        "candidate URL visible: {text}"
    );
    assert!(text.contains("low"), "low confidence: {text}");
    assert!(text.contains("25%"), "score visible: {text}");
    assert!(
        text.contains("weak evidence"),
        "cautious evidence wording: {text}"
    );
    // Must never claim a weak candidate is an observed public profile.
    let candidate_section = text
        .lines()
        .skip_while(|line| !line.contains("example-site"))
        .take(4)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !candidate_section.contains("public profile"),
        "possible must not claim public profile: {candidate_section}"
    );
}

#[test]
fn constructed_candidate_not_mislabeled_as_observed() {
    // Possible with a constructed URL (no observed fetch): renderer must
    // still show it as a candidate, never as an observed profile.
    let rows = vec![SearchRow {
        status: "possible",
        provider: "example-site".to_owned(),
        confidence: 25,
        detail: "weak evidence".to_owned(),
        tier: RowTier::Positive,
        url: "https://example.test/u/exampleuser".to_owned(),
        url_observed: false,
    }];
    let text = render_default(&rows, &summary_for(1));
    assert!(text.contains("https://example.test/u/exampleuser"));
    assert!(
        !text.lines().any(|line| {
            line.contains("Profile") && line.contains("https://example.test/u/exampleuser")
        }),
        "candidate URL must not be labeled Profile: {text}"
    );
}

#[test]
fn confidence_values_remain_unchanged() {
    let rows = vec![
        confirmed_row("github", "https://example.test/github/exampleuser"),
        possible_row("example-site", "https://example.test/u/exampleuser"),
    ];
    let text = render_default(&rows, &summary_for(2));
    assert!(text.contains("94%"), "{text}");
    assert!(text.contains("25%"), "{text}");
    assert_eq!(rows[0].confidence, 94);
    assert_eq!(rows[1].confidence, 25);
}

#[test]
fn default_respects_ten_finding_budget_with_cards() {
    let mut rows = Vec::new();
    for i in 0..14 {
        rows.push(confirmed_row(
            &format!("confirmed-provider-{i:02}"),
            &format!("https://example.test/c{i:02}/exampleuser"),
        ));
    }
    for i in 0..11 {
        rows.push(possible_row(
            &format!("possible-provider-{i:02}"),
            &format!("https://example.test/p{i:02}/exampleuser"),
        ));
    }
    let text = render_default(&rows, &summary_for(25));
    // 8 confirmed + 2 possible under shared budget.
    let mut shown = 0;
    for i in 0..14 {
        if text.contains(&format!("confirmed-provider-{i:02}")) {
            shown += 1;
        }
    }
    for i in 0..11 {
        if text.contains(&format!("possible-provider-{i:02}")) {
            shown += 1;
        }
    }
    assert_eq!(shown, 10, "budget is 10: {text}");
    assert!(text.contains("+ 15 additional findings"), "{text}");
    // Each displayed finding shows its URL.
    assert!(text.contains("https://example.test/c00/exampleuser"));
}

#[test]
fn negative_outcomes_remain_summarized() {
    let mut rows = vec![
        confirmed_row("github", "https://example.test/github/exampleuser"),
        possible_row("example-site", "https://example.test/u/exampleuser"),
    ];
    for status in ["blocked", "unknown", "rate_limited", "error"] {
        rows.push(SearchRow {
            status,
            provider: format!("{status}-provider-00"),
            confidence: 0,
            detail: "no signal".to_owned(),
            tier: RowTier::Attention,
            url: String::new(),
            url_observed: false,
        });
    }
    rows.push(SearchRow {
        status: "not_found",
        provider: "missing-provider-00".to_owned(),
        confidence: 0,
        detail: String::new(),
        tier: RowTier::Quiet,
        url: String::new(),
        url_observed: false,
    });
    let summary = SearchSummary {
        requested: 7,
        completed: 7,
        skipped: 0,
        cancelled: 0,
        unscanned: 0,
        truncated: false,
    };
    let text = render_default(&rows, &summary);
    for hidden in [
        "blocked-provider-00",
        "unknown-provider-00",
        "rate_limited-provider-00",
        "error-provider-00",
        "missing-provider-00",
    ] {
        assert!(!text.contains(hidden), "hidden {hidden}: {text}");
    }
    for label in ["BLOCKED", "UNKNOWN", "RATE LIMITED", "ERROR", "NOT FOUND"] {
        assert!(!text.contains(label), "hidden {label}: {text}");
    }
    assert!(text.contains("COVERAGE"), "{text}");
    assert!(text.contains("Blocked"), "{text}");
}

#[test]
fn long_urls_do_not_break_layout() {
    // Honest long URL: identity-specific (contains the target username) so
    // it renders as an observed profile and exercises truncation.
    let long = format!("https://example.test/{}/exampleuser", "u".repeat(180));
    let rows = vec![confirmed_row("github", &long)];
    let text = render_default(&rows, &summary_for(1));
    // Visually truncated with ellipsis, never raw overlong line.
    assert!(text.contains("..."), "truncated marker: {text}");
    for line in text.lines() {
        assert!(
            line.chars().count() <= 130,
            "bounded line width: {}",
            line.chars().count()
        );
    }
    assert!(!text.contains(&"u".repeat(200)), "full URL not dumped");
}

#[test]
fn terminal_control_characters_are_sanitized() {
    let evil_provider = "evil\x1b[31mprovider\x1b[0m";
    let evil_url = "https://example.test/\x1b]0;pwned\x07exampleuser";
    let evil_detail = "public\x00profile\ninjected";
    let rows = vec![SearchRow {
        status: "confirmed",
        provider: evil_provider.to_owned(),
        confidence: 94,
        detail: evil_detail.to_owned(),
        tier: RowTier::Positive,
        url: evil_url.to_owned(),
        url_observed: true,
    }];
    let text = render_default(&rows, &summary_for(1));
    assert!(!text.contains('\x1b'), "no ANSI from remote: {text:?}");
    assert!(!text.contains('\x07'), "no BEL: {text:?}");
    assert!(!text.contains('\x00'), "no NUL: {text:?}");
    // Sanitized content still shows the useful core.
    assert!(text.contains("evil"), "{text}");
    assert!(text.contains("provider"), "{text}");
    assert!(text.contains("https://example.test/"), "{text}");
}

#[test]
fn empty_results_remain_clear() {
    let text = render_default(&[], &summary_for(0));
    assert!(
        text.contains("No confirmed or possible accounts found."),
        "{text}"
    );
    assert!(!text.contains("STATUS"), "no empty table: {text}");
}

// --- NETWORK --------------------------------------------------------------

fn recon_report_with_ports(
    open_summary: &str,
    details: Vec<rxscan::run::PortServiceDetail>,
) -> rxscan::run::RunReport {
    use clap::Parser;
    let cli = rxscan::cli::Cli::try_parse_from(["rxscan", "example.test", "--level", "3"]).unwrap();
    let plan = rxscan::plan::ScanPlan::compile(cli).unwrap();
    rxscan::run::RunReport {
        plan,
        task_count: 1,
        scheduler_report: rxscan::execution::SchedulerReport::default(),
        jsonl_bytes: 0,
        output_path: None,
        open_ports_summary: open_summary.to_owned(),
        tcp_totals: rxscan::tcp_discovery::TcpScanTotals {
            completed_tasks: 1,
            ports_requested: 3,
            ports_attempted: 3,
            open: 1,
            closed: 2,
            filtered_or_timed_out: 0,
            error: 0,
            unscanned: 0,
            truncated: false,
            port_sources: vec!["explicit".to_owned()],
            elapsed_ms_max: 5,
            fd_peak_max: 4,
        },
        services_identified: 1,
        udp_summary: String::new(),
        udp_totals: rxscan::udp_discovery::UdpScanTotals::default(),
        duration_ms: 100,
        graph_entities: 0,
        graph_edges: 0,
        graph_truncated: false,
        certificates_observed: 0,
        certificate_reuse_groups: 0,
        fingerprint_packs_loaded: 0,
        fingerprint_rules: 0,
        fingerprint_files_rejected: 0,
        scan_id: "scan_test".to_owned(),
        port_details: details,
        project_import: None,
        project_changes: Vec::new(),
        attention: Vec::new(),
    }
}

#[test]
fn open_port_renders_service_product() {
    let report = recon_report_with_ports(
        "HOST example.test\nPORT SERVICE PRODUCT\n22/tcp ssh OpenSSH",
        vec![rxscan::run::PortServiceDetail {
            port: 22,
            service: "ssh".to_owned(),
            product: Some("OpenSSH".to_owned()),
            version: None,
            banner: Some("SSH-2.0-OpenSSH".to_owned()),
            endpoint: None,
            title: None,
            technologies: Vec::new(),
            tls_name: None,
            tls_issuer: None,
            ssh_key: None,
        }],
    );
    let human = rxscan::run::human_summary(&report);
    assert!(human.contains("22/tcp"), "{human}");
    assert!(human.contains("OPEN"), "{human}");
    assert!(
        human.to_ascii_lowercase().contains("ssh"),
        "service visible: {human}"
    );
    assert!(human.contains("OpenSSH"), "product visible: {human}");
}

#[test]
fn version_renders_only_with_evidence() {
    // With version: shown.
    let with = recon_report_with_ports(
        "HOST example.test\nPORT SERVICE PRODUCT\n22/tcp ssh OpenSSH",
        vec![rxscan::run::PortServiceDetail {
            port: 22,
            service: "ssh".to_owned(),
            product: Some("OpenSSH".to_owned()),
            version: Some("9.2p1".to_owned()),
            banner: None,
            endpoint: None,
            title: None,
            technologies: Vec::new(),
            tls_name: None,
            tls_issuer: None,
            ssh_key: None,
        }],
    );
    let human = rxscan::run::human_summary(&with);
    assert!(human.contains("9.2p1"), "version shown: {human}");
    // Without version: no Version line, no fabrication.
    let without = recon_report_with_ports(
        "HOST example.test\nPORT SERVICE PRODUCT\n22/tcp ssh OpenSSH",
        vec![rxscan::run::PortServiceDetail {
            port: 22,
            service: "ssh".to_owned(),
            product: Some("OpenSSH".to_owned()),
            version: None,
            banner: None,
            endpoint: None,
            title: None,
            technologies: Vec::new(),
            tls_name: None,
            tls_issuer: None,
            ssh_key: None,
        }],
    );
    let plain = rxscan::run::human_summary(&without);
    assert!(
        !plain.contains("Version"),
        "no Version line without evidence: {plain}"
    );
}

#[test]
fn http_endpoint_renders_when_observed() {
    let report = recon_report_with_ports(
        "HOST example.test\nPORT SERVICE PRODUCT\n80/tcp http nginx",
        vec![rxscan::run::PortServiceDetail {
            port: 80,
            service: "http".to_owned(),
            product: Some("nginx".to_owned()),
            version: None,
            banner: None,
            endpoint: Some("http://example.test/".to_owned()),
            title: Some("Example Site".to_owned()),
            technologies: vec!["nginx".to_owned()],
            tls_name: None,
            tls_issuer: None,
            ssh_key: None,
        }],
    );
    let human = rxscan::run::human_summary(&report);
    assert!(human.contains("http://example.test/"), "{human}");
    assert!(human.contains("nginx"), "{human}");
    assert!(human.contains("Example Site"), "{human}");
}

#[test]
fn tls_identity_renders_only_when_observed() {
    let with = recon_report_with_ports(
        "HOST example.test\nPORT SERVICE PRODUCT\n443/tcp https nginx",
        vec![rxscan::run::PortServiceDetail {
            port: 443,
            service: "https".to_owned(),
            product: Some("nginx".to_owned()),
            version: None,
            banner: None,
            endpoint: Some("https://example.test/".to_owned()),
            title: None,
            technologies: Vec::new(),
            tls_name: Some("example.test".to_owned()),
            tls_issuer: None,
            ssh_key: None,
        }],
    );
    let human = rxscan::run::human_summary(&with);
    assert!(human.contains("example.test"), "{human}");
    assert!(human.contains("TLS name"), "{human}");

    let without = recon_report_with_ports(
        "HOST example.test\nPORT SERVICE PRODUCT\n443/tcp https nginx",
        vec![rxscan::run::PortServiceDetail {
            port: 443,
            service: "https".to_owned(),
            product: Some("nginx".to_owned()),
            version: None,
            banner: None,
            endpoint: Some("https://example.test/".to_owned()),
            title: None,
            technologies: Vec::new(),
            tls_name: None,
            tls_issuer: None,
            ssh_key: None,
        }],
    );
    let plain = rxscan::run::human_summary(&without);
    assert!(
        !plain.contains("TLS name"),
        "no TLS without evidence: {plain}"
    );
}

#[test]
fn unknown_open_service_remains_honest() {
    let report = recon_report_with_ports(
        "HOST example.test\nPORT SERVICE PRODUCT\n443/tcp unknown -",
        vec![rxscan::run::PortServiceDetail {
            port: 443,
            service: "unknown".to_owned(),
            product: None,
            version: None,
            banner: None,
            endpoint: None,
            title: None,
            technologies: Vec::new(),
            tls_name: None,
            tls_issuer: None,
            ssh_key: None,
        }],
    );
    let human = rxscan::run::human_summary(&report);
    assert!(human.contains("443/tcp"), "{human}");
    assert!(human.contains("OPEN"), "{human}");
    assert!(
        human.to_ascii_lowercase().contains("unknown"),
        "honest unknown: {human}"
    );
    assert!(!human.contains("Product"), "no fabricated product: {human}");
    assert!(!human.contains("Version"), "no fabricated version: {human}");
    assert!(!human.contains("TLS name"), "no fabricated TLS: {human}");
}

#[test]
fn port_output_sanitizes_remote_text() {
    let report = recon_report_with_ports(
        "HOST example.test\nPORT SERVICE PRODUCT\n80/tcp http nginx",
        vec![rxscan::run::PortServiceDetail {
            port: 80,
            service: "http".to_owned(),
            product: Some("nginx\x1b[31m".to_owned()),
            version: None,
            banner: None,
            endpoint: Some("http://example.test/\x07".to_owned()),
            title: Some("Title\x00with\x1b control".to_owned()),
            technologies: Vec::new(),
            tls_name: None,
            tls_issuer: None,
            ssh_key: None,
        }],
    );
    let human = rxscan::run::human_summary(&report);
    assert!(!human.contains('\x1b'), "no ANSI: {human:?}");
    assert!(!human.contains('\x07'), "no BEL");
    assert!(!human.contains('\x00'), "no NUL");
    assert!(human.contains("nginx"), "{human}");
    assert!(human.contains("http://example.test/"), "{human}");
}

// --- INVESTIGATION --------------------------------------------------------

#[test]
fn investigation_account_exposes_public_url() {
    use rxscan::investigate::{
        FixtureDnsFetcher, FixtureProfileFetcher, FixtureSearchRunner, InvestigationConfig,
    };
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;
    let search = FixtureSearchRunner::default().with_account(
        "exampleuser",
        "github",
        "GitHub",
        "https://example.test/github/exampleuser",
    );
    let profile = FixtureProfileFetcher::default().with_page(
        "https://example.test/github/exampleuser",
        "https://example.test/github/exampleuser",
        "<html><body>profile</body></html>",
    );
    let dns = FixtureDnsFetcher::default();
    let cancelled = AtomicBool::new(false);
    let mut config = InvestigationConfig::username("exampleuser");
    config.depth = 1;
    config.allow_test_loopback = true;
    config.deadline = Duration::from_secs(10);
    let report =
        rxscan::investigate::run_investigation_with(config, &search, &profile, &dns, &cancelled)
            .unwrap();
    let human = rxscan::investigate::render_human(&report, false, false, true);
    assert!(
        human.contains("https://example.test/github/exampleuser"),
        "profile URL visible: {human}"
    );
    assert!(human.contains("ACCOUNTS"), "{human}");
}

#[test]
fn investigation_hides_internal_ids() {
    use rxscan::investigate::{
        FixtureDnsFetcher, FixtureProfileFetcher, FixtureSearchRunner, InvestigationConfig,
    };
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;
    let search = FixtureSearchRunner::default().with_account(
        "exampleuser",
        "github",
        "GitHub",
        "https://example.test/github/exampleuser",
    );
    let profile = FixtureProfileFetcher::default();
    let dns = FixtureDnsFetcher::default();
    let cancelled = AtomicBool::new(false);
    let mut config = InvestigationConfig::username("exampleuser");
    config.depth = 1;
    config.allow_test_loopback = true;
    config.deadline = Duration::from_secs(10);
    let report =
        rxscan::investigate::run_investigation_with(config, &search, &profile, &dns, &cancelled)
            .unwrap();
    let human = rxscan::investigate::render_human(&report, false, false, true);
    for internal in [
        "transform_id",
        "provenance_id",
        "relationship_id",
        "graph_id",
        "evidence_id",
        "task_",
    ] {
        assert!(
            !human.contains(internal),
            "default must not leak {internal}: {human}"
        );
    }
    assert!(!human.contains('\x1b'), "plain stays ANSI-free");
}

// --- MACHINE OUTPUT -------------------------------------------------------

#[test]
fn machine_schemas_unchanged_and_ansi_free() {
    use rxscan::search::{
        ContactClass, SearchAccounting, SearchEntity, SearchObservation, SearchStatus,
        UsernameSearchReport,
    };
    use std::collections::BTreeMap;
    let seed = SearchEntity::username("exampleuser", 1_700_000_000).unwrap();
    let results = vec![SearchObservation {
        provider_id: "github".to_owned(),
        provider_version: "1".to_owned(),
        task_id: "task-github".to_owned(),
        input_entity_id: seed.id.clone(),
        contact_class: ContactClass::PublicHttp,
        status: SearchStatus::Confirmed,
        confidence: 94,
        timestamp: 1_700_000_000,
        evidence: vec!["all required profile markers matched".to_owned()],
        attributes: BTreeMap::from([
            (
                "profile_url".to_owned(),
                "https://example.test/github/exampleuser".to_owned(),
            ),
            (
                "final_url".to_owned(),
                "https://example.test/github/exampleuser".to_owned(),
            ),
        ]),
    }];
    let mut counts = BTreeMap::new();
    counts.insert(SearchStatus::Confirmed, 1);
    let report = UsernameSearchReport {
        schema_version: 1,
        run_id: "search_run_example".to_owned(),
        seed,
        provider_pack_version: "fixture-v1".to_owned(),
        accounting: SearchAccounting {
            providers_requested: 1,
            providers_completed: 1,
            skipped: 0,
            cancelled: 0,
            unscanned: 0,
            counts,
            truncated: false,
        },
        results,
        graph: rxscan::graph::ScanGraph::default(),
        network_scans: 0,
        started_at: 1_700_000_000,
        completed_at: 1_700_000_001,
    };
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains('\x1b'));
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["results"].as_array().unwrap().len(), 1);
    assert_eq!(
        parsed["results"][0]["attributes"]["profile_url"],
        serde_json::Value::String("https://example.test/github/exampleuser".to_owned())
    );
    let jsonl = rxscan::search::render_username_jsonl(&report);
    assert!(!jsonl.contains('\x1b'));
    assert!(jsonl.contains("https://example.test/github/exampleuser"));
    for line in jsonl.lines() {
        serde_json::from_str::<serde_json::Value>(line).expect("valid JSONL");
    }
}

#[test]
fn human_truncation_does_not_remove_machine_records() {
    use rxscan::search::{
        ContactClass, SearchAccounting, SearchEntity, SearchObservation, SearchStatus,
        UsernameSearchReport,
    };
    use std::collections::BTreeMap;
    let seed = SearchEntity::username("exampleuser", 1_700_000_000).unwrap();
    let mut results = Vec::new();
    for i in 0..14 {
        results.push(SearchObservation {
            provider_id: format!("confirmed-provider-{i:02}"),
            provider_version: "1".to_owned(),
            task_id: format!("task-{i:02}"),
            input_entity_id: seed.id.clone(),
            contact_class: ContactClass::PublicHttp,
            status: SearchStatus::Confirmed,
            confidence: 94,
            timestamp: 1_700_000_000,
            evidence: vec!["profile".to_owned()],
            attributes: BTreeMap::from([
                (
                    "profile_url".to_owned(),
                    format!("https://example.test/c{i:02}/exampleuser"),
                ),
                (
                    "final_url".to_owned(),
                    format!("https://example.test/c{i:02}/exampleuser"),
                ),
            ]),
        });
    }
    let mut counts = BTreeMap::new();
    counts.insert(SearchStatus::Confirmed, 14);
    let report = UsernameSearchReport {
        schema_version: 1,
        run_id: "search_run_example".to_owned(),
        seed,
        provider_pack_version: "fixture-v1".to_owned(),
        accounting: SearchAccounting {
            providers_requested: 14,
            providers_completed: 14,
            skipped: 0,
            cancelled: 0,
            unscanned: 0,
            counts,
            truncated: false,
        },
        results,
        graph: rxscan::graph::ScanGraph::default(),
        network_scans: 0,
        started_at: 1_700_000_000,
        completed_at: 1_700_000_001,
    };
    // Human shows 10 + additional.
    let rows: Vec<SearchRow> = report
        .results
        .iter()
        .map(|r| SearchRow {
            status: "confirmed",
            provider: r.provider_id.clone(),
            confidence: r.confidence,
            detail: "public profile".to_owned(),
            tier: RowTier::Positive,
            url: r.attributes.get("final_url").cloned().unwrap_or_default(),
            url_observed: true,
        })
        .collect();
    let summary = SearchSummary {
        requested: 14,
        completed: 14,
        skipped: 0,
        cancelled: 0,
        unscanned: 0,
        truncated: false,
    };
    let human = rxscan::terminal::render_search_report_caps(
        "exampleuser",
        14,
        &rows,
        &summary,
        false,
        caps_plain(),
    );
    assert!(human.contains("+ 4 additional findings"), "{human}");
    // Machine keeps all 14.
    let jsonl = rxscan::search::render_username_jsonl(&report);
    assert_eq!(jsonl.lines().count(), 16, "start + 14 + summary");
    assert!(jsonl.contains("confirmed-provider-13"));
}
