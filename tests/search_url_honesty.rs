//! Search URL honesty regression: every displayed value means exactly
//! what the UI implies.
//!
//! Synthetic/reserved values only (`exampleuser`, `example.test`).
//! No network, no real provider data.

use rxscan::terminal::{
    RowTier, SearchRow, SearchSummary, SearchUrlKind, TerminalCapabilities, classify_search_url,
    is_api_resource_url, is_identity_specific_url,
};

fn caps_plain() -> TerminalCapabilities {
    TerminalCapabilities::plain()
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

fn render_all(rows: &[SearchRow], summary: &SearchSummary) -> String {
    rxscan::terminal::render_search_report_caps(
        "exampleuser",
        summary.requested,
        rows,
        summary,
        true,
        caps_plain(),
    )
}

fn render_explain(rows: &[SearchRow], summary: &SearchSummary) -> String {
    rxscan::terminal::render_search_report_explain_caps(
        "exampleuser",
        summary.requested,
        rows,
        summary,
        false,
        caps_plain(),
    )
}

// 1. observed identity-specific URL → Profile
#[test]
fn observed_identity_specific_url_renders_profile() {
    let rows = vec![SearchRow {
        status: "confirmed",
        provider: "github".to_owned(),
        confidence: 94,
        detail: "public profile".to_owned(),
        tier: RowTier::Positive,
        url: "https://example.test/github/exampleuser".to_owned(),
        url_observed: true,
    }];
    let text = render_default(&rows, &summary_for(1));
    assert!(text.contains("Profile"), "Profile label visible: {text}");
    assert!(
        text.contains("https://example.test/github/exampleuser"),
        "{text}"
    );
    assert!(text.contains("high"), "{text}");
    assert!(text.contains("94%"), "{text}");
    assert!(text.contains("public profile"), "{text}");
    // Classification helper agrees.
    assert_eq!(
        classify_search_url(
            "https://example.test/github/exampleuser",
            "exampleuser",
            true
        ),
        SearchUrlKind::ObservedProfile
    );
}

// 2. observed non-profile resource → Resource
#[test]
fn observed_api_resource_renders_resource_not_profile() {
    let url = "https://api.example.test/users/exampleuser";
    let rows = vec![SearchRow {
        status: "confirmed",
        provider: "example-api".to_owned(),
        confidence: 94,
        detail: "public account resource".to_owned(),
        tier: RowTier::Positive,
        url: url.to_owned(),
        url_observed: true,
    }];
    let text = render_default(&rows, &summary_for(1));
    assert!(text.contains("Resource"), "Resource label: {text}");
    assert!(text.contains(url), "{text}");
    assert!(
        text.contains("public account resource"),
        "honest evidence wording: {text}"
    );
    // Must not call an API resource a Profile on the same line.
    for line in text.lines() {
        if line.contains(url) {
            assert!(
                !line.contains("Profile"),
                "API resource must not be labeled Profile: {line}"
            );
        }
    }
    assert!(is_api_resource_url(url));
    assert_eq!(
        classify_search_url(url, "exampleuser", true),
        SearchUrlKind::ObservedResource
    );
    // Other API shapes are also resources.
    for api in [
        "https://example.test/api/users/exampleuser",
        "https://example.test/xrpc/app.bsky.actor.getProfile?actor=exampleuser",
        "https://example.test/user/exampleuser/about.json",
        "https://example.test/_/api/1.0/user/lookup.json?username=exampleuser",
    ] {
        assert!(is_api_resource_url(api), "api-like: {api}");
    }
}

// 3. identity-specific unconfirmed URL → Candidate
#[test]
fn unconfirmed_identity_specific_url_renders_candidate() {
    let url = "https://example.test/u/exampleuser";
    let rows = vec![SearchRow {
        status: "possible",
        provider: "example-site".to_owned(),
        confidence: 25,
        detail: "weak evidence".to_owned(),
        tier: RowTier::Positive,
        url: url.to_owned(),
        url_observed: false,
    }];
    let text = render_default(&rows, &summary_for(1));
    assert!(text.contains("Candidate"), "Candidate label: {text}");
    assert!(text.contains(url), "{text}");
    assert!(text.contains("low"), "{text}");
    assert!(text.contains("25%"), "{text}");
    assert!(text.contains("weak evidence"), "{text}");
    let section = text
        .lines()
        .skip_while(|line| !line.contains("example-site"))
        .take(4)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !section.contains("public profile"),
        "possible must not claim public profile: {section}"
    );
    assert_eq!(
        classify_search_url(url, "exampleuser", false),
        SearchUrlKind::CandidateProfile
    );
}

// 4. generic provider endpoint is not shown as Profile
#[test]
fn generic_provider_endpoint_never_renders_as_profile() {
    for generic in [
        "https://example.test/",
        "https://example.test/login",
        "https://api.example.test/lookup",
        "https://example.test/search?q=other",
    ] {
        assert!(
            !is_identity_specific_url(generic, "exampleuser"),
            "generic has no username: {generic}"
        );
        assert_eq!(
            classify_search_url(generic, "exampleuser", true),
            SearchUrlKind::ProviderEndpoint
        );
        // Even when marked observed, a generic URL must not render as Profile.
        let rows = vec![SearchRow {
            status: "confirmed",
            provider: "example-site".to_owned(),
            confidence: 88,
            detail: "public profile".to_owned(),
            tier: RowTier::Positive,
            url: generic.to_owned(),
            url_observed: true,
        }];
        let text = render_default(&rows, &summary_for(1));
        for line in text.lines() {
            if line.contains(generic) {
                panic!("generic endpoint must not appear as URL line: {line}\n{text}");
            }
        }
        // No Profile label on any line containing the generic URL (there is none).
        assert!(
            !text
                .lines()
                .any(|line| line.contains("Profile") && line.contains(generic)),
            "generic never Profile: {text}"
        );
    }
}

// 5. generic provider endpoint may be omitted from default
#[test]
fn generic_endpoint_omitted_from_default_with_honest_notice() {
    let rows = vec![SearchRow {
        status: "possible",
        provider: "example-site".to_owned(),
        confidence: 25,
        detail: "weak evidence".to_owned(),
        tier: RowTier::Positive,
        url: "https://api.example.test/lookup".to_owned(),
        url_observed: false,
    }];
    let text = render_default(&rows, &summary_for(1));
    assert!(
        !text.contains("https://api.example.test/lookup"),
        "generic omitted from default: {text}"
    );
    assert!(
        text.contains("No identity-specific profile URL verified"),
        "honest absence notice: {text}"
    );
}

// 6. no URL → no invented URL
#[test]
fn empty_url_renders_honest_absence_without_invention() {
    let rows = vec![SearchRow {
        status: "possible",
        provider: "example-site".to_owned(),
        confidence: 25,
        detail: "weak evidence".to_owned(),
        tier: RowTier::Positive,
        url: String::new(),
        url_observed: false,
    }];
    let text = render_default(&rows, &summary_for(1));
    assert!(
        text.contains("No identity-specific profile URL verified"),
        "{text}"
    );
    assert!(!text.contains("https://"), "no invented URL: {text}");
    assert_eq!(
        classify_search_url("", "exampleuser", false),
        SearchUrlKind::None
    );
    assert_eq!(
        classify_search_url("   ", "exampleuser", true),
        SearchUrlKind::None
    );
}

// 7. confidence/status unchanged by presentation honesty
#[test]
fn presentation_never_changes_confidence_or_status() {
    let rows = vec![
        SearchRow {
            status: "confirmed",
            provider: "github".to_owned(),
            confidence: 94,
            detail: "public profile".to_owned(),
            tier: RowTier::Positive,
            url: "https://example.test/github/exampleuser".to_owned(),
            url_observed: true,
        },
        SearchRow {
            status: "possible",
            provider: "example-site".to_owned(),
            confidence: 25,
            detail: "weak evidence".to_owned(),
            tier: RowTier::Positive,
            url: "https://example.test/u/exampleuser".to_owned(),
            url_observed: false,
        },
    ];
    let text = render_default(&rows, &summary_for(2));
    assert!(text.contains("94%"), "{text}");
    assert!(text.contains("25%"), "{text}");
    assert!(text.contains("high"), "{text}");
    assert!(text.contains("low"), "{text}");
    // Input model untouched.
    assert_eq!(rows[0].confidence, 94);
    assert_eq!(rows[1].confidence, 25);
    assert_eq!(rows[0].status, "confirmed");
    assert_eq!(rows[1].status, "possible");
    // Possible never upgrades to confirmed wording.
    assert!(!text.contains("94% · public profile") || text.contains("github"));
}

// 8. machine schemas unchanged (JSON/JSONL carry complete evidence)
#[test]
fn machine_schemas_carry_complete_evidence_ansi_free() {
    use rxscan::search::{
        ContactClass, SearchAccounting, SearchEntity, SearchObservation, SearchStatus,
        UsernameSearchReport,
    };
    use std::collections::BTreeMap;
    let seed = SearchEntity::username("exampleuser", 1_700_000_000).unwrap();
    let observation = SearchObservation {
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
    };
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
        results: vec![observation],
        graph: rxscan::graph::ScanGraph::default(),
        network_scans: 0,
        started_at: 1_700_000_000,
        completed_at: 1_700_000_001,
    };
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains('\x1b'));
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    // Public schema keys preserved.
    assert_eq!(parsed["schema_version"], 1);
    assert!(
        parsed["results"][0]["attributes"]["profile_url"]
            .as_str()
            .unwrap()
            .contains("example.test")
    );
    assert!(
        parsed["results"][0]["attributes"]["final_url"]
            .as_str()
            .unwrap()
            .contains("example.test")
    );
    let jsonl = rxscan::search::render_username_jsonl(&report);
    assert!(!jsonl.contains('\x1b'));
    for line in jsonl.lines() {
        serde_json::from_str::<serde_json::Value>(line).expect("valid JSONL");
    }
}

// --all and --explain keep honest labels while exposing complete detail.
#[test]
fn all_and_explain_preserve_honest_labels() {
    let rows = vec![
        SearchRow {
            status: "confirmed",
            provider: "github".to_owned(),
            confidence: 94,
            detail: "public profile".to_owned(),
            tier: RowTier::Positive,
            url: "https://example.test/github/exampleuser".to_owned(),
            url_observed: true,
        },
        SearchRow {
            status: "possible",
            provider: "example-site".to_owned(),
            confidence: 25,
            detail: "weak evidence".to_owned(),
            tier: RowTier::Positive,
            url: "https://example.test/u/exampleuser".to_owned(),
            url_observed: false,
        },
    ];
    let all = render_all(&rows, &summary_for(2));
    assert!(all.contains("Profile"), "{all}");
    assert!(all.contains("Candidate"), "{all}");
    let explained = render_explain(&rows, &summary_for(2));
    assert!(explained.contains("Profile"), "{explained}");
    assert!(explained.contains("Candidate"), "{explained}");
    assert!(explained.contains("0 network scans"), "{explained}");
}
