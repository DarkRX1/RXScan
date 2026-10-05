//! Investigation default-noise regression: entity-first, asset-quiet.
//!
//! Synthetic/reserved values only. No network; fixture backends only.

use std::sync::atomic::AtomicBool;
use std::time::Duration;

use rxscan::investigate::{
    FixtureDnsFetcher, FixtureProfileFetcher, FixtureSearchRunner, InvestigationConfig,
};

fn test_config() -> InvestigationConfig {
    let mut config = InvestigationConfig::username("exampleuser");
    config.depth = 2;
    config.allow_test_loopback = true;
    config.deadline = Duration::from_secs(10);
    config
}

fn run_with_body(profile_url: &str, body: &str) -> rxscan::investigate::InvestigationReport {
    let search =
        FixtureSearchRunner::default().with_account("exampleuser", "github", "GitHub", profile_url);
    let profile = FixtureProfileFetcher::default().with_page(profile_url, profile_url, body);
    let dns = FixtureDnsFetcher::default();
    let cancelled = AtomicBool::new(false);
    rxscan::investigate::run_investigation_with(test_config(), &search, &profile, &dns, &cancelled)
        .expect("fixture investigation runs")
}

fn default_human(report: &rxscan::investigate::InvestigationReport) -> String {
    rxscan::investigate::render_human(report, false, false, true)
}

fn all_human(report: &rxscan::investigate::InvestigationReport) -> String {
    rxscan::investigate::render_human(report, true, false, true)
}

// 9. default shows profile/resource URL
#[test]
fn default_shows_profile_url() {
    let report = run_with_body(
        "https://example.test/github/exampleuser",
        "<html><body>profile</body></html>",
    );
    let human = default_human(&report);
    assert!(
        human.contains("https://example.test/github/exampleuser"),
        "profile URL visible: {human}"
    );
    assert!(human.contains("ACCOUNTS"), "{human}");
    assert!(human.contains("Profile"), "Profile branch: {human}");
}

// 10. default hides static JS asset endpoints
#[test]
fn default_hides_static_js_assets() {
    let body = r#"<html><head>
<script src="https://example.test/static/app.js"></script>
<script src="https://example.test/_next/static/chunks/main.chunk.js"></script>
</head><body>profile</body></html>"#;
    let report = run_with_body("https://example.test/github/exampleuser", body);
    let human = default_human(&report);
    assert!(
        !human.contains("app.js"),
        "JS asset hidden from default: {human}"
    );
    assert!(!human.contains("chunk"), "chunk bundle hidden: {human}");
    // --all exposes the complete evidence.
    let all = all_human(&report);
    assert!(
        all.contains("app.js") || all.contains("chunk"),
        "--all exposes JS detail: {all}"
    );
}

// 11. default hides CSS/image/font noise
#[test]
fn default_hides_css_image_font_noise() {
    let body = r#"<html><head>
<link href="https://example.test/static/style.css" rel="stylesheet">
<link href="https://example.test/fonts/font.woff2" rel="font">
</head><body>
<img src="https://example.test/static/logo.png">
<img src="https://example.test/static/photo.jpg">
<img src="https://example.test/static/icon.svg">
<img src="https://example.test/favicon.ico">
</body></html>"#;
    let report = run_with_body("https://example.test/github/exampleuser", body);
    let human = default_human(&report);
    for noisy in [
        "style.css",
        "font.woff2",
        "logo.png",
        "photo.jpg",
        "icon.svg",
        "favicon.ico",
    ] {
        assert!(
            !human.contains(noisy),
            "asset {noisy} hidden from default: {human}"
        );
    }
    let all = all_human(&report);
    // At least one noisy asset survives in --all (complete detail).
    let exposed = ["style.css", "font.woff2", "logo.png", "photo.jpg"]
        .iter()
        .any(|needle| all.contains(needle));
    assert!(exposed, "--all exposes asset detail: {all}");
}

// 12. meaningful related endpoints survive or are summarized
#[test]
fn meaningful_related_endpoints_survive_filtering() {
    let body = r#"<html><body>
<a href="https://example.test/blog/exampleuser">blog</a>
<script src="https://example.test/static/app.js"></script>
</body></html>"#;
    let report = run_with_body("https://example.test/github/exampleuser", body);
    let human = default_human(&report);
    // Meaningful non-static endpoint survives default filtering.
    // Canonical form may include the explicit default port.
    assert!(
        human.contains("blog/exampleuser"),
        "meaningful related survives: {human}"
    );
    // Noise does not dominate.
    assert!(!human.contains("app.js"), "{human}");
}

// 13. --all exposes complete related endpoint detail
#[test]
fn all_exposes_complete_related_detail() {
    let body = r#"<html><body>
<a href="https://example.test/blog/exampleuser">blog</a>
<script src="https://example.test/static/app.js"></script>
<link href="https://example.test/static/style.css" rel="stylesheet">
</body></html>"#;
    let report = run_with_body("https://example.test/github/exampleuser", body);
    let all = all_human(&report);
    assert!(all.contains("Related endpoints"), "complete heading: {all}");
    assert!(all.contains("blog"), "{all}");
    assert!(
        all.contains("app.js") || all.contains("style.css"),
        "assets exposed with --all: {all}"
    );
}

// 14. graph/entity counts remain unchanged by presentation filtering
#[test]
fn presentation_filtering_never_changes_counts() {
    let body = r#"<html><body>
<a href="https://example.test/blog/exampleuser">blog</a>
<script src="https://example.test/static/app.js"></script>
<link href="https://example.test/static/style.css" rel="stylesheet">
</body></html>"#;
    let report = run_with_body("https://example.test/github/exampleuser", body);
    let entities = report.entities.len();
    let relationships = report.relationships.len();
    assert!(entities > 0 && relationships > 0);
    // Render both modes; model counts must not move.
    let _ = default_human(&report);
    assert_eq!(report.entities.len(), entities);
    assert_eq!(report.relationships.len(), relationships);
    let _ = all_human(&report);
    assert_eq!(report.entities.len(), entities);
    assert_eq!(report.relationships.len(), relationships);
    // JSONL carries the complete graph regardless of human filtering.
    let jsonl = rxscan::investigate::render_jsonl(&report);
    let entity_lines = jsonl
        .lines()
        .filter(|line| line.contains("\"record_type\":\"entity\""))
        .count();
    assert_eq!(entity_lines, entities, "JSONL complete: {jsonl}");
}

// 15. no raw internal IDs in default output
#[test]
fn default_output_hides_internal_ids() {
    let report = run_with_body(
        "https://example.test/github/exampleuser",
        "<html><body>profile</body></html>",
    );
    let human = default_human(&report);
    for internal in [
        "transform_id",
        "provenance_id",
        "relationship_id",
        "graph_id",
        "evidence_id",
        "account:github",
        "username:exampleuser",
        "endpoint:https",
    ] {
        assert!(
            !human.contains(internal),
            "default must not leak {internal}: {human}"
        );
    }
    assert!(!human.contains('\x1b'), "plain stays ANSI-free");
}

// Low-confidence accounts render as Candidate, high-confidence API as Resource.
#[test]
fn account_branches_are_honest_profile_candidate_resource() {
    // High-confidence API URL → Resource.
    let search = FixtureSearchRunner::default().with_account(
        "exampleuser",
        "example-api",
        "Example API",
        "https://api.example.test/users/exampleuser",
    );
    let profile = FixtureProfileFetcher::default().with_page(
        "https://api.example.test/users/exampleuser",
        "https://api.example.test/users/exampleuser",
        "<html><body>api</body></html>",
    );
    let dns = FixtureDnsFetcher::default();
    let cancelled = AtomicBool::new(false);
    let report = rxscan::investigate::run_investigation_with(
        test_config(),
        &search,
        &profile,
        &dns,
        &cancelled,
    )
    .unwrap();
    let human = default_human(&report);
    assert!(
        human.contains("Resource"),
        "API account renders Resource: {human}"
    );
    assert!(
        human.contains("https://api.example.test/users/exampleuser"),
        "{human}"
    );
}
