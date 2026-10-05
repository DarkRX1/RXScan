//! Final polish regression: one FINDINGS table, one 10-row budget.
//!
//! Uses only reserved/synthetic fixtures (`exampleuser`, `example.test`,
//! `192.0.2.10`, ...). No network, no real provider data.

use rxscan::terminal::{RowTier, SearchRow, SearchSummary, TerminalCapabilities};

fn confirmed_row(index: usize) -> SearchRow {
    SearchRow {
        status: "confirmed",
        provider: format!("confirmed-provider-{index:02}"),
        confidence: 94,
        detail: "public profile".to_owned(),
        tier: RowTier::Positive,
        url: format!("https://example.test/c{index:02}/exampleuser"),
        url_observed: true,
    }
}

fn possible_row(index: usize) -> SearchRow {
    SearchRow {
        status: "possible",
        provider: format!("possible-provider-{index:02}"),
        confidence: 25,
        detail: "weak evidence".to_owned(),
        tier: RowTier::Positive,
        url: format!("https://example.test/p{index:02}/exampleuser"),
        url_observed: false,
    }
}

fn attention_row(status: &'static str, provider: String) -> SearchRow {
    let detail = match status {
        "blocked" => "provider denied access",
        "unknown" => "no signal",
        "rate_limited" => "HTTP 429",
        "error" => "request failed",
        _ => "no signal",
    };
    SearchRow {
        status,
        provider,
        confidence: 0,
        detail: detail.to_owned(),
        tier: RowTier::Attention,
        url: String::new(),
        url_observed: false,
    }
}

fn quiet_row(provider: String) -> SearchRow {
    SearchRow {
        status: "not_found",
        provider,
        confidence: 0,
        detail: String::new(),
        tier: RowTier::Quiet,
        url: String::new(),
        url_observed: false,
    }
}

fn build_rows(confirmed: usize, possible: usize) -> Vec<SearchRow> {
    let mut rows = Vec::new();
    for i in 0..confirmed {
        rows.push(confirmed_row(i));
    }
    for i in 0..possible {
        rows.push(possible_row(i));
    }
    rows
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
        TerminalCapabilities::plain(),
    )
}

fn render_all(rows: &[SearchRow], summary: &SearchSummary) -> String {
    rxscan::terminal::render_search_report_caps(
        "exampleuser",
        summary.requested,
        rows,
        summary,
        true,
        TerminalCapabilities::plain(),
    )
}

fn render_explain(rows: &[SearchRow], summary: &SearchSummary, show_all: bool) -> String {
    rxscan::terminal::render_search_report_explain_caps(
        "exampleuser",
        summary.requested,
        rows,
        summary,
        show_all,
        TerminalCapabilities::plain(),
    )
}

fn displayed_finding_count(text: &str, confirmed: usize, possible: usize) -> usize {
    let mut count = 0;
    for i in 0..confirmed {
        if text.contains(&format!("confirmed-provider-{i:02}")) {
            count += 1;
        }
    }
    for i in 0..possible {
        if text.contains(&format!("possible-provider-{i:02}")) {
            count += 1;
        }
    }
    count
}

#[test]
fn default_renders_findings_header_exactly_once() {
    let rows = build_rows(14, 11);
    let summary = summary_for(25);
    let text = render_default(&rows, &summary);
    assert!(text.contains("FINDINGS"), "FINDINGS section: {text}");
    assert_eq!(
        text.matches("FINDINGS").count(),
        1,
        "one FINDINGS section: {text}"
    );
    // Findings-first cards: no database-like STATUS table for positives.
    assert!(
        !text.contains("STATUS"),
        "cards replace STATUS table for positives: {text}"
    );
}

#[test]
fn default_displays_no_more_than_10_rows() {
    let rows = build_rows(14, 11);
    let summary = summary_for(25);
    let text = render_default(&rows, &summary);
    let shown = displayed_finding_count(&text, 14, 11);
    assert!(shown <= 10, "at most 10 rows, got {shown}: {text}");
    assert_eq!(shown, 10, "budget is exactly 10 when overflow: {text}");
    // Small fixture shows everything.
    let small = build_rows(2, 1);
    let small_summary = summary_for(3);
    let small_text = render_default(&small, &small_summary);
    assert_eq!(
        displayed_finding_count(&small_text, 2, 1),
        3,
        "small fixture shows all: {small_text}"
    );
}

#[test]
fn confirmed_are_prioritized_before_possible() {
    let rows = build_rows(14, 11);
    let summary = summary_for(25);
    let text = render_default(&rows, &summary);
    // 8 confirmed + 2 possible under the shared budget.
    for i in 0..8 {
        assert!(
            text.contains(&format!("confirmed-provider-{i:02}")),
            "confirmed {i:02} visible: {text}"
        );
    }
    assert!(
        !text.contains("confirmed-provider-08"),
        "9th confirmed hidden by budget: {text}"
    );
    let last_confirmed = text.find("confirmed-provider-07").unwrap();
    let first_possible = text.find("possible-provider-00").unwrap();
    assert!(last_confirmed < first_possible, "confirmed first: {text}");
    // Deterministic order within the group.
    let first = text.find("confirmed-provider-00").unwrap();
    let second = text.find("confirmed-provider-01").unwrap();
    assert!(first < second, "provider order stable: {text}");
}

#[test]
fn possible_reserve_remains_visible() {
    // 14 confirmed + 11 possible => 8 confirmed + 2 possible.
    let rows = build_rows(14, 11);
    let summary = summary_for(25);
    let text = render_default(&rows, &summary);
    assert!(text.contains("possible-provider-00"));
    assert!(text.contains("possible-provider-01"));
    assert!(
        !text.contains("possible-provider-02"),
        "reserve is 2 rows: {text}"
    );
}

#[test]
fn unused_confirmed_capacity_flows_to_possible() {
    // 5 confirmed + 12 possible => 5 confirmed + 5 possible.
    let rows = build_rows(5, 12);
    let summary = summary_for(17);
    let text = render_default(&rows, &summary);
    for i in 0..5 {
        assert!(text.contains(&format!("confirmed-provider-{i:02}")));
    }
    for i in 0..5 {
        assert!(
            text.contains(&format!("possible-provider-{i:02}")),
            "possible {i:02} uses spare capacity: {text}"
        );
    }
    assert!(
        !text.contains("possible-provider-05"),
        "budget still 10: {text}"
    );
    assert_eq!(displayed_finding_count(&text, 5, 12), 10);
    // 14 confirmed + 0 possible => confirmed may use the whole budget.
    let only = build_rows(14, 0);
    let only_summary = summary_for(14);
    let only_text = render_default(&only, &only_summary);
    assert_eq!(displayed_finding_count(&only_text, 14, 0), 10);
    assert!(only_text.contains("confirmed-provider-09"));
    assert!(!only_text.contains("confirmed-provider-10"));
}

#[test]
fn additional_count_is_exact() {
    // 14 + 11 = 25 total, 10 shown => + 15.
    let rows = build_rows(14, 11);
    let text = render_default(&rows, &summary_for(25));
    assert!(
        text.contains("+ 15 additional findings"),
        "14+11 budget math: {text}"
    );
    // 5 + 12 = 17 total, 10 shown => + 7.
    let rows = build_rows(5, 12);
    let text = render_default(&rows, &summary_for(17));
    assert!(text.contains("+ 7 additional findings"), "{text}");
    // 14 + 0 = 14 total, 10 shown => + 4.
    let rows = build_rows(14, 0);
    let text = render_default(&rows, &summary_for(14));
    assert!(text.contains("+ 4 additional findings"), "{text}");
    // 2 + 1 = 3 total, all shown => no line.
    let rows = build_rows(2, 1);
    let text = render_default(&rows, &summary_for(3));
    assert!(
        !text.contains("additional findings"),
        "no overflow, no line: {text}"
    );
}

#[test]
fn default_hides_negative_provider_rows() {
    let mut rows = build_rows(2, 1);
    rows.push(attention_row("blocked", "blocked-provider-00".to_owned()));
    rows.push(attention_row("unknown", "unknown-provider-00".to_owned()));
    rows.push(attention_row(
        "rate_limited",
        "limited-provider-00".to_owned(),
    ));
    rows.push(attention_row("error", "error-provider-00".to_owned()));
    rows.push(quiet_row("missing-provider-00".to_owned()));
    let summary = SearchSummary {
        requested: 8,
        completed: 8,
        skipped: 0,
        cancelled: 0,
        unscanned: 0,
        truncated: false,
    };
    let text = render_default(&rows, &summary);
    for provider in [
        "blocked-provider-00",
        "unknown-provider-00",
        "limited-provider-00",
        "error-provider-00",
        "missing-provider-00",
    ] {
        assert!(!text.contains(provider), "hidden {provider}: {text}");
    }
    for label in ["BLOCKED", "UNKNOWN", "RATE LIMITED", "ERROR", "NOT FOUND"] {
        assert!(!text.contains(label), "hidden {label}: {text}");
    }
    // Positive findings remain.
    assert!(text.contains("confirmed-provider-00"));
    assert!(text.contains("possible-provider-00"));
}

#[test]
fn coverage_totals_remain_complete() {
    let mut rows = build_rows(14, 11);
    for i in 0..5 {
        rows.push(attention_row("blocked", format!("blocked-provider-{i:02}")));
    }
    for i in 0..3 {
        rows.push(attention_row("unknown", format!("unknown-provider-{i:02}")));
    }
    for i in 0..2 {
        rows.push(attention_row(
            "rate_limited",
            format!("limited-provider-{i:02}"),
        ));
    }
    rows.push(attention_row("error", "error-provider-00".to_owned()));
    let total = rows.len();
    let summary = SearchSummary {
        requested: total,
        completed: total,
        skipped: 0,
        cancelled: 0,
        unscanned: 0,
        truncated: false,
    };
    let text = render_default(&rows, &summary);
    assert!(text.contains("COVERAGE"), "{text}");
    for section in [
        "Completed",
        "Confirmed",
        "Possible",
        "Blocked",
        "Unknown",
        "Rate limited",
        "Errors",
        "Unscanned",
    ] {
        assert!(text.contains(section), "missing {section}: {text}");
    }
    // Exact totals survive the 10-row display budget.
    assert!(text.contains("14"), "confirmed total: {text}");
    assert!(text.contains("11"), "possible total: {text}");
    // Incomplete verification stays visible in plain language.
    assert!(
        text.contains("Some providers could not be verified."),
        "{text}"
    );
}

#[test]
fn all_bypasses_display_limit() {
    let rows = build_rows(14, 11);
    let summary = summary_for(25);
    let text = render_all(&rows, &summary);
    assert_eq!(displayed_finding_count(&text, 14, 11), 25);
    assert!(text.contains("confirmed-provider-13"));
    assert!(text.contains("possible-provider-10"));
    assert!(
        !text.contains("additional findings"),
        "no limits with --all: {text}"
    );
    // Full human detail includes negative rows.
    let mut with_negative = rows.clone();
    with_negative.push(attention_row("blocked", "blocked-provider-00".to_owned()));
    with_negative.push(quiet_row("missing-provider-00".to_owned()));
    let neg_summary = SearchSummary {
        requested: 27,
        completed: 27,
        skipped: 0,
        cancelled: 0,
        unscanned: 0,
        truncated: false,
    };
    let all_text = render_all(&with_negative, &neg_summary);
    assert!(all_text.contains("blocked-provider-00"));
    assert!(all_text.contains("missing-provider-00"));
}

#[test]
fn explain_retains_explanation_detail() {
    let mut rows = build_rows(2, 1);
    rows.push(attention_row("blocked", "blocked-provider-00".to_owned()));
    let summary = SearchSummary {
        requested: 4,
        completed: 4,
        skipped: 0,
        cancelled: 0,
        unscanned: 0,
        truncated: false,
    };
    let default = render_default(&rows, &summary);
    assert!(
        !default.contains("0 network scans"),
        "raw accounting lives in --explain: {default}"
    );
    assert!(
        !default.contains("4 requested"),
        "raw accounting lives in --explain: {default}"
    );
    let explained = render_explain(&rows, &summary, false);
    assert!(explained.contains("4 requested"), "{explained}");
    assert!(explained.contains("4 completed"), "{explained}");
    assert!(explained.contains("0 network scans"), "{explained}");
    // Explain keeps reasoning visibility (attention rows).
    assert!(explained.contains("blocked-provider-00"), "{explained}");
    // Concepts stay separate: --explain without --all still hides quiet rows.
    let mut with_quiet = rows.clone();
    with_quiet.push(quiet_row("missing-provider-00".to_owned()));
    let quiet_summary = SearchSummary {
        requested: 5,
        completed: 5,
        skipped: 0,
        cancelled: 0,
        unscanned: 0,
        truncated: false,
    };
    let explained_only = render_explain(&with_quiet, &quiet_summary, false);
    assert!(
        !explained_only.contains("missing-provider-00"),
        "quiet needs --all: {explained_only}"
    );
    let explained_all = render_explain(&with_quiet, &quiet_summary, true);
    assert!(explained_all.contains("missing-provider-00"));
}

#[test]
fn machine_output_unaffected_and_ansi_free() {
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
            task_id: format!("task-confirmed-{i:02}"),
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
    for i in 0..11 {
        results.push(SearchObservation {
            provider_id: format!("possible-provider-{i:02}"),
            provider_version: "1".to_owned(),
            task_id: format!("task-possible-{i:02}"),
            input_entity_id: seed.id.clone(),
            contact_class: ContactClass::PublicHttp,
            status: SearchStatus::Possible,
            confidence: 25,
            timestamp: 1_700_000_000,
            evidence: vec!["weak evidence".to_owned()],
            attributes: BTreeMap::from([
                (
                    "profile_url".to_owned(),
                    format!("https://example.test/p{i:02}/exampleuser"),
                ),
                (
                    "final_url".to_owned(),
                    format!("https://example.test/p{i:02}/exampleuser"),
                ),
            ]),
        });
    }
    let mut counts = BTreeMap::new();
    counts.insert(SearchStatus::Confirmed, 14);
    counts.insert(SearchStatus::Possible, 11);
    let report = UsernameSearchReport {
        schema_version: 1,
        run_id: "search_run_example".to_owned(),
        seed,
        provider_pack_version: "fixture-v1".to_owned(),
        accounting: SearchAccounting {
            providers_requested: 25,
            providers_completed: 25,
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
    // JSON keeps every record and never carries ANSI.
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains('\x1b'), "JSON ANSI-free");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["results"].as_array().unwrap().len(), 25);
    // JSONL keeps every observation plus start/summary and stays ANSI-free.
    let jsonl = rxscan::search::render_username_jsonl(&report);
    assert!(!jsonl.contains('\x1b'), "JSONL ANSI-free");
    let lines: Vec<&str> = jsonl.lines().collect();
    assert_eq!(lines.len(), 27, "start + 25 observations + summary");
    for line in &lines {
        serde_json::from_str::<serde_json::Value>(line).expect("valid JSONL");
    }
    assert!(jsonl.contains("confirmed-provider-13"));
    assert!(jsonl.contains("possible-provider-10"));
    // Human budget does not leak into machine output: all 25 present.
    let observation_lines = lines.len() - 2;
    assert_eq!(observation_lines, 25);
}

// --- CLI presentation (binary) ------------------------------------------

fn rxscan_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_rxscan"))
}

fn run_cli(args: &[&str]) -> (i32, String, String) {
    let output = std::process::Command::new(rxscan_bin())
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
fn help_contains_single_workflow_overview() {
    let (code, stdout, _) = run_cli(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("USAGE"), "{stdout}");
    assert!(stdout.contains("QUICK START"), "{stdout}");
    assert!(stdout.contains("WORKFLOWS"), "{stdout}");
    assert_eq!(
        stdout.matches("QUICK START").count(),
        1,
        "one quick start: {stdout}"
    );
    assert_eq!(
        stdout.matches("WORKFLOWS").count(),
        1,
        "one workflows overview: {stdout}"
    );
    assert!(
        !stdout.contains("Major workflows:"),
        "legacy block removed: {stdout}"
    );
    assert!(
        stdout.contains("Run `rxscan <command> --help`"),
        "transition line: {stdout}"
    );
    // Clap reference remains.
    assert!(
        stdout.contains("TARGET") || stdout.contains("--max-tasks"),
        "{stdout}"
    );
}

#[test]
fn root_welcome_uses_consistent_placeholders() {
    let (code, stdout, _) = run_cli(&[]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("rxscan search --username <name>"),
        "{stdout}"
    );
    assert!(
        stdout.contains("rxscan investigate --username <name>"),
        "{stdout}"
    );
    assert!(!stdout.contains("<n>"), "no legacy <n>: {stdout}");
}

#[test]
fn friendly_error_suggestions_unchanged() {
    let (code, _, stderr) = run_cli(&["search", "exampleuser"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("search needs a search type"), "{stderr}");
    assert!(
        stderr.contains("rxscan search --username exampleuser"),
        "{stderr}"
    );
    let (code, _, stderr) = run_cli(&["--investigate", "exampleuser"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("rxscan investigate --username exampleuser"),
        "{stderr}"
    );
    let (code, _, stderr) = run_cli(&["capability"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("Did you mean"), "{stderr}");
    assert!(stderr.contains("rxscan capabilities"), "{stderr}");
}
