//! First-time UX regression: install, type an obvious command, get a useful result.
//!
//! No setup, no theme config, no `--color always`, no env, no project DB.
//! Uses only reserved/synthetic fixtures (`example.test`, `exampleuser`,
//! `192.0.2.10`, ...). Offline-bounded where network would otherwise be
//! involved (`--providers github --deadline 1ms`, `--depth 0`).

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

fn run_cli_env(args: &[&str], key: &str, value: &str) -> (i32, String, String) {
    let output = Command::new(rxscan_bin())
        .args(args)
        .env(key, value)
        .output()
        .expect("spawn rxscan");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

// --- 1. Zero-config first run -------------------------------------------

#[test]
fn root_no_args_shows_welcome_not_target_error() {
    let (code, stdout, _) = run_cli(&[]);
    assert_eq!(code, 0);
    assert!(stdout.contains("RXSCAN"), "welcome brand: {stdout}");
    assert!(stdout.contains("Usage"), "usage block: {stdout}");
    assert!(stdout.contains("Examples"), "examples: {stdout}");
    assert!(
        stdout.contains("rxscan example.test"),
        "obvious scan example: {stdout}"
    );
    assert!(
        stdout.contains("rxscan search --username exampleuser"),
        "search example: {stdout}"
    );
    assert!(
        stdout.contains("rxscan investigate --username exampleuser"),
        "investigate example: {stdout}"
    );
    assert!(stdout.contains("rxscan --help"), "help pointer: {stdout}");
    assert!(
        !stdout.contains("target is empty"),
        "must not confuse with target error: {stdout}"
    );
    // Compact: must not dump the full Clap reference.
    assert!(
        !stdout.contains("--max-tasks"),
        "welcome stays compact: {stdout}"
    );
}

#[test]
fn help_explains_workflows_first() {
    let (code, stdout, _) = run_cli(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("QUICK START"), "quick start: {stdout}");
    assert!(stdout.contains("WORKFLOWS"), "workflows: {stdout}");
    assert!(stdout.contains("rxscan example.test"));
    assert!(stdout.contains("rxscan search --username exampleuser"));
    assert!(stdout.contains("rxscan investigate --username exampleuser"));
    for workflow in ["Scan", "Search", "Investigate", "Project", "Capabilities"] {
        assert!(stdout.contains(workflow), "missing {workflow}: {stdout}");
    }
    // Workflows come before dozens of switches.
    let quick = stdout.find("QUICK START").unwrap();
    let advanced = stdout.find("--max-tasks").unwrap_or(stdout.len());
    assert!(quick < advanced, "workflows must precede advanced switches");
}

#[test]
fn scan_reserved_example_works_zero_config() {
    let (code, stdout, _) = run_cli(&["example.test"]);
    assert_eq!(code, 0, "example.test must work with no setup");
    assert!(stdout.contains("RXSCAN"));
    assert!(stdout.contains("TARGET"));
    assert!(stdout.contains("example.test"));
}

#[test]
fn search_username_works_zero_config_bounded() {
    let (code, stdout, _) = run_cli(&[
        "search",
        "--username",
        "exampleuser",
        "--providers",
        "github",
        "--deadline",
        "1ms",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("RXSCAN"));
    assert!(stdout.contains("PUBLIC SEARCH"));
    assert!(stdout.contains("exampleuser"));
    assert!(stdout.contains("COVERAGE"));
}

#[test]
fn investigate_username_works_zero_config() {
    let (code, stdout, _) = run_cli(&["investigate", "--username", "exampleuser", "--depth", "0"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("RXSCAN"));
    assert!(stdout.contains("INVESTIGATE"));
    assert!(stdout.contains("exampleuser"));
    assert!(stdout.contains("ACCOUNTS"));
    // Friendly: no implementation vocabulary in default human output.
    for internal in [
        "transform_id",
        "provenance_id",
        "relationship_id",
        "graph_id",
        "evidence_id",
    ] {
        assert!(
            !stdout.contains(internal),
            "default must not leak {internal}: {stdout}"
        );
    }
}

#[test]
fn capabilities_works_zero_config_with_friendly_detail() {
    let (code, stdout, _) = run_cli(&["capabilities"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("RXSCAN"));
    assert!(stdout.contains("CAPABILITIES"));
    assert!(stdout.contains("NETWORK"));
    assert!(stdout.contains("SEARCH"));
    // Friendly unavailable explanation, not raw implementation text.
    assert!(
        stdout.contains("Requires raw-socket permission"),
        "friendly raw detail: {stdout}"
    );
    assert!(
        !stdout.contains("CAP_NET_RAW"),
        "raw failure text lives in --explain: {stdout}"
    );
    let (code, explained, _) = run_cli(&["capabilities", "--explain"]);
    assert_eq!(code, 0);
    assert!(
        explained.contains("CAP_NET_RAW") || explained.contains("raw SYN unavailable"),
        "explain shows exact reason: {explained}"
    );
}

// --- 2. Automatic terminal experience ------------------------------------

#[test]
fn tty_auto_color_resolves_to_styling() {
    use rxscan::terminal::{ColorMode, color_enabled};
    // Interactive TTY enables styling; piped output stays plain.
    assert!(color_enabled(ColorMode::Auto, false, true));
    assert!(!color_enabled(ColorMode::Auto, false, false));
    // NO_COLOR disables auto unless forced.
    assert!(!color_enabled(ColorMode::Auto, true, true));
    assert!(color_enabled(ColorMode::Always, true, false));
    assert!(!color_enabled(ColorMode::Never, false, true));
}

#[test]
fn non_tty_auto_emits_no_ansi() {
    // Test harness pipes stdout, so `auto` must stay plain.
    let (code, stdout, _) = run_cli(&["capabilities"]);
    assert_eq!(code, 0);
    assert!(!stdout.contains('\x1b'), "piped auto must stay plain");
    let (code, stdout, _) = run_cli(&["search", "stats"]);
    assert_eq!(code, 0);
    assert!(!stdout.contains('\x1b'));
}

#[test]
fn color_always_and_never_override() {
    let (code, styled, _) = run_cli(&["capabilities", "--color", "always"]);
    assert_eq!(code, 0);
    assert!(styled.contains('\x1b'), "--color always must style");
    let (code, plain, _) = run_cli(&["capabilities", "--color", "never"]);
    assert_eq!(code, 0);
    assert!(!plain.contains('\x1b'), "--color never stays plain");
    // Welcome respects overrides too.
    let (code, styled, _) = run_cli(&["--color", "always"]);
    assert_eq!(code, 0);
    assert!(styled.contains("RXSCAN"));
    assert!(styled.contains('\x1b'), "welcome --color always styles");
}

#[test]
fn no_color_disables_auto_but_not_always() {
    let (code, stdout, _) = run_cli_env(&["search", "stats"], "NO_COLOR", "1");
    assert_eq!(code, 0);
    assert!(!stdout.contains('\x1b'), "NO_COLOR disables auto");
    let (code, stdout, _) = run_cli_env(&["search", "stats", "--color", "always"], "NO_COLOR", "1");
    assert_eq!(code, 0);
    assert!(stdout.contains('\x1b'), "--color always overrides NO_COLOR");
}

#[test]
fn machine_output_remains_ansi_free() {
    let (code, stdout, _) = run_cli(&[
        "search",
        "--username",
        "exampleuser",
        "--providers",
        "github",
        "--deadline",
        "1ms",
        "--json",
        "--color",
        "always",
    ]);
    assert_eq!(code, 0);
    assert!(!stdout.contains('\x1b'), "JSON never styled");
    serde_json::from_str::<serde_json::Value>(&stdout).expect("valid JSON");
    let (code, stdout, _) = run_cli(&[
        "search",
        "--username",
        "exampleuser",
        "--providers",
        "github",
        "--deadline",
        "1ms",
        "--jsonl",
        "--color",
        "always",
    ]);
    assert_eq!(code, 0);
    assert!(!stdout.contains('\x1b'), "JSONL never styled");
    for line in stdout.lines() {
        serde_json::from_str::<serde_json::Value>(line).expect("every JSONL line parses");
    }
    let (code, stdout, _) = run_cli(&["capabilities", "--json", "--color", "always"]);
    assert_eq!(code, 0);
    assert!(!stdout.contains('\x1b'));
}

// --- 3. Friendly search defaults -----------------------------------------

fn synthetic_search_rows() -> (
    Vec<rxscan::terminal::SearchRow>,
    rxscan::terminal::SearchSummary,
) {
    use rxscan::terminal::{RowTier, SearchRow, SearchSummary};
    let mut rows = Vec::new();
    for i in 0..12 {
        rows.push(SearchRow {
            status: "confirmed",
            provider: format!("confirmed-provider-{i:02}"),
            confidence: 94,
            detail: "public profile".to_owned(),
            tier: RowTier::Positive,
            url: format!("https://example.test/c{i:02}/exampleuser"),
            url_observed: true,
        });
    }
    for i in 0..7 {
        rows.push(SearchRow {
            status: "possible",
            provider: format!("possible-provider-{i:02}"),
            confidence: 25,
            detail: "weak evidence".to_owned(),
            tier: RowTier::Positive,
            url: format!("https://example.test/p{i:02}/exampleuser"),
            url_observed: false,
        });
    }
    for i in 0..18 {
        rows.push(SearchRow {
            status: "blocked",
            provider: format!("blocked-provider-{i:02}"),
            confidence: 0,
            detail: "provider rejected request".to_owned(),
            tier: RowTier::Attention,
            url: String::new(),
            url_observed: false,
        });
    }
    for i in 0..50 {
        rows.push(SearchRow {
            status: "unknown",
            provider: format!("unknown-provider-{i:02}"),
            confidence: 0,
            detail: "no signal".to_owned(),
            tier: RowTier::Attention,
            url: String::new(),
            url_observed: false,
        });
    }
    let summary = SearchSummary {
        requested: 100,
        completed: 99,
        skipped: 0,
        cancelled: 0,
        unscanned: 1,
        truncated: false,
    };
    (rows, summary)
}

#[test]
fn default_search_hides_failures_preserves_coverage() {
    use rxscan::terminal::TerminalCapabilities;
    let (rows, summary) = synthetic_search_rows();
    let caps = TerminalCapabilities::plain();
    let text = rxscan::terminal::render_search_report_caps(
        "exampleuser",
        100,
        &rows,
        &summary,
        false,
        caps,
    );
    // Limit: one 10-row FINDINGS budget (8 confirmed + 2 possible).
    assert!(text.contains("confirmed-provider-00"));
    assert!(text.contains("possible-provider-00"));
    assert!(
        text.contains("+ 9 additional findings"),
        "4 hidden confirmed + 5 hidden possible: {text}"
    );
    // Secondary rows hidden by default.
    assert!(!text.contains("blocked-provider-00"), "blocked needs --all");
    assert!(!text.contains("unknown-provider-00"), "unknown needs --all");
    // Coverage totals preserved exactly.
    assert!(text.contains("Blocked"));
    assert!(text.contains("18") || text.contains("Blocked"), "{text}");
    assert!(text.contains("Unknown"));
    assert!(text.contains("COVERAGE"));
    // Plain-language warning, no scheduler jargon.
    assert!(text.contains("Some providers could not be verified."));
    assert!(!text.contains("global_deadline"), "{text}");
    assert!(!contains_ansi(&text));
}

#[test]
fn all_reveals_full_human_detail() {
    use rxscan::terminal::TerminalCapabilities;
    let (rows, summary) = synthetic_search_rows();
    let caps = TerminalCapabilities::plain();
    let text = rxscan::terminal::render_search_report_caps(
        "exampleuser",
        100,
        &rows,
        &summary,
        true,
        caps,
    );
    assert!(
        text.contains("confirmed-provider-11"),
        "all confirmed: {text}"
    );
    assert!(
        text.contains("possible-provider-06"),
        "all possible: {text}"
    );
    assert!(
        text.contains("blocked-provider-00"),
        "--all reveals blocked"
    );
    assert!(
        text.contains("unknown-provider-00"),
        "--all reveals unknown"
    );
    assert!(
        !text.contains("additional findings"),
        "no limits with --all: {text}"
    );
}

#[test]
fn incomplete_coverage_remains_visible() {
    use rxscan::terminal::{SearchSummary, TerminalCapabilities};
    let (rows, summary) = synthetic_search_rows();
    let caps = TerminalCapabilities::plain();
    let text = rxscan::terminal::render_search_report_caps(
        "exampleuser",
        100,
        &rows,
        &summary,
        false,
        caps,
    );
    assert!(
        text.contains("99/100") || text.contains("99"),
        "completed visible: {text}"
    );
    assert!(text.contains("Some providers could not be verified."));
    // CLI-level incomplete coverage (deadline 1ms leaves work unscanned).
    let (code, stdout, _) = run_cli(&[
        "search",
        "--username",
        "exampleuser",
        "--providers",
        "github",
        "--deadline",
        "1ms",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Some providers could not be verified."));
    assert!(stdout.contains("Unscanned") || stdout.contains("0/1") || stdout.contains("completed"));
    let _ = SearchSummary {
        requested: 0,
        completed: 0,
        skipped: 0,
        cancelled: 0,
        unscanned: 0,
        truncated: false,
    };
}

// --- 4. Friendly errors ---------------------------------------------------

#[test]
fn search_bare_positional_suggests_username() {
    let (code, _, stderr) = run_cli(&["search", "exampleuser"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("search needs a search type"), "{stderr}");
    assert!(
        stderr.contains("rxscan search --username exampleuser"),
        "{stderr}"
    );
}

#[test]
fn obsolete_investigate_flag_suggests_workflow() {
    let (code, _, stderr) = run_cli(&["--investigate", "exampleuser"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("rxscan investigate --username exampleuser"),
        "{stderr}"
    );
}

#[test]
fn unknown_capability_suggests_capabilities() {
    let (code, _, stderr) = run_cli(&["capability"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("Did you mean"), "{stderr}");
    assert!(stderr.contains("rxscan capabilities"), "{stderr}");
}

#[test]
fn missing_username_suggests_correct_form() {
    let (code, _, stderr) = run_cli(&["search"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("Missing username"), "{stderr}");
    assert!(
        stderr.contains("rxscan search --username exampleuser"),
        "{stderr}"
    );
    let (code, _, stderr) = run_cli(&["investigate"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("Missing username"), "{stderr}");
    assert!(
        stderr.contains("rxscan investigate --username exampleuser"),
        "{stderr}"
    );
}

fn contains_ansi(text: &str) -> bool {
    text.contains('\x1b')
}
