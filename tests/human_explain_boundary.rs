//! Default vs `--explain` information hierarchy.
//!
//! Default human output is findings-first and concise; engineering detail
//! lives in `--explain`. Uses only synthetic/reserved examples.
//!
//! Covers RECON, SEARCH, INVESTIGATION, and CAPABILITIES human names.

use clap::Parser;
use rxscan::{capabilities, cli::Cli, plan::ScanPlan};

fn recon_report(
    target: &str,
    termination: rxscan::execution::TerminationReason,
    tcp: rxscan::tcp_discovery::TcpScanTotals,
    duration_ms: u64,
    failed_tasks: usize,
    not_admitted: u64,
    deadline_ms: u64,
) -> rxscan::run::RunReport {
    let cli = Cli::try_parse_from(["rxscan", target, "--level", "3"]).unwrap();
    let plan = ScanPlan::compile(cli).unwrap();
    let mut retries_by_module = std::collections::BTreeMap::new();
    retries_by_module.insert("rxscan.port".to_owned(), 2);
    let mut failed = Vec::new();
    for index in 0..failed_tasks {
        failed.push(rxscan::execution::TaskId(format!("failed_{index}")));
    }
    let scheduler = rxscan::execution::SchedulerReport {
        termination,
        tasks_admitted: 3,
        tasks_not_admitted: not_admitted,
        completed: vec![
            rxscan::execution::TaskId("task_1".to_owned()),
            rxscan::execution::TaskId("task_2".to_owned()),
        ],
        failed,
        retries_consumed: 2,
        retries_by_module,
        evidence_bytes: 1024,
        deadline_ms,
        wall_ms: duration_ms,
        deadline_overrun_ms: 0,
        cleanup_ms: 5,
        ..Default::default()
    };
    rxscan::run::RunReport {
        plan,
        task_count: 3,
        scheduler_report: scheduler,
        jsonl_bytes: 4096,
        output_path: None,
        open_ports_summary: String::new(),
        tcp_totals: tcp,
        services_identified: 0,
        udp_summary: String::new(),
        udp_totals: rxscan::udp_discovery::UdpScanTotals::default(),
        duration_ms,
        graph_entities: 4,
        graph_edges: 2,
        graph_truncated: false,
        certificates_observed: 1,
        certificate_reuse_groups: 0,
        fingerprint_packs_loaded: 2,
        fingerprint_rules: 10,
        fingerprint_files_rejected: 0,
        scan_id: "scan_test".to_owned(),
        project_import: None,
        project_changes: Vec::new(),
        attention: Vec::new(),
    }
}

fn normal_totals() -> rxscan::tcp_discovery::TcpScanTotals {
    rxscan::tcp_discovery::TcpScanTotals {
        completed_tasks: 1,
        ports_requested: 3,
        ports_attempted: 3,
        open: 0,
        closed: 0,
        filtered_or_timed_out: 3,
        error: 0,
        unscanned: 0,
        truncated: false,
        port_sources: vec!["explicit".to_owned()],
        elapsed_ms_max: 12,
        fd_peak_max: 8,
    }
}

fn deadline_totals() -> rxscan::tcp_discovery::TcpScanTotals {
    rxscan::tcp_discovery::TcpScanTotals {
        completed_tasks: 1,
        ports_requested: 65_535,
        ports_attempted: 64,
        open: 0,
        closed: 0,
        filtered_or_timed_out: 63,
        error: 1,
        unscanned: 65_471,
        truncated: true,
        port_sources: vec!["all".to_owned()],
        elapsed_ms_max: 2_000,
        fd_peak_max: 8,
    }
}

#[test]
fn normal_default_recon_has_no_legacy_diagnostic_lines() {
    let report = recon_report(
        "192.0.2.10",
        rxscan::execution::TerminationReason::Completed,
        normal_totals(),
        5_093,
        0,
        0,
        60_000,
    );
    let human = rxscan::run::human_summary(&report);
    // Findings-first structure stays.
    assert!(human.contains("RXSCAN"));
    assert!(human.contains("TARGET"));
    assert!(human.contains("192.0.2.10"));
    assert!(human.contains("PORTS"));
    assert!(human.contains("No open TCP ports observed."));
    assert!(human.contains("SCAN SUMMARY"));
    assert!(human.contains("0 services"));
    // Intended human duration field stays (exactly once in the body).
    assert!(human.contains("Duration"));
    assert_eq!(
        human.matches("Duration").count(),
        1,
        "duration renders once in default body: {human}"
    );
    // Legacy verbose telemetry must not print in default.
    for legacy in [
        "tasks admitted:",
        "retry budget",
        "evidence bytes:",
        "fingerprints:",
        "jsonl bytes:",
        "TCP discovery",
        "Services:",
        "Duration:",
        "DIAGNOSTICS",
        "Diagnostics",
        "Run with --explain",
        "Service probing uses",
    ] {
        assert!(
            !human.contains(legacy),
            "default must not contain {legacy:?}: {human}"
        );
    }
    // Footer recap repeats duration as compact summary context (allowed).
    assert!(human.contains("5.09s"));
}

#[test]
fn explain_retains_operational_detail() {
    let report = recon_report(
        "192.0.2.10",
        rxscan::execution::TerminationReason::Completed,
        normal_totals(),
        5_093,
        0,
        0,
        60_000,
    );
    let explained = rxscan::run::human_summary_explain(&report);
    for expected in [
        "tasks admitted:",
        "retry budget",
        "evidence bytes:",
        "fingerprints:",
        "jsonl bytes:",
        "TCP discovery",
        "Services:",
        "Duration:",
    ] {
        assert!(
            explained.contains(expected),
            "explain must expose {expected:?}: {explained}"
        );
    }
    // Explain still carries the findings so detail never replaces truth.
    assert!(explained.contains("SCAN SUMMARY"));
    assert!(explained.contains("No open TCP ports observed."));
}

#[test]
fn deadline_truncation_stays_visible_in_default() {
    let report = recon_report(
        "192.0.2.10",
        rxscan::execution::TerminationReason::GlobalDeadline,
        deadline_totals(),
        2_090,
        0,
        0,
        2_000,
    );
    let human = rxscan::run::human_summary(&report);
    // Material incompleteness is never hidden (plain language).
    assert!(human.contains("65,471"), "unscanned stays visible: {human}");
    assert!(human.contains("64"), "attempted stays visible: {human}");
    assert!(
        human.to_lowercase().contains("time limit"),
        "time-limit warning stays visible: {human}"
    );
    assert!(
        human.contains("Partial results are shown below."),
        "preservation note stays visible: {human}"
    );
    // But legacy telemetry still stays out of default.
    for legacy in [
        "tasks admitted:",
        "retry budget",
        "evidence bytes:",
        "TCP discovery",
        "Duration:",
    ] {
        assert!(
            !human.contains(legacy),
            "default must not contain {legacy:?}: {human}"
        );
    }
    let explained = rxscan::run::human_summary_explain(&report);
    assert!(explained.to_lowercase().contains("deadline"));
    assert!(explained.contains("tasks admitted:"));
}

#[test]
fn cancellation_and_failures_stay_visible_in_default() {
    let cancelled = recon_report(
        "198.51.100.20",
        rxscan::execution::TerminationReason::UserCancelled,
        normal_totals(),
        1_200,
        0,
        0,
        60_000,
    );
    let human = rxscan::run::human_summary(&cancelled);
    assert!(
        human.to_lowercase().contains("cancel"),
        "cancellation stays visible: {human}"
    );

    let failed = recon_report(
        "203.0.113.10",
        rxscan::execution::TerminationReason::Completed,
        normal_totals(),
        900,
        3,
        0,
        60_000,
    );
    let failed_human = rxscan::run::human_summary(&failed);
    assert!(
        failed_human.contains("3 scan task"),
        "task failures stay visible: {failed_human}"
    );

    let budget = recon_report(
        "2001:db8::10",
        rxscan::execution::TerminationReason::TaskBudget,
        deadline_totals(),
        2_000,
        0,
        5,
        60_000,
    );
    let budget_human = rxscan::run::human_summary(&budget);
    assert!(
        budget_human.contains("were not scanned"),
        "budget truncation stays visible: {budget_human}"
    );
}

#[test]
fn search_default_omits_raw_accounting_while_explain_keeps_it() {
    use rxscan::terminal::{RowTier, SearchRow, SearchSummary};
    let rows = vec![
        SearchRow {
            status: "confirmed",
            provider: "example-provider".to_owned(),
            confidence: 90,
            detail: "profile".to_owned(),
            tier: RowTier::Positive,
        },
        SearchRow {
            status: "possible",
            provider: "other-provider".to_owned(),
            confidence: 30,
            detail: "weak evidence".to_owned(),
            tier: RowTier::Positive,
        },
    ];
    let summary = SearchSummary {
        requested: 2,
        completed: 2,
        skipped: 0,
        cancelled: 0,
        unscanned: 0,
        truncated: false,
    };
    let caps = rxscan::terminal::TerminalCapabilities::plain();
    let default =
        rxscan::terminal::render_search_report_caps("exampleuser", 2, &rows, &summary, false, caps);
    assert!(default.contains("2 confirmed") || default.contains("1 confirmed"));
    assert!(default.contains("completed"));
    assert!(
        !default.contains("2 requested"),
        "default must not duplicate raw accounting: {default}"
    );
    assert!(
        !default.contains("0 network scans"),
        "raw line lives in --explain: {default}"
    );
    let explained = rxscan::terminal::render_search_report_explain_caps(
        "exampleuser",
        2,
        &rows,
        &summary,
        false,
        caps,
    );
    assert!(explained.contains("2 requested"));
    assert!(explained.contains("0 network scans"));

    // Incomplete coverage stays visible in default.
    let incomplete = SearchSummary {
        requested: 4,
        completed: 2,
        skipped: 0,
        cancelled: 0,
        unscanned: 2,
        truncated: false,
    };
    let partial = rxscan::terminal::render_search_report_caps(
        "exampleuser",
        4,
        &rows,
        &incomplete,
        false,
        caps,
    );
    assert!(
        partial.contains("Incomplete coverage") || partial.contains("Unscanned"),
        "incomplete coverage stays visible: {partial}"
    );
}

#[test]
fn capabilities_use_human_labels_and_groups() {
    let report = capabilities::probe();
    let human = capabilities::render_human(&report);
    for label in [
        "Project persistence",
        "Search project database",
        "Username search",
        "Raw SYN",
    ] {
        assert!(
            human.contains(label),
            "missing human label {label}: {human}"
        );
    }
    for id in [
        "investigation_project_persistence",
        "search_project_db",
        "search_username",
        "raw_syn_ipv6",
    ] {
        assert!(
            !human.contains(id),
            "human output must not show raw id {id}: {human}"
        );
    }
    for group in [
        "NETWORK",
        "SEARCH",
        "INVESTIGATION",
        "INTELLIGENCE",
        "PROJECT",
    ] {
        assert!(human.contains(group), "missing group {group}: {human}");
    }
    // Machine output keeps stable IDs.
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("investigation_project_persistence"));
    assert!(json.contains("raw_syn_ipv6"));
}
