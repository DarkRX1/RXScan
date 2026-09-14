use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use clap::Parser;
use rxscan::{
    analysis::{self, AnalysisOptions},
    cli::Cli,
    diff,
    execution::{RetryPolicy, Task, TaskKind, TaskScopeTarget, TaskState},
    model::{
        Asset, AssetKind, BoundedDetails, Confidence, Event, EventKind, Evidence, Finding,
        Provenance, Relationship, RelationshipKind, RelationshipSubject, Severity, Timestamp,
    },
    persistence::{
        CHECKPOINT_SCHEMA_VERSION, PersistedModuleOutput, PersistedRegistries, PersistedScanState,
        PersistedTask, save_checkpoint,
    },
    plan::ScanPlan,
    report::{self, ReportFormat, ReportOptions},
};

static HOST_CONTACTS: AtomicUsize = AtomicUsize::new(0);
static TCP_CONTACTS: AtomicUsize = AtomicUsize::new(0);
static SERVICE_CONTACTS: AtomicUsize = AtomicUsize::new(0);
static DNS_CONTACTS: AtomicUsize = AtomicUsize::new(0);
static HTTP_CONTACTS: AtomicUsize = AtomicUsize::new(0);
static CRAWL_CONTACTS: AtomicUsize = AtomicUsize::new(0);
static CONTENT_CONTACTS: AtomicUsize = AtomicUsize::new(0);
static FUZZ_CONTACTS: AtomicUsize = AtomicUsize::new(0);
static SCHEDULER_ENTERED: AtomicUsize = AtomicUsize::new(0);

fn reset_counters() {
    for counter in [
        &HOST_CONTACTS,
        &TCP_CONTACTS,
        &SERVICE_CONTACTS,
        &DNS_CONTACTS,
        &HTTP_CONTACTS,
        &CRAWL_CONTACTS,
        &CONTENT_CONTACTS,
        &FUZZ_CONTACTS,
        &SCHEDULER_ENTERED,
    ] {
        counter.store(0, Ordering::SeqCst);
    }
}

fn assert_zero_counters() {
    assert_eq!(HOST_CONTACTS.load(Ordering::SeqCst), 0);
    assert_eq!(TCP_CONTACTS.load(Ordering::SeqCst), 0);
    assert_eq!(SERVICE_CONTACTS.load(Ordering::SeqCst), 0);
    assert_eq!(DNS_CONTACTS.load(Ordering::SeqCst), 0);
    assert_eq!(HTTP_CONTACTS.load(Ordering::SeqCst), 0);
    assert_eq!(CRAWL_CONTACTS.load(Ordering::SeqCst), 0);
    assert_eq!(CONTENT_CONTACTS.load(Ordering::SeqCst), 0);
    assert_eq!(FUZZ_CONTACTS.load(Ordering::SeqCst), 0);
    assert_eq!(SCHEDULER_ENTERED.load(Ordering::SeqCst), 0);
}

fn plan(speed: &str) -> ScanPlan {
    ScanPlan::compile(
        Cli::try_parse_from([
            "rxscan",
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--scope",
            "http://127.0.0.1",
            "--scope",
            "::1",
            "--level",
            "5",
            "--speed",
            speed,
        ])
        .unwrap(),
    )
    .unwrap()
}

fn provenance(plan: &ScanPlan) -> Provenance {
    Provenance::new("phase17.test", "17.0.0", plan.stable_id(), Timestamp(1)).unwrap()
}

fn task(plan: &ScanPlan, kind: TaskKind, state: TaskState, variant: &str) -> Task {
    let guard = rxscan::execution::PolicyScopeGuard::new(plan.scope.clone());
    let mut params = BTreeMap::new();
    params.insert("target".to_owned(), "127.0.0.1".to_owned());
    params.insert("variant".to_owned(), variant.to_owned());
    let mut task = Task::new_with_params(
        kind,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        10,
        Duration::from_secs(1),
        RetryPolicy::default(),
        "phase17.test",
        provenance(plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        params,
        &guard,
    )
    .unwrap();
    task.state = state;
    task
}

fn asset_ip(plan: &ScanPlan, value: &str) -> Asset {
    Asset::scoped(AssetKind::Ip, value, &plan.scope, provenance(plan)).unwrap()
}

fn asset_url(plan: &ScanPlan, value: &str) -> Asset {
    Asset::scoped(AssetKind::Url, value, &plan.scope, provenance(plan)).unwrap()
}

fn child(plan: &ScanPlan, kind: AssetKind, parent: &Asset, value: &str) -> Asset {
    Asset::child(kind, &parent.id, value, provenance(plan)).unwrap()
}

fn evidence(plan: &ScanPlan, asset: &Asset, marker: &str) -> Evidence {
    Evidence::new(
        "phase17.test",
        asset.id.clone(),
        BoundedDetails::from_value(serde_json::json!({"marker": marker}), 512).unwrap(),
        Confidence::new(80).unwrap(),
        provenance(plan),
    )
    .unwrap()
}

fn finding(plan: &ScanPlan, asset: &Asset, title: &str, confidence: u8) -> Finding {
    let mut finding = Finding::new(
        title,
        Severity::Info,
        Confidence::new(confidence).unwrap(),
        asset.id.clone(),
        provenance(plan),
    )
    .unwrap();
    finding
        .evidence_ids
        .push(evidence(plan, asset, "finding").id);
    finding
}

fn module_output(
    plan: &ScanPlan,
    assets: Vec<Asset>,
    relationships: Vec<Relationship>,
    evidence: Vec<Evidence>,
    findings: Vec<Finding>,
) -> rxscan::execution::ModuleOutput {
    rxscan::execution::ModuleOutput {
        events: vec![Event {
            schema_version: rxscan::model::SCHEMA_VERSION,
            kind: EventKind::EvidenceCollected,
            asset_id: assets.first().map(|asset| asset.id.clone()),
            details: BoundedDetails::from_value(serde_json::json!({"phase": 17}), 512).unwrap(),
            relationships,
            provenance: provenance(plan),
        }],
        evidence,
        findings,
        assets,
    }
}

fn state_with_speed(speed: &str, include_pending: bool) -> PersistedScanState {
    let p = plan(speed);
    let ip = asset_ip(&p, "127.0.0.1");
    let ip6 = asset_ip(&p, "::1");
    let port = child(&p, AssetKind::Port, &ip, "443").with_attributes(BTreeMap::from([
        ("port".to_owned(), "443".to_owned()),
        ("state".to_owned(), "open".to_owned()),
    ]));
    let svc = child(&p, AssetKind::Service, &port, "https");
    let url = asset_url(&p, "http://127.0.0.1/admin");
    let external =
        child(&p, AssetKind::Other, &url, "edge.external.test").with_attributes(BTreeMap::from([
            ("scope".to_owned(), "out_of_scope".to_owned()),
        ]));
    let dns_rel = Relationship::new(
        RelationshipKind::HostnameResolvesToIp,
        RelationshipSubject::Asset(url.id.clone()),
        RelationshipSubject::Asset(ip.id.clone()),
        provenance(&p),
    )
    .unwrap();
    let external_rel = Relationship::new(
        RelationshipKind::ReferencesEndpoint,
        RelationshipSubject::Asset(url.id.clone()),
        RelationshipSubject::Asset(external.id.clone()),
        provenance(&p),
    )
    .unwrap();
    let refl = Relationship::new(
        RelationshipKind::ReflectsInput,
        RelationshipSubject::Asset(url.id.clone()),
        RelationshipSubject::Asset(svc.id.clone()),
        provenance(&p),
    )
    .unwrap();
    let mut tasks = vec![task(&p, TaskKind::HttpProbe, TaskState::Succeeded, "done")];
    if include_pending {
        tasks.push(task(&p, TaskKind::Crawl, TaskState::TimedOut, "timeout"));
    }
    let task_id = tasks[0].id.clone();
    PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: p.stable_id(),
        saved_at: Timestamp(2),
        plan: p.clone(),
        tasks: tasks
            .into_iter()
            .map(|task| PersistedTask { task })
            .collect(),
        outputs: vec![PersistedModuleOutput {
            task_id,
            output: module_output(
                &p,
                vec![ip.clone(), ip6, port.clone(), svc, url.clone(), external],
                vec![dns_rel, external_rel, refl],
                vec![evidence(&p, &ip, "a"), evidence(&p, &port, "b")],
                vec![finding(&p, &port, "Report finding", 80)],
            ),
        }],
        registries: PersistedRegistries::default(),
    }
}

fn temp(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "rxscan_phase17_{name}_{}.rxscan",
        std::process::id()
    ));
    let _ = fs::remove_file(&path);
    path
}

fn save_state(name: &str, state: &PersistedScanState) -> PathBuf {
    let path = temp(name);
    save_checkpoint(&path, state).unwrap();
    path
}

fn report_model(
    state: &PersistedScanState,
    diff_report: Option<diff::DiffReport>,
    analysis_report: Option<analysis::AnalysisReport>,
    format: ReportFormat,
) -> report::ReportModel {
    report::build_report_model(
        state,
        diff_report,
        analysis_report,
        &ReportOptions {
            format,
            summary_only: false,
            top_n: 10,
        },
    )
    .unwrap()
}

#[test]
fn scan_only_report_has_useful_summary_and_zero_network() {
    reset_counters();
    let state = state_with_speed("50", true);
    let model = report_model(&state, None, None, ReportFormat::Human);
    assert_eq!(model.report_schema_version, report::REPORT_SCHEMA_VERSION);
    assert_eq!(model.summary.assets, 6);
    assert_eq!(model.summary.open_ports, 1);
    assert_eq!(model.summary.services, 1);
    assert_eq!(model.summary.endpoints, 1);
    assert_eq!(model.summary.findings, 1);
    assert_eq!(model.summary.failed_incomplete_tasks, 1);
    assert_eq!(model.summary.network_requests, 0);
    let human = report::render_human(&model, &ReportOptions::default());
    assert!(human.contains("RXScan Summary"));
    assert!(human.contains("Incomplete / Inconclusive Work"));
    assert!(!human.contains("High Severity"));
    assert_zero_counters();
}

#[test]
fn full_stack_report_preserves_diff_certainty_and_attention_language() {
    let old = state_with_speed("50", false);
    let current = state_with_speed("50", true);
    let mut diff_report =
        diff::compare_states(&old, &current, diff::DiffOptions::default()).unwrap();
    diff_report.records.push(diff::DiffRecord {
        change_type: diff::ChangeType::InconclusiveMissing,
        entity_type: diff::EntityType::Asset,
        semantic_id: "asset:url:http://127.0.0.1/internal".to_owned(),
        certainty: diff::Certainty::Inconclusive,
        reason: diff::ReasonCode::CoverageReduced,
        before: None,
        after: None,
    });
    let analysis_report =
        analysis::analyze_state(&current, Some(&diff_report), AnalysisOptions::default()).unwrap();
    let model = report_model(
        &current,
        Some(diff_report),
        Some(analysis_report),
        ReportFormat::Json,
    );
    let human = report::render_human(&model, &ReportOptions::default());
    assert!(human.contains("InconclusiveMissing"));
    assert!(!human.contains("Endpoint removed"));
    assert!(human.contains("Attention"));
    assert!(!human.contains("Critical"));
    assert!(!human.contains("VULNERABILITY"));
    assert_eq!(
        model.summary.high_attention,
        model.analysis.as_ref().unwrap().summary.high_attention
    );
}

#[test]
fn json_jsonl_raw_are_valid_consistent_and_preserve_confidence_separately() {
    let state = state_with_speed("50", false);
    let analysis_report =
        analysis::analyze_state(&state, None, AnalysisOptions::default()).unwrap();
    let json_model = report_model(&state, None, Some(analysis_report), ReportFormat::Json);
    let json = report::render_json(&json_model).unwrap();
    let parsed: report::ReportModel = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.summary, json_model.summary);
    assert_eq!(parsed.findings[0].confidence, 80);
    assert_ne!(
        parsed.findings[0].confidence,
        parsed.analysis.as_ref().unwrap().top_signals[0].attention_score
    );

    let mut jsonl = Vec::new();
    report::render_jsonl(&json_model, &mut jsonl).unwrap();
    let text = String::from_utf8(jsonl).unwrap();
    let mut lines = text.lines();
    let meta: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    assert_eq!(meta["record_type"], "report_meta");
    for line in lines {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(value["record_type"].is_string());
    }

    let raw_model = report_model(&state, None, parsed.analysis.clone(), ReportFormat::Raw);
    let raw = report::render_raw(&raw_model).unwrap();
    assert!(raw.contains("\"raw_schema_version\""));
    for forbidden in [
        "raw_http_body_marker",
        "raw_dns_packet_marker",
        "Authorization:",
        "Cookie:",
    ] {
        assert!(!raw.contains(forbidden));
    }
}

#[test]
fn deterministic_outputs_ignore_order_path_timestamp_and_speed() {
    let a = state_with_speed("10", false);
    let mut b = state_with_speed("100", false);
    b.saved_at = Timestamp(999);
    b.outputs[0].output.assets.reverse();
    b.outputs[0].output.evidence.reverse();
    b.outputs[0].output.findings.reverse();
    let path_a = save_state("det_a", &a);
    let path_b = save_state("det_b", &a);
    let loaded_a =
        report::report_checkpoint(&path_a, None, true, ReportOptions::default()).unwrap();
    let loaded_b =
        report::report_checkpoint(&path_b, None, true, ReportOptions::default()).unwrap();
    assert_eq!(
        report::render_json(&loaded_a).unwrap(),
        report::render_json(&loaded_b).unwrap()
    );
    let model_a = report_model(&a, None, None, ReportFormat::Json);
    let model_b = report_model(&b, None, None, ReportFormat::Json);
    assert_eq!(model_a.assets, model_b.assets);
    assert_eq!(model_a.relationships, model_b.relationships);
    let model_c = report_model(&a, None, None, ReportFormat::Json);
    assert_eq!(
        report::render_human(&model_a, &ReportOptions::default()),
        report::render_human(&model_c, &ReportOptions::default())
    );
    assert_eq!(model_a.summary.assets, model_b.summary.assets);
    assert_eq!(model_a.assets, model_b.assets);
}

#[test]
fn terminal_sanitization_and_machine_encoding_are_separate() {
    let p = plan("50");
    let ip = asset_ip(&p, "127.0.0.1");
    let mut bad = child(&p, AssetKind::Service, &ip, "\u{1b}]0;bad\nservice");
    bad.identity = "svc\u{1b}[31m\nname\tend".to_owned();
    let state = PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: p.stable_id(),
        saved_at: Timestamp(2),
        plan: p.clone(),
        tasks: vec![PersistedTask {
            task: task(&p, TaskKind::ServiceProbe, TaskState::Succeeded, "bad"),
        }],
        outputs: vec![PersistedModuleOutput {
            task_id: task(&p, TaskKind::ServiceProbe, TaskState::Succeeded, "bad").id,
            output: module_output(&p, vec![ip, bad], vec![], vec![], vec![]),
        }],
        registries: PersistedRegistries::default(),
    };
    let model = report_model(&state, None, None, ReportFormat::Json);
    let human = report::render_human(&model, &ReportOptions::default());
    assert!(!human.contains('\u{1b}'));
    assert!(!human.contains('\n') || human.lines().all(|line| !line.contains("]0;bad")));
    let json = report::render_json(&model).unwrap();
    assert!(json.contains("\\u001b"));
}

#[test]
fn top_n_summary_only_large_jsonl_and_output_caps_are_bounded() {
    let p = plan("50");
    let ip = asset_ip(&p, "127.0.0.1");
    let mut assets = vec![ip.clone()];
    for i in 0..150 {
        assets.push(
            child(&p, AssetKind::Port, &ip, &format!("{}", 1000 + i)).with_attributes(
                BTreeMap::from([
                    ("port".to_owned(), format!("{}", 1000 + i)),
                    ("state".to_owned(), "open".to_owned()),
                ]),
            ),
        );
    }
    let state = PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: p.stable_id(),
        saved_at: Timestamp(2),
        plan: p.clone(),
        tasks: vec![PersistedTask {
            task: task(&p, TaskKind::PortDiscovery, TaskState::Succeeded, "large"),
        }],
        outputs: vec![PersistedModuleOutput {
            task_id: task(&p, TaskKind::PortDiscovery, TaskState::Succeeded, "large").id,
            output: module_output(&p, assets, vec![], vec![], vec![]),
        }],
        registries: PersistedRegistries::default(),
    };
    let analysis_report =
        analysis::analyze_state(&state, None, AnalysisOptions::default()).unwrap();
    assert!(analysis_report.total_signals > 100);
    let model = report_model(&state, None, Some(analysis_report), ReportFormat::Jsonl);
    let options = ReportOptions {
        format: ReportFormat::Human,
        summary_only: false,
        top_n: 3,
    };
    let human = report::render_human(&model, &options);
    assert_eq!(
        human.matches("- LowAttention").count()
            + human.matches("- MediumAttention").count()
            + human.matches("- HighAttention").count(),
        3
    );
    assert!(human.contains("signals_total="));
    let summary = report::render_human(
        &model,
        &ReportOptions {
            summary_only: true,
            ..options.clone()
        },
    );
    assert!(!summary.contains("Surface Overview\n-"));
    let mut jsonl = Vec::new();
    report::render_jsonl(&model, &mut jsonl).unwrap();
    assert!(String::from_utf8(jsonl).unwrap().lines().count() > 150);
}

#[test]
fn output_file_collision_rejected_and_inputs_unchanged() {
    let state = state_with_speed("50", false);
    let path = save_state("collision", &state);
    let before = fs::read(&path).unwrap();
    let model = report_model(&state, None, None, ReportFormat::Json);
    let bytes = report::render_to_bytes(
        &model,
        &ReportOptions {
            format: ReportFormat::Json,
            ..ReportOptions::default()
        },
    )
    .unwrap();
    assert!(report::write_output(&path, &bytes, &[&path]).is_err());
    assert_eq!(before, fs::read(&path).unwrap());
    let out = temp("report_out");
    fs::write(&out, b"old valid report").unwrap();
    let bad = out.join("child");
    assert!(report::write_output(&bad, &bytes, &[&path]).is_err());
    assert_eq!(fs::read(&out).unwrap(), b"old valid report");
}

#[test]
fn invalid_checkpoint_and_pairing_fail_without_network_or_output() {
    reset_counters();
    let invalid = temp("invalid");
    fs::write(&invalid, b"{not json").unwrap();
    assert!(report::report_checkpoint(&invalid, None, false, ReportOptions::default()).is_err());
    assert_zero_counters();

    let old = state_with_speed("50", false);
    let current = state_with_speed("50", false);
    let mut other = state_with_speed("50", false);
    other.plan = plan("10");
    other.scan_id = other.plan.stable_id();
    let diff_report = diff::compare_states(&old, &current, diff::DiffOptions::default()).unwrap();
    assert!(
        report::build_report_model(&other, Some(diff_report), None, &ReportOptions::default())
            .is_err()
    );
    assert_zero_counters();
}

#[test]
fn cli_report_paths_are_clean_and_use_production_api() {
    let state = state_with_speed("50", false);
    let path = save_state("cli", &state);
    let exe = env!("CARGO_BIN_EXE_rxscan");

    let help = Command::new(exe)
        .args(["report", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());

    let json = Command::new(exe)
        .args(["report", "--format", "json", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        json.status.success(),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    assert!(json.stderr.is_empty());
    let parsed: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(
        parsed["report_schema_version"],
        report::REPORT_SCHEMA_VERSION
    );

    let jsonl = Command::new(exe)
        .args(["report", "--format", "jsonl", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(jsonl.status.success());
    for line in String::from_utf8(jsonl.stdout).unwrap().lines() {
        let _: serde_json::Value = serde_json::from_str(line).unwrap();
    }

    let raw = Command::new(exe)
        .args(["report", "--format", "raw", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(raw.status.success());
    assert!(
        String::from_utf8(raw.stdout)
            .unwrap()
            .contains("raw_schema_version")
    );

    let bad = Command::new(exe)
        .args(["report", "--format", "xml", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!bad.status.success());
}

#[test]
fn format_counts_match_across_human_json_jsonl_and_raw_with_multitarget_ipv6() {
    let state = state_with_speed("50", false);
    let analysis_report =
        analysis::analyze_state(&state, None, AnalysisOptions::default()).unwrap();
    let model = report_model(&state, None, Some(analysis_report), ReportFormat::Raw);
    let human = report::render_human(&model, &ReportOptions::default());
    assert!(human.contains("::1"));
    assert!(human.contains("external / out of scope"));
    let json: report::ReportModel =
        serde_json::from_str(&report::render_json(&model).unwrap()).unwrap();
    assert_eq!(json.summary, model.summary);
    let mut jsonl = Vec::new();
    report::render_jsonl(&model, &mut jsonl).unwrap();
    let summary_line = String::from_utf8(jsonl)
        .unwrap()
        .lines()
        .find(|line| line.contains("\"record_type\":\"summary\""))
        .unwrap()
        .to_owned();
    let summary_record: serde_json::Value = serde_json::from_str(&summary_line).unwrap();
    assert_eq!(
        summary_record["payload"]["assets"].as_u64().unwrap() as usize,
        model.summary.assets
    );
    assert_eq!(model.summary.hosts_ips, 2);
}
