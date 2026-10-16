//! Phase 2 standalone HTML reports: templates, offline, masking.
//!
//! Synthetic/reserved values only. Fake secrets use `FAKE-HTML-*`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use clap::Parser;
use rxscan::cli::Cli;
use rxscan::execution::{
    ModuleOutput, PolicyScopeGuard, RetryPolicy, Task, TaskKind, TaskScopeTarget, TaskState,
};
use rxscan::model::{
    Asset, AssetKind, BoundedDetails, Confidence, Event, EventKind, Evidence, Finding,
    MAX_EVENT_DETAILS_BYTES, Provenance, Relationship, RelationshipKind, RelationshipSubject,
    Severity, Timestamp,
};
use rxscan::persistence::{
    CHECKPOINT_SCHEMA_VERSION, PersistedModuleOutput, PersistedRegistries, PersistedScanState,
    PersistedTask,
};
use rxscan::plan::ScanPlan;

const PW: &str = "FAKE-HTML-PW-3";
const TOKEN: &str = "FAKE-HTML-TOK-3";

fn plan() -> ScanPlan {
    ScanPlan::compile(
        Cli::try_parse_from([
            "rxscan",
            "192.0.2.10",
            "--scope",
            "192.0.2.0/24",
            "--level",
            "3",
        ])
        .unwrap(),
    )
    .unwrap()
}

fn provenance(plan: &ScanPlan) -> Provenance {
    Provenance::new(
        "phase2.test",
        "2.0.0",
        plan.stable_id(),
        Timestamp(1_700_000_000),
    )
    .unwrap()
}

fn task(plan: &ScanPlan, kind: TaskKind, state: TaskState) -> Task {
    let guard = PolicyScopeGuard::new(plan.scope.clone());
    let mut params = BTreeMap::new();
    params.insert("target".to_owned(), "192.0.2.10".to_owned());
    let mut task = Task::new_with_params(
        kind,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        10,
        Duration::from_secs(1),
        RetryPolicy::default(),
        "phase2.test",
        provenance(plan),
        TaskScopeTarget::Ip("192.0.2.10".parse().unwrap()),
        params,
        &guard,
    )
    .unwrap();
    task.state = state;
    task
}

fn event(plan: &ScanPlan, kind: EventKind, data: serde_json::Value) -> Event {
    Event::new(
        kind,
        None,
        BoundedDetails::from_value(data, MAX_EVENT_DETAILS_BYTES).unwrap(),
        provenance(plan),
    )
    .unwrap()
}

fn state() -> PersistedScanState {
    let p = plan();
    let ip = Asset::scoped(AssetKind::Ip, "192.0.2.10", &p.scope, provenance(&p)).unwrap();
    let port = Asset::child(AssetKind::Port, &ip.id, "443", provenance(&p))
        .unwrap()
        .with_attributes(BTreeMap::from([
            ("port".to_owned(), "443".to_owned()),
            ("state".to_owned(), "open".to_owned()),
        ]));
    let secret_evidence = Evidence::new(
        "phase2.test",
        port.id.clone(),
        BoundedDetails::from_value(
            serde_json::json!({"note": format!("login token={TOKEN}"), "password": PW}),
            512,
        )
        .unwrap(),
        Confidence::new(85).unwrap(),
        provenance(&p),
    )
    .unwrap();
    let mut finding = Finding::new(
        format!("Exposed console token={TOKEN}"),
        Severity::High,
        Confidence::new(80).unwrap(),
        port.id.clone(),
        provenance(&p),
    )
    .unwrap();
    finding.evidence_ids.push(secret_evidence.id.clone());
    let scan_events = vec![
        event(
            &p,
            EventKind::PortOpen,
            serde_json::json!({"target": "192.0.2.10", "address": "192.0.2.10", "transport": "tcp", "port": 443}),
        ),
        event(
            &p,
            EventKind::ServiceIdentified,
            serde_json::json!({"target": "192.0.2.10", "address": "192.0.2.10", "port": 443, "protocol": "https", "service": "https", "product_hint": "nginx", "confidence": 90u64, "matcher": "https"}),
        ),
        event(
            &p,
            EventKind::DnsRecordObserved,
            serde_json::json!({"name": "example.test", "record_type": "A", "value": "192.0.2.10"}),
        ),
        event(
            &p,
            EventKind::EndpointObserved,
            serde_json::json!({"url": format!("https://admin:{PW}@example.test/")}),
        ),
    ];
    let tasks = vec![
        task(&p, TaskKind::PortDiscovery, TaskState::Succeeded),
        task(&p, TaskKind::Crawl, TaskState::TimedOut),
    ];
    let task_id = tasks[0].id.clone();
    PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: p.stable_id(),
        saved_at: Timestamp(1_700_000_100),
        plan: p,
        tasks: tasks
            .into_iter()
            .map(|task| PersistedTask { task })
            .collect(),
        outputs: vec![PersistedModuleOutput {
            task_id,
            output: ModuleOutput {
                events: scan_events
                    .into_iter()
                    .map(|event| {
                        let mut event = event;
                        event.relationships = vec![];
                        event
                    })
                    .collect(),
                evidence: vec![secret_evidence],
                findings: vec![finding],
                assets: vec![ip, port],
            },
        }],
        registries: PersistedRegistries::default(),
    }
}

fn rel_event(plan: &ScanPlan, rel: Relationship) -> Event {
    let mut event = event(
        plan,
        EventKind::EndpointObserved,
        serde_json::json!({"url": "https://example.test/"}),
    );
    event.relationships = vec![rel];
    event
}

fn state_with_graph_rel() -> PersistedScanState {
    let mut state = state();
    let p = state.plan.clone();
    let assets: Vec<Asset> = state
        .outputs
        .iter()
        .flat_map(|o| o.output.assets.clone())
        .collect();
    let (ip, port) = (assets[0].clone(), assets[1].clone());
    let rel = Relationship::new(
        RelationshipKind::HostnameResolvesToIp,
        RelationshipSubject::Asset(port.id.clone()),
        RelationshipSubject::Asset(ip.id.clone()),
        provenance(&p),
    )
    .unwrap();
    state.outputs[0].output.events.push(rel_event(&p, rel));
    state
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rxscan-html2-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn render(state: &PersistedScanState, template: &str, graph: bool) -> String {
    let model = rxscan::report::build_report_model(
        state,
        None,
        None,
        &rxscan::report::ReportOptions::default(),
    )
    .unwrap();
    rxscan::report_html::render_html(
        state,
        &model,
        &rxscan::report_html::HtmlReportOptions {
            template: rxscan::report_html::ReportTemplate::parse(template).unwrap(),
            include_graph: graph,
            ..rxscan::report_html::HtmlReportOptions::default()
        },
    )
}

fn assert_offline(html: &str) {
    assert!(html.contains("<html") && html.contains("</html>"));
    assert!(!html.contains("<script src") && !html.contains("<link"));
    for pat in ["src=\"http", "href=\"http", "@import", "url(http"] {
        assert!(!html.contains(pat), "report must be offline ({pat})");
    }
}

#[test]
fn both_templates_render_required_sections() {
    let state = state_with_graph_rel();
    for template in ["executive", "technical"] {
        let html = render(&state, template, true);
        assert_offline(&html);
        for section in [
            "Executive summary",
            "Scope and coverage",
            "Evidence graph",
            "Findings",
            "Methodology and limitations",
        ] {
            assert!(html.contains(section), "{template} missing {section}");
        }
        // Scope + time window honesty.
        assert!(html.contains("192.0.2.10"));
        assert!(html.contains("checkpoint saved"));
        // Secrets never appear.
        for secret in [PW, TOKEN] {
            assert!(!html.contains(secret), "{template} leaked a secret");
        }
    }
    let exec = render(&state, "executive", true);
    let tech = render(&state, "technical", true);
    assert!(
        exec.len() < tech.len(),
        "executive must be the short template"
    );
    // Technical carries full evidence; finding + chain present in both.
    assert!(tech.contains("Evidence chains"));
    assert!(tech.contains("phase2.test"));
    // Embedded interactive graph (Phase 1 viewer, inlined).
    assert!(tech.contains("srcdoc="));
    assert!(tech.contains("Evidence graph"));
}

#[test]
fn report_is_deterministic_and_bounded() {
    let state = state_with_graph_rel();
    let first = render(&state, "technical", true);
    let second = render(&state, "technical", true);
    assert_eq!(
        first, second,
        "same state must render byte-identical reports"
    );
    let no_graph = render(&state, "technical", false);
    assert!(!no_graph.contains("srcdoc="));
    assert!(no_graph.contains("Findings"));
}

#[test]
fn golden_checkpoint_renders() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/golden_checkpoint_v1.rxscan");
    if !path.exists() {
        eprintln!("golden checkpoint missing: skipping");
        return;
    }
    let loaded = rxscan::persistence::load_checkpoint(&path).expect("golden loads");
    let model = rxscan::report::build_report_model(
        &loaded.state,
        None,
        None,
        &rxscan::report::ReportOptions::default(),
    )
    .unwrap();
    let html = rxscan::report_html::render_html(
        &loaded.state,
        &model,
        &rxscan::report_html::HtmlReportOptions::default(),
    );
    assert_offline(&html);
    assert!(html.contains("Executive summary"));
    assert!(html.contains("Methodology and limitations"));
}

#[test]
fn cli_html_report_end_to_end() {
    let dir = temp("cli");
    let state = state_with_graph_rel();
    let checkpoint = dir.join("scan.rxscan");
    rxscan::persistence::save_checkpoint(&checkpoint, &state).expect("save checkpoint");
    let out = dir.join("report.html");
    for template in ["executive", "technical"] {
        let result = Command::new(env!("CARGO_BIN_EXE_rxscan"))
            .arg("report")
            .arg("--format")
            .arg("html")
            .arg("--template")
            .arg(template)
            .arg("--output")
            .arg(&out)
            .arg(&checkpoint)
            .output()
            .expect("rxscan report runs");
        assert!(
            result.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let html = std::fs::read_to_string(&out).unwrap();
        assert_offline(&html);
        for secret in [PW, TOKEN] {
            assert!(
                !html.contains(secret),
                "CLI {template} report leaked a secret"
            );
        }
    }
    // Bad template is a usage error.
    let result = Command::new(env!("CARGO_BIN_EXE_rxscan"))
        .arg("report")
        .arg("--format")
        .arg("html")
        .arg("--template")
        .arg("pdf")
        .arg(&checkpoint)
        .output()
        .expect("runs");
    assert_eq!(result.status.code(), Some(2));
}
