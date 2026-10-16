//! Phase 7 explain mode: finding/node chains, masking, CLI/GUI parity.
//!
//! Synthetic/reserved values only. Secrets use `FAKE-EXPLAIN-*`.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

use clap::Parser;
use rxscan::cli::Cli;
use rxscan::execution::{
    ModuleOutput, PolicyScopeGuard, RetryPolicy, Task, TaskKind, TaskScopeTarget, TaskState,
};
use rxscan::graph::build_graph;
use rxscan::model::{
    Asset, AssetKind, BoundedDetails, Confidence, Event, EventKind, Evidence, Finding,
    MAX_EVENT_DETAILS_BYTES, Provenance, Severity, Timestamp,
};
use rxscan::persistence::{
    CHECKPOINT_SCHEMA_VERSION, PersistedModuleOutput, PersistedRegistries, PersistedScanState,
    PersistedTask, save_checkpoint,
};
use rxscan::plan::ScanPlan;
use rxscan::project_db::{
    ClassifierProvenance, CoverageSnapshot, ProjectDb, RetentionMode, ScanImport, TOOL_VERSION,
};

const SECRET: &str = "FAKE-EXPLAIN-9";

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
        "phase7.test",
        "7.0.0",
        plan.stable_id(),
        Timestamp(1_700_000_000),
    )
    .unwrap()
}

fn checkpoint_path(dir: &std::path::Path) -> std::path::PathBuf {
    let p = plan();
    let ip = Asset::scoped(AssetKind::Ip, "192.0.2.10", &p.scope, provenance(&p)).unwrap();
    let evidence = Evidence::new(
        "phase7.test",
        ip.id.clone(),
        BoundedDetails::from_value(
            serde_json::json!({"note": format!("session cookie={SECRET}"), "port": 80}),
            512,
        )
        .unwrap(),
        Confidence::new(85).unwrap(),
        provenance(&p),
    )
    .unwrap();
    let mut finding = Finding::new(
        format!("Open console token={SECRET}"),
        Severity::High,
        Confidence::new(80).unwrap(),
        ip.id.clone(),
        provenance(&p),
    )
    .unwrap();
    finding.evidence_ids.push(evidence.id.clone());
    let guard = PolicyScopeGuard::new(p.scope.clone());
    let mut task = Task::new_with_params(
        TaskKind::PortDiscovery,
        None,
        Vec::new(),
        None,
        p.stable_id(),
        10,
        Duration::from_secs(1),
        RetryPolicy::default(),
        "phase7.test",
        provenance(&p),
        TaskScopeTarget::Ip("192.0.2.10".parse().unwrap()),
        BTreeMap::from([("target".to_owned(), "192.0.2.10".to_owned())]),
        &guard,
    )
    .unwrap();
    task.state = TaskState::Succeeded;
    let task_id = task.id.clone();
    let state = PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: p.stable_id(),
        saved_at: Timestamp(1_700_000_100),
        plan: p,
        tasks: vec![PersistedTask { task }],
        outputs: vec![PersistedModuleOutput {
            task_id,
            output: ModuleOutput {
                events: vec![],
                evidence: vec![evidence],
                findings: vec![finding],
                assets: vec![ip],
            },
        }],
        registries: PersistedRegistries::default(),
    };
    let path = dir.join("scan.rxscan");
    save_checkpoint(&path, &state).unwrap();
    path
}

fn db_path(dir: &std::path::Path) -> std::path::PathBuf {
    let event = Event::new(
        EventKind::PortOpen,
        None,
        BoundedDetails::from_value(
            serde_json::json!({"target": "192.0.2.10", "address": "192.0.2.10", "transport": "tcp", "port": 80}),
            MAX_EVENT_DETAILS_BYTES,
        )
        .unwrap(),
        Provenance::new(
            "phase7.test",
            "7.0.0",
            rxscan::model::ScanPlanId("plan_7".to_owned()),
            Timestamp(7),
        )
        .unwrap(),
    )
    .unwrap();
    let endpoint = Event::new(
        EventKind::EndpointObserved,
        None,
        BoundedDetails::from_value(
            serde_json::json!({"url": format!("https://admin:{SECRET}@example.test/")}),
            MAX_EVENT_DETAILS_BYTES,
        )
        .unwrap(),
        Provenance::new(
            "phase7.test",
            "7.0.0",
            rxscan::model::ScanPlanId("plan_7".to_owned()),
            Timestamp(7),
        )
        .unwrap(),
    )
    .unwrap();
    let graph = build_graph(
        &[(
            rxscan::execution::TaskId("task_7".to_owned()),
            ModuleOutput {
                events: vec![event, endpoint],
                ..ModuleOutput::default()
            },
        )],
        None,
    );
    let path = dir.join("proj.db");
    let mut db = ProjectDb::open(&path).unwrap();
    db.import_scan(
        &ScanImport {
            scan_id: "scan-7".to_owned(),
            plan_id: "plan_7".to_owned(),
            started_at_ms: 1,
            finished_at_ms: 2,
            scope_json: r#"{"allow":["192.0.2.0/24"]}"#.to_owned(),
            workflow: "recon".to_owned(),
            level: 3,
            termination: "completed".to_owned(),
            tasks_admitted: 2,
            tasks_completed: 2,
            coverage: CoverageSnapshot {
                hosts_attempted: vec!["192.0.2.10".to_owned()],
                tcp_attempted: BTreeMap::from([("192.0.2.10".to_owned(), vec![(1, 1000)])]),
                ..CoverageSnapshot::default()
            },
            classifier: ClassifierProvenance {
                tool_version: TOOL_VERSION.to_owned(),
                packs: vec![],
                rules_used: vec![],
            },
            retention: RetentionMode::Standard,
        },
        &graph,
    )
    .unwrap();
    path
}

fn tmp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("rxscan-explain7-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_rxscan"))
}

fn finding_id(dir: &std::path::Path) -> (std::path::PathBuf, String) {
    let checkpoint = checkpoint_path(dir);
    let loaded = rxscan::persistence::load_checkpoint(&checkpoint).unwrap();
    let id = loaded.state.outputs[0].output.findings[0].id.0.clone();
    (checkpoint, id)
}

#[test]
fn finding_explain_shows_chain_masked() {
    let dir = tmp("finding");
    let (checkpoint, id) = finding_id(&dir);
    let out = Command::new(bin())
        .arg("explain")
        .arg("finding")
        .arg(&id)
        .arg("--checkpoint")
        .arg(&checkpoint)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    for section in [
        "observed:",
        "interpreted:",
        "confidence:",
        "raising confidence",
        "lowering confidence",
    ] {
        assert!(text.contains(section), "missing {section}:\n{text}");
    }
    assert!(text.contains("phase7.test"));
    assert!(!text.contains(SECRET), "finding explain leaked a secret");
    // JSON path is masked and parses.
    let out = Command::new(bin())
        .arg("explain")
        .arg("finding")
        .arg(&id)
        .arg("--checkpoint")
        .arg(&checkpoint)
        .arg("--json")
        .output()
        .unwrap();
    assert!(out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["confidence"], 80);
    assert!(!value.to_string().contains(SECRET));
}

#[test]
fn node_explain_matches_gui_chain() {
    let dir = tmp("node");
    let db = db_path(&dir);
    let out = Command::new(bin())
        .arg("explain")
        .arg("node")
        .arg("ip:192.0.2.10")
        .arg("--project-db")
        .arg(&db)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("linked confidence"));
    assert!(text.contains("raising confidence"));
    assert!(!text.contains(SECRET));
    // Same code path as the GUI: the API node endpoint renders
    // graph_view::node_detail, whose explanation text the CLI embeds.
    let data_dir = dir.join("srv");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::copy(&db, data_dir.join("g.db")).unwrap();
    let handle = rxscan::web_api::serve(rxscan::web_api::WebOptions {
        bind: "127.0.0.1".to_owned(),
        port: 0,
        data_dir: data_dir.clone(),
        allow_remote: false,
        fixture_investigation: true,
    })
    .unwrap();
    let base = handle.base_url().to_owned();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(mut stream) = TcpStream::connect(base.trim_start_matches("http://")) {
            let _ = stream.write_all(
                b"GET /api/v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            );
            let mut head = [0u8; 12];
            if stream.read_exact(&mut head).is_ok() {
                break;
            }
        }
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(25));
    }
    let mut stream = TcpStream::connect(base.trim_start_matches("http://")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    stream
        .write_all(b"GET /api/v1/projects/g/graph/node?node=ip:192.0.2.10 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let body: serde_json::Value = serde_json::from_slice(&raw[split..]).unwrap();
    handle.shutdown();
    let api_explanation = body["explanation"].as_str().unwrap();
    // Verbatim agreement on the shared explanation core.
    for phrase in [
        "linked confidence",
        "raising confidence",
        "lowering confidence",
    ] {
        assert!(
            text.contains(phrase) && api_explanation.contains(phrase),
            "CLI/GUI drift on {phrase}"
        );
    }
    assert!(
        !body.to_string().contains(SECRET),
        "API detail leaked a secret"
    );
}

#[test]
fn explain_errors_are_typed() {
    let dir = tmp("errors");
    let (checkpoint, _) = finding_id(&dir);
    let db = db_path(&dir);
    // Unknown ids fail (exit 1), missing sources fail usage (exit 2).
    let out = Command::new(bin())
        .arg("explain")
        .arg("finding")
        .arg("nope")
        .arg("--checkpoint")
        .arg(&checkpoint)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let out = Command::new(bin())
        .arg("explain")
        .arg("node")
        .arg("nope")
        .arg("--project-db")
        .arg(&db)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let out = Command::new(bin())
        .arg("explain")
        .arg("finding")
        .arg("x")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(bin())
        .arg("explain")
        .arg("node")
        .arg("x")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(bin())
        .arg("explain")
        .arg("planet")
        .arg("x")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}
