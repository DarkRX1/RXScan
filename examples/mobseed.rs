//! Temporary fixture seeder for mobile verification screenshots.
//! Builds one project database with a small graph over reserved ranges
//! (example domains, 192.0.2.0/24) and fake-but-masked secrets, then exits.

use rxscan::execution::{ModuleOutput, TaskId};
use rxscan::graph::build_graph;
use rxscan::model::{
    BoundedDetails, Event, EventKind, MAX_EVENT_DETAILS_BYTES, Provenance, ScanPlanId, Timestamp,
};
use rxscan::project_db::{
    ClassifierProvenance, CoverageSnapshot, ProjectDb, RetentionMode, ScanImport,
};
use std::path::PathBuf;

fn plan_id() -> ScanPlanId {
    ScanPlanId("plan_mob".to_owned())
}

fn provenance() -> Provenance {
    Provenance::new("test.module", "1.0.0", plan_id(), Timestamp(7)).unwrap()
}

fn event(kind: EventKind, data: serde_json::Value) -> Event {
    Event::new(
        kind,
        None,
        BoundedDetails::from_value(data, MAX_EVENT_DETAILS_BYTES).unwrap(),
        provenance(),
    )
    .unwrap()
}

fn main() {
    let out_dir = PathBuf::from(std::env::args().nth(1).expect("usage: mobseed <out-dir>"));
    std::fs::create_dir_all(&out_dir).unwrap();
    let db_path = out_dir.join("default.db");

    let graph = build_graph(
        &[(
            TaskId("task_mob".to_owned()),
            ModuleOutput {
                events: vec![
                    event(
                        EventKind::PortOpen,
                        serde_json::json!({"target": "192.0.2.10", "address": "192.0.2.10", "transport": "tcp", "port": 443}),
                    ),
                    event(
                        EventKind::ServiceIdentified,
                        serde_json::json!({
                            "target": "192.0.2.10", "address": "192.0.2.10", "port": 443,
                            "protocol": "https", "service": "https",
                            "product_hint": "nginx", "version_hint": "1.24.0",
                            "confidence": 90u64, "matcher": "https",
                        }),
                    ),
                    event(
                        EventKind::TlsObserved,
                        serde_json::json!({
                            "target": "192.0.2.10", "address": "192.0.2.10", "port": 443,
                            "subject": "CN=example.test", "issuer": "CN=Fixture CA",
                            "san_dns": ["example.test"], "san_ip": [],
                            "not_before": "2026-01-01", "not_after": "2027-01-01",
                            "fingerprint_sha256": "aa".repeat(32),
                        }),
                    ),
                    event(
                        EventKind::DnsRecordObserved,
                        serde_json::json!({"name": "example.test", "record_type": "A", "value": "192.0.2.10"}),
                    ),
                    event(
                        EventKind::PortOpen,
                        serde_json::json!({"target": "192.0.2.11", "address": "192.0.2.11", "transport": "tcp", "port": 22}),
                    ),
                    event(
                        EventKind::ServiceIdentified,
                        serde_json::json!({
                            "target": "192.0.2.11", "address": "192.0.2.11", "port": 22,
                            "protocol": "ssh", "service": "ssh",
                            "product_hint": "OpenSSH", "version_hint": "8.9p1",
                            "confidence": 80u64, "matcher": "ssh",
                        }),
                    ),
                ],
                ..ModuleOutput::default()
            },
        )],
        None,
    );
    assert!(graph.entity_count() >= 5);

    let mut db = ProjectDb::open(&db_path).expect("create fixture db");
    db.import_scan(
        &ScanImport {
            scan_id: "scan-mob-1".to_owned(),
            plan_id: "plan_mob".to_owned(),
            started_at_ms: 1_700_000_000_000,
            finished_at_ms: 1_700_000_001_000,
            scope_json: r#"{"allow":["192.0.2.0/24"]}"#.to_owned(),
            workflow: "recon".to_owned(),
            level: 3,
            termination: "completed".to_owned(),
            tasks_admitted: 5,
            tasks_completed: 5,
            coverage: CoverageSnapshot {
                hosts_attempted: vec!["192.0.2.10".to_owned(), "192.0.2.11".to_owned()],
                tcp_attempted: std::collections::BTreeMap::from([
                    ("192.0.2.10".to_owned(), vec![(22, 443)]),
                    ("192.0.2.11".to_owned(), vec![(22, 22)]),
                ]),
                udp_attempted: std::collections::BTreeMap::new(),
                dns_queried: vec!["example.test".to_owned()],
                modules_completed: vec!["PortDiscovery".to_owned(), "DnsProbe".to_owned()],
                truncated: false,
            },
            classifier: ClassifierProvenance {
                tool_version: "1.2.0".to_owned(),
                packs: vec![],
                rules_used: vec![],
            },
            retention: RetentionMode::Standard,
        },
        &graph,
    )
    .expect("import succeeds");
    println!("{}", db_path.display());
}
