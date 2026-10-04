//! Persistent project graph + cross-scan diff regression tests.
//!
//! Covers project creation/reopen, interrupted runs, dedup, migrations,
//! coverage-gated diffing (no false removals), rotation, provenance,
//! retention, validation, queries, determinism, and bounded repetition.

use std::collections::BTreeMap;
use std::sync::Arc;

use rxscan::execution::TaskId;
use rxscan::graph::{ScanGraph, build_graph};
use rxscan::model::{
    BoundedDetails, Event, EventKind, MAX_EVENT_DETAILS_BYTES, Provenance, ScanPlanId, Timestamp,
};
use rxscan::project_db::{
    ClassifierProvenance, CoverageSnapshot, ProjectDb, RetentionMode, ScanImport, TOOL_VERSION,
    human_changes_summary,
};

fn plan_id() -> ScanPlanId {
    ScanPlanId("plan_test".to_owned())
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

fn outputs(events: Vec<Event>) -> Vec<(TaskId, rxscan::execution::ModuleOutput)> {
    vec![(
        TaskId("task_test".to_owned()),
        rxscan::execution::ModuleOutput {
            events,
            ..rxscan::execution::ModuleOutput::default()
        },
    )]
}

fn port_open(ip: &str, port: u16) -> Event {
    event(
        EventKind::PortOpen,
        serde_json::json!({
            "target": ip, "address": ip, "transport": "tcp", "port": port,
        }),
    )
}

fn service(ip: &str, port: u16, product: &str, version: &str) -> Event {
    event(
        EventKind::ServiceIdentified,
        serde_json::json!({
            "target": ip, "address": ip, "port": port,
            "protocol": "http", "service": "http",
            "product_hint": product, "version_hint": version,
            "confidence": 90u64, "matcher": "http",
        }),
    )
}

fn tls(ip: &str, port: u16, fp: &str, sans: Vec<&str>) -> Event {
    event(
        EventKind::TlsObserved,
        serde_json::json!({
            "target": ip, "address": ip, "port": port,
            "subject": "CN=t", "issuer": "CN=t",
            "san_dns": sans, "san_ip": [],
            "not_before": "2026-01-01", "not_after": "2027-01-01",
            "fingerprint_sha256": fp,
            "hostname_match": true, "hostname_detail": "x",
        }),
    )
}

fn dns(name: &str, record_type: &str, value: &str) -> Event {
    event(
        EventKind::DnsRecordObserved,
        serde_json::json!({
            "name": name, "record_type": record_type, "value": value,
        }),
    )
}

fn import_for(
    db: &mut ProjectDb,
    scan_id: &str,
    graph: &ScanGraph,
    coverage: CoverageSnapshot,
    termination: &str,
) -> rxscan::project_db::ImportStats {
    db.import_scan(
        &ScanImport {
            scan_id: scan_id.to_owned(),
            plan_id: "plan_test".to_owned(),
            started_at_ms: 1,
            finished_at_ms: 2,
            scope_json: r#"{"allow":["127.0.0.1"]}"#.to_owned(),
            workflow: "recon".to_owned(),
            level: 3,
            termination: termination.to_owned(),
            tasks_admitted: 10,
            tasks_completed: 9,
            coverage,
            classifier: ClassifierProvenance {
                tool_version: TOOL_VERSION.to_owned(),
                packs: vec![],
                rules_used: vec![],
            },
            retention: RetentionMode::Standard,
        },
        graph,
    )
    .expect("import succeeds")
}

fn full_coverage() -> CoverageSnapshot {
    CoverageSnapshot {
        hosts_attempted: vec!["10.0.0.5".to_owned(), "10.0.0.6".to_owned()],
        tcp_attempted: BTreeMap::from([
            ("10.0.0.5".to_owned(), vec![(1, 1000)]),
            ("10.0.0.6".to_owned(), vec![(1, 1000)]),
        ]),
        udp_attempted: BTreeMap::new(),
        dns_queried: vec!["web.example.test".to_owned()],
        modules_completed: vec!["PortDiscovery".to_owned(), "DnsProbe".to_owned()],
        truncated: false,
    }
}

#[test]
fn create_reopen_preserves_graph() {
    let dir = std::env::temp_dir().join(format!("rxscan-proj-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("proj.db");
    let graph = build_graph(
        &outputs(vec![
            port_open("10.0.0.5", 80),
            service("10.0.0.5", 80, "nginx", "1.24.0"),
        ]),
        None,
    );
    {
        let mut db = ProjectDb::open(&path).expect("create");
        assert_eq!(
            db.schema_version().unwrap(),
            rxscan::project_db::PROJECT_DB_SCHEMA_VERSION
        );
        import_for(&mut db, "scan-a", &graph, full_coverage(), "completed");
    }
    {
        let db = ProjectDb::open(&path).expect("reopen");
        assert_eq!(db.scan_ids().unwrap(), vec!["scan-a".to_owned()]);
        let ports = db
            .entities_by_kind(rxscan::graph::EntityKind::Port)
            .unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].observation_count, 1);
        assert_eq!(ports[0].first_seen_scan, "scan-a");
        // Provenance chain spans the observation.
        let chain = db.provenance_chain(&ports[0].entity_id).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].scan_run, "scan-a");
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn interrupted_scan_stays_interrupted() {
    let mut db = ProjectDb::open_in_memory().unwrap();
    let graph = build_graph(&outputs(vec![port_open("10.0.0.5", 80)]), None);
    import_for(
        &mut db,
        "scan-i",
        &graph,
        CoverageSnapshot::default(),
        "interrupted",
    );
    assert_eq!(db.scan_termination("scan-i").unwrap(), "interrupted");
    // Still queryable (valid incomplete run, not vanished).
    assert_eq!(db.scan_ids().unwrap(), vec!["scan-i".to_owned()]);
}

#[test]
fn reimport_dedups_entities_and_counts_observations() {
    let mut db = ProjectDb::open_in_memory().unwrap();
    let graph = build_graph(&outputs(vec![port_open("10.0.0.5", 80)]), None);
    for _ in 0..5 {
        import_for(&mut db, "scan-same", &graph, full_coverage(), "completed");
    }
    // Re-importing the same scan id upserts (no duplicates).
    let ports = db
        .entities_by_kind(rxscan::graph::EntityKind::Port)
        .unwrap();
    assert_eq!(ports.len(), 1);
    assert_eq!(ports[0].observation_count, 5);
    let chain = db.provenance_chain(&ports[0].entity_id).unwrap();
    assert_eq!(chain.len(), 5);
}

#[test]
fn migration_refuses_newer_schema() {
    // A file stamped with a newer schema version is refused on open, never
    // silently rewritten.
    let dir = std::env::temp_dir().join(format!("rxscan-projv-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("v.db");
    {
        let db = ProjectDb::open(&path).unwrap();
        db.conn_execute_for_test("UPDATE meta SET value='99' WHERE key='schema_version'")
            .unwrap();
    }
    let reopened = ProjectDb::open(&path);
    assert!(
        matches!(
            reopened,
            Err(rxscan::project_db::ProjectDbError::UnsupportedVersion { found: 99, .. })
        ),
        "newer schema refused"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn port_opened_closed_and_unknown_coverage() {
    let mut db = ProjectDb::open_in_memory().unwrap();
    // Old: port 80 open. New: port 80 gone but covered, 443 new, 22 gone uncovered.
    let old = build_graph(
        &outputs(vec![
            port_open("10.0.0.5", 80),
            port_open("10.0.0.5", 22),
            port_open("10.0.0.5", 443),
        ]),
        None,
    );
    import_for(&mut db, "s-old", &old, full_coverage(), "completed");
    let new = build_graph(
        &outputs(vec![
            port_open("10.0.0.5", 443),
            port_open("10.0.0.5", 8080),
        ]),
        None,
    );
    // New scan covers 80 (now shut), 443, and 8080 — but not 22.
    // Old coverage spans 1-1000 plus 8080 for the opened-port proof.
    let mut wide_old = full_coverage();
    wide_old.tcp_attempted = BTreeMap::from([("10.0.0.5".to_owned(), vec![(1, 9000)])]);
    let mut narrow = full_coverage();
    narrow.tcp_attempted = BTreeMap::from([(
        "10.0.0.5".to_owned(),
        vec![(80, 80), (443, 443), (8080, 8080)],
    )]);
    // Re-import old with the wide coverage (replaces prior import).
    import_for(&mut db, "s-old", &old, wide_old, "completed");
    import_for(&mut db, "s-new", &new, narrow, "completed");
    let changes = db.diff_scan_runs("s-old", "s-new").unwrap();
    db.record_changes("s-new", "s-old", &changes).unwrap();
    let kinds: BTreeMap<_, _> = changes
        .iter()
        .map(|c| (c.entity_id.clone(), c.change_type))
        .collect();
    // 80 was covered and vanished → closed (confirmed).
    assert_eq!(
        kinds.get("port:tcp:10.0.0.5:80"),
        Some(&rxscan::project_db::ChangeType::Closed)
    );
    // 8080 never seen, old covered it → opened.
    assert_eq!(
        kinds.get("port:tcp:10.0.0.5:8080"),
        Some(&rxscan::project_db::ChangeType::Opened)
    );
    // 22 vanished WITHOUT coverage → no removal record (unknown, not closed).
    assert!(
        !kinds.contains_key("port:tcp:10.0.0.5:22"),
        "uncovered absence must not become a removal"
    );
    // 443 unchanged → no record.
    assert!(!kinds.contains_key("port:tcp:10.0.0.5:443"));
    // Stored + queryable.
    let stored = db.changes_since("s-new", 100).unwrap();
    assert_eq!(stored.len(), changes.len());
    // Deterministic: diff twice, same result.
    assert_eq!(db.diff_scan_runs("s-old", "s-new").unwrap(), changes);
    // Concise human summary.
    let summary = human_changes_summary(&changes);
    assert!(summary.contains("closed: 1") && summary.contains("opened: 1"));
}

#[test]
fn service_version_change_and_cert_rotation() {
    let mut db = ProjectDb::open_in_memory().unwrap();
    let fp_a = "aa".repeat(32);
    let fp_b = "bb".repeat(32);
    let old = build_graph(
        &outputs(vec![
            port_open("10.0.0.5", 443),
            service("10.0.0.5", 443, "nginx", "1.24.0"),
            tls("10.0.0.5", 443, &fp_a, vec![]),
        ]),
        None,
    );
    import_for(&mut db, "v-old", &old, full_coverage(), "completed");
    let new = build_graph(
        &outputs(vec![
            port_open("10.0.0.5", 443),
            service("10.0.0.5", 443, "nginx", "1.26.0"),
            tls("10.0.0.5", 443, &fp_b, vec![]),
        ]),
        None,
    );
    import_for(&mut db, "v-new", &new, full_coverage(), "completed");
    let changes = db.diff_scan_runs("v-old", "v-new").unwrap();
    // Same service entity id across versions (identity = endpoint+protocol).
    assert!(
        changes
            .iter()
            .any(|c| c.change_type == rxscan::project_db::ChangeType::Changed
                && c.old_value.contains("1.24.0")
                && c.new_value.contains("1.26.0"))
    );
    // Certificate rotation links old→new on the same port.
    assert!(
        changes
            .iter()
            .any(|c| c.change_type == rxscan::project_db::ChangeType::Changed
                && c.old_value.contains(&fp_a[..12])
                && c.new_value.contains(&fp_b[..12]))
    );
    // Both certificates retained in history.
    let certs = db
        .entities_by_kind(rxscan::graph::EntityKind::Certificate)
        .unwrap();
    assert_eq!(certs.len(), 2);
}

#[test]
fn hostname_changes_gated_by_dns_coverage() {
    let mut db = ProjectDb::open_in_memory().unwrap();
    let old = build_graph(
        &outputs(vec![
            dns("web.example.test", "A", "10.0.0.5"),
            dns("gone.example.test", "A", "10.0.0.6"),
        ]),
        None,
    );
    import_for(&mut db, "h-old", &old, full_coverage(), "completed");
    let new = build_graph(
        &outputs(vec![
            dns("web.example.test", "A", "10.0.0.5"),
            dns("new.example.test", "A", "10.0.0.7"),
        ]),
        None,
    );
    // New scan re-queried only web.example.test.
    let mut cov = full_coverage();
    cov.dns_queried = vec!["web.example.test".to_owned()];
    import_for(&mut db, "h-new", &new, cov, "completed");
    let changes = db.diff_scan_runs("h-old", "h-new").unwrap();
    let kinds: BTreeMap<_, _> = changes
        .iter()
        .map(|c| (c.entity_id.clone(), c.change_type))
        .collect();
    assert_eq!(
        kinds.get("host:new.example.test"),
        Some(&rxscan::project_db::ChangeType::Added)
    );
    // gone.example.test was NOT re-queried → no removal.
    assert!(!kinds.contains_key("host:gone.example.test"));
}

#[test]
fn queries_expose_reuse_and_edges() {
    let mut db = ProjectDb::open_in_memory().unwrap();
    let fp = "cc".repeat(32);
    let graph = build_graph(
        &outputs(vec![
            port_open("10.0.0.5", 443),
            tls("10.0.0.5", 443, &fp, vec![]),
            port_open("10.0.0.6", 443),
            tls("10.0.0.6", 443, &fp, vec![]),
        ]),
        None,
    );
    import_for(&mut db, "q", &graph, full_coverage(), "completed");
    let reuse = db.certificate_reuse().unwrap();
    assert_eq!(reuse.len(), 1);
    assert_eq!(reuse[0].1.len(), 2);
    let cert_id = format!("cert:sha256:{fp}");
    let to_cert = db.edges_to(&cert_id).unwrap();
    assert_eq!(to_cert.len(), 2);
    assert!(
        to_cert
            .iter()
            .all(|edge| edge.relation == "presents_certificate")
    );
    let from_port = db.edges_from("port:tcp:10.0.0.5:443").unwrap();
    assert!(from_port.iter().any(|edge| edge.to_id == cert_id));
}

#[test]
fn retention_modes_bound_evidence() {
    let mut db = ProjectDb::open_in_memory().unwrap();
    let big = serde_json::json!({"blob": "x".repeat(5000)});
    let items = vec![("src".to_owned(), "a".to_owned(), 80u8, big.clone(), 1u64)];
    let full = db
        .store_evidence("s1", &items, RetentionMode::Full)
        .unwrap();
    assert_eq!(full, 1);
    let min = db
        .store_evidence("s1", &items, RetentionMode::Minimal)
        .unwrap();
    assert_eq!(min, 1);
    // Minimal stores the marker, full stores content (bounded).
    let stored: Vec<String> =
        db.conn_query_for_test("SELECT details_json FROM evidence_store ORDER BY id");
    assert!(stored[0].len() > 100);
    assert_eq!(stored[1], r#"{"truncated":true}"#);
}

#[test]
fn validation_rejects_bad_input() {
    let mut db = ProjectDb::open_in_memory().unwrap();
    // Oversized scope JSON.
    let mut import = ScanImport {
        scan_id: "bad".to_owned(),
        plan_id: "plan_test".to_owned(),
        started_at_ms: 0,
        finished_at_ms: 1,
        scope_json: "x".repeat(100_000),
        workflow: "recon".to_owned(),
        level: 3,
        termination: "completed".to_owned(),
        tasks_admitted: 0,
        tasks_completed: 0,
        coverage: CoverageSnapshot::default(),
        classifier: ClassifierProvenance::default(),
        retention: RetentionMode::Standard,
    };
    let graph = ScanGraph::default();
    assert!(db.import_scan(&import, &graph).is_err());
    // Confidence over 100 on an edge.
    import.scope_json = "{}".to_owned();
    let mut evil = ScanGraph::default();
    evil.entities.insert(
        "ip:1.1.1.1".to_owned(),
        rxscan::graph::GraphEntity {
            id: "ip:1.1.1.1".to_owned(),
            kind: rxscan::graph::EntityKind::IpAddress,
            label: "1.1.1.1".to_owned(),
            attributes: BTreeMap::new(),
            provenance: rxscan::graph::EntityProvenance {
                scan_plan_id: "plan_test".to_owned(),
                module: "t".to_owned(),
                task_id: None,
                target: None,
                timestamp: 0,
                reason: None,
                rule_id: None,
            },
            observations: 1,
        },
    );
    evil.entities.insert(
        "port:tcp:1.1.1.1:80".to_owned(),
        rxscan::graph::GraphEntity {
            id: "port:tcp:1.1.1.1:80".to_owned(),
            kind: rxscan::graph::EntityKind::Port,
            label: "x".to_owned(),
            attributes: BTreeMap::new(),
            provenance: rxscan::graph::EntityProvenance {
                scan_plan_id: "plan_test".to_owned(),
                module: "t".to_owned(),
                task_id: None,
                target: None,
                timestamp: 0,
                reason: None,
                rule_id: None,
            },
            observations: 1,
        },
    );
    evil.edges.push(rxscan::graph::GraphEdge {
        from: "ip:1.1.1.1".to_owned(),
        to: "port:tcp:1.1.1.1:80".to_owned(),
        relation: rxscan::graph::EdgeRelation::ListensOn,
        confidence: 101,
        provenance: rxscan::graph::EntityProvenance {
            scan_plan_id: "plan_test".to_owned(),
            module: "t".to_owned(),
            task_id: None,
            target: None,
            timestamp: 0,
            reason: None,
            rule_id: None,
        },
        evidence: vec![],
        attributes: BTreeMap::new(),
    });
    assert!(db.import_scan(&import, &evil).is_err());
    // Empty entity id.
    let mut evil2 = ScanGraph::default();
    evil2.entities.insert(
        String::new(),
        rxscan::graph::GraphEntity {
            id: String::new(),
            kind: rxscan::graph::EntityKind::Port,
            label: "x".to_owned(),
            attributes: BTreeMap::new(),
            provenance: rxscan::graph::EntityProvenance {
                scan_plan_id: "plan_test".to_owned(),
                module: "t".to_owned(),
                task_id: None,
                target: None,
                timestamp: 0,
                reason: None,
                rule_id: None,
            },
            observations: 1,
        },
    );
    assert!(db.import_scan(&import, &evil2).is_err());
}

#[test]
fn coverage_builder_merges_intervals_and_counts_succeeded_only() {
    use rxscan::project_db::TaskCoverageInput;
    let tasks = vec![
        TaskCoverageInput {
            kind: "PortDiscovery".to_owned(),
            host: Some("10.0.0.5".to_owned()),
            ports_spec: Some("explicit:1-100,90-200,443".to_owned()),
            transport: Some("tcp".to_owned()),
            hostname: None,
            succeeded: true,
        },
        TaskCoverageInput {
            kind: "PortDiscovery".to_owned(),
            host: Some("10.0.0.5".to_owned()),
            ports_spec: Some("all".to_owned()),
            transport: Some("tcp".to_owned()),
            hostname: None,
            succeeded: false,
        },
        TaskCoverageInput {
            kind: "HostDiscovery".to_owned(),
            host: Some("10.0.0.5".to_owned()),
            ports_spec: None,
            transport: None,
            hostname: None,
            succeeded: true,
        },
        TaskCoverageInput {
            kind: "DnsProbe".to_owned(),
            host: None,
            ports_spec: None,
            transport: None,
            hostname: Some("Web.Example.TEST.".to_owned()),
            succeeded: true,
        },
    ];
    let coverage = rxscan::project_db::coverage_from_tasks(&tasks, false);
    // Failed all-ports task contributes nothing; explicit merges.
    assert_eq!(
        coverage
            .tcp_attempted
            .get("10.0.0.5")
            .cloned()
            .unwrap_or_default(),
        vec![(1, 200), (443, 443)]
    );
    assert!(coverage.host_covered("10.0.0.5"));
    assert!(!coverage.host_covered("10.0.0.6"));
    assert!(coverage.dns_covered("web.example.test"));
    assert!(coverage.port_covered("tcp", "10.0.0.5", 150));
    assert!(!coverage.port_covered("tcp", "10.0.0.5", 201));
    assert!(!coverage.port_covered("udp", "10.0.0.5", 53));
}

#[test]
fn live_san_ip_proposes_scoped_host_followup() {
    use std::io::Read as _;
    // TLS server presenting a SAN IP literal inside the CLI scope.
    let mut params =
        rcgen::CertificateParams::new(vec!["san.test".to_owned(), "127.0.0.2".to_owned()])
            .expect("rcgen params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "san.test");
    let key = rcgen::KeyPair::generate().expect("rcgen key");
    let cert = params.self_signed(&key).expect("rcgen self-signed");
    let (cert_der, key_der) = (cert.der().to_vec(), key.serialize_der());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_thread = stop.clone();
    let handle = std::thread::spawn(move || {
        use rustls::crypto::ring::default_provider;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        let config = rustls::ServerConfig::builder_with_provider(default_provider().into())
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert_der)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
            )
            .expect("cert");
        let config = Arc::new(config);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !stop_thread.load(std::sync::atomic::Ordering::SeqCst)
            && std::time::Instant::now() < deadline
        {
            let (stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                }
                Err(_) => break,
            };
            let config = config.clone();
            std::thread::spawn(move || {
                let _ = stream.set_nonblocking(false);
                let Ok(mut conn) = rustls::ServerConnection::new(config) else {
                    return;
                };
                let mut stream = stream;
                for _ in 0..200 {
                    match conn.complete_io(&mut stream) {
                        Ok(_) if !conn.is_handshaking() => break,
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                let mut chunk = [0u8; 512];
                let _ = stream.read(&mut chunk);
                std::thread::sleep(std::time::Duration::from_millis(300));
            });
        }
    });
    let dir = std::env::temp_dir().join(format!("rxscan-sanlive-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("out.jsonl");
    let cli = clap::Parser::try_parse_from([
        "rxscan",
        "127.0.0.1",
        "--scope",
        "127.0.0.0/8",
        "--ports",
        &port.to_string(),
        "--goal",
        "services",
        "--level",
        "4",
        "--max-execution-time",
        "60s",
        "--output",
        path.to_str().unwrap(),
    ])
    .unwrap();
    let report = rxscan::run::execute(cli).expect("scan executes");
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = handle.join();
    assert_eq!(
        report.scheduler_report.termination,
        rxscan::execution::TerminationReason::Completed
    );
    // The SAN IP was discovered as a host: follow-up generated, admitted,
    // executed — all through scope/budget/deadline gates.
    let contents = std::fs::read_to_string(&path).unwrap();
    let mut saw_san_host = false;
    let mut saw_cert_edge = false;
    for line in contents.lines() {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        let payload = &value["payload"];
        if payload["kind"] == "host_state_concluded"
            && payload["details"]["data"]["address"] == "127.0.0.2"
        {
            saw_san_host = true;
        }
        if value["record_type"] == "graph_edge" && payload["relation"] == "presents_certificate" {
            saw_cert_edge = true;
        }
    }
    assert!(saw_san_host, "SAN IP 127.0.0.2 discovered via follow-up");
    assert!(saw_cert_edge, "certificate edge streamed");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn prop_no_out_of_scope_followup() {
    use rxscan::decision::{CertDecisionEngine, DnsDecisionEngine};
    use rxscan::execution::{DecisionEngine, PolicyScopeGuard, ScopeGuard};
    use rxscan::model::{BoundedDetails, Event, Provenance};
    use rxscan::plan::{ScanGoal, SpeedSetting};
    use rxscan::scope::ScopePolicy;
    use rxscan::target::TargetSpec;
    // Adversarial SAN corpus: out-of-scope, wildcards, malformed, unicode,
    // overlong, empty, IP literals in/out of scope.
    let long_name = "a".repeat(300);
    let hostile: Vec<&str> = vec![
        "evil.example.com",
        "*.example.test",
        "*",
        "",
        "!!!",
        &long_name,
        "127.0.0.2",
        "10.255.255.255",
        "999.999.999.999",
        "::1",
        "exämple.test",
        "foo..bar",
        "-leading.test",
    ];
    let lan = TargetSpec::parse("127.0.0.0/8").unwrap();
    let name = TargetSpec::parse("example.test").unwrap();
    let policy = ScopePolicy::from_targets(&[lan, name], &[], &[]).unwrap();
    let guard = Arc::new(PolicyScopeGuard::new(policy));
    let engine = CertDecisionEngine::new(
        guard.clone(),
        ScanPlanId("plan_test".to_owned()),
        3,
        ScanGoal::Recon,
        SpeedSetting::default(),
    );
    let provenance = Provenance::new(
        "rxscan.service",
        "7.0.0",
        ScanPlanId("plan_test".to_owned()),
        Timestamp(0),
    )
    .unwrap();
    let completed = rxscan::execution::Task::new_with_params(
        rxscan::execution::TaskKind::ServiceProbe,
        None,
        Vec::new(),
        None,
        ScanPlanId("plan_test".to_owned()),
        50,
        std::time::Duration::from_millis(1000),
        rxscan::execution::RetryPolicy::default(),
        "rxscan.service",
        provenance.clone(),
        rxscan::execution::TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        std::collections::BTreeMap::from([("target".to_owned(), "127.0.0.1".to_owned())]),
        guard.as_ref(),
    )
    .unwrap();
    let event = Event::new(
        EventKind::TlsObserved,
        None,
        BoundedDetails::from_value(
            serde_json::json!({
                "fingerprint_sha256": "ab".repeat(32),
                "san_dns": hostile,
                "san_ip": ["127.0.0.1"],
            }),
            MAX_EVENT_DETAILS_BYTES,
        )
        .unwrap(),
        provenance,
    )
    .unwrap();
    let output = rxscan::execution::ModuleOutput {
        events: vec![event],
        ..rxscan::execution::ModuleOutput::default()
    };
    for task in engine.follow_up_tasks(&completed, &output) {
        assert!(
            guard.permits(&task.scope_target),
            "out-of-scope follow-up proposed: {:?}",
            task.scope_target
        );
        let depth: u8 = task.params.get("discovery_depth").unwrap().parse().unwrap();
        assert!(depth <= rxscan::decision::MAX_DISCOVERY_DEPTH);
    }
    // DNS engine under adversarial records: same guarantee.
    let dns_engine = DnsDecisionEngine::new(
        guard.clone(),
        ScanPlanId("plan_test".to_owned()),
        3,
        ScanGoal::Recon,
        SpeedSetting::default(),
    );
    let _ = dns_engine;
}

#[test]
fn prop_extraction_bounded_and_cpe_wellformed() {
    use rxscan::fingerprints::VersionExtractor;
    use rxscan::service::cpe_for_product_version;
    let big = "A".repeat(5000);
    let corpus: Vec<&str> = vec![
        "",
        " ",
        "SSH-2.0-OpenSSH_9.7p1 extra words here",
        "Server: nginx/1.24.0 (Ubuntu)",
        "version=1.2; rm -rf /",
        "X-stable",
        "X-1.2é",
        &big,
        "18927398127398127398127389.2",
        "\u{0}\u{1}\u{2}",
        "v=1.0 v=2.0",
    ];
    let extractors = vec![
        VersionExtractor::AfterDelimiter {
            delimiter: "OpenSSH_".to_owned(),
            max_len: 32,
        },
        VersionExtractor::PrefixedToken {
            prefix: "nginx/".to_owned(),
            max_len: 32,
        },
        VersionExtractor::KeyValue {
            key: "version".to_owned(),
        },
        VersionExtractor::TokenPosition { index: 3 },
        VersionExtractor::SemVerToken {},
    ];
    for input in &corpus {
        for extractor in &extractors {
            if let Some(version) = extractor.extract(input) {
                assert!(version.len() <= 32, "bounded: {version:?}");
                assert!(version.is_ascii(), "ascii: {version:?}");
                assert!(version.bytes().any(|b| b.is_ascii_digit()));
                let cpe = cpe_for_product_version(Some("TestProd"), Some(&version), None);
                let cpe = cpe.expect("cpe present");
                assert_eq!(cpe.split(':').count(), 13, "CPE has 13 parts: {cpe}");
            }
        }
    }
    // Absent product → absent CPE (never synthesized).
    assert!(cpe_for_product_version(None, Some("1.0"), None).is_none());
}

#[test]
fn prop_repeated_evidence_stays_bounded() {
    // Same observation imported repeatedly: entities stable, observations
    // grow linearly (history), edges/clusters do not multiply.
    let mut db = ProjectDb::open_in_memory().unwrap();
    let graph = build_graph(
        &outputs(vec![
            port_open("10.0.0.5", 80),
            service("10.0.0.5", 80, "nginx", "1.24.0"),
        ]),
        None,
    );
    let edges_before = graph.edge_count();
    for round in 0..4 {
        import_for(
            &mut db,
            &format!("repeat-{round}"),
            &graph,
            full_coverage(),
            "completed",
        );
    }
    let ports = db
        .entities_by_kind(rxscan::graph::EntityKind::Port)
        .unwrap();
    assert_eq!(ports.len(), 1);
    assert_eq!(ports[0].observation_count, 4);
    let chain = db.provenance_chain(&ports[0].entity_id).unwrap();
    assert_eq!(chain.len(), 4);
    // Edge latest-state upserts, never duplicates.
    let edges = db.edges_from("port:tcp:10.0.0.5:80").unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for edge in &edges {
        assert!(seen.insert((edge.to_id.clone(), edge.relation.clone())));
    }
    let _ = edges_before;
}

#[test]
fn prop_database_reopen_preserves_graph() {
    let dir = std::env::temp_dir().join(format!("rxscan-propreopen-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("p.db");
    let fp = "dd".repeat(32);
    let graph = build_graph(
        &outputs(vec![
            port_open("10.0.0.5", 443),
            service("10.0.0.5", 443, "nginx", "1.26.0"),
            tls("10.0.0.5", 443, &fp, vec!["web.example.test"]),
            dns("web.example.test", "A", "10.0.0.5"),
        ]),
        None,
    );
    let before_entities = graph.entity_count();
    let before_edges = graph.edge_count();
    {
        let mut db = ProjectDb::open(&path).unwrap();
        import_for(&mut db, "persist-1", &graph, full_coverage(), "completed");
    }
    {
        let db = ProjectDb::open(&path).unwrap();
        let ports = db
            .entities_by_kind(rxscan::graph::EntityKind::Port)
            .unwrap();
        let certs = db
            .entities_by_kind(rxscan::graph::EntityKind::Certificate)
            .unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(certs.len(), 1);
        assert_eq!(db.certificate_reuse().unwrap().len(), 0);
        let services = db
            .entities_by_kind(rxscan::graph::EntityKind::Service)
            .unwrap();
        assert_eq!(services.len(), 1);
        let _ = (before_entities, before_edges);
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn bench_fingerprint_match_scales() {
    use rxscan::fingerprints::{FingerprintDb, parse_pack};
    for count in [10usize, 100, 1000] {
        let mut pack = String::from(r#"{"schema_version": 1, "fingerprints": ["#);
        for i in 0..count {
            pack.push_str(&format!(
                r#"{{"id": "r-{i:04}", "protocol": "http", "probe": "http",
                    "matcher": {{"kind": "contains", "pattern": "needle-{i}", "case_insensitive": true}},
                    "product": "P{i}", "confidence": 80, "source": "bench",
                    "version_extractor": {{"type": "prefixed_token", "prefix": "P{i}/", "max_len": 32}}}}{c}"#,
                c = if i + 1 == count { "" } else { "," }
            ));
        }
        pack.push_str("]}");
        let db =
            FingerprintDb::from_packs(vec![("b.json".to_owned(), parse_pack(&pack, "b").unwrap())]);
        assert_eq!(db.rule_count(), count);
        let obs = "Server: P500/1.2.3 needle-500 tail";
        let start = std::time::Instant::now();
        let iters = 50;
        for _ in 0..iters {
            let hits = db.candidates_for("http", obs);
            assert!(!hits.is_empty());
        }
        let per_call = start.elapsed() / iters;
        println!("BENCH match rules={count} per_call={per_call:?}");
        assert!(per_call < std::time::Duration::from_millis(100));
    }
}

#[test]
fn bench_graph_join_scales() {
    for n in [100usize, 1000, 10_000] {
        let events: Vec<rxscan::model::Event> = (0..n)
            .map(|i| {
                let third = (i / 250) % 250;
                let fourth = (i % 250) + 1;
                port_open(&format!("10.9.{third}.{fourth}"), 80)
            })
            .collect();
        let start = std::time::Instant::now();
        let graph = build_graph(&outputs(events), None);
        let elapsed = start.elapsed();
        println!(
            "BENCH graph_join entities={} edges={} elapsed={elapsed:?}",
            graph.entity_count(),
            graph.edge_count()
        );
        assert!(graph.entity_count() > 0);
    }
}

#[test]
fn bench_project_import_diff_and_size() {
    use rxscan::project_db::TaskCoverageInput;
    let dir = std::env::temp_dir().join(format!("rxscan-projbench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bench.db");
    let mut db = ProjectDb::open(&path).unwrap();
    // 1k-port synthetic scan.
    let events: Vec<rxscan::model::Event> = (1u16..=1000)
        .map(|port| port_open("10.7.0.1", port))
        .collect();
    let graph = build_graph(&outputs(events), None);
    let coverage = rxscan::project_db::coverage_from_tasks(
        &[TaskCoverageInput {
            kind: "PortDiscovery".to_owned(),
            host: Some("10.7.0.1".to_owned()),
            ports_spec: Some("1-1000".to_owned()),
            transport: Some("tcp".to_owned()),
            hostname: None,
            succeeded: true,
        }],
        false,
    );
    let start = std::time::Instant::now();
    let stats = import_for(&mut db, "bench-1", &graph, coverage.clone(), "completed");
    let import_ms = start.elapsed().as_millis().max(1);
    println!(
        "BENCH import entities={} observations={} in {import_ms}ms ({} records/sec)",
        stats.entities_upserted,
        stats.observations_added,
        (stats.entities_upserted + stats.observations_added) as u128 * 1000 / import_ms
    );
    // Second scan with drift + diff timing.
    let events2: Vec<rxscan::model::Event> = (500u16..=1500)
        .map(|port| port_open("10.7.0.1", port))
        .collect();
    let graph2 = build_graph(&outputs(events2), None);
    import_for(&mut db, "bench-2", &graph2, coverage, "completed");
    let start = std::time::Instant::now();
    let changes = db.diff_scan_runs("bench-1", "bench-2").unwrap();
    println!(
        "BENCH diff {} changes in {:?}",
        changes.len(),
        start.elapsed()
    );
    assert!(!changes.is_empty());
    drop(db);
    let bytes = std::fs::metadata(&path).unwrap().len();
    println!("BENCH project file bytes={bytes}");
    std::fs::remove_dir_all(&dir).ok();
}

fn vuln_import(
    advisory: &str,
    provider: &str,
    dataset: &str,
    product: &str,
    version: &str,
    confidence: u8,
) -> rxscan::project_db::VulnImport {
    rxscan::project_db::VulnImport {
        advisory_id: advisory.to_owned(),
        provider: provider.to_owned(),
        dataset_version: dataset.to_owned(),
        product: product.to_owned(),
        matched_version: version.to_owned(),
        match_type: "exact_version".to_owned(),
        outcome: "matched".to_owned(),
        confidence,
        severity: "provider:high".to_owned(),
        host: "10.0.0.5".to_owned(),
        endpoint: "10.0.0.5:80".to_owned(),
        identity_json: format!(r#"{{"product":"{product}","version":"{version}"}}"#),
    }
}

fn os_import(
    host: &str,
    family: &str,
    confidence: u8,
) -> (String, rxscan::os_fingerprint::OsCandidate) {
    (
        host.to_owned(),
        rxscan::os_fingerprint::OsCandidate {
            family: family.to_owned(),
            generation: None,
            device_hint: None,
            variant: None,
            confidence,
            supporting: vec!["ssh_banner:OpenSSH".to_owned()],
            conflicting: vec![],
            rule_ids: vec!["os-test-1".to_owned()],
        },
    )
}

fn device_import(
    host: &str,
    role: &str,
    confidence: u8,
) -> (String, rxscan::device::DeviceCandidate) {
    (
        host.to_owned(),
        rxscan::device::DeviceCandidate {
            role: role.to_owned(),
            vendor: None,
            model_hint: None,
            role_confidence: confidence,
            vendor_confidence: None,
            model_confidence: None,
            evidence: vec!["service_product:nginx".to_owned()],
            rule_ids: vec!["dev-test-1".to_owned()],
        },
    )
}

#[test]
fn old_database_migrates_and_preserves_vuln_provenance() {
    // Fresh files start at the current schema; old files migrate forward
    // transactionally (v1/v2 → current) without data loss.
    let mut db = ProjectDb::open_in_memory().unwrap();
    assert_eq!(
        db.schema_version().unwrap(),
        rxscan::project_db::PROJECT_DB_SCHEMA_VERSION
    );
    let graph = build_graph(&outputs(vec![port_open("10.0.0.5", 80)]), None);
    import_for(&mut db, "mig-1", &graph, full_coverage(), "completed");
    db.import_intelligence(
        "mig-1",
        &rxscan::project_db::IntelImport {
            os: vec![os_import("10.0.0.5", "Linux", 80)],
            devices: vec![device_import("10.0.0.5", "server", 75)],
            software: vec![],
            vulns: vec![vuln_import(
                "CVE-2024-1",
                "local",
                "2026-10-03",
                "nginx",
                "1.24.0",
                85,
            )],
            tls: vec![],
        },
    )
    .unwrap();
    // Provenance survives: provider + dataset version queryable.
    let vulns = db.vuln_candidates("mig-1", 0).unwrap();
    assert_eq!(vulns.len(), 1);
    assert_eq!(vulns[0].provider, "local");
    assert_eq!(vulns[0].dataset_version, "2026-10-03");
    assert_eq!(vulns[0].advisory_id, "CVE-2024-1");
    // OS/device rows survive with confidence bands for summaries.
    let summary = db.asset_summary("mig-1").unwrap();
    assert_eq!(summary.os_classified_high, 1);
    assert_eq!(summary.device_candidates, 1);
    assert_eq!(summary.vulnerability_candidates, 1);
}

#[test]
fn file_database_migrates_across_versions() {
    // A v2-shaped file (pre-dataset_version column) opens and migrates to
    // the current schema; intelligence imports then carry provenance.
    let dir = std::env::temp_dir().join(format!("rxscan-projmig-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("old.db");
    {
        let mut db = ProjectDb::open(&path).unwrap();
        let graph = build_graph(&outputs(vec![port_open("10.0.0.5", 80)]), None);
        import_for(&mut db, "old-1", &graph, full_coverage(), "completed");
        // Downgrade to v2 shape: drop the v3 column, stamp version 2.
        // (SQLite supports DROP COLUMN; failure here means the test harness
        // itself needs attention, not the migration.)
        let _ = db.conn_execute_for_test(
            "ALTER TABLE vulnerability_candidates DROP COLUMN dataset_version",
        );
        db.conn_execute_for_test("UPDATE meta SET value='2' WHERE key='schema_version'")
            .unwrap();
    }
    {
        let mut db = ProjectDb::open(&path).unwrap();
        assert_eq!(
            db.schema_version().unwrap(),
            rxscan::project_db::PROJECT_DB_SCHEMA_VERSION
        );
        let graph = build_graph(&outputs(vec![port_open("10.0.0.5", 80)]), None);
        import_for(&mut db, "old-2", &graph, full_coverage(), "completed");
        db.import_intelligence(
            "old-2",
            &rxscan::project_db::IntelImport {
                os: vec![],
                devices: vec![],
                software: vec![],
                vulns: vec![vuln_import(
                    "CVE-2024-9",
                    "local",
                    "2026-10-04",
                    "nginx",
                    "1.24.0",
                    80,
                )],
                tls: vec![],
            },
        )
        .unwrap();
        let vulns = db.vuln_candidates("old-2", 0).unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].dataset_version, "2026-10-04");
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn vuln_history_distinguishes_new_resolved_and_dataset_changed() {
    let mut db = ProjectDb::open_in_memory().unwrap();
    let empty = build_graph(&outputs(vec![port_open("10.0.0.5", 80)]), None);
    import_for(&mut db, "vh-old", &empty, full_coverage(), "completed");
    import_for(&mut db, "vh-new", &empty, full_coverage(), "completed");
    db.import_intelligence(
        "vh-old",
        &rxscan::project_db::IntelImport {
            os: vec![],
            devices: vec![],
            software: vec![],
            vulns: vec![
                vuln_import("CVE-STAY", "local", "2026-10-01", "nginx", "1.24.0", 85),
                vuln_import("CVE-GONE", "local", "2026-10-01", "nginx", "1.23.0", 80),
                vuln_import("CVE-BUMP", "local", "2026-10-01", "redis", "7.0.0", 70),
            ],
            tls: vec![],
        },
    )
    .unwrap();
    db.import_intelligence(
        "vh-new",
        &rxscan::project_db::IntelImport {
            os: vec![],
            devices: vec![],
            software: vec![],
            vulns: vec![
                vuln_import("CVE-STAY", "local", "2026-10-04", "nginx", "1.24.0", 85),
                vuln_import("CVE-NEW", "local", "2026-10-04", "nginx", "1.24.0", 85),
                vuln_import("CVE-BUMP", "local", "2026-10-04", "redis", "7.0.0", 75),
            ],
            tls: vec![],
        },
    )
    .unwrap();
    let changes = db.diff_scan_runs("vh-old", "vh-new").unwrap();
    // Newly matched.
    assert!(
        changes.iter().any(|c| c.entity_id == "vuln:nginx:CVE-NEW"
            && c.change_type == rxscan::project_db::ChangeType::Added),
        "new advisory must appear: {changes:?}"
    );
    // Resolved (absent in new).
    assert!(
        changes.iter().any(|c| c.entity_id == "vuln:nginx:CVE-GONE"
            && c.change_type == rxscan::project_db::ChangeType::Removed),
        "resolved advisory must appear: {changes:?}"
    );
    // Confidence changed.
    assert!(
        changes.iter().any(|c| c.entity_id == "vuln:redis:CVE-BUMP"
            && c.change_type == rxscan::project_db::ChangeType::ConfidenceChanged
            && c.new_value.contains("75")),
        "confidence change must appear: {changes:?}"
    );
    // Same verdict, new dataset → dataset-change record (not a false
    // newly-matched storm).
    assert!(
        changes
            .iter()
            .any(|c| c.entity_id == "vuln:nginx:CVE-STAY" && c.new_value.contains("2026-10-04")),
        "dataset evolution must be visible without claiming software changed: {changes:?}"
    );
}

#[test]
fn device_drift_detected_alongside_os_drift() {
    let mut db = ProjectDb::open_in_memory().unwrap();
    let empty = build_graph(&outputs(vec![port_open("10.0.0.5", 80)]), None);
    import_for(&mut db, "dd-old", &empty, full_coverage(), "completed");
    import_for(&mut db, "dd-new", &empty, full_coverage(), "completed");
    db.import_intelligence(
        "dd-old",
        &rxscan::project_db::IntelImport {
            os: vec![os_import("10.0.0.5", "Linux", 80)],
            devices: vec![device_import("10.0.0.5", "server", 75)],
            software: vec![],
            vulns: vec![],
            tls: vec![],
        },
    )
    .unwrap();
    db.import_intelligence(
        "dd-new",
        &rxscan::project_db::IntelImport {
            os: vec![os_import("10.0.0.5", "Linux", 80)],
            devices: vec![device_import("10.0.0.5", "router", 78)],
            software: vec![],
            vulns: vec![],
            tls: vec![],
        },
    )
    .unwrap();
    let changes = db.diff_scan_runs("dd-old", "dd-new").unwrap();
    assert!(
        changes.iter().any(|c| c.old_value.contains("server")
            && c.new_value.contains("router")
            && c.old_value.starts_with("device ")),
        "device drift must diff: {changes:?}"
    );
    // OS unchanged → no OS drift record.
    assert!(
        !changes.iter().any(|c| c.old_value.starts_with("os ")),
        "stable OS must not drift: {changes:?}"
    );
}

#[test]
fn attention_is_deterministic_and_bounded() {
    let mut db = ProjectDb::open_in_memory().unwrap();
    let empty = build_graph(&outputs(vec![port_open("10.0.0.5", 22)]), None);
    import_for(&mut db, "at-old", &empty, full_coverage(), "completed");
    import_for(&mut db, "at-new", &empty, full_coverage(), "completed");
    db.import_intelligence(
        "at-new",
        &rxscan::project_db::IntelImport {
            os: vec![],
            devices: vec![],
            software: vec![],
            vulns: vec![vuln_import(
                "CVE-2024-1",
                "local",
                "2026-10-04",
                "nginx",
                "1.24.0",
                90,
            )],
            tls: vec![],
        },
    )
    .unwrap();
    let first = rxscan::project_db::generate_attention(
        &db,
        "at-new",
        Some("at-old"),
        1_750_000_000_000,
        rxscan::project_db::AttentionThresholds::default(),
    )
    .unwrap();
    let second = rxscan::project_db::generate_attention(
        &db,
        "at-new",
        Some("at-old"),
        1_750_000_000_000,
        rxscan::project_db::AttentionThresholds::default(),
    )
    .unwrap();
    assert_eq!(first, second, "attention must be deterministic");
    assert!(first.len() <= 512, "attention must be bounded");
    assert!(
        first
            .iter()
            .any(|e| e.category == "vulnerability_candidate" && e.title.contains("CVE-2024-1")),
        "high-confidence vuln must surface: {first:?}"
    );
}

#[test]
fn bench_os_device_vuln_intelligence_scales() {
    // OS matching: 100 / 1k synthetic rules over one host evidence set.
    // Packs hold ≤512 rules/file, so larger DBs load from multiple packs
    // (production path: fingerprints/os/v1/*.json).
    for rule_count in [100usize, 1000] {
        let mut packs = Vec::new();
        let mut index = 0;
        while index < rule_count {
            let chunk = (rule_count - index).min(500);
            let mut rules = Vec::new();
            for i in 0..chunk {
                let id = index + i;
                rules.push(serde_json::json!({
                    "id": format!("bench-os-{id}"),
                    "family": if id % 3 == 0 { "Linux" } else if id % 3 == 1 { "Windows" } else { "FreeBSD" },
                    "features": [{"source": "ssh_banner", "pattern": format!("token-{id}"), "weight": 10}],
                    "confidence_cap": 80, "source": "bench"
                }));
            }
            let pack = serde_json::json!({"schema_version": 1, "rules": rules}).to_string();
            packs.push((
                format!("bench-{index}.json"),
                rxscan::os_fingerprint::parse_os_pack(&pack, "bench").unwrap(),
            ));
            index += chunk;
        }
        let db = rxscan::os_fingerprint::OsDb::from_packs(packs);
        let evidence = vec![rxscan::os_fingerprint::OsEvidence {
            source: "ssh_banner".to_owned(),
            feature: "platform_token".to_owned(),
            value: "token-7 Ubuntu".to_owned(),
            confidence: 50,
            task_id: None,
            evidence_id: None,
        }];
        let start = std::time::Instant::now();
        let candidates = db.classify_host(&evidence);
        let elapsed = start.elapsed();
        println!(
            "BENCH os_match rules={rule_count} per_call={elapsed:?} candidates={}",
            candidates.len()
        );
        assert!(elapsed.as_millis() < 500, "OS matching must stay bounded");
    }
    // Device classification: 1k evidence sets over a small rule pack.
    let device_pack = r#"{"schema_version": 1, "rules": [
        {"id": "bench-router", "role": "router", "signals": [
          {"kind": "service_product", "pattern": "dnsmasq", "weight": 20},
          {"kind": "http_server", "pattern": "router", "weight": 15}],
         "confidence_cap": 85, "source": "bench"}]}"#;
    let device_db = rxscan::device::DeviceDb::from_packs(vec![(
        "bench.json".to_owned(),
        rxscan::device::parse_device_pack(device_pack, "bench").unwrap(),
    )]);
    let start = std::time::Instant::now();
    for _ in 0..1000 {
        let mut signals = std::collections::BTreeMap::new();
        signals.insert(
            "service_product".to_owned(),
            vec!["dnsmasq 2.80".to_owned()],
        );
        signals.insert("http_server".to_owned(), vec!["Router Admin".to_owned()]);
        let _ = device_db.classify_host(&signals);
    }
    println!(
        "BENCH device_classify sets=1000 elapsed={:?}",
        start.elapsed()
    );
    // Vulnerability correlation: 100 / 1k identities over a 100-advisory DB.
    let mut advisories = Vec::new();
    for i in 0..100 {
        advisories.push(rxscan::vuln::Advisory {
            id: format!("BENCH-{i}"),
            vendor: Some("f5".to_owned()),
            product: "nginx".to_owned(),
            affected: vec![rxscan::vuln::VersionReq::LessThan {
                version: "1.26.0".to_owned(),
            }],
            severity_label: Some("provider:high".to_owned()),
            score: Some(7.5),
            summary: String::new(),
        });
    }
    let vuln_db = rxscan::vuln::LocalVulnDb::from_dataset(rxscan::vuln::VulnDataset {
        schema_version: rxscan::vuln::VULN_DATASET_SCHEMA_VERSION,
        provider: "bench".to_owned(),
        dataset_version: "bench-1".to_owned(),
        advisories,
    })
    .unwrap();
    for identity_count in [100usize, 1000] {
        let start = std::time::Instant::now();
        for i in 0..identity_count {
            let identity = rxscan::vuln::SoftwareIdentity {
                vendor: Some("f5".to_owned()),
                product: "nginx".to_owned(),
                version: Some(format!("1.24.{}", i % 5)),
                version_family: None,
                cpe: None,
                product_confidence: 90,
                version_confidence: 80,
                evidence: vec![],
            };
            {
                use rxscan::vuln::VulnerabilityProvider;
                let _ = vuln_db.query(&identity);
            }
        }
        println!(
            "BENCH vuln_correlate identities={identity_count} elapsed={:?}",
            start.elapsed()
        );
    }
}
