//! Phase 3 diff timeline: run-to-run statuses, coverage honesty, API, GUI.
//!
//! Synthetic/reserved values only. The coverage test plants an entity
//! that vanishes WITHOUT coverage and proves it is `not_covered` (gray),
//! never `removed` (red).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

use rxscan::execution::TaskId;
use rxscan::graph::build_graph;
use rxscan::model::{
    BoundedDetails, Event, EventKind, MAX_EVENT_DETAILS_BYTES, Provenance, ScanPlanId, Timestamp,
};
use rxscan::project_db::{
    ClassifierProvenance, CoverageSnapshot, ProjectDb, RetentionMode, ScanImport, TOOL_VERSION,
};
use rxscan::project_diff::{DiffStatus, diff_scans};

fn provenance() -> Provenance {
    Provenance::new(
        "test.module",
        "1.0.0",
        ScanPlanId("plan_diff_test".to_owned()),
        Timestamp(7),
    )
    .unwrap()
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

fn port_open(ip: &str, port: u16) -> Event {
    event(
        EventKind::PortOpen,
        serde_json::json!({"target": ip, "address": ip, "transport": "tcp", "port": port}),
    )
}

fn service(ip: &str, port: u16, version: &str) -> Event {
    event(
        EventKind::ServiceIdentified,
        serde_json::json!({
            "target": ip, "address": ip, "port": port,
            "protocol": "ssh", "service": "ssh",
            "product_hint": "OpenSSH", "version_hint": version,
            "confidence": 80u64, "matcher": "ssh",
        }),
    )
}

fn dns_a(name: &str, value: &str) -> Event {
    event(
        EventKind::DnsRecordObserved,
        serde_json::json!({"name": name, "record_type": "A", "value": value}),
    )
}

fn coverage(
    hosts: Vec<&str>,
    tcp: Vec<(&str, Vec<(u16, u16)>)>,
    dns: Vec<&str>,
) -> CoverageSnapshot {
    CoverageSnapshot {
        hosts_attempted: hosts.into_iter().map(str::to_owned).collect(),
        tcp_attempted: tcp
            .into_iter()
            .map(|(host, ranges)| (host.to_owned(), ranges))
            .collect(),
        udp_attempted: BTreeMap::new(),
        dns_queried: dns.into_iter().map(str::to_owned).collect(),
        modules_completed: vec!["PortDiscovery".to_owned(), "DnsProbe".to_owned()],
        truncated: false,
    }
}

fn import(db: &mut ProjectDb, scan_id: &str, events: Vec<Event>, coverage: CoverageSnapshot) {
    let graph = build_graph(
        &[(
            TaskId(format!("task_{scan_id}")),
            rxscan::execution::ModuleOutput {
                events,
                ..rxscan::execution::ModuleOutput::default()
            },
        )],
        None,
    );
    db.import_scan(
        &ScanImport {
            scan_id: scan_id.to_owned(),
            plan_id: "plan_diff_test".to_owned(),
            started_at_ms: 1,
            finished_at_ms: 2,
            scope_json: r#"{"allow":["192.0.2.0/24"]}"#.to_owned(),
            workflow: "recon".to_owned(),
            level: 3,
            termination: "completed".to_owned(),
            tasks_admitted: 4,
            tasks_completed: 4,
            coverage,
            classifier: ClassifierProvenance {
                tool_version: TOOL_VERSION.to_owned(),
                packs: vec![],
                rules_used: vec![],
            },
            retention: RetentionMode::Standard,
        },
        &graph,
    )
    .expect("import succeeds");
}

/// Scan A: broad. Scan B: port 80 closed (but covered), port 443 new,
/// SSH version changed, 192.0.2.99 no longer attempted at all.
fn fixture_db(path: &std::path::Path) -> ProjectDb {
    let mut db = ProjectDb::open(path).expect("create");
    import(
        &mut db,
        "scan-a",
        vec![
            port_open("192.0.2.10", 80),
            port_open("192.0.2.10", 22),
            port_open("192.0.2.99", 80),
            service("192.0.2.10", 22, "9.0"),
            dns_a("example.test", "192.0.2.10"),
        ],
        coverage(
            vec!["192.0.2.10", "192.0.2.99"],
            vec![
                ("192.0.2.10", vec![(1, 1000)]),
                ("192.0.2.99", vec![(1, 1000)]),
            ],
            vec!["example.test"],
        ),
    );
    import(
        &mut db,
        "scan-b",
        vec![
            port_open("192.0.2.10", 443),
            port_open("192.0.2.10", 22),
            service("192.0.2.10", 22, "9.1"),
            dns_a("example.test", "192.0.2.10"),
        ],
        coverage(
            vec!["192.0.2.10"],
            vec![("192.0.2.10", vec![(1, 1000)])],
            vec!["example.test"],
        ),
    );
    db
}

fn tmp_db(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("rxscan-diff3-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("proj.db");
    fixture_db(&path);
    path
}

fn status_of(rows: &[rxscan::project_diff::EntityDiff], id: &str) -> Option<DiffStatus> {
    rows.iter()
        .find(|row| row.entity_id == id)
        .map(|row| row.status)
}

#[test]
fn coverage_gap_is_not_covered_never_removed() {
    let path = tmp_db("core");
    let db = ProjectDb::open(&path).unwrap();
    let diff = diff_scans(&db, "scan-a", "scan-b", 500).expect("diff computes");
    // New port with no history is added (green).
    assert_eq!(
        status_of(&diff.rows, "port:tcp:192.0.2.10:443"),
        Some(DiffStatus::Added)
    );
    // Port 80 was covered by scan B's attempted range but unobserved:
    // confirmed removal (red).
    assert_eq!(
        status_of(&diff.rows, "port:tcp:192.0.2.10:80"),
        Some(DiffStatus::Removed)
    );
    // 192.0.2.99 was never attempted by scan B: NOT covered, so it must
    // be gray inconclusive — never presented as a deletion.
    assert_eq!(
        status_of(&diff.rows, "ip:192.0.2.99"),
        Some(DiffStatus::NotCovered)
    );
    assert_eq!(
        status_of(&diff.rows, "port:tcp:192.0.2.99:80"),
        Some(DiffStatus::NotCovered)
    );
    for row in &diff.rows {
        if row.entity_id.contains("192.0.2.99") {
            assert_ne!(
                row.status,
                DiffStatus::Removed,
                "coverage gap shown as removed: {}",
                row.entity_id
            );
        }
    }
    // SSH version bump on a still-open port is a change (amber).
    let ssh_changed = diff.rows.iter().any(|row| {
        row.entity_id.starts_with("service:port:tcp:192.0.2.10:22")
            && row.status == DiffStatus::Changed
    });
    assert!(ssh_changed, "version change must surface as changed");
    // Unchanged DNS observation is counted, not rowed.
    assert!(diff.summary.unchanged >= 1);
    assert!(!diff.truncated);
    assert!(diff.summary.not_covered >= 2);
    assert_eq!(diff.summary.removed, 1);
}

#[test]
fn truncated_runs_confirm_nothing() {
    let dir = std::env::temp_dir().join(format!("rxscan-diff3-{}-trunc", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("proj.db");
    let mut db = ProjectDb::open(&path).unwrap();
    import(
        &mut db,
        "scan-a",
        vec![port_open("192.0.2.10", 80)],
        coverage(
            vec!["192.0.2.10"],
            vec![("192.0.2.10", vec![(1, 1000)])],
            vec![],
        ),
    );
    let mut cov = coverage(
        vec!["192.0.2.10"],
        vec![("192.0.2.10", vec![(1, 1000)])],
        vec![],
    );
    cov.truncated = true;
    import(&mut db, "scan-b", vec![], cov);
    let diff = diff_scans(&db, "scan-a", "scan-b", 500).unwrap();
    assert_eq!(
        status_of(&diff.rows, "port:tcp:192.0.2.10:80"),
        Some(DiffStatus::NotCovered)
    );
    assert_eq!(diff.summary.removed, 0);
}

#[test]
fn unknown_scans_are_typed_errors() {
    let path = tmp_db("errors");
    let db = ProjectDb::open(&path).unwrap();
    assert!(diff_scans(&db, "nope", "scan-b", 10).is_err());
    assert!(diff_scans(&db, "scan-a", "nope", 10).is_err());
    let same = diff_scans(&db, "scan-a", "scan-a", 500).unwrap();
    assert_eq!(same.summary.added, 0);
    assert_eq!(same.summary.removed, 0);
    assert_eq!(same.summary.not_covered, 0);
}

// ---------------------------------------------------------------------------
// API + GUI wiring.
// ---------------------------------------------------------------------------

struct Server {
    base: String,
    data_dir: std::path::PathBuf,
    owned: Option<Box<rxscan::web_api::ServerHandle>>,
}

impl Server {
    fn start(db_path: &std::path::Path) -> Self {
        let data_dir = db_path.parent().unwrap().join("srv");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::copy(db_path, data_dir.join("g.db")).unwrap();
        let handle = rxscan::web_api::serve(rxscan::web_api::WebOptions {
            bind: "127.0.0.1".to_owned(),
            port: 0,
            data_dir: data_dir.clone(),
            allow_remote: false,
            fixture_investigation: true,
        })
        .expect("server binds");
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
        Self {
            base,
            data_dir,
            owned: Some(Box::new(handle)),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(handle) = self.owned.take() {
            handle.shutdown();
        }
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

fn get(server: &Server, path: &str) -> (u16, serde_json::Value) {
    let addr = server.base.trim_start_matches("http://").to_owned();
    let mut stream = TcpStream::connect(&addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("head");
    let status: u16 = String::from_utf8_lossy(&raw[..split])
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&raw[split + 4..]).unwrap_or(serde_json::Value::Null);
    (status, body)
}

#[test]
fn api_diff_serves_masked_statuses() {
    let path = tmp_db("api");
    let server = Server::start(&path);
    let (status, diff) = get(
        &server,
        "/api/v1/projects/g/diff?old=scan-a&new=scan-b&limit=500",
    );
    assert_eq!(status, 200, "diff: {diff}");
    let rows = diff["rows"].as_array().unwrap();
    assert!(!rows.is_empty());
    let statuses: Vec<&str> = rows
        .iter()
        .map(|row| row["status"].as_str().unwrap())
        .collect();
    assert!(statuses.contains(&"added"));
    assert!(statuses.contains(&"removed"));
    assert!(statuses.contains(&"not_covered"));
    // No row may present a coverage gap as removed.
    for row in rows {
        if row["entity_id"].as_str().unwrap().contains("192.0.2.99") {
            assert_eq!(row["status"], "not_covered");
        }
    }
    let (status, _) = get(&server, "/api/v1/projects/g/diff?old=nope&new=scan-b");
    assert_eq!(status, 404);
    let (status, _) = get(&server, "/api/v1/projects/g/diff?old=scan-a");
    assert_eq!(status, 400);
}

#[test]
fn gui_timeline_slider_is_wired() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let html = std::fs::read_to_string(manifest.join("app/index.html")).unwrap();
    let js = std::fs::read_to_string(manifest.join("app/rxscan.js")).unwrap();
    for id in [
        "p-diff-old",
        "p-diff-new",
        "p-diff-slider",
        "p-diff-apply",
        "p-diff-clear",
        "p-diff-summary",
        "p-diff-list",
    ] {
        assert!(
            html.contains(&format!("id=\"{id}\"")),
            "html must define #{id}"
        );
        assert!(js.contains(id), "js must reference {id}");
    }
    // Slider moves between runs; statuses use words, never color alone.
    assert!(js.contains("/diff?old="));
    assert!(js.contains("setStatusColors"));
    assert!(js.contains("not covered (inconclusive)"));
    assert!(js.contains("is never red") || js.contains("never red"));
}
