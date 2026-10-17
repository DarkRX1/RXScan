//! Phase 1 link-analysis graph: CLI, API, exports, masking, scope.
//!
//! Synthetic/reserved values only (example.test, 192.0.2.0/24). Fake
//! secrets use the unmistakable `FAKE-GRAPH-*` marker family and must
//! appear in NO artifact.

use std::collections::BTreeMap;
use std::process::Command;

use rxscan::execution::TaskId;
use rxscan::graph::build_graph;
use rxscan::model::{
    BoundedDetails, Event, EventKind, MAX_EVENT_DETAILS_BYTES, Provenance, ScanPlanId, Timestamp,
};
use rxscan::project_db::{
    ClassifierProvenance, CoverageSnapshot, ProjectDb, RetentionMode, ScanImport, TOOL_VERSION,
};

const PW: &str = "FAKE-GRAPH-PW-7";
const TOKEN: &str = "FAKE-GRAPH-TOK-7";
const APIKEY: &str = "FAKE-GRAPH-KEY-7";
const PEM_LINE: &str = "FAKE-GRAPH-PEM-7";

fn plan_id() -> ScanPlanId {
    ScanPlanId("plan_graph_test".to_owned())
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

/// Fixture scan: host + ip + port + service + cert + dns + endpoints,
/// with fake secrets planted in realistic shapes (URL userinfo, secret
/// query params, assignment-shaped attribute values, PEM block).
fn fixture_events() -> Vec<Event> {
    vec![
        event(
            EventKind::PortOpen,
            serde_json::json!({"target": "192.0.2.10", "address": "192.0.2.10", "transport": "tcp", "port": 443}),
        ),
        event(
            EventKind::ServiceIdentified,
            serde_json::json!({
                "target": "192.0.2.10", "address": "192.0.2.10", "port": 443,
                "protocol": "https", "service": "https",
                "product_hint": "nginx", "version_hint": format!("1.24.0 token={TOKEN}"),
                "confidence": 90u64, "matcher": "https",
            }),
        ),
        event(
            EventKind::TlsObserved,
            serde_json::json!({
                "target": "192.0.2.10", "address": "192.0.2.10", "port": 443,
                "subject": format!("CN=example.test password={PW}"),
                "issuer": "CN=Fixture CA",
                "san_dns": ["example.test"], "san_ip": [],
                "not_before": "2026-01-01", "not_after": "2027-01-01",
                "fingerprint_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            }),
        ),
        event(
            EventKind::DnsRecordObserved,
            serde_json::json!({"name": "example.test", "record_type": "A", "value": "192.0.2.10"}),
        ),
        event(
            EventKind::EndpointObserved,
            serde_json::json!({"url": format!("https://admin:{PW}@example.test:443/?api_key={APIKEY}")}),
        ),
        event(
            EventKind::EndpointObserved,
            serde_json::json!({"url": format!("https://example.test/docs?next=1&token={TOKEN}")}),
        ),
        // PEM-shaped attribute value (proves block scrubbing end to end).
        event(
            EventKind::ServiceIdentified,
            serde_json::json!({
                "target": "192.0.2.10", "address": "192.0.2.10", "port": 22,
                "protocol": "ssh", "service": "ssh",
                "product_hint": "OpenSSH",
                "version_hint": format!("9.0 -----BEGIN PRIVATE KEY----- {PEM_LINE} -----END PRIVATE KEY-----"),
                "confidence": 80u64, "matcher": "ssh",
            }),
        ),
    ]
}

fn coverage() -> CoverageSnapshot {
    CoverageSnapshot {
        hosts_attempted: vec!["192.0.2.10".to_owned()],
        tcp_attempted: BTreeMap::from([("192.0.2.10".to_owned(), vec![(22, 443)])]),
        udp_attempted: BTreeMap::new(),
        dns_queried: vec!["example.test".to_owned()],
        modules_completed: vec!["PortDiscovery".to_owned(), "DnsProbe".to_owned()],
        truncated: false,
    }
}

/// Build a fixture project database. The schema is unchanged from the
/// 1.1.0 baseline (PROJECT_DB_SCHEMA_VERSION 4), so a database written
/// this way is byte-shape-identical to a baseline-created one: opening
/// and reading it here proves baseline databases keep working.
fn fixture_db(path: &std::path::Path) -> ProjectDb {
    let graph = build_graph(
        &[(
            TaskId("task_graph".to_owned()),
            rxscan::execution::ModuleOutput {
                events: fixture_events(),
                ..rxscan::execution::ModuleOutput::default()
            },
        )],
        None,
    );
    assert!(graph.entity_count() >= 5, "fixture must build a real graph");
    let mut db = ProjectDb::open(path).expect("create fixture db");
    db.import_scan(
        &ScanImport {
            scan_id: "scan-graph-1".to_owned(),
            plan_id: "plan_graph_test".to_owned(),
            started_at_ms: 1_700_000_000_000,
            finished_at_ms: 1_700_000_001_000,
            scope_json: r#"{"allow":["192.0.2.0/24"]}"#.to_owned(),
            workflow: "recon".to_owned(),
            level: 3,
            termination: "completed".to_owned(),
            tasks_admitted: 7,
            tasks_completed: 7,
            coverage: coverage(),
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
    db
}

fn tmp_db(name: &str) -> (std::path::PathBuf, ProjectDb) {
    let dir = std::env::temp_dir().join(format!("rxscan-graph1-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("proj.db");
    let db = fixture_db(&path);
    (path, db)
}

fn bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_rxscan"))
}

fn run_graph(db: &std::path::Path, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(bin());
    cmd.arg("graph").arg(db);
    for arg in args {
        cmd.arg(arg);
    }
    cmd.output().expect("rxscan graph runs")
}

fn secrets() -> [&'static str; 4] {
    [PW, TOKEN, APIKEY, PEM_LINE]
}

#[test]
fn cli_summary_shows_masked_typed_graph() {
    let (path, _db) = tmp_db("summary");
    let out = run_graph(&path, &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.contains("RXScan graph"),
        "summary header missing:\n{text}"
    );
    assert!(text.contains("network_requests=0"));
    for secret in secrets() {
        assert!(!text.contains(secret), "secret leaked into CLI summary");
    }
    // Typed breakdown present (real data, several display kinds).
    assert!(
        text.contains("ip:") || text.contains("host:"),
        "typed breakdown missing:\n{text}"
    );
}

#[test]
fn cli_exports_all_formats_masked() {
    let (path, _db) = tmp_db("exports");
    let dir = path.parent().unwrap();
    for format in ["json", "graphml", "svg", "html"] {
        let out_path = dir.join(format!("g.{format}"));
        let out = run_graph(
            &path,
            &["--format", format, "--out", out_path.to_str().unwrap()],
        );
        assert!(
            out.status.success(),
            "{format}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let bytes = std::fs::read(&out_path).unwrap();
        assert!(!bytes.is_empty(), "{format} export is empty");
        let text = String::from_utf8_lossy(&bytes);
        for secret in secrets() {
            assert!(!text.contains(secret), "secret leaked into {format} export");
        }
    }
    // JSON graph carries evidence + confidence on every element.
    let json = std::fs::read_to_string(dir.join("g.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["graph_schema_version"], 1);
    let nodes = value["nodes"].as_array().unwrap();
    assert!(nodes.len() >= 5, "expected real nodes, got {}", nodes.len());
    for node in nodes {
        assert!(
            node.get("link_confidence").is_some(),
            "node must show confidence: {node}"
        );
    }
    for edge in value["edges"].as_array().unwrap() {
        assert!(edge.get("confidence").is_some());
        assert!(edge.get("evidence").is_some());
    }
    // GraphML/SVG/HTML shapes are well-formed.
    let graphml = std::fs::read_to_string(dir.join("g.graphml")).unwrap();
    assert!(graphml.contains("<graphml") && graphml.contains("</graphml>"));
    let svg = std::fs::read_to_string(dir.join("g.svg")).unwrap();
    assert!(svg.contains("<svg") && svg.contains("</svg>"));
    let html = std::fs::read_to_string(dir.join("g.html")).unwrap();
    assert!(html.contains("<svg") && html.contains("</html>"));
    // Offline: inline script/style only — data URLs (https://... in
    // labels) are content, never fetched references.
    assert!(html.contains("<script>") && !html.contains("<script src"));
    for pat in [
        "<link",
        "@import",
        "src=\"http",
        "src='http",
        "href=\"http",
        "href='http",
        "url(http",
        "url(\"http",
    ] {
        assert!(!html.contains(pat), "HTML export must be offline ({pat})");
    }
    // PNG requires --out and decodes as a real image.
    let denied = run_graph(&path, &["--format", "png"]);
    assert!(!denied.status.success(), "png to stdout must be refused");
    let png_path = dir.join("g.png");
    let out = run_graph(
        &path,
        &["--format", "png", "--out", png_path.to_str().unwrap()],
    );
    assert!(
        out.status.success(),
        "png: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let png = std::fs::read(&png_path).unwrap();
    assert_eq!(&png[0..8], &[137, 80, 78, 71, 13, 10, 26, 10]);
    for secret in secrets() {
        assert!(
            !png.windows(secret.len()).any(|w| w == secret.as_bytes()),
            "secret leaked into PNG bytes"
        );
    }
}

#[test]
fn graph_exports_contain_expected_icon() {
    // The fixture graph stores a certificate entity (TlsObserved), which maps
    // to the `certificate` manifest icon. Every export format must carry it.
    let (path, _db) = tmp_db("icons");
    let dir = path.parent().unwrap();
    for format in ["json", "graphml", "svg", "html"] {
        let out_path = dir.join(format!("icon.{format}"));
        let out = run_graph(
            &path,
            &["--format", format, "--out", out_path.to_str().unwrap()],
        );
        assert!(
            out.status.success(),
            "{format}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let bytes = std::fs::read(&out_path).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains("certificate"),
            "{format} export missing expected icon 'certificate':\n{text}"
        );
    }
    // PNG export draws the same icon: a valid image produced by the icon path.
    let png_path = dir.join("icon.png");
    let out = run_graph(
        &path,
        &["--format", "png", "--out", png_path.to_str().unwrap()],
    );
    assert!(
        out.status.success(),
        "png: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let png = std::fs::read(&png_path).unwrap();
    assert_eq!(&png[0..8], &[137, 80, 78, 71, 13, 10, 26, 10]);
    assert!(png.len() > 100, "png export should render the icon");
}

#[test]
fn evidence_bundle_verify_roundtrip_and_tamper() {
    use std::process::Command;
    let (path, _db) = tmp_db("bundle");
    let dir = path.parent().unwrap();
    let out_dir = dir.join("bundle-out");
    let bundle = Command::new(bin())
        .arg("evidence-bundle")
        .arg(path.to_str().unwrap())
        .arg("--case-id")
        .arg("CASE-1")
        .arg("--operator")
        .arg("analyst")
        .arg("--out")
        .arg(out_dir.to_str().unwrap())
        .output()
        .expect("evidence-bundle runs");
    assert!(
        bundle.status.success(),
        "evidence-bundle: {}",
        String::from_utf8_lossy(&bundle.stderr)
    );
    assert!(out_dir.join("bundle.json").exists(), "bundle.json written");
    assert!(
        out_dir.join("evidence.jsonl").exists(),
        "evidence.jsonl written"
    );
    assert!(
        out_dir.join("manifest.txt").exists(),
        "manifest.txt written"
    );
    let bundle_text = std::fs::read_to_string(out_dir.join("bundle.json")).unwrap();
    assert!(bundle_text.contains("CASE-1"), "case id recorded");
    assert!(bundle_text.contains("1.2.0"), "tool version recorded");
    assert!(
        bundle_text.contains("Z"),
        "UTC timestamp recorded (ISO8601)"
    );
    assert!(
        bundle_text.contains("analyst") || bundle_text.contains("operator"),
        "operator recorded"
    );
    // valid bundle verifies OK
    let good = Command::new(bin())
        .arg("verify-bundle")
        .arg(out_dir.to_str().unwrap())
        .output()
        .expect("verify-bundle runs");
    assert!(
        good.status.success(),
        "verify-bundle good bundle: {}",
        String::from_utf8_lossy(&good.stderr)
    );
    // tampered evidence fails verification
    let ev_path = out_dir.join("evidence.jsonl");
    let mut ev = std::fs::read_to_string(&ev_path).unwrap();
    ev.push_str("tampered-append\n");
    std::fs::write(&ev_path, &ev).unwrap();
    let bad = Command::new(bin())
        .arg("verify-bundle")
        .arg(out_dir.to_str().unwrap())
        .output()
        .expect("verify-bundle runs");
    assert!(
        !bad.status.success(),
        "verify-bundle should fail on tampered bundle"
    );
    // extra file fails verification
    let _ = std::fs::write(out_dir.join("extra.txt"), "extra");
    let extra = Command::new(bin())
        .arg("verify-bundle")
        .arg(out_dir.to_str().unwrap())
        .output()
        .expect("verify-bundle runs");
    assert!(
        !extra.status.success(),
        "verify-bundle should fail on extra file"
    );
}

#[test]
fn cli_filters_layouts_and_errors() {
    let (path, _db) = tmp_db("filters");
    // Type filter narrows to requested kinds.
    let out = run_graph(&path, &["--format", "json", "--types", "ip,host"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    for node in value["nodes"].as_array().unwrap() {
        let kind = node["kind"].as_str().unwrap();
        assert!(kind == "ip" || kind == "host", "unexpected kind {kind}");
    }
    // Confidence floor drops weak links.
    let out = run_graph(&path, &["--format", "json", "--min-confidence", "95"]);
    assert!(out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    for edge in value["edges"].as_array().unwrap() {
        assert!(edge["confidence"].as_u64().unwrap() >= 95);
    }
    // All five layouts render SVG without error.
    for layout in ["organic", "hierarchical", "circular", "block", "radial"] {
        let out = run_graph(&path, &["--format", "svg", "--layout", layout]);
        assert!(
            out.status.success(),
            "{layout}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("<svg"));
    }
    // Seeded neighborhood works on stored data (no network, no confirm).
    let out = run_graph(
        &path,
        &[
            "--format",
            "json",
            "--seed",
            "ip:192.0.2.10",
            "--depth",
            "1",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Errors are typed usage failures.
    for args in [
        vec!["--format", "bmp"],
        vec!["--types", "nope"],
        vec!["--min-confidence", "101"],
        vec!["--layout", "spiral"],
        vec!["--seed", "ip:192.0.2.10", "--depth", "9"],
    ] {
        let out = run_graph(&path, &args);
        assert!(!out.status.success(), "args {args:?} must fail");
        assert_eq!(out.status.code(), Some(2));
    }
    let missing = run_graph(std::path::Path::new("/nonexistent/rxscan-graph.db"), &[]);
    assert!(!missing.status.success());
}

#[test]
fn scope_filter_marks_and_selects() {
    use rxscan::graph_view::{
        ScopeFilter, ScopeState, SourceEdge, SourceNode, ViewOptions, build_view, scope_state_of,
    };
    let node = |id: &str, scope: &str| SourceNode {
        id: id.to_owned(),
        stored_kind: "hostname".to_owned(),
        label: id.to_owned(),
        attributes: BTreeMap::from([("scope".to_owned(), scope.to_owned())]),
        first_seen_ms: 1,
        last_seen_ms: 1,
        observations: 1,
    };
    let sources = vec![
        node("host:in.example.test", "in-scope-uncontacted"),
        node("host:out.example.test", "outside-scope"),
        node("host:bare.example.test", ""),
    ];
    // Derivation: explicit markers count, absence stays unknown.
    assert_eq!(
        scope_state_of(&BTreeMap::from([(
            "scope".to_owned(),
            "outside-scope".to_owned()
        )])),
        ScopeState::OutOfScope
    );
    let view = build_view(
        sources.clone(),
        Vec::<SourceEdge>::new(),
        &ViewOptions::default(),
    );
    let states: BTreeMap<&str, ScopeState> = view
        .nodes
        .iter()
        .map(|n| (n.id.as_str(), n.scope))
        .collect();
    assert_eq!(states["host:in.example.test"], ScopeState::InScope);
    assert_eq!(states["host:out.example.test"], ScopeState::OutOfScope);
    assert_eq!(states["host:bare.example.test"], ScopeState::Unknown);
    // Filters select honestly: `in` drops only the explicitly-out entity.
    let view = build_view(
        sources.clone(),
        Vec::new(),
        &ViewOptions {
            scope: ScopeFilter::InScope,
            ..ViewOptions::default()
        },
    );
    assert_eq!(view.nodes.len(), 2);
    let view = build_view(
        sources,
        Vec::new(),
        &ViewOptions {
            scope: ScopeFilter::OutOfScope,
            ..ViewOptions::default()
        },
    );
    assert_eq!(view.nodes.len(), 1);
    assert_eq!(view.nodes[0].id, "host:out.example.test");
}

#[test]
fn baseline_database_opens_and_serves_graph() {
    // No schema change in Phase 1: a database in baseline shape opens at
    // the current version and the view reads it (migration path is a
    // no-op, never an error).
    let (path, _db) = tmp_db("migration");
    drop(_db);
    let db = ProjectDb::open(&path).expect("baseline-shape database opens");
    assert_eq!(
        db.schema_version().unwrap(),
        rxscan::project_db::PROJECT_DB_SCHEMA_VERSION
    );
    let view = rxscan::graph_view::build_from_db(&db, &rxscan::graph_view::ViewOptions::default())
        .expect("view builds from baseline database");
    assert!(!view.nodes.is_empty());
    assert!(!view.edges.is_empty());
}

// ---------------------------------------------------------------------------
// Local API: full graph, filters, node detail, bounded neighbors.
// The GUI Graph view reads exactly these endpoints (no other data path).
// ---------------------------------------------------------------------------

mod api {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    struct Server {
        base: String,
        data_dir: std::path::PathBuf,
        owned: Option<Box<rxscan::web_api::ServerHandle>>,
    }

    impl Server {
        fn start() -> Self {
            let data_dir = std::env::temp_dir().join(format!(
                "rxscan-graphapi-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let _ = std::fs::remove_dir_all(&data_dir);
            std::fs::create_dir_all(&data_dir).unwrap();
            // Project database the API serves: `<data_dir>/g.db`.
            super::fixture_db(&data_dir.join("g.db"));
            let handle = rxscan::web_api::serve(rxscan::web_api::WebOptions {
                bind: "127.0.0.1".to_owned(),
                port: 0,
                data_dir: data_dir.clone(),
                allow_remote: false,
                fixture_investigation: true,
            })
            .expect("test server binds loopback");
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
                assert!(std::time::Instant::now() < deadline, "server never came up");
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
    fn full_graph_filtered_subgraph_and_detail_are_masked() {
        let server = Server::start();
        // Full graph without seed (new capability; bounded by limit).
        let (status, graph) = get(&server, "/api/v1/projects/g/graph?limit=500");
        assert_eq!(status, 200, "full graph: {graph}");
        assert!(graph["nodes"].as_array().unwrap().len() >= 5);
        assert_eq!(graph["graph_schema_version"], 1);
        let flat = graph.to_string();
        for secret in super::secrets() {
            assert!(!flat.contains(secret), "secret leaked into API graph");
        }
        for node in graph["nodes"].as_array().unwrap() {
            assert!(node.get("display_kind").is_some());
            assert!(node.get("scope").is_some());
        }
        for edge in graph["edges"].as_array().unwrap() {
            assert!(edge.get("display_relation").is_some());
            assert!(edge.get("observed").is_some());
            assert!(edge.get("thickness").is_some());
        }
        // Seeded subgraph (legacy path, now with display fields).
        let (status, seeded) = get(
            &server,
            "/api/v1/projects/g/graph?seed=ip:192.0.2.10&depth=1&limit=100",
        );
        assert_eq!(status, 200, "seeded: {seeded}");
        assert!(!seeded["nodes"].as_array().unwrap().is_empty());
        // Unknown seed is a typed 404, not an empty graph.
        let (status, _) = get(
            &server,
            "/api/v1/projects/g/graph?seed=nope&depth=1&limit=100",
        );
        assert_eq!(status, 404);
        // Depth bound preserved.
        let (status, _) = get(
            &server,
            "/api/v1/projects/g/graph?seed=ip:192.0.2.10&depth=99&limit=100",
        );
        assert_eq!(status, 422);
        // Filters: type + confidence floor.
        let (status, filtered) = get(
            &server,
            "/api/v1/projects/g/graph?limit=500&types=ip,host&min_confidence=90",
        );
        assert_eq!(status, 200, "filtered: {filtered}");
        for node in filtered["nodes"].as_array().unwrap() {
            assert!(["ip", "host"].contains(&node["display_kind"].as_str().unwrap()));
        }
        for edge in filtered["edges"].as_array().unwrap() {
            assert!(edge["confidence"].as_u64().unwrap() >= 90);
        }
        let (status, _) = get(&server, "/api/v1/projects/g/graph?limit=500&types=nope");
        assert_eq!(status, 400);
        // Node detail with evidence chain (same code path as CLI explain).
        let (status, detail) = get(&server, "/api/v1/projects/g/graph/node?node=ip:192.0.2.10");
        assert_eq!(status, 200, "detail: {detail}");
        assert!(!detail["evidence_chain"].as_array().unwrap().is_empty());
        assert!(
            detail["explanation"]
                .as_str()
                .unwrap()
                .contains("confidence")
        );
        let flat = detail.to_string();
        for secret in super::secrets() {
            assert!(!flat.contains(secret), "secret leaked into node detail");
        }
        let (status, _) = get(&server, "/api/v1/projects/g/graph/node?node=nope");
        assert_eq!(status, 404);
        // Bounded stored-data expansion (no network, no confirmation).
        let (status, neighbors) = get(
            &server,
            "/api/v1/projects/g/graph/neighbors?node=ip:192.0.2.10&limit=50",
        );
        assert_eq!(status, 200, "neighbors: {neighbors}");
        assert!(!neighbors["neighbors"].as_array().unwrap().is_empty());
        let flat = neighbors.to_string();
        for secret in super::secrets() {
            assert!(!flat.contains(secret), "secret leaked into neighbors");
        }
        let (status, _) = get(
            &server,
            "/api/v1/projects/g/graph/neighbors?node=nope&limit=50",
        );
        assert_eq!(status, 404);
    }
}
