//! Web/API integration tests: deterministic, no public Internet.
//!
//! Each test spawns its own loopback server (`port 0` = OS-assigned) with
//! fixture investigation backends and an isolated data directory under the
//! system temp dir. Scans run against local synthetic listeners through the
//! real RXScan core; nothing is fabricated in handlers.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

use rxscan::web_api::{self, WebOptions};

struct TestServer {
    base: String,
    data_dir: PathBuf,
    owned: Option<Box<web_api::ServerHandle>>,
}

// The handle is only used for shutdown after all client I/O completes.

impl TestServer {
    fn start() -> Self {
        let data_dir = std::env::temp_dir().join(format!(
            "rxscan-web-test-{}-{}",
            std::process::id(),
            rxscan_test_nonce()
        ));
        std::fs::create_dir_all(&data_dir).expect("test data dir");
        let handle = web_api::serve(WebOptions {
            bind: "127.0.0.1".to_owned(),
            port: 0,
            data_dir: data_dir.clone(),
            allow_remote: false,
            fixture_investigation: true,
        })
        .expect("test server binds loopback");
        let base = handle.base_url().to_owned();
        let owned = Box::new(handle);
        // Wait until the acceptor answers.
        let deadline = Instant::now() + Duration::from_secs(10);
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
            assert!(Instant::now() < deadline, "test server never came up");
            thread::sleep(Duration::from_millis(25));
        }
        Self {
            base,
            data_dir,
            owned: Some(owned),
        }
    }

    fn stop(mut self) {
        if let Some(handle) = self.owned.take() {
            handle.shutdown();
        }
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn rxscan_test_nonce() -> u64 {
    NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        + (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as u64)
            .unwrap_or(0)
            % 1_000_000)
}

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("response body is JSON")
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

fn request(
    server: &TestServer,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Response {
    let addr = server.base.trim_start_matches("http://").to_owned();
    let mut stream = TcpStream::connect(&addr).expect("connect test server");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("read timeout");
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    let mut has_content_type = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-type") {
            has_content_type = true;
        }
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        if !has_content_type {
            head.push_str("Content-Type: application/json\r\n");
        }
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).expect("write head");
    if let Some(body) = body {
        stream.write_all(body).expect("write body");
    }
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response has head");
    let head_text = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head_text.lines();
    let status_line = lines.next().expect("status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    let mut response_headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            response_headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    Response {
        status,
        headers: response_headers,
        body: raw[split + 4..].to_vec(),
    }
}

fn get(server: &TestServer, path: &str) -> Response {
    request(server, "GET", path, &[], None)
}

fn post_json(server: &TestServer, path: &str, body: &serde_json::Value) -> Response {
    request(
        server,
        "POST",
        path,
        &[("Content-Type", "application/json")],
        Some(&serde_json::to_vec(body).expect("json")),
    )
}

fn post_raw(server: &TestServer, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Response {
    request(server, "POST", path, headers, Some(body))
}

fn wait_for_job(server: &TestServer, id: &str, timeout: Duration) -> serde_json::Value {
    let deadline = Instant::now() + timeout;
    loop {
        let response = get(server, &format!("/api/v1/jobs/{id}"));
        assert_eq!(response.status, 200, "job lookup must succeed");
        let job = response.json();
        let status = job["status"].as_str().unwrap_or("?");
        if !matches!(status, "queued" | "running") {
            return job;
        }
        assert!(Instant::now() < deadline, "job {id} never finished");
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn health_is_lightweight_and_request_tagged() {
    let server = TestServer::start();
    let response = get(&server, "/api/v1/health");
    assert_eq!(response.status, 200);
    let body = response.json();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["api_version"], 1);
    assert!(response.header("x-request-id").is_some());
    let text = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    for leaked in ["token", "secret", "password", "api_key", "home", "env"] {
        assert!(!text.contains(leaked), "health must not leak {leaked}");
    }
    server.stop();
}

#[test]
fn capabilities_distinguish_states() {
    let server = TestServer::start();
    let response = get(&server, "/api/v1/capabilities");
    assert_eq!(response.status, 200);
    let body = response.json();
    let capabilities = body["capabilities"].as_array().expect("array");
    assert!(!capabilities.is_empty());
    let states: Vec<&str> = capabilities
        .iter()
        .map(|entry| entry["state"].as_str().expect("state"))
        .collect();
    for state in &states {
        assert!(
            ["available", "configured", "unavailable"].contains(state),
            "unexpected capability state {state}"
        );
    }
    assert!(states.contains(&"available") || states.contains(&"configured"));
    assert!(states.contains(&"unavailable"));
    assert!(
        capabilities
            .iter()
            .any(|entry| entry["name"] == "connect_scan"),
        "connect capability must be advertised"
    );
    server.stop();
}

#[test]
fn unknown_routes_and_methods_are_typed() {
    let server = TestServer::start();
    let response = get(&server, "/api/v1/nope");
    assert_eq!(response.status, 404);
    assert_eq!(response.json()["error"]["code"], "not_found");
    let response = request(&server, "DELETE", "/api/v1/health", &[], None);
    assert_eq!(response.status, 405);
    assert_eq!(response.json()["error"]["code"], "method_not_allowed");
    server.stop();
}

#[test]
fn invalid_json_oversized_and_media_type_are_typed() {
    let server = TestServer::start();
    let response = post_raw(
        &server,
        "/api/v1/scans",
        &[("Content-Type", "application/json")],
        b"{oops",
    );
    assert_eq!(response.status, 400);
    assert_eq!(response.json()["error"]["code"], "invalid_json");
    // Wrong content type on a mutation API (simple-form cross-site POSTs
    // cannot set application/json without preflight, which is never answered).
    let response = request(
        &server,
        "POST",
        "/api/v1/scans",
        &[("Content-Type", "text/plain")],
        Some(br#"{"target":"127.0.0.1"}"#),
    );
    assert_eq!(response.status, 400);
    assert_eq!(response.json()["error"]["code"], "unsupported_media_type");
    // Oversized payload is rejected with 413, never buffered unboundedly.
    let big = vec![b'x'; 600 * 1024];
    let response = post_raw(
        &server,
        "/api/v1/scans",
        &[("Content-Type", "application/json")],
        &big,
    );
    assert_eq!(response.status, 413);
    assert_eq!(response.json()["error"]["code"], "payload_too_large");
    server.stop();
}

#[test]
fn invalid_targets_entities_and_scope_fail_before_jobs() {
    let server = TestServer::start();
    for target in ["", "not a target @@", "-"] {
        let response = post_json(
            &server,
            "/api/v1/scans",
            &serde_json::json!({"target": target, "ports": [80]}),
        );
        assert_eq!(response.status, 422, "target {target:?} must be rejected");
    }
    let response = post_json(
        &server,
        "/api/v1/scans",
        &serde_json::json!({"target": "127.0.0.1", "ports": [0]}),
    );
    assert_eq!(response.status, 422);
    let response = post_json(
        &server,
        "/api/v1/scans",
        &serde_json::json!({"target": "127.0.0.1", "scope": ["not a scope @@"]}),
    );
    assert_eq!(response.status, 422);
    let response = post_json(
        &server,
        "/api/v1/scans",
        &serde_json::json!({"target": "127.0.0.1", "mode": "turbo"}),
    );
    assert_eq!(response.status, 422);
    for entity in ["nope", ""] {
        let response = post_json(
            &server,
            "/api/v1/investigations",
            &serde_json::json!({"entity_type": entity, "value": "exampleuser"}),
        );
        assert_eq!(response.status, 422, "entity {entity:?} must be rejected");
    }
    // Network bridge without scope is rejected by core validation.
    let response = post_json(
        &server,
        "/api/v1/investigations",
        &serde_json::json!({"entity_type": "username", "value": "exampleuser", "network": true}),
    );
    assert_eq!(response.status, 422);
    // Nothing above may have created a job.
    let jobs = get(&server, "/api/v1/jobs").json();
    assert_eq!(jobs["total"], 0);
    server.stop();
}

#[test]
fn foreign_host_and_origin_are_rejected() {
    let server = TestServer::start();
    let response = request(
        &server,
        "GET",
        "/api/v1/health",
        &[("Host", "evil.test")],
        None,
    );
    assert_eq!(response.status, 403);
    assert_eq!(response.json()["error"]["code"], "foreign_host");
    let response = request(
        &server,
        "POST",
        "/api/v1/scans",
        &[
            ("Content-Type", "application/json"),
            ("Origin", "https://evil.test"),
        ],
        Some(br#"{"target":"127.0.0.1"}"#),
    );
    assert_eq!(response.status, 403);
    assert_eq!(response.json()["error"]["code"], "foreign_origin");
    server.stop();
}

#[test]
fn projects_crud_and_lookup() {
    let server = TestServer::start();
    let response = get(&server, "/api/v1/projects/missing");
    assert_eq!(response.status, 404);
    let response = post_json(
        &server,
        "/api/v1/projects",
        &serde_json::json!({"name": "alpha"}),
    );
    assert_eq!(response.status, 201);
    let response = post_json(
        &server,
        "/api/v1/projects",
        &serde_json::json!({"name": "alpha"}),
    );
    assert_eq!(response.status, 409);
    let response = post_json(
        &server,
        "/api/v1/projects",
        &serde_json::json!({"name": "../evil"}),
    );
    assert_eq!(response.status, 400);
    let response = get(&server, "/api/v1/projects");
    assert_eq!(response.status, 200);
    let names: Vec<String> = response.json()["projects"]
        .as_array()
        .expect("array")
        .iter()
        .map(|project| project["name"].as_str().expect("name").to_owned())
        .collect();
    assert!(names.contains(&"alpha".to_owned()));
    let response = get(&server, "/api/v1/projects/alpha?limit=1");
    assert_eq!(response.status, 200);
    assert_eq!(response.json()["name"], "alpha");
    server.stop();
}

#[test]
fn scan_end_to_end_through_real_core() {
    let server = TestServer::start();
    // Synthetic SSH service on loopback; the scan must observe it through
    // the real scheduler, probes, and scope enforcement.
    let service = TcpListener::bind("127.0.0.1:0").expect("synthetic service");
    let port = service.local_addr().expect("addr").port();
    thread::spawn(move || {
        for mut stream in service.incoming().take(16).flatten() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
            let mut probe = [0u8; 2048];
            let _ = stream.read(&mut probe);
            let _ = stream.write_all(b"SSH-2.0-OpenSSH_9.3 fixture\r\n");
        }
    });
    let response = post_json(
        &server,
        "/api/v1/scans",
        &serde_json::json!({
            "target": "127.0.0.1",
            "ports": [port],
            "mode": "connect",
            "level": 1,
            "deadline_seconds": 60,
            "project": "e2e",
        }),
    );
    assert_eq!(response.status, 202);
    let job_id = response.json()["job_id"]
        .as_str()
        .expect("job id")
        .to_owned();
    let job = wait_for_job(&server, &job_id, Duration::from_secs(60));
    assert_eq!(job["status"], "completed", "scan job: {job}");
    let result = &job["result"];
    assert_eq!(result["termination"], "completed");
    let open: Vec<u64> = result["open_ports"]
        .as_array()
        .expect("open ports")
        .iter()
        .map(|entry| entry["port"].as_u64().expect("port"))
        .collect();
    assert!(
        open.contains(&(port as u64)),
        "synthetic service must be observed"
    );
    // The scan imported into the existing project database: entities,
    // findings, graph, and timeline all serve from that store.
    let entities = get(&server, "/api/v1/projects/e2e/entities?limit=50").json();
    assert!(
        !entities["entities"]
            .as_array()
            .expect("entities")
            .is_empty(),
        "scan must persist entities"
    );
    let findings = get(&server, "/api/v1/projects/e2e/findings?limit=50").json();
    assert!(
        !findings["findings"]
            .as_array()
            .expect("findings")
            .is_empty(),
        "scan must persist findings"
    );
    let seed = entities["entities"][0]["entity_id"]
        .as_str()
        .expect("seed")
        .to_owned();
    let graph = get(
        &server,
        &format!("/api/v1/projects/e2e/graph?seed={seed}&depth=2&limit=100"),
    )
    .json();
    assert!(
        !graph["nodes"].as_array().expect("nodes").is_empty(),
        "graph must expand from stored relationships"
    );
    let timeline = get(&server, "/api/v1/projects/e2e/timeline?limit=50").json();
    let events = timeline["events"].as_array().expect("events");
    assert!(!events.is_empty(), "timeline must show observations");
    assert!(
        events.iter().any(|event| event["current"] == true),
        "latest run observations must be marked current"
    );
    // Graph bounds hold.
    let bounded = get(
        &server,
        &format!("/api/v1/projects/e2e/graph?seed={seed}&depth=99&limit=100"),
    );
    assert_eq!(bounded.status, 422);
    // Pagination holds.
    let page = get(&server, "/api/v1/projects/e2e/entities?limit=1&offset=0").json();
    assert_eq!(page["entities"].as_array().expect("page").len(), 1);
    server.stop();
}

#[test]
fn investigation_end_to_end_through_real_core() {
    let server = TestServer::start();
    let response = post_json(
        &server,
        "/api/v1/investigations",
        &serde_json::json!({
            "entity_type": "username",
            "value": "exampleuser",
            "depth": 3,
            "deadline_seconds": 60,
            "project": "inve2e",
        }),
    );
    assert_eq!(response.status, 202);
    let job_id = response.json()["job_id"]
        .as_str()
        .expect("job id")
        .to_owned();
    let job = wait_for_job(&server, &job_id, Duration::from_secs(60));
    assert_eq!(job["status"], "completed", "investigation job: {job}");
    let result = &job["result"];
    assert!(
        result["entities"].as_u64().unwrap_or(0) >= 2,
        "seed + account expected"
    );
    assert!(
        result["relationships"].as_u64().unwrap_or(0) >= 1,
        "correlation expected"
    );
    assert!(result["observations"].as_u64().unwrap_or(0) >= 1);
    // Same core pivot objects as the CLI: evidence-backed next steps.
    let pivots = result["pivots"].as_array().expect("pivots array");
    for pivot in pivots {
        for key in [
            "target_kind",
            "target_value",
            "reason",
            "source",
            "state",
            "action",
        ] {
            assert!(
                pivot
                    .get(key)
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty()),
                "web pivot missing {key}: {pivot}"
            );
        }
    }
    // Planner output is real: the seed entity id is canonical.
    let sample = result["entities_sample"].as_array().expect("sample");
    assert!(
        sample
            .iter()
            .any(|entity| entity["id"] == "username:exampleuser"),
        "canonical seed entity must be present"
    );
    // Persisted through the existing project layer (same as CLI).
    let entities = get(&server, "/api/v1/projects/inve2e/entities?limit=50").json();
    assert!(
        entities["entities"].as_array().expect("entities").len() >= 2,
        "investigation must persist entities"
    );
    server.stop();
}

#[test]
fn cancellation_reaches_real_core_work() {
    let server = TestServer::start();
    let response = post_json(
        &server,
        "/api/v1/investigations",
        &serde_json::json!({
            "entity_type": "username",
            "value": "slowcanceluser",
            "depth": 3,
            "deadline_seconds": 60,
            "project": "cancel",
        }),
    );
    assert_eq!(response.status, 202);
    let job_id = response.json()["job_id"]
        .as_str()
        .expect("job id")
        .to_owned();
    // Cancel while the slow DNS stage is provably in flight.
    thread::sleep(Duration::from_millis(500));
    let cancel = request(
        &server,
        "POST",
        &format!("/api/v1/jobs/{job_id}/cancel"),
        &[("Content-Type", "application/json")],
        Some(b"{}"),
    );
    assert_eq!(cancel.status, 200, "cancel must be accepted");
    let job = wait_for_job(&server, &job_id, Duration::from_secs(30));
    assert_eq!(
        job["status"], "cancelled",
        "cancel must reach core work: {job}"
    );
    // Cancelling a terminal job is a conflict, not a silent success.
    let again = request(
        &server,
        "POST",
        &format!("/api/v1/jobs/{job_id}/cancel"),
        &[("Content-Type", "application/json")],
        Some(b"{}"),
    );
    assert_eq!(again.status, 409);
    server.stop();
}

#[test]
fn scan_cancellation_reaches_scheduler() {
    // Direct core proof: a pre-cancelled flag drives the real scheduler to
    // UserCancelled semantics with evidence preserved, no HTTP involved.
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let cli = rxscan::cli::Cli {
        target: Some("127.0.0.1".to_owned()),
        targets: None,
        config: None,
        project_config: None,
        goal: None,
        level: Some(1),
        speed: None,
        profile: None,
        scope: vec!["127.0.0.1".to_owned()],
        exclude: vec![],
        ports: Some("9".to_owned()),
        all_ports: false,
        ping: false,
        discover: false,
        udp: false,
        os: false,
        wordlist: None,
        scan_mode: Some("connect".to_owned()),
        explain: false,
        max_tasks: None,
        max_retries: None,
        max_concurrency: None,
        max_hosts: None,
        max_execution_time: Some("60s".to_owned()),
        max_evidence_bytes: None,
        output: None,
        checkpoint: None,
        resume: None,
        project_db: None,
        format: None,
        color: None,
    };
    let report = rxscan::run::execute_with_cancellation(cli, Some(cancel)).expect("run returns");
    assert_eq!(
        report.scheduler_report.termination.to_string(),
        "user_cancelled"
    );
}

#[test]
fn job_events_stream_terminal_state() {
    let server = TestServer::start();
    let response = post_json(
        &server,
        "/api/v1/investigations",
        &serde_json::json!({
            "entity_type": "domain",
            "value": "example.test",
            "depth": 2,
            "deadline_seconds": 60,
            "project": "sse",
        }),
    );
    assert_eq!(response.status, 202);
    let job_id = response.json()["job_id"]
        .as_str()
        .expect("job id")
        .to_owned();
    let finished = wait_for_job(&server, &job_id, Duration::from_secs(60));
    assert_eq!(finished["status"], "completed");
    // SSE replays the buffered terminal event then closes.
    let addr = server.base.trim_start_matches("http://").to_owned();
    let mut stream = TcpStream::connect(&addr).expect("sse connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("timeout");
    let head = format!(
        "GET /api/v1/jobs/{job_id}/events HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).expect("sse request");
    let mut text = String::new();
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(count) => {
                text.push_str(&String::from_utf8_lossy(&buf[..count]));
                if text.contains("job_completed") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    assert!(
        text.contains("text/event-stream"),
        "SSE content type required"
    );
    assert!(text.contains("job_completed"), "terminal event must stream");
    server.stop();
}

#[test]
fn gui_and_api_share_one_origin() {
    let server = TestServer::start();
    // `/` is the RXScan application (not a marketing page).
    let root = get(&server, "/");
    assert_eq!(root.status, 200);
    let html = String::from_utf8_lossy(&root.body).into_owned();
    assert!(html.contains("rxscan.js"), "GUI must load its client");
    assert!(html.contains("scan-form"), "GUI must expose the scan form");
    assert!(html.contains("Dashboard"), "GUI must expose Dashboard nav");
    assert!(
        html.contains("Investigate"),
        "GUI must expose Investigate nav"
    );
    assert!(html.contains("Projects"), "GUI must expose Projects nav");
    assert!(html.contains("Jobs"), "GUI must expose Jobs nav");
    assert!(
        !html.contains("DARKRX") && !html.contains("Purple-Team"),
        "root must be the RXScan app, not the portfolio site"
    );
    // RXScan branding: root GUI references the packaged logo, never an
    // absolute filesystem path, Downloads, or remote URL.
    assert!(
        html.contains("RXScanlogo.png"),
        "GUI must reference the packaged RXScan logo"
    );
    assert!(
        html.contains("rel=\"icon\""),
        "GUI must declare a local favicon"
    );
    for forbidden in ["Downloads", "/home/", "/Users/", "C:\\", "~/"] {
        assert!(
            !html.contains(forbidden),
            "GUI must not reference local path {forbidden}"
        );
    }
    // `/app` stays as a backwards-compatible alias for the same GUI.
    let app = get(&server, "/app");
    assert_eq!(app.status, 200);
    let app_html = String::from_utf8_lossy(&app.body).into_owned();
    assert!(app_html.contains("rxscan.js"));
    assert!(app_html.contains("scan-form"));
    let js = get(&server, "/app/rxscan.js");
    assert_eq!(js.status, 200);
    let js_text = String::from_utf8_lossy(&js.body).into_owned();
    assert!(
        !js_text.contains("console.log"),
        "GUI client must keep the browser console clean"
    );
    // No fabricated findings in the shipped client.
    for marker in ["192.168.1.", "10.0.0.99", "attacker-example"] {
        assert!(
            !js_text.contains(marker),
            "GUI client must not embed fake findings ({marker})"
        );
    }
    // RXScan logo is packaged and served with the correct content type.
    for path in [
        "/app/assets/RXScanlogo.png",
        "/assets/RXScanlogo.png",
        "/favicon.png",
        "/favicon.ico",
    ] {
        let asset = get(&server, path);
        assert_eq!(asset.status, 200, "logo asset must serve at {path}");
        let content_type = asset.header("content-type").unwrap_or("").to_owned();
        assert!(
            content_type.starts_with("image/png"),
            "logo at {path} must be image/png, got {content_type}"
        );
        assert!(
            asset.body.len() > 8
                && asset.body[1] == b'P'
                && asset.body[2] == b'N'
                && asset.body[3] == b'G',
            "logo at {path} must be PNG bytes"
        );
    }
    // Portfolio separation: the local server serves RXScan only. No
    // portfolio runtime routes, branding, or embedded portfolio assets.
    for path in [
        "/site",
        "/site/",
        "/portfolio",
        "/portfolio/",
        "/css/app.css",
        "/js/app.js",
        "/js/data.js",
        "/js/icons.js",
        "/js/lab.js",
        "/js/lattice.js",
    ] {
        let response = get(&server, path);
        assert_eq!(
            response.status, 404,
            "portfolio route {path} must not exist on the RXScan server"
        );
    }
    assert!(
        !html.contains("darkrx.local") || html.contains("RXScan"),
        "GUI must not carry portfolio contact branding"
    );
    server.stop();
}

#[test]
fn passive_entity_search_is_sync_and_local() {
    let server = TestServer::start();
    let response = post_json(
        &server,
        "/api/v1/search",
        &serde_json::json!({"entity_type": "domain", "value": "example.test", "project": "searchsync"}),
    );
    assert_eq!(
        response.status,
        200,
        "passive search: {}",
        String::from_utf8_lossy(&response.body)
    );
    let body = response.json();
    assert_eq!(body["seed_canonical"], "example.test");
    assert_eq!(body["network_scans"], 0);
    assert_eq!(body["contact_class"], "passive_public");
    assert!(!body["entities"].as_array().expect("entities").is_empty());
    // Username provider search must not run synchronously here.
    let response = post_json(
        &server,
        "/api/v1/search",
        &serde_json::json!({"entity_type": "username", "value": "exampleuser"}),
    );
    assert_eq!(response.status, 422);
    // Invalid kinds fail before any work.
    let response = post_json(
        &server,
        "/api/v1/search",
        &serde_json::json!({"entity_type": "nope", "value": "x"}),
    );
    assert_eq!(response.status, 422);
    server.stop();
}

#[test]
fn username_search_runs_as_cancellable_job() {
    let server = TestServer::start();
    let response = post_json(
        &server,
        "/api/v1/username-searches",
        &serde_json::json!({"value": "exampleuser", "deadline_seconds": 25, "project": "usearch"}),
    );
    assert_eq!(
        response.status,
        202,
        "username search: {}",
        String::from_utf8_lossy(&response.body)
    );
    let job_id = response.json()["job_id"]
        .as_str()
        .expect("job id")
        .to_owned();
    let job = wait_for_job(&server, &job_id, Duration::from_secs(60));
    assert_eq!(job["status"], "completed", "username search job: {job}");
    assert_eq!(job["kind"], "username_search");
    let result = &job["result"];
    assert!(result["coverage"]["requested"].as_u64().unwrap_or(0) >= 1);
    assert!(
        !result["results_sample"]
            .as_array()
            .expect("sample")
            .is_empty()
    );
    // Kind-scoped lookup works; wrong-kind lookup is 404.
    let scoped = get(&server, &format!("/api/v1/username-searches/{job_id}"));
    assert_eq!(scoped.status, 200);
    let wrong = get(&server, &format!("/api/v1/scans/{job_id}"));
    assert_eq!(wrong.status, 404);
    // Persisted through the existing project layer.
    let entities = get(&server, "/api/v1/projects/usearch/entities?limit=50").json();
    assert!(
        !entities["entities"]
            .as_array()
            .expect("entities")
            .is_empty()
    );
    server.stop();
}

#[test]
fn scan_result_carries_evidence_backed_details() {
    let server = TestServer::start();
    let service = TcpListener::bind("127.0.0.1:0").expect("synthetic service");
    let port = service.local_addr().expect("addr").port();
    thread::spawn(move || {
        for mut stream in service.incoming().take(8).flatten() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
            let mut probe = [0u8; 2048];
            let _ = stream.read(&mut probe);
            let _ = stream.write_all(b"SSH-2.0-OpenSSH_9.3 fixture\r\n");
        }
    });
    let response = post_json(
        &server,
        "/api/v1/scans",
        &serde_json::json!({
            "target": "127.0.0.1",
            "ports": [port],
            "mode": "connect",
            "level": 1,
            "goal": "recon",
            "speed": "balanced",
            "deadline_seconds": 60,
            "project": "evdetail",
        }),
    );
    assert_eq!(response.status, 202);
    let job_id = response.json()["job_id"]
        .as_str()
        .expect("job id")
        .to_owned();
    let job = wait_for_job(&server, &job_id, Duration::from_secs(60));
    assert_eq!(job["status"], "completed", "scan job: {job}");
    let open = job["result"]["open_ports"].as_array().expect("open ports");
    assert!(!open.is_empty());
    // Evidence-backed detail keys exist; unknown stays null (never fabricated).
    let first = &open[0];
    assert!(first.get("port").is_some());
    assert!(first.get("service").is_some());
    assert!(first.get("product").is_some());
    assert!(first.get("version").is_some());
    assert!(first.get("http_title").is_some() || first.get("technologies").is_some());
    server.stop();
}
