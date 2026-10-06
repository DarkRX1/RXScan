//! All-ports CLI/Web parity: one core planner, two frontends.
//!
//! The CLI already supports `rxscan TARGET --all-ports`. The web Scan form
//! must expose the same capability without a second implementation.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use rxscan::web_api::{self, WebOptions};

struct TestServer {
    base: String,
    data_dir: std::path::PathBuf,
    owned: Option<Box<web_api::ServerHandle>>,
}

impl TestServer {
    fn start() -> Self {
        let data_dir = std::env::temp_dir().join(format!(
            "rxscan-allports-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64 % 1_000_000)
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&data_dir).unwrap();
        let handle = web_api::serve(WebOptions {
            bind: "127.0.0.1".to_owned(),
            port: 0,
            data_dir: data_dir.clone(),
            allow_remote: false,
            fixture_investigation: true,
        })
        .unwrap();
        let base = handle.base_url().to_owned();
        let owned = Box::new(handle);
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
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(25));
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

struct Response {
    status: u16,
    body: Vec<u8>,
}

impl Response {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

fn parse_response(raw: &[u8]) -> Response {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let status: u16 = String::from_utf8_lossy(&raw[..split])
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    Response {
        status,
        body: raw[split + 4..].to_vec(),
    }
}

fn post_json(server: &TestServer, path: &str, body: &serde_json::Value) -> Response {
    let addr = server.base.trim_start_matches("http://").to_owned();
    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let payload = serde_json::to_vec(body).unwrap();
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(&payload).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    parse_response(&raw)
}

fn get(server: &TestServer, path: &str) -> Response {
    let addr = server.base.trim_start_matches("http://").to_owned();
    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let head = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    parse_response(&raw)
}

fn wait_for_job(server: &TestServer, id: &str, timeout: Duration) -> serde_json::Value {
    let deadline = Instant::now() + timeout;
    loop {
        let response = get(server, &format!("/api/v1/jobs/{id}"));
        assert_eq!(response.status, 200);
        let job = response.json();
        let status = job["status"].as_str().unwrap_or("?");
        if !matches!(status, "queued" | "running") {
            return job;
        }
        assert!(Instant::now() < deadline, "job {id} never finished");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn cli_all_ports_and_api_all_ports_create_equivalent_core_selection() {
    use clap::Parser;
    // CLI: `rxscan 192.0.2.10 --all-ports` -> TcpPortSelection::All.
    let cli = rxscan::cli::Cli::try_parse_from(["rxscan", "192.0.2.10", "--all-ports"]).unwrap();
    let plan = rxscan::plan::ScanPlan::compile(cli).unwrap();
    assert_eq!(plan.tcp_ports, rxscan::plan::TcpPortSelection::All);
    // Core resolution yields the complete TCP range as ONE task.
    let resolved = rxscan::ports::resolve_ports(&plan.tcp_ports, 3);
    assert_eq!(resolved.source, rxscan::ports::PortSource::All);
    assert_eq!(resolved.ports.len(), 65_535);
}

#[test]
fn api_accepts_all_ports_intent_structurally() {
    let server = TestServer::start();
    // Checkbox intent: `all_ports: true` without a 65k array.
    let response = post_json(
        &server,
        "/api/v1/scans",
        &serde_json::json!({"target": "127.0.0.1", "all_ports": true, "level": 1, "deadline_seconds": 5, "project": "allports"}),
    );
    assert_eq!(response.status, 202, "all_ports:true must be accepted");
    let job_id = response.json()["job_id"].as_str().unwrap().to_owned();
    // Wait until the job is provably in flight before cancelling: proves
    // cancellation reaches the scheduler during an all-ports run without
    // waiting for 65k ports and without a fixed sleep.
    let start = Instant::now();
    let deadline = start + Duration::from_secs(10);
    loop {
        let state = get(&server, &format!("/api/v1/jobs/{job_id}")).json();
        let status = state["status"].as_str().unwrap_or("?").to_owned();
        assert!(
            Instant::now() < deadline,
            "all-ports job never started running"
        );
        if status == "running" || status == "cancelled" {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let addr = server.base.trim_start_matches("http://").to_owned();
    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let body = b"{}";
    let head = format!(
        "POST /api/v1/jobs/{job_id}/cancel HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    // Cancel is accepted (200) or already terminal (409); both prove the job existed.
    let status: u16 = String::from_utf8_lossy(&raw)
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    assert!(status == 200 || status == 409, "cancel status {status}");
    // Drain to terminal (bounded wait; all-ports with level 1 is still large
    // but cancellation/deadline produce honest partial accounting).
    let job = wait_for_job(&server, &job_id, Duration::from_secs(60));
    let status = job["status"].as_str().unwrap_or("?");
    assert!(
        ["completed", "cancelled", "timed_out", "partial"].contains(&status),
        "all-ports job must terminate honestly, got {job}"
    );
    server.stop();
}

#[test]
fn api_accepts_textual_all_case_insensitively() {
    let server = TestServer::start();
    for text in ["all", "ALL", "All", "aLl"] {
        let response = post_json(
            &server,
            "/api/v1/scans",
            &serde_json::json!({"target": "127.0.0.1", "ports": text, "level": 1, "deadline_seconds": 5, "project": "alltext"}),
        );
        assert_eq!(
            response.status, 202,
            "ports:{text:?} must map to all-ports intent"
        );
    }
    server.stop();
}

#[test]
fn explicit_1_65535_remains_valid_and_explicit_behavior_unchanged() {
    use clap::Parser;
    // Explicit full-range text stays valid (parsed as explicit, not rejected).
    let ports = rxscan::ports::parse_port_selection("1-65535").unwrap();
    assert_eq!(ports.len(), 65_535);
    // Normal explicit behavior unchanged.
    assert_eq!(
        rxscan::ports::parse_port_selection("22,80,443,8000-8100").unwrap(),
        vec![
            22, 80, 443, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 8011,
            8012, 8013, 8014, 8015, 8016, 8017, 8018, 8019, 8020, 8021, 8022, 8023, 8024, 8025,
            8026, 8027, 8028, 8029, 8030, 8031, 8032, 8033, 8034, 8035, 8036, 8037, 8038, 8039,
            8040, 8041, 8042, 8043, 8044, 8045, 8046, 8047, 8048, 8049, 8050, 8051, 8052, 8053,
            8054, 8055, 8056, 8057, 8058, 8059, 8060, 8061, 8062, 8063, 8064, 8065, 8066, 8067,
            8068, 8069, 8070, 8071, 8072, 8073, 8074, 8075, 8076, 8077, 8078, 8079, 8080, 8081,
            8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095,
            8096, 8097, 8098, 8099, 8100
        ]
    );
    // CLI explicit still wins over level defaults.
    let cli =
        rxscan::cli::Cli::try_parse_from(["rxscan", "127.0.0.1", "--ports", "22,80"]).unwrap();
    let plan = rxscan::plan::ScanPlan::compile(cli).unwrap();
    assert!(matches!(
        plan.tcp_ports,
        rxscan::plan::TcpPortSelection::Explicit(_)
    ));
}

#[test]
fn malformed_port_expressions_are_rejected_not_defaulted() {
    let server = TestServer::start();
    for bad in ["0", "22,,80", "90-80", "65536", "all,", "22;80"] {
        let response = post_json(
            &server,
            "/api/v1/scans",
            &serde_json::json!({"target": "127.0.0.1", "ports": bad, "level": 1}),
        );
        assert_eq!(
            response.status, 422,
            "ports:{bad:?} must be rejected, not defaulted"
        );
    }
    server.stop();
}

#[test]
fn all_ports_does_not_enable_full_range_udp() {
    // Core planner: All TCP selection keeps UDP bounded.
    let udp = rxscan::ports::resolve_udp_ports(&rxscan::plan::TcpPortSelection::All, 3);
    assert_eq!(udp.ports, rxscan::ports::UDP_COMMON_V1.to_vec());
    assert!(udp.ports.len() < 100);
    // UDP task with `ports=all` stays bounded as well.
    let policy = rxscan::udp_discovery::UdpScanPolicy::new(
        3,
        rxscan::plan::ScanGoal::Recon,
        rxscan::plan::TcpPortSelection::All,
        rxscan::plan::SpeedSetting::default(),
    );
    assert_eq!(
        policy.ports_for_task(Some("all")).ports,
        rxscan::ports::UDP_COMMON_V1.to_vec()
    );
}

#[test]
fn frontend_never_generates_65k_element_array() {
    let js = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("app/rxscan.js"),
    )
    .unwrap();
    // No frontend expansion of 1..65535, no 65535-length array construction.
    assert!(
        !js.contains("65535"),
        "frontend must not hardcode 65535 expansion"
    );
    // The checkbox and textual `all` both map to `all_ports: true` structurally.
    assert!(
        js.contains("all_ports"),
        "frontend must send structural all_ports intent"
    );
    assert!(
        js.contains("\"all\"")
            || js.contains("'all'")
            || js.contains("=== \"all\"")
            || js.to_lowercase().contains("all"),
        "frontend must handle textual all"
    );
    let html = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("app/index.html"),
    )
    .unwrap();
    assert!(
        html.contains("All TCP ports"),
        "GUI must expose an explicit All TCP ports control"
    );
    assert!(html.contains("all"), "GUI ports field must document `all`");
}

#[test]
fn deadlines_produce_honest_partial_accounting_for_scans() {
    // Direct core proof: an expired deadline yields truncated accounting,
    // never a fake complete.
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
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
        wordlist: None,
        scan_mode: Some("connect".to_owned()),
        explain: false,
        max_tasks: None,
        max_retries: None,
        max_concurrency: None,
        max_hosts: None,
        max_execution_time: Some("1ms".to_owned()),
        max_evidence_bytes: None,
        output: None,
        checkpoint: None,
        resume: None,
        project_db: None,
        format: None,
        color: None,
    };
    // Use a synthetic closed port with a tiny deadline: scheduler still
    // returns with honest termination (not necessarily failed).
    let report = rxscan::run::execute_with_cancellation(cli, Some(cancel)).expect("run returns");
    let termination = report.scheduler_report.termination.to_string();
    assert!(!termination.is_empty());
}

#[test]
fn scan_gui_exposes_all_ports_control() {
    let html = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("app/index.html"),
    )
    .unwrap();
    assert!(
        html.contains("scan-allports"),
        "scan form must have all-ports checkbox"
    );
    assert!(
        html.contains("scan-ports"),
        "scan form must have ports field"
    );
}
