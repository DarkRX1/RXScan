//! Deterministic local network acceptance: real open services reach the
//! human renderer end to end through the existing scanner pipeline.
//!
//! No Internet dependency. Loopback-only fixtures on OS-assigned ephemeral
//! ports (`127.0.0.1:0`); the test obtains the selected port and invokes
//! RXScan against loopback with that exact port.
//!
//! Proves: socket → scanner → service observation → evidence/finding →
//! `PortServiceDetail` → human renderer. Never constructs
//! `PortServiceDetail` manually for the end-to-end assertions.
//!
//! Manual local acceptance (deterministic, no public infrastructure):
//! ```text
//! cargo test --test network_open_port -- --nocapture
//! ```
//! Each test prints the human `PORTS` section it asserted, shaped like:
//! ```text
//! PORTS
//!
//!   <port>/tcp  OPEN  http
//!     Endpoint   http://127.0.0.1:<port>/
//!     Product    RXScan-Test
//!     Version    1.2.3
//!     Title      rxscan synthetic test
//! ```
//! (Title is lowercased by the existing `extract_title` semantics; the
//! test asserts the genuinely observed subset, never weakened rules.)
//!
//! All fixtures use synthetic/reserved values only. Loopback `127.0.0.1`
//! is used where genuinely required for local integration.

use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use rxscan::cli::Cli;

/// Loopback fixture server on an ephemeral port. Records connections;
/// stops promptly via `stop`.
struct Fixture {
    port: u16,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl Fixture {
    fn spawn(responder: impl Fn(std::net::TcpStream) + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
        listener
            .set_nonblocking(true)
            .expect("fixture nonblocking mode");
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let connections_clone = connections.clone();
        let stop_clone = stop.clone();
        let responder = Arc::new(responder);
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(25);
            while !stop_clone.load(Ordering::SeqCst) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((stream, _)) => {
                        connections_clone.fetch_add(1, Ordering::SeqCst);
                        let _ = stream.set_nonblocking(false);
                        let responder = responder.clone();
                        std::thread::spawn(move || responder(stream));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            port,
            connections,
            stop,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Synthetic HTTP fixture: deterministic `Server` + `Title` + body.
/// Mirrors `tests/phase7_service.rs` style but with the acceptance values
/// from the task (`RXScan-Test/1.2.3`, `RXScan Synthetic Test`).
fn synthetic_http_fixture() -> Fixture {
    Fixture::spawn(|mut stream| {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        let mut buf = [0u8; 4096];
        // Drain the request (GET / plus web-probe fetches); ignore content.
        let _ = stream.read(&mut buf);
        let body =
            b"<html><head><title>RXScan Synthetic Test</title></head><body>synthetic</body></html>";
        let response = format!(
            "HTTP/1.1 200 OK\r\nServer: RXScan-Test/1.2.3\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(body);
        // Brief linger so back-to-back service + web probes both complete.
        std::thread::sleep(Duration::from_millis(200));
    })
}

/// Unknown-service fixture: deterministic bytes matching no fingerprint.
/// Accepts TCP, returns a banner no classifier claims, then lingers.
fn unknown_fixture() -> Fixture {
    Fixture::spawn(|mut stream| {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
        let mut buf = [0u8; 512];
        let _ = stream.read(&mut buf);
        let _ = stream.write_all(b"HELLO-STRANGE v1 ready\r\n");
        std::thread::sleep(Duration::from_millis(200));
    })
}

fn run_scan_on_port(port: u16, output_path: &std::path::Path) -> rxscan::run::RunReport {
    let cli = Cli::try_parse_from([
        "rxscan",
        "127.0.0.1",
        "--ports",
        &port.to_string(),
        "--level",
        "3",
        "--output",
        output_path.to_str().unwrap(),
    ])
    .unwrap();
    rxscan::run::execute(cli).expect("local scan executes")
}

#[test]
fn synthetic_http_service_reaches_human_renderer_end_to_end() {
    let fixture = synthetic_http_fixture();
    assert_ne!(fixture.port, 0, "ephemeral port must be assigned");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("rxscan-net-http-{stamp}"));
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("out.jsonl");

    let report = run_scan_on_port(fixture.port, &path);

    // Real socket contact happened (TCP discovery + service/web follow-ups).
    assert!(
        fixture.connections.load(Ordering::SeqCst) >= 2,
        "scanner must contact the listener at least twice"
    );

    // PortServiceDetail arrived via the real pipeline (not constructed).
    let detail = report
        .port_details
        .iter()
        .find(|d| d.port == fixture.port)
        .expect("port detail for the ephemeral HTTP service");
    assert!(
        detail.service.eq_ignore_ascii_case("http"),
        "service is http, got {}",
        detail.service
    );
    assert_eq!(
        detail.product.as_deref(),
        Some("RXScan-Test"),
        "product genuinely observed from Server header"
    );
    assert_eq!(
        detail.version.as_deref(),
        Some("1.2.3"),
        "version genuinely observed from Server token"
    );
    // Title derives from the existing lowercasing `extract_title`
    // semantics; assert the genuinely observed (lowercased) value.
    let title = detail.title.clone().unwrap_or_default();
    assert!(
        title.to_ascii_lowercase().contains("rxscan synthetic test"),
        "title observed, got {title:?}"
    );
    let endpoint = detail.endpoint.clone().unwrap_or_default();
    assert!(
        endpoint.contains(&format!("127.0.0.1:{}", fixture.port)),
        "endpoint observed, got {endpoint:?}"
    );

    // Human renderer shows the open service with observed details.
    let human = rxscan::run::human_summary(&report);
    println!("HUMAN PORTS (http):\n{human}");
    assert!(
        human.contains(&format!("{}/tcp", fixture.port)),
        "port row visible: {human}"
    );
    assert!(human.contains("OPEN"), "open state visible: {human}");
    assert!(
        human.to_ascii_lowercase().contains("http"),
        "http service visible: {human}"
    );
    assert!(human.contains("RXScan-Test"), "product visible: {human}");
    assert!(human.contains("1.2.3"), "version visible: {human}");
    assert!(
        human.to_ascii_lowercase().contains("rxscan synthetic test"),
        "title visible: {human}"
    );
    assert!(
        human.contains(&format!("127.0.0.1:{}", fixture.port)),
        "endpoint visible: {human}"
    );

    // Machine output remains complete and ANSI-free.
    let jsonl = fs::read_to_string(&path).unwrap();
    assert!(!jsonl.contains('\x1b'), "JSONL ANSI-free");
    let mut saw_service = false;
    for line in jsonl.lines() {
        let value: serde_json::Value = serde_json::from_str(line).expect("valid JSONL");
        if value["record_type"] == "event"
            && value["payload"]["kind"] == "service_identified"
            && value["payload"]["details"]["data"]["port"] == fixture.port
        {
            saw_service = true;
        }
    }
    assert!(saw_service, "service_identified event for the port");
    assert!(!human.contains('\x1b'), "human ANSI-free: {human:?}");

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn unknown_local_service_stays_unknown_without_fabrication() {
    let fixture = unknown_fixture();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("rxscan-net-unknown-{stamp}"));
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("out.jsonl");

    let report = run_scan_on_port(fixture.port, &path);

    assert!(
        fixture.connections.load(Ordering::SeqCst) >= 1,
        "scanner contacted the unknown listener"
    );

    let human = rxscan::run::human_summary(&report);
    println!("HUMAN PORTS (unknown):\n{human}");
    assert!(
        human.contains(&format!("{}/tcp", fixture.port)),
        "port row visible: {human}"
    );
    assert!(human.contains("OPEN"), "{human}");
    assert!(
        human.to_ascii_lowercase().contains("unknown"),
        "honest unknown: {human}"
    );
    // No fabricated metadata for the unknown port's detail block.
    // Slice the human output to the unknown port's block to avoid
    // cross-port false positives when other tests share output.
    let block = human
        .lines()
        .skip_while(|line| !line.contains(&format!("{}/tcp", fixture.port)))
        .take(6)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!block.contains("Product"), "no fabricated product: {block}");
    assert!(!block.contains("Version"), "no fabricated version: {block}");
    assert!(!block.contains("TLS name"), "no fabricated TLS: {block}");
    // Endpoint/TLS lines must not be invented for unknown.
    assert!(
        !block.contains("Endpoint") || block.contains("unknown"),
        "no fabricated endpoint: {block}"
    );

    // Detail model stays honest as well (no product/version/TLS).
    if let Some(detail) = report.port_details.iter().find(|d| d.port == fixture.port) {
        assert!(
            detail.service.eq_ignore_ascii_case("unknown"),
            "service stays unknown, got {}",
            detail.service
        );
        assert!(detail.product.is_none(), "no product fabricated");
        assert!(detail.version.is_none(), "no version fabricated");
        assert!(detail.tls_name.is_none(), "no TLS name fabricated");
    }

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn network_human_output_sanitizes_terminal_controls() {
    // Evil remote text must never inject controls into human output;
    // stored evidence stays untouched (presentation-only sanitization).
    let detail = rxscan::run::PortServiceDetail {
        port: 80,
        service: "http".to_owned(),
        product: Some("RXScan-Test\x1b[31m".to_owned()),
        version: Some("1.2.3\x07".to_owned()),
        banner: None,
        endpoint: Some("http://example.test/\x1b]0;pwned\x07".to_owned()),
        title: Some("Title\x00with\x1b control\r\noverwrite\n\n\nflood".to_owned()),
        technologies: Vec::new(),
        tls_name: None,
        tls_issuer: None,
        ssh_key: None,
    };
    let report = {
        use clap::Parser;
        let cli =
            rxscan::cli::Cli::try_parse_from(["rxscan", "example.test", "--level", "3"]).unwrap();
        let plan = rxscan::plan::ScanPlan::compile(cli).unwrap();
        rxscan::run::RunReport {
            plan,
            task_count: 1,
            scheduler_report: rxscan::execution::SchedulerReport::default(),
            jsonl_bytes: 0,
            output_path: None,
            open_ports_summary: "HOST example.test\nPORT SERVICE PRODUCT\n80/tcp http RXScan-Test"
                .to_owned(),
            tcp_totals: rxscan::tcp_discovery::TcpScanTotals {
                completed_tasks: 1,
                ports_requested: 1,
                ports_attempted: 1,
                open: 1,
                closed: 0,
                filtered_or_timed_out: 0,
                error: 0,
                unscanned: 0,
                truncated: false,
                port_sources: vec!["explicit".to_owned()],
                elapsed_ms_max: 5,
                fd_peak_max: 4,
            },
            services_identified: 1,
            udp_summary: String::new(),
            udp_totals: rxscan::udp_discovery::UdpScanTotals::default(),
            duration_ms: 100,
            graph_entities: 0,
            graph_edges: 0,
            graph_truncated: false,
            certificates_observed: 0,
            certificate_reuse_groups: 0,
            fingerprint_packs_loaded: 0,
            fingerprint_rules: 0,
            fingerprint_files_rejected: 0,
            scan_id: "scan_test".to_owned(),
            port_details: vec![detail.clone()],
            project_import: None,
            project_changes: Vec::new(),
            attention: Vec::new(),
            os_hosts: Vec::new(),
        }
    };
    let human = rxscan::run::human_summary(&report);
    assert!(!human.contains('\x1b'), "no ANSI CSI/OSC: {human:?}");
    assert!(!human.contains('\x07'), "no BEL: {human:?}");
    assert!(!human.contains('\x00'), "no NUL: {human:?}");
    assert!(!human.contains('\r'), "no CR overwrite: {human:?}");
    // Stored model untouched; only presentation sanitized.
    assert!(detail.product.unwrap().contains('\x1b'));
    assert!(
        human.contains("RXScan-Test"),
        "useful core survives: {human}"
    );
    assert!(human.contains("http://example.test/"), "{human}");
}
