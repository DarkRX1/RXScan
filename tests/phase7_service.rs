//! Phase 7 service-intelligence tests: local deterministic fixtures only.
//!
//! No public Internet dependency. Fake banner servers, a local HTTP server,
//! an in-test rustls TLS server (rcgen certificate), and silent/oversized/
//! delayed fixtures — all on loopback.

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use rxscan::{
    cli::Cli,
    decision::{Phase7Engine, open_ports_from_output},
    execution::{
        BudgetLimits, CancellationToken, DecisionEngine, Module, ModuleContext, ModuleError,
        ModuleOutput, PolicyScopeGuard, RetryPolicy, Scheduler, ScopeGuard, SpeedGovernor, Task,
        TaskKind, TaskScopeTarget, VecEventSink,
    },
    model::{Provenance, SCHEMA_VERSION, Timestamp},
    plan::{ScanGoal, ScanPlan, SpeedSetting},
    service::{MAX_PROBES_PER_PORT, plan_probes, service_asset_id},
    service_probe::ServiceProbeModule,
};

// ---------- fixture framework ----------

/// A loopback fixture server. Records every byte clients send (for no-auth
/// auditing) and counts connections. Stops promptly via `stop`.
struct Fixture {
    port: u16,
    received: Arc<std::sync::Mutex<Vec<u8>>>,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl Fixture {
    fn spawn(
        responder: impl Fn(TcpStream, Arc<std::sync::Mutex<Vec<u8>>>) + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
        listener
            .set_nonblocking(false)
            .expect("fixture blocking mode");
        listener
            .set_nonblocking(true)
            .expect("fixture nonblocking mode");
        let port = listener.local_addr().unwrap().port();
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let received_clone = received.clone();
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
                        // Per-connection thread: slow responders (silent /
                        // delayed fixtures) must never stall later accepts.
                        let responder = responder.clone();
                        let received = received_clone.clone();
                        std::thread::spawn(move || responder(stream, received));
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
            received,
            connections,
            stop,
        }
    }

    fn received_bytes(&self) -> Vec<u8> {
        self.received.lock().unwrap().clone()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn record_all(mut stream: TcpStream, received: Arc<std::sync::Mutex<Vec<u8>>>) -> Vec<u8> {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(400)));
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                data.extend_from_slice(&chunk[..count]);
                if data.len() > 64 * 1024 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    received.lock().unwrap().extend_from_slice(&data);
    data
}

fn ssh_fixture() -> Fixture {
    Fixture::spawn(|mut stream, received| {
        let _ = stream.write_all(b"SSH-2.0-OpenSSH_9.8 fixture\r\n");
        let _ = stream.set_read_timeout(Some(Duration::from_millis(600)));
        let mut chunk = [0u8; 512];
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
        }
        std::thread::sleep(Duration::from_millis(100));
    })
}

fn ssh_malformed_fixture() -> Fixture {
    Fixture::spawn(|mut stream, received| {
        let _ = stream.write_all(b"HELLO NOT SSH\r\n");
        let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
        let mut chunk = [0u8; 512];
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
        }
    })
}

fn http_response_fixture() -> Fixture {
    Fixture::spawn(|mut stream, received| {
        let request = record_all(stream.try_clone().expect("clone fixture stream"), received);
        let _ = request;
        let body = b"<html><head><title>Fixture</title></head><body>hi</body></html>";
        let response = format!(
            "HTTP/1.1 200 OK\r\nServer: nginx/1.27.2\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(body);
    })
}

fn http_redirect_fixture(counter: Arc<AtomicUsize>) -> Fixture {
    Fixture::spawn(move |mut stream, received| {
        let request = record_all(stream.try_clone().expect("clone fixture stream"), received);
        let _ = request;
        counter.fetch_add(1, Ordering::SeqCst);
        let response = "HTTP/1.1 302 Found\r\nServer: redirector/2.0\r\nLocation: /login\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(response.as_bytes());
    })
}

fn ftp_fixture() -> Fixture {
    Fixture::spawn(|mut stream, received| {
        let _ = stream.write_all(b"220 FixtureFTP 1.0 ready\r\n");
        let _ = stream.set_read_timeout(Some(Duration::from_millis(400)));
        let mut chunk = [0u8; 512];
        // Answer the disambiguation exchange the way a real FTP server
        // does: reject EHLO, accept NOOP. A lone 220 never classifies.
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
            if chunk[..count].starts_with(b"EHLO") {
                let _ = stream.write_all(b"500 EHLO not understood\r\n");
                let _ = stream.set_read_timeout(Some(Duration::from_millis(400)));
                if let Ok(count) = stream.read(&mut chunk) {
                    received.lock().unwrap().extend_from_slice(&chunk[..count]);
                    if chunk[..count].starts_with(b"NOOP") {
                        let _ = stream.write_all(b"200 NOOP ok\r\n");
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    })
}

fn smtp_fixture() -> Fixture {
    Fixture::spawn(|mut stream, received| {
        let _ = stream.write_all(b"220 fixture.test ESMTP ready\r\n");
        let request = record_all(
            stream.try_clone().expect("clone fixture stream"),
            received.clone(),
        );
        if request.starts_with(b"EHLO") {
            let _ = stream.write_all(b"250-fixture.test Hello\r\n250-STARTTLS\r\n250 8BITMIME\r\n");
            // Drain any further pipelined bytes for the audit log.
            let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
            let mut chunk = [0u8; 512];
            if let Ok(count) = stream.read(&mut chunk) {
                received.lock().unwrap().extend_from_slice(&chunk[..count]);
            }
        }
    })
}

fn redis_fixture() -> Fixture {
    Fixture::spawn(|mut stream, received| {
        let request = record_all(stream.try_clone().expect("clone fixture stream"), received);
        if request == b"PING\r\n" {
            let _ = stream.write_all(b"+PONG\r\n");
        } else {
            let _ = stream.write_all(b"-ERR unknown\r\n");
        }
    })
}

fn mysql_fixture() -> Fixture {
    Fixture::spawn(|mut stream, received| {
        let version = b"8.0.36-fixture";
        let mut payload = vec![10u8];
        payload.extend_from_slice(version);
        payload.push(0);
        payload.extend_from_slice(&[1, 0, 0, 0]); // connection id
        let length = payload.len() as u32;
        let mut packet = vec![
            (length & 0xFF) as u8,
            ((length >> 8) & 0xFF) as u8,
            ((length >> 16) & 0xFF) as u8,
            0u8,
        ];
        packet.extend_from_slice(&payload);
        let _ = stream.write_all(&packet);
        let _ = stream.set_read_timeout(Some(Duration::from_millis(400)));
        let mut chunk = [0u8; 512];
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
        }
    })
}

fn postgres_fixture(expected: Arc<AtomicBool>) -> Fixture {
    Fixture::spawn(move |mut stream, received| {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(2000)));
        let mut magic = [0u8; 8];
        let mut read = 0;
        while read < 8 {
            match stream.read(&mut magic[read..]) {
                Ok(0) => break,
                Ok(count) => read += count,
                Err(_) => break,
            }
        }
        received.lock().unwrap().extend_from_slice(&magic[..read]);
        if magic == [0, 0, 0, 8, 4, 210, 22, 47] {
            expected.store(true, Ordering::SeqCst);
            let _ = stream.write_all(b"N");
        }
        std::thread::sleep(Duration::from_millis(100));
    })
}

fn unknown_banner_fixture() -> Fixture {
    Fixture::spawn(|mut stream, received| {
        let _ = stream.write_all(b"HELLO-STRANGE v1 ready\r\n");
        let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
        let mut chunk = [0u8; 512];
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
        }
    })
}

fn silent_fixture() -> Fixture {
    Fixture::spawn(|stream, _| {
        std::thread::sleep(Duration::from_secs(6));
        drop(stream);
    })
}

fn oversized_fixture() -> Fixture {
    Fixture::spawn(|mut stream, received| {
        let big = vec![b'A'; 100_000];
        let _ = stream.write_all(&big);
        let _ = stream.write_all(b"\r\n");
        let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
        let mut chunk = [0u8; 512];
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
        }
    })
}

fn delayed_fixture(delay: Duration) -> Fixture {
    Fixture::spawn(move |mut stream, received| {
        std::thread::sleep(delay);
        let _ = stream.write_all(b"SSH-2.0-late arrival\r\n");
        let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
        let mut chunk = [0u8; 512];
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
        }
    })
}

// ---------- TLS fixtures (rustls server + rcgen cert, loopback only) ----------

struct TlsFixture {
    port: u16,
    stop: Arc<AtomicBool>,
    received_http: Arc<std::sync::Mutex<Vec<u8>>>,
}

fn rcgen_test_cert() -> (Vec<u8>, Vec<u8>) {
    let mut params =
        rcgen::CertificateParams::new(vec!["svc7test.local".to_owned(), "127.0.0.1".to_owned()])
            .expect("rcgen params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "svc7test.local");
    let key_pair = rcgen::KeyPair::generate().expect("rcgen key");
    let cert = params.self_signed(&key_pair).expect("rcgen self-signed");
    (cert.der().to_vec(), key_pair.serialize_der())
}

fn tls_server_fixture(https: bool) -> TlsFixture {
    use rustls::ServerConfig;
    use rustls::crypto::ring::default_provider;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let (cert_der, key_der) = rcgen_test_cert();
    let config = ServerConfig::builder_with_provider(default_provider().into())
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
        )
        .expect("server cert");
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls fixture");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let received_http = Arc::new(std::sync::Mutex::new(Vec::new()));
    let stop_clone = stop.clone();
    let received_clone = received_http.clone();
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(25);
        while !stop_clone.load(Ordering::SeqCst) && Instant::now() < deadline {
            let (stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(_) => break,
            };
            let config = config.clone();
            let received_clone = received_clone.clone();
            std::thread::spawn(move || {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(4)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(4)));
                let Ok(mut conn) = rustls::ServerConnection::new(config) else {
                    return;
                };
                let mut stream = stream;
                let mut handshook = false;
                for _ in 0..200 {
                    match conn.complete_io(&mut stream) {
                        Ok(_) => {
                            if !conn.is_handshaking() {
                                handshook = true;
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                if !handshook {
                    return;
                }
                if https {
                    let mut tls = rustls::Stream::new(&mut conn, &mut stream);
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        use std::io::Read as _;
                        match tls.read(&mut chunk) {
                            Ok(0) => break,
                            Ok(count) => {
                                request.extend_from_slice(&chunk[..count]);
                                if request.windows(4).any(|w| w == b"\r\n\r\n")
                                    || request.len() > 8192
                                {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    received_clone.lock().unwrap().extend_from_slice(&request);
                    let body = b"<html><head><title>TLS Fixture</title></head></html>";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nServer: tls-fixture/1.0\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    use std::io::Write as _;
                    let _ = tls.write_all(response.as_bytes());
                    let _ = tls.write_all(body);
                    let _ = tls.flush();
                } else {
                    std::thread::sleep(Duration::from_millis(400));
                }
            });
        }
    });
    TlsFixture {
        port,
        stop,
        received_http,
    }
}

impl Drop for TlsFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

// ---------- module test helpers ----------

fn plan_for_ports(ports: &str) -> ScanPlan {
    let cli =
        Cli::try_parse_from(["rxscan", "127.0.0.1", "--ports", ports, "--level", "4"]).unwrap();
    ScanPlan::compile(cli).unwrap()
}

fn provenance_for(plan: &ScanPlan) -> Provenance {
    Provenance::new("test.module", "7.0.0", plan.stable_id(), Timestamp(0)).unwrap()
}

struct AllowAll;
impl ScopeGuard for AllowAll {
    fn permits(&self, _target: &TaskScopeTarget) -> bool {
        true
    }
}

fn service_task_for(
    plan: &ScanPlan,
    address: &str,
    port: u16,
    probes: &str,
    timeout_ms: u64,
    guard: &dyn ScopeGuard,
) -> Task {
    let parent = rxscan::tcp_discovery::port_asset_id(
        &rxscan::tcp_discovery::parent_asset_id_for_ip(&address.parse().unwrap()),
        "tcp",
        port,
    );
    Task::new_with_params(
        TaskKind::ServiceProbe,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        50,
        Duration::from_millis(timeout_ms),
        RetryPolicy::default(),
        "rxscan.service",
        provenance_for(plan),
        TaskScopeTarget::Ip(address.parse().unwrap()),
        BTreeMap::from([
            ("target".to_owned(), "127.0.0.1".to_owned()),
            ("address".to_owned(), address.to_owned()),
            ("port".to_owned(), port.to_string()),
            ("transport".to_owned(), "tcp".to_owned()),
            ("parent_asset".to_owned(), parent),
            ("probes".to_owned(), probes.to_owned()),
        ]),
        guard,
    )
    .unwrap()
}

fn fast_policy(plan: &ScanPlan) -> rxscan::service_probe::ServicePolicy {
    rxscan::service_probe::ServicePolicy::new(plan.level, plan.goal, SpeedSetting::Numeric(100))
}

fn block_on_service(
    module: &ServiceProbeModule,
    context: ModuleContext,
) -> Result<ModuleOutput, ModuleError> {
    use std::task::{Context as TaskContext, Poll, RawWaker, RawWakerVTable, Waker};
    unsafe fn raw_waker(thread: std::thread::Thread) -> RawWaker {
        unsafe fn clone(data: *const ()) -> RawWaker {
            let thread = unsafe { &*(data as *const std::thread::Thread) };
            unsafe { raw_waker(thread.clone()) }
        }
        unsafe fn wake(data: *const ()) {
            let thread = unsafe { Box::from_raw(data as *mut std::thread::Thread) };
            thread.unpark();
        }
        unsafe fn wake_by_ref(data: *const ()) {
            unsafe { (&*(data as *const std::thread::Thread)).unpark() };
        }
        unsafe fn drop_waker(data: *const ()) {
            drop(unsafe { Box::from_raw(data as *mut std::thread::Thread) });
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop_waker);
        RawWaker::new(Box::into_raw(Box::new(thread)) as *const (), &VTABLE)
    }
    let waker = unsafe { Waker::from_raw(raw_waker(std::thread::current())) };
    let mut task_context = TaskContext::from_waker(&waker);
    let mut future = module.execute(context);
    loop {
        match future.as_mut().poll(&mut task_context) {
            Poll::Ready(value) => break value,
            Poll::Pending => std::thread::park(),
        }
    }
}

fn service_observation_in(output: &ModuleOutput) -> serde_json::Value {
    // The observation evidence carries a `protocol` field; certificate
    // evidence (TLS family) does not — skip straight to the observation.
    output
        .evidence
        .iter()
        .find(|evidence| {
            evidence.source == "rxscan.service" && evidence.details.data.get("protocol").is_some()
        })
        .map(|evidence| evidence.details.data.clone())
        .expect("service observation evidence")
}

fn service_finding_in(output: &ModuleOutput) -> Option<&rxscan::model::Finding> {
    output
        .findings
        .iter()
        .find(|finding| finding.title.contains("service on port"))
}

// ---------- recognition ----------

#[test]
fn ssh_banner_recognition_without_authentication() {
    let fixture = ssh_fixture();
    let plan = plan_for_ports(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        fixture.port,
        "ssh",
        8000,
        guard.as_ref(),
    );
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let observation = service_observation_in(&output);
    assert_eq!(observation["protocol"], "ssh");
    assert_eq!(observation["protocol_version"], "2.0");
    assert_eq!(observation["product_hint"], "OpenSSH");
    assert_eq!(observation["version_hint"], "9.8");
    assert!(observation["confidence"].as_u64().unwrap() >= 85);
    assert!(
        observation["evidence_lines"]
            .as_array()
            .unwrap()
            .iter()
            .any(|line| line.as_str().unwrap().contains("SSH-2.0-"))
    );
    assert!(service_finding_in(&output).is_some());
    // No authentication bytes ever reached the fixture.
    assert!(fixture.received_bytes().is_empty());
    assert!(
        output
            .events
            .iter()
            .any(|event| { format!("{:?}", event.kind) == "ProtocolDetected" })
    );
}

#[test]
fn ssh_malformed_banner_is_not_ssh() {
    let fixture = ssh_malformed_fixture();
    let plan = plan_for_ports(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        fixture.port,
        "ssh",
        5000,
        guard.as_ref(),
    );
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let observation = service_observation_in(&output);
    assert_eq!(observation["protocol"], "unknown");
    assert!(service_finding_in(&output).is_none());
}

#[test]
fn ssh_timeout_becomes_unknown_not_error_state() {
    let fixture = delayed_fixture(Duration::from_secs(4));
    let plan = plan_for_ports(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        fixture.port,
        "ssh",
        6000,
        guard.as_ref(),
    );
    let started = Instant::now();
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert!(started.elapsed() < Duration::from_secs(10));
    let observation = service_observation_in(&output);
    assert_eq!(observation["protocol"], "unknown");
}

#[test]
fn http_recognition_with_headers_status_and_title() {
    let fixture = http_response_fixture();
    let plan = plan_for_ports(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        fixture.port,
        "http",
        8000,
        guard.as_ref(),
    );
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let observation = service_observation_in(&output);
    assert_eq!(observation["protocol"], "http");
    assert_eq!(observation["product_hint"], "nginx");
    assert_eq!(observation["version_hint"], "1.27.2");
    assert!(observation["confidence"].as_u64().unwrap() >= 85);
    let lines = observation["evidence_lines"].as_array().unwrap();
    assert!(
        lines
            .iter()
            .any(|line| line.as_str().unwrap().contains("200"))
    );
    assert!(
        lines
            .iter()
            .any(|line| line.as_str().unwrap().contains(" Fixture")
                || line.as_str().unwrap().contains("fixture"))
            || lines
                .iter()
                .any(|line| line.as_str().unwrap().contains("title"))
    );
    // Fixture saw exactly one safe GET, never a crawl.
    let received = String::from_utf8_lossy(&fixture.received_bytes()).to_string();
    assert!(received.starts_with("GET / HTTP/1.0"));
    assert_eq!(received.matches("GET ").count(), 1);
    assert!(!received.contains(".."));
}

#[test]
fn http_redirect_is_observed_never_followed() {
    let counter = Arc::new(AtomicUsize::new(0));
    let fixture = http_redirect_fixture(counter.clone());
    let plan = plan_for_ports(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        fixture.port,
        "http",
        8000,
        guard.as_ref(),
    );
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let observation = service_observation_in(&output);
    assert_eq!(observation["protocol"], "http");
    assert!(
        observation["evidence_lines"]
            .as_array()
            .unwrap()
            .iter()
            .any(|line| line.as_str().unwrap().contains("/login"))
    );
    // Exactly one request served: the redirect target was never fetched.
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[test]
fn http_body_is_bounded() {
    let fixture = Fixture::spawn(|mut stream, received| {
        let request = record_all(stream.try_clone().expect("clone fixture stream"), received);
        let _ = request;
        let body = vec![b'B'; 100_000];
        let header = format!(
            "HTTP/1.1 200 OK\r\nServer: big/1.0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(&body);
    });
    let plan = plan_for_ports(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        fixture.port,
        "http",
        8000,
        guard.as_ref(),
    );
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let observation = service_observation_in(&output);
    assert_eq!(observation["protocol"], "http");
    let blob = serde_json::to_string(&observation).unwrap();
    assert!(
        blob.len() < 48 * 1024,
        "observation must stay bounded, got {}",
        blob.len()
    );
}

// ---------- TLS ----------

#[test]
fn tls_success_with_certificate_extraction() {
    let fixture = tls_server_fixture(false);
    let plan = plan_for_ports(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        fixture.port,
        "tls",
        10_000,
        guard.as_ref(),
    );
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let observation = service_observation_in(&output);
    assert_eq!(observation["protocol"], "tls");
    assert!(observation["confidence"].as_u64().unwrap() >= 85);
    let blob = format!("{output:?}");
    assert!(blob.contains("svc7test.local"));
    assert!(blob.contains("127.0.0.1"));
    // Fingerprint is 64 lowercase hex chars.
    let fingerprint = output
        .evidence
        .iter()
        .find_map(|evidence| {
            evidence.details.data["fingerprint_sha256"]
                .as_str()
                .map(str::to_owned)
        })
        .expect("certificate evidence carries a fingerprint");
    assert_eq!(fingerprint.len(), 64);
    assert!(
        fingerprint
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    );
    // Validity window is sane and machine-readable.
    let not_before = output
        .evidence
        .iter()
        .find_map(|evidence| {
            evidence.details.data["not_before"]
                .as_str()
                .map(str::to_owned)
        })
        .unwrap_or_default();
    assert_eq!(not_before.len(), 10, "YYYY-MM-DD date, got {not_before:?}");
}

#[test]
fn tls_failure_never_becomes_https() {
    // Plain-HTTP fixture probed for TLS: handshake fails, no HTTPS claim.
    let fixture = http_response_fixture();
    let plan = plan_for_ports(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        fixture.port,
        "tls",
        8000,
        guard.as_ref(),
    );
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let observation = service_observation_in(&output);
    assert_eq!(observation["protocol"], "unknown");
    assert_ne!(observation["service_label"], "https");
}

#[test]
fn https_requires_real_http_over_tls_evidence() {
    // Fixture speaks HTTPS (HTTP inside TLS). With an https-capable plan the
    // module must classify `https` (tls=true); with a tls-only plan the same
    // fixture honestly stays bare `tls`.
    let fixture = tls_server_fixture(true);
    let plan = plan_for_ports(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());

    let task = service_task_for(
        &plan,
        "127.0.0.1",
        fixture.port,
        "tls,http",
        10_000,
        guard.as_ref(),
    );
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let observation = service_observation_in(&output);
    assert_eq!(observation["protocol"], "http");
    assert_eq!(observation["tls"], true);
    assert_eq!(observation["service_label"], "https");
    assert!(observation["confidence"].as_u64().unwrap() >= 85);
    // The HTTP request really ran inside the TLS session server-side.
    let seen = String::from_utf8_lossy(&fixture.received_http.lock().unwrap()).to_string();
    assert!(seen.starts_with("GET / HTTP/1.0"));

    let task = service_task_for(
        &plan,
        "127.0.0.1",
        fixture.port,
        "tls",
        10_000,
        guard.as_ref(),
    );
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let observation = service_observation_in(&output);
    assert_eq!(observation["protocol"], "tls");
    assert_ne!(observation["service_label"], "https");
}

// ---------- FTP / SMTP / databases ----------

#[test]
fn ftp_banner_recognition_stays_passive() {
    let fixture = ftp_fixture();
    let plan = plan_for_ports(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        fixture.port,
        "ftp",
        8000,
        guard.as_ref(),
    );
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let observation = service_observation_in(&output);
    assert_eq!(observation["protocol"], "ftp");
    assert_eq!(observation["product_hint"], "FixtureFTP");
    assert_eq!(observation["version_hint"], "1.0");
    // Disambiguation exchange only: one EHLO (rejected) + one NOOP
    // (accepted). Still no authentication, no file commands.
    assert_eq!(fixture.received_bytes(), b"EHLO rxscan.local\r\nNOOP\r\n");
}

#[test]
fn smtp_greeting_and_bounded_ehlo_capabilities() {
    let fixture = smtp_fixture();
    let plan = plan_for_ports(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        fixture.port,
        "smtp",
        8000,
        guard.as_ref(),
    );
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let observation = service_observation_in(&output);
    assert_eq!(observation["protocol"], "smtp");
    let capabilities = observation["capabilities"].as_array().unwrap();
    let names: Vec<&str> = capabilities
        .iter()
        .filter_map(|value| value.as_str())
        .collect();
    assert!(names.contains(&"STARTTLS"));
    assert!(names.contains(&"8BITMIME"));
    // Only greeting + one EHLO observed server-side; no mail, no auth.
    let received = String::from_utf8_lossy(&fixture.received_bytes()).to_string();
    assert!(received.contains("EHLO rxscan.local"));
    assert!(!received.contains("MAIL"));
    assert!(!received.contains("AUTH"));
}

#[test]
fn redis_mysql_postgres_safe_handshakes() {
    let redis = redis_fixture();
    let mysql = mysql_fixture();
    let pg_seen = Arc::new(AtomicBool::new(false));
    let postgres = postgres_fixture(pg_seen.clone());
    let plan = plan_for_ports("6379");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());

    let task = service_task_for(
        &plan,
        "127.0.0.1",
        redis.port,
        "redis",
        8000,
        guard.as_ref(),
    );
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert_eq!(service_observation_in(&output)["protocol"], "redis");
    assert_eq!(redis.received_bytes(), b"PING\r\n");

    let task = service_task_for(
        &plan,
        "127.0.0.1",
        mysql.port,
        "mysql",
        8000,
        guard.as_ref(),
    );
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let observation = service_observation_in(&output);
    assert_eq!(observation["protocol"], "mysql");
    assert!(
        observation["version_hint"]
            .as_str()
            .unwrap()
            .contains("8.0.36")
    );
    assert!(mysql.received_bytes().is_empty());

    let task = service_task_for(
        &plan,
        "127.0.0.1",
        postgres.port,
        "postgres",
        8000,
        guard.as_ref(),
    );
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert_eq!(service_observation_in(&output)["protocol"], "postgres");
    assert!(pg_seen.load(Ordering::SeqCst));
    assert_eq!(postgres.received_bytes(), vec![0, 0, 0, 8, 4, 210, 22, 47]);
}

// ---------- unknown / bounds ----------

#[test]
fn unknown_service_stays_unknown_with_banner() {
    let fixture = unknown_banner_fixture();
    let plan = plan_for_ports(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        fixture.port,
        "generic",
        8000,
        guard.as_ref(),
    );
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let observation = service_observation_in(&output);
    assert_eq!(observation["protocol"], "unknown");
    assert!(
        observation["banner"]
            .as_str()
            .unwrap()
            .contains("HELLO-STRANGE")
    );
    assert!(service_finding_in(&output).is_none());
    assert!(fixture.received_bytes().is_empty());
}

fn vague_banner_fixture(banner: &'static [u8]) -> Fixture {
    Fixture::spawn(|mut stream, received| {
        let _ = stream.write_all(banner);
        let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
        let mut chunk = [0u8; 512];
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
        }
    })
}

#[test]
fn vague_ssh_like_banners_stay_unknown() {
    // A bare `SSH-` prefix or a malformed version is vague text, not
    // protocol evidence — even the generic probe must not classify it.
    // Only a grammar-valid identification string earns an SSH claim.
    for banner in [
        &b"SSH-hello\r\n"[..],
        &b"SSH-\r\n"[..],
        &b"SSH-2\r\n"[..],
        &b"SSH-bogus comment\r\n"[..],
    ] {
        let fixture = vague_banner_fixture(banner);
        let plan = plan_for_ports(&fixture.port.to_string());
        let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
        let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
        for probes in ["generic", "ssh"] {
            let task = service_task_for(
                &plan,
                "127.0.0.1",
                fixture.port,
                probes,
                5000,
                guard.as_ref(),
            );
            let output = block_on_service(
                &module,
                ModuleContext::new(task, CancellationToken::default()),
            )
            .unwrap();
            let observation = service_observation_in(&output);
            assert_eq!(
                observation["protocol"], "unknown",
                "banner {banner:?} via {probes} must stay unknown"
            );
            assert!(service_finding_in(&output).is_none());
        }
    }
    // An unterminated fragment is not a banner line and never classifies,
    // even when its bytes look SSH-shaped.
    let fragment = Fixture::spawn(|mut stream, received| {
        let _ = stream.write_all(b"SSH-2.0-Partial");
        std::thread::sleep(Duration::from_secs(4));
        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
        let mut chunk = [0u8; 512];
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
        }
    });
    let plan = plan_for_ports(&fragment.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    for probes in ["generic", "ssh"] {
        let task = service_task_for(
            &plan,
            "127.0.0.1",
            fragment.port,
            probes,
            6000,
            guard.as_ref(),
        );
        let output = block_on_service(
            &module,
            ModuleContext::new(task, CancellationToken::default()),
        )
        .unwrap();
        assert_eq!(
            service_observation_in(&output)["protocol"],
            "unknown",
            "unterminated fragment via {probes} must stay unknown"
        );
    }
}

#[test]
fn port_hints_never_confer_identity() {
    // Running the WRONG probe against a speaking service must not mislabel
    // it: hints select probe order, only handshake bytes prove identity.
    let ssh = ssh_fixture();
    let http = http_response_fixture();
    let plan = plan_for_ports("22");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    // SSH probe against an HTTP speaker: unknown, never ssh.
    let task = service_task_for(&plan, "127.0.0.1", http.port, "ssh", 6000, guard.as_ref());
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert_eq!(service_observation_in(&output)["protocol"], "unknown");
    // HTTP probe against an SSH speaker: unknown, never http.
    let task = service_task_for(&plan, "127.0.0.1", ssh.port, "http", 6000, guard.as_ref());
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert_eq!(service_observation_in(&output)["protocol"], "unknown");
    // Generic probe against a grammar-valid SSH banner on an unknown port
    // still extracts the full observation (concrete matcher evidence).
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        ssh.port,
        "generic",
        6000,
        guard.as_ref(),
    );
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let observation = service_observation_in(&output);
    assert_eq!(observation["protocol"], "ssh");
    assert_eq!(observation["product_hint"], "OpenSSH");
}

#[test]
fn failed_composition_is_recorded_not_silent() {
    // TLS-only fixture (no HTTP inside) with an https-capable plan: bare
    // `tls` stands, and the completed summary records why no application
    // layer was claimed.
    let plain_tls = tls_server_fixture(false);
    let plan = plan_for_ports(&plain_tls.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        plain_tls.port,
        "tls,http",
        10_000,
        guard.as_ref(),
    );
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert_eq!(service_observation_in(&output)["protocol"], "tls");
    let completed = output
        .events
        .iter()
        .find(|event| format!("{:?}", event.kind) == "ServiceProbeCompleted")
        .unwrap();
    let attempts = completed.details.data["attempts"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(
        attempts.contains("staying bare TLS"),
        "negative composition must be recorded, got: {attempts}"
    );
    // Sanity: an HTTPS fixture with the same plan classifies https, proving
    // the negative above is an evidence outcome, not a broken composition.
    let https = tls_server_fixture(true);
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        https.port,
        "tls,http",
        10_000,
        guard.as_ref(),
    );
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert_eq!(service_observation_in(&output)["service_label"], "https");
}

#[test]
fn generic_banner_is_bounded_and_truncation_noted() {
    let fixture = oversized_fixture();
    let plan = plan_for_ports(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        fixture.port,
        "generic",
        8000,
        guard.as_ref(),
    );
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let blob = serde_json::to_string(&service_observation_in(&output)).unwrap();
    assert!(
        blob.len() < 16 * 1024,
        "bounded observation, got {}",
        blob.len()
    );
    assert!(blob.contains("truncat"));
}

#[test]
fn silent_service_completes_as_unknown() {
    let fixture = silent_fixture();
    let plan = plan_for_ports(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        fixture.port,
        "generic",
        6000,
        guard.as_ref(),
    );
    let started = Instant::now();
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(service_observation_in(&output)["protocol"], "unknown");
}

// ---------- cancellation / timeout / retries ----------

#[test]
fn cancellation_is_prompt_before_and_during_probes() {
    let fixture = ssh_fixture();
    let plan = plan_for_ports(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        fixture.port,
        "ssh",
        8000,
        guard.as_ref(),
    );
    let token = CancellationToken::default();
    token.cancel();
    let started = Instant::now();
    let result = block_on_service(&module, ModuleContext::new(task, token));
    assert!(matches!(result, Err(ModuleError::Cancelled)));
    assert!(started.elapsed() < Duration::from_millis(500));

    // Mid-probe cancel against a silent fixture stays bounded.
    let silent = silent_fixture();
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        silent.port,
        "generic",
        20_000,
        guard.as_ref(),
    );
    let token = CancellationToken::default();
    let token_clone = token.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        token_clone.cancel();
    });
    let started = Instant::now();
    let result = block_on_service(&module, ModuleContext::new(task, token));
    assert!(matches!(result, Err(ModuleError::Cancelled)));
    assert!(started.elapsed() < Duration::from_secs(8));
}

#[test]
fn timeouts_produce_partial_unknown_with_truncation() {
    let fixture = delayed_fixture(Duration::from_secs(5));
    let plan = plan_for_ports(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    // Task deadline shorter than the fixture delay: partial, truncated, Ok.
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        fixture.port,
        "generic,http",
        900,
        guard.as_ref(),
    );
    let started = Instant::now();
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert!(started.elapsed() < Duration::from_secs(8));
    let completed = output
        .events
        .iter()
        .find(|event| format!("{:?}", event.kind) == "ServiceProbeCompleted")
        .unwrap();
    assert_eq!(completed.details.data["protocol"], "unknown");
}

#[test]
fn connections_are_never_retried_per_probe() {
    // Silent fixture + two planned probes: exactly two connections total —
    // timeouts become evidence, never retries.
    let fixture = silent_fixture();
    let plan = plan_for_ports(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        fixture.port,
        "generic,http",
        12_000,
        guard.as_ref(),
    );
    let before = fixture.connections.load(Ordering::SeqCst);
    let _ = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let after = fixture.connections.load(Ordering::SeqCst);
    assert_eq!(after - before, 2);
}

// ---------- scope ----------

#[test]
fn scope_guard_blocks_service_scans_without_network() {
    struct DenyAll;
    impl ScopeGuard for DenyAll {
        fn permits(&self, _target: &TaskScopeTarget) -> bool {
            false
        }
    }
    let plan = plan_for_ports("80");
    let task = service_task_for(&plan, "127.0.0.1", 80, "http", 3000, &AllowAll);
    let policy = rxscan::service_probe::ServicePolicy::new(plan.level, plan.goal, plan.speed);
    let module = ServiceProbeModule::new(policy, Arc::new(DenyAll));
    let result = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    );
    assert!(matches!(result, Err(ModuleError::Failed { .. })));
}

#[test]
fn stale_scope_skips_service_task_without_network() {
    use std::sync::atomic::AtomicBool;
    struct FlippingGuard {
        allowed: AtomicBool,
    }
    impl ScopeGuard for FlippingGuard {
        fn permits(&self, _target: &TaskScopeTarget) -> bool {
            self.allowed.load(Ordering::SeqCst)
        }
    }
    let plan = plan_for_ports("80");
    let guard = Arc::new(FlippingGuard {
        allowed: AtomicBool::new(true),
    });
    let mut scheduler = Scheduler::new(
        8,
        BudgetLimits::default(),
        SpeedGovernor::new(SpeedSetting::Numeric(100), 2).unwrap(),
        guard.clone(),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    let policy = rxscan::service_probe::ServicePolicy::new(plan.level, plan.goal, plan.speed);
    scheduler.register_module(Arc::new(ServiceProbeModule::new(policy, guard.clone())));
    let parent = rxscan::tcp_discovery::port_asset_id(
        &rxscan::tcp_discovery::parent_asset_id_for_ip(&"127.0.0.1".parse().unwrap()),
        "tcp",
        80,
    );
    let task = Task::new_with_params(
        TaskKind::ServiceProbe,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        50,
        Duration::from_millis(3000),
        RetryPolicy::default(),
        "rxscan.service",
        provenance_for(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([
            ("target".to_owned(), "127.0.0.1".to_owned()),
            ("address".to_owned(), "127.0.0.1".to_owned()),
            ("port".to_owned(), "80".to_owned()),
            ("parent_asset".to_owned(), parent),
            ("probes".to_owned(), "http".to_owned()),
        ]),
        guard.as_ref(),
    )
    .unwrap();
    scheduler.add_task(task).unwrap();
    guard.allowed.store(false, Ordering::SeqCst);
    let report = scheduler.run().unwrap();
    assert_eq!(report.skipped.len(), 1);
    assert!(report.completed.is_empty());
}

// ---------- policy ----------

#[test]
fn speed_changes_pressure_not_truth_criteria() {
    let slow =
        rxscan::service_probe::ServicePolicy::new(3, ScanGoal::Recon, SpeedSetting::Numeric(0));
    let fast =
        rxscan::service_probe::ServicePolicy::new(3, ScanGoal::Recon, SpeedSetting::Numeric(100));
    assert!(fast.probe_budget() < slow.probe_budget());
    assert_eq!(
        plan_probes(22, 3, ScanGoal::Recon),
        plan_probes(22, 3, ScanGoal::Recon)
    );
}

#[test]
fn level_controls_probe_breadth_explicit_probes_preserved() {
    assert!(plan_probes(22, 1, ScanGoal::Recon).len() <= 1);
    assert!(plan_probes(22, 5, ScanGoal::Recon).len() <= MAX_PROBES_PER_PORT);
    // Engine-recorded probe lists ride in task params untouched.
    let plan = plan_for_ports("22");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let task = service_task_for(&plan, "127.0.0.1", 22, "ssh,generic", 3000, guard.as_ref());
    assert_eq!(task.params["probes"], "ssh,generic");
}

// ---------- decision engine ----------

fn open_port_output(plan: &ScanPlan, address: &str, port: u16, port_asset: &str) -> ModuleOutput {
    let provenance =
        Provenance::new("rxscan.port", "6.0.0", plan.stable_id(), Timestamp(1)).unwrap();
    let mut finding = rxscan::model::Finding::new(
        format!("Open TCP port {port}"),
        rxscan::model::Severity::Info,
        rxscan::model::Confidence::new(95).unwrap(),
        rxscan::model::AssetId(port_asset.to_owned()),
        provenance,
    )
    .unwrap();
    finding.metadata.insert(
        "address".to_owned(),
        serde_json::Value::String(address.to_owned()),
    );
    finding
        .metadata
        .insert("port".to_owned(), serde_json::Value::from(port));
    ModuleOutput {
        events: Vec::new(),
        evidence: Vec::new(),
        findings: vec![finding],
        assets: Vec::new(),
    }
}

#[test]
fn decision_engine_proposes_service_for_open_ports() {
    let plan = plan_for_ports("80");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let engine = Phase7Engine::new(
        guard.clone(),
        plan.stable_id(),
        4,
        plan.goal,
        plan.tcp_ports.clone(),
        plan.speed,
    );
    let port_asset = rxscan::tcp_discovery::port_asset_id(
        &rxscan::tcp_discovery::parent_asset_id_for_ip(&"127.0.0.1".parse().unwrap()),
        "tcp",
        80,
    );
    let port_task = Task::new_with_params(
        TaskKind::PortDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        60,
        Duration::from_millis(5000),
        RetryPolicy::default(),
        "rxscan.port",
        provenance_for(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([
            ("target".to_owned(), "127.0.0.1".to_owned()),
            ("ports".to_owned(), "explicit:80".to_owned()),
        ]),
        guard.as_ref(),
    )
    .unwrap();
    let output = open_port_output(&plan, "127.0.0.1", 80, &port_asset);
    let proposals = engine.follow_up_tasks(&port_task, &output);
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].kind, TaskKind::ServiceProbe);
    assert_eq!(proposals[0].params["address"], "127.0.0.1");
    assert_eq!(proposals[0].params["port"], "80");
    assert_eq!(proposals[0].params["parent_asset"], port_asset);
    // Host completions never propose *service* tasks (host→port rule only
    // fires for host outputs with conclusions; empty outputs propose nothing).
    let host_task = Task::new_with_params(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        80,
        Duration::from_millis(5000),
        RetryPolicy::default(),
        "rxscan.host",
        provenance_for(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([("target".to_owned(), "127.0.0.1".to_owned())]),
        guard.as_ref(),
    )
    .unwrap();
    assert!(
        engine
            .follow_up_tasks(&host_task, &ModuleOutput::default())
            .iter()
            .all(|task| task.kind != TaskKind::ServiceProbe)
    );
    assert!(
        engine
            .follow_up_tasks(&port_task, &ModuleOutput::default())
            .is_empty()
    );
}

#[test]
fn duplicate_service_proposals_share_ids_and_dedup() {
    let plan = plan_for_ports("80");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let engine = Phase7Engine::new(
        guard.clone(),
        plan.stable_id(),
        4,
        plan.goal,
        plan.tcp_ports.clone(),
        plan.speed,
    );
    let port_asset = rxscan::tcp_discovery::port_asset_id(
        &rxscan::tcp_discovery::parent_asset_id_for_ip(&"127.0.0.1".parse().unwrap()),
        "tcp",
        80,
    );
    let port_task = Task::new_with_params(
        TaskKind::PortDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        60,
        Duration::from_millis(5000),
        RetryPolicy::default(),
        "rxscan.port",
        provenance_for(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([
            ("target".to_owned(), "127.0.0.1".to_owned()),
            ("ports".to_owned(), "explicit:80".to_owned()),
        ]),
        guard.as_ref(),
    )
    .unwrap();
    let output = open_port_output(&plan, "127.0.0.1", 80, &port_asset);
    let first = engine.follow_up_tasks(&port_task, &output);
    let second = engine.follow_up_tasks(&port_task, &output);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].id, second[0].id);
    // Scheduler admission enforces the dedup.
    let mut scheduler = Scheduler::new(
        16,
        BudgetLimits::default(),
        SpeedGovernor::new(SpeedSetting::Numeric(100), 2).unwrap(),
        guard.clone(),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler
        .add_task(first[0].clone())
        .expect("first admission");
    assert!(scheduler.add_task(second[0].clone()).is_err());
}

#[test]
fn out_of_scope_service_proposals_are_rejected() {
    struct DenyAll;
    impl ScopeGuard for DenyAll {
        fn permits(&self, _target: &TaskScopeTarget) -> bool {
            false
        }
    }
    let plan = plan_for_ports("80");
    let engine = Phase7Engine::new(
        Arc::new(DenyAll),
        plan.stable_id(),
        4,
        plan.goal,
        plan.tcp_ports.clone(),
        plan.speed,
    );
    let guard = AllowAll;
    let port_task = Task::new_with_params(
        TaskKind::PortDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        60,
        Duration::from_millis(5000),
        RetryPolicy::default(),
        "rxscan.port",
        provenance_for(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([
            ("target".to_owned(), "127.0.0.1".to_owned()),
            ("ports".to_owned(), "explicit:80".to_owned()),
        ]),
        &guard,
    )
    .unwrap();
    let output = open_port_output(&plan, "127.0.0.1", 80, "asset_port_x");
    assert!(engine.follow_up_tasks(&port_task, &output).is_empty());
}

// ---------- assets / output ----------

#[test]
fn service_asset_ids_are_stable_and_scoped() {
    let parent = "asset_port_abc123";
    assert_eq!(
        service_asset_id(parent, "ssh", false),
        service_asset_id(parent, "ssh", false)
    );
    assert_ne!(
        service_asset_id(parent, "ssh", false),
        service_asset_id(parent, "http", false)
    );
    assert_ne!(
        service_asset_id(parent, "http", false),
        service_asset_id(parent, "http", true)
    );
    assert_ne!(
        service_asset_id("asset_port_aaa", "http", false),
        service_asset_id("asset_port_bbb", "http", false)
    );
    // open_ports_from_output parses findings deterministically.
    let plan = plan_for_ports("80,443");
    let output = open_port_output(&plan, "127.0.0.1", 443, "asset_port_q");
    let mut second = open_port_output(&plan, "127.0.0.1", 80, "asset_port_p");
    second.findings.extend(output.findings);
    let facts = open_ports_from_output(&second);
    assert_eq!(facts.len(), 2);
    assert_eq!(facts[0].port, 80);
    assert_eq!(facts[1].port, 443);
}

#[test]
fn jsonl_and_human_output_carry_services() {
    let ssh = ssh_fixture();
    let http = http_response_fixture();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("rxscan-phase7-jsonl-{stamp}"));
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("out.jsonl");
    let cli = Cli::try_parse_from([
        "rxscan",
        "127.0.0.1",
        "--ports",
        &format!("{},{}", ssh.port, http.port),
        "--level",
        "4",
        "--output",
        path.to_str().unwrap(),
    ])
    .unwrap();
    let report = rxscan::run::execute(cli).unwrap();
    assert!(report.jsonl_bytes > 0);
    let contents = fs::read_to_string(&path).unwrap();
    let mut saw_service_asset = false;
    let mut saw_identified = false;
    let mut saw_service_finding = false;
    let mut saw_cert_or_banner = false;
    for line in contents.lines() {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(value["schema_version"], SCHEMA_VERSION);
        let record_type = value["record_type"].as_str().unwrap();
        let payload = &value["payload"];
        assert!(
            payload["provenance"]["scan_plan_id"]
                .as_str()
                .unwrap()
                .starts_with("plan_")
        );
        match record_type {
            "asset"
                if payload["id"]
                    .as_str()
                    .unwrap()
                    .starts_with("asset_service_") =>
            {
                saw_service_asset = true;
            }
            "event" if payload["kind"] == "service_identified" => {
                saw_identified = true;
                assert!(payload["details"]["data"]["protocol"] != "unknown");
            }
            "finding"
                if payload["title"]
                    .as_str()
                    .unwrap()
                    .contains("service on port") =>
            {
                saw_service_finding = true;
            }
            "event"
                if payload["kind"] == "banner_observed" || payload["kind"] == "tls_observed" =>
            {
                saw_cert_or_banner = true;
            }
            _ => {}
        }
    }
    assert!(saw_service_asset && saw_identified && saw_service_finding && saw_cert_or_banner);
    // Human table shows services with product hints, one row per open port.
    assert!(report.open_ports_summary.contains("HOST 127.0.0.1"));
    assert!(report.open_ports_summary.contains("SERVICE"));
    assert!(report.open_ports_summary.contains("ssh"));
    assert!(report.open_ports_summary.contains("http"));
    assert!(report.open_ports_summary.contains("OpenSSH"));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn no_authentication_or_destructive_bytes_are_ever_sent() {
    // Aggregate every byte all fixtures receive across every safe probe.
    let ssh = ssh_fixture();
    let http = http_response_fixture();
    let ftp = ftp_fixture();
    let smtp = smtp_fixture();
    let redis = redis_fixture();
    let mysql = mysql_fixture();
    let pg_seen = Arc::new(AtomicBool::new(false));
    let postgres = postgres_fixture(pg_seen);
    let generic = unknown_banner_fixture();
    let plan = plan_for_ports("22");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    for (port, probes) in [
        (ssh.port, "ssh"),
        (http.port, "http"),
        (ftp.port, "ftp"),
        (smtp.port, "smtp"),
        (redis.port, "redis"),
        (mysql.port, "mysql"),
        (postgres.port, "postgres"),
        (generic.port, "generic"),
    ] {
        let task = service_task_for(&plan, "127.0.0.1", port, probes, 8000, guard.as_ref());
        let _ = block_on_service(
            &module,
            ModuleContext::new(task, CancellationToken::default()),
        );
    }
    let mut aggregate = Vec::new();
    for fixture in [
        &ssh, &http, &ftp, &smtp, &redis, &mysql, &postgres, &generic,
    ] {
        aggregate.extend_from_slice(&fixture.received_bytes());
    }
    let upper = String::from_utf8_lossy(&aggregate).to_ascii_uppercase();
    for forbidden in [
        "AUTH",
        "USER ",
        "PASS",
        "LOGIN",
        "VRFY",
        "EXPN",
        "MAIL FROM",
        "RCPT",
        "DELETE",
        "DROP",
        "FLUSHALL",
        "SHUTDOWN",
        "KEYS ",
        "CONFIG ",
    ] {
        assert!(
            !upper.contains(forbidden),
            "forbidden protocol bytes observed: {forbidden}"
        );
    }
    // Exact allowlist: purely passive probes send nothing at all.
    assert!(ssh.received_bytes().is_empty());
    assert!(mysql.received_bytes().is_empty());
    assert!(generic.received_bytes().is_empty());
    // Mail disambiguation sends exactly EHLO (+NOOP for FTP).
    assert_eq!(ftp.received_bytes(), b"EHLO rxscan.local\r\nNOOP\r\n");
    // Active probes send exactly their documented payloads.
    assert_eq!(redis.received_bytes(), b"PING\r\n");
    assert_eq!(postgres.received_bytes(), vec![0, 0, 0, 8, 4, 210, 22, 47]);
    let http_text = String::from_utf8_lossy(&http.received_bytes()).to_string();
    assert!(http_text.starts_with("GET / HTTP/1.0\r\n"));
    let smtp_text = String::from_utf8_lossy(&smtp.received_bytes()).to_string();
    assert_eq!(smtp_text, "EHLO rxscan.local\r\n");
}

// ---------- no Phase 0-6 regressions (spot) ----------

#[test]
fn service_tasks_do_not_chain_further() {
    let plan = plan_for_ports("80");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let engine = Phase7Engine::new(
        guard.clone(),
        plan.stable_id(),
        4,
        plan.goal,
        plan.tcp_ports.clone(),
        plan.speed,
    );
    let task = service_task_for(&plan, "127.0.0.1", 80, "http", 3000, guard.as_ref());
    let mut task = task;
    task.kind = TaskKind::ServiceProbe;
    assert!(
        engine
            .follow_up_tasks(&task, &ModuleOutput::default())
            .is_empty()
    );
}

// ---------- acceptance gate: service truth on nonstandard ports ----------

#[test]
fn proofssh_banner_on_nonstandard_port_is_identified_end_to_end() {
    // Controlled loopback listener on an ephemeral (nonstandard, never 22)
    // port emitting `SSH-2.0-ProofSSH_1.0`. Full run must prove: exact port
    // requested + attempted, port open, service identified as SSH from
    // banner evidence (product/version only to banner precision), evidence
    // with provenance, and completed service follow-up.
    let fixture = Fixture::spawn(|mut stream, received| {
        let _ = stream.write_all(b"SSH-2.0-ProofSSH_1.0\r\n");
        let _ = stream.set_read_timeout(Some(Duration::from_millis(600)));
        let mut chunk = [0u8; 512];
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
        }
        std::thread::sleep(Duration::from_millis(100));
    });
    assert_ne!(fixture.port, 22, "fixture must be nonstandard");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("rxscan-svc-proof-{stamp}"));
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("out.jsonl");
    let cli = Cli::try_parse_from([
        "rxscan",
        "127.0.0.1",
        "--ports",
        &fixture.port.to_string(),
        "--level",
        "3",
        "--output",
        path.to_str().unwrap(),
    ])
    .unwrap();
    let report = rxscan::run::execute(cli).unwrap();
    // Scan + service probe each opened a real connection.
    assert!(
        fixture.connections.load(Ordering::SeqCst) >= 2,
        "port scan and service follow-up must both contact the listener"
    );
    let contents = fs::read_to_string(&path).unwrap();
    let mut saw_open = false;
    let mut saw_identified = false;
    let mut saw_banner = false;
    let mut saw_evidence = false;
    let mut saw_completed = false;
    let mut saw_ssh_finding = false;
    for line in contents.lines() {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        let record_type = value["record_type"].as_str().unwrap();
        let payload = &value["payload"];
        match record_type {
            "event" if payload["kind"] == "port_scan_completed" => {
                let data = &payload["details"]["data"];
                assert_eq!(data["requested_ports"], serde_json::json!([fixture.port]));
                assert_eq!(data["attempted_ports"], serde_json::json!([fixture.port]));
                assert_eq!(data["open_ports"], serde_json::json!([fixture.port]));
                assert_eq!(data["unscanned"], serde_json::json!(0));
            }
            "event" if payload["kind"] == "port_open" => {
                assert_eq!(
                    payload["details"]["data"]["port"],
                    serde_json::json!(fixture.port)
                );
                saw_open = true;
            }
            "event" if payload["kind"] == "service_identified" => {
                let data = &payload["details"]["data"];
                assert_eq!(data["port"], serde_json::json!(fixture.port));
                assert_eq!(data["protocol"], serde_json::json!("ssh"));
                // Precision actually supported by the banner: product/version
                // split from `ProofSSH_1.0`, protocol version from `2.0`.
                // Nothing more specific is claimed.
                assert_eq!(data["product_hint"], serde_json::json!("ProofSSH"));
                assert_eq!(data["version_hint"], serde_json::json!("1.0"));
                saw_identified = true;
            }
            "event" if payload["kind"] == "banner_observed" => {
                assert_eq!(
                    payload["details"]["data"]["banner"],
                    serde_json::json!("SSH-2.0-ProofSSH_1.0")
                );
                saw_banner = true;
            }
            "evidence" => {
                let data = &payload["details"]["data"];
                if data.get("protocol") == Some(&serde_json::json!("ssh"))
                    && data.get("port") == Some(&serde_json::json!(fixture.port))
                {
                    assert_eq!(
                        payload["provenance"]["module_name"],
                        serde_json::json!("rxscan.service")
                    );
                    saw_evidence = true;
                }
            }
            "event" if payload["kind"] == "service_probe_completed" => {
                assert_eq!(
                    payload["details"]["data"]["protocol"],
                    serde_json::json!("ssh")
                );
                saw_completed = true;
            }
            "finding"
                if payload["title"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("ssh service on port") =>
            {
                saw_ssh_finding = true;
            }
            _ => {}
        }
    }
    assert!(saw_open, "port must be reported open");
    assert!(saw_identified, "service must be identified as SSH");
    assert!(saw_banner, "banner evidence must exist");
    assert!(saw_evidence, "service evidence with provenance must exist");
    assert!(saw_completed, "service follow-up must complete");
    assert!(saw_ssh_finding, "SSH finding must exist");
    let human = rxscan::run::human_summary(&report);
    assert!(human.contains("ssh"), "human must report SSH: {human}");
    assert!(
        human.contains("ProofSSH"),
        "human must report product: {human}"
    );
    assert!(human.contains(&format!("{}/tcp", fixture.port)));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn malformed_and_silent_nonstandard_ports_stay_unknown_end_to_end() {
    // Negative control (unrelated banner) + silent listener: ports stay
    // open, RXScan must NOT classify either as SSH, unknown stays valid,
    // and the silent port completes in bounded time (no hang).
    let bad = Fixture::spawn(|mut stream, received| {
        let _ = stream.write_all(b"HELLO-NOT-SSH\r\n");
        let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
        let mut chunk = [0u8; 512];
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
        }
    });
    let silent = silent_fixture();
    assert_ne!(bad.port, 22);
    assert_ne!(silent.port, 22);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("rxscan-svc-neg-{stamp}"));
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("out.jsonl");
    let ports = format!("{},{}", bad.port, silent.port);
    let cli = Cli::try_parse_from([
        "rxscan",
        "127.0.0.1",
        "--ports",
        &ports,
        "--level",
        "3",
        "--output",
        path.to_str().unwrap(),
    ])
    .unwrap();
    let started = Instant::now();
    let report = rxscan::run::execute(cli).unwrap();
    // Bounded even with a 6s-silent listener: probes time out on their own
    // budgets, the task never hangs near the 15s scheduler timeout.
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "silent listener must not stall the run"
    );
    let contents = fs::read_to_string(&path).unwrap();
    let mut opens = Vec::new();
    let mut ssh_identified = Vec::new();
    let mut unknown_completions = 0;
    for line in contents.lines() {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        let record_type = value["record_type"].as_str().unwrap();
        let payload = &value["payload"];
        if record_type == "event" && payload["kind"] == "port_open" {
            opens.push(payload["details"]["data"]["port"].as_u64().unwrap() as u16);
        }
        if record_type == "event" && payload["kind"] == "service_identified" {
            ssh_identified.push(payload["details"]["data"]["port"].as_u64().unwrap() as u16);
        }
        if record_type == "event" && payload["kind"] == "service_probe_completed" {
            assert_eq!(
                payload["details"]["data"]["protocol"],
                serde_json::json!("unknown"),
                "negative/silent ports must stay unknown"
            );
            unknown_completions += 1;
        }
    }
    assert!(opens.contains(&bad.port), "malformed port is still open");
    assert!(opens.contains(&silent.port), "silent port is still open");
    assert!(
        !ssh_identified.contains(&bad.port),
        "malformed banner must NOT classify as SSH"
    );
    assert!(
        !ssh_identified.contains(&silent.port),
        "silence must NOT classify as SSH"
    );
    assert_eq!(
        unknown_completions, 2,
        "both follow-ups complete as unknown"
    );
    let human = rxscan::run::human_summary(&report);
    assert!(!human.contains("ssh"), "human must not claim SSH: {human}");
    fs::remove_dir_all(directory).unwrap();
}

// ---------- Wave 1: port-independent identification matrix ----------

fn plan_for_ports_at_level(ports: &str, level: &str) -> ScanPlan {
    let cli =
        Cli::try_parse_from(["rxscan", "127.0.0.1", "--ports", ports, "--level", level]).unwrap();
    ScanPlan::compile(cli).unwrap()
}

fn run_unknown_plan(port: u16, level: &str, timeout_ms: u64) -> ModuleOutput {
    // No explicit probe order: the module derives the level-graded
    // speculative plan, exactly as production DecisionEngine tasks do.
    let plan = plan_for_ports_at_level(&port.to_string(), level);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    let parent = rxscan::tcp_discovery::port_asset_id(
        &rxscan::tcp_discovery::parent_asset_id_for_ip(&"127.0.0.1".parse().unwrap()),
        "tcp",
        port,
    );
    let task = Task::new_with_params(
        TaskKind::ServiceProbe,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        50,
        Duration::from_millis(timeout_ms),
        RetryPolicy::default(),
        "rxscan.service",
        provenance_for(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([
            ("target".to_owned(), "127.0.0.1".to_owned()),
            ("address".to_owned(), "127.0.0.1".to_owned()),
            ("port".to_owned(), port.to_string()),
            ("transport".to_owned(), "tcp".to_owned()),
            ("parent_asset".to_owned(), parent),
        ]),
        guard.as_ref(),
    )
    .unwrap();
    block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap()
}

fn completed_details(output: &ModuleOutput) -> serde_json::Value {
    output
        .events
        .iter()
        .find(|event| format!("{:?}", event.kind) == "ServiceProbeCompleted")
        .map(|event| event.details.data.clone())
        .expect("service_probe_completed event")
}

#[test]
fn wave1_protocols_identified_on_ephemeral_ports() {
    // Every Wave-1 protocol on a nonstandard ephemeral port, at the level
    // where the selector first reaches it. Port numbers never participate.
    let ssh = ssh_fixture();
    assert_eq!(
        service_observation_in(&run_unknown_plan(ssh.port, "1", 8000))["protocol"],
        "ssh",
        "SSH classifies from passive bytes even at L1"
    );
    let http = http_response_fixture();
    assert_eq!(
        service_observation_in(&run_unknown_plan(http.port, "2", 8000))["protocol"],
        "http",
        "HTTP classifies via L2 speculative GET"
    );
    let redis = redis_fixture();
    assert_eq!(
        service_observation_in(&run_unknown_plan(redis.port, "3", 10000))["protocol"],
        "redis",
        "Redis classifies via L3 speculative PING"
    );
    let mysql = mysql_fixture();
    assert_eq!(
        service_observation_in(&run_unknown_plan(mysql.port, "3", 10000))["protocol"],
        "mysql",
        "MySQL classifies from passive framing at any level"
    );
    let tls = tls_server_fixture(false);
    assert_eq!(
        service_observation_in(&run_unknown_plan(tls.port, "4", 15000))["protocol"],
        "tls",
        "TLS handshakes classify on ephemeral ports at L4"
    );
    let postgres = postgres_fixture(Arc::new(AtomicBool::new(false)));
    assert_eq!(
        service_observation_in(&run_unknown_plan(postgres.port, "5", 20000))["protocol"],
        "postgres",
        "PostgreSQL classifies via L5 speculative SSLRequest"
    );
}

#[test]
fn mail_protocols_identified_on_ephemeral_ports_at_l5() {
    // FTP/SMTP greetings gate disambiguation at L5 unknown plans; the
    // exchange (not the port) decides between them.
    let ftp = ftp_fixture();
    let observation = service_observation_in(&run_unknown_plan(ftp.port, "5", 20000));
    assert_eq!(observation["protocol"], "ftp");
    assert_eq!(observation["product_hint"], "FixtureFTP");
    let smtp = smtp_fixture();
    let observation = service_observation_in(&run_unknown_plan(smtp.port, "5", 20000));
    assert_eq!(observation["protocol"], "smtp");
}

// ---------- Wave 1: adversarial collisions ----------

#[test]
fn http_body_containing_ssh_banner_stays_http() {
    let fixture = Fixture::spawn(|mut stream, received| {
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 26\r\n\r\nbody with SSH-2.0-noise\r\n");
        let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
        let mut chunk = [0u8; 512];
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
        }
    });
    let observation = service_observation_in(&run_unknown_plan(fixture.port, "3", 10000));
    assert_eq!(observation["protocol"], "http");
    assert!(
        observation["evidence_lines"]
            .as_array()
            .unwrap()
            .iter()
            .any(|line| line.as_str().unwrap().contains("200")),
        "status evidence must survive an SSH-looking body: {observation}"
    );
}

#[test]
fn smtp_banner_containing_http_word_stays_smtp() {
    // Grammar (220 + 250), not substrings, decides. The banner token
    // `HTTP-mailer` is preserved as product evidence, not identity.
    let fixture = Fixture::spawn(|mut stream, received| {
        let _ = stream.write_all(b"220 HTTP-mailer 1.0 ready\r\n");
        let _ = stream.set_read_timeout(Some(Duration::from_millis(400)));
        let mut chunk = [0u8; 512];
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
            if chunk[..count].starts_with(b"EHLO") {
                let _ = stream.write_all(b"250-mailer Hello\r\n250 8BITMIME\r\n");
            }
        }
    });
    let observation = service_observation_in(&run_unknown_plan(fixture.port, "5", 20000));
    assert_eq!(observation["protocol"], "smtp");
}

#[test]
fn garbage_on_likely_ports_never_invents_identity() {
    let garbage = Fixture::spawn(|mut stream, received| {
        let _ = stream.write_all(b"\x00\xffGARBAGE!!\r\n");
        let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
        let mut chunk = [0u8; 512];
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
        }
    });
    // SSH-shaped plan against garbage: unknown.
    let plan = plan_for_ports(&garbage.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    for probes in ["ssh", "ftp", "smtp", "generic"] {
        let task = service_task_for(
            &plan,
            "127.0.0.1",
            garbage.port,
            probes,
            8000,
            guard.as_ref(),
        );
        let output = block_on_service(
            &module,
            ModuleContext::new(task, CancellationToken::default()),
        )
        .unwrap();
        assert_eq!(
            service_observation_in(&output)["protocol"],
            "unknown",
            "garbage via {probes} must stay unknown"
        );
    }
}

#[test]
fn tls_prefix_without_handshake_stays_unknown() {
    // TLS record header bytes with no handshake behind them: the rustls
    // handshake fails, and failure is a miss, never an identity.
    let fixture = Fixture::spawn(|mut stream, received| {
        let _ = stream.write_all(b"\x16\x03\x01\x00\x04nope");
        let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
        let mut chunk = [0u8; 512];
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
        }
        std::thread::sleep(Duration::from_millis(200));
    });
    let plan = plan_for_ports(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    let task = service_task_for(
        &plan,
        "127.0.0.1",
        fixture.port,
        "tls",
        8000,
        guard.as_ref(),
    );
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert_eq!(service_observation_in(&output)["protocol"], "unknown");
}

#[test]
fn redis_lookalikes_require_exact_pong() {
    for banner in ["+PONG is great\r\n", "x+PONG\r\n", "+pong\r\n", "PONG\r\n"] {
        let owned = banner.to_owned();
        let fixture = Fixture::spawn(move |mut stream, received| {
            let _ = stream.write_all(owned.as_bytes());
            let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
            let mut chunk = [0u8; 512];
            if let Ok(count) = stream.read(&mut chunk) {
                received.lock().unwrap().extend_from_slice(&chunk[..count]);
            }
        });
        let plan = plan_for_ports(&fixture.port.to_string());
        let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
        let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
        let task = service_task_for(
            &plan,
            "127.0.0.1",
            fixture.port,
            "redis",
            8000,
            guard.as_ref(),
        );
        let output = block_on_service(
            &module,
            ModuleContext::new(task, CancellationToken::default()),
        )
        .unwrap();
        assert_eq!(
            service_observation_in(&output)["protocol"],
            "unknown",
            "embedded +PONG {banner:?} must not classify as Redis"
        );
    }
}

#[test]
fn postgres_single_byte_from_noise_stays_unknown() {
    // A chatterbox whose first byte happens to be `N` (or `S`) but keeps
    // talking refutes PostgreSQL via the trailing-bytes grace check.
    // (A lone `N` followed by true silence is byte-identical to a real
    // refusal, so it stays Probable by design — never Confirmed.)
    for payload in [b"NOPE\r\n".as_slice(), b"SSH-2.0-x\r\n".as_slice()] {
        let owned = payload.to_owned();
        let fixture = Fixture::spawn(move |mut stream, received| {
            let _ = stream.write_all(&owned);
            std::thread::sleep(Duration::from_millis(300));
            let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
            let mut chunk = [0u8; 512];
            if let Ok(count) = stream.read(&mut chunk) {
                received.lock().unwrap().extend_from_slice(&chunk[..count]);
            }
        });
        let plan = plan_for_ports(&fixture.port.to_string());
        let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
        let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
        let task = service_task_for(
            &plan,
            "127.0.0.1",
            fixture.port,
            "postgres",
            8000,
            guard.as_ref(),
        );
        let output = block_on_service(
            &module,
            ModuleContext::new(task, CancellationToken::default()),
        )
        .unwrap();
        assert_eq!(
            service_observation_in(&output)["protocol"],
            "unknown",
            "noise {payload:?} must not classify as PostgreSQL"
        );
    }
}

#[test]
fn ambiguous_and_malformed_220_stay_unknown() {
    // 220 greeting whose EHLO goes unanswered: ambiguous, never resolved
    // by port or by prefix.
    let hanging = Fixture::spawn(|mut stream, received| {
        let _ = stream.write_all(b"220 quiet.example.com ready\r\n");
        let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
        let mut chunk = [0u8; 512];
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
            std::thread::sleep(Duration::from_millis(600));
        }
    });
    // Malformed 220 (no separator): not a greeting at all.
    let malformed = Fixture::spawn(|mut stream, received| {
        let _ = stream.write_all(b"220X not a greeting\r\n");
        let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
        let mut chunk = [0u8; 512];
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
        }
    });
    // Multiline FTP greeting disambiguates via NOOP after EHLO rejection.
    // (Includes non-ASCII bytes to prove lossy handling never breaks framing.)
    let multiline = Fixture::spawn(|mut stream, received| {
        let _ = stream.write_all("220-welcome to корпус\r\n220 MultiFTP 2.0 ready\r\n".as_bytes());
        let _ = stream.set_read_timeout(Some(Duration::from_millis(400)));
        let mut chunk = [0u8; 512];
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
            if chunk[..count].starts_with(b"EHLO") {
                let _ = stream.write_all(b"500 no EHLO here\r\n");
                let _ = stream.set_read_timeout(Some(Duration::from_millis(400)));
                if let Ok(count) = stream.read(&mut chunk) {
                    received.lock().unwrap().extend_from_slice(&chunk[..count]);
                    if chunk[..count].starts_with(b"NOOP") {
                        let _ = stream.write_all(b"200 ok\r\n");
                    }
                }
            }
        }
    });
    for (fixture, expected) in [(&hanging, "unknown"), (&malformed, "unknown")] {
        let plan = plan_for_ports(&fixture.port.to_string());
        let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
        let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
        for probes in ["ftp", "smtp"] {
            let task = service_task_for(
                &plan,
                "127.0.0.1",
                fixture.port,
                probes,
                8000,
                guard.as_ref(),
            );
            let output = block_on_service(
                &module,
                ModuleContext::new(task, CancellationToken::default()),
            )
            .unwrap();
            assert_eq!(
                service_observation_in(&output)["protocol"],
                expected,
                "ambiguous greeting via {probes} must stay unknown"
            );
        }
    }
    let observation = service_observation_in(&run_unknown_plan(multiline.port, "5", 20000));
    assert_eq!(observation["protocol"], "ftp");
}

#[test]
fn delayed_greeting_within_window_still_classifies() {
    // A 300ms-delayed SSH banner arrives inside the passive window:
    // delay alone must not downgrade real evidence to unknown.
    let fixture = Fixture::spawn(|mut stream, received| {
        std::thread::sleep(Duration::from_millis(300));
        let _ = stream.write_all(b"SSH-2.0-PatientSSH_1.0\r\n");
        let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
        let mut chunk = [0u8; 512];
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
        }
    });
    let observation = service_observation_in(&run_unknown_plan(fixture.port, "2", 10000));
    assert_eq!(observation["protocol"], "ssh");
    assert_eq!(observation["product_hint"], "PatientSSH");
}

#[test]
fn fragmented_ssh_banner_still_classifies() {
    // Byte-at-a-time delivery: framing accumulates, grammar still proves.
    let fixture = Fixture::spawn(|mut stream, received| {
        for byte in b"SSH-2.0-FragSSH_3.1\r\n" {
            let _ = stream.write_all(&[*byte]);
            std::thread::sleep(Duration::from_millis(5));
        }
        let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
        let mut chunk = [0u8; 512];
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
        }
    });
    let observation = service_observation_in(&run_unknown_plan(fixture.port, "2", 10000));
    assert_eq!(observation["protocol"], "ssh");
    assert_eq!(observation["product_hint"], "FragSSH");
}

// ---------- Wave 1: fingerprint, accounting, precision ----------

#[test]
fn unknown_fingerprint_is_bounded_deterministic_and_honest() {
    let fixture = unknown_banner_fixture();
    let observation = service_observation_in(&run_unknown_plan(fixture.port, "3", 10000));
    assert_eq!(observation["protocol"], "unknown");
    let fingerprint = observation
        .get("unknown_fingerprint")
        .expect("unknown services carry a fingerprint");
    assert_eq!(fingerprint["hash16"].as_str().unwrap().len(), 16);
    assert!(fingerprint["len"].as_u64().unwrap() > 0);
    assert!(fingerprint["len"].as_u64().unwrap() <= 2048);
    assert_eq!(fingerprint["spoke_first"], serde_json::json!(true));
    assert_eq!(fingerprint["truncated"], serde_json::json!(false));
    // Deterministic: the same observation twice yields the same hash.
    let again = service_observation_in(&run_unknown_plan(fixture.port, "3", 10000));
    assert_eq!(
        again["unknown_fingerprint"]["hash16"],
        fingerprint["hash16"]
    );
    // Silence fingerprints nothing.
    let silent = silent_fixture();
    let silent_observation = service_observation_in(&run_unknown_plan(silent.port, "3", 15000));
    assert_eq!(silent_observation["protocol"], "unknown");
    assert!(
        silent_observation.get("unknown_fingerprint").is_none()
            || silent_observation["unknown_fingerprint"].is_null()
    );
}

#[test]
fn service_accounting_is_exact_per_open_port() {
    // SSH via passive only: 1 connection, 1 probe, 0 writes.
    let ssh = ssh_fixture();
    let plan = plan_for_ports(&ssh.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    let task = service_task_for(&plan, "127.0.0.1", ssh.port, "ssh", 8000, guard.as_ref());
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let details = completed_details(&output);
    assert_eq!(details["connections_opened"], serde_json::json!(1));
    assert_eq!(details["probes_attempted"], serde_json::json!(1));
    assert_eq!(details["writes"], serde_json::json!(0));
    assert_eq!(details["bytes_written"], serde_json::json!(0));
    assert!(details["bytes_read"].as_u64().unwrap() > 0);
    // Matched-by attribution travels with findings and observations.
    // Explicit single-probe plan: the dedicated probe is responsible.
    assert_eq!(details["matcher"], serde_json::json!("ssh"));
    // Unknown-plan run: the shared passive observation is responsible.
    let passive_observation = service_observation_in(&run_unknown_plan(ssh.port, "1", 8000));
    assert_eq!(passive_observation["protocol"], "ssh");
    assert_eq!(
        passive_observation["matched_by"],
        serde_json::json!("passive")
    );
    // Active HTTP path without passive coverage: 1 connection, 1 probe,
    // exactly 1 write, bytes both directions.
    let http = http_response_fixture();
    let plan = plan_for_ports(&http.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(fast_policy(&plan), guard.clone());
    let task = service_task_for(&plan, "127.0.0.1", http.port, "http", 8000, guard.as_ref());
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let details = completed_details(&output);
    assert_eq!(details["protocol"], serde_json::json!("http"));
    assert_eq!(details["connections_opened"], serde_json::json!(1));
    assert_eq!(details["probes_attempted"], serde_json::json!(1));
    assert_eq!(details["writes"], serde_json::json!(1));
    assert!(details["bytes_written"].as_u64().unwrap() > 0);
    assert!(details["bytes_read"].as_u64().unwrap() > 0);
    assert_eq!(details["matcher"], serde_json::json!("http"));
}

#[test]
fn misleading_product_words_never_become_products() {
    // `220 server ESMTP`: no justifiable product — protocol without product.
    let fixture = Fixture::spawn(|mut stream, received| {
        let _ = stream.write_all(b"220 server ESMTP\r\n");
        let _ = stream.set_read_timeout(Some(Duration::from_millis(400)));
        let mut chunk = [0u8; 512];
        if let Ok(count) = stream.read(&mut chunk) {
            received.lock().unwrap().extend_from_slice(&chunk[..count]);
            if chunk[..count].starts_with(b"EHLO") {
                let _ = stream.write_all(b"250-server Hello\r\n250 8BITMIME\r\n");
            }
        }
    });
    let observation = service_observation_in(&run_unknown_plan(fixture.port, "5", 20000));
    assert_eq!(observation["protocol"], "smtp");
    assert!(
        observation.get("product_hint").is_none() || observation["product_hint"].is_null(),
        "chatter must not become product: {}",
        observation
    );
    // Banner itself is still preserved verbatim.
    assert!(
        observation["banner"]
            .as_str()
            .unwrap()
            .contains("220 server ESMTP")
    );
}
