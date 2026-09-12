//! Phase 8 HTTP/TLS web-foundation tests: controlled LOCAL fixtures only.
//!
//! No public Internet dependency. Loopback HTTP servers with scripted
//! responses, an in-test rustls+rcgen HTTPS fixture, and silent/oversized/
//! delayed/malformed fixtures — plus request counters proving exactly which
//! URLs were contacted (no crawling, no scope expansion).

use std::{
    collections::BTreeMap,
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
use rxscan::{
    cli::Cli,
    decision::Phase7Engine,
    execution::{
        BudgetLimits, CancellationToken, DecisionEngine, Module, ModuleContext, ModuleError,
        ModuleOutput, PolicyScopeGuard, RetryPolicy, Scheduler, ScopeGuard, SpeedGovernor, Task,
        TaskKind, TaskScopeTarget, VecEventSink,
    },
    model::{Provenance, SCHEMA_VERSION, Timestamp},
    plan::{ScanGoal, ScanPlan, SpeedSetting},
    web_probe::{WEB_MODULE_VERSION, WebProbeModule},
};

// ---------- fixture framework ----------

/// Scripted loopback HTTP fixture. Records request lines, Host headers,
/// methods, and paths; counts requests; never fetches anything itself.
struct HttpFixture {
    port: u16,
    requests: Arc<std::sync::Mutex<Vec<FixtureRequest>>>,
    stop: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
struct FixtureRequest {
    method: String,
    path: String,
    host: String,
    raw_head: String,
}

impl HttpFixture {
    fn spawn(responder: impl Fn(&FixtureRequest) -> Vec<u8> + Send + Sync + 'static) -> Self {
        Self::spawn_with_delay(responder, Duration::ZERO)
    }

    fn spawn_with_delay(
        responder: impl Fn(&FixtureRequest) -> Vec<u8> + Send + Sync + 'static,
        delay: Duration,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let requests_clone = requests.clone();
        let stop_clone = stop.clone();
        let responder = Arc::new(responder);
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !stop_clone.load(Ordering::SeqCst) && Instant::now() < deadline {
                let (stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => break,
                };
                let _ = stream.set_nonblocking(false);
                let requests = requests_clone.clone();
                let responder = responder.clone();
                std::thread::spawn(move || {
                    if !delay.is_zero() {
                        std::thread::sleep(delay);
                    }
                    let mut stream = stream;
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(4)));
                    let mut raw = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        match stream.read(&mut chunk) {
                            Ok(0) => break,
                            Ok(count) => {
                                raw.extend_from_slice(&chunk[..count]);
                                if raw.windows(4).any(|w| w == b"\r\n\r\n") || raw.len() > 16 * 1024
                                {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let head = String::from_utf8_lossy(&raw).to_string();
                    let mut lines = head.split("\r\n");
                    let request_line = lines.next().unwrap_or("");
                    let mut parts = request_line.split_whitespace();
                    let method = parts.next().unwrap_or("").to_owned();
                    let path = parts.next().unwrap_or("").to_owned();
                    let mut host = String::new();
                    for line in lines {
                        if line.is_empty() {
                            break;
                        }
                        if let Some((name, value)) = line.split_once(':') {
                            if name.trim().eq_ignore_ascii_case("host") {
                                host = value.trim().to_owned();
                            }
                        }
                    }
                    requests.lock().unwrap().push(FixtureRequest {
                        method,
                        path,
                        host,
                        raw_head: head,
                    });
                    let response = responder(requests.lock().unwrap().last().expect("just pushed"));
                    let _ = stream.write_all(&response);
                });
            }
        });
        Self {
            port,
            requests,
            stop,
        }
    }

    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    fn snapshot(&self) -> Vec<FixtureRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

// ---------- TLS fixture (rustls server + rcgen cert, loopback only) ----------

struct TlsFixture {
    port: u16,
    stop: Arc<AtomicBool>,
    requests: Arc<std::sync::Mutex<Vec<String>>>,
}

fn rcgen_test_cert() -> (Vec<u8>, Vec<u8>) {
    let mut params =
        rcgen::CertificateParams::new(vec!["svc8test.local".to_owned(), "127.0.0.1".to_owned()])
            .expect("rcgen params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "svc8test.local");
    let key_pair = rcgen::KeyPair::generate().expect("rcgen key");
    let cert = params.self_signed(&key_pair).expect("rcgen self-signed");
    (cert.der().to_vec(), key_pair.serialize_der())
}

/// HTTPS fixture: completes handshakes, serves one scripted responder per
/// connection over TLS, records request lines. `https_body` selects whether
/// HTTP answers inside TLS (false = handshake-only, for TLS≠HTTPS tests).
fn tls_fixture(https_body: bool) -> TlsFixture {
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
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let stop_clone = stop.clone();
    let requests_clone = requests.clone();
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
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
            let requests = requests_clone.clone();
            std::thread::spawn(move || {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(4)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(4)));
                let Ok(mut conn) = rustls::ServerConnection::new(config) else {
                    return;
                };
                let mut stream = stream;
                for _ in 0..200 {
                    match conn.complete_io(&mut stream) {
                        Ok(_) => {
                            if !conn.is_handshaking() {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                }
                if conn.is_handshaking() {
                    return;
                }
                if !https_body {
                    std::thread::sleep(Duration::from_millis(400));
                    return;
                }
                let mut tls = rustls::Stream::new(&mut conn, &mut stream);
                let mut request = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    use std::io::Read as _;
                    match tls.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(count) => {
                            request.extend_from_slice(&chunk[..count]);
                            if request.windows(4).any(|w| w == b"\r\n\r\n") || request.len() > 8192
                            {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let line = String::from_utf8_lossy(&request)
                    .split("\r\n")
                    .next()
                    .unwrap_or("")
                    .to_owned();
                requests.lock().unwrap().push(line);
                let body = b"<html><head><title>Secure</title></head></html>";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nServer: tls-web/2.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                use std::io::Write as _;
                let _ = tls.write_all(response.as_bytes());
                let _ = tls.write_all(body);
                let _ = tls.flush();
            });
        }
    });
    TlsFixture {
        port,
        stop,
        requests,
    }
}

impl Drop for TlsFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

// ---------- module test helpers ----------

fn plan_for_web() -> ScanPlan {
    let cli = Cli::try_parse_from(["rxscan", "127.0.0.1", "--level", "4"]).unwrap();
    ScanPlan::compile(cli).unwrap()
}

fn provenance_for(plan: &ScanPlan) -> Provenance {
    Provenance::new("test.module", "8.0.0", plan.stable_id(), Timestamp(0)).unwrap()
}

fn web_task_for_url(plan: &ScanPlan, url: &str, timeout_ms: u64, guard: &dyn ScopeGuard) -> Task {
    let target = rxscan::web::WebTarget::parse(url).unwrap();
    let scope = match target.ip_literal() {
        Some(ip) => TaskScopeTarget::Ip(ip),
        None => TaskScopeTarget::Host(target.host.clone()),
    };
    let mut params = BTreeMap::from([
        ("target".to_owned(), "127.0.0.1".to_owned()),
        ("url".to_owned(), target.canonical()),
        ("address".to_owned(), target.host.clone()),
        ("port".to_owned(), target.port.to_string()),
        ("scheme".to_owned(), target.scheme.as_str().to_owned()),
    ]);
    if url.contains("svc8test") {
        params.insert("parent_service".to_owned(), "asset_service_test".to_owned());
    }
    Task::new_with_params(
        TaskKind::HttpProbe,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        45,
        Duration::from_millis(timeout_ms),
        RetryPolicy::default(),
        "rxscan.http",
        provenance_for(plan),
        scope,
        params,
        guard,
    )
    .unwrap()
}

fn fast_policy(plan: &ScanPlan) -> rxscan::web::WebPolicy {
    rxscan::web::WebPolicy::new(plan.level, plan.goal, SpeedSetting::Numeric(100))
}

fn block_on_web(
    module: &rxscan::web_probe::WebProbeModule,
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

fn observation_in(output: &ModuleOutput) -> serde_json::Value {
    output
        .evidence
        .iter()
        .find(|evidence| {
            evidence.source == "rxscan.http" && evidence.details.data.get("status").is_some()
        })
        .map(|evidence| evidence.details.data.clone())
        .expect("web observation evidence")
}

fn completed_in(output: &ModuleOutput) -> serde_json::Value {
    output
        .events
        .iter()
        .find(|event| format!("{:?}", event.kind) == "WebProbeCompleted")
        .map(|event| event.details.data.clone())
        .expect("completed event")
}

// ---------- basic HTTP ----------

#[test]
fn local_http_observation_with_status_headers_title() {
    let body = b"<html><head><title>Local</title></head><body>x</body></html>";
    let fixture = HttpFixture::spawn(|_| {
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nServer: mini/3.1\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    });
    let plan = plan_for_web();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = WebProbeModule::new(fast_policy(&plan), guard.clone());
    let url = format!("http://127.0.0.1:{}/", fixture.port);
    let task = web_task_for_url(&plan, &url, 8000, guard.as_ref());
    let output = block_on_web(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let observation = observation_in(&output);
    assert_eq!(observation["status"], 200);
    assert_eq!(observation["server"], "mini/3.1");
    assert_eq!(observation["content_type"], "text/html");
    assert_eq!(observation["title"], "local");
    // Request used HTTP/1.1 with a correct Host header (custom port kept).
    let requests = fixture.snapshot();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].raw_head.starts_with("GET / HTTP/1.1\r\n"));
    assert_eq!(requests[0].host, format!("127.0.0.1:{}", fixture.port));
    // Provenance on every record.
    for event in &output.events {
        assert_eq!(event.provenance.module_name, "rxscan.http");
        assert_eq!(event.provenance.module_version, WEB_MODULE_VERSION);
    }
}

#[test]
fn status_variants_parse_without_guessing() {
    for (status, reason) in [(201, "Created"), (404, "Not Found"), (500, "Boom")] {
        let fixture = HttpFixture::spawn(move |_| {
            format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .into_bytes()
        });
        let plan = plan_for_web();
        let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
        let module = WebProbeModule::new(fast_policy(&plan), guard.clone());
        let url = format!("http://127.0.0.1:{}/missing", fixture.port);
        let task = web_task_for_url(&plan, &url, 8000, guard.as_ref());
        let output = block_on_web(
            &module,
            ModuleContext::new(task, CancellationToken::default()),
        )
        .unwrap();
        let observation = observation_in(&output);
        assert_eq!(observation["status"], status);
        assert!(output.findings.iter().any(|finding| finding.title
            == format!("HTTP {status} at {}", observation["url"].as_str().unwrap())));
    }
}

#[test]
fn cookies_are_bounded_observations() {
    let fixture = HttpFixture::spawn(|_| {
        let mut head = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n".to_owned();
        for index in 0..20 {
            head.push_str(&format!("Set-Cookie: c{index}=v{index}; Path=/\r\n"));
        }
        head.push_str("\r\n");
        head.into_bytes()
    });
    let plan = plan_for_web();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = WebProbeModule::new(fast_policy(&plan), guard.clone());
    let url = format!("http://127.0.0.1:{}/", fixture.port);
    let task = web_task_for_url(&plan, &url, 8000, guard.as_ref());
    let output = block_on_web(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let observation = observation_in(&output);
    let cookies = observation["cookies"].as_array().unwrap();
    assert_eq!(cookies.len(), rxscan::web::MAX_COOKIES);
    assert_eq!(cookies[0]["name"], "c0");
}

#[test]
fn ipv6_and_custom_ports_and_host_headers() {
    let listener = TcpListener::bind("[::1]:0").expect("bind ::1 fixture");
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let seen_host = Arc::new(std::sync::Mutex::new(String::new()));
    let stop_clone = stop.clone();
    let seen_clone = seen_host.clone();
    std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while !stop_clone.load(Ordering::SeqCst) && Instant::now() < deadline {
            let (stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(_) => break,
            };
            let _ = stream.set_nonblocking(false);
            let mut stream = stream;
            let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
            let mut raw = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(count) => {
                        raw.extend_from_slice(&chunk[..count]);
                        if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let head = String::from_utf8_lossy(&raw).to_string();
            for line in head.split("\r\n").skip(1) {
                if line.is_empty() {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    if name.trim().eq_ignore_ascii_case("host") {
                        *seen_clone.lock().unwrap() = value.trim().to_owned();
                    }
                }
            }
            let body = b"v6";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(body);
        }
    });
    // Scope must cover ::1 for this run.
    let cli = Cli::try_parse_from(["rxscan", "::1", "--level", "4"]).unwrap();
    let plan = ScanPlan::compile(cli).unwrap();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = WebProbeModule::new(fast_policy(&plan), guard.clone());
    let url = format!("http://[::1]:{port}/");
    let task = web_task_for_url(&plan, &url, 8000, guard.as_ref());
    let output = block_on_web(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert_eq!(observation_in(&output)["status"], 200);
    assert_eq!(*seen_host.lock().unwrap(), format!("[::1]:{port}"));
    stop.store(true, Ordering::SeqCst);
    drop(plan);
}

#[test]
fn level_selects_head_vs_get_and_redirect_depth() {
    // L1 sends HEAD (headers only, no body read); L4 sends GET and follows.
    let fixture = HttpFixture::spawn(|_| {
        let body = b"<html><head><title>Depth</title></head></html>";
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    });
    let plan = plan_for_web();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let url = format!("http://127.0.0.1:{}/", fixture.port);

    let low = WebProbeModule::new(
        rxscan::web::WebPolicy::new(1, plan.goal, plan.speed),
        guard.clone(),
    );
    let task = web_task_for_url(&plan, &url, 8000, guard.as_ref());
    let output =
        block_on_web(&low, ModuleContext::new(task, CancellationToken::default())).unwrap();
    assert_eq!(observation_in(&output)["status"], 200);
    assert!(observation_in(&output)["title"].is_null());

    let high = WebProbeModule::new(
        rxscan::web::WebPolicy::new(4, plan.goal, plan.speed),
        guard.clone(),
    );
    let task = web_task_for_url(&plan, &url, 8000, guard.as_ref());
    let output = block_on_web(
        &high,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert_eq!(observation_in(&output)["title"], "depth");

    let methods: Vec<String> = fixture
        .snapshot()
        .iter()
        .map(|request| request.method.clone())
        .collect();
    assert!(methods.contains(&"HEAD".to_owned()), "L1 must send HEAD");
    assert!(methods.contains(&"GET".to_owned()), "L4 must send GET");
}

// ---------- bounds ----------

#[test]
fn oversized_body_truncates_with_metadata() {
    let fixture = HttpFixture::spawn(|_| {
        let body = vec![b'B'; 100_000];
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(&body);
        response
    });
    let plan = plan_for_web();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = WebProbeModule::new(
        rxscan::web::WebPolicy::new(4, plan.goal, plan.speed),
        guard.clone(),
    );
    let url = format!("http://127.0.0.1:{}/", fixture.port);
    let task = web_task_for_url(&plan, &url, 10_000, guard.as_ref());
    let output = block_on_web(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let observation = observation_in(&output);
    assert_eq!(observation["status"], 200);
    assert_eq!(observation["body_truncated"], true);
    assert!(observation["body_bytes"].as_u64().unwrap() <= 16 * 1024);
    let blob = serde_json::to_string(&observation).unwrap();
    assert!(blob.len() < 48 * 1024);
}

#[test]
fn malformed_response_is_recorded_never_classified() {
    let fixture = HttpFixture::spawn(|_| b"THIS IS NOT HTTP AT ALL\r\n\r\n".to_vec());
    let plan = plan_for_web();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = WebProbeModule::new(fast_policy(&plan), guard.clone());
    let url = format!("http://127.0.0.1:{}/", fixture.port);
    let task = web_task_for_url(&plan, &url, 8000, guard.as_ref());
    let output = block_on_web(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    // No observation evidence, no findings — but a completed event with notes.
    assert!(output.findings.is_empty());
    assert!(
        completed_in(&output)["chain"]
            .as_array()
            .unwrap()
            .iter()
            .any(|line| line.as_str().unwrap().contains("not valid HTTP"))
    );
}

#[test]
fn connection_failure_is_evidence_not_a_task_failure() {
    // Closed loopback port: refused fast, recorded, task still succeeds.
    let plan = plan_for_web();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = WebProbeModule::new(fast_policy(&plan), guard.clone());
    let task = web_task_for_url(&plan, "http://127.0.0.1:64999/", 5000, guard.as_ref());
    let started = Instant::now();
    let output = block_on_web(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(output.findings.is_empty());
    assert!(
        completed_in(&output)["chain"]
            .as_array()
            .unwrap()
            .iter()
            .any(|line| line.as_str().unwrap().contains("connection failed"))
    );
}

#[test]
fn timeout_yields_notes_within_bounds() {
    let fixture = HttpFixture::spawn_with_delay(
        |_| b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        Duration::from_secs(5),
    );
    let plan = plan_for_web();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = WebProbeModule::new(fast_policy(&plan), guard.clone());
    let url = format!("http://127.0.0.1:{}/", fixture.port);
    let task = web_task_for_url(&plan, &url, 6000, guard.as_ref());
    let started = Instant::now();
    let output = block_on_web(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert!(started.elapsed() < Duration::from_secs(10));
    // Delayed past the fast 500ms budget: no observation, notes explain why.
    assert!(output.findings.is_empty());
    drop(fixture);
}

#[test]
fn cancellation_is_prompt_before_and_mid_flight() {
    let fixture = HttpFixture::spawn(|_| {
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
    });
    let plan = plan_for_web();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = WebProbeModule::new(fast_policy(&plan), guard.clone());
    let url = format!("http://127.0.0.1:{}/", fixture.port);
    let task = web_task_for_url(&plan, &url, 8000, guard.as_ref());
    let token = CancellationToken::default();
    token.cancel();
    let started = Instant::now();
    let result = block_on_web(&module, ModuleContext::new(task, token));
    assert!(matches!(result, Err(ModuleError::Cancelled)));
    assert!(started.elapsed() < Duration::from_millis(500));

    // Mid-flight cancel against a silent fixture stays bounded.
    let silent = HttpFixture::spawn_with_delay(
        |_| b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        Duration::from_secs(6),
    );
    let url = format!("http://127.0.0.1:{}/", silent.port);
    let task = web_task_for_url(&plan, &url, 20_000, guard.as_ref());
    let token = CancellationToken::default();
    let token_clone = token.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        token_clone.cancel();
    });
    let started = Instant::now();
    let result = block_on_web(&module, ModuleContext::new(task, token));
    assert!(matches!(result, Err(ModuleError::Cancelled)));
    assert!(started.elapsed() < Duration::from_secs(8));
}

// ---------- redirects ----------

#[test]
fn redirect_chain_with_relative_resolution() {
    let fixture = HttpFixture::spawn(|request| {
        if request.path == "/a" {
            b"HTTP/1.1 301 Moved\r\nLocation: /b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec()
        } else if request.path == "/b" {
            b"HTTP/1.1 302 Found\r\nLocation: c\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec()
        } else {
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec()
        }
    });
    let plan = plan_for_web();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    // Level 4 follows redirects; level 1 records only.
    let module = WebProbeModule::new(
        rxscan::web::WebPolicy::new(4, plan.goal, plan.speed),
        guard.clone(),
    );
    let url = format!("http://127.0.0.1:{}/a", fixture.port);
    let task = web_task_for_url(&plan, &url, 10_000, guard.as_ref());
    let output = block_on_web(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    // Three requests total (a → b → c), final landing observed.
    assert_eq!(fixture.count(), 3);
    let completed = completed_in(&output);
    assert_eq!(completed["chain"].as_array().unwrap().len(), 3);
    let landing = output
        .evidence
        .iter()
        .find(|evidence| {
            evidence.source == "rxscan.http"
                && evidence.details.data["url"]
                    .as_str()
                    .is_some_and(|url| url.ends_with("/c"))
        })
        .map(|evidence| evidence.details.data.clone())
        .expect("final landing observation");
    assert_eq!(landing["status"], 200);
    let observation = observation_in(&output);
    assert_eq!(observation["status"], 301);

    // Level 1 records the redirect without following it.
    let module = WebProbeModule::new(
        rxscan::web::WebPolicy::new(1, plan.goal, plan.speed),
        guard.clone(),
    );
    let before = fixture.count();
    let task = web_task_for_url(&plan, &url, 10_000, guard.as_ref());
    let output = block_on_web(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert_eq!(fixture.count(), before + 1);
    assert_eq!(observation_in(&output)["status"], 301);
}

#[test]
fn redirect_loop_stops_with_evidence() {
    let fixture = HttpFixture::spawn(|_| {
        b"HTTP/1.1 302 Found\r\nLocation: /loop\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_vec()
    });
    let plan = plan_for_web();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = WebProbeModule::new(
        rxscan::web::WebPolicy::new(5, plan.goal, plan.speed),
        guard.clone(),
    );
    let url = format!("http://127.0.0.1:{}/loop", fixture.port);
    let task = web_task_for_url(&plan, &url, 10_000, guard.as_ref());
    let output = block_on_web(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    // Exactly one request: the loop is detected before a second fetch.
    assert_eq!(fixture.count(), 1);
    assert!(output.events.iter().any(|event| {
        format!("{:?}", event.kind) == "RedirectObserved"
            && event.details.data["followed"] == false
            && event.details.data["reason"]
                .as_str()
                .unwrap()
                .contains("loop")
    }));
}

#[test]
fn redirect_cap_bounds_long_chains() {
    let fixture = HttpFixture::spawn(|request| {
        // /n redirects to /n+1 forever; the cap must stop the walk.
        let next: u32 = request
            .path
            .trim_start_matches('/')
            .parse::<u32>()
            .unwrap_or(0)
            .saturating_add(1);
        format!(
            "HTTP/1.1 302 Found\r\nLocation: /{next}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes()
    });
    let plan = plan_for_web();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = WebProbeModule::new(
        rxscan::web::WebPolicy::new(5, plan.goal, plan.speed),
        guard.clone(),
    );
    let url = format!("http://127.0.0.1:{}/0", fixture.port);
    let task = web_task_for_url(&plan, &url, 15_000, guard.as_ref());
    let output = block_on_web(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    // Start + 4 follows at L5, then the cap note — never unbounded.
    assert_eq!(fixture.count(), 5);
    assert!(output.events.iter().any(|event| {
        format!("{:?}", event.kind) == "RedirectObserved"
            && event.details.data["followed"] == false
            && event.details.data["reason"]
                .as_str()
                .unwrap()
                .contains("cap")
    }));
}

#[test]
fn out_of_scope_redirect_is_recorded_never_contacted() {
    // Canary listener on an out-of-scope address: any contact fails the test.
    let canary = TcpListener::bind("127.0.0.2:0").expect("bind canary");
    let canary_port = canary.local_addr().unwrap().port();
    let canary_hits = Arc::new(AtomicUsize::new(0));
    let canary_hits_clone = canary_hits.clone();
    canary.set_nonblocking(true).unwrap();
    let canary_stop = Arc::new(AtomicBool::new(false));
    let canary_stop_clone = canary_stop.clone();
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !canary_stop_clone.load(Ordering::SeqCst) && Instant::now() < deadline {
            match canary.accept() {
                Ok(_) => {
                    canary_hits_clone.fetch_add(1, Ordering::SeqCst);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    // Scope covers .1 only; the fixture redirects to .2.
    let fixture = HttpFixture::spawn(move |_| {
        format!(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.2:{canary_port}/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes()
    });
    let plan = plan_for_web();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    assert!(!guard.permits(&TaskScopeTarget::Ip("127.0.0.2".parse().unwrap())));
    let module = WebProbeModule::new(
        rxscan::web::WebPolicy::new(5, plan.goal, plan.speed),
        guard.clone(),
    );
    let url = format!("http://127.0.0.1:{}/start", fixture.port);
    let task = web_task_for_url(&plan, &url, 10_000, guard.as_ref());
    let output = block_on_web(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert_eq!(canary_hits.load(Ordering::SeqCst), 0);
    assert!(
        output
            .events
            .iter()
            .any(|event| format!("{:?}", event.kind) == "RedirectObserved"
                && event.details.data["followed"] == false)
    );
    canary_stop.store(true, Ordering::SeqCst);
}

#[test]
fn malformed_location_stops_safely() {
    let fixture = HttpFixture::spawn(|_| {
        b"HTTP/1.1 302 Found\r\nLocation: http://[::1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_vec()
    });
    let plan = plan_for_web();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = WebProbeModule::new(
        rxscan::web::WebPolicy::new(5, plan.goal, plan.speed),
        guard.clone(),
    );
    let url = format!("http://127.0.0.1:{}/x", fixture.port);
    let task = web_task_for_url(&plan, &url, 10_000, guard.as_ref());
    let output = block_on_web(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert_eq!(fixture.count(), 1);
    assert!(output.events.iter().any(|event| {
        format!("{:?}", event.kind) == "RedirectObserved"
            && event.details.data["followed"] == false
            && event.details.data["reason"]
                .as_str()
                .unwrap()
                .contains("malformed")
    }));
}

// ---------- HTTPS / TLS ----------

#[test]
fn https_observation_with_certificate_facts() {
    let fixture = tls_fixture(true);
    let plan = plan_for_web();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = WebProbeModule::new(
        rxscan::web::WebPolicy::new(4, plan.goal, plan.speed),
        guard.clone(),
    );
    let url = format!("https://127.0.0.1:{}/", fixture.port);
    let task = web_task_for_url(&plan, &url, 12_000, guard.as_ref());
    let output = block_on_web(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let observation = observation_in(&output);
    assert_eq!(observation["status"], 200);
    assert_eq!(observation["service"], "https");
    assert_eq!(observation["title"], "secure");
    assert!(observation["tls"].is_object());
    assert!(
        observation["tls"]["version"]
            .as_str()
            .unwrap()
            .starts_with("TLS")
    );
    // Certificate asset + evidence with stable fingerprint identity.
    assert!(
        output
            .assets
            .iter()
            .any(|asset| matches!(asset.kind, rxscan::model::AssetKind::Certificate))
    );
    assert!(
        output
            .events
            .iter()
            .any(|event| { format!("{:?}", event.kind) == "TlsObserved" })
    );
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
    // Hostname relationship: IP SAN covers 127.0.0.1.
    assert!(format!("{output:?}").contains("127.0.0.1"));
    assert!(!fixture.requests.lock().unwrap().is_empty());
}

#[test]
fn http_and_https_never_cross_classify() {
    // Plain HTTP fixture behind an https:// URL: TLS handshake fails, the
    // URL stays unobserved — never labeled HTTPS.
    let plain = HttpFixture::spawn(|_| {
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
    });
    let plan = plan_for_web();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = WebProbeModule::new(fast_policy(&plan), guard.clone());
    let url = format!("https://127.0.0.1:{}/", plain.port);
    let task = web_task_for_url(&plan, &url, 8000, guard.as_ref());
    let output = block_on_web(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert!(output.findings.is_empty());
    // HTTPS fixture behind an http:// URL: garbage to the HTTP parser,
    // unobserved — never labeled HTTP.
    let secure = tls_fixture(true);
    let url = format!("http://127.0.0.1:{}/", secure.port);
    let task = web_task_for_url(&plan, &url, 8000, guard.as_ref());
    let output = block_on_web(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert!(output.findings.is_empty());
}

#[test]
fn tls_without_http_is_not_https() {
    // Handshake-only TLS fixture: no HTTP inside, so no HTTPS claim even
    // though TLS itself negotiates cleanly.
    let fixture = tls_fixture(false);
    let plan = plan_for_web();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = WebProbeModule::new(fast_policy(&plan), guard.clone());
    let url = format!("https://127.0.0.1:{}/", fixture.port);
    let task = web_task_for_url(&plan, &url, 10_000, guard.as_ref());
    let output = block_on_web(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert!(output.findings.is_empty());
    assert!(output.events.iter().all(|event| {
        event
            .details
            .data
            .get("service")
            .is_none_or(|service| service != "https")
    }));
    assert!(output.evidence.iter().all(|evidence| {
        evidence
            .details
            .data
            .get("service")
            .is_none_or(|service| service != "https")
    }));
}

// ---------- scope / identity / engine ----------

#[test]
fn stale_scope_skips_web_task_without_network() {
    use std::sync::atomic::AtomicBool;
    struct FlippingGuard {
        allowed: AtomicBool,
    }
    impl ScopeGuard for FlippingGuard {
        fn permits(&self, _target: &TaskScopeTarget) -> bool {
            self.allowed.load(Ordering::SeqCst)
        }
    }
    let plan = plan_for_web();
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
    let policy = rxscan::web::WebPolicy::new(plan.level, plan.goal, plan.speed);
    scheduler.register_module(Arc::new(WebProbeModule::new(policy, guard.clone())));
    let task = Task::new_with_params(
        TaskKind::HttpProbe,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        45,
        Duration::from_millis(3000),
        RetryPolicy::default(),
        "rxscan.http",
        provenance_for(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([
            ("target".to_owned(), "127.0.0.1".to_owned()),
            ("url".to_owned(), "http://127.0.0.1:80/".to_owned()),
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

#[test]
fn endpoint_ids_are_stable_and_collision_free() {
    let a = rxscan::web::WebTarget::parse("http://example.test/").unwrap();
    let b = rxscan::web::WebTarget::parse("http://example.test:80/").unwrap();
    assert_eq!(
        rxscan::web::endpoint_asset_id(&a),
        rxscan::web::endpoint_asset_id(&b)
    );
    for other in [
        "https://example.test/",
        "http://example.test:8080/",
        "http://example.test/a",
        "http://example.test/?x=1",
        "http://other.test/",
    ] {
        assert_ne!(
            rxscan::web::endpoint_asset_id(&a),
            rxscan::web::endpoint_asset_id(&rxscan::web::WebTarget::parse(other).unwrap()),
            "collision for {other}"
        );
    }
}

#[test]
fn decision_engine_proposes_web_for_confirmed_services_only() {
    let plan = plan_for_web();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let engine = Phase7Engine::new(
        guard.clone(),
        plan.stable_id(),
        4,
        plan.goal,
        plan.tcp_ports.clone(),
        plan.speed,
    );
    let service_output = |service: &str| {
        let provenance =
            Provenance::new("rxscan.service", "7.0.0", plan.stable_id(), Timestamp(1)).unwrap();
        let mut finding = rxscan::model::Finding::new(
            format!("{service} service on port 80"),
            rxscan::model::Severity::Info,
            rxscan::model::Confidence::new(90).unwrap(),
            rxscan::model::AssetId("asset_service_x".to_owned()),
            provenance,
        )
        .unwrap();
        finding.metadata.insert(
            "service".to_owned(),
            serde_json::Value::String(service.to_owned()),
        );
        finding
            .metadata
            .insert("port".to_owned(), serde_json::Value::from(80));
        finding.metadata.insert(
            "address".to_owned(),
            serde_json::Value::String("127.0.0.1".to_owned()),
        );
        ModuleOutput {
            events: Vec::new(),
            evidence: Vec::new(),
            findings: vec![finding],
            assets: Vec::new(),
        }
    };
    let service_task = Task::new_with_params(
        TaskKind::ServiceProbe,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        50,
        Duration::from_millis(5000),
        RetryPolicy::default(),
        "rxscan.service",
        provenance_for(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([("target".to_owned(), "127.0.0.1".to_owned())]),
        guard.as_ref(),
    )
    .unwrap();
    let https = engine.follow_up_tasks(&service_task, &service_output("https"));
    assert_eq!(https.len(), 1);
    assert_eq!(https[0].kind, TaskKind::HttpProbe);
    assert_eq!(https[0].params["url"], "https://127.0.0.1:80/");
    let http = engine.follow_up_tasks(&service_task, &service_output("http"));
    assert_eq!(http.len(), 1);
    assert_eq!(http[0].params["url"], "http://127.0.0.1:80/");
    // Non-web services propose nothing; web completions never chain.
    assert!(
        engine
            .follow_up_tasks(&service_task, &service_output("ssh"))
            .is_empty()
    );
    let web_task = Task::new_with_params(
        TaskKind::HttpProbe,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        45,
        Duration::from_millis(5000),
        RetryPolicy::default(),
        "rxscan.http",
        provenance_for(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([("target".to_owned(), "127.0.0.1".to_owned())]),
        guard.as_ref(),
    )
    .unwrap();
    assert!(
        engine
            .follow_up_tasks(&web_task, &service_output("http"))
            .is_empty()
    );
}

#[test]
fn web_proposals_dedup_by_stable_identity() {
    let plan = plan_for_web();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let engine = Phase7Engine::new(
        guard.clone(),
        plan.stable_id(),
        4,
        plan.goal,
        plan.tcp_ports.clone(),
        plan.speed,
    );
    let provenance =
        Provenance::new("rxscan.service", "7.0.0", plan.stable_id(), Timestamp(1)).unwrap();
    let mut finding = rxscan::model::Finding::new(
        "https service on port 443".to_owned(),
        rxscan::model::Severity::Info,
        rxscan::model::Confidence::new(90).unwrap(),
        rxscan::model::AssetId("asset_service_y".to_owned()),
        provenance,
    )
    .unwrap();
    finding.metadata.insert(
        "service".to_owned(),
        serde_json::Value::String("https".to_owned()),
    );
    finding
        .metadata
        .insert("port".to_owned(), serde_json::Value::from(443));
    finding.metadata.insert(
        "address".to_owned(),
        serde_json::Value::String("127.0.0.1".to_owned()),
    );
    let output = ModuleOutput {
        events: Vec::new(),
        evidence: Vec::new(),
        findings: vec![finding],
        assets: Vec::new(),
    };
    let service_task = Task::new_with_params(
        TaskKind::ServiceProbe,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        50,
        Duration::from_millis(5000),
        RetryPolicy::default(),
        "rxscan.service",
        provenance_for(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([("target".to_owned(), "127.0.0.1".to_owned())]),
        guard.as_ref(),
    )
    .unwrap();
    let first = engine.follow_up_tasks(&service_task, &output);
    let second = engine.follow_up_tasks(&service_task, &output);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].id, second[0].id);
    assert_eq!(first[0].params["url"], "https://127.0.0.1:443/");
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

// ---------- policy semantics ----------

#[test]
fn level_controls_breadth_explicit_context_preserved() {
    let low = rxscan::web::WebPolicy::new(1, ScanGoal::Recon, SpeedSetting::default());
    let high = rxscan::web::WebPolicy::new(5, ScanGoal::Recon, SpeedSetting::default());
    assert_eq!(low.method(), "HEAD");
    assert_eq!(high.method(), "GET");
    assert_eq!(low.max_redirects(), 0);
    assert!(high.max_redirects() <= rxscan::web::MAX_REDIRECT_HOPS_HARD);
}

#[test]
fn speed_changes_timeouts_never_classification() {
    let bytes =
        b"HTTP/1.1 200 OK\r\nServer: s/1.0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let slow = rxscan::web::parse_response(bytes, 10).unwrap();
    let fast = rxscan::web::parse_response(bytes, 900);
    assert!(fast.is_some());
    assert_eq!(slow.status, fast.unwrap().status);
    let slow_policy = rxscan::web::WebPolicy::new(3, ScanGoal::Recon, SpeedSetting::Numeric(0));
    let fast_policy = rxscan::web::WebPolicy::new(3, ScanGoal::Recon, SpeedSetting::Numeric(100));
    assert_eq!(slow_policy.method(), fast_policy.method());
    assert!(fast_policy.connect_timeout() < slow_policy.connect_timeout());
}

// ---------- output / boundaries ----------

#[test]
fn jsonl_round_trip_preserves_web_records() {
    let body = b"<html><head><title>Round</title></head></html>";
    let fixture = HttpFixture::spawn(|_| {
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nServer: round/9.9\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    });
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("rxscan-phase8-jsonl-{stamp}"));
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("out.jsonl");
    let cli = Cli::try_parse_from([
        "rxscan",
        "127.0.0.1",
        "--ports",
        &fixture.port.to_string(),
        "--level",
        "4",
        "--output",
        path.to_str().unwrap(),
    ])
    .unwrap();
    let report = rxscan::run::execute(cli).unwrap();
    assert!(report.jsonl_bytes > 0);
    let contents = fs::read_to_string(&path).unwrap();
    let mut saw_endpoint = false;
    let mut saw_web_completed = false;
    let mut saw_http_finding = false;
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
                    .starts_with("asset_endpoint_") =>
            {
                saw_endpoint = true;
            }
            "event" if payload["kind"] == "web_probe_completed" => {
                saw_web_completed = true;
            }
            "finding" if payload["title"].as_str().unwrap().starts_with("HTTP ") => {
                saw_http_finding = true;
                assert!(!payload["evidence_ids"].as_array().unwrap().is_empty());
            }
            _ => {}
        }
    }
    assert!(saw_endpoint && saw_web_completed && saw_http_finding);
    assert!(report.open_ports_summary.contains("HOST 127.0.0.1"));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn no_crawling_links_and_forms_are_never_followed() {
    // Body advertises tempting links, a form, and robots mentions. The module
    // must fetch exactly the planned URL(s) and nothing else.
    let body = b"<html><head><title>Hub</title></head><body><a href=\"/secret\">s</a><a href=\"http://127.0.0.1:9/other\">o</a><form action=\"/login\"></form><!-- /robots.txt /sitemap.xml --></body></html>";
    let fixture = HttpFixture::spawn(|_| {
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    });
    let plan = plan_for_web();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = WebProbeModule::new(
        rxscan::web::WebPolicy::new(5, plan.goal, plan.speed),
        guard.clone(),
    );
    let url = format!("http://127.0.0.1:{}/", fixture.port);
    let task = web_task_for_url(&plan, &url, 8000, guard.as_ref());
    let output = block_on_web(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert_eq!(fixture.count(), 1);
    assert_eq!(observation_in(&output)["status"], 200);
    // No finding or asset references the advertised-but-unfetched paths.
    let blob = serde_json::to_string(&output.events).unwrap();
    assert!(!blob.contains("/secret"));
    assert!(!blob.contains("/login"));
}
