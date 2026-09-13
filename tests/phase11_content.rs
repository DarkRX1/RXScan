//! Phase 11 managed content discovery tests: deterministic local fixtures only.

use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use clap::Parser;
use rxscan::{
    baseline::{BaselineModule, BaselinePolicy, signature_for_response},
    cli::Cli,
    content::{
        CONTENT_MODULE_NAME, ContentDiscoveryModule, ContentDiscoveryPolicy, ContentDiscoveryState,
        builtin_candidates, content_task_params, normalize_candidate,
    },
    crawl::{CRAWL_MODULE_NAME, CrawlModule, CrawlPolicy, crawl_task_params},
    decision::Phase7Engine,
    execution::{
        BudgetLimits, CancellationToken, DecisionEngine, Module, ModuleContext, ModuleError,
        ModuleFuture, ModuleOutput, PolicyScopeGuard, RetryPolicy, Scheduler, ScopeGuard,
        SpeedGovernor, Task, TaskKind, TaskScopeTarget, VecEventSink,
    },
    model::{AssetId, BoundedDetails, Event, EventKind, Provenance, Timestamp},
    output::JsonlWriter,
    plan::{ScanGoal, ScanPlan, SpeedSetting},
    web::{WebTarget, endpoint_asset_id},
};

#[derive(Clone)]
struct FixtureRequest {
    path: String,
}

struct HttpFixture {
    host: String,
    port: u16,
    requests: Arc<std::sync::Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl HttpFixture {
    fn spawn(responder: impl Fn(&FixtureRequest) -> Vec<u8> + Send + Sync + 'static) -> Self {
        Self::spawn_on("127.0.0.1:0", Duration::ZERO, responder).expect("bind fixture")
    }

    fn spawn_with_delay(
        delay: Duration,
        responder: impl Fn(&FixtureRequest) -> Vec<u8> + Send + Sync + 'static,
    ) -> Self {
        Self::spawn_on("127.0.0.1:0", delay, responder).expect("bind fixture")
    }

    fn spawn_ipv6(
        responder: impl Fn(&FixtureRequest) -> Vec<u8> + Send + Sync + 'static,
    ) -> Option<Self> {
        Self::spawn_on("[::1]:0", Duration::ZERO, responder).ok()
    }

    fn spawn_on(
        bind: &str,
        delay: Duration,
        responder: impl Fn(&FixtureRequest) -> Vec<u8> + Send + Sync + 'static,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(bind)?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let host = if addr.ip().is_ipv6() {
            "::1".to_owned()
        } else {
            "127.0.0.1".to_owned()
        };
        let port = addr.port();
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let responder = Arc::new(responder);
        let requests_clone = requests.clone();
        let stop_clone = stop.clone();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(20);
            while !stop_clone.load(Ordering::SeqCst) && Instant::now() < deadline {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(_) => break,
                };
                let responder = responder.clone();
                let requests = requests_clone.clone();
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                    let mut raw = Vec::new();
                    let mut chunk = [0u8; 1024];
                    loop {
                        match stream.read(&mut chunk) {
                            Ok(0) => break,
                            Ok(count) => {
                                raw.extend_from_slice(&chunk[..count]);
                                if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let path = String::from_utf8_lossy(&raw)
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_owned();
                    requests.lock().unwrap().push(path.clone());
                    if !delay.is_zero() {
                        std::thread::sleep(delay);
                    }
                    let _ = stream.write_all(&responder(&FixtureRequest { path }));
                });
            }
        });
        Ok(Self {
            host,
            port,
            requests,
            stop,
        })
    }

    fn url(&self, path: &str) -> String {
        if self.host.contains(':') {
            format!("http://[{}]:{}{}", self.host, self.port, path)
        } else {
            format!("http://{}:{}{}", self.host, self.port, path)
        }
    }

    fn paths(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

struct ConfirmedEndpointModule {
    root: WebTarget,
}

impl Module for ConfirmedEndpointModule {
    fn kind(&self) -> TaskKind {
        TaskKind::HttpProbe
    }

    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let root = self.root.clone();
        Box::pin(async move {
            let provenance = Provenance::new(
                "phase11.test.http",
                "1.0.0",
                context.task.scan_plan_id.clone(),
                Timestamp(0),
            )
            .unwrap();
            Ok(ModuleOutput {
                events: vec![
                    Event::new(
                        EventKind::EndpointObserved,
                        Some(AssetId(endpoint_asset_id(&root))),
                        BoundedDetails::from_value(
                            serde_json::json!({"url": root.canonical(), "target": root.host, "status": 200}),
                            4096,
                        )
                        .unwrap(),
                        provenance,
                    )
                    .unwrap(),
                ],
                evidence: Vec::new(),
                findings: Vec::new(),
                assets: Vec::new(),
            })
        })
    }
}

fn response(status: u16, content_type: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn redirect(location: &str) -> Vec<u8> {
    format!("HTTP/1.1 301 Moved\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
}

fn plan_for(level: &str) -> ScanPlan {
    ScanPlan::compile(Cli::try_parse_from(["rxscan", "127.0.0.1", "--level", level]).unwrap())
        .unwrap()
}

fn provenance(plan: &ScanPlan) -> Provenance {
    Provenance::new("test", "11.0.0", plan.stable_id(), Timestamp(0)).unwrap()
}

fn parsed(status: u16, content_type: &str, body: &str) -> rxscan::web::HttpResponse {
    rxscan::web::parse_response(&response(status, content_type, body), 1).unwrap()
}

fn baseline_hash(body: &str) -> String {
    signature_for_response(&parsed(200, "text/html", body), body.as_bytes()).normalized_sha256
}

fn temp_path(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("rxscan_phase11_{}_{}", std::process::id(), name));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn content_task(
    plan: &ScanPlan,
    origin: &WebTarget,
    wordlist: Option<&Path>,
    baseline_hash: Option<&str>,
    guard: &dyn ScopeGuard,
    timeout_ms: u64,
) -> Task {
    let mut params = content_task_params(origin, &endpoint_asset_id(origin), wordlist);
    if let Some(hash) = baseline_hash {
        params.insert("baseline_normalized_sha256".to_owned(), hash.to_owned());
    }
    let scope_target = match origin.ip_literal() {
        Some(ip) => TaskScopeTarget::Ip(ip),
        None => TaskScopeTarget::Host(origin.host.clone()),
    };
    Task::new_with_params(
        TaskKind::ContentDiscovery,
        None,
        Vec::new(),
        Some(AssetId(endpoint_asset_id(origin))),
        plan.stable_id(),
        30,
        Duration::from_millis(timeout_ms),
        RetryPolicy::default(),
        CONTENT_MODULE_NAME,
        provenance(plan),
        scope_target,
        params,
        guard,
    )
    .unwrap()
}

fn block_on(module: &dyn Module, context: ModuleContext) -> Result<ModuleOutput, ModuleError> {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
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
    let mut task_context = Context::from_waker(&waker);
    let mut future = module.execute(context);
    loop {
        match future.as_mut().poll(&mut task_context) {
            Poll::Ready(value) => break value,
            Poll::Pending => std::thread::park(),
        }
    }
}

fn crawl_task(plan: &ScanPlan, url: &WebTarget, guard: &dyn ScopeGuard) -> Task {
    Task::new_with_params(
        TaskKind::Crawl,
        None,
        Vec::new(),
        Some(AssetId(endpoint_asset_id(url))),
        plan.stable_id(),
        25,
        Duration::from_secs(5),
        RetryPolicy::default(),
        CRAWL_MODULE_NAME,
        provenance(plan),
        match url.ip_literal() {
            Some(ip) => TaskScopeTarget::Ip(ip),
            None => TaskScopeTarget::Host(url.host.clone()),
        },
        crawl_task_params(url, url, 1, 2, &endpoint_asset_id(url), &url.host, true),
        guard,
    )
    .unwrap()
}

#[test]
fn candidate_sources_normalize_stream_and_dedup() {
    assert_eq!(builtin_candidates().len(), 12);
    assert_eq!(
        normalize_candidate(" admin#frag ").unwrap(),
        Some("/admin".to_owned())
    );
    assert!(normalize_candidate("../admin").is_err());

    let fixture = HttpFixture::spawn(|request| match request.path.as_str() {
        "/login" => response(200, "text/html", "<html>login</html>"),
        "/docs/" => response(301, "text/html", ""),
        "/static/app.js" => response(200, "application/javascript", "console.log(1)"),
        "/api/data.json" => response(200, "application/json", r#"{"ok":true}"#),
        _ => response(404, "text/html", "missing"),
    });
    let path = temp_path("sources").join("paths.txt");
    {
        let mut file = File::create(&path).unwrap();
        writeln!(file, "# comment").unwrap();
        writeln!(file).unwrap();
        writeln!(file, "login").unwrap();
        writeln!(file, "/login#frag").unwrap();
        writeln!(file, "/docs/").unwrap();
        writeln!(file, "/static//app.js").unwrap();
        writeln!(file, "/api/data.json").unwrap();
        writeln!(file, "../escape").unwrap();
        writeln!(file, "{}", "a".repeat(600)).unwrap();
    }
    let plan = plan_for("5");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ContentDiscoveryModule::new(
        ContentDiscoveryPolicy::new(5, ScanGoal::Content, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let origin = WebTarget::parse(&fixture.url("/")).unwrap();
    let output = block_on(
        &module,
        ModuleContext::new(
            content_task(&plan, &origin, Some(&path), None, guard.as_ref(), 8000),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    let requests = fixture.paths();
    assert_eq!(
        requests
            .iter()
            .filter(|path| path.starts_with("/login"))
            .count(),
        1
    );
    assert!(output.events.iter().any(|event| {
        matches!(event.kind, EventKind::ContentDiscovered)
            && event.details.data["state"] == serde_json::json!(ContentDiscoveryState::Found)
    }));
    assert!(
        output
            .events
            .iter()
            .any(|event| matches!(event.kind, EventKind::ContentRedirectObserved))
    );
    assert!(
        output
            .events
            .iter()
            .any(|event| matches!(event.kind, EventKind::EndpointDiscovered))
    );
}

#[test]
fn crawl_then_content_discovery_uses_scan_lifetime_contact_dedup() {
    let fixture = HttpFixture::spawn(|request| match request.path.as_str() {
        "/" => response(
            200,
            "text/html",
            r#"<html><a href="/login">login</a></html>"#,
        ),
        "/login" => response(200, "text/html", "<html>login</html>"),
        _ => response(404, "text/html", "missing"),
    });
    let path = temp_path("cross_module").join("paths.txt");
    {
        let mut file = File::create(&path).unwrap();
        writeln!(file, "login").unwrap();
        writeln!(file, "/login").unwrap();
        writeln!(file, "/login#fragment").unwrap();
    }
    let plan = plan_for("5");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let contacts = rxscan::contact::ContactRegistry::new();
    let crawl_module = CrawlModule::with_contact_registry(
        CrawlPolicy::new(5, ScanGoal::Content, SpeedSetting::Numeric(100)),
        guard.clone(),
        contacts.clone(),
    );
    let content_module = ContentDiscoveryModule::with_contact_registry(
        ContentDiscoveryPolicy::new(5, ScanGoal::Content, SpeedSetting::Numeric(100)),
        guard.clone(),
        contacts,
    );
    let root = WebTarget::parse(&fixture.url("/")).unwrap();
    let root_task = crawl_task(&plan, &root, guard.as_ref());
    let root_output = block_on(
        &crawl_module,
        ModuleContext::new(root_task.clone(), CancellationToken::default()),
    )
    .unwrap();
    assert!(root_output.events.iter().any(|event| {
        matches!(event.kind, EventKind::EndpointDiscovered)
            && event.details.data["url"]
                .as_str()
                .is_some_and(|url| url.ends_with("/login"))
    }));

    let engine = Phase7Engine::new(
        guard.clone(),
        plan.stable_id(),
        5,
        ScanGoal::Content,
        plan.tcp_ports.clone(),
        SpeedSetting::Numeric(100),
    );
    let child_tasks = engine.follow_up_tasks(&root_task, &root_output);
    let login_task = child_tasks
        .into_iter()
        .find(|task| task.kind == TaskKind::Crawl && task.params["url"].ends_with("/login"))
        .expect("decision engine should propose child crawl");
    let _login_output = block_on(
        &crawl_module,
        ModuleContext::new(login_task, CancellationToken::default()),
    )
    .unwrap();
    assert_eq!(
        fixture
            .paths()
            .iter()
            .filter(|path| path.as_str() == "/login")
            .count(),
        1
    );

    let content_output = block_on(
        &content_module,
        ModuleContext::new(
            content_task(&plan, &root, Some(&path), None, guard.as_ref(), 8000),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(content_output.events.iter().any(|event| {
        matches!(event.kind, EventKind::ContentDiscoveryCompleted)
            && event.details.data["dedup_avoided_requests"]
                .as_u64()
                .unwrap_or(0)
                >= 4
    }));
    assert_eq!(
        fixture
            .paths()
            .iter()
            .filter(|path| path.as_str() == "/login")
            .count(),
        1
    );
}

#[test]
fn baseline_filtering_scope_redirect_canary_and_jsonl_are_observable() {
    let canary = HttpFixture::spawn(|_| response(200, "text/html", "outside"));
    let canary_port = canary.port;
    let missing = "<html><title>Missing</title>not found 99999</html>";
    let fixture = HttpFixture::spawn(move |request| match request.path.as_str() {
        "/real" => response(200, "text/html", "<html><title>Real</title>ok</html>"),
        "/secret" => response(403, "text/html", "forbidden"),
        "/auth" => response(401, "text/html", "auth"),
        "/redir" => redirect(&format!("http://localhost:{canary_port}/outside")),
        _ => response(200, "text/html", missing),
    });
    let path = temp_path("baseline").join("paths.txt");
    {
        let mut file = File::create(&path).unwrap();
        writeln!(file, "/real").unwrap();
        writeln!(file, "/missing").unwrap();
        writeln!(file, "/secret").unwrap();
        writeln!(file, "/auth").unwrap();
        writeln!(file, "/redir").unwrap();
    }
    let plan = plan_for("5");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ContentDiscoveryModule::new(
        ContentDiscoveryPolicy::new(5, ScanGoal::Content, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let origin = WebTarget::parse(&fixture.url("/")).unwrap();
    let output = block_on(
        &module,
        ModuleContext::new(
            content_task(
                &plan,
                &origin,
                Some(&path),
                Some(&baseline_hash(missing)),
                guard.as_ref(),
                8000,
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(canary.paths().is_empty());
    assert!(output.events.iter().any(|event| {
        matches!(event.kind, EventKind::ContentRejectedByBaseline)
            && event.details.data["state"] == serde_json::json!(ContentDiscoveryState::SoftNotFound)
    }));
    assert!(output.events.iter().any(|event| {
        matches!(event.kind, EventKind::ContentDiscovered)
            && event.details.data["state"] == serde_json::json!(ContentDiscoveryState::Forbidden)
    }));
    let mut bytes = Vec::new();
    {
        let mut writer = JsonlWriter::new(&mut bytes, 1024 * 1024);
        for event in &output.events {
            writer.write_event(event).unwrap();
        }
        for evidence in &output.evidence {
            writer.write_evidence(evidence).unwrap();
        }
    }
    assert!(!bytes.is_empty());
}

#[test]
fn budgets_cancellation_timeout_and_unreadable_files_are_bounded() {
    let fixture = HttpFixture::spawn_with_delay(Duration::from_secs(2), |_| {
        response(200, "text/html", "<html>late</html>")
    });
    let plan = plan_for("5");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ContentDiscoveryModule::new(
        ContentDiscoveryPolicy::new(5, ScanGoal::Content, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let origin = WebTarget::parse(&fixture.url("/")).unwrap();
    let cancel = CancellationToken::default();
    cancel.cancel();
    let cancelled = block_on(
        &module,
        ModuleContext::new(
            content_task(&plan, &origin, None, None, guard.as_ref(), 1000),
            cancel,
        ),
    );
    assert!(matches!(cancelled, Err(ModuleError::Cancelled)));
    assert!(fixture.paths().is_empty());

    let timed = block_on(
        &module,
        ModuleContext::new(
            content_task(&plan, &origin, None, None, guard.as_ref(), 700),
            CancellationToken::default(),
        ),
    );
    if let Ok(output) = timed {
        assert!(
            output
                .events
                .iter()
                .any(|event| matches!(event.kind, EventKind::ContentDiscoveryCompleted))
        );
    } else {
        assert!(matches!(timed, Err(ModuleError::Cancelled)));
    }

    let fast_fixture = HttpFixture::spawn(|_| response(404, "text/html", "missing"));
    let fast_origin = WebTarget::parse(&fast_fixture.url("/")).unwrap();
    let unreadable = block_on(
        &module,
        ModuleContext::new(
            content_task(
                &plan,
                &fast_origin,
                Some(Path::new("/tmp/rxscan-no-such-wordlist")),
                None,
                guard.as_ref(),
                1000,
            ),
            CancellationToken::default(),
        ),
    );
    assert!(matches!(
        unreadable,
        Err(ModuleError::Failed {
            retryable: false,
            ..
        })
    ));
}

#[test]
fn decision_engine_and_scheduler_path_admit_content_after_baseline() {
    let fixture = HttpFixture::spawn(|request| {
        if request.path.starts_with("/__rxscan_baseline_") {
            response(404, "text/html", "missing")
        } else if request.path == "/login" {
            response(200, "text/html", "<html>login</html>")
        } else {
            response(404, "text/html", "missing")
        }
    });
    let plan = plan_for("5");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let root = WebTarget::parse(&fixture.url("/")).unwrap();
    let mut scheduler = Scheduler::new(
        64,
        BudgetLimits {
            max_concurrency: 1,
            max_tasks: 16,
            ..BudgetLimits::default()
        },
        SpeedGovernor::new(SpeedSetting::Numeric(100), 1).unwrap(),
        guard.clone(),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler.register_module(Arc::new(ConfirmedEndpointModule { root: root.clone() }));
    scheduler.register_module(Arc::new(BaselineModule::new(
        BaselinePolicy::new(5, ScanGoal::Content, SpeedSetting::Numeric(100)),
        guard.clone(),
    )));
    scheduler.register_module(Arc::new(ContentDiscoveryModule::new(
        ContentDiscoveryPolicy::new(5, ScanGoal::Content, SpeedSetting::Numeric(100)),
        guard.clone(),
    )));
    scheduler.set_decision_engine(Arc::new(Phase7Engine::new(
        guard.clone(),
        plan.stable_id(),
        5,
        ScanGoal::Content,
        plan.tcp_ports.clone(),
        SpeedSetting::Numeric(100),
    )));
    let seed = Task::new_with_params(
        TaskKind::HttpProbe,
        None,
        Vec::new(),
        Some(AssetId(endpoint_asset_id(&root))),
        plan.stable_id(),
        50,
        Duration::from_secs(5),
        RetryPolicy::default(),
        "phase11.test.http",
        provenance(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([("url".to_owned(), root.canonical())]),
        guard.as_ref(),
    )
    .unwrap();
    scheduler.add_task(seed).unwrap();
    let report = scheduler.run().unwrap();
    assert!(report.failed.is_empty());
    assert!(
        scheduler
            .tasks()
            .any(|task| task.kind == TaskKind::Baseline)
    );
    assert!(
        scheduler
            .tasks()
            .any(|task| task.kind == TaskKind::ContentDiscovery)
    );
    assert!(scheduler.module_outputs().iter().any(|(_, output)| {
        output
            .events
            .iter()
            .any(|event| matches!(event.kind, EventKind::ContentDiscovered))
    }));
}

#[test]
fn large_wordlist_is_streamed_and_capped_without_loading_whole_file() {
    let fixture = HttpFixture::spawn(|request| {
        if request.path == "/hit" {
            response(200, "text/html", "hit")
        } else {
            response(404, "text/html", "missing")
        }
    });
    let path = temp_path("large").join("large.txt");
    {
        let mut file = File::create(&path).unwrap();
        writeln!(file, "/hit").unwrap();
        for index in 0..3000 {
            writeln!(file, "/miss-{index}").unwrap();
        }
    }
    let plan = plan_for("5");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ContentDiscoveryModule::new(
        ContentDiscoveryPolicy::new(4, ScanGoal::Content, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let origin = WebTarget::parse(&fixture.url("/")).unwrap();
    let output = block_on(
        &module,
        ModuleContext::new(
            content_task(&plan, &origin, Some(&path), None, guard.as_ref(), 8000),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(fixture.paths().len() <= 64);
    assert!(
        output
            .events
            .iter()
            .any(|event| matches!(event.kind, EventKind::ContentDiscoveryBudgetExhausted))
    );
}

#[test]
fn ipv6_content_discovery_uses_canonical_bracketed_origin_when_supported() {
    let Some(fixture) = HttpFixture::spawn_ipv6(|request| {
        if request.path == "/login" {
            response(200, "text/html", "login")
        } else {
            response(404, "text/html", "missing")
        }
    }) else {
        eprintln!("skipping IPv6 content discovery test: ::1 bind unavailable");
        return;
    };
    let plan = ScanPlan::compile(
        Cli::try_parse_from(["rxscan", "::1", "--scope", "::1", "--level", "5"]).unwrap(),
    )
    .unwrap();
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ContentDiscoveryModule::new(
        ContentDiscoveryPolicy::new(5, ScanGoal::Content, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let origin = WebTarget::parse(&fixture.url("/")).unwrap();
    assert!(origin.canonical().starts_with("http://[::1]:"));
    let output = block_on(
        &module,
        ModuleContext::new(
            content_task(&plan, &origin, None, None, guard.as_ref(), 8000),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(fixture.paths().contains(&"/login".to_owned()));
    assert!(
        output
            .events
            .iter()
            .any(|event| matches!(event.kind, EventKind::ContentDiscovered))
    );
}

#[test]
fn level_and_speed_preserve_semantics() {
    let l1 = ContentDiscoveryPolicy::new(1, ScanGoal::Content, SpeedSetting::Numeric(100));
    let l2 = ContentDiscoveryPolicy::new(2, ScanGoal::Content, SpeedSetting::Numeric(100));
    let l5_fast = ContentDiscoveryPolicy::new(5, ScanGoal::Content, SpeedSetting::Numeric(100));
    let l5_slow = ContentDiscoveryPolicy::new(5, ScanGoal::Content, SpeedSetting::Numeric(1));
    assert!(!l1.enabled());
    assert!(l2.builtin_limit() < l5_fast.builtin_limit());
    assert_eq!(l5_fast.builtin_limit(), l5_slow.builtin_limit());
    assert_eq!(l5_fast.request_limit(), l5_slow.request_limit());
}
