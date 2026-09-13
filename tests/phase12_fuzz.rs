//! Phase 12 contextual fuzzing tests: local fixtures only.

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
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
    decision::Phase7Engine,
    execution::{
        BudgetLimits, CancellationToken, DecisionEngine, Module, ModuleContext, ModuleError,
        ModuleFuture, ModuleOutput, PolicyScopeGuard, RetryPolicy, Scheduler, ScopeGuard,
        SpeedGovernor, Task, TaskKind, TaskScopeTarget, VecEventSink,
    },
    fuzz::{FUZZ_MODULE_NAME, FuzzModule, FuzzOutcome, FuzzPolicy, fuzz_task_params},
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
                "phase12.test.http",
                "1.0.0",
                context.task.scan_plan_id.clone(),
                Timestamp(0),
            )
            .unwrap();
            Ok(ModuleOutput {
                events: vec![Event::new(
                    EventKind::EndpointObserved,
                    Some(AssetId(endpoint_asset_id(&root))),
                    BoundedDetails::from_value(
                        serde_json::json!({"url": root.canonical(), "target": root.host, "status": 200}),
                        4096,
                    )
                    .unwrap(),
                    provenance,
                )
                .unwrap()],
                evidence: Vec::new(),
                findings: Vec::new(),
                assets: Vec::new(),
            })
        })
    }
}

struct ConfirmedEndpointsModule {
    roots: Vec<WebTarget>,
}

impl Module for ConfirmedEndpointsModule {
    fn kind(&self) -> TaskKind {
        TaskKind::HttpProbe
    }

    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let roots = self.roots.clone();
        Box::pin(async move {
            let provenance = Provenance::new(
                "phase12.test.http",
                "1.0.0",
                context.task.scan_plan_id.clone(),
                Timestamp(0),
            )
            .unwrap();
            let mut events = Vec::new();
            for root in roots {
                events.push(
                    Event::new(
                        EventKind::EndpointObserved,
                        Some(AssetId(endpoint_asset_id(&root))),
                        BoundedDetails::from_value(
                            serde_json::json!({"url": root.canonical(), "target": root.host, "status": 200}),
                            4096,
                        )
                        .unwrap(),
                        provenance.clone(),
                    )
                    .unwrap(),
                );
            }
            Ok(ModuleOutput {
                events,
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
    format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
}

fn parsed(status: u16, content_type: &str, body: &str) -> rxscan::web::HttpResponse {
    rxscan::web::parse_response(&response(status, content_type, body), 1).unwrap()
}

fn plan_for(level: &str, goal: &str) -> ScanPlan {
    ScanPlan::compile(
        Cli::try_parse_from(["rxscan", "127.0.0.1", "--level", level, "--goal", goal]).unwrap(),
    )
    .unwrap()
}

fn provenance(plan: &ScanPlan) -> Provenance {
    Provenance::new("test", "12.0.0", plan.stable_id(), Timestamp(0)).unwrap()
}

fn signature(status: u16, content_type: &str, body: &str) -> rxscan::baseline::ResponseSignature {
    signature_for_response(&parsed(status, content_type, body), body.as_bytes())
}

fn fuzz_task(
    plan: &ScanPlan,
    url: &WebTarget,
    param: &str,
    baseline: Option<&rxscan::baseline::ResponseSignature>,
    guard: &dyn ScopeGuard,
    timeout_ms: u64,
) -> Task {
    Task::new_with_params(
        TaskKind::Fuzz,
        None,
        Vec::new(),
        Some(AssetId(endpoint_asset_id(url))),
        plan.stable_id(),
        20,
        Duration::from_millis(timeout_ms),
        RetryPolicy::default(),
        FUZZ_MODULE_NAME,
        provenance(plan),
        match url.ip_literal() {
            Some(ip) => TaskScopeTarget::Ip(ip),
            None => TaskScopeTarget::Host(url.host.clone()),
        },
        fuzz_task_params(url, &endpoint_asset_id(url), param, baseline),
        guard,
    )
    .unwrap()
}

fn baseline_task(plan: &ScanPlan, url: &WebTarget, guard: &dyn ScopeGuard) -> Task {
    Task::new_with_params(
        TaskKind::Baseline,
        None,
        Vec::new(),
        Some(AssetId(endpoint_asset_id(url))),
        plan.stable_id(),
        30,
        Duration::from_secs(5),
        RetryPolicy::default(),
        rxscan::baseline::BASELINE_MODULE_NAME,
        provenance(plan),
        match url.ip_literal() {
            Some(ip) => TaskScopeTarget::Ip(ip),
            None => TaskScopeTarget::Host(url.host.clone()),
        },
        BTreeMap::from([("url".to_owned(), url.canonical())]),
        guard,
    )
    .unwrap()
}

fn baseline_output(plan: &ScanPlan, url: &WebTarget) -> ModuleOutput {
    let provenance = provenance(plan);
    ModuleOutput {
        events: vec![
            Event::new(
                EventKind::ResponseSignatureObserved,
                Some(AssetId(endpoint_asset_id(url))),
                BoundedDetails::from_value(
                    serde_json::json!({
                        "url": url.canonical(),
                        "signature": signature(200, "text/html", "control"),
                    }),
                    8192,
                )
                .unwrap(),
                provenance,
            )
            .unwrap(),
        ],
        evidence: Vec::new(),
        findings: Vec::new(),
        assets: Vec::new(),
    }
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

#[test]
fn fuzz_disabled_without_observed_safe_query_context() {
    let fixture = HttpFixture::spawn(|_| response(200, "text/html", "ok"));
    let plan = plan_for("1", "fuzz");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = FuzzModule::new(
        FuzzPolicy::new(1, ScanGoal::Fuzz, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let url = WebTarget::parse(&fixture.url("/search?q=alice")).unwrap();
    let output = block_on(
        &module,
        ModuleContext::new(
            fuzz_task(&plan, &url, "q", None, guard.as_ref(), 1000),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(output.events.is_empty());
    assert!(fixture.paths().is_empty());

    let enabled = FuzzModule::new(
        FuzzPolicy::new(5, ScanGoal::Fuzz, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let no_param = block_on(
        &enabled,
        ModuleContext::new(
            fuzz_task(&plan, &url, "unobserved", None, guard.as_ref(), 1000),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(no_param.events.iter().any(|event| {
        matches!(event.kind, EventKind::FuzzBudgetExhausted)
            && event.details.data["reason"] == "no-observed-query-parameter"
    }));
    assert!(fixture.paths().is_empty());
}

#[test]
fn mutations_are_safe_one_parameter_at_a_time_and_classify_deltas() {
    let fixture = HttpFixture::spawn(|request| {
        if request.path.contains("limit=0") {
            response(400, "application/json", r#"{"error":"bad limit"}"#)
        } else if request.path.contains("limit=20") {
            response(200, "text/html", "<html><title>Items</title>normal</html>")
        } else {
            response(
                200,
                "text/html",
                "<html><title>Items</title>changed body</html>",
            )
        }
    });
    let plan = plan_for("5", "fuzz");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = FuzzModule::new(
        FuzzPolicy::new(5, ScanGoal::Fuzz, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let url = WebTarget::parse(&fixture.url("/items?limit=20&sort=asc")).unwrap();
    let output = block_on(
        &module,
        ModuleContext::new(
            fuzz_task(
                &plan,
                &url,
                "limit",
                Some(&signature(
                    200,
                    "text/html",
                    "<html><title>Items</title>normal</html>",
                )),
                guard.as_ref(),
                8000,
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    let paths = fixture.paths();
    assert!(!paths.is_empty());
    assert!(
        paths
            .iter()
            .all(|path| path.contains("sort=asc") || !path.contains('?'))
    );
    assert!(paths.iter().filter(|path| path.contains("limit=")).count() <= 3);
    assert!(output.events.iter().any(|event| {
        matches!(event.kind, EventKind::FuzzBehaviorDeltaObserved)
            && event.details.data["outcome"] == serde_json::json!(FuzzOutcome::ErrorBehaviorChanged)
    }));
}

#[test]
fn text_reflection_redirect_content_type_and_sensitive_skip_are_observed_safely() {
    let canary = HttpFixture::spawn(|_| response(200, "text/html", "outside"));
    let canary_port = canary.port;
    let fixture = HttpFixture::spawn(move |request| {
        if request.path.starts_with("/echo") {
            let reflected = request
                .path
                .split("q=")
                .nth(1)
                .and_then(|rest| rest.split('&').next())
                .unwrap_or("");
            response(200, "text/html", &format!("<html>{reflected}</html>"))
        } else if request.path.starts_with("/redir") {
            redirect(&format!("http://localhost:{canary_port}/outside"))
        } else if request.path.starts_with("/type") {
            response(200, "application/json", r#"{"ok":true}"#)
        } else {
            response(200, "text/html", "ok")
        }
    });
    let plan = plan_for("5", "fuzz");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = FuzzModule::new(
        FuzzPolicy::new(5, ScanGoal::Fuzz, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let echo = WebTarget::parse(&fixture.url("/echo?q=alice")).unwrap();
    let echoed = block_on(
        &module,
        ModuleContext::new(
            fuzz_task(
                &plan,
                &echo,
                "q",
                Some(&signature(200, "text/html", "<html>alice</html>")),
                guard.as_ref(),
                8000,
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(
        echoed
            .events
            .iter()
            .any(|event| matches!(event.kind, EventKind::FuzzInputReflected))
    );

    let redir = WebTarget::parse(&fixture.url("/redir?next=home")).unwrap();
    let redir_out = block_on(
        &module,
        ModuleContext::new(
            fuzz_task(
                &plan,
                &redir,
                "next",
                Some(&signature(200, "text/html", "ok")),
                guard.as_ref(),
                8000,
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(canary.paths().is_empty());
    assert!(redir_out.events.iter().any(|event| {
        matches!(event.kind, EventKind::FuzzBehaviorDeltaObserved)
            && event.details.data["outcome"] == serde_json::json!(FuzzOutcome::RedirectChanged)
    }));

    let sensitive = WebTarget::parse(&fixture.url("/echo?csrf_token=abc")).unwrap();
    let skipped = block_on(
        &module,
        ModuleContext::new(
            fuzz_task(&plan, &sensitive, "csrf_token", None, guard.as_ref(), 8000),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(
        skipped
            .events
            .iter()
            .any(|event| matches!(event.kind, EventKind::FuzzSkippedSensitiveInput))
    );
}

#[test]
fn cancellation_timeout_dedup_jsonl_and_ipv6_are_bounded() {
    let fixture = HttpFixture::spawn_with_delay(Duration::from_secs(2), |_| {
        response(200, "text/html", "late")
    });
    let plan = plan_for("5", "fuzz");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let contacts = rxscan::contact::ContactRegistry::new();
    let module = FuzzModule::with_contact_registry(
        FuzzPolicy::new(5, ScanGoal::Fuzz, SpeedSetting::Numeric(100)),
        guard.clone(),
        contacts,
    );
    let url = WebTarget::parse(&fixture.url("/slow?q=alice")).unwrap();
    let cancel = CancellationToken::default();
    cancel.cancel();
    let cancelled = block_on(
        &module,
        ModuleContext::new(
            fuzz_task(&plan, &url, "q", None, guard.as_ref(), 1000),
            cancel,
        ),
    );
    assert!(matches!(cancelled, Err(ModuleError::Cancelled)));
    assert!(fixture.paths().is_empty());

    let timed = block_on(
        &module,
        ModuleContext::new(
            fuzz_task(
                &plan,
                &url,
                "q",
                Some(&signature(200, "text/html", "late")),
                guard.as_ref(),
                700,
            ),
            CancellationToken::default(),
        ),
    );
    if let Ok(output) = &timed {
        assert!(
            output
                .events
                .iter()
                .any(|event| matches!(event.kind, EventKind::ContextualFuzzCompleted))
        );
    } else {
        assert!(matches!(timed, Err(ModuleError::Cancelled)));
    }

    let mut bytes = Vec::new();
    if let Ok(output) = &timed {
        {
            let mut writer = JsonlWriter::new(&mut bytes, 1024 * 1024);
            for event in &output.events {
                writer.write_event(event).unwrap();
            }
        }
        assert!(!bytes.is_empty());
    }

    if let Some(ipv6) = HttpFixture::spawn_ipv6(|_| response(200, "text/html", "v6")) {
        let plan = ScanPlan::compile(
            Cli::try_parse_from([
                "rxscan", "::1", "--scope", "::1", "--level", "5", "--goal", "fuzz",
            ])
            .unwrap(),
        )
        .unwrap();
        let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
        let module = FuzzModule::new(
            FuzzPolicy::new(5, ScanGoal::Fuzz, SpeedSetting::Numeric(100)),
            guard.clone(),
        );
        let target = WebTarget::parse(&ipv6.url("/v?q=1")).unwrap();
        assert!(target.canonical().starts_with("http://[::1]:"));
        let output = block_on(
            &module,
            ModuleContext::new(
                fuzz_task(
                    &plan,
                    &target,
                    "q",
                    Some(&signature(200, "text/html", "v6")),
                    guard.as_ref(),
                    8000,
                ),
                CancellationToken::default(),
            ),
        )
        .unwrap();
        assert!(!output.events.is_empty());
    } else {
        eprintln!("skipping IPv6 contextual fuzz coverage: ::1 bind unavailable in this runtime");
    }
}

#[test]
fn production_decision_scheduler_wires_baseline_to_fuzz_tasks() {
    let fixture = HttpFixture::spawn(|request| match request.path.as_str() {
        path if path.starts_with("/__rxscan_baseline_") => response(404, "text/html", "missing"),
        path if path.contains("q=alice") => response(200, "text/html", "<html>alice</html>"),
        path if path.contains("q=") => response(200, "text/html", "<html>changed</html>"),
        _ => response(200, "text/html", "<html>root</html>"),
    });
    let plan = plan_for("5", "fuzz");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let root = WebTarget::parse(&fixture.url("/search?q=alice")).unwrap();
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
        BaselinePolicy::new(5, ScanGoal::Fuzz, SpeedSetting::Numeric(100)),
        guard.clone(),
    )));
    scheduler.register_module(Arc::new(FuzzModule::new(
        FuzzPolicy::new(5, ScanGoal::Fuzz, SpeedSetting::Numeric(100)),
        guard.clone(),
    )));
    scheduler.set_decision_engine(Arc::new(Phase7Engine::new(
        guard.clone(),
        plan.stable_id(),
        5,
        ScanGoal::Fuzz,
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
        "phase12.test.http",
        provenance(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([("url".to_owned(), root.canonical())]),
        guard.as_ref(),
    )
    .unwrap();
    scheduler.add_task(seed).unwrap();
    let report = scheduler.run().unwrap();
    assert!(report.failed.is_empty());
    assert!(scheduler.tasks().any(|task| task.kind == TaskKind::Fuzz));
    assert!(scheduler.module_outputs().iter().any(|(_, output)| {
        output
            .events
            .iter()
            .any(|event| matches!(event.kind, EventKind::FuzzBehaviorDeltaObserved))
    }));
}

fn fuzz_outcomes(output: &ModuleOutput) -> Vec<FuzzOutcome> {
    output
        .events
        .iter()
        .filter(|event| matches!(event.kind, EventKind::FuzzBehaviorDeltaObserved))
        .filter_map(|event| serde_json::from_value(event.details.data["outcome"].clone()).ok())
        .collect()
}

#[test]
fn advertised_delta_outcomes_are_reachable_or_bounded_errors() {
    let fixture = HttpFixture::spawn(|request| match request.path.as_str() {
        path if path.starts_with("/same") => response(200, "text/html", "same"),
        path if path.starts_with("/type") && path.contains("q=alice") => {
            response(200, "text/html", "type")
        }
        path if path.starts_with("/type") => response(200, "application/json", r#"{"type":true}"#),
        path if path.starts_with("/template") && path.contains("q=alice") => response(
            200,
            "text/html",
            &format!(
                "<html><title>Items</title><main>{}</main></html>",
                "product alpha ".repeat(32)
            ),
        ),
        path if path.starts_with("/template") => response(
            200,
            "text/html",
            &format!(
                "<html><title>Items</title><main>{}</main></html>",
                "product beta ".repeat(32)
            ),
        ),
        path if path.starts_with("/short") && path.contains("q=alice") => {
            response(200, "text/html", "alpha")
        }
        path if path.starts_with("/short") => response(200, "text/html", "bravo"),
        path if path.starts_with("/long") && path.contains("q=alice") => {
            response(200, "text/html", "small")
        }
        path if path.starts_with("/long") => response(
            200,
            "text/html",
            "this response is intentionally much longer",
        ),
        path if path.starts_with("/status") && path.contains("q=alice") => {
            response(201, "text/html", "created")
        }
        path if path.starts_with("/status") => response(202, "text/html", "accepted"),
        _ => response(200, "text/html", "fallback"),
    });
    let plan = plan_for("5", "fuzz");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = FuzzModule::new(
        FuzzPolicy::new(5, ScanGoal::Fuzz, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let cases = [
        (
            "/same?q=alice",
            signature(200, "text/html", "same"),
            FuzzOutcome::NoMeaningfulChange,
        ),
        (
            "/type?q=alice",
            signature(200, "text/html", "type"),
            FuzzOutcome::ContentTypeChanged,
        ),
        (
            "/template?q=alice",
            signature(
                200,
                "text/html",
                &format!(
                    "<html><title>Items</title><main>{}</main></html>",
                    "product alpha ".repeat(32)
                ),
            ),
            FuzzOutcome::TemplateChanged,
        ),
        (
            "/short?q=alice",
            signature(200, "text/html", "alpha"),
            FuzzOutcome::BodyChanged,
        ),
        (
            "/long?q=alice",
            signature(200, "text/html", "small"),
            FuzzOutcome::LengthChanged,
        ),
        (
            "/status?q=alice",
            signature(201, "text/html", "created"),
            FuzzOutcome::StatusChanged,
        ),
    ];
    for (path, baseline, expected) in cases {
        let url = WebTarget::parse(&fixture.url(path)).unwrap();
        let output = block_on(
            &module,
            ModuleContext::new(
                fuzz_task(&plan, &url, "q", Some(&baseline), guard.as_ref(), 8000),
                CancellationToken::default(),
            ),
        )
        .unwrap();
        assert!(
            fuzz_outcomes(&output).contains(&expected),
            "{expected:?} not emitted for {path}: {:?}",
            fuzz_outcomes(&output)
        );
    }

    let inconclusive = WebTarget::parse(&fixture.url("/same?q=alice")).unwrap();
    let inconclusive_module = FuzzModule::new(
        FuzzPolicy::new(5, ScanGoal::Fuzz, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let output = block_on(
        &inconclusive_module,
        ModuleContext::new(
            fuzz_task(&plan, &inconclusive, "q", None, guard.as_ref(), 8000),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(fuzz_outcomes(&output).contains(&FuzzOutcome::Inconclusive));

    let missing = WebTarget::parse("http://127.0.0.1:9/missing?q=alice").unwrap();
    let bad_module = FuzzModule::new(
        FuzzPolicy::new(5, ScanGoal::Fuzz, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let output = block_on(
        &bad_module,
        ModuleContext::new(
            fuzz_task(
                &plan,
                &missing,
                "q",
                Some(&signature(200, "text/html", "fallback")),
                guard.as_ref(),
                8000,
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(fuzz_outcomes(&output).contains(&FuzzOutcome::RequestError));
}

#[test]
fn baseline_reuse_and_cross_batch_fuzz_dedup_have_counter_proof() {
    let fixture = HttpFixture::spawn(|request| {
        if request.path.contains("q=alice") {
            response(200, "text/html", "control")
        } else {
            response(200, "text/html", "changed")
        }
    });
    let plan = plan_for("5", "fuzz");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let contacts = rxscan::contact::ContactRegistry::new();
    let module = FuzzModule::with_contact_registry(
        FuzzPolicy::new(5, ScanGoal::Fuzz, SpeedSetting::Numeric(100)),
        guard.clone(),
        contacts,
    );
    let url = WebTarget::parse(&fixture.url("/search?q=alice")).unwrap();
    let baseline = signature(200, "text/html", "control");
    for _ in 0..2 {
        let output = block_on(
            &module,
            ModuleContext::new(
                fuzz_task(&plan, &url, "q", Some(&baseline), guard.as_ref(), 8000),
                CancellationToken::default(),
            ),
        )
        .unwrap();
        assert!(
            output
                .events
                .iter()
                .any(|event| matches!(event.kind, EventKind::ContextualFuzzCompleted))
        );
    }
    let paths = fixture.paths();
    assert!(
        paths
            .iter()
            .all(|path| !path.contains("q=alice") && !path.starts_with("/__rxscan_baseline_")),
        "fuzz should reuse supplied baseline without fresh control requests: {paths:?}"
    );
    let unique: std::collections::BTreeSet<_> = paths.iter().collect();
    assert_eq!(
        paths.len(),
        unique.len(),
        "duplicate fuzz requests were contacted"
    );
    assert!(
        paths.len() > 1,
        "distinct mutation values must remain distinct"
    );
}

#[test]
fn scheduler_budget_bounds_scan_wide_fuzz_growth_across_many_endpoints() {
    let fixture = HttpFixture::spawn(|request| match request.path.as_str() {
        path if path.starts_with("/__rxscan_baseline_") => response(404, "text/html", "missing"),
        path if path.contains("q=alice") => response(200, "text/html", "control"),
        _ => response(200, "text/html", "changed"),
    });
    let plan = plan_for("5", "fuzz");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let roots: Vec<_> = (0..32)
        .map(|index| WebTarget::parse(&fixture.url(&format!("/p{index}?q=alice"))).unwrap())
        .collect();
    let mut scheduler = Scheduler::new(
        64,
        BudgetLimits {
            max_concurrency: 1,
            max_tasks: 12,
            ..BudgetLimits::default()
        },
        SpeedGovernor::new(SpeedSetting::Numeric(100), 1).unwrap(),
        guard.clone(),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler.register_module(Arc::new(ConfirmedEndpointsModule {
        roots: roots.clone(),
    }));
    scheduler.register_module(Arc::new(BaselineModule::new(
        BaselinePolicy::new(5, ScanGoal::Fuzz, SpeedSetting::Numeric(100)),
        guard.clone(),
    )));
    scheduler.register_module(Arc::new(FuzzModule::new(
        FuzzPolicy::new(5, ScanGoal::Fuzz, SpeedSetting::Numeric(100)),
        guard.clone(),
    )));
    scheduler.set_decision_engine(Arc::new(Phase7Engine::new(
        guard.clone(),
        plan.stable_id(),
        5,
        ScanGoal::Fuzz,
        plan.tcp_ports.clone(),
        SpeedSetting::Numeric(100),
    )));
    let seed = Task::new_with_params(
        TaskKind::HttpProbe,
        None,
        Vec::new(),
        Some(AssetId(endpoint_asset_id(&roots[0]))),
        plan.stable_id(),
        50,
        Duration::from_secs(5),
        RetryPolicy::default(),
        "phase12.test.http",
        provenance(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::new(),
        guard.as_ref(),
    )
    .unwrap();
    scheduler.add_task(seed).unwrap();
    let report = scheduler.run().unwrap();
    assert!(report.completed.len() <= 12);
    assert_eq!(scheduler.tasks().count(), 12);
    let fuzz_tasks = scheduler
        .tasks()
        .filter(|task| task.kind == TaskKind::Fuzz)
        .count();
    let mutation_attempts = scheduler
        .module_outputs()
        .iter()
        .flat_map(|(_, output)| &output.events)
        .filter(|event| matches!(event.kind, EventKind::FuzzMutationAttempted))
        .count();
    assert!(fuzz_tasks <= 12);
    assert!(mutation_attempts <= fuzz_tasks * rxscan::fuzz::MAX_FUZZ_REQUESTS_PER_TASK);
    assert!(fixture.paths().len() <= 12 + mutation_attempts + 10);
}

#[test]
fn level_two_fuzzing_is_disabled_with_zero_mutation_contacts() {
    let fixture = HttpFixture::spawn(|_| response(200, "text/html", "ok"));
    let plan = plan_for("2", "fuzz");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = FuzzModule::new(
        FuzzPolicy::new(2, ScanGoal::Fuzz, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let url = WebTarget::parse(&fixture.url("/search?q=alice")).unwrap();
    let output = block_on(
        &module,
        ModuleContext::new(
            fuzz_task(
                &plan,
                &url,
                "q",
                Some(&signature(200, "text/html", "ok")),
                guard.as_ref(),
                8000,
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(output.events.is_empty());
    assert!(fixture.paths().is_empty());
}

fn mutation_attempts(output: &ModuleOutput) -> Vec<(serde_json::Value, String)> {
    output
        .events
        .iter()
        .filter(|event| matches!(event.kind, EventKind::FuzzMutationAttempted))
        .map(|event| {
            (
                event.details.data["mutation_class"].clone(),
                event.details.data["url"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect()
}

#[test]
fn speed_changes_pressure_not_fuzz_semantics() {
    let fixture = HttpFixture::spawn(|request| {
        if request.path.contains("q=alice") {
            response(200, "text/html", "control")
        } else {
            response(200, "text/html", "changed")
        }
    });
    let plan = plan_for("5", "fuzz");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let url = WebTarget::parse(&fixture.url("/search?q=alice")).unwrap();
    let baseline = signature(200, "text/html", "control");
    let run = |speed| {
        let module = FuzzModule::new(FuzzPolicy::new(5, ScanGoal::Fuzz, speed), guard.clone());
        block_on(
            &module,
            ModuleContext::new(
                fuzz_task(&plan, &url, "q", Some(&baseline), guard.as_ref(), 8000),
                CancellationToken::default(),
            ),
        )
        .unwrap()
    };
    let slow = run(SpeedSetting::Numeric(10));
    let fast = run(SpeedSetting::Numeric(100));
    assert_eq!(mutation_attempts(&slow), mutation_attempts(&fast));
    assert_eq!(fuzz_outcomes(&slow), fuzz_outcomes(&fast));

    let engine = |speed| {
        Phase7Engine::new(
            guard.clone(),
            plan.stable_id(),
            5,
            ScanGoal::Fuzz,
            plan.tcp_ports.clone(),
            speed,
        )
    };
    let slow_tasks = engine(SpeedSetting::Numeric(10)).follow_up_tasks(
        &baseline_task(&plan, &url, guard.as_ref()),
        &baseline_output(&plan, &url),
    );
    let fast_tasks = engine(SpeedSetting::Numeric(100)).follow_up_tasks(
        &baseline_task(&plan, &url, guard.as_ref()),
        &baseline_output(&plan, &url),
    );
    assert_eq!(slow_tasks.len(), fast_tasks.len());
    assert_eq!(slow_tasks[0].id, fast_tasks[0].id);
    assert_eq!(slow_tasks[0].params, fast_tasks[0].params);
}

#[test]
fn fuzz_task_identity_is_plan_shaped_and_mutation_requests_are_independent() {
    let plan = plan_for("5", "fuzz");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let one = WebTarget::parse("http://127.0.0.1:80/search?q=alice").unwrap();
    let same = WebTarget::parse("http://127.0.0.1:80/search?q=alice#fragment").unwrap();
    let other_param = WebTarget::parse("http://127.0.0.1:80/search?q=alice&page=1").unwrap();
    let other_endpoint = WebTarget::parse("http://127.0.0.1:80/other?q=alice").unwrap();
    let sig = signature(200, "text/html", "control");
    let first = fuzz_task(&plan, &one, "q", Some(&sig), guard.as_ref(), 8000);
    let second = fuzz_task(&plan, &same, "q", Some(&sig), guard.as_ref(), 8000);
    let third = fuzz_task(
        &plan,
        &other_param,
        "page",
        Some(&sig),
        guard.as_ref(),
        8000,
    );
    let fourth = fuzz_task(
        &plan,
        &other_endpoint,
        "q",
        Some(&sig),
        guard.as_ref(),
        8000,
    );
    assert_eq!(first.id, second.id);
    assert_ne!(first.id, third.id);
    assert_ne!(first.id, fourth.id);
    assert!(!format!("{:?}", first.id).contains("alice"));

    let contacts = rxscan::contact::ContactRegistry::new();
    let omitted = WebTarget::parse("http://127.0.0.1:80/search").unwrap();
    let empty = WebTarget::parse("http://127.0.0.1:80/search?q=").unwrap();
    assert!(contacts.claim(&omitted, rxscan::contact::RequestPurpose::FuzzMutation));
    assert!(!contacts.claim(&omitted, rxscan::contact::RequestPurpose::FuzzMutation));
    assert!(contacts.claim(&empty, rxscan::contact::RequestPurpose::FuzzMutation));
    assert!(contacts.claim(&omitted, rxscan::contact::RequestPurpose::ContentCandidate));
    assert!(contacts.claim(&one, rxscan::contact::RequestPurpose::BaselineSynthetic));
}

#[test]
fn per_origin_fuzz_budget_is_scan_lifetime_and_origin_scoped() {
    let plan = plan_for("5", "fuzz");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let engine = Phase7Engine::new(
        guard.clone(),
        plan.stable_id(),
        5,
        ScanGoal::Fuzz,
        plan.tcp_ports.clone(),
        SpeedSetting::Numeric(100),
    );
    let origin_a: Vec<_> = (0..(rxscan::fuzz::MAX_FUZZ_TASKS_PER_ORIGIN_HARD + 3))
        .map(|idx| WebTarget::parse(&format!("http://127.0.0.1:8080/a{idx}?q=alice")).unwrap())
        .collect();
    let origin_b = WebTarget::parse("http://127.0.0.1:8081/b?q=alice").unwrap();
    let https_same_host = WebTarget::parse("https://127.0.0.1:8080/s?q=alice").unwrap();
    let mut accepted_a = 0usize;
    for url in &origin_a {
        accepted_a += engine
            .follow_up_tasks(
                &baseline_task(&plan, url, guard.as_ref()),
                &baseline_output(&plan, url),
            )
            .len();
    }
    assert_eq!(accepted_a, rxscan::fuzz::MAX_FUZZ_TASKS_PER_ORIGIN_HARD);
    assert!(
        engine
            .follow_up_tasks(
                &baseline_task(&plan, &origin_a[0], guard.as_ref()),
                &baseline_output(&plan, &origin_a[0]),
            )
            .len()
            <= 1
    );
    assert_eq!(
        engine
            .follow_up_tasks(
                &baseline_task(&plan, &origin_b, guard.as_ref()),
                &baseline_output(&plan, &origin_b),
            )
            .len(),
        1
    );
    assert_eq!(
        engine
            .follow_up_tasks(
                &baseline_task(&plan, &https_same_host, guard.as_ref()),
                &baseline_output(&plan, &https_same_host),
            )
            .len(),
        1
    );

    if let Some(ipv6) = HttpFixture::spawn_ipv6(|_| response(200, "text/html", "v6")) {
        let v6_plan = ScanPlan::compile(
            Cli::try_parse_from([
                "rxscan", "::1", "--scope", "::1", "--level", "5", "--goal", "fuzz",
            ])
            .unwrap(),
        )
        .unwrap();
        let v6_guard = Arc::new(PolicyScopeGuard::new(v6_plan.scope.clone()));
        let v6_engine = Phase7Engine::new(
            v6_guard.clone(),
            v6_plan.stable_id(),
            5,
            ScanGoal::Fuzz,
            v6_plan.tcp_ports.clone(),
            SpeedSetting::Numeric(100),
        );
        let v6 = WebTarget::parse(&ipv6.url("/v?q=alice")).unwrap();
        assert_eq!(
            rxscan::fuzz::origin_key(&v6),
            format!("http://[::1]:{}/", ipv6.port)
        );
        assert_eq!(
            v6_engine
                .follow_up_tasks(
                    &baseline_task(&v6_plan, &v6, v6_guard.as_ref()),
                    &baseline_output(&v6_plan, &v6),
                )
                .len(),
            1
        );
    } else {
        eprintln!("skipping IPv6 origin budget coverage: ::1 bind unavailable in this runtime");
    }
}
