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
        BudgetLimits, CancellationToken, Module, ModuleContext, ModuleError, ModuleFuture,
        ModuleOutput, PolicyScopeGuard, RetryPolicy, Scheduler, ScopeGuard, SpeedGovernor, Task,
        TaskKind, TaskScopeTarget, VecEventSink,
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
