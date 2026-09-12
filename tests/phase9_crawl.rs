//! Phase 9 bounded crawler tests: controlled local fixtures only.

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{IpAddr, Ipv6Addr, TcpListener},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use clap::Parser;
use rxscan::{
    cli::Cli,
    crawl::{CRAWL_MODULE_NAME, CrawlModule, CrawlPolicy, crawl_task_params},
    decision::Phase7Engine,
    execution::{
        BudgetLimits, CancellationToken, DecisionEngine, Module, ModuleContext, ModuleError,
        ModuleOutput, PolicyScopeGuard, RetryPolicy, Scheduler, ScopeGuard, SpeedGovernor, Task,
        TaskKind, TaskScopeTarget, VecEventSink,
    },
    model::{AssetId, BoundedDetails, Event, EventKind, Provenance, Timestamp},
    plan::{ScanGoal, ScanPlan, SpeedSetting},
    web::{WebTarget, endpoint_asset_id},
};

#[derive(Debug, Clone)]
struct FixtureRequest {
    method: String,
    path: String,
    host: String,
}

struct HttpFixture {
    port: u16,
    requests: Arc<std::sync::Mutex<Vec<FixtureRequest>>>,
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
        Self::spawn_on("127.0.0.1:0", delay, responder).expect("bind delayed fixture")
    }

    fn try_spawn_ipv6(
        responder: impl Fn(&FixtureRequest) -> Vec<u8> + Send + Sync + 'static,
    ) -> std::io::Result<Self> {
        Self::spawn_on("[::1]:0", Duration::ZERO, responder)
    }

    fn spawn_on(
        bind: &str,
        delay: Duration,
        responder: impl Fn(&FixtureRequest) -> Vec<u8> + Send + Sync + 'static,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(bind)?;
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().unwrap().port();
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
                        std::thread::sleep(Duration::from_millis(5));
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
                    let head = String::from_utf8_lossy(&raw);
                    let mut parts = head.lines().next().unwrap_or("").split_whitespace();
                    let mut host = String::new();
                    for line in head.lines().skip(1) {
                        if line.is_empty() {
                            break;
                        }
                        if let Some((name, value)) = line.split_once(':') {
                            if name.trim().eq_ignore_ascii_case("host") {
                                host = value.trim().to_owned();
                            }
                        }
                    }
                    let request = FixtureRequest {
                        method: parts.next().unwrap_or("").to_owned(),
                        path: parts.next().unwrap_or("").to_owned(),
                        host,
                    };
                    requests.lock().unwrap().push(request.clone());
                    if !delay.is_zero() {
                        std::thread::sleep(delay);
                    }
                    let _ = stream.write_all(&responder(&request));
                });
            }
        });
        Ok(Self {
            port,
            requests,
            stop,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn paths(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.path.clone())
            .collect()
    }

    fn methods(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.method.clone())
            .collect()
    }

    fn hosts(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.host.clone())
            .collect()
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn response(content_type: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn plan_for(level: &str) -> ScanPlan {
    let cli = Cli::try_parse_from(["rxscan", "127.0.0.1", "--level", level]).unwrap();
    ScanPlan::compile(cli).unwrap()
}

fn plan_for_seed(seed: &str, level: &str) -> ScanPlan {
    let cli = Cli::try_parse_from(["rxscan", seed, "--level", level]).unwrap();
    ScanPlan::compile(cli).unwrap()
}

fn provenance(plan: &ScanPlan) -> Provenance {
    Provenance::new("test", "9.0.0", plan.stable_id(), Timestamp(0)).unwrap()
}

fn crawl_task(
    plan: &ScanPlan,
    url: &str,
    depth: u8,
    pages_left: u32,
    guard: &dyn ScopeGuard,
) -> Task {
    let target = WebTarget::parse(url).unwrap();
    let parent = endpoint_asset_id(&target);
    Task::new_with_params(
        TaskKind::Crawl,
        None,
        Vec::new(),
        Some(AssetId(parent.clone())),
        plan.stable_id(),
        40,
        Duration::from_millis(8000),
        RetryPolicy::default(),
        CRAWL_MODULE_NAME,
        provenance(plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        crawl_task_params(
            &target,
            &target,
            depth,
            pages_left,
            &parent,
            "127.0.0.1",
            true,
        ),
        guard,
    )
    .unwrap()
}

fn crawl_task_for_target(
    plan: &ScanPlan,
    url: &str,
    depth: u8,
    pages_left: u32,
    timeout_ms: u64,
    scope_target: TaskScopeTarget,
    guard: &dyn ScopeGuard,
) -> Task {
    let target = WebTarget::parse(url).unwrap();
    let parent = endpoint_asset_id(&target);
    Task::new_with_params(
        TaskKind::Crawl,
        None,
        Vec::new(),
        Some(AssetId(parent.clone())),
        plan.stable_id(),
        40,
        Duration::from_millis(timeout_ms),
        RetryPolicy::default(),
        CRAWL_MODULE_NAME,
        provenance(plan),
        scope_target,
        crawl_task_params(
            &target,
            &target,
            depth,
            pages_left,
            &parent,
            &target.host,
            true,
        ),
        guard,
    )
    .unwrap()
}

fn block_on(module: &CrawlModule, context: ModuleContext) -> Result<ModuleOutput, ModuleError> {
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

struct ConfirmedHttpModule {
    root: WebTarget,
}

impl Module for ConfirmedHttpModule {
    fn kind(&self) -> TaskKind {
        TaskKind::HttpProbe
    }

    fn execute(&self, context: ModuleContext) -> rxscan::execution::ModuleFuture {
        let root = self.root.clone();
        Box::pin(async move {
            if context.is_cancelled() {
                return Err(ModuleError::Cancelled);
            }
            let provenance = Provenance::new(
                "test.http",
                "9.0.0",
                context.task.scan_plan_id.clone(),
                Timestamp(0),
            )
            .unwrap();
            let asset = AssetId(endpoint_asset_id(&root));
            let event = Event::new(
                EventKind::EndpointObserved,
                Some(asset.clone()),
                BoundedDetails::from_value(
                    serde_json::json!({
                        "target": root.host,
                        "url": root.canonical(),
                        "status": 200,
                    }),
                    4096,
                )
                .unwrap(),
                provenance,
            )
            .unwrap();
            Ok(ModuleOutput {
                events: vec![event],
                evidence: Vec::new(),
                findings: Vec::new(),
                assets: Vec::new(),
            })
        })
    }
}

fn http_seed_task(plan: &ScanPlan, root: &WebTarget, guard: &dyn ScopeGuard) -> Task {
    Task::new_with_params(
        TaskKind::HttpProbe,
        None,
        Vec::new(),
        Some(AssetId(endpoint_asset_id(root))),
        plan.stable_id(),
        50,
        Duration::from_millis(1000),
        RetryPolicy::default(),
        "test.http",
        provenance(plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([("url".to_owned(), root.canonical())]),
        guard,
    )
    .unwrap()
}

fn scheduler_with_crawl(plan: &ScanPlan, guard: Arc<PolicyScopeGuard>) -> Scheduler {
    let budgets = BudgetLimits {
        max_concurrency: 1,
        ..BudgetLimits::default()
    };
    let governor = SpeedGovernor::new(SpeedSetting::Numeric(100), 1).unwrap();
    let mut scheduler = Scheduler::new(
        budgets.queue_capacity(),
        budgets,
        governor,
        guard.clone(),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler.register_module(Arc::new(CrawlModule::new(
        CrawlPolicy::new(plan.level, plan.goal, SpeedSetting::Numeric(100)),
        guard.clone(),
    )));
    scheduler.set_decision_engine(Arc::new(Phase7Engine::new(
        guard,
        plan.stable_id(),
        plan.level,
        plan.goal,
        plan.tcp_ports.clone(),
        SpeedSetting::Numeric(100),
    )));
    scheduler
}

#[test]
fn root_extracts_links_forms_scripts_robots_and_sitemaps_without_self_scheduling() {
    let fixture = HttpFixture::spawn(|request| match request.path.as_str() {
        "/" => response(
            "text/html",
            r#"<a href="/next?a=1#frag">n</a><a href="http://127.0.0.1:1/out">o</a>
               <form action="/login" method="post"><input name="user" type="text"></form>
               <script src="/app.js"></script><img src="/logo.png">"#,
        ),
        "/robots.txt" => response(
            "text/plain",
            "Allow: /public\nDisallow: /admin\nSitemap: /sitemap.xml\n",
        ),
        "/sitemap.xml" => response(
            "application/xml",
            r#"<urlset><url><loc>/listed?q=1</loc></url></urlset>"#,
        ),
        "/app.js" => response("application/javascript", r#"fetch("/api/v1/users");"#),
        _ => response("text/html", "ok"),
    });
    let plan = plan_for("4");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = CrawlModule::new(
        CrawlPolicy::new(4, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let output = block_on(
        &module,
        ModuleContext::new(
            crawl_task(&plan, &fixture.url("/"), 2, 8, guard.as_ref()),
            CancellationToken::default(),
        ),
    )
    .unwrap();

    let discovered: Vec<String> = output
        .events
        .iter()
        .filter(|event| matches!(event.kind, EventKind::EndpointDiscovered))
        .filter_map(|event| event.details.data.get("url")?.as_str().map(str::to_owned))
        .collect();
    assert!(discovered.iter().any(|url| url.ends_with("/next?a=1")));
    assert!(discovered.iter().any(|url| url.ends_with("/login")));
    assert!(discovered.iter().any(|url| url.ends_with("/app.js")));
    assert!(discovered.iter().any(|url| url.ends_with("/api/v1/users")));
    assert!(discovered.iter().any(|url| url.ends_with("/listed?q=1")));
    assert!(
        output
            .events
            .iter()
            .any(|event| matches!(event.kind, EventKind::FormObserved))
    );
    assert!(
        output
            .events
            .iter()
            .any(|event| matches!(event.kind, EventKind::RobotsObserved))
    );
    assert!(
        output
            .events
            .iter()
            .any(|event| matches!(event.kind, EventKind::SitemapObserved))
    );
    assert!(fixture.paths().contains(&"/app.js".to_owned()));
    assert!(!fixture.paths().contains(&"/login".to_owned()));
    assert!(fixture.methods().iter().all(|method| method == "GET"));
    assert!(
        output
            .events
            .iter()
            .all(|event| event.relationships.len() <= 1)
    );
}

#[test]
fn decision_engine_admits_crawl_roots_and_bounded_same_origin_followups() {
    let plan = plan_for("3");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let engine = Phase7Engine::new(
        guard.clone(),
        plan.stable_id(),
        3,
        ScanGoal::Recon,
        plan.tcp_ports.clone(),
        SpeedSetting::Numeric(100),
    );
    let root = WebTarget::parse("http://127.0.0.1:8080/").unwrap();
    let root_asset = AssetId(endpoint_asset_id(&root));
    let endpoint_event = Event::new(
        EventKind::EndpointObserved,
        Some(root_asset.clone()),
        BoundedDetails::from_value(
            serde_json::json!({"target": "127.0.0.1", "url": root.canonical(), "status": 200}),
            4096,
        )
        .unwrap(),
        provenance(&plan),
    )
    .unwrap();
    let http_task = Task::new_with_params(
        TaskKind::HttpProbe,
        None,
        Vec::new(),
        Some(root_asset.clone()),
        plan.stable_id(),
        50,
        Duration::from_millis(1000),
        RetryPolicy::default(),
        "rxscan.http",
        provenance(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([("url".to_owned(), root.canonical())]),
        guard.as_ref(),
    )
    .unwrap();
    let roots = engine.follow_up_tasks(
        &http_task,
        &ModuleOutput {
            events: vec![endpoint_event],
            evidence: Vec::new(),
            findings: Vec::new(),
            assets: Vec::new(),
        },
    );
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].kind, TaskKind::Crawl);
    assert_eq!(
        roots[0].params.get("is_root").map(String::as_str),
        Some("true")
    );

    let child = WebTarget::parse("http://127.0.0.1:8080/child#frag").unwrap();
    let off_origin = WebTarget::parse("http://127.0.0.1:8081/off").unwrap();
    let crawl_event = |url: &WebTarget| {
        Event::new(
            EventKind::EndpointDiscovered,
            Some(AssetId(endpoint_asset_id(url))),
            BoundedDetails::from_value(
                serde_json::json!({
                    "target": "127.0.0.1",
                    "url": url.canonical(),
                    "source": "link",
                    "parent_asset_id": root_asset.0,
                    "scope_permitted": true,
                    "crawl_eligible": true
                }),
                4096,
            )
            .unwrap(),
            provenance(&plan),
        )
        .unwrap()
    };
    let followups = engine.follow_up_tasks(
        &roots[0],
        &ModuleOutput {
            events: vec![crawl_event(&child), crawl_event(&off_origin)],
            evidence: Vec::new(),
            findings: Vec::new(),
            assets: Vec::new(),
        },
    );
    assert_eq!(followups.len(), 1);
    assert_eq!(
        followups[0].params.get("url").map(String::as_str),
        Some("http://127.0.0.1:8080/child")
    );
    assert_eq!(
        followups[0].params.get("depth").map(String::as_str),
        Some("1")
    );
}

#[test]
fn forms_are_not_submitted_and_out_of_scope_candidates_are_not_contacted() {
    let fixture = HttpFixture::spawn(move |_| {
        response(
            "text/html",
            r#"<form action="/login" method="post"><input name="p"></form>
               <a href="http://example.invalid/forbidden">x</a>"#,
        )
    });
    let plan = plan_for("3");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = CrawlModule::new(
        CrawlPolicy::new(3, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let output = block_on(
        &module,
        ModuleContext::new(
            crawl_task(&plan, &fixture.url("/"), 1, 2, guard.as_ref()),
            CancellationToken::default(),
        ),
    )
    .unwrap();

    assert!(!fixture.paths().contains(&"/login".to_owned()));
    assert!(output.events.iter().any(|event| {
        matches!(event.kind, EventKind::EndpointDiscovered)
            && event
                .details
                .data
                .get("scope_permitted")
                .and_then(serde_json::Value::as_bool)
                == Some(false)
    }));
}

#[test]
fn ipv6_crawler_fetches_and_records_relationship_when_loopback_ipv6_is_available() {
    let fixture = match HttpFixture::try_spawn_ipv6(|_| {
        response("text/html", r#"<a href="/v6-child?q=1#frag">v6</a>"#)
    }) {
        Ok(fixture) => fixture,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::AddrNotAvailable
                    | std::io::ErrorKind::PermissionDenied
                    | std::io::ErrorKind::Unsupported
            ) =>
        {
            eprintln!("skipping IPv6 crawler test: cannot bind [::1]:0 ({error})");
            return;
        }
        Err(error) => panic!("unexpected IPv6 bind failure: {error}"),
    };
    let plan = plan_for_seed("::1", "3");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = CrawlModule::new(
        CrawlPolicy::new(3, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let url = format!("http://[::1]:{}/", fixture.port);
    let target = WebTarget::parse(&url).unwrap();
    assert_eq!(
        target.canonical(),
        format!("http://[::1]:{}/", fixture.port)
    );
    let output = block_on(
        &module,
        ModuleContext::new(
            crawl_task_for_target(
                &plan,
                &url,
                1,
                2,
                8000,
                TaskScopeTarget::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                guard.as_ref(),
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert_eq!(
        fixture.paths(),
        vec!["/".to_owned(), "/robots.txt".to_owned()]
    );
    assert_eq!(fixture.hosts()[0], format!("[::1]:{}", fixture.port));
    let discovery = output
        .events
        .iter()
        .find(|event| {
            matches!(event.kind, EventKind::EndpointDiscovered)
                && event
                    .details
                    .data
                    .get("url")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|url| url.ends_with("/v6-child?q=1"))
        })
        .expect("IPv6 child discovery");
    assert!(discovery.details.data["scope_permitted"].as_bool().unwrap());
    assert!(
        discovery.relationships.iter().any(|relationship| matches!(
            relationship.kind,
            rxscan::model::RelationshipKind::LinksTo
        ))
    );
}

#[test]
fn cancellation_before_execution_makes_no_request_and_no_followups() {
    let fixture = HttpFixture::spawn(|_| response("text/html", r#"<a href="/never">x</a>"#));
    let plan = plan_for("3");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = CrawlModule::new(
        CrawlPolicy::new(3, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let cancel = CancellationToken::default();
    cancel.cancel();
    let result = block_on(
        &module,
        ModuleContext::new(
            crawl_task(&plan, &fixture.url("/"), 1, 2, guard.as_ref()),
            cancel,
        ),
    );
    assert!(matches!(result, Err(ModuleError::Cancelled)));
    assert!(fixture.paths().is_empty());

    let engine = Phase7Engine::new(
        guard,
        plan.stable_id(),
        3,
        ScanGoal::Recon,
        plan.tcp_ports.clone(),
        SpeedSetting::Numeric(100),
    );
    assert!(
        engine
            .follow_up_tasks(
                &crawl_task(
                    &plan,
                    &fixture.url("/"),
                    1,
                    2,
                    &PolicyScopeGuard::new(plan.scope.clone())
                ),
                &ModuleOutput {
                    events: Vec::new(),
                    evidence: Vec::new(),
                    findings: Vec::new(),
                    assets: Vec::new(),
                },
            )
            .is_empty()
    );
}

#[test]
fn cancellation_during_delayed_response_finishes_boundedly() {
    let fixture = HttpFixture::spawn_with_delay(Duration::from_secs(2), |_| {
        response("text/html", r#"<a href="/late">late</a>"#)
    });
    let plan = plan_for("3");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = CrawlModule::new(
        CrawlPolicy::new(3, ScanGoal::Recon, SpeedSetting::Numeric(1)),
        guard.clone(),
    );
    let task = crawl_task(&plan, &fixture.url("/"), 1, 2, guard.as_ref());
    let cancel = CancellationToken::default();
    let cancel_for_thread = cancel.clone();
    let started = Instant::now();
    let handle =
        std::thread::spawn(move || block_on(&module, ModuleContext::new(task, cancel_for_thread)));
    while fixture.paths().is_empty() && started.elapsed() < Duration::from_secs(1) {
        std::thread::sleep(Duration::from_millis(10));
    }
    cancel.cancel();
    let result = handle.join().expect("crawler thread");
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(
        matches!(result, Err(ModuleError::Cancelled))
            || result
                .unwrap()
                .events
                .iter()
                .all(|event| !matches!(event.kind, EventKind::EndpointDiscovered))
    );
}

#[test]
fn delayed_response_timeout_is_clean_and_proposes_no_followups() {
    let fixture = HttpFixture::spawn_with_delay(Duration::from_secs(2), |_| {
        response("text/html", r#"<a href="/late">late</a>"#)
    });
    let plan = plan_for("3");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = CrawlModule::new(
        CrawlPolicy::new(3, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let started = Instant::now();
    let output = block_on(
        &module,
        ModuleContext::new(
            crawl_task_for_target(
                &plan,
                &fixture.url("/"),
                1,
                2,
                700,
                TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
                guard.as_ref(),
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(fixture.paths().len(), 1);
    assert!(
        output
            .events
            .iter()
            .any(|event| matches!(event.kind, EventKind::CrawlCompleted))
    );
    assert!(
        output
            .events
            .iter()
            .all(|event| !matches!(event.kind, EventKind::EndpointDiscovered))
    );
    let engine = Phase7Engine::new(
        guard,
        plan.stable_id(),
        3,
        ScanGoal::Recon,
        plan.tcp_ports.clone(),
        SpeedSetting::Numeric(100),
    );
    let completed_task = crawl_task(
        &plan,
        &fixture.url("/"),
        1,
        2,
        &PolicyScopeGuard::new(plan.scope.clone()),
    );
    assert!(engine.follow_up_tasks(&completed_task, &output).is_empty());
}

#[test]
fn recursive_scheduler_path_fetches_second_page_dedups_cycle_and_honors_depth() {
    let fixture = HttpFixture::spawn(|request| match request.path.as_str() {
        "/" => response(
            "text/html",
            r##"<a href="/a#one">a</a><a href="/a#two">a2</a>"##,
        ),
        "/a" => response(
            "text/html",
            r##"<a href="/">root</a><a href="/a#again">self</a><a href="/b">too-deep</a>"##,
        ),
        _ => response("text/html", "unexpected"),
    });
    let plan = plan_for("2");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let root = WebTarget::parse(&fixture.url("/")).unwrap();
    let mut scheduler = scheduler_with_crawl(&plan, guard.clone());
    scheduler.register_module(Arc::new(ConfirmedHttpModule { root: root.clone() }));
    scheduler
        .add_task(http_seed_task(&plan, &root, guard.as_ref()))
        .unwrap();
    let report = scheduler.run().unwrap();
    assert!(report.failed.is_empty());
    assert_eq!(fixture.paths(), vec!["/".to_owned(), "/a".to_owned()]);
    let crawl_outputs: Vec<_> = scheduler
        .module_outputs()
        .into_iter()
        .filter(|(_, output)| {
            output
                .events
                .iter()
                .any(|event| matches!(event.kind, EventKind::CrawlStarted))
        })
        .collect();
    assert_eq!(crawl_outputs.len(), 2);
    assert_eq!(
        scheduler
            .tasks()
            .filter(|task| task.kind == TaskKind::Crawl)
            .count(),
        2
    );
}

#[test]
fn recursive_out_of_scope_candidate_is_recorded_but_not_admitted_or_contacted() {
    let canary = HttpFixture::spawn(|_| response("text/html", "canary"));
    let canary_port = canary.port;
    let fixture = HttpFixture::spawn(move |request| match request.path.as_str() {
        "/" => response("text/html", r#"<a href="/a">a</a>"#),
        "/a" => response(
            "text/html",
            &format!(r#"<a href="http://localhost:{canary_port}/forbidden">x</a>"#),
        ),
        _ => response("text/html", "unexpected"),
    });
    let plan = plan_for("2");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let root = WebTarget::parse(&fixture.url("/")).unwrap();
    let mut scheduler = scheduler_with_crawl(&plan, guard.clone());
    scheduler.register_module(Arc::new(ConfirmedHttpModule { root: root.clone() }));
    scheduler
        .add_task(http_seed_task(&plan, &root, guard.as_ref()))
        .unwrap();
    scheduler.run().unwrap();
    assert_eq!(fixture.paths(), vec!["/".to_owned(), "/a".to_owned()]);
    assert!(canary.paths().is_empty());
    let observed_denial = scheduler.module_outputs().iter().any(|(_, output)| {
        output.events.iter().any(|event| {
            matches!(event.kind, EventKind::EndpointDiscovered)
                && event
                    .details
                    .data
                    .get("scope_permitted")
                    .and_then(serde_json::Value::as_bool)
                    == Some(false)
                && !event.relationships.is_empty()
        })
    });
    assert!(observed_denial);
    assert_eq!(
        scheduler
            .tasks()
            .filter(|task| {
                task.kind == TaskKind::Crawl
                    && task
                        .params
                        .get("url")
                        .is_some_and(|url| url.contains("/forbidden"))
            })
            .count(),
        0
    );
}

#[test]
fn link_budget_exhaustion_emits_typed_event() {
    let fixture = HttpFixture::spawn(|_| {
        let links = (0..150)
            .map(|index| format!(r#"<a href="/p{index}">x</a>"#))
            .collect::<String>();
        response("text/html", &links)
    });
    let plan = plan_for("3");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = CrawlModule::new(
        CrawlPolicy::new(3, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let output = block_on(
        &module,
        ModuleContext::new(
            crawl_task(&plan, &fixture.url("/"), 1, 2, guard.as_ref()),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(output.events.iter().any(|event| {
        matches!(event.kind, EventKind::CrawlBudgetExhausted)
            && event
                .details
                .data
                .get("reason")
                .and_then(serde_json::Value::as_str)
                == Some("links-per-page-cap")
    }));
}
