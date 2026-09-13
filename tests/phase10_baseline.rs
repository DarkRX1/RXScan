//! Phase 10 baseline web intelligence tests: local fixtures only.

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
    baseline::{
        BASELINE_MODULE_NAME, BaselineModule, BaselinePolicy, BaselineSimilarityRegistry,
        EndpointClass, OriginBaselineRegistry, SimilarityClass, Soft404Class, baseline_task_params,
        classify_endpoint, query_parameters, signature_for_response, similarity,
    },
    cli::Cli,
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
    port: u16,
    requests: Arc<std::sync::Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

struct DenyGuard;

impl ScopeGuard for DenyGuard {
    fn permits(&self, _target: &TaskScopeTarget) -> bool {
        false
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
            if context.is_cancelled() {
                return Err(ModuleError::Cancelled);
            }
            let provenance = Provenance::new(
                "phase10.test.http",
                "1.0.0",
                context.task.scan_plan_id.clone(),
                Timestamp(0),
            )
            .unwrap();
            let event = Event::new(
                EventKind::EndpointObserved,
                Some(AssetId(endpoint_asset_id(&root))),
                BoundedDetails::from_value(
                    serde_json::json!({"target": root.host, "url": root.canonical(), "status": 200}),
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

impl HttpFixture {
    fn spawn(responder: impl Fn(&FixtureRequest) -> Vec<u8> + Send + Sync + 'static) -> Self {
        Self::spawn_with_delay(Duration::ZERO, responder)
    }

    fn spawn_with_delay(
        delay: Duration,
        responder: impl Fn(&FixtureRequest) -> Vec<u8> + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind baseline fixture");
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
        Self {
            port,
            requests,
            stop,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
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

fn parsed_response(status: u16, content_type: &str, body: &str) -> rxscan::web::HttpResponse {
    rxscan::web::parse_response(&response(status, content_type, body), 1).unwrap()
}

fn plan_for(level: &str) -> ScanPlan {
    ScanPlan::compile(Cli::try_parse_from(["rxscan", "127.0.0.1", "--level", level]).unwrap())
        .unwrap()
}

fn provenance(plan: &ScanPlan) -> Provenance {
    Provenance::new("test", "10.0.0", plan.stable_id(), Timestamp(0)).unwrap()
}

fn baseline_task(plan: &ScanPlan, url: &str, timeout_ms: u64, guard: &dyn ScopeGuard) -> Task {
    let target = WebTarget::parse(url).unwrap();
    let endpoint = endpoint_asset_id(&target);
    Task::new_with_params(
        TaskKind::Baseline,
        None,
        Vec::new(),
        Some(AssetId(endpoint.clone())),
        plan.stable_id(),
        32,
        Duration::from_millis(timeout_ms),
        RetryPolicy::default(),
        BASELINE_MODULE_NAME,
        provenance(plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        baseline_task_params(&target, &endpoint, true),
        guard,
    )
    .unwrap()
}

fn http_seed_task(plan: &ScanPlan, url: &WebTarget, guard: &dyn ScopeGuard) -> Task {
    Task::new_with_params(
        TaskKind::HttpProbe,
        None,
        Vec::new(),
        Some(AssetId(endpoint_asset_id(url))),
        plan.stable_id(),
        45,
        Duration::from_secs(5),
        RetryPolicy::default(),
        "phase10.test.http",
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

fn block_on(module: &BaselineModule, context: ModuleContext) -> Result<ModuleOutput, ModuleError> {
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
fn signatures_similarity_and_classification_are_deterministic() {
    let a = parsed_response(200, "text/html", "<html><title>A</title>ID 12345</html>");
    let b = parsed_response(200, "text/html", "<html><title>A</title>ID 99999</html>");
    let c = parsed_response(200, "text/html", "<html><title>A</title>other words</html>");
    let sig_a = signature_for_response(&a, b"<html><title>A</title>ID 12345</html>");
    let sig_b = signature_for_response(&b, b"<html><title>A</title>ID 99999</html>");
    let sig_c = signature_for_response(&c, b"<html><title>A</title>other words</html>");
    assert_ne!(sig_a.raw_sha256, sig_b.raw_sha256);
    assert_eq!(similarity(&sig_a, &sig_b).0, SimilarityClass::NearDuplicate);
    assert_eq!(similarity(&sig_a, &sig_c).0, SimilarityClass::Different);
    let target = WebTarget::parse("http://127.0.0.1:80/api").unwrap();
    assert_eq!(
        classify_endpoint(
            &target,
            &parsed_response(200, "application/json", r#"{"ok":true}"#),
            br#"{"ok":true}"#,
            false
        ),
        EndpointClass::JsonResponse
    );
}

#[test]
fn soft404_wildcard_parameters_and_jsonl_are_observable() {
    let fixture = HttpFixture::spawn(|request| {
        if request.path.starts_with("/real") {
            response(
                200,
                "text/html",
                "<html><title>Missing</title>not found 12345</html>",
            )
        } else {
            response(
                200,
                "text/html",
                "<html><title>Missing</title>not found 99999</html>",
            )
        }
    });
    let plan = plan_for("5");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = BaselineModule::new(
        BaselinePolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let output = block_on(
        &module,
        ModuleContext::new(
            baseline_task(
                &plan,
                &fixture.url("/real?id=123&next=%2Fhome"),
                8000,
                guard.as_ref(),
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert_eq!(fixture.paths().len(), 3);
    assert!(output.events.iter().any(|event| {
        matches!(event.kind, EventKind::Soft404Observed)
            && event.details.data["classification"] == serde_json::json!(Soft404Class::SoftNotFound)
    }));
    assert!(
        output
            .events
            .iter()
            .any(|event| matches!(event.kind, EventKind::WildcardBehaviorObserved))
    );
    assert!(
        output
            .events
            .iter()
            .any(|event| matches!(event.kind, EventKind::ParameterObserved))
    );
    let mut bytes = Vec::new();
    {
        let mut writer = JsonlWriter::new(&mut bytes, 1024 * 1024);
        for event in &output.events {
            writer.write_event(event).unwrap();
        }
    }
    assert!(!bytes.is_empty());
}

#[test]
fn hard_404_redirect_and_scope_canary_behaviors_are_bounded() {
    let canary = HttpFixture::spawn(|_| response(200, "text/html", "canary"));
    let canary_port = canary.port;
    let fixture = HttpFixture::spawn(move |request| {
        if request.path.starts_with("/redir") {
            redirect(&format!("http://localhost:{canary_port}/outside"))
        } else {
            response(404, "text/html", "<html>missing</html>")
        }
    });
    let plan = plan_for("4");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = BaselineModule::new(
        BaselinePolicy::new(4, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let output = block_on(
        &module,
        ModuleContext::new(
            baseline_task(&plan, &fixture.url("/redir"), 8000, guard.as_ref()),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(canary.paths().is_empty());
    assert!(
        output
            .events
            .iter()
            .any(|event| matches!(event.kind, EventKind::EndpointClassified))
    );
    let hard = block_on(
        &module,
        ModuleContext::new(
            baseline_task(&plan, &fixture.url("/missing"), 8000, guard.as_ref()),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(hard.events.iter().any(|event| {
        matches!(event.kind, EventKind::Soft404Observed)
            && event.details.data["classification"] == serde_json::json!(Soft404Class::HardNotFound)
    }));
}

#[test]
fn decision_engine_proposes_baseline_for_confirmed_and_crawled_endpoints_once_per_origin() {
    let plan = plan_for("4");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let engine = Phase7Engine::new(
        guard.clone(),
        plan.stable_id(),
        4,
        ScanGoal::Recon,
        plan.tcp_ports.clone(),
        SpeedSetting::Numeric(100),
    );
    let one = WebTarget::parse("http://127.0.0.1:8080/a").unwrap();
    let two = WebTarget::parse("http://127.0.0.1:8080/b").unwrap();
    let event_for = |url: &WebTarget| {
        Event::new(
            EventKind::EndpointDiscovered,
            Some(AssetId(endpoint_asset_id(url))),
            BoundedDetails::from_value(
                serde_json::json!({"url": url.canonical(), "scope_permitted": true}),
                4096,
            )
            .unwrap(),
            provenance(&plan),
        )
        .unwrap()
    };
    let task = http_seed_task(&plan, &one, guard.as_ref());
    let proposals = engine.follow_up_tasks(
        &task,
        &ModuleOutput {
            events: vec![event_for(&one), event_for(&two)],
            evidence: Vec::new(),
            findings: Vec::new(),
            assets: Vec::new(),
        },
    );
    let baseline_tasks: Vec<_> = proposals
        .iter()
        .filter(|task| task.kind == TaskKind::Baseline)
        .collect();
    assert_eq!(baseline_tasks.len(), 2);
    assert_eq!(
        baseline_tasks
            .iter()
            .filter(|task| task
                .params
                .get("origin_baseline")
                .is_some_and(|value| value == "true"))
            .count(),
        1
    );
}

#[test]
fn origin_baseline_registry_is_reused_across_decision_batches() {
    let plan = plan_for("5");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let engine = Phase7Engine::new(
        guard.clone(),
        plan.stable_id(),
        5,
        ScanGoal::Recon,
        plan.tcp_ports.clone(),
        SpeedSetting::Numeric(100),
    );
    let first = WebTarget::parse("http://127.0.0.1:8080/a").unwrap();
    let second = WebTarget::parse("http://127.0.0.1:8080/b").unwrap();
    let output_for =
        |url: &WebTarget| ModuleOutput {
            events: vec![Event::new(
            EventKind::EndpointObserved,
            Some(AssetId(endpoint_asset_id(url))),
            BoundedDetails::from_value(
                serde_json::json!({"url": url.canonical(), "target": url.host, "status": 200}),
                4096,
            )
            .unwrap(),
            provenance(&plan),
        )
        .unwrap()],
            evidence: Vec::new(),
            findings: Vec::new(),
            assets: Vec::new(),
        };
    let seed_task = http_seed_task(&plan, &first, guard.as_ref());
    let first_proposals = engine.follow_up_tasks(&seed_task, &output_for(&first));
    assert!(first_proposals.iter().any(|task| {
        task.params
            .get("origin_baseline")
            .is_some_and(|value| value == "true")
    }));

    let baseline_output = ModuleOutput {
        events: vec![
            Event::new(
                EventKind::OriginBaselineObserved,
                Some(AssetId(endpoint_asset_id(&first))),
                BoundedDetails::from_value(
                    serde_json::json!({
                        "origin": rxscan::baseline::origin_root(&first).canonical(),
                        "normalized_sha256": ["hash-a", "hash-b"],
                        "samples": 2
                    }),
                    4096,
                )
                .unwrap(),
                provenance(&plan),
            )
            .unwrap(),
            Event::new(
                EventKind::BaselineCompleted,
                Some(AssetId(endpoint_asset_id(&first))),
                BoundedDetails::from_value(
                    serde_json::json!({"url": first.canonical(), "has_signature": true}),
                    4096,
                )
                .unwrap(),
                provenance(&plan),
            )
            .unwrap(),
        ],
        evidence: Vec::new(),
        findings: Vec::new(),
        assets: Vec::new(),
    };
    let first_baseline_task = first_proposals
        .iter()
        .find(|task| task.kind == TaskKind::Baseline)
        .unwrap();
    assert!(
        engine
            .follow_up_tasks(first_baseline_task, &baseline_output)
            .iter()
            .any(|task| task.kind == TaskKind::ContentDiscovery
                && task
                    .params
                    .get("baseline_normalized_sha256")
                    .is_some_and(|value| value == "hash-a,hash-b"))
    );

    let second_proposals = engine.follow_up_tasks(&seed_task, &output_for(&second));
    assert!(second_proposals.iter().any(
        |task| task.kind == TaskKind::Baseline && !task.params.contains_key("origin_baseline")
    ));

    let other_port = WebTarget::parse("http://127.0.0.1:8081/c").unwrap();
    let other_port_proposals = engine.follow_up_tasks(&seed_task, &output_for(&other_port));
    assert!(other_port_proposals.iter().any(|task| {
        task.params
            .get("origin_baseline")
            .is_some_and(|value| value == "true")
    }));

    let https_same_host = WebTarget::parse("https://127.0.0.1:8443/c").unwrap();
    let https_proposals = engine.follow_up_tasks(&seed_task, &output_for(&https_same_host));
    assert!(https_proposals.iter().any(|task| {
        task.params
            .get("origin_baseline")
            .is_some_and(|value| value == "true")
    }));

    let ipv6 = WebTarget::parse("http://[::1]:8080/a").unwrap();
    assert_eq!(
        rxscan::baseline::origin_root(&ipv6).canonical(),
        "http://[::1]:8080/"
    );
}

#[test]
fn baseline_module_emits_cross_task_duplicate_and_similarity_relationships() {
    let fixture = HttpFixture::spawn(|request| match request.path.as_str() {
        "/exact-a" | "/exact-b" => response(
            200,
            "text/html",
            "<html><title>Exact</title><main>same 12345</main></html>",
        ),
        "/near" => response(
            200,
            "text/html",
            "<html><title>Exact</title><main>same 99999</main></html>",
        ),
        "/template-a" => response(
            200,
            "text/html",
            &format!(
                "<html><title>Template</title><main>{}</main></html>",
                "a".repeat(400)
            ),
        ),
        "/template-b" => response(
            200,
            "text/html",
            &format!(
                "<html><title>Template</title><main>{}</main></html>",
                "b".repeat(400)
            ),
        ),
        "/different" => response(200, "application/json", r#"{"different":true}"#),
        _ => response(404, "text/html", "missing"),
    });
    let plan = plan_for("5");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let contacts = rxscan::contact::ContactRegistry::new();
    let similarity = BaselineSimilarityRegistry::new();
    let module = BaselineModule::with_shared_state(
        BaselinePolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
        contacts,
        similarity,
    );
    let run = |path: &str| {
        block_on(
            &module,
            ModuleContext::new(
                baseline_task(&plan, &fixture.url(path), 8000, guard.as_ref()),
                CancellationToken::default(),
            ),
        )
        .unwrap()
    };
    let _ = run("/exact-a");
    let exact = run("/exact-b");
    assert!(
        exact
            .events
            .iter()
            .any(|event| matches!(event.kind, EventKind::DuplicateObserved)
                && event.relationships.iter().any(|relationship| matches!(
                    relationship.kind,
                    rxscan::model::RelationshipKind::DuplicateOf
                )))
    );
    let near = run("/near");
    assert!(
        near.events
            .iter()
            .any(|event| matches!(event.kind, EventKind::DuplicateObserved))
    );
    let _ = run("/template-a");
    let template = run("/template-b");
    assert!(template.events.iter().any(|event| matches!(
        event.kind,
        EventKind::SimilarResponseObserved
    ) && event.relationships.iter().any(
        |relationship| matches!(
            relationship.kind,
            rxscan::model::RelationshipKind::SimilarTo
        )
    )));
    let different = run("/different");
    assert!(different.events.iter().all(|event| !matches!(
        event.kind,
        EventKind::DuplicateObserved | EventKind::SimilarResponseObserved
    )));

    let registry = OriginBaselineRegistry::new();
    registry.remember("http://127.0.0.1:80/".to_owned(), "x".to_owned());
    assert_eq!(
        registry.get_hashes("http://127.0.0.1:80/").as_deref(),
        Some("x")
    );
}

#[test]
fn cancellation_timeout_and_stale_scope_do_not_emit_discoveries() {
    let fixture = HttpFixture::spawn_with_delay(Duration::from_secs(2), |_| {
        response(200, "text/html", "<html>late</html>")
    });
    let plan = plan_for("3");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = BaselineModule::new(
        BaselinePolicy::new(3, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let cancel = CancellationToken::default();
    cancel.cancel();
    let cancelled = block_on(
        &module,
        ModuleContext::new(
            baseline_task(&plan, &fixture.url("/"), 1000, guard.as_ref()),
            cancel,
        ),
    );
    assert!(matches!(cancelled, Err(ModuleError::Cancelled)));
    let output = block_on(
        &module,
        ModuleContext::new(
            baseline_task(&plan, &fixture.url("/"), 700, guard.as_ref()),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(
        output
            .events
            .iter()
            .any(|event| matches!(event.kind, EventKind::BaselineCompleted))
    );
    assert!(
        output
            .events
            .iter()
            .all(|event| !matches!(event.kind, EventKind::ResponseSignatureObserved))
    );

    let denied_module = BaselineModule::new(
        BaselinePolicy::new(3, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        Arc::new(DenyGuard),
    );
    let stale = block_on(
        &denied_module,
        ModuleContext::new(
            baseline_task(&plan, &fixture.url("/"), 1000, guard.as_ref()),
            CancellationToken::default(),
        ),
    );
    assert!(matches!(
        stale,
        Err(ModuleError::Failed {
            retryable: false,
            ..
        })
    ));
}

#[test]
fn production_scheduler_admits_baseline_through_decision_engine_only() {
    let fixture = HttpFixture::spawn(|request| {
        if request.path.starts_with("/__rxscan_baseline_") {
            response(404, "text/html", "missing")
        } else {
            response(200, "text/html", "<html><title>Root</title>ok</html>")
        }
    });
    let plan = plan_for("4");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let root = WebTarget::parse(&fixture.url("/")).unwrap();
    let mut scheduler = Scheduler::new(
        32,
        BudgetLimits {
            max_concurrency: 1,
            max_tasks: 8,
            ..BudgetLimits::default()
        },
        SpeedGovernor::new(SpeedSetting::Numeric(100), 1).unwrap(),
        guard.clone(),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler.register_module(Arc::new(ConfirmedEndpointModule { root: root.clone() }));
    scheduler.register_module(Arc::new(BaselineModule::new(
        BaselinePolicy::new(4, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    )));
    scheduler.set_decision_engine(Arc::new(Phase7Engine::new(
        guard.clone(),
        plan.stable_id(),
        4,
        ScanGoal::Recon,
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
        "phase10.test.http",
        provenance(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([("url".to_owned(), root.canonical())]),
        guard.as_ref(),
    )
    .unwrap();
    scheduler.add_task(seed).unwrap();
    let report = scheduler.run().unwrap();
    assert_eq!(report.failed.len(), 0);
    assert_eq!(
        scheduler
            .tasks()
            .filter(|task| task.kind == TaskKind::Baseline)
            .count(),
        1
    );
    assert!(scheduler.module_outputs().iter().any(|(_, output)| {
        output
            .events
            .iter()
            .any(|event| matches!(event.kind, EventKind::ResponseSignatureObserved))
    }));
    assert_eq!(fixture.paths().len(), 3);
}

#[test]
fn parameter_inventory_classifies_shapes_without_retaining_secret_semantics() {
    let target = WebTarget::parse(
        "http://127.0.0.1:80/path?id=123&enabled=true&uuid=550e8400-e29b-41d4-a716-446655440000&next=https%3A%2F%2Fexample.test",
    )
    .unwrap();
    let params = query_parameters(&target);
    let classes: Vec<_> = params
        .iter()
        .map(|param| param.value_class.as_str())
        .collect();
    assert!(classes.contains(&"numeric"));
    assert!(classes.contains(&"boolean_like"));
    assert!(classes.contains(&"uuid_like"));
    assert!(classes.contains(&"url_like"));
}
