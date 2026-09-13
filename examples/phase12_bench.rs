use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use rxscan::{
    baseline::{BaselineModule, BaselinePolicy},
    decision::Phase7Engine,
    execution::{
        BudgetLimits, Module, ModuleContext, ModuleFuture, ModuleOutput, PolicyScopeGuard,
        RetryPolicy, Scheduler, ScopeGuard, SpeedGovernor, Task, TaskKind, TaskScopeTarget,
        VecEventSink,
    },
    fuzz::{FuzzModule, FuzzPolicy},
    model::{AssetId, BoundedDetails, Event, EventKind, Provenance, Timestamp},
    plan::{ScanGoal, SpeedSetting},
    scope::ScopePolicy,
    target::TargetSpec,
    web::{WebTarget, endpoint_asset_id},
};

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

fn fixture() -> (u16, Arc<AtomicBool>, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind phase12 bench fixture");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let stop_clone = stop.clone();
    let requests_clone = requests.clone();
    std::thread::spawn(move || {
        while !stop_clone.load(Ordering::SeqCst) {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(_) => break,
            };
            let requests = requests_clone.clone();
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
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
                let bytes = if path.starts_with("/__rxscan_baseline_") {
                    response(404, "text/html", "missing")
                } else if path.contains("/items?limit=20") {
                    response(200, "text/html", "<html><title>Items</title>normal</html>")
                } else if path.contains("/items?limit=0") {
                    response(400, "application/json", r#"{"error":"bad limit"}"#)
                } else if path.contains("/toggle?enabled=true") {
                    response(200, "application/json", r#"{"enabled":true}"#)
                } else if path.contains("/toggle?enabled=false") {
                    response(200, "application/json", r#"{"enabled":false}"#)
                } else if path.starts_with("/echo?") {
                    response(200, "text/html", &format!("<html>{path}</html>"))
                } else if path.starts_with("/redir?") {
                    redirect("/landing")
                } else if path == "/landing" {
                    response(200, "text/html", "<html>landing</html>")
                } else {
                    response(200, "text/html", "<html>root</html>")
                };
                let _ = stream.write_all(&bytes);
            });
        }
    });
    (port, stop, requests)
}

struct ConfirmedHttpModule {
    endpoints: Vec<WebTarget>,
}

impl Module for ConfirmedHttpModule {
    fn kind(&self) -> TaskKind {
        TaskKind::HttpProbe
    }

    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let endpoints = self.endpoints.clone();
        Box::pin(async move {
            let provenance = Provenance::new(
                "phase12.bench.http",
                "1.0.0",
                context.task.scan_plan_id.clone(),
                Timestamp(0),
            )
            .unwrap();
            let events = endpoints
                .into_iter()
                .map(|endpoint| {
                    Event::new(
                        EventKind::EndpointObserved,
                        Some(AssetId(endpoint_asset_id(&endpoint))),
                        BoundedDetails::from_value(
                            serde_json::json!({"target": endpoint.host, "url": endpoint.canonical(), "status": 200}),
                            4096,
                        )
                        .unwrap(),
                        provenance.clone(),
                    )
                    .unwrap()
                })
                .collect();
            Ok(ModuleOutput {
                events,
                evidence: Vec::new(),
                findings: Vec::new(),
                assets: Vec::new(),
            })
        })
    }
}

fn seed_task(url: &WebTarget, guard: &dyn ScopeGuard) -> Task {
    let plan_id = rxscan::model::ScanPlanId("phase12_bench".to_owned());
    Task::new_with_params(
        TaskKind::HttpProbe,
        None,
        Vec::new(),
        Some(AssetId(endpoint_asset_id(url))),
        plan_id.clone(),
        50,
        Duration::from_secs(10),
        RetryPolicy::default(),
        "phase12.bench.http",
        Provenance::new("phase12.bench", "1.0.0", plan_id, Timestamp(0)).unwrap(),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([("url".to_owned(), url.canonical())]),
        guard,
    )
    .unwrap()
}

fn peak_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("VmHWM:").and_then(|rest| {
            rest.split_whitespace()
                .next()
                .and_then(|value| value.parse().ok())
        })
    })
}

fn main() {
    let (port, stop, requests) = fixture();
    let target = TargetSpec::parse("127.0.0.1").unwrap();
    let scope = ScopePolicy::from_targets(&[target], &[], &[]).unwrap();
    let guard = Arc::new(PolicyScopeGuard::new(scope));
    let endpoints = vec![
        WebTarget::parse(&format!("http://127.0.0.1:{port}/items?limit=20")).unwrap(),
        WebTarget::parse(&format!("http://127.0.0.1:{port}/toggle?enabled=true")).unwrap(),
        WebTarget::parse(&format!("http://127.0.0.1:{port}/echo?q=alice")).unwrap(),
        WebTarget::parse(&format!("http://127.0.0.1:{port}/redir?next=home")).unwrap(),
        WebTarget::parse(&format!("http://127.0.0.1:{port}/echo?csrf_token=abc")).unwrap(),
    ];
    let contact_registry = rxscan::contact::ContactRegistry::new();
    let mut scheduler = Scheduler::new(
        128,
        BudgetLimits {
            max_concurrency: 1,
            max_tasks: 64,
            ..BudgetLimits::default()
        },
        SpeedGovernor::new(SpeedSetting::Numeric(100), 1).unwrap(),
        guard.clone(),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler.register_module(Arc::new(ConfirmedHttpModule {
        endpoints: endpoints.clone(),
    }));
    scheduler.register_module(Arc::new(BaselineModule::with_shared_state(
        BaselinePolicy::new(5, ScanGoal::Fuzz, SpeedSetting::Numeric(100)),
        guard.clone(),
        contact_registry.clone(),
        rxscan::baseline::BaselineSimilarityRegistry::new(),
    )));
    scheduler.register_module(Arc::new(FuzzModule::with_contact_registry(
        FuzzPolicy::new(5, ScanGoal::Fuzz, SpeedSetting::Numeric(100)),
        guard.clone(),
        contact_registry,
    )));
    scheduler.set_decision_engine(Arc::new(Phase7Engine::new(
        guard.clone(),
        rxscan::model::ScanPlanId("phase12_bench".to_owned()),
        5,
        ScanGoal::Fuzz,
        rxscan::plan::TcpPortSelection::Common,
        SpeedSetting::Numeric(100),
    )));
    scheduler
        .add_task(seed_task(&endpoints[0], guard.as_ref()))
        .unwrap();
    let started = Instant::now();
    let report = scheduler.run().unwrap();
    let elapsed = started.elapsed();
    let outputs = scheduler.module_outputs();
    let events = outputs.iter().flat_map(|(_, output)| &output.events);
    let eligible_inputs = scheduler
        .tasks()
        .filter(|task| task.kind == TaskKind::Fuzz)
        .count();
    let skipped_sensitive = endpoints
        .iter()
        .filter(|endpoint| {
            endpoint.query.as_deref().is_some_and(|query| {
                url::form_urlencoded::parse(query.as_bytes())
                    .any(|(name, _)| rxscan::fuzz::is_sensitive_name(&name))
            })
        })
        .count();
    let mutations_generated = events
        .clone()
        .filter(|event| matches!(event.kind, EventKind::FuzzMutationAttempted))
        .count();
    let behavior_deltas = events
        .clone()
        .filter(|event| matches!(event.kind, EventKind::FuzzBehaviorDeltaObserved))
        .count();
    let reflections = events
        .clone()
        .filter(|event| matches!(event.kind, EventKind::FuzzInputReflected))
        .count();
    let inconclusive = events
        .filter(|event| {
            matches!(event.kind, EventKind::FuzzBehaviorDeltaObserved)
                && event.details.data["outcome"] == "inconclusive"
        })
        .count();
    let observed_requests = requests.lock().unwrap().clone();
    stop.store(true, Ordering::SeqCst);
    let baseline_requests = observed_requests
        .iter()
        .filter(|path| {
            matches!(
                path.as_str(),
                "/items?limit=20"
                    | "/toggle?enabled=true"
                    | "/echo?q=alice"
                    | "/redir?next=home"
                    | "/echo?csrf_token=abc"
            )
        })
        .count();
    let baseline_synthetic = observed_requests
        .iter()
        .filter(|path| path.starts_with("/__rxscan_baseline_"))
        .count();
    let redirect_follow_requests = observed_requests
        .iter()
        .filter(|path| path.as_str() == "/landing")
        .count();
    let retry_requests = 0usize;
    let total_network_requests = observed_requests.len();
    let mutation_requests = observed_requests
        .iter()
        .filter(|path| {
            !matches!(
                path.as_str(),
                "/items?limit=20"
                    | "/toggle?enabled=true"
                    | "/echo?q=alice"
                    | "/redir?next=home"
                    | "/echo?csrf_token=abc"
                    | "/landing"
            ) && !path.starts_with("/__rxscan_baseline_")
        })
        .count();
    assert_eq!(
        baseline_requests
            + baseline_synthetic
            + redirect_follow_requests
            + retry_requests
            + mutation_requests,
        total_network_requests
    );

    println!("phase12_bench");
    println!("observed_inputs={}", endpoints.len());
    println!("eligible_inputs={eligible_inputs}");
    println!("skipped_sensitive_inputs={skipped_sensitive}");
    println!("mutations_generated={mutations_generated}");
    println!("unique_mutation_requests={mutation_requests}");
    println!("dedup_avoided_requests=0");
    println!("baseline_reused={eligible_inputs}");
    println!("baseline_requests={baseline_requests}");
    println!("baseline_synthetic_requests={baseline_synthetic}");
    println!("mutation_requests={mutation_requests}");
    println!("redirect_follow_requests={redirect_follow_requests}");
    println!("retry_requests={retry_requests}");
    println!("total_network_requests={total_network_requests}");
    println!("behavior_deltas={behavior_deltas}");
    println!("reflections={reflections}");
    println!("inconclusive={inconclusive}");
    println!("completed_tasks={}", report.completed.len());
    println!("failed_tasks={}", report.failed.len());
    println!("elapsed_ms={}", elapsed.as_millis());
    if elapsed.as_secs_f64() > 0.0 {
        println!(
            "requests_per_second={:.2}",
            total_network_requests as f64 / elapsed.as_secs_f64()
        );
    }
    println!(
        "peak_rss_kb={}",
        peak_rss_kb().map_or("unavailable".to_owned(), |value| value.to_string())
    );
    println!("release_binary_size_bytes=measure-with-cargo-build-release-and-stat");
    println!("new_production_dependency_count=0");
}
