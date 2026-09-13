use std::{
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
        BudgetLimits, Module, ModuleContext, ModuleError, ModuleFuture, ModuleOutput,
        PolicyScopeGuard, RetryPolicy, Scheduler, ScopeGuard, SpeedGovernor, Task, TaskKind,
        TaskScopeTarget, VecEventSink,
    },
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

fn fixture() -> (u16, Arc<AtomicBool>, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind phase10 bench fixture");
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
                let (content_type, body) = match path.as_str() {
                    "/" => (
                        "text/html",
                        "<html><title>Home</title>same body 10001</html>",
                    ),
                    "/copy" => (
                        "text/html",
                        "<html><title>Home</title>same body 10002</html>",
                    ),
                    "/template-a" => (
                        "text/html",
                        "<html><title>Item</title><main>Product 12345 available</main></html>",
                    ),
                    "/template-b" => (
                        "text/html",
                        "<html><title>Item</title><main>Product 67890 available</main></html>",
                    ),
                    "/unique" => (
                        "text/html",
                        "<html><title>Unique</title>different page</html>",
                    ),
                    "/data.json" => ("application/json", r#"{"ok":true,"id":12345}"#),
                    "/feed.xml" => ("application/xml", "<?xml version=\"1.0\"?><root/>"),
                    "/app.js" => ("application/javascript", "const path = \"/api/status\";"),
                    path if path.starts_with("/__rxscan_baseline_") => (
                        "text/html",
                        "<html><title>Missing</title>not found 99999</html>",
                    ),
                    _ => (
                        "text/html",
                        "<html><title>Fallback</title>not found 88888</html>",
                    ),
                };
                let _ = stream.write_all(&response(200, content_type, body));
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
            if context.is_cancelled() {
                return Err(ModuleError::Cancelled);
            }
            let provenance = Provenance::new(
                "phase10.bench.http",
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
    let plan_id = rxscan::model::ScanPlanId("phase10_bench".to_owned());
    Task::new_with_params(
        TaskKind::HttpProbe,
        None,
        Vec::new(),
        Some(AssetId(endpoint_asset_id(url))),
        plan_id.clone(),
        50,
        Duration::from_secs(5),
        RetryPolicy::default(),
        "phase10.bench.http",
        Provenance::new("phase10.bench", "1.0.0", plan_id, Timestamp(0)).unwrap(),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        std::collections::BTreeMap::from([("url".to_owned(), url.canonical())]),
        guard,
    )
    .unwrap()
}

fn main() {
    let (port, stop, requests) = fixture();
    let target = TargetSpec::parse("127.0.0.1").unwrap();
    let scope = ScopePolicy::from_targets(&[target], &[], &[]).unwrap();
    let guard = Arc::new(PolicyScopeGuard::new(scope));
    let paths = [
        "/",
        "/copy",
        "/template-a",
        "/template-b",
        "/unique",
        "/data.json",
        "/feed.xml",
        "/app.js",
    ];
    let endpoints = paths
        .iter()
        .map(|path| WebTarget::parse(&format!("http://127.0.0.1:{port}{path}")).unwrap())
        .collect::<Vec<_>>();

    let mut scheduler = Scheduler::new(
        128,
        BudgetLimits {
            max_concurrency: 1,
            max_tasks: 32,
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
    scheduler.register_module(Arc::new(BaselineModule::new(
        BaselinePolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    )));
    scheduler.set_decision_engine(Arc::new(Phase7Engine::new(
        guard.clone(),
        rxscan::model::ScanPlanId("phase10_bench".to_owned()),
        5,
        ScanGoal::Recon,
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
    let signatures = outputs
        .iter()
        .flat_map(|(_, output)| &output.events)
        .filter(|event| matches!(event.kind, EventKind::ResponseSignatureObserved))
        .count();
    let soft404 = outputs
        .iter()
        .flat_map(|(_, output)| &output.events)
        .filter(|event| matches!(event.kind, EventKind::Soft404Observed))
        .count();
    let classified = outputs
        .iter()
        .flat_map(|(_, output)| &output.events)
        .filter(|event| matches!(event.kind, EventKind::EndpointClassified))
        .count();
    let request_count = requests.lock().unwrap().len();
    stop.store(true, Ordering::SeqCst);

    println!("phase10_bench");
    println!("elapsed_ms={}", elapsed.as_millis());
    println!("completed_tasks={}", report.completed.len());
    println!("failed_tasks={}", report.failed.len());
    println!("network_requests={request_count}");
    println!("response_signatures={signatures}");
    println!("soft404_observations={soft404}");
    println!("endpoint_classifications={classified}");
    if elapsed.as_secs_f64() > 0.0 {
        println!(
            "signatures_per_second={:.2}",
            signatures as f64 / elapsed.as_secs_f64()
        );
    }
    println!("deterministic_fixture_paths={}", paths.len());
    println!("peak_rss_kb=not-collected");
}
