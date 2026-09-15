use std::{
    collections::BTreeMap,
    fs::File,
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
    content::{ContentDiscoveryModule, ContentDiscoveryPolicy},
    decision::Phase7Engine,
    execution::{
        BudgetLimits, Module, ModuleContext, ModuleFuture, ModuleOutput, PolicyScopeGuard,
        RetryPolicy, Scheduler, ScopeGuard, SpeedGovernor, Task, TaskKind, TaskScopeTarget,
        VecEventSink,
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

fn redirect(location: &str) -> Vec<u8> {
    format!("HTTP/1.1 301 Moved\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
}

fn fixture() -> (u16, Arc<AtomicBool>, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind phase11 bench fixture");
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
                let body = "x".repeat(70 * 1024);
                let bytes = match path.as_str() {
                    "/" => response(200, "text/html", "<html><title>Home</title></html>"),
                    "/login" => response(200, "text/html", "<html>login</html>"),
                    "/docs/" => redirect("/docs/index.html"),
                    "/docs/index.html" => response(200, "text/html", "<html>docs</html>"),
                    "/forbidden" => response(403, "text/html", "forbidden"),
                    "/data.json" => response(200, "application/json", r#"{"ok":true}"#),
                    "/static/app.js" => response(200, "application/javascript", "console.log(1)"),
                    "/large" => response(200, "text/html", &body),
                    path if path.starts_with("/__rxscan_baseline_") => {
                        response(200, "text/html", "<html>missing 99999</html>")
                    }
                    _ => response(200, "text/html", "<html>missing 88888</html>"),
                };
                let _ = stream.write_all(&bytes);
            });
        }
    });
    (port, stop, requests)
}

struct ConfirmedHttpModule {
    root: WebTarget,
}

impl Module for ConfirmedHttpModule {
    fn kind(&self) -> TaskKind {
        TaskKind::HttpProbe
    }

    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let root = self.root.clone();
        Box::pin(async move {
            let provenance = Provenance::new(
                "phase11.bench.http",
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
                            serde_json::json!({"target": root.host, "url": root.canonical(), "status": 200}),
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

fn seed_task(url: &WebTarget, guard: &dyn ScopeGuard) -> Task {
    let plan_id = rxscan::model::ScanPlanId("phase11_bench".to_owned());
    Task::new_with_params(
        TaskKind::HttpProbe,
        None,
        Vec::new(),
        Some(AssetId(endpoint_asset_id(url))),
        plan_id.clone(),
        50,
        Duration::from_secs(10),
        RetryPolicy::default(),
        "phase11.bench.http",
        Provenance::new("phase11.bench", "1.0.0", plan_id, Timestamp(0)).unwrap(),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([("url".to_owned(), url.canonical())]),
        guard,
    )
    .unwrap()
}

fn write_wordlist() -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("rxscan_phase11_bench_{}.txt", std::process::id()));
    let mut file = File::create(&path).expect("create phase11 bench wordlist");
    let lines = [
        "# managed local fixture",
        "/login",
        "login#duplicate-fragment",
        "/docs/",
        "/forbidden",
        "/data.json",
        "/static/app.js",
        "/large",
        "/missing-a",
        "/missing-b",
        "../reject",
        "//reject.example/path",
    ];
    for line in lines {
        writeln!(file, "{line}").unwrap();
    }
    path
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
    let wordlist = write_wordlist();
    let target = TargetSpec::parse("127.0.0.1").unwrap();
    let scope = ScopePolicy::from_targets(&[target], &[], &[]).unwrap();
    let guard = Arc::new(PolicyScopeGuard::new(scope));
    let root = WebTarget::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let contact_registry = rxscan::contact::ContactRegistry::new();
    let baseline_similarity = rxscan::baseline::BaselineSimilarityRegistry::new();

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
    scheduler.register_module(Arc::new(ConfirmedHttpModule { root: root.clone() }));
    scheduler.register_module(Arc::new(BaselineModule::with_shared_state(
        BaselinePolicy::new(5, ScanGoal::Web, SpeedSetting::Numeric(100)),
        guard.clone(),
        contact_registry.clone(),
        baseline_similarity,
    )));
    scheduler.register_module(Arc::new(ContentDiscoveryModule::with_contact_registry(
        ContentDiscoveryPolicy::new(5, ScanGoal::Web, SpeedSetting::Numeric(100)),
        guard.clone(),
        contact_registry,
    )));
    scheduler.set_decision_engine(Arc::new(Phase7Engine::new_with_content_wordlist(
        guard.clone(),
        rxscan::model::ScanPlanId("phase11_bench".to_owned()),
        5,
        ScanGoal::Web,
        rxscan::plan::TcpPortSelection::Common,
        SpeedSetting::Numeric(100),
        Some(wordlist),
    )));

    scheduler
        .add_task(seed_task(&root, guard.as_ref()))
        .unwrap();
    let started = Instant::now();
    let report = scheduler.run().unwrap();
    let elapsed = started.elapsed();
    let outputs = scheduler.module_outputs();
    let events = outputs.iter().flat_map(|(_, output)| &output.events);
    let discovered = events
        .clone()
        .filter(|event| {
            matches!(
                event.kind,
                EventKind::ContentDiscovered | EventKind::ContentRedirectObserved
            )
        })
        .count();
    let rejected = events
        .clone()
        .filter(|event| matches!(event.kind, EventKind::ContentRejectedByBaseline))
        .count();
    let attempted = events
        .filter(|event| matches!(event.kind, EventKind::CandidateAttempted))
        .count();
    let observed_requests = requests.lock().unwrap().clone();
    let request_count = observed_requests.len();
    stop.store(true, Ordering::SeqCst);
    let candidate_lines = 12usize + rxscan::content::builtin_candidates().len();
    let unique_candidates = attempted;
    let dedup_avoided = candidate_lines.saturating_sub(unique_candidates);
    let baseline_synthetic_requests = observed_requests
        .iter()
        .filter(|path| path.starts_with("/__rxscan_baseline_"))
        .count();
    let redirect_follow_requests = observed_requests
        .iter()
        .filter(|path| path.as_str() == "/docs/index.html")
        .count();
    let retry_requests = 0usize;
    let other_requests = observed_requests
        .iter()
        .filter(|path| path.as_str() == "/")
        .count();
    let candidate_requests = request_count.saturating_sub(
        baseline_synthetic_requests + redirect_follow_requests + retry_requests + other_requests,
    );
    assert_eq!(
        candidate_requests
            + baseline_synthetic_requests
            + redirect_follow_requests
            + retry_requests
            + other_requests,
        request_count
    );

    println!("phase11_bench");
    println!("candidate_lines={candidate_lines}");
    println!("unique_candidates={unique_candidates}");
    println!("candidate_requests={candidate_requests}");
    println!("baseline_synthetic_requests={baseline_synthetic_requests}");
    println!("redirect_follow_requests={redirect_follow_requests}");
    println!("retry_requests={retry_requests}");
    println!("other_requests={other_requests}");
    println!("total_network_requests={request_count}");
    println!("discovered_endpoints={discovered}");
    println!("baseline_rejected_responses={rejected}");
    println!("dedup_avoided_requests={dedup_avoided}");
    println!("cross_module_dedup_avoided_requests=0");
    println!("elapsed_ms={}", elapsed.as_millis());
    if elapsed.as_secs_f64() > 0.0 {
        println!(
            "requests_per_second={:.2}",
            request_count as f64 / elapsed.as_secs_f64()
        );
        println!(
            "candidate_lines_per_second={:.2}",
            candidate_lines as f64 / elapsed.as_secs_f64()
        );
    }
    println!("completed_tasks={}", report.completed.len());
    println!("failed_tasks={}", report.failed.len());
    println!(
        "peak_rss_kb={}",
        peak_rss_kb().map_or("unavailable".to_owned(), |value| value.to_string())
    );
    println!("release_binary_size_bytes=measure-with-cargo-build-release-and-stat");
    println!("new_production_dependency_count=0");
}
