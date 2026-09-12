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
    crawl::{CrawlModule, CrawlPolicy},
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

fn response(content_type: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn fixture() -> (u16, Arc<AtomicBool>, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind phase9 bench fixture");
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
                let body = match path.as_str() {
                    "/" => r##"<a href="/a#one">a</a><a href="/a#two">dup</a><a href="/b?q=1">b</a><script src="/app.js"></script><form action="/login"><input name="q"></form>"##.to_owned(),
                    "/a" => r##"<a href="/">cycle</a><a href="/c">c</a>"##.to_owned(),
                    "/b?q=1" => r##"<a href="/c#frag">c</a>"##.to_owned(),
                    "/c" => r##"<a href="/a">cycle</a>"##.to_owned(),
                    "/app.js" => r#"const api = "/api/v1/items";"#.to_owned(),
                    "/robots.txt" => "Allow: /public\nSitemap: /sitemap.xml\n".to_owned(),
                    "/sitemap.xml" => r#"<urlset><url><loc>/listed</loc></url></urlset>"#.to_owned(),
                    _ => "ok".to_owned(),
                };
                let content_type = if path.ends_with(".js") {
                    "application/javascript"
                } else if path.ends_with(".xml") {
                    "application/xml"
                } else if path.ends_with(".txt") {
                    "text/plain"
                } else {
                    "text/html"
                };
                let _ = stream.write_all(&response(content_type, &body));
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
            if context.is_cancelled() {
                return Err(ModuleError::Cancelled);
            }
            let provenance = Provenance::new(
                "phase9.bench.http",
                "1.0.0",
                context.task.scan_plan_id.clone(),
                Timestamp(0),
            )
            .unwrap();
            let event = Event::new(
                EventKind::EndpointObserved,
                Some(AssetId(endpoint_asset_id(&root))),
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

fn seed_task(url: &WebTarget, guard: &dyn ScopeGuard) -> Task {
    let plan_id = rxscan::model::ScanPlanId("phase9_bench".to_owned());
    Task::new_with_params(
        TaskKind::HttpProbe,
        None,
        Vec::new(),
        Some(AssetId(endpoint_asset_id(url))),
        plan_id.clone(),
        50,
        Duration::from_secs(5),
        RetryPolicy::default(),
        "phase9.bench.http",
        Provenance::new("phase9.bench", "1.0.0", plan_id, Timestamp(0)).unwrap(),
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
    let root = WebTarget::parse(&format!("http://127.0.0.1:{port}/")).unwrap();

    let budgets = BudgetLimits {
        max_concurrency: 1,
        max_tasks: 64,
        ..BudgetLimits::default()
    };
    budgets.validate().unwrap();
    let governor = SpeedGovernor::new(SpeedSetting::Numeric(100), 1).unwrap();
    let mut scheduler = Scheduler::new(
        budgets.queue_capacity(),
        budgets,
        governor,
        guard.clone(),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler.register_module(Arc::new(ConfirmedHttpModule { root: root.clone() }));
    scheduler.register_module(Arc::new(CrawlModule::new(
        CrawlPolicy::new(4, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    )));
    scheduler.set_decision_engine(Arc::new(Phase7Engine::new(
        guard.clone(),
        rxscan::model::ScanPlanId("phase9_bench".to_owned()),
        4,
        ScanGoal::Recon,
        rxscan::plan::TcpPortSelection::Common,
        SpeedSetting::Numeric(100),
    )));
    scheduler
        .add_task(seed_task(&root, guard.as_ref()))
        .unwrap();

    let started = Instant::now();
    let report = scheduler.run().expect("crawl benchmark");
    let elapsed = started.elapsed();
    stop.store(true, Ordering::SeqCst);

    let outputs = scheduler.module_outputs();
    let discoveries = outputs
        .iter()
        .flat_map(|(_, output)| output.events.iter())
        .filter(|event| matches!(event.kind, EventKind::EndpointDiscovered))
        .count();
    let crawl_tasks = scheduler
        .tasks()
        .filter(|task| task.kind == TaskKind::Crawl)
        .count();
    let paths = requests.lock().unwrap().clone();
    let mut unique = paths.clone();
    unique.sort();
    unique.dedup();
    println!("phase9_crawl_bench");
    println!("elapsed_ms={}", elapsed.as_millis());
    println!("crawl_tasks={crawl_tasks}");
    println!("discoveries={discoveries}");
    println!("requests_made={}", paths.len());
    println!("unique_paths={}", unique.len());
    println!("paths={}", paths.join(","));
    println!(
        "completed={} failed={} cancelled={} timed_out={}",
        report.completed.len(),
        report.failed.len(),
        report.cancelled.len(),
        report.timed_out.len()
    );
}
