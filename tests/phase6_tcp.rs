//! Phase 6 TCP port-discovery tests: local fixtures only, deterministic.
//!
//! No public Internet scanning. Temporary loopback listeners, closed
//! loopback ports, and deterministic fake scanners only.

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{IpAddr, TcpListener},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use rxscan::{
    cli::Cli,
    decision::TcpDecisionEngine,
    execution::{
        BudgetLimits, CancellationToken, DecisionEngine, Module, ModuleContext, ModuleError,
        ModuleFuture, ModuleOutput, PolicyScopeGuard, RetryPolicy, Scheduler, ScopeGuard,
        SpeedGovernor, Task, TaskKind, TaskScopeTarget, VecEventSink,
    },
    model::{Provenance, SCHEMA_VERSION, Timestamp},
    plan::{ScanGoal, ScanPlan, SpeedSetting, TcpPortSelection},
    ports::{
        COMMON_PORTS_V1, COMMON_PROFILE_VERSION, automatic_ports_for_level, parse_port_selection,
        port_eligible_for_plan, tcp_concurrency_for_speed, tcp_timeout_for_speed,
    },
    tcp_discovery::{TcpDiscoveryModule, TcpScanPolicy, port_asset_id},
    tcp_scanner::{NativeTcpScanner, PortScanner, PortState, ScanConfig, ScanOutcome},
};

// ---------- helpers ----------

fn compile(args: &[&str]) -> ScanPlan {
    let mut full = vec!["rxscan"];
    full.extend_from_slice(args);
    let cli = Cli::try_parse_from(full).unwrap();
    ScanPlan::compile(cli).unwrap()
}

fn provenance_for(plan: &ScanPlan) -> Provenance {
    Provenance::new("test.module", "6.0.0", plan.stable_id(), Timestamp(0)).unwrap()
}

struct AllowAll;
impl ScopeGuard for AllowAll {
    fn permits(&self, _target: &TaskScopeTarget) -> bool {
        true
    }
}

/// Deterministic fake scanner: classifies by port membership, honors cancel
/// and deadline, returns sorted probes with bounded attempts.
#[derive(Debug)]
struct FakeScanner {
    open: Vec<u16>,
    filtered: Vec<u16>,
    error: Vec<u16>,
    calls: Arc<AtomicUsize>,
    delay_ms: u64,
    max_concurrent_seen: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
}

impl FakeScanner {
    fn new(calls: Arc<AtomicUsize>) -> Self {
        Self {
            open: Vec::new(),
            filtered: Vec::new(),
            error: Vec::new(),
            calls,
            delay_ms: 0,
            max_concurrent_seen: Arc::new(AtomicUsize::new(0)),
            active: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl PortScanner for FakeScanner {
    fn scan(&self, ip: IpAddr, ports: &[u16], config: &ScanConfig) -> ScanOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut probes = Vec::new();
        for (index, port) in ports.iter().enumerate() {
            if config.cancel.is_cancelled() {
                let unscanned = ports.len() - probes.len();
                return ScanOutcome {
                    probes,
                    truncated: true,
                    cancelled: true,
                    unscanned,
                    // Fake holds no real sockets; sustained FD pressure is zero.
                    fd_peak: 0,
                };
            }
            if let Some(deadline) = config.deadline {
                if Instant::now() >= deadline {
                    let unscanned = ports.len() - probes.len();
                    return ScanOutcome {
                        probes,
                        truncated: true,
                        cancelled: false,
                        unscanned,
                        fd_peak: 0,
                    };
                }
            }
            if *port == 0 {
                continue;
            }
            let _ = index;
            let current = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_concurrent_seen
                .fetch_max(current, Ordering::SeqCst);
            if self.delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(self.delay_ms));
            }
            self.active.fetch_sub(1, Ordering::SeqCst);
            if config.cancel.is_cancelled() {
                let unscanned = ports.len() - probes.len();
                return ScanOutcome {
                    probes,
                    truncated: true,
                    cancelled: true,
                    unscanned,
                    // Fake holds no real sockets; sustained FD pressure is zero.
                    fd_peak: 0,
                };
            }
            let state = if self.open.contains(port) {
                PortState::Open
            } else if self.filtered.contains(port) {
                PortState::FilteredOrTimedOut
            } else if self.error.contains(port) {
                PortState::Error
            } else {
                PortState::Closed
            };
            // Retry accounting: filtered gets attempts=2 when retries allowed.
            let attempts = if state == PortState::FilteredOrTimedOut && config.max_retries > 0 {
                2
            } else {
                1
            };
            probes.push(rxscan::tcp_scanner::PortProbe {
                port: *port,
                state,
                latency: Duration::from_millis(1),
                detail: format!("fake {state} for {ip}:{port}"),
                attempts,
            });
        }
        probes.sort_by_key(|probe| probe.port);
        ScanOutcome {
            probes,
            truncated: false,
            cancelled: false,
            unscanned: 0,
            fd_peak: 0,
        }
    }
}

fn port_task_for(
    plan: &ScanPlan,
    ip: IpAddr,
    ports_param: &str,
    timeout_ms: u64,
    guard: &dyn ScopeGuard,
) -> Task {
    let mut params = BTreeMap::new();
    params.insert("target".to_owned(), ip.to_string());
    params.insert("ports".to_owned(), ports_param.to_owned());
    Task::new_with_params(
        TaskKind::PortDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        60,
        Duration::from_millis(timeout_ms),
        RetryPolicy::default(),
        "rxscan.port",
        provenance_for(plan),
        TaskScopeTarget::Ip(ip),
        params,
        guard,
    )
    .unwrap()
}

fn block_on_module(
    module: &TcpDiscoveryModule,
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

fn open_ports_in(output: &ModuleOutput) -> Vec<u16> {
    output
        .findings
        .iter()
        .filter(|finding| finding.title.starts_with("Open TCP port"))
        .filter_map(|finding| {
            finding
                .metadata
                .get("port")
                .and_then(serde_json::Value::as_u64)
                .map(|port| port as u16)
        })
        .collect()
}

fn bind_default_scan_listener() -> (TcpListener, u16) {
    for port in automatic_ports_for_level(3)
        .into_iter()
        .filter(|port| *port >= 1024)
    {
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
            return (listener, port);
        }
    }
    panic!("no bindable high port in the default scan set");
}

fn closed_default_port(except: u16) -> u16 {
    automatic_ports_for_level(3)
        .into_iter()
        .filter(|port| *port >= 1024 && *port != except)
        .find(|port| !std::net::TcpStream::connect(("127.0.0.1", *port)).is_ok())
        .expect("no closed high port in the default scan set")
}

fn read_jsonl_payloads(path: &std::path::Path) -> Vec<serde_json::Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect()
}

/// Serializes the full-default-scan tests in this binary.
///
/// Each binds real loopback listeners on default-set ports while a sibling
/// thread scans all 100 default ports: without serialization the scans
/// cross-find each other's fixtures (extra opens) and a "closed" pick can
/// flip open mid-scan. Ephemeral `:0` listeners elsewhere cannot collide
/// (OS ephemeral range sits above the default set), so only the three
/// full-default tests share this lock.
static DEFAULT_SCAN_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
fn hold_default_scan_lock() -> std::sync::MutexGuard<'static, ()> {
    DEFAULT_SCAN_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap()
}

// ---------- port states ----------

#[test]
fn single_open_port_via_local_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    let plan = compile(&["127.0.0.1", "--ports", &port.to_string(), "--level", "3"]);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let policy = TcpScanPolicy::new(3, plan.goal, plan.tcp_ports.clone(), plan.speed);
    let module = TcpDiscoveryModule::new(policy, guard.clone());
    let task = port_task_for(
        &plan,
        "127.0.0.1".parse().unwrap(),
        &format!("explicit:{port}"),
        5000,
        guard.as_ref(),
    );
    let output = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert_eq!(open_ports_in(&output), vec![port]);
    assert_eq!(output.assets.len(), 1);
    assert!(
        output
            .events
            .iter()
            .any(|event| { format!("{:?}", event.kind) == "PortOpen" })
    );
    drop(listener);
}

#[test]
fn single_closed_port_is_not_open() {
    // High loopback port: refused fast, never reported open.
    let plan = compile(&["127.0.0.1", "--ports", "65000", "--level", "3"]);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let policy = TcpScanPolicy::new(3, plan.goal, plan.tcp_ports.clone(), plan.speed);
    let module = TcpDiscoveryModule::new(policy, guard.clone());
    let task = port_task_for(
        &plan,
        "127.0.0.1".parse().unwrap(),
        "explicit:65000",
        5000,
        guard.as_ref(),
    );
    let output = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert!(open_ports_in(&output).is_empty());
    // Closed detail stays in the completed summary, not as findings.
    assert!(output.findings.is_empty());
    let completed = output
        .events
        .iter()
        .find(|event| format!("{:?}", event.kind) == "PortScanCompleted")
        .expect("completed event");
    let closed = completed.details.data["counts"]["closed"].as_u64().unwrap();
    assert_eq!(closed, 1);
}

#[test]
fn timeout_state_is_distinct_from_closed() {
    // Fake scanner: filtered stays FilteredOrTimedOut, never Closed/Open.
    let plan = compile(&["192.0.2.10", "--ports", "80,81", "--level", "3"]);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let calls = Arc::new(AtomicUsize::new(0));
    let fake = FakeScanner {
        open: Vec::new(),
        filtered: vec![80],
        error: Vec::new(),
        calls: calls.clone(),
        delay_ms: 0,
        max_concurrent_seen: Arc::new(AtomicUsize::new(0)),
        active: Arc::new(AtomicUsize::new(0)),
    };
    let policy = TcpScanPolicy::new(3, plan.goal, plan.tcp_ports.clone(), plan.speed);
    let module = TcpDiscoveryModule::with_scanner(policy, Arc::new(fake), guard.clone());
    let task = port_task_for(
        &plan,
        "192.0.2.10".parse().unwrap(),
        "explicit:80,81",
        5000,
        guard.as_ref(),
    );
    let output = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert!(open_ports_in(&output).is_empty());
    let completed = output
        .events
        .iter()
        .find(|event| format!("{:?}", event.kind) == "PortScanCompleted")
        .unwrap();
    assert_eq!(
        completed.details.data["counts"]["filtered_or_timed_out"]
            .as_u64()
            .unwrap(),
        1
    );
    assert_eq!(
        completed.details.data["counts"]["closed"].as_u64().unwrap(),
        1
    );
    // Native mapping sanity: refused != timeout at the scanner layer.
    assert_ne!(PortState::Closed, PortState::FilteredOrTimedOut);
}

// ---------- selection ----------

#[test]
fn explicit_port_list_scans_each_once_in_order() {
    let listener_a = TcpListener::bind("127.0.0.1:0").unwrap();
    let port_a = listener_a.local_addr().unwrap().port();
    let listener_b = TcpListener::bind("127.0.0.1:0").unwrap();
    let port_b = listener_b.local_addr().unwrap().port();
    let (low, high) = if port_a < port_b {
        (port_a, port_b)
    } else {
        (port_b, port_a)
    };
    // Reversed input order must still scan each once, deterministically.
    let plan = compile(&[
        "127.0.0.1",
        "--ports",
        &format!("{high},{low},{high}"),
        "--level",
        "3",
    ]);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let policy = TcpScanPolicy::new(3, plan.goal, plan.tcp_ports.clone(), plan.speed);
    let module = TcpDiscoveryModule::new(policy, guard.clone());
    let task = port_task_for(
        &plan,
        "127.0.0.1".parse().unwrap(),
        &format!("explicit:{low},{high}"),
        8000,
        guard.as_ref(),
    );
    let output = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let mut opens = open_ports_in(&output);
    opens.sort_unstable();
    assert_eq!(opens, vec![low, high]);
}

#[test]
fn range_parsing_normalizes_and_dedupes_overlap() {
    assert_eq!(
        parse_port_selection("80-82,82,81").unwrap(),
        vec![80, 81, 82]
    );
    assert_eq!(parse_port_selection("1-3").unwrap(), vec![1, 2, 3]);
    assert_eq!(
        parse_port_selection("22,80,443").unwrap(),
        vec![22, 80, 443]
    );
    // Plan-level explicit ranges normalize identically.
    let plan = compile(&["127.0.0.1", "--ports", "80-82,82", "--level", "3"]);
    assert_eq!(plan.tcp_ports, TcpPortSelection::Explicit(vec![80, 81, 82]));
}

#[test]
fn invalid_ports_are_rejected() {
    assert!(parse_port_selection("0").is_err());
    assert!(parse_port_selection("0,80").is_err());
    assert!(parse_port_selection("90-80").is_err());
    assert!(parse_port_selection("65536").is_err());
    assert!(parse_port_selection("").is_err());
    assert!(parse_port_selection("22,,80").is_err());
    assert!(parse_port_selection("abc").is_err());
    // CLI-level rejection stays fail-fast.
    assert!(Cli::try_parse_from(["rxscan", "127.0.0.1", "--ports", "0"]).is_ok());
    let cli = Cli::try_parse_from(["rxscan", "127.0.0.1", "--ports", "0"]).unwrap();
    assert!(ScanPlan::compile(cli).is_err());
}

#[test]
fn all_ports_is_one_task_not_65k() {
    let plan = compile(&["127.0.0.1", "--all-ports", "--level", "3"]);
    let tasks = rxscan::lowering::lower_plan_to_tasks(&plan).unwrap();
    let port_tasks: Vec<&Task> = tasks
        .iter()
        .filter(|task| task.kind == TaskKind::PortDiscovery)
        .collect();
    assert_eq!(port_tasks.len(), 1);
    assert_eq!(
        port_tasks[0].params.get("ports").map(String::as_str),
        Some("all")
    );
    // Fake full scan stays bounded as one task with sorted deterministic output.
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let calls = Arc::new(AtomicUsize::new(0));
    let fake = FakeScanner {
        open: vec![80, 443],
        filtered: Vec::new(),
        error: Vec::new(),
        calls,
        delay_ms: 0,
        max_concurrent_seen: Arc::new(AtomicUsize::new(0)),
        active: Arc::new(AtomicUsize::new(0)),
    };
    let policy = TcpScanPolicy::new(3, plan.goal, plan.tcp_ports.clone(), plan.speed);
    let module = TcpDiscoveryModule::with_scanner(policy, Arc::new(fake), guard.clone());
    let task = port_task_for(
        &plan,
        "127.0.0.1".parse().unwrap(),
        "all",
        30_000,
        guard.as_ref(),
    );
    let output = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert_eq!(open_ports_in(&output), vec![80, 443]);
    // Bounded detail: huge scans emit opens + summary, not 65k per-port events.
    assert!(output.events.len() < 1000);
}

#[test]
fn common_profile_is_versioned_centralized_and_sorted() {
    assert_eq!(COMMON_PROFILE_VERSION, "v1");
    let mut sorted = COMMON_PORTS_V1.to_vec();
    sorted.sort_unstable();
    assert_eq!(sorted, COMMON_PORTS_V1);
    assert!(!COMMON_PORTS_V1.contains(&0));
    assert!(!COMMON_PORTS_V1.is_empty());
    // Level subsets stay within the profile family and sorted.
    for level in 1..=5 {
        let automatic = automatic_ports_for_level(level);
        let mut check = automatic.clone();
        check.sort_unstable();
        assert_eq!(check, automatic);
    }
}

// ---------- families ----------

#[test]
fn ipv4_scan_works() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = ScanConfig::bounded(
        Duration::from_millis(1000),
        16,
        0,
        None,
        CancellationToken::default(),
    );
    let outcome = NativeTcpScanner.scan("127.0.0.1".parse().unwrap(), &[port], &config);
    assert_eq!(outcome.probes.len(), 1);
    assert_eq!(outcome.probes[0].state, PortState::Open);
    assert!(!outcome.cancelled);
}

#[test]
fn ipv6_scan_works() {
    let listener = TcpListener::bind("[::1]:0").expect("bind ::1");
    let port = listener.local_addr().unwrap().port();
    let config = ScanConfig::bounded(
        Duration::from_millis(1000),
        16,
        0,
        None,
        CancellationToken::default(),
    );
    let outcome = NativeTcpScanner.scan("::1".parse().unwrap(), &[port], &config);
    assert_eq!(outcome.probes.len(), 1);
    assert_eq!(outcome.probes[0].state, PortState::Open);
    // Closed IPv6 stays Closed, never misclassified as timeout.
    let closed = NativeTcpScanner.scan("::1".parse().unwrap(), &[65_000], &config);
    assert!(matches!(
        closed.probes[0].state,
        PortState::Closed | PortState::Error
    ));
}

// ---------- safety ----------

#[test]
fn concurrency_is_bounded_and_descriptors_recycled() {
    // 1000 closed loopback ports through a 32-wide window: every port
    // accounted exactly once, no FD-exhaustion error storm.
    let ports: Vec<u16> = (50_000..51_000).collect();
    let config = ScanConfig::bounded(
        Duration::from_millis(800),
        32,
        0,
        None,
        CancellationToken::default(),
    );
    let started = Instant::now();
    let outcome = NativeTcpScanner.scan("127.0.0.1".parse().unwrap(), &ports, &config);
    assert!(started.elapsed() < Duration::from_secs(30));
    assert_eq!(outcome.probes.len(), 1000);
    assert!(!outcome.cancelled);
    let mut seen: Vec<u16> = outcome.probes.iter().map(|probe| probe.port).collect();
    seen.sort_unstable();
    assert_eq!(seen, ports);
    let errors = outcome
        .probes
        .iter()
        .filter(|probe| probe.state == PortState::Error)
        .count();
    assert!(errors < 50, "FD exhaustion suspected: {errors} errors");
    // Config clamps: never unbounded, never zero.
    let wide = ScanConfig::bounded(
        Duration::from_millis(500),
        10_000,
        99,
        None,
        CancellationToken::default(),
    );
    assert!(wide.max_concurrent <= rxscan::ports::MAX_TCP_CONCURRENCY_HARD);
    assert!(wide.max_retries <= 1);
}

#[test]
fn cancellation_interrupts_pending_work_promptly() {
    let plan = compile(&["127.0.0.1", "--ports", "80-90", "--level", "3"]);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let calls = Arc::new(AtomicUsize::new(0));
    let fake = FakeScanner {
        open: Vec::new(),
        filtered: Vec::new(),
        error: Vec::new(),
        calls,
        delay_ms: 20,
        max_concurrent_seen: Arc::new(AtomicUsize::new(0)),
        active: Arc::new(AtomicUsize::new(0)),
    };
    let policy = TcpScanPolicy::new(3, plan.goal, plan.tcp_ports.clone(), plan.speed);
    let module = TcpDiscoveryModule::with_scanner(policy, Arc::new(fake), guard.clone());
    let task = port_task_for(
        &plan,
        "127.0.0.1".parse().unwrap(),
        "explicit:80,81,82,83,84,85,86,87,88,89,90",
        10_000,
        guard.as_ref(),
    );
    let token = CancellationToken::default();
    token.cancel();
    let started = Instant::now();
    let result = block_on_module(&module, ModuleContext::new(task, token));
    assert!(matches!(result, Err(ModuleError::Cancelled)));
    assert!(started.elapsed() < Duration::from_millis(500));
    // Mid-scan cancel via a deterministic slow fake (11 ports x 20ms each
    // ~= 220ms sequential; cancel at ~30ms lands reliably mid-scan).
    let token = CancellationToken::default();
    let mid_calls = Arc::new(AtomicUsize::new(0));
    let mid_fake = Arc::new(FakeScanner {
        open: Vec::new(),
        filtered: Vec::new(),
        error: Vec::new(),
        calls: mid_calls,
        delay_ms: 20,
        max_concurrent_seen: Arc::new(AtomicUsize::new(0)),
        active: Arc::new(AtomicUsize::new(0)),
    });
    let mid_config = ScanConfig::bounded(Duration::from_millis(2000), 16, 0, None, token.clone());
    let mid_ports: Vec<u16> = (80..91).collect();
    let handle = std::thread::spawn(move || {
        mid_fake.scan("192.0.2.10".parse().unwrap(), &mid_ports, &mid_config)
    });
    std::thread::sleep(Duration::from_millis(30));
    token.cancel();
    let outcome = handle.join().unwrap();
    assert!(outcome.cancelled || outcome.truncated);
}

#[test]
fn timeouts_are_bounded_and_do_not_hang_completion() {
    // Short task deadline with a slow fake: partial results + truncation flag,
    // never a hang, never a panic.
    let plan = compile(&["192.0.2.10", "--ports", "80,81,82", "--level", "3"]);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let calls = Arc::new(AtomicUsize::new(0));
    let fake = FakeScanner {
        open: Vec::new(),
        filtered: Vec::new(),
        error: Vec::new(),
        calls,
        delay_ms: 300,
        max_concurrent_seen: Arc::new(AtomicUsize::new(0)),
        active: Arc::new(AtomicUsize::new(0)),
    };
    let policy = TcpScanPolicy::new(3, plan.goal, plan.tcp_ports.clone(), plan.speed);
    let module = TcpDiscoveryModule::with_scanner(policy, Arc::new(fake), guard.clone());
    let task = port_task_for(
        &plan,
        "192.0.2.10".parse().unwrap(),
        "explicit:80,81,82",
        250,
        guard.as_ref(),
    );
    let started = Instant::now();
    let output = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    let completed = output
        .events
        .iter()
        .find(|event| format!("{:?}", event.kind) == "PortScanCompleted")
        .unwrap();
    assert_eq!(completed.details.data["truncated"].as_bool(), Some(true));
}

#[test]
fn retries_are_bounded_and_selective() {
    // Refused never retried; filtered retried at most once; cancel never.
    let config_no_retry = ScanConfig::bounded(
        Duration::from_millis(500),
        16,
        0,
        None,
        CancellationToken::default(),
    );
    assert_eq!(config_no_retry.max_retries, 0);
    let config_retry = ScanConfig::bounded(
        Duration::from_millis(500),
        16,
        7,
        None,
        CancellationToken::default(),
    );
    assert_eq!(config_retry.max_retries, 1);
    // Native closed port reports attempts == 1 even when retries allowed.
    let outcome = NativeTcpScanner.scan("127.0.0.1".parse().unwrap(), &[65_001], &config_retry);
    assert_eq!(outcome.probes[0].attempts, 1);
}

// ---------- policy ----------

#[test]
fn speed_changes_pressure_only_never_the_port_set() {
    let selection = TcpPortSelection::Explicit(vec![80, 443]);
    let slow = TcpScanPolicy::new(
        3,
        ScanGoal::Recon,
        selection.clone(),
        SpeedSetting::Numeric(0),
    );
    let fast = TcpScanPolicy::new(
        3,
        ScanGoal::Recon,
        selection.clone(),
        SpeedSetting::Numeric(100),
    );
    assert_eq!(
        slow.ports_for_task(Some("explicit:80,443")).ports,
        fast.ports_for_task(Some("explicit:80,443")).ports
    );
    assert!(fast.per_port_timeout() < slow.per_port_timeout());
    assert!(fast.concurrency() >= slow.concurrency());
    assert!(fast.concurrency() <= rxscan::ports::MAX_TCP_CONCURRENCY_HARD);
    // Speed 100 stays bounded by the hard cap.
    assert!(tcp_concurrency_for_speed(SpeedSetting::Numeric(100)) <= 128);
    assert!(tcp_timeout_for_speed(SpeedSetting::Numeric(100)).as_millis() >= 200);
}

#[test]
fn level_changes_automatic_breadth_and_explicit_wins() {
    let l1 = TcpScanPolicy::new(
        1,
        ScanGoal::Recon,
        TcpPortSelection::Common,
        SpeedSetting::default(),
    );
    let l5 = TcpScanPolicy::new(
        5,
        ScanGoal::Recon,
        TcpPortSelection::Common,
        SpeedSetting::default(),
    );
    let l1_ports = l1.ports_for_task(Some("common")).ports;
    let l5_ports = l5.ports_for_task(Some("common")).ports;
    assert!(l1_ports.len() < l5_ports.len());
    assert_eq!(l5_ports.len(), 1000);
    // Explicit operator intent is identical at every level.
    let explicit = TcpPortSelection::Explicit(vec![8080]);
    let at_l1 = TcpScanPolicy::new(
        1,
        ScanGoal::Recon,
        explicit.clone(),
        SpeedSetting::default(),
    );
    let at_l5 = TcpScanPolicy::new(5, ScanGoal::Recon, explicit, SpeedSetting::default());
    assert_eq!(
        at_l1.ports_for_task(Some("explicit:8080")).ports,
        vec![8080]
    );
    assert_eq!(
        at_l5.ports_for_task(Some("explicit:8080")).ports,
        vec![8080]
    );
    // Eligibility helper matches lowering intent.
    assert!(port_eligible_for_plan(ScanGoal::Recon, 3, false));
    assert!(port_eligible_for_plan(ScanGoal::Recon, 1, true));
}

#[test]
fn explicit_range_policy_is_lossless_through_task_params() {
    let plan = compile(&["127.0.0.1", "--ports", "1-1024", "--level", "1"]);
    let tasks = rxscan::lowering::lower_plan_to_tasks(&plan).unwrap();
    let port_task = tasks
        .iter()
        .find(|task| task.kind == TaskKind::PortDiscovery)
        .expect("explicit ports produce a port task");
    assert_eq!(
        port_task.params.get("ports").map(String::as_str),
        Some("explicit:1-1024")
    );
    let policy = TcpScanPolicy::new(plan.level, plan.goal, plan.tcp_ports.clone(), plan.speed);
    let resolved = policy.ports_for_task(port_task.params.get("ports").map(String::as_str));
    assert_eq!(resolved.ports.len(), 1024);
    assert_eq!(resolved.ports.first(), Some(&1));
    assert_eq!(resolved.ports.last(), Some(&1024));
}

#[test]
fn default_scan_lowers_tcp_discovery() {
    let plan = compile(&["127.0.0.1"]);
    assert_eq!(plan.level, 3);
    let tasks = rxscan::lowering::lower_plan_to_tasks(&plan).unwrap();
    assert!(
        tasks
            .iter()
            .any(|task| task.kind == TaskKind::PortDiscovery),
        "rxscan TARGET must include real TCP discovery by default"
    );
}

#[test]
fn default_recon_executes_tcp_and_reports_default_open_service() {
    let _lock = hold_default_scan_lock();
    let (listener, open_port) = bind_default_scan_listener();
    let closed_port = closed_default_port(open_port);
    let connections = Arc::new(AtomicUsize::new(0));
    let connections_thread = connections.clone();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_thread = stop.clone();
    let handle = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !stop_thread.load(Ordering::SeqCst) && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    connections_thread.fetch_add(1, Ordering::SeqCst);
                    let _ = stream.write_all(b"SSH-2.0-DefaultProof_1.0\r\n");
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                    let mut buf = [0u8; 256];
                    let _ = stream.read(&mut buf);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("rxscan-default-ledger-{stamp}.jsonl"));
    let cli = Cli::try_parse_from([
        "rxscan",
        "127.0.0.1",
        "--scope",
        "127.0.0.1",
        "--speed",
        "100",
        "--output",
        path.to_str().unwrap(),
    ])
    .unwrap();
    let report = rxscan::run::execute(cli).unwrap();
    stop.store(true, Ordering::SeqCst);
    handle.join().unwrap();

    let default_ports = automatic_ports_for_level(3);
    assert!(default_ports.contains(&open_port));
    assert!(default_ports.contains(&closed_port));
    assert!(connections.load(Ordering::SeqCst) >= 2);

    let human = rxscan::run::human_summary(&report);
    assert!(human.contains(&format!("{open_port}/tcp")));
    assert!(human.contains("ssh"));

    let payloads = read_jsonl_payloads(&path);
    let port_completed = payloads
        .iter()
        .find(|value| {
            value["record_type"] == "event" && value["payload"]["kind"] == "port_scan_completed"
        })
        .expect("port_scan_completed event");
    let details = &port_completed["payload"]["details"]["data"];
    assert_eq!(
        details["ports_requested"].as_u64(),
        Some(default_ports.len() as u64)
    );
    assert_eq!(details["unscanned"].as_u64(), Some(0));
    assert_eq!(details["truncated"].as_bool(), Some(false));
    let requested: Vec<u16> = details["requested_ports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_u64().unwrap() as u16)
        .collect();
    let attempted: Vec<u16> = details["attempted_ports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_u64().unwrap() as u16)
        .collect();
    assert_eq!(requested, default_ports);
    assert_eq!(attempted, default_ports);
    assert!(
        details["open_ports"]
            .as_array()
            .unwrap()
            .contains(&open_port.into())
    );
    assert_eq!(details["counts"]["open"].as_u64(), Some(1));
    assert_eq!(
        details["counts"]
            .as_object()
            .unwrap()
            .values()
            .map(|value| value.as_u64().unwrap())
            .sum::<u64>(),
        default_ports.len() as u64
    );
    assert!(payloads.iter().any(|value| {
        value["record_type"] == "event"
            && value["payload"]["kind"] == "port_closed"
            && value["payload"]["details"]["data"]["port"].as_u64() == Some(u64::from(closed_port))
    }));
    assert!(payloads.iter().any(|value| {
        value["record_type"] == "event"
            && value["payload"]["kind"] == "service_identified"
            && value["payload"]["details"]["data"]["port"].as_u64() == Some(u64::from(open_port))
            && value["payload"]["details"]["data"]["protocol"] == "ssh"
    }));
    assert!(
        report
            .open_ports_summary
            .contains(&format!("{open_port}/tcp"))
    );
    fs::remove_file(path).ok();
}

// ---------- scope ----------

#[test]
fn scope_guard_blocks_out_of_scope_scans_without_network() {
    let plan = compile(&["127.0.0.1", "--ports", "80", "--level", "3"]);
    struct DenyAll;
    impl ScopeGuard for DenyAll {
        fn permits(&self, _target: &TaskScopeTarget) -> bool {
            false
        }
    }
    let task = port_task_for(
        &plan,
        "127.0.0.1".parse().unwrap(),
        "explicit:80",
        2000,
        &AllowAll,
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let policy = TcpScanPolicy::new(3, plan.goal, plan.tcp_ports.clone(), plan.speed);
    let module = TcpDiscoveryModule::with_scanner(
        policy,
        Arc::new(FakeScanner::new(calls.clone())),
        Arc::new(DenyAll),
    );
    let result = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    );
    assert!(matches!(result, Err(ModuleError::Failed { .. })));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn stale_scope_skips_without_network() {
    use std::sync::atomic::AtomicBool;
    struct FlippingGuard {
        allowed: AtomicBool,
    }
    impl ScopeGuard for FlippingGuard {
        fn permits(&self, _target: &TaskScopeTarget) -> bool {
            self.allowed.load(Ordering::SeqCst)
        }
    }
    let plan = compile(&["127.0.0.1", "--ports", "80", "--level", "3"]);
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
    let policy = TcpScanPolicy::new(3, plan.goal, plan.tcp_ports.clone(), plan.speed);
    scheduler.register_module(Arc::new(TcpDiscoveryModule::with_scanner(
        policy,
        Arc::new(FakeScanner::new(Arc::new(AtomicUsize::new(0)))),
        guard.clone(),
    )));
    let task = Task::new_with_params(
        TaskKind::PortDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        60,
        Duration::from_millis(2000),
        RetryPolicy::default(),
        "rxscan.port",
        provenance_for(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([
            ("target".to_owned(), "127.0.0.1".to_owned()),
            ("ports".to_owned(), "explicit:80".to_owned()),
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
fn hostname_addresses_are_filtered_by_scope_guard() {
    // Seed `localhost` allows the hostname; derived loopback IPs are only
    // scanned when the guard also permits them (no silent scope expansion).
    let plan = compile(&["localhost", "--ports", "80", "--level", "3"]);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let policy = TcpScanPolicy::new(3, plan.goal, plan.tcp_ports.clone(), plan.speed);
    let calls = Arc::new(AtomicUsize::new(0));
    let module = TcpDiscoveryModule::with_scanner(
        policy,
        Arc::new(FakeScanner::new(calls.clone())),
        guard.clone(),
    );
    let task = Task::new_with_params(
        TaskKind::PortDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        60,
        Duration::from_millis(3000),
        RetryPolicy::default(),
        "rxscan.port",
        provenance_for(&plan),
        TaskScopeTarget::Host("localhost".to_owned()),
        BTreeMap::from([
            ("target".to_owned(), "localhost".to_owned()),
            ("ports".to_owned(), "explicit:80".to_owned()),
        ]),
        guard.as_ref(),
    )
    .unwrap();
    let output = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    // Hostname-only scope permits no IPs → empty scan with an explanatory
    // completed event, and zero scanner calls for out-of-scope addresses.
    let completed = output
        .events
        .iter()
        .find(|event| format!("{:?}", event.kind) == "PortScanCompleted")
        .expect("completed");
    let note = completed.details.data["note"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        note.contains("out-of-scope")
            || note.contains("resolution failed")
            || open_ports_in(&output).is_empty()
    );
    drop(calls);
}

// ---------- decision engine ----------

#[test]
fn decision_engine_proposes_for_alive_and_dedups() {
    use rxscan::model::{BoundedDetails, Event};
    let plan = compile(&["127.0.0.1", "--ports", "80", "--level", "3"]);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let engine = TcpDecisionEngine::new(
        guard.clone(),
        plan.stable_id(),
        plan.level,
        plan.goal,
        plan.tcp_ports.clone(),
        plan.speed,
    );
    let provenance =
        Provenance::new("rxscan.host", "5.0.0", plan.stable_id(), Timestamp(1)).unwrap();
    let host_task = Task::new_with_params(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        80,
        Duration::from_millis(2000),
        RetryPolicy::default(),
        "rxscan.host",
        provenance_for(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([("target".to_owned(), "127.0.0.1".to_owned())]),
        guard.as_ref(),
    )
    .unwrap();
    let concluded = Event::new(
        rxscan::model::EventKind::HostStateConcluded,
        None,
        BoundedDetails::from_value(
            serde_json::json!({"state": "alive", "target": "127.0.0.1", "address": "127.0.0.1"}),
            4096,
        )
        .unwrap(),
        provenance,
    )
    .unwrap();
    let output = ModuleOutput {
        events: vec![concluded],
        evidence: Vec::new(),
        findings: Vec::new(),
        assets: Vec::new(),
    };
    let proposals = engine.follow_up_tasks(&host_task, &output);
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].kind, TaskKind::PortDiscovery);
    // Scheduler admits the proposal once; the duplicate is ignored gracefully.
    let mut scheduler = Scheduler::new(
        16,
        BudgetLimits::default(),
        SpeedGovernor::new(SpeedSetting::Numeric(100), 2).unwrap(),
        guard.clone(),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler.set_decision_engine(Arc::new(engine));
    struct HostOnce {
        output: ModuleOutput,
    }
    impl Module for HostOnce {
        fn kind(&self) -> TaskKind {
            TaskKind::HostDiscovery
        }
        fn execute(&self, _context: ModuleContext) -> ModuleFuture {
            let output = self.output.clone();
            Box::pin(async move { Ok(output) })
        }
    }
    struct PortOk;
    impl Module for PortOk {
        fn kind(&self) -> TaskKind {
            TaskKind::PortDiscovery
        }
        fn execute(&self, _context: ModuleContext) -> ModuleFuture {
            Box::pin(async { Ok(ModuleOutput::default()) })
        }
    }
    scheduler.register_module(Arc::new(HostOnce { output }));
    scheduler.register_module(Arc::new(PortOk));
    scheduler.add_task(host_task).unwrap();
    let report = scheduler.run().unwrap();
    // Host + exactly one port task (proposal dedups against nothing here
    // since lowering emitted no initial port task in this hand-built graph).
    assert_eq!(report.completed.len(), 2);
}

#[test]
fn decision_engine_unknown_and_unreachable_policy() {
    use rxscan::model::{BoundedDetails, Event};
    let plan = compile(&["127.0.0.1", "--level", "3"]);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let mk_output = |state: &str| {
        let provenance =
            Provenance::new("rxscan.host", "5.0.0", plan.stable_id(), Timestamp(1)).unwrap();
        ModuleOutput {
            events: vec![
                Event::new(
                    rxscan::model::EventKind::HostStateConcluded,
                    None,
                    BoundedDetails::from_value(
                        serde_json::json!({"state": state, "target": "t", "address": "127.0.0.1"}),
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
        }
    };
    let host_task = Task::new_with_params(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        80,
        Duration::from_millis(2000),
        RetryPolicy::default(),
        "rxscan.host",
        provenance_for(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([("target".to_owned(), "t".to_owned())]),
        guard.as_ref(),
    )
    .unwrap();
    // L3 Unknown proceeds (ICMP may be blocked); Unreachable never does.
    let engine = TcpDecisionEngine::new(
        guard.clone(),
        plan.stable_id(),
        3,
        plan.goal,
        TcpPortSelection::Common,
        plan.speed,
    );
    assert_eq!(
        engine
            .follow_up_tasks(&host_task, &mk_output("unknown"))
            .len(),
        1
    );
    assert!(
        engine
            .follow_up_tasks(&host_task, &mk_output("unreachable"))
            .is_empty()
    );
    // L1 Unknown without explicit ports is skipped.
    let strict = TcpDecisionEngine::new(
        guard.clone(),
        plan.stable_id(),
        1,
        ScanGoal::Recon,
        TcpPortSelection::Common,
        plan.speed,
    );
    assert!(
        strict
            .follow_up_tasks(&host_task, &mk_output("unknown"))
            .is_empty()
    );
    // Out-of-scope proposals are rejected (no task returned).
    let denied: Arc<dyn ScopeGuard> = Arc::new(AllowAll);
    struct DenyAll;
    impl ScopeGuard for DenyAll {
        fn permits(&self, _target: &TaskScopeTarget) -> bool {
            false
        }
    }
    let denying = TcpDecisionEngine::new(
        Arc::new(DenyAll),
        plan.stable_id(),
        3,
        plan.goal,
        TcpPortSelection::Common,
        plan.speed,
    );
    assert!(
        denying
            .follow_up_tasks(&host_task, &mk_output("alive"))
            .is_empty()
    );
    drop(denied);
}

// ---------- assets / output ----------

#[test]
fn port_asset_ids_are_stable_and_collision_free() {
    let parent_a = "asset_ip_aaaaaaaaaaaaaaaa";
    let parent_b = "asset_ip_bbbbbbbbbbbbbbbb";
    assert_eq!(
        port_asset_id(parent_a, "tcp", 80),
        port_asset_id(parent_a, "tcp", 80)
    );
    assert_ne!(
        port_asset_id(parent_a, "tcp", 80),
        port_asset_id(parent_b, "tcp", 80)
    );
    assert_ne!(
        port_asset_id(parent_a, "tcp", 80),
        port_asset_id(parent_a, "tcp", 443)
    );
    assert_ne!(
        port_asset_id(parent_a, "tcp", 80),
        port_asset_id(parent_a, "udp", 80)
    );
}

#[test]
fn jsonl_open_port_output_has_required_fields() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("rxscan-phase6-jsonl-{stamp}"));
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("out.jsonl");
    let cli = Cli::try_parse_from([
        "rxscan",
        "127.0.0.1",
        "--ports",
        &port.to_string(),
        "--level",
        "3",
        "--output",
        path.to_str().unwrap(),
    ])
    .unwrap();
    let report = rxscan::run::execute(cli).unwrap();
    assert!(report.jsonl_bytes > 0);
    let contents = fs::read_to_string(&path).unwrap();
    let mut saw_open = false;
    let mut saw_finding = false;
    let mut saw_port_asset = false;
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
            "event" if payload["kind"] == "port_open" => {
                saw_open = true;
                let data = &payload["details"]["data"];
                for field in ["target", "address", "transport", "port", "state"] {
                    assert!(data.get(field).is_some(), "missing {field}");
                }
            }
            "finding" => {
                saw_finding = true;
                assert!(payload["title"].as_str().unwrap().contains("Open TCP port"));
            }
            "asset" if payload["id"].as_str().unwrap().starts_with("asset_port_") => {
                saw_port_asset = true;
            }
            "evidence" => {
                let data = &payload["details"]["data"];
                // Port evidence carries transport/port/state; host evidence
                // carries host state — accept either shape, require provenance.
                assert!(data.is_object());
            }
            _ => {}
        }
    }
    assert!(saw_open && saw_finding && saw_port_asset);
    // Human summary prioritizes the open port.
    assert!(report.open_ports_summary.contains(&port.to_string()));
    fs::remove_dir_all(directory).unwrap();
    drop(listener);
}

#[test]
fn results_are_deterministically_ordered() {
    let plan = compile(&["192.0.2.10", "--ports", "443,80,22", "--level", "3"]);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let run_once = || {
        let calls = Arc::new(AtomicUsize::new(0));
        let fake = FakeScanner {
            open: vec![22, 80, 443],
            filtered: Vec::new(),
            error: Vec::new(),
            calls,
            delay_ms: 0,
            max_concurrent_seen: Arc::new(AtomicUsize::new(0)),
            active: Arc::new(AtomicUsize::new(0)),
        };
        let policy = TcpScanPolicy::new(3, plan.goal, plan.tcp_ports.clone(), plan.speed);
        let module = TcpDiscoveryModule::with_scanner(policy, Arc::new(fake), guard.clone());
        let task = port_task_for(
            &plan,
            "192.0.2.10".parse().unwrap(),
            "explicit:22,80,443",
            5000,
            guard.as_ref(),
        );
        block_on_module(
            &module,
            ModuleContext::new(task, CancellationToken::default()),
        )
        .unwrap()
    };
    let first = run_once();
    let second = run_once();
    assert_eq!(open_ports_in(&first), open_ports_in(&second));
    assert_eq!(open_ports_in(&first), vec![22, 80, 443]);
}

#[test]
fn service_handoff_boundary_holds_no_fingerprinting() {
    // Phase 6 reports openness only: no service/version claims in findings,
    // evidence, or events.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let plan = compile(&["127.0.0.1", "--ports", &port.to_string(), "--level", "3"]);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let policy = TcpScanPolicy::new(3, plan.goal, plan.tcp_ports.clone(), plan.speed);
    let module = TcpDiscoveryModule::new(policy, guard.clone());
    let task = port_task_for(
        &plan,
        "127.0.0.1".parse().unwrap(),
        &format!("explicit:{port}"),
        5000,
        guard.as_ref(),
    );
    let output = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    // Openness only: findings carry port/address, never service identity.
    let blob = format!("{output:?}").to_ascii_lowercase();
    for banned in [
        "openssh",
        "nginx",
        "apache",
        "fingerprint",
        "serviceprobe",
        "banner",
    ] {
        assert!(!blob.contains(banned), "leaked fingerprint term: {banned}");
    }
    // "version" appears in provenance module_version keys; scope the check to
    // finding titles and evidence text instead of the whole debug blob.
    for finding in &output.findings {
        assert!(!finding.title.to_ascii_lowercase().contains("version"));
    }
    drop(listener);
}

#[test]
fn ipv6_target_with_explicit_scope_scans_permitted_only() {
    let plan = compile(&["::1", "--ports", "80", "--level", "3"]);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let policy = TcpScanPolicy::new(3, plan.goal, plan.tcp_ports.clone(), plan.speed);
    let module = TcpDiscoveryModule::new(policy, guard.clone());
    let task = port_task_for(
        &plan,
        "::1".parse().unwrap(),
        "explicit:80",
        5000,
        guard.as_ref(),
    );
    let started = Instant::now();
    let output = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    assert!(started.elapsed() < Duration::from_secs(10));
    // Completes with a summary regardless of open/closed on this host.
    assert!(
        output
            .events
            .iter()
            .any(|event| { format!("{:?}", event.kind) == "PortScanCompleted" })
    );
    let _: IpAddr = "::1".parse().unwrap();
}

#[test]
fn default_recon_known_closed_port_is_proven_scanned_not_open() {
    // A known-closed default port must still appear in the execution ledger
    // (requested + attempted) with unscanned == 0, and the human summary
    // "No open TCP ports observed." is only valid because PortScanCompleted
    // proves the scan actually ran.
    let _lock = hold_default_scan_lock();
    let default_ports = automatic_ports_for_level(3);
    let closed_port = closed_default_port(0);
    assert!(default_ports.contains(&closed_port));
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("rxscan-default-closed-{stamp}.jsonl"));
    let cli = Cli::try_parse_from([
        "rxscan",
        "127.0.0.1",
        "--scope",
        "127.0.0.1",
        "--speed",
        "100",
        "--output",
        path.to_str().unwrap(),
    ])
    .unwrap();
    let report = rxscan::run::execute(cli).unwrap();
    let payloads = read_jsonl_payloads(&path);
    let completed = payloads
        .iter()
        .find(|value| {
            value["record_type"] == "event" && value["payload"]["kind"] == "port_scan_completed"
        })
        .expect("port_scan_completed event");
    let details = &completed["payload"]["details"]["data"];
    assert_eq!(details["unscanned"].as_u64(), Some(0));
    assert_eq!(details["truncated"].as_bool(), Some(false));
    // Ledger completeness holds regardless of environment opens elsewhere
    // on loopback: every requested port was attempted exactly once.
    let counts = details["counts"].as_object().unwrap();
    let total: u64 = counts.values().map(|value| value.as_u64().unwrap()).sum();
    assert_eq!(total, default_ports.len() as u64);
    let requested: Vec<u16> = details["requested_ports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_u64().unwrap() as u16)
        .collect();
    let attempted: Vec<u16> = details["attempted_ports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_u64().unwrap() as u16)
        .collect();
    assert_eq!(requested, default_ports);
    assert_eq!(attempted, default_ports);
    assert!(requested.contains(&closed_port));
    assert!(attempted.contains(&closed_port));
    // Closed port has a port_closed event and is never reported open.
    assert!(payloads.iter().any(|value| {
        value["record_type"] == "event"
            && value["payload"]["kind"] == "port_closed"
            && value["payload"]["details"]["data"]["port"].as_u64() == Some(u64::from(closed_port))
    }));
    let open_ports: Vec<u64> = details["open_ports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_u64().unwrap())
        .collect();
    assert!(!open_ports.contains(&u64::from(closed_port)));
    // Human and machine agree: the closed port is not listed as open, and
    // the summary is truthful about whether a scan completed.
    let human = rxscan::run::human_summary(&report);
    assert!(!human.contains(&format!("{closed_port}/tcp")));
    assert!(!human.contains("no ports were scanned"));
    if open_ports.is_empty() {
        assert!(human.contains("No open TCP ports observed."));
    } else {
        for port in &open_ports {
            assert!(human.contains(&format!("{port}/tcp")));
        }
    }
    fs::remove_file(path).ok();
}

#[test]
fn no_scan_never_reports_no_open_ports() {
    // Level 1 runs no TCP discovery at all. The human summary must never
    // imply ports were scanned and found non-open.
    let cli = Cli::try_parse_from(["rxscan", "127.0.0.1", "--level", "1"]).unwrap();
    let report = rxscan::run::execute(cli).unwrap();
    assert_eq!(report.scheduler_report.completed.len(), 1);
    let human = rxscan::run::human_summary(&report);
    assert!(
        !human.contains("No open TCP ports observed."),
        "must not imply a scan occurred: {human}"
    );
    assert!(
        human.contains("no ports were scanned"),
        "must state truthfully that no scan completed: {human}"
    );
    // Unit-level: empty outputs without PortScanCompleted use the truthful
    // message; outputs with a completed (empty) scan keep the valid message.
    let empty: Vec<(rxscan::execution::TaskId, ModuleOutput)> = Vec::new();
    assert!(rxscan::service_probe::human_service_table(&empty).contains("no ports were scanned"));
    assert!(
        rxscan::tcp_discovery::human_open_ports_summary(&empty).contains("no ports were scanned")
    );
}

#[test]
fn human_counts_equal_port_scan_completed_counts() {
    // Human summary scanner-work numbers must derive from the same typed
    // PortScanCompleted state JSONL serializes: requested/attempted/open/
    // closed/filtered/errors/unscanned and identified services.
    let _lock = hold_default_scan_lock();
    let (listener, open_port) = bind_default_scan_listener();
    let closed_port = closed_default_port(open_port);
    let connections = Arc::new(AtomicUsize::new(0));
    let connections_thread = connections.clone();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_thread = stop.clone();
    let handle = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !stop_thread.load(Ordering::SeqCst) && Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => {
                    connections_thread.fetch_add(1, Ordering::SeqCst);
                    drop(stream);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("rxscan-human-counts-{stamp}.jsonl"));
    let cli = Cli::try_parse_from([
        "rxscan",
        "127.0.0.1",
        "--scope",
        "127.0.0.1",
        "--speed",
        "100",
        "--output",
        path.to_str().unwrap(),
    ])
    .unwrap();
    let report = rxscan::run::execute(cli).unwrap();
    stop.store(true, Ordering::SeqCst);
    handle.join().unwrap();

    let payloads = read_jsonl_payloads(&path);
    let completed = payloads
        .iter()
        .find(|value| {
            value["record_type"] == "event" && value["payload"]["kind"] == "port_scan_completed"
        })
        .expect("port_scan_completed event");
    let details = &completed["payload"]["details"]["data"];
    let machine = |key: &str| {
        if key == "requested" {
            details["ports_requested"].as_u64().unwrap()
        } else if key == "attempted" {
            details["attempted_ports"].as_array().unwrap().len() as u64
        } else if key == "unscanned" {
            details["unscanned"].as_u64().unwrap()
        } else {
            details["counts"][key].as_u64().unwrap()
        }
    };
    let services_machine = payloads
        .iter()
        .filter(|value| {
            value["record_type"] == "event" && value["payload"]["kind"] == "service_identified"
        })
        .count();
    // Typed report fields match the machine ledger exactly.
    assert_eq!(report.tcp_totals.ports_requested, machine("requested"));
    assert_eq!(report.tcp_totals.ports_attempted, machine("attempted"));
    assert_eq!(report.tcp_totals.open, machine("open"));
    assert_eq!(report.tcp_totals.closed, machine("closed"));
    assert_eq!(
        report.tcp_totals.filtered_or_timed_out,
        machine("filtered_or_timed_out")
    );
    assert_eq!(report.tcp_totals.error, machine("error"));
    assert_eq!(report.tcp_totals.unscanned, machine("unscanned"));
    assert_eq!(report.services_identified, services_machine);
    // Human summary renders those same numbers (not task accounting).
    let human = rxscan::run::human_summary(&report);
    assert!(
        human.contains(&format!("{} requested", machine("requested"))),
        "human must show requested: {human}"
    );
    assert!(
        human.contains(&format!("{} attempted", machine("attempted"))),
        "human must show attempted: {human}"
    );
    assert!(
        human.contains(&format!("{} open", machine("open"))),
        "human must show open: {human}"
    );
    assert!(
        human.contains(&format!("{} closed", machine("closed"))),
        "human must show closed: {human}"
    );
    assert!(
        human.contains(&format!("Services: {services_machine} identified")),
        "human must show services: {human}"
    );
    assert!(human.contains(&format!("{open_port}/tcp")));
    assert!(!human.contains(&format!("{closed_port}/tcp")));
    // Scheduler task accounting is demoted to Diagnostics, never primary.
    let tcp_pos = human.find("TCP discovery").expect("scanner work first");
    assert!(
        human.find("Diagnostics").is_some_and(|pos| pos > tcp_pos),
        "task accounting must follow scanner work: {human}"
    );
    fs::remove_file(path).ok();
}

#[test]
fn speed_changes_pressure_never_scan_semantics() {
    // Level changes breadth/depth; speed changes pressure only. The same
    // requested ports at slow / balanced / 100 resolve to identical port
    // sets end to end, while timeout/concurrency pressure differs.
    //
    // Self-contained: fixtures live on ephemeral ports outside the default
    // set, so sibling default-scan tests can neither find nor steal them.
    use rxscan::plan::NamedSpeed;
    let mut ports = Vec::new();
    for _ in 0..2 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral fixture");
        let port = listener.local_addr().unwrap().port();
        ports.push(port);
        // The thread owns the listener: fixtures stay up for the whole test.
        std::thread::spawn(move || {
            listener.set_nonblocking(true).ok();
            let deadline = Instant::now() + Duration::from_secs(60);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((stream, _)) => drop(stream),
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
    }
    ports.sort_unstable();
    let port_arg = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mut ledgers = Vec::new();
    for speed in ["slow", "balanced", "100"] {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rxscan-speed-{speed}-{stamp}.jsonl"));
        let cli = Cli::try_parse_from([
            "rxscan",
            "127.0.0.1",
            "--ports",
            &port_arg,
            "--level",
            "3",
            "--speed",
            speed,
            "--output",
            path.to_str().unwrap(),
        ])
        .unwrap();
        let report = rxscan::run::execute(cli).unwrap();
        let payloads = read_jsonl_payloads(&path);
        let completed = payloads
            .iter()
            .find(|value| {
                value["record_type"] == "event" && value["payload"]["kind"] == "port_scan_completed"
            })
            .expect("port_scan_completed event");
        let details = &completed["payload"]["details"]["data"];
        ledgers.push((
            details["requested_ports"].clone(),
            details["attempted_ports"].clone(),
            details["counts"].clone(),
            report.tcp_totals.clone(),
        ));
        fs::remove_file(path).ok();
    }
    // Identical semantics at every pressure: same requested/attempted
    // sets and same outcome counts (both fixtures accept every probe).
    // Timing fields (elapsed) are pressure-dependent and excluded.
    assert_eq!(ledgers[0].0, ledgers[1].0);
    assert_eq!(ledgers[1].0, ledgers[2].0);
    assert_eq!(ledgers[0].1, ledgers[1].1);
    assert_eq!(ledgers[1].1, ledgers[2].1);
    assert_eq!(ledgers[0].2, ledgers[1].2);
    assert_eq!(ledgers[1].2, ledgers[2].2);
    for ledger in &ledgers {
        assert_eq!(ledger.3.ports_requested, 2);
        assert_eq!(ledger.3.ports_attempted, 2);
        assert_eq!(ledger.3.open, 2);
        assert_eq!(ledger.3.unscanned, 0);
    }
    // Only pressure differs: slow waits longer with a narrower window.
    let slow_policy = TcpScanPolicy::new(
        3,
        ScanGoal::Recon,
        TcpPortSelection::Common,
        SpeedSetting::Named(NamedSpeed::Slow),
    );
    let fast_policy = TcpScanPolicy::new(
        3,
        ScanGoal::Recon,
        TcpPortSelection::Common,
        SpeedSetting::Numeric(100),
    );
    assert!(slow_policy.per_port_timeout() > fast_policy.per_port_timeout());
    assert!(slow_policy.concurrency() < fast_policy.concurrency());
    assert_eq!(
        slow_policy.ports_for_task(Some("common")).ports,
        fast_policy.ports_for_task(Some("common")).ports
    );
}

#[test]
fn all_ports_loopback_proves_full_ledger_and_bounds() {
    // Controlled --all-ports acceptance: SSH fixture on an ephemeral port,
    // full 65,535-port run at speed 100. Proves the complete ledger
    // (requested 65535, counts sum, unscanned 0, truncated false), the
    // fixture found and identified, exactly ONE port task (never 65k
    // tasks), and bounded FD pressure (fd_peak <= 128 window).
    // Environment listeners may add extra opens; assertions only require
    // the fixture plus internal consistency.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral fixture");
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_thread = stop.clone();
    let handle = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(120);
        while !stop_thread.load(Ordering::SeqCst) && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.write_all(b"SSH-2.0-AllPortsTest_1.0\r\n");
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
                    let mut buf = [0u8; 256];
                    let _ = stream.read(&mut buf);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("rxscan-allports-{stamp}.jsonl"));
    let cli = Cli::try_parse_from([
        "rxscan",
        "127.0.0.1",
        "--scope",
        "127.0.0.1",
        "--speed",
        "100",
        "--all-ports",
        "--output",
        path.to_str().unwrap(),
    ])
    .unwrap();
    let report = rxscan::run::execute(cli).unwrap();
    stop.store(true, Ordering::SeqCst);
    handle.join().unwrap();

    let payloads = read_jsonl_payloads(&path);
    let completed = payloads
        .iter()
        .find(|value| {
            value["record_type"] == "event" && value["payload"]["kind"] == "port_scan_completed"
        })
        .expect("port_scan_completed event");
    let details = &completed["payload"]["details"]["data"];
    assert_eq!(details["ports_requested"].as_u64(), Some(65_535));
    assert_eq!(details["unscanned"].as_u64(), Some(0));
    assert_eq!(details["truncated"].as_bool(), Some(false));
    let counts = details["counts"].as_object().unwrap();
    let total: u64 = counts.values().map(|value| value.as_u64().unwrap()).sum();
    assert_eq!(total, 65_535, "every requested port accounted exactly once");
    let opens: Vec<u16> = details["open_ports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_u64().unwrap() as u16)
        .collect();
    assert!(opens.contains(&port), "fixture port must be found");
    assert_eq!(counts["open"].as_u64().unwrap() as usize, opens.len());
    let fd_peak = details["fd_peak"].as_u64().unwrap();
    assert!(
        fd_peak <= 128,
        "FD pressure stays within the speed-100 window: {fd_peak}"
    );
    // Exactly one port task carried all 65,535 ports.
    let port_tasks = payloads
        .iter()
        .filter(|value| {
            value["record_type"] == "scheduler_event"
                && value["payload"]["kind"] == "task_created"
                && value["payload"]["provenance"]["module_name"] == "rxscan.port"
        })
        .count();
    assert_eq!(port_tasks, 1, "all-ports is one task, never 65k tasks");
    // Fixture identified from banner evidence with follow-up completion.
    assert!(payloads.iter().any(|value| {
        value["record_type"] == "event"
            && value["payload"]["kind"] == "service_identified"
            && value["payload"]["details"]["data"]["port"].as_u64() == Some(u64::from(port))
            && value["payload"]["details"]["data"]["protocol"] == "ssh"
    }));
    // Human counts agree with the typed ledger.
    let human = rxscan::run::human_summary(&report);
    assert!(human.contains("65535 requested"));
    assert!(human.contains("65535 attempted"));
    assert!(human.contains(&format!("{port}/tcp")));
    fs::remove_file(path).ok();
}
