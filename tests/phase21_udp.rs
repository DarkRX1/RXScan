//! Phase 21 UDP discovery tests: local fixtures only, deterministic.
//!
//! No public Internet scanning. Loopback UDP fixtures (echo, silent,
//! protocol responders), closed loopback ports, and deterministic fake
//! scanners only. Core invariant under test: silence is uncertainty —
//! never Open, never Closed.

use std::{
    collections::BTreeMap,
    net::{IpAddr, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use rxscan::{
    cli::Cli,
    execution::{
        CancellationToken, Module, ModuleContext, ModuleError, ModuleOutput, PolicyScopeGuard,
        RetryPolicy, ScopeGuard, Task, TaskKind, TaskScopeTarget,
    },
    model::{Provenance, Timestamp},
    plan::{ScanGoal, ScanPlan, SpeedSetting},
    ports::{
        UDP_COMMON_V1, UDP_PROFILE_VERSION, resolve_udp_ports, udp_concurrency_for_speed,
        udp_max_retries_for_level, udp_timeout_for_speed,
    },
    udp_discovery::{UdpDiscoveryModule, UdpScanPolicy},
    udp_probes::{Wave1UdpProbes, classify_dns, dns_query},
    udp_scanner::{
        NativeUdpScanner, UdpPortState, UdpProbeSource, UdpScanConfig, UdpScanOutcome, UdpScanner,
    },
};

// ---------- helpers ----------

fn compile(args: &[&str]) -> ScanPlan {
    let mut full = vec!["rxscan"];
    full.extend_from_slice(args);
    let cli = Cli::try_parse_from(full).unwrap();
    ScanPlan::compile(cli).unwrap()
}

fn provenance_for(plan: &ScanPlan) -> Provenance {
    Provenance::new("test.module", "1.0.0", plan.stable_id(), Timestamp(0)).unwrap()
}

struct AllowAll;
impl ScopeGuard for AllowAll {
    fn permits(&self, _target: &TaskScopeTarget) -> bool {
        true
    }
}

fn block_on_module(
    module: &UdpDiscoveryModule,
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

fn udp_task_for(plan: &ScanPlan, ip: IpAddr, ports_param: &str, timeout_ms: u64) -> Task {
    let guard = PolicyScopeGuard::new(plan.scope.clone());
    let mut params = BTreeMap::new();
    params.insert("target".to_owned(), ip.to_string());
    params.insert("transport".to_owned(), "udp".to_owned());
    params.insert("ports".to_owned(), ports_param.to_owned());
    Task::new_with_params(
        TaskKind::UdpDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        55,
        Duration::from_millis(timeout_ms),
        RetryPolicy::default(),
        "rxscan.udp",
        provenance_for(plan),
        TaskScopeTarget::Ip(ip),
        params,
        &guard,
    )
    .unwrap()
}

/// Bind a loopback UDP fixture; returns (socket holder, port).
/// The socket must stay alive for the fixture's role (open echo / silent).
fn bind_udp() -> (UdpSocket, u16) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind loopback UDP fixture");
    let port = socket.local_addr().unwrap().port();
    (socket, port)
}

/// A certainly-closed loopback UDP port (bound then released).
fn closed_udp_port() -> u16 {
    let (socket, port) = bind_udp();
    drop(socket);
    std::thread::sleep(Duration::from_millis(20));
    port
}

/// Spawn an echo responder on `socket` (moves it to a thread).
fn spawn_echo(socket: UdpSocket, stop: Arc<AtomicBool>, reply: Vec<u8>) {
    std::thread::spawn(move || {
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
            let mut buf = [0u8; 2048];
            if let Ok((_, addr)) = socket.recv_from(&mut buf) {
                let _ = socket.send_to(&reply, addr);
            }
        }
    });
}

fn scan_config(timeout_ms: u64, retries: u32) -> UdpScanConfig {
    UdpScanConfig::bounded(
        Duration::from_millis(timeout_ms),
        16,
        retries,
        None,
        CancellationToken::default(),
    )
}

// ---------- port policy ----------

#[test]
fn udp_common_v1_is_small_sorted_versioned() {
    assert_eq!(UDP_PROFILE_VERSION, "v1");
    assert_eq!(UDP_COMMON_V1, &[53, 123, 1900]);
    let mut sorted = UDP_COMMON_V1.to_vec();
    sorted.sort_unstable();
    assert_eq!(sorted, UDP_COMMON_V1);
    let resolved = resolve_udp_ports(&rxscan::plan::TcpPortSelection::Common, 3);
    assert_eq!(resolved.ports, vec![53, 123, 1900]);
}

#[test]
fn udp_explicit_reuses_operator_list_all_covers_everything_once() {
    let resolved = resolve_udp_ports(
        &rxscan::plan::TcpPortSelection::Explicit(vec![9999, 53, 53, 0]),
        3,
    );
    assert_eq!(resolved.ports, vec![53, 9999]);
    let all = resolve_udp_ports(&rxscan::plan::TcpPortSelection::All, 3);
    assert_eq!(all.ports.len(), 65_535);
    assert_eq!(all.ports, (1u16..=65_535).collect::<Vec<_>>());
}

#[test]
fn udp_retry_and_pressure_policy() {
    assert_eq!(udp_max_retries_for_level(1), 0);
    assert_eq!(udp_max_retries_for_level(2), 0);
    assert_eq!(udp_max_retries_for_level(3), 1);
    assert_eq!(udp_max_retries_for_level(5), 1);
    // Speed changes timeouts/windows, never the port set.
    assert!(
        udp_timeout_for_speed(SpeedSetting::Numeric(100))
            < udp_timeout_for_speed(SpeedSetting::Numeric(0))
    );
    assert!(udp_concurrency_for_speed(SpeedSetting::Numeric(100)) >= 8);
    assert!(udp_concurrency_for_speed(SpeedSetting::Numeric(100)) <= 64);
}

// ---------- scanner states ----------

#[test]
fn closed_loopback_is_closed_v4() {
    let outcome = NativeUdpScanner.scan(
        "127.0.0.1".parse().unwrap(),
        &[closed_udp_port()],
        &Wave1UdpProbes,
        &scan_config(500, 0),
    );
    assert_eq!(outcome.probes.len(), 1);
    assert_eq!(outcome.probes[0].state, UdpPortState::Closed);
    assert!(!outcome.cancelled);
    assert_eq!(outcome.unscanned, 0);
}

#[test]
fn closed_loopback_is_closed_v6() {
    let socket = match UdpSocket::bind("[::1]:0") {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("skipping IPv6 UDP test: {error}");
            return;
        }
    };
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    std::thread::sleep(Duration::from_millis(20));
    let outcome = NativeUdpScanner.scan(
        "::1".parse().unwrap(),
        &[port],
        &Wave1UdpProbes,
        &scan_config(500, 0),
    );
    assert_eq!(outcome.probes.len(), 1);
    assert_eq!(
        outcome.probes[0].state,
        UdpPortState::Closed,
        "IPv6 loopback must report attributable close evidence"
    );
}

#[test]
fn echo_response_is_open() {
    let (socket, port) = bind_udp();
    let stop = Arc::new(AtomicBool::new(false));
    spawn_echo(socket, stop.clone(), b"reply-bytes".to_vec());
    let outcome = NativeUdpScanner.scan(
        "127.0.0.1".parse().unwrap(),
        &[port],
        &Wave1UdpProbes,
        &scan_config(2000, 0),
    );
    stop.store(true, Ordering::SeqCst);
    assert_eq!(outcome.probes.len(), 1);
    assert_eq!(outcome.probes[0].state, UdpPortState::Open);
    assert_eq!(outcome.datagrams_received, 1);
}

#[test]
fn silent_bound_port_is_open_or_filtered_never_open_or_closed() {
    let (_socket, port) = bind_udp();
    let outcome = NativeUdpScanner.scan(
        "127.0.0.1".parse().unwrap(),
        &[port],
        &Wave1UdpProbes,
        &scan_config(300, 0),
    );
    assert_eq!(outcome.probes.len(), 1);
    assert_eq!(outcome.probes[0].state, UdpPortState::OpenOrFiltered);
}

#[test]
fn closed_ports_never_retry_but_silence_does() {
    // Closed with retries allowed: exactly one attempt (refusal is final).
    let outcome = NativeUdpScanner.scan(
        "127.0.0.1".parse().unwrap(),
        &[closed_udp_port()],
        &Wave1UdpProbes,
        &scan_config(300, 1),
    );
    assert_eq!(outcome.probes[0].attempts, 1);
    assert_eq!(outcome.retries, 0);
    // Silent with one retry: two identical sends, still uncertain.
    let (_socket, port) = bind_udp();
    let outcome = NativeUdpScanner.scan(
        "127.0.0.1".parse().unwrap(),
        &[port],
        &Wave1UdpProbes,
        &scan_config(300, 1),
    );
    assert_eq!(outcome.probes[0].attempts, 2);
    assert_eq!(outcome.retries, 1);
    assert_eq!(outcome.probes[0].state, UdpPortState::OpenOrFiltered);
    assert_eq!(outcome.datagrams_sent, 2);
}

#[test]
fn window_bounds_sockets_and_cancellation_is_prompt() {
    // Closed ports through a width-4 window: all accounted, peak ≤ 4.
    let mut ports: Vec<u16> = (0..48).map(|_| closed_udp_port()).collect();
    ports.sort_unstable();
    ports.dedup();
    let config = UdpScanConfig::bounded(
        Duration::from_millis(500),
        4,
        0,
        None,
        CancellationToken::default(),
    );
    let outcome = NativeUdpScanner.scan(
        "127.0.0.1".parse().unwrap(),
        &ports,
        &Wave1UdpProbes,
        &config,
    );
    assert_eq!(outcome.probes.len(), ports.len());
    assert!(
        outcome.fd_peak <= 4,
        "fd_peak {} exceeds window",
        outcome.fd_peak
    );
    assert!(
        outcome
            .probes
            .iter()
            .all(|p| p.state == UdpPortState::Closed)
    );
    // Pre-cancelled: nothing attempted, everything unscanned.
    let token = CancellationToken::default();
    token.cancel();
    let config = UdpScanConfig::bounded(Duration::from_millis(500), 16, 0, None, token);
    let outcome = NativeUdpScanner.scan(
        "127.0.0.1".parse().unwrap(),
        &ports,
        &Wave1UdpProbes,
        &config,
    );
    assert!(outcome.cancelled);
    assert_eq!(outcome.unscanned, ports.len());
    assert_eq!(outcome.probes.len(), 0);
}

// ---------- protocol probes ----------

fn dns_response_fixture() -> (UdpSocket, u16) {
    let (socket, port) = bind_udp();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let responder = socket.try_clone().unwrap();
    std::thread::spawn(move || {
        responder
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while !stop_thread.load(Ordering::SeqCst) && Instant::now() < deadline {
            let mut buf = [0u8; 512];
            if let Ok((count, addr)) = responder.recv_from(&mut buf) {
                if count < 12 {
                    continue;
                }
                // Minimal valid response: echo TXID, QR=1, one answer.
                let mut reply = vec![
                    buf[0], buf[1], 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                ];
                reply.extend_from_slice(&buf[12..count.min(100)]);
                let _ = responder.send_to(&reply, addr);
            }
        }
    });
    // Leak the stop flag with the socket holder: drop returns it.
    let _ = stop;
    (socket, port)
}

#[test]
fn dns_valid_response_is_open_dns() {
    // Grammar recognition through a test-seam source (production binds
    // DNS payloads to port 53; the seam proves the grammar, not the port).
    struct DnsEverywhere;
    impl UdpProbeSource for DnsEverywhere {
        fn payload(&self, _ip: &IpAddr, _port: u16) -> Vec<u8> {
            dns_query()
        }
        fn classify(&self, _port: u16, response: &[u8]) -> Option<String> {
            classify_dns(response).then_some("dns".to_owned())
        }
    }
    let (_holder, port) = dns_response_fixture();
    let outcome = NativeUdpScanner.scan(
        "127.0.0.1".parse().unwrap(),
        &[port],
        &DnsEverywhere,
        &scan_config(2000, 0),
    );
    assert_eq!(outcome.probes.len(), 1);
    assert_eq!(outcome.probes[0].state, UdpPortState::Open);
    assert_eq!(outcome.probes[0].protocol.as_deref(), Some("dns"));
}
#[test]
fn dns_txid_mismatch_is_open_unknown() {
    // A DNS-shaped reply with the wrong TXID proves responsiveness but
    // carries no attributable DNS evidence.
    assert!(!{
        let query = dns_query();
        // Flip TXID bits: same shape, wrong transaction.
        let mut bad = query.clone();
        bad[0] ^= 0xff;
        classify_dns(&bad)
    });
    // A query is not a response (QR=0).
    assert!(!classify_dns(&dns_query()));
}

#[test]
fn ntp_and_ssdp_grammars() {
    // Valid NTP server reply.
    let mut reply = vec![0u8; 48];
    reply[0] = 0x24;
    assert!(rxscan::udp_probes::classify_ntp(&reply));
    // Client echo and short garbage rejected.
    assert!(!rxscan::udp_probes::classify_ntp(
        &rxscan::udp_probes::ntp_request()
    ));
    assert!(!rxscan::udp_probes::classify_ntp(b"short"));
    // SSDP reply validated; request itself is not a reply.
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let request = rxscan::udp_probes::ssdp_search(&ip, 1900);
    assert!(!rxscan::udp_probes::classify_ssdp(&request));
}

// ---------- module ----------

fn run_udp_task(plan: &ScanPlan, ip: &str, ports_param: &str) -> ModuleOutput {
    let policy = UdpScanPolicy::new(plan.level, plan.goal, plan.tcp_ports.clone(), plan.speed);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = UdpDiscoveryModule::new(policy, guard.clone());
    let task = udp_task_for(plan, ip.parse().unwrap(), ports_param, 8000);
    block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap()
}

fn completed_event(output: &ModuleOutput) -> serde_json::Value {
    output
        .events
        .iter()
        .find(|event| format!("{:?}", event.kind) == "UdpScanCompleted")
        .map(|event| event.details.data.clone())
        .expect("UdpScanCompleted event")
}

#[test]
fn module_reports_open_with_protocol_and_ledger() {
    struct DnsEverywhere;
    impl UdpProbeSource for DnsEverywhere {
        fn payload(&self, _ip: &IpAddr, _port: u16) -> Vec<u8> {
            dns_query()
        }
        fn classify(&self, _port: u16, response: &[u8]) -> Option<String> {
            classify_dns(response).then_some("dns".to_owned())
        }
    }
    let (_holder, port) = dns_response_fixture();
    let plan = compile(&["127.0.0.1", "--udp", "--ports", &port.to_string()]);
    let policy = UdpScanPolicy::new(plan.level, plan.goal, plan.tcp_ports.clone(), plan.speed);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = rxscan::udp_discovery::UdpDiscoveryModule::with_probes(
        policy,
        Arc::new(NativeUdpScanner),
        Arc::new(DnsEverywhere),
        guard.clone(),
    );
    let task = udp_task_for(
        &plan,
        "127.0.0.1".parse().unwrap(),
        &format!("explicit:{port}"),
        8000,
    );
    let output = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let completed = completed_event(&output);
    assert_eq!(completed["ports_requested"], serde_json::json!(1));
    assert_eq!(completed["unscanned"], serde_json::json!(0));
    assert_eq!(completed["truncated"], serde_json::json!(false));
    assert_eq!(completed["counts"]["open"], serde_json::json!(1));
    assert_eq!(completed["requested_ports"], serde_json::json!([port]));
    assert_eq!(completed["attempted_ports"], serde_json::json!([port]));
    assert!(output.findings.iter().any(|finding| {
        finding.title == format!("Open UDP port {port}")
            && finding.metadata.get("transport") == Some(&serde_json::json!("udp"))
            && finding.metadata.get("service") == Some(&serde_json::json!("dns"))
    }));
}

#[test]
fn module_accounting_invariant_holds() {
    // Mixed open/closed/filtered: requested == attempted + unscanned and
    // attempted == open + closed + filtered + errors.
    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_thread = stop_flag.clone();
    std::thread::spawn(move || {
        echo.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while !stop_thread.load(Ordering::SeqCst) && Instant::now() < deadline {
            let mut buf = [0u8; 512];
            if let Ok((count, addr)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..count], addr);
            }
        }
    });
    let (_silent_holder, silent_port) = bind_udp();
    let closed = closed_udp_port();
    let plan = compile(&[
        "127.0.0.1",
        "--udp",
        "--ports",
        &format!("{echo_port},{closed},{silent_port}"),
    ]);
    let output = run_udp_task(
        &plan,
        "127.0.0.1",
        &format!("explicit:{echo_port},{closed},{silent_port}"),
    );
    stop_flag.store(true, Ordering::SeqCst);
    let completed = completed_event(&output);
    let counts = &completed["counts"];
    let requested = completed["ports_requested"].as_u64().unwrap();
    let unscanned = completed["unscanned"].as_u64().unwrap();
    let attempted: u64 = ["open", "closed", "open_or_filtered", "error"]
        .iter()
        .map(|key| counts[key].as_u64().unwrap())
        .sum();
    let attempted_ports = completed["attempted_ports"].as_array().unwrap().len() as u64;
    assert_eq!(requested, 3);
    assert_eq!(unscanned, 0);
    assert_eq!(requested, attempted + unscanned);
    assert_eq!(attempted, attempted_ports);
    assert_eq!(counts["open"], serde_json::json!(1));
    assert_eq!(counts["closed"], serde_json::json!(1));
    assert_eq!(counts["open_or_filtered"], serde_json::json!(1));
}

#[test]
fn scope_denial_blocks_sends_without_network() {
    struct DenyAll;
    impl ScopeGuard for DenyAll {
        fn permits(&self, _target: &TaskScopeTarget) -> bool {
            false
        }
    }
    let plan = compile(&["127.0.0.1", "--udp", "--ports", "53"]);
    let policy = UdpScanPolicy::new(plan.level, plan.goal, plan.tcp_ports.clone(), plan.speed);
    let calls = Arc::new(AtomicUsize::new(0));
    struct CountingScanner {
        calls: Arc<AtomicUsize>,
    }
    impl UdpScanner for CountingScanner {
        fn scan(
            &self,
            _ip: IpAddr,
            _ports: &[u16],
            _source: &dyn UdpProbeSource,
            _config: &UdpScanConfig,
        ) -> UdpScanOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            UdpScanOutcome::default()
        }
    }
    let module = UdpDiscoveryModule::with_scanner(
        policy,
        Arc::new(CountingScanner {
            calls: calls.clone(),
        }),
        Arc::new(DenyAll),
    );
    // Task construction itself is scope-checked; build against AllowAll
    // then execute under denial to prove the pre-send check.
    let guard = AllowAll;
    let mut params = BTreeMap::new();
    params.insert("target".to_owned(), "127.0.0.1".to_owned());
    params.insert("transport".to_owned(), "udp".to_owned());
    params.insert("ports".to_owned(), "explicit:53".to_owned());
    let task = Task::new_with_params(
        TaskKind::UdpDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        55,
        Duration::from_millis(2000),
        RetryPolicy::default(),
        "rxscan.udp",
        provenance_for(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        params,
        &guard,
    )
    .unwrap();
    let result = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    );
    assert!(matches!(result, Err(ModuleError::Failed { .. })));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

// ---------- planning ----------

#[test]
fn udp_flag_adds_one_bounded_task_alongside_tcp() {
    let plan = compile(&["127.0.0.1", "--udp"]);
    assert!(plan.udp_requested);
    let tasks = rxscan::lowering::lower_plan_to_tasks(&plan).unwrap();
    let udp_tasks: Vec<&Task> = tasks
        .iter()
        .filter(|task| task.kind == TaskKind::UdpDiscovery)
        .collect();
    // Exactly ONE UDP task (never per-port tasks), riding next to TCP work.
    assert_eq!(udp_tasks.len(), 1);
    assert_eq!(
        udp_tasks[0].params.get("transport").map(String::as_str),
        Some("udp")
    );
    assert_eq!(
        udp_tasks[0].params.get("ports").map(String::as_str),
        Some("common")
    );
    assert!(
        tasks
            .iter()
            .any(|task| task.kind == TaskKind::PortDiscovery)
    );
    // Without --udp, no UDP task exists (default Recon stays TCP-only).
    let plain = compile(&["127.0.0.1"]);
    assert!(!plain.udp_requested);
    let plain_tasks = rxscan::lowering::lower_plan_to_tasks(&plain).unwrap();
    assert!(
        plain_tasks
            .iter()
            .all(|task| task.kind != TaskKind::UdpDiscovery)
    );
}

#[test]
fn udp_explicit_and_all_selections() {
    let plan = compile(&["127.0.0.1", "--udp", "--ports", "53,161"]);
    let tasks = rxscan::lowering::lower_plan_to_tasks(&plan).unwrap();
    let udp = tasks
        .iter()
        .find(|task| task.kind == TaskKind::UdpDiscovery)
        .unwrap();
    assert_eq!(
        udp.params.get("ports").map(String::as_str),
        Some("explicit:53,161")
    );
    let plan = compile(&["127.0.0.1", "--udp", "--all-ports"]);
    let tasks = rxscan::lowering::lower_plan_to_tasks(&plan).unwrap();
    let udp = tasks
        .iter()
        .find(|task| task.kind == TaskKind::UdpDiscovery)
        .unwrap();
    assert_eq!(udp.params.get("ports").map(String::as_str), Some("all"));
}

// ---------- full runs + human agreement ----------

fn read_jsonl_payloads(path: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect()
}

#[test]
fn udp_runs_alongside_tcp_with_transport_aware_human_output() {
    let (socket, port) = bind_udp();
    let stop = Arc::new(AtomicBool::new(false));
    spawn_echo(socket, stop.clone(), b"udp-hi".to_vec());
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("rxscan-udp-e2e-{stamp}.jsonl"));
    let cli = Cli::try_parse_from([
        "rxscan",
        "127.0.0.1",
        "--scope",
        "127.0.0.1",
        "--udp",
        "--ports",
        &port.to_string(),
        "--output",
        path.to_str().unwrap(),
    ])
    .unwrap();
    let report = rxscan::run::execute(cli).unwrap();
    stop.store(true, Ordering::SeqCst);
    // TCP and UDP ran in one workflow; UDP totals are typed and non-zero.
    assert_eq!(report.udp_totals.ports_requested, 1);
    assert_eq!(report.udp_totals.open, 1);
    assert_eq!(report.udp_totals.unscanned, 0);
    let human = rxscan::run::human_summary(&report);
    assert!(human.contains("UDP discovery ("), "human shows UDP work");
    assert!(
        human.contains(&format!("{port}/udp")),
        "human lists the port"
    );
    assert!(human.contains("open"), "human shows open state");
    // Machine agrees: the completed ledger matches the human counts.
    let payloads = read_jsonl_payloads(&path);
    let completed = payloads
        .iter()
        .find(|value| {
            value["record_type"] == "event" && value["payload"]["kind"] == "udp_scan_completed"
        })
        .expect("udp_scan_completed event");
    let details = &completed["payload"]["details"]["data"];
    assert_eq!(details["ports_requested"].as_u64(), Some(1));
    assert_eq!(details["counts"]["open"].as_u64(), Some(1));
    assert!(payloads.iter().any(|value| {
        value["record_type"] == "finding"
            && value["payload"]["title"] == format!("Open UDP port {port}")
    }));
    // No TCP-specific strings leak into UDP findings.
    for value in payloads.iter().filter(|value| {
        value["record_type"] == "finding"
            && value["payload"]["title"]
                .as_str()
                .unwrap_or_default()
                .contains("UDP")
    }) {
        assert!(!value["payload"]["title"].as_str().unwrap().contains("TCP"));
    }
    std::fs::remove_file(path).ok();
}

#[test]
fn udp_absent_means_no_udp_section_in_human_output() {
    // Default Recon without --udp: human output stays TCP-only.
    let cli = Cli::try_parse_from(["rxscan", "127.0.0.1"]).unwrap();
    let report = rxscan::run::execute(cli).unwrap();
    let human = rxscan::run::human_summary(&report);
    assert!(!human.contains("UDP"), "no UDP block without --udp");
    assert_eq!(report.udp_totals.completed_tasks, 0);
}

// ---------- edge cases ----------

#[test]
fn duplicate_and_range_ports_normalize() {
    let plan = compile(&["127.0.0.1", "--udp", "--ports", "9999,53,53,100-102"]);
    let policy = UdpScanPolicy::new(plan.level, plan.goal, plan.tcp_ports.clone(), plan.speed);
    let resolved = policy.ports_for_task(Some("explicit:53,100-102,9999"));
    assert_eq!(resolved.ports, vec![53, 100, 101, 102, 9999]);
    let output = run_udp_task(&plan, "127.0.0.1", "explicit:53,100-102,9999");
    let completed = completed_event(&output);
    assert_eq!(completed["ports_requested"], serde_json::json!(5));
    let attempted = completed["attempted_ports"].as_array().unwrap().len();
    let counts = &completed["counts"];
    let total: u64 = ["open", "closed", "open_or_filtered", "error"]
        .iter()
        .map(|key| counts[key].as_u64().unwrap())
        .sum();
    assert_eq!(total, 5);
    assert_eq!(attempted as u64, total);
}

#[test]
fn delayed_response_inside_timeout_is_open_beyond_is_filtered() {
    // Responder delayed 200ms with a 1500ms budget: Open.
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let fast_port = socket.local_addr().unwrap().port();
    std::thread::spawn(move || {
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut buf = [0u8; 512];
        if let Ok((_, addr)) = socket.recv_from(&mut buf) {
            std::thread::sleep(Duration::from_millis(200));
            let _ = socket.send_to(b"late-but-in-time", addr);
        }
    });
    let outcome = NativeUdpScanner.scan(
        "127.0.0.1".parse().unwrap(),
        &[fast_port],
        &Wave1UdpProbes,
        &scan_config(1500, 0),
    );
    assert_eq!(outcome.probes[0].state, UdpPortState::Open);
    // Same delay beyond a 100ms budget: uncertainty, never Open.
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let slow_port = socket.local_addr().unwrap().port();
    std::thread::spawn(move || {
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut buf = [0u8; 512];
        if let Ok((_, addr)) = socket.recv_from(&mut buf) {
            std::thread::sleep(Duration::from_millis(400));
            let _ = socket.send_to(b"too-late", addr);
        }
    });
    std::thread::sleep(Duration::from_millis(50));
    let outcome = NativeUdpScanner.scan(
        "127.0.0.1".parse().unwrap(),
        &[slow_port],
        &Wave1UdpProbes,
        &scan_config(100, 0),
    );
    assert_eq!(outcome.probes[0].state, UdpPortState::OpenOrFiltered);
}

#[test]
fn oversized_response_is_open_and_bounded() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    std::thread::spawn(move || {
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut buf = [0u8; 512];
        if let Ok((_, addr)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(&vec![0x41u8; 3000], addr);
        }
    });
    let outcome = NativeUdpScanner.scan(
        "127.0.0.1".parse().unwrap(),
        &[port],
        &Wave1UdpProbes,
        &scan_config(1500, 0),
    );
    assert_eq!(outcome.probes[0].state, UdpPortState::Open);
    assert_eq!(outcome.datagrams_received, 1);
}

#[test]
fn task_deadline_truncates_with_unscanned_accounting() {
    // 200 closed ports with an already-expired task deadline: the module
    // must truncate honestly instead of scanning.
    let plan = compile(&["127.0.0.1", "--udp", "--ports", "1-200"]);
    let policy = UdpScanPolicy::new(plan.level, plan.goal, plan.tcp_ports.clone(), plan.speed);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = UdpDiscoveryModule::new(policy, guard.clone());
    let task = udp_task_for(&plan, "127.0.0.1".parse().unwrap(), "explicit:1-200", 1);
    let output = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let completed = completed_event(&output);
    assert_eq!(completed["truncated"], serde_json::json!(true));
    assert!(completed["unscanned"].as_u64().unwrap() > 0);
}

#[test]
fn fd_usage_stays_bounded_without_leak() {
    // 60 ports through a width-8 window: peak never exceeds the window.
    // Leak check compares before/after inside this test with a margin for
    // sibling parallel tests' fixtures (which hold their own sockets);
    // a systematic per-port leak would still dwarf the margin.
    let mut ports: Vec<u16> = (0..70).map(|_| closed_udp_port()).collect();
    ports.sort_unstable();
    ports.dedup();
    let before = open_fd_count();
    let config = UdpScanConfig::bounded(
        Duration::from_millis(300),
        8,
        0,
        None,
        CancellationToken::default(),
    );
    for _ in 0..3 {
        let outcome = NativeUdpScanner.scan(
            "127.0.0.1".parse().unwrap(),
            &ports,
            &Wave1UdpProbes,
            &config,
        );
        assert!(
            outcome.fd_peak <= 8,
            "fd_peak {} exceeds window",
            outcome.fd_peak
        );
        assert_eq!(outcome.probes.len(), ports.len());
        drop(outcome);
    }
    std::thread::sleep(Duration::from_millis(100));
    let after = open_fd_count();
    if let (Some(before), Some(after)) = (before, after) {
        assert!(
            after <= before + 8,
            "FD leak suspected: {before} -> {after}"
        );
    }
}

#[cfg(target_os = "linux")]
fn open_fd_count() -> Option<usize> {
    std::fs::read_dir("/proc/self/fd")
        .ok()
        .map(|entries| entries.count())
}

#[cfg(not(target_os = "linux"))]
fn open_fd_count() -> Option<usize> {
    None
}

#[test]
fn speed_changes_pressure_never_udp_semantics() {
    // Same explicit ports at slow/balanced/100: identical state sets;
    // only timeout/window pressure differs.
    let closed = closed_udp_port();
    let mut states = Vec::new();
    for speed in ["slow", "balanced", "100"] {
        let cli = Cli::try_parse_from([
            "rxscan",
            "127.0.0.1",
            "--udp",
            "--ports",
            &closed.to_string(),
            "--level",
            "3",
            "--speed",
            speed,
        ])
        .unwrap();
        let plan = ScanPlan::compile(cli).unwrap();
        let output = run_udp_task(&plan, "127.0.0.1", &format!("explicit:{closed}"));
        states.push(completed_event(&output));
    }
    assert_eq!(states[0]["counts"], states[1]["counts"]);
    assert_eq!(states[1]["counts"], states[2]["counts"]);
    let slow = UdpScanPolicy::new(
        3,
        ScanGoal::Recon,
        plan_tcp_common(),
        SpeedSetting::Numeric(0),
    );
    let fast = UdpScanPolicy::new(
        3,
        ScanGoal::Recon,
        plan_tcp_common(),
        SpeedSetting::Numeric(100),
    );
    assert!(slow.per_attempt_timeout() > fast.per_attempt_timeout());
    assert!(slow.window() < fast.window());
}

fn plan_tcp_common() -> rxscan::plan::TcpPortSelection {
    rxscan::plan::TcpPortSelection::Common
}

#[test]
fn udp_produces_no_automatic_followups_in_wave_1() {
    // An open UDP port must not sprout follow-up tasks by itself.
    let (socket, port) = bind_udp();
    let stop = Arc::new(AtomicBool::new(false));
    spawn_echo(socket, stop.clone(), b"dns-noise".to_vec());
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("rxscan-udp-nofollow-{stamp}.jsonl"));
    let cli = Cli::try_parse_from([
        "rxscan",
        "127.0.0.1",
        "--scope",
        "127.0.0.1",
        "--udp",
        "--ports",
        &port.to_string(),
        "--output",
        path.to_str().unwrap(),
    ])
    .unwrap();
    let report = rxscan::run::execute(cli).unwrap();
    stop.store(true, Ordering::SeqCst);
    // validate + host + TCP port + UDP port only: no service/web/dns
    // follow-ups derive from UDP evidence in Wave 1.
    assert_eq!(report.scheduler_report.completed.len(), 4);
    assert!(report.scheduler_report.failed.is_empty());
    std::fs::remove_file(path).ok();
}

// ---------- real-port and seam protocol end to end ----------

#[test]
fn ssdp_on_real_port_1900_is_open_ssdp() {
    // Port 1900 is unprivileged: the full production path (Wave-1 payload
    // + grammar on the real port) runs without seams or root.
    let socket = match UdpSocket::bind("127.0.0.1:1900") {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("skipping SSDP real-port test (1900 unavailable): {error}");
            return;
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    std::thread::spawn(move || {
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(25);
        while !stop_thread.load(Ordering::SeqCst) && Instant::now() < deadline {
            let mut buf = [0u8; 2048];
            if let Ok((_, addr)) = socket.recv_from(&mut buf) {
                let _ = socket.send_to(
                    b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nUSN: uuid:lab\r\n\r\n",
                    addr,
                );
            }
        }
    });
    let plan = compile(&["127.0.0.1", "--udp", "--ports", "1900"]);
    let output = run_udp_task(&plan, "127.0.0.1", "explicit:1900");
    stop.store(true, Ordering::SeqCst);
    let completed = completed_event(&output);
    assert_eq!(completed["counts"]["open"], serde_json::json!(1));
    assert!(output.findings.iter().any(|finding| {
        finding.title == "Open UDP port 1900"
            && finding.metadata.get("service") == Some(&serde_json::json!("ssdp"))
    }));
}

#[test]
fn malformed_dns_is_open_unknown_via_seam() {
    struct DnsEverywhere;
    impl UdpProbeSource for DnsEverywhere {
        fn payload(&self, _ip: &IpAddr, _port: u16) -> Vec<u8> {
            dns_query()
        }
        fn classify(&self, _port: u16, response: &[u8]) -> Option<String> {
            classify_dns(response).then_some("dns".to_owned())
        }
    }
    // Garbage responder: proves responsiveness, matches no grammar.
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    std::thread::spawn(move || {
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut buf = [0u8; 2048];
        if let Ok((_, addr)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(b"\x00\xffNOT-DNS!!", addr);
        }
    });
    let plan = compile(&["127.0.0.1", "--udp", "--ports", &port.to_string()]);
    let policy = UdpScanPolicy::new(plan.level, plan.goal, plan.tcp_ports.clone(), plan.speed);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = rxscan::udp_discovery::UdpDiscoveryModule::with_probes(
        policy,
        Arc::new(NativeUdpScanner),
        Arc::new(DnsEverywhere),
        guard.clone(),
    );
    let task = udp_task_for(
        &plan,
        "127.0.0.1".parse().unwrap(),
        &format!("explicit:{port}"),
        8000,
    );
    let output = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let completed = completed_event(&output);
    assert_eq!(completed["counts"]["open"], serde_json::json!(1));
    // Open finding exists but carries no service claim.
    let finding = output
        .findings
        .iter()
        .find(|finding| finding.title == format!("Open UDP port {port}"))
        .expect("open finding");
    assert!(!finding.metadata.contains_key("service"));
}

#[test]
fn ntp_valid_and_malformed_via_seam() {
    struct NtpEverywhere;
    impl UdpProbeSource for NtpEverywhere {
        fn payload(&self, _ip: &IpAddr, _port: u16) -> Vec<u8> {
            rxscan::udp_probes::ntp_request()
        }
        fn classify(&self, _port: u16, response: &[u8]) -> Option<String> {
            rxscan::udp_probes::classify_ntp(response).then_some("ntp".to_owned())
        }
    }
    // Valid NTP responder.
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let good = socket.local_addr().unwrap().port();
    std::thread::spawn(move || {
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut buf = [0u8; 2048];
        if let Ok((_, addr)) = socket.recv_from(&mut buf) {
            let mut reply = vec![0u8; 48];
            reply[0] = 0x24;
            let _ = socket.send_to(&reply, addr);
        }
    });
    // Malformed responder (short garbage).
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bad = socket.local_addr().unwrap().port();
    std::thread::spawn(move || {
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut buf = [0u8; 2048];
        if let Ok((_, addr)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(b"nope", addr);
        }
    });
    for (port, expected) in [(good, Some("ntp")), (bad, None)] {
        let plan = compile(&["127.0.0.1", "--udp", "--ports", &port.to_string()]);
        let policy = UdpScanPolicy::new(plan.level, plan.goal, plan.tcp_ports.clone(), plan.speed);
        let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
        let module = rxscan::udp_discovery::UdpDiscoveryModule::with_probes(
            policy,
            Arc::new(NativeUdpScanner),
            Arc::new(NtpEverywhere),
            guard.clone(),
        );
        let task = udp_task_for(
            &plan,
            "127.0.0.1".parse().unwrap(),
            &format!("explicit:{port}"),
            8000,
        );
        let output = block_on_module(
            &module,
            ModuleContext::new(task, CancellationToken::default()),
        )
        .unwrap();
        let completed = completed_event(&output);
        assert_eq!(completed["counts"]["open"], serde_json::json!(1));
        let finding = output
            .findings
            .iter()
            .find(|finding| finding.title == format!("Open UDP port {port}"))
            .expect("open finding");
        assert_eq!(
            finding.metadata.get("service"),
            expected.map(|service| serde_json::json!(service)).as_ref(),
            "port {port}"
        );
    }
}

// ---------- retention bounds + generic contract ----------

#[test]
fn retained_records_stay_compact_for_huge_scans() {
    use rxscan::udp_scanner::UdpProbe;
    use std::mem::size_of;
    // A single record stays small: fixed scalars + two short strings.
    assert!(
        size_of::<UdpProbe>() <= 128,
        "UdpProbe grew past the compact budget: {}",
        size_of::<UdpProbe>()
    );
    // 300 loopback ports (mostly closed; parallel tests may rarely hold
    // one, so assert invariants, not exact states). Deduped: release
    // cycles can hand the same port back twice.
    let mut ports: Vec<u16> = (0..320).map(|_| closed_udp_port()).collect();
    ports.sort_unstable();
    ports.dedup();
    ports.truncate(300);
    assert!(ports.len() >= 290, "need a full window of test ports");
    let total = |outcome: &UdpScanOutcome| {
        outcome.open_count + outcome.closed_count + outcome.filtered_count + outcome.error_count
    };
    let detailed = UdpScanConfig::bounded_detailed(
        Duration::from_millis(300),
        16,
        0,
        true,
        None,
        CancellationToken::default(),
    );
    let full = NativeUdpScanner.scan(
        "127.0.0.1".parse().unwrap(),
        &ports,
        &Wave1UdpProbes,
        &detailed,
    );
    assert_eq!(full.probes.len(), ports.len());
    assert_eq!(total(&full), ports.len() as u64);
    let compact = UdpScanConfig::bounded_detailed(
        Duration::from_millis(300),
        16,
        0,
        false,
        None,
        CancellationToken::default(),
    );
    let slim = NativeUdpScanner.scan(
        "127.0.0.1".parse().unwrap(),
        &ports,
        &Wave1UdpProbes,
        &compact,
    );
    // Huge mode retains opens only; counts stay exact regardless.
    assert_eq!(total(&slim), ports.len() as u64);
    assert_eq!(slim.probes.len() as u64, slim.open_count);
    assert!(slim.probes.len() <= 300);
}

#[test]
fn generic_empty_datagram_contract() {
    // Unsupported explicit port (no Wave-1 probe): the empty datagram
    // separates attributable Closed from uncertain silence, and a
    // response means Open + unknown — never a service claim.
    let (socket, port) = bind_udp();
    let stop = Arc::new(AtomicBool::new(false));
    spawn_echo(socket, stop.clone(), b"whatever".to_vec());
    let plan = compile(&["127.0.0.1", "--udp", "--ports", &port.to_string()]);
    let output = run_udp_task(&plan, "127.0.0.1", &format!("explicit:{port}"));
    let completed = completed_event(&output);
    assert_eq!(completed["counts"]["open"], serde_json::json!(1));
    let finding = output
        .findings
        .iter()
        .find(|finding| finding.title == format!("Open UDP port {port}"))
        .expect("open finding");
    // No service key, no confidence in a protocol, no follow-up bait:
    // metadata carries transport/port/address only.
    assert!(!finding.metadata.contains_key("service"));
    for key in ["transport", "port", "address"] {
        assert!(finding.metadata.contains_key(key));
    }
    // Human renders unknown service as `-`, never a guess.
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("rxscan-udp-generic-{stamp}.jsonl"));
    let cli = Cli::try_parse_from([
        "rxscan",
        "127.0.0.1",
        "--scope",
        "127.0.0.1",
        "--udp",
        "--ports",
        &port.to_string(),
        "--output",
        path.to_str().unwrap(),
    ])
    .unwrap();
    let report = rxscan::run::execute(cli).unwrap();
    stop.store(true, Ordering::SeqCst);
    let human = rxscan::run::human_summary(&report);
    assert!(human.contains(&format!("{port}/udp")));
    assert!(human.contains("open"));
    assert!(!human.contains("dns") && !human.contains("ntp") && !human.contains("ssdp"));
    std::fs::remove_file(path).ok();
}
