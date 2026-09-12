//! Phase 5 host-discovery tests: safe, local-only, deterministic.
//!
//! No public Internet hosts. Loopback, temporary TCP listeners, and
//! deterministic fake/mock backends only.

use std::{
    collections::BTreeMap,
    fs,
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
    discovery::{
        AddressFamily, DiscoveryMode, DiscoveryTechnique, HostDiscoveryPolicy, HostState,
        ProbeOutcome, ProbeRecord, conclude_state, expand_cidr_bounded, parse_discovery_ports,
        probe_timeout_ms_for_speed,
    },
    execution::{
        BudgetLimits, CancellationToken, DecisionEngine, Module, ModuleContext, ModuleError,
        ModuleFuture, ModuleOutput, PolicyScopeGuard, RetryPolicy, Scheduler, ScopeGuard,
        SpeedGovernor, Task, TaskKind, TaskScopeTarget, VecEventSink,
    },
    host_discovery::{HostDiscoveryModule, HostDiscoveryResult},
    icmp::IcmpProber,
    model::{Confidence, Provenance, SCHEMA_VERSION, Timestamp},
    output::parse_envelope_payload,
    plan::{ScanPlan, SpeedSetting},
    tcp_probe::TcpProber,
};

// ---------- helpers ----------

fn compile(args: &[&str]) -> ScanPlan {
    let mut full = vec!["rxscan"];
    full.extend_from_slice(args);
    let cli = Cli::try_parse_from(full).unwrap();
    ScanPlan::compile(cli).unwrap()
}

fn plan_for(target: &str) -> ScanPlan {
    compile(&[target, "--level", "3", "--discover"])
}

fn provenance_for(plan: &ScanPlan) -> Provenance {
    Provenance::new("test.module", "5.0.0", plan.stable_id(), Timestamp(0)).unwrap()
}

struct AllowAll;
impl ScopeGuard for AllowAll {
    fn permits(&self, _target: &TaskScopeTarget) -> bool {
        true
    }
}

#[derive(Debug)]
struct FakeIcmp {
    outcome: ProbeOutcome,
    calls: Arc<AtomicUsize>,
}

impl FakeIcmp {
    fn success(calls: Arc<AtomicUsize>) -> Self {
        Self {
            outcome: ProbeOutcome::Success {
                latency: Duration::from_millis(1),
                detail: "fake ICMP echo reply".to_owned(),
            },
            calls,
        }
    }

    fn timeout(calls: Arc<AtomicUsize>) -> Self {
        Self {
            outcome: ProbeOutcome::Timeout,
            calls,
        }
    }

    fn unavailable(calls: Arc<AtomicUsize>) -> Self {
        Self {
            outcome: ProbeOutcome::Unavailable {
                reason: "ICMP probe unavailable: insufficient privileges (fake)".to_owned(),
            },
            calls,
        }
    }
}

impl IcmpProber for FakeIcmp {
    fn probe(&self, _ip: IpAddr, _timeout: Duration, cancel: &CancellationToken) -> ProbeOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if cancel.is_cancelled() {
            return ProbeOutcome::Cancelled;
        }
        self.outcome.clone()
    }
}

#[derive(Debug)]
struct FakeTcp {
    /// Ports that return Alive (refused-style). Others time out.
    alive_ports: Vec<u16>,
    unreachable_ports: Vec<u16>,
    unavailable: bool,
    calls: Arc<AtomicUsize>,
    delay_ms: u64,
}

impl FakeTcp {
    fn alive_on(alive_ports: Vec<u16>, calls: Arc<AtomicUsize>) -> Self {
        Self {
            alive_ports,
            unreachable_ports: Vec::new(),
            unavailable: false,
            calls,
            delay_ms: 0,
        }
    }

    fn timeout(calls: Arc<AtomicUsize>) -> Self {
        Self {
            alive_ports: Vec::new(),
            unreachable_ports: Vec::new(),
            unavailable: false,
            calls,
            delay_ms: 0,
        }
    }
}

impl TcpProber for FakeTcp {
    fn probe(
        &self,
        ip: IpAddr,
        port: u16,
        _timeout: Duration,
        cancel: &CancellationToken,
    ) -> ProbeOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if cancel.is_cancelled() {
            return ProbeOutcome::Cancelled;
        }
        if self.delay_ms > 0 {
            // Cooperative sleep so cancellation stays prompt.
            let started = Instant::now();
            while started.elapsed() < Duration::from_millis(self.delay_ms) {
                if cancel.is_cancelled() {
                    return ProbeOutcome::Cancelled;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        if self.unavailable {
            return ProbeOutcome::Unavailable {
                reason: "fake TCP unavailable".to_owned(),
            };
        }
        if self.unreachable_ports.contains(&port) {
            return ProbeOutcome::Unreachable {
                detail: format!("fake {ip}:{port} unreachable"),
            };
        }
        if self.alive_ports.contains(&port) {
            return ProbeOutcome::Success {
                latency: Duration::from_millis(1),
                detail: format!(
                    "TCP connection refused (RST) on {ip}:{port}; host responded so it is reachable (port closed)"
                ),
            };
        }
        ProbeOutcome::Timeout
    }
}

fn host_task_for(plan: &ScanPlan, ip: IpAddr, timeout_ms: u64, guard: &dyn ScopeGuard) -> Task {
    Task::new_with_params(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        80,
        Duration::from_millis(timeout_ms),
        RetryPolicy::default(),
        "rxscan.host",
        provenance_for(plan),
        TaskScopeTarget::Ip(ip),
        BTreeMap::from([
            ("target".to_owned(), ip.to_string()),
            ("discovery".to_owned(), "discover".to_owned()),
        ]),
        guard,
    )
    .unwrap()
}

fn block_on_module(
    module: &HostDiscoveryModule,
    context: ModuleContext,
) -> Result<ModuleOutput, ModuleError> {
    // Minimal cooperative block_on (mirrors scheduler worker path).
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

fn discovery_result_from(output: &ModuleOutput) -> HostDiscoveryResult {
    let evidence = output.evidence.first().expect("one evidence");
    let data = &evidence.details.data;
    serde_json::from_value::<HostDiscoveryResult>(serde_json::json!({
        "asset_id": evidence.asset_id.0,
        "target": data["target"].as_str().unwrap_or(""),
        "address": data["address"].as_str().map(str::to_owned),
        "address_family": data["address_family"].as_str().and_then(|family| match family {
            "v4" => Some(AddressFamily::V4),
            "v6" => Some(AddressFamily::V6),
            _ => None,
        }),
        "state": match data["state"].as_str().unwrap_or("unknown") {
            "alive" => HostState::Alive,
            "unreachable" => HostState::Unreachable,
            _ => HostState::Unknown,
        },
        "confidence": data["confidence"].as_u64().unwrap_or(0) as u8,
        "techniques": data["techniques"].as_array().map(|items| items.iter().map(|item| match item.as_str().unwrap_or("") {
            "icmp_echo" => DiscoveryTechnique::IcmpEcho,
            "tcp_connect" => DiscoveryTechnique::TcpConnect,
            "arp" => DiscoveryTechnique::Arp,
            _ => DiscoveryTechnique::NeighborDiscovery,
        }).collect::<Vec<DiscoveryTechnique>>()).unwrap_or_default(),
        "latency_ms": data["latency_ms"].as_u64(),
        "evidence": data["evidence"].as_str().unwrap_or(""),
        "probe_details": data["probe_details"].as_array().map(|items| items.iter().filter_map(|item| item.as_str().map(str::to_owned)).collect::<Vec<String>>()).unwrap_or_default(),
        "timestamp": data["timestamp"].as_u64().unwrap_or(0),
    }))
    .expect("evidence carries HostDiscoveryResult fields")
}

// ---------- loopback / address families ----------

#[test]
fn loopback_host_discovery_is_alive_with_evidence() {
    // Real probers against loopback: always Alive (ICMP reply or TCP RST).
    let plan = compile(&["127.0.0.1", "--discover", "--level", "3"]);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let policy = HostDiscoveryPolicy::for_level(3, DiscoveryMode::Discover, plan.speed, None);
    let module = HostDiscoveryModule::new(policy, guard.clone());
    let task = host_task_for(&plan, "127.0.0.1".parse().unwrap(), 5000, guard.as_ref());
    let context = ModuleContext::new(task, CancellationToken::default());
    let started = Instant::now();
    let output = block_on_module(&module, context).expect("loopback succeeds");
    assert!(started.elapsed() < Duration::from_secs(10));
    let result = discovery_result_from(&output);
    assert_eq!(result.state, HostState::Alive);
    assert!((85..=95).contains(&result.confidence));
    assert_eq!(result.address.as_deref(), Some("127.0.0.1"));
    assert_eq!(result.address_family, Some(AddressFamily::V4));
    assert!(!result.techniques.is_empty());
    assert!(result.latency_ms.is_some());
    assert!(result.evidence.contains("Alive"));
    assert!(!result.probe_details.is_empty());
    // Typed events: started + attempts + outcomes + concluded (+ discovered).
    let kinds: Vec<_> = output
        .events
        .iter()
        .map(|event| format!("{:?}", event.kind))
        .collect();
    assert!(kinds.contains(&"DiscoveryStarted".to_owned()));
    assert!(kinds.contains(&"HostStateConcluded".to_owned()));
    assert!(kinds.contains(&"HostDiscovered".to_owned()));
}

#[test]
fn ipv4_handling_uses_v4_family_and_stable_asset_id() {
    let plan = plan_for("192.0.2.10");
    let icmp_calls = Arc::new(AtomicUsize::new(0));
    let tcp_calls = Arc::new(AtomicUsize::new(0));
    let policy = HostDiscoveryPolicy::for_level(3, DiscoveryMode::Discover, plan.speed, None);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = HostDiscoveryModule::with_probers(
        policy,
        Arc::new(FakeIcmp::success(icmp_calls.clone())),
        Arc::new(FakeTcp::alive_on(vec![80], tcp_calls.clone())),
        guard.clone(),
    );
    let task = host_task_for(&plan, "192.0.2.10".parse().unwrap(), 2000, guard.as_ref());
    let output = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let result = discovery_result_from(&output);
    assert_eq!(result.address_family, Some(AddressFamily::V4));
    assert_eq!(result.state, HostState::Alive);
    assert!(result.asset_id.starts_with("asset_ip_"));
    // Stable: same IP yields same asset ID across runs.
    let again = rxscan::discovery::asset_id_for_ip(&"192.0.2.10".parse().unwrap());
    assert_eq!(result.asset_id, again);
}

#[test]
fn ipv6_target_handling_uses_v6_family() {
    let plan = compile(&["::1", "--discover", "--level", "3"]);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let policy = HostDiscoveryPolicy::for_level(3, DiscoveryMode::Discover, plan.speed, None);
    let module = HostDiscoveryModule::new(policy, guard.clone());
    let task = host_task_for(&plan, "::1".parse().unwrap(), 5000, guard.as_ref());
    let output = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let result = discovery_result_from(&output);
    assert_eq!(result.address_family, Some(AddressFamily::V6));
    assert_eq!(result.address.as_deref(), Some("::1"));
    assert_eq!(result.state, HostState::Alive);
}

// ---------- ICMP paths ----------

#[test]
fn icmp_success_path_reports_alive_with_high_confidence() {
    let plan = plan_for("192.0.2.10");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let policy = HostDiscoveryPolicy::for_level(2, DiscoveryMode::Ping, plan.speed, None);
    let module = HostDiscoveryModule::with_probers(
        policy,
        Arc::new(FakeIcmp::success(Arc::new(AtomicUsize::new(0)))),
        Arc::new(FakeTcp::timeout(Arc::new(AtomicUsize::new(0)))),
        guard.clone(),
    );
    let task = host_task_for(&plan, "192.0.2.10".parse().unwrap(), 2000, guard.as_ref());
    let output = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let result = discovery_result_from(&output);
    assert_eq!(result.state, HostState::Alive);
    assert_eq!(result.confidence, 95);
    assert!(result.techniques.contains(&DiscoveryTechnique::IcmpEcho));
}

#[test]
fn icmp_unavailable_permission_path_is_unknown_not_dead() {
    let plan = plan_for("192.0.2.10");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let policy = HostDiscoveryPolicy::for_level(3, DiscoveryMode::Discover, plan.speed, None);
    let module = HostDiscoveryModule::with_probers(
        policy,
        Arc::new(FakeIcmp::unavailable(Arc::new(AtomicUsize::new(0)))),
        Arc::new(FakeTcp::timeout(Arc::new(AtomicUsize::new(0)))),
        guard.clone(),
    );
    let task = host_task_for(&plan, "192.0.2.10".parse().unwrap(), 2000, guard.as_ref());
    let output = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let result = discovery_result_from(&output);
    assert_eq!(result.state, HostState::Unknown);
    // Mixed unavailable + timeouts => Unknown with moderate-low confidence
    // (20 only when every probe is unavailable; 30 otherwise). Either way it
    // must never be Unreachable/Alive from unavailable alone.
    assert!((20..=30).contains(&result.confidence));
    assert!(result.evidence.contains("unavailable") || result.evidence.contains("Unknown"));
    assert!(result.evidence.contains("No definitive") || result.evidence.contains("does not mean"));
    // Unavailable must never be reported as Unreachable.
    assert_ne!(result.state, HostState::Unreachable);
}

#[test]
fn icmp_timeout_reports_unknown_rather_than_false_dead() {
    let target: IpAddr = "192.0.2.10".parse().unwrap();
    let probes = vec![
        ProbeRecord::timeout(DiscoveryTechnique::IcmpEcho, target, None),
        ProbeRecord::timeout(DiscoveryTechnique::TcpConnect, target, Some(80)),
    ];
    let (state, confidence, _, evidence) = conclude_state(&probes);
    assert_eq!(state, HostState::Unknown);
    assert_eq!(confidence, 30);
    assert!(evidence.contains("Unknown"));
    assert!(evidence.contains("does not mean"));
}

#[test]
fn tcp_fallback_discovers_host_when_icmp_blocked() {
    let plan = plan_for("192.0.2.10");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let policy = HostDiscoveryPolicy::for_level(3, DiscoveryMode::Discover, plan.speed, None);
    let module = HostDiscoveryModule::with_probers(
        policy,
        Arc::new(FakeIcmp::timeout(Arc::new(AtomicUsize::new(0)))),
        Arc::new(FakeTcp::alive_on(
            vec![80, 443, 22],
            Arc::new(AtomicUsize::new(0)),
        )),
        guard.clone(),
    );
    let task = host_task_for(&plan, "192.0.2.10".parse().unwrap(), 3000, guard.as_ref());
    let output = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let result = discovery_result_from(&output);
    assert_eq!(result.state, HostState::Alive);
    assert_eq!(result.confidence, 85);
    assert!(result.techniques.contains(&DiscoveryTechnique::TcpConnect));
    assert!(result.evidence.contains("Alive"));
}

#[test]
fn tcp_connect_to_local_listener_is_alive() {
    // Controlled fixture: temporary local TCP listener proves reachability.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    let plan = compile(&["127.0.0.1", "--discover", "--level", "3"]);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let policy =
        HostDiscoveryPolicy::for_level(3, DiscoveryMode::Discover, plan.speed, Some(&[port]));
    let module = HostDiscoveryModule::new(policy, guard.clone());
    let task = host_task_for(&plan, "127.0.0.1".parse().unwrap(), 5000, guard.as_ref());
    let output = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let result = discovery_result_from(&output);
    assert_eq!(result.state, HostState::Alive);
    drop(listener);
}

#[test]
fn multiple_probe_evidence_is_correlated() {
    let target: IpAddr = "192.0.2.10".parse().unwrap();
    let probes = vec![
        ProbeRecord::timeout(DiscoveryTechnique::IcmpEcho, target, None),
        ProbeRecord::timeout(DiscoveryTechnique::IcmpEcho, target, None),
        ProbeRecord::timeout(DiscoveryTechnique::TcpConnect, target, Some(80)),
        ProbeRecord::success(
            DiscoveryTechnique::TcpConnect,
            target,
            Some(443),
            Duration::from_millis(2),
            "TCP connection refused (RST) on 192.0.2.10:443; host responded so it is reachable (port closed)",
        ),
    ];
    let (state, confidence, techniques, evidence) = conclude_state(&probes);
    assert_eq!(state, HostState::Alive);
    assert_eq!(confidence, 85);
    assert!(techniques.contains(&DiscoveryTechnique::IcmpEcho));
    assert!(techniques.contains(&DiscoveryTechnique::TcpConnect));
    assert!(evidence.contains("Alive"));
    // Unknown correlation keeps every probe line for audit.
    let unknown_probes = vec![
        ProbeRecord::timeout(DiscoveryTechnique::IcmpEcho, target, None),
        ProbeRecord::timeout(DiscoveryTechnique::TcpConnect, target, Some(80)),
    ];
    let (state, _, _, evidence) = conclude_state(&unknown_probes);
    assert_eq!(state, HostState::Unknown);
    assert!(evidence.contains("icmp_echo"));
    assert!(evidence.contains("tcp_connect"));
}

// ---------- cancellation / timeout / retries / concurrency ----------

#[test]
fn cancellation_is_observed_promptly_by_discovery() {
    let plan = plan_for("127.0.0.1");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let policy = HostDiscoveryPolicy::for_level(3, DiscoveryMode::Discover, plan.speed, None);
    let module = HostDiscoveryModule::with_probers(
        policy,
        Arc::new(FakeIcmp::timeout(Arc::new(AtomicUsize::new(0)))),
        Arc::new(FakeTcp::timeout(Arc::new(AtomicUsize::new(0)))),
        guard.clone(),
    );
    let task = host_task_for(&plan, "127.0.0.1".parse().unwrap(), 5000, guard.as_ref());
    let token = CancellationToken::default();
    token.cancel();
    let started = Instant::now();
    let result = block_on_module(&module, ModuleContext::new(task, token));
    assert!(matches!(result, Err(ModuleError::Cancelled)));
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "cancellation latency {:?} exceeds bound",
        started.elapsed()
    );
}

#[test]
fn timeout_is_bounded_and_frees_scheduler_slot() {
    use rxscan::execution::TaskState;
    let plan = plan_for("127.0.0.1");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let sink = Arc::new(VecEventSink::default());
    let mut scheduler = Scheduler::new(
        8,
        BudgetLimits {
            max_execution_time_ms: 5000,
            ..BudgetLimits::default()
        },
        SpeedGovernor::new(SpeedSetting::Numeric(100), 2).unwrap(),
        guard.clone(),
        sink,
    )
    .unwrap();
    // Slow fake: cooperative 800ms delay per TCP probe.
    struct SlowTcp {
        calls: Arc<AtomicUsize>,
    }
    impl TcpProber for SlowTcp {
        fn probe(
            &self,
            _ip: IpAddr,
            _port: u16,
            _timeout: Duration,
            cancel: &CancellationToken,
        ) -> ProbeOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let started = Instant::now();
            while started.elapsed() < Duration::from_millis(800) {
                if cancel.is_cancelled() {
                    return ProbeOutcome::Cancelled;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            ProbeOutcome::Timeout
        }
    }
    struct SlowIcmp;
    impl IcmpProber for SlowIcmp {
        fn probe(
            &self,
            _ip: IpAddr,
            _timeout: Duration,
            cancel: &CancellationToken,
        ) -> ProbeOutcome {
            if cancel.is_cancelled() {
                return ProbeOutcome::Cancelled;
            }
            ProbeOutcome::Timeout
        }
    }
    let policy = HostDiscoveryPolicy::for_level(3, DiscoveryMode::Discover, plan.speed, None);
    scheduler.register_module(Arc::new(HostDiscoveryModule::with_probers(
        policy,
        Arc::new(SlowIcmp),
        Arc::new(SlowTcp {
            calls: Arc::new(AtomicUsize::new(0)),
        }),
        guard.clone(),
    )));
    // Task timeout long enough that the module actually enters the slow TCP
    // probe (remaining >50ms after fast ICMP), but far shorter than the
    // 800ms fake delay so the scheduler timeout fires and frees the slot.
    let mut task = host_task_for(&plan, "127.0.0.1".parse().unwrap(), 150, guard.as_ref());
    task.retry_policy = RetryPolicy::default();
    let task_id = task.id.clone();
    scheduler.add_task(task).unwrap();
    let started = Instant::now();
    let report = scheduler.run().unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(
        report.timed_out.contains(&task_id),
        "expected timeout, got {report:?}"
    );
    assert_eq!(scheduler.task(&task_id).unwrap().state, TaskState::TimedOut);
}

#[test]
fn retries_are_bounded_for_probes_and_scheduler() {
    // ICMP attempts clamp to 1..=5.
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let cancel = CancellationToken::default();
    let fake = FakeIcmp::timeout(Arc::new(AtomicUsize::new(0)));
    let records = rxscan::icmp::icmp_probe_with_retries(
        &fake,
        target,
        10,
        Duration::from_millis(20),
        &cancel,
    );
    assert!(records.len() <= 5);
    let records =
        rxscan::icmp::icmp_probe_with_retries(&fake, target, 0, Duration::from_millis(20), &cancel);
    assert_eq!(records.len(), 1);
    // TCP ports truncate to 8.
    let fake_tcp = FakeTcp::timeout(Arc::new(AtomicUsize::new(0)));
    let many_ports: Vec<u16> = (1..=20).collect();
    let records = rxscan::tcp_probe::tcp_probe_ports(
        &fake_tcp,
        target,
        &many_ports,
        Duration::from_millis(5),
        &cancel,
        None,
    );
    assert!(records.len() <= 8);
    // Scheduler retry limit is bounded even at speed 100.
    let governor = SpeedGovernor::new(SpeedSetting::Numeric(100), 4).unwrap();
    assert!(governor.retry_limit() <= 4);
}

#[test]
fn concurrency_is_bounded_by_speed_and_budgets() {
    let plan = plan_for("127.0.0.1");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    struct TrackingModule {
        active: Arc<AtomicUsize>,
        maximum: Arc<AtomicUsize>,
    }
    impl Module for TrackingModule {
        fn kind(&self) -> TaskKind {
            TaskKind::HostDiscovery
        }
        fn execute(&self, context: ModuleContext) -> ModuleFuture {
            let active = self.active.clone();
            let maximum = self.maximum.clone();
            Box::pin(async move {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(current, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(20));
                active.fetch_sub(1, Ordering::SeqCst);
                if context.is_cancelled() {
                    return Err(ModuleError::Cancelled);
                }
                Ok(ModuleOutput::default())
            })
        }
    }
    let mut scheduler = Scheduler::new(
        32,
        BudgetLimits {
            max_concurrency: 2,
            ..BudgetLimits::default()
        },
        SpeedGovernor::new(SpeedSetting::Numeric(100), 2).unwrap(),
        guard.clone(),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler.register_module(Arc::new(TrackingModule {
        active: active.clone(),
        maximum: maximum.clone(),
    }));
    for index in 0..6 {
        // Distinct asset at construction time so canonical IDs differ.
        let task = Task::new_with_params(
            TaskKind::HostDiscovery,
            None,
            Vec::new(),
            Some(rxscan::model::AssetId(format!("host-{index}"))),
            plan.stable_id(),
            80,
            Duration::from_millis(2000),
            RetryPolicy::default(),
            "rxscan.host",
            provenance_for(&plan),
            TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
            BTreeMap::from([
                ("target".to_owned(), "127.0.0.1".to_owned()),
                ("discovery".to_owned(), "discover".to_owned()),
            ]),
            guard.as_ref(),
        )
        .unwrap();
        scheduler.add_task(task).unwrap();
    }
    let report = scheduler.run().unwrap();
    assert_eq!(report.completed.len(), 6);
    assert!(maximum.load(Ordering::SeqCst) <= 2);
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

// ---------- policy ----------

#[test]
fn speed_policy_influences_pressure_not_meaning() {
    let slow =
        HostDiscoveryPolicy::for_level(3, DiscoveryMode::Discover, SpeedSetting::Numeric(0), None);
    let fast = HostDiscoveryPolicy::for_level(
        3,
        DiscoveryMode::Discover,
        SpeedSetting::Numeric(100),
        None,
    );
    assert!(fast.tcp_timeout_ms < slow.tcp_timeout_ms);
    assert!(fast.icmp_timeout_ms < slow.icmp_timeout_ms);
    assert_eq!(slow.tcp_ports, fast.tcp_ports);
    assert_eq!(slow.icmp_attempts, fast.icmp_attempts);
    // Same probes conclude the same state at any speed.
    let target: IpAddr = "192.0.2.10".parse().unwrap();
    let probes = vec![ProbeRecord::timeout(
        DiscoveryTechnique::IcmpEcho,
        target,
        None,
    )];
    assert_eq!(conclude_state(&probes).0, HostState::Unknown);
    // Governor still caps speed 100 by max_concurrency.
    let capped = SpeedGovernor::new(SpeedSetting::Numeric(100), 3).unwrap();
    assert_eq!(capped.concurrency(), 3);
    // Probe timeout helper is bounded.
    assert!(probe_timeout_ms_for_speed(SpeedSetting::Numeric(100)) >= 300);
    assert!(probe_timeout_ms_for_speed(SpeedSetting::Numeric(0)) <= 3000);
}

#[test]
fn level_policy_influences_breadth_within_bounds() {
    let l1 = HostDiscoveryPolicy::for_level(
        1,
        DiscoveryMode::Lightweight,
        SpeedSetting::Numeric(50),
        None,
    );
    let l5 = HostDiscoveryPolicy::for_level(
        5,
        DiscoveryMode::Lightweight,
        SpeedSetting::Numeric(50),
        None,
    );
    assert!(l1.tcp_ports.len() < l5.tcp_ports.len());
    assert!(l1.icmp_attempts < l5.icmp_attempts);
    assert!(l5.tcp_ports.len() <= 5);
    assert!(l5.icmp_attempts <= 3);
    // Discover at L1 is promoted to multi-probe.
    let discover_l1 =
        HostDiscoveryPolicy::for_level(1, DiscoveryMode::Discover, SpeedSetting::Numeric(50), None);
    assert!(discover_l1.use_tcp);
    assert!(discover_l1.tcp_ports.len() >= 2);
    // Ping at L1 is ICMP-only minimal.
    let ping_l1 =
        HostDiscoveryPolicy::for_level(1, DiscoveryMode::Ping, SpeedSetting::Numeric(50), None);
    assert!(ping_l1.use_icmp);
    assert!(!ping_l1.use_tcp);
    // Ping at higher levels keeps a single-port TCP fallback.
    let ping_l3 =
        HostDiscoveryPolicy::for_level(3, DiscoveryMode::Ping, SpeedSetting::Numeric(50), None);
    assert!(ping_l3.use_tcp);
    assert_eq!(ping_l3.tcp_ports.len(), 1);
    // Custom discovery_ports override is bounded and sorted.
    let custom = parse_discovery_ports("443,80").unwrap();
    assert_eq!(custom, vec![80, 443]);
    assert!(parse_discovery_ports("80,80,80").unwrap().len() == 1);
    assert!(parse_discovery_ports("0").is_err());
    let policy = HostDiscoveryPolicy::for_level(
        5,
        DiscoveryMode::Discover,
        SpeedSetting::Numeric(50),
        Some(&[8080, 80]),
    );
    assert_eq!(policy.tcp_ports, vec![80, 8080]);
}

// ---------- CIDR / scope ----------

#[test]
fn cidr_scheduling_is_bounded_deterministic_and_ordered() {
    // 127.0.0.0/29 has 6 usable hosts (.1-.6) in deterministic order.
    let plan = compile(&["127.0.0.0/29", "--discover", "--level", "3"]);
    let first = rxscan::lowering::lower_plan_to_tasks(&plan).unwrap();
    let second = rxscan::lowering::lower_plan_to_tasks(&plan).unwrap();
    assert_eq!(
        rxscan::lowering::task_graph_fingerprint(&first),
        rxscan::lowering::task_graph_fingerprint(&second)
    );
    let host_tasks: Vec<&Task> = first
        .iter()
        .filter(|task| task.kind == TaskKind::HostDiscovery)
        .collect();
    assert_eq!(host_tasks.len(), 6);
    let mut hosts: Vec<IpAddr> = host_tasks
        .iter()
        .map(|task| match &task.scope_target {
            TaskScopeTarget::Ip(ip) => *ip,
            other => panic!("expected IP scope, got {other:?}"),
        })
        .collect();
    let mut sorted = hosts.clone();
    sorted.sort();
    assert_eq!(hosts.len(), sorted.len());
    // Deterministic order: sorted by task ID implies stable host order via
    // params; hosts themselves must be the expected set.
    hosts.sort();
    assert_eq!(
        hosts,
        vec![
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            "127.0.0.2".parse::<IpAddr>().unwrap(),
            "127.0.0.3".parse::<IpAddr>().unwrap(),
            "127.0.0.4".parse::<IpAddr>().unwrap(),
            "127.0.0.5".parse::<IpAddr>().unwrap(),
            "127.0.0.6".parse::<IpAddr>().unwrap(),
        ]
    );
}

#[test]
fn large_cidr_stays_bounded_by_max_hosts() {
    let plan = compile(&[
        "10.0.0.0/8",
        "--discover",
        "--level",
        "3",
        "--max-hosts",
        "4",
    ]);
    let tasks = rxscan::lowering::lower_plan_to_tasks(&plan).unwrap();
    let host_tasks: Vec<&Task> = tasks
        .iter()
        .filter(|task| task.kind == TaskKind::HostDiscovery)
        .collect();
    assert_eq!(host_tasks.len(), 4);
    // Deterministic bounded set: sorted hosts start at the range base.
    // (Task order is by canonical ID, so sort addresses before asserting.)
    let mut hosts: Vec<IpAddr> = host_tasks
        .iter()
        .map(|task| match &task.scope_target {
            TaskScopeTarget::Ip(ip) => *ip,
            _ => panic!("expected IP"),
        })
        .collect();
    hosts.sort();
    assert_eq!(hosts[0], "10.0.0.1".parse::<IpAddr>().unwrap());
}

#[test]
fn max_host_budget_defaults_and_validates() {
    assert_eq!(BudgetLimits::default().max_hosts, 256);
    let plan = compile(&["127.0.0.0/29", "--discover", "--level", "2"]);
    assert_eq!(plan.budgets.max_hosts, 256);
    let plan = compile(&[
        "127.0.0.0/29",
        "--discover",
        "--level",
        "2",
        "--max-hosts",
        "2",
    ]);
    assert_eq!(plan.budgets.max_hosts, 2);
    let tasks = rxscan::lowering::lower_plan_to_tasks(&plan).unwrap();
    let host_tasks: Vec<&Task> = tasks
        .iter()
        .filter(|task| task.kind == TaskKind::HostDiscovery)
        .collect();
    assert_eq!(host_tasks.len(), 2);
    // Zero/over-limit rejected fail-fast.
    assert!(Cli::try_parse_from(["rxscan", "127.0.0.1", "--max-hosts", "0"]).is_err());
    let cli = Cli::try_parse_from(["rxscan", "127.0.0.1", "--max-hosts", "999999999"]).unwrap();
    assert!(ScanPlan::compile(cli).is_err());
}

#[test]
fn cidr_exclusions_always_win() {
    let plan = compile(&[
        "127.0.0.0/29",
        "--discover",
        "--level",
        "2",
        "--exclude",
        "127.0.0.2",
    ]);
    let tasks = rxscan::lowering::lower_plan_to_tasks(&plan).unwrap();
    let hosts: Vec<IpAddr> = tasks
        .iter()
        .filter(|task| task.kind == TaskKind::HostDiscovery)
        .map(|task| match &task.scope_target {
            TaskScopeTarget::Ip(ip) => *ip,
            _ => panic!("expected IP"),
        })
        .collect();
    assert!(!hosts.contains(&"127.0.0.2".parse().unwrap()));
    assert_eq!(hosts.len(), 5);
    // Direct scope check: excluded host not permitted.
    assert!(!plan.scope.permits(Some("127.0.0.2".parse().unwrap()), None));
    assert!(plan.scope.permits(Some("127.0.0.1".parse().unwrap()), None));
}

#[test]
fn scope_guard_enforcement_is_fail_closed() {
    let plan = plan_for("192.0.2.10");
    let guard = PolicyScopeGuard::new(plan.scope.clone());
    // Out-of-scope admission rejected.
    let mut scheduler = Scheduler::new(
        8,
        BudgetLimits::default(),
        SpeedGovernor::new(SpeedSetting::Numeric(50), 2).unwrap(),
        Arc::new(PolicyScopeGuard::new(plan.scope.clone())),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler.register_module(Arc::new(FakeHostModule));
    let outsider = Task::new(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        50,
        Duration::from_millis(200),
        RetryPolicy::default(),
        "m",
        provenance_for(&plan),
        TaskScopeTarget::Ip("198.51.100.99".parse().unwrap()),
        &guard,
    );
    // Construction itself is fail-closed (guard rejects).
    assert!(outsider.is_err());
    // Lowering with emptied scope is fail-closed.
    let mut emptied = plan.clone();
    emptied.scope.allowed.clear();
    assert!(rxscan::lowering::lower_plan_to_tasks(&emptied).is_err());
    // No discovery-derived address may expand scope: resolved out-of-scope
    // IPs are skipped without probing (covered by module test below).
    let cidr = "192.0.2.0/30".parse::<ipnet::IpNet>().unwrap();
    let expanded = expand_cidr_bounded(cidr, &plan.scope, 100);
    for host in &expanded {
        assert!(plan.scope.permits(Some(*host), None));
    }
}

struct FakeHostModule;
impl Module for FakeHostModule {
    fn kind(&self) -> TaskKind {
        TaskKind::HostDiscovery
    }
    fn execute(&self, _context: ModuleContext) -> ModuleFuture {
        Box::pin(async { Ok(ModuleOutput::default()) })
    }
}

#[test]
fn stale_scope_rejection_skips_without_network() {
    use std::sync::atomic::AtomicBool;
    struct FlippingGuard {
        allowed: AtomicBool,
    }
    impl ScopeGuard for FlippingGuard {
        fn permits(&self, _target: &TaskScopeTarget) -> bool {
            self.allowed.load(Ordering::SeqCst)
        }
    }
    let plan = plan_for("127.0.0.1");
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
    let policy = HostDiscoveryPolicy::for_level(2, DiscoveryMode::Discover, plan.speed, None);
    // Module holds the same flipping guard for pre-execution checks.
    scheduler.register_module(Arc::new(HostDiscoveryModule::with_probers(
        policy,
        Arc::new(FakeIcmp::success(Arc::new(AtomicUsize::new(0)))),
        Arc::new(FakeTcp::timeout(Arc::new(AtomicUsize::new(0)))),
        guard.clone(),
    )));
    let task = Task::new(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        50,
        Duration::from_millis(500),
        RetryPolicy::default(),
        "rxscan.host",
        provenance_for(&plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
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
fn module_pre_execution_scope_check_blocks_network() {
    // Direct module check: stale guard => Failed without probing.
    let plan = plan_for("192.0.2.10");
    struct DenyAll;
    impl ScopeGuard for DenyAll {
        fn permits(&self, _target: &TaskScopeTarget) -> bool {
            false
        }
    }
    // Construction with AllowAll so we can build the task, then execute with
    // a denying guard to simulate scope changing after admission.
    let task = host_task_for(&plan, "192.0.2.10".parse().unwrap(), 1000, &AllowAll);
    let icmp_calls = Arc::new(AtomicUsize::new(0));
    let tcp_calls = Arc::new(AtomicUsize::new(0));
    let policy = HostDiscoveryPolicy::for_level(3, DiscoveryMode::Discover, plan.speed, None);
    let module = HostDiscoveryModule::with_probers(
        policy,
        Arc::new(FakeIcmp::success(icmp_calls.clone())),
        Arc::new(FakeTcp::alive_on(vec![80], tcp_calls.clone())),
        Arc::new(DenyAll),
    );
    let result = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    );
    assert!(matches!(result, Err(ModuleError::Failed { .. })));
    assert_eq!(icmp_calls.load(Ordering::SeqCst), 0);
    assert_eq!(tcp_calls.load(Ordering::SeqCst), 0);
}

// ---------- output / provenance / confidence ----------

#[test]
fn jsonl_serialization_carries_required_discovery_fields() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("rxscan-phase5-jsonl-{stamp}"));
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("out.jsonl");
    let cli = Cli::try_parse_from([
        "rxscan",
        "127.0.0.1",
        "--discover",
        "--level",
        "2",
        "--output",
        path.to_str().unwrap(),
    ])
    .unwrap();
    let report = rxscan::run::execute(cli).unwrap();
    assert!(report.jsonl_bytes > 0);
    let contents = fs::read_to_string(&path).unwrap();
    let mut saw_asset = false;
    let mut saw_concluded = false;
    let mut saw_evidence = false;
    for line in contents.lines() {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(value["schema_version"], SCHEMA_VERSION);
        let record_type = value["record_type"].as_str().unwrap().to_owned();
        let payload = &value["payload"];
        let provenance = &payload["provenance"];
        // Every record carries provenance with a stable plan ID.
        assert!(
            provenance["scan_plan_id"]
                .as_str()
                .unwrap()
                .starts_with("plan_")
        );
        match record_type.as_str() {
            "asset" => {
                saw_asset = true;
                assert!(payload["id"].as_str().unwrap().starts_with("asset_ip_"));
            }
            "event" => {
                if payload["kind"] == "host_state_concluded" {
                    saw_concluded = true;
                    let data = &payload["details"]["data"];
                    for field in [
                        "target",
                        "address",
                        "state",
                        "confidence",
                        "techniques",
                        "evidence",
                    ] {
                        assert!(data.get(field).is_some(), "missing {field}");
                    }
                }
            }
            "evidence" => {
                saw_evidence = true;
                let data = &payload["details"]["data"];
                for field in [
                    "target",
                    "address",
                    "state",
                    "confidence",
                    "techniques",
                    "evidence",
                    "probe_details",
                    "timestamp",
                ] {
                    assert!(data.get(field).is_some(), "missing {field}");
                }
                assert!(Confidence::new(data["confidence"].as_u64().unwrap() as u8).is_ok());
            }
            _ => {}
        }
    }
    assert!(saw_asset && saw_concluded && saw_evidence);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn provenance_confidence_and_state_are_correct() {
    let plan = plan_for("192.0.2.10");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let policy = HostDiscoveryPolicy::for_level(3, DiscoveryMode::Discover, plan.speed, None);
    let module = HostDiscoveryModule::with_probers(
        policy,
        Arc::new(FakeIcmp::timeout(Arc::new(AtomicUsize::new(0)))),
        Arc::new(FakeTcp::alive_on(vec![80], Arc::new(AtomicUsize::new(0)))),
        guard.clone(),
    );
    let task = host_task_for(&plan, "192.0.2.10".parse().unwrap(), 2000, guard.as_ref());
    let output = block_on_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    // Provenance on every record.
    for event in &output.events {
        assert_eq!(event.provenance.module_name, "rxscan.host");
        assert_eq!(event.provenance.module_version, "5.0.0");
        assert!(event.provenance.scan_plan_id.0.starts_with("plan_"));
    }
    for evidence in &output.evidence {
        assert_eq!(evidence.provenance.module_name, "rxscan.host");
        assert!(evidence.confidence.0 <= 100);
    }
    let result = discovery_result_from(&output);
    assert_eq!(result.state, HostState::Alive);
    assert!((85..=95).contains(&result.confidence));
    // JSONL round-trip for the concluded event.
    let concluded = output
        .events
        .iter()
        .find(|event| format!("{:?}", event.kind) == "HostStateConcluded")
        .expect("concluded event");
    let mut buffer = Vec::new();
    {
        let mut writer = rxscan::output::JsonlWriter::new(&mut buffer, 1024 * 1024);
        writer.write_event(concluded).unwrap();
        writer.flush().unwrap();
    }
    let line = String::from_utf8(buffer).unwrap();
    let (_, record_type, parsed): (u16, String, rxscan::model::Event) =
        parse_envelope_payload(line.trim_end()).unwrap();
    assert_eq!(record_type, "event");
    assert_eq!(parsed, *concluded);
}

#[test]
fn decision_engine_boundary_emits_results_only() {
    // The module never schedules follow-ups; only the DecisionEngine may
    // propose, and Phase 5 uses NoFollowUps (Phase 6 owns port expansion).
    let engine = rxscan::host_discovery::HostDiscoveryDecisionEngine;
    let plan = plan_for("127.0.0.1");
    let guard = PolicyScopeGuard::new(plan.scope.clone());
    let task = host_task_for(&plan, "127.0.0.1".parse().unwrap(), 1000, &guard);
    let output = ModuleOutput::default();
    let followups: Vec<Task> = engine.follow_up_tasks(&task, &output);
    assert!(followups.is_empty());
}

#[test]
fn no_worker_or_resource_leaks_in_controlled_run() {
    // Bounded run with fakes: all tasks terminal exactly once, no hang,
    // active count returns to zero, and a second run still works.
    let plan = compile(&["127.0.0.0/30", "--discover", "--level", "2"]);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    struct CountingFake {
        active: Arc<AtomicUsize>,
        maximum: Arc<AtomicUsize>,
    }
    impl Module for CountingFake {
        fn kind(&self) -> TaskKind {
            TaskKind::HostDiscovery
        }
        fn execute(&self, context: ModuleContext) -> ModuleFuture {
            let active = self.active.clone();
            let maximum = self.maximum.clone();
            Box::pin(async move {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(current, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(5));
                active.fetch_sub(1, Ordering::SeqCst);
                if context.is_cancelled() {
                    return Err(ModuleError::Cancelled);
                }
                Ok(ModuleOutput::default())
            })
        }
    }
    let run_once = || {
        let mut scheduler = Scheduler::new(
            16,
            BudgetLimits::default(),
            SpeedGovernor::new(SpeedSetting::Numeric(100), 4).unwrap(),
            guard.clone(),
            Arc::new(VecEventSink::default()),
        )
        .unwrap();
        scheduler.register_module(Arc::new(CountingFake {
            active: active.clone(),
            maximum: maximum.clone(),
        }));
        let tasks = rxscan::lowering::lower_plan_to_tasks(&plan).unwrap();
        let expected = tasks.len();
        for task in tasks {
            scheduler.add_task(task).unwrap();
        }
        let started = Instant::now();
        let report = scheduler.run().unwrap();
        let total = report.completed.len()
            + report.failed.len()
            + report.cancelled.len()
            + report.timed_out.len()
            + report.skipped.len();
        assert_eq!(total, expected);
        assert!(started.elapsed() < Duration::from_secs(5));
        report
    };
    let first = run_once();
    assert!(!first.completed.is_empty());
    let second = run_once();
    assert_eq!(first.completed.len(), second.completed.len());
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert!(maximum.load(Ordering::SeqCst) <= 4);
}

#[test]
fn deferred_link_discovery_is_documented_not_faked() {
    // ARP / Neighbor Discovery exist as technique variants but the executor
    // never claims support: policy documents them as deferred.
    assert_eq!(DiscoveryTechnique::Arp.to_string(), "arp".to_owned());
    assert_eq!(
        DiscoveryTechnique::NeighborDiscovery.to_string(),
        "neighbor_discovery".to_owned()
    );
    // Concluding from an unavailable deferred probe stays Unknown.
    let target: IpAddr = "192.0.2.10".parse().unwrap();
    let probes = vec![ProbeRecord::unavailable(
        DiscoveryTechnique::Arp,
        target,
        None,
        "ARP is deferred: requires raw link-layer access; not attempted",
    )];
    let (state, _, _, evidence) = conclude_state(&probes);
    assert_eq!(state, HostState::Unknown);
    assert!(evidence.contains("Unknown"));
}
