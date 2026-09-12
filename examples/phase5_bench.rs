//! Phase 5 host-discovery baseline: controlled local fixtures only.
//!
//! Run: `cargo run --example phase5_bench`
//! Measures, without touching the public Internet:
//! * time to discover N local simulated hosts (fake backends + loopback)
//! * scheduler throughput with real `HostDiscoveryModule` + fakes
//! * cancellation latency, timeout behavior, peak queued hosts,
//!   effective concurrency, and approximate peak RSS.
//!
//! No competitive performance claims are made. Results are recorded in
//! `docs/benchmark-results/phase5-host-discovery-baseline.md`.

use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use clap::Parser;
use rxscan::{
    discovery::{DiscoveryMode, HostDiscoveryPolicy, ProbeOutcome},
    execution::{
        BudgetLimits, CancellationToken, Module, ModuleContext, PolicyScopeGuard, Scheduler,
        SpeedGovernor, Task, TaskKind, TaskScopeTarget, VecEventSink,
    },
    host_discovery::HostDiscoveryModule,
    icmp::IcmpProber,
    lowering::lower_plan_to_tasks,
    model::{Provenance, Timestamp},
    plan::ScanPlan,
    tcp_probe::TcpProber,
};

struct FakeIcmp;
impl IcmpProber for FakeIcmp {
    fn probe(&self, _ip: IpAddr, _timeout: Duration, cancel: &CancellationToken) -> ProbeOutcome {
        if cancel.is_cancelled() {
            return ProbeOutcome::Cancelled;
        }
        std::thread::sleep(Duration::from_millis(1));
        ProbeOutcome::Timeout
    }
}

struct FakeTcp {
    active: Arc<AtomicUsize>,
    maximum: Arc<AtomicUsize>,
}
impl TcpProber for FakeTcp {
    fn probe(
        &self,
        ip: IpAddr,
        port: u16,
        _timeout: Duration,
        cancel: &CancellationToken,
    ) -> ProbeOutcome {
        if cancel.is_cancelled() {
            return ProbeOutcome::Cancelled;
        }
        let current = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.maximum.fetch_max(current, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(2));
        self.active.fetch_sub(1, Ordering::SeqCst);
        // Every simulated host answers RST on its first probe port: Alive.
        ProbeOutcome::Success {
            latency: Duration::from_millis(2),
            detail: format!(
                "TCP connection refused (RST) on {ip}:{port}; host responded so it is reachable (port closed)"
            ),
        }
    }
}

fn peak_rss_kb() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmHWM:").map(|rest| {
                rest.split_whitespace()
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0)
            })
        })
}

fn main() {
    let cli =
        rxscan::cli::Cli::try_parse_from(["rxscan", "127.0.0.0/29", "--discover", "--level", "3"])
            .unwrap();
    let plan = ScanPlan::compile(cli).unwrap();
    let lowered = lower_plan_to_tasks(&plan).unwrap();
    let host_count = lowered
        .iter()
        .filter(|task| task.kind == TaskKind::HostDiscovery)
        .count();
    println!("phase5_baseline: CIDR 127.0.0.0/29 lowers to {host_count} host tasks");

    // Throughput: N simulated hosts via fakes (deterministic, local only).
    let budgets = BudgetLimits {
        max_concurrency: 4,
        max_execution_time_ms: 60_000,
        ..BudgetLimits::default()
    };
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let sink = Arc::new(VecEventSink::default());
    let policy =
        HostDiscoveryPolicy::for_level(plan.level, DiscoveryMode::Discover, plan.speed, None);
    println!("phase5_baseline: policy {}", policy.describe());
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let mut scheduler = Scheduler::new(
        budgets.queue_capacity(),
        budgets.clone(),
        SpeedGovernor::new(plan.speed, budgets.max_concurrency).unwrap(),
        guard.clone(),
        sink,
    )
    .unwrap();
    scheduler.register_module(Arc::new(HostDiscoveryModule::with_probers(
        policy,
        Arc::new(FakeIcmp),
        Arc::new(FakeTcp {
            active: active.clone(),
            maximum: maximum.clone(),
        }),
        guard.clone(),
    )));
    scheduler.register_module(Arc::new(rxscan::modules::ScaffoldModule::control_validate()));
    scheduler.register_module(Arc::new(rxscan::modules::ScaffoldModule::port_intent()));
    let provenance = Provenance::new("bench", "5.0.0", plan.stable_id(), Timestamp(0)).unwrap();
    // Build N host tasks directly (loopback range, in-scope for this plan's
    // scope only when the plan covers them; use 127.0.0.x which the /29 plan
    // permits for .1-.6, plus synthetic 127.0.0.x tasks admitted via the same
    // guard — all loopback, no external traffic).
    let task_count = 50usize;
    let started = Instant::now();
    for index in 0..task_count {
        // Cycle through the 6 permitted loopback hosts deterministically.
        let octet = 1 + (index % 6) as u8;
        let ip: IpAddr = format!("127.0.0.{octet}").parse().unwrap();
        let task = Task::new_with_params(
            TaskKind::HostDiscovery,
            None,
            Vec::new(),
            Some(rxscan::model::AssetId(format!("bench-{index}"))),
            plan.stable_id(),
            80,
            Duration::from_millis(5000),
            rxscan::execution::RetryPolicy::default(),
            "bench.host",
            provenance.clone(),
            TaskScopeTarget::Ip(ip),
            [("target".to_owned(), ip.to_string())]
                .into_iter()
                .collect(),
            guard.as_ref(),
        )
        .unwrap();
        scheduler.add_task(task).unwrap();
    }
    let queue_capacity = scheduler.queue_capacity();
    let report = scheduler.run().unwrap();
    let elapsed = started.elapsed();
    let throughput = task_count as f64 / elapsed.as_secs_f64();
    println!(
        "phase5_baseline: discovered {task_count} simulated hosts in {}ms ({throughput:.1} hosts/s)",
        elapsed.as_millis()
    );
    println!(
        "phase5_baseline: completed {} failed {} cancelled {} timed_out {} skipped {}",
        report.completed.len(),
        report.failed.len(),
        report.cancelled.len(),
        report.timed_out.len(),
        report.skipped.len()
    );
    println!(
        "phase5_baseline: max observed probe concurrency {} (cap {})",
        maximum.load(Ordering::SeqCst),
        scheduler.effective_concurrency()
    );
    println!("phase5_baseline: queue capacity {queue_capacity}");
    println!("phase5_baseline: peak RSS {:?} kB (VmHWM)", peak_rss_kb());

    // Cancellation latency with a pre-cancelled discovery task.
    let policy = HostDiscoveryPolicy::for_level(3, DiscoveryMode::Discover, plan.speed, None);
    let module = HostDiscoveryModule::with_probers(
        policy,
        Arc::new(FakeIcmp),
        Arc::new(FakeTcp {
            active: Arc::new(AtomicUsize::new(0)),
            maximum: Arc::new(AtomicUsize::new(0)),
        }),
        guard.clone(),
    );
    let task = Task::new(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        50,
        Duration::from_millis(5000),
        rxscan::execution::RetryPolicy::default(),
        "bench.cancel",
        provenance.clone(),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        guard.as_ref(),
    )
    .unwrap();
    let token = CancellationToken::default();
    token.cancel();
    let context = ModuleContext::new(task, token);
    let started = Instant::now();
    let future = module.execute(context);
    // Minimal block_on.
    let result = {
        let thread = std::thread::current();
        let waker = unsafe {
            use std::task::{RawWaker, RawWakerVTable, Waker};
            unsafe fn clone(data: *const ()) -> RawWaker {
                let thread = unsafe { &*(data as *const std::thread::Thread) };
                unsafe { raw(data, thread.clone()) }
            }
            unsafe fn raw(data: *const (), thread: std::thread::Thread) -> RawWaker {
                let _ = data;
                RawWaker::new(Box::into_raw(Box::new(thread)) as *const (), &VTABLE)
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
            static VTABLE: RawWakerVTable =
                RawWakerVTable::new(clone, wake, wake_by_ref, drop_waker);
            Waker::from_raw(raw(std::ptr::null(), thread))
        };
        let mut context = std::task::Context::from_waker(&waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                std::task::Poll::Ready(value) => break value,
                std::task::Poll::Pending => std::thread::park(),
            }
        }
    };
    assert!(matches!(
        result,
        Err(rxscan::execution::ModuleError::Cancelled)
    ));
    println!(
        "phase5_baseline: cancellation latency {}ms",
        started.elapsed().as_millis()
    );

    // Timeout behavior: one slow host with a short task timeout.
    println!(
        "phase5_baseline: timeout behavior covered by `timeout_is_bounded_and_frees_scheduler_slot` (50-150ms task timeout, 800ms fake delay, slot freed, no double-count)"
    );
    // Determinism.
    let first = lower_plan_to_tasks(&plan).unwrap();
    let second = lower_plan_to_tasks(&plan).unwrap();
    let same = first
        .iter()
        .map(|task| &task.id)
        .eq(second.iter().map(|task| &task.id));
    println!("phase5_baseline: lowering deterministic: {same}");
}
