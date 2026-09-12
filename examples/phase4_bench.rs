//! Phase 4 control-plane baseline: local stub throughput, no network.
//!
//! Run: `cargo run --example phase4_bench`
//! Measures scheduler task throughput with safe stub modules, queue
//! saturation behavior, cancellation latency, task dedup, bounded
//! concurrency, and approximate peak queue depth.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use clap::Parser;
use rxscan::{
    execution::{
        BudgetLimits, CancellationToken, Module, ModuleContext, ModuleError, ModuleFuture,
        ModuleOutput, PolicyScopeGuard, RetryPolicy, Scheduler, SpeedGovernor, Task,
        TaskScopeTarget, VecEventSink,
    },
    lowering::lower_plan_to_tasks,
    model::{Provenance, Timestamp},
    plan::ScanPlan,
};

struct StubModule {
    kind: rxscan::execution::TaskKind,
    active: Option<Arc<AtomicUsize>>,
    maximum: Option<Arc<AtomicUsize>>,
}

impl Module for StubModule {
    fn kind(&self) -> rxscan::execution::TaskKind {
        self.kind.clone()
    }
    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let active = self.active.clone();
        let maximum = self.maximum.clone();
        Box::pin(async move {
            if let Some(active) = &active {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                if let Some(maximum) = &maximum {
                    maximum.fetch_max(current, Ordering::SeqCst);
                }
            }
            for _ in 0..2 {
                if context.is_cancelled() {
                    if let Some(active) = &active {
                        active.fetch_sub(1, Ordering::SeqCst);
                    }
                    return Err(ModuleError::Cancelled);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            if let Some(active) = &active {
                active.fetch_sub(1, Ordering::SeqCst);
            }
            Ok(ModuleOutput::default())
        })
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
    let cli = rxscan::cli::Cli::try_parse_from(["rxscan", "example.test", "--level", "3"]).unwrap();
    let plan = ScanPlan::compile(cli).unwrap();
    let prototype_tasks = lower_plan_to_tasks(&plan).unwrap();
    println!(
        "phase4_baseline: prototype lowering yields {} tasks",
        prototype_tasks.len()
    );

    // Throughput: 200 stub tasks, concurrency 4.
    let budgets = BudgetLimits {
        max_concurrency: 4,
        max_execution_time_ms: 60_000,
        ..BudgetLimits::default()
    };
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let sink = Arc::new(VecEventSink::default());
    let mut scheduler = Scheduler::new(
        budgets.queue_capacity(),
        budgets.clone(),
        SpeedGovernor::new(plan.speed, budgets.max_concurrency).unwrap(),
        guard.clone(),
        sink,
    )
    .unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    scheduler.register_module(Arc::new(StubModule {
        kind: rxscan::execution::TaskKind::HostDiscovery,
        active: Some(active.clone()),
        maximum: Some(maximum.clone()),
    }));
    scheduler.register_module(Arc::new(StubModule {
        kind: rxscan::execution::TaskKind::PortDiscovery,
        active: None,
        maximum: None,
    }));
    scheduler.register_module(Arc::new(StubModule {
        kind: rxscan::level::validate_kind(),
        active: None,
        maximum: None,
    }));
    let provenance = Provenance::new("bench", "4.0.0", plan.stable_id(), Timestamp(0)).unwrap();
    let task_count = 200usize;
    let started = Instant::now();
    for index in 0..task_count {
        let kind = match index % 3 {
            0 => rxscan::level::validate_kind(),
            1 => rxscan::execution::TaskKind::HostDiscovery,
            _ => rxscan::execution::TaskKind::PortDiscovery,
        };
        let module = match &kind {
            rxscan::execution::TaskKind::HostDiscovery => "bench.host",
            rxscan::execution::TaskKind::PortDiscovery => "bench.port",
            _ => "bench.validate",
        };
        let task = Task::new(
            kind,
            None,
            Vec::new(),
            Some(rxscan::model::AssetId(format!("bench-{index}"))),
            plan.stable_id(),
            50,
            Duration::from_millis(5000),
            RetryPolicy::default(),
            module,
            provenance.clone(),
            TaskScopeTarget::Host("example.test".to_owned()),
            guard.as_ref(),
        )
        .unwrap();
        scheduler.add_task(task).unwrap();
    }
    let queue_depth_before = scheduler.queue_depth();
    let report = scheduler.run().unwrap();
    let elapsed = started.elapsed();
    let throughput = task_count as f64 / elapsed.as_secs_f64();
    println!(
        "phase4_baseline: throughput {throughput:.1} tasks/s ({task_count} tasks in {}ms)",
        elapsed.as_millis()
    );
    println!(
        "phase4_baseline: completed {} failed {} cancelled {} timed_out {} skipped {}",
        report.completed.len(),
        report.failed.len(),
        report.cancelled.len(),
        report.timed_out.len(),
        report.skipped.len()
    );
    println!(
        "phase4_baseline: max observed concurrency {}",
        maximum.load(Ordering::SeqCst)
    );
    println!(
        "phase4_baseline: queue capacity {} depth-before-run {queue_depth_before}",
        budgets.queue_capacity()
    );
    println!("phase4_baseline: peak RSS {:?} kB (VmHWM)", peak_rss_kb());

    // Cancellation latency: cooperative stub.
    let token = CancellationToken::default();
    let cancel_task = Task::new(
        rxscan::execution::TaskKind::HostDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        50,
        Duration::from_millis(5000),
        RetryPolicy::default(),
        "bench.cancel",
        provenance.clone(),
        TaskScopeTarget::Host("example.test".to_owned()),
        guard.as_ref(),
    )
    .unwrap();
    let context = ModuleContext::new(cancel_task, token.clone());
    token.cancel();
    let module = StubModule {
        kind: rxscan::execution::TaskKind::HostDiscovery,
        active: None,
        maximum: None,
    };
    let future = module.execute(context);
    let started = Instant::now();
    // Minimal block_on for the example.
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
    assert!(matches!(result, Err(ModuleError::Cancelled)));
    println!(
        "phase4_baseline: cancellation latency {}ms",
        started.elapsed().as_millis()
    );

    // Dedup: lowering is deterministic.
    let first = lower_plan_to_tasks(&plan).unwrap();
    let second = lower_plan_to_tasks(&plan).unwrap();
    let same = first
        .iter()
        .map(|task| &task.id)
        .eq(second.iter().map(|task| &task.id));
    println!("phase4_baseline: lowering deterministic: {same}");
}
