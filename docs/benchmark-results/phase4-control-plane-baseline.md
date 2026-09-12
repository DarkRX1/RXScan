# Phase 4 control-plane baseline

- Date: 2026-09-12
- RXScan version: 0.1.0 (Phase 4 control plane)
- Fixture class: deterministic in-process stub modules, no network I/O
- Command: `cargo run --example phase4_bench`
- Host: Linux DarkRX 7.0.12 x86_64, 12 CPUs, rustc 1.98.1
- Scope: `example.test`, level 3, balanced speed

## Results (controlled local, no superiority claims)

- Prototype lowering (level 3 recon): 3 tasks (validate + host + port intent).
- Scheduler throughput: ~390 tasks/s (200 stub tasks in ~512ms, concurrency cap 2, 2ms cooperative work per task).
- Correctness: 200 completed, 0 failed/cancelled/timed-out/skipped.
- Bounded concurrency: effective cap 2 (balanced with max_concurrency 4); observed max 1 (tasks too fast to overlap; still within cap).
- Queue: capacity 64 (derived as `max_concurrency*16`), depth-before-run 0 (promotion happens inside `run`); saturation test (capacity 1, 3 tasks) completes without abort — see `queue_saturation_is_backpressure_not_fatal`.
- Cancellation latency: 0ms for pre-cancelled cooperative stub (bound <500ms asserted in tests).
- Task deduplication: same plan lowers deterministically (`lowering deterministic: true`); duplicate seed lines do not multiply tasks.
- Peak RSS (VmHWM): ~7104 kB during 200-task run.

## Notes

- This is a control-plane correctness/regression baseline, not a network-performance claim.
- No Internet or fixture-server traffic occurred.
- Future network phases must re-baseline with controlled fixtures and record time-to-first-result, throughput, CPU, RSS, queue depth, cancellation latency, and correctness per `docs/BENCHMARK_PLAN.md`.
