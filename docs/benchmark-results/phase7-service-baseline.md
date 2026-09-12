# Phase 7 service-intelligence baseline

- Date: 2026-09-12
- RXScan version: 0.1.0 (Phase 7 native protocol probing)
- Fixture class: controlled local only — loopback SSH/HTTP/generic banner
  fixtures plus a silent fixture (no public Internet traffic).
- Command: `cargo run --example phase7_bench`
- Host: Linux 7.0.12 x86_64 (12 CPUs), rustc 1.98.1
- Policy: per-probe budget 2000ms (bench) / 800ms (timeout probe)

## Results (controlled local, no superiority claims)

- 30 identifications (SSH/HTTP/generic mix) in ~62ms (~480/sec).
- Time to first identified service: ~2ms.
- Bytes: ~1740 in / ~810 out across 30 probes (requests <160B each;
  responses capped by per-probe budgets).
- Silent-service timeout: ~504ms for an 800ms budget (short 500ms socket
  slices keep the observed latency under budget, never hanging to deadline).
- Cancellation latency: ~353ms mid-probe (bounded by the 500ms socket read
  slice; pre-cancelled tasks abort in <1ms per unit tests).
- Planner deterministic: `true` across repeated plans.
- Service tasks run sequentially per port at scheduler concurrency (no
  intra-task thread fan-out); peak RSS ~3292 kB (VmHWM).

## Notes

- This is a correctness/regression baseline, not a comparison against any
  external scanner. Future phases must re-baseline with controlled fixtures
  per `docs/BENCHMARK_PLAN.md`.
