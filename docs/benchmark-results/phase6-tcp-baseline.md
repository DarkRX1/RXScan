# Phase 6 TCP baseline

- Date: 2026-09-12
- RXScan version: 0.1.0 (Phase 6 native TCP connect scanning)
- Fixture class: controlled local only — 8 held loopback listeners plus
  synthetic closed loopback ranges (no public Internet traffic).
- Command: `cargo run --example phase6_bench`
- Host: Linux 7.0.12 x86_64 (12 CPUs), rustc 1.98.1, balanced speed
- Policy: per-port timeout 800ms, window 64 (hard cap 256), retries 0

## Results (controlled local, no superiority claims)

- 100 ports (closed synthetic): ~47k ports/sec (~2ms), 0 opens.
- 1,000 ports (closed synthetic): ~52k ports/sec (~19ms), 0 opens.
- 10,000 ports (closed synthetic): ~55k ports/sec (~181ms), 0 opens.
- Mixed 108 ports (100 closed + 8 held listeners): 8 opens,
  time-to-first-open ~0ms.
- Cancellation: 0ms to observe cancel on a 20,000-port in-flight scan
  (5,568 probed before abort, `cancelled` + `truncated` set, no hang).
- Ordering: deterministic across repeated scans (`true`).
- Peak RSS (VmHWM): ~4740 kB during bench. Queue depth is scheduler-side;
  the scanner window itself (64) is the port-level bound under test.

## Notes

- Loopback refused (Closed) is sub-millisecond; filtered/timeout ranges
  would be slower per-port by design (bounded by per-port timeout and task
  deadline, with partial results + truncation instead of hangs).
- This is a correctness/regression baseline, not a comparison against
  Nmap/RustScan. Future phases must re-baseline with controlled fixtures
  per `docs/BENCHMARK_PLAN.md`.
