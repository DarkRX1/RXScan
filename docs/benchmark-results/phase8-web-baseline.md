# Phase 8 web-foundation baseline

- Date: 2026-09-12
- RXScan version: 0.1.0 (Phase 8 bounded HTTP/1.1 observations)
- Fixture class: controlled local only — loopback scripted HTTP server
  (200s, 3-hop redirect chain, 100KiB oversized body, silent endpoint).
- Command: `cargo run --example phase8_bench`
- Host: Linux 7.0.12 x86_64 (12 CPUs), rustc 1.98.1
- Policy: 500ms socket read slices, 16KiB header / 16KiB body caps

## Results (controlled local, no superiority claims)

- 50 requests in ~105ms (~475 req/sec), first observation ~2ms, ~7KiB total.
- Oversized 100KiB transfer capped at ~20KiB raw total (16KiB body budget
  plus headers; observation bodies never exceed the cap).
- 3-hop redirect walk in ~6ms (3 requests, one per hop, deterministic).
- Silent-server wait bounded at ~1010ms against an 800ms budget (short
  socket slices keep waits near budget, never hanging to deadline).
- Deterministic classification: `true` across repeated identical fetches.
- Peak RSS (VmHWM): ~3716 kB during bench.

## Notes

- This is a correctness/regression baseline, not a comparison against
  Nmap/httpx/Nuclei/etc. Cancellation latency mid-flight is covered by the
  test suite (`tests/phase8_web.rs`) rather than this batch benchmark.
  Future phases must re-baseline with controlled fixtures per
  `docs/BENCHMARK_PLAN.md`.
