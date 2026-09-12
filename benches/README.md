# Benchmark harness

Phase 0 establishes a benchmark discipline before scanner modules exist. Every completed phase records its fixture, command, RXScan revision, host environment, and relevant measures under `docs/benchmark-results/` (ignored until results exist).

Phase 4 adds a control-plane baseline (`docs/benchmark-results/phase4-control-plane-baseline.md`, reproduced via `cargo run --example phase4_bench`) using safe stub modules with no network I/O. It records scheduler throughput, bounded concurrency, queue behavior, cancellation latency, dedup determinism, and peak RSS.

The first executable network benchmark is introduced with the first network module. It must use only controlled fixtures and record time-to-first-result, throughput, CPU, RSS, queue depth, cancellation latency, and correctness.
