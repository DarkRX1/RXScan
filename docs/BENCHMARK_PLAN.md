# Benchmark plan

Benchmarks use controlled local fixtures, fixed scope, documented host conditions, and ground truth. They do not run against public targets.

Per executable phase, record: RXScan revision, fixture revision, command/configuration, time-to-first-result, throughput, correctness/coverage, false positives, CPU, peak RSS, network bytes, queue depth, cancellation latency, and failures.

Fixture coverage expands from Phase 0 target/scope samples to IPv4/IPv6, TCP/UDP, SSH, HTTP/TLS, DNS, wildcards, redirects, throttling, oversized bodies, crawl, API, and fuzzing. Competitive comparisons are optional, controlled, and never grounds for unsupported superiority claims.

## Baselines recorded

- Phase 0: `docs/benchmark-results/phase0-baseline.md` (target/scope/plan correctness).
- Phase 2: `docs/benchmark-results/phase2-model-baseline.md` (model identity and bounded records; no throughput claim).
- Phase 4: `docs/benchmark-results/phase4-control-plane-baseline.md` (scheduler throughput with stub modules, queue saturation, cancellation latency, dedup, bounded concurrency, peak RSS). Reproduce with `cargo run --example phase4_bench`. No network I/O; no performance superiority claims.

The first executable network benchmark is introduced with the first network module (Phase 5+). It must use only controlled fixtures and record time-to-first-result, throughput, CPU, RSS, queue depth, cancellation latency, and correctness.
