# Benchmark harness

Phase 0 establishes a benchmark discipline before scanner modules exist. Every completed phase records its fixture, command, RXScan revision, host environment, and relevant measures under `docs/benchmark-results/` (ignored until results exist).

The first executable network benchmark is introduced with the first network module. It must use only controlled fixtures and record time-to-first-result, throughput, CPU, RSS, queue depth, cancellation latency, and correctness.
