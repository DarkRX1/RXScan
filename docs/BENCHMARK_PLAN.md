# Benchmark plan

Benchmarks use controlled local fixtures, fixed scope, documented host conditions, and ground truth. They do not run against public targets.

Per executable phase, record: RXScan revision, fixture revision, command/configuration, time-to-first-result, throughput, correctness/coverage, false positives, CPU, peak RSS, network bytes, queue depth, cancellation latency, and failures.

Fixture coverage expands from Phase 0 target/scope samples to IPv4/IPv6, TCP/UDP, SSH, HTTP/TLS, DNS, wildcards, redirects, throttling, oversized bodies, crawl, API, and fuzzing. Competitive comparisons are optional, controlled, and never grounds for unsupported superiority claims.

## Baselines recorded

- Phase 0: `docs/benchmark-results/phase0-baseline.md` (target/scope/plan correctness).
- Phase 2: `docs/benchmark-results/phase2-model-baseline.md` (model identity and bounded records; no throughput claim).
- Phase 4: `docs/benchmark-results/phase4-control-plane-baseline.md` (scheduler throughput with stub modules, queue saturation, cancellation latency, dedup, bounded concurrency, peak RSS). Reproduce with `cargo run --example phase4_bench`. No network I/O; no performance superiority claims.
- Phase 5: `docs/benchmark-results/phase5-host-discovery-baseline.md` (controlled local host discovery: CIDR lowering, simulated-host throughput, cancellation latency, timeout behavior, peak queued hosts, effective concurrency, CPU/RSS observations). Reproduce with `cargo run --example phase5_bench`. Local loopback/fake fixtures only; no public Internet; no performance superiority claims.
- Phase 6: `docs/benchmark-results/phase6-tcp-baseline.md` (controlled local TCP scanning: 100/1,000/10,000-port sets, ports/sec, time-to-first-open, effective concurrency, cancellation latency, CPU/RSS, queue/window depth, ordering determinism). Reproduce with `cargo run --example phase6_bench`. Local loopback listeners + synthetic closed ranges only; no public Internet; no Nmap/RustScan claims.

The first executable network benchmark is Phase 5. It uses only controlled fixtures (loopback, temporary local listeners, deterministic fakes) and records time-to-first-result, throughput, CPU, RSS, queue depth, cancellation latency, timeout behavior, and correctness.
- Phase 7: `docs/benchmark-results/phase7-service-baseline.md` (controlled local service identification: identifications/sec, time-to-first-service, bytes in/out, silent-timeout behavior, cancellation latency, planner determinism, CPU/RSS). Reproduce with `cargo run --example phase7_bench`. Local loopback fixtures only; no public Internet; no competitor claims.
- Phase 8: `docs/benchmark-results/phase8-web-baseline.md` (controlled local web observations: requests/sec, time-to-first-observation, capped oversized transfers, redirect-walk overhead, bounded silent waits, deterministic classification, CPU/RSS). Reproduce with `cargo run --example phase8_bench`. Local loopback fixtures only; no public Internet; no httpx/Nuclei claims.
- Phase 9: `docs/benchmark-results/phase9-crawler-baseline.md` (controlled local bounded crawling: elapsed time, endpoint discoveries, event/evidence/asset counts, cyclic/oversized/sitemap-ready fixture shape, deterministic completion metadata). Reproduce with `cargo run --example phase9_bench`. Local loopback fixture only; no public Internet; no competitor claims.
- Phase 10: `docs/benchmark-results/phase10-baseline-intelligence.md` (controlled local baseline intelligence: endpoint signatures, shared origin soft-404 baseline, classifications, request counts, throughput, deterministic fixture shape). Reproduce with `cargo run --example phase10_bench`. Local loopback fixture only; no public Internet; no competitor claims.
- Phase 11: `docs/benchmark-results/phase11-content-discovery.md` (controlled local managed content discovery: candidate lines, unique candidates, category-exclusive request accounting, discovered endpoints, baseline rejections, dedup avoided requests, throughput, `/proc/self/status` peak RSS, release binary size). Reproduce with `cargo run --example phase11_bench` and `cargo build --release && stat -c '%s' target/release/rxscan`. Local loopback fixture only; no public Internet; no competitor claims.
