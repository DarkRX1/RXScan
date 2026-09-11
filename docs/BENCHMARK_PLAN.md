# Benchmark plan

Benchmarks use controlled local fixtures, fixed scope, documented host conditions, and ground truth. They do not run against public targets.

Per executable phase, record: RXScan revision, fixture revision, command/configuration, time-to-first-result, throughput, correctness/coverage, false positives, CPU, peak RSS, network bytes, queue depth, cancellation latency, and failures.

Fixture coverage expands from Phase 0 target/scope samples to IPv4/IPv6, TCP/UDP, SSH, HTTP/TLS, DNS, wildcards, redirects, throttling, oversized bodies, crawl, API, and fuzzing. Competitive comparisons are optional, controlled, and never grounds for unsupported superiority claims.
