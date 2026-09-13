# Phase 11 Managed Content Discovery Benchmark

Date: 2026-09-13

Commands:

```bash
cargo run --example phase11_bench
cargo build --release
stat -c '%s' target/release/rxscan
```

Fixture:

- Local loopback HTTP server only; no public Internet.
- One confirmed web origin flows through the production Scheduler and Decision Engine into Phase 10 baseline and Phase 11 content discovery.
- Candidate source is the 12-entry built-in set plus a streamed 12-line user candidate file containing duplicates, comments, malformed/rejected entries, JSON/static paths, a redirect, a forbidden path, an oversized response path, and soft-404-like misses.

Result:

```text
phase11_bench
candidate_lines=24
unique_candidates=17
candidate_requests=22
baseline_synthetic_requests=2
redirect_follow_requests=2
retry_requests=0
other_requests=1
total_network_requests=27
discovered_endpoints=6
baseline_rejected_responses=11
dedup_avoided_requests=7
cross_module_dedup_avoided_requests=0
elapsed_ms=65
requests_per_second=409.65
candidate_lines_per_second=364.13
completed_tasks=9
failed_tasks=0
peak_rss_kb=7584
release_binary_size_bytes=measure-with-cargo-build-release-and-stat
new_production_dependency_count=0
```

Release binary size:

```text
6160864
```

Methodology:

- Request accounting is category-exclusive: `candidate_requests + baseline_synthetic_requests + redirect_follow_requests + retry_requests + other_requests == total_network_requests`.
- Peak RSS is read by the benchmark from `/proc/self/status` `VmHWM`. `/usr/bin/time -v` was unavailable on the integrity-gate host, so no external RSS sample was recorded there.
- Release binary size is measured with `stat -c '%s' target/release/rxscan` after `cargo build --release`.
- Phase 10 release-size comparison is unavailable because no trustworthy Phase 10 release binary measurement was recorded before this change.

No competitor comparison or superiority claim is made.
