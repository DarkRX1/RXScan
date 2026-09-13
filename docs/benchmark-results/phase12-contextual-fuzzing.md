# Phase 12 Contextual Fuzzing Benchmark

Date: 2026-09-13

Commands:

```bash
cargo run --example phase12_bench
cargo build --release
stat -c '%s' target/release/rxscan
```

Fixture:

- Local loopback HTTP server only; no public Internet.
- Seven observed parameterized endpoints flow through the production Scheduler and Decision Engine into Phase 10 baseline tasks and Phase 12 fuzz tasks.
- Inputs include numeric, boolean, short text reflection, no-meaningful-change behavior, redirect behavior, a duplicate observed endpoint, and one sensitive `csrf_token` query parameter skipped at Decision Engine eligibility.
- Mutations are one-parameter-at-a-time and use only inert Phase 12 mutation classes.

Result:

```text
phase12_bench
observed_inputs=7
eligible_inputs=4
skipped_sensitive_inputs=1
mutations_generated=15
unique_mutation_requests=15
dedup_avoided_requests=2
baseline_reused=4
baseline_requests=6
baseline_synthetic_requests=2
mutation_requests=15
redirect_follow_requests=1
retry_requests=0
total_network_requests=24
behavior_deltas=15
no_meaningful_change=3
reflections=3
inconclusive=0
completed_tasks=11
failed_tasks=0
elapsed_ms=50
requests_per_second=475.68
peak_rss_kb=7768
release_binary_size_bytes=6378080
new_production_dependency_count=0
```

Release binary size:

```text
6378080 bytes
```

Methodology:

- Request accounting is category-exclusive: `baseline_requests` are primary endpoint control requests, `baseline_synthetic_requests` are Phase 10 missing-resource probes, `mutation_requests` are Phase 12 mutation requests, `redirect_follow_requests` are same-origin redirect hops, and `retry_requests` are retry attempts. These disjoint categories sum to `total_network_requests`.
- Peak RSS is read by the benchmark from `/proc/self/status` `VmHWM` when external `/usr/bin/time -v` is unavailable.
- `/usr/bin/time -v` is unavailable in this environment, so the RSS value above is the benchmark process high-water mark read from `/proc/self/status`.
- Phase 11 accepted release size was 6,160,864 bytes; Phase 12 measured 6,378,080 bytes, a +217,216 byte delta.

No competitor comparison or superiority claim is made.
