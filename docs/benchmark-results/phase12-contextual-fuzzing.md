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
- Five observed parameterized endpoints flow through the production Scheduler and Decision Engine into Phase 10 baseline tasks and Phase 12 fuzz tasks.
- Inputs include numeric, boolean, short text reflection, redirect behavior, and one sensitive `csrf_token` query parameter skipped at Decision Engine eligibility.
- Mutations are one-parameter-at-a-time and use only inert Phase 12 mutation classes.

Result:

```text
phase12_bench
observed_inputs=5
eligible_inputs=3
skipped_sensitive_inputs=1
mutations_generated=11
unique_mutation_requests=11
dedup_avoided_requests=0
baseline_reused=3
baseline_requests=5
baseline_synthetic_requests=2
mutation_requests=11
redirect_follow_requests=1
retry_requests=0
total_network_requests=19
behavior_deltas=11
reflections=3
inconclusive=0
completed_tasks=9
failed_tasks=0
elapsed_ms=55
requests_per_second=343.08
peak_rss_kb=7692
release_binary_size_bytes=6378080
new_production_dependency_count=0
```

Release binary size:

```text
6378080 bytes
```

Methodology:

- Request accounting is category-exclusive: baseline primary requests, synthetic baseline requests, mutation requests, redirect-follow requests, and retry requests account for total observed network requests.
- Peak RSS is read by the benchmark from `/proc/self/status` `VmHWM` when external `/usr/bin/time -v` is unavailable.
- `/usr/bin/time -v` is unavailable in this environment, so the RSS value above is the benchmark process high-water mark read from `/proc/self/status`.
- Phase 11 accepted release size was 6,160,864 bytes; Phase 12 measured 6,378,080 bytes, a +217,216 byte delta.

No competitor comparison or superiority claim is made.
