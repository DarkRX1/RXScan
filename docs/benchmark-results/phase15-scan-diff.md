# Phase 15 Scan Diff Benchmark

Date: 2026-09-14

Commands:

```bash
cargo run --example phase15_bench
cargo build --release
stat -c '%s' target/release/rxscan
```

Fixture:

- Two deterministic Phase 14 checkpoints are written to the OS temp directory.
- Baseline has unchanged host/IP context, an open HTTPS-like service relationship, a DNS alias relationship, one endpoint, and one finding.
- Current has an added endpoint, modified port/service attributes, changed service and DNS relationships, modified finding metadata, and reduced level/coverage so one old endpoint is inconclusive rather than confirmed removed.
- Diff runs fully offline and reports `network_requests=0`.

Result:

```text
phase15_bench
baseline_assets=6
current_assets=6
baseline_relationships=2
current_relationships=2
baseline_findings=1
current_findings=1
confirmed_added=5
confirmed_removed=0
modified=2
inconclusive_missing=3
unchanged=2
plan_differences=1
diff_records_emitted=12
diff_records_truncated=false
checkpoint_load_ms=3
normalization_ms=0
comparison_ms=0
total_diff_ms=3
asset_changes=7
relationship_changes=4
finding_changes=1
endpoint_changes=7
dns_changes=2
network_requests=0
peak_rss_kb=8104
release_binary_size_bytes=measure-with-cargo-build-release-and-stat
new_production_dependency_count=0
```

Peak RSS is read from `/proc/self/status` `VmHWM` when `/usr/bin/time -v` is unavailable.
