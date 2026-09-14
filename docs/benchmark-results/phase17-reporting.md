# Phase 17 Reporting / Summary / Raw Data Benchmark

Command:

```sh
cargo run --example phase17_bench
```

Current measured output:

```text
phase17_bench
assets=7
relationships=2
findings=1
evidence=2
diff_records=1
analysis_signals=10
human_bytes=2117
json_bytes=14657
jsonl_bytes=10233
raw_bytes=21851
human_render_ms=0
json_render_ms=0
jsonl_render_ms=1
raw_render_ms=1
summary_only_ms=0
network_requests=0
peak_rss_kb=7772
release_binary_size_bytes=measure-with-cargo-build-release-and-stat
new_production_dependency_count=0
```

The fixture builds a deterministic persisted scan state with IPv4, IPv6, a
hostname-like DNS asset, an open service, endpoints, evidence, a finding,
partial work, a Phase 15 diff, and Phase 16 analysis. Reporting is offline:
`network_requests=0`.
