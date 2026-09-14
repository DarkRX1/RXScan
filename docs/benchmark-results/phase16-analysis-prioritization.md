# Phase 16 Analysis / Prioritization Benchmark

Date: 2026-09-14

Command:

```bash
cargo run --example phase16_bench
```

Fixture:

- Builds deterministic Phase 14-style states in memory.
- Compares them with the Phase 15 diff engine.
- Runs Phase 16 offline analysis over assets, relationships, findings, and diff records.
- Includes unchanged exposure, newly opened service, endpoint behavior change, reflection relationship, DNS relationship, new/persistent findings, and corroborating evidence.
- Performs no network work.

Result:

```text
phase16_bench
assets_analyzed=9
relationships_analyzed=6
findings_analyzed=2
diff_records_analyzed=16
signals_generated=15
signals_emitted=15
signals_truncated=false
high_attention=0
medium_attention=5
low_attention=9
informational=1
network_signals=3
web_signals=5
dns_signals=2
finding_signals=2
change_signals=11
correlation_signals=2
inconclusive_signals=2
max_attention_score=62
min_attention_score=0
analysis_ms=1
network_requests=0
peak_rss_kb=7140
release_binary_size_bytes=measure-with-cargo-build-release-and-stat
new_production_dependency_count=0
```

Peak RSS is read from `/proc/self/status` `VmHWM` when external `/usr/bin/time -v` is unavailable.
