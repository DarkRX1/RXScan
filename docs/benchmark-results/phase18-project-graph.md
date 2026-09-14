# Phase 18 Project / Graph Mode Benchmark

Commands:

```sh
cargo run --example phase18_bench
cargo build --release && stat -c '%s' target/release/rxscan
```

Current measured output (`cargo run --example phase18_bench`):

```text
phase18_bench
scans=3
entities=2847
relationships=1424
observations=4452
findings=2
change_refs=60
analysis_refs=100
duplicate_entities_avoided=1604
duplicate_relationships_avoided=802
duplicate_observations_avoided=0
project_bytes=2089429
initial_import_ms=172
incremental_import_ms=227
duplicate_import_ms=20
project_open_ms=82
summary_ms=0
entity_lookup_ms=0
neighbors_depth1_ms=0
neighbors_depth3_ms=0
threads_used=1
network_requests=0
peak_project_rss_kb=25576
release_binary_size_bytes=8210768
new_production_dependency_count=0
background_cpu_percent=0
background_rss_kb=0
duplicate_scan_noop=true
bytes_after_first_import=987131
bytes_added_incremental=361651
duplicate_bytes_avoided=1102298
available_parallelism=12
wall_ms=2426
graph_query_queue_peak=2
graph_query_visited_peak=5
graph_query_expansions=4
graph_query_exhaustive=true
graph_query_max_queue_cap=2048
graph_query_max_visited_cap=4096
graph_query_max_expansions_cap=2048
graph_query_max_edge_budget=8192
fingerprint_whole_state_clones=0
fingerprint_serialization_buffer_bytes=0
project_serialization_buffer_bytes=8192
project_open_rss_kb=25576
fingerprint_rss_kb=25576
query_peak_rss_kb=25576
current_rss_kb=25576
fingerprint_ms=166
```

Methodology: deterministic local fixture with three scans (800-port base,
820-port incremental delta of 20 ports plus services, 600-port second target),
plus a duplicate import. `project_open_ms` measures temp-file streaming save
plus `load_project` wall time. Query timings measure in-memory lookup and
hard-bounded BFS (no full adjacency map; per-expansion incident-edge scan).
`peak_project_rss_kb` / `project_open_rss_kb` / `fingerprint_rss_kb` /
`query_peak_rss_kb` read `/proc/self/status` `VmHWM` at each phase.
`release_binary_size_bytes` stats `target/release/rxscan` when present
(P17 baseline 7665408, P18 8210768, delta +545360). `threads_used=1`
(single-threaded, no daemon/watcher/indexer/pool). `network_requests=0`
offline. `available_parallelism` reports host parallelism without saturating
it. `graph_query_*_peak` are the observed BFS peaks for the representative
highest-degree entity (exhaustive=true on this fixture; high-degree and
adversarial fixtures in `phase18_project` tests prove caps: queue<=2048,
visited<=4096, expansions<=2048, edge budget 8192, truncated with
`exhaustive=false`). `fingerprint_whole_state_clones=0` (borrowed view
streamed into SHA-256, zero canonical buffer) and
`project_serialization_buffer_bytes=8192` (streaming save, no full pretty
`Vec`). Exact timings/RSS vary by machine; storage and dedup counts are
deterministic for the fixture.

The benchmark imports an initial scan, an incremental scan with a small delta,
a duplicate scan, and a second target. It validates summary, lookup, neighbor
query, streaming fingerprint, and streaming save paths. Project mode is
offline and single-threaded for ordinary operations. Storage grows with new
semantic information (incremental delta ~353 KiB) not repeated work (duplicate
is a no-op). Both the 16 MiB file cap and collection caps apply, whichever
first rejects; the file cap is hit far before 500k realistic observations.
