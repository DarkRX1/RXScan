# Phase 14 Persistence / Resume Benchmark

Date: 2026-09-14

Commands:

```bash
cargo run --example phase14_bench
cargo build --release
stat -c '%s' target/release/rxscan
```

Fixture:

- Local semantic Scheduler fixture only; no public network.
- Writes a bounded JSON checkpoint to the OS temp directory.
- Loads and validates the checkpoint.
- Persists compact semantic state: two assets, one relationship, one evidence
  record, one informational finding, one completed task, one pending task, and
  Phase 10-13 registry entries.
- Restores one completed task and one pending task through the real Scheduler.
- Completed task is not re-run; pending task executes once.

Result:

```text
phase14_bench
assets_persisted=2
relationships_persisted=1
evidence_persisted=1
findings_persisted=1
completed_tasks_persisted=1
pending_tasks_persisted=1
contact_registry_entries=1
origin_baseline_entries=1
fuzz_budget_entries=1
dns_query_entries=1
dns_domain_entries=1
registry_entries_persisted=5
checkpoint_bytes=10429
checkpoint_write_ms=0
checkpoint_load_ms=0
resume_tasks_restored=2
completed_tasks_skipped_on_resume=1
duplicate_contacts_avoided=1
network_requests_after_resume=1
completed_tasks_after_resume=2
failed_tasks_after_resume=0
peak_rss_kb=8436
release_binary_size_bytes=measure-with-cargo-build-release-and-stat
new_production_dependency_count=0
```

Disk IO:

- One checkpoint write.
- Writes use `checkpoint.tmp` beside the target, flush, file sync, then rename.
- Parent-directory fsync is not performed; crash durability across power loss is not claimed.
- Loading buffers at most the hard checkpoint cap before JSON parsing.

Peak RSS is read from `/proc/self/status` `VmHWM` when `/usr/bin/time -v` is unavailable.
