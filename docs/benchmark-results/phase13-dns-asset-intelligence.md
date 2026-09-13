# Phase 13 DNS / Asset Intelligence Benchmark

Date: 2026-09-14

Commands:

```bash
cargo run --example phase13_bench
cargo build --release
stat -c '%s' target/release/rxscan
```

Fixture:

- Local UDP DNS server only; no public DNS.
- One scoped hostname flows through the production Scheduler and Decision Engine into a DNS task.
- Fixture returns CNAME, in-scope A/AAAA, out-of-scope A, MX, NS, and TXT records.
- A/AAAA observations may propose scoped HostDiscovery follow-ups through the Decision Engine.
- One duplicate A query request is intentionally proposed and avoided by the scan-lifetime DNS registry.

Result:

```text
phase13_bench
seed_hostnames=1
derived_hostnames=3
unique_dns_tasks=1
dedup_avoided_queries=1
a_queries=1
aaaa_queries=1
cname_queries=0
mx_queries=1
ns_queries=1
txt_queries=1
ptr_queries=0
wildcard_queries=0
retry_queries=0
other_queries=0
total_dns_queries=5
dns_records_observed=7
hostname_assets=4
ip_assets=3
relationships_created=6
in_scope_followups=2
out_of_scope_followups_blocked=1
completed_tasks=3
failed_tasks=0
elapsed_ms=11
queries_per_second=421.51
peak_rss_kb=5484
release_binary_size_bytes=measure-with-cargo-build-release-and-stat
new_production_dependency_count=0
```

Accounting invariant:

```text
a_queries + aaaa_queries + cname_queries + mx_queries + ns_queries + txt_queries + ptr_queries + wildcard_queries + retry_queries + other_queries = total_dns_queries
```

Peak RSS is read from `/proc/self/status` `VmHWM` when `/usr/bin/time -v` is unavailable.
