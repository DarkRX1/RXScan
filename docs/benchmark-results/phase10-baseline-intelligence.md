# Phase 10 Baseline Web Intelligence Benchmark

Date: 2026-09-13

Command:

```bash
cargo run --example phase10_bench
```

Fixture:

- Local loopback HTTP server only; no public Internet.
- Eight confirmed endpoint observations on one origin: exact/normalized duplicate pages, template variants, a unique HTML page, JSON, XML, and JavaScript/static responses.
- One shared origin baseline with two inert missing-path probes shaped as `/__rxscan_baseline_<token>__`.

Result:

```text
phase10_bench
elapsed_ms=21
completed_tasks=9
failed_tasks=0
network_requests=10
response_signatures=8
soft404_observations=1
endpoint_classifications=8
signatures_per_second=377.36
deterministic_fixture_paths=8
peak_rss_kb=not-collected
```

Interpretation:

- The benchmark exercises the production Scheduler and Decision Engine path from confirmed endpoint evidence to baseline tasks.
- Endpoint-specific signatures are generated for all eight confirmed endpoints.
- Origin-level synthetic missing-path characterization is performed once for the origin, not once per endpoint.
- Request count is bounded and explainable: eight endpoint responses plus two synthetic baseline responses.
- Peak RSS was not collected in this lightweight example; memory pressure remains bounded by the 64KiB signature input cap and existing scheduler/output caps.

No competitor comparison or superiority claim is made.
