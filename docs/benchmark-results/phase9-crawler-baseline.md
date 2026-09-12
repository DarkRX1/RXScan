# Phase 9 crawler baseline

Baseline command:

```text
cargo run --example phase9_bench
```

Fixture: local loopback HTTP server only. The fixture serves one confirmed root, a small multi-page link graph, duplicate links, cycles, one referenced JavaScript file, robots.txt, and a sitemap. No public Internet traffic is used.

Measures recorded by the example:

- elapsed wall-clock milliseconds
- endpoint discovery event count
- event/evidence/asset counts
- crawl task count and scheduler terminal states
- request count, unique path count, and contacted path order

The benchmark is intended as a deterministic local safety/performance baseline, not a competitor comparison. Phase 9 currently measures a single root crawl module execution; full scheduler-recursive crawl throughput remains a future benchmark expansion.

Observed baseline on 2026-09-12 after the recursive scheduler finalization pass:

```text
elapsed_ms=23
crawl_tasks=8
discoveries=15
requests_made=11
unique_paths=9
paths=/,/app.js,/robots.txt,/sitemap.xml,/listed,/b?q=1,/public,/a,/c,/c,/a
completed=9
failed=0
cancelled=0
timed_out=0
```

Interpretation: one confirmed web endpoint seeded crawler work through the Decision Engine and Scheduler. The root page, robots.txt, sitemap.xml, one referenced JavaScript file, and bounded recursive pages were fetched. Duplicate/cyclic graph edges produced bounded repeated contacts through distinct remaining-budget paths; no unbounded recursion occurred. Forms and JavaScript literals were observed only; no form submission or JavaScript execution occurred.
