# Changelog

## v0.1.0 (prerelease, unreleased)

First public prerelease candidate of RXScan, covering implementation phases
0–20 on Linux x86_64.

**Capabilities.** Native reconnaissance pipeline: target normalization with
deny-by-default scope; reactive scheduler with budgets, backpressure,
cancellation, and retries; host discovery (ICMP echo + TCP reachability);
TCP connect port scanning; service identification over native handshakes
(SSH/HTTP/TLS/HTTPS/FTP/SMTP/Redis/MySQL/PostgreSQL/generic, no auth);
bounded HTTP/1.1 observations with redirects and certificates; bounded
crawling of confirmed endpoints; response baselines with soft-404 handling;
managed content discovery (embedded + streaming user wordlists); safe
single-parameter GET fuzzing from observed inputs; native UDP DNS
observations; typed JSONL output; versioned checkpoints with resume;
offline scan diff with coverage-aware certainty; deterministic attention
analysis (attention is not severity); offline reports
(human/JSON/JSONL/raw); offline multi-scan project graph with bounded
queries.

**Release hardening (Phase 20).** Single-derivation speed governor;
fail-fast unreadable wordlists and unknown config keys; atomic scan output;
broken-pipe-safe machine output with a documented exit-code contract;
checkpoint-validity fixes so real multi-stage scans persist (typed port
assets, owned-evidence anchors, cross-task asset merges, resolvable
relationships, asymmetric crawl/content contact rule); golden schema
fixtures; release validation script and gate benchmark.

**Known limitations.** Linux x86_64 only; hard caps everywhere (tasks,
concurrency, hosts, evidence, registries, 8 MiB checkpoints, 16 MiB
projects); ICMP degrades without privileges; no exploit/vuln/credential/
stealth capability by design; external mid-run cancellation handle absent
(per-task timeouts and the global budget bound runs instead); project
multi-writer conflicts fail loudly rather than merging; release artifacts
are checksummed but not cryptographically signed; no crates.io publication,
man page, or shell completions yet. `LICENSE` file pending maintainer
confirmation (manifest declares MIT).
