# Changelog

## Unreleased

Host discovery is first-class: local neighbor-cache reads, bounded active ARP
and NDP on directly connected targets, interface/link-scope awareness, TCP
SYN/ACK technique identities, and
corroboration without confidence summing (strongest source wins, capped at
95). TCP scan modes `connect|syn|auto`, Linux IPv4 raw SYN with capability-
gated fallback, and the full open/closed/filtered/open|filtered/unknown/error
state model.
Deterministic feedback-driven adaptive pacing within scheduler budgets.
UDP Wave-2 safe probes (TFTP/SIP/IKE/mDNS/SNMP-response-grammar/QUIC
indicator) alongside DNS/NTP/SSDP. Fingerprint corpus grown from 5 to 265
rules across 13 packs with per-rule
self-consistency tests. Read-only SMB/RDP/MongoDB/MQTT identification (no
auth). DNS SRV with a typed service-discovery relation. Web technology
normalization with weak-signal caps, emitted per web observation. Canonical
endpoint/service asset registry. `rxscan project explain` for per-entity
conclusions, evidence, findings, changes, and discovery chain.
Coverage-aware vulnerability resolution
(resolved_by_software_change/dataset_changed/coverage_insufficient/unknown).

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
