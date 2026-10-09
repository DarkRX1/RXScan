# Changelog

## Unreleased (master, newer than v1.1.0)

(nothing yet)

## v1.1.0

First release with ready-to-run binaries. Everything below shipped in
this release and is covered by hosted proof (CI plus the Distribution
artifacts workflow with post-extraction smoke tests, checksums, and a
release manifest).

- Distribution: version-derived artifacts (`RXScan-<version>-<os>-<arch>`)
  for Windows x86_64 (runtime-tested), Linux x86_64 (runtime-tested),
  Linux ARM64 (build-only), macOS ARM64 (runtime-tested), macOS x86_64
  (build-only), plus SHA256SUMS and a machine-readable
  release-manifest.json. GUI assets are embedded in the binary; archives
  additionally carry `app/`, `fingerprints/`, and `search/` sidecars.
- Android APK (beta/experimental): same Rust core plus the shared
  frontend in a thin WebView shell over loopback; install- and
  launch-tested on an emulator. Physical ARM64-device execution remains
  unverified. Debug-signed only.
- Responsive web console: phone/tablet layouts (360–768px), touch-sized
  graph targets, pinch zoom; desktop presentation unchanged.
- Host discovery: neighbor-cache reads, bounded ARP/NDP, SYN/ACK technique
  identities, corroboration without confidence summing.
- TCP `connect|syn|auto` modes (Linux IPv4 raw SYN with fallback) and the
  full port-state model; adaptive pacing within scheduler budgets.
- UDP: bounded Wave-2 probes alongside DNS/NTP/SSDP; `open|filtered`
  uncertainty preserved.
- Fingerprints: 13 packs with per-rule self-consistency tests; read-only
  SMB/RDP/MongoDB/MQTT identification (no auth); DNS SRV relation; web
  technology normalization with weak-signal caps.
- Asset registry, `project explain`, coverage-aware vulnerability
  resolution.
- Local web console (`rxscan web`): loopback-only same-origin GUI plus
  versioned `/api/v1` over the same core (jobs with cancellation,
  server-sent progress, project evidence views). No command-execution
  endpoint; no new dependencies.
- Search: shared category registry with CLI/Web parity, findings-first
  terminal output, metadata/provenance, coverage accounting, and
  `all_ports` parity (TCP-only; UDP stays bounded).

## v1.0.2

First correctly versioned 1.x release (`Cargo.toml` version `1.0.2`).
No code changes beyond version metadata relative to the v1.0.0/v1.0.1
commit. Historical tags are left unchanged (see Releases in README).

## v1.0.1 / v1.0.0 (same commit)

Published tags `v1.0.0` and `v1.0.1` point at the same commit and carry
incorrect `0.1.0` Cargo package metadata. Left unchanged for tag
immutability; `v1.0.2` is the first correctly versioned 1.x release.
Capability baseline for these tags is the Phase 0–20 prerelease scope
described below.

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
