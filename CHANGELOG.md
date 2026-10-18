# Changelog

## Unreleased

- UDP evidence: a datagram the scanner's own probe socket sent to the port
  it was probing is no longer read as a response (both the native poll
  scanner and the portable Windows/macOS scanner), so an ephemeral bind
  that lands on a probed port can no longer fabricate `Open`. A refusal
  reported by `send_to` (`WSAECONNRESET` on Windows) is classified as
  `Closed`, the same closure evidence a refusal on receive produces,
  instead of a local `Error`.
- Test fixtures: UDP tests that assert port states now reserve their
  loopback ports (the bound sockets are held for the test's duration)
  instead of binding and releasing them. A released port is bindable
  again immediately, so sibling tests running in parallel could occupy
  one and answer on it.

## v1.2.0

Graph visualization and intelligence upgrade. Backward compatible: CLI
flags, JSON/JSONL schemas, and project databases from v1.1.0 keep
working (no schema migration required).

- Link-analysis graph: typed entities/links with evidence and
  confidence, five layouts (organic, hierarchical, circular, block,
  radial), clustering for large projects, and masked PNG/SVG/GraphML/
  JSON/HTML exports via `rxscan graph` and the GUI Graph view.
- Standalone offline HTML reports (`rxscan report --format html`,
  executive/technical templates) with embedded interactive graph,
  sortable findings, evidence chains, and methodology.
- Run-to-run diff timeline in the Projects view (added/removed/changed/
  not-covered; coverage gaps are never shown as removals) with
  `GET /api/v1/projects/:name/diff`.
- Secret-safe display masking across graph, exports, API, and reports;
  scope-gated stored-data expansion; bounded resources throughout.
- Icon pack: the 74-icon manifest pack is integrated into the graph view,
  reports, and exports (`app/assets/icons/`, covered by the existing
  `app/**/*` packaging include). SVG safety and manifest/file-parity tests
  guard the shipped icons; `manifest.json` is the single source of truth.
  Graph JSON and GraphML gain additive `icon` and `category` fields; PNG
  export draws the icon's shape and ramp color, not the glyph artwork (the
  glyph appears in SVG, HTML and the GUI). Attribution icons
  (hacker, threat-group, terrorist, botnet, sanctions, law-enforcement,
  watchlist) are never assigned by heuristic.
- Mobile: responsive breakpoints for phones (≤480px), stacked-card tables
  (≤600px), a bottom-sheet detail panel (≤760px) and tablet layout (≤768px),
  safe-area insets, 44px touch targets, double-tap zoom on the graph, and a
  default 200-node render budget with an explicit "show more" control on
  narrow viewports; headless-Chromium screenshots at 360x800, 390x844, 430x932
  and 768x1024 (dashboard, graph with nodes, detail sheet) are recorded under
  `docs/`, each verified to have no horizontal overflow. Android APK execution
  is not verified locally (no NDK/SDK in this environment).
- Evidence bundle: `rxscan evidence-bundle <project> --case-id ID --out
  <path>` writes a masked, tamper-evident bundle (bundle.json, masked
  evidence items, SHA-256 manifest) and prints the SHA-256 of manifest.txt
  as the bundle digest; record that digest out-of-band (case file, ticket).
  A non-empty output directory is refused unless `--force` is given, and
  `--force` replaces only the bundle's own files: a directory holding
  anything else (unrelated file, subdirectory, symlink) is refused so a
  mistyped `--out` cannot destroy unrelated data.
  `rxscan verify-bundle <path>` recomputes every hash and fails on a
  mismatch, an extra, missing, or unexpected file, a subdirectory or
  symlink, a manifest entry naming a path outside the bundle, or a
  `bundle.json` that disagrees with `evidence.jsonl`;
  `rxscan verify-bundle --expect-digest <hex>` additionally fails when the
  recorded digest differs. Verification alone detects accidental change:
  manifest.txt can be regenerated alongside the files, so deliberate
  rewriting is only caught by the out-of-band digest. The masked bundle is a
  redacted copy, not the original evidence; RXScan does not claim legal
  admissibility, signing, or operator authentication.
- Cleanup: scoped restatement/comment trimming on files added during 1.2.0
  and this mission; zero behavior change (full test suite passes
  unmodified).

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
