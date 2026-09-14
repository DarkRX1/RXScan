# Implementation status and gap analysis

## Repository baseline

The repository had no commits and contained an uncommitted Rust Phase-0-style skeleton plus a separate static portfolio. The portfolio is preserved and excluded from RXScan engine work. The skeleton normalized targets, performed basic scope checks, and compiled a plan, but had no CI, fixture or benchmark foundation, TOML configuration, goal/level/speed model, or complete planning docs.

## Current state

Phases 0 through 15 are complete. RXScan now performs real bounded host discovery, native TCP connect port scanning, native service/protocol identification, bounded DNS observations, bounded HTTP/1.1 web observations, deterministic bounded crawling from confirmed web endpoint evidence, baseline web intelligence for confirmed/crawled endpoints, managed content discovery, contextual GET query fuzzing, bounded checkpoint/resume through the existing scheduler, and offline semantic scan diffing. Decision Engine flow is host→port, open-port→service, DNS A/AAAA→scoped host discovery, service→web, confirmed endpoint/discovery→crawl/baseline, origin baseline→content, and baseline signature with observed safe query parameter→fuzz. No UDP scanning, POST/form fuzzing, cookie/header/path-variable fuzzing, authentication automation, JavaScript execution, headless browsing, vulnerability checks, brute force, exploitation, cipher enumeration, Phase 16 prioritization/analysis, or technology fingerprinting exist yet.

| Area | Current state | Next |
| --- | --- | --- |
| Native Rust core | Foundation + data model + control plane + host + TCP + DNS + service + web + bounded crawler + baseline intelligence + managed content discovery + contextual GET query fuzzing + checkpoint/resume + offline scan diff established (rustls/x509-parser for TLS observation) | Phase 16 analysis/prioritization |
| Target, scope, CLI, config, plan | Implemented/tested; level/goal/budget-aware plus discovery/TCP/service/web/crawl policy | Future explicit crawler tuning flags if needed |
| Events/assets/findings | Implemented/tested; host + port + service + web + crawl producers emit real typed events/evidence/assets/findings and endpoint relationships | Phase 20+ reporting |
| Scheduler/speed/budgets | Implemented, wired to binary, tested; auto is non-adaptive baseline; `max_hosts` bounds CIDR; follow-ups best-effort (dup/scope/budget skip) | Phase 4.1 adaptive governor (optional) |
| Plan→task lowering | Deterministic, scope-checked, deduped, ONE port task per target (never 65k), CIDR host expansion bounded; service/web tasks proposed per open port/service by the engine | Phase 9 dependency expansion |
| JSONL output | Typed, versioned, provenanced, bounded, tested; includes discovery + scan + service + web assets/events/evidence/findings; terminal shows service table | Phase 20+ reporting |
| Network and web modules | Host discovery + TCP port scanning + service probing + bounded DNS observations + bounded HTTP/1.1 web observations + bounded same-origin crawler + baseline web intelligence + managed content discovery + contextual GET query fuzzing; ARP/ND deferred; no UDP/checks/fingerprint engine | Phase 15 onward |
| CI/fixtures/benchmark discipline | Established; Phase 5 + 6 + 7 + 8 + 9 + 10 + 11 + 12 baselines recorded | Add executable fixtures per module |

No performance or capability superiority is claimed. No scanning functionality is claimed beyond bounded host discovery, TCP connect port scanning, safe service identification, bounded web observations, and bounded evidence-backed crawling plus control-plane execution of scaffold tasks.

## Phase 0–1 verification

Verified locally on 2026-09-11:

- `cargo fmt --check` — passed
- `cargo check` — passed
- `cargo test` — passed: 10 tests, 0 failures
- `cargo clippy --all-targets --all-features -- -D warnings` — passed
- `cargo run -- https://Example.test:8443 --goal web --level 4 --speed 30 --ports 443,80,8000-8002 --explain` — passed; produced an inspectable plan and made no network connection

## Phase 2 verification

Verified locally on 2026-09-11:

- `cargo fmt --check` — passed
- `cargo check` — passed
- `cargo test` — passed: 13 tests, 0 failures
- `cargo clippy --all-targets --all-features -- -D warnings` — passed

## Phase 3 verification

Phase 3 scheduler/execution core was implemented and tested in library code (9 integration tests). It was orphaned from the binary until Phase 4 wired it via `src/run.rs`. Phase 3 behaviors (queues, lifecycle, retries, timeouts, budgets, scope) remain covered and passing after Phase 4 hardening.

## Phase 4 verification

Verified locally on 2026-09-12 (see validation results in the Phase 4 completion report):

- `cargo fmt --check` — passed
- `cargo check` — passed
- `cargo test` — passed (unit + phase1/phase2/phase3/phase4 suites)
- `cargo clippy --all-targets --all-features -- -D warnings` — passed
- `git diff --check` — passed
- `cargo run -- example.test --explain` — shows goal/level/speed policy, effective concurrency, retry limits, budgets, selected/skipped modules with reasons
- `cargo run -- example.test` — runs scaffold tasks to completion with no network I/O
- `cargo run -- example.test --output <path>` — writes valid typed JSONL with schema version and provenance
- `cargo run --example phase4_bench` — control-plane baseline recorded in `docs/benchmark-results/phase4-control-plane-baseline.md`

## Phase 5 verification

- `cargo fmt --check`, `cargo check`, `cargo test` (unit + phase1–5 suites), `cargo clippy --all-targets --all-features -- -D warnings`, `git diff --check` — all pass; Phase 4 suites remain green.
- `cargo run -- 127.0.0.1 --discover --level 3 --output <path>` — Alive via ICMP echo (95) or TCP RST (85) with typed events/evidence/assets in JSONL; `::1` similarly Alive via ICMPv6.
- `cargo run -- 127.0.0.0/29 --discover` — 6 bounded host tasks in deterministic order; `--max-hosts 2` truncates to 2; `--exclude 127.0.0.2` omits it.
- `cargo run --example phase5_bench` — controlled local baseline recorded in `docs/benchmark-results/phase5-host-discovery-baseline.md` (no Internet, no superiority claims).

## Phase 6 verification

- `cargo fmt --check`, `cargo check`, `cargo test` (unit + phase1–6 suites, 121 tests), `cargo clippy --all-targets --all-features -- -D warnings`, `git diff --check` — all pass; Phase 0–5 suites remain green.
- `cargo run -- 127.0.0.1 --ports 22,80,443 --level 3` — bounded port task scans 3 ports; open listeners surface in the human `HOST`/`PORT STATE` table and JSONL findings.
- `cargo run -- 127.0.0.1 --all-ports --level 1 --output <path>` — ONE task scans 65,535 ports internally (~47 JSONL lines: opens + summary, never 65k tasks/events).
- `cargo run --example phase6_bench` — controlled local baseline recorded in `docs/benchmark-results/phase6-tcp-baseline.md` (~50k ports/sec loopback, 0ms cancel, deterministic; no Internet, no Nmap/RustScan claims).

## Phase 7 verification

- `cargo fmt --check`, `cargo check`, `cargo test` (unit + phase1–7 suites, 161 tests), `cargo clippy --all-targets --all-features -- -D warnings`, `git diff --check` — all pass; Phase 0–6 suites remain green.
- `cargo run -- 127.0.0.1 --ports 22,80 --level 4` against local SSH/HTTP fixtures — human `PORT/SERVICE/PRODUCT` table shows classified services with observed product hints; JSONL carries service assets, `ServiceIdentified` events with `Runs` relationships, certificate evidence, and per-service findings.
- `cargo run --example phase7_bench` — controlled local baseline recorded in `docs/benchmark-results/phase7-service-baseline.md` (~480 identifications/sec, first ~2ms, bounded cancel/timeout; no Internet, no competitor claims).

## Phase 8 verification

- `cargo fmt --check`, `cargo check`, `cargo test` (unit + phase1–8 suites, 192 tests), `cargo clippy --all-targets --all-features -- -D warnings`, `git diff --check` — all pass; Phase 0–7 suites remain green.
- `cargo run -- 127.0.0.1 --ports 18888 --level 4` against a local HTTP fixture — human table shows the service row; `--output` JSONL carries endpoint assets, `EndpointObserved`/`RedirectObserved`/`WebProbeCompleted` events, per-URL evidence with headers/cookies/title, certificate assets for HTTPS, and per-URL findings.
- `cargo run --example phase8_bench` — controlled local baseline recorded in `docs/benchmark-results/phase8-web-baseline.md` (~475 req/sec, first ~2ms, capped oversized transfers, 3-hop walk ~6ms, bounded silent waits, deterministic; no Internet, no httpx/Nuclei claims).

## Phase 9 verification

- `cargo fmt --check`, `cargo check`, `cargo test`, `cargo clippy --all-targets --all-features -- -D warnings`, `git diff --check`, and `cargo run --example phase9_bench` are the required completion checks.
- Phase 9 adds `CrawlModule`, `CrawlDecisionEngine`, `extract` helpers, and endpoint graph relationships. Confirmed `HttpProbe` endpoint observations propose root crawl tasks; crawl discovery events propose same-origin follow-ups only through the Decision Engine with depth/page budgets.
- Local tests cover root extraction, relative/absolute/query/fragment behavior, forms observation without submission, static JavaScript extraction without execution, robots/sitemap handling, out-of-scope observations without contact, relationship emission, and Decision Engine eligibility/dedup boundaries.

## Phase 10 verification

- `cargo fmt --check`, `cargo check`, `cargo test`, `cargo clippy --all-targets --all-features -- -D warnings`, `git diff --check`, and `cargo run --example phase10_bench` are the required completion checks.
- Phase 10 adds `BaselineModule`, `BaselineDecisionEngine`, typed baseline events, and baseline relationships. Confirmed/crawled endpoint events propose endpoint baseline tasks; only the first baseline task per scan-lifetime origin performs synthetic missing-path probes. Origin identity is scheme + canonical host + effective port.
- Phase 10 duplicate/similarity intelligence is implemented with compact scan-lifetime signature representatives keyed by raw hash, normalized hash, and bounded template buckets. It emits `DuplicateObserved` / `SimilarResponseObserved` with `DuplicateOf` / `SimilarTo` relationships without retaining response bodies.
- Baseline evidence records bounded response signatures, conservative normalized fingerprints, endpoint class, parameter inventory, redirect out-of-scope state, soft-404/wildcard observations, and optional interestingness factors. It does not submit forms, mutate parameters, execute JavaScript, brute force content, guess sensitive paths, or infer vulnerabilities.
- Local tests cover deterministic signatures, normalization, similarity thresholds, scan-lifetime origin-baseline reuse, cross-task duplicate/similarity relationships, soft-404/wildcard behavior, redirect canaries, query parameter value classes, cancellation, timeout, stale scope, JSONL round trip, and Scheduler/Decision Engine production admission.
- `cargo run --example phase10_bench` — controlled local baseline recorded in `docs/benchmark-results/phase10-baseline-intelligence.md` (8 endpoint signatures, one shared origin baseline, local-only, no competitor claims).

## Phase 11 verification

- `cargo fmt --check`, `cargo check`, `cargo test`, `cargo clippy --all-targets --all-features -- -D warnings`, `git diff --check`, `cargo run --example phase11_bench`, and `cargo build --release` are the required completion checks.
- Phase 11 adds `ContentDiscoveryModule`, `ContentDecisionEngine`, `-w/--wordlist`, TOML `wordlist`, typed content events, and content relationships. Content tasks are origin-stable for scheduler deduplication and are proposed by the Decision Engine only.
- Candidate sources are a 12-entry built-in set and optional streamed user file at L4+. Candidate memory is released line-by-line; large files remain bounded by line, candidate, request, event, evidence, and dedup caps.
- Baseline-aware classification rejects soft-404/wildcard-like matches using Phase 10 origin-baseline normalized signatures. A 200 response alone is not considered discovered. Content candidate contacts also consult the compact scan-lifetime contacted-request registry shared with crawling and baseline work.
- Local tests cover built-in/user-file candidates, comments/blanks/oversized lines, normalization, canonical dedup, out-of-scope redirect canary, hard/soft not-found, forbidden/unauthorized/redirect/static/JSON discovery, budgets, cancellation, timeout, unreadable files, scheduler integration, level/speed behavior, JSONL/provenance, large streamed wordlists, and IPv6 when loopback bind is available.
- `cargo run --example phase11_bench` — controlled local benchmark recorded in `docs/benchmark-results/phase11-content-discovery.md` (24 candidate lines, explicit request-category accounting, local-only, no competitor claims).

## Phase 12 verification

- `cargo fmt --check`, `cargo check`, `cargo test`, `cargo clippy --all-targets --all-features -- -D warnings`, `git diff --check`, `cargo run --example phase12_bench`, and `cargo build --release` are the required completion checks.
- Phase 12 adds `FuzzModule`, `FuzzDecisionEngine`, typed fuzz events, and behavior-delta relationships. Fuzz tasks are proposed only from Phase 10 `ResponseSignatureObserved` events for endpoints with observed non-sensitive GET query parameters, and only for `fuzz`/`custom` goals at L3+. A bounded scan-lifetime origin budget admits at most 2/4/8 fuzz tasks per canonical origin at L3/L4/L5, with 256 tracked origins per scan.
- Active mutation support is intentionally narrow: GET query parameters only, one parameter at a time. POST forms, GET-form active submission, cookies, headers, path-variable mutation, exploit payloads, credential attacks, and vulnerability findings are not implemented.
- Local tests cover disabled levels, observed-parameter requirement, sensitive skips, omission/empty/numeric/text mutations, one-parameter-at-a-time behavior, per-origin fuzz budgeting, speed semantic invariance, task/request identity, redirect out-of-scope canary, cancellation, timeout, JSONL/provenance, IPv6 when loopback bind is available, and production Scheduler/Decision Engine wiring.
- `cargo run --example phase12_bench` — controlled local benchmark recorded in `docs/benchmark-results/phase12-contextual-fuzzing.md` (observed inputs, eligible inputs, mutation/request accounting, behavior deltas, reflections, local-only, no competitor claims).

## Phase 13 verification

- Phase 13 adds `DnsModule`, native bounded UDP DNS queries, defensive DNS packet parsing, scan-lifetime DNS query/domain dedup, typed DNS events/evidence/assets/relationships, and Decision Engine follow-up proposals from in-scope A/AAAA answers to existing HostDiscovery tasks.
- Supported record observations: A, AAAA, CNAME, MX, NS, TXT, PTR. TXT is informational and byte-bounded. PTR is observational and does not authorize active hostname scanning. UDP responses with the TC bit set produce an explicit `Truncated` outcome and are not treated as complete answers; TCP fallback is NOT IMPLEMENTED. Wildcard DNS, SRV, DoH/DoT, custom CLI resolver flags, subdomain brute force, AXFR/IXFR, DNS persistence, and takeover/vulnerability findings are NOT IMPLEMENTED.
- DNS uses system resolver configuration by default; tests and benchmarks pass an explicit local UDP resolver through task params. No new production dependency is added.
- Local tests cover hostname canonicalization, resolver config parsing, parser malformed-packet boundaries, truncated UDP handling, A/AAAA/CNAME chain/loop/depth, MX/NS/TXT/PTR observations, JSONL/provenance, NXDOMAIN/SERVFAIL/REFUSED, timeout, cancellation before query, exact and cross-batch DNS query dedup, registry capacity, per-domain budget fairness, scope-blocked follow-ups, IPv4/IPv6 records, and production Decision Engine follow-up wiring.
- `cargo run --example phase13_bench` — controlled local DNS benchmark recorded in `docs/benchmark-results/phase13-dns-asset-intelligence.md`.

## Phase 14 verification

- Phase 14 adds `persistence`, a versioned schema-1 JSON checkpoint format with an 8 MiB hard input/output cap, temp-file write/flush/file-sync/rename, old-checkpoint preservation before successful rename, and strict validation before any resume execution.
- Checkpoints persist semantic state: effective `ScanPlan`, scan ID, task snapshots, completed module outputs, compact ContactRegistry entries, origin baseline hashes, fuzz origin-budget consumption, and DNS query/domain registry state. Raw HTTP bodies, raw DNS packets, sockets, channels, thread handles, TLS sessions, credentials, cookies, and wordlists are not persisted.
- Resume reconstructs tasks through the real Scheduler. Succeeded tasks remain completed; running/ready tasks are restored as pending/interrupted work. Persisted scope is authoritative and cannot be widened by resume. Speed may be overridden because speed is pressure only.
- Local tests cover schema round trip, unsupported/malformed/truncated/oversized rejection, atomic-save preservation, filesystem save-failure preservation, resume CLI override rejection, scope rejection, malicious pending-task rejection, invalid-load zero-contact matrix, dangling graph rejection, registry restoration, origin-baseline production-path reuse, baseline-similarity reconstruction, fuzz/DNS budget continuity, completed-work skip, duplicate post-resume task proposals, pending/running restoration, task identity validation, checkpoint relocation identity, IPv6 state round trip, fresh-vs-resumed scheduler equivalence, repeated resume boundedness, collection limit validation, sensitive-marker rejection/absence, and JSONL event compatibility.
- `cargo run --example phase14_bench` — controlled local persistence benchmark recorded in `docs/benchmark-results/phase14-persistence-resume.md`.

## Phase 15 verification

- Phase 15 adds `diff`, a zero-network semantic comparison layer for two validated Phase 14 checkpoints. It indexes assets, relationships, findings, and task coverage by stable semantic keys.
- `rxscan diff <old.rxscan> <new.rxscan>` prints a compact human summary; `--json`/`--jsonl` emits deterministic structured output with diff schema version `1`.
- Missing entities are coverage-aware: comparable completed coverage can produce confirmed removals, while reduced level/module coverage, partial tasks, or timeout/error/cancelled states produce inconclusive missing records.
- Local tests cover same-state/no-change, insertion order, speed-only difference, checkpoint path independence, incompatible targets, added/modified assets, port/service transition, DNS relationship changes, finding changes, reduced/expanded coverage semantics, network-error false-removal prevention, invalid checkpoints, output cap truncation, IPv4/IPv6 state, and large bounded comparison.
- `cargo run --example phase15_bench` — controlled local diff benchmark recorded in `docs/benchmark-results/phase15-scan-diff.md`.

## Phase 16 verification

- Phase 16 adds `analysis`, a zero-network deterministic attention-ranking layer over validated Phase 14 scan state and optional Phase 15 `DiffReport` records.
- Output is typed `AnalysisReport` schema version `1` with bounded `PrioritySignal` records, score components, attention bands, reason codes, evidence IDs, related asset IDs, and `network_requests=0`.
- Scores are attention ranking, not vulnerability severity: evidence, novelty/change, exposure, corroboration, breadth, context, and uncertainty penalty are explicit integer components clamped to 0..100. Bands are `HighAttention` 80–100, `MediumAttention` 50–79, `LowAttention` 20–49, and `Informational` 0–19.
- `rxscan analyze [--json|--jsonl] [--diff <old.rxscan>] <current.rxscan>` is a thin offline CLI wrapper. It does not start the Scheduler, contact DNS/TCP/HTTP services, mutate checkpoints, or implement Phase 17 reporting.
- Local tests cover analysis without diff, diff-boosted new/changed exposure, confirmed vs inconclusive priority, corroboration, reflection/admin wording safety, soft404 suppression, out-of-scope relationship marking, duplicate/cap determinism, invalid diff pairing, IPv6 state, zero-network counters, speed/timestamp/insertion-order invariance, and finding priority.
- `cargo run --example phase16_bench` — controlled offline analysis benchmark recorded in `docs/benchmark-results/phase16-analysis-prioritization.md`.

## Phase 17 verification

- Phase 17 adds `report`, a deterministic offline presentation layer over validated Phase 14 scan state, optional Phase 15 `DiffReport`, and optional Phase 16 `AnalysisReport`.
- `rxscan report [--format human|json|jsonl|raw] [--summary-only] [--top N] [--diff <old.rxscan>] [--analysis] [--output <path>] <scan.rxscan>` renders one normalized report model. The default human output is concise; JSON is one complete model; JSONL streams typed records; raw is a versioned semantic export of persisted typed data, not raw network payloads.
- Report schema version is `1`. Default human top attention count is 10 and `--top` is hard-capped at 100. Human detail lists are bounded and terminal-visible strings are sanitized for control characters. Machine output remains JSON-encoded and deterministic.
- Phase 17 does not rescore analysis, reinterpret diff certainty, create findings, infer vulnerabilities, contact the network, mutate checkpoints, implement HTML/PDF/Markdown templates, or implement Phase 18 project/history mode.
- Local tests cover scan-only reports, full diff+analysis reports, InconclusiveMissing preservation, attention-vs-severity wording, finding confidence separate from attention score, terminal sanitization, deterministic JSON/JSONL/human output, path/timestamp/speed invariance, IPv6/multi-target state, partial scan wording, summary-only/top-N behavior, raw semantic export exclusions, JSON round trip, JSONL line validity, large JSONL output, output collision/write-failure preservation, invalid inputs, CLI paths, clean machine stdout, language safety, and zero-network counters.
- `cargo run --example phase17_bench` — controlled offline report benchmark recorded in `docs/benchmark-results/phase17-reporting.md`.

## Phase 18 verification

- Phase 18 adds `project`, a versioned schema-1 JSON project state with deterministic project identity, revision/fingerprint conflict detection, atomic temp-file/flush/file-sync/rename writes, and a 16 MiB hard file cap.
- `rxscan project create|add|summary|show|neighbors|scans|findings|changes|attention` provides a minimal offline CLI with human/JSON/JSONL renderers. It does not start the Scheduler, contact network modules, watch files, spawn a daemon, or initialize during normal scans/diff/analyze/report commands.
- Project state separates entities from observations. Repeated assets, relationships, and findings deduplicate by stable semantic identity (severity-aware findings, kind+identity entities, kind+endpoints relationships) while observation counts/history track where they appeared. Semantic fingerprint ignores timestamps/speed/paths/order. P15 change refs preserve certainty; P16 analysis refs preserve score/band without rescoring.
- Bounded graph queries support entity lookup, neighbor traversal (default depth 1, hard max 3), and findings/changes/attention filters (default limit 100, hard max 1000). Neighbor BFS is hard capped by `MAX_GRAPH_QUERY_VISITED` (4096), `MAX_GRAPH_QUERY_QUEUE` (2048), `MAX_GRAPH_QUERY_EXPANSIONS` (2048), `MAX_GRAPH_QUERY_EDGE_BUDGET` (8192) with no full-project adjacency map; results are canonically ordered and deterministic under caps with `exhaustive`/`results_discovered`/`queue_peak`/`visited_peak`/`expansions` metadata (`results_total` exact only when `exhaustive`).
- Fingerprinting streams a borrowed view directly into SHA-256 with zero whole-state clones and zero serialization buffer; saves stream pretty JSON to temp with size enforced during the write (8 KiB buffer, no stacked full copies). Both the 16 MiB file cap and collection caps apply, whichever first rejects.
- Local tests (40) cover create/import, semantic fingerprint invariance, duplicate and repeated duplicate import, incremental import, entity/relationship/finding dedup, severity preservation, target separation, IPv6 service/endpoint survival, external entity marking without authorization, change certainty, attention preservation, depth/cycle/result caps, query ordering, corrupt/unsupported/dangling rejection, relocation/path invariance, determinism, import-order semantics, atomic save, save-failure preservation, conflict detection, collection-limit boundaries, human conciseness, JSON determinism, streaming JSONL, terminal safety, raw-marker/credential exclusion, path-leak exclusion, CLI paths, zero-network counters, lazy isolation, thread bounds, memory bounds, large bounded growth, fingerprint no-clone audit, high-degree/adversarial bounded queries, capped determinism, lower-bound totals, large open memory, oversized-save preservation, and cap/streaming audits.
- `cargo run --example phase18_bench` — controlled offline project benchmark recorded in `docs/benchmark-results/phase18-project-graph.md`.

## Phase 20 verification (release candidate ready, NOT released)

- Phase 20 proves release readiness without assuming it: clean build/install,
  predictable CLI, safe interruption, stable formats, useful errors, no
  hidden runtimes, offline guarantees, reproducible validation, and
  artifact/source correspondence. No new reconnaissance capability.
- Release-critical fixes: speed-governor single derivation (exact regression
  tests + monotone pressure matrix); checkpoint validity for real scans
  (typed port assets, owned-evidence anchors, same-ID asset merges,
  resolvable crawl/content relationships, asymmetric crawl/content contact
  rule); non-UTF8 CLI panic; silent missing wordlists (fail fast) and
  unknown config keys (rejected); atomic scan output; broken-pipe-safe
  machine output with exit codes 0/1/2.
- Release engineering: `scripts/release-check.sh` full gate;
  `examples/phase20_release_gate.rs` evidence bench; `tests/phase20_release.rs`
  (CLI/exit/stdio/SIGINT/schema/E2E/soak coverage); golden schema fixtures;
  rewritten README; CHANGELOG; SECURITY.md; `docs/RELEASE_CHECKLIST.md`;
  release-gate benchmark record. CI runs fmt/check/tests/clippy/release
  build on Linux x86_64 (Rust 1.85 pin); no macOS/Windows claims.
- Remaining release blocker: no `LICENSE` file ships (manifest declares
  MIT; copyright-holder confirmation required before distribution).
- Full suite: 23 targets, 452 debug + 452 release tests passing, 0 failed,
  0 ignored. Nothing published, pushed, tagged, or uploaded.

## Phase 19 verification

- Phase 19 hardens P0–P18 under realistic scale with zero new reconnaissance
  capability, zero new production dependencies (10 prod / 1 dev, unchanged),
  and zero new tuning knobs. All optimizations preserve semantic truth
  (level = breadth/depth, speed = pressure).
- Production changes: scheduler peak observability (`queue_peak`,
  `active_peak`) plus a linear final sweep; TCP `fd_peak` observability;
  cached sort keys in open-port extraction and crawl follow-up planning;
  interval port-coverage in diff normalization (no 65k-String expansion);
  streaming checkpoint saves (byte-identical output); borrow-based output
  sorting. Before/after behavior is covered by the unchanged P0–P18 suites
  plus 43 new structural tests.
- `cargo run --example phase19_bench` — six-section controlled benchmark
  (scheduler/TCP/web/persistence/project/fairness) recorded in
  `docs/benchmark-results/phase19-performance-hardening.md`. Release on the
  reference box: 1500 scheduler tasks in 459ms (queue 64/64, 4 of 12 CPUs),
  65,535 ports resolved in 0ms with `fd_peak=32`, 4.6 MiB checkpoint
  save/load in 21/23ms, 11.7 MiB project open/fingerprint/query in
  72/21/450ms with all graph caps hit exactly, peak RSS 104 MiB composite,
  CPU/wall ratio 0.7. Release binary `8,305,344` bytes (+94,576 over P18).
- Local tests (43) cover large scheduler accounting, fairness under bounded
  sustained load, mass cancellation, deadline/timeout under load, retry and
  failure storms, all-ports structure and diff coverage, real-socket FD
  bounds, FD exhaustion in a 64-FD child process, saturation backpressure,
  level/speed invariance, CIDR caps, service plan bounds, crawl/content/fuzz/
  DNS scale and dedup, slow/oversized HTTP peers, checkpoint/resume/diff/
  analysis/report scale, large project bounds with P18 invariants, duplicate
  storms, determinism, multitasking bounds, IPv6, malformed inputs,
  zero-contact rejections, startup laziness, output backpressure, and offline
  counters. Full workspace suite (22 targets) green; `cargo fmt --check`,
  `cargo clippy --all-targets --all-features -- -D warnings`, and
  `git diff --check` clean.
- Known limitation documented: external mid-run `cancel_all` is unreachable
  while `run()` holds `&mut`; in-run cancellation via tokens, per-task
  timeouts, and the global budget is stressed instead.
