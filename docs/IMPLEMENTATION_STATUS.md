# Implementation status and gap analysis

## Repository baseline

The repository had no commits and contained an uncommitted Rust Phase-0-style skeleton plus a separate static portfolio. The portfolio is preserved and excluded from RXScan engine work. The skeleton normalized targets, performed basic scope checks, and compiled a plan, but had no CI, fixture or benchmark foundation, TOML configuration, goal/level/speed model, or complete planning docs.

## Current state

Phases 0 through 14 are complete. RXScan now performs real bounded host discovery, native TCP connect port scanning, native service/protocol identification, bounded DNS observations, bounded HTTP/1.1 web observations, deterministic bounded crawling from confirmed web endpoint evidence, baseline web intelligence for confirmed/crawled endpoints, managed content discovery, contextual GET query fuzzing, and bounded checkpoint/resume through the existing scheduler. Decision Engine flow is host→port, open-port→service, DNS A/AAAA→scoped host discovery, service→web, confirmed endpoint/discovery→crawl/baseline, origin baseline→content, and baseline signature with observed safe query parameter→fuzz. No UDP scanning, POST/form fuzzing, cookie/header/path-variable fuzzing, authentication automation, JavaScript execution, headless browsing, vulnerability checks, brute force, exploitation, cipher enumeration, scan diff/change detection, or technology fingerprinting exist yet.

| Area | Current state | Next |
| --- | --- | --- |
| Native Rust core | Foundation + data model + control plane + host + TCP + DNS + service + web + bounded crawler + baseline intelligence + managed content discovery + contextual GET query fuzzing + checkpoint/resume established (rustls/x509-parser for TLS observation) | Phase 15 scan diff/change detection |
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
