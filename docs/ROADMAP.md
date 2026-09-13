# RXScan roadmap

Each phase requires tests, benchmark/regression evidence where applicable, documentation, and an explicit exit review.

| Phase | Deliverable | Status |
| --- | --- | --- |
| 0 | Architecture, tooling, fixtures, benchmark discipline, CI | Complete |
| 1 | Target model, CLI, Scope Guard, config, ScanPlan | Complete |
| 2 | Events, findings, stable asset IDs, relationships | Complete |
| 3 | Reactive scheduler, queues, cancellation, backpressure | Complete |
| 4 | Control-plane completion: plan→task lowering, level/speed policy, budgets, scheduler bootstrap, scaffold executors, JSONL output | Complete |
| 5 | Host Discovery Engine: real bounded ICMP echo + TCP reachability via scheduler, host-state model, discovery policy, CIDR bounding, evidence/events, JSONL | Complete |
| 6 | Native TCP Port Discovery Engine: TCP connect scanning via scheduler, port-state model, bounded tasks, Decision Engine V1, open-port JSONL + summary | Complete |
| 7 | Service Intelligence + Native Protocol Probing: SSH/HTTP/TLS/HTTPS/FTP/SMTP/Redis/MySQL/PostgreSQL/generic probes via scheduler, service assets, Decision Engine open-port→service, evidence-graded confidence | Complete |
| 8 | HTTP/TLS Web Foundation: bounded HTTP/1.1 observations, canonical URLs, bounded redirects, TLS/certificate evidence, Decision Engine service→web, no crawling | Complete |
| 9 | Bounded Web Crawler + Endpoint Graph: confirmed endpoint→crawl proposals, bounded same-origin extraction, forms/robots/sitemaps/static-JS observations, endpoint relationships | Complete |
| 10 | Baseline Web Intelligence: bounded response signatures, conservative normalization/similarity, soft-404/wildcard origin baselines, endpoint classes, parameter inventory, interestingness metadata | Complete |
| 11 | Managed Content Discovery: bounded built-in/user-file path candidates, Phase 10 baseline filtering, typed content evidence, no fuzzing | Complete (current) |
| 12–15 | Contextual fuzzing, DNS, deeper API workflows, UDP, technology fingerprinting | Not implemented |
| 16–19 | Decision engine workflows, API workflows, checks, graph/correlation | Not implemented |
| 20–24 | Outputs, resume/diff/projects, packs, benchmark lab, releases | Not implemented |

Phase 6 is the first real port-scanning engine (TCP connect only). No UDP scanning, SSH protocol enumeration, HTTP crawling, fuzzing, DNS enumeration, vulnerability checks, exploitation, or broad service fingerprinting exist yet (open means open; versions belong to Phase 7). Deeper network tasks still run as `Skipped` (`module unavailable`).

Phase 7 takes open TCP ports and identifies the speaking service with native protocol probes (SSH/HTTP/TLS/HTTPS/FTP/SMTP/Redis/MySQL/PostgreSQL + passive generic) through the scheduler, with evidence-graded confidence and no authentication. No web crawling, directory discovery, fuzzing, DNS enumeration, UDP scanning, vulnerability checks, brute force, or exploitation exist yet.

Phase 8 adds the HTTP/TLS web foundation: bounded HTTP/1.1 GET/HEAD observations (status/headers/cookies/title/body-sample/redirects), canonical URLs with stable IDs, bounded redirect chains with per-hop scope checks, and TLS/certificate evidence for HTTPS — all through the scheduler and Decision Engine. Still absent by design: crawling, recursive link following, robots/sitemap traversal, directory brute forcing, content discovery, endpoint/API enumeration, JavaScript extraction, parameter discovery, wordlists, fuzzing, cipher enumeration, vulnerability scanning, and exploitation.

Phase 9 adds deterministic bounded crawling from confirmed HTTP/HTTPS endpoint evidence only. `HttpProbe` completions propose root `Crawl` tasks through the Decision Engine; crawler discoveries return to the Decision Engine for same-origin follow-up proposals with inherited depth/page budgets. Extraction covers links, forms as observation-only metadata, script/style/image/frame/canonical references, robots.txt, sitemap XML, and conservative static JavaScript string literals. Out-of-scope candidates are recorded and never contacted. Still absent by design: directory brute forcing, path guessing, wordlists, parameter mutation/fuzzing, form submission, authentication automation, JavaScript execution, headless browsers, vulnerability checks, exploitation, and arbitrary scope expansion.

Phase 10 adds baseline web intelligence for confirmed and crawled endpoints. `HttpProbe`/`Crawl` outputs propose `Baseline` tasks through the Decision Engine; endpoint-specific tasks record signatures/classes/parameters while origin-level synthetic missing-path probes are deduped per decision output. Signatures include raw and normalized SHA-256 body fingerprints, selected header/title/HTML-structure hashes, status, MIME, length bucket, and truncation. Soft-404 and wildcard-like behavior require two same-origin inert missing-path samples. Still absent by design: wordlists, guessed paths beyond inert baseline tokens, parameter mutation/fuzzing, form submission, vulnerability scanning, JavaScript execution, headless browsers, UDP, cipher enumeration, and technology fingerprinting.

Phase 11 adds managed content discovery. Content tasks are proposed by the Decision Engine from confirmed web origins and Phase 10 origin baselines; the module consumes a small built-in candidate set and optional streamed `-w/--wordlist` file. Candidates are path/resource names only, normalized into the same origin, scope-checked before contact, deduped by canonical URL, fetched with Phase 8 HTTP/TLS primitives, and filtered with Phase 10 baseline signatures. It does not perform placeholder fuzzing, parameter mutation, form submission, method enumeration, recursive directory explosion, vulnerability scanning, JavaScript execution, or headless browsing.

## Phase 9 exit criteria

- Crawl eligibility starts only from confirmed `EndpointObserved` HTTP/HTTPS evidence; port numbers and guesses are insufficient.
- `Crawl` modules never enqueue work directly. Root and recursive crawl tasks are proposed by the Decision Engine and admitted by scheduler scope/budget/dedup.
- URLs use the Phase 8 `WebTarget` canonical form: scheme/host/port/path/query are stable; fragments do not create network identities.
- Level matrix: L1 root-only extraction, no recursion; L2 shallow same-origin crawl (depth 1, 5 pages/root); L3 normal bounded crawl (depth 2, 15 pages/root) with robots/forms/scripts observations; L4 deeper crawl (depth 3, 40 pages/root) with sitemap and static-JS extraction; L5 deepest Phase 9 bounded crawl (depth 4, 100 pages/root). Hard ceilings remain depth 6 and 200 pages/root.
- Per-page and resource caps are enforced: 100 links/page hard cap, 20 forms/page, 20 scripts/page, 50 images/page, 128KiB HTML, 64KiB JS, 32KiB robots, 500 sitemap entries, 3 sitemap files/root, bounded redirects via Phase 8 policy.
- Scope is checked before admission, execution, request, redirect, discovered fetch, JS fetch, robots fetch, sitemap fetch, and Decision Engine follow-up.
- Typed events/evidence/assets include crawl lifecycle, endpoint discoveries, link/form/script/robots/sitemap observations, budget exhaustion, and relationships (`LinksTo`, `SubmitsTo`, `LoadsScript`, `ReferencesEndpoint`, `ReferencesSitemap`, `ListsEndpoint`).
- Tests are deterministic/local-only and include canary proof that forms are not submitted and out-of-scope links receive zero contacts. Baseline recorded in `docs/benchmark-results/phase9-crawler-baseline.md`.

## Phase 10 exit criteria

- Baseline eligibility starts from confirmed `EndpointObserved` or in-scope `EndpointDiscovered` evidence only; the `Baseline` module never self-schedules.
- Baseline requests reuse Phase 8 `WebTarget` and HTTP/TLS fetch primitives, including redirect caps, per-hop scope checks, deadlines, cancellation, and body/header bounds.
- Level matrix: L1 basic signature/classification only; L2 adds exact duplicate-ready signatures; L3 adds normalized signatures plus two synthetic missing-path samples for soft-404/wildcard characterization; L4 enables bounded similarity/template grouping signals and parameter inventory; L5 adds deterministic interestingness scoring. Hard caps include 64KiB signature body input, two synthetic requests/origin, 128 endpoint proposals/completion, 32 parameter records/task, and 8 baseline findings/task.
- Normalization is conservative: lowercase, whitespace collapse, tag-adjacent whitespace cleanup, and obvious long numeric/request IDs normalized; unrelated short pages with the same title are not collapsed.
- Synthetic paths use inert `__rxscan_baseline_<token>__` names on the same origin only. They are not wordlist/content discovery and never expand scope.
- Typed output includes baseline lifecycle, response signature, origin baseline, soft-404, wildcard, endpoint classification, parameter, budget-exhaustion events, evidence, and relationships for future duplicate/similarity grouping.
- Tests are deterministic/local-only and cover signatures, similarity thresholds, soft-404/wildcard, redirect canaries, parameters, cancellation/timeout/stale scope, JSONL round trip, and production Scheduler/Decision Engine admission. Baseline recorded in `docs/benchmark-results/phase10-baseline-intelligence.md`.

## Phase 11 exit criteria

- Content discovery starts from confirmed web origin evidence and Decision Engine proposals; modules never self-schedule.
- Candidate sources are a 12-entry built-in set plus explicit streamed user files at L4+. Blank lines and `#` comments are ignored; lines over 512 bytes, absolute URLs, authorities, backslashes, control characters, and traversal components are rejected.
- Level matrix: L1 disabled; L2 tiny built-in set; L3 larger built-in set with baseline-aware filtering; L4 full built-in set plus streamed user file; L5 largest Phase 11 request/candidate budgets. Speed controls pressure only.
- Hard caps include 2,000 candidate lines read, 512 admitted candidates, 128 requests/task, 64KiB response bytes, 64 discovered endpoints, 256 events, 128 evidence records, 16 findings, and 1,024 dedup entries.
- Typed output includes content lifecycle, candidate attempts, discovered/rejected/redirect observations, budget exhaustion, endpoint assets, evidence, and relationships (`DiscoveredByContentProbe`, `DerivedFromCandidateSource`).
- Tests are deterministic/local-only and cover built-in/user candidate sources, streaming, dedup, baseline rejection, canary redirects, budgets, cancellation, timeout, scheduler integration, level/speed behavior, JSONL, provenance, and IPv6 where loopback bind is available. Benchmark recorded in `docs/benchmark-results/phase11-content-discovery.md`.

## MVP v0.1 gate

TargetSpec, Scope Guard, ScanPlan, stable IDs/events, scheduler, speed/budgets, host discovery, TCP, basic SSH/HTTP/HTTPS/TLS fingerprinting, managed content discovery, basic path fuzzing, JSON output, tests, and benchmark baseline.

## Phase 1 exit criteria

- IPv4, IPv6, hostname, URL, CIDR, file, and stdin target inputs normalize safely.
- Scope is deny-by-default; exclusions override allowances and excluded seeds fail before execution.
- Explicit global and project TOML configuration resolve deterministically; CLI overrides them.
- Goals, level 1–5, and speed presets/0–100/auto are represented independently in `ScanPlan`.
- `--explain` describes choices and deferred capability.

## Phase 2 exit criteria

- Canonical assets, findings, evidence, events, and relationships have versioned JSON/JSONL representations and deterministic correlation IDs.
- Every record has module/version/plan/timestamp provenance; confidence is validated from 0 through 100.
- Host, IP, and URL assets are admitted through the existing Scope Guard. Recording an observation never grants scheduling authority.
- Evidence detail capture is capped at 64 KiB and records truncation metadata.

## Phase 3 exit criteria

- Reactive scheduler with bounded priority queue, dependencies, retries, timeouts, cancellation, budgets, and speed governor exists in library code and is tested.
- Decision Engine boundary is enforced (only the engine proposes follow-ups; scheduler admits them).
- Queue saturation, retry fairness, timeout/cancel terminal states, scope/stale-scope enforcement, and evidence/task budgets are covered by tests.

## Phase 4 exit criteria

- Scheduler is reachable from the `rxscan` binary via `src/run.rs` bootstrap.
- `ScanPlan` lowers deterministically to initial tasks (`lower_plan_to_tasks`) with scope validation, level/goal filtering, dedup, and safe all-ports representation (one task, never 65k).
- `--level` selects task/module eligibility (centralized `src/level.rs` v1 policy); `--speed` controls concurrency, retry defaults, and timeout defaults (auto v1 is an honest non-adaptive balanced baseline).
- Budgets (`max_tasks`, `max_retries`, `max_concurrency`, `max_execution_time`, `max_evidence_bytes`) are configurable via TOML + CLI with documented precedence and fail-fast validation.
- Runtime emits valid typed JSONL (`--output <path>`, `--format jsonl`) with schema version and provenance; filesystem errors are clean errors.
- Task IDs are canonical SHA-256 over all execution-relevant fields; collision-regression tests exist.
- Timeout/cancellation, backpressure, and retry fairness are hardened and tested; module cancellation contract is documented.

## Phase 5 exit criteria

- `HostDiscovery` is a real scheduler module (native ICMP echo via unprivileged ping sockets + bounded TCP reachability; no shell `ping`); ICMP failure never means dead (Unknown, not Unreachable) and TCP RST/connect is Alive evidence.
- Discovery policy is centralized (`src/discovery.rs`): `--ping` prioritizes ICMP, `--discover` uses multi-probe, lightweight follows level; `--level` controls breadth (L1 minimal … L5 deepest bounded to 5 ports / 3 ICMP attempts), `--speed` controls pressure only (timeouts, concurrency, retry timing) and never state meaning.
- CIDR targets expand to bounded per-host tasks (lazy `hosts()` order, `max_hosts` default 256, exclusions win, deterministic, never materializing massive ranges); every target passes Scope Guard at lowering, admission/dispatch, and immediately before network execution; derived addresses never expand scope.
- Every probe honors timeout, cancellation, bounded retries (ICMP 1–3, TCP 1/port ≤8), concurrency via scheduler, budget accounting, and cleanup (no hanging sockets/leaked workers).
- Typed events (`DiscoveryStarted`, `ProbeAttempted/Succeeded/TimedOut/Unavailable`, `HostStateConcluded`, `HostDiscovered`) plus evidence explain every Alive/Unreachable/Unknown conclusion with confidence, techniques, latency, provenance, and timestamps in the existing JSONL envelope.
- CLI preserved (`TARGET --ping`, `TARGET --discover`, `CIDR --discover`); advanced tuning via config (`max_hosts`, `discovery_ports`); no Phase 6 port scanner claimed.
- Tests are deterministic/local-only (loopback, temporary listeners, fakes); benchmark baseline recorded in `docs/benchmark-results/phase5-host-discovery-baseline.md` with no Internet traffic and no superiority claims.

## Phase 6 exit criteria

- Native TCP connect scanning is real (non-blocking `poll(2)` window, no shell/external scanner, no raw SYN, no thread per port); single/explicit/range/common/`--all-ports` plus IPv4/IPv6 work.
- Port states are explicit (`Open`/`Closed`/`FilteredOrTimedOut`/`Error`): success vs refused/reset vs timeout vs unreachable/permission vs cancel stay distinct with evidence.
- ONE `PortDiscovery` scheduler task per target carries the full selection (`ports=common|explicit|all`); the module scans internally with a bounded window (16–128, hard 256), sorted deterministic output, truncated per-port detail for huge scans.
- Canonical selection (`common`/`explicit`/`ranges`/`all`) normalizes/dedupes/sorts and rejects port 0, >65535, reversed/malformed input; overlaps scan once. Versioned common profile (`COMMON_PORTS_V1`) is centralized for future packs.
- Host→port flow runs through Decision Engine V1 (Alive → propose, Unknown → explicit-or-level≥3, Unreachable → skip; scope pre-check; dedup-shaped proposals; best-effort admission); modules never self-schedule; ICMP failure never stops scanning by itself.
- `--speed` controls concurrency/pacing/timeouts/retries only (never the set); `--level` controls automatic breadth only (L1 minimal … L5 broad ≤32); explicit `--ports`/`--all-ports` override level.
- Concurrency/resource safety holds (bounded window, FD cleanup/backoff, task deadline truncation, prompt cancel); timeouts derive from speed with hard limits; retries only for filtered (≤1), never for refused/cancel.
- Scope cannot be bypassed (lowering/admission/dispatch/module checks; derived hostname IPs filtered; max-host respected); port assets are stable children (`parent:tcp/port`, no cross-parent/proto collisions).
- Typed port events (`PortScanStarted/ProbeAttempted/Open/Closed/TimedOut/ProbeError/Completed`), per-open evidence/findings/assets, and a scan summary flow into the existing JSONL envelope; terminal output prioritizes opens (`HOST`/`PORT STATE` table) and stays quiet on closed detail.
- Service boundary holds: open means open, no version claims (checked by test).
- Tests are deterministic/local-only (listeners, closed loopback, fakes, synthetic ranges); benchmark baseline recorded in `docs/benchmark-results/phase6-tcp-baseline.md` with no Internet traffic and no Nmap/RustScan claims; all previous suites remain green.

## Phase 7 exit criteria

- Open TCP ports trigger `ServiceProbe` tasks via the Decision Engine only (open-port finding → scoped proposal → Scope Guard → scheduler admission; modules never self-schedule; service tasks never chain further).
- Probes are native Rust with an extensible `ProbeSpec` registry + deterministic `ProbePlanner` (port/level/goal → ordered probes; likely-probe-first ordering; level breadth L1 single … L5 ≤6; speed affects pressure only).
- SSH identification works without authentication (passive banner parse, product/version split, malformed/timeout paths stay non-SSH).
- HTTP identification works (status/headers/Server/Content-Type/Location/title, bounded 16KiB headers + 16KiB body, redirects observed never followed).
- Basic TLS identification works (rustls handshake observation, leaf subject/issuer/SAN/validity/fingerprint/hostname-match via x509-parser; no cipher enumeration).
- HTTPS requires real HTTP-over-TLS evidence inside the same session (TLS-only success stays bare `tls`, never `https`); SMTPS composes analogously.
- FTP/SMTP/Redis/MySQL/PostgreSQL identification is safe and bounded (passive greetings where possible; one EHLO / PING / SSLRequest at most; no credentials, no mail, no queries, no destructive commands — asserted by an exact-bytes allowlist test).
- Unknown services stay unknown with preserved bounded banners (generic passive read only; only a grammar-valid SSH identification string may classify, bare prefixes and fragments stay unknown); silent services complete as low-confidence unknown.
- Every classification carries evidence (handshake/banner/cert lines); findings exist only for classified services, never without evidence.
- Response sizes are bounded (2KiB banners, 16KiB HTTP halves, 32KiB chains, 4KiB SMTP) with truncation flags; requests are fixed small payloads.
- Cancellation is prompt (pre-cancel <1ms, mid-probe bounded by the 500ms read slice) and timeouts yield partial unknown results with truncation flags; per-probe connections are never retried.
- Scope cannot be bypassed (lowering/admission/dispatch/module/derived-address checks; out-of-scope and stale-scope paths tested); level affects probe breadth; speed affects budgets only.
- Stable service assets (`parent:service/label` identity, `asset_service_*` IDs) hang under port assets via `Runs` relationships; certificates are child assets with fingerprint identity.
- JSONL carries service assets/events/evidence/findings with provenance; the human table shows `PORT/SERVICE/PRODUCT` rows with `-` for absent products and no guessed versions.
- Tests are deterministic/local-only (fake banner servers, local HTTP, in-test rustls+rcgen TLS fixtures, silent/oversized/delayed fixtures); benchmark baseline recorded in `docs/benchmark-results/phase7-service-baseline.md` with no Internet traffic and no competitor claims; all Phase 0–6 suites remain green.

## Phase 8 exit criteria

- Bounded HTTP/1.1 probing is real (native GET/HEAD over plaintext and TLS, correct Host headers incl. IPv6 brackets and non-default ports, explicit ports honored); IPv4/IPv6/hostnames/custom ports work.
- Canonical URL model fills defaults, brackets IPv6, preserves path case/query, resolves relative redirects, and yields stable collision-free endpoint IDs.
- Redirects follow a deterministic policy cap (L1–L2 record-only, L3 ≤2, L4–L5 ≤4, hard 5) with per-hop scope checks, loop detection, malformed-Location safety, and full chain evidence; out-of-scope destinations are recorded, never contacted.
- Responses are strictly bounded (≤64 headers, 16KiB headers/body halves, ≤8 cookies/256B values, read/connect timeouts, task deadlines, cancellation, evidence budget) with truncation flags; malformed input is evidence, never panic or guess.
- Web assets (endpoint children of service/port assets), per-URL evidence, per-URL findings, certificate assets, and typed events (`WebProbeStarted/Completed`, `RedirectObserved`, `EndpointObserved` plus reused `HttpObserved`/`TlsObserved`) flow into the existing versioned JSONL envelope with provenance and relationships.
- Decision Engine proposes bounded WebProbe work for confirmed HTTP/HTTPS services only (scope/policy/budget/dedup enforced); `HttpProbe` completions propose nothing — no crawling follow-ups.
- `--level` sets breadth (HEAD vs GET, redirect depth, body detail), never pressure; `--speed` sets timeouts/concurrency only, never classification (same bytes classify identically at any speed).
- Tests are deterministic/local-only (scripted HTTP, in-test rustls+rcgen HTTPS, silent/oversized/delayed/malformed/loop/cap/canary fixtures); benchmark baseline recorded in `docs/benchmark-results/phase8-web-baseline.md` with no Internet traffic and no httpx/Nuclei claims; all Phase 0–7 suites remain green.
