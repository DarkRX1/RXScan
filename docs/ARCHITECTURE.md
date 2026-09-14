# RXScan architecture

RXScan is a native Rust, policy-driven reactive reconnaissance engine: **simple outside, serious inside**. It is not a wrapper around external scanners.

```text
Target / Scope -> ScanPlan Compiler -> Task Lowering -> Reactive Scheduler <-> Speed + Budgets
                                                     <-> Backpressure / Queue
                                                     -> HostDiscovery + TcpDiscovery + ServiceProbe + DnsProbe + WebProbe + Crawl + Baseline + ContentDiscovery + Fuzz Modules -> Typed Events / Evidence / Assets / Findings
                                                     -> JSONL Output + human service summary -> Decision Engine (host→port, open-port→service, service→web→crawl→baseline→content→fuzz)
                                                     -> scoped task proposals -> Scheduler
                                                     -> Checkpoint -> Diff -> Analysis -> Report renderers
                                                     -> ProjectState semantic graph / bounded queries
```

The Decision Engine proposes work only. The Scope Guard, policy validation, budget validation, and scheduler admission must approve every task before execution.

## Phase 0–12 Boundary

`cli` captures operator intent (`--ports`/`--all-ports`/`--ping`/`--discover` preserved; `--max-hosts` bounds CIDR; `-w/--wordlist` streams managed content candidates at L4+; `--checkpoint`/`--resume` save and restore one bounded scan state; `rxscan diff` compares two checkpoints offline; `rxscan analyze` ranks attention signals offline; `rxscan report` renders deterministic human/JSON/JSONL/raw semantic reports offline; `rxscan project` manages an offline compact project graph). `config` resolves explicit global then project TOML configuration with CLI precedence. `target`, `scope`, and `plan` normalize seeds, enforce deny-by-default scope, and create immutable `ScanPlan`s. `execution` owns scheduler admission, canonical task IDs, speed, budgets, cancellation, retries, output retention, and best-effort follow-up admission. `persistence` stores versioned semantic checkpoint JSON and reconstructs tasks through the Scheduler; it does not serialize sockets, threads, raw packets, or raw bodies. `diff` builds compact semantic snapshots from validated checkpoints and compares assets, relationships, findings, and coverage without contacting the network. `analysis` consumes validated scan state plus optional diff records and emits deterministic attention signals; attention is not severity and analysis never contacts the network. `report` builds one normalized versioned report model and renders human, JSON, JSONL, and raw semantic exports without reinterpreting P15/P16 meaning. `project` stores versioned project JSON with deduplicated entities, relationships, observations, finding refs, change refs, and analysis refs; graph traversal is bounded and project membership never authorizes scanning. Native modules perform host discovery, TCP connect scanning, DNS asset intelligence, service observation, HTTP/TLS probing, bounded crawling, Phase 10 baseline characterization, Phase 11 managed content discovery, and Phase 12 contextual GET query fuzzing. `decision` is the only component that turns facts into follow-up tasks: host→port, open-port→service, DNS A/AAAA→host discovery, service→web, confirmed/crawled endpoint→crawl/baseline, origin baseline→content, baseline signature with observed safe query parameter→fuzz. `dns` uses a bounded native UDP DNS client and defensive parser for A/AAAA/CNAME/MX/NS/TXT/PTR observations; DNS relationships are observational and do not authorize third-party follow-up. Still deferred: UDP port scanning, Phase 19 functionality, generic exploit fuzzing, POST/form submission, cookie/header/path-variable fuzzing, wildcard DNS, JavaScript execution, headless browsers, vulnerability checks, exploitation, cipher enumeration, and technology fingerprinting.

`--level` is investigation breadth/depth; `--speed` is execution pressure. They are deliberately independent. `--speed auto` v1 is a conservative deterministic baseline identical to `balanced` (non-adaptive; adaptive feedback deferred to Phase 4.1+). Stable asset/event/finding identity begins in Phase 2, before execution modules. Task identity (Phase 4) covers kind, module, scope target, params, priority, timeout, retry policy, asset, parent, dependencies, and plan.

## Security invariants

- No task may execute beyond central scope (checked at lowering, admission, promotion, and dispatch; stale scope skips; host module re-checks immediately before network execution; derived CIDR/DNS addresses re-checked and never expand scope).
- No module may schedule arbitrary follow-up work (only the Decision Engine proposes; scheduler admits).
- All operations require timeout, cancellation, response cap, retry cap, and budget accounting.
- Typed data crosses module boundaries; terminal output is never an API.
- Findings retain provenance, timestamps, confidence, and stable identities.
- Root host/IP/URL assets are created only through `Scope Guard`; child resources are namespaced by their already-checked parent and remain observations, not task authority.
- Evidence details are capped at 64 KiB with explicit captured/original byte counts and truncation state; JSONL output is additionally bounded by `max_evidence_bytes`.
- Task IDs are SHA-256 over canonical execution-relevant fields (collision-resistant for untrusted inputs).
- Timed-out tasks free their scheduler slot immediately; orphaned workers are bounded by the task budget and their late results are discarded without double-counting.
- Queue saturation is backpressure (tasks stay `Pending`), never a fatal abort; retry-delayed tasks never head-of-line block others.
- Host discovery never shells out to `ping`; raw/privileged failures degrade to structured `Unavailable` (never false Dead); CIDR expansion is bounded by `max_hosts` (default 256) and Level 5 host breadth is bounded (5 TCP ports, 3 ICMP attempts).
- TCP scanning never shells out and never uses raw SYN; connect success is Open, refused/reset is Closed, timeout is FilteredOrTimedOut (never misclassified as Closed), unreachable/permission failures are Error; one task per target with a bounded internal window (no thread per port, ≤256 concurrent FDs, retries only for filtered ≤1). Detailed non-open observations carry typed port assets; summary evidence anchors to an owned port asset (skipped when asset-less, counts preserved by the completion event).
- Crawling starts only from confirmed HTTP/HTTPS endpoint evidence. Every discovered URL is canonicalized, scope-checked, and budget-checked before contact; out-of-scope discoveries may be recorded but never fetched. Forms are observation only; JavaScript is never executed; crawler modules never self-schedule recursive work.
- Baseline intelligence starts only from confirmed or crawled endpoint evidence. Synthetic missing-path probes stay same-origin and inert (`/__rxscan_baseline_<token>__`), are remembered in compact scan-lifetime origin state keyed by scheme + canonical host + effective port, and remain scope/redirect checked before contact. Baseline code signs and classifies observed responses only; it never mutates parameters, submits forms, guesses paths, fuzzes, executes JavaScript, or reports vulnerabilities.
- Managed content discovery consumes bounded candidate sources only. Candidates cannot change scheme/authority, cannot traverse with `.`/`..`, and cannot trigger POST/PUT/PATCH/DELETE, form submission, method fuzzing, header fuzzing, or recursive directory explosions. Crawler-fetched URLs are skipped by content discovery (scan-lifetime contacted-URL dedup); content-fetched URLs never block crawler fetches, because only the crawler extracts links and skipping would silently drop crawl subtrees depending on task order (Phase 20 asymmetric rule).
- Contextual fuzzing starts only from existing evidence: a baseline signature for an endpoint with an observed non-sensitive GET query parameter. It mutates one parameter per request with inert values, reuses Phase 8 fetch and Phase 10 signatures, and emits behavior deltas/reflection observations only. It never submits forms, fuzzes POST bodies/cookies/headers, uses exploit payloads, or creates vulnerability findings.
- Reporting is presentation only. It loads validated semantic state, optional Phase 15 diff records, and optional Phase 16 analysis signals; it never starts the Scheduler, contacts the network, changes scope, rescoring signals, upgrades certainty, creates findings, or writes back to checkpoints. Human output sanitizes control characters; machine JSON/JSONL preserve data through JSON encoding.
- Project mode is organization only. It imports validated checkpoints into a compact `ProjectState`, separates entities from observations, deduplicates repeated semantic assets/relationships/findings, and serves bounded graph queries. It never starts the Scheduler, contacts the network, creates authorization, rescans assets, or runs background indexing.

## Phase 18 project graph

`ProjectState` (schema version `1`, 16 MiB hard file cap) stores semantic
information, not runtime machinery: `scans` (scan id, plan id, semantic
fingerprint, import sequence, coverage counts), `entities` (stable
`entity_<kind>_<hash(kind:identity)>` ids, kind, identity, attributes,
first/last scan, observation count, bounded per-entity observation history),
`relationships` (typed `RelationshipKind` edges with `rel_<hash>` ids,
first/last scan, observation count), `observations` (scan, entity,
fingerprint), `findings` (stable `finding_<hash(severity:title:entity:identity)>`
with severity/confidence/affected entity/history), `changes` (P15
`change_type`/`certainty`/`reason` refs), and `analysis_refs` (P16
score/band/label refs, never rescored).

Entity/observation separation: one entity plus bounded observation history,
not N copies of URL metadata. Same edge in 20 scans is one relationship plus
count/first/last. Same finding is one record plus history. P15
`InconclusiveMissing` stays inconclusive; P16 score/band render verbatim.

Semantic fingerprint hashes plan semantics (targets/scope/goal/level/ports/
discovery), deduplicated asset/relationship/finding semantics, and task
coverage shape. It ignores timestamps, `saved_at`, provenance timestamps,
speed/pressure, budgets, checkpoint paths, insertion order, and runtime task
order. Duplicate fingerprints import as no-ops (idempotent). Entity ids are
stable across import orders; `import_sequence` defines chronology explicitly
(B-then-A vs A-then-B differ in sequence, not in entity identity).

Indexes are `BTreeMap`/`BTreeSet`/`Vec` with stable ids; no graph library.
Traversal is hard-bounded BFS without a full-project adjacency map (each
expansion scans only its incident edges): default depth 1, hard max 3,
default limit 100, hard max 1000, plus work caps `MAX_GRAPH_QUERY_VISITED`
(4096), `MAX_GRAPH_QUERY_QUEUE` (2048), `MAX_GRAPH_QUERY_EXPANSIONS` (2048),
`MAX_GRAPH_QUERY_EDGE_BUDGET` (8192), independent of total entity count.
Deterministic canonical ordering (depth, relationship type, entity id,
relationship id) keeps capped queries identical under insertion-order
permutations. Metadata is `results_total` (= `results_discovered`, exact only
when `exhaustive`), `results_emitted`, `truncated`, `exhaustive`,
`queue_peak`/`visited_peak`/`expansions`; no unbounded traversal is done
merely to compute an exact total. Ordinary queries are bounded work, not
`O(project)`; no all-pairs, no PageRank/centrality/embeddings.

Mutation is `load revision N -> modify -> save N+1` with a deterministic
SHA-256 fingerprint streamed from a borrowed view (no whole-state clone, no
canonical byte buffer). Saves validate, stream pretty JSON directly to a temp
file beside the target via `to_writer_pretty` + 8 KiB `BufWriter` +
size-enforcing writer, flush, file-sync, then rename. The 16 MiB file cap is
enforced during the write; on `SizeLimit` the temp is removed and the old
project is unchanged. Concurrent writers are detected via
revision/fingerprint mismatch (no silent last-write-wins); documented race
window, no heavyweight locking. Corrupt/unsupported projects are rejected
before mutation with zero network. Both the file cap and per-collection caps
apply; whichever is reached first rejects (the file cap is usually hit far
before 500k observations with realistic records).

Offline invariant: project create/add/summary/show/neighbors/scans/findings/
changes/attention perform zero network requests and never enter the
Scheduler. Lazy invariant: `scan`/`diff`/`analyze`/`report` never initialize
`ProjectState` (proven by source isolation plus `PROJECT_INIT_COUNT`).
Single-threaded invariant: `PROJECT_THREADS_USED=1`, no daemon, watcher,
indexer, pool, or persistent workers; `background_cpu_percent=0` and
`background_rss_kb=0` architecturally. Storage grows with new semantic
information, not repeated work. Membership never grants scan authorization;
external (`scope=out_of_scope`) edges stay observational.

## Phase 19 performance / bounded-work model

Phase 19 proves the architecture stays correct, bounded, responsive, fast,
light, and multitasking-friendly as workload grows. The permanent invariant:
broad like a toolchain, fast like a native CLI, light enough to forget it is
running — fast through efficiency, never by monopolizing the machine.

- Bounded work: every grow-with-work container derives from an explicit
  budget or hard constant (scheduler queue from concurrency/tasks caps,
  TCP window 16..128 by speed with a 256 hard cap, per-module admit/request/
  event caps, registry caps, 8 MiB checkpoint / 16 MiB project file caps).
  Queue saturation is backpressure, never abort; retries never dominate fresh
  work; priorities never starve eligible tasks under bounded arrivals.
- Streaming boundaries: checkpoint saves stream to disk (8 KiB buffer, no
  whole-state serialization buffer); JSONL renders record-by-record; wordlists
  stream line-by-line with reuse buffers; raw HTTP/DNS/TLS bytes are parsed
  into compact semantics and released per fetch — never accumulated.
- Memory lifetime scales with bounded active work, not total theoretical
  workload: per-scan port vectors are freed per task, bodies are function
  locals, query temporaries are freed per tick, and peak RSS is observed via
  `/proc/self/status` VmHWM (peak) vs VmRSS (current).
- Descriptor bounds: sustained per-scan sockets equal TCP `max_concurrent`;
  `ScanOutcome::fd_peak` and `SchedulerReport::{queue_peak, active_peak}`
  make active/peak use observable. EMFILE degrades to bounded Error/backoff
  outcomes, never panic/spin/misclassification.
- Cancellation: per-task tokens (polled every few ms), per-task timeouts
  (slots freed immediately, orphans discarded without double-count), and the
  global execution budget (stops backoff queues promptly). Slow sinks never
  cause unbounded output buffering.
- Multitasking: worker/concurrency policy derives deterministically from
  speed+budget only (`available_parallelism` is informational); the benchmark
  uses 4 threads of 12 with CPU/wall ratio 0.7. No new tuning knobs: `level`
  stays breadth/depth, `speed` stays pressure (task IDs embed pressure fields
  by design; semantic params are speed-invariant, proven by test).
- No performance dependency bloat: 10 production / 1 dev, unchanged.

## Phase 20 production / release boundaries

Speed pressure derives exactly once from the speed setting and the tighter
of caller/scheduler budgets (idempotent; the explicit budget is an upper
bound; `available_parallelism` never sizes pools). Scan file output is
atomic (temp + file-sync + rename; prior valid files are never replaced by
partial runs). Machine stdout never carries diagnostics and never panics on
closed pipes; exit codes are 0/2/1 (success/usage/runtime). Checkpoints merge
same-ID asset re-observations deterministically (first-wins attributes,
timestamp span) and reject cross-kind collisions; every event asset ID and
relationship endpoint must resolve to a persisted asset, which modules
guarantee locally. Unknown config keys and unreadable wordlists fail fast at
plan compile. The binary needs only the OS C library at runtime and shells
out to nothing.

## Repository ownership

- Foundation: `cli`, `config`, `target`, `scope`, `plan`
- Control plane: `level`, `lowering`, `execution` (scheduler/speed/budgets/queue/cancel/best-effort follow-ups), `modules` (control scaffold), `run` (bootstrap), `output` (JSONL), `decision` (host→port + open-port→service engine)
- Host discovery: `discovery` (state/policy/CIDR), `icmp` (native echo), `tcp_probe` (reachability), `host_discovery` (scheduler module)
- TCP discovery: `ports` (selection/profile/level/speed), `tcp_scanner` (non-blocking engine), `tcp_discovery` (scheduler module + open-port summary)
- Service intelligence: `service` (observation/confidence/planner), `probes` (native handshakes), `tls` (observe-only rustls client + composition), `service_probe` (scheduler module + service table)
- DNS/web/crawl/baseline/content/fuzz: `dns` (bounded UDP DNS observations, parser, DNS asset graph), `web` (canonical URLs, HTTP/1.1 exchange, bounded redirects, response bounds, web policy), `web_probe` (`HttpProbe` scheduler module), `extract` (pure bounded HTML/robots/sitemap/JS extraction), `crawl` (`Crawl` scheduler module), `baseline` (`Baseline` scheduler module, response signatures, scan-lifetime origin baselines, bounded duplicate/similarity representatives, soft-404/wildcard observations, classes, parameter records, interestingness), `content` (`ContentDiscovery` scheduler module, built-in/user-file candidate streaming, canonical plus scan-lifetime contacted-URL dedup, baseline-aware classification), `fuzz` (`Fuzz` scheduler module, observed GET query mutation, response delta/reflection evidence)
- Deferred scaffold modules: `network`, `fingerprint`, `web`, `checks` remain placeholders for later UDP/fingerprint/check phases where not otherwise implemented.
- Persistence/output/analysis/reporting/project: `persistence` (Phase 14 versioned checkpoint/resume), `diff` (Phase 15 offline checkpoint comparison), `analysis` (Phase 16 deterministic attention ranking), `report` (Phase 17 deterministic summary/machine/raw semantic export), `project` (Phase 18 compact project graph), `graph`, `storage`, `output`
