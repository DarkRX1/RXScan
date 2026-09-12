# RXScan roadmap

Each phase requires tests, benchmark/regression evidence where applicable, documentation, and an explicit exit review.

| Phase | Deliverable | Status |
| --- | --- | --- |
| 0 | Architecture, tooling, fixtures, benchmark discipline, CI | Complete |
| 1 | Target model, CLI, Scope Guard, config, ScanPlan | Complete |
| 2 | Events, findings, stable asset IDs, relationships | Complete |
| 3 | Reactive scheduler, queues, cancellation, backpressure | Complete |
| 4 | Control-plane completion: plan→task lowering, level/speed policy, budgets, scheduler bootstrap, scaffold executors, JSONL output | Complete |
| 5 | Host Discovery Engine: real bounded ICMP echo + TCP reachability via scheduler, host-state model, discovery policy, CIDR bounding, evidence/events, JSONL | Complete (current) |
| 6–10 | TCP port scanning, UDP, probes, TLS/fingerprints, HTTP | Not implemented |
| 11–15 | DNS, crawler, baseline, content, fuzzing | Not implemented |
| 16–19 | Decision engine, API workflows, checks, graph/correlation | Not implemented |
| 20–24 | Outputs, resume/diff/projects, packs, benchmark lab, releases | Not implemented |

Phase 5 is the first real network capability (host discovery only). No TCP port scanning, UDP port scanning, HTTP, SSH service probing, crawling, fuzzing, DNS enumeration, vulnerability checks, or exploitation exist yet. Deeper network tasks still run as `Skipped` (`module unavailable`); host-discovery tasks run real bounded ICMP/TCP probing without fake discoveries.

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
