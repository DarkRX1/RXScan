# RXScan roadmap

Each phase requires tests, benchmark/regression evidence where applicable, documentation, and an explicit exit review.

| Phase | Deliverable | Status |
| --- | --- | --- |
| 0 | Architecture, tooling, fixtures, benchmark discipline, CI | Complete |
| 1 | Target model, CLI, Scope Guard, config, ScanPlan | Complete |
| 2 | Events, findings, stable asset IDs, relationships | Complete |
| 3 | Reactive scheduler, queues, cancellation, backpressure | Complete |
| 4 | Control-plane completion: plan→task lowering, level/speed policy, budgets, scheduler bootstrap, scaffold executors, JSONL output | Complete (current) |
| 5–10 | Discovery, TCP, UDP, probes, TLS/fingerprints, HTTP | Not implemented |
| 11–15 | DNS, crawler, baseline, content, fuzzing | Not implemented |
| 16–19 | Decision engine, API workflows, checks, graph/correlation | Not implemented |
| 20–24 | Outputs, resume/diff/projects, packs, benchmark lab, releases | Not implemented |

Phase 4 is control-plane only. No TCP, UDP, ICMP, DNS, HTTP, TLS, SSH, crawling, fuzzing, wordlists, service probing, fingerprinting, or vulnerability checks exist yet. Network tasks are represented as intended work and run as `Skipped` (`module unavailable`); scaffold tasks exercise the pipeline without fake discoveries.

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
