# RXScan architecture

RXScan is a native Rust, policy-driven reactive reconnaissance engine: **simple outside, serious inside**. It is not a wrapper around external scanners.

```text
Target / Scope -> ScanPlan Compiler -> Task Lowering -> Reactive Scheduler <-> Speed + Budgets
                                                     <-> Backpressure / Queue
                                                     -> HostDiscovery Module -> Typed Events / Evidence
                                                     -> JSONL Output -> Decision Engine (NoFollowUps in Phase 5)
                                                     -> scoped task proposals -> Scheduler
```

The Decision Engine proposes work only. The Scope Guard, policy validation, budget validation, and scheduler admission must approve every task before execution.

## Phase 0–5 boundary

`cli` captures operator intent (`--ping`/`--discover` preserved; `--max-hosts` bounds CIDR). `config` resolves explicit global then project TOML configuration with CLI precedence (plus `max_hosts`, `discovery_ports`). `target` converts seeds into `TargetSpec`; `scope` applies deny-by-default scope; `plan` creates an immutable and explainable `ScanPlan` with level/goal/speed/budget/discovery policy. `discovery` centralizes host-state semantics and breadth/pressure policy (`HostDiscoveryPolicy`; `Alive`/`Unreachable`/`Unknown`; ICMP failure is never dead). `level` centralizes investigation breadth/depth eligibility; `lowering` deterministically translates a validated plan into initial tasks (scope-checked, deduped, all-ports safe via single-task params, CIDR host expansion bounded by `max_hosts`). `execution` owns the reactive scheduler, canonical task IDs (SHA-256), speed governor, budgets, queues, cancellation, retries, and completed-output retention for JSONL. `icmp`/`tcp_probe` provide native bounded probing (unprivileged ping sockets, no shell `ping`; TCP RST/connect as Alive evidence); `host_discovery` is the scheduler module (scope re-checked immediately before network execution; emits results only, never schedules follow-ups). `modules` provides control/port scaffolds (deeper intents run as `Skipped`). `output` writes typed versioned JSONL (scheduler events plus discovery assets/events/evidence). `run` bootstraps the binary: plan → guard → tasks → governor → budgets → scheduler → host discovery → run → JSONL. `model` is the interchange boundary: deterministic asset and finding IDs, typed discovery lifecycle events, bounded evidence, typed relationships, provenance, and versioned JSON/JSONL records. No TCP/UDP port scanning, HTTP, SSH probing, crawling, fuzzing, DNS enumeration, or exploitation exists in Phase 5.

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
- Host discovery never shells out to `ping`; raw/privileged failures degrade to structured `Unavailable` (never false Dead); CIDR expansion is bounded by `max_hosts` (default 256) and Level 5 is bounded (5 TCP ports, 3 ICMP attempts).

## Repository ownership

- Foundation: `cli`, `config`, `target`, `scope`, `plan`
- Control plane: `level`, `lowering`, `execution` (scheduler/speed/budgets/queue/cancel), `modules` (control/port scaffolds), `run` (bootstrap), `output` (JSONL), `decision` (NoFollowUps in Phase 5)
- Host discovery: `discovery` (state/policy/CIDR), `icmp` (native echo), `tcp_probe` (reachability), `host_discovery` (scheduler module + decision boundary)
- Modules: `network`, `dns`, `fingerprint`, `web`, `checks` (port scanning and beyond not implemented until Phase 6+)
- Persistence/output: `graph`, `storage`, `output`
