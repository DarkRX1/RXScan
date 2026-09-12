# RXScan architecture

RXScan is a native Rust, policy-driven reactive reconnaissance engine: **simple outside, serious inside**. It is not a wrapper around external scanners.

```text
Target / Scope -> ScanPlan Compiler -> Task Lowering -> Reactive Scheduler <-> Speed + Budgets
                                                     <-> Backpressure / Queue
                                                     -> HostDiscovery + TcpDiscovery + ServiceProbe Modules -> Typed Events / Evidence / Assets / Findings
                                                     -> JSONL Output + human service summary -> Decision Engine (host→port, open-port→service)
                                                     -> scoped task proposals -> Scheduler
```

The Decision Engine proposes work only. The Scope Guard, policy validation, budget validation, and scheduler admission must approve every task before execution.

## Phase 0–7 boundary

`cli` captures operator intent (`--ports`/`--all-ports`/`--ping`/`--discover` preserved; `--max-hosts` bounds CIDR). `config` resolves explicit global then project TOML configuration with CLI precedence (plus `max_hosts`, `discovery_ports`). `target` converts seeds into `TargetSpec`; `scope` applies deny-by-default scope; `plan` creates an immutable and explainable `ScanPlan` with level/goal/speed/budget/discovery/TCP policy. `discovery` centralizes host-state semantics and breadth/pressure policy (`HostDiscoveryPolicy`; `Alive`/`Unreachable`/`Unknown`; ICMP failure is never dead). `ports` centralizes TCP selection (`common`/`explicit`/`all`, versioned `COMMON_PORTS_V1`, level breadth L1 minimal … L5 broad ≤32, explicit always wins; speed never changes the set). `level` centralizes investigation breadth/depth eligibility; `lowering` deterministically translates a validated plan into initial tasks (scope-checked, deduped, ONE `PortDiscovery` task per target with `ports=common|explicit|all` params — never 65k tasks — CIDR host expansion bounded by `max_hosts`). `execution` owns the reactive scheduler, canonical task IDs (SHA-256), speed governor, budgets, queues, cancellation, retries, completed-output retention, and best-effort follow-up admission (duplicates/out-of-scope/budget-exhausted proposals skipped, never aborting the run). `icmp`/`tcp_probe` provide native bounded host probing (unprivileged ping sockets, no shell `ping`; TCP RST/connect as Alive evidence); `tcp_scanner` provides the native non-blocking TCP connect engine (sliding `poll(2)` window 16–128, hard 256, no thread per port, per-port timeouts, one retry for filtered only, prompt cancel, FD cleanup). `host_discovery`/`tcp_discovery` are the scheduler modules (scope re-checked immediately before network execution; emit facts only, never self-schedule). `decision` is the Decision Engine (host→port V1 plus open-port→service V2 rules; scope pre-check; dedup-shaped proposals; best-effort admission). `service` centralizes the observation model, evidence-graded confidence, and the deterministic ProbePlanner (port/level/goal → ordered probes; new protocols register without scheduler changes). `probes` implements the native handshakes (SSH/HTTP/FTP/SMTP/Redis/MySQL/PostgreSQL passive-or-single-exchange probes plus a passive generic banner read; fixed small request payloads; bounded reads). `tls` wraps rustls as an observe-only TLS client (records the presented chain, never evaluates trust) with HTTP/SMTP-inside-TLS composition on the same session. `service_probe` is the scheduler module (one task per open port, sequential probes, first classification wins, TLS compositions reuse the session; emits facts only, never self-schedules). `modules` provides the control scaffold (deeper intents run as `Skipped`). `output` writes typed versioned JSONL (scheduler events plus discovery/scan/service assets/events/evidence/findings). `run` bootstraps the binary: plan → guard → tasks → governor → budgets → scheduler → host+port+service modules → engine → run → JSONL + service table. `model` is the interchange boundary: deterministic asset and finding IDs (service children namespaced `port:service/label`, certificates by fingerprint), typed host+port+service lifecycle events, bounded evidence, typed relationships (`Runs` port→service), provenance, and versioned JSON/JSONL records. No UDP scanning, web crawling, directory discovery, fuzzing, DNS enumeration, vulnerability checks, brute force, exploitation, cipher enumeration, or technology fingerprinting exists in Phase 7 (open means open; service labels come from handshakes, versions only from observed strings).

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
- TCP scanning never shells out and never uses raw SYN; connect success is Open, refused/reset is Closed, timeout is FilteredOrTimedOut (never misclassified as Closed), unreachable/permission failures are Error; one task per target with a bounded internal window (no thread per port, ≤256 concurrent FDs, retries only for filtered ≤1).

## Repository ownership

- Foundation: `cli`, `config`, `target`, `scope`, `plan`
- Control plane: `level`, `lowering`, `execution` (scheduler/speed/budgets/queue/cancel/best-effort follow-ups), `modules` (control scaffold), `run` (bootstrap), `output` (JSONL), `decision` (host→port + open-port→service engine)
- Host discovery: `discovery` (state/policy/CIDR), `icmp` (native echo), `tcp_probe` (reachability), `host_discovery` (scheduler module)
- TCP discovery: `ports` (selection/profile/level/speed), `tcp_scanner` (non-blocking engine), `tcp_discovery` (scheduler module + open-port summary)
- Service intelligence: `service` (observation/confidence/planner), `probes` (native handshakes), `tls` (observe-only rustls client + composition), `service_probe` (scheduler module + service table)
- Modules: `network`, `dns`, `fingerprint`, `web`, `checks` (UDP/crawling/fuzzing/fingerprint engine not implemented until Phase 8+)
- Persistence/output: `graph`, `storage`, `output`
