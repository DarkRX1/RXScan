# RXScan architecture

RXScan is a native Rust, policy-driven reactive reconnaissance engine: **simple outside, serious inside**. It is not a wrapper around external scanners.

```text
Target / Scope -> ScanPlan Compiler -> Task Lowering -> Reactive Scheduler <-> Speed + Budgets
                                                     <-> Backpressure / Queue
                                                     -> HostDiscovery + TcpDiscovery + ServiceProbe + DnsProbe + WebProbe + Crawl + Baseline + ContentDiscovery + Fuzz Modules -> Typed Events / Evidence / Assets / Findings
                                                     -> JSONL Output + human service summary -> Decision Engine (host→port, open-port→service, service→web→crawl→baseline→content→fuzz)
                                                     -> scoped task proposals -> Scheduler
```

The Decision Engine proposes work only. The Scope Guard, policy validation, budget validation, and scheduler admission must approve every task before execution.

## Phase 0–12 Boundary

`cli` captures operator intent (`--ports`/`--all-ports`/`--ping`/`--discover` preserved; `--max-hosts` bounds CIDR; `-w/--wordlist` streams managed content candidates at L4+). `config` resolves explicit global then project TOML configuration with CLI precedence. `target`, `scope`, and `plan` normalize seeds, enforce deny-by-default scope, and create immutable `ScanPlan`s. `execution` owns scheduler admission, canonical task IDs, speed, budgets, cancellation, retries, output retention, and best-effort follow-up admission. Native modules perform host discovery, TCP connect scanning, DNS asset intelligence, service observation, HTTP/TLS probing, bounded crawling, Phase 10 baseline characterization, Phase 11 managed content discovery, and Phase 12 contextual GET query fuzzing. `decision` is the only component that turns facts into follow-up tasks: host→port, open-port→service, DNS A/AAAA→host discovery, service→web, confirmed/crawled endpoint→crawl/baseline, origin baseline→content, baseline signature with observed safe query parameter→fuzz. `dns` uses a bounded native UDP DNS client and defensive parser for A/AAAA/CNAME/MX/NS/TXT/PTR observations; DNS relationships are observational and do not authorize third-party follow-up. Still deferred: UDP port scanning, generic exploit fuzzing, POST/form submission, cookie/header/path-variable fuzzing, wildcard DNS, JavaScript execution, headless browsers, vulnerability checks, exploitation, cipher enumeration, persistence/resume, and technology fingerprinting.

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
- Crawling starts only from confirmed HTTP/HTTPS endpoint evidence. Every discovered URL is canonicalized, scope-checked, and budget-checked before contact; out-of-scope discoveries may be recorded but never fetched. Forms are observation only; JavaScript is never executed; crawler modules never self-schedule recursive work.
- Baseline intelligence starts only from confirmed or crawled endpoint evidence. Synthetic missing-path probes stay same-origin and inert (`/__rxscan_baseline_<token>__`), are remembered in compact scan-lifetime origin state keyed by scheme + canonical host + effective port, and remain scope/redirect checked before contact. Baseline code signs and classifies observed responses only; it never mutates parameters, submits forms, guesses paths, fuzzes, executes JavaScript, or reports vulnerabilities.
- Managed content discovery consumes bounded candidate sources only. Candidates cannot change scheme/authority, cannot traverse with `.`/`..`, and cannot trigger POST/PUT/PATCH/DELETE, form submission, method fuzzing, header fuzzing, or recursive directory explosions. Content candidate contacts consult the scan-lifetime contacted-request registry so crawler/content duplicate URLs such as `/login`, `login`, and `/login#fragment` do not create redundant requests.
- Contextual fuzzing starts only from existing evidence: a baseline signature for an endpoint with an observed non-sensitive GET query parameter. It mutates one parameter per request with inert values, reuses Phase 8 fetch and Phase 10 signatures, and emits behavior deltas/reflection observations only. It never submits forms, fuzzes POST bodies/cookies/headers, uses exploit payloads, or creates vulnerability findings.

## Repository ownership

- Foundation: `cli`, `config`, `target`, `scope`, `plan`
- Control plane: `level`, `lowering`, `execution` (scheduler/speed/budgets/queue/cancel/best-effort follow-ups), `modules` (control scaffold), `run` (bootstrap), `output` (JSONL), `decision` (host→port + open-port→service engine)
- Host discovery: `discovery` (state/policy/CIDR), `icmp` (native echo), `tcp_probe` (reachability), `host_discovery` (scheduler module)
- TCP discovery: `ports` (selection/profile/level/speed), `tcp_scanner` (non-blocking engine), `tcp_discovery` (scheduler module + open-port summary)
- Service intelligence: `service` (observation/confidence/planner), `probes` (native handshakes), `tls` (observe-only rustls client + composition), `service_probe` (scheduler module + service table)
- DNS/web/crawl/baseline/content/fuzz: `dns` (bounded UDP DNS observations, parser, DNS asset graph), `web` (canonical URLs, HTTP/1.1 exchange, bounded redirects, response bounds, web policy), `web_probe` (`HttpProbe` scheduler module), `extract` (pure bounded HTML/robots/sitemap/JS extraction), `crawl` (`Crawl` scheduler module), `baseline` (`Baseline` scheduler module, response signatures, scan-lifetime origin baselines, bounded duplicate/similarity representatives, soft-404/wildcard observations, classes, parameter records, interestingness), `content` (`ContentDiscovery` scheduler module, built-in/user-file candidate streaming, canonical plus scan-lifetime contacted-URL dedup, baseline-aware classification), `fuzz` (`Fuzz` scheduler module, observed GET query mutation, response delta/reflection evidence)
- Deferred scaffold modules: `network`, `fingerprint`, `web`, `checks` remain placeholders for later UDP/fingerprint/check phases where not otherwise implemented.
- Persistence/output: `graph`, `storage`, `output`
