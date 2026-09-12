# Implementation status and gap analysis

## Repository baseline

The repository had no commits and contained an uncommitted Rust Phase-0-style skeleton plus a separate static portfolio. The portfolio is preserved and excluded from RXScan engine work. The skeleton normalized targets, performed basic scope checks, and compiled a plan, but had no CI, fixture or benchmark foundation, TOML configuration, goal/level/speed model, or complete planning docs.

## Current state

Phases 0 through 8 are complete. RXScan now performs real bounded host discovery, native TCP connect port scanning, native service/protocol identification, and bounded HTTP/1.1 web observations through the existing scheduler, with explicit host/port/service states, Decision Engine host→port, open-port→service, and service→web proposals, and evidence throughout. No UDP scanning, web crawling, directory/content discovery, endpoint/API enumeration, fuzzing, DNS enumeration, vulnerability checks, brute force, exploitation, cipher enumeration, or technology fingerprinting exist yet.

| Area | Current state | Next |
| --- | --- | --- |
| Native Rust core | Foundation + data model + control plane + host + TCP + service + web discovery established (rustls/x509-parser for TLS observation) | Phase 9 crawling/content |
| Target, scope, CLI, config, plan | Implemented/tested; level/goal/budget-aware plus discovery/TCP/service/web policy | Phase 9 executors |
| Events/assets/findings | Implemented/tested; host + port + service + web producers emit real typed events/evidence/assets/findings (per-open, per-service, per-URL) | Phase 9 real producers |
| Scheduler/speed/budgets | Implemented, wired to binary, tested; auto is non-adaptive baseline; `max_hosts` bounds CIDR; follow-ups best-effort (dup/scope/budget skip) | Phase 4.1 adaptive governor (optional) |
| Plan→task lowering | Deterministic, scope-checked, deduped, ONE port task per target (never 65k), CIDR host expansion bounded; service/web tasks proposed per open port/service by the engine | Phase 9 dependency expansion |
| JSONL output | Typed, versioned, provenanced, bounded, tested; includes discovery + scan + service + web assets/events/evidence/findings; terminal shows service table | Phase 20+ reporting |
| Network and web modules | Host discovery + TCP port scanning + service probing + bounded HTTP/1.1 web observations (single exchanges, bounded redirects, no crawling); ARP/ND deferred; no UDP/crawling/content-discovery/fuzzing/DNS/checks/fingerprint engine | Phase 9 onward |
| CI/fixtures/benchmark discipline | Established; Phase 5 + 6 + 7 + 8 baselines recorded | Add executable fixtures per module |

No performance or capability superiority is claimed. No scanning functionality is claimed beyond bounded host discovery, TCP connect port scanning, safe service identification, and bounded single-exchange web observations plus control-plane execution of scaffold tasks.

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
