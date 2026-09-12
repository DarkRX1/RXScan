# Implementation status and gap analysis

## Repository baseline

The repository had no commits and contained an uncommitted Rust Phase-0-style skeleton plus a separate static portfolio. The portfolio is preserved and excluded from RXScan engine work. The skeleton normalized targets, performed basic scope checks, and compiled a plan, but had no CI, fixture or benchmark foundation, TOML configuration, goal/level/speed model, or complete planning docs.

## Current state

Phases 0, 1, 2, 3, 4, and 5 are complete. RXScan's first real network capability is host discovery: bounded native ICMP echo + TCP reachability through the existing scheduler, with explicit Alive/Unreachable/Unknown states and evidence. No TCP/UDP port scanning, HTTP, SSH probing, crawling, fuzzing, DNS enumeration, vulnerability checks, or exploitation exist yet.

| Area | Current state | Next |
| --- | --- | --- |
| Native Rust core | Foundation + data model + control plane + host discovery established | Phase 6 TCP port scanning |
| Target, scope, CLI, config, plan | Implemented/tested; level/goal/budget-aware plus discovery mode/ports/hosts | Phase 6 executors |
| Events/assets/findings | Implemented/tested; host-discovery producers emit real typed events/evidence/assets | Phase 6 real producers |
| Scheduler/speed/budgets | Implemented, wired to binary, tested; auto is non-adaptive baseline; `max_hosts` bounds CIDR | Phase 4.1 adaptive governor (optional) |
| Plan→task lowering | Deterministic, scope-checked, deduped, all-ports safe, CIDR host expansion bounded | Phase 6 dependency expansion |
| JSONL output | Typed, versioned, provenanced, bounded, tested; includes discovery assets/events/evidence | Phase 20+ reporting |
| Network and web modules | Host discovery only (ICMP echo + TCP reachability; ARP/ND deferred) | Phase 6 onward |
| CI/fixtures/benchmark discipline | Established; Phase 5 host-discovery baseline recorded | Add executable fixtures per module |

No performance or capability superiority is claimed. No scanning functionality is claimed beyond bounded host discovery plus control-plane execution of scaffold tasks.

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
