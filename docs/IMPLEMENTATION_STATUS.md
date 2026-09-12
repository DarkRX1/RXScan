# Implementation status and gap analysis

## Repository baseline

The repository had no commits and contained an uncommitted Rust Phase-0-style skeleton plus a separate static portfolio. The portfolio is preserved and excluded from RXScan engine work. The skeleton normalized targets, performed basic scope checks, and compiled a plan, but had no CI, fixture or benchmark foundation, TOML configuration, goal/level/speed model, or complete planning docs.

## Current state

Phases 0, 1, 2, 3, and 4 are complete. RXScan performs no network I/O by design. It can compile a policy-bearing plan, lower it deterministically to executable tasks, run those tasks through the reactive scheduler with speed/budget control, and emit typed JSONL — all without fake discoveries.

| Area | Current state | Next |
| --- | --- | --- |
| Native Rust core | Foundation + data model + control plane established | Phase 5 network modules |
| Target, scope, CLI, config, plan | Implemented/tested; level/goal/budget-aware | Phase 5 executors |
| Events/assets/findings | Implemented/tested; scaffold producers return empty output (no fakes) | Phase 5 real producers |
| Scheduler/speed/budgets | Implemented, wired to binary, tested; auto is non-adaptive baseline | Phase 4.1 adaptive governor (optional) |
| Plan→task lowering | Deterministic, scope-checked, deduped, all-ports safe | Phase 5 dependency expansion |
| JSONL output | Typed, versioned, provenanced, bounded, tested | Phase 20+ reporting |
| Network and web modules | Not implemented | Phase 5 onward |
| CI/fixtures/benchmark discipline | Established; Phase 4 control-plane baseline recorded | Add executable fixtures per module |

No performance or capability superiority is claimed. No scanning functionality is claimed beyond control-plane execution of scaffold tasks.

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
