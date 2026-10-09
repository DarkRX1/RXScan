# Contributing to RXScan

Scope: bounded, evidence-driven, testable changes. Network behavior requires
deterministic local fixtures — never tests that depend on arbitrary public
services. New detection claims need executable evidence behind them. Changes
to scanning behavior must preserve scope, deadlines, cancellation, partial
results, and accounting.

## Required local gates

Run the canonical gate list in [`docs/TESTING.md`](docs/TESTING.md) before
submitting (kept in exactly one place so copies cannot drift).

`cargo test --locked` passing locally means "local gates passed" — it does
not mean hosted GitHub CI passed. Never claim CI is green from local runs.

## Rust changes

- Keep changes bounded; do not add dependencies for novelty. New
  dependencies need justification (why stdlib is insufficient).
- No `unwrap`/`expect`/`panic` on runtime network paths; return typed
  errors with provenance.
- Preserve cancellation, deadlines, budgets, and partial-evidence
  accounting. A truncated run must report what was covered, never present
  itself as complete.
- Update `docs/ARCHITECTURE.md` only where the flow actually changed; link
  to the source module rather than duplicating logic that will go stale.

## Scanner changes

- Scope Guard stays deny-by-default. Derived addresses (DNS, SAN, CIDR)
  are re-checked and never expand scope.
- Port numbers alone never identify a service; HTTP 200 alone never
  confirms anything; UDP silence stays `open|filtered` uncertainty.
- One bounded task per target for all-port scans (never 65k tasks);
  concurrency stays bounded independently of target count.

## Provider additions

Full contract: `docs/PROVIDER_CONTRACT.md`. Corpus layout and health
states: `search/providers/v1/README.md`. Short version:

- Start at `needs_review` with `source_notes` describing what is known.
- Required fixtures for every provider:
  `search/fixtures/username/<provider-id>/cases.json` with found,
  not-found, generic-200, and blocked cases.
- Evidence rules (enforced by review, lint, and tests):
  HTTP 200 != identity. Generated URL != observed profile. Redirect !=
  identity confirmation. Blocked != negative. Rate-limited != negative.
  Candidate != confirmed. Provider endpoint != profile.
- A provider must NOT become `live_verified` merely because its fixture
  passes, its URL resolves, it returns HTTP 200, or a generated profile
  URL exists. Promotion requires checking a known-existing AND a
  known-absent username against live behavior, plus `verified_at`
  (`YYYY-MM-DD`, calendar-valid) and `verification_method`. No test
  usernames or operator data in the definition.
- Run `cargo run --locked -- search lint` (exit 1 on errors) plus the
  full test suite. Lint rejects contradictory metadata
  (`live_verified` + provisional/`await live verification` notes),
  duplicate IDs, bad URL templates/schemes, bad categories, missing
  fixtures, and invalid result rules.

## Fingerprint additions

- Fingerprints supplement unobserved products only; deterministic
  handshake evidence always wins; port priors add zero confidence.
- Every rule needs per-rule self-consistency coverage
  (`tests/fingerprint_corpus.rs`, `tests/fingerprint_packs.rs`).
- Unknown stays unknown when evidence is insufficient. Never fabricate
  product, version, banner, TLS, or SSH details.

## Web / API changes

- Loopback-only default; non-loopback bind requires explicit
  `--allow-remote` and stays unauthenticated (never recommended).
- Host must be loopback; unsafe methods require absent or loopback
  Origin; no CORS emitted. No `/execute`, `/command`, or `/shell`
  route — ever.
- Same core planner as the CLI; categories/providers come from the
  backend registry, never a hardcoded JS list. Request bodies stay
  bounded. Provider-controlled values render via `textContent`/DOM
  APIs only — no `innerHTML` for untrusted strings.
- `node --check app/rxscan.js` must pass; `tests/web_api.rs` and
  `tests/web_frontend.rs` cover routes, separation, and syntax.

## Documentation changes

- README stays an index, not a manual; point to `docs/` instead of
  duplicating. No competitor comparisons, no superlatives, no claims
  about how code was produced.
- Never document a command or flag that current `--help` does not
  expose. CLI help is the authority for user-facing syntax.
- Distinguish the published release (`v1.1.0`) from current master.
  Never present master-only work as shipped.
- Every local Markdown link must resolve (checked by
  `tests/repo_hygiene.rs`). No external network dependency for link
  validation. No private or environment-specific values in docs.

## Regression tests

- Every behavior fix ships with a test proving it stays fixed.
- Prefer deterministic loopback fixtures on ephemeral ports with
  readiness synchronization (poll with deadline), not fixed sleeps.
- Never `#[ignore]`, delete, or weaken a failing test to make a gate
  green. Fix the cause. Counts (providers, vectors, categories) must
  derive dynamically from the registry — never hardcode totals.
