# Provider verification contract

Authoritative companion to `search/providers/v1/README.md` (corpus layout)
and `src/search.rs` (enforcement). If this document and the loader
disagree, the loader plus `search lint` wins — file a docs fix.

## Identity

- One provider = one `metadata.id` (unique across the corpus;
  `build.rs` rejects duplicates at compile time).
- One provider currently yields one search vector
  (`username_search_vectors` in `src/search.rs`); counts are kept
  distinct (`providers_configured` vs `vectors_registered` in
  `username_registry_counts`) so multi-vector providers never inflate
  either number later. See `docs/SEARCH_CORPUS.md`.
- Corpus files: `search/providers/v1/username/<category>.json`, merged
  by `build.rs` in sorted filename order, then sorted by provider ID —
  deterministic output.

## Categories

- Vocabulary owned by the core: `known_username_categories()` in
  `src/search.rs`. File name, top-level `category`, and
  `metadata.source_category` must agree; drift is a lint error.
- CLI and web filter through the same planner
  (`plan_username_providers`): `--category` / Sources panel narrow the
  real plan before contact. Unknown categories and unknown provider IDs
  are typed validation errors, never silent skips.

## Accepted entity type

- v1 corpus accepts `username` and produces `account`
  (`metadata.accepts` / `metadata.produces`). Passive entity kinds
  (domain, hostname, IP, ASN, URL, repo, org) are local
  canonicalization only — no network, no provider contact.

## URL construction

- `profile_url` must be `https://` and contain `{username}` (lint
  error otherwise). No `http://`, no schemeless templates.
- Duplicate or suspiciously equivalent templates (case/trailing-slash
  normalized) are lint errors — two IDs must not resolve to the same
  identity endpoint.

## Positive evidence

- Required markers (`success.required`) must be username-anchored and
  verified against real response structure (watch HTML whitespace and
  attribute order). Bare URL echoes false-confirm and were removed
  from the corpus for that reason.
- Status alone never confirms: `success_status` gates candidacy, but
  confirmation needs identity evidence (canonical username field,
  documented public profile object, canonical profile URL, or provider
  API identity match).

## Absence evidence

- Every enabled provider needs absence handling: a `not_found_status`
  (e.g. 404), a not-found body marker, or a verified absence redirect
  destination. Missing all three is a lint error.
- HTTP 200 with an absent-identity body is not-found evidence, not a
  weak confirm — absence markers are checked before success markers.

## Unknown / blocked / rate-limited / auth-required

- `SearchStatus` (`src/search.rs`) keeps eleven states distinct:
  `Confirmed`, `Probable`, `Possible`, `NotFound`, `Unknown`,
  `RateLimited`, `Blocked`, `AuthenticationRequired`, `Error`,
  `Cancelled`, `Unscanned`. Blocked and rate-limited are never
  converted into negatives (`NotFound`).
- `Probable` is an above-`Possible` uncertain finding: it still
  renders in the Possible family (`?`, amber) and is never a
  confirmed-`Profile` conclusion. Status (identity confidence) stays
  orthogonal to URL kind (what the URL observation shows).
- Blocked markers must never match ordinary profile pages (a bare
  `"captcha"` once converted live confirmations into `Blocked` via
  embedded script names). Absence markers get the same treatment.

## URL-kind semantics

- `core_url_kind()` (`src/search.rs`) is shared by CLI, web, and
  machine output: same inputs always yield the same kind.
- Kinds: identity-specific observed profile, identity-specific
  observed resource (not necessarily a public profile), unconfirmed
  identity-specific candidate location, generic provider endpoint
  (never presented as a profile), or none. The terminal renders these
  as `Profile` / `Resource` / `Candidate`; generic homepages and API
  endpoints are never profile URLs.
- Rule of thumb: generated URL != observed profile. Only an observed
  response with identity evidence earns profile/resource status.

## Metadata and provenance

- Observations may expose bounded public metadata (username, display
  name, profile ID, bio, profile/avatar URL, joined date, public
  counts, location text, website, repo/org links, account type) only
  where actually observed. Every value is bounded, sanitized for
  terminal rendering, and carries provenance
  (`provider_id` + `provider_version`).
- Metadata never merges identities: weak evidence does not merge
  entities; shared infrastructure relates without implying identity.
  Remote imagery is never auto-rendered.

## Fixtures

- Required per provider:
  `search/fixtures/username/<provider-id>/cases.json` with found,
  not-found, generic-200, and blocked cases. Missing fixtures or
  incomplete coverage is a lint error; `fixture_complete` must equal
  the vector count.
- Fixture bodies are minimal synthetic representations of response
  structure, never bulk-copied live pages.

## Review state vs live verification

- `HealthState` (`src/search.rs`): `fixture_verified` (synthetic
  fixtures pass; live behavior NOT checked), `live_verified` (live
  behavior actually checked — requires `verified_at` +
  `verification_method`), `needs_review` (provisional, blocked, or
  ambiguous live behavior), `disabled` (never queried; actively
  misleading definitions, e.g. verified false-confirm).
- `live_verified` means: a maintainer checked a known-existing AND a
  known-absent username against live behavior and recorded a
  calendar-valid `verified_at` (`YYYY-MM-DD`,
  `is_verification_date()`) plus `verification_method` (e.g.
  `live-probe`; no test usernames, machine names, or operator data).
- A passing fixture DOES NOT mean the provider works live. Fixtures
  prove classifier behavior; only live observation validates the
  classifier against reality.
- Promotion is never granted because the fixture passes, the URL
  resolves, HTTP 200 occurs, or a generated profile URL exists.
- Contradictory metadata is a hard error, not a warning: the loader
  (`validate_definitions`) and `lint_definitions` reject
  `live_verified` without `verified_at`, `verified_at` on a non-live
  provider, a method without a date, and `live_verified` combined
  with provisional notes (`verification_notes_contradict_live()`:
  "provisional", "needs_review", "await live verification",
  "unverified", and equivalents).
- Batch verification (many providers sharing one date) is legitimate
  only when verification was actually performed that day. Never assign
  a date because a migration script touched the file.

## Verification timestamps

- Format `YYYY-MM-DD`, calendar-valid (leap-year aware), no
  impossible dates (`2026-02-31` fails). Staleness derives from a
  180-day review window (`stale_count` in lint output) — stale is a
  review queue, not an automatic demotion.

## Disabling stale / broken providers

- Demote to `needs_review` when verification can no longer be
  substantiated (provider changed, blocked, ambiguous). Demotion
  removes `verified_at`/`verification_method` and keeps the honest
  provisional note — never invent a fresh date.
- Set `disabled` only for actively misleading definitions (verified
  false-confirm). Disabled providers are never queried and are
  excluded from scheduling with explicit reasons.

## Enforcement

```bash
cargo run --locked -- search lint
```

Errors fail the gate (exit 1); warnings do not. A trust-claim
contradiction is always an error. Current corpus state is printed by
`rxscan search stats` and `rxscan search providers` — both derive
counts dynamically from the registry.
