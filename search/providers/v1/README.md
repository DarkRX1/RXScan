# RXScan username search corpus (v1)

Public-source username/account discovery. Each file holds the providers for
one category; `build.rs` merges them into a single deterministic embedded
pack (sorted by provider ID; duplicate IDs rejected).

```text
search/providers/v1/username/
    developer.json
    social.json
    forum.json
    gaming.json
    creative.json
    security.json
    professional.json
    media.json
    commerce.json
```

Fixtures live next to the corpus, one directory per provider ID:

```text
search/fixtures/username/<provider-id>/cases.json
```

## Real CLI

```text
rxscan search --username exampleuser
rxscan search username exampleuser
rxscan search providers
rxscan search stats
rxscan search lint
```

## Health states (never conflate these)

```text
fixture_verified   synthetic fixtures pass; live behavior NOT checked
live_verified      live behavior actually checked (requires verified_at)
needs_review       provisional, blocked, or ambiguous live behavior
disabled           never queried (actively misleading definitions)
```

A passing synthetic fixture DOES NOT mean the provider works live.
Fixtures prove classifier behavior; only live observation validates the
classifier against reality. Fixture bodies are minimal synthetic
representations of response structure, never bulk-copied live pages.

`live_verified` requires `verified_at` (date) and `verification_method`
(no test usernames, machine names, or operator data). The loader rejects
`live_verified` without verification metadata.

## Evidence rules

```text
possible != confirmed        weak evidence stays weak
HTTP 200 != account existence  status alone never confirms
public search != network scan  username search performs zero network scans
```

Strong confirmation needs identity evidence: a canonical username field,
a documented public profile object, a canonical profile URL, or a
provider API identity match. Required markers must be username-anchored
and verified against real response structure; watch for whitespace and
attribute-order differences in HTML.

Blocked markers must never match normal profile pages (a bare
`"captcha"` once matched ordinary pages via embedded script names and
silently converted every confirmation into `Blocked`). Absence markers
must never match normal pages either (absence is checked first).

Responses beyond the provider's fetch budget classify as `Unknown`
rather than risking partial-body evidence. Typical profile pages above
the budget are documented in `source_notes`; prefer small documented
public APIs where available.

## Adding a provider

1. Real public username/account mechanism only. No mechanism, no provider.
2. Start at `needs_review` with `source_notes` explaining what is known.
3. Found / not-found / generic-200 / blocked fixtures (all four).
4. Conservative `username_rules` only where well-supported; when in
   doubt, leave rules unset so the username is queried, not skipped.
5. Run `rxscan search lint` (exit 1 on errors) and the full test suite.
6. Promote to `live_verified` only after checking a known-existing and
   a known-absent username against live behavior, plus `verified_at`.

## Username rules

Declarative, conservative: `min_length`, `max_length`, `charset`.
Violations skip the provider with an explicit reason (visible in
`--explain`), counted in exact scheduler accounting. Never guess at
limits; an uncertain provider stays permissive.

## Security boundary

Username search is `PublicHttp` reconnaissance: no authentication, no
password recovery, no CAPTCHA evasion, no rate-limit evasion, no proxy
rotation, no private/internal destinations (resolve → validate → pin on
every redirect hop), no automatic network scanning. Bot walls and
challenges are *detected* (`blocked`), never bypassed.
