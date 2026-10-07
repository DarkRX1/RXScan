# RXScan AI-ready boundary (documented for future, not implemented)

RXScan does not depend on AI, does not require an API key, and must never
let a model decide whether evidence exists. This document fixes the
architecture boundary so an *optional* future AI layer can only consume
structured evidence — never produce it.

## Authority direction

```text
Optional AI (summarize / explain / suggest)
        │ consumes structured evidence, cites evidence IDs
        ▼
Evidence API (read-only views over finished reports)
        │ InvestigationReport, ScanGraph, observations, pivots
        ▼
RXScan Core (authoritative: observation → evidence → entity → relationship)
```

Rules for any future layer:

- The model reasons over `InvestigationReport` / project-graph JSON,
  including `entities`, `relationships`, `observations`, `pivots`, and
  provenance (`source`, `provider`, `contact_class`, `timestamp`,
  `confidence`). It must cite the evidence IDs behind every claim.
- It may rephrase `reason`/`state` text and rank the existing
  `suggest_pivots` output. It must not invent entities, relationships,
  confidence values, or pivots that have no backing evidence object.
- It must preserve the active/passive boundary: suggesting an authorized
  scan target requires the same explicit `--network --scope` operator
  action as today. A model suggestion is never authorization.
- It must preserve `unknown means unknown`: absence handling, coverage
  awareness (`UNKNOWN` vs negative), and historical-vs-current
  distinctions flow through unchanged.
- No cloud AI SDK in the deterministic build. If a future integration
  needs one, it lives behind an explicit opt-in feature/flag, sends only
  operator-selected report excerpts, and normal RXScan operation (all
  gates in `docs/TESTING.md`) passes without it.

## What exists today (no AI needed)

- `suggest_pivots` already produces evidence-backed next steps with
  reason/source/state (`docs/INVESTIGATION.md`).
- `explain_entity` walks any entity back to the seed with citations.
- `--explain`, `--json`, and project history give complete deterministic
  provenance for any external summarizer to consume.

Status: boundary documented. No AI dependency added.
