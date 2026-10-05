# RXScan monitoring foundations (Stage 7)

RXScan is local-first: there is no cloud service. Repeatability comes
from stable machine output plus the project database, composed by the
operator's own scheduler (cron, systemd timers, CI).

## Repeat-and-compare workflow

```bash
# 1. Repeat the investigation into a persistent project database.
rxscan investigate --username exampleuser --depth 2 \
  --project-db project.db

# 2. Compare the two latest runs (run ids come from `project-db scans`).
rxscan project-db diff --db project.db <old-run> <new-run> --check
echo "diff exit: $?   # 0 = agree, 3 = changes detected"
```

A monitoring run knows previous vs current, coverage differences, new
and removed entities, changed relationships, and new exposures — with
one invariant: **missing evidence is never negative evidence**. A
provider that was blocked, rate-limited, or truncated in the new run
leaves `UNKNOWN`, never a fake removal (see `docs/INVESTIGATION.md`).

## Exit codes

```text
0  success (diff --check: runs agree)
1  invalid input/state or runtime failure
2  CLI/configuration/usage error
3  diff --check: changes detected
```

Exit 3 exists only under explicit `--check`; default commands keep
their historical codes so existing scripts do not break.

## Machine contracts for automation

- JSON and JSONL schemas carry `schema_version` and stable
  `record_type` envelopes; treat them as versioned interfaces.
- Every JSONL line parses independently; stdout carries no ANSI,
  banners, or progress output; broken pipes exit silently with status 0.
- Investigation summaries reconcile exactly
  (`requested == completed + skipped + cancelled + unscanned`); a
  monitoring harness should assert this before trusting a run.
- `truncated` plus `truncation_reasons` distinguish partial runs from
  complete ones; alert on truncation, not just on changes.

## Suggested scheduled checks

1. Re-run the investigation nightly into the same `project.db`.
2. `project-db diff --check` against the previous run id.
3. On exit 3, archive the JSON report and notify; on exit 0, do nothing.
4. Weekly: review `truncated` runs and adjust budgets rather than
   ignoring them.
