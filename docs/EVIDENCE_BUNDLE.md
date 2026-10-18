# Evidence bundles

`rxscan evidence-bundle` exports a masked, self-describing copy of the
evidence stored in a project database. `rxscan verify-bundle` re-checks that
copy later, offline.

```sh
rxscan evidence-bundle <project.db> --case-id CASE-2026-014 \
    --operator analyst --out ./case-014
rxscan verify-bundle ./case-014
```

## What a bundle contains

| File | Contents |
| --- | --- |
| `bundle.json` | schema version, tool version, UTC creation time, `case_id`, `operator`, `run_ids`, the stored `scopes` per run, `evidence_count`, `evidence_ids` |
| `evidence.jsonl` | one masked evidence record per line (`id`, `scan_run`, `source`, `asset_id`, `confidence`, `details`, `timestamp_ms`) |
| `manifest.txt` | SHA-256 of `bundle.json` and `evidence.jsonl` |

The bundle is a **redacted copy**. The originals stay in the project
database. Secrets are masked before writing, and a non-empty output
directory is refused unless `--force` is given (with `--force` the directory
is cleared first, so a bundle never mixes old and new files).

## Recording the digest

At creation the command prints the **bundle digest**: the SHA-256 of
`manifest.txt`.

```
bundle digest (sha256 of manifest.txt): 8f7a1044...
```

**Record that digest out of band** — in the case file, the ticket, or
wherever the case is tracked — and pass it back at verification time:

```sh
rxscan verify-bundle ./case-014 --expect-digest 8f7a1044...
```

### Why the out-of-band digest matters

`manifest.txt` is stored *inside* the bundle. Anyone who can rewrite the
bundle can regenerate `manifest.txt` from the rewritten files, and then every
hash still matches. Verification on its own therefore detects **accidental**
change only (truncation, partial copies, bit rot, an edited file).

The out-of-band digest is what detects **deliberate** rewriting: an attacker
who changes the files cannot change the digest you recorded elsewhere. Without
it, do not treat a passing `verify-bundle` as proof against a motivated
party.

## What verification rejects

`verify-bundle` fails on:

- a hash mismatch for any listed file
- a missing file, or an extra file in the bundle directory
- a subdirectory or a symlink inside the bundle (symlinks are never followed)
- a manifest entry naming anything other than `bundle.json` /
  `evidence.jsonl`, which is what stops a rewritten manifest from pulling in
  `../outside.txt` or `/etc/passwd`
- a malformed manifest line or hash
- `evidence_count` disagreeing with the line count of `evidence.jsonl`, or
  the ids in `bundle.json` disagreeing with the records in it
- a digest mismatch when `--expect-digest` is given

## Limits

RXScan does not provide or claim legal admissibility, digital signing, or
operator authentication. A bundle plus its recorded digest is evidence of
*internal consistency*, and nothing more.