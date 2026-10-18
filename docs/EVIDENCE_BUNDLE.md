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
database. Secrets are masked before writing.

A non-empty output directory is refused unless `--force` is given. `--force`
means *replace the bundle this command wrote* — it never means *empty this
directory*. Only `bundle.json`, `evidence.jsonl` and `manifest.txt` are
removed; if the directory holds anything else (an unrelated file, a
subdirectory, a symlink), the command refuses and writes nothing:

```
$ rxscan evidence-bundle ./notes --case-id C1 --force --out ./work
rxscan evidence-bundle: output directory './work' holds entry 'notes.txt'
this bundle does not own; point --out at a directory used only for bundles,
or move them first
```

Point `--out` at a directory used only for bundles. This is deliberate: a
mistyped `--out` must not destroy unrelated data.

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

## What evidence-bundle refuses

`evidence-bundle` writes nothing and exits non-zero when:

- the project cannot be opened, or the evidence cannot be read
- the output directory holds anything other than a previous bundle (see
  above), with or without `--force`
- the output path exists and is not a directory
- any file cannot be written and re-read successfully

Files are staged in a temporary directory beside the target and moved into
place only once every one is written and verified, so a failure never leaves
a partial bundle behind.

## Limits

RXScan does not provide or claim legal admissibility, digital signing, or
operator authentication. A bundle plus its recorded digest is evidence of
*internal consistency*, and nothing more.