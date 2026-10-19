# History exposure report

Date: 2026-10-19
Repository state: `master` at `8fdbe82905953d2de47dc0a44b41d6083f7610d1`, 130 commits across all refs.

**This report is informational only. No history was rewritten, no tag was
moved, amended, rebased or force-pushed, and no command that would do so was
run.** Rewriting history is the maintainer's decision, taken deliberately, in
a fresh clone.

## Read this first

Removing a value from the working tree does **not** remove it from existing
clones, forks, mirrors, GitHub's cache, or published release archives. Git
stores every version of every file forever. Anything that was ever a live
secret must be **rotated**, not merely deleted. Deleting a line from the
current tree leaves that line perfectly readable in any existing clone with
`git log -p`, and the same content may already be indexed by third parties.

For this repository the exposure assessed below is **identity and authorship
metadata, not live secrets**. No credential requiring rotation was found. If
that assessment is ever wrong, rotation is the only remedy.

## Method

Sweeps used generic, non-project-specific patterns only, plus standard author
metadata. No literal maintainer terms were committed to any file, and no raw
matched value appears in this report. Results are reported as counts by commit
and by **class** of exposure.

## Finding 1 — author identity on every commit

**Class:** maintainer identity (personal contact address in commit metadata).

All 130 commits across all refs carry a single author identity whose address
is on a consumer mail domain (class: personal mail address, redacted). This
is inherent to Git: the author name and email are recorded in every commit
object and are propagated to every clone.

This cannot be fixed in the working tree. It is a property of the existing
history.

## Finding 2 — repository identity strings in historical commits

**Class:** maintainer identity (handle in source and metadata).

The maintainer handle appears in the content of 11 commits. Because the same
string is a substring in several places, the lowercase variant sweep reports 6
distinct commits; the union is the 11 commits below.

| Commit | Date | Subject |
| --- | --- | --- |
| `26c55e16918afe94c5e951a0db10726269e4d747` | 2026-10-17 | import: add 74-icon pack to app/assets/icons with SVG safety and manifest parity tests |
| `204409641e910e155b626f3379350e3b70d6f688` | 2026-10-06 | feat: expand RXScan parity and harden repository |
| `847e70f8464de265bbe13927d815135f5e29c9ee` | 2026-10-05 | feat: rebuild portfolio around scroll-driven lattice motif |
| `88bbfa0da10c18882ed1eb751a80f6be5eb5d9a0` | 2026-10-05 | Update README.md |
| `4a5377c7b1dee35a7bfea13772882322b2e835bb` | 2026-10-05 | Update README.md |
| `b0ea9b309a0e09d304149ec7bf403c805da4ce55` | 2026-10-05 | fix: harden username search scheduling and HTTP policy |
| `11023e8c9a0551cae88d94d857c5981203458932` | 2026-10-04 | feat: expand intelligence, correlation, and project analysis |
| `3213a2169dae62bdf76241150dccf29e29aee478` | 2026-09-14 | docs: add MIT license |
| `8352f3e9d37658f7aa4920b5e4f6cb28baedc4ad` | 2026-09-12 | feat: implement RXScan phase 5 host discovery |
| `70500120723129c4a363cf4a3b399933a91eac57` | 2026-09-12 | feat: complete RXScan phase 4 control plane |
| `76f1a9781bd26aafaffed5f1eac4515a246e6f4b` | 2026-09-11 | feat: implement RXScan phases 0-1 foundation |

Current-tree occurrences of the same class are public repository coordinates
that the maintainer confirmed should stay; see
`docs/PRIVACY_SCRUB_REPORT.md`.

One commit in that list, `847e70f` ("feat: rebuild portfolio around
scroll-driven lattice motif"), is reachable only from the local
`backup/portfolio-847e70f` branch and not from `master`. It belongs to the
separate personal portfolio work that the packaging policy already excludes,
so it is unreachable from any release, but it remains a readable object in
this clone.

## Finding 3 — absolute home paths in history

**Class:** development-side identity (machine-local paths).

`/home/` and `/Users/` each appear in 4 historical commits. The occurrences
that exist in the current tree are the redaction tests' own forbidden-path
needle lists, which are intentional and must stay.

## Finding 4 — bearer-token-shaped strings in history

**Class:** possible secret (reviewed, not a real credential).

The literal `Bearer ` appears in 3 commits. A full sweep of every commit for a
well-formed bearer token of 20 or more token characters found the occurrences
are the synthetic fixtures in the secret-masker's own tests. **No live
credential was found.** No rotation is indicated.

## Finding 5 — `ghp_`-prefixed strings in history

**Class:** possible secret (reviewed, not a real credential).

The literal `ghp_` appears in 2 commits. Every commit was swept for a
well-formed GitHub personal access token (prefix plus exactly 36 token
characters): **none was found in any commit.** The literal occurs only as a
secret-detector pattern in `src/repo_intel.rs` and as short synthetic strings
in tests. No rotation is indicated.

## Clean

- **No `Co-Authored-By` trailers** in any commit.
- **No AI/agent attribution footers** in any commit. A naive sweep for
  "generated with" produced one apparent hit on `912ce20`; inspection showed
  it was the ordinary English phrase "regenerated with it" in prose about the
  evidence bundle. A precise sweep for AI/agent attribution across all 130
  commits returned zero.
- **No well-formed AWS access keys, GitHub PATs, Slack tokens or `sk-` API
  keys** in any commit.
- **No private key material** in any commit. The `-----BEGIN ... PRIVATE
  KEY-----` headers present are synthetic masker fixtures.
- **No absolute Windows user paths** (`C:\Users\...`) in any commit.
- **No `.env`, session artifacts or editor backups** in any commit.

## Maintainer-run options (documentation only — not executed)

The agent deliberately did not run, and will not run, any of the following.

**Option A — accept.** Take no action. Reasonable here: the exposure is
identity metadata, not live secrets. Cost: the handle and the personal mail
address remain readable in every existing clone.

**Option B — rotate nothing, rewrite nothing, and rely on the v1.3.0 tree.**
The scrubbed tree plus the new `privacy-gate` CI job prevents *new*
exposure. This is the default recommendation if history rewrite is not worth
the disruption.

**Option C — rewrite history with `git filter-repo`, deliberately.** This is
the only way to remove a value from existing clones. It is destructive and
must be done by the maintainer in a fresh clone.

Risks to weigh before choosing Option C:

- Every commit SHA changes. The existing tags `v0.1.0-rc.1` through `v1.2.1`
  would have to be recreated, and v1.2.0/v1.2.1 are already published, so the
  rewritten history would no longer match those releases.
- Anyone with an existing clone must re-clone or rebase. Divergence is
  unavoidable.
- It requires a force push, which rewrites shared state.
- The published release archives and GitHub's cached views of the old commits
  are **not** removed by a rewrite.
- Commit-graph tooling, forks and mirrors break.

Sketch of the procedure, for the maintainer to run only if Option C is chosen:

```sh
# 1. Fresh clone. Never run this in the working repository.
git clone <url> rxscan-rewrite && cd rxscan-rewrite

# 2. Install the tool.
pipx install git-filter-repo

# 3. Rewrite author metadata to a neutral identity.
#    Supply the replacement values as shell variables; do not inline them.
git filter-repo --mailmap "$MAILMAP_FILE"

# 4. Rewrite content occurrences of the handle in the specific paths that
#    carry it, leaving its occurrences in fixtures and tests intact.
git filter-repo --path Cargo.toml --path LICENSE --path README.md \
  --replace-text "$REPLACEMENTS_FILE"

# 5. Verify before touching the remote.
git log --all --format='%an <%ae>' | sort -u
sh scripts/privacy_gate.sh
cargo test --all-targets

# 6. Only then, and only deliberately:
#    Recreate the published tags on the rewritten commits, then force-push.
git push --force --tags origin master
```

Recommended mitigations regardless of which option is chosen:

- Add a `.mailmap` file so future commits collapse to one neutral identity.
- Configure `git config user.name` / `user.email` to a neutral or
  `noreply` address for all future work.
- Keep the `privacy-gate` CI job red-capable so the gate blocks merge.

## Statement

This agent did not rewrite, rebase, amend, filter, force-push, or move any tag,
and will not do so on request. The commands above are provided as
documentation for the maintainer to evaluate and run at their own discretion
and risk.