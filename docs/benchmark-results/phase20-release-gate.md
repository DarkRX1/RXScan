# Phase 20 Release Gate

Final phase before deciding on a first public prerelease candidate. The gate
does not celebrate RXScan; it tries to stop shipment. Every section below
records what was attempted, what broke, and what remains.

```sh
cargo run --example phase20_release_gate
cargo test --test phase20_release
sh scripts/release-check.sh
```

Environment: `Linux 7.0.12-1-aegis-offensive`, x86_64, 12 logical CPUs,
`rustc/cargo 1.98.1` locally (CI pins `1.85.0`), loopback/synthetic
fixtures only. Nothing was published, pushed, tagged, or uploaded.

## Measured output (`cargo run --release --example phase20_release_gate`)

```text
phase20_release_gate
version=0.1.0
git_commit=fd029b6e3c0fd3ccecc2923a1666ae20bda24079
git_clean=false
rustc=rustc 1.98.1 (48a229cea 2026-09-01)
cargo=cargo 1.98.1 (797e8a9bc 2026-08-05)
target=x86_64-linux
release_binary_size_bytes=8351304
p19_binary_delta_bytes=45960
startup_samples=11
startup_min_ms=1.35
startup_median_ms=1.49
startup_max_ms=1.74
full_test_count=452
release_test_count=452
ignored_tests=0
end_to_end_scan_ms=530
resume_duplicate_contacts=0
diff_network_requests=0
analysis_network_requests=0
report_network_requests=0
project_network_requests=0
sigint_shutdown_ms=2
open_fds_before=5
open_fds_after=5
threads_before=2
threads_after=2
checkpoint_valid_after_interrupt=true
project_valid_after_interrupt=true
artifact_checksum_verified=true
production_dependencies=10
dev_dependencies=1
```

(`git_clean=false` is the uncommitted P20 work itself, which this document
describes. Test counts are `--list` methodology; executed totals match:
452 debug + 452 release, 0 failed, 0 ignored.)

## Release blockers found and fixed

1. **Checkpoint save rejected real scans (NOT READY → fixed).**
   `--checkpoint` failed on a trivial closed-port scan (`event asset
   missing`), then on multi-stage scans (`conflicting duplicate asset id`,
   `dangling asset relationship`). Root causes, all in module emission or
   persistence merge semantics, never in validation (validation did its job):
   - TCP discovery emitted detailed closed/filtered/error events referencing
     port assets it never created → now emits bounded typed port assets
     (same ≤256 `detailed` gate as the events; no evidence/findings).
   - TCP summary evidence anchored to the parent host asset, which no output
     owns at level 1 → now anchors to the first port asset the output owns;
     skipped when asset-less (the `PortScanCompleted` event already carries
     counts).
   - `collect_global_assets` demanded byte-identical duplicates, but
     overlapping port tasks and http/baseline/content endpoint observations
     legitimately re-observe one stable ID → now merges same-kind duplicates
     (first-wins attributes, timestamp span); different-kind collisions still
     rejected.
   - Content `DiscoveredByContentProbe` pointed at a mangled URL string →
     now references the shared `endpoint_asset_id`, ensures the origin asset
     locally, and skips self-links.
   - Baseline `ParameterOf` pointed at a synthetic `asset_param_*` with no
     asset → relationship removed (engines read event details, verified).
   - Crawl out-of-scope denials pushed an edge to a deliberately unfetched
     URL → the discovered URL is now assetized under P18 external-entity
     semantics (recorded, never contacted, no follow-up).
2. **Crawl coverage depended on task completion order (NOT READY → fixed).**
   The contact registry blocked crawl fetches after content claims, so adding
   an unrelated open port reordered tasks and silently dropped all crawl
   coverage of the first host (proven: identical fixture, links found vs
   lost). Only crawl extracts links, so the rule is now asymmetric: content
   still skips crawler-fetched URLs (P11 contract + test preserved; baseline
   classifies independently), crawl never skips content-claimed URLs.
3. **Governor double-derivation (NOT READY → fixed).** `Scheduler::new` fed
   the derived concurrency back as the new maximum, collapsing e.g.
   `Numeric(50)`+budget 4 from 2 slots to 1. Budgets are now combined by
   minimum *before* a single derivation (idempotent); setting/timeouts/
   retries preserved; hard cap retained. Exact regression tests + monotone
   speed matrix (0/25/50/75/100 × slow/balanced/fast/auto × budgets 1–64).
4. **Non-UTF8 CLI argument panicked (exit 101 + backtrace → fixed).**
   `main` now uses `args_os` and exits 2 with a clean message.
5. **Missing `--wordlist` silently ignored (fixed).** Unreadable candidate
   files now fail at plan compile (exit 2, names the file).
6. **Unknown TOML keys silently ignored (fixed).** `deny_unknown_fields`:
   typos like `max_task` now fail with file + location (exit 2).
7. **Scan `--output` wrote directly to the final path (fixed).** Truncated
   output could masquerade as complete after interruption. Now temp +
   file-sync + atomic rename; prior valid files are never touched until the
   stream completes; unfinished temps are removed best-effort on drop.
8. **Broken pipe panicked (fixed).** All stdout paths exit silently with
   status 0 on EPIPE; stderr diagnostics never panic.

## SIGINT behavior (measured, real binary)

Default OS disposition (no signal machinery added, deliberately): a slow
content scan SIGINTed mid-run dies in ~2ms by signal (no exit code = killed,
shell reports 130), no panic text, prior checkpoint/output files
byte-identical afterwards, checkpoint still loads. A second SIGINT during
shutdown is equally prompt (nothing to shut down). Death latency is measured
from after the last signal so helper-spawn time under suite churn cannot
contaminate the product measurement; a 30s watchdog with SIGKILL guarantees
a hung shutdown fails loudly instead of hanging CI. Stale `*.tmp-*` files
from a killed run are inert (overwritten next run, safe to delete);
successful runs leave zero stray temps (asserted).

Four ~16.0s shutdown readings occurred during investigation, all inside
backgrounded `nohup sh scripts/release-check.sh &` runs — and the cause was
the invocation, not the product: a non-interactive shell without job
control sets SIGINT/SIGQUIT to SIG_IGN for backgrounded commands, and exec
preserves SIG_IGN down the whole tree, so the scan literally could not
observe the kills (`SigIgn` showed bit 1 set on a manually reproduced
process; foreground runs always show clear masks and ~2ms deaths). The test
now detects an inherited SIG_IGN up front and skips loudly instead of
failing confusingly; the script is meant to run foregrounded (as CI does).
Recorded here, not hidden — and the product deliberately does NOT reset
inherited dispositions (that would steal explicit `trap '' INT` protection
users may rely on).

## Exit-code / stdio contract (implemented + tested)

`0` success; `2` CLI/config/usage (bad level/speed/ports/CIDR/budget,
unknown command, excluded seed, non-UTF8 args, unreadable wordlist/config);
`1` invalid input/state or runtime failure (bad checkpoint/project/report
input, unwritable output). Machine stdout (`--json`/`--jsonl`/`raw`, JSONL
streams) is never polluted by diagnostics; every JSONL line parses;
`report --format json` parses as one document. An explicit target is always
authorized (`--scope` only adds rules); excluded seeds fail loudly (exit 2).
All-failed tasks still exit 0 when RXScan itself worked (documented).

## Panic / unsafe / shell audits

113 `unwrap`/`expect`/`panic` sites inventoried: test modules, mutex-poisoning
only, constant `Confidence::new(N≤100)`, infallible serde of fixed structs,
same-statement `Some` presence, contains→get, pre-initialized map keys, and
two early-return-guarded `unreachable!`s (DNS TXT, verified) — zero reachable
via user input; the three risky sites (DNS match, service/web TLS expects)
verified guarded. `unsafe` is confined to `tcp_scanner`/`icmp` Linux syscall
wrappers (`#[repr(C)]` structs, owned-FD close-on-drop) and the standard
`RawWaker` boxing pattern; no new `unsafe`. Zero `Command::new` in
production paths. No `dbg!`/stray prints in `src/`.

## Schemas and compatibility policy

Checkpoints (`schema_version=1`, 8 MiB), projects
(`project_schema_version=1`, 16 MiB), reports (`report_schema_version=1`,
`raw_schema_version=1`): unknown future versions fail safely naming the
version; no forward compatibility claimed or tested; backward compatibility
is byte-stability of committed golden fixtures
(`tests/fixtures/golden_checkpoint_v1.rxscan`,
`golden_project_v1.rxproj`, `future_checkpoint.rxscan`), which load and
re-save byte-identically. Config files reject unknown keys (no silent
typos); precedence stays defaults < global < project < CLI (tested).

## Release engineering proofs

- Clean worktree (`HEAD` + applied diff + copied untracked files, no home
  files): `cargo build --release --locked` succeeds; binary runs `--version`.
- `cargo build --release --locked --offline` succeeds (no build-time web
  beyond prefetched crates; cold-registry fetch not re-proven here).
- `ldd`: only `libc.so.6`, `ld-linux`, `libgcc_s` (via `ring`). No
  Python/Node/Docker/scanner/daemon runtimes.
- Isolated `cargo install --path . --root <tmp>` succeeds; installed binary
  reports `rxscan 0.1.0`; root removed afterwards.
- Artifact dry-run procedure (recorded in `docs/RELEASE_CHECKLIST.md`):
  `rxscan-<version>-<target>.tar.gz` with binary + README + checksums
  (`SHA256SUMS`, verified with `sha256sum -c`); no signing identity exists
  (documented, deferred). No tag/push/publish performed.
- Dirty-tree protection lives in `scripts/release-check.sh`, which runs the
  full gate (fmt, check, tests, clippy, rustdoc, P19 bench, P20 gate,
  release build, smoke, offline commands, optional install proof) and stops
  on first failure without publishing anything.

## E2E transcript (loopback lab, release binary)

Lab: one open TCP port, one HTTP server (`/` with 7 links incl. an
out-of-scope canary on 127.0.0.2, `/a`, `/b`, `/redirect`→`/a`, `/admin`,
`/search?q=hello`), level-4 scan with checkpoint + JSONL output.

```sh
rxscan http://127.0.0.1:$P/ --scope 127.0.0.1 --level 4 \
  --ports $P,$Q --checkpoint lab-a.rxscan --output lab-a.jsonl
# exit 0; canary connections: 0; Authorization headers sent: 0; POSTs: 0
rxscan --resume lab-a.rxscan --checkpoint lab-r.rxscan  # same IDs, same scope
rxscan diff lab-a.rxscan lab-r.rxscan
rxscan analyze lab-a.rxscan
rxscan report --format json lab-a.rxscan                # summary.network_requests=0
rxscan project create lab.rxproj
rxscan project add lab.rxproj lab-a.rxscan
rxscan project summary lab.rxproj
```

Soak: 6 repeated level-2 scans — no slowdown beyond 5× first run, exactly
12 files remain, zero `*.tmp-*` residue. FD counts equal before/after the
offline chain. Privacy probe (40 KiB-buried 128-char secret, 500-char
cookie): secret never persists verbatim in checkpoint/JSONL; cookie
observations stay ≤256B + truncation flag.

## P19 regression (after P20 changes)

`cargo run --release --example phase19_bench` (post-P20 semantics):
scheduler 1500/1500 in 512ms, queue 64/64, 65,535 ports at `fd_peak=32`,
checkpoint save/load 31/33ms, diff 37ms, analysis 18ms, report render 16ms,
project 11.7 MiB open/fingerprint/query 85/25/578ms with caps hit exactly,
peak RSS 103 MiB — same structural profile as the Phase 19 record, no RSS/
startup/binary/throughput/thread/FD regression beyond the documented
+45,960-byte growth. P18 invariants (single-threaded project, zero
background CPU/RAM, streaming fingerprint/save with 0 whole-state clones,
16 MiB cap) and P14–P17 semantics re-verified by their untouched suites.

## P18 RSS-flake investigation (closed)

`large_project_open_memory_is_reasonable` failed once under full-workspace
parallel load. Cause: VmRSS is process-wide; sibling tests sharing the
binary's allocator inflate current-RSS deltas (the fingerprint delta sat at
~80% of its budget, so allocator noise alone could trip it). Fix: the
measurement now runs in an isolated child process (`--exact` + env flag);
thresholds unchanged — noise removed, protection intact. Verified green
repeatedly since.

## P10–P11 history audit

`3680568` (phases 10–11, 27 files) and `4f9f59a` (same message, 16 files)
are sequential legitimate work, not duplicates: the second is a mislabeled
Phase 12 draft (fuzz engine + tests + bench), strictly additive on top of
the first. No action taken; history untouched.

## Repository audit

112 tracked files, 2.0 MiB `.git`; largest blobs are test/source files
(≤88 KiB); no binaries, dumps, or logs tracked. No secrets, tokens, or
personal paths in tracked content. `target/`, `dist/`, logs ignored.
Root `css/`/`js/`/`index.html` are a leftover portfolio prototype: excluded
from release artifacts by the allowlist procedure, left untouched in-tree.

## Known limitations (prerelease)

Linux x86_64 only; hard caps everywhere; ICMP degrades without privileges;
no exploit/vuln/credential/stealth capability by design; external mid-run
cancellation handle absent (tokens/timeouts/global budget instead); project
multi-writer conflicts fail loudly; checksums but no release signing; no
crates.io, man page, or completions; all-failed scans exit 0 when RXScan
itself worked; content refetches crawler-seen pages by design (bounded).

## Tested platform statement

Built, tested, and benchmarked on Linux x86_64 (kernel 7.0.12) with Rust
1.85 (CI pin) and 1.98.1 (local). "Rust is cross-platform" is not claimed
as RXScan evidence. No macOS/Windows builds were attempted.

## Draft v0.1.0 prerelease notes

RXScan v0.1.0 is a prerelease for controlled evaluation on Linux x86_64:
native policy-driven reconnaissance (host/TCP/service/web/crawl/baseline/
content/fuzz/DNS) with typed JSONL, checkpoints + resume, offline
diff/analysis/report/project, and hard resource bounds throughout. For
authorized systems only. Not production-proven; not signed; install via
`cargo install --path .` or the release tarball; remove by deleting the
binary. Report security issues privately (see `SECURITY.md`).
