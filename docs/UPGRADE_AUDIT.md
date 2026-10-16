# RXScan 1.2.0 Graph Upgrade — Audit (Phase 0)

Baseline: HEAD `1f2b1b3`, clean tree, `0 0` vs `origin/master`,
`version = "1.1.0"` in `Cargo.toml`, tags `v0.1.0-rc.1 v1.0.0 v1.0.1 v1.0.2 v1.1.0`
untouched. Toolchain in this environment: `rustc 1.99.0`; MSRV per
`Cargo.toml` is `1.85`.

All file/line references below were read from the baseline tree, not the
prompt snapshot. Where the snapshot was wrong it is called out.

---

## 1. Current graph data model (`src/graph.rs`)

**In-memory correlation graph, built post-scan, pure/bounded/deterministic.**

- `ScanGraph` (`graph.rs:377`): `entities: BTreeMap<String, GraphEntity>`,
  `edges: Vec<GraphEdge>`, `truncated: bool`. Bounds: `MAX_GRAPH_ENTITIES =
  8192`, `MAX_GRAPH_EDGES = 16384`, `MAX_EDGE_EVIDENCE = 4` (`graph.rs:20-25`).
- `GraphEntity` (`graph.rs:350`): stable content-derived `id`, `kind:
  EntityKind`, `label`, bounded string `attributes` (≤12 pairs, key ≤64 B,
  value ≤256 B via `bounded_attrs`), `provenance: EntityProvenance`,
  `observations: u32`.
- `GraphEdge` (`graph.rs:363`): `from`, `to` (entity ids, directed),
  `relation: EdgeRelation`, `confidence: u8` (capped at 95 on insert,
  `graph.rs:585`), `provenance: EntityProvenance`, bounded `evidence:
  Vec<String>` (≤4 excerpts, each ≤256 B), `attributes`.
- `EntityProvenance` (`graph.rs:333`): `scan_plan_id`, `module`, optional
  `task_id`/`target`/`reason`/`rule_id`, `timestamp`. Same envelope shape as
  record provenance so JSONL `payload.provenance.scan_plan_id` stays uniform.
- Dedup: same `(from, to, relation)` keeps max confidence and merges bounded
  evidence (`graph.rs:551-569`). Self-edges dropped; edges to missing
  entities dropped.

**Node types — `EntityKind` (`graph.rs:31-65`, 32 variants).** The prompt's
Phase-1 list (Network, IP, Host, Port/Service, Software/Version, Certificate,
Domain, URL, Username, Account/Profile, Exposure Finding, Evidence, Scope)
does NOT match the code 1:1. Actual variants: `Username, EmailAddress,
Domain, Account, Organization, NetworkEndpoint, Repository, Asn, Host,
IpAddress, Hostname, Port, Service, Certificate, SshHostKey, DnsRecord,
WebEndpoint, Technology, Fingerprint, OsCandidate, DeviceCandidate,
Exposure, ExposureSource, NetworkPrefix, Package, Document, ArchiveSnapshot,
PublicKey, Route, Provider, IdentityHypothesis, Software`. There is no
dedicated `Evidence`, `Scope`, or `Url` kind (`WebEndpoint` covers URLs;
scope state rides on edge attributes, e.g. `HasSan` edges carry
`contacted=false` + `scope=in-scope-uncontacted|outside-scope|scope-unknown`,
`graph.rs:1192-1195`). `graph_view.rs` must therefore define a *view* mapping
(lens) from these 32 stored kinds to the 13 upgrade-spec display entities
rather than renaming the stored model (renames would break DB compat).

**Edge types — `EdgeRelation` (`graph.rs:153-223`, 43 variants):**
`HasAccount, UsesUsername, LinksTo, ReverseResolvesTo, BelongsToAsn,
AnnouncesPrefix, FoundBy, HasAddress, ResolvesTo, ListensOn, RunsService,
PresentsCertificate, PresentsSshHostKey, HasSan, RedirectsTo, IdentifiedBy,
DiscoveredFrom, ObservedAt, Suggests, References, ServedBy,
ResolvesToEndpoint, ExposedIn, ObservedIn, Affects, ReportedBy,
TargetedDomain, MailExchanger, NameServerFor, AliasOf, OwnsRepository,
ContributedTo, PublishedRelease, ReferencesDomain, ReferencesUrl,
UsesPackage, SignedBy, ObservedAssociation, LikelyAssociation,
PossibleAssociation, Ownership, Supports, Contradicts`. The prompt's
Phase-1 link names (resolves-to, hosts, runs, serves-cert, signed-by,
same-fingerprint, found-on, correlated-with, derived-from) are again a
*display* vocabulary; the stored relations are finer-grained. `graph_view.rs`
will map stored relations → display link labels (incl. an observed/inferred
flag — see gap below).

**Evidence links:** every edge carries `evidence: Vec<String>` excerpts plus
full `provenance` (module/task/target/reason/rule/timestamp). Entities carry
first-observation provenance + `observations` count. `find_path(from, to,
max_depth 1..=6, deterministic BFS, ≤4096 visited)` (`graph.rs:430-471`)
already answers "why are these connected?" — the Explain chain primitive.

**Confidence fields:** edge `confidence: u8` (insert ceiling 95;
`ListensOn`=90, `ResolvesTo`=85, `ResolvesToEndpoint`/`ServedBy` derived
joins=85, `HasSan`=95, service edges carry classifier confidence). No
per-edge observed-vs-inferred boolean exists yet — Phase 1 must derive it
(stored-relation → display-style rule, e.g. `ResolvesToEndpoint`/`ServedBy`
joins are derived; direct handshake observations are observed). Fusion
semantics live in `confidence.rs` (`fuse_confidence`: min(strength,
reliability), independence cap 75/90, contradiction caps, recency penalty,
ownership cap 70, clamp ≤95) and are currently used by investigation
transforms, not by `graph.rs` builders (builders use fixed per-relation
constants). Preserve that behavior; visuals must show the stored value.

**Persistence:** `project_db.rs` (`PROJECT_DB_SCHEMA_VERSION = 4`,
`MIGRATIONS = [V1..V4]`) stores entities/edges per scan import
(`import_scan`, `graph.rs` → `project_db.rs:767+`); `GraphChange` records
computed changes (`project_db.rs:368`). The `graph` CLI is a summary/counts
view (`main.rs:~2321`). Baseline DBs for the migration test exist at
`tests/fixtures/golden_project_v1.rxproj` (+ `golden_checkpoint_v1.rxscan`,
`future_checkpoint.rxscan`).

---

## 2. How the GUI fetches data (`app/rxscan.js` ↔ `src/web_api.rs`)

- Transport: same-origin `fetch()` helper `api(path)` / `postJson`
  (`rxscan.js:25`), SSE via `EventSource("/api/v1/jobs/<id>/events")`
  (`rxscan.js:495`). All routes under `/api/v1/` (`web_api.rs:53`);
  unknown API routes → typed JSON error (`web_api.rs:3591`).
- Project graph endpoint: `GET /api/v1/projects/:name/graph?seed=<entity-id>&depth=N&limit=M`
  (`web_api.rs:3546`, handler `handle_project_graph`, `web_api.rs:2579`).
  **Seed is mandatory** (400 without it); BFS over *stored* relationships
  server-side (`web_api.rs:2646-2683`), bounded by `depth ≤
  INVEST_MAX_DEPTH` and `limit ≤ MAX_GRAPH_NODES`. Returns `GraphNodeDto`
  (`id, kind, label, first_seen_ms, last_seen_ms, observation_count`) and
  `GraphEdgeDto` (`from, to, relation, confidence, module, scan_run,
  evidence`). Related: `entities?limit&offset`, `findings`, `timeline`
  endpoints; investigation results via `POST /api/v1/investigations` (async
  job + SSE) and username search via `POST /api/v1/username-searches`.
- Rendering: `makeGraph(svg, legend, inspector, inspectorEmpty)`
  (`rxscan.js:119-361`) — inline SVG, radial layout only, hard caps
  (`nodes.slice(0,120)`, `edges.slice(0,400)`), pan (pointer drag) + wheel /
  pinch zoom (`0.4..4`), click/Enter/Space selection, kind filter dropdown,
  legend (≤12 kinds, color only), inspector kv list. Two instances:
  investigation graph (`#inv-graph`) and project graph (`#p-graph`).
- Gaps vs Phase 1 (all confirmed by reading): no full-graph or filtered
  endpoint (seed-required only; no `min_confidence`/`types`/`scope`/`time`
  filters; node DTO has no evidence chain, only counts); no expand-neighbors
  endpoint (client would re-request with new seed — acceptable primitive but
  no bounded single-hop API); no search-and-highlight, multi/box select,
  drag nodes, context menu, collections, clustering/LOD, undo/redo,
  alternate layouts, per-entity icons/shapes, diff coloring, exports.

---

## 3. Design tokens to reuse (`app/rxscan.css`)

Single source of truth, `:root` (`rxscan.css:6-36`): `--rx-bg #020711`,
`--rx-bg-deep #00040b`, `--rx-surface #061426`, `--rx-surface-2 #081c32`,
`--rx-border #123553`, `--rx-border-soft #0e2a44`, `--rx-cyan #00efff`,
`--rx-cyan-bright #19f4ff`, `--rx-blue #078cff`, `--rx-blue-deep #0758ff`,
`--rx-text #f4f8ff`, `--rx-text-muted #8fa9c2`; legacy aliases `--bg --panel
--panel-2 --line --text --muted --accent --focus --info`; status `--ok
#3ddc84 --warn #f0a04b --bad #f06666 --neutral #6b7d94`; `--radius: 6px`;
`--mono` (monospace stack) / `--sans` (system stack — **no webfonts, offline
by construction**). Graph styles exist (`rxscan.css:316-332`): `.gnode`
(+`.selected` cyan glow, `.dim`), `.glabel` 11px, `.gedge` (+`.selected`,
`.contradictory` dashed purple), `.graph-toolbar`, `.graph-split`,
`.inspector`, `.legend`, plus `prefers-reduced-motion` kill-switch
(`rxscan.css:406-408`) and `:focus-visible` outlines. Diff palette for
Phase 3 maps naturally: added→`--ok`, removed→`--bad`, changed→`--warn`,
not-covered→`--neutral` (gray; never red). All new Graph-view CSS must use
these vars; no new palette except per-entity hues derived from the existing
ramp + shape/label redundancy (contract: never color-alone).

---

## 4. Per-phase: exists / missing / plan

### Phase 1 — Maltego-style graph (priority)
- **Exists:** 32-kind/43-relation bounded evidence graph (`graph.rs`);
  `certificate_reuse`/`ssh_key_reuse` correlation; `find_path` explain
  primitive; SQLite persistence + seed-BFS API DTOs; `rxscan project graph |
  neighbors | related | path | show | explain` CLI (`main.rs:~2055-2343`);
  basic SVG radial viewer with pan/zoom/select/filter/inspect/legend.
- **Missing:** `graph_view.rs` (display-entity/link mapping, observed-vs-
  inferred style flags, confidence→thickness, filters, bounded neighbor
  expansion over stored data, layout algorithms, export serializers with
  masking); API query params (full graph is unsafe unbounded — must be
  *bounded* full-graph with caps, not unlimited); five GUI layouts, LOD/
  clustering, interactions listed in §2; `rxscan graph` CLI with
  `--format/--out/--min-confidence/--types`; PNG/SVG/GraphML/JSON/HTML
  exporters; 1k/10k/50k benches (`benches/` holds only `README.md` —
  criterion Bench harness must be added; examples/ holds phase benches as
  precedent).
- **Plan:** new `src/graph_view.rs` (view model + filters + layouts data +
  all serializers; PNG via pure-Rust rasterization of the SVG scene — no
  new system deps); small `web_api.rs` hook (extend graph endpoint params,
  add `…/graph/neighbors`); new `src/graph_cli.rs`-style wiring or extend
  `main.rs` dispatch minimally; GUI Graph view in `app/` reusing tokens;
  `benches/graph_scale.rs`; secret test across all five exports + API + GUI
  payload.

### Phase 2 — Standalone HTML report
- **Exists:** `report.rs` (human/json/jsonl/raw formats, `ReportModel`,
  bounded `top_n`, truncation flags, checkpoint-overwrite guard). No HTML.
- **Missing:** `report_html.rs` (or `report.rs` extension): single offline
  `.html` with summary, scope/coverage + time window, embedded Phase-1
  interactive graph (inline SVG + inlined data, no external assets),
  sortable/filterable findings table (vanilla JS, inlined), per-finding
  evidence chains, methodology/limitations; Executive vs Technical
  templates; secret masking in HTML.
- **Plan:** new module generating self-contained HTML (escape all values,
  reuse `safe_display`, mask via `exposure.rs` policy + a shared
  `mask_secrets` helper); wire `--format html --template executive|
  technical` through report options + `web_api` download; tests: offline
  (no `http` refs), masking, both templates render from fixture DB.

### Phase 3 — Diff timeline
- **Exists:** `diff.rs` (semantic checkpoint diff with
  `Added/Removed/Modified/Unchanged/InconclusiveMissing` + `ReasonCode`
  coverage taxonomy — `MissingWithoutComparableCoverage`,
  `CoverageReduced`, `ModuleDisabled`, `ScopeNarrowed`, etc.; already
  refuses to call gaps removals: `human_summary`/report text states
  "not rendered as removed", `report.rs:493-497`). `monitoring.rs`
  (`monitor_diff`) already yields `Unknown` (never fake removal) when the
  producing transform didn't complete. GUI has a *provenance* timeline
  (`#inv-timeline`, `#p-timeline`) but no run-to-run diff slider.
- **Missing:** run-to-run timeline slider in GUI mapping diff statuses to
  green/red/amber/gray; graph overlay coloring from diff records;
  explicit `not_covered` display state end-to-end + regression test
  (coverage gap ⇒ not-covered, never deletion).
- **Plan:** extend `web_api` project timeline payload with diff status per
  entity (or a `…/diff` endpoint consumed by the slider); GUI slider +
  legend with the four colors + text labels; integration test with two
  checkpoints of differing coverage asserting gray/not-covered. **Version
  bump to 1.2.0 only after Phases 1–3 gates pass** (Cargo.toml + lockstep
  `CHANGELOG.md` entry; tags untouched).

### Phase 4 — Terminal dashboard
- **Exists:** `terminal.rs` (3253 lines: styles, tables, key/value,
  workflow headers, TTY/`NO_COLOR`/color-mode logic) + `src/terminal/`
  (empty dir — dead placeholder, do not create `terminal/` files that
  collide; new code goes in a fresh module file). `exposure.rs`
  `render_human_caps` shows the caps-aware pattern to follow.
- **Missing:** live progress view (progress %, budget/deadline status,
  concurrency, streaming findings, cancel key), TTY detection with plain
  fallback, guarantee that piped output is byte-identical to today.
- **Plan:** new `src/terminal_dashboard.rs` (frame renderer over existing
  primitives; non-TTY path delegates to current renderers untouched);
  tests: golden non-TTY output unchanged, TTY frames bounded; no change to
  JSON/JSONL.

### Phase 5 — Interoperability (`interop.rs`, new)
- **Exists:** nothing for Nmap/SARIF/STIX/CSV; GraphML export arrives with
  Phase 1 (`graph_view.rs`). Bounded parsers exist as style precedent
  (`LocalDatasetProvider`: 1 MiB cap, entry cap — `exposure.rs:539-683`).
- **Missing:** everything: bounded Nmap XML import (no entity expansion —
  use a small hand-rolled pull parser or `quick-xml`; see dependency note),
  SARIF/STIX 2.1/CSV exporters, origin labeling + lowered default
  confidence for imports, hostile-input rejection tests, CLI wiring.
- **Plan:** new `src/interop.rs`; imports become graph/project entities
  with `origin=import:<format>` provenance + confidence penalty (e.g.
  `min(native, 60)` — exact rule documented); exports reuse masked
  serializers; fuzz-ish hostile fixtures (billion-laughs-shaped XML,
  100 MB CSV, bad UTF-8) assert bounded rejection.

### Phase 6 — Monitoring/alerts
- **Exists:** `monitoring.rs` (`monitor_diff`, coverage-aware
  Added/Removed/Changed/Unknown — no scheduling, no thresholds, no
  outputs). No `monitor` subcommand in `main.rs` (grep: none).
- **Missing:** scheduled re-scans of a project+scope on top of `diff.rs`,
  meaningful-change thresholds config, console/file/webhook outputs,
  scope-gate + budget enforcement on scheduled runs, secret-masked webhook
  payloads.
- **Plan:** extend `monitoring.rs` + new `src/monitor_run.rs` (scheduler
  glue, threshold evaluation, three sinks); webhook body built from the
  same masked serializer as exports; tests: scope refusal, threshold
  gating (no alert on noise), masking of webhook payload.

### Phase 7 — Explain mode
- **Exists:** `rxscan project explain <project> <entity>` (`main.rs:~2062`),
  `find_path`, `confidence.rs` explanations, exposure `explain_exposure`.
  No top-level `rxscan explain <finding|node>`.
- **Missing:** unified `rxscan explain` CLI sharing one code path with the
  GUI detail panel (observed → interpreted → confidence → what would move
  it), for both findings and graph nodes.
- **Plan:** new `src/explain.rs` used by both the CLI and a `web_api`
  `…/explain` hook feeding the existing inspector; tests cover parity
  (CLI text vs API JSON same chain).

### Phase 8 — Extension SDK
- **Exists:** `extensions.rs` (`validate_pack_dir`: typed JSON packs for
  fingerprints/OS/device/search providers, 4 MiB/file cap, schema checks).
  No transform/plugin interface, no scope-permission model.
- **Missing:** documented versioned interface for fingerprints +
  bounded public-source transforms; `requires_scope` declarations enforced
  at runtime (out-of-scope rejected); `examples/` working sample; `docs/`
  guide.
- **Plan:** extend `extensions.rs` + new `src/extension_sdk.rs` (trait +
  manifest + permission gate; no `dlopen`/WASM — JSON-pack + in-process
  trait model as today); example pack + transform in `examples/`;
  `docs/EXTENSIONS.md`; tests: permission rejection, malformed-pack
  determinism (existing tests stay).

---

## 5. Dependencies

**Proposed: none for Phases 0–4, 6–8.** SVG/HTML/CSV/SARIF/STIX/GraphML are
hand-rolled text; PNG is rasterized from the SVG scene with a ~200-line
software renderer inside `graph_view.rs` (or `tiny-skia`-free rect/circle/
line rasterizer — decision recorded here to avoid review surprise).
Benchmarks use existing dev-dependency patterns (`examples/phase*_bench.rs`
precedent; add `benches/graph_scale.rs` with the repo's harness style).

**Phase 5 XML only: `quick-xml` (MIT, streaming, `no_std`-capable,
no entity expansion by default).** Justification: Nmap XML needs a
spec-correct pull parser; hand-rolling XML invites entity-expansion and
encoding bugs that violate the hostile-input contract. Alternatives
rejected: `serde-xml-rs` (builds full DOM → unbounded allocation), `xml-rs`
(less maintained). If `quick-xml` review fails, fallback is a byte-level
`<tag attr="">` scanner limited to the Nmap schema subset, documented here
first. No other new crates are proposed.

---

## 6. Risks

1. **10k-node interactivity** — current GUI caps at 120 nodes / radial
   only. LOD + clustering + canvas-friendly SVG batching is the highest
   technical risk; benches (1k/10k/50k) land with Phase 1, not after.
2. **Display-vs-stored vocabulary drift** (EntityKind/EdgeRelation §1) —
   mitigated by keeping the stored model frozen and putting the 14-entity /
   9-link mapping in `graph_view.rs` with exhaustive match tests.
3. **Secret leakage surface growth** — every new serializer/API/GUI payload
   multiplies leak paths. Mitigation: one shared masking helper + one
   secret-canary test executed against *every* artifact (exports, API,
   report, webhook, logs), using `exposure.rs:413-433`-style fake secrets.
4. **Scope-gated expansion UX** — stored-data expansion needs no confirm;
   anything that could hit network must confirm + scope-check. The two
   paths must be visually distinct in GUI and CLI.
5. **Module-hygiene pressure** — `main.rs`/`web_api.rs`/`investigate.rs`/
   `search.rs` are already very large; all new logic lands in new modules
   with thin hooks, enforced at review (`git diff --stat` per commit).
6. **Packaging** — `Cargo.toml` `include` already covers `src/**`,
   `app/**`, `tests/**`, `fixtures/**`, `examples/**`, `docs/**`,
   `benches/**`; new files must live under those. Never emit
   `.rxscan-web/`/`*.sqlite`/logs.
7. **MSRV 1.85** — environment runs 1.99.0; compatibility gates must use
   the 1.85 toolchain. No edition-2024-only or new-stdlib APIs in new code.
8. **Frozen portfolio** (`index.html`, `js/`, `css/`, `_headers`,
   `certificates/`, `rxscan-web-dashboard.png`) — no tool, test, or script
   may read from or write to those paths.

---

## 7. Test strategy (maps to the prompt's required tests)

| Required test | Where it lands |
|---|---|
| Secret masking, all artifacts | `tests/graph_secrets.rs` (Phase 1) + reuse in report/interop/monitor |
| Migration (open baseline DB) | extend `tests/` with `tests/fixtures/golden_project_v1.rxproj` open-after-migration |
| Scope (expand + monitoring refuse OOS) | `graph_view` expansion gate test + monitor scope test |
| Coverage (not-covered ≠ removed) | diff timeline test, Phase 3 |
| Scale benches 1k/10k/50k | `benches/graph_scale.rs`, Phase 1 |
| Existing suite unchanged | no test weakened/removed/`#[ignore]`d, ever |

Baseline gate output for this audit is recorded in the commit message trailer
(`gates: …`) after the run below completes on the untouched tree.
