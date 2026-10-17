# RXScan 1.2.0 Icon + Mobile Audit

Audit of the untouched 1.2.0 baseline (HEAD `8aa290e71c272adc1145d711b5ebeb88b773d523`),
run before any feature code. This document is the plan for Phases 1-6. It
records what exists, what is missing, and the risks per phase.

## 1. Baseline verification (Step 0)

All checked on the untouched tree:

| Check | Expected | Actual | Status |
|---|---|---|---|
| `git rev-parse HEAD` | `8aa290e7…` | `8aa290e71c272adc1145d711b5ebeb88b773d523` | pass |
| `git status --short` | only `?? rxscan-icons/` | `?? rxscan-icons/` | pass |
| `rev-list --left-right --count origin/master…HEAD` | `0 0` | `0 0` | pass |
| `grep '^version' Cargo.toml` | `1.2.0` | `version = "1.2.0"` | pass |
| `git tag --list 'v*'` | no `v1.2.0` | `v0.1.0-rc.1 v1.0.0 v1.0.1 v1.0.2 v1.1.0` | pass |

Icon-pack integrity (`rxscan-icons/`):

| Check | Required | Actual | Status |
|---|---|---|---|
| `rxscan-icons/SHA256SUMS` exists | yes | yes | pass |
| `SHA256SUMS` digest | `45d8eb39…d78a91` | `45d8eb39f78fd18ac38abe65338a22820d4a7d280bedb629484223cdf2d78a91` | pass |
| `manifest.json` digest | `de0fd025…b6a4` | `de0fd025474961ead85283fe653efa88a8fea683e265227d61fc8c3dcb32b6a4` | pass |
| `sha256sum -c SHA256SUMS` | exit 0, 376 lines | exit 0, 376 lines, all OK | pass |
| manifest entity count | 74 | 74 | pass |
| categories | non-empty | infrastructure 29, threat 12, investigation 11, contact-and-asset 9, source-and-media 7, identity 6 | pass |
| every implied glyph exists | yes | all 74 glyphs present under `glyphs/` | pass |

Manifest structure: keyed by icon name; each entry has `glyph`, `ramp`, `shape`, `category`.
`manifest.json` is the single source of truth for icon names, categories, colors (ramps), and shapes.

## 2. Display-entity kinds in graph_view.rs and current marking

`src/graph_view.rs` defines the 1.2.0 graph view lens over the frozen stored model
(`graph.rs`: 33 `EntityKind`s, 42 `EdgeRelation`s).

### DisplayKind (14 variants incl. Cluster)

| Variant | as_str | color | shape | Current mark |
|---|---|---|---|---|
| Network | `network` | `#078cff` | hexagon | color + shape |
| Ip | `ip` | `#00efff` | circle | color + shape |
| Host | `host` | `#3ddc84` | square | color + shape |
| PortService | `port_service` | `#f0a04b` | diamond | color + shape |
| Software | `software` | `#b07cc4` | triangle | color + shape |
| Certificate | `certificate` | `#e5488f` | pentagon | color + shape |
| Domain | `domain` | `#19f4ff` | ellipse | color + shape |
| Url | `url` | `#8fa9c2` | rounded_rect | color + shape |
| Username | `username` | `#e2e8f0` | ring | color + shape |
| Account | `account` | `#f4f8ff` | double_square | color + shape |
| Exposure | `exposure` | `#f06666` | triangle_down | color + shape |
| Evidence | `evidence` | `#6b7d94` | parallelogram | color + shape |
| Scope | `scope` | `#4a9eff` | dashed_circle | color + shape |
| Cluster | `cluster` | `#2a4a6b` | octagon | color + shape |

Color is never the sole encoding: `shape` distinguishes every kind (documented in
`DisplayKind::color`). Every stored `EntityKind` maps exhaustively via
`display_kind_of` (no wildcard). `DisplayKind::all()` lists the 13 filterable kinds
(legend/CLI help share this); `Cluster` is view-only.

`display_kind_of` groupings (stored kind -> display kind):
- Network: NetworkPrefix, Asn, Route, Provider
- Ip: IpAddress
- Host: Host, Hostname
- PortService: Port, Service, NetworkEndpoint
- Software: Software, Technology, Package, Fingerprint, OsCandidate, DeviceCandidate
- Certificate: Certificate, SshHostKey, PublicKey
- Domain: Domain, DnsRecord
- Url: WebEndpoint, Document, ArchiveSnapshot, Repository
- Username: Username, EmailAddress
- Account: Account, Organization, IdentityHypothesis
- Exposure: Exposure, ExposureSource

No 74-type icon mapping exists yet; the 74 `EntityKind` variants are NOT in
`graph.rs` on the clean baseline (they appeared only in an earlier uncommitted
working state that has since been reset). Phase 2 must add mapping in a new
`src/graph_icons.rs`, not inline in `graph_view.rs`.

### DisplayRel (9 variants)
ResolvesTo, Hosts, Runs, ServesCert, SignedBy, SameFingerprint, FoundOn,
CorrelatedWith, DerivedFrom. `display_rel_of` maps 42 stored `EdgeRelation`s
exhaustively and derives observed-vs-inferred (dash) plus confidence thickness.

### View model
`ViewNode` { id, kind, stored_kind, label, link_confidence, scope, first_seen_ms,
last_seen_ms, observations, attributes, evidence, member_count }. `ViewEdge` {
from, to, relation, stored_relation, observed, confidence, thickness, module,
scan_run, evidence }. Everything masked at build time via `exposure::scrub_text` /
`mask_value_for_key`. `build_view` is deterministic, capped, bounded.

### Exports (all from masked ViewGraph)
- `to_json` — graph_schema_version, truncated, total_nodes/edges, nodes, edges
- `to_graphml` — directed GraphML with data keys (`xmlns` is a namespace id, never fetched)
- `to_svg` — standalone SVG, shape=kind, dash=inference, width=confidence, legend in `<desc>`
- `to_html` — standalone offline HTML, inlined CSS/JS/data, `iframe srcdoc`-safe, zero external refs
- `to_png` — dependency-free rasterizer + stored-deflate PNG encoder; shape=kind, no text (no offline font stack)

## 3. How app assets are embedded / served (assets.rs / build.rs)

**Important naming trap:** `src/assets.rs` is NOT about icon assets. It is entity-ID
hashing (`endpoint_id`, `service_id`, `hostname_id`, `certificate_id`, `ssh_key_id`,
`software_id`, `public_entity_id`) plus an `AssetRegistry` dedup. There is no icon
asset embedding anywhere in the Rust codebase today.

`build.rs` merges the split username provider corpus
(`search/providers/v1/username/<category>.json`) into one embedded bundle
(`OUT_DIR/username_pack.json`). Nothing about icons.

`src/web_api.rs` serves GUI static assets via `include_str!`/`include_bytes!`:
- `/app/rxscan.js` -> `include_str!("../app/rxscan.js")` (application/javascript)
- `/app/rxscan.css` -> `include_str!("../app/rxscan.css")` (text/css)
- `/app/assets/RXScanlogo.png` (+ alias paths) -> `include_bytes!("../app/assets/RXScanlogo.png")` (image/png)

These are compiled into the binary, so the GUI works from `file://`-served or
loopback-served HTML with zero network. The logo PNG is the only embedded image.

**Can standalone HTML/SVG/PNG exports reach asset files?**
- SVG (`to_svg`) and HTML (`to_html`/`REPORT_JS`/`HTML_TEMPLATE`) are fully
  self-contained: inlined shapes, CSS, JS, data. They do NOT reference external
  asset files and work from `file://`.
- PNG (`to_png`) is a software rasterizer drawing shapes directly to RGB bytes;
  no asset files, no fonts, no text.
- GraphML/JSON carry no images.
Conclusion: exports can reach asset files trivially because they embed nothing
external — but they also currently embed NO icons. Phase 4 must inline the
needed icon symbols into SVG/HTML and draw them in PNG so all formats agree.

## 4. How PNG export currently renders nodes

`to_png` (graph_view.rs:2204) uses `PngCanvas`, a tiny RGB framebuffer with a
stored-deflate PNG encoder (no compression library, no font stack). For each
node it calls `canvas.glyph(shape, x, y, r, color, border)` which draws a convex
polygon per `DisplayKind::shape()` (circle handled analytically). Color comes
from `DisplayKind::color()`; text is intentionally not rasterized (labels live in
SVG/HTML/JSON). Edges drawn under nodes with Bresenham lines, thickness from
confidence, dash for inferred. Capped at `MAX_VIEW_NODES` / 20_000 edges.

PNG export does not use icon tiles today. Phase 4 must draw the same icons so
PNG agrees with SVG/HTML; options: rasterize tile SVGs at build time into the
binary, or draw shape+color glyphs consistent with the tile. The audit recommends
shape/color glyphs in PNG (consistent with current approach, no new decoder),
while SVG/HTML embed inline `<symbol>`s from the tile SVGs.

## 5. Existing offline / no-external-reference tests icons must keep passing

- `tests/web_frontend.rs`: `no_local_paths_or_external_deps`, `gui_has_no_fake_or_demo_findings`,
  `console_styles_cover_states_and_viewports`, `javascript_syntax_check_when_node_exists`
  (runs `node --check` when node exists), `logo_asset_exists_and_gui_references_it`.
- `tests/graph_phase1.rs` `cli_exports_all_formats_masked`: asserts HTML export
  has `<script>` but no `<script src>`, no `<link`, `@import`, `src="http`,
  `href="http`, `url(http`, `url("http`; asserts zero fetched references; secret
  canaries on json/graphml/svg/html/png.
- `tests/report_html.rs`: `escaping_neutralizes_markup_after_masking`.
- `src/exposure.rs` `assert_no_secrets` used across export/API/report/alert/webhook tests.
- `src/graph_view.rs` tests: `every_stored_kind_maps_to_a_display_entity`,
  `secrets_are_masked_at_view_build`, `exports_are_masked_and_well_formed`,
  `expand_neighbors_is_bounded_and_sorted`.

Icons must not introduce `<script src>`, `<link href=http>`, `url(http`, etc.
SVG safety test (Phase 1) adds: no `<script>`, `<foreignObject>`, `<img>`,
event-handler attributes, external `href`/`url(...)`, per-file size cap.

## 6. What android/ actually is

`android/` is a Gradle Android app project (WebView host), NOT a bundled-assets
app:

- `android/build.gradle`: applies `com.android.application` 8.5.2 +
  `org.jetbrains.kotlin.android` 2.0.20 (no version pinned in this file).
- `android/settings.gradle`: `include(":app")`, repositories google/mavenCentral.
- `android/gradle.properties`: `android.useAndroidX=false`, nonTransitiveRClass.
- `android/app/src/main/AndroidManifest.xml`: single `MainActivity`,
  `android:configChanges="orientation|screenSize|screenLayout|keyboardHidden"`,
  `uses-permission INTERNET` only, `usesCleartextTraffic="false"`,
  `networkSecurityConfig` (@xml/network_security_config), `allowBackup="false"`.
- `MainActivity.kt`: starts the shared Rust core's loopback server via
  `RustBridge.startServer(dataDir)` against app-private `filesDir/rxscan-web`,
  then loads `http://127.0.0.1:$port/` in a WebView. JS enabled; file/content
  access off; no `addJavascriptInterface`; no remote debugging. All API traffic
  is the page's own same-origin fetch/EventSource to `/api/v1`.
- `RustBridge.kt`: `System.loadLibrary("rxscan")`; four typed JNI functions
  (`startServer`, `stopServer`, `version`, `capabilitiesJson`, `lastError`).
  Builds `librxscan.so` via `scripts/android-libs.sh` (referenced only in
  `.github/workflows/dist.yml`).

**How the UI gets to the app:** the WebView points at the in-process loopback
Rust server (`rxscan web` flow), which serves the same embedded `app/rxscan.js`,
`rxscan.css`, and HTML via `web_api.rs`. So mobile gets the identical desktop
frontend; there are no separate mobile assets.

**What can be built/verified here:** No Android NDK/SDK is installed in this
environment, and `scripts/android-libs.sh` was not found to run locally. The
`aarch64-linux-android` cross target appears only in CI `rust-cross` (build
check only, requires runner NAND). So the Android APK cannot be built or run
locally. Mobile verification here = `node --check` on `app/rxscan.js` + desktop
responsive reasoning + CI `dist.yml` android-emulator lane (hosted). Honest
framing: Android build/runtime = "not verified locally".

## 7. Current mobile behavior of app/ at 360px and 768px widths

`app/rxscan.css`:
- `:root` design tokens: near-black `#020711` bg, deep navy surfaces, electric
  cyan `#00efff` + bright blue emphasis; dark large surfaces, cyan/blue emphasis
  only; system font stacks only.
- Breakpoints: `@media (max-width: 1000px)`, `@media (max-width: 760px)`,
  `@media (max-width: 420px)`. At 760px: `.shell` collapses to 1fr (sidebar
  becomes a horizontal row), `.grid-form`/`cards`/`grid-2`/`graph-split` stack
  to 1fr, `.sources-grid` 2 columns, `.kv` wraps, `.graph-toolbar select` max-width.
- `@media (pointer: coarse)`: larger tap targets (sidebar 0.7rem padding, tabs
  0.6rem).
- `#graph-canvas` / `#inv-graph` / `#p-graph`: `touch-action: pan-y pinch-zoom`.
- `prefers-reduced-motion: reduce`: kills animations/transitions.
- No safe-area inset handling beyond `viewport-fit=cover` in `index.html`.
- No 360px-specific breakpoint; 420px is the narrowest. At 360px the sidebar
  row and stacked forms likely fit, but there is no explicit "no horizontal
  scroll at 360px" guarantee and no bottom-sheet detail panel, no stacked
  findings cards, no 200-node narrow viewport budget, no dedicated pinch/inertia
  tuning beyond the existing pan/zoom.

`app/rxscan.js` graph renderer (`makeGraph`): pointerdown/pointermove/pointerup
for one-finger pan, two-finger pinch zoom (`view.k` clamped 0.4..4), wheel zoom,
`setKindFilter`, `setStatusColors`, undo/redo, collapse/pin, collections.
Render caps: `GV_RENDER_NODES = 1500`, `GV_RENDER_EDGES = 3000`; auto-clusters
dense components past the budget. Nodes are SVG circles (`gnode-shape`) colored
by `GV_COLORS`, no icons, no theme tiles.

The `makeGraph` used by `/investigate` and `/projects` graph tabs caps at
120 nodes / 240 edges (`setData` slice) — these are separate small renderers.

Mobile gaps vs Phase 6 requirements:
- Responsive breakpoints exist but no 360px guarantee / no horizontal-scroll test.
- Pointer events + pinch zoom present; inertia modest (no explicit inertia
  decay), no double-tap-to-zoom, no explicit safe-area insets, orientation
  handled via `configChanges` on Android + CSS media queries.
- Touch targets: pointer:coarse enlarges sidebar/tabs but graph nodes are r=8
  SVG circles (~16px) — below 44px on mobile. Need 44px touch targets.
- Detail panel is an aside (desktop), not a bottom sheet on narrow viewports.
- Findings tables remain tables, not stacked cards.
- No narrow-viewport node budget / "show more" control (the graph renderer caps
  at 1500/3000, not 200).

## 8. Files created or modified in commits 9a42d78..HEAD (Phase 7 scope)

The baseline tree is clean (`git status` shows only untracked `rxscan-icons/`),
so the working tree equals HEAD. I have not enumerated `git log 9a42d78..HEAD`
file-by-file here; Phase 7 will run `git log --stat 9a42d78..HEAD` and scope
cleanup to exactly those files plus new files from this mission. No mass
reformatting of older modules.

## 9. What `git push origin <tag>` triggers in CI

`.github/workflows/ci.yml` (runs on `push` and `pull_request`):
- `rust-matrix` (ubuntu-latest, windows-latest, macos-26): cargo fmt --check,
  cargo check --locked, cargo check --all-targets --all-features --locked,
  cargo clippy --all-targets --all-features --locked -D warnings,
  cargo test --locked (full suite, no substring skips), cargo build --locked,
  Apple Intel target build check (macOS only, build evidence), `cargo run --version`,
  `capabilities --json`, `search lint`, `git diff --check`, `cargo package --list`.
- `rust-cross` (ubuntu): cross check for x86_64-unknown-linux-musl,
  aarch64-unknown-linux-gnu, aarch64-unknown-linux-musl (container),
  aarch64-linux-android (runner NAND). Build evidence only, no runtime.
- `frontend` (ubuntu): `node --check app/rxscan.js`.
Required on a pushed tag: frontend, ubuntu, macos, windows, all cross-builds,
overall SUCCESS. 7/8 is failure.

`.github/workflows/release.yml` (runs on push tags matching `v*.*.*`):
- `validate`: tag/version consistency (`v$VERSION == $TAG`), fmt, clippy, test,
  `git diff --check`, `search lint`.
- `build`: release build for 5 targets (linux x86_64/aarch64, windows x86_64
  MSVC, macos x86_64/aarch64), stage raw binaries, upload artifacts.
- `package`: reconstruct layout, `scripts/package-artifact.sh` for all 5 targets,
  `sha256sum` -> `dist/SHA256SUMS`, upload `rxscan-artifacts` (tar.gz/zip/SHA256SUMS).
No auto-publish to crates.io or stores; contents: read only. Tag push does NOT
create a GitHub Release or publish anywhere — it builds + stages artifacts only.
Irreversible: none (artifacts are uploads, not releases).

`.github/workflows/dist.yml` (manual `workflow_dispatch` only, NOT triggered by
tag push): build 5 targets, android APK (NDK on runner, emulator smoke at API 30
x86_64), package + checksums + `release-manifest.json` privacy self-check,
smoke linux/windows/macOS. `official=true` input yields bare version names;
default `-dev`.

## 10. Asset size budget

Current embedded GUI assets (in `rxscan` binary via web_api.rs):
- `app/rxscan.js`, `app/rxscan.css`, `app/assets/RXScanlogo.png` — embedded via
  `include_str!`/`include_bytes!`. Exact bytes not measured in this audit;
  `RXScanlogo.png` is the only embedded image.

Icon pack on disk (`rxscan-icons/`):
- 376 checksummed entries: `manifest.json`, `README.md`, `contact-sheet.png`,
  74 glyphs/*.svg, 2 placeholders/*.svg, png/light/* (74), png/dark/* (74),
  tiles/light/* (subset), tiles/dark/* (subset). Total on-disk size not measured
  here; Phase 1 should `du -sh app/assets/icons` after copy and record delta.

Projected delta (Phase 1 plan): copy `tiles/light`, `tiles/dark`, `glyphs`
(incl. `rxscan-sprite.svg`), `placeholders`, `manifest.json` into
`app/assets/icons/`; PNGs left OUT unless the audit shows PNG export needs them
(PNG currently rasterizes shapes, so PNGs are NOT required — leaving them out
protects binary size). SVG tiles are small; the sprite is the key file. Projected
delta: tens of KiB, well within the 10k/50k benchmark budget (icons are not part
of the graph build/render path).

## 11. Per-phase status: exists / missing / plan + risks

| Phase | Status | Plan | Risks |
|---|---|---|---|
| 0 Audit | exists (this doc) | commit alone | none |
| 1 Import icon pack | missing | copy tiles/light, tiles/dark, glyphs, rxscan-sprite.svg, placeholders, manifest.json to `app/assets/icons/`; no PNGs; add `docs/ICONS.md`; SVG safety test; manifest parity test | binary size if PNGs added; SVG safety regressions |
| 2 Entity->Icon mapping | missing | new `src/graph_icons.rs` static table kind/subtype -> manifest icon; exhaustiveness tests; UNMAPPED_BY_DESIGN list; no heuristic attribution icons; additive `icon`/`category` on JSON+GraphML | exhaustiveness "fails the build" must be a real compile/test failure; subtype data availability |
| 3 Desktop GUI | missing (icons) | replace node markers with icon tiles (sprite `<use>`/cached bitmaps), theme-aware, legend+filters by category, a11y, lightweight markers when clustered/zoomed/narrow; rerun benchmarks | 10% benchmark regression; DOM caps; sprite `<use>` cross-browser |
| 4 Exports & reports | missing (icons) | inline symbols in SVG/HTML; PNG draws icons; rerun zero-fetched-ref + secret-canary assertions; per-format icon-presence test | PNG icon rasterization approach; keeping all formats in agreement |
| 5 Investigation workflow | partial | evidence-bundle CLI (A) needs new code; multi-hop expansion preview/breadcrumb/collapse (B) partly exists (`expand_neighbors`, undo/redo, collections) but needs preview count + depth 1-3 + back; attribution labels (C) — no stored attribution model exists, leave icons unused, document | inventing an attribution model (forbidden); bundle hashing crate choice |
| 6 Mobile | partial | responsive breakpoints exist but need 360px guarantee, 44px touch targets, bottom sheet, stacked cards, 200-node budget + show more, double-tap zoom, safe-area; verify via node --check + headless-browser screenshots if available; Android not buildable locally | claiming Android works (forbidden); headless browser availability |
| 7 Cleanup | not started | scope = commits 9a42d78..HEAD + new mission files; restate-code comment removal; match older-module style; error-message trim; docs filler trim | zero behavior change must hold; don't touch older modules |
| 8 Release prep | not started | CHANGELOG entry; install check from temp dir; read workflows (done above); annotated local tag `v1.2.0`, do NOT push; print push command | `v1.2.0` must not already exist locally or on origin |

## 12. Hashing crate availability for evidence bundle (Phase 5-A)

`sha2` is already in the dependency tree (used by `exposure::identifier_hash` via
`sha2::Sha256::digest`). No new crate needed for SHA-256 bundle manifest. Justify
in Phase 5 commit: reuse existing `sha2` dependency.

## 13. Frozen files (contract #11)

Root `index.html`, `js/`, `css/`, `_headers`, `certificates/`, dashboard PNG are
frozen — Phase 1 must copy icons into `app/assets/icons/` (a new subdirectory,
not modifying frozen files) and must not alter `app/index.html`,
`app/rxscan.js`, `app/rxscan.css`.
