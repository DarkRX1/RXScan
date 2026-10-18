# Mobile verification screenshots

Screenshots in this directory are captured from a **synthetic** fixture
project. No real target, host, or secret is involved.

## What is captured

`scripts/mobile-screenshots.mjs` drives headless Chromium over the DevTools
protocol (no npm dependencies) and writes, per viewport:

| Viewport | Files |
| --- | --- |
| 360x800, 390x844, 430x932, 768x1024 | `screenshot_<vp>_dashboard.png` |
| 360x800, 390x844, 430x932, 768x1024 | `screenshot_<vp>_graph.png` (graph with nodes drawn) |
| 360x800, 390x844, 430x932 | `screenshot_<vp>_sheet.png` (detail bottom sheet open) |
| 390x844, 600x900, 768x1024 | `screenshot_<vp>_findings_jobs.png` (stacked-card findings table) |

It also writes `mobile-overflow-report.json`, recording the horizontal-overflow
check (`document.documentElement.scrollWidth <= window.innerWidth`) for each
view. All recorded values are `true`.

At 768x1024 there is no bottom sheet: the sheet is a phone affordance and the
detail panel is the inspector at that width, so no `_sheet.png` is written
there. That is expected, not a gap.

## Reproducing

```sh
cargo run --locked --example mobseed -- /tmp/rxscan-mobseed
cargo build --locked --bin rxscan
./target/debug/rxscan web --port 8918 --data-dir /tmp/rxscan-mobseed --no-open &
node scripts/mobile-screenshots.mjs http://127.0.0.1:8918 docs
```

The graph view requires an explicit **Load graph** click before nodes are
drawn, and the findings table needs at least one completed job; the script
performs both.

## Data provenance

`examples/mobseed.rs` builds the fixture from reserved ranges only
(`192.0.2.0/24`, `example.test`) plus fake secret markers that the exporter
masks. To populate the findings tables, the capture run also performs a scan
of **loopback only** (`127.0.0.1` against the local web server's own port).

## Not verified locally

Android rendering is **not verified locally**: no Android device or emulator
build was run for these screenshots. Only the Chromium-based viewports above
are evidenced.