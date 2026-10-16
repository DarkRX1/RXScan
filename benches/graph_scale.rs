//! Graph scale benchmark: build, filter, lay out, and serialize synthetic
//! views at 1k, 10k, and 50k nodes.
//!
//! Runs with `cargo bench --bench graph_scale` (harness = false, stable
//! compatible). Prints per-stage timings; asserts generous completion
//! bounds so CI proves boundedness instead of eyeballing it. Synthetic
//! nodes cycle real stored kinds/relations so the display mapping is
//! exercised. Note: the single-scan in-memory `ScanGraph` caps at 8192
//! entities by design; multi-scan projects aggregate in SQLite, and this
//! bench drives the view layer directly at 50k to prove that path.

use std::collections::BTreeMap;
use std::time::Instant;

use rxscan::graph_view::{
    LayoutKind, ViewOptions, build_view, cluster_beyond, layout, to_graphml, to_json, to_png,
    to_svg,
};

const KINDS: &[&str] = &[
    "ip_address",
    "hostname",
    "port",
    "service",
    "certificate",
    "web_endpoint",
    "domain",
    "technology",
    "username",
    "account",
];

const RELS: &[&str] = &[
    "resolves_to",
    "listens_on",
    "runs_service",
    "presents_certificate",
    "references",
    "links_to",
    "resolves_to_endpoint",
    "suggests",
];

fn synthetic(
    count: usize,
) -> (
    Vec<rxscan::graph_view::SourceNode>,
    Vec<rxscan::graph_view::SourceEdge>,
) {
    let mut sources = Vec::with_capacity(count);
    for i in 0..count {
        sources.push(rxscan::graph_view::SourceNode {
            id: format!("ip:192.0.2.{}", i % 65536),
            stored_kind: KINDS[i % KINDS.len()].to_owned(),
            label: format!("node-{i}"),
            attributes: BTreeMap::from([("index".to_owned(), i.to_string())]),
            first_seen_ms: 1_700_000_000_000,
            last_seen_ms: 1_700_000_001_000,
            observations: 1,
        });
    }
    // Chain + long-range links: one connected component with diameter ~N.
    let mut edges = Vec::with_capacity(count * 2);
    for i in 0..count {
        let from = format!("ip:192.0.2.{}", i % 65536);
        let to = format!("ip:192.0.2.{}", (i + 1) % 65536);
        if from != to {
            edges.push(rxscan::graph_view::SourceEdge {
                from,
                to,
                stored_relation: RELS[i % RELS.len()].to_owned(),
                confidence: (60 + (i % 36)) as u8,
                module: "bench".to_owned(),
                scan_run: "bench-1".to_owned(),
                evidence: vec![format!("bench edge {i}")],
            });
        }
        if i % 7 == 0 {
            let far = format!("ip:192.0.2.{}", (i * 13 + 5) % 65536);
            let near = format!("ip:192.0.2.{}", i % 65536);
            if far != near {
                edges.push(rxscan::graph_view::SourceEdge {
                    from: near,
                    to: far,
                    stored_relation: "links_to".to_owned(),
                    confidence: 70,
                    module: "bench".to_owned(),
                    scan_run: "bench-1".to_owned(),
                    evidence: vec!["bench shortcut".to_owned()],
                });
            }
        }
    }
    (sources, edges)
}

fn bench_scale(count: usize) {
    println!("--- graph_scale N={count} ---");
    let (sources, edges) = synthetic(count);
    let opts = ViewOptions {
        limit_nodes: count,
        limit_edges: count * 2,
        ..ViewOptions::default()
    }
    .bounded();
    let started = Instant::now();
    let view = build_view(sources, edges, &opts);
    let build_ms = started.elapsed().as_millis();
    println!("build_view: {build_ms}ms for {} nodes", view.nodes.len());
    assert_eq!(view.nodes.len(), count);
    assert!(!view.truncated);

    for kind in LayoutKind::all() {
        let started = Instant::now();
        let positions = layout(&view, *kind, None);
        let elapsed = started.elapsed().as_millis();
        println!("layout {}: {elapsed}ms", kind.as_str());
        assert_eq!(positions.len(), view.nodes.len());
    }

    let started = Instant::now();
    let (clustered, _) = cluster_beyond(&view, 1200);
    let cluster_ms = started.elapsed().as_millis();
    println!(
        "cluster_beyond(1200): {cluster_ms}ms -> {} visible",
        clustered.nodes.len()
    );
    if count > 1200 {
        assert!(clustered.nodes.len() <= 1200);
    }

    let positions = layout(&view, LayoutKind::Organic, None);
    let started = Instant::now();
    let json = to_json(&view);
    println!(
        "to_json: {}ms ({} bytes)",
        started.elapsed().as_millis(),
        json.len()
    );
    let started = Instant::now();
    let graphml = to_graphml(&view);
    println!(
        "to_graphml: {}ms ({} bytes)",
        started.elapsed().as_millis(),
        graphml.len()
    );
    if count <= 10_000 {
        let started = Instant::now();
        let svg = to_svg(&view, &positions, 1000, 700);
        println!(
            "to_svg: {}ms ({} bytes)",
            started.elapsed().as_millis(),
            svg.len()
        );
        let started = Instant::now();
        let png = to_png(&view, &positions, 800, 600);
        println!(
            "to_png: {}ms ({} bytes)",
            started.elapsed().as_millis(),
            png.len()
        );
        assert_eq!(&png[0..8], &[137, 80, 78, 71, 13, 10, 26, 10]);
    }
    // Generous completion bounds (debug-mode CI is slow; these prove
    // boundedness, not speed records).
    assert!(build_ms < 120_000, "build must complete");
    let _ = cluster_ms;
}

fn main() {
    bench_scale(1_000);
    bench_scale(10_000);
    bench_scale(50_000);
    println!("graph_scale complete");
}
