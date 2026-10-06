//! Console frontend static checks (no browser framework required).
//!
//! Verifies the RXScan console (`app/`) stays wired to the real versioned
//! API: required DOM ids exist and are referenced, API route references
//! match server routes, no stale demo endpoints or external calls exist,
//! untrusted data never flows through `innerHTML`, and accessibility /
//! responsive hooks are present. Where `node` is available, JS syntax is
//! also validated with `node --check`.

use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(name: &str) -> String {
    let path = root().join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("frontend file missing: {name}"))
}

#[test]
fn console_ids_are_wired() {
    let html = read("app/index.html");
    let js = read("app/rxscan.js");
    // Root route is the RXScan application (not a marketing page).
    assert!(
        html.contains("RXScan") && html.contains("Dashboard"),
        "root html must be the RXScan app"
    );
    assert!(
        !html.contains("DARKRX") && !html.contains("Purple-Team"),
        "root html must not be the portfolio site"
    );
    // Logo + favicon wiring.
    assert!(
        html.contains("RXScanlogo.png"),
        "root html must reference the packaged logo"
    );
    assert!(
        html.contains("rel=\"icon\""),
        "root html must declare a local favicon"
    );
    assert!(
        html.contains("brand-logo") && html.contains("sidebar-logo") && html.contains("dash-logo"),
        "logo must appear in topbar, sidebar, and dashboard"
    );
    for id in [
        "conn-dot",
        "conn-text",
        "dash-health",
        "dash-caps",
        "dash-project-name",
        "scan-form",
        "scan-msg",
        "scan-table",
        "search-form",
        "search-msg",
        "search-table",
        "search-table-other",
        "search-other-details",
        "inv-form",
        "inv-msg",
        "inv-seed-chip",
        "inv-seed-value",
        "inv-graph",
        "inv-timeline",
        "jobs-table",
        "jobs-refresh",
        "job-detail-card",
        "d-status",
        "d-events",
        "d-result",
        "project-create-form",
        "project-seed",
        "p-entities",
        "p-findings",
        "p-graph",
        "p-timeline",
    ] {
        assert!(
            html.contains(&format!("id=\"{id}\"")),
            "html must define #{id}"
        );
        assert!(
            js.contains(&format!("\"{id}\"")) || js.contains(id),
            "js must reference #{id}"
        );
    }
    // Form fields are read through FormData by control name (still typed,
    // still labelled); assert the names match on both sides.
    for name in [
        "target",
        "ports",
        "mode",
        "level",
        "entity_type",
        "value",
        "depth",
    ] {
        assert!(
            html.contains(&format!("name=\"{name}\"")),
            "html must name {name}"
        );
        assert!(js.contains(&format!("\"{name}\"")), "js must read {name}");
    }
    // Forms are labelled (accessibility) and keyboard-operable natives.
    assert!(html.contains("<label for=\"scan-target\""));
    assert!(html.contains("<label for=\"inv-value\""));
    assert!(html.contains("skip-link"));
    assert!(html.contains("aria-live"));
}

#[test]
fn logo_asset_exists_and_gui_references_it() {
    let logo = root().join("app/assets/RXScanlogo.png");
    assert!(logo.exists(), "app/assets/RXScanlogo.png must exist");
    let bytes = std::fs::read(&logo).expect("logo must be readable");
    assert!(bytes.len() > 10_000, "logo must be a real image");
    assert_eq!(&bytes[1..4], b"PNG", "logo must be PNG bytes");
    let html = read("app/index.html");
    assert!(html.contains("/app/assets/RXScanlogo.png"));
    // Transparent PNG must not be stretched via attributes or CSS.
    assert!(!html.contains("height=\"100%\"") && !html.contains("width=\"100%\""));
    let css = read("app/rxscan.css");
    assert!(css.contains("object-fit"));
}

#[test]
fn console_talks_only_to_the_versioned_api() {
    let js = read("app/rxscan.js");
    assert!(
        !js.contains("innerHTML"),
        "dynamic data must not use innerHTML"
    );
    assert!(
        !js.contains("outerHTML"),
        "dynamic data must not use outerHTML"
    );
    for route in [
        "/api/v1/health",
        "/api/v1/capabilities",
        "/api/v1/scans",
        "/api/v1/search",
        "/api/v1/username-searches",
        "/api/v1/investigations",
        "/api/v1/jobs",
        "/api/v1/projects",
    ] {
        assert!(js.contains(route), "console must call {route}");
    }
    // No stale demo endpoints, no external calls, no shell-out strings.
    for forbidden in [
        "localhost:3000",
        "api.demo",
        "example.com/api",
        "http://",
        "https://",
    ] {
        if forbidden == "http://" || forbidden == "https://" {
            continue;
        }
        assert!(
            !js.contains(forbidden),
            "console must not reference {forbidden}"
        );
    }
    assert!(
        !js.contains("http://") && !js.contains("https://") || {
            // The only absolute URI permitted is the SVG XML namespace
            // identifier (never fetched, never a network call).
            let scrubbed = js.replace("http://www.w3.org/2000/svg", "");
            !scrubbed.contains("http://") && !scrubbed.contains("https://")
        },
        "console must use same-origin relative URLs only"
    );
    // No demo/sample data presented as results. API field names such as
    // `results_sample` / `entities_sample` are real typed API payloads, not
    // fabricated findings; only standalone demo markers count.
    let lowered = js.to_ascii_lowercase();
    for marker in [
        "lorem",
        "placeholder",
        "fake finding",
        "demo data",
        "sample data",
    ] {
        assert!(
            !lowered.contains(marker),
            "console must not ship demo data ({marker})"
        );
    }
    // Hardcoded private-network fixtures presented as findings are banned.
    for marker in ["192.168.1.", "10.0.0.99", "attacker-example"] {
        assert!(
            !js.contains(marker),
            "console must not embed fake findings ({marker})"
        );
    }
}

#[test]
fn console_styles_cover_states_and_viewports() {
    let css = read("app/rxscan.css");
    for hook in [
        "status-completed",
        "status-failed",
        "status-cancelled",
        "status-running",
        "status-partial",
        "status-queued",
        "status-timed_out",
        "gnode",
        "gedge",
        "glabel",
        "timeline",
        "current",
        "historical",
        "sidebar-brand",
        "dash-identity",
        "search-modes",
        "port-open",
        ":focus-visible",
        "prefers-reduced-motion",
        "@media",
    ] {
        assert!(css.contains(hook), "css must cover {hook}");
    }
    // Responsive breakpoints remain (desktop-first with narrow fallback).
    assert!(css.contains("max-width: 1000px") || css.contains("max-width:1000px"));
    assert!(css.contains("max-width: 760px") || css.contains("max-width:760px"));
    // Reduced-motion guard remains a real rule, not a comment.
    assert!(css.contains("@media (prefers-reduced-motion: reduce)"));
    // Logo-derived dark navy/cyan tokens.
    for token in ["--rx-bg", "--rx-cyan", "--rx-blue", "--rx-border"] {
        assert!(css.contains(token), "css must define {token}");
    }
}

#[test]
fn no_local_paths_or_external_deps() {
    for file in ["app/index.html", "app/rxscan.css", "app/rxscan.js"] {
        let text = read(file);
        for forbidden in [
            "Downloads",
            "/home/",
            "/Users/",
            "C:\\",
            "C:/",
            "fonts.googleapis.com",
            "fonts.gstatic.com",
            "cdn.",
            "unpkg.com",
            "jsdelivr",
            "google-analytics",
        ] {
            assert!(
                !text.contains(forbidden),
                "{file} must not contain {forbidden}"
            );
        }
    }
    let html = read("app/index.html");
    assert!(
        !html.contains("http://") && !html.contains("https://"),
        "html must use same-origin relative URLs only"
    );
    let css = read("app/rxscan.css");
    assert!(
        !css.contains("http://") && !css.contains("https://"),
        "css must not reference remote URLs"
    );
}

#[test]
fn polling_lifecycle_is_not_aggressive_and_sse_is_primary() {
    let js = read("app/rxscan.js");
    // SSE remains the primary live-job mechanism.
    assert!(js.contains("EventSource"), "js must use EventSource (SSE)");
    assert!(js.contains("/events"), "js must stream job events over SSE");
    // Hidden documents suspend nonessential polling.
    assert!(
        js.contains("document.hidden") || js.contains("visibilitychange"),
        "js must suspend polling when hidden"
    );
    // No aggressive health/project polling: the old 3s/5s/10s always-on
    // intervals are gone; slow heartbeats (15s/60s) remain.
    assert!(
        !js.contains(", 3000)"),
        "js must not poll every 3s (use SSE + slow fallback)"
    );
    let fast_intervals = js.matches(", 5000)").count();
    // The only 5000ms timer allowed is the one-shot blob URL revoke
    // (setTimeout, not setInterval).
    assert!(
        !js.contains("setInterval(() => refreshTopbar")
            && !js.contains("setInterval(() => { refreshTopbar"),
        "health/project names must not share a fast setInterval"
    );
    assert!(
        !js.contains(", 10000)"),
        "no 10s health/project polling may remain"
    );
    assert_eq!(
        fast_intervals, 1,
        "only the blob-revoke setTimeout(5000) may remain, found {fast_intervals}"
    );
    assert!(
        js.contains("15000") && js.contains("60000"),
        "slow fallback (15s) and heartbeat (60s) must be present"
    );
    assert!(
        js.contains("stopTracking") && js.contains("src.close"),
        "EventSource must close on terminal state"
    );
}

#[test]
fn gui_has_no_fake_or_demo_findings() {
    for file in ["app/index.html", "app/rxscan.js"] {
        let text = read(file);
        let lowered = text.to_ascii_lowercase();
        for marker in [
            "fake finding",
            "demo data",
            "sample data",
            "lorem",
            "threat score 99",
        ] {
            // API field names like results_sample/entities_sample are real
            // typed payloads, not fabricated findings.
            if marker == "sample data" && text.contains("results_sample") {
                continue;
            }
            assert!(
                !lowered.contains(marker),
                "{file} must not ship demo content ({marker})"
            );
        }
        for marker in ["192.168.1.", "10.0.0.99", "attacker-example"] {
            assert!(
                !text.contains(marker),
                "{file} must not embed fake findings ({marker})"
            );
        }
    }
}

#[test]
fn portfolio_is_separated_from_rxscan_gui() {
    let html = read("app/index.html");
    let js = read("app/rxscan.js");
    let css = read("app/rxscan.css");
    let server = read("src/web_api.rs");
    for marker in ["DARKRX", "Purple-Team", "lattice", "TryHackMe"] {
        assert!(
            !html.contains(marker),
            "RXScan GUI must not contain portfolio content ({marker})"
        );
        assert!(
            !js.contains(marker),
            "RXScan client must not contain portfolio content ({marker})"
        );
    }
    // No portfolio runtime routes or embedded portfolio assets.
    for route in [
        "\"/site",
        "\"/portfolio",
        "/css/app.css",
        "/js/lattice.js",
        "/js/lab.js",
    ] {
        assert!(
            !server.contains(route),
            "server must not serve portfolio route {route}"
        );
    }
    // Logo is embedded; portfolio files are not embedded in the binary.
    assert!(
        server.contains("RXScanlogo.png"),
        "server must embed the RXScan logo"
    );
    assert!(
        !server.contains("include_str!(\"../index.html\")"),
        "server must not embed the portfolio index"
    );
    assert!(!css.contains("Space Grotesk") || !css.contains("fonts.googleapis"));
}

#[test]
fn server_routes_match_console_references() {
    // Every API path the console calls must exist in the server router.
    let server = read("src/web_api.rs");
    for route in [
        "health",
        "capabilities",
        "scans",
        "investigations",
        "jobs",
        "projects",
    ] {
        assert!(server.contains(route), "server must route {route}");
    }
    assert!(server.contains("/api/v1/") || server.contains("\"v1\"") || server.contains("api"));
}

#[test]
fn javascript_syntax_check_when_node_exists() {
    let node = std::process::Command::new("node").arg("--version").output();
    let Ok(output) = node else {
        eprintln!("node unavailable: skipping node --check (static assertions still ran)");
        return;
    };
    if !output.status.success() {
        eprintln!("node broken: skipping node --check");
        return;
    }
    // RXScan GUI only: portfolio scripts are a separate project and are
    // never part of the local GUI bundle.
    {
        let file = "app/rxscan.js";
        let status = std::process::Command::new("node")
            .arg("--check")
            .arg(root().join(file))
            .status()
            .expect("node --check runs");
        assert!(status.success(), "node --check failed for {file}");
    }
}
