//! Phase 5 interoperability: Nmap import, SARIF/STIX/CSV exports.
//!
//! Synthetic/reserved values only. Hostile inputs must fail closed.

use std::process::Command;

const NMAP: &str = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
<host><status state="up"/>
<address addr="192.0.2.10" addrtype="ipv4"/>
<hostnames><hostname name="example.test" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.24.0"/></port>
<port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
</ports>
</host>
</nmaprun>"#;

const EVIL: &str =
    r#"<!DOCTYPE x [<!ENTITY a "b">]><nmaprun><host><address addr="192.0.2.10"/></host></nmaprun>"#;

fn bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_rxscan"))
}

fn tmp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("rxscan-interop5-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(bin());
    cmd.arg("graph");
    for arg in args {
        cmd.arg(arg);
    }
    cmd.output().expect("rxscan graph runs")
}

#[test]
fn import_exports_end_to_end_masked() {
    let dir = tmp("e2e");
    let xml = dir.join("scan.xml");
    // Plant a secret-shaped URL? Nmap has no free URLs; plant via a
    // service version carrying an assignment-shaped secret instead.
    let xml_text = NMAP.replace("1.24.0", "1.24.0 token=FAKE-INTEROP-5");
    std::fs::write(&xml, &xml_text).unwrap();
    for format in ["json", "graphml", "sarif", "stix", "csv", "svg", "html"] {
        let out_path = dir.join(format!("g.{format}"));
        let out = run(&[
            "--import-nmap",
            xml.to_str().unwrap(),
            "--format",
            format,
            "--out",
            out_path.to_str().unwrap(),
        ]);
        assert!(
            out.status.success(),
            "{format}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let bytes = std::fs::read(&out_path).unwrap();
        assert!(!bytes.is_empty(), "{format} must not be empty");
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("FAKE-INTEROP-5"), "{format} leaked a secret");
    }
    // Origin labeling + capped confidence in the JSON view.
    let json = std::fs::read_to_string(dir.join("g.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let nodes = value["nodes"].as_array().unwrap();
    assert!(nodes.len() >= 3, "import must yield host+port+service");
    for node in nodes {
        let attrs = node["attributes"].as_object().unwrap();
        assert_eq!(
            attrs["origin"], "import:nmap",
            "origin label missing: {node}"
        );
    }
    for edge in value["edges"].as_array().unwrap() {
        assert!(
            edge["confidence"].as_u64().unwrap() <= 60,
            "import must stay capped: {edge}"
        );
        assert!(!edge["evidence"].as_array().unwrap().is_empty());
    }
    // SARIF shape: version + runs + tool; STIX shape: bundle + identity.
    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("g.sarif")).unwrap()).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "RXScan");
    assert!(!sarif.to_string().contains("http://") && !sarif.to_string().contains("https://"));
    let stix: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("g.stix")).unwrap()).unwrap();
    assert_eq!(stix["type"], "bundle");
    assert_eq!(stix["spec_version"], "2.1");
    // Every relationship endpoint resolves to a bundled object.
    let ids: std::collections::BTreeSet<&str> = stix["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["id"].as_str().unwrap())
        .collect();
    for object in stix["objects"].as_array().unwrap() {
        if object["type"] == "relationship" {
            assert!(
                ids.contains(object["source_ref"].as_str().unwrap()),
                "dangling source_ref"
            );
            assert!(
                ids.contains(object["target_ref"].as_str().unwrap()),
                "dangling target_ref"
            );
        }
        if object["type"] == "network-traffic" {
            assert!(
                ids.contains(object["dst_ref"].as_str().unwrap()),
                "dangling dst_ref"
            );
        }
    }
    // CSV has both sections.
    let csv = std::fs::read_to_string(dir.join("g.csv")).unwrap();
    assert!(csv.contains("record_type,id,kind,label"));
    assert!(csv.contains("record_type,from,to,relation"));
    // GraphML shape sanity.
    let graphml = std::fs::read(dir.join("g.graphml")).unwrap();
    assert!(graphml.starts_with(b"<?xml"));
    // (The cap policy itself is pinned by a const assertion in the
    // interop unit tests; the per-edge checks above prove it applies.)
}

#[test]
fn hostile_and_broken_imports_fail_closed() {
    let dir = tmp("hostile");
    let evil = dir.join("evil.xml");
    std::fs::write(&evil, EVIL).unwrap();
    let out = run(&["--import-nmap", evil.to_str().unwrap(), "--format", "json"]);
    assert!(!out.status.success(), "DTD input must be rejected");
    assert_eq!(out.status.code(), Some(1));
    let broken = dir.join("broken.xml");
    std::fs::write(&broken, "<nmaprun><host>").unwrap();
    let out = run(&[
        "--import-nmap",
        broken.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(!out.status.success());
    let missing = dir.join("missing.xml");
    let out = run(&[
        "--import-nmap",
        missing.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(!out.status.success());
    // Oversize file refused before parsing.
    let big = dir.join("big.xml");
    let mut file = std::fs::File::create(&big).unwrap();
    use std::io::Write as _;
    file.write_all(b"<nmaprun>").unwrap();
    let chunk = vec![b' '; 1024 * 1024];
    for _ in 0..5 {
        file.write_all(&chunk).unwrap();
    }
    file.write_all(b"</nmaprun>").unwrap();
    drop(file);
    let out = run(&["--import-nmap", big.to_str().unwrap(), "--format", "json"]);
    assert!(!out.status.success(), "oversize import must be refused");
}

#[test]
fn interop_graphml_matches_view_export() {
    // One code path for GraphML: interop delegates to the view exporter.
    let view = rxscan::graph_view::ViewGraph::default();
    assert_eq!(
        rxscan::interop::render_export(&view, rxscan::interop::InteropFormat::Graphml),
        rxscan::graph_view::to_graphml(&view).into_bytes()
    );
    assert!(rxscan::interop::InteropFormat::parse("sarif").is_some());
    assert!(rxscan::interop::InteropFormat::parse("nope").is_none());
}
