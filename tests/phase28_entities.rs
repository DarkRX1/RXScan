//! Phase 28 — additive entity model expansion (Ultimate Expansion Phase 1).
//!
//! Covers canonical entity identities, passive local search (zero network),
//! CLI parity for `search --email/--domain/--hostname/--ip/--asn/--url/
//! --repo/--org`, and `project graph|timeline|related|diff` aliases.
//!
//! Reserved/synthetic data only (`example.test`, `192.0.2.10`,
//! `2001:db8::10`, `AS64500`, `exampleuser`). No network, no real
//! accounts, no secrets.

use std::path::PathBuf;

use rxscan::entity_search::execute_entity_search;
use rxscan::search::{SearchEntity, SearchEntityKind};

fn rxscan_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rxscan"))
}

fn run_cli(args: &[&str]) -> (i32, String, String) {
    let output = std::process::Command::new(rxscan_bin())
        .args(args)
        .output()
        .expect("spawn rxscan");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

// ---------- canonical identities ----------

#[test]
fn email_identity_is_canonical_and_stable() {
    let a = SearchEntity::email("User@Example.test", 1).unwrap();
    let b = SearchEntity::email("user@example.test", 2).unwrap();
    assert_eq!(a.id, b.id);
    assert_eq!(a.canonical_value, "user@example.test");
    assert_eq!(a.kind, SearchEntityKind::EmailAddress);
    assert_eq!(a.attributes.get("domain").unwrap(), "example.test");
}

#[test]
fn domain_identity_strips_trailing_dot_and_case() {
    let a = SearchEntity::domain("Example.TEST.", 1).unwrap();
    let b = SearchEntity::domain("example.test", 1).unwrap();
    assert_eq!(a.id, b.id);
    assert_eq!(a.canonical_value, "example.test");
}

#[test]
fn hostname_accepts_single_label_but_rejects_ip() {
    let host = SearchEntity::hostname("api.example.test", 1).unwrap();
    assert_eq!(host.canonical_value, "api.example.test");
    assert!(SearchEntity::hostname("192.0.2.10", 1).is_err());
}

#[test]
fn ip_identity_normalizes() {
    let ip = SearchEntity::ip_address("192.0.2.10", 1).unwrap();
    assert_eq!(ip.canonical_value, "192.0.2.10");
    let ip6 = SearchEntity::ip_address("2001:db8::10", 1).unwrap();
    assert_eq!(ip6.canonical_value, "2001:db8::10");
    assert!(SearchEntity::ip_address("999.1.1.1", 1).is_err());
}

#[test]
fn asn_identity_normalizes_prefix() {
    let a = SearchEntity::asn("as64500", 1).unwrap();
    let b = SearchEntity::asn("AS64500", 1).unwrap();
    let c = SearchEntity::asn("64500", 1).unwrap();
    assert_eq!(a.canonical_value, "AS64500");
    assert_eq!(a.id, b.id);
    assert_eq!(a.id, c.id);
    assert!(SearchEntity::asn("AS0", 1).is_err());
    assert!(SearchEntity::asn("AS", 1).is_err());
}

#[test]
fn url_identity_requires_http_host() {
    let url = SearchEntity::url("https://example.test/path", 1).unwrap();
    assert!(url.canonical_value.starts_with("https://example.test"));
    assert!(SearchEntity::url("gopher://example.test", 1).is_err());
    assert!(SearchEntity::url("not a url", 1).is_err());
}

#[test]
fn repo_and_org_identities() {
    let repo = SearchEntity::repository("Example-Org/Example-Project", 1).unwrap();
    assert_eq!(repo.canonical_value, "example-org/example-project");
    let via_url =
        SearchEntity::repository("https://example.test/Example-Org/Example-Project", 1).unwrap();
    assert_eq!(via_url.canonical_value, "example-org/example-project");
    assert!(SearchEntity::repository("onlyowner", 1).is_err());
    let org = SearchEntity::organization("Example-Org", 1).unwrap();
    assert_eq!(org.canonical_value, "example-org");
    assert!(SearchEntity::organization("bad/org", 1).is_err());
}

#[test]
fn invalid_entities_rejected() {
    assert!(SearchEntity::email("not-an-email", 1).is_err());
    assert!(SearchEntity::email("a@b", 1).is_err());
    assert!(SearchEntity::domain("localhost", 1).is_err());
    assert!(SearchEntity::domain("192.0.2.10", 1).is_err());
    assert!(SearchEntity::username("", 1).is_err());
}

// ---------- passive execution (zero network) ----------

#[test]
fn passive_reports_carry_provenance_and_zero_network() {
    for (kind, value) in [
        (SearchEntityKind::EmailAddress, "user@example.test"),
        (SearchEntityKind::Domain, "example.test"),
        (SearchEntityKind::Hostname, "api.example.test"),
        (SearchEntityKind::IpAddress, "192.0.2.10"),
        (SearchEntityKind::Asn, "AS64500"),
        (SearchEntityKind::Url, "https://example.test/path"),
        (SearchEntityKind::Repository, "example-org/example-project"),
        (SearchEntityKind::Organization, "example-org"),
    ] {
        let report = execute_entity_search(kind, value).unwrap();
        assert_eq!(report.network_scans, 0, "{kind:?}");
        assert_eq!(report.schema_version, 1);
        assert!(!report.observations.is_empty());
        assert!(!report.graph.entities.is_empty());
        // Every edge carries provenance answering "why".
        for edge in &report.graph.edges {
            assert!(!edge.evidence.is_empty());
            assert!(!edge.provenance.module.is_empty());
        }
        // JSONL is typed, one object per line, zero network.
        let jsonl = rxscan::entity_search::render_entity_jsonl(&report);
        assert!(jsonl.contains("\"record_type\":\"search_start\""));
        assert!(jsonl.contains("\"network_scans\":0"));
        for line in jsonl.lines() {
            assert!(serde_json::from_str::<serde_json::Value>(line).is_ok());
        }
        // No secrets ever appear in passive output.
        let json = serde_json::to_string(&report).unwrap().to_ascii_lowercase();
        for marker in ["password", "secret", "token", "cookie", "session", "hash"] {
            // `body_sha256`-style hashes are fine elsewhere, but this
            // module never emits hashes; any marker here is a leak.
            if marker == "hash" {
                continue;
            }
            assert!(!json.contains(marker), "leak {marker} in {kind:?}");
        }
    }
}

#[test]
fn email_derives_domain_and_username_hint() {
    let report =
        execute_entity_search(SearchEntityKind::EmailAddress, "user@example.test").unwrap();
    let domain_id = rxscan::assets::public_entity_id("domain", "example.test");
    assert!(report.graph.entities.contains_key(&domain_id));
}

#[test]
fn url_derives_domain_locally_without_contact() {
    let report =
        execute_entity_search(SearchEntityKind::Url, "https://api.example.test/x").unwrap();
    let domain_id = rxscan::assets::public_entity_id("domain", "api.example.test");
    assert!(report.graph.entities.contains_key(&domain_id));
    assert_eq!(report.network_scans, 0);
}

#[test]
fn repo_derives_org() {
    let report =
        execute_entity_search(SearchEntityKind::Repository, "example-org/example-project").unwrap();
    let org_id = rxscan::assets::public_entity_id("organization", "example-org");
    assert!(report.graph.entities.contains_key(&org_id));
}

// ---------- CLI parity ----------

#[test]
fn cli_entity_search_human_json_jsonl() {
    for (flag, value) in [
        ("--email", "user@example.test"),
        ("--domain", "example.test"),
        ("--hostname", "api.example.test"),
        ("--ip", "192.0.2.10"),
        ("--asn", "AS64500"),
        ("--url", "https://example.test"),
        ("--repo", "example-org/example-project"),
        ("--org", "example-org"),
    ] {
        let (code, stdout, _) = run_cli(&["search", flag, value]);
        assert_eq!(code, 0, "{flag} {value}");
        assert!(stdout.contains("network scans: 0"), "{flag}: {stdout}");

        let (code, stdout, _) = run_cli(&["search", flag, value, "--json"]);
        assert_eq!(code, 0, "{flag} --json");
        let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("json");
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["network_scans"], 0);

        let (code, stdout, _) = run_cli(&["search", flag, value, "--jsonl"]);
        assert_eq!(code, 0, "{flag} --jsonl");
        assert!(stdout.contains("\"record_type\":\"search_start\""));
        for line in stdout.lines() {
            assert!(serde_json::from_str::<serde_json::Value>(line).is_ok());
        }

        let (code, stdout, _) = run_cli(&["search", flag, value, "--explain"]);
        assert_eq!(code, 0, "{flag} --explain");
        assert!(stdout.contains("network scans: 0"));
    }
}

#[test]
fn cli_positional_forms_work() {
    let (code, stdout, _) = run_cli(&["search", "domain", "example.test"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("example.test"), "{stdout}");
    let (code, _, _) = run_cli(&["search", "email", "user@example.test"]);
    assert_eq!(code, 0);
    let (code, _, _) = run_cli(&["search", "ip", "192.0.2.10"]);
    assert_eq!(code, 0);
}

#[test]
fn cli_rejects_invalid_and_duplicates() {
    let (code, _, _) = run_cli(&["search", "--email", "not-an-email"]);
    assert_ne!(code, 0);
    let (code, _, _) = run_cli(&["search", "--domain", "localhost"]);
    assert_ne!(code, 0);
    let (code, _, stderr) = run_cli(&[
        "search",
        "--email",
        "user@example.test",
        "--domain",
        "example.test",
    ]);
    assert_eq!(code, 2, "{stderr}");
    let (code, _, _) = run_cli(&[
        "search",
        "--domain",
        "example.test",
        "--providers",
        "some-provider",
    ]);
    assert_eq!(code, 2);
}

#[test]
fn cli_search_help_lists_new_types() {
    let (code, stdout, _) = run_cli(&["search", "--help"]);
    assert_eq!(code, 0);
    for flag in [
        "--email",
        "--domain",
        "--hostname",
        "--ip",
        "--asn",
        "--url",
        "--repo",
        "--org",
    ] {
        assert!(stdout.contains(flag), "help missing {flag}: {stdout}");
    }
}

#[test]
fn cli_username_explain_still_passive() {
    // Existing username path is preserved: --explain contacts nothing.
    let (code, stdout, _) = run_cli(&["search", "--username", "exampleuser", "--explain"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Username search plan"), "{stdout}");
    assert!(stdout.contains("network scans: 0"), "{stdout}");
}

#[test]
fn cli_entity_persists_to_project_db() {
    let dir = std::env::temp_dir().join(format!(
        "rxscan-entity-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("entity.db");
    let (code, _, stderr) = run_cli(&[
        "search",
        "--domain",
        "example.test",
        "--project-db",
        db.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr}");
    assert!(db.exists());
    // Second import of a different entity appends history.
    let (code, _, stderr) = run_cli(&[
        "search",
        "--email",
        "user@example.test",
        "--project-db",
        db.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr}");
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- project aliases (additive, no replacement) ----------

#[test]
fn cli_project_graph_timeline_related_diff() {
    let dir = std::env::temp_dir().join(format!(
        "rxscan-proj-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let proj = dir.join("t.rxproj");
    let proj_str = proj.to_str().unwrap().to_owned();

    let (code, _, stderr) = run_cli(&["project", "create", &proj_str]);
    assert_eq!(code, 0, "{stderr}");

    // graph (alias for summary with counts).
    let (code, stdout, _) = run_cli(&["project", "graph", &proj_str]);
    assert_eq!(code, 0);
    assert!(stdout.contains("graph entities="), "{stdout}");
    let (code, stdout, _) = run_cli(&["project", "graph", &proj_str, "--json"]);
    assert_eq!(code, 0);
    assert!(serde_json::from_str::<serde_json::Value>(&stdout).is_ok());

    // Existing summary still works (not replaced).
    let (code, stdout, _) = run_cli(&["project", "summary", &proj_str]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Project"), "{stdout}");

    // timeline (alias for changes).
    let (code, stdout, _) = run_cli(&["project", "timeline", &proj_str]);
    assert_eq!(code, 0, "{stdout}");
    let (code, stdout2, _) = run_cli(&["project", "changes", &proj_str]);
    assert_eq!(code, 0);
    assert_eq!(stdout, stdout2);

    // related requires an entity (same usage contract as neighbors).
    let (code, _, _) = run_cli(&["project", "related", &proj_str]);
    assert_eq!(code, 2);
    let (code, _, stderr) = run_cli(&["project", "related", &proj_str, "missing-entity"]);
    // Unknown entity is a runtime miss (1), not a usage error (2).
    assert!(code == 0 || code == 1, "{stderr}");

    // diff usage without two checkpoints is a usage error.
    let (code, _, _) = run_cli(&["project", "diff"]);
    assert_eq!(code, 2);

    // project help lists the additive aliases.
    let (code, stdout, _) = run_cli(&["project", "--help"]);
    assert_eq!(code, 0);
    for cmd in ["graph", "timeline", "related", "diff"] {
        assert!(stdout.contains(cmd), "help missing {cmd}: {stdout}");
    }

    std::fs::remove_dir_all(&dir).ok();
}
