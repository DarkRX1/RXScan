use std::process::Command;

use rxscan::os_lab::OsLabFixture;

const FIXTURE: &str = "fixtures/os_lab/synthetic-repeat-v1.json";

#[test]
fn checked_fixture_is_sanitized_and_separate_from_production_corpus() {
    let fixture = OsLabFixture::from_json(&std::fs::read_to_string(FIXTURE).unwrap()).unwrap();
    assert_eq!(fixture, fixture.sanitized().unwrap());
    assert!(FIXTURE.starts_with("fixtures/os_lab/"));
    assert!(!FIXTURE.starts_with("fingerprints/os/"));
    assert_eq!(
        fixture.provenance,
        rxscan::os_lab::LabProvenance::SyntheticFixture
    );
}

#[test]
fn offline_cli_analysis_is_deterministic_and_review_only() {
    let binary = env!("CARGO_BIN_EXE_rxscan");
    let run = || {
        Command::new(binary)
            .args(["os-lab", "analyze", FIXTURE])
            .output()
            .unwrap()
    };
    let first = run();
    let second = run();
    assert!(first.status.success());
    assert_eq!(first.stdout, second.stdout);
    let analysis: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(analysis["sample_count"], 2);
    assert_eq!(analysis["production_pack_modified"], false);
    assert_eq!(analysis["stable_features"][0]["kind"], "ttl");
    assert_eq!(analysis["variable_features"][0]["kind"], "window");
}

#[test]
fn malformed_cli_fixture_fails_without_touching_corpus() {
    let before = std::fs::read("fingerprints/os/v1/linux.json").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rxscan"))
        .args(["os-lab", "analyze", "Cargo.toml"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        before,
        std::fs::read("fingerprints/os/v1/linux.json").unwrap()
    );
}
