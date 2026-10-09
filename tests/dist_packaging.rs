//! Distribution packaging gates: artifact names derive from version +
//! target metadata (never scattered hardcoded release numbers), and the
//! release manifest carries exactly the documented machine-readable schema
//! with no private build-environment details.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn print_name(target: &str, dev: bool) -> Result<String, String> {
    let script = repo_root().join("scripts/package-artifact.sh");
    let mut cmd = Command::new("bash");
    cmd.arg(&script).arg("--print-name").arg(target);
    cmd.env("RXSCAN_VERSION", "1.0.2");
    cmd.env("RXSCAN_DEV", if dev { "1" } else { "0" });
    let output = cmd.output().map_err(|e| format!("spawn bash: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "print-name {target} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[test]
fn artifact_names_derive_from_version_and_target() {
    // Development artifacts carry -dev so nobody mistakes them for a release.
    let cases = [
        (
            "x86_64-unknown-linux-gnu",
            "RXScan-1.0.2-dev-linux-x86_64.tar.gz",
        ),
        (
            "aarch64-unknown-linux-gnu",
            "RXScan-1.0.2-dev-linux-aarch64.tar.gz",
        ),
        (
            "x86_64-pc-windows-msvc",
            "RXScan-1.0.2-dev-windows-x86_64.zip",
        ),
        (
            "aarch64-apple-darwin",
            "RXScan-1.0.2-dev-macos-arm64.tar.gz",
        ),
        (
            "x86_64-apple-darwin",
            "RXScan-1.0.2-dev-macos-x86_64.tar.gz",
        ),
    ];
    for (target, expected) in cases {
        assert_eq!(
            print_name(target, true).expect("derivation must succeed"),
            expected,
            "target {target}"
        );
    }
    // Official (non-dev) names have no -dev segment.
    assert_eq!(
        print_name("x86_64-unknown-linux-gnu", false).expect("official name"),
        "RXScan-1.0.2-linux-x86_64.tar.gz"
    );
}

#[test]
fn unknown_target_has_no_name_mapping() {
    assert!(
        print_name("wasm32-unknown-unknown", true).is_err(),
        "unmapped targets must fail closed, never invent a filename"
    );
}

#[test]
fn manifest_schema_and_privacy() {
    let dir =
        std::env::temp_dir().join(format!("rxscan-dist-manifest-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    // Minimal stand-in archives with distribution names (content is
    // irrelevant; the manifest records hashes/sizes of whatever it scans).
    for name in [
        "RXScan-1.0.2-dev-linux-x86_64.tar.gz",
        "RXScan-1.0.2-dev-windows-x86_64.zip",
    ] {
        std::fs::write(dir.join(name), format!("payload for {name}")).expect("fixture");
    }
    // A non-distribution file must be ignored, never break the manifest.
    std::fs::write(dir.join("notes.txt"), "ignore me").expect("fixture");
    let script = repo_root().join("scripts/dist-manifest.py");
    let out = dir.join("release-manifest.json");
    let status = Command::new("python3")
        .arg(&script)
        .arg("--dist")
        .arg(&dir)
        .arg("--out")
        .arg(&out)
        .env("RXSCAN_VERSION", "1.0.2")
        .env("RXSCAN_COMMIT", "0123456789abcdef0123456789abcdef01234567")
        .status()
        .expect("spawn python3");
    assert!(status.success(), "manifest generation must succeed");
    let text = std::fs::read_to_string(&out).expect("manifest written");
    let manifest: serde_json::Value = serde_json::from_str(&text).expect("manifest is valid JSON");
    assert_eq!(manifest["project"], "RXScan");
    assert_eq!(manifest["version"], "1.0.2");
    let artifacts = manifest["artifacts"].as_array().expect("artifacts array");
    assert_eq!(artifacts.len(), 2, "only distribution archives listed");
    for entry in artifacts {
        for key in [
            "filename",
            "platform",
            "architecture",
            "target",
            "artifact_type",
            "development",
            "version",
            "commit",
            "sha256",
            "size_bytes",
        ] {
            assert!(
                entry.get(key).is_some(),
                "manifest entry lacks {key}: {entry}"
            );
        }
        assert_eq!(entry["version"], "1.0.2");
        assert_eq!(entry["development"], true);
        let sha = entry["sha256"].as_str().expect("sha string");
        assert_eq!(sha.len(), 64, "sha256 hex length");
        assert!(
            sha.chars().all(|c| c.is_ascii_hexdigit()),
            "sha256 hex only"
        );
    }
    // Privacy: manifest must not leak local paths, usernames, or homes.
    for needle in ["notes.txt", "/home/", "/Users/", "C:\\", "PRIVATE"] {
        assert!(
            !text.contains(needle),
            "manifest leaks environment detail: {needle}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
