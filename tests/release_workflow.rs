//! Release-workflow guards (no network, no publish).
//!
//! Validates that `.github/workflows/release.yml` and
//! `scripts/package-artifact.sh` keep release-security properties:
//! structured version check, manual-prefix, single-Linux packaging,
//! explicit required-asset checks.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn release_uses_structured_version_and_manual_prefix() {
    let yml = std::fs::read_to_string(repo_root().join(".github/workflows/release.yml")).unwrap();
    assert!(
        yml.contains("cargo metadata"),
        "version must come from cargo metadata, not grep"
    );
    assert!(
        !yml.contains("grep '^version'"),
        "fragile grep must be gone"
    );
    assert!(yml.contains("manual-"), "manual builds must be prefixed");
    assert!(
        yml.contains("SHA256SUMS") || yml.contains("SHA256SUM"),
        "checksums must be generated"
    );
    // Single Linux packaging job (no per-OS zip/sha256sum).
    assert!(yml.contains("needs: build"), "package job follows builds");
    assert!(yml.contains("ubuntu-latest"), "packaging on known Linux");
}

#[test]
fn packaging_fails_on_missing_required_assets() {
    let sh = std::fs::read_to_string(repo_root().join("scripts/package-artifact.sh")).unwrap();
    assert!(
        sh.contains("test -d \"$dir\"") || sh.contains("required asset"),
        "required dirs must be checked"
    );
    assert!(
        !sh.contains("cp -r app fingerprints search \"$STAGE/rxscan/\" 2>/dev/null || true"),
        "silent || true for required assets must be gone"
    );
    assert!(
        sh.contains("command -v zip"),
        "zip availability must be checked"
    );
    assert!(sh.contains("Bash"), "Bash requirement must be documented");
}

#[test]
fn termux_has_no_published_artifact() {
    let yml = std::fs::read_to_string(repo_root().join(".github/workflows/release.yml")).unwrap();
    assert!(
        !yml.contains("termux"),
        "release must not claim a Termux artifact it does not build"
    );
    let install = std::fs::read_to_string(repo_root().join("docs/INSTALLATION.md")).unwrap();
    assert!(
        !install.contains("tar -xzf rxscan-termux"),
        "docs must not give a Termux download command without an artifact"
    );
}
