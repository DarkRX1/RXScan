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

#[test]
fn ci_cross_matrix_has_no_invalid_linux_hosted_targets() {
    // CI #23: MSVC and Apple targets must never be Linux-hosted matrix
    // entries (Ubuntu gcc is not MSVC; Linux cc with -arch flags is not
    // an Apple toolchain). They are validated on native runners instead.
    // Match YAML list items precisely: comments may name the targets while
    // explaining why they are absent from the matrix.
    let yml = std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml")).unwrap();
    for entry in [
        "\n          - x86_64-pc-windows-msvc",
        "\n          - x86_64-apple-darwin",
        "\n          - aarch64-apple-darwin",
    ] {
        assert!(
            !yml.contains(entry),
            "invalid Linux-hosted cross entry must stay removed: {entry:?}"
        );
    }
    // The native lanes that replace them must still exist. macOS is
    // pinned to the explicit current ARM64 label (never mutable
    // macos-latest as a matrix runner); Apple Intel build validation is
    // gated to that same macOS runner.
    assert!(
        yml.contains("windows-latest"),
        "native Windows lane must remain"
    );
    assert!(
        yml.contains("macos-26"),
        "native macOS lane must use the pinned ARM64 label"
    );
    assert!(
        !yml.contains(", macos-latest]"),
        "mutable macos-latest must not be a matrix runner"
    );
    assert!(
        yml.contains("matrix.os == 'macos-26'"),
        "Apple build validation must be gated to the macOS runner"
    );
}

#[test]
fn ci_cross_toolchains_are_real_not_faked() {
    // CI #23: musl/Android jobs must provision genuine toolchains and fail
    // loudly without them. Host-gcc masquerading (symlinking /usr/bin/gcc
    // to a cross name) or swallowing setup errors would fake validation.
    let yml = std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml")).unwrap();
    for marker in [
        "musl-tools",
        "CC_x86_64_unknown_linux_musl=musl-gcc",
        "musl.cc/aarch64-linux-musl-cross.tgz",
        "CC_aarch64_unknown_linux_musl=",
        "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=",
        "ANDROID_NDK_HOME",
        "aarch64-linux-android24-clang",
        "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=",
    ] {
        assert!(
            yml.contains(marker),
            "real toolchain configuration missing: {marker}"
        );
    }
    assert!(
        !yml.contains("ln -s /usr/bin/gcc"),
        "host gcc must never masquerade as a cross compiler"
    );
    assert!(
        !yml.contains("continue-on-error"),
        "cross validation must not be optional"
    );
}
