# RXScan Packaging

No fake availability is claimed: do not document `apt install rxscan`, AUR, Homebrew, winget, Chocolatey, Scoop, or crates.io until the artifact/repo truly exists. Packaging definitions and release automation may precede publication.

## Artifacts (future releases)

Released `v1.0.2`: source archives only (no ready-to-run binaries). Below
lists `master` development artifact names produced by the `Distribution
artifacts` workflow (manual dispatch; Actions artifacts, never releases).
Names derive from package version + target metadata
(`scripts/package-artifact.sh --print-name <target>`); official releases
drop the `-dev` segment. Linux x86_64 is the only locally runtime-tested
artifact; see `docs/PLATFORMS.md` for hosted validation status.

- `RXScan-<version>-dev-linux-x86_64.tar.gz` (locally runtime-tested; native smoke)
- `RXScan-<version>-dev-linux-aarch64.tar.gz` (build-only: extraction-verified)
- musl variants where provided (`RXScan-<version>-dev-linux-*-musl.tar.gz`; configured)
- `RXScan-<version>-dev-windows-x86_64.zip` (native smoke: PowerShell + cmd + Git Bash launch, GUI loopback check)
- `RXScan-<version>-dev-macos-arm64.tar.gz` (native smoke)
- `RXScan-<version>-dev-macos-x86_64.tar.gz` (build-only: extraction + arch verified)
- Termux: no published archive yet (experimental cross-build configured only, runtime unverified; do not
  document an installable Termux/APK filename until the workflow actually produces one)
- Android APK: development artifact `RXScan-<version>-dev-android-arm64.apk` once the Android job lands (see `docs/ANDROID.md`); sideloading requires user permission, debug-signed only

Each desktop archive extracts: executable, `README.md`, `LICENSE`, required
bundled runtime assets (`app/`, `fingerprints/`, `search/` corpus).
`SHA-256` checksums ship alongside (`dist/SHA256SUMS`) plus a
machine-readable `dist/release-manifest.json` (filename, platform,
architecture, target triple, artifact type, version, commit, sha256, size;
no usernames, hostnames, or local paths).

Build locally:

```sh
bash scripts/package-artifact.sh x86_64-unknown-linux-gnu
bash scripts/dist-smoke.sh dist/RXScan-*-linux-x86_64.tar.gz
sha256sum dist/RXScan-*.tar.gz
python3 scripts/dist-manifest.py
```

Distribution workflow (`.github/workflows/dist.yml`, manual dispatch only):
builds native binaries per OS, packages once on Linux (deterministic Bash+tar
env, explicit required-asset checks, no `|| true` for required content),
smoke-tests each native artifact after extraction (`--version`,
`capabilities`, offline loopback GUI check; Windows additionally launched
from PowerShell, cmd, and Git Bash), generates `SHA256SUMS` +
`release-manifest.json` with a privacy self-check, uploads Actions artifacts
only. Never tags, releases, publishes, or mutates historical tags
(`v1.0.0`/`v1.0.1`/`v1.0.2` immutable).

Release workflow (`.github/workflows/release.yml`): validates version/tag consistency via `cargo metadata` (no grep), runs gates, builds native binaries per OS, packages once on Linux (deterministic Bash+tar env, explicit required-asset checks, no `|| true` for required content), generates `SHA256SUMS`, preserves licenses and `.exe` suffixes, uploads artifacts with `manual-*` prefix for untagged dispatches. Never publishes or mutates historical tags (`v1.0.0`/`v1.0.1`/`v1.0.2` immutable).

## Linux packages

- Debian/Ubuntu: `.deb` scaffolding (maintainable `cargo-deb` or `fpm` config; no repo claim until configured).
- Fedora/RHEL/openSUSE: `.rpm` where practical.
- Arch: `PKGBUILD` template.
- Alpine: portable musl binary + packaging notes where provided (configured; hosted validation pending).

## Windows

ZIP first. Optional manifests for winget/Scoop/Chocolatey are scaffolding only (no publication without maintainer authorization). A PowerShell installer, if added, must download only official artifacts, verify integrity, have understandable behavior, not weaken PowerShell security, and not silently modify unrelated config. Manual ZIP always remains.

## macOS

Arch-specific archives; universal binaries only if they simplify distribution. Homebrew formula/tap scaffolding only until published. Document quarantine accurately; never instruct global security disable.

## Termux

Experimental cross-build configured; runtime unverified; no published
archive. Reproducible source build only, no root, no weakened Android
security. Document ordinary vs privileged capability differences; root never required for OSINT/investigation.
