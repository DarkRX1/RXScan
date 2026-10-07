# RXScan Packaging

No fake availability is claimed: do not document `apt install rxscan`, AUR, Homebrew, winget, Chocolatey, Scoop, or crates.io until the artifact/repo truly exists. Packaging definitions and release automation may precede publication.

## Artifacts (future releases)

Released `v1.0.2`: Linux x86_64 only. Below lists `master` development
artifact names; Windows/macOS and other variants are configured with hosted
validation pending and runtime unverified (see `docs/PLATFORMS.md`).
Linux x86_64 is the only locally runtime-tested artifact.

- `rxscan-linux-x86_64.tar.gz` (locally runtime-tested)
- `rxscan-linux-aarch64.tar.gz` (configured; hosted validation pending)
- musl variants where provided (`rxscan-linux-*-musl.tar.gz`; configured; hosted validation pending)
- `rxscan-windows-x86_64.zip` (native CI configured; hosted validation pending; runtime unverified)
- `rxscan-macos-x86_64.tar.gz`, `rxscan-macos-aarch64.tar.gz` (native CI configured; hosted validation pending; runtime unverified)
- Termux: no published archive yet (experimental cross-build configured only, runtime unverified; do not
  document `rxscan-termux-aarch64.tar.gz` as downloadable until the release
  workflow actually produces an Android-appropriate binary)

Each includes: executable, required bundled runtime assets (`app/`,
`fingerprints/`, `search/` corpus), `LICENSE`, minimal usage readme.
`SHA-256` checksums ship alongside (`dist/SHA256SUMS` from the single Linux
packaging job).

Build locally:

```sh
bash scripts/package-artifact.sh x86_64-unknown-linux-gnu rxscan-linux-x86_64.tar.gz
sha256sum dist/rxscan-linux-x86_64.tar.gz
```

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
