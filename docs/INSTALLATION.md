# RXScan Installation

Released `v1.0.2` is source-archives only (GitHub-generated source
tarballs; no ready-to-run binaries). Below covers current `master`
development distribution artifacts; see `docs/PLATFORMS.md` for per-target
validation status (native post-extraction smoke proof for Linux x86_64,
Windows x86_64, and macOS arm64; build-only for Linux arm64 and macOS
x86_64; emulator install/launch proof for the Android APK).

Development artifacts are named `RXScan-<version>-dev-<os>-<arch>.tar.gz`
(`.zip` on Windows); official releases will drop the `-dev` segment.
Development builds are GitHub Actions artifacts of the `Distribution
artifacts` workflow — they are not releases and never replace `v1.0.2`.

Start with the easiest route for your platform. No Rust toolchain required to *use* RXScan.

Unsigned-binary notice: development executables are unsigned. Windows
SmartScreen may warn for the unsigned `.exe`; macOS Gatekeeper may warn
for unsigned/not-notarized binaries (verify SHA-256, move via Finder, never
disable system security globally). No signing/notarization exists yet.

## Linux

```sh
tar -xzf RXScan-1.0.2-dev-linux-x86_64.tar.gz
./rxscan --help
./rxscan capabilities
```

Each archive extracts `rxscan`, `README.md`, `LICENSE`, plus the required
runtime sidecars (`app/`, `fingerprints/`, `search/`). Verify with
`sha256sum -c SHA256SUMS` using the shipped checksum file.

ARM64: use `RXScan-1.0.2-dev-linux-aarch64.tar.gz` where provided
(build-only in current CI: extraction-verified, execution unverified).
Musl variants are named similarly where provided. Linux x86_64 is locally
runtime-tested with hosted smoke proof; per-variant status lives in
`docs/PLATFORMS.md`. See `docs/PACKAGING.md` for `.deb`/`.rpm`/PKGBUILD
scaffolding (no fake `apt install rxscan` until a real repo exists).

## Windows

PowerShell:

```powershell
Expand-Archive RXScan-1.0.2-dev-windows-x86_64.zip -DestinationPath rxscan
cd rxscan
.\rxscan.exe --help
.\rxscan.exe capabilities
```

Command Prompt:

```cmd
rxscan.exe --help
```

Git Bash (same native binary, Bash shell only):

```sh
./rxscan.exe --help
```

Manual ZIP install always works. Optional winget/Scoop/Chocolatey manifests are scaffolding only until maintainer-authorized publication. No WSL or Git Bash required.

## macOS

```sh
tar -xzf RXScan-1.0.2-dev-macos-arm64.tar.gz   # Apple Silicon (native smoke-tested)
# or: tar -xzf RXScan-1.0.2-dev-macos-x86_64.tar.gz  # Intel (build-only: extraction-verified, execution unverified)
./rxscan --help
```

If Gatekeeper quarantines the binary, verify the SHA-256 checksum and move the app via Finder (do not disable system security globally). Homebrew formula/tap is scaffolding only until published.

## Android

Two separate distributions; do not confuse them.

**APK (normal install, development):** download
`RXScan-1.0.2-dev-android-arm64.apk` from the `Distribution artifacts`
workflow's Actions artifacts (not a release), allow sideloaded installs
when Android asks, and install. The APK is the application: no Termux,
no Rust, no repository clone, no separately running server. It is
debug-signed only (Gradle debug flow; production/Play signing is out of
scope). Raw-packet and active OS-probe capabilities report as
restricted/unavailable on Android (see `docs/ANDROID.md`); TCP/DNS/HTTP/
TLS/search/investigation/graph/projects work unprivileged, no root.

**Termux (source build, experimental):** no root required. Core
search/investigation works unprivileged.

Termux is experimental; cross-build configured with hosted validation
pending and runtime unverified (see `docs/PLATFORMS.md`).
No Termux archive is published by the release workflow yet; build from
source with the Android NDK (`aarch64-linux-android`, see
`docs/BUILDING.md`) or use the Linux archives on regular Linux only.
Do not use a normal Linux ARM64 glibc binary on Termux/Android.

Restricted capabilities (raw packet, active OS probes, some privileged
enumeration) report one controlled explanation with passive fallback. CLI
remains usable on narrow widths via the existing width-aware renderer.

## Build from source

```sh
cargo build --release
./target/release/rxscan --help
```

See `docs/BUILDING.md` for targets and `docs/PACKAGING.md` for checksums. Verify `SHA-256` files shipped with each artifact.
