# RXScan Installation

Released `v1.1.0` ships ready-to-run artifacts (see below); `v1.0.2` and
earlier were source-archives only. Per-target validation status lives in
`docs/PLATFORMS.md`: Windows x86_64, Linux x86_64, and macOS ARM64 are
runtime-tested; Linux ARM64 and macOS x86_64 are build-only; the Android
APK is beta/experimental (emulator install/launch-tested, physical-device
execution unverified).

Release artifacts are named `RXScan-<version>-<os>-<arch>.tar.gz`
(`.zip` on Windows, `.apk` on Android). Development builds from `master`
carry a `-dev` segment and are GitHub Actions artifacts of the
`Distribution artifacts` workflow — they are not releases.

Start with the easiest route for your platform. No Rust toolchain required to *use* RXScan.

Unsigned-binary notice: release executables are unsigned. Windows
SmartScreen may warn for the unsigned `.exe`; macOS Gatekeeper may warn
for unsigned/not-notarized binaries (verify SHA-256, move via Finder, never
disable system security globally). No signing/notarization exists yet.

## Linux

```sh
tar -xzf RXScan-1.1.0-linux-x86_64.tar.gz
./rxscan --help
./rxscan capabilities
```

Each archive extracts `rxscan`, `README.md`, `LICENSE`, plus the required
runtime sidecars (`app/`, `fingerprints/`, `search/`). Verify with
`sha256sum -c SHA256SUMS` using the shipped checksum file.

ARM64: use `RXScan-1.1.0-linux-aarch64.tar.gz` where provided
(build-only: extraction-verified, execution unverified).
Musl variants are named similarly where provided. Linux x86_64 is locally
runtime-tested with hosted smoke proof; per-variant status lives in
`docs/PLATFORMS.md`. See `docs/PACKAGING.md` for `.deb`/`.rpm`/PKGBUILD
scaffolding (no fake `apt install rxscan` until a real repo exists).

## Windows

PowerShell:

```powershell
Expand-Archive RXScan-1.1.0-windows-x86_64.zip -DestinationPath rxscan
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
tar -xzf RXScan-1.1.0-macos-arm64.tar.gz   # Apple Silicon (runtime-tested)
# or: tar -xzf RXScan-1.1.0-macos-x86_64.tar.gz  # Intel (build-only: extraction-verified, execution unverified)
./rxscan --help
```

If Gatekeeper quarantines the binary, verify the SHA-256 checksum and move the app via Finder (do not disable system security globally). Homebrew formula/tap is scaffolding only until published.

## Android

Two separate distributions; do not confuse them.

**APK (normal install; beta/experimental):** download
`RXScan-1.1.0-android-arm64.apk` from the `v1.1.0` GitHub Release, allow
sideloaded installs when Android asks, and install. The APK is the
application: no Termux,
no Rust, no repository clone, no separately running server. It is
debug-signed only (Gradle debug flow; production/Play signing is out of
scope). Emulator install/launch-tested; physical ARM64-device execution
remains unverified. Raw-packet and active OS-probe capabilities report as
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
