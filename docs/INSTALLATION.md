# RXScan Installation

Released `v1.0.2` is Linux x86_64 only. Below covers current `master`
development artifacts; Windows/macOS native binaries and other variants are
configured with hosted validation pending and runtime unverified (see
`docs/PLATFORMS.md`).

Start with the easiest route for your platform. No Rust toolchain required to *use* RXScan.

## Linux

```sh
tar -xzf rxscan-linux-x86_64.tar.gz
cd rxscan
./rxscan --help
./rxscan capabilities
```

ARM64: use `rxscan-linux-aarch64.tar.gz` where provided. Musl variants are named
similarly where provided. Linux x86_64 is locally runtime-tested; other
variants are configured with hosted validation pending (see
`docs/PLATFORMS.md`). See `docs/PACKAGING.md` for `.deb`/`.rpm`/PKGBUILD scaffolding (no fake `apt install rxscan` until a real repo exists).

## Windows

PowerShell:

```powershell
Expand-Archive rxscan-windows-x86_64.zip -DestinationPath rxscan
cd rxscan\rxscan
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
tar -xzf rxscan-macos-aarch64.tar.gz   # Apple Silicon
# or: tar -xzf rxscan-macos-x86_64.tar.gz  # Intel
cd rxscan
./rxscan --help
```

If Gatekeeper quarantines the binary, verify the SHA-256 checksum and move the app via Finder (do not disable system security globally). Homebrew formula/tap is scaffolding only until published.

## Android / Termux

No root required. Core search/investigation works unprivileged.

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
