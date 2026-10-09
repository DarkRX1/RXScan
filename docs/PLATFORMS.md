# RXScan Platform Support

Technical, restrained matrix. Released version behavior (`v1.0.2`) differs
from current `master` development behavior; only `master` gains the portable
platform layer described here.

Released `v1.0.2`: Linux x86_64 only.

Current `master` (development): portable core with explicit capability
detection. Hosted proof comes from two workflows: `CI` (deterministic
test suite on ubuntu/windows/macos plus musl/gnu/Android cross-build
checks) and `Distribution artifacts` (manual dispatch: native release
builds, versioned `-dev` packaging, post-extraction native smoke tests,
checksums, manifest, and an Android emulator install/launch proof).
Build-only entries are labeled build-only; only executed artifacts claim
runtime evidence. The only *local* runtime evidence claimed is execution
on Linux x86_64.

Statuses: **locally runtime-tested** · **hosted runtime proof**
(executed post-extraction on hosted runners) · **build-only**
(extraction/arch verified, execution unverified) · **cross-build
configured; hosted validation pending** · **experimental** ·
**capability-dependent**. `Supported` is reserved for locally
runtime-tested platforms. Build configuration alone is not runtime
evidence, and a smoke test is not full support.

## Runtime matrix (master)

| Platform | Status | Notes |
|---|---|---|
| Linux x86_64 (gnu) | locally runtime-tested; hosted runtime proof | Primary development platform; full TCP/UDP/DNS/HTTP/TLS/SSH, raw SYN where permitted. Distribution smoke: `--version`, `capabilities`, offline loopback GUI check post-extraction |
| Linux ARM64 (gnu) | build-only (extraction + layout verified; execution unverified) | Same core; no execution claim on hosted runners |
| Linux musl (x86_64/aarch64) | experimental; cross-build configured; hosted validation pending | Portable builds where configured; runtime unverified; see BUILDING.md |
| Debian family (Debian/Ubuntu/Mint/Kali/Parrot) | shared Linux implementation; distro-specific runtime validation pending | Same Linux core; no distro-specific logic |
| Arch family (Arch/Manjaro/EndeavourOS) | shared Linux implementation; distro-specific runtime validation pending | Same Linux core; runtime unverified |
| Fedora/RHEL family (Fedora/RHEL/Rocky/Alma) | shared Linux implementation; distro-specific runtime validation pending | Same Linux core; `.rpm` scaffolding in PACKAGING.md |
| SUSE (openSUSE) | shared Linux implementation; distro-specific runtime validation pending | Same Linux core; runtime unverified |
| Alpine/musl | capability-dependent / experimental; runtime unverified | Portable musl binary where configured; no glibc assumption |
| Windows native x86_64 (msvc) | hosted runtime proof | `rxscan.exe` launched from PowerShell, cmd, and Git Bash post-extraction, plus offline loopback GUI check; bounded worker-pool TCP/UDP, DNS/HTTP/TLS/SSH, GUI, cancellation, persistence |
| Windows ARM64 | experimental; runtime unverified | Enabled if deps + CI allow |
| Windows PowerShell / cmd / Git Bash | hosted runtime proof (same binary) | Same `rxscan.exe`; Git Bash is a shell, not a platform |
| Windows WSL | capability-dependent; runtime validation pending | Linux binary; surfaced as `windows_wsl` environment via capability detection |
| macOS Intel (x86_64-darwin) | build-only (extraction + `lipo` arch verified; execution unverified) | Cross-built with the native Apple toolchain on Apple Silicon runners; no Intel runtime claimed |
| macOS Apple Silicon (aarch64-darwin) | hosted runtime proof | Native post-extraction smoke (`--version`, `capabilities`, offline loopback GUI check) |
| Android/Termux ARM64 | experimental; cross-build configured; runtime unverified; no release artifact | Search/investigation/DNS/HTTP/TLS/TCP connect/graph/projects; raw packet + active OS probes restricted; no published archive yet (build from source) |
| Android APK (arm64-v8a) | development artifact; install/runtime proof on x86_64 emulator slice | `RXScan-<version>-dev-android-arm64.apk` (debug-signed): aapt badging, zipalign, apksigner verified; installed and launched on an API-30 x86_64 emulator with logcat proof that the embedded Rust core serves loopback. arm64-device execution unverified; sideloading requires user permission |

Restricted platforms lose only genuinely unavailable capabilities. One
controlled explanation is emitted (e.g. active OS probes experimental with
passive fallback), never repeated low-level failures.

## Capability summary

- Always: TCP connect scanning, DNS, HTTP, TLS, SSH observation, public-source search, investigation, evidence graph, projects/history, persistence, local web UI (loopback), cancellation.
- Gated: raw packet send/capture, privileged interface/route details, some UDP ICMP attribution.
- Experimental: active OS fingerprinting (timing/behavior only; raw header observation not validated; passive remains primary).
- Never required: root (core OSINT/investigation works unprivileged).

## Environments

- Native Windows: `rxscan.exe`
- WSL: Linux `rxscan` binary (`windows_wsl`)
- Git Bash: native `rxscan.exe` launched from Bash (still `windows_native`)
- Termux: experimental cross-build, no root, narrow-width CLI supported via existing width-aware renderer; no published archive yet.

See `docs/INSTALLATION.md` for the easiest route per platform, `docs/BUILDING.md` for targets, `docs/PACKAGING.md` for artifacts.
