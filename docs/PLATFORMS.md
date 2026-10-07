# RXScan Platform Support

Technical, restrained matrix. Released version behavior (`v1.0.2`) differs
from current `master` development behavior; only `master` gains the portable
platform layer described here.

Released `v1.0.2`: Linux x86_64 only.

Current `master` (development): portable core with explicit capability
detection. Hosted GitHub Actions workflows are configured but hosted
validation is still pending, so no hosted runtime claim is made below.
The only runtime evidence claimed is local execution on Linux x86_64.

Statuses: **locally runtime-tested** · **native CI configured; hosted
validation pending** · **cross-build configured; hosted validation pending**
· **experimental** · **capability-dependent**. `Supported` is reserved for
locally runtime-tested platforms. Build configuration alone is not runtime
evidence, and a smoke test is not full support.

## Runtime matrix (master)

| Platform | Status | Notes |
|---|---|---|
| Linux x86_64 (gnu) | locally runtime-tested | Primary development platform; full TCP/UDP/DNS/HTTP/TLS/SSH, raw SYN where permitted. Hosted CI configured; hosted validation pending |
| Linux ARM64 (gnu) | cross-build configured; hosted validation pending | Same core; runtime unverified; no local compile validation claimed |
| Linux musl (x86_64/aarch64) | experimental; cross-build configured; hosted validation pending | Portable builds where configured; runtime unverified; see BUILDING.md |
| Debian family (Debian/Ubuntu/Mint/Kali/Parrot) | shared Linux implementation; distro-specific runtime validation pending | Same Linux core; no distro-specific logic |
| Arch family (Arch/Manjaro/EndeavourOS) | shared Linux implementation; distro-specific runtime validation pending | Same Linux core; runtime unverified |
| Fedora/RHEL family (Fedora/RHEL/Rocky/Alma) | shared Linux implementation; distro-specific runtime validation pending | Same Linux core; `.rpm` scaffolding in PACKAGING.md |
| SUSE (openSUSE) | shared Linux implementation; distro-specific runtime validation pending | Same Linux core; runtime unverified |
| Alpine/musl | capability-dependent / experimental; runtime unverified | Portable musl binary where configured; no glibc assumption |
| Windows native x86_64 (msvc) | native CI configured; hosted validation pending; runtime unverified | `rxscan.exe`; bounded worker-pool TCP/UDP, DNS/HTTP/TLS/SSH, GUI, cancellation, persistence; real-world runtime validation pending |
| Windows ARM64 | experimental; runtime unverified | Enabled if deps + CI allow |
| Windows PowerShell / cmd / Git Bash | native CI configured; hosted validation pending (same binary) | Same `rxscan.exe`; Git Bash is a shell, not a platform; runtime unverified |
| Windows WSL | capability-dependent; runtime validation pending | Linux binary; surfaced as `windows_wsl` environment via capability detection |
| macOS Intel (x86_64-darwin) | native CI configured; hosted validation pending; runtime unverified | Bounded worker-pool TCP/UDP, DNS/HTTP/TLS, search/investigation/graph/persistence/GUI |
| macOS Apple Silicon (aarch64-darwin) | native CI configured; hosted validation pending; runtime unverified | Same as Intel; runtime unverified |
| Android/Termux ARM64 | experimental; cross-build configured; runtime unverified; no release artifact | Search/investigation/DNS/HTTP/TLS/TCP connect/graph/projects; raw packet + active OS probes restricted; no published archive yet (build from source) |

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
