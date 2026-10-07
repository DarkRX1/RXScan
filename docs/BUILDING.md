# RXScan Building

## Toolchain

- Rust 1.85+, edition 2024.
- `cargo fmt --check`, `cargo check --all-targets`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features` (see TESTING.md categories).

Fish compatibility is welcome for maintainer instructions; RXScan itself never depends on fish, Bash, or PowerShell at runtime.

## Configured targets

Hosted CI is configured for the targets below, but hosted validation is
still pending. Only Linux x86_64 is locally runtime-tested. Other targets
are cross-build configured with runtime unverified unless stated otherwise
in `docs/PLATFORMS.md`.

Do not claim a target is tested or supported unless evidence in
`docs/PLATFORMS.md` supports it.

```sh
cargo check --target x86_64-unknown-linux-gnu
cargo check --target aarch64-unknown-linux-gnu        # cross-build configured; hosted validation pending
cargo check --target x86_64-unknown-linux-musl        # where configured
cargo check --target aarch64-unknown-linux-musl       # where configured
cargo check --target x86_64-pc-windows-msvc           # native CI configured; hosted validation pending
cargo check --target x86_64-apple-darwin              # native CI configured; hosted validation pending
cargo check --target aarch64-apple-darwin             # native CI configured; hosted validation pending
cargo check --target aarch64-linux-android            # Termux-compatible; cross-build configured; runtime unverified
```

Linux distributions share one Linux core; architectures differ by build/backend, never by duplicated RXScan implementations.

## musl / ARM notes

- `rusqlite` uses `bundled` SQLite (no system lib required).
- `reqwest` uses `rustls-tls-webpki-roots` (no OpenSSL/native TLS).
- `ring` (via rustls) supports musl with the standard toolchain; if a blocker appears, document it here and do not rewrite major subsystems for theoretical portability.
- ARM64 Windows is investigated separately; enable only if deps + CI allow.

## Cross-compiling

```sh
rustup target add aarch64-unknown-linux-gnu
sudo apt-get install -y gcc-aarch64-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
```

Android/Termux: use `aarch64-linux-android` with the NDK toolchain; hosted
runtime tests remain pending and no release artifact is published.
