# Release Checklist (v0.1.0 prerelease)

Reusable gate for any release candidate. Stop on the first failure.

## Gates

- [ ] Working tree clean (`git status --porcelain` empty); release from an
  exact commit, recorded with `git rev-parse HEAD`.
- [ ] `cargo fmt --check`
- [ ] `cargo check --locked`
- [ ] `cargo test --locked` (all targets green, zero ignored release tests)
- [ ] `cargo test --release --locked` (release-mode proof)
- [ ] `cargo clippy --all-targets --all-features --locked -- -D warnings`
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items`
- [ ] `git diff --check`
- [ ] `cargo run --example phase19_bench` (no P19 regression)
- [ ] `cargo run --example phase20_release_gate` (record output)
- [ ] `cargo build --release --locked`; record size + delta vs baseline
- [ ] Startup: 11+ samples of release `--help` (min/median/max)
- [ ] `sh scripts/release-check.sh` (or with `--skip-install` + separate
  documented install proof)
- [ ] `LICENSE` file present and confirmed by maintainer (**currently
  missing: manifest declares MIT but no file ships — release blocker**)

## Artifact dry run (no publishing)

```sh
COMMIT=$(git rev-parse --short HEAD)
TARGET=$(rustc -vV | sed -n 's/host: //p')
NAME="rxscan-0.1.0-${TARGET}"
DIST="dist/${NAME}"
mkdir -p "$DIST"
cargo build --release --locked
cp target/release/rxscan "$DIST/"
cp README.md CHANGELOG.md SECURITY.md "$DIST/"
# LICENSE goes here once the file exists (blocker).
(cd dist && tar -czf "${NAME}.tar.gz" "$NAME")
(cd dist && sha256sum "${NAME}.tar.gz" > SHA256SUMS)
(cd dist && sha256sum -c SHA256SUMS)
./dist/$NAME/rxscan --version   # run the EXTRACTED artifact for final smoke
```

Record with the artifact: git commit, version, target triple, `rustc -V`,
`cargo -V`. Never `git tag`, `git push`, `gh release create`,
`cargo publish`, or external upload without explicit maintainer instruction.
No signing identity exists; ship checksums and say so.
