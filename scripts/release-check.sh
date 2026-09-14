#!/bin/sh
# RXScan release validation entry point (Phase 20).
#
# Runs the release gates and stops on the first failure. This script never
# publishes, pushes, tags, deletes user files, or requires root. It writes
# only into a caller-provided scratch area via TMPDIR (defaults to a fresh
# directory under the system temp dir) for smoke artifacts.
#
# Usage: sh scripts/release-check.sh [--skip-install]
#   --skip-install  skip the isolated `cargo install` proof (slowest gate).

set -eu

SKIP_INSTALL=0
if [ "${1:-}" = "--skip-install" ]; then
  SKIP_INSTALL=1
fi

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

SCRATCH="${TMPDIR:-$(mktemp -d "${TMPDIR:-/tmp}/rxscan-release-check.XXXXXX")}"
export TMPDIR="$SCRATCH"
mkdir -p "$SCRATCH"

fail() {
  echo "release-check FAILED: $1" >&2
  exit 1
}

step() {
  echo "==> $1"
}

require_clean_tree() {
  if [ -n "$(git status --porcelain)" ]; then
    echo "--- git status ---" >&2
    git status --short >&2
    fail "working tree is dirty; release validation requires a clean tree"
  fi
}

step "git clean/dirty check"
require_clean_tree
git rev-parse HEAD

step "cargo fmt --check"
cargo fmt --check || fail "fmt"

step "cargo check --locked"
cargo check --locked || fail "check"

step "cargo test --locked"
cargo test --locked || fail "tests"

step "cargo clippy --all-targets --all-features --locked -- -D warnings"
cargo clippy --all-targets --all-features --locked -- -D warnings || fail "clippy"

step "rustdoc (warnings denied)"
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items || fail "rustdoc"

step "git diff --check"
git diff --check || fail "whitespace"

step "P19 benchmark regression"
cargo run --locked --example phase19_bench > "$SCRATCH/phase19_bench.out" || fail "phase19 bench"
grep -q "scheduler_tasks_completed=1500" "$SCRATCH/phase19_bench.out" || fail "phase19 bench output"

step "P20 release gate benchmark"
cargo run --locked --example phase20_release_gate > "$SCRATCH/phase20_gate.out" || fail "phase20 gate"
grep -q "artifact_checksum_verified=" "$SCRATCH/phase20_gate.out" || fail "phase20 gate output"

step "cargo build --release --locked"
cargo build --release --locked || fail "release build"

step "release binary size + version"
stat -c '%s' target/release/rxscan
./target/release/rxscan --version || fail "version"

step "release smoke (isolated HOME, /tmp cwd)"
SMOKE_HOME="$SCRATCH/fakehome"
mkdir -p "$SMOKE_HOME"
HOME="$SMOKE_HOME" ./target/release/rxscan --help > /dev/null || fail "help"
HOME="$SMOKE_HOME" ./target/release/rxscan 127.0.0.1 --scope 127.0.0.1 --level 1 --ports 9 \
  --checkpoint "$SCRATCH/smoke.rxscan" > /dev/null || fail "smoke scan"
HOME="$SMOKE_HOME" ./target/release/rxscan report --format json "$SCRATCH/smoke.rxscan" \
  > /dev/null || fail "smoke report"

step "offline commands stay offline and succeed"
HOME="$SMOKE_HOME" ./target/release/rxscan diff "$SCRATCH/smoke.rxscan" "$SCRATCH/smoke.rxscan" \
  > /dev/null || fail "diff smoke"
HOME="$SMOKE_HOME" ./target/release/rxscan analyze "$SCRATCH/smoke.rxscan" \
  > /dev/null || fail "analyze smoke"
HOME="$SMOKE_HOME" ./target/release/rxscan project create "$SCRATCH/smoke.rxproj" \
  > /dev/null || fail "project smoke"

if [ "$SKIP_INSTALL" -eq 0 ]; then
  step "isolated cargo install proof"
  INSTALL_ROOT="$SCRATCH/install-root"
  cargo install --locked --path . --root "$INSTALL_ROOT" || fail "cargo install"
  "$INSTALL_ROOT/bin/rxscan" --version || fail "installed version"
  rm -rf "$INSTALL_ROOT"
else
  echo "    (skipped)"
fi

echo "release-check PASSED"
