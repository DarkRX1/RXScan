#!/usr/bin/env bash
# Package one RXScan distribution artifact with a version-derived name.
#
# Usage:
#   bash scripts/package-artifact.sh <rust-target> [artifact-name]
#   bash scripts/package-artifact.sh --print-name <rust-target>
#
# Names are derived from Cargo.toml version + target metadata, never from
# scattered hardcoded release numbers:
#   RXScan-<version>[-dev]-<os>-<arch>.tar.gz|.zip
# Set RXSCAN_DEV=1 (or DIST_SUFFIX=-dev) for development artifacts so nobody
# mistakes them for an official release. Official (tagged-release) builds
# leave the suffix empty. RXSCAN_VERSION overrides version detection
# (used by tests; production derives it from Cargo metadata).
#
# Must run in a known Bash+tar environment (packaging jobs on
# ubuntu-latest). Native Windows/macOS build jobs upload raw binaries only;
# they never run this script. No Bash required to *use* RXScan itself.
#
# Layout per artifact (flat, at archive root):
#   rxscan[.exe], README.md, LICENSE, app/ GUI reference assets,
#   fingerprints/, search/ provider corpus.
# The binary itself embeds the GUI + username pack, so CLI/GUI work with no
# toolchain; fingerprints/search sidecars keep full-fidelity behavior
# instead of silently degraded corpora.
set -euo pipefail

print_name() {
  TARGET="${1:?target required}"
  case "$TARGET" in
    x86_64-unknown-linux-gnu) OSARCH="linux-x86_64"; EXT="tar.gz" ;;
    aarch64-unknown-linux-gnu) OSARCH="linux-aarch64"; EXT="tar.gz" ;;
    x86_64-unknown-linux-musl) OSARCH="linux-x86_64-musl"; EXT="tar.gz" ;;
    aarch64-unknown-linux-musl) OSARCH="linux-aarch64-musl"; EXT="tar.gz" ;;
    x86_64-pc-windows-msvc) OSARCH="windows-x86_64"; EXT="zip" ;;
    aarch64-apple-darwin) OSARCH="macos-arm64"; EXT="tar.gz" ;;
    x86_64-apple-darwin) OSARCH="macos-x86_64"; EXT="tar.gz" ;;
    *) echo "unsupported target: $TARGET (no platform/arch mapping)" >&2; exit 1 ;;
  esac
  if [ -n "${RXSCAN_VERSION:-}" ]; then
    VERSION="$RXSCAN_VERSION"
  elif command -v cargo >/dev/null 2>&1; then
    VERSION="$(cargo metadata --format-version 1 --no-deps 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["version"])')"
  else
    VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)"
  fi
  test -n "${VERSION:-}" || { echo "cannot determine package version" >&2; exit 1; }
  SUFFIX="${DIST_SUFFIX:-}"
  if [ "${RXSCAN_DEV:-0}" = "1" ] && [ -z "$SUFFIX" ]; then
    SUFFIX="-dev"
  fi
  echo "RXScan-${VERSION}${SUFFIX}-${OSARCH}.${EXT}"
}

if [ "${1:-}" = "--print-name" ]; then
  print_name "${2:?target required}"
  exit 0
fi

TARGET="${1:?target required}"
ARTIFACT="${2:-}"
if [ -z "$ARTIFACT" ]; then
  ARTIFACT="$(print_name "$TARGET")"
fi
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"
BIN="target/$TARGET/release/rxscan"
if [[ "$TARGET" == *windows* ]]; then
  BIN="$BIN.exe"
fi
test -f "$BIN" || { echo "missing binary $BIN" >&2; exit 1; }
STAGE="$(mktemp -d)"
mkdir -p "$STAGE" dist
cp "$BIN" "$STAGE/"
cp LICENSE "$STAGE/"
cp README.md "$STAGE/"
# Required runtime sidecars: fail explicitly if any are missing (no `|| true`
# for required content).
for dir in app fingerprints search; do
  test -d "$dir" || { echo "required asset dir missing: $dir" >&2; exit 1; }
  cp -r "$dir" "$STAGE/"
done
# Verify staged content before archiving.
test -f "$STAGE/LICENSE" || { echo "LICENSE missing in stage" >&2; exit 1; }
test -f "$STAGE/README.md" || { echo "README.md missing in stage" >&2; exit 1; }
if [[ "$TARGET" == *windows* ]]; then
  test -f "$STAGE/rxscan.exe" || { echo "windows binary missing in stage" >&2; exit 1; }
else
  test -f "$STAGE/rxscan" || { echo "binary missing in stage" >&2; exit 1; }
  chmod +x "$STAGE/rxscan"
fi
test -d "$STAGE/app" || { echo "app/ missing in stage" >&2; exit 1; }
test -d "$STAGE/fingerprints" || { echo "fingerprints/ missing in stage" >&2; exit 1; }
test -d "$STAGE/search" || { echo "search/ missing in stage" >&2; exit 1; }
if [[ "$ARTIFACT" == *.zip ]]; then
  command -v zip >/dev/null || { echo "zip required for $ARTIFACT" >&2; exit 1; }
  rm -f "dist/$ARTIFACT"
  (cd "$STAGE" && zip -r "$OLDPWD/dist/$ARTIFACT" .) >/dev/null
else
  tar -czf "dist/$ARTIFACT" -C "$STAGE" .
fi
rm -rf "$STAGE"
echo "packaged dist/$ARTIFACT"
