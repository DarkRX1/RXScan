#!/usr/bin/env bash
# Package one RXScan release artifact.
# Usage: bash scripts/package-artifact.sh <rust-target> <artifact-name>
# Must run in a known Bash+tar environment (release `package` job on
# ubuntu-latest). Native Windows/macOS build jobs upload raw binaries only;
# they never run this script. No Bash required to *use* RXScan itself.
# Layout per artifact:
#   rxscan[.exe], LICENSE, README excerpt, app/ GUI assets, fingerprints/,
#   search/ provider corpus.
set -euo pipefail
TARGET="${1:?target required}"
ARTIFACT="${2:?artifact name required}"
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"
BIN="target/$TARGET/release/rxscan"
if [[ "$TARGET" == *windows* ]]; then
  BIN="$BIN.exe"
fi
test -f "$BIN" || { echo "missing binary $BIN" >&2; exit 1; }
STAGE="$(mktemp -d)"
mkdir -p "$STAGE/rxscan" dist
cp "$BIN" "$STAGE/rxscan/"
cp LICENSE "$STAGE/rxscan/"
# Minimal usage readme (copy/pasteable per shell; no toolchain required).
cat > "$STAGE/rxscan/README-RXSCAN.txt" <<'EOF'
RXScan — Reconnaissance & Evidence Engine
Run: rxscan --help
Docs: docs/INSTALLATION.md, docs/PLATFORMS.md
License: MIT (see LICENSE)
EOF
# Required runtime assets: fail explicitly if any are missing (no `|| true`
# for required content).
for dir in app fingerprints search; do
  test -d "$dir" || { echo "required asset dir missing: $dir" >&2; exit 1; }
  cp -r "$dir" "$STAGE/rxscan/"
done
# Verify staged content before archiving.
test -f "$STAGE/rxscan/LICENSE" || { echo "LICENSE missing in stage" >&2; exit 1; }
if [[ "$TARGET" == *windows* ]]; then
  test -f "$STAGE/rxscan/rxscan.exe" || { echo "windows binary missing in stage" >&2; exit 1; }
else
  test -f "$STAGE/rxscan/rxscan" || { echo "binary missing in stage" >&2; exit 1; }
fi
test -d "$STAGE/rxscan/app" || { echo "app/ missing in stage" >&2; exit 1; }
test -d "$STAGE/rxscan/fingerprints" || { echo "fingerprints/ missing in stage" >&2; exit 1; }
test -d "$STAGE/rxscan/search" || { echo "search/ missing in stage" >&2; exit 1; }
if [[ "$ARTIFACT" == *.zip ]]; then
  command -v zip >/dev/null || { echo "zip required for $ARTIFACT" >&2; exit 1; }
  (cd "$STAGE" && zip -r "$OLDPWD/dist/$ARTIFACT" rxscan)
else
  tar -czf "dist/$ARTIFACT" -C "$STAGE" rxscan
fi
rm -rf "$STAGE"
echo "packaged dist/$ARTIFACT"
