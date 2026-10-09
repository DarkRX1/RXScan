#!/usr/bin/env bash
# Smoke-test a packaged RXScan distribution archive AFTER extraction.
# Usage: bash scripts/dist-smoke.sh <archive> [--build-only]
#   (default)  extract, verify layout, run --version, capabilities
#              (human + --json), and an offline loopback GUI smoke test
#              (`rxscan web --port 0` + /api/v1/health + / page check).
#   --build-only  extraction + layout/file checks only (no execution):
#              for artifacts whose arch cannot run on this host.
# Offline/local only. Fails closed on the first problem.
set -euo pipefail
ARCHIVE="${1:?archive required}"
MODE="${2:-native}"
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
test -f "$ARCHIVE" || { echo "archive missing: $ARCHIVE" >&2; exit 1; }
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
case "$ARCHIVE" in
  *.zip)
    command -v unzip >/dev/null || { echo "unzip required" >&2; exit 1; }
    unzip -q "$ARCHIVE" -d "$WORK"
    ;;
  *.tar.gz)
    tar -xzf "$ARCHIVE" -C "$WORK"
    ;;
  *) echo "unsupported archive: $ARCHIVE" >&2; exit 1 ;;
esac
echo "--- extracted layout ---"
ls "$WORK"
EXE="$WORK/rxscan"
if [ -f "$WORK/rxscan.exe" ]; then
  EXE="$WORK/rxscan.exe"
fi
test -f "$EXE" || { echo "binary missing after extraction" >&2; exit 1; }
test -f "$WORK/LICENSE" || { echo "LICENSE missing after extraction" >&2; exit 1; }
test -f "$WORK/README.md" || { echo "README.md missing after extraction" >&2; exit 1; }
test -d "$WORK/app" || { echo "app/ missing after extraction" >&2; exit 1; }
test -d "$WORK/fingerprints" || { echo "fingerprints/ missing after extraction" >&2; exit 1; }
test -d "$WORK/search" || { echo "search/ missing after extraction" >&2; exit 1; }
echo "layout OK: $(basename "$EXE") + README.md + LICENSE + app/ + fingerprints/ + search/"
if [ "$MODE" = "--build-only" ]; then
  echo "build-only: skipping execution"
  exit 0
fi
if [[ "$EXE" == *.exe ]]; then
  echo "native Windows artifact on non-Windows host: layout only" >&2
  exit 1
fi
chmod +x "$EXE"
echo "--- rxscan --version ---"
"$EXE" --version
echo "--- rxscan capabilities ---"
"$EXE" capabilities >/dev/null
echo "--- rxscan capabilities --json ---"
CAPS_JSON="$("$EXE" capabilities --json)"
echo "$CAPS_JSON" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "capabilities" in d or "environment" in d, d.keys()'
echo "capabilities JSON parses"
echo "--- offline GUI smoke (loopback web, OS-assigned port) ---"
WEBDIR="$WORK/webdata"
mkdir -p "$WEBDIR"
LOG="$WORK/web.log"
"$EXE" web --port 0 --no-open --data-dir "$WEBDIR" >"$LOG" 2>&1 &
SERVER_PID=$!
BASE=""
for _ in $(seq 1 100); do
  sleep 0.2
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "server exited early:" >&2; cat "$LOG" >&2; exit 1
  fi
  BASE="$(grep -Eo 'http://127\.0\.0\.1:[0-9]+' "$LOG" | head -n 1 || true)"
  if [ -n "$BASE" ]; then break; fi
done
test -n "$BASE" || { echo "no Listening URL in log:" >&2; cat "$LOG" >&2; kill "$SERVER_PID" 2>/dev/null || true; exit 1; }
echo "GUI up at $BASE"
HEALTH="$(python3 - "$BASE" <<'EOF'
import json,sys,urllib.request
base = sys.argv[1]
with urllib.request.urlopen(base + "/api/v1/health", timeout=10) as r:
    body = json.load(r)
assert body.get("status") == "ok", body
print("health ok")
EOF
)"
echo "$HEALTH"
python3 - "$BASE" <<'EOF'
import sys,urllib.request
base = sys.argv[1]
with urllib.request.urlopen(base + "/", timeout=10) as r:
    page = r.read().decode("utf-8", "replace")
assert "RXScan" in page, "GUI page lacks RXScan marker"
print("GUI page ok")
EOF
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
echo "smoke PASSED for $ARCHIVE"
