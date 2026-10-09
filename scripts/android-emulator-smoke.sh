#!/usr/bin/env bash
# Install + launch the RXScan dev APK on the attached emulator and prove
# the embedded Rust core starts its loopback server (logcat proof).
# Usage: bash scripts/android-emulator-smoke.sh '<apk-glob>'
# Offline except for the emulator itself; fails closed.
set -euo pipefail
GLOB="${1:?apk glob required}"
# Intentional glob expansion of the caller-provided pattern.
# shellcheck disable=SC2206
matches=($GLOB)
test "${#matches[@]}" -eq 1 || {
  echo "expected exactly one APK for '$GLOB', found: ${matches[*]:-<none>}" >&2
  exit 1
}
APK="${matches[0]}"
echo "APK=$APK"
adb install "$APK"
adb logcat -c
adb shell am start -n dev.rxscan.app.debug/dev.rxscan.app.MainActivity
for _ in $(seq 1 30); do
  sleep 5
  if adb logcat -d | grep -qE "RXScan.*serving on port [0-9]+"; then
    echo "EMULATOR RUNTIME PROOF:"
    adb logcat -d | grep -E "RXScan" | head -n 10
    exit 0
  fi
done
echo "embedded server start not observed in logcat" >&2
adb logcat -d | tail -n 50 >&2 || true
exit 1
