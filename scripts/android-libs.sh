#!/usr/bin/env bash
# Build the RXScan Rust core as Android shared libraries.
# Usage: bash scripts/android-libs.sh [abi...]
# Default ABIs: arm64-v8a x86_64 (devices + CI emulator).
# Requires ANDROID_NDK_HOME (or ANDROID_NDK_ROOT) with the LLVM prebuilt
# toolchain; API 24 drivers match the documented Android floor.
# Outputs: android/app/src/main/jniLibs/<abi>/librxscan.so
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"
NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
test -n "$NDK" || { echo "ANDROID_NDK_HOME/ANDROID_NDK_ROOT is unset" >&2; exit 1; }
test -d "$NDK" || { echo "NDK dir missing: $NDK" >&2; exit 1; }
BIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
test -d "$BIN" || { echo "NDK llvm bin missing: $BIN" >&2; exit 1; }

build_abi() {
  local abi="$1" target="$2" clang="$3" cc_var="$4" linker_var="$5"
  test -x "$clang" || { echo "NDK clang driver missing: $clang" >&2; exit 1; }
  rustup target add "$target"
  export "$cc_var=$clang"
  export "$linker_var=$clang"
  cargo build --locked --release --target "$target" --lib
  local out="android/app/src/main/jniLibs/$abi"
  mkdir -p "$out"
  cp "target/$target/release/librxscan.so" "$out/"
  echo "staged $out/librxscan.so ($abi)"
}

ABIS="${*:-arm64-v8a x86_64}"
for abi in $ABIS; do
  case "$abi" in
    arm64-v8a)
      build_abi "$abi" "aarch64-linux-android" \
        "$BIN/aarch64-linux-android24-clang" \
        "CC_aarch64_linux_android" \
        "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"
      ;;
    x86_64)
      build_abi "$abi" "x86_64-linux-android" \
        "$BIN/x86_64-linux-android24-clang" \
        "CC_x86_64_linux_android" \
        "CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER"
      ;;
    *) echo "unsupported ABI: $abi" >&2; exit 1 ;;
  esac
done
