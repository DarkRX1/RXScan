# RXScan on Android

Development status: an installable development APK is produced by the
`Distribution artifacts` workflow (manual dispatch; Actions artifacts,
never releases). Released `v1.0.2` has no Android artifact of any kind.
Termux (source-build, experimental) and the APK (normal install) are
separate distributions; see `docs/PLATFORMS.md`.

## Architecture decision

```
              RXScan Rust Core (librxscan.so, same crate)
                              |
                  narrow JNI module (src/android.rs:
                  start/stop/version/capabilities only)
                              |
                  shared RXScan frontend (app/, embedded)
                      /                \
             desktop browser      Android WebView
                                  (loopback HTTP, no bridge)
```

Evaluated options:

- **A. Thin native shell + WebView + Rust native library** — chosen.
  Smallest Kotlin surface (lifecycle + WebView), zero logic duplication,
  no new Rust dependencies (hand-rolled JNI for four functions).
- **B. Shell running the existing local HTTP/API architecture over
  loopback** — adopted as the *runtime* half of A: the APK starts the
  same `web_api::serve` loopback server the desktop `rxscan web`
  command runs (`127.0.0.1`, OS-assigned port, `allow_remote` never
  exposed). The WebView is just a loopback browser for it.
- **C. A Rust/WebView application framework** — rejected: every
  candidate would force a rewrite of the working web/API layer for no
  capability gain, and would add supply-chain surface.

So: **A for packaging, B for runtime, no C**. No scanning logic in
Kotlin/Java/JavaScript, no separate Android GUI codebase — the existing
`app/` frontend is reused verbatim (embedded in the core, responsive
since the mobile CSS pass) and reached over loopback like desktop.

## Capabilities (tested, not assumed)

Android reports the existing restricted environment (`target_os =
"android"` is not `target_os = "linux"`, so raw-packet code is compiled
out; the capability system already maps this honestly):

- Available: TCP connect, DNS, HTTP, TLS, SSH observation,
  public-source search, investigation, evidence graph, projects/history,
  persistence, local web UI.
- Restricted/unavailable, shown as such (never faked): raw packet
  send/capture, ARP/NDP, raw ICMP, active OS fingerprinting probes, some
  UDP ICMP attribution, privileged interface/route detail.
- Never required: root. Do not ask users to root, weaken security, or
  sideload anything beyond the APK itself with their explicit permission.

## Security

- Loopback only: server binds `127.0.0.1` with an OS-assigned port; the
  server refuses non-loopback peers and non-loopback Host/Origin values
  (same gates as desktop). `allow_remote` is not exposed to the app.
- WebView: JavaScript on (the existing frontend needs it); file/content
  access, geolocation, and form/password saving off; no
  `addJavascriptInterface` bridge of any kind — privileged actions only
  happen through the page's own same-origin `/api/v1` calls, which stay
  scope-gated server-side. Cleartext HTTP is permitted only for
  `127.0.0.1`/`localhost` (`network_security_config.xml`); the base
  config stays HTTPS-only. No remote debugging in release builds.
- Signing: development APKs are debug-signed by the normal Gradle flow
  (auto-generated debug keystore, never committed). Production/Play
  signing and AAB publication are out of scope.

## Storage

Project/history/database storage lives in the app-private directory
(`filesDir/rxscan-web`), passed to the core at startup. No Unix-home
assumptions, no hardcoded developer paths. Uninstall follows normal
Android conventions (app-private data goes with the app).

## Building the APK locally

Requires the Android SDK + NDK and Java 17 (CI proves the exact flow):

```sh
# 1. Build the Rust core for Android (from the repo root):
export ANDROID_NDK_HOME=<ndk>   # provides aarch64-linux-android24-clang
bash scripts/android-libs.sh    # -> android/app/src/main/jniLibs/<abi>/librxscan.so
# 2. Assemble (Gradle Wrapper pin in gradle/wrapper/gradle-wrapper.properties):
cd android && gradle assembleDebug
# Output: android/app/build/outputs/apk/debug/app-debug.apk
```

The distributable is renamed to `RXScan-<version>-dev-android-arm64.apk`
by the workflow (version derived from Cargo.toml). Sideloading requires
the user's install permission; debug-signed only.
