# RXScan on iOS (evaluation)

Status: evaluation only. No iOS artifact ships yet. Android remains the
reference mobile embedding (`docs/ANDROID.md`); iOS reuses the same
architecture: Rust core + loopback web API + shared `app/` frontend.

## Architecture options

### A. WebKit WebView + Rust staticlib (recommended for evaluation)
- Build `rxscan` as a `staticlib` (or reuse `cdylib` via a thin shim) and
  link into a Swift app.
- Run the existing `web_api::serve` loopback server on `127.0.0.1` with an
  OS-assigned port; the `WKWebView` loads `http://127.0.0.1:<port>`.
- Reuses `app/` verbatim; zero frontend rewrite; security model identical
  to desktop/Android (loopback peer checks, Host/Origin gates).
- Cost: Xcode toolchain, Apple Developer Program for distribution.

### B. Native Swift bridge (not recommended)
- Hand-rolled Swift wrappers around FFI calls, duplicating the web API.
- Higher maintenance, no capability gain; rejected (same reasoning as
  Android option C).

Decision: **A for packaging, reuse loopback runtime (option B from Android).**
No scanning logic in Swift; the WebView is a loopback browser.

## Build: staticlib vs cdylib
- iOS prefers `staticlib` (`.a`) linked into the app bundle; `cdylib`
  (`.dylib`) is possible but complicates signing/sandboxing and is
  discouraged for App Store.
- Current crate ships `cdylib` + `rlib`. Adding `staticlib` to
  `crate-type` is a one-line change and produces `librxscan.a` for the
  `aarch64-apple-ios` target. Recommended when an iOS target is added.

## Distribution paths
- Free 7-day sideload: personal Apple ID, app expires after 7 days and
  must be re-signed/reinstalled. Suitable for development only.
- $99/year Apple Developer Program: TestFlight (90-day beta builds) and
  App Store distribution. Required for any real user reach.
- Enterprise program: not applicable (internal-only, no public release).

## Mobile testing matrix

| Capability | Desktop | Android | iOS (eval) |
| --- | --- | --- | --- |
| TCP connect scan | yes | yes | yes (via core) |
| DNS | yes | yes | yes |
| HTTP/TLS web | yes | yes | yes |
| Raw ICMP/ARP/NDP | yes (privileged) | no | no |
| Active OS fingerprint | yes | no | no |
| Local web UI | yes | yes (loopback) | yes (loopback) |
| Offline caching | n/a | limited | limited (WebKit cache) |
| Background scan | yes | limited | very limited (iOS suspends) |
| Camera QR scope import | n/a | possible | possible (AVFoundation) |

## Limitations
- iOS aggressively suspends background apps; long scans must be foreground
  or use background-task APIs with short windows.
- No raw sockets without entitlements; raw ICMP/ARP/NDP stay compiled out
  under `target_os = "ios"`, matching Android.
- WebView JavaScript must stay enabled for the shared frontend.
- Free sideload builds expire every 7 days.

## CI
A macOS workflow (`.github/workflows/ios.yml`) builds the Rust core for
`aarch64-apple-ios` to catch compile regressions; it does not produce a
signed app.
