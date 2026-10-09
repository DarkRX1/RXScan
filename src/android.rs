//! Android embedding: run the existing RXScan core inside an Android app
//! process and serve the shared frontend over loopback.
//!
//! Architecture (see `docs/ANDROID.md`): thin native shell + WebView +
//! Rust core in-process. No logic is reimplemented: the Android shell owns
//! lifecycle/permissions, starts the same `web_api::serve` loopback server
//! the desktop `rxscan web` command runs, and the WebView loads the same
//! embedded GUI (`app/`) over `http://127.0.0.1:<port>/`.
//!
//! Security: loopback-only bind (the server itself refuses non-loopback
//! peers and non-loopback Host/Origin values), no `allow_remote` exposure,
//! no arbitrary-command bridge — the JNI surface is four narrowly typed
//! functions (start/stop/version/capabilities). Storage uses the
//! app-private directory passed in from Kotlin; no Unix-home assumptions.
//!
//! Capability honesty comes free: `target_os = "android"` is not
//! `target_os = "linux"`, so raw-packet paths are compiled out and the
//! existing capability system reports them unavailable/restricted, exactly
//! as on other restricted platforms.

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use crate::web_api::{self, WebOptions};

/// Process-wide embedded server state. One server per process; start is
/// idempotent and returns the already-bound port on repeat calls.
static SERVER: OnceLock<Mutex<Option<web_api::ServerHandle>>> = OnceLock::new();

/// Last error text for `last_error()` (narrow typed error channel, no
/// panics across FFI).
static LAST_ERROR: OnceLock<Mutex<String>> = OnceLock::new();

fn server_slot() -> &'static Mutex<Option<web_api::ServerHandle>> {
    SERVER.get_or_init(|| Mutex::new(None))
}

fn set_last_error(message: String) {
    *LAST_ERROR
        .get_or_init(|| Mutex::new(String::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = message;
}

/// Start the loopback RXScan server against an app-private data directory.
/// Returns the bound port. Repeat calls return the existing port.
pub fn start_server(data_dir: &str) -> Result<u16, String> {
    let mut slot = server_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(handle) = slot.as_ref() {
        return Ok(handle.port());
    }
    if data_dir.trim().is_empty() {
        let message = "data directory must not be empty".to_owned();
        set_last_error(message.clone());
        return Err(message);
    }
    let options = WebOptions {
        bind: "127.0.0.1".to_owned(),
        port: 0,
        data_dir: PathBuf::from(data_dir),
        allow_remote: false,
        fixture_investigation: false,
    };
    match web_api::serve(options) {
        Ok(handle) => {
            let port = handle.port();
            *slot = Some(handle);
            Ok(port)
        }
        Err(error) => {
            let message = format!("failed to start RXScan server: {error}");
            set_last_error(message.clone());
            Err(message)
        }
    }
}

/// Stop the embedded server if running. Idempotent.
pub fn stop_server() {
    let mut slot = server_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(handle) = slot.take() {
        handle.shutdown();
    }
}

/// Bound loopback port of the running embedded server, if any.
pub fn server_port() -> Option<u16> {
    server_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .map(|handle| handle.port())
}

/// Crate version (same core as desktop; single source of truth).
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Machine-readable capability report (same `capabilities::probe()` the
/// desktop CLI emits with `--json`; restricted entries stay restricted).
pub fn capabilities_json() -> String {
    serde_json::to_string(&crate::capabilities::probe())
        .unwrap_or_else(|_| "{\"error\":\"serialize\"}".to_owned())
}

/// Last error text, empty when no error was recorded.
pub fn last_error() -> String {
    LAST_ERROR
        .get_or_init(|| Mutex::new(String::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

// ---------------------------------------------------------------------------
// Minimal JNI bindings (Android only). Hand-rolled against the stable JNI
// function table so no new crate dependency is needed for four narrow
// functions. Indices follow jni.h and are stable across JVMs:
// NewStringUTF = 167, GetStringUTFChars = 169,
// ReleaseStringUTFChars = 170.
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "android", test))]
mod jni {
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_int, c_void};

    pub type Jint = c_int;
    pub type Jstring = *mut c_void;
    pub type Jclass = *mut c_void;
    pub type JNIEnv = *mut c_void;

    type GetStringUtfChars = unsafe extern "C" fn(*mut c_void, Jstring, *const u8) -> *const c_char;
    type ReleaseStringUtfChars = unsafe extern "C" fn(*mut c_void, Jstring, *const c_char);
    type NewStringUtf = unsafe extern "C" fn(*mut c_void, *const c_char) -> Jstring;

    unsafe fn table_entry<T>(env: JNIEnv, index: usize) -> T
    where
        T: Copy,
    {
        // SAFETY: env is a valid JNIEnv whose function table is alive for
        // the call; indices follow the stable jni.h layout.
        unsafe {
            let table = *(env as *const *const *const c_void);
            *table.add(index).cast::<T>()
        }
    }

    pub unsafe fn jstring_to_rust(env: JNIEnv, value: Jstring) -> String {
        if value.is_null() {
            return String::new();
        }
        // SAFETY: env/value come from the calling JVM frame.
        unsafe {
            let get: GetStringUtfChars = table_entry(env, 169);
            let chars = get(env as *mut c_void, value, std::ptr::null());
            if chars.is_null() {
                return String::new();
            }
            let text = CStr::from_ptr(chars).to_string_lossy().into_owned();
            let release: ReleaseStringUtfChars = table_entry(env, 170);
            release(env as *mut c_void, value, chars);
            text
        }
    }

    pub unsafe fn rust_to_jstring(env: JNIEnv, text: &str) -> Jstring {
        let owned = CString::new(text).unwrap_or_default();
        // SAFETY: env comes from the calling JVM frame.
        unsafe {
            let new: NewStringUtf = table_entry(env, 167);
            new(env as *mut c_void, owned.as_ptr())
        }
    }

    /// Package `dev.rxscan.app`, Kotlin `RustBridge` companion `@JvmStatic`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn Java_dev_rxscan_app_RustBridge_startServer(
        env: JNIEnv,
        _cls: Jclass,
        data_dir: Jstring,
    ) -> Jint {
        // SAFETY: called by the JVM with a valid env/object args.
        let dir = unsafe { jstring_to_rust(env, data_dir) };
        match super::start_server(&dir) {
            Ok(port) => i32::from(port),
            Err(_) => -1,
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn Java_dev_rxscan_app_RustBridge_stopServer(_env: JNIEnv, _cls: Jclass) {
        super::stop_server();
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn Java_dev_rxscan_app_RustBridge_version(
        env: JNIEnv,
        _cls: Jclass,
    ) -> Jstring {
        // SAFETY: called by the JVM with a valid env.
        unsafe { rust_to_jstring(env, &super::version()) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn Java_dev_rxscan_app_RustBridge_capabilitiesJson(
        env: JNIEnv,
        _cls: Jclass,
    ) -> Jstring {
        // SAFETY: called by the JVM with a valid env.
        unsafe { rust_to_jstring(env, &super::capabilities_json()) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn Java_dev_rxscan_app_RustBridge_lastError(
        env: JNIEnv,
        _cls: Jclass,
    ) -> Jstring {
        // SAFETY: called by the JVM with a valid env.
        unsafe { rust_to_jstring(env, &super::last_error()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    /// The embedded server is process-global: tests touching it must hold
    /// this lock for their whole body, or parallel scheduling makes
    /// start/stop assertions race (observed on hosted macOS runners).
    fn serial() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn version_matches_package() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn capabilities_json_parses_with_environment() {
        let parsed: serde_json::Value =
            serde_json::from_str(&capabilities_json()).expect("valid JSON");
        assert!(parsed.get("environment").is_some());
    }

    #[test]
    fn empty_data_dir_is_rejected_not_started() {
        let _guard = serial()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        stop_server();
        assert!(start_server("").is_err());
        assert!(!last_error().is_empty());
        assert!(server_port().is_none());
    }

    #[test]
    fn embedded_server_starts_idempotent_on_loopback() {
        let _guard = serial()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        stop_server();
        let dir = std::env::temp_dir().join(format!("rxscan-android-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = start_server(&dir.to_string_lossy()).expect("start");
        assert!(first > 0);
        assert_eq!(server_port(), Some(first));
        let second = start_server(&dir.to_string_lossy()).expect("restart");
        assert_eq!(first, second, "repeat start returns the bound port");
        stop_server();
        assert!(server_port().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
