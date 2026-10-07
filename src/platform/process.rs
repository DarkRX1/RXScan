//! Portable process helpers: cancellation and browser launching.
//!
//! Process Ctrl-C state has process lifetime by construction. The OS handler
//! performs exactly one atomic store and never allocates, locks, formats,
//! does I/O, or dereferences short-lived state. All registration and reset
//! happens in normal Rust code outside the handler.
//!
//! * Unix (incl. Linux/macOS/Termux/WSL): `signal(SIGINT)` handler.
//! * Windows native: `SetConsoleCtrlHandler` (CTRL_C_EVENT).
//! * Other: polling only (no OS hook; cancellation still works via
//!   deadline/API paths).
//!
//! `CancellationFlag` remains for per-job API cancellation (Web/API jobs,
//! scheduler tasks). It is independent from process Ctrl-C state on purpose:
//! process cancellation and API job cancellation must not couple.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

// SAFETY: process-lifetime Ctrl-C latch. Only atomic load/store from the
// handler (`store(true)`) and from normal code (`load`/`store`). No lock,
// no allocation, no I/O in the handler. `AcqRel` ordering is unnecessary;
// `Release` on store + `Acquire` on load suffices for cancellation polling.
static PROCESS_CANCELLED: AtomicBool = AtomicBool::new(false);

// SAFETY: ensures the OS handler is installed at most once per process.
// `compare_exchange` runs in normal code, never in the handler. Installing
// `signal` twice is idempotent but `SetConsoleCtrlHandler` would stack
// handlers, so once-installation matters on Windows.
static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Process-lifetime cancellation flag. Cheaply cloneable; all clones share
/// one atomic so the handler can never observe a destroyed object.
///
/// This is for per-job/API cancellation, independent from process Ctrl-C.
/// See [`process_cancel_flag`] for process state.
#[derive(Debug, Clone)]
pub struct CancellationFlag {
    inner: Arc<AtomicBool>,
}

impl CancellationFlag {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.load(Ordering::Acquire)
    }

    pub fn cancel(&self) {
        self.inner.store(true, Ordering::Release);
    }

    pub fn reset(&self) {
        self.inner.store(false, Ordering::Release);
    }
}

impl Default for CancellationFlag {
    fn default() -> Self {
        Self::new()
    }
}

/// Direct reference to process Ctrl-C state. Pass this to schedulers that
/// take `&AtomicBool` instead of maintaining a mirror flag.
///
/// Lifetime is `'static` by construction; the handler only stores `true`.
pub fn process_cancel_flag() -> &'static AtomicBool {
    &PROCESS_CANCELLED
}

/// True when Ctrl-C has been observed since the last reset.
pub fn process_cancelled() -> bool {
    PROCESS_CANCELLED.load(Ordering::Acquire)
}

/// Clear process Ctrl-C state. Call at operation start so a previous
/// operation never leaks cancellation into the next one.
pub fn reset_process_cancellation() {
    PROCESS_CANCELLED.store(false, Ordering::Release);
}

/// Test/simulated Ctrl-C without a real signal. Normal code only.
pub fn request_process_cancellation() {
    PROCESS_CANCELLED.store(true, Ordering::Release);
}

#[cfg(unix)]
extern "C" fn unix_cancel_handler(_: i32) {
    // SAFETY: single atomic store, async-signal-safe. No lock/alloc/IO.
    PROCESS_CANCELLED.store(true, Ordering::Release);
}

#[cfg(unix)]
unsafe extern "C" {
    fn signal(signum: i32, handler: usize) -> usize;
}

#[cfg(windows)]
unsafe extern "system" {
    fn SetConsoleCtrlHandler(handler: usize, add: i32) -> i32;
}

#[cfg(windows)]
unsafe extern "system" fn windows_cancel_handler(_event: u32) -> i32 {
    // SAFETY: single atomic store. No lock/alloc/IO. Always claims handled
    // so the process does not terminate before schedulers drain evidence.
    PROCESS_CANCELLED.store(true, Ordering::Release);
    1
}

/// Install the process Ctrl-C handler once and reset process state.
///
/// Idempotent: safe to call before every operation. The OS handler is
/// installed only on the first call; subsequent calls only reset state.
/// No thread is spawned; no per-install growth. Never panics.
///
/// SAFETY notes for the two `unsafe` blocks below:
/// - Unix `signal(2, handler)`: `handler` is a plain `extern "C" fn(i32)`
///   doing one atomic store; reinstalling is idempotent; return ignored
///   because polling/deadlines still cancel.
/// - Windows `SetConsoleCtrlHandler(handler, 1)`: handler does one atomic
///   store and returns 1; installed once via `HANDLER_INSTALLED` so handlers
///   never stack; errors ignored because polling still applies.
pub fn install_process_cancellation() {
    reset_process_cancellation();
    // Install once per process.
    if HANDLER_INSTALLED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    #[cfg(unix)]
    unsafe {
        // SIGINT = 2.
        let _ = signal(2, unix_cancel_handler as *const () as usize);
    }
    #[cfg(windows)]
    unsafe {
        let _ = SetConsoleCtrlHandler(windows_cancel_handler as *const () as usize, 1);
    }
    #[cfg(not(any(unix, windows)))]
    {}
}

/// Legacy per-flag installer. Now only resets the flag and ensures the
/// process handler is installed; it does NOT mirror process state into the
/// flag (no thread, no OnceLock). For process cancellation, pass
/// [`process_cancel_flag`] directly. For per-job cancellation, use
/// [`CancellationFlag`] without this function.
pub fn install_cancellation_handler(flag: &CancellationFlag) {
    flag.reset();
    install_process_cancellation();
}

/// Best-effort default-browser open. Only attempts on interactive
/// terminals; any failure is silent since the server is already usable.
/// `NO_BROWSER` disables it (tests/CI/headless).
pub fn open_browser(base_url: &str) {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        return;
    }
    if std::env::var_os("NO_BROWSER").is_some() {
        return;
    }
    let url = format!("{base_url}/");
    // WSL: prefer Windows browser via powershell when available, else
    // fall back to Linux openers. Git Bash is just a shell: the native
    // Windows opener path still applies there via `cmd /c start`.
    let attempts: &[&[&str]] = if cfg!(target_os = "macos") {
        &[&["open", &url]]
    } else if cfg!(target_os = "windows") {
        &[&["cmd", "/c", "start", "", &url]]
    } else if crate::platform::network::is_wsl() {
        &[
            &[
                "powershell.exe",
                "-NoProfile",
                "-Command",
                &format!("Start-Process '{url}'"),
            ],
            &["xdg-open", &url],
            &["sensible-browser", &url],
        ]
    } else {
        &[
            &["xdg-open", &url],
            &["sensible-browser", &url],
            &["gio", "open", &url],
            &["termux-open-url", &url],
        ]
    };
    for attempt in attempts {
        let mut command = std::process::Command::new(attempt[0]);
        for arg in &attempt[1..] {
            command.arg(arg);
        }
        match command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(_) => return,
            Err(_) => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_cancel_and_reset_roundtrip() {
        let flag = CancellationFlag::new();
        assert!(!flag.is_cancelled());
        flag.cancel();
        assert!(flag.is_cancelled());
        flag.reset();
        assert!(!flag.is_cancelled());
        // Clones share one atomic.
        let other = flag.clone();
        flag.cancel();
        assert!(other.is_cancelled());
    }

    #[test]
    fn install_handler_does_not_panic() {
        let flag = CancellationFlag::new();
        install_cancellation_handler(&flag);
        assert!(!flag.is_cancelled());
    }

    #[test]
    fn repeated_install_resets_without_leak() {
        // First install + simulated Ctrl-C.
        install_process_cancellation();
        assert!(!process_cancelled());
        request_process_cancellation();
        assert!(process_cancelled());
        assert!(process_cancel_flag().load(Ordering::Acquire));
        // Second install resets; old cancellation never leaks.
        install_process_cancellation();
        assert!(!process_cancelled());
        // Repeated Ctrl-C stays latched until reset.
        request_process_cancellation();
        request_process_cancellation();
        assert!(process_cancelled());
        reset_process_cancellation();
        assert!(!process_cancelled());
    }

    #[test]
    fn per_job_flag_stays_independent_from_process() {
        let job = CancellationFlag::new();
        install_process_cancellation();
        request_process_cancellation();
        assert!(process_cancelled());
        // Job flag unaffected by process state (no accidental coupling).
        assert!(!job.is_cancelled());
        job.cancel();
        assert!(job.is_cancelled());
        reset_process_cancellation();
        // Job stays cancelled until its own reset.
        assert!(job.is_cancelled());
        job.reset();
        assert!(!job.is_cancelled());
    }
}
