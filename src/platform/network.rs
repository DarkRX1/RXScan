//! Portable networking helpers: detection, error normalization, and
//! bounded portable connect support.
//!
//! Raw libc constants (`__errno_location`, Linux `poll`, AF_PACKET) must not
//! leak into core evidence classification. This module normalizes
//! platform-specific errors before they reach evidence, and exposes runtime
//! environment probes (WSL, Termux) used by capability detection.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

/// True when running under Windows Subsystem for Linux.
///
/// Detection is best-effort: checks `WSL_DISTRO_NAME`/`WSL_INTEROP` plus
/// `/proc/version` or `/proc/sys/kernel/osrelease` for Microsoft/WSL
/// markers. Never panics; missing files mean "not WSL".
pub fn is_wsl() -> bool {
    if std::env::var_os("WSL_DISTRO_NAME").is_some() || std::env::var_os("WSL_INTEROP").is_some() {
        return true;
    }
    for path in ["/proc/version", "/proc/sys/kernel/osrelease"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            let lower = text.to_ascii_lowercase();
            if lower.contains("microsoft") || lower.contains("wsl") {
                return true;
            }
        }
    }
    false
}

/// True when running inside Termux on Android.
///
/// Checks `TERMUX_VERSION`/`PREFIX` plus the Termux data prefix. Never
/// panics.
pub fn is_termux() -> bool {
    if std::env::var_os("TERMUX_VERSION").is_some() {
        return true;
    }
    if let Some(prefix) = std::env::var_os("PREFIX") {
        let s = prefix.to_string_lossy().to_ascii_lowercase();
        if s.contains("com.termux") {
            return true;
        }
    }
    std::path::Path::new("/data/data/com.termux").exists()
}

/// Normalize a platform I/O error into RXScan's stable error taxonomy.
///
/// Linux `connection refused` and Windows `WSAECONNREFUSED (10061)` map to
/// the same evidence meaning; timeouts stay timeouts; permission failures
/// never become "host closed". Unknown errors map to `other` without losing
/// the original message upstream.
pub fn normalize_io_error(error: &io::Error) -> crate::execution::ErrorCategory {
    use crate::execution::ErrorCategory;
    // Prefer ErrorKind (portable) first, then raw OS codes for Windows WSA
    // and Unix errno parity.
    match error.kind() {
        io::ErrorKind::ConnectionRefused => return ErrorCategory::ConnectionRefused,
        // `ConnectionReset` on a connect path means the peer answered with
        // RST: same evidence as refused (host responded, port closed). The
        // portable TCP scanner maps this to Closed; other contexts keep it
        // as refused-equivalent and never as timeout.
        io::ErrorKind::ConnectionReset => return ErrorCategory::ConnectionRefused,
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => {
            return ErrorCategory::ConnectTimeout;
        }
        io::ErrorKind::PermissionDenied => return ErrorCategory::PermissionDenied,
        io::ErrorKind::AddrNotAvailable | io::ErrorKind::NetworkUnreachable => {
            return ErrorCategory::NetworkUnreachable;
        }
        io::ErrorKind::HostUnreachable => return ErrorCategory::HostUnreachable,
        // Invalid socket/argument are programming errors, never network
        // evidence. They stay `Other` → `Error`, never Closed/timeout.
        io::ErrorKind::InvalidInput | io::ErrorKind::NotConnected => return ErrorCategory::Other,
        _ => {}
    }
    if let Some(code) = error.raw_os_error() {
        match code {
            // Unix errno parity. 104 ECONNRESET answered RST → Closed.
            111 | 104 => return ErrorCategory::ConnectionRefused,
            110 | 60 => return ErrorCategory::ConnectTimeout,
            113 => return ErrorCategory::HostUnreachable,
            101 | 51 | 65 => return ErrorCategory::NetworkUnreachable,
            13 | 1 => return ErrorCategory::PermissionDenied,
            24 | 23 | 12 => return ErrorCategory::FdExhaustion,
            // Windows WSA parity. 10035 WOULDBLOCK in a timeout context is
            // a timeout; 10054 ECONNRESET answered RST → Closed;
            // 10038/10022 (NOTSOCK/INVAL) are programming errors → Other.
            10060 | 10061 | 10064 | 10065 | 10051 | 10013 | 10055 | 10024 | 10053 | 10054
            | 10035 | 10038 | 10022 => {
                return match code {
                    10061 | 10054 => ErrorCategory::ConnectionRefused,
                    10060 | 10035 => ErrorCategory::ConnectTimeout,
                    10064 => ErrorCategory::HostUnreachable,
                    10051 => ErrorCategory::NetworkUnreachable,
                    10013 => ErrorCategory::PermissionDenied,
                    10055 | 10024 | 10053 => ErrorCategory::ResourceExhaustion,
                    // 10038 NOTSOCK, 10022 INVAL, 10065 TRY_AGAIN, others:
                    // internal error surface, never fake network evidence.
                    _ => ErrorCategory::Other,
                };
            }
            _ => {}
        }
    }
    let lower = error.to_string().to_ascii_lowercase();
    crate::execution::classify_error_detail(&lower)
}

/// Portable bounded TCP connect used by non-Linux fallbacks and tests.
///
/// Uses `TcpStream::connect_timeout` (available on all Rust targets) so no
/// raw `poll(2)`/`__errno_location` linkage is required outside Linux.
pub fn tcp_connect(addr: SocketAddr, timeout: Duration) -> io::Result<std::net::TcpStream> {
    std::net::TcpStream::connect_timeout(&addr, timeout)
}

/// Classify a raw OS errno/WSA code without an `io::Error` wrapper.
/// Useful for scanners that observe `SO_ERROR` directly on Linux.
pub fn normalize_errno(errno: i32) -> crate::execution::ErrorCategory {
    use crate::execution::ErrorCategory;
    match errno {
        111 | 104 | 10061 | 10054 => ErrorCategory::ConnectionRefused,
        110 | 60 | 10060 | 10035 => ErrorCategory::ConnectTimeout,
        113 | 10064 => ErrorCategory::HostUnreachable,
        101 | 51 | 65 | 10051 => ErrorCategory::NetworkUnreachable,
        13 | 1 | 10013 => ErrorCategory::PermissionDenied,
        24 | 23 | 12 => ErrorCategory::FdExhaustion,
        _ => ErrorCategory::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_and_linux_refused_map_together() {
        let linux = io::Error::from_raw_os_error(111);
        let windows = io::Error::from_raw_os_error(10061);
        let kinded = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        assert_eq!(
            normalize_io_error(&linux),
            crate::execution::ErrorCategory::ConnectionRefused
        );
        assert_eq!(
            normalize_io_error(&windows),
            crate::execution::ErrorCategory::ConnectionRefused
        );
        assert_eq!(
            normalize_io_error(&kinded),
            crate::execution::ErrorCategory::ConnectionRefused
        );
    }

    #[test]
    fn timeouts_stay_timeouts_and_permission_stays_permission() {
        assert_eq!(
            normalize_io_error(&io::Error::new(io::ErrorKind::TimedOut, "t")),
            crate::execution::ErrorCategory::ConnectTimeout
        );
        assert_eq!(
            normalize_io_error(&io::Error::from_raw_os_error(10060)),
            crate::execution::ErrorCategory::ConnectTimeout
        );
        assert_eq!(
            normalize_io_error(&io::Error::new(io::ErrorKind::PermissionDenied, "p")),
            crate::execution::ErrorCategory::PermissionDenied
        );
        assert_eq!(
            normalize_io_error(&io::Error::from_raw_os_error(10013)),
            crate::execution::ErrorCategory::PermissionDenied
        );
    }

    #[test]
    fn windows_reset_is_closed_wouldblock_is_timeout_invalid_is_error() {
        // 10054 ECONNRESET answered RST → Closed (refused-equivalent).
        assert_eq!(
            normalize_io_error(&io::Error::from_raw_os_error(10054)),
            crate::execution::ErrorCategory::ConnectionRefused
        );
        assert_eq!(
            normalize_errno(10054),
            crate::execution::ErrorCategory::ConnectionRefused
        );
        // 10035 WOULDBLOCK in timeout context → timeout/retry.
        assert_eq!(
            normalize_io_error(&io::Error::from_raw_os_error(10035)),
            crate::execution::ErrorCategory::ConnectTimeout
        );
        // 10038 NOTSOCK / 10022 INVAL are programming errors → Error.
        assert_eq!(
            normalize_io_error(&io::Error::from_raw_os_error(10038)),
            crate::execution::ErrorCategory::Other
        );
        assert_eq!(
            normalize_io_error(&io::Error::from_raw_os_error(10022)),
            crate::execution::ErrorCategory::Other
        );
        // ErrorKind equivalents stay honest.
        assert_eq!(
            normalize_io_error(&io::Error::new(io::ErrorKind::ConnectionReset, "reset")),
            crate::execution::ErrorCategory::ConnectionRefused
        );
        assert_eq!(
            normalize_io_error(&io::Error::new(io::ErrorKind::WouldBlock, "would block")),
            crate::execution::ErrorCategory::ConnectTimeout
        );
        assert_eq!(
            normalize_io_error(&io::Error::new(io::ErrorKind::InvalidInput, "bad fd")),
            crate::execution::ErrorCategory::Other
        );
    }

    #[test]
    fn detectors_never_panic() {
        let _ = is_wsl();
        let _ = is_termux();
    }

    #[test]
    fn loopback_connect_or_refused_is_not_a_panic() {
        // Loopback connect to a closed port must either refuse or (in a
        // sandboxed CI) fail with a normalized category — never panic.
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        match tcp_connect(addr, Duration::from_millis(200)) {
            Ok(stream) => drop(stream),
            Err(error) => {
                let _ = normalize_io_error(&error);
            }
        }
    }
}
