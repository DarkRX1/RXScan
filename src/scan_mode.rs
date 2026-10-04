use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanMode {
    Connect,
    Syn,
    #[default]
    Auto,
}

impl ScanMode {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "connect" => Ok(Self::Connect),
            "syn" => Ok(Self::Syn),
            "auto" => Ok(Self::Auto),
            other => Err(format!(
                "invalid scan mode '{other}': expected connect, syn, or auto"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Syn => "syn",
            Self::Auto => "auto",
        }
    }
}

impl fmt::Display for ScanMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedMode {
    Connect,
    Syn,
}

impl ResolvedMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Syn => "syn",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeCapability {
    pub privileged: bool,
    pub linux: bool,
    pub raw_supported: bool,
    pub raw_reason: String,
}

impl ModeCapability {
    pub fn probe() -> Self {
        let raw = probe_raw_syn();
        Self {
            privileged: is_privileged(),
            linux: cfg!(target_os = "linux"),
            raw_supported: raw.supported,
            raw_reason: raw.reason,
        }
    }

    pub fn test(privileged: bool, linux: bool) -> Self {
        let (raw_supported, raw_reason) = if privileged && linux {
            (true, "test capability: raw SYN available".to_owned())
        } else {
            (false, "test capability: raw SYN unavailable".to_owned())
        };
        Self {
            privileged,
            linux,
            raw_supported,
            raw_reason,
        }
    }

    pub fn test_raw(raw_supported: bool) -> Self {
        Self {
            privileged: raw_supported,
            linux: true,
            raw_supported,
            raw_reason: if raw_supported {
                "test capability: raw SYN available".to_owned()
            } else {
                "raw SYN unavailable: CAP_NET_RAW not available".to_owned()
            },
        }
    }
}

/// Raw-socket capability probe: can this process open the socket the SYN
/// engine needs? Opens and immediately closes one socket; sends nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCapability {
    pub supported: bool,
    pub reason: String,
}

pub fn probe_raw_syn() -> RawCapability {
    #[cfg(target_os = "linux")]
    {
        const AF_INET: i32 = 2;
        const SOCK_RAW: i32 = 3;
        const IPPROTO_TCP: i32 = 6;
        unsafe extern "C" {
            fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
            fn close(fd: i32) -> i32;
            fn __errno_location() -> *mut i32;
        }
        // SAFETY: socket/close with constant arguments; errno read immediately.
        let fd = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_TCP) };
        if fd >= 0 {
            unsafe { close(fd) };
            return RawCapability {
                supported: true,
                reason: "raw TCP socket available".to_owned(),
            };
        }
        let errno = unsafe { *__errno_location() };
        let reason = match errno {
            1 | 13 => "raw SYN unavailable: CAP_NET_RAW not available".to_owned(),
            93 | 94 => "raw SYN unavailable: socket type unsupported on this platform".to_owned(),
            _ => format!("raw SYN unavailable: socket creation failed (errno {errno})"),
        };
        RawCapability {
            supported: false,
            reason,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        RawCapability {
            supported: false,
            reason: "raw SYN unavailable: Linux-only implementation".to_owned(),
        }
    }
}

fn is_privileged() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid takes no arguments and has no failure mode.
        unsafe { libc_geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(unix)]
unsafe fn libc_geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeResolution {
    pub requested: ScanMode,
    pub resolved: ResolvedMode,
    pub reason: String,
}

impl ModeResolution {
    /// Machine-readable fallback marker for output. `None` when the
    /// effective mechanism is what was requested (explicit or via auto
    /// selection); `Some` only when an explicit `syn` request could not be
    /// honored and connect was substituted.
    pub fn fallback(&self) -> Option<&'static str> {
        match (self.requested, self.resolved) {
            (ScanMode::Syn, ResolvedMode::Connect) => Some("raw_syn_unavailable"),
            _ => None,
        }
    }
}

pub fn resolve(requested: ScanMode, capability: ModeCapability) -> ModeResolution {
    match requested {
        ScanMode::Connect => ModeResolution {
            requested,
            resolved: ResolvedMode::Connect,
            reason: "explicit connect mode".to_owned(),
        },
        ScanMode::Syn if capability.raw_supported => ModeResolution {
            requested,
            resolved: ResolvedMode::Syn,
            reason: "explicit syn mode with raw-socket capability".to_owned(),
        },
        ScanMode::Syn => ModeResolution {
            requested,
            resolved: ResolvedMode::Connect,
            reason: format!(
                "syn requested without raw-socket capability ({}); connect fallback preserves accounting",
                capability.raw_reason
            ),
        },
        ScanMode::Auto if capability.raw_supported => ModeResolution {
            requested,
            resolved: ResolvedMode::Syn,
            reason: "auto selected syn: raw-socket capability present".to_owned(),
        },
        ScanMode::Auto => ModeResolution {
            requested,
            resolved: ResolvedMode::Connect,
            reason: format!("auto selected connect: {}", capability.raw_reason),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modes() {
        assert_eq!(ScanMode::parse("connect"), Ok(ScanMode::Connect));
        assert_eq!(ScanMode::parse("SYN"), Ok(ScanMode::Syn));
        assert_eq!(ScanMode::parse("auto"), Ok(ScanMode::Auto));
        assert!(ScanMode::parse("raw").is_err());
    }

    #[test]
    fn explicit_connect_never_escalates() {
        let out = resolve(ScanMode::Connect, ModeCapability::test(true, true));
        assert_eq!(out.resolved, ResolvedMode::Connect);
    }

    #[test]
    fn syn_without_privilege_falls_back_with_reason() {
        let out = resolve(ScanMode::Syn, ModeCapability::test(false, true));
        assert_eq!(out.resolved, ResolvedMode::Connect);
        assert!(out.reason.contains("fallback"));
        assert_eq!(out.fallback(), Some("raw_syn_unavailable"));
    }

    #[test]
    fn explicit_syn_has_no_fallback_when_honored() {
        let out = resolve(ScanMode::Syn, ModeCapability::test(true, true));
        assert_eq!(out.resolved, ResolvedMode::Syn);
        assert_eq!(out.fallback(), None);
    }

    #[test]
    fn auto_selection_is_not_a_fallback() {
        let out = resolve(ScanMode::Auto, ModeCapability::test(false, true));
        assert_eq!(out.resolved, ResolvedMode::Connect);
        assert_eq!(out.fallback(), None);
    }

    #[test]
    fn raw_probe_reports_usable_reason() {
        let raw = probe_raw_syn();
        assert!(!raw.reason.is_empty());
        if raw.supported {
            assert!(raw.reason.contains("available"));
        } else {
            assert!(raw.reason.contains("unavailable"));
        }
    }

    #[test]
    fn syn_on_non_linux_falls_back() {
        let out = resolve(ScanMode::Syn, ModeCapability::test(true, false));
        assert_eq!(out.resolved, ResolvedMode::Connect);
    }

    #[test]
    fn auto_selects_by_capability() {
        assert_eq!(
            resolve(ScanMode::Auto, ModeCapability::test(true, true)).resolved,
            ResolvedMode::Syn
        );
        assert_eq!(
            resolve(ScanMode::Auto, ModeCapability::test(false, true)).resolved,
            ResolvedMode::Connect
        );
        assert_eq!(
            resolve(ScanMode::Auto, ModeCapability::test(true, false)).resolved,
            ResolvedMode::Connect
        );
    }
}
