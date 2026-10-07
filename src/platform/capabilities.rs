//! Typed platform capability model.
//!
//! RXScan stops assuming every runtime can perform every networking
//! operation. Capabilities are detected at runtime where possible rather
//! than inferred purely from the OS name (e.g. Termux supports TCP connect
//! but generally lacks raw packet transmission).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Runtime environment. `Other` preserves the raw OS string so future
/// platforms degrade honestly instead of misreporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Environment {
    LinuxNative,
    WindowsNative,
    WindowsWsl,
    MacOs,
    AndroidTermux,
    UnknownUnix,
    Other { os: String },
}

impl Environment {
    pub fn as_str(&self) -> String {
        match self {
            Self::LinuxNative => "linux_native".to_owned(),
            Self::WindowsNative => "windows_native".to_owned(),
            Self::WindowsWsl => "windows_wsl".to_owned(),
            Self::MacOs => "macos".to_owned(),
            Self::AndroidTermux => "android_termux".to_owned(),
            Self::UnknownUnix => "unknown_unix".to_owned(),
            Self::Other { os } => format!("other:{os}"),
        }
    }
}

/// Actual operations RXScan may attempt. Names are stable for machine
/// output; human labels live in `capabilities.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    TcpConnectScan,
    UdpScan,
    RawPacketSend,
    RawPacketCapture,
    InterfaceEnumeration,
    RouteEnumeration,
    PassiveOsInference,
    ActiveOsFingerprinting,
    TlsCollection,
    SshCollection,
    HttpCollection,
    DnsIntelligence,
    PublicSourceSearch,
    LocalWebUi,
    SignalCancellation,
    ProjectPersistence,
}

impl Capability {
    pub fn all() -> &'static [Self] {
        &[
            Self::TcpConnectScan,
            Self::UdpScan,
            Self::RawPacketSend,
            Self::RawPacketCapture,
            Self::InterfaceEnumeration,
            Self::RouteEnumeration,
            Self::PassiveOsInference,
            Self::ActiveOsFingerprinting,
            Self::TlsCollection,
            Self::SshCollection,
            Self::HttpCollection,
            Self::DnsIntelligence,
            Self::PublicSourceSearch,
            Self::LocalWebUi,
            Self::SignalCancellation,
            Self::ProjectPersistence,
        ]
    }

    pub fn id(self) -> &'static str {
        match self {
            Self::TcpConnectScan => "tcp_connect_scan",
            Self::UdpScan => "udp_scan",
            Self::RawPacketSend => "raw_packet_send",
            Self::RawPacketCapture => "raw_packet_capture",
            Self::InterfaceEnumeration => "interface_enumeration",
            Self::RouteEnumeration => "route_enumeration",
            Self::PassiveOsInference => "passive_os_inference",
            Self::ActiveOsFingerprinting => "active_os_fingerprinting",
            Self::TlsCollection => "tls_collection",
            Self::SshCollection => "ssh_collection",
            Self::HttpCollection => "http_collection",
            Self::DnsIntelligence => "dns_intelligence",
            Self::PublicSourceSearch => "public_source_search",
            Self::LocalWebUi => "local_web_ui",
            Self::SignalCancellation => "signal_cancellation",
            Self::ProjectPersistence => "project_persistence",
        }
    }
}

/// Availability of one capability. Restricted and unavailable states carry
/// a human reason; machine output keeps the structured triple.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "reason")]
pub enum CapabilityStatus {
    Available,
    Restricted { reason: String },
    Unavailable { reason: String },
}

impl CapabilityStatus {
    pub fn available(&self) -> bool {
        matches!(self, Self::Available)
    }

    pub fn detail(&self, available_detail: &str) -> String {
        match self {
            Self::Available => available_detail.to_owned(),
            Self::Restricted { reason } | Self::Unavailable { reason } => reason.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformInfo {
    pub os: String,
    pub arch: String,
    pub environment: Environment,
    pub capabilities: BTreeMap<String, CapabilityStatus>,
}

impl PlatformInfo {
    pub fn get(&self, capability: Capability) -> Option<&CapabilityStatus> {
        self.capabilities.get(capability.id())
    }

    pub fn is_available(&self, capability: Capability) -> bool {
        self.get(capability).is_some_and(|s| s.available())
    }

    /// Controlled explanation for an unavailable capability. Returns `None`
    /// when the capability is available so callers emit no noise.
    pub fn explanation(&self, capability: Capability, fallback: &str) -> Option<String> {
        match self.get(capability) {
            Some(CapabilityStatus::Available) | None => None,
            Some(CapabilityStatus::Restricted { reason })
            | Some(CapabilityStatus::Unavailable { reason }) => Some(format!(
                "{} unavailable\nReason: {reason}\nFallback: {fallback}",
                capability.id()
            )),
        }
    }
}

/// Detect the current platform. Uses compile-time OS/arch plus runtime
/// probes (WSL, Termux) where possible; never panics.
pub fn detect() -> PlatformInfo {
    let os = std::env::consts::OS.to_owned();
    let arch = std::env::consts::ARCH.to_owned();
    let environment = detect_environment(&os);
    let capabilities = probe_capabilities(&environment);
    PlatformInfo {
        os,
        arch,
        environment,
        capabilities,
    }
}

fn detect_environment(os: &str) -> Environment {
    if crate::platform::network::is_termux() {
        return Environment::AndroidTermux;
    }
    if crate::platform::network::is_wsl() {
        return Environment::WindowsWsl;
    }
    match os {
        "linux" => {
            if cfg!(target_os = "android") {
                Environment::AndroidTermux
            } else {
                Environment::LinuxNative
            }
        }
        "windows" => Environment::WindowsNative,
        "macos" => Environment::MacOs,
        "android" => Environment::AndroidTermux,
        _ => {
            if cfg!(unix) {
                Environment::UnknownUnix
            } else {
                Environment::Other { os: os.to_owned() }
            }
        }
    }
}

fn probe_capabilities(environment: &Environment) -> BTreeMap<String, CapabilityStatus> {
    let raw = crate::scan_mode::probe_raw_syn();
    let raw_available = raw.supported;
    let raw_reason = raw.reason.clone();
    let mut map = BTreeMap::new();
    let insert = |map: &mut BTreeMap<String, CapabilityStatus>,
                  cap: Capability,
                  status: CapabilityStatus| {
        map.insert(cap.id().to_owned(), status);
    };
    // TCP connect scanning works everywhere std sockets work.
    insert(
        &mut map,
        Capability::TcpConnectScan,
        CapabilityStatus::Available,
    );
    // UDP via connected sockets works on desktop; Termux keeps it but
    // notes privileged ICMP errors may be invisible.
    match environment {
        Environment::AndroidTermux => insert(
            &mut map,
            Capability::UdpScan,
            CapabilityStatus::Restricted {
                reason: "UDP probing available; ICMP-unreachable attribution may be limited without privileges".to_owned(),
            },
        ),
        _ => insert(&mut map, Capability::UdpScan, CapabilityStatus::Available),
    }
    // Raw packet operations require the raw SYN probe to succeed.
    if raw_available {
        insert(
            &mut map,
            Capability::RawPacketSend,
            CapabilityStatus::Available,
        );
        insert(
            &mut map,
            Capability::RawPacketCapture,
            CapabilityStatus::Available,
        );
    } else {
        insert(
            &mut map,
            Capability::RawPacketSend,
            CapabilityStatus::Unavailable {
                reason: raw_reason.clone(),
            },
        );
        insert(
            &mut map,
            Capability::RawPacketCapture,
            CapabilityStatus::Unavailable { reason: raw_reason },
        );
    }
    // Interface / route enumeration: best-effort everywhere, restricted
    // where Termux or unknown environments limit visibility.
    match environment {
        Environment::AndroidTermux => {
            insert(
                &mut map,
                Capability::InterfaceEnumeration,
                CapabilityStatus::Restricted {
                    reason: "interface visibility may be limited in Termux; link-scope results stay best-effort"
                        .to_owned(),
                },
            );
            insert(
                &mut map,
                Capability::RouteEnumeration,
                CapabilityStatus::Restricted {
                    reason: "route table access may be limited in Termux".to_owned(),
                },
            );
        }
        Environment::UnknownUnix | Environment::Other { .. } => {
            insert(
                &mut map,
                Capability::InterfaceEnumeration,
                CapabilityStatus::Restricted {
                    reason: "interface enumeration is best-effort on this platform".to_owned(),
                },
            );
            insert(
                &mut map,
                Capability::RouteEnumeration,
                CapabilityStatus::Restricted {
                    reason: "route enumeration is best-effort on this platform".to_owned(),
                },
            );
        }
        _ => {
            insert(
                &mut map,
                Capability::InterfaceEnumeration,
                CapabilityStatus::Available,
            );
            insert(
                &mut map,
                Capability::RouteEnumeration,
                CapabilityStatus::Available,
            );
        }
    }
    insert(
        &mut map,
        Capability::PassiveOsInference,
        CapabilityStatus::Available,
    );
    // Active OS fingerprinting is experimental: raw capability alone does
    // not mean functional fingerprinting. The collector currently emits no
    // validated raw header signals (TTL/window) and the production corpus
    // has no matching rules, so this stays Restricted even when raw exists.
    // Passive OS inference remains the supported path.
    if raw_available {
        insert(
            &mut map,
            Capability::ActiveOsFingerprinting,
            CapabilityStatus::Restricted {
                reason: "Active OS probes experimental: bounded timing/behavior signals only; raw header observation not yet validated; fallback: passive OS evidence remains enabled"
                    .to_owned(),
            },
        );
    } else {
        insert(
            &mut map,
            Capability::ActiveOsFingerprinting,
            CapabilityStatus::Unavailable {
                reason: "Active OS probes unavailable: raw-packet capability is unavailable in this environment; fallback: passive OS evidence remains enabled"
                    .to_owned(),
            },
        );
    }
    for cap in [
        Capability::TlsCollection,
        Capability::SshCollection,
        Capability::HttpCollection,
        Capability::DnsIntelligence,
        Capability::PublicSourceSearch,
        Capability::LocalWebUi,
        Capability::SignalCancellation,
        Capability::ProjectPersistence,
    ] {
        insert(&mut map, cap, CapabilityStatus::Available);
    }
    map
}

/// Synthetic fixture: full-capability Linux desktop.
pub fn fixture_linux_full() -> PlatformInfo {
    let mut capabilities = BTreeMap::new();
    for cap in Capability::all() {
        capabilities.insert(cap.id().to_owned(), CapabilityStatus::Available);
    }
    PlatformInfo {
        os: "linux".to_owned(),
        arch: "x86_64".to_owned(),
        environment: Environment::LinuxNative,
        capabilities,
    }
}

/// Synthetic fixture: standard Windows desktop (no raw).
pub fn fixture_windows_standard() -> PlatformInfo {
    let mut info = fixture_linux_full();
    info.os = "windows".to_owned();
    info.environment = Environment::WindowsNative;
    for cap in [
        Capability::RawPacketSend,
        Capability::RawPacketCapture,
        Capability::ActiveOsFingerprinting,
    ] {
        info.capabilities.insert(
            cap.id().to_owned(),
            CapabilityStatus::Unavailable {
                reason: "raw-packet capability is unavailable in this environment".to_owned(),
            },
        );
    }
    info
}

/// Synthetic fixture: standard macOS desktop (no raw).
pub fn fixture_macos_standard() -> PlatformInfo {
    let mut info = fixture_windows_standard();
    info.os = "macos".to_owned();
    info.environment = Environment::MacOs;
    info
}

/// Synthetic fixture: restricted Termux environment.
pub fn fixture_termux_restricted() -> PlatformInfo {
    let mut info = fixture_windows_standard();
    info.os = "android".to_owned();
    info.arch = "aarch64".to_owned();
    info.environment = Environment::AndroidTermux;
    info.capabilities.insert(
        Capability::UdpScan.id().to_owned(),
        CapabilityStatus::Restricted {
            reason: "UDP probing available; ICMP-unreachable attribution may be limited without privileges"
                .to_owned(),
        },
    );
    info.capabilities.insert(
        Capability::InterfaceEnumeration.id().to_owned(),
        CapabilityStatus::Restricted {
            reason: "interface visibility may be limited in Termux".to_owned(),
        },
    );
    info
}

/// Synthetic fixture: unknown restricted environment.
pub fn fixture_unknown_restricted() -> PlatformInfo {
    let mut info = fixture_windows_standard();
    info.os = "unknown".to_owned();
    info.environment = Environment::UnknownUnix;
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_never_panics_and_covers_all_capabilities() {
        let info = detect();
        assert!(!info.os.is_empty());
        assert!(!info.arch.is_empty());
        for cap in Capability::all() {
            assert!(info.get(*cap).is_some(), "missing {}", cap.id());
        }
    }

    #[test]
    fn restricted_environments_degrade_gracefully() {
        let termux = fixture_termux_restricted();
        assert!(!termux.is_available(Capability::RawPacketSend));
        assert!(termux.is_available(Capability::TcpConnectScan));
        assert!(termux.is_available(Capability::PublicSourceSearch));
        let explanation = termux
            .explanation(
                Capability::ActiveOsFingerprinting,
                "passive OS evidence remains enabled",
            )
            .unwrap();
        assert!(explanation.contains("passive OS evidence remains enabled"));

        let windows = fixture_windows_standard();
        assert!(windows.is_available(Capability::TcpConnectScan));
        assert!(!windows.is_available(Capability::ActiveOsFingerprinting));
        assert!(
            windows
                .explanation(Capability::TcpConnectScan, "x")
                .is_none()
        );
    }

    #[test]
    fn active_fingerprinting_never_claims_full_availability() {
        // Raw capability alone must not advertise functional fingerprinting.
        // Production detect() is Restricted (experimental) when raw exists,
        // Unavailable otherwise — never Available until raw signals validate.
        let info = detect();
        assert!(!info.is_available(Capability::ActiveOsFingerprinting));
        let status = info.get(Capability::ActiveOsFingerprinting).unwrap();
        match status {
            CapabilityStatus::Restricted { reason } => {
                assert!(reason.contains("experimental"));
                assert!(reason.contains("passive OS evidence remains enabled"));
            }
            CapabilityStatus::Unavailable { reason } => {
                assert!(reason.contains("passive OS evidence remains enabled"));
            }
            CapabilityStatus::Available => panic!("active must not be Available"),
        }
    }

    #[test]
    fn fixtures_cover_required_environments() {
        assert_eq!(fixture_linux_full().environment, Environment::LinuxNative);
        assert_eq!(
            fixture_windows_standard().environment,
            Environment::WindowsNative
        );
        assert_eq!(fixture_macos_standard().environment, Environment::MacOs);
        assert_eq!(
            fixture_termux_restricted().environment,
            Environment::AndroidTermux
        );
        assert_eq!(
            fixture_unknown_restricted().environment,
            Environment::UnknownUnix
        );
    }
}
