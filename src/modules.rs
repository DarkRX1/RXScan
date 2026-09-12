//! Phase 6 scaffold + real modules.
//!
//! * `HostDiscovery` runs the real bounded `HostDiscoveryModule` (native ICMP
//!   echo + TCP reachability, no shell `ping`). See `host_discovery.rs`.
//! * `PortDiscovery` runs the real bounded `TcpDiscoveryModule` (native TCP
//!   connect scanning, one task per target with a bounded internal window,
//!   no thread per port). See `tcp_discovery.rs`.
//! * Control validation remains an honest scaffold.
//!
//! * [`ControlValidateModule`] (`rxscan.control.validate`): per-target
//!   control validation. Always registered.
//!
//! All deeper intents (`ServiceProbe`, `HttpProbe`, `TlsProbe`, `DnsProbe`,
//! `Fingerprint`, `ContentDiscovery`, `Crawl`, `Fuzz`, `rxscan.udp.intent`)
//! have NO registered module in Phase 6 and run as `Skipped`
//! (`module unavailable`). That is intentional honesty, visible in
//! `--explain` and runtime output.
//!
//! Every scaffold module is cooperative: it checks cancellation every
//! millisecond and returns `Cancelled` promptly. Typical latency <5ms.

use std::time::Duration;

use crate::execution::{Module, ModuleContext, ModuleError, ModuleFuture, ModuleOutput, TaskKind};

/// Generic cooperative NoOp holder for one task kind.
#[derive(Debug, Clone)]
pub struct ScaffoldModule {
    kind: TaskKind,
    /// Simulated bounded work in 1ms slices (total). Always tiny.
    work_slices: u32,
}

impl ScaffoldModule {
    pub fn new(kind: TaskKind) -> Self {
        Self {
            kind,
            work_slices: 2,
        }
    }

    pub fn control_validate() -> Self {
        Self {
            kind: crate::level::validate_kind(),
            work_slices: 1,
        }
    }

    pub fn host_intent() -> Self {
        Self {
            kind: TaskKind::HostDiscovery,
            work_slices: 2,
        }
    }

    pub fn port_intent() -> Self {
        Self {
            kind: TaskKind::PortDiscovery,
            work_slices: 2,
        }
    }
}

impl Module for ScaffoldModule {
    fn kind(&self) -> TaskKind {
        self.kind.clone()
    }

    fn execute(&self, context: ModuleContext) -> ModuleFuture {
        let slices = self.work_slices;
        Box::pin(async move {
            // Cooperative bounded work: check cancellation every 1ms.
            // Never reports fake discoveries; returns empty output.
            for _ in 0..slices {
                if context.is_cancelled() {
                    return Err(ModuleError::Cancelled);
                }
                std::thread::sleep(Duration::from_millis(1));
                if context.is_cancelled() {
                    return Err(ModuleError::Cancelled);
                }
            }
            if context.is_cancelled() {
                return Err(ModuleError::Cancelled);
            }
            Ok(ModuleOutput::default())
        })
    }
}

/// Backwards-compatible aliases used by runtime bootstrap and tests.
pub type ControlValidateModule = ScaffoldModule;
pub type HostIntentModule = ScaffoldModule;
pub type PortIntentModule = ScaffoldModule;

/// All Phase-4-safe modules to register on a scheduler (retained for
/// backwards-compatible tests; Phase 5 runtime uses `phase5_*` below).
pub fn phase4_modules() -> Vec<ScaffoldModule> {
    vec![
        ScaffoldModule::control_validate(),
        ScaffoldModule::host_intent(),
        ScaffoldModule::port_intent(),
    ]
}

/// Phase 5 control scaffolds (validation only; host discovery is real).
pub fn phase5_control_modules() -> Vec<ScaffoldModule> {
    vec![ScaffoldModule::control_validate()]
}

/// Phase 5 port-discovery intent scaffold (Phase 6 owns real scanning).
pub fn port_intent_module() -> ScaffoldModule {
    ScaffoldModule::port_intent()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaffold_kinds_are_phase4_safe() {
        let modules = phase4_modules();
        assert_eq!(modules.len(), 3);
        let kinds: Vec<TaskKind> = modules.iter().map(|module| module.kind()).collect();
        assert!(kinds.contains(&crate::level::validate_kind()));
        assert!(kinds.contains(&TaskKind::HostDiscovery));
        assert!(kinds.contains(&TaskKind::PortDiscovery));
    }
}
