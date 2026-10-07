//! Portable platform layer for RXScan.
//!
//! One core, explicit capabilities, small backends, graceful degradation.
//!
//! The core (search, evidence, graph, investigation, fingerprint scoring,
//! persistence) stays platform-independent. Only transmission, discovery,
//! paths, terminal, and process lifetime consult this module.
//!
//! Capability checks belong near platform boundaries, not scattered through
//! business logic. Unavailable capabilities produce one controlled
//! explanation, never repeated low-level failures.

pub mod capabilities;
pub mod network;
pub mod paths;
pub mod process;

pub use capabilities::{Capability, CapabilityStatus, Environment, PlatformInfo};
pub use network::{is_termux, is_wsl, normalize_io_error};
pub use paths::{cache_dir, config_dir, data_dir, resolve_web_data_dir};
pub use process::{
    CancellationFlag, install_cancellation_handler, install_process_cancellation,
    process_cancel_flag, process_cancelled, request_process_cancellation,
    reset_process_cancellation,
};
