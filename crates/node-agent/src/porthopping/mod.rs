//! Hysteria2 UDP port-hopping plan and machine-wide forwarding lifecycle.

mod errors;
mod manager;
mod plan;
mod port_ranges;

#[cfg(target_os = "linux")]
mod backend_linux;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod backend_other;
#[cfg(target_os = "windows")]
mod backend_windows;

#[cfg(target_os = "linux")]
mod platform {
    use super::backend_linux::NftBackend;
    use super::manager::Backend;

    pub(super) fn new_backend(machine_id: &str) -> Box<dyn Backend> {
        Box::new(NftBackend::new(machine_id))
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::backend_windows::WindowsBackend;
    use super::manager::Backend;

    pub(super) fn new_backend(machine_id: &str) -> Box<dyn Backend> {
        Box::new(WindowsBackend::new(machine_id))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod platform {
    use super::backend_other::UnsupportedBackend;
    use super::manager::Backend;

    pub(super) fn new_backend(_machine_id: &str) -> Box<dyn Backend> {
        Box::new(UnsupportedBackend)
    }
}

pub use errors::{
    CapabilityError, RouterClosedError, StateUncertainError, is_capability_unsupported,
    is_router_closed, is_state_uncertain,
};
pub use manager::Manager;
pub use plan::{Plan, PlanError, Redirect, build_plan};
pub use port_ranges::{PortRange, PortRangeError, normalize_port_ranges, parse_port_ranges};
