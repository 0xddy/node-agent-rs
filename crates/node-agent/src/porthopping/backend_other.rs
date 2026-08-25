use super::errors::{BackendResult, CapabilityError};
use super::manager::Backend;
use super::plan::Plan;

pub(super) struct UnsupportedBackend;

impl Backend for UnsupportedBackend {
    fn apply(&mut self, desired: &Plan) -> BackendResult {
        if desired.is_empty() {
            return Ok(());
        }
        Err(Box::new(CapabilityError::new(
            std::env::consts::OS,
            "UDP destination-port redirection",
            "no native port hopping backend is registered for this platform",
        )))
    }
}
