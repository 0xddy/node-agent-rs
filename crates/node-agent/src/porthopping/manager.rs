//! Serialized lifecycle for the platform forwarding backend.

use std::sync::Mutex;

use super::errors::{BackendResult, OperationError, RouterClosedError};
use super::plan::Plan;

pub(crate) trait Backend: Send {
    /// Replace all forwarding state owned by this node-agent.
    ///
    /// Ordinary errors must leave the previous state unchanged. Once an atomic
    /// operation has been submitted and cannot be verified, implementations
    /// must return `StateUncertainError` so the topology transaction restores
    /// its previous full plan explicitly.
    fn apply(&mut self, desired: &Plan) -> BackendResult;
}

struct State {
    backend: Box<dyn Backend>,
    closed: bool,
}

/// Machine-wide port-hopping router.
pub struct Manager {
    state: Mutex<State>,
}

impl Manager {
    pub fn new(machine_id: &str) -> Self {
        Self::with_backend(super::platform::new_backend(machine_id))
    }

    pub(crate) fn with_backend(backend: Box<dyn Backend>) -> Self {
        Self {
            state: Mutex::new(State {
                backend,
                closed: false,
            }),
        }
    }

    /// Atomically reconcile the backend with a complete desired plan.
    pub fn apply(&self, desired: &Plan) -> BackendResult {
        let mut state = self.state.lock().map_err(|_| {
            Box::new(OperationError::message(
                "port hopping manager lock is poisoned",
            )) as super::errors::BoxError
        })?;
        if state.closed {
            return Err(Box::new(RouterClosedError));
        }
        state.backend.apply(desired)
    }

    /// Alias matching the Go router interface terminology.
    pub fn reconcile(&self, desired: &Plan) -> BackendResult {
        self.apply(desired)
    }

    /// Remove owned forwarding state and permanently close this manager.
    ///
    /// Successful closes are idempotent. A failed cleanup does not mark the
    /// manager closed and can therefore be retried.
    pub fn close(&self) -> BackendResult {
        let mut state = self.state.lock().map_err(|_| {
            Box::new(OperationError::message(
                "port hopping manager lock is poisoned",
            )) as super::errors::BoxError
        })?;
        if state.closed {
            return Ok(());
        }
        state.backend.apply(&Plan::default())?;
        state.closed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::sync::{Arc, Mutex};

    use super::{Backend, Manager};
    use crate::porthopping::errors::{
        BackendResult, StateUncertainError, is_router_closed, is_state_uncertain,
    };
    use crate::porthopping::{Plan, Redirect};

    #[derive(Default)]
    struct RecordingState {
        plans: Vec<Plan>,
        committed: Plan,
        errors: VecDeque<ErrorKind>,
    }

    enum ErrorKind {
        Ordinary,
        Uncertain,
    }

    struct RecordingBackend(Arc<Mutex<RecordingState>>);

    impl Backend for RecordingBackend {
        fn apply(&mut self, desired: &Plan) -> BackendResult {
            let mut state = self.0.lock().unwrap();
            state.plans.push(desired.clone());
            match state.errors.pop_front() {
                Some(ErrorKind::Ordinary) => Err(Box::new(io::Error::other("rejected"))),
                Some(ErrorKind::Uncertain) => Err(Box::new(StateUncertainError::new(
                    io::Error::other("acknowledgement lost"),
                ))),
                None => {
                    state.committed = desired.clone();
                    Ok(())
                }
            }
        }
    }

    fn plan(port: u16) -> Plan {
        Plan {
            redirects: vec![Redirect {
                node_id: "node-a".into(),
                listen_port: port,
                ports: Vec::new(),
            }],
        }
    }

    #[test]
    fn serializes_replacement_and_closes_idempotently() {
        let state = Arc::new(Mutex::new(RecordingState::default()));
        let manager = Manager::with_backend(Box::new(RecordingBackend(state.clone())));
        manager.apply(&plan(443)).unwrap();
        manager.apply(&plan(8443)).unwrap();
        manager.close().unwrap();
        manager.close().unwrap();

        let state = state.lock().unwrap();
        assert_eq!(state.plans.len(), 3);
        assert!(state.plans[2].is_empty());
        assert!(state.committed.is_empty());
        drop(state);
        let error = manager.apply(&Plan::default()).unwrap_err();
        assert!(is_router_closed(error.as_ref()));
    }

    #[test]
    fn ordinary_failure_keeps_old_state_and_close_failure_can_retry() {
        let state = Arc::new(Mutex::new(RecordingState::default()));
        let manager = Manager::with_backend(Box::new(RecordingBackend(state.clone())));
        let old = plan(443);
        manager.apply(&old).unwrap();
        state.lock().unwrap().errors.push_back(ErrorKind::Ordinary);
        assert!(manager.apply(&plan(8443)).is_err());
        assert_eq!(state.lock().unwrap().committed, old);

        state.lock().unwrap().errors.push_back(ErrorKind::Ordinary);
        assert!(manager.close().is_err());
        manager.close().unwrap();
        assert!(state.lock().unwrap().committed.is_empty());
    }

    #[test]
    fn uncertain_failure_is_distinct_and_does_not_close_manager() {
        let state = Arc::new(Mutex::new(RecordingState::default()));
        state.lock().unwrap().errors.push_back(ErrorKind::Uncertain);
        let manager = Manager::with_backend(Box::new(RecordingBackend(state)));
        let error = manager.close().unwrap_err();
        assert!(is_state_uncertain(error.as_ref()));
        manager.close().unwrap();
    }
}
