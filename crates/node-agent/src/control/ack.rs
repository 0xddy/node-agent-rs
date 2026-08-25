//! Short-lived idempotency cache for control command acknowledgements.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};

const DEFAULT_ACK_STORE_CAPACITY: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckStatus {
    Accepted,
    Applied,
    Failed,
    RolledBack,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Command {
    pub command_id: String,
    pub operation_id: String,
    pub machine_id: String,
    pub node_id: String,
    pub revision: u64,
    pub idempotency_key: String,
    pub command_type: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    pub command_id: String,
    pub operation_id: String,
    pub machine_id: String,
    pub node_id: String,
    pub revision: u64,
    pub idempotency_key: String,
    pub status: AckStatus,
    pub message: String,
}

impl Default for Ack {
    fn default() -> Self {
        Self {
            command_id: String::new(),
            operation_id: String::new(),
            machine_id: String::new(),
            node_id: String::new(),
            revision: 0,
            idempotency_key: String::new(),
            status: AckStatus::Accepted,
            message: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecuteError;

impl std::fmt::Display for ExecuteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("idempotency key is required")
    }
}

impl std::error::Error for ExecuteError {}

struct State {
    seen: HashMap<String, Ack>,
    order: VecDeque<String>,
}

/// FIFO-bounded replay cache matching Go's `internal/control.AckStore`.
///
/// Failed and rolled-back results are deliberately not cached, so the panel can
/// retry the same logical operation with the same idempotency key. Execution is
/// outside the mutex just as in Go; the ACP control worker is serial, and keeping
/// the store from holding a lock across arbitrary work avoids turning it into a
/// hidden transaction lock.
pub struct AckStore {
    state: Mutex<State>,
    capacity: usize,
}

impl Default for AckStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AckStore {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_ACK_STORE_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            state: Mutex::new(State {
                seen: HashMap::new(),
                order: VecDeque::new(),
            }),
            capacity,
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Looks up a previously completed successful command.
    ///
    /// Split lookup/completion is used by the async control workers: it preserves
    /// the Go store's semantics without holding a synchronous mutex across an
    /// `.await` point.
    pub fn replay(&self, command: &Command) -> Result<Option<Ack>, ExecuteError> {
        if command.idempotency_key.is_empty() {
            return Err(ExecuteError);
        }
        Ok(self
            .state()
            .seen
            .get(&command.idempotency_key)
            .cloned()
            .map(|mut ack| {
                ack.command_id.clone_from(&command.command_id);
                ack.operation_id.clone_from(&command.operation_id);
                ack
            }))
    }

    /// Adds transport envelope fields and conditionally caches a terminal ACK.
    pub fn complete(&self, command: &Command, mut ack: Ack) -> Result<Ack, ExecuteError> {
        if command.idempotency_key.is_empty() {
            return Err(ExecuteError);
        }
        ack.command_id.clone_from(&command.command_id);
        ack.operation_id.clone_from(&command.operation_id);
        ack.machine_id.clone_from(&command.machine_id);
        ack.node_id.clone_from(&command.node_id);
        ack.revision = command.revision;
        ack.idempotency_key.clone_from(&command.idempotency_key);

        if matches!(ack.status, AckStatus::Failed | AckStatus::RolledBack) {
            return Ok(ack);
        }
        let mut state = self.state();
        if !state.seen.contains_key(&command.idempotency_key) {
            state
                .seen
                .insert(command.idempotency_key.clone(), ack.clone());
            state.order.push_back(command.idempotency_key.clone());
            while state.order.len() > self.capacity {
                if let Some(oldest) = state.order.pop_front() {
                    state.seen.remove(&oldest);
                }
            }
        }
        Ok(ack)
    }

    /// Executes once or replays the cached successful acknowledgement.
    ///
    /// The boolean is true for a replay. A replay replaces the transport-level
    /// command and operation ids with those of the incoming delivery; all other
    /// fields remain the cached logical command, exactly as the Go implementation.
    pub fn execute(
        &self,
        command: Command,
        execute: impl FnOnce(&Command) -> Ack,
    ) -> Result<(Ack, bool), ExecuteError> {
        if let Some(ack) = self.replay(&command)? {
            return Ok((ack, true));
        }

        let ack = self.complete(&command, execute(&command))?;
        Ok((ack, false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(key: &str) -> Command {
        Command {
            command_id: "cmd-1".into(),
            operation_id: "operation-1".into(),
            machine_id: "machine-1".into(),
            node_id: "node-1".into(),
            revision: 7,
            idempotency_key: key.into(),
            ..Default::default()
        }
    }

    #[test]
    fn duplicate_replays_result_but_echoes_new_delivery_ids() {
        let store = AckStore::new();
        let first = command("same-key");
        let (first_ack, replayed) = store
            .execute(first.clone(), |_| Ack {
                status: AckStatus::Applied,
                message: "ok".into(),
                ..Default::default()
            })
            .unwrap();
        assert!(!replayed);

        let mut duplicate = first;
        duplicate.command_id = "cmd-2".into();
        duplicate.operation_id = "operation-2".into();
        let (replay, replayed) = store
            .execute(duplicate, |_| panic!("a cached command must not execute"))
            .unwrap();
        assert!(replayed);
        assert_eq!(replay.command_id, "cmd-2");
        assert_eq!(replay.operation_id, "operation-2");
        assert_eq!(replay.status, first_ack.status);
        assert_eq!(replay.message, first_ack.message);
    }

    #[test]
    fn a_failed_result_can_be_retried_with_the_same_key() {
        let store = AckStore::new();
        let command = command("retry");
        let (_, replayed) = store
            .execute(command.clone(), |_| Ack {
                status: AckStatus::Failed,
                message: "boom".into(),
                ..Default::default()
            })
            .unwrap();
        assert!(!replayed);

        let (ack, replayed) = store
            .execute(command, |_| Ack {
                status: AckStatus::Applied,
                message: "ok".into(),
                ..Default::default()
            })
            .unwrap();
        assert!(!replayed);
        assert_eq!(ack.status, AckStatus::Applied);
    }

    #[test]
    fn fifo_capacity_evicts_the_oldest_key() {
        let store = AckStore::with_capacity(2);
        for key in ["one", "two", "three"] {
            store
                .execute(command(key), |_| Ack {
                    status: AckStatus::Applied,
                    ..Default::default()
                })
                .unwrap();
        }

        let (_, replayed) = store
            .execute(command("one"), |_| Ack {
                status: AckStatus::Applied,
                message: "executed again".into(),
                ..Default::default()
            })
            .unwrap();
        assert!(!replayed);
        let (_, replayed) = store
            .execute(command("three"), |_| panic!("three remains cached"))
            .unwrap();
        assert!(replayed);
    }

    #[test]
    fn missing_idempotency_key_is_rejected_before_execution() {
        let store = AckStore::new();
        let error = store
            .execute(Command::default(), |_| panic!("must not execute"))
            .unwrap_err();
        assert_eq!(error.to_string(), "idempotency key is required");
    }
}
