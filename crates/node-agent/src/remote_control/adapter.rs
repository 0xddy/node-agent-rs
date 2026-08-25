//! Production panel/topology adapter for remote maintenance operations.

use std::sync::Arc;

use acp_proto::ReloadSingBoxOutcome;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use super::{
    ReloadProgressReporter, ReloadProgressStage, RemoteFetcher, RemoteOperationError,
    RemoteReloadResult, RemoteRuntime, UserSyncChanges,
};
use crate::control::TopologyFetcher;
use crate::runtime::NodeRuntime;
use crate::topology::manager::{
    ReloadOutcome, ReloadProgress, ReloadStage, TopologyErrorKind, TopologyManager,
    TopologyReloadResult, UserRefreshChanges,
};

const MAX_USER_REFRESH_ATTEMPTS: usize = 3;
const CONTEXT_CANCELED: &str = "context canceled";

/// Cloneable diagnostic view over the same runtime used by topology apply.
/// This bridges unrelated `Arc<dyn NodeRuntime>` and `Arc<dyn RemoteRuntime>`
/// trait objects without making the main binary own an ad-hoc wrapper.
#[derive(Clone)]
pub struct RuntimeRemoteView {
    runtime: Arc<dyn NodeRuntime>,
}

impl RuntimeRemoteView {
    pub fn new(runtime: Arc<dyn NodeRuntime>) -> Self {
        Self { runtime }
    }

    pub fn runtime(&self) -> &Arc<dyn NodeRuntime> {
        &self.runtime
    }
}

impl RemoteRuntime for RuntimeRemoteView {
    fn current_config(&self) -> Vec<u8> {
        self.runtime.current_config()
    }
}

/// Couples authoritative panel reads to the serialized topology transaction
/// manager used by the running node.
///
/// `TopologyFetcher` is object-safe so production can pass a
/// `PanelTopologyFetcher`, while tests can exercise the same transaction path
/// with a deterministic panel double.
#[derive(Clone)]
pub struct PanelRemoteFetcher {
    panel: Arc<dyn TopologyFetcher>,
    topologies: Arc<TopologyManager>,
}

impl PanelRemoteFetcher {
    pub fn new(panel: Arc<dyn TopologyFetcher>, topologies: Arc<TopologyManager>) -> Self {
        Self { panel, topologies }
    }

    pub fn panel(&self) -> &Arc<dyn TopologyFetcher> {
        &self.panel
    }

    pub fn topologies(&self) -> &Arc<TopologyManager> {
        &self.topologies
    }

    async fn reload_topology(
        &self,
        cancel: CancellationToken,
        progress: ReloadProgressReporter,
    ) -> Result<RemoteReloadResult, RemoteOperationError> {
        if cancel.is_cancelled() {
            return Err(cancelled());
        }

        let panel = Arc::clone(&self.panel);
        let fetch_cancel = cancel.clone();
        let protocol_progress: Arc<dyn ReloadProgress> =
            Arc::new(ProtocolReloadProgress { progress });
        let result = self
            .topologies
            .reload_from(
                move |reporter| async move {
                    tokio::select! {
                        biased;
                        () = fetch_cancel.cancelled() => Err(cancelled()),
                        result = panel.fetch_machine_topology_with_progress(reporter) => {
                            result.map_err(|error| RemoteOperationError::new(error.to_string()))
                        }
                    }
                },
                Some(protocol_progress),
            )
            .await;
        // `TopologyManager` turns fetch failures into a classified reload
        // result. Preserve cancellation as an operation error so the protocol
        // deadline owner can translate it to Go's exact
        // "context deadline exceeded" terminal message. A cancellation that
        // arrived during the local phase cannot mask that phase's real result.
        normalize_reload_result(&cancel, result)
    }

    /// Force-fetches the complete user list and publishes it with the same
    /// optimistic retry fence as the Go agent. Revision zero deliberately
    /// leaves the machine topology revision unchanged for maintenance pulls.
    pub async fn sync_node_users(
        &self,
        cancel: &CancellationToken,
        node_id: &str,
    ) -> Result<UserSyncChanges, RemoteOperationError> {
        if node_id.is_empty() {
            return Err(RemoteOperationError::new("user refresh requires node_id"));
        }

        for _ in 0..MAX_USER_REFRESH_ATTEMPTS {
            let current = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(cancelled()),
                result = self.topologies.loaded_users(node_id) => {
                    result.map_err(|error| RemoteOperationError::new(error.to_string()))?
                }
            };
            let desired = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(cancelled()),
                result = self.panel.fetch_node_users(node_id) => {
                    result.map_err(|error| RemoteOperationError::new(format!(
                        "fetch users for node {node_id}: {error}"
                    )))?
                }
            };
            if cancel.is_cancelled() {
                return Err(cancelled());
            }

            // From this point forward the manager owns the complete runtime
            // apply + publication transaction. Cancellation is intentionally
            // not selected here: the caller keeps awaiting the real result.
            match self
                .topologies
                .refresh_node_users_if_current_at_revision(node_id, desired, current, 0)
                .await
            {
                Ok(changes) => return Ok(changes.into()),
                Err(error) if error.kind() == TopologyErrorKind::UsersChangedDuringRefresh => {}
                Err(error) => return Err(RemoteOperationError::new(error.to_string())),
            }
        }

        Err(RemoteOperationError::new(format!(
            "refresh users for node {node_id} did not stabilize after {MAX_USER_REFRESH_ATTEMPTS} attempts: node users changed during refresh"
        )))
    }
}

#[async_trait]
impl RemoteFetcher for PanelRemoteFetcher {
    async fn reload(
        &self,
        cancel: CancellationToken,
        progress: ReloadProgressReporter,
    ) -> Result<RemoteReloadResult, RemoteOperationError> {
        self.reload_topology(cancel, progress).await
    }

    async fn sync_users(
        &self,
        cancel: CancellationToken,
        node_id: &str,
    ) -> Result<UserSyncChanges, RemoteOperationError> {
        self.sync_node_users(&cancel, node_id).await
    }
}

struct ProtocolReloadProgress {
    progress: ReloadProgressReporter,
}

#[async_trait]
impl ReloadProgress for ProtocolReloadProgress {
    async fn report(&self, stage: ReloadStage) {
        let stage = match stage {
            ReloadStage::PullConfiguration => ReloadProgressStage::PullConfiguration,
            ReloadStage::PullUsers => ReloadProgressStage::PullUsers,
            ReloadStage::BuildConfiguration => ReloadProgressStage::BuildConfiguration,
            ReloadStage::ConfigurePortHopping => ReloadProgressStage::ConfigurePortHopping,
            ReloadStage::StartInstance => ReloadProgressStage::StartInstance,
            // These are terminal result stages, not progress frames in the Go
            // stream. `handle_reload` sends exactly one final response.
            ReloadStage::Rollback | ReloadStage::Completed => return,
        };
        let _ = self.progress.report(stage).await;
    }
}

impl From<TopologyReloadResult> for RemoteReloadResult {
    fn from(result: TopologyReloadResult) -> Self {
        let succeeded = result.outcome == ReloadOutcome::Succeeded;
        Self {
            outcome: match result.outcome {
                ReloadOutcome::Succeeded => ReloadSingBoxOutcome::Succeeded,
                ReloadOutcome::FailedUnchanged => ReloadSingBoxOutcome::FailedUnchanged,
                ReloadOutcome::FailedRolledBack => ReloadSingBoxOutcome::FailedRolledBack,
                ReloadOutcome::FailedStopped => ReloadSingBoxOutcome::FailedStopped,
            },
            stage: result.stage.as_str().to_string(),
            message: if succeeded {
                "sing-box reloaded with fresh panel configuration and users".into()
            } else {
                result.message
            },
            topology_revision: result.topology_revision,
            config_sha256: result.config_sha256,
            loaded_user_count: result.loaded_user_count,
        }
    }
}

impl From<UserRefreshChanges> for UserSyncChanges {
    fn from(changes: UserRefreshChanges) -> Self {
        Self {
            added: changes.added,
            updated: changes.updated,
            deleted: changes.deleted,
            applied: changes.applied,
        }
    }
}

fn cancelled() -> RemoteOperationError {
    RemoteOperationError::new(CONTEXT_CANCELED)
}

fn normalize_reload_result(
    cancel: &CancellationToken,
    result: TopologyReloadResult,
) -> Result<RemoteReloadResult, RemoteOperationError> {
    if cancel.is_cancelled()
        && result.outcome == ReloadOutcome::FailedUnchanged
        && result.message == "reload data from panel: context canceled"
    {
        return Err(cancelled());
    }
    Ok(result.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed_reload(message: &str) -> TopologyReloadResult {
        TopologyReloadResult {
            outcome: ReloadOutcome::FailedUnchanged,
            stage: ReloadStage::PullConfiguration,
            message: message.into(),
            topology_revision: 0,
            config_sha256: String::new(),
            loaded_user_count: 0,
        }
    }

    #[test]
    fn deadline_cancellation_escapes_fetch_failure_classification_only() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let error = normalize_reload_result(
            &cancel,
            failed_reload("reload data from panel: context canceled"),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), CONTEXT_CANCELED);

        let local_failure = normalize_reload_result(
            &cancel,
            failed_reload("replacement failed after fetch completed"),
        )
        .unwrap();
        assert_eq!(
            local_failure.message,
            "replacement failed after fetch completed"
        );
    }
}
