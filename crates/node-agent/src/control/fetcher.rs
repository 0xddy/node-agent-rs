//! Authenticated, bounded ConfigService reads used by initial sync and recovery.

use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::time::Duration;

use acp_proto::config_service_client::ConfigServiceClient;
use acp_proto::{GetMachineConfigRequest, ListUsersRequest};
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::session::{AuthenticatedSession, PANEL_REQUEST_TIMEOUT};
use crate::topology::manager::{ReloadReporter, ReloadStage};
use crate::topology::{MachineTopology, UserCredential, from_machine_config, replace_node_users};

const USER_PAGE_SIZE: u32 = 500;
const MAX_USER_PAGES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchError(String);

impl FetchError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for FetchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for FetchError {}

#[async_trait]
pub trait TopologyFetcher: Send + Sync {
    async fn fetch_machine_topology(&self) -> Result<MachineTopology, FetchError>;
    /// Generation-scoped read used by control commands. Dropping an in-flight
    /// ConfigService future is safe because it has not mutated local state.
    async fn fetch_machine_topology_cancellable(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<MachineTopology, FetchError> {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(FetchError::new("control command execution canceled")),
            result = self.fetch_machine_topology() => result,
        }
    }
    async fn fetch_machine_topology_with_progress(
        &self,
        reporter: ReloadReporter,
    ) -> Result<MachineTopology, FetchError> {
        let topology = self.fetch_machine_topology().await?;
        reporter.report(ReloadStage::PullUsers).await;
        Ok(topology)
    }
    async fn fetch_node_users(&self, node_id: &str) -> Result<Vec<UserCredential>, FetchError>;
    /// Generation-scoped paginated read. Cancellation drops the current unary
    /// RPC and the enclosing pagination loop instead of retaining an old panel
    /// session for up to `MAX_USER_PAGES` per-call timeouts.
    async fn fetch_node_users_cancellable(
        &self,
        cancellation: &CancellationToken,
        node_id: &str,
    ) -> Result<Vec<UserCredential>, FetchError> {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(FetchError::new("control command execution canceled")),
            result = self.fetch_node_users(node_id) => result,
        }
    }
}

/// ConfigService fetcher that signs every unary call with the active session.
///
/// A fresh generated client is intentionally cheap and ensures every call goes
/// through `SessionInterceptor`; each unary call site also has its own explicit
/// ten-second timeout, rather than relying on a channel-wide timeout that would
/// break long-lived streaming RPCs.
#[derive(Clone)]
pub struct PanelTopologyFetcher {
    machine_id: String,
    session: AuthenticatedSession,
}

impl PanelTopologyFetcher {
    pub fn new(machine_id: impl Into<String>, session: AuthenticatedSession) -> Self {
        Self {
            machine_id: machine_id.into(),
            session,
        }
    }

    async fn list_node_users(&self, node_id: &str) -> Result<Vec<UserCredential>, FetchError> {
        if node_id.is_empty() {
            return Err(FetchError::new("list users requires node_id"));
        }
        let mut client = ConfigServiceClient::new(self.session.authenticated_channel());
        let mut users = Vec::new();
        let mut page_token = String::new();
        let mut seen_page_tokens = BTreeSet::new();

        for _ in 0..MAX_USER_PAGES {
            if !page_token.is_empty() && !seen_page_tokens.insert(page_token.clone()) {
                return Err(FetchError::new(format!(
                    "list users pagination repeated page_token={page_token:?} for node {node_id}"
                )));
            }
            let request = ListUsersRequest {
                machine_id: self.machine_id.clone(),
                session_id: self.session.descriptor().session_id.clone(),
                node_id: node_id.to_string(),
                page_size: USER_PAGE_SIZE,
                page_token: page_token.clone(),
            };
            // Keep this timeout at the unary call site. Do not move it to the
            // endpoint, whose channel is shared by long-lived streams.
            let response = bounded_unary(
                format!("list users for node {node_id}"),
                client.list_users(request),
            )
            .await?
            .into_inner();

            users.extend(response.users.iter().map(UserCredential::from));
            let total_size = response.total_size as usize;
            if total_size > 0 && users.len() > total_size {
                return Err(FetchError::new(format!(
                    "list users returned {} users beyond total_size={total_size} for node {node_id}",
                    users.len()
                )));
            }
            if !response.has_next {
                if !response.next_page_token.is_empty() {
                    return Err(FetchError::new(format!(
                        "list users returned has_next=false with next_page_token={:?} for node {node_id}",
                        response.next_page_token
                    )));
                }
                return Ok(users);
            }
            if response.next_page_token.is_empty() {
                return Err(FetchError::new(format!(
                    "list users returned has_next=true without next_page_token for node {node_id}"
                )));
            }
            if response.users.is_empty() {
                return Err(FetchError::new(format!(
                    "list users returned empty page with next_page_token={:?} for node {node_id}",
                    response.next_page_token
                )));
            }
            if total_size > 0 && users.len() >= total_size {
                return Err(FetchError::new(format!(
                    "list users reached total_size={total_size} but still got next_page_token={:?} for node {node_id}",
                    response.next_page_token
                )));
            }
            if response.next_page_token == page_token {
                return Err(FetchError::new(format!(
                    "list users pagination did not advance page_token={page_token:?} for node {node_id}"
                )));
            }
            page_token = response.next_page_token;
        }
        Err(FetchError::new(format!(
            "list users exceeded max pages={MAX_USER_PAGES} for node {node_id}"
        )))
    }

    async fn machine_topology(
        &self,
        reporter: Option<&ReloadReporter>,
    ) -> Result<MachineTopology, FetchError> {
        let mut client = ConfigServiceClient::new(self.session.authenticated_channel());
        let request = GetMachineConfigRequest {
            machine_id: self.machine_id.clone(),
            session_id: self.session.descriptor().session_id.clone(),
        };
        // Explicit per-unary 10s fence, for the same reason as ListUsers above.
        let config = bounded_unary("get machine topology", client.get_machine_config(request))
            .await?
            .into_inner();
        if let Some(reporter) = reporter {
            reporter.report(ReloadStage::PullUsers).await;
        }

        let mut topology = from_machine_config(self.machine_id.clone(), Some(&config));
        let node_ids: Vec<String> = topology
            .nodes
            .iter()
            .map(|node| node.node_id.clone())
            .collect();
        for (index, node_id) in node_ids.iter().enumerate() {
            let users = self.list_node_users(node_id).await?;
            topology.nodes[index].users.clone_from(&users);
            replace_node_users(&mut topology, node_id, &users);
        }
        Ok(topology)
    }
}

#[async_trait]
impl TopologyFetcher for PanelTopologyFetcher {
    async fn fetch_machine_topology(&self) -> Result<MachineTopology, FetchError> {
        self.machine_topology(None).await
    }

    async fn fetch_machine_topology_with_progress(
        &self,
        reporter: ReloadReporter,
    ) -> Result<MachineTopology, FetchError> {
        self.machine_topology(Some(&reporter)).await
    }

    async fn fetch_node_users(&self, node_id: &str) -> Result<Vec<UserCredential>, FetchError> {
        self.list_node_users(node_id).await
    }
}

async fn bounded_unary<T, F>(
    operation: impl Into<String>,
    future: F,
) -> Result<tonic::Response<T>, FetchError>
where
    F: Future<Output = Result<tonic::Response<T>, tonic::Status>>,
{
    bounded_unary_with_timeout(operation, PANEL_REQUEST_TIMEOUT, future).await
}

async fn bounded_unary_with_timeout<T, F>(
    operation: impl Into<String>,
    timeout: Duration,
    future: F,
) -> Result<tonic::Response<T>, FetchError>
where
    F: Future<Output = Result<tonic::Response<T>, tonic::Status>>,
{
    let operation = operation.into();
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| FetchError::new(format!("{operation} timed out after {timeout:?}")))?
        .map_err(|status| FetchError::new(format!("{operation}: {status}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unary_timeout_is_enforced_at_the_call_site() {
        let error = bounded_unary_with_timeout(
            "get machine topology",
            Duration::from_millis(1),
            std::future::pending::<Result<tonic::Response<()>, tonic::Status>>(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "get machine topology timed out after 1ms"
        );
    }
}
