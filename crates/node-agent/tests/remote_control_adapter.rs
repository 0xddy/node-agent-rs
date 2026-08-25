use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use acp_proto::remote_control_request::Command;
use acp_proto::remote_control_response::Payload;
use acp_proto::{
    ReloadSingBoxOutcome, ReloadSingBoxRequest, RemoteControlRequest, RemoteControlResponseStatus,
};
use async_trait::async_trait;
use node_agent::control::{FetchError, TopologyFetcher};
use node_agent::remote_control::{
    PanelRemoteFetcher, RemoteControlDependencies, RemoteControlTarget, RemoteController,
    RemoteFetcher, RemoteRuntime, RuntimeRemoteView, handle_remote_control_request,
};
use node_agent::runtime::{
    ConnectionStats, NodeRuntime, ReloadStatus as RuntimeReloadStatus, RuntimeConfig, RuntimeError,
    TrafficDrain,
};
use node_agent::topology::manager::{TopologyError, TopologyManager, TopologyRuntime};
use node_agent::topology::{MachineTopology, NodeInstance, UserCredential};
use tokio::sync::{Notify, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn user(user_id: &str, credential: &str) -> UserCredential {
    UserCredential {
        user_id: user_id.into(),
        credential: credential.into(),
        status: "active".into(),
        ..Default::default()
    }
}

fn topology(revision: u64, users: Vec<UserCredential>) -> MachineTopology {
    MachineTopology {
        machine_id: "machine-1".into(),
        revision,
        nodes: vec![NodeInstance {
            node_id: "node-1".into(),
            users,
            ..Default::default()
        }],
        ..Default::default()
    }
}

#[derive(Default)]
struct RecordingTopologyRuntime {
    applied: Mutex<Vec<MachineTopology>>,
    closed_users: Mutex<Vec<(String, String)>>,
}

#[async_trait]
impl TopologyRuntime for RecordingTopologyRuntime {
    async fn apply(&self, topology: &MachineTopology) -> Result<(), TopologyError> {
        lock(&self.applied).push(topology.clone());
        Ok(())
    }

    async fn close_user_connections(&self, node_id: &str, user_id: &str) -> u64 {
        lock(&self.closed_users).push((node_id.into(), user_id.into()));
        1
    }

    fn current_config(&self) -> Vec<u8> {
        b"running: true\n".to_vec()
    }

    fn prepare_reload(&self, _topology: &MachineTopology) -> Result<RuntimeConfig, TopologyError> {
        Ok(RuntimeConfig {
            diagnostic_yaml: b"revision: 2\n".to_vec(),
            ..Default::default()
        })
    }
}

struct StaticPanel {
    topology: Mutex<Result<MachineTopology, FetchError>>,
    users: Mutex<Vec<UserCredential>>,
    topology_calls: AtomicUsize,
    user_calls: AtomicUsize,
}

impl StaticPanel {
    fn new(topology: MachineTopology, users: Vec<UserCredential>) -> Self {
        Self {
            topology: Mutex::new(Ok(topology)),
            users: Mutex::new(users),
            topology_calls: AtomicUsize::new(0),
            user_calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl TopologyFetcher for StaticPanel {
    async fn fetch_machine_topology(&self) -> Result<MachineTopology, FetchError> {
        self.topology_calls.fetch_add(1, Ordering::SeqCst);
        lock(&self.topology).clone()
    }

    async fn fetch_node_users(&self, _node_id: &str) -> Result<Vec<UserCredential>, FetchError> {
        self.user_calls.fetch_add(1, Ordering::SeqCst);
        Ok(lock(&self.users).clone())
    }
}

struct ConfigView;

impl RemoteRuntime for ConfigView {
    fn current_config(&self) -> Vec<u8> {
        b"running: true\n".to_vec()
    }
}

#[tokio::test]
async fn remote_reload_force_fetches_once_emits_go_stages_and_publishes_atomically() {
    let runtime = Arc::new(RecordingTopologyRuntime::default());
    let manager = Arc::new(TopologyManager::new("machine-1", runtime.clone()));
    manager
        .apply_initial(topology(1, vec![user("old", "old-secret")]))
        .await
        .unwrap();
    let candidate = topology(2, vec![user("new", "new-secret")]);
    let panel = Arc::new(StaticPanel::new(candidate.clone(), Vec::new()));
    let adapter = Arc::new(PanelRemoteFetcher::new(panel.clone(), manager.clone()));
    let dependencies =
        RemoteControlDependencies::new(manager.clone(), Arc::new(ConfigView), adapter);
    let (responses, mut receiver) = mpsc::channel(32);

    handle_remote_control_request(
        CancellationToken::new(),
        RemoteControlTarget {
            machine_id: "machine-1".into(),
            node_id: "node-1".into(),
        },
        dependencies,
        RemoteController::new(),
        RemoteControlRequest {
            request_id: "reload-1".into(),
            command: Some(Command::ReloadSingBox(ReloadSingBoxRequest {})),
        },
        responses,
    )
    .await;

    let frames = tokio::time::timeout(Duration::from_secs(5), async move {
        let mut frames = Vec::new();
        while let Some(frame) = receiver.recv().await {
            frames.push(frame);
        }
        frames
    })
    .await
    .expect("reload response channel should close");
    let stages: Vec<&str> = frames
        .iter()
        .filter(|frame| frame.status == RemoteControlResponseStatus::Progress as i32)
        .map(|frame| frame.stage.as_str())
        .collect();
    assert_eq!(
        stages,
        [
            "pull_configuration",
            "pull_users",
            "build_configuration",
            "configure_port_hopping",
            "start_instance",
        ]
    );
    let terminal = frames.last().expect("terminal reload response");
    assert_eq!(
        terminal.status,
        RemoteControlResponseStatus::Completed as i32
    );
    let Some(Payload::ReloadResult(result)) = terminal.payload.as_ref() else {
        panic!("terminal response must carry ReloadSingBoxResult");
    };
    assert_eq!(result.outcome, ReloadSingBoxOutcome::Succeeded as i32);
    assert_eq!(result.stage, "completed");
    assert_eq!(
        result.message,
        "sing-box reloaded with fresh panel configuration and users"
    );
    assert_eq!(result.topology_revision, 2);
    assert_eq!(result.loaded_user_count, 1);
    assert_eq!(
        result.config_sha256,
        "ea8e486ba259cd252ee99d956f79978f6efc3989aa9ddd35cd22faf8c663c2b3"
    );
    assert_eq!(panel.topology_calls.load(Ordering::SeqCst), 1);
    assert_eq!(lock(&runtime.applied).len(), 2, "initial + one reload");
    assert_eq!(manager.current_topology(), candidate);
}

struct RacingUserPanel {
    desired: Vec<UserCredential>,
    calls: AtomicUsize,
    first_entered: Semaphore,
    first_release: Semaphore,
}

impl RacingUserPanel {
    fn new(desired: Vec<UserCredential>) -> Self {
        Self {
            desired,
            calls: AtomicUsize::new(0),
            first_entered: Semaphore::new(0),
            first_release: Semaphore::new(0),
        }
    }
}

#[async_trait]
impl TopologyFetcher for RacingUserPanel {
    async fn fetch_machine_topology(&self) -> Result<MachineTopology, FetchError> {
        Err(FetchError::new("unused machine fetch"))
    }

    async fn fetch_node_users(&self, _node_id: &str) -> Result<Vec<UserCredential>, FetchError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.first_entered.add_permits(1);
            self.first_release
                .acquire()
                .await
                .expect("test release semaphore closed")
                .forget();
        }
        Ok(self.desired.clone())
    }
}

#[tokio::test]
async fn remote_user_sync_retries_a_racing_refresh_and_keeps_revision() {
    let runtime = Arc::new(RecordingTopologyRuntime::default());
    let manager = Arc::new(TopologyManager::new("machine-1", runtime));
    manager
        .apply_initial(topology(7, vec![user("user-1", "old")]))
        .await
        .unwrap();
    let panel = Arc::new(RacingUserPanel::new(vec![user("user-1", "final")]));
    let adapter = Arc::new(PanelRemoteFetcher::new(panel.clone(), manager.clone()));
    let sync = tokio::spawn({
        let adapter = adapter.clone();
        async move { adapter.sync_users(CancellationToken::new(), "node-1").await }
    });

    panel
        .first_entered
        .acquire()
        .await
        .expect("sync should enter first panel fetch")
        .forget();
    manager
        .refresh_node_users("node-1", vec![user("user-1", "racing")])
        .await
        .unwrap();
    panel.first_release.add_permits(1);

    let changes = sync.await.unwrap().unwrap();
    assert_eq!(changes.updated, 1);
    assert!(changes.applied);
    assert_eq!(panel.calls.load(Ordering::SeqCst), 2);
    assert_eq!(manager.current_revision(), Some(7));
    assert_eq!(
        manager.current_topology().nodes[0].users,
        vec![user("user-1", "final")]
    );
}

struct ConfigNodeRuntime {
    config: Vec<u8>,
    close_called: Notify,
}

#[async_trait]
impl NodeRuntime for ConfigNodeRuntime {
    async fn apply_config(&self, _config: RuntimeConfig) -> Result<(), RuntimeError> {
        Ok(())
    }

    async fn reload_config(
        &self,
        _config: RuntimeConfig,
    ) -> Result<RuntimeReloadStatus, RuntimeError> {
        Ok(RuntimeReloadStatus {
            running: true,
            rolled_back: false,
        })
    }

    fn current_config(&self) -> Vec<u8> {
        self.config.clone()
    }

    async fn close(&self) -> Result<(), RuntimeError> {
        self.close_called.notify_waiters();
        Ok(())
    }

    fn connection_stats(&self, _node_id: &str) -> ConnectionStats {
        ConnectionStats::default()
    }

    async fn close_user_connections(&self, _node_id: &str, _user_id: &str) -> u64 {
        0
    }

    async fn drain_traffic(&self) -> Result<Vec<TrafficDrain>, RuntimeError> {
        Ok(Vec::new())
    }
}

#[test]
fn runtime_remote_view_forwards_current_config_from_trait_object() {
    let runtime: Arc<dyn NodeRuntime> = Arc::new(ConfigNodeRuntime {
        config: b"diagnostic: true\n".to_vec(),
        close_called: Notify::new(),
    });
    let view = RuntimeRemoteView::new(runtime.clone());
    assert!(Arc::ptr_eq(view.runtime(), &runtime));
    assert_eq!(RemoteRuntime::current_config(&view), b"diagnostic: true\n");
    let _: Arc<dyn RemoteRuntime> = Arc::new(view);
}
