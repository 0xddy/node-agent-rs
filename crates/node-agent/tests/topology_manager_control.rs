use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use acp_proto::control_command::Payload;
use acp_proto::{
    ControlAck, ControlAckStatus, ControlCommand, ControlCommandType, MutationOperation,
    NodeMutation, TopologyDelta, UserCredential as ProtoUser, UserMutation, UserStatus,
};
use async_trait::async_trait;
use node_agent::control::{
    AckStatus, AckStore, CommandExecutor, ControlCommandWorker, FetchError,
    MAX_QUEUED_CONTROL_ACKS, TerminalResult, TopologyCommandExecutor, TopologyFetcher,
};
use node_agent::policy::PolicyState;
use node_agent::topology::manager::{
    ReloadOutcome, ReloadProgress, ReloadReporter, ReloadStage, TopologyError, TopologyErrorKind,
    TopologyManager, TopologyRuntime,
};
use node_agent::topology::{MachineTopology, NodeInstance, UserCredential, to_snapshot};
use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Default)]
struct RecordingRuntime {
    applied: Mutex<Vec<MachineTopology>>,
    closed: Mutex<Vec<(String, String)>>,
    reconciled: Mutex<Vec<MachineTopology>>,
    close_calls: AtomicUsize,
    fail: AtomicBool,
    rolled_back: AtomicBool,
}

#[async_trait]
impl TopologyRuntime for RecordingRuntime {
    async fn apply(&self, topology: &MachineTopology) -> Result<(), TopologyError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(TopologyError::runtime(
                "runtime update failed",
                self.rolled_back.load(Ordering::SeqCst),
            ));
        }
        lock(&self.applied).push(topology.clone());
        Ok(())
    }

    async fn close_user_connections(&self, node_id: &str, user_id: &str) -> u64 {
        lock(&self.closed).push((node_id.into(), user_id.into()));
        1
    }

    fn current_config(&self) -> Vec<u8> {
        b"running: true\n".to_vec()
    }

    async fn reconcile_current(&self, topology: &MachineTopology) -> Result<(), TopologyError> {
        lock(&self.reconciled).push(topology.clone());
        Ok(())
    }

    async fn close(&self) -> Result<(), TopologyError> {
        self.close_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn user(user_id: &str, credential: &str) -> UserCredential {
    UserCredential {
        user_id: user_id.into(),
        credential: credential.into(),
        ..Default::default()
    }
}

fn topology(revision: u64, users: Vec<UserCredential>) -> MachineTopology {
    let mut topology = MachineTopology {
        machine_id: "machine-1".into(),
        revision,
        nodes: vec![NodeInstance {
            node_id: "node-1".into(),
            provider_id: "provider".into(),
            provider_config_version: 1,
            users,
            ..Default::default()
        }],
        ..Default::default()
    };
    topology.snapshot = Some(to_snapshot(&topology));
    topology
}

fn proto_user(user_id: &str, credential: &str) -> ProtoUser {
    ProtoUser {
        user_id: user_id.into(),
        credential: credential.into(),
        status: UserStatus::Active as i32,
        ..Default::default()
    }
}

#[tokio::test]
async fn delta_fence_rejects_stale_mismatch_and_unversioned_without_mutation() {
    let runtime = Arc::new(RecordingRuntime::default());
    let manager = TopologyManager::new("machine-1", runtime.clone());
    manager
        .apply_initial(topology(100, vec![user("user-1", "old")]))
        .await
        .unwrap();

    for (delta, expected) in [
        (
            TopologyDelta {
                base_revision: 100,
                target_revision: 99,
                ..Default::default()
            },
            TopologyErrorKind::StaleRevision,
        ),
        (
            TopologyDelta {
                base_revision: 99,
                target_revision: 101,
                ..Default::default()
            },
            TopologyErrorKind::RevisionMismatch,
        ),
        (
            TopologyDelta {
                base_revision: 0,
                target_revision: 101,
                ..Default::default()
            },
            TopologyErrorKind::RevisionMismatch,
        ),
    ] {
        assert_eq!(
            manager.apply_delta(Some(&delta)).await.unwrap_err().kind(),
            expected
        );
    }
    assert_eq!(manager.current_revision(), Some(100));
    assert_eq!(manager.current_topology().nodes[0].users.len(), 1);
    assert_eq!(lock(&runtime.applied).len(), 1);
}

#[tokio::test]
async fn delta_user_mutation_is_published_only_after_runtime_success() {
    let runtime = Arc::new(RecordingRuntime::default());
    let manager = TopologyManager::new("machine-1", runtime.clone());
    manager
        .apply_initial(topology(1, vec![user("user-1", "old")]))
        .await
        .unwrap();
    runtime.fail.store(true, Ordering::SeqCst);

    let delta = TopologyDelta {
        base_revision: 1,
        target_revision: 2,
        user_mutations: vec![UserMutation {
            operation: MutationOperation::Delete as i32,
            node_id: "node-1".into(),
            revision: 2,
            user: Some(proto_user("user-1", "")),
            kick_existing_connections: true,
            ..Default::default()
        }],
        ..Default::default()
    };
    assert!(manager.apply_delta(Some(&delta)).await.is_err());
    assert_eq!(manager.current_revision(), Some(1));
    assert_eq!(manager.current_topology().nodes[0].users.len(), 1);
    assert!(lock(&runtime.closed).is_empty());
}

#[tokio::test]
async fn successful_user_mutations_close_removed_and_explicitly_kicked_sessions() {
    let runtime = Arc::new(RecordingRuntime::default());
    let manager = TopologyManager::new("machine-1", runtime.clone());
    manager
        .apply_initial(topology(1, vec![user("user-1", "old")]))
        .await
        .unwrap();

    manager
        .apply_user_mutation(
            Some(&UserMutation {
                operation: MutationOperation::Upsert as i32,
                node_id: "node-1".into(),
                revision: 2,
                user: Some(proto_user("user-1", "old")),
                kick_existing_connections: true,
                ..Default::default()
            }),
            1,
        )
        .await
        .unwrap();
    assert_eq!(
        lock(&runtime.closed).as_slice(),
        &[("node-1".into(), "user-1".into())]
    );

    manager
        .apply_user_mutation(
            Some(&UserMutation {
                operation: MutationOperation::Delete as i32,
                node_id: "node-1".into(),
                revision: 3,
                user: Some(proto_user("user-1", "")),
                kick_existing_connections: true,
                ..Default::default()
            }),
            2,
        )
        .await
        .unwrap();
    // Removal is closed by the old/new topology diff exactly once; the
    // explicit-kick path sees that the user is no longer authorized and skips.
    assert_eq!(lock(&runtime.closed).len(), 2);
}

#[tokio::test]
async fn refresh_replaces_all_users_and_noop_only_advances_revision() {
    let runtime = Arc::new(RecordingRuntime::default());
    let manager = TopologyManager::new("machine-1", runtime.clone());
    manager
        .apply_initial(topology(
            10,
            vec![user("keep", "old"), user("delete", "gone")],
        ))
        .await
        .unwrap();

    let desired = vec![user("keep", "new"), user("add", "fresh")];
    let changes = manager
        .refresh_node_users("node-1", desired.clone())
        .await
        .unwrap();
    assert_eq!((changes.added, changes.updated, changes.deleted), (1, 1, 1));
    assert!(changes.applied);
    assert_eq!(manager.current_topology().nodes[0].users, desired);
    assert_eq!(lock(&runtime.applied).len(), 2);

    let expected = manager.loaded_users("node-1").await.unwrap();
    let changes = manager
        .refresh_node_users_if_current_at_revision("node-1", expected.clone(), expected, 20)
        .await
        .unwrap();
    assert_eq!(changes, Default::default());
    assert_eq!(manager.current_revision(), Some(20));
    assert_eq!(manager.current_topology().snapshot.unwrap().revision, 20);
    assert_eq!(lock(&runtime.applied).len(), 2);
}

#[tokio::test]
async fn loaded_users_pages_preserve_order_and_bound_the_requested_range() {
    let runtime = Arc::new(RecordingRuntime::default());
    let manager = TopologyManager::new("machine-1", runtime);
    let users: Vec<_> = (0..5)
        .map(|index| user(&format!("user-{index}"), &format!("credential-{index}")))
        .collect();
    manager
        .apply_initial(topology(1, users.clone()))
        .await
        .unwrap();

    for (offset, limit, expected) in [
        (0, 2, &users[..2]),
        (4, 2, &users[4..]),
        (5, 2, &users[5..]),
        (u64::MAX, usize::MAX, &users[5..]),
        (0, 0, &users[..0]),
        (2, usize::MAX, &users[2..]),
    ] {
        let (total, page) = manager
            .loaded_users_page("node-1", offset, limit)
            .await
            .unwrap();
        assert_eq!(total, users.len());
        assert_eq!(page.as_slice(), expected);
    }
    assert_eq!(manager.loaded_users("node-1").await.unwrap(), users);
    let error = manager
        .loaded_users_page("missing", 0, 2)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), TopologyErrorKind::InvalidMutation);
    assert_eq!(
        error.to_string(),
        "node missing not found in loaded topology"
    );

    manager
        .refresh_node_users("node-1", Vec::new())
        .await
        .unwrap();
    assert_eq!(
        manager.loaded_users_page("node-1", 0, 2).await.unwrap(),
        (0, Vec::new())
    );
}

#[tokio::test]
async fn refresh_compare_and_swap_rejects_a_concurrent_user_mutation() {
    let runtime = Arc::new(RecordingRuntime::default());
    let manager = TopologyManager::new("machine-1", runtime);
    manager
        .apply_initial(topology(1, vec![user("user-1", "old")]))
        .await
        .unwrap();
    let stale = manager.loaded_users("node-1").await.unwrap();
    manager
        .apply_user_mutation(
            Some(&UserMutation {
                operation: MutationOperation::Upsert as i32,
                node_id: "node-1".into(),
                revision: 2,
                user: Some(proto_user("user-2", "new")),
                ..Default::default()
            }),
            1,
        )
        .await
        .unwrap();
    let error = manager
        .refresh_node_users_if_current_at_revision("node-1", vec![user("user-1", "old")], stale, 0)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), TopologyErrorKind::UsersChangedDuringRefresh);
    assert_eq!(manager.current_topology().nodes[0].users.len(), 2);
}

#[tokio::test]
async fn route_patch_replaces_only_global_routing_and_preserves_nodes() {
    let runtime = Arc::new(RecordingRuntime::default());
    let manager = TopologyManager::new("machine-1", runtime);
    manager
        .apply_initial(topology(1, vec![user("user-1", "old")]))
        .await
        .unwrap();
    manager
        .apply_route_patch(
            Some(&acp_proto::TopologyRoutePatch {
                machine_id: "machine-1".into(),
                revision: 2,
                outbounds: vec![acp_proto::OutboundConfig {
                    r#type: "direct".into(),
                    tag: "direct".into(),
                    ..Default::default()
                }],
                route: Some(acp_proto::RouteConfig {
                    r#final: "direct".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            1,
        )
        .await
        .unwrap();
    let current = manager.current_topology();
    assert_eq!(current.revision, 2);
    assert_eq!(current.nodes.len(), 1);
    assert_eq!(current.nodes[0].users[0].user_id, "user-1");
    assert_eq!(current.outbounds[0].tag, "direct");
    assert_eq!(current.route.unwrap().final_, "direct");
}

#[derive(Default)]
struct ProgressLog(Mutex<Vec<ReloadStage>>);

#[async_trait]
impl ReloadProgress for ProgressLog {
    async fn report(&self, stage: ReloadStage) {
        lock(&self.0).push(stage);
    }
}

#[tokio::test]
async fn reconcile_repairs_platform_state_without_reapply_or_revision_change() {
    let runtime = Arc::new(RecordingRuntime::default());
    let manager = TopologyManager::new("machine-1", runtime.clone());
    manager
        .apply_initial(topology(7, vec![user("user-1", "old")]))
        .await
        .unwrap();
    manager.reconcile_current().await.unwrap();
    assert_eq!(lock(&runtime.reconciled).len(), 1);
    assert_eq!(lock(&runtime.applied).len(), 1);
    assert_eq!(manager.current_revision(), Some(7));
    manager.close().await.unwrap();
    assert_eq!(runtime.close_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn forced_reload_reports_exact_stages_and_never_follows_with_apply() {
    let runtime = Arc::new(RecordingRuntime::default());
    let manager = Arc::new(TopologyManager::new("machine-1", runtime.clone()));
    manager
        .apply_initial(topology(1, vec![user("user-1", "old")]))
        .await
        .unwrap();
    let candidate = topology(2, vec![user("user-1", "new"), user("user-2", "fresh")]);
    let progress = Arc::new(ProgressLog::default());
    let result = manager
        .reload_from(
            move |reporter| async move {
                reporter.report(ReloadStage::PullUsers).await;
                Ok::<_, String>(candidate)
            },
            Some(progress.clone()),
        )
        .await;

    assert_eq!(result.outcome, ReloadOutcome::Succeeded);
    assert_eq!(result.stage, ReloadStage::Completed);
    assert_eq!(result.topology_revision, 2);
    assert_eq!(result.loaded_user_count, 2);
    assert_eq!(result.config_sha256.len(), 64);
    assert_eq!(manager.current_revision(), Some(2));
    // One initial apply plus one forced reload. A reload-then-apply bug records three.
    assert_eq!(lock(&runtime.applied).len(), 2);
    assert_eq!(
        lock(&progress.0).as_slice(),
        &[
            ReloadStage::PullConfiguration,
            ReloadStage::PullUsers,
            ReloadStage::BuildConfiguration,
            ReloadStage::ConfigurePortHopping,
            ReloadStage::StartInstance,
            ReloadStage::Completed,
        ]
    );
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReloadFailurePoint {
    Build,
    Configure,
    Start,
}

struct FailingReloadRuntime {
    point: ReloadFailurePoint,
    rolled_back: bool,
}

#[async_trait]
impl TopologyRuntime for FailingReloadRuntime {
    async fn apply(&self, _topology: &MachineTopology) -> Result<(), TopologyError> {
        Ok(())
    }

    async fn close_user_connections(&self, _node_id: &str, _user_id: &str) -> u64 {
        0
    }

    fn current_config(&self) -> Vec<u8> {
        Vec::new()
    }

    fn prepare_reload(
        &self,
        _topology: &MachineTopology,
    ) -> Result<node_agent::runtime::RuntimeConfig, TopologyError> {
        if self.point == ReloadFailurePoint::Build {
            Err(TopologyError::runtime("build failed", false))
        } else {
            Ok(Default::default())
        }
    }

    async fn configure_reload(&self, _topology: &MachineTopology) -> Result<(), TopologyError> {
        if self.point == ReloadFailurePoint::Configure {
            Err(TopologyError::runtime("configure failed", false))
        } else {
            Ok(())
        }
    }

    async fn reload_prepared(
        &self,
        _topology: &MachineTopology,
        _prepared: node_agent::runtime::RuntimeConfig,
    ) -> Result<node_agent::runtime::ReloadStatus, TopologyError> {
        if self.point == ReloadFailurePoint::Start {
            Err(TopologyError::runtime("start failed", self.rolled_back))
        } else {
            unreachable!()
        }
    }
}

#[tokio::test]
async fn forced_reload_classifies_pull_build_configure_and_start_failures() {
    let manager = Arc::new(TopologyManager::new(
        "machine-1",
        Arc::new(RecordingRuntime::default()),
    ));
    let pull_config = manager
        .reload_from(
            |_reporter| async { Err::<MachineTopology, _>("machine fetch failed") },
            None,
        )
        .await;
    assert_eq!(pull_config.stage, ReloadStage::PullConfiguration);
    let pull_users = manager
        .reload_from(
            |reporter| async move {
                reporter.report(ReloadStage::PullUsers).await;
                Err::<MachineTopology, _>("users fetch failed")
            },
            None,
        )
        .await;
    assert_eq!(pull_users.stage, ReloadStage::PullUsers);

    for (point, expected_stage) in [
        (ReloadFailurePoint::Build, ReloadStage::BuildConfiguration),
        (
            ReloadFailurePoint::Configure,
            ReloadStage::ConfigurePortHopping,
        ),
        (ReloadFailurePoint::Start, ReloadStage::StartInstance),
    ] {
        let manager = Arc::new(TopologyManager::new(
            "machine-1",
            Arc::new(FailingReloadRuntime {
                point,
                rolled_back: false,
            }),
        ));
        let result = manager
            .reload_from(
                |reporter| async move {
                    reporter.report(ReloadStage::PullUsers).await;
                    Ok::<_, String>(topology(2, vec![]))
                },
                None,
            )
            .await;
        assert_eq!(result.outcome, ReloadOutcome::FailedUnchanged);
        assert_eq!(result.stage, expected_stage);
        assert_eq!(manager.current_revision(), None);
    }

    let manager = Arc::new(TopologyManager::new(
        "machine-1",
        Arc::new(FailingReloadRuntime {
            point: ReloadFailurePoint::Start,
            rolled_back: true,
        }),
    ));
    let rolled_back = manager
        .reload_from(
            |reporter| async move {
                reporter.report(ReloadStage::PullUsers).await;
                Ok::<_, String>(topology(2, vec![]))
            },
            None,
        )
        .await;
    assert_eq!(rolled_back.outcome, ReloadOutcome::FailedRolledBack);
    assert_eq!(rolled_back.stage, ReloadStage::Rollback);
}

struct CancellationSafeReloadRuntime {
    runtime_revision: AtomicUsize,
    forwarding_revision: AtomicUsize,
    start_entered: Notify,
    allow_start: Semaphore,
}

#[async_trait]
impl TopologyRuntime for CancellationSafeReloadRuntime {
    async fn apply(&self, topology: &MachineTopology) -> Result<(), TopologyError> {
        self.runtime_revision
            .store(topology.revision as usize, Ordering::SeqCst);
        Ok(())
    }

    async fn close_user_connections(&self, _node_id: &str, _user_id: &str) -> u64 {
        0
    }

    fn current_config(&self) -> Vec<u8> {
        Vec::new()
    }

    async fn configure_reload(&self, topology: &MachineTopology) -> Result<(), TopologyError> {
        self.forwarding_revision
            .store(topology.revision as usize, Ordering::SeqCst);
        Ok(())
    }

    async fn reload_prepared(
        &self,
        topology: &MachineTopology,
        _prepared: node_agent::runtime::RuntimeConfig,
    ) -> Result<node_agent::runtime::ReloadStatus, TopologyError> {
        self.start_entered.notify_waiters();
        self.allow_start.acquire().await.unwrap().forget();
        self.runtime_revision
            .store(topology.revision as usize, Ordering::SeqCst);
        Ok(node_agent::runtime::ReloadStatus {
            running: true,
            rolled_back: false,
        })
    }
}

#[tokio::test]
async fn cancelling_reload_caller_does_not_abandon_configured_transaction() {
    let runtime = Arc::new(CancellationSafeReloadRuntime {
        runtime_revision: AtomicUsize::new(0),
        forwarding_revision: AtomicUsize::new(0),
        start_entered: Notify::new(),
        allow_start: Semaphore::new(0),
    });
    let manager = Arc::new(TopologyManager::new("machine-1", runtime.clone()));
    manager.apply_initial(topology(1, vec![])).await.unwrap();

    let start_entered = runtime.start_entered.notified();
    let reload_manager = manager.clone();
    let caller = tokio::spawn(async move {
        reload_manager
            .reload_from(
                |reporter| async move {
                    reporter.report(ReloadStage::PullUsers).await;
                    Ok::<_, String>(topology(2, vec![]))
                },
                None,
            )
            .await
    });
    start_entered.await;
    assert_eq!(runtime.forwarding_revision.load(Ordering::SeqCst), 2);
    assert_eq!(runtime.runtime_revision.load(Ordering::SeqCst), 1);
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());

    runtime.allow_start.add_permits(1);
    tokio::time::timeout(Duration::from_secs(1), async {
        while manager.current_revision() != Some(2) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("owned reload transaction did not finish after caller cancellation");
    assert_eq!(runtime.forwarding_revision.load(Ordering::SeqCst), 2);
    assert_eq!(runtime.runtime_revision.load(Ordering::SeqCst), 2);
}

struct QueueFetcher {
    topologies: Mutex<VecDeque<MachineTopology>>,
    users: Mutex<Vec<UserCredential>>,
    topology_calls: AtomicUsize,
}

struct DelayedTopologyFetcher {
    topology: Mutex<Option<MachineTopology>>,
    started: Notify,
    release: Semaphore,
}

#[async_trait]
impl TopologyFetcher for DelayedTopologyFetcher {
    async fn fetch_machine_topology(&self) -> Result<MachineTopology, FetchError> {
        let topology = lock(&self.topology)
            .take()
            .ok_or_else(|| FetchError::new("no delayed topology queued"))?;
        self.started.notify_waiters();
        self.release.acquire().await.unwrap().forget();
        Ok(topology)
    }

    async fn fetch_node_users(&self, _node_id: &str) -> Result<Vec<UserCredential>, FetchError> {
        Ok(Vec::new())
    }
}

impl QueueFetcher {
    fn new(topologies: Vec<MachineTopology>) -> Self {
        Self {
            topologies: Mutex::new(topologies.into()),
            users: Mutex::new(Vec::new()),
            topology_calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl TopologyFetcher for QueueFetcher {
    async fn fetch_machine_topology(&self) -> Result<MachineTopology, FetchError> {
        self.topology_calls.fetch_add(1, Ordering::SeqCst);
        lock(&self.topologies)
            .pop_front()
            .ok_or_else(|| FetchError::new("no authoritative topology queued"))
    }

    async fn fetch_machine_topology_with_progress(
        &self,
        reporter: ReloadReporter,
    ) -> Result<MachineTopology, FetchError> {
        reporter.report(ReloadStage::PullUsers).await;
        self.fetch_machine_topology().await
    }

    async fn fetch_node_users(&self, _node_id: &str) -> Result<Vec<UserCredential>, FetchError> {
        Ok(lock(&self.users).clone())
    }
}

struct FetchDropGuard(Arc<AtomicBool>);

impl Drop for FetchDropGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct BlockingUserFetcher {
    started: Notify,
    dropped: Arc<AtomicBool>,
}

#[async_trait]
impl TopologyFetcher for BlockingUserFetcher {
    async fn fetch_machine_topology(&self) -> Result<MachineTopology, FetchError> {
        Err(FetchError::new("machine topology is not used"))
    }

    async fn fetch_node_users(&self, _node_id: &str) -> Result<Vec<UserCredential>, FetchError> {
        let _drop_guard = FetchDropGuard(self.dropped.clone());
        self.started.notify_waiters();
        std::future::pending().await
    }
}

struct BlockingTransactionRuntime {
    calls: AtomicUsize,
    applied: Mutex<Vec<MachineTopology>>,
    started: Notify,
    permits: Semaphore,
}

impl Default for BlockingTransactionRuntime {
    fn default() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            applied: Mutex::new(Vec::new()),
            started: Notify::new(),
            permits: Semaphore::new(0),
        }
    }
}

#[async_trait]
impl TopologyRuntime for BlockingTransactionRuntime {
    async fn apply(&self, topology: &MachineTopology) -> Result<(), TopologyError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call > 0 {
            self.started.notify_waiters();
            self.permits.acquire().await.unwrap().forget();
        }
        lock(&self.applied).push(topology.clone());
        Ok(())
    }

    async fn close_user_connections(&self, _node_id: &str, _user_id: &str) -> u64 {
        0
    }

    fn current_config(&self) -> Vec<u8> {
        b"running: true\n".to_vec()
    }
}

fn user_refresh_command() -> ControlCommand {
    ControlCommand {
        command_id: "refresh".into(),
        operation_id: "operation-refresh".into(),
        machine_id: "machine-1".into(),
        node_id: "node-1".into(),
        base_revision: 1,
        revision: 2,
        r#type: ControlCommandType::UserRefresh as i32,
        ..Default::default()
    }
}

#[tokio::test]
async fn generation_cancel_drops_dequeued_panel_fetch_without_late_apply() {
    let runtime = Arc::new(RecordingRuntime::default());
    let manager = Arc::new(TopologyManager::new("machine-1", runtime.clone()));
    manager
        .apply_initial(topology(1, vec![user("old", "old")]))
        .await
        .unwrap();
    let dropped = Arc::new(AtomicBool::new(false));
    let fetcher = Arc::new(BlockingUserFetcher {
        started: Notify::new(),
        dropped: dropped.clone(),
    });
    let started = fetcher.started.notified();
    let cancellation = CancellationToken::new();
    let (worker, mut acks) = ControlCommandWorker::spawn_with_cancel(
        Arc::new(TopologyCommandExecutor::new(
            manager.clone(),
            fetcher.clone(),
        )),
        Arc::new(AckStore::new()),
        cancellation.clone(),
    );

    worker.submit(user_refresh_command()).await.unwrap();
    assert_eq!(
        ack(&mut acks).await.status,
        ControlAckStatus::Accepted as i32
    );
    started.await;
    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !dropped.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("generation cancellation did not drop the panel fetch");

    assert_eq!(manager.current_revision(), Some(1));
    assert_eq!(lock(&runtime.applied).len(), 1, "no late apply is allowed");
    assert!(
        acks.try_recv().is_err(),
        "cancelled session gets no terminal ACK"
    );
    drop(worker);
}

#[tokio::test]
async fn generation_cancel_after_local_transaction_start_still_commits_consistently() {
    let runtime = Arc::new(BlockingTransactionRuntime::default());
    let manager = Arc::new(TopologyManager::new("machine-1", runtime.clone()));
    manager
        .apply_initial(topology(1, vec![user("old", "old")]))
        .await
        .unwrap();
    let fetcher = Arc::new(QueueFetcher::new(Vec::new()));
    *lock(&fetcher.users) = vec![user("new", "new")];
    let started = runtime.started.notified();
    let cancellation = CancellationToken::new();
    let (worker, mut acks) = ControlCommandWorker::spawn_with_cancel(
        Arc::new(TopologyCommandExecutor::new(manager.clone(), fetcher)),
        Arc::new(AckStore::new()),
        cancellation.clone(),
    );

    worker.submit(user_refresh_command()).await.unwrap();
    assert_eq!(
        ack(&mut acks).await.status,
        ControlAckStatus::Accepted as i32
    );
    started.await;
    cancellation.cancel();
    runtime.permits.add_permits(1);
    tokio::time::timeout(Duration::from_secs(1), async {
        while manager.current_revision() != Some(2) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("started local transaction did not finish after generation cancellation");

    assert_eq!(lock(&runtime.applied).len(), 2);
    assert_eq!(manager.current_topology().nodes[0].users[0].user_id, "new");
    assert!(
        acks.try_recv().is_err(),
        "cancelled session gets no terminal ACK"
    );
    drop(worker);
}

fn user_upsert_command(base: u64, target: u64, user_id: &str) -> ControlCommand {
    ControlCommand {
        command_id: "command-1".into(),
        operation_id: "operation-1".into(),
        machine_id: "machine-1".into(),
        node_id: "node-1".into(),
        base_revision: base,
        revision: target,
        r#type: ControlCommandType::UserMutation as i32,
        payload: Some(Payload::UserMutation(UserMutation {
            operation: MutationOperation::Upsert as i32,
            machine_id: "machine-1".into(),
            node_id: "node-1".into(),
            revision: target,
            user: Some(proto_user(user_id, "credential")),
            ..Default::default()
        })),
        ..Default::default()
    }
}

#[tokio::test]
async fn missing_predecessor_resyncs_and_rebases_original_command() {
    let runtime = Arc::new(RecordingRuntime::default());
    let manager = Arc::new(TopologyManager::new("machine-1", runtime));
    manager
        .apply_initial(topology(100, vec![user("user-1", "old")]))
        .await
        .unwrap();
    let fetcher = Arc::new(QueueFetcher::new(vec![topology(
        200,
        vec![user("user-1", "old")],
    )]));
    let executor = TopologyCommandExecutor::new(manager.clone(), fetcher);

    let result = executor
        .execute(user_upsert_command(200, 300, "user-2"))
        .await;
    assert_eq!(result.status, AckStatus::Applied);
    assert!(result.message.contains("replayed"), "{}", result.message);
    assert_eq!(manager.current_revision(), Some(300));
    assert_eq!(manager.current_topology().nodes[0].users.len(), 2);
}

#[tokio::test]
async fn newer_authoritative_snapshot_wins_without_replaying_old_command() {
    let runtime = Arc::new(RecordingRuntime::default());
    let manager = Arc::new(TopologyManager::new("machine-1", runtime));
    manager
        .apply_initial(topology(100, vec![user("user-1", "old")]))
        .await
        .unwrap();
    let fetcher = Arc::new(QueueFetcher::new(vec![topology(
        400,
        vec![user("authoritative", "new")],
    )]));
    let executor = TopologyCommandExecutor::new(manager.clone(), fetcher);

    let result = executor
        .execute(user_upsert_command(200, 300, "must-not-apply"))
        .await;
    assert_eq!(result.status, AckStatus::Applied);
    assert!(!result.message.contains("replayed"));
    assert_eq!(manager.current_revision(), Some(400));
    assert_eq!(
        manager.current_topology().nodes[0].users[0].user_id,
        "authoritative"
    );
}

#[tokio::test]
async fn delayed_resync_cannot_roll_back_a_newer_snapshot_from_the_other_lane() {
    let runtime = Arc::new(RecordingRuntime::default());
    let manager = Arc::new(TopologyManager::new("machine-1", runtime.clone()));
    manager
        .apply_initial(topology(100, vec![user("initial", "old")]))
        .await
        .unwrap();
    let fetcher = Arc::new(DelayedTopologyFetcher {
        topology: Mutex::new(Some(topology(150, vec![user("stale-resync", "stale")]))),
        started: Notify::new(),
        release: Semaphore::new(0),
    });
    let fetch_started = fetcher.started.notified();
    let (worker, mut acks) = ControlCommandWorker::spawn(
        Arc::new(TopologyCommandExecutor::new(
            manager.clone(),
            fetcher.clone(),
        )),
        Arc::new(AckStore::new()),
    );

    worker
        .submit(ControlCommand {
            command_id: "refresh-stale".into(),
            operation_id: "refresh-stale".into(),
            machine_id: "machine-1".into(),
            node_id: "node-1".into(),
            base_revision: 99,
            revision: 150,
            r#type: ControlCommandType::UserRefresh as i32,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        ack(&mut acks).await.status,
        ControlAckStatus::Accepted as i32
    );
    fetch_started.await;

    let newer = topology(300, vec![user("newer", "new")]);
    worker
        .submit(ControlCommand {
            command_id: "snapshot-newer".into(),
            operation_id: "snapshot-newer".into(),
            machine_id: "machine-1".into(),
            revision: 300,
            r#type: ControlCommandType::TopologySnapshot as i32,
            payload: Some(Payload::TopologySnapshot(to_snapshot(&newer))),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        ack(&mut acks).await.status,
        ControlAckStatus::Accepted as i32
    );
    let applied = ack(&mut acks).await;
    assert_eq!(applied.command_id, "snapshot-newer");
    assert_eq!(applied.status, ControlAckStatus::Applied as i32);
    assert_eq!(manager.current_revision(), Some(300));

    fetcher.release.add_permits(1);
    let rejected = ack(&mut acks).await;
    assert_eq!(rejected.command_id, "refresh-stale");
    assert_eq!(rejected.status, ControlAckStatus::Failed as i32);
    assert!(rejected.message.contains("stale authoritative topology"));
    assert_eq!(manager.current_revision(), Some(300));
    assert_eq!(
        manager.current_topology().nodes[0].users[0].user_id,
        "newer"
    );
    assert_eq!(
        lock(&runtime.applied)
            .iter()
            .map(|candidate| candidate.revision)
            .collect::<Vec<_>>(),
        vec![100, 300]
    );
    drop(worker);
}

#[tokio::test]
async fn delayed_resync_cannot_roll_back_different_content_at_the_same_revision() {
    let runtime = Arc::new(RecordingRuntime::default());
    let manager = Arc::new(TopologyManager::new("machine-1", runtime.clone()));
    manager
        .apply_initial(topology(100, vec![user("initial", "old")]))
        .await
        .unwrap();
    let fetcher = Arc::new(DelayedTopologyFetcher {
        topology: Mutex::new(Some(topology(150, vec![user("stale-resync", "stale")]))),
        started: Notify::new(),
        release: Semaphore::new(0),
    });
    let fetch_started = fetcher.started.notified();
    let (worker, mut acks) = ControlCommandWorker::spawn(
        Arc::new(TopologyCommandExecutor::new(
            manager.clone(),
            fetcher.clone(),
        )),
        Arc::new(AckStore::new()),
    );

    worker
        .submit(ControlCommand {
            command_id: "refresh-stale-equal".into(),
            operation_id: "refresh-stale-equal".into(),
            machine_id: "machine-1".into(),
            node_id: "node-1".into(),
            base_revision: 99,
            revision: 150,
            r#type: ControlCommandType::UserRefresh as i32,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        ack(&mut acks).await.status,
        ControlAckStatus::Accepted as i32
    );
    fetch_started.await;

    let winner = topology(150, vec![user("same-revision-winner", "new")]);
    worker
        .submit(ControlCommand {
            command_id: "snapshot-equal".into(),
            operation_id: "snapshot-equal".into(),
            machine_id: "machine-1".into(),
            revision: 150,
            r#type: ControlCommandType::TopologySnapshot as i32,
            payload: Some(Payload::TopologySnapshot(to_snapshot(&winner))),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        ack(&mut acks).await.status,
        ControlAckStatus::Accepted as i32
    );
    let applied = ack(&mut acks).await;
    assert_eq!(applied.command_id, "snapshot-equal");
    assert_eq!(applied.status, ControlAckStatus::Applied as i32);

    fetcher.release.add_permits(1);
    let rejected = ack(&mut acks).await;
    assert_eq!(rejected.command_id, "refresh-stale-equal");
    assert_eq!(rejected.status, ControlAckStatus::Failed as i32);
    assert!(
        rejected
            .message
            .contains("authoritative topology changed during fetch"),
        "{}",
        rejected.message
    );
    assert_eq!(manager.current_revision(), Some(150));
    assert_eq!(
        manager.current_topology().nodes[0].users[0].user_id,
        "same-revision-winner"
    );
    assert_eq!(
        lock(&runtime.applied)
            .iter()
            .map(|candidate| (
                candidate.revision,
                candidate.nodes[0].users[0].user_id.clone()
            ))
            .collect::<Vec<_>>(),
        vec![
            (100, "initial".to_string()),
            (150, "same-revision-winner".to_string())
        ]
    );
    drop(worker);
}

#[tokio::test]
async fn user_refresh_rejects_replay_from_older_authoritative_snapshot() {
    let runtime = Arc::new(RecordingRuntime::default());
    let manager = Arc::new(TopologyManager::new("machine-1", runtime.clone()));
    manager
        .apply_initial(topology(100, vec![user("user-1", "old")]))
        .await
        .unwrap();
    let fetcher = Arc::new(QueueFetcher::new(vec![topology(
        150,
        vec![user("user-1", "old")],
    )]));
    let executor = TopologyCommandExecutor::new(manager.clone(), fetcher);
    let result = executor
        .execute(ControlCommand {
            command_id: "refresh".into(),
            node_id: "node-1".into(),
            base_revision: 200,
            revision: 300,
            r#type: ControlCommandType::UserRefresh as i32,
            ..Default::default()
        })
        .await;
    assert_eq!(result.status, AckStatus::Failed);
    assert!(result.message.contains("older authoritative snapshot"));
    assert_eq!(manager.current_revision(), Some(100));
    assert_eq!(lock(&runtime.applied).len(), 1);
}

#[tokio::test]
async fn fenced_user_refresh_fetches_and_applies_complete_replacement() {
    let runtime = Arc::new(RecordingRuntime::default());
    let manager = Arc::new(TopologyManager::new("machine-1", runtime));
    manager
        .apply_initial(topology(1, vec![user("old", "old")]))
        .await
        .unwrap();
    let fetcher = Arc::new(QueueFetcher::new(vec![]));
    *lock(&fetcher.users) = vec![user("new", "new")];
    let executor = TopologyCommandExecutor::new(manager.clone(), fetcher);
    let result = executor
        .execute(ControlCommand {
            command_id: "refresh".into(),
            node_id: "node-1".into(),
            base_revision: 1,
            revision: 2,
            r#type: ControlCommandType::UserRefresh as i32,
            ..Default::default()
        })
        .await;
    assert_eq!(result.status, AckStatus::Applied);
    assert!(
        result
            .message
            .contains("added=1 updated=0 deleted=1 applied=true")
    );
    assert_eq!(manager.current_revision(), Some(2));
    assert_eq!(manager.current_topology().nodes[0].users[0].user_id, "new");
}

#[tokio::test]
async fn runtime_rollback_maps_to_rolled_back_terminal_status() {
    let runtime = Arc::new(RecordingRuntime::default());
    let manager = Arc::new(TopologyManager::new("machine-1", runtime.clone()));
    manager
        .apply_initial(topology(1, vec![user("user-1", "old")]))
        .await
        .unwrap();
    runtime.fail.store(true, Ordering::SeqCst);
    runtime.rolled_back.store(true, Ordering::SeqCst);
    let executor =
        TopologyCommandExecutor::new(manager.clone(), Arc::new(QueueFetcher::new(Vec::new())));
    let result = executor.execute(user_upsert_command(1, 2, "user-2")).await;
    assert_eq!(result.status, AckStatus::RolledBack);
    assert_eq!(manager.current_revision(), Some(1));
}

#[tokio::test]
async fn dispatcher_routes_maintenance_and_diagnostics_to_policy_state() {
    let manager = Arc::new(TopologyManager::new(
        "machine-1",
        Arc::new(RecordingRuntime::default()),
    ));
    let policy = Arc::new(PolicyState::new());
    let executor = TopologyCommandExecutor::with_policy(
        manager,
        Arc::new(QueueFetcher::new(Vec::new())),
        policy.clone(),
    );
    let maintenance = executor
        .execute(ControlCommand {
            r#type: ControlCommandType::Maintenance as i32,
            payload: Some(Payload::Maintenance(acp_proto::MaintenanceCommand {
                enabled: true,
                ..Default::default()
            })),
            ..Default::default()
        })
        .await;
    assert_eq!(maintenance.status, AckStatus::Applied);
    assert!(policy.maintenance());
    let diagnostics = executor
        .execute(ControlCommand {
            r#type: ControlCommandType::Diagnostics as i32,
            payload: Some(Payload::Diagnostics(
                acp_proto::DiagnosticsCommand::default(),
            )),
            ..Default::default()
        })
        .await;
    assert_eq!(diagnostics.status, AckStatus::Applied);
    let upgrade = executor
        .execute(ControlCommand {
            r#type: ControlCommandType::Upgrade as i32,
            ..Default::default()
        })
        .await;
    assert_eq!(upgrade.status, AckStatus::Failed);
}

struct ImmediateExecutor {
    calls: AtomicUsize,
}

#[async_trait]
impl CommandExecutor for ImmediateExecutor {
    async fn execute(&self, _command: ControlCommand) -> TerminalResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        TerminalResult::applied("applied")
    }
}

struct PanicExecutor;

#[async_trait]
impl CommandExecutor for PanicExecutor {
    async fn execute(&self, _command: ControlCommand) -> TerminalResult {
        panic!("boom")
    }
}

struct CancelExecutor {
    calls: AtomicUsize,
    completed: AtomicUsize,
    started: Notify,
    permits: Semaphore,
}

#[async_trait]
impl CommandExecutor for CancelExecutor {
    async fn execute(&self, _command: ControlCommand) -> TerminalResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.notify_waiters();
        self.permits.acquire().await.unwrap().forget();
        self.completed.fetch_add(1, Ordering::SeqCst);
        TerminalResult::applied("applied")
    }
}

async fn ack(receiver: &mut tokio::sync::mpsc::Receiver<ControlAck>) -> ControlAck {
    tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await
        .expect("timed out waiting for ACK")
        .expect("ACK channel closed")
}

fn queued_command(id: &str, kind: ControlCommandType) -> ControlCommand {
    ControlCommand {
        command_id: id.into(),
        operation_id: format!("operation-{id}"),
        machine_id: "machine-1".into(),
        node_id: "node-1".into(),
        revision: 10,
        r#type: kind as i32,
        ..Default::default()
    }
}

#[tokio::test]
async fn worker_sends_accepted_then_terminal_and_replays_ack_store() {
    let executor = Arc::new(ImmediateExecutor {
        calls: AtomicUsize::new(0),
    });
    let (worker, mut acks) =
        ControlCommandWorker::spawn(executor.clone(), Arc::new(AckStore::new()));
    let mut first = queued_command("first", ControlCommandType::UserMutation);
    first.idempotency_key = "same-operation".into();
    worker.submit(first).await.unwrap();
    assert_eq!(
        ack(&mut acks).await.status,
        ControlAckStatus::Accepted as i32
    );
    assert_eq!(
        ack(&mut acks).await.status,
        ControlAckStatus::Applied as i32
    );

    let mut replay = queued_command("second", ControlCommandType::UserMutation);
    replay.idempotency_key = "same-operation".into();
    worker.submit(replay).await.unwrap();
    let accepted = ack(&mut acks).await;
    let terminal = ack(&mut acks).await;
    assert_eq!(accepted.command_id, "second");
    assert_eq!(terminal.command_id, "second");
    assert_eq!(terminal.operation_id, "operation-second");
    assert_eq!(terminal.status, ControlAckStatus::Applied as i32);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn worker_preserves_command_payload_and_terminal_envelope() {
    struct PayloadExecutor(Mutex<Option<ControlCommand>>);

    #[async_trait]
    impl CommandExecutor for PayloadExecutor {
        async fn execute(&self, command: ControlCommand) -> TerminalResult {
            *lock(&self.0) = Some(command);
            TerminalResult::applied("payload executed")
        }
    }

    let executor = Arc::new(PayloadExecutor(Mutex::new(None)));
    let (worker, mut acks) =
        ControlCommandWorker::spawn(executor.clone(), Arc::new(AckStore::new()));
    let mut command = queued_command("snapshot", ControlCommandType::TopologySnapshot);
    command.idempotency_key = "snapshot-operation".into();
    command.legacy_payload = vec![7; 4096];
    command.payload = Some(Payload::TopologySnapshot(acp_proto::TopologySnapshot {
        machine_id: "machine-1".into(),
        revision: 10,
        ..Default::default()
    }));
    worker.submit(command.clone()).await.unwrap();
    assert_eq!(
        ack(&mut acks).await.status,
        ControlAckStatus::Accepted as i32
    );
    let terminal = ack(&mut acks).await;

    assert_eq!(lock(&executor.0).take(), Some(command.clone()));
    assert_eq!(terminal.command_id, command.command_id);
    assert_eq!(terminal.operation_id, command.operation_id);
    assert_eq!(terminal.machine_id, command.machine_id);
    assert_eq!(terminal.node_id, command.node_id);
    assert_eq!(terminal.revision, command.revision);
    assert_eq!(terminal.idempotency_key, command.idempotency_key);
    assert_eq!(terminal.status, ControlAckStatus::Applied as i32);
    assert_eq!(terminal.message, "payload executed");
}

#[tokio::test]
async fn worker_converts_panics_to_failed_terminal_ack() {
    let (worker, mut acks) =
        ControlCommandWorker::spawn(Arc::new(PanicExecutor), Arc::new(AckStore::new()));
    worker
        .submit(queued_command("panic", ControlCommandType::UserMutation))
        .await
        .unwrap();
    assert_eq!(
        ack(&mut acks).await.status,
        ControlAckStatus::Accepted as i32
    );
    let failed = ack(&mut acks).await;
    assert_eq!(failed.status, ControlAckStatus::Failed as i32);
    assert!(
        failed.message.contains("panicked: boom"),
        "{}",
        failed.message
    );
}

#[tokio::test]
async fn dropping_worker_finishes_started_command_but_discards_ack_and_queue() {
    let executor = Arc::new(CancelExecutor {
        calls: AtomicUsize::new(0),
        completed: AtomicUsize::new(0),
        started: Notify::new(),
        permits: Semaphore::new(0),
    });
    let (worker, mut acks) = ControlCommandWorker::spawn_with_capacity(
        executor.clone(),
        Arc::new(AckStore::new()),
        2,
        2,
    );
    let started = executor.started.notified();
    worker
        .submit(queued_command("started", ControlCommandType::UserMutation))
        .await
        .unwrap();
    assert_eq!(
        ack(&mut acks).await.status,
        ControlAckStatus::Accepted as i32
    );
    started.await;
    worker
        .submit(queued_command("queued", ControlCommandType::UserMutation))
        .await
        .unwrap();
    assert_eq!(
        ack(&mut acks).await.status,
        ControlAckStatus::Accepted as i32
    );

    drop(worker);
    executor.permits.add_permits(1);
    tokio::time::timeout(Duration::from_secs(1), async {
        while executor.completed.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::task::yield_now().await;
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    assert!(
        acks.try_recv().is_err(),
        "disconnected session must not receive a terminal ACK"
    );
}

struct GateExecutor {
    block_refresh_only: bool,
    started: Notify,
    permits: Semaphore,
}

impl GateExecutor {
    fn new(block_refresh_only: bool) -> Self {
        Self {
            block_refresh_only,
            started: Notify::new(),
            permits: Semaphore::new(0),
        }
    }
}

#[async_trait]
impl CommandExecutor for GateExecutor {
    async fn execute(&self, command: ControlCommand) -> TerminalResult {
        let should_block =
            !self.block_refresh_only || command.r#type == ControlCommandType::UserRefresh as i32;
        if should_block {
            self.started.notify_waiters();
            self.permits.acquire().await.unwrap().forget();
        }
        TerminalResult::applied("applied")
    }
}

#[tokio::test]
async fn acknowledgement_queue_backpressures_at_its_memory_bound() {
    let executor = Arc::new(GateExecutor::new(false));
    let (worker, mut acks) = ControlCommandWorker::spawn_with_capacity(
        executor.clone(),
        Arc::new(AckStore::new()),
        MAX_QUEUED_CONTROL_ACKS + 1,
        1,
    );
    let started = executor.started.notified();
    worker
        .submit(queued_command(
            "bounded-0",
            ControlCommandType::UserMutation,
        ))
        .await
        .unwrap();
    started.await;
    for index in 1..MAX_QUEUED_CONTROL_ACKS {
        worker
            .submit(queued_command(
                &format!("bounded-{index}"),
                ControlCommandType::UserMutation,
            ))
            .await
            .unwrap();
    }
    assert_eq!(acks.len(), MAX_QUEUED_CONTROL_ACKS);

    let clone = worker.clone();
    let mut blocked = tokio::spawn(async move {
        clone
            .submit(queued_command(
                "bounded-overflow",
                ControlCommandType::UserMutation,
            ))
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut blocked)
            .await
            .is_err(),
        "ACK production must wait instead of growing past its bound"
    );

    assert_eq!(ack(&mut acks).await.command_id, "bounded-0");
    blocked.await.unwrap().unwrap();
    assert_eq!(acks.len(), MAX_QUEUED_CONTROL_ACKS);
    drop(worker);
    executor.permits.add_permits(1);
}

#[tokio::test]
async fn refresh_lane_full_is_failed_explicitly() {
    let executor = Arc::new(GateExecutor::new(false));
    let (worker, mut acks) = ControlCommandWorker::spawn_with_capacity(
        executor.clone(),
        Arc::new(AckStore::new()),
        1,
        1,
    );
    let started = executor.started.notified();
    worker
        .submit(queued_command("refresh-1", ControlCommandType::UserRefresh))
        .await
        .unwrap();
    assert_eq!(
        ack(&mut acks).await.status,
        ControlAckStatus::Accepted as i32
    );
    started.await;
    worker
        .submit(queued_command("refresh-2", ControlCommandType::UserRefresh))
        .await
        .unwrap();
    assert_eq!(
        ack(&mut acks).await.status,
        ControlAckStatus::Accepted as i32
    );
    worker
        .submit(queued_command("refresh-3", ControlCommandType::UserRefresh))
        .await
        .unwrap();
    assert_eq!(
        ack(&mut acks).await.status,
        ControlAckStatus::Accepted as i32
    );
    let failed = ack(&mut acks).await;
    assert_eq!(failed.command_id, "refresh-3");
    assert_eq!(failed.status, ControlAckStatus::Failed as i32);
    assert_eq!(failed.message, "user refresh queue is full");
    executor.permits.add_permits(2);
}

#[tokio::test]
async fn regular_lane_backpressures_while_refresh_lane_does_not_block_it() {
    let executor = Arc::new(GateExecutor::new(false));
    let (worker, mut acks) = ControlCommandWorker::spawn_with_capacity(
        executor.clone(),
        Arc::new(AckStore::new()),
        1,
        1,
    );
    let started = executor.started.notified();
    worker
        .submit(queued_command(
            "regular-1",
            ControlCommandType::UserMutation,
        ))
        .await
        .unwrap();
    assert_eq!(
        ack(&mut acks).await.status,
        ControlAckStatus::Accepted as i32
    );
    started.await;
    worker
        .submit(queued_command(
            "regular-2",
            ControlCommandType::UserMutation,
        ))
        .await
        .unwrap();
    assert_eq!(
        ack(&mut acks).await.status,
        ControlAckStatus::Accepted as i32
    );

    let clone = worker.clone();
    let mut blocked = tokio::spawn(async move {
        clone
            .submit(queued_command(
                "regular-3",
                ControlCommandType::UserMutation,
            ))
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut blocked)
            .await
            .is_err(),
        "third regular command should wait for bounded queue capacity"
    );
    assert!(
        acks.try_recv().is_err(),
        "a backpressured command is not accepted yet"
    );
    executor.permits.add_permits(3);
    blocked.await.unwrap().unwrap();
    loop {
        let candidate = ack(&mut acks).await;
        if candidate.command_id == "regular-3"
            && candidate.status == ControlAckStatus::Accepted as i32
        {
            break;
        }
    }

    let independent = Arc::new(GateExecutor::new(true));
    let (worker, mut acks) = ControlCommandWorker::spawn_with_capacity(
        independent.clone(),
        Arc::new(AckStore::new()),
        1,
        1,
    );
    let refresh_started = independent.started.notified();
    worker
        .submit(queued_command("refresh", ControlCommandType::UserRefresh))
        .await
        .unwrap();
    assert_eq!(
        ack(&mut acks).await.status,
        ControlAckStatus::Accepted as i32
    );
    refresh_started.await;
    worker
        .submit(queued_command("regular", ControlCommandType::UserMutation))
        .await
        .unwrap();
    assert_eq!(ack(&mut acks).await.command_id, "regular");
    let terminal = ack(&mut acks).await;
    assert_eq!(terminal.command_id, "regular");
    assert_eq!(terminal.status, ControlAckStatus::Applied as i32);
    independent.permits.add_permits(1);
}

#[tokio::test]
async fn node_delta_upsert_and_delete_match_go_mutation_defaults() {
    let runtime = Arc::new(RecordingRuntime::default());
    let manager = TopologyManager::new("machine-1", runtime);
    manager.apply_initial(topology(1, vec![])).await.unwrap();
    manager
        .apply_delta(Some(&TopologyDelta {
            base_revision: 1,
            target_revision: 2,
            node_mutations: vec![NodeMutation {
                operation: MutationOperation::Upsert as i32,
                node_id: "node-2".into(),
                node: None,
            }],
            ..Default::default()
        }))
        .await
        .unwrap();
    assert!(
        manager
            .current_topology()
            .nodes
            .iter()
            .any(|node| node.node_id == "node-2")
    );
    manager
        .apply_delta(Some(&TopologyDelta {
            base_revision: 2,
            target_revision: 2,
            node_mutations: vec![NodeMutation {
                operation: MutationOperation::Disable as i32,
                node_id: "node-2".into(),
                node: None,
            }],
            ..Default::default()
        }))
        .await
        .unwrap();
    assert!(
        !manager
            .current_topology()
            .nodes
            .iter()
            .any(|node| node.node_id == "node-2")
    );
}

#[derive(Clone)]
struct ConfigPanel {
    nonces: Arc<Mutex<Vec<String>>>,
}

#[tonic::async_trait]
impl acp_proto::auth_service_server::AuthService for ConfigPanel {
    async fn hello(
        &self,
        _request: tonic::Request<acp_proto::HelloRequest>,
    ) -> Result<tonic::Response<acp_proto::Session>, tonic::Status> {
        Ok(tonic::Response::new(acp_proto::Session {
            session_id: "session-1".into(),
            topology_revision: 7,
        }))
    }
}

#[tonic::async_trait]
impl acp_proto::config_service_server::ConfigService for ConfigPanel {
    async fn get_machine_config(
        &self,
        request: tonic::Request<acp_proto::GetMachineConfigRequest>,
    ) -> Result<tonic::Response<acp_proto::MachineConfig>, tonic::Status> {
        self.verify(request.metadata())?;
        let request = request.into_inner();
        assert_eq!(request.machine_id, "machine-1");
        assert_eq!(request.session_id, "session-1");
        Ok(tonic::Response::new(acp_proto::MachineConfig {
            machine_id: "machine-1".into(),
            revision: 7,
            nodes: vec![acp_proto::NodeConfig {
                node_id: "node-1".into(),
                provider_id: "provider".into(),
                provider_config_version: 1,
                provider_config_json: b"{}".to_vec(),
            }],
            ..Default::default()
        }))
    }

    async fn list_users(
        &self,
        request: tonic::Request<acp_proto::ListUsersRequest>,
    ) -> Result<tonic::Response<acp_proto::ListUsersResponse>, tonic::Status> {
        self.verify(request.metadata())?;
        let request = request.into_inner();
        assert_eq!(request.page_size, 500);
        let response = if request.page_token.is_empty() {
            acp_proto::ListUsersResponse {
                users: vec![proto_user("user-1", "credential-1")],
                next_page_token: "page-2".into(),
                total_size: 2,
                has_next: true,
            }
        } else {
            assert_eq!(request.page_token, "page-2");
            acp_proto::ListUsersResponse {
                users: vec![proto_user("user-2", "credential-2")],
                total_size: 2,
                has_next: false,
                ..Default::default()
            }
        };
        Ok(tonic::Response::new(response))
    }
}

impl ConfigPanel {
    fn verify(&self, metadata: &tonic::metadata::MetadataMap) -> Result<(), tonic::Status> {
        use acp_proto::auth::{
            METADATA_MACHINE_ID, METADATA_NONCE, METADATA_SESSION_ID, METADATA_SIGNATURE,
            METADATA_TIMESTAMP_UNIX, SessionFields, sign_session,
        };

        let value = |key: &'static str| {
            let mut values = metadata.get_all(key).iter();
            let value = values
                .next()
                .ok_or_else(|| tonic::Status::unauthenticated(format!("missing {key}")))?;
            if values.next().is_some() {
                return Err(tonic::Status::unauthenticated(format!("duplicate {key}")));
            }
            value
                .to_str()
                .map(str::to_string)
                .map_err(|error| tonic::Status::unauthenticated(error.to_string()))
        };
        let fields = SessionFields {
            machine_id: value(METADATA_MACHINE_ID)?,
            session_id: value(METADATA_SESSION_ID)?,
            timestamp_unix: value(METADATA_TIMESTAMP_UNIX)?
                .parse()
                .map_err(|error| tonic::Status::unauthenticated(format!("{error}")))?,
            nonce: value(METADATA_NONCE)?,
        };
        let signature = value(METADATA_SIGNATURE)?;
        let expected = sign_session("secret", &fields)
            .map_err(|error| tonic::Status::unauthenticated(error.to_string()))?;
        if signature != expected {
            return Err(tonic::Status::unauthenticated("invalid signature"));
        }
        lock(&self.nonces).push(fields.nonce);
        Ok(())
    }
}

#[tokio::test]
async fn panel_fetcher_authenticates_every_unary_and_fetches_all_user_pages() {
    use acp_proto::auth_service_server::AuthServiceServer;
    use acp_proto::config_service_server::ConfigServiceServer;
    use node_agent::config;
    use node_agent::control::PanelTopologyFetcher;
    use node_agent::session::PanelClient;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let panel = ConfigPanel {
        nonces: Arc::new(Mutex::new(Vec::new())),
    };
    let server_panel = panel.clone();
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(AuthServiceServer::new(server_panel.clone()))
            .add_service(ConfigServiceServer::new(server_panel))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let config = config::parse(&format!(
        "panel_grpc_endpoint = \"grpc://{address}\"\nmachine_id = \"machine-1\"\nnode_id = \"node-1\"\nmachine_secret = \"secret\"\n"
    ))
    .unwrap();
    let client = PanelClient::new(config, "test-agent", "test-shoes");
    let channel = client.dial().await.unwrap();
    let session = client.authenticate(channel, 0).await.unwrap();
    let fetcher = PanelTopologyFetcher::new("machine-1", session);
    let topology = fetcher.fetch_machine_topology().await.unwrap();

    assert_eq!(topology.revision, 7);
    assert_eq!(topology.nodes[0].users.len(), 2);
    assert_eq!(topology.nodes[0].users[1].user_id, "user-2");
    {
        let nonces = lock(&panel.nonces);
        assert_eq!(nonces.len(), 3);
        assert_ne!(nonces[0], nonces[1]);
        assert_ne!(nonces[1], nonces[2]);
    }
    server.abort();
    let _ = server.await;
}
