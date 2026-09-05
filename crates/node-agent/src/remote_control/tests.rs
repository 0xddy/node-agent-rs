use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use acp_proto::auth::{
    METADATA_MACHINE_ID, METADATA_NONCE, METADATA_SESSION_ID, METADATA_SIGNATURE,
    METADATA_TIMESTAMP_UNIX, SessionFields, sign_session,
};
use acp_proto::remote_control_request::Command;
use acp_proto::remote_control_response::Payload;
use acp_proto::remote_control_service_server::{RemoteControlService, RemoteControlServiceServer};
use acp_proto::{
    LoadedUsersRequest, PeriodicUserPullRequest, ReloadSingBoxRequest, RemoteControlStatusRequest,
    Session, SingBoxConfigRequest, SyncUsersRequest,
};
use async_trait::async_trait;
use tokio::sync::{Notify, Semaphore, mpsc};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::metadata::MetadataMap;
use tonic::transport::{Endpoint, Server};
use tonic::{Request, Response, Status};

use super::*;
use crate::config;

struct FakeServices {
    users: Mutex<Vec<UserCredential>>,
    users_error: Mutex<Option<String>>,
    config: Mutex<Vec<u8>>,
    sync_result: Mutex<UserSyncChanges>,
    sync_error: Mutex<Option<String>>,
    sync_calls: AtomicUsize,
    sync_called: Notify,
    sync_block: AtomicBool,
    sync_finish_after_cancel: AtomicBool,
    sync_after_cancel: Notify,
    sync_release: Semaphore,
    reload_result: Mutex<Option<RemoteReloadResult>>,
    reload_error: Mutex<Option<String>>,
    reload_block: AtomicBool,
    reload_finish_after_cancel: AtomicBool,
    reload_after_cancel: Notify,
    reload_started: Notify,
    reload_release: Semaphore,
}

impl Default for FakeServices {
    fn default() -> Self {
        Self {
            users: Mutex::new(Vec::new()),
            users_error: Mutex::new(None),
            config: Mutex::new(Vec::new()),
            sync_result: Mutex::new(UserSyncChanges::default()),
            sync_error: Mutex::new(None),
            sync_calls: AtomicUsize::new(0),
            sync_called: Notify::new(),
            sync_block: AtomicBool::new(false),
            sync_finish_after_cancel: AtomicBool::new(false),
            sync_after_cancel: Notify::new(),
            sync_release: Semaphore::new(0),
            reload_result: Mutex::new(None),
            reload_error: Mutex::new(None),
            reload_block: AtomicBool::new(false),
            reload_finish_after_cancel: AtomicBool::new(false),
            reload_after_cancel: Notify::new(),
            reload_started: Notify::new(),
            reload_release: Semaphore::new(0),
        }
    }
}

impl FakeServices {
    fn dependencies(self: &Arc<Self>) -> RemoteControlDependencies {
        RemoteControlDependencies::new(self.clone(), self.clone(), self.clone())
    }

    fn user(id: usize) -> UserCredential {
        UserCredential {
            user_id: format!("user-{id:03}"),
            name: format!("User {id}"),
            credential: format!("credential-{id}"),
            status: if id == 0 { "disabled" } else { "active" }.into(),
            upload_speed_limit_bps: id as u64 * 10,
            download_speed_limit_bps: id as u64 * 20,
        }
    }
}

#[async_trait]
impl RemoteTopology for FakeServices {
    async fn loaded_users(
        &self,
        _node_id: &str,
    ) -> Result<Vec<UserCredential>, RemoteOperationError> {
        if let Some(error) = self.users_error.lock().unwrap().clone() {
            return Err(error.into());
        }
        Ok(self.users.lock().unwrap().clone())
    }
}

impl RemoteRuntime for FakeServices {
    fn current_config(&self) -> Vec<u8> {
        self.config.lock().unwrap().clone()
    }
}

#[async_trait]
impl RemoteFetcher for FakeServices {
    async fn reload(
        &self,
        cancel: CancellationToken,
        progress: ReloadProgressReporter,
    ) -> Result<RemoteReloadResult, RemoteOperationError> {
        for stage in ReloadProgressStage::ALL {
            progress.report(stage).await;
        }
        self.reload_started.notify_one();
        if self.reload_block.load(Ordering::SeqCst) {
            tokio::select! {
                permit = self.reload_release.acquire() => {
                    permit.unwrap().forget();
                }
                () = cancel.cancelled() => {
                    if self.reload_finish_after_cancel.load(Ordering::SeqCst) {
                        self.reload_after_cancel.notify_one();
                        self.reload_release.acquire().await.unwrap().forget();
                    } else {
                        return Err(CONTEXT_DEADLINE_EXCEEDED.into());
                    }
                }
            }
        }
        if let Some(error) = self.reload_error.lock().unwrap().clone() {
            return Err(error.into());
        }
        Ok(self
            .reload_result
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(RemoteReloadResult {
                outcome: ReloadSingBoxOutcome::Succeeded,
                stage: RELOAD_STAGE_COMPLETED.into(),
                message: "sing-box reloaded with fresh panel configuration and users".into(),
                topology_revision: 42,
                config_sha256: "a".repeat(64),
                loaded_user_count: self.users.lock().unwrap().len(),
            }))
    }

    async fn sync_users(
        &self,
        cancel: CancellationToken,
        _node_id: &str,
    ) -> Result<UserSyncChanges, RemoteOperationError> {
        self.sync_calls.fetch_add(1, Ordering::SeqCst);
        self.sync_called.notify_one();
        if self.sync_block.load(Ordering::SeqCst) {
            cancel.cancelled().await;
            if self.sync_finish_after_cancel.load(Ordering::SeqCst) {
                self.sync_after_cancel.notify_one();
                self.sync_release.acquire().await.unwrap().forget();
            } else {
                return Err("context canceled".into());
            }
        }
        if let Some(error) = self.sync_error.lock().unwrap().clone() {
            return Err(error.into());
        }
        Ok(*self.sync_result.lock().unwrap())
    }
}

fn target() -> RemoteControlTarget {
    RemoteControlTarget {
        machine_id: "machine-1".into(),
        node_id: "node-1".into(),
    }
}

fn request(id: &str, command: Option<Command>) -> RemoteControlRequest {
    RemoteControlRequest {
        request_id: id.into(),
        command,
    }
}

async fn dispatch(
    services: &Arc<FakeServices>,
    controller: &RemoteController,
    request: RemoteControlRequest,
) -> Vec<RemoteControlResponse> {
    let (sender, mut receiver) = mpsc::channel(128);
    handle_remote_control_request(
        CancellationToken::new(),
        target(),
        services.dependencies(),
        controller.clone(),
        request,
        sender,
    )
    .await;
    let mut responses = Vec::new();
    while let Some(response) = receiver.recv().await {
        responses.push(response);
    }
    responses
}

#[test]
fn controller_state_is_process_scoped_and_snapshots_are_deep_clones() {
    let controller = RemoteController::new();
    let state = controller.set_periodic(true, Duration::from_secs(7 * 60));
    assert!(state.periodic_user_pull_enabled);
    assert_eq!(state.periodic_user_pull_interval_minutes, 7);
    assert_ne!(state.periodic_user_pull_next_attempt_at_unix_milli, 0);

    let lease = controller.begin_reload("operation-1").unwrap();
    assert!(controller.begin_reload("operation-2").is_none());
    let mut result = ReloadSingBoxResult {
        operation_id: "operation-1".into(),
        outcome: ReloadSingBoxOutcome::Succeeded as i32,
        stage: RELOAD_STAGE_COMPLETED.into(),
        message: "completed".into(),
        ..Default::default()
    };
    lease.finish(&result);
    result.message = "mutated after finish".into();

    let mut snapshot = controller.snapshot();
    assert!(!snapshot.reload_in_progress);
    assert_eq!(snapshot.last_reload.as_ref().unwrap().message, "completed");
    snapshot.last_reload.as_mut().unwrap().message = "mutated snapshot".into();
    assert_eq!(
        controller.snapshot().last_reload.unwrap().message,
        "completed"
    );

    let state = controller.set_periodic(false, Duration::ZERO);
    assert!(!state.periodic_user_pull_enabled);
    assert_eq!(state.periodic_user_pull_next_attempt_at_unix_milli, 0);
}

#[tokio::test]
async fn status_missing_command_and_empty_request_id_match_go_messages() {
    let services = Arc::new(FakeServices::default());
    let controller = RemoteController::new();
    controller.set_periodic(true, Duration::from_secs(3 * 60));

    let responses = dispatch(
        &services,
        &controller,
        request(
            "status-1",
            Some(Command::Status(RemoteControlStatusRequest {})),
        ),
    )
    .await;
    assert_eq!(responses.len(), 1);
    let response = &responses[0];
    assert_eq!(response.request_id, "status-1");
    assert_eq!(
        response.status,
        RemoteControlResponseStatus::Completed as i32
    );
    assert_eq!(response.stage, "");
    assert_eq!(response.message, "remote control state loaded");
    let Some(Payload::ControlState(state)) = &response.payload else {
        panic!("missing control state")
    };
    assert!(state.periodic_user_pull_enabled);

    let failed = dispatch(&services, &controller, request("bad-1", None)).await;
    assert_eq!(failed[0].status, RemoteControlResponseStatus::Failed as i32);
    assert_eq!(failed[0].stage, "request");
    assert_eq!(failed[0].message, "remote control command is required");

    let ignored = dispatch(
        &services,
        &controller,
        request("", Some(Command::Status(RemoteControlStatusRequest {}))),
    )
    .await;
    assert!(ignored.is_empty());
}

#[tokio::test]
async fn loaded_users_normalizes_pagination_and_preserves_credentials() {
    let services = Arc::new(FakeServices::default());
    *services.users.lock().unwrap() = (0..205).map(FakeServices::user).collect();
    let controller = RemoteController::new();
    let first = dispatch(
        &services,
        &controller,
        request(
            "users-1",
            Some(Command::LoadedUsers(LoadedUsersRequest {
                page: 0,
                page_size: 0,
            })),
        ),
    )
    .await;
    let Some(Payload::LoadedUsers(page)) = &first[0].payload else {
        panic!("missing users page")
    };
    assert_eq!((page.page, page.page_size, page.total_size), (1, 100, 205));
    assert_eq!(page.users.len(), 100);
    assert_eq!(page.users[0].user_id, "user-000");
    assert_eq!(page.users[0].status, UserStatus::Disabled as i32);
    assert_eq!(page.users[1].status, UserStatus::Active as i32);
    assert_eq!(page.users[1].upload_speed_limit_bps, 10);
    assert_eq!(first[0].message, "loaded users returned");

    let last = dispatch(
        &services,
        &controller,
        request(
            "users-3",
            Some(Command::LoadedUsers(LoadedUsersRequest {
                page: 3,
                page_size: 501,
            })),
        ),
    )
    .await;
    let Some(Payload::LoadedUsers(page)) = &last[0].payload else {
        panic!("missing users page")
    };
    assert_eq!(page.page_size, 100);
    assert_eq!(page.users.len(), 5);
    assert_eq!(page.users[0].user_id, "user-200");

    let beyond_end = dispatch(
        &services,
        &controller,
        request(
            "users-beyond-end",
            Some(Command::LoadedUsers(LoadedUsersRequest {
                page: u32::MAX,
                page_size: MAX_LOADED_USERS_PAGE_SIZE,
            })),
        ),
    )
    .await;
    let Some(Payload::LoadedUsers(page)) = &beyond_end[0].payload else {
        panic!("missing users page")
    };
    assert_eq!(page.total_size, 205);
    assert!(page.users.is_empty());

    *services.users_error.lock().unwrap() = Some("node node-1 not found".into());
    let failed = dispatch(
        &services,
        &controller,
        request(
            "users-fail",
            Some(Command::LoadedUsers(LoadedUsersRequest {
                page: 1,
                page_size: 500,
            })),
        ),
    )
    .await;
    assert_eq!(failed[0].stage, "loaded_users");
    assert_eq!(failed[0].message, "node node-1 not found");
}

#[tokio::test]
async fn loaded_users_requests_only_the_normalized_page_from_the_backend() {
    struct PagedTopology;

    #[async_trait]
    impl RemoteTopology for PagedTopology {
        async fn loaded_users(
            &self,
            _node_id: &str,
        ) -> Result<Vec<UserCredential>, RemoteOperationError> {
            panic!("a page request must not load every user");
        }

        async fn loaded_users_page(
            &self,
            node_id: &str,
            offset: u64,
            limit: usize,
        ) -> Result<(usize, Vec<UserCredential>), RemoteOperationError> {
            assert_eq!(node_id, "node-1");
            assert_eq!((offset, limit), (200, 100));
            Ok((205, (200..205).map(FakeServices::user).collect()))
        }
    }

    let services = Arc::new(FakeServices::default());
    let dependencies =
        RemoteControlDependencies::new(Arc::new(PagedTopology), services.clone(), services);
    let (sender, mut receiver) = mpsc::channel(1);
    handle_remote_control_request(
        CancellationToken::new(),
        target(),
        dependencies,
        RemoteController::new(),
        request(
            "users-page",
            Some(Command::LoadedUsers(LoadedUsersRequest {
                page: 3,
                page_size: MAX_LOADED_USERS_PAGE_SIZE + 1,
            })),
        ),
        sender,
    )
    .await;
    let response = receiver.recv().await.unwrap();
    assert_eq!(
        response.status,
        RemoteControlResponseStatus::Completed as i32
    );
    let Some(Payload::LoadedUsers(page)) = response.payload else {
        panic!("missing users page")
    };
    assert_eq!((page.page, page.page_size, page.total_size), (3, 100, 205));
    assert_eq!(page.users.len(), 5);
    assert_eq!(page.users[0].credential, "credential-200");
    assert_eq!(page.users[4].user_id, "user-204");
}

#[tokio::test]
async fn config_is_chunked_at_64k_and_eof_carries_size_and_sha256() {
    let services = Arc::new(FakeServices::default());
    let mut config = br#"{"log":{"level":"info"},"padding":""#.to_vec();
    config.extend(std::iter::repeat_n(b'x', REMOTE_CONFIG_CHUNK_SIZE * 2));
    config.extend_from_slice(br#""}"#);
    *services.config.lock().unwrap() = config.clone();
    let responses = dispatch(
        &services,
        &RemoteController::new(),
        request(
            "config-1",
            Some(Command::SingBoxConfig(SingBoxConfigRequest {})),
        ),
    )
    .await;

    let mut rebuilt = Vec::new();
    for (index, response) in responses.iter().enumerate() {
        assert_eq!(response.request_id, "config-1");
        assert_eq!(response.stage, "sing_box_config");
        let Some(Payload::SingBoxConfig(chunk)) = &response.payload else {
            panic!("missing config chunk")
        };
        assert_eq!(chunk.sequence as usize, index);
        if chunk.eof {
            assert_eq!(
                response.status,
                RemoteControlResponseStatus::Completed as i32
            );
            assert_eq!(response.message, "current sing-box configuration returned");
            assert_eq!(chunk.total_bytes, config.len() as u64);
            assert_eq!(chunk.sha256, lower_hex(&Sha256::digest(&config)));
        } else {
            assert_eq!(
                response.status,
                RemoteControlResponseStatus::Progress as i32
            );
            assert!(chunk.data.len() <= REMOTE_CONFIG_CHUNK_SIZE);
            rebuilt.extend_from_slice(&chunk.data);
        }
    }
    assert_eq!(rebuilt, config);

    services.config.lock().unwrap().clear();
    let failed = dispatch(
        &services,
        &RemoteController::new(),
        request(
            "config-empty",
            Some(Command::SingBoxConfig(SingBoxConfigRequest {})),
        ),
    )
    .await;
    assert_eq!(failed[0].status, RemoteControlResponseStatus::Failed as i32);
    assert_eq!(failed[0].stage, "sing_box_config");
    assert_eq!(
        failed[0].message,
        "sing-box runtime has no active configuration"
    );
}

#[tokio::test]
async fn sync_users_reports_changes_loaded_count_and_exact_failures() {
    let services = Arc::new(FakeServices::default());
    *services.users.lock().unwrap() = (0..7).map(FakeServices::user).collect();
    *services.sync_result.lock().unwrap() = UserSyncChanges {
        added: 2,
        updated: 3,
        deleted: 1,
        applied: true,
    };
    let completed = dispatch(
        &services,
        &RemoteController::new(),
        request("sync-1", Some(Command::SyncUsers(SyncUsersRequest {}))),
    )
    .await;
    assert_eq!(
        completed[0].status,
        RemoteControlResponseStatus::Completed as i32
    );
    assert_eq!(completed[0].stage, "sync_users");
    assert_eq!(completed[0].message, "node users synchronized from panel");
    let Some(Payload::SyncUsersResult(result)) = &completed[0].payload else {
        panic!("missing sync result")
    };
    assert_eq!(
        (
            result.added_count,
            result.updated_count,
            result.deleted_count,
            result.applied,
            result.loaded_user_count,
        ),
        (2, 3, 1, true, 7)
    );
    assert!(result.completed_at_unix_milli > 0);

    *services.sync_error.lock().unwrap() = Some("panel rejected refresh".into());
    let failed = dispatch(
        &services,
        &RemoteController::new(),
        request("sync-2", Some(Command::SyncUsers(SyncUsersRequest {}))),
    )
    .await;
    assert_eq!(failed[0].status, RemoteControlResponseStatus::Failed as i32);
    assert_eq!(failed[0].stage, "sync_users");
    assert_eq!(failed[0].message, "panel rejected refresh");
}

#[tokio::test(start_paused = true)]
async fn sync_timeout_is_one_minute_and_cancels_the_fetcher() {
    let services = Arc::new(FakeServices::default());
    services.sync_block.store(true, Ordering::SeqCst);
    let controller = RemoteController::new();
    let task_services = services.clone();
    let task = tokio::spawn(async move {
        dispatch(
            &task_services,
            &controller,
            request(
                "sync-timeout",
                Some(Command::SyncUsers(SyncUsersRequest {})),
            ),
        )
        .await
    });
    services.sync_called.notified().await;
    tokio::time::advance(REMOTE_SYNC_USERS_TIMEOUT + Duration::from_millis(1)).await;
    let responses = task.await.unwrap();
    assert_eq!(responses[0].stage, "sync_users");
    assert_eq!(responses[0].message, CONTEXT_DEADLINE_EXCEEDED);
}

#[tokio::test(start_paused = true)]
async fn sync_deadline_waits_for_an_already_started_local_transaction() {
    let services = Arc::new(FakeServices::default());
    services.sync_block.store(true, Ordering::SeqCst);
    services
        .sync_finish_after_cancel
        .store(true, Ordering::SeqCst);
    *services.users.lock().unwrap() = (0..3).map(FakeServices::user).collect();
    *services.sync_result.lock().unwrap() = UserSyncChanges {
        added: 1,
        applied: true,
        ..UserSyncChanges::default()
    };
    let controller = RemoteController::new();
    let task_services = services.clone();
    let task = tokio::spawn(async move {
        dispatch(
            &task_services,
            &controller,
            request(
                "sync-owned-after-timeout",
                Some(Command::SyncUsers(SyncUsersRequest {})),
            ),
        )
        .await
    });
    services.sync_called.notified().await;
    tokio::time::advance(REMOTE_SYNC_USERS_TIMEOUT + Duration::from_millis(1)).await;
    services.sync_after_cancel.notified().await;
    assert!(
        !task.is_finished(),
        "deadline dropped an in-flight local user transaction"
    );

    services.sync_release.add_permits(1);
    let responses = task.await.unwrap();
    assert_eq!(responses.len(), 1);
    assert_eq!(
        responses[0].status,
        RemoteControlResponseStatus::Completed as i32
    );
    assert_eq!(responses[0].stage, "sync_users");
    let Some(Payload::SyncUsersResult(result)) = &responses[0].payload else {
        panic!("missing sync result")
    };
    assert!(result.applied);
    assert_eq!(result.loaded_user_count, 3);
}

#[tokio::test]
async fn periodic_setting_validates_range_and_scheduler_attempts_immediately() {
    let services = Arc::new(FakeServices::default());
    let controller = RemoteController::new();
    for interval in [0, 61] {
        let failed = dispatch(
            &services,
            &controller,
            request(
                "periodic-bad",
                Some(Command::PeriodicUserPull(PeriodicUserPullRequest {
                    enabled: true,
                    interval_minutes: interval,
                })),
            ),
        )
        .await;
        assert_eq!(failed[0].stage, "periodic_user_pull");
        assert_eq!(
            failed[0].message,
            "interval_minutes must be between 1 and 60"
        );
    }

    let completed = dispatch(
        &services,
        &controller,
        request(
            "periodic-ok",
            Some(Command::PeriodicUserPull(PeriodicUserPullRequest {
                enabled: true,
                interval_minutes: 7,
            })),
        ),
    )
    .await;
    assert_eq!(completed[0].message, "periodic user pull setting updated");

    let cancel = CancellationToken::new();
    let runner = tokio::spawn(run_periodic_user_pull(
        cancel.clone(),
        target(),
        services.dependencies(),
        controller.clone(),
    ));
    services.sync_called.notified().await;
    cancel.cancel();
    runner.await.unwrap();
    let state = controller.snapshot();
    assert!(state.periodic_user_pull_last_attempt_at_unix_milli > 0);
    assert!(state.periodic_user_pull_last_success_at_unix_milli > 0);
    assert!(state.periodic_user_pull_next_attempt_at_unix_milli > 0);
}

#[tokio::test]
async fn periodic_disconnect_waits_for_local_transaction_before_releasing_attempt() {
    let services = Arc::new(FakeServices::default());
    services.sync_block.store(true, Ordering::SeqCst);
    services
        .sync_finish_after_cancel
        .store(true, Ordering::SeqCst);
    let controller = RemoteController::new();
    controller.set_periodic(true, Duration::from_secs(60));
    let cancel = CancellationToken::new();
    let runner = tokio::spawn(run_periodic_user_pull(
        cancel.clone(),
        target(),
        services.dependencies(),
        controller.clone(),
    ));
    services.sync_called.notified().await;
    cancel.cancel();
    services.sync_after_cancel.notified().await;
    assert!(
        !runner.is_finished(),
        "stream cancellation dropped the periodic local transaction"
    );
    assert!(
        controller
            .inner
            .state
            .lock()
            .unwrap()
            .periodic_attempt
            .is_some(),
        "periodic attempt was released before its transaction"
    );

    services.sync_release.add_permits(1);
    runner.await.unwrap();
    let state = controller.snapshot();
    assert!(state.periodic_user_pull_last_success_at_unix_milli > 0);
    assert!(
        controller
            .inner
            .state
            .lock()
            .unwrap()
            .periodic_attempt
            .is_none()
    );
}

#[tokio::test]
async fn replacement_periodic_scheduler_waits_for_attempt_completion_without_self_waking() {
    use std::future::Future;
    use std::task::{Context, Poll, Wake, Waker};

    #[derive(Default)]
    struct WakeCounter(AtomicUsize);

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let controller = RemoteController::new();
    controller.set_periodic(true, Duration::from_secs(60));
    let old_cancel = CancellationToken::new();
    let previous = controller.begin_periodic_attempt(&old_cancel).unwrap();
    let previous_cancel = previous.cancel.clone();
    let services = Arc::new(FakeServices::default());
    let cancel = CancellationToken::new();
    let mut replacement = Box::pin(run_periodic_user_pull(
        cancel.clone(),
        target(),
        services.dependencies(),
        controller.clone(),
    ));
    let counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(counter.clone());
    let mut context = Context::from_waker(&waker);
    assert!(matches!(
        replacement.as_mut().poll(&mut context),
        Poll::Pending
    ));
    assert_eq!(
        counter.0.load(Ordering::SeqCst),
        0,
        "an occupied attempt must sleep instead of repeatedly yielding"
    );
    assert_eq!(services.sync_calls.load(Ordering::SeqCst), 0);

    // Also exercise unwinding/abandonment of an attempt owner: its RAII cleanup
    // must wake the replacement without falsely recording a successful pull.
    drop(previous);
    assert!(previous_cancel.is_cancelled());
    assert!(counter.0.load(Ordering::SeqCst) > 0);
    assert_eq!(
        controller
            .snapshot()
            .periodic_user_pull_last_success_at_unix_milli,
        0
    );
    controller.set_periodic(true, Duration::from_secs(60));
    assert!(matches!(
        replacement.as_mut().poll(&mut context),
        Poll::Pending
    ));
    assert_eq!(services.sync_calls.load(Ordering::SeqCst), 1);
    cancel.cancel();
    assert!(matches!(
        replacement.as_mut().poll(&mut context),
        Poll::Ready(())
    ));
}

#[derive(Default)]
struct BackpressureRuntime {
    configured: AtomicBool,
    applied: AtomicBool,
    closed: AtomicBool,
}

#[async_trait]
impl crate::topology::manager::TopologyRuntime for BackpressureRuntime {
    async fn apply(
        &self,
        _: &crate::topology::MachineTopology,
    ) -> Result<(), crate::topology::manager::TopologyError> {
        self.applied.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn close_user_connections(&self, _: &str, _: &str) -> u64 {
        0
    }
    fn current_config(&self) -> Vec<u8> {
        Vec::new()
    }

    async fn configure_reload(
        &self,
        _: &crate::topology::MachineTopology,
    ) -> Result<(), crate::topology::manager::TopologyError> {
        self.configured.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn close(&self) -> Result<(), crate::topology::manager::TopologyError> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

impl RemoteRuntime for BackpressureRuntime {
    fn current_config(&self) -> Vec<u8> {
        Vec::new()
    }
}

struct BackpressurePanel;

#[async_trait]
impl crate::control::TopologyFetcher for BackpressurePanel {
    async fn fetch_machine_topology(
        &self,
    ) -> Result<crate::topology::MachineTopology, crate::control::FetchError> {
        Ok(crate::topology::MachineTopology {
            machine_id: "machine-1".into(),
            revision: 1,
            ..Default::default()
        })
    }

    async fn fetch_node_users(
        &self,
        _: &str,
    ) -> Result<Vec<UserCredential>, crate::control::FetchError> {
        Ok(Vec::new())
    }
}

async fn reload_with_response_backpressure(initially_full: bool) {
    let runtime = Arc::new(BackpressureRuntime::default());
    let manager = Arc::new(crate::topology::manager::TopologyManager::new(
        "machine-1",
        runtime.clone(),
    ));
    let fetcher = Arc::new(PanelRemoteFetcher::new(
        Arc::new(BackpressurePanel),
        manager.clone(),
    ));
    let dependencies = RemoteControlDependencies::new(manager.clone(), runtime.clone(), fetcher);
    let controller = RemoteController::new();
    let session_cancel = CancellationToken::new();
    let stream_cancel = session_cancel.child_token();
    let (sender, _receiver) = mpsc::channel(REMOTE_RESPONSE_QUEUE_SIZE);
    // Four accepted stages leave StartInstance blocked after port configuration.
    let occupied = REMOTE_RESPONSE_QUEUE_SIZE - if initially_full { 0 } else { 4 };
    for _ in 0..occupied {
        sender.send(RemoteControlResponse::default()).await.unwrap();
    }
    let task = tokio::spawn(handle_remote_control_request(
        stream_cancel.clone(),
        target(),
        dependencies,
        controller.clone(),
        request(
            "backpressure",
            Some(Command::ReloadSingBox(ReloadSingBoxRequest {})),
        ),
        sender,
    ));
    let expected_stage = if initially_full {
        RELOAD_STAGE_PULL_CONFIGURATION
    } else {
        RELOAD_STAGE_START_INSTANCE
    };
    for _ in 0..100 {
        tokio::task::yield_now().await;
        if controller.snapshot().reload_stage == expected_stage {
            break;
        }
    }
    assert_eq!(controller.snapshot().reload_stage, expected_stage);
    assert_eq!(runtime.configured.load(Ordering::SeqCst), !initially_full);
    assert!(!runtime.applied.load(Ordering::SeqCst));

    tokio::time::timeout(RELOAD_PROGRESS_SEND_TIMEOUT + Duration::from_secs(1), task)
        .await
        .expect("response backpressure retained the topology lock")
        .unwrap();
    tokio::time::timeout(Duration::from_millis(10), manager.close())
        .await
        .expect("close remained blocked by progress reporting")
        .unwrap();
    assert!(stream_cancel.is_cancelled());
    assert!(
        !session_cancel.is_cancelled(),
        "only the remote stream should retire"
    );
    assert!(
        runtime.applied.load(Ordering::SeqCst),
        "the owned transaction must finish even when progress delivery fails"
    );
    assert!(runtime.closed.load(Ordering::SeqCst));
    assert_eq!(manager.current_revision(), Some(1));
    let state = controller.snapshot();
    assert!(!state.reload_in_progress);
    assert_eq!(
        state.last_reload.unwrap().outcome,
        ReloadSingBoxOutcome::Succeeded as i32
    );
}

#[tokio::test(start_paused = true)]
async fn full_response_queue_cannot_retain_topology_lock_or_block_close() {
    reload_with_response_backpressure(true).await;
}

#[tokio::test(start_paused = true)]
async fn backpressure_after_port_configuration_still_completes_the_owned_reload() {
    reload_with_response_backpressure(false).await;
}

#[tokio::test]
async fn reload_emits_fixed_progress_rejects_concurrency_and_stores_final_result() {
    let services = Arc::new(FakeServices::default());
    services.reload_block.store(true, Ordering::SeqCst);
    let controller = RemoteController::new();
    let (sender, mut receiver) = mpsc::channel(128);
    let first_services = services.clone();
    let first_controller = controller.clone();
    let first_sender = sender.clone();
    let first = tokio::spawn(async move {
        handle_remote_control_request(
            CancellationToken::new(),
            target(),
            first_services.dependencies(),
            first_controller,
            request(
                "reload-1",
                Some(Command::ReloadSingBox(ReloadSingBoxRequest {})),
            ),
            first_sender,
        )
        .await;
    });
    services.reload_started.notified().await;

    handle_remote_control_request(
        CancellationToken::new(),
        target(),
        services.dependencies(),
        controller.clone(),
        request(
            "reload-2",
            Some(Command::ReloadSingBox(ReloadSingBoxRequest {})),
        ),
        sender.clone(),
    )
    .await;
    services.reload_release.add_permits(1);
    first.await.unwrap();
    drop(sender);

    let mut by_request: BTreeMap<String, Vec<RemoteControlResponse>> = BTreeMap::new();
    while let Some(response) = receiver.recv().await {
        by_request
            .entry(response.request_id.clone())
            .or_default()
            .push(response);
    }
    let busy = &by_request["reload-2"];
    assert_eq!(busy.len(), 1);
    assert_eq!(busy[0].status, RemoteControlResponseStatus::Failed as i32);
    assert_eq!(busy[0].stage, RELOAD_STAGE_BUSY);
    assert_eq!(
        busy[0].message,
        "another sing-box reload is already running"
    );
    let Some(Payload::ReloadResult(result)) = &busy[0].payload else {
        panic!("missing busy reload result")
    };
    assert_eq!(result.outcome, ReloadSingBoxOutcome::RejectedBusy as i32);
    assert_eq!(result.operation_id, "reload-2");

    let successful = &by_request["reload-1"];
    assert_eq!(successful.len(), 6);
    let stages: Vec<_> = successful[..5]
        .iter()
        .map(|response| response.stage.as_str())
        .collect();
    assert_eq!(
        stages,
        ReloadProgressStage::ALL.map(ReloadProgressStage::as_str)
    );
    assert!(successful[..5].iter().all(|response| response.status
        == RemoteControlResponseStatus::Progress as i32
        && response.message == response.stage));
    let terminal = successful.last().unwrap();
    assert_eq!(
        terminal.status,
        RemoteControlResponseStatus::Completed as i32
    );
    assert_eq!(terminal.stage, RELOAD_STAGE_COMPLETED);
    assert_eq!(terminal.request_id, "reload-1");
    let state = controller.snapshot();
    assert!(!state.reload_in_progress);
    assert_eq!(state.last_reload.unwrap().operation_id, "reload-1");
}

#[tokio::test(start_paused = true)]
async fn reload_timeout_releases_the_singleton_gate() {
    let services = Arc::new(FakeServices::default());
    services.reload_block.store(true, Ordering::SeqCst);
    let controller = RemoteController::new();
    let task_services = services.clone();
    let task_controller = controller.clone();
    let task = tokio::spawn(async move {
        dispatch(
            &task_services,
            &task_controller,
            request(
                "reload-timeout",
                Some(Command::ReloadSingBox(ReloadSingBoxRequest {})),
            ),
        )
        .await
    });
    services.reload_started.notified().await;
    tokio::time::advance(REMOTE_RELOAD_TIMEOUT + Duration::from_millis(1)).await;
    let responses = task.await.unwrap();
    let terminal = responses.last().unwrap();
    assert_eq!(
        terminal.status,
        RemoteControlResponseStatus::Completed as i32
    );
    assert_eq!(terminal.message, CONTEXT_DEADLINE_EXCEEDED);
    let Some(Payload::ReloadResult(result)) = &terminal.payload else {
        panic!("missing timeout reload result")
    };
    assert_eq!(result.outcome, ReloadSingBoxOutcome::FailedUnchanged as i32);
    assert!(!controller.snapshot().reload_in_progress);
    assert!(controller.begin_reload("after-timeout").is_some());
}

#[tokio::test(start_paused = true)]
async fn reload_deadline_keeps_singleton_until_local_transaction_finishes() {
    let services = Arc::new(FakeServices::default());
    services.reload_block.store(true, Ordering::SeqCst);
    services
        .reload_finish_after_cancel
        .store(true, Ordering::SeqCst);
    let controller = RemoteController::new();
    let task_services = services.clone();
    let task_controller = controller.clone();
    let first = tokio::spawn(async move {
        dispatch(
            &task_services,
            &task_controller,
            request(
                "reload-owned-after-timeout",
                Some(Command::ReloadSingBox(ReloadSingBoxRequest {})),
            ),
        )
        .await
    });
    services.reload_started.notified().await;
    tokio::time::advance(REMOTE_RELOAD_TIMEOUT + Duration::from_millis(1)).await;
    services.reload_after_cancel.notified().await;
    assert!(controller.snapshot().reload_in_progress);
    assert!(
        !first.is_finished(),
        "deadline returned before the local reload transaction"
    );

    let busy = dispatch(
        &services,
        &controller,
        request(
            "reload-while-local-finishes",
            Some(Command::ReloadSingBox(ReloadSingBoxRequest {})),
        ),
    )
    .await;
    assert_eq!(busy.len(), 1);
    assert_eq!(busy[0].stage, RELOAD_STAGE_BUSY);
    assert_eq!(busy[0].status, RemoteControlResponseStatus::Failed as i32);

    services.reload_release.add_permits(1);
    let responses = first.await.unwrap();
    let terminal = responses.last().unwrap();
    assert_eq!(
        terminal.status,
        RemoteControlResponseStatus::Completed as i32
    );
    assert_eq!(terminal.stage, RELOAD_STAGE_COMPLETED);
    assert_eq!(
        terminal.message,
        "sing-box reloaded with fresh panel configuration and users"
    );
    let state = controller.snapshot();
    assert!(!state.reload_in_progress);
    let last = state.last_reload.unwrap();
    assert_eq!(last.operation_id, "reload-owned-after-timeout");
    assert_eq!(last.outcome, ReloadSingBoxOutcome::Succeeded as i32);
}

#[derive(Clone)]
struct MockRemotePanel {
    requests: Arc<Mutex<Option<MockRequestReceiver>>>,
    responses: mpsc::UnboundedSender<RemoteControlResponse>,
    metadata: mpsc::UnboundedSender<SessionFields>,
}

type MockRequestReceiver = mpsc::Receiver<Result<RemoteControlRequest, Status>>;

#[tonic::async_trait]
impl RemoteControlService for MockRemotePanel {
    type RemoteControlStreamStream = ReceiverStream<Result<RemoteControlRequest, Status>>;

    async fn remote_control_stream(
        &self,
        request: Request<tonic::Streaming<RemoteControlResponse>>,
    ) -> Result<Response<Self::RemoteControlStreamStream>, Status> {
        self.metadata
            .send(verify_metadata(request.metadata())?)
            .unwrap();
        let mut incoming = request.into_inner();
        let responses = self.responses.clone();
        tokio::spawn(async move {
            while let Ok(Some(response)) = incoming.message().await {
                if responses.send(response).is_err() {
                    break;
                }
            }
        });
        let receiver = self
            .requests
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| Status::failed_precondition("stream already opened"))?;
        Ok(Response::new(ReceiverStream::new(receiver)))
    }
}

fn verify_metadata(metadata: &MetadataMap) -> Result<SessionFields, Status> {
    let value = |key| {
        let mut values = metadata.get_all(key).iter();
        let value = values
            .next()
            .ok_or_else(|| Status::unauthenticated(format!("missing {key}")))?
            .to_str()
            .map_err(|error| Status::unauthenticated(error.to_string()))?;
        if values.next().is_some() {
            return Err(Status::unauthenticated(format!("duplicate {key}")));
        }
        Ok(value.to_string())
    };
    let fields = SessionFields {
        machine_id: value(METADATA_MACHINE_ID)?,
        session_id: value(METADATA_SESSION_ID)?,
        timestamp_unix: value(METADATA_TIMESTAMP_UNIX)?
            .parse()
            .map_err(|error| Status::unauthenticated(format!("bad timestamp: {error}")))?,
        nonce: value(METADATA_NONCE)?,
    };
    if value(METADATA_SIGNATURE)? != sign_session("secret", &fields).unwrap() {
        return Err(Status::unauthenticated("invalid signature"));
    }
    Ok(fields)
}

struct TestRemoteStream {
    request_sender: mpsc::Sender<Result<RemoteControlRequest, Status>>,
    response_receiver: mpsc::UnboundedReceiver<RemoteControlResponse>,
    metadata_receiver: mpsc::UnboundedReceiver<SessionFields>,
    client_cancel: CancellationToken,
    runner: JoinHandle<Result<(), SessionError>>,
    server_cancel: CancellationToken,
    server: JoinHandle<()>,
}

async fn start_test_remote_stream(
    services: &Arc<FakeServices>,
    controller: &RemoteController,
) -> TestRemoteStream {
    let (request_sender, request_receiver) = mpsc::channel(8);
    let (response_sender, response_receiver) = mpsc::unbounded_channel();
    let (metadata_sender, metadata_receiver) = mpsc::unbounded_channel();
    let panel = MockRemotePanel {
        requests: Arc::new(Mutex::new(Some(request_receiver))),
        responses: response_sender,
        metadata: metadata_sender,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_cancel = CancellationToken::new();
    let server_shutdown = server_cancel.clone();
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(RemoteControlServiceServer::new(panel))
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(listener),
                server_shutdown.cancelled_owned(),
            )
            .await
            .unwrap();
    });

    let channel = Endpoint::from_shared(format!("http://{address}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let config = config::parse(&format!(
        r#"panel_grpc_endpoint = "grpc://{address}"
machine_id = "machine-1"
node_id = "node-1"
machine_secret = "secret"
"#,
    ))
    .unwrap();
    let authenticator = SessionAuthenticator::new(
        &config,
        &Session {
            session_id: "session-1".into(),
            topology_revision: 1,
        },
    )
    .unwrap();
    let client_cancel = CancellationToken::new();
    let runner_cancel = client_cancel.clone();
    let runner = tokio::spawn(run_remote_control_stream(
        runner_cancel,
        channel,
        authenticator,
        target(),
        services.dependencies(),
        controller.clone(),
    ));

    TestRemoteStream {
        request_sender,
        response_receiver,
        metadata_receiver,
        client_cancel,
        runner,
        server_cancel,
        server,
    }
}

#[tokio::test]
async fn tonic_stream_is_authenticated_bidirectional_concurrent_and_cancel_safe() {
    let services = Arc::new(FakeServices::default());
    *services.config.lock().unwrap() = b"diagnostic".to_vec();
    let controller = RemoteController::new();
    let TestRemoteStream {
        request_sender,
        mut response_receiver,
        mut metadata_receiver,
        client_cancel,
        runner,
        server_cancel,
        server,
    } = start_test_remote_stream(&services, &controller).await;

    let metadata = tokio::time::timeout(Duration::from_secs(1), metadata_receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(metadata.machine_id, "machine-1");
    assert_eq!(metadata.session_id, "session-1");
    assert_eq!(metadata.nonce.len(), 32);

    request_sender
        .send(Ok(request(
            "stream-status",
            Some(Command::Status(RemoteControlStatusRequest {})),
        )))
        .await
        .unwrap();
    request_sender
        .send(Ok(request(
            "stream-config",
            Some(Command::SingBoxConfig(SingBoxConfigRequest {})),
        )))
        .await
        .unwrap();

    let mut finals = BTreeMap::new();
    while finals.len() < 2 {
        let response = tokio::time::timeout(Duration::from_secs(1), response_receiver.recv())
            .await
            .unwrap()
            .unwrap();
        if response.status == RemoteControlResponseStatus::Completed as i32 {
            finals.insert(response.request_id.clone(), response);
        }
    }
    assert_eq!(
        finals["stream-status"].message,
        "remote control state loaded"
    );
    assert_eq!(
        finals["stream-config"].message,
        "current sing-box configuration returned"
    );

    // The panel can send tiny requests much faster than a local transaction
    // completes. Request 17 must receive an explicit rejection without spawning
    // another task or suspending reads from the healthy transport.
    services.sync_block.store(true, Ordering::SeqCst);
    for index in 0..=MAX_CONCURRENT_REMOTE_REQUESTS {
        request_sender
            .send(Ok(request(
                &format!("bounded-sync-{index}"),
                Some(Command::SyncUsers(SyncUsersRequest {})),
            )))
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while services.sync_calls.load(Ordering::SeqCst) < MAX_CONCURRENT_REMOTE_REQUESTS {
            services.sync_called.notified().await;
        }
    })
    .await
    .expect("request slots never filled");
    let rejected = tokio::time::timeout(Duration::from_secs(1), response_receiver.recv())
        .await
        .expect("excess request was silently discarded")
        .unwrap();
    assert_eq!(
        rejected.request_id,
        format!("bounded-sync-{MAX_CONCURRENT_REMOTE_REQUESTS}")
    );
    assert_eq!(rejected.status, RemoteControlResponseStatus::Failed as i32);
    assert_eq!(rejected.stage, "busy");
    assert!(rejected.payload.is_none());
    assert_eq!(
        services.sync_calls.load(Ordering::SeqCst),
        MAX_CONCURRENT_REMOTE_REQUESTS
    );
    assert_eq!(controller.inner.request_slots.available_permits(), 0);

    client_cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), runner)
        .await
        .expect("remote stream ignored cancellation")
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while controller.inner.request_slots.available_permits() != MAX_CONCURRENT_REMOTE_REQUESTS {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled requests retained their admission slots");
    server_cancel.cancel();
    server.await.unwrap();
}

async fn saturated_stream_observes_panel_end(
    excess_requests: usize,
    panel_error: bool,
    finish_local_transaction: bool,
) {
    let services = Arc::new(FakeServices::default());
    services.sync_block.store(true, Ordering::SeqCst);
    services
        .sync_finish_after_cancel
        .store(finish_local_transaction, Ordering::SeqCst);
    let controller = RemoteController::new();
    let TestRemoteStream {
        request_sender,
        mut response_receiver,
        mut metadata_receiver,
        client_cancel,
        mut runner,
        server_cancel,
        server,
    } = start_test_remote_stream(&services, &controller).await;
    tokio::time::timeout(Duration::from_secs(1), metadata_receiver.recv())
        .await
        .unwrap()
        .unwrap();

    for index in 0..MAX_CONCURRENT_REMOTE_REQUESTS {
        request_sender
            .send(Ok(request(
                &format!("active-{index}"),
                Some(Command::SyncUsers(SyncUsersRequest {})),
            )))
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while services.sync_calls.load(Ordering::SeqCst) < MAX_CONCURRENT_REMOTE_REQUESTS {
            services.sync_called.notified().await;
        }
    })
    .await
    .expect("request slots never filled");
    assert_eq!(controller.inner.request_slots.available_permits(), 0);
    request_sender
        .send(Ok(request(
            "",
            Some(Command::SyncUsers(SyncUsersRequest {})),
        )))
        .await
        .unwrap();

    // Queue excess requests immediately before EOF. A single request lookahead
    // that waits for capacity would still leave EOF hidden behind this backlog.
    for index in 0..excess_requests {
        request_sender
            .send(Ok(request(
                &format!("excess-{index}"),
                Some(Command::SyncUsers(SyncUsersRequest {})),
            )))
            .await
            .unwrap();
    }
    if panel_error {
        request_sender
            .send(Err(Status::aborted("panel stopped the stream")))
            .await
            .unwrap();
    }
    drop(request_sender);

    // The panel keeps reading the opposite side of this bidirectional stream,
    // so response_sender.closed() cannot stand in for polling panel EOF/errors.
    let outcome = tokio::time::timeout(Duration::from_secs(1), &mut runner).await;
    if outcome.is_err() {
        client_cancel.cancel();
        services
            .sync_release
            .add_permits(MAX_CONCURRENT_REMOTE_REQUESTS);
        let _ = runner.await;
        server_cancel.cancel();
        server.await.unwrap();
        panic!("saturated remote stream ignored panel EOF/error");
    }
    let Err(SessionError::Rpc(status)) = outcome.unwrap().unwrap() else {
        panic!("panel termination must retire the remote stream")
    };
    assert_eq!(
        status.code(),
        if panel_error {
            tonic::Code::Aborted
        } else {
            tonic::Code::Unavailable
        }
    );
    assert!(
        !client_cancel.is_cancelled(),
        "parent session must remain live"
    );
    if finish_local_transaction {
        assert_eq!(
            controller.inner.request_slots.available_permits(),
            0,
            "retiring a stream must retain its owned local transactions and slots"
        );
        services
            .sync_release
            .add_permits(MAX_CONCURRENT_REMOTE_REQUESTS);
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while controller.inner.request_slots.available_permits() != MAX_CONCURRENT_REMOTE_REQUESTS {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("panel termination did not cancel outstanding reads");
    assert_eq!(
        services.sync_calls.load(Ordering::SeqCst),
        MAX_CONCURRENT_REMOTE_REQUESTS
    );
    for index in 0..excess_requests {
        let rejection = tokio::time::timeout(Duration::from_secs(1), response_receiver.recv())
            .await
            .expect("excess request was silently discarded")
            .unwrap();
        assert_eq!(rejection.request_id, format!("excess-{index}"));
        assert_eq!(rejection.status, RemoteControlResponseStatus::Failed as i32);
        assert_eq!(rejection.stage, "busy");
        assert!(rejection.payload.is_none());
    }
    server_cancel.cancel();
    server.await.unwrap();
}

#[tokio::test]
async fn saturated_tonic_stream_observes_panel_eof() {
    saturated_stream_observes_panel_end(0, false, false).await;
}

#[tokio::test]
async fn saturated_tonic_stream_rejects_queued_requests_then_observes_eof() {
    saturated_stream_observes_panel_end(4, false, false).await;
}

#[tokio::test]
async fn saturated_tonic_stream_observes_panel_error() {
    saturated_stream_observes_panel_end(0, true, false).await;
}

#[tokio::test]
async fn saturated_tonic_stream_keeps_local_transactions_owned_after_eof() {
    saturated_stream_observes_panel_end(0, false, true).await;
}

#[test]
fn overload_rejection_retires_a_stream_if_the_response_queue_is_full() {
    let (sender, _receiver) = mpsc::channel(1);
    sender.try_send(RemoteControlResponse::default()).unwrap();
    let Err(SessionError::Rpc(status)) = reject_busy_request(&sender, "excess") else {
        panic!("a full response queue must retire the overloaded stream")
    };
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);
}

#[test]
fn constants_and_stage_names_match_go() {
    assert_eq!(REMOTE_RESPONSE_QUEUE_SIZE, 64);
    assert_eq!(REMOTE_CONFIG_CHUNK_SIZE, 64 * 1024);
    assert_eq!(REMOTE_RELOAD_TIMEOUT, Duration::from_secs(120));
    assert_eq!(REMOTE_SYNC_USERS_TIMEOUT, Duration::from_secs(60));
    assert_eq!(DEFAULT_LOADED_USERS_PAGE_SIZE, 100);
    assert_eq!(MAX_LOADED_USERS_PAGE_SIZE, 500);
    assert_eq!(
        ReloadProgressStage::ALL.map(ReloadProgressStage::as_str),
        [
            "pull_configuration",
            "pull_users",
            "build_configuration",
            "configure_port_hopping",
            "start_instance",
        ]
    );
    assert_eq!(RELOAD_STAGE_COMPLETED, "completed");
    assert_eq!(RELOAD_STAGE_ROLLBACK, "rollback");
    assert_eq!(RELOAD_STAGE_BUSY, "busy");
}
