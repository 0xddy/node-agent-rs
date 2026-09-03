//! Process-level orchestration for one ACP node agent.
//!
//! The individual protocol runners deliberately remain small and independently
//! testable. This module owns the ordering between them: authenticate, converge
//! topology, confirm the control stream, then run all five session streams; on
//! shutdown it keeps the panel session alive until the data plane's tail traffic
//! has been queued and acknowledged.

use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use acp_proto::ControlAck;

use crate::cli::AGENT_VERSION;
use crate::config::Config;
use crate::control::{
    AckStore, ControlCommandWorker, PanelTopologyFetcher, TopologyCommandExecutor, TopologyFetcher,
};
use crate::logging::run_log_stream;
use crate::policy::PolicyState;
use crate::remote_control::{
    PanelRemoteFetcher, RemoteControlDependencies, RemoteControlTarget, RemoteController,
    RemoteFetcher, RemoteRuntime, RemoteTopology, RuntimeRemoteView, run_remote_control_stream,
};
use crate::runtime::{NodeRuntime, RuntimeError, ShoesRuntime};
use crate::session::{
    AuthenticatedSession, OpenedControlStream, PanelClient, SessionError, StreamGroup,
    run_panel_sessions,
};
use crate::telemetry::run_telemetry_stream;
use crate::topology::manager::{TopologyError, TopologyManager};
use crate::traffic::{
    Aggregator, FINAL_TRAFFIC_FLUSH_LIMIT, TrafficQueue, collect_runtime_traffic,
    run_traffic_flusher, run_traffic_stream,
};

pub const BACKGROUND_SHUTDOWN_LIMIT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum AgentError {
    Runtime(RuntimeError),
    Topology(TopologyError),
    Session(SessionError),
    Background(String),
}

impl fmt::Display for AgentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(error) => write!(formatter, "initialize shoes runtime: {error}"),
            Self::Topology(error) => write!(formatter, "close runtime or port forwarding: {error}"),
            Self::Session(error) => write!(formatter, "panel session runner: {error}"),
            Self::Background(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for AgentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::Topology(error) => Some(error),
            Self::Session(error) => Some(error),
            Self::Background(_) => None,
        }
    }
}

/// Process-scoped state. The acknowledgement cache, policy state, traffic
/// aggregator and remote controller intentionally survive panel reconnects.
pub struct Agent {
    config: Arc<Config>,
    panel: PanelClient,
    runtime: Arc<dyn NodeRuntime>,
    topologies: Arc<TopologyManager>,
    policy: Arc<PolicyState>,
    traffic: Arc<Aggregator>,
    traffic_queue: TrafficQueue,
    acknowledgements: Arc<AckStore>,
    remote_controller: RemoteController,
}

impl Agent {
    pub async fn bootstrap(config: Config) -> Result<Arc<Self>, AgentError> {
        let runtime: Arc<dyn NodeRuntime> = Arc::new(
            ShoesRuntime::bootstrap()
                .await
                .map_err(AgentError::Runtime)?,
        );
        Ok(Self::with_runtime(config, runtime))
    }

    /// Injectable constructor used by lifecycle and real-panel integration
    /// tests. Production uses [`Self::bootstrap`].
    pub fn with_runtime(config: Config, runtime: Arc<dyn NodeRuntime>) -> Arc<Self> {
        let panel = PanelClient::new(
            config.clone(),
            AGENT_VERSION,
            shoes_engine::DATA_PLANE_VERSION,
        );
        let topologies = Arc::new(TopologyManager::from_node_runtime(
            config.machine_id.clone(),
            runtime.clone(),
        ));
        Arc::new(Self {
            traffic: Arc::new(Aggregator::new(config.traffic_report_min_delta_bytes)),
            config: Arc::new(config),
            panel,
            runtime,
            topologies,
            policy: Arc::new(PolicyState::new()),
            traffic_queue: TrafficQueue::new(),
            acknowledgements: Arc::new(AckStore::new()),
            remote_controller: RemoteController::new(),
        })
    }

    pub fn topologies(&self) -> &Arc<TopologyManager> {
        &self.topologies
    }

    pub fn runtime(&self) -> &Arc<dyn NodeRuntime> {
        &self.runtime
    }

    /// Runs until the supplied process token is cancelled or a process-scoped
    /// background task exits unexpectedly.
    ///
    /// Dropping or aborting the caller requests the same ordered shutdown. The
    /// owned supervisor finishes runtime close and final traffic delivery even
    /// when there is no longer a caller waiting for its result.
    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) -> Result<(), AgentError> {
        let shutdown = shutdown.child_token();
        let _cancel_on_drop = shutdown.clone().drop_guard();
        tokio::spawn(self.run_owned(shutdown))
            .await
            .map_err(|error| {
                AgentError::Background(format!("agent supervisor task failed: {error}"))
            })?
    }

    async fn run_owned(self: Arc<Self>, shutdown: CancellationToken) -> Result<(), AgentError> {
        // This token is intentionally detached from `shutdown`: the panel
        // session must remain alive while final traffic is delivered.
        let session_shutdown = CancellationToken::new();
        let flusher_shutdown = CancellationToken::new();
        // These guards also signal the children if the supervisor unwinds.
        // Normal shutdown below still controls their order explicitly.
        let _cancel_sessions = session_shutdown.clone().drop_guard();
        let _cancel_flusher = flusher_shutdown.clone().drop_guard();

        let mut flusher = self.spawn_traffic_flusher(flusher_shutdown.clone());
        let mut sessions = self.spawn_panel_sessions(session_shutdown.clone());
        let mut sessions_running = true;
        let mut flusher_running = true;

        let trigger_error = tokio::select! {
            biased;
            () = shutdown.cancelled() => None,
            joined = &mut flusher => {
                flusher_running = false;
                Some(background_result("traffic flusher", joined))
            }
            joined = &mut sessions => {
                sessions_running = false;
                Some(session_result(joined))
            }
        };

        log::info!("node-agent 收到停止请求，准备关闭");

        flusher_shutdown.cancel();
        if flusher_running {
            wait_for_task(&mut flusher, "流量汇总任务").await;
        }

        // Match Go's synchronous runtime.Close: topology/runtime shutdown owns
        // its completion boundary (including bounded port backends). Applying the
        // generic background-task timeout here could abandon a live close halfway.
        let close_error = match self.topologies.close().await {
            Ok(()) => None,
            Err(error) => {
                log::error!("node-agent 关闭运行时或防火墙失败：{error}");
                Some(AgentError::Topology(error))
            }
        };

        // Match Go: a dead panel session has no consumer that could acknowledge
        // the drain request, so only attempt the bounded final flush while that
        // session generation is still alive.
        if sessions_running {
            self.flush_traffic_before_shutdown().await;
        }

        session_shutdown.cancel();
        if sessions_running {
            wait_for_task(&mut sessions, "面板会话").await;
        }
        log::info!("node-agent 已停止");

        if let Some(error) = trigger_error {
            return Err(error);
        }
        if let Some(error) = close_error {
            return Err(error);
        }
        Ok(())
    }

    fn spawn_traffic_flusher(
        self: &Arc<Self>,
        cancel: CancellationToken,
    ) -> JoinHandle<Result<(), SessionError>> {
        let runtime = self.runtime.clone();
        let traffic = self.traffic.clone();
        let queue = self.traffic_queue.clone();
        let machine_id = self.config.machine_id.clone();
        tokio::spawn(async move {
            run_traffic_flusher(cancel, runtime, traffic, queue, machine_id).await
        })
    }

    fn spawn_panel_sessions(
        self: &Arc<Self>,
        shutdown: CancellationToken,
    ) -> JoinHandle<Result<(), SessionError>> {
        let agent = self.clone();
        tokio::spawn(async move {
            run_panel_sessions(shutdown, move |attempt_cancel| {
                let agent = agent.clone();
                async move { agent.run_panel_session(attempt_cancel).await }
            })
            .await
        })
    }

    async fn run_panel_session(
        self: Arc<Self>,
        attempt_cancel: CancellationToken,
    ) -> Result<(), SessionError> {
        let local_revision = self.topologies.current_revision().unwrap_or(0);
        let local_digest = self.topologies.current_digest();
        let channel = self.panel.dial().await?;
        let session = self.panel.authenticate(channel, local_revision).await?;
        log::info!(
            "面板认证成功：会话已建立，拓扑版本={}",
            session.descriptor().topology_revision
        );

        let control = session.open_control_stream().await?;
        let panel_digest = control.panel_digest().to_string();
        let fetcher: Arc<dyn TopologyFetcher> = Arc::new(PanelTopologyFetcher::new(
            self.config.machine_id.clone(),
            session.clone(),
        ));
        let executor = Arc::new(TopologyCommandExecutor::with_policy(
            self.topologies.clone(),
            fetcher.clone(),
            self.policy.clone(),
        ));

        if topology_resync_required(local_digest.as_deref(), &panel_digest) {
            let message = executor.sync_initial().await.map_err(|message| {
                session_task_error("initial topology synchronization", message)
            })?;
            log::info!("{message}");
        } else {
            self.topologies.reconcile_current().await.map_err(|error| {
                session_task_error("reconcile unchanged topology", error.to_string())
            })?;
            log::info!(
                "panel topology digest unchanged; keeping current runtime: revision={local_revision}"
            );
        }

        let current_digest = self.topologies.current_digest().ok_or_else(|| {
            session_task_error(
                "control stream readiness",
                "current topology does not have a convergence digest",
            )
        })?;
        let current_revision = self
            .topologies
            .current_revision()
            .filter(|value| *value != 0)
            .ok_or_else(|| {
                session_task_error(
                    "control stream readiness",
                    "current topology does not have a revision",
                )
            })?;
        control
            .confirm_ready(&current_digest, current_revision)
            .await?;

        log::info!(
            "node-agent 已连接面板：地址={}，机器={}",
            self.config.panel_grpc_endpoint,
            self.config.machine_id
        );
        self.run_session_streams(attempt_cancel, session, control, fetcher, executor)
            .await
    }

    async fn run_session_streams(
        self: Arc<Self>,
        attempt_cancel: CancellationToken,
        session: AuthenticatedSession,
        control: OpenedControlStream,
        fetcher: Arc<dyn TopologyFetcher>,
        executor: Arc<TopologyCommandExecutor>,
    ) -> Result<(), SessionError> {
        let mut group = StreamGroup::new(&attempt_cancel);
        let group_cancel = group.cancellation_token();
        let (worker, acknowledgements) = ControlCommandWorker::spawn_with_cancel(
            executor,
            self.acknowledgements.clone(),
            group_cancel.clone(),
        );
        group.start_session_critical("control stream", move |cancel| async move {
            run_control_stream(cancel, control, worker, acknowledgements).await
        });

        let traffic_channel = session.channel();
        let traffic_auth = session.authenticator().clone();
        let traffic_queue = self.traffic_queue.clone();
        group.start_auxiliary("traffic stream", move |cancel| {
            run_traffic_stream(
                cancel,
                traffic_channel.clone(),
                traffic_auth.clone(),
                traffic_queue.clone(),
            )
        });

        let telemetry_channel = session.channel();
        let telemetry_auth = session.authenticator().clone();
        let machine_id = self.config.machine_id.clone();
        let node_id = self.config.node_id.clone();
        let policy = self.policy.clone();
        let runtime = self.runtime.clone();
        group.start_auxiliary("telemetry stream", move |cancel| {
            run_telemetry_stream(
                cancel,
                telemetry_channel.clone(),
                telemetry_auth.clone(),
                machine_id.clone(),
                node_id.clone(),
                policy.clone(),
                runtime.clone(),
            )
        });

        let log_channel = session.channel();
        let log_auth = session.authenticator().clone();
        group.start_auxiliary("log stream", move |cancel| {
            run_log_stream(cancel, log_channel.clone(), log_auth.clone())
        });

        let remote_channel = session.channel();
        let remote_auth = session.authenticator().clone();
        let target = RemoteControlTarget {
            machine_id: self.config.machine_id.clone(),
            node_id: self.config.node_id.clone(),
        };
        let remote_topology: Arc<dyn RemoteTopology> = self.topologies.clone();
        let remote_runtime: Arc<dyn RemoteRuntime> =
            Arc::new(RuntimeRemoteView::new(self.runtime.clone()));
        let remote_fetcher: Arc<dyn RemoteFetcher> =
            Arc::new(PanelRemoteFetcher::new(fetcher, self.topologies.clone()));
        let dependencies =
            RemoteControlDependencies::new(remote_topology, remote_runtime, remote_fetcher);
        let controller = self.remote_controller.clone();
        group.start_auxiliary("remote control stream", move |cancel| {
            run_remote_control_stream(
                cancel,
                remote_channel.clone(),
                remote_auth.clone(),
                target.clone(),
                dependencies.clone(),
                controller.clone(),
            )
        });

        group.wait().await
    }

    async fn flush_traffic_before_shutdown(&self) {
        let cancel = CancellationToken::new();
        let operation_cancel = cancel.clone();
        let flush = async {
            if let Err(error) = collect_runtime_traffic(
                self.runtime.as_ref(),
                &self.traffic,
                &self.config.machine_id,
            )
            .await
            {
                log::error!("停止前采集数据面尾流量失败：{error}");
            }
            let queued = self
                .traffic_queue
                .flush_all(&operation_cancel, &self.traffic)
                .await;
            if queued > 0 {
                log::info!("停止前已补发流量报告：报告数={queued}");
            }
            self.traffic_queue
                .wait_for_panel_drain(&operation_cancel)
                .await
        };
        let (result, timed_out) =
            cancel_and_finish_at_deadline(FINAL_TRAFFIC_FLUSH_LIMIT, &cancel, flush).await;
        if timed_out {
            log::error!("停止前流量报告未能在时限内由面板确认：超时={FINAL_TRAFFIC_FLUSH_LIMIT:?}");
        } else if let Err(error) = result {
            log::error!("停止前流量报告未能由面板确认：{error}");
        }
    }
}

/// Waits until `limit`, then signals the operation and still awaits its cleanup
/// path. Unlike `tokio::time::timeout`, this never drops an enqueue future after
/// it has removed reports from the aggregator but before it restores the suffix.
async fn cancel_and_finish_at_deadline<T>(
    limit: Duration,
    cancel: &CancellationToken,
    operation: impl Future<Output = T>,
) -> (T, bool) {
    tokio::pin!(operation);
    tokio::select! {
        biased;
        result = &mut operation => (result, false),
        () = tokio::time::sleep(limit) => {
            cancel.cancel();
            (operation.await, true)
        }
    }
}

/// Consumes commands and worker acknowledgements without coupling execution to
/// tonic's receive task. Acknowledgements are biased so ACCEPTED/terminal frames
/// already queued by a worker are flushed before more commands are drained.
async fn run_control_stream(
    cancel: CancellationToken,
    mut control: OpenedControlStream,
    worker: ControlCommandWorker,
    mut acknowledgements: mpsc::Receiver<ControlAck>,
) -> Result<(), SessionError> {
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                worker.cancel();
                return Ok(());
            }
            acknowledgement = acknowledgements.recv() => {
                let Some(acknowledgement) = acknowledgement else {
                    worker.cancel();
                    return Err(SessionError::CriticalStreamEnded(
                        "control acknowledgement worker closed".into(),
                    ));
                };
                control.send_ack(acknowledgement).await?;
            }
            command = control.message() => {
                let Some(command) = command? else {
                    worker.cancel();
                    return Err(SessionError::CriticalStreamEnded(
                        "control stream closed by panel".into(),
                    ));
                };
                worker.submit(command).await.map_err(|error| {
                    session_task_error("control command submission", error.to_string())
                })?;
            }
        }
    }
}

fn topology_resync_required(local_digest: Option<&str>, panel_digest: &str) -> bool {
    local_digest != Some(panel_digest)
}

fn session_task_error(name: impl Into<String>, message: impl Into<String>) -> SessionError {
    SessionError::Task {
        name: name.into(),
        message: message.into(),
    }
}

fn background_result(
    name: &str,
    joined: Result<Result<(), SessionError>, tokio::task::JoinError>,
) -> AgentError {
    match joined {
        Ok(Ok(())) => AgentError::Background(format!("{name} exited unexpectedly")),
        Ok(Err(error)) => AgentError::Session(error),
        Err(error) => AgentError::Background(format!("{name} task failed: {error}")),
    }
}

fn session_result(joined: Result<Result<(), SessionError>, tokio::task::JoinError>) -> AgentError {
    match joined {
        Ok(Ok(())) => AgentError::Background("panel session runner exited unexpectedly".into()),
        Ok(Err(error)) => AgentError::Session(error),
        Err(error) => AgentError::Background(format!("panel session runner task failed: {error}")),
    }
}

async fn wait_for_task<T>(task: &mut JoinHandle<T>, name: &str) {
    if tokio::time::timeout(BACKGROUND_SHUTDOWN_LIMIT, &mut *task)
        .await
        .is_err()
    {
        log::error!("node-agent 等待{name}停止超时：超时={BACKGROUND_SHUTDOWN_LIMIT:?}");
        task.abort();
        let _ = task.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::runtime::{ConnectionStats, ReloadStatus, RuntimeConfig, TrafficDrain};
    use crate::topology::MachineTopology;
    use crate::traffic::TrafficEvent;

    struct LifecycleRuntime {
        events: Mutex<Vec<&'static str>>,
        apply_started: tokio::sync::Notify,
        allow_apply: tokio::sync::Semaphore,
        close_calls: AtomicUsize,
    }

    impl LifecycleRuntime {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
                apply_started: tokio::sync::Notify::new(),
                allow_apply: tokio::sync::Semaphore::new(0),
                close_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl NodeRuntime for LifecycleRuntime {
        async fn apply_config(&self, _config: RuntimeConfig) -> Result<(), RuntimeError> {
            self.events.lock().unwrap().push("apply started");
            self.apply_started.notify_one();
            self.allow_apply.acquire().await.unwrap().forget();
            self.events.lock().unwrap().push("apply finished");
            Ok(())
        }

        async fn reload_config(&self, config: RuntimeConfig) -> Result<ReloadStatus, RuntimeError> {
            self.apply_config(config).await?;
            Ok(ReloadStatus {
                running: true,
                rolled_back: false,
            })
        }

        fn current_config(&self) -> Vec<u8> {
            Vec::new()
        }

        async fn close(&self) -> Result<(), RuntimeError> {
            self.events.lock().unwrap().push("close");
            self.close_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn connection_stats(&self, _node_id: &str) -> ConnectionStats {
            ConnectionStats::default()
        }

        async fn close_user_connections(&self, _node_id: &str, _user_id: &str) -> u64 {
            0
        }

        async fn drain_traffic(&self) -> Result<Vec<TrafficDrain>, RuntimeError> {
            self.events.lock().unwrap().push("traffic drain");
            Ok(Vec::new())
        }
    }

    fn lifecycle_agent(
        address: std::net::SocketAddr,
        runtime: Arc<LifecycleRuntime>,
    ) -> Arc<Agent> {
        let config = crate::config::parse(&format!(
            "panel_grpc_endpoint = \"grpc://{address}\"\nmachine_id = \"machine\"\nnode_id = \"node\"\nmachine_secret = \"test-secret\"\n"
        ))
        .unwrap();
        Agent::with_runtime(config, runtime)
    }

    async fn wait_for_agent_release(agent: &std::sync::Weak<Agent>) {
        tokio::time::timeout(Duration::from_secs(20), async {
            while agent.strong_count() != 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("all process tasks must release the agent after shutdown");
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_run_future_stops_owned_background_tasks() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let runtime = Arc::new(LifecycleRuntime::new());
        let agent = lifecycle_agent(listener.local_addr().unwrap(), runtime.clone());
        let weak = Arc::downgrade(&agent);
        let shutdown = CancellationToken::new();
        let mut run = Box::pin(agent.run(shutdown.clone()));
        std::future::poll_fn(|cx| {
            assert!(run.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        tokio::task::yield_now().await;
        drop(run);
        wait_for_agent_release(&weak).await;
        assert!(
            !shutdown.is_cancelled(),
            "only this run's child token is cancelled"
        );
        assert_eq!(runtime.close_calls.load(Ordering::SeqCst), 1);
        assert_eq!(*runtime.events.lock().unwrap(), ["close", "traffic drain"]);
    }

    #[tokio::test(start_paused = true)]
    async fn aborting_run_waits_for_topology_then_closes_before_tail_traffic() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let runtime = Arc::new(LifecycleRuntime::new());
        let agent = lifecycle_agent(listener.local_addr().unwrap(), runtime.clone());
        let topologies = agent.topologies.clone();
        let applying = tokio::spawn(async move {
            topologies
                .apply_initial(MachineTopology {
                    machine_id: "machine".into(),
                    revision: 1,
                    ..Default::default()
                })
                .await
        });
        runtime.apply_started.notified().await;
        let weak = Arc::downgrade(&agent);
        let run = tokio::spawn(agent.run(CancellationToken::new()));
        tokio::time::timeout(Duration::from_secs(1), async {
            // The panel runner's Arc proves the supervisor and its children ran.
            while weak.strong_count() < 2 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        run.abort();
        assert!(run.await.unwrap_err().is_cancelled());
        tokio::time::advance(BACKGROUND_SHUTDOWN_LIMIT + Duration::from_secs(1)).await;
        assert!(
            !applying.is_finished(),
            "the accepted topology transaction must not be aborted"
        );
        assert_eq!(runtime.close_calls.load(Ordering::SeqCst), 0);
        runtime.allow_apply.add_permits(1);
        applying.await.unwrap().unwrap();
        wait_for_agent_release(&weak).await;
        assert_eq!(
            *runtime.events.lock().unwrap(),
            ["apply started", "apply finished", "close", "traffic drain"]
        );
        assert_eq!(runtime.close_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn digest_match_is_the_only_fast_path() {
        assert!(topology_resync_required(None, &"a".repeat(64)));
        assert!(topology_resync_required(
            Some(&"a".repeat(64)),
            &"b".repeat(64)
        ));
        assert!(!topology_resync_required(
            Some(&"a".repeat(64)),
            &"a".repeat(64)
        ));
    }

    #[tokio::test]
    async fn shutdown_deadline_restores_report_blocked_beyond_queue_capacity() {
        let aggregator = Aggregator::new(1);
        let queue = TrafficQueue::new();
        for index in 0..=crate::traffic::TRAFFIC_QUEUE_SIZE {
            aggregator.observe(TrafficEvent {
                machine_id: "machine".into(),
                node_id: "node".into(),
                user_id: format!("user-{index:03}"),
                protocol: "vless".into(),
                uplink_bytes: 1,
                downlink_bytes: 0,
                observed_at: None,
            });
        }

        let cancel = CancellationToken::new();
        let operation_cancel = cancel.clone();
        let operation = async {
            let queued = queue.flush_all(&operation_cancel, &aggregator).await;
            let drained = queue.wait_for_panel_drain(&operation_cancel).await;
            (queued, drained)
        };
        let ((queued, drained), timed_out) =
            cancel_and_finish_at_deadline(Duration::from_millis(20), &cancel, operation).await;

        assert!(timed_out);
        assert_eq!(queued, crate::traffic::TRAFFIC_QUEUE_SIZE);
        assert!(drained.is_err());
        assert_eq!(queue.queued_len(), crate::traffic::TRAFFIC_QUEUE_SIZE);
        let restored = aggregator.flush_all();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].user_id, "user-256");
    }
}
