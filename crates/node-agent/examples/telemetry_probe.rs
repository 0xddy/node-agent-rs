//! Docker compatibility probe: the production reporter and host collector,
//! deterministic runtime counts, and an actual panel-api-server peer.
use std::sync::Arc;
use std::time::{Duration, Instant};

use acp_proto::Session;
use async_trait::async_trait;
use node_agent::config;
use node_agent::policy::PolicyState;
use node_agent::runtime::{
    ConnectionStats, NodeRuntime, ReloadStatus, RuntimeConfig, RuntimeError, TrafficDrain,
};
use node_agent::session::{PanelClient, SessionAuthenticator, SessionError};
use node_agent::telemetry::TelemetryReporter;
use tokio_util::sync::CancellationToken;

struct ProbeRuntime;

#[async_trait]
impl NodeRuntime for ProbeRuntime {
    async fn apply_config(&self, _: RuntimeConfig) -> Result<(), RuntimeError> {
        Ok(())
    }
    async fn reload_config(&self, _: RuntimeConfig) -> Result<ReloadStatus, RuntimeError> {
        Ok(ReloadStatus {
            running: true,
            rolled_back: false,
        })
    }
    fn current_config(&self) -> Vec<u8> {
        Vec::new()
    }
    async fn close(&self) -> Result<(), RuntimeError> {
        Ok(())
    }
    fn connection_stats(&self, _: &str) -> ConnectionStats {
        ConnectionStats {
            active_connections: 7,
            online_users: 3,
        }
    }
    fn connection_stats_snapshot(&self, node_id: &str) -> Option<ConnectionStats> {
        Some(self.connection_stats(node_id))
    }
    async fn close_user_connections(&self, _: &str, _: &str) -> u64 {
        0
    }
    async fn drain_traffic(&self) -> Result<Vec<TrafficDrain>, RuntimeError> {
        Ok(Vec::new())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: telemetry_probe PANEL_ADDRESS SESSION_ID auth|timeout".into());
    }
    let cfg = config::parse(&format!(
        "panel_grpc_endpoint = 'grpc://{}'\nmachine_id = 'machine-example'\nnode_id = 'node-vless-1'\nmachine_secret = 'secret'\n",
        args[0]
    ))?;
    let session = Session {
        session_id: args[1].clone(),
        ..Default::default()
    };
    let auth = SessionAuthenticator::new(&cfg, &session)?;
    let panel = PanelClient::new(cfg.clone(), "docker-telemetry-probe", "probe-runtime");
    let reporter = Arc::new(TelemetryReporter::new(
        cfg.machine_id,
        cfg.node_id,
        Arc::new(PolicyState::new()),
    ));
    let cancel = CancellationToken::new();
    let sampling = reporter
        .clone()
        .start_sampling(cancel.clone(), Arc::new(ProbeRuntime));
    let start = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(90), async {
        for attempt in 1..=8 {
            let error = reporter.clone().run_stream(cancel.clone(), panel.clone(), auth.clone())
                .await.expect_err("fixture always terminates each stream");
            println!("{}", serde_json::json!({ "attempt": attempt, "elapsed_ms": start.elapsed().as_millis(), "error": error.to_string() }));
            match (&error, args[2].as_str()) {
                (SessionError::Rpc(status), "auth") if matches!(status.code(), tonic::Code::Unauthenticated | tonic::Code::PermissionDenied) => return Ok(()),
                (SessionError::Timeout { .. }, "timeout") => return Ok(()),
                // Leave sampling active during an outage long enough to replace
                // several latest values. Reconnection must not replay them.
                (_, "auth") if attempt < 8 => tokio::time::sleep(Duration::from_secs(7)).await,
                _ => return Err(error.to_string()),
            }
        }
        Err("fixture did not deliver its terminal error".to_string())
    }).await;
    cancel.cancel();
    sampling.await?;
    result??;
    Ok(())
}
