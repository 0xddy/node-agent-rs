use std::sync::Arc;
use std::time::Duration;

use acp_proto::traffic_analysis_service_client::TrafficAnalysisServiceClient;
use acp_proto::{TrafficAnalysisBatch, TrafficAnalysisConfig};
use prost::Message;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::time::Instant;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use super::{Collector, QueuedBatch};
use crate::session::{PanelClient, SessionAuthenticator, SessionError};

/// One token bucket per main session; analysis transport retries share its balance.
pub(crate) struct SendLimiter {
    rate: f64,
    burst: f64,
    tokens: f64,
    updated_at: Instant,
}

impl SendLimiter {
    pub(crate) fn new(config: &TrafficAnalysisConfig) -> Self {
        Self {
            rate: config.send_bytes_per_second as f64,
            burst: config.send_burst_bytes as f64,
            tokens: config.send_burst_bytes as f64,
            updated_at: Instant::now(),
        }
    }

    async fn acquire(&mut self, bytes: usize, expires_at: Instant) -> bool {
        let bytes = bytes as f64;
        if bytes > self.burst || self.rate <= 0.0 {
            return false;
        }
        loop {
            let now = Instant::now();
            if now >= expires_at {
                return false;
            }
            self.tokens = (self.tokens
                + now.duration_since(self.updated_at).as_secs_f64() * self.rate)
                .min(self.burst);
            self.updated_at = now;
            if self.tokens >= bytes {
                self.tokens -= bytes;
                return true;
            }
            let ready = now + Duration::from_secs_f64((bytes - self.tokens) / self.rate);
            if ready >= expires_at {
                return false;
            }
            tokio::time::sleep_until(ready).await;
        }
    }
}

struct OutgoingBatch {
    message: TrafficAnalysisBatch,
    consumed: oneshot::Sender<()>,
}

/// A popped batch is consumed once even if this future is aborted mid-send.
struct PendingBatch {
    collector: Arc<Collector>,
    batch: Arc<QueuedBatch>,
    finished: bool,
}

impl PendingBatch {
    fn complete(&mut self, success: bool) {
        self.collector.complete(&self.batch, success);
        self.finished = true;
    }

    fn drop_with_reason(&mut self, reason: &str) {
        self.collector.drop_batch(&self.batch, reason);
        self.finished = true;
    }
}

impl Drop for PendingBatch {
    fn drop(&mut self) {
        if !self.finished {
            self.collector.drop_batch(&self.batch, "session_reset");
        }
    }
}

pub(crate) async fn run_analysis_stream(
    cancel: CancellationToken,
    panel: PanelClient,
    authenticator: SessionAuthenticator,
    collector: Arc<Collector>,
    epoch: u64,
    limiter: Arc<Mutex<SendLimiter>>,
) -> Result<(), SessionError> {
    // Cloning the main Channel would still share HTTP/2 flow control. Dial a
    // separate TCP connection but reuse the authenticated session, without Hello.
    let channel = tokio::select! {
        biased;
        () = cancel.cancelled() => return Ok(()),
        result = panel.dial() => result?,
    };
    let config = collector.config();
    let mut client = TrafficAnalysisServiceClient::new(authenticator.intercepted_channel(channel))
        .max_encoding_message_size(config.batch_max_bytes as usize)
        .max_decoding_message_size(1024);
    let (sender, receiver) = mpsc::channel::<OutgoingBatch>(1);
    let outgoing = ReceiverStream::new(receiver).map(|batch| {
        // A local queue send alone cannot detect HTTP/2 backpressure. Wait for
        // tonic to consume the body, just like the telemetry transport does.
        let _ = batch.consumed.send(());
        batch.message
    });
    // Go's client-streaming handler sends no initial headers or business ACK.
    // Keep its final response future polled while producing the request body.
    let response = client.analysis_stream(tonic::Request::new(outgoing));
    tokio::pin!(response);
    loop {
        let batch = tokio::select! {
            biased;
            () = cancel.cancelled() => return Ok(()),
            result = &mut response => return terminal_response(result),
            batch = collector.next(&cancel, epoch) => match batch {
                Some(batch) => batch,
                None => return Ok(()),
            },
        };
        let mut pending = PendingBatch {
            collector: collector.clone(),
            batch,
            finished: false,
        };
        let acquire = async {
            limiter
                .lock()
                .await
                .acquire(
                    pending.batch.message.encoded_len(),
                    pending.batch.expires_at,
                )
                .await
        };
        let acquired = tokio::select! {
            biased;
            () = cancel.cancelled() => return Ok(()),
            result = &mut response => {
                pending.complete(false);
                return terminal_response(result);
            }
            acquired = acquire => acquired,
        };
        if !acquired {
            pending.drop_with_reason("expired");
            continue;
        }
        let duration = Duration::from_millis(config.send_timeout_millis.into());
        let deadline = (Instant::now() + duration).min(pending.batch.expires_at);
        let sent = tokio::select! {
            biased;
            () = cancel.cancelled() => return Ok(()),
            result = &mut response => {
                pending.complete(false);
                return terminal_response(result);
            }
            result = tokio::time::timeout_at(deadline, send_batch(&sender, pending.batch.message.clone())) => {
                result.map_err(|_| SessionError::Timeout { operation: "analysis send", duration })
                    .and_then(|result| result)
            },
        };
        pending.complete(sent.is_ok());
        // Dropping the sole RPC/Channel tears down this attempt on timeout; no
        // detached Send task or retry of an uncertain batch can survive it.
        sent?;
    }
}

async fn send_batch(
    sender: &mpsc::Sender<OutgoingBatch>,
    message: TrafficAnalysisBatch,
) -> Result<(), SessionError> {
    let (consumed, receipt) = oneshot::channel();
    sender
        .send(OutgoingBatch { message, consumed })
        .await
        .map_err(|_| SessionError::CriticalStreamEnded("analysis request body closed".into()))?;
    receipt
        .await
        .map_err(|_| SessionError::CriticalStreamEnded("analysis request body dropped".into()))
}

fn terminal_response(
    result: Result<tonic::Response<acp_proto::StreamClosed>, tonic::Status>,
) -> Result<(), SessionError> {
    match result {
        Ok(_) => Err(SessionError::CriticalStreamEnded(
            "analysis stream closed by panel".into(),
        )),
        Err(error) => Err(SessionError::Rpc(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acp_proto::traffic_analysis_service_server::{
        TrafficAnalysisService, TrafficAnalysisServiceServer,
    };
    use tonic::{Request, Response, Status};

    #[derive(Clone)]
    struct TestReceiver {
        read: bool,
        batches: mpsc::UnboundedSender<TrafficAnalysisBatch>,
        stop: CancellationToken,
    }

    #[tonic::async_trait]
    impl TrafficAnalysisService for TestReceiver {
        async fn analysis_stream(
            &self,
            request: Request<tonic::Streaming<TrafficAnalysisBatch>>,
        ) -> Result<Response<acp_proto::StreamClosed>, Status> {
            let mut stream = request.into_inner();
            loop {
                tokio::select! {
                    biased;
                    () = self.stop.cancelled() => return Ok(Response::new(acp_proto::StreamClosed::default())),
                    message = stream.message(), if self.read => {
                        match message? {
                            Some(batch) => { let _ = self.batches.send(batch); }
                            None => return Ok(Response::new(acp_proto::StreamClosed::default())),
                        }
                    }
                }
            }
        }
    }

    async fn panel_fixture(
        read: bool,
    ) -> (
        PanelClient,
        SessionAuthenticator,
        mpsc::UnboundedReceiver<TrafficAnalysisBatch>,
        CancellationToken,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let config = crate::config::parse(&format!("panel_grpc_endpoint = \"grpc://{address}\"\nmachine_id = \"machine\"\nnode_id = \"node\"\nmachine_secret = \"test-secret\"\n")).unwrap();
        let auth = SessionAuthenticator::new(
            &config,
            &acp_proto::Session {
                session_id: "test-session".into(),
                topology_revision: 1,
            },
        )
        .unwrap();
        let panel = PanelClient::new(config, "test", "test");
        let stop = CancellationToken::new();
        let (batches, receiver) = mpsc::unbounded_channel();
        let service = TestReceiver {
            read,
            batches,
            stop: stop.clone(),
        };
        let shutdown = stop.clone();
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .initial_stream_window_size(1024)
                .add_service(TrafficAnalysisServiceServer::new(service))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    shutdown.cancelled_owned(),
                )
                .await
                .unwrap();
        });
        (panel, auth, receiver, stop, task)
    }

    fn ready_collector(domains: usize) -> (Arc<Collector>, u64, TrafficAnalysisConfig) {
        let collector = Collector::new("stream-test".into());
        let epoch = collector.begin_session();
        let mut config = acp_proto::analysis::default_config(true);
        config.send_bytes_per_second = 16 << 20;
        config.send_burst_bytes = 16 << 20;
        config.batch_max_bytes = 1024;
        assert!(collector.configure(epoch, Some(&config)));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        collector.sample(now);
        for i in 0..domains {
            let domain = format!("{i}.{}.Example.COM.", "a".repeat(50));
            let flow = collector
                .register(super::super::Metadata {
                    node_id: "node".into(),
                    user_id: "user".into(),
                    proxy_protocol: "vless".into(),
                    network: "tcp".into(),
                    domain,
                    ech_present: true,
                    app_protocol: "tls".into(),
                    destination: Some(super::super::Target {
                        host: "Requested.Example.".into(),
                        port: 443,
                    }),
                    sniff_destination: None,
                })
                .unwrap();
            flow.begin().done(17, 39);
            flow.close();
        }
        collector.sample(now);
        collector.sample(now + 60);
        (collector, epoch, config)
    }

    #[tokio::test]
    async fn streams_batches_without_waiting_for_response_headers_or_ack() {
        let (panel, auth, mut received, stop, server) = panel_fixture(true).await;
        let (collector, epoch, config) = ready_collector(1);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(run_analysis_stream(
            cancel.clone(),
            panel,
            auth,
            collector.clone(),
            epoch,
            Arc::new(Mutex::new(SendLimiter::new(&config))),
        ));
        let batch = tokio::time::timeout(Duration::from_secs(15), received.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(batch.epoch, epoch);
        assert_eq!(batch.user_minutes[0].uplink_bytes, 17);
        assert_eq!(batch.user_minutes[0].downlink_bytes, 39);
        assert_eq!(batch.user_minutes[0].identified_uplink_bytes, 17);
        assert_eq!(batch.user_minutes[0].identified_downlink_bytes, 39);
        assert_eq!(batch.domain_minutes[0].app_protocol, "tls");
        assert_eq!(
            batch.domain_minutes[0].domain,
            format!("0.{}.Example.COM.", "a".repeat(50)),
        );
        assert_eq!(
            batch.domain_minutes[0].destination_domain,
            "Requested.Example.",
        );
        assert!(batch.domain_minutes[0].ech_present);
        assert!(
            !task.is_finished(),
            "no final response is required to continue sending"
        );
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        stop.cancel();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn unread_http2_stream_times_out_without_leaking_a_sender_or_resetting_collection() {
        let (panel, auth, _received, stop, server) = panel_fixture(false).await;
        let (collector, epoch, config) = ready_collector(4000);
        let cancel = CancellationToken::new();
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            run_analysis_stream(
                cancel,
                panel,
                auth,
                collector.clone(),
                epoch,
                Arc::new(Mutex::new(SendLimiter::new(&config))),
            ),
        )
        .await
        .unwrap();
        assert!(matches!(
            result,
            Err(SessionError::Timeout {
                operation: "analysis send",
                ..
            })
        ));
        assert_eq!(collector.status().send_failures, 1);
        assert!(
            collector.is_active(),
            "analysis transport failure must not pause the main session"
        );
        stop.cancel();
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn limiter_preserves_burst_balance_and_rejects_expired_batches() {
        let mut config = acp_proto::analysis::default_config(true);
        config.send_bytes_per_second = 1024;
        config.send_burst_bytes = 2048;
        let mut limiter = SendLimiter::new(&config);
        assert!(
            limiter
                .acquire(2048, Instant::now() + Duration::from_secs(20))
                .await
        );
        let started = Instant::now();
        assert!(
            limiter
                .acquire(1024, Instant::now() + Duration::from_secs(20))
                .await
        );
        assert_eq!(started.elapsed(), Duration::from_secs(1));
        assert!(
            !limiter
                .acquire(1024, Instant::now() + Duration::from_millis(100))
                .await
        );
        assert!(
            !limiter
                .acquire(2049, Instant::now() + Duration::from_secs(20))
                .await
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_or_unpolled_request_body_cannot_block_the_sender_forever() {
        let (sender, _receiver) = mpsc::channel(1);
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            send_batch(&sender, TrafficAnalysisBatch::default()),
        )
        .await;
        assert!(result.is_err());
    }
}
