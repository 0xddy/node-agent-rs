//! ACP bidirectional live-log stream.

use std::future::pending;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use acp_proto::log_service_client::LogServiceClient;
use acp_proto::{NodeLogBatch, NodeLogCommandType, NodeLogLine};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_stream::{Stream, StreamExt, wrappers::ReceiverStream};
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;

use super::{RemoteLine, RemoteSubscription, remote_source_id, subscribe_remote};
use crate::session::{SessionAuthenticator, SessionError};

pub const LOG_BATCH_MAX_LINES: usize = 64;
pub const LOG_BATCH_MAX_BYTES: usize = 32 << 10;
pub const LOG_BATCH_WAIT: Duration = Duration::from_millis(100);
const FLUSH_REQUEST_QUEUE: usize = 1;

struct FlushRequest {
    subscription: Arc<RemoteSubscription>,
    subscription_id: String,
    completed: oneshot::Sender<bool>,
}

/// Runs one authenticated LogStream generation. START replaces any existing
/// subscription, STOP only affects the matching subscription id, and lines are
/// coalesced for 100ms before each bounded batch just like the Go agent.
pub async fn run_log_stream(
    cancel: CancellationToken,
    channel: Channel,
    authenticator: SessionAuthenticator,
) -> Result<(), SessionError> {
    // Queue permission to drain, not already-drained batches. Tonic polls this
    // stream when it can accept another request message; only then are lines
    // removed from the subscription. A stalled or disconnected transport can
    // therefore never hide up to N batches outside the broker's dropped count.
    let (flush_sender, flush_receiver) = mpsc::channel(FLUSH_REQUEST_QUEUE);
    let mut client = LogServiceClient::new(authenticator.intercepted_channel(channel));
    let response = client
        .log_stream(deferred_batch_stream(flush_receiver))
        .await
        .map_err(SessionError::Rpc)?;
    let mut commands = response.into_inner();

    let mut subscription: Option<Arc<RemoteSubscription>> = None;
    let mut subscription_id = String::new();
    let mut flush_at: Option<Instant> = None;

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                close_subscription(&mut subscription, &mut subscription_id, &mut flush_at);
                return Ok(());
            }
            command = commands.message() => {
                let Some(command) = command.map_err(SessionError::Rpc)? else {
                    close_subscription(&mut subscription, &mut subscription_id, &mut flush_at);
                    return Ok(());
                };
                if command.subscription_id.is_empty() {
                    continue;
                }
                match NodeLogCommandType::try_from(command.r#type).ok() {
                    Some(NodeLogCommandType::Start) => {
                        close_subscription(
                            &mut subscription,
                            &mut subscription_id,
                            &mut flush_at,
                        );
                        subscription = Some(Arc::new(subscribe_remote()));
                        subscription_id = command.subscription_id;
                        log::info!("实时日志通道已连接");
                    }
                    Some(NodeLogCommandType::Stop) if command.subscription_id == subscription_id => {
                        close_subscription(
                            &mut subscription,
                            &mut subscription_id,
                            &mut flush_at,
                        );
                        log::info!("实时日志通道已断开");
                    }
                    _ => {}
                }
            }
            () = wait_for_notification(subscription.as_ref()) => {
                if subscription.is_some() && flush_at.is_none() {
                    flush_at = Some(Instant::now() + LOG_BATCH_WAIT);
                }
            }
            () = wait_for_flush(flush_at) => {
                flush_at = None;
                let Some(current) = subscription.as_ref().cloned() else {
                    continue;
                };
                let (completed, completion) = oneshot::channel();
                let request = FlushRequest {
                    subscription: current.clone(),
                    subscription_id: subscription_id.clone(),
                    completed,
                };
                let queued = tokio::select! {
                    biased;
                    () = cancel.cancelled() => {
                        close_subscription(
                            &mut subscription,
                            &mut subscription_id,
                            &mut flush_at,
                        );
                        return Ok(());
                    }
                    result = flush_sender.send(request) => result.is_ok(),
                };
                if !queued {
                    close_subscription(
                        &mut subscription,
                        &mut subscription_id,
                        &mut flush_at,
                    );
                    return Err(SessionError::ControlStreamClosed);
                }
                let has_more = tokio::select! {
                    biased;
                    result = completion => result.map_err(|_| SessionError::ControlStreamClosed)?,
                    () = cancel.cancelled() => {
                        close_subscription(
                            &mut subscription,
                            &mut subscription_id,
                            &mut flush_at,
                        );
                        return Ok(());
                    }
                };
                if has_more || !current.is_empty() {
                    flush_at = Some(Instant::now() + LOG_BATCH_WAIT);
                }
            }
        }
    }
}

/// Converts drain permissions into request messages. The subscription is read
/// only from `poll_next`, so backpressure before that point leaves every line in
/// the bounded broker queue where eviction is reflected by `dropped_line_count`.
fn deferred_batch_stream(
    receiver: mpsc::Receiver<FlushRequest>,
) -> impl Stream<Item = NodeLogBatch> {
    ReceiverStream::new(receiver).filter_map(|request| {
        let (lines, dropped) = request
            .subscription
            .drain(LOG_BATCH_MAX_LINES, LOG_BATCH_MAX_BYTES);
        let has_more = !request.subscription.is_empty();
        let batch = (!lines.is_empty())
            .then(|| build_batch(&request.subscription_id, remote_source_id(), lines, dropped));
        let _ = request.completed.send(has_more);
        batch
    })
}

async fn wait_for_notification(subscription: Option<&Arc<RemoteSubscription>>) {
    match subscription {
        Some(subscription) => subscription.notified().await,
        None => pending().await,
    }
}

async fn wait_for_flush(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => pending().await,
    }
}

fn close_subscription(
    subscription: &mut Option<Arc<RemoteSubscription>>,
    subscription_id: &mut String,
    flush_at: &mut Option<Instant>,
) {
    *flush_at = None;
    if let Some(subscription) = subscription.take() {
        subscription.close();
    }
    subscription_id.clear();
}

fn build_batch(
    subscription_id: &str,
    source_id: &str,
    lines: Vec<RemoteLine>,
    dropped_line_count: u64,
) -> NodeLogBatch {
    NodeLogBatch {
        subscription_id: subscription_id.to_string(),
        source_id: source_id.to_string(),
        dropped_line_count,
        lines: lines
            .into_iter()
            .map(|line| NodeLogLine {
                sequence: line.sequence,
                captured_at_unix_milli: unix_millis(line.captured_at),
                text: line.text,
            })
            .collect(),
    }
}

fn unix_millis(timestamp: SystemTime) -> i64 {
    match timestamp.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
        Err(error) => -i64::try_from(error.duration().as_millis()).unwrap_or(i64::MAX),
    }
}

#[cfg(test)]
mod tests {
    use acp_proto::auth::{
        METADATA_MACHINE_ID, METADATA_NONCE, METADATA_SESSION_ID, METADATA_SIGNATURE,
        METADATA_TIMESTAMP_UNIX,
    };
    use acp_proto::log_service_server::{LogService, LogServiceServer};
    use acp_proto::{NodeLogCommand, Session};
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::{Endpoint, Server};
    use tonic::{Request, Response, Status};

    use super::*;
    use crate::config;

    #[test]
    fn batch_copies_sequence_timestamp_text_and_drop_count() {
        let batch = build_batch(
            "subscription",
            "source",
            vec![RemoteLine {
                sequence: 7,
                captured_at: UNIX_EPOCH + Duration::from_millis(1_234),
                text: "line".into(),
            }],
            9,
        );
        assert_eq!(batch.subscription_id, "subscription");
        assert_eq!(batch.source_id, "source");
        assert_eq!(batch.dropped_line_count, 9);
        assert_eq!(batch.lines.len(), 1);
        assert_eq!(batch.lines[0].sequence, 7);
        assert_eq!(batch.lines[0].captured_at_unix_milli, 1_234);
        assert_eq!(batch.lines[0].text, "line");
    }

    #[test]
    fn timestamps_before_epoch_stay_negative() {
        assert_eq!(unix_millis(UNIX_EPOCH - Duration::from_millis(5)), -5);
    }

    #[tokio::test]
    async fn transport_backpressure_does_not_prefetch_lines_out_of_subscription() {
        let broker = super::super::RemoteBroker::new("deferred-source");
        let subscription = Arc::new(broker.subscribe());
        for index in 0..(super::super::REMOTE_QUEUE_MAX_LINES + 3) {
            broker.publish(format!("line-{index}"));
        }
        assert_eq!(subscription.len(), super::super::REMOTE_QUEUE_MAX_LINES);

        let (sender, receiver) = mpsc::channel(FLUSH_REQUEST_QUEUE);
        let mut batches = Box::pin(deferred_batch_stream(receiver));
        let (completed, completion) = oneshot::channel();
        sender
            .send(FlushRequest {
                subscription: subscription.clone(),
                subscription_id: "subscription".into(),
                completed,
            })
            .await
            .unwrap();

        assert_eq!(
            subscription.len(),
            super::super::REMOTE_QUEUE_MAX_LINES,
            "queuing flush permission must not drain a hidden batch"
        );
        let batch = batches.next().await.unwrap();
        assert_eq!(batch.lines.len(), LOG_BATCH_MAX_LINES);
        assert_eq!(batch.dropped_line_count, 3);
        assert!(completion.await.unwrap());
        assert_eq!(
            subscription.len(),
            super::super::REMOTE_QUEUE_MAX_LINES - LOG_BATCH_MAX_LINES
        );
    }

    #[tokio::test]
    async fn disconnect_before_transport_poll_leaves_unsent_lines_in_subscription() {
        let broker = super::super::RemoteBroker::new("disconnect-source");
        let subscription = Arc::new(broker.subscribe());
        broker.publish("must-survive");

        let (sender, receiver) = mpsc::channel(FLUSH_REQUEST_QUEUE);
        let batches = deferred_batch_stream(receiver);
        let (completed, completion) = oneshot::channel();
        sender
            .send(FlushRequest {
                subscription: subscription.clone(),
                subscription_id: "subscription".into(),
                completed,
            })
            .await
            .unwrap();
        drop(batches);

        assert!(completion.await.is_err());
        assert_eq!(subscription.len(), 1);
        let (lines, dropped) = subscription.drain(LOG_BATCH_MAX_LINES, LOG_BATCH_MAX_BYTES);
        assert_eq!(dropped, 0);
        assert_eq!(lines[0].text, "must-survive");
    }

    #[derive(Clone)]
    struct MockLogPanel {
        batches: mpsc::UnboundedSender<NodeLogBatch>,
    }

    #[tonic::async_trait]
    impl LogService for MockLogPanel {
        type LogStreamStream = ReceiverStream<Result<acp_proto::NodeLogCommand, Status>>;

        async fn log_stream(
            &self,
            request: Request<tonic::Streaming<NodeLogBatch>>,
        ) -> Result<Response<Self::LogStreamStream>, Status> {
            for key in [
                METADATA_MACHINE_ID,
                METADATA_SESSION_ID,
                METADATA_TIMESTAMP_UNIX,
                METADATA_NONCE,
                METADATA_SIGNATURE,
            ] {
                if request.metadata().get_all(key).iter().count() != 1 {
                    return Err(Status::unauthenticated(format!(
                        "expected exactly one {key}"
                    )));
                }
            }

            let mut batches = request.into_inner();
            let batch_events = self.batches.clone();
            let (commands, receiver) = mpsc::channel(2);
            tokio::spawn(async move {
                if commands
                    .send(Ok(NodeLogCommand {
                        subscription_id: "subscription-1".into(),
                        r#type: NodeLogCommandType::Start as i32,
                    }))
                    .await
                    .is_err()
                {
                    return;
                }
                if let Ok(Some(batch)) = batches.message().await {
                    let _ = batch_events.send(batch);
                }
            });
            Ok(Response::new(ReceiverStream::new(receiver)))
        }
    }

    #[tokio::test]
    async fn tonic_stream_authenticates_starts_and_sends_a_bounded_batch() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let incoming = TcpListenerStream::new(listener);
        let (batch_events, mut batches) = mpsc::unbounded_channel();
        let server_cancel = CancellationToken::new();
        let server_token = server_cancel.clone();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(LogServiceServer::new(MockLogPanel {
                    batches: batch_events,
                }))
                .serve_with_incoming_shutdown(incoming, server_token.cancelled_owned())
                .await
                .unwrap();
        });

        let config = config::parse(&format!(
            r#"panel_grpc_endpoint = "grpc://{address}"
machine_id = "machine-1"
node_id = "node-1"
machine_secret = "secret"
"#
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
        let channel = Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let cancel = CancellationToken::new();
        let runner_cancel = cancel.clone();
        let runner = tokio::spawn(run_log_stream(runner_cancel, channel, authenticator));

        // The command is delivered through a separate HTTP/2 direction; yield a
        // few times so the subscription exists before publishing the test line.
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            super::super::publish_remote("test", "wire-marker");
        }
        let batch = tokio::time::timeout(Duration::from_secs(2), batches.recv())
            .await
            .expect("log batch timed out")
            .expect("mock batch channel closed");
        assert_eq!(batch.subscription_id, "subscription-1");
        assert_eq!(batch.source_id, super::super::remote_source_id());
        assert!(batch.lines.len() <= LOG_BATCH_MAX_LINES);
        assert!(
            batch
                .lines
                .iter()
                .any(|line| line.text.contains("wire-marker"))
        );

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), runner)
            .await
            .expect("log runner did not stop")
            .expect("log runner panicked")
            .unwrap();
        server_cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("mock server did not stop")
            .expect("mock server panicked");
    }
}
