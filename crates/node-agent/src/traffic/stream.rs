//! Traffic queue, runtime counter drain, and ACP client stream.

use std::sync::Arc;
use std::time::Duration;

use acp_proto::TrafficReport;
use acp_proto::traffic_service_client::TrafficServiceClient;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;

use super::{Aggregator, Report, TrafficEvent};
use crate::runtime::{NodeRuntime, TrafficDrain};
use crate::session::{SHUTDOWN_GRACE_PERIOD, SessionAuthenticator, SessionError};

pub const TRAFFIC_QUEUE_SIZE: usize = 256;
pub const TRAFFIC_FLUSH_INTERVAL: Duration = Duration::from_secs(10);
pub const FINAL_TRAFFIC_FLUSH_LIMIT: Duration = Duration::from_secs(3);
const QUEUE_DRAIN_POLL: Duration = Duration::from_millis(50);

type DrainResultSender = oneshot::Sender<Result<(), String>>;

#[derive(Clone)]
pub struct TrafficQueue {
    report_sender: mpsc::Sender<TrafficReport>,
    report_receiver: Arc<Mutex<mpsc::Receiver<TrafficReport>>>,
    drain_sender: mpsc::Sender<DrainResultSender>,
    drain_receiver: Arc<Mutex<mpsc::Receiver<DrainResultSender>>>,
    capacity: usize,
}

impl Default for TrafficQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficQueue {
    pub fn new() -> Self {
        Self::with_capacity(TRAFFIC_QUEUE_SIZE)
    }

    fn with_capacity(capacity: usize) -> Self {
        let (report_sender, report_receiver) = mpsc::channel(capacity);
        let (drain_sender, drain_receiver) = mpsc::channel(1);
        Self {
            report_sender,
            report_receiver: Arc::new(Mutex::new(report_receiver)),
            drain_sender,
            drain_receiver: Arc::new(Mutex::new(drain_receiver)),
            capacity,
        }
    }

    pub fn queued_len(&self) -> usize {
        self.capacity.saturating_sub(self.report_sender.capacity())
    }

    /// Queues reports in order. If cancellation or closure stops the enqueue,
    /// the unqueued suffix is added back to the aggregator.
    pub async fn enqueue(
        &self,
        cancel: &CancellationToken,
        aggregator: &Aggregator,
        reports: Vec<Report>,
    ) -> usize {
        let mut queued = 0;
        for (index, report) in reports.iter().enumerate() {
            let wire = report_to_proto(report);
            let sent = tokio::select! {
                biased;
                () = cancel.cancelled() => false,
                result = self.report_sender.send(wire) => result.is_ok(),
            };
            if !sent {
                aggregator.restore(reports[index..].iter().cloned());
                return queued;
            }
            queued += 1;
        }
        queued
    }

    pub async fn flush(&self, cancel: &CancellationToken, aggregator: &Aggregator) -> usize {
        self.enqueue(cancel, aggregator, aggregator.flush()).await
    }

    pub async fn flush_all(&self, cancel: &CancellationToken, aggregator: &Aggregator) -> usize {
        self.enqueue(cancel, aggregator, aggregator.flush_all())
            .await
    }

    /// Matches the Go shutdown sequence: first wait until the buffered channel
    /// is empty, then ask the active stream to close and wait for panel reply.
    pub async fn wait_for_panel_drain(
        &self,
        cancel: &CancellationToken,
    ) -> Result<(), SessionError> {
        let mut interval = tokio::time::interval(QUEUE_DRAIN_POLL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        while self.queued_len() != 0 {
            tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    return Err(SessionError::ControlStreamClosed);
                }
                _ = interval.tick() => {}
            }
        }

        let (result_sender, result_receiver) = oneshot::channel();
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(SessionError::ControlStreamClosed),
            result = self.drain_sender.send(result_sender) => {
                if result.is_err() {
                    return Err(SessionError::ControlStreamClosed);
                }
            }
        }
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(SessionError::ControlStreamClosed),
            result = result_receiver => match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(message)) => Err(SessionError::Task {
                    name: "traffic drain".into(),
                    message,
                }),
                Err(_) => Err(SessionError::ControlStreamClosed),
            }
        }
    }
}

pub async fn collect_runtime_traffic(
    runtime: &dyn NodeRuntime,
    aggregator: &Aggregator,
    machine_id: &str,
) -> Result<usize, SessionError> {
    let drains = runtime
        .drain_traffic()
        .await
        .map_err(|error| SessionError::Task {
            name: "drain shoes traffic".into(),
            message: error.to_string(),
        })?;
    Ok(observe_runtime_drains(aggregator, machine_id, drains))
}

fn observe_runtime_drains(
    aggregator: &Aggregator,
    machine_id: &str,
    drains: Vec<TrafficDrain>,
) -> usize {
    let count = drains.len();
    for drain in drains {
        aggregator.observe(TrafficEvent {
            machine_id: machine_id.to_string(),
            node_id: drain.node_id,
            user_id: drain.user_id,
            protocol: drain.protocol,
            uplink_bytes: drain.uplink_bytes,
            downlink_bytes: drain.downlink_bytes,
            observed_at: drain.observed_at,
        });
    }
    count
}

/// Every ten seconds atomically drains shoes counters, aggregates them, and
/// queues reports that crossed the byte/age threshold.
pub async fn run_traffic_flusher(
    cancel: CancellationToken,
    runtime: Arc<dyn NodeRuntime>,
    aggregator: Arc<Aggregator>,
    queue: TrafficQueue,
    machine_id: String,
) -> Result<(), SessionError> {
    let start = tokio::time::Instant::now() + TRAFFIC_FLUSH_INTERVAL;
    let mut interval = tokio::time::interval_at(start, TRAFFIC_FLUSH_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {
                collect_runtime_traffic(runtime.as_ref(), &aggregator, &machine_id).await?;
                queue.flush(&cancel, &aggregator).await;
            }
        }
    }
}

/// Runs one authenticated client-streaming traffic RPC. The queue survives
/// session reconnects; only its active receiver is held for this generation.
pub async fn run_traffic_stream(
    cancel: CancellationToken,
    channel: Channel,
    authenticator: SessionAuthenticator,
    queue: TrafficQueue,
) -> Result<(), SessionError> {
    let (outgoing_sender, outgoing_receiver) = mpsc::channel(1);
    let consume_cancel = cancel.child_token();
    let consume = consume_reports(consume_cancel.clone(), queue, outgoing_sender);
    tokio::pin!(consume);

    let mut client = TrafficServiceClient::new(authenticator.intercepted_channel(channel));
    let response = client.traffic_stream(ReceiverStream::new(outgoing_receiver));
    tokio::pin!(response);

    tokio::select! {
        stop = &mut consume => {
            match stop {
                ConsumeStop::Drain(reply) => {
                    let result = response.await;
                    match result {
                        Ok(_) => {
                            let _ = reply.send(Ok(()));
                            Ok(())
                        }
                        Err(status) => {
                            let _ = reply.send(Err(status.to_string()));
                            Err(SessionError::Rpc(status))
                        }
                    }
                }
                ConsumeStop::Cancelled => {
                    let _ = tokio::time::timeout(SHUTDOWN_GRACE_PERIOD, &mut response).await;
                    Ok(())
                }
                ConsumeStop::OutgoingClosed => {
                    match response.await {
                        Ok(_) if cancel.is_cancelled() => Ok(()),
                        Ok(_) => Err(SessionError::CriticalStreamEnded("traffic stream closed".into())),
                        Err(status) => Err(SessionError::Rpc(status)),
                    }
                }
            }
        }
        result = &mut response => {
            consume_cancel.cancel();
            let _ = consume.await;
            match result {
                Ok(_) if cancel.is_cancelled() => Ok(()),
                Ok(_) => Err(SessionError::CriticalStreamEnded("traffic stream closed".into())),
                Err(status) => Err(SessionError::Rpc(status)),
            }
        }
    }
}

enum ConsumeStop {
    Drain(DrainResultSender),
    Cancelled,
    OutgoingClosed,
}

async fn consume_reports(
    cancel: CancellationToken,
    queue: TrafficQueue,
    outgoing: mpsc::Sender<TrafficReport>,
) -> ConsumeStop {
    let mut reports = queue.report_receiver.lock().await;
    let mut drain_requests = queue.drain_receiver.lock().await;
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return ConsumeStop::Cancelled,
            request = drain_requests.recv() => {
                return request.map_or(ConsumeStop::OutgoingClosed, ConsumeStop::Drain);
            }
            report = reports.recv() => {
                let Some(report) = report else {
                    return ConsumeStop::OutgoingClosed;
                };
                let sent = tokio::select! {
                    biased;
                    () = cancel.cancelled() => false,
                    result = outgoing.send(report) => result.is_ok(),
                };
                if !sent {
                    return if cancel.is_cancelled() {
                        ConsumeStop::Cancelled
                    } else {
                        ConsumeStop::OutgoingClosed
                    };
                }
            }
        }
    }
}

fn report_to_proto(report: &Report) -> TrafficReport {
    TrafficReport {
        machine_id: report.machine_id.clone(),
        node_id: report.node_id.clone(),
        user_id: report.user_id.clone(),
        protocol: report.protocol.clone(),
        uplink_bytes: report.uplink_bytes,
        downlink_bytes: report.downlink_bytes,
        observed_at_unix: report.observed_at_unix(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn report(user: &str, value: u64) -> Report {
        Report {
            machine_id: "machine".into(),
            node_id: "node".into(),
            user_id: user.into(),
            protocol: "vless".into(),
            uplink_bytes: value,
            downlink_bytes: value + 1,
            observed_at: UNIX_EPOCH + Duration::from_secs(1_234),
        }
    }

    #[test]
    fn protobuf_mapping_preserves_identity_bytes_and_timestamp() {
        let wire = report_to_proto(&report("user", 10));
        assert_eq!(wire.machine_id, "machine");
        assert_eq!(wire.node_id, "node");
        assert_eq!(wire.user_id, "user");
        assert_eq!(wire.protocol, "vless");
        assert_eq!((wire.uplink_bytes, wire.downlink_bytes), (10, 11));
        assert_eq!(wire.observed_at_unix, 1_234);
    }

    #[tokio::test]
    async fn cancellation_restores_the_unqueued_suffix() {
        let aggregator = Aggregator::new(1);
        let queue = TrafficQueue::with_capacity(1);
        let cancel = CancellationToken::new();
        let reports = vec![report("one", 1), report("two", 2)];
        let task_cancel = cancel.clone();
        let enqueue = queue.enqueue(&task_cancel, &aggregator, reports);
        tokio::pin!(enqueue);

        tokio::select! {
            _ = &mut enqueue => panic!("second report unexpectedly fit in a one-slot queue"),
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
        cancel.cancel();
        assert_eq!(enqueue.await, 1);
        let restored = aggregator.flush_all();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].user_id, "two");
        assert_eq!(queue.queued_len(), 1);
    }

    #[test]
    fn runtime_byte_time_survives_collection_across_minutes() {
        let aggregator = Aggregator::new(u64::MAX);
        let first = UNIX_EPOCH + Duration::from_secs(59);
        let second = UNIX_EPOCH + Duration::from_secs(121);
        let drain = |uplink_bytes, downlink_bytes, observed_at: SystemTime| TrafficDrain {
            inbound_tag: "edge".into(),
            node_id: "node".into(),
            protocol: "vless".into(),
            user_id: "alice".into(),
            uplink_bytes,
            downlink_bytes,
            observed_at: Some(observed_at),
        };

        assert_eq!(
            observe_runtime_drains(&aggregator, "machine", vec![drain(10, 0, first)]),
            1
        );
        assert_eq!(
            observe_runtime_drains(&aggregator, "machine", vec![drain(0, 20, second)]),
            1
        );

        let reports = aggregator.flush_all();
        assert_eq!(reports.len(), 1);
        assert_eq!(
            (reports[0].uplink_bytes, reports[0].downlink_bytes),
            (10, 20)
        );
        assert_eq!(reports[0].observed_at_unix(), 120);
    }
}
