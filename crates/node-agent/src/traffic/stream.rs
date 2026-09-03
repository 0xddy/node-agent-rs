//! Traffic queue, runtime counter drain, and ACP client stream.

use std::sync::{Arc, Mutex as StdMutex, MutexGuard as StdMutexGuard};
use std::time::Duration;

use acp_proto::TrafficReport;
use acp_proto::traffic_service_client::TrafficServiceClient;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_stream::StreamExt;
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

struct OutgoingReport {
    report: TrafficReport,
    consumed: oneshot::Sender<()>,
}

impl OutgoingReport {
    fn acknowledge_consumption(self) -> TrafficReport {
        // This method runs only when tonic polls and yields the request item.
        // A successful local mpsc send is not enough to release the durable
        // in-flight copy: the RPC may end before polling its request stream.
        let _ = self.consumed.send(());
        self.report
    }
}

fn outgoing_report_stream(
    receiver: mpsc::Receiver<OutgoingReport>,
) -> impl tokio_stream::Stream<Item = TrafficReport> {
    ReceiverStream::new(receiver).map(OutgoingReport::acknowledge_consumption)
}

struct TrafficConsumerState {
    reports: Mutex<mpsc::Receiver<TrafficReport>>,
    in_flight: StdMutex<Option<TrafficReport>>,
    drain_requests: Mutex<mpsc::Receiver<DrainResultSender>>,
}

#[derive(Clone)]
pub struct TrafficQueue {
    report_sender: mpsc::Sender<TrafficReport>,
    drain_sender: mpsc::Sender<DrainResultSender>,
    consumer: Arc<TrafficConsumerState>,
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
            drain_sender,
            consumer: Arc::new(TrafficConsumerState {
                reports: Mutex::new(report_receiver),
                in_flight: StdMutex::new(None),
                drain_requests: Mutex::new(drain_receiver),
            }),
            capacity,
        }
    }

    pub fn queued_len(&self) -> usize {
        self.capacity.saturating_sub(self.report_sender.capacity())
            + usize::from(self.in_flight().is_some())
    }

    fn in_flight(&self) -> StdMutexGuard<'_, Option<TrafficReport>> {
        self.consumer
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
        let mut reports = reports.into_iter();
        while let Some(report) = reports.next() {
            // Retain ownership until capacity is reserved so cancellation can
            // restore this report along with the remaining batch.
            let permit = tokio::select! {
                biased;
                () = cancel.cancelled() => None,
                result = self.report_sender.reserve() => result.ok(),
            };
            let Some(permit) = permit else {
                aggregator.restore(std::iter::once(report).chain(reports));
                return queued;
            };
            permit.send(report_to_proto(report));
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
    let response = client.traffic_stream(outgoing_report_stream(outgoing_receiver));
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
    outgoing: mpsc::Sender<OutgoingReport>,
) -> ConsumeStop {
    // Holding both receiver guards gives one stream generation exclusive
    // ownership while the Arc-backed durable slot survives reconnects.
    let mut reports = queue.consumer.reports.lock().await;
    let mut drain_requests = queue.consumer.drain_requests.lock().await;
    loop {
        let pending = queue.in_flight().clone();
        if let Some(report) = pending {
            let (consumed_sender, consumed_receiver) = oneshot::channel();
            let sent = tokio::select! {
                biased;
                () = cancel.cancelled() => false,
                result = outgoing.send(OutgoingReport {
                    report,
                    consumed: consumed_sender,
                }) => result.is_ok(),
            };
            if !sent {
                return if cancel.is_cancelled() {
                    ConsumeStop::Cancelled
                } else {
                    ConsumeStop::OutgoingClosed
                };
            }

            let consumed = tokio::select! {
                // If stream consumption and cancellation become ready
                // together, commit the already-observed consumption. If the
                // stream disappears before polling the item, the oneshot is
                // closed and the durable copy remains for the next session.
                biased;
                result = consumed_receiver => match result {
                    Ok(()) => true,
                    Err(_) if cancel.is_cancelled() => return ConsumeStop::Cancelled,
                    Err(_) => false,
                },
                () = cancel.cancelled() => return ConsumeStop::Cancelled,
            };
            if !consumed {
                return ConsumeStop::OutgoingClosed;
            }
            queue.in_flight().take();
            continue;
        }

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
                *queue.in_flight() = Some(report);
            }
        }
    }
}

fn report_to_proto(report: Report) -> TrafficReport {
    let observed_at_unix = report.observed_at_unix();
    TrafficReport {
        machine_id: report.machine_id,
        node_id: report.node_id,
        user_id: report.user_id,
        protocol: report.protocol,
        uplink_bytes: report.uplink_bytes,
        downlink_bytes: report.downlink_bytes,
        observed_at_unix,
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

    async fn receive_and_ack(receiver: &mut mpsc::Receiver<OutgoingReport>) -> TrafficReport {
        let outgoing = receiver
            .recv()
            .await
            .expect("outgoing report channel closed");
        let report = outgoing.report;
        outgoing
            .consumed
            .send(())
            .expect("consumer stopped before consumption acknowledgement");
        report
    }

    #[test]
    fn protobuf_mapping_preserves_identity_bytes_and_timestamp() {
        let wire = report_to_proto(report("user", 10));
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
        let reports = vec![report("one", 1), report("two", 2), report("three", 3)];
        let task_cancel = cancel.clone();
        let enqueue = queue.enqueue(&task_cancel, &aggregator, reports);
        tokio::pin!(enqueue);

        tokio::select! {
            biased;
            _ = &mut enqueue => panic!("second report unexpectedly fit in a one-slot queue"),
            _ = tokio::task::yield_now() => {}
        }
        assert_eq!(queue.queued_len(), 1);
        // Counters can accrue while enqueue waits for capacity. Restoring the
        // suffix must add to them without duplicating the already queued prefix.
        aggregator.observe(TrafficEvent {
            machine_id: "machine".into(),
            node_id: "node".into(),
            user_id: "two".into(),
            protocol: "vless".into(),
            uplink_bytes: 10,
            downlink_bytes: 20,
            observed_at: Some(UNIX_EPOCH + Duration::from_secs(1_235)),
        });
        cancel.cancel();
        assert_eq!(enqueue.await, 1);
        let restored = aggregator.flush_all();
        assert_eq!(restored.len(), 2);
        assert_eq!(restored[0].user_id, "three");
        assert_eq!(
            (restored[0].uplink_bytes, restored[0].downlink_bytes),
            (3, 4)
        );
        assert_eq!(restored[1].user_id, "two");
        assert_eq!(
            (restored[1].uplink_bytes, restored[1].downlink_bytes),
            (12, 23)
        );
        assert_eq!(queue.queued_len(), 1);
        assert_eq!(
            queue.consumer.reports.lock().await.try_recv().unwrap(),
            report_to_proto(report("one", 1))
        );
        assert!(aggregator.flush_all().is_empty());
    }

    #[tokio::test]
    async fn closed_queue_restores_the_unqueued_suffix() {
        let aggregator = Aggregator::new(1);
        let queue = TrafficQueue::with_capacity(1);
        let cancel = CancellationToken::new();
        let reports = vec![report("one", 1), report("two", 2), report("three", 3)];
        let enqueue = queue.enqueue(&cancel, &aggregator, reports);
        tokio::pin!(enqueue);

        tokio::select! {
            biased;
            _ = &mut enqueue => panic!("second report unexpectedly fit in a one-slot queue"),
            _ = tokio::task::yield_now() => {}
        }
        let mut receiver = queue.consumer.reports.lock().await;
        receiver.close();
        assert_eq!(enqueue.await, 1);
        assert_eq!(
            receiver.try_recv().unwrap(),
            report_to_proto(report("one", 1))
        );
        assert!(receiver.try_recv().is_err());

        let mut expected = vec![report("three", 3), report("two", 2)];
        for report in &mut expected {
            report.observed_at = UNIX_EPOCH + Duration::from_secs(1_200);
        }
        assert_eq!(aggregator.flush_all(), expected);
        assert!(aggregator.flush_all().is_empty());
    }

    #[tokio::test]
    async fn already_cancelled_enqueue_restores_the_entire_batch() {
        let aggregator = Aggregator::new(1);
        let queue = TrafficQueue::with_capacity(3);
        let cancel = CancellationToken::new();
        cancel.cancel();

        assert_eq!(
            queue
                .enqueue(
                    &cancel,
                    &aggregator,
                    vec![report("one", 1), report("two", 2), report("three", 3)],
                )
                .await,
            0
        );
        assert_eq!(queue.queued_len(), 0);
        let mut expected = vec![report("one", 1), report("three", 3), report("two", 2)];
        for report in &mut expected {
            report.observed_at = UNIX_EPOCH + Duration::from_secs(1_200);
        }
        assert_eq!(aggregator.flush_all(), expected);
        assert!(aggregator.flush_all().is_empty());
    }

    #[tokio::test]
    async fn outgoing_close_retains_the_dequeued_report_for_the_next_stream() {
        let aggregator = Aggregator::new(1);
        let queue = TrafficQueue::with_capacity(1);
        let cancel = CancellationToken::new();
        let expected = report_to_proto(report("one", 11));
        assert_eq!(
            queue
                .enqueue(&cancel, &aggregator, vec![report("one", 11)])
                .await,
            1
        );

        let (closed_sender, closed_receiver) = mpsc::channel(1);
        drop(closed_receiver);
        assert!(matches!(
            consume_reports(cancel.clone(), queue.clone(), closed_sender).await,
            ConsumeStop::OutgoingClosed
        ));
        assert_eq!(queue.queued_len(), 1);
        assert_eq!(queue.in_flight().as_ref(), Some(&expected));

        let next_cancel = CancellationToken::new();
        let (next_sender, mut next_receiver) = mpsc::channel(1);
        let consumer = tokio::spawn(consume_reports(
            next_cancel.clone(),
            queue.clone(),
            next_sender,
        ));
        assert_eq!(receive_and_ack(&mut next_receiver).await, expected);
        next_cancel.cancel();
        assert!(matches!(consumer.await.unwrap(), ConsumeStop::Cancelled));
        assert_eq!(queue.queued_len(), 0);
    }

    #[tokio::test]
    async fn cancellation_while_outgoing_is_blocked_retains_the_dequeued_report() {
        let aggregator = Aggregator::new(1);
        let queue = TrafficQueue::with_capacity(1);
        let cancel = CancellationToken::new();
        let expected = report_to_proto(report("one", 21));
        assert_eq!(
            queue
                .enqueue(&cancel, &aggregator, vec![report("one", 21)])
                .await,
            1
        );

        let (blocked_sender, mut blocked_receiver) = mpsc::channel(1);
        let (dummy_consumed, _dummy_ack) = oneshot::channel();
        blocked_sender
            .send(OutgoingReport {
                report: report_to_proto(report("already-buffered", 1)),
                consumed: dummy_consumed,
            })
            .await
            .unwrap();
        let consumer = tokio::spawn(consume_reports(
            cancel.clone(),
            queue.clone(),
            blocked_sender,
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if queue.in_flight().as_ref() == Some(&expected) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("consumer did not move the report into the durable in-flight slot");

        cancel.cancel();
        assert!(matches!(consumer.await.unwrap(), ConsumeStop::Cancelled));
        assert_eq!(queue.queued_len(), 1);
        assert_eq!(queue.in_flight().as_ref(), Some(&expected));
        let _ = blocked_receiver.recv().await;

        let next_cancel = CancellationToken::new();
        let (next_sender, mut next_receiver) = mpsc::channel(1);
        let next_consumer = tokio::spawn(consume_reports(
            next_cancel.clone(),
            queue.clone(),
            next_sender,
        ));
        assert_eq!(receive_and_ack(&mut next_receiver).await, expected);
        next_cancel.cancel();
        assert!(matches!(
            next_consumer.await.unwrap(),
            ConsumeStop::Cancelled
        ));
        assert_eq!(queue.queued_len(), 0);
    }

    #[tokio::test]
    async fn locally_buffered_but_unpolled_report_is_retried_on_the_next_stream() {
        let aggregator = Aggregator::new(1);
        let queue = TrafficQueue::with_capacity(1);
        let cancel = CancellationToken::new();
        let expected = report_to_proto(report("one", 31));
        assert_eq!(
            queue
                .enqueue(&cancel, &aggregator, vec![report("one", 31)])
                .await,
            1
        );

        let (sender, receiver) = mpsc::channel(1);
        let sender_probe = sender.clone();
        let consumer = tokio::spawn(consume_reports(cancel.clone(), queue.clone(), sender));
        let unpolled_stream = outgoing_report_stream(receiver);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if sender_probe.capacity() == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("report was not buffered in the unpolled request stream");

        // Dropping the unpolled RPC stream drops the consumption acknowledgement.
        drop(unpolled_stream);
        assert!(matches!(
            consumer.await.unwrap(),
            ConsumeStop::OutgoingClosed
        ));
        assert_eq!(queue.queued_len(), 1);
        assert_eq!(queue.in_flight().as_ref(), Some(&expected));

        let next_cancel = CancellationToken::new();
        let (next_sender, next_receiver) = mpsc::channel(1);
        let next_consumer = tokio::spawn(consume_reports(
            next_cancel.clone(),
            queue.clone(),
            next_sender,
        ));
        let mut next_stream = Box::pin(outgoing_report_stream(next_receiver));
        assert_eq!(next_stream.next().await, Some(expected));
        next_cancel.cancel();
        assert!(matches!(
            next_consumer.await.unwrap(),
            ConsumeStop::Cancelled
        ));
        assert_eq!(queue.queued_len(), 0);
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
