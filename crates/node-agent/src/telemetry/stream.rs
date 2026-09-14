use std::sync::Arc;

use acp_proto::{StreamClosed, TELEMETRY_READY_METADATA_KEY, TelemetrySnapshot};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::codegen::http::uri::PathAndQuery;
use tonic::{Request, Status};

use super::{MAX_SAMPLE_AGE, TELEMETRY_SEND_TIMEOUT, TelemetryReporter};
use crate::session::{PANEL_REQUEST_TIMEOUT, PanelClient, SessionAuthenticator, SessionError};

const STREAM_PATH: &str = "/acp.v1.TelemetryService/TelemetryStream";

struct OutgoingSample {
    snapshot: TelemetrySnapshot,
    consumed: oneshot::Sender<()>,
}

impl TelemetryReporter {
    /// Each retry owns a transport, so telemetry backpressure and cancellation
    /// cannot interrupt the session's control and accounting streams.
    pub async fn run_stream(
        self: Arc<Self>,
        cancel: CancellationToken,
        panel: PanelClient,
        authenticator: SessionAuthenticator,
    ) -> Result<(), SessionError> {
        let channel = tokio::select! {
            biased;
            () = cancel.cancelled() => return Ok(()),
            result = panel.dial() => result?,
        };
        let (sender, receiver) = mpsc::channel::<OutgoingSample>(1);
        let outgoing = ReceiverStream::new(receiver).map(|sample| {
            // Queue insertion is insufficient: receipt waits until tonic polls
            // the body, allowing HTTP/2 flow control to reach the sole sender.
            let _ = sample.consumed.send(());
            sample.snapshot
        });
        let mut client = tonic::client::Grpc::new(authenticator.intercepted_channel(channel));
        let handshake = async {
            client.ready().await.map_err(|error| {
                SessionError::Rpc(Status::unavailable(format!(
                    "telemetry transport not ready: {error}"
                )))
            })?;
            // Generated client_streaming waits for the final unary response.
            // Using streaming on the same wire route returns the initial header
            // without waiting for either a first sample or per-sample ACKs.
            let response = client
                .streaming(
                    Request::new(outgoing),
                    PathAndQuery::from_static(STREAM_PATH),
                    tonic_prost::ProstCodec::<TelemetrySnapshot, StreamClosed>::default(),
                )
                .await
                .map_err(SessionError::Rpc)?;
            validate_ready_metadata(response.metadata())?;
            let baseline_ms = self.elapsed_ms();
            Ok::<_, SessionError>((response.into_inner(), baseline_ms))
        };
        let (mut response, baseline_ms) = tokio::select! {
            biased;
            () = cancel.cancelled() => return Ok(()),
            result = tokio::time::timeout(PANEL_REQUEST_TIMEOUT, handshake) => {
                result.map_err(|_| SessionError::Timeout {
                    operation: "telemetry clock handshake",
                    duration: PANEL_REQUEST_TIMEOUT,
                })??
            }
        };
        let mut latest = self.latest.subscribe();
        let mut last_sequence = 0;
        loop {
            let snapshot = tokio::select! {
                biased;
                () = cancel.cancelled() => return Ok(()),
                result = response.message() => return stream_ended(result),
                snapshot = next_sample(&mut latest, &mut last_sequence) => snapshot,
            };
            if !sample_is_fresh(&snapshot, baseline_ms, self.elapsed_ms()) {
                continue;
            }
            let mut message = (*snapshot).clone();
            message.stream_started_elapsed_ms = baseline_ms;
            let send_deadline = tokio::time::Instant::now() + TELEMETRY_SEND_TIMEOUT;
            tokio::select! {
                biased;
                () = cancel.cancelled() => return Ok(()),
                result = response.message() => return stream_ended(result),
                result = send_sample(&sender, message) => {
                    if let Err(error) = result {
                        // On EOF inspect the bounded final status to preserve
                        // Unauthenticated and let the session layer reauthenticate.
                        if matches!(&error, SessionError::CriticalStreamEnded(_)) {
                            return tokio::select! {
                                biased;
                                () = cancel.cancelled() => Ok(()),
                                result = tokio::time::timeout_at(send_deadline, response.message()) => match result {
                                    Ok(result) => stream_ended(result),
                                    Err(_) => Err(SessionError::Timeout {
                                        operation: "send telemetry sample",
                                        duration: TELEMETRY_SEND_TIMEOUT,
                                    }),
                                },
                            };
                        }
                        return Err(error);
                    }
                }
            }
            log::debug!(
                "telemetry report sent: sequence={}, cpu_valid={}, network_interfaces={}",
                snapshot.sample_seq,
                snapshot.cpu_valid,
                snapshot.network_interfaces.len()
            );
        }
    }
}

fn validate_ready_metadata(metadata: &tonic::metadata::MetadataMap) -> Result<(), SessionError> {
    let mut values = metadata.get_all(TELEMETRY_READY_METADATA_KEY).iter();
    if values.next().and_then(|value| value.to_str().ok()) != Some("1") || values.next().is_some() {
        return Err(SessionError::Metadata(
            "telemetry clock handshake is missing".into(),
        ));
    }
    Ok(())
}

fn sample_is_fresh(snapshot: &TelemetrySnapshot, baseline_ms: u64, now_ms: u64) -> bool {
    snapshot.sample_elapsed_ms >= baseline_ms
        && now_ms.saturating_sub(snapshot.sample_elapsed_ms) <= MAX_SAMPLE_AGE.as_millis() as u64
}

async fn next_sample(
    latest: &mut watch::Receiver<Option<Arc<TelemetrySnapshot>>>,
    last_sequence: &mut u64,
) -> Arc<TelemetrySnapshot> {
    loop {
        let value = latest.borrow_and_update().clone();
        if let Some(snapshot) = value
            && snapshot.sample_seq > *last_sequence
        {
            *last_sequence = snapshot.sample_seq;
            return snapshot;
        }
        // This stream holds the reporter, keeping the sender alive.
        if latest.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

async fn send_sample(
    sender: &mpsc::Sender<OutgoingSample>,
    snapshot: TelemetrySnapshot,
) -> Result<(), SessionError> {
    tokio::time::timeout(TELEMETRY_SEND_TIMEOUT, async {
        let (consumed, receipt) = oneshot::channel();
        sender
            .send(OutgoingSample { snapshot, consumed })
            .await
            .map_err(|_| {
                SessionError::CriticalStreamEnded("telemetry request body closed".into())
            })?;
        receipt
            .await
            .map_err(|_| SessionError::CriticalStreamEnded("telemetry request body closed".into()))
    })
    .await
    .map_err(|_| SessionError::Timeout {
        operation: "send telemetry sample",
        duration: TELEMETRY_SEND_TIMEOUT,
    })?
}

fn stream_ended(result: Result<Option<StreamClosed>, Status>) -> Result<(), SessionError> {
    match result {
        Err(status) => Err(SessionError::Rpc(status)),
        Ok(_) => Err(SessionError::CriticalStreamEnded(
            "telemetry stream closed".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_handshake_requires_exactly_one_ready_marker() {
        let mut metadata = tonic::metadata::MetadataMap::new();
        assert!(validate_ready_metadata(&metadata).is_err());
        metadata.insert(TELEMETRY_READY_METADATA_KEY, "0".parse().unwrap());
        assert!(validate_ready_metadata(&metadata).is_err());
        metadata.insert(TELEMETRY_READY_METADATA_KEY, "1".parse().unwrap());
        assert!(validate_ready_metadata(&metadata).is_ok());
        metadata.append(TELEMETRY_READY_METADATA_KEY, "1".parse().unwrap());
        assert!(validate_ready_metadata(&metadata).is_err());
    }

    #[test]
    fn reconnect_rejects_samples_before_its_clock_and_expired_samples() {
        let sample = TelemetrySnapshot {
            sample_elapsed_ms: 100,
            ..Default::default()
        };
        assert!(!sample_is_fresh(&sample, 101, 102));
        assert!(sample_is_fresh(&sample, 100, 6100));
        assert!(!sample_is_fresh(&sample, 100, 6101));
    }

    #[tokio::test(start_paused = true)]
    async fn unconsumed_body_times_out_without_an_orphan_sender() {
        let (sender, mut receiver) = mpsc::channel(1);
        let result = send_sample(&sender, TelemetrySnapshot::default()).await;
        assert!(matches!(
            result,
            Err(SessionError::Timeout {
                operation: "send telemetry sample",
                ..
            })
        ));
        let pending = receiver.recv().await.unwrap();
        assert!(pending.consumed.is_closed());
    }
}
