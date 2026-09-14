//! The telemetry RPC sends response headers before reading its request stream.
//! Tonic's generated client-streaming server waits for the final response, so
//! these fixtures adapt its handler to the equivalent streaming wire transport.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use acp_proto::telemetry_service_server::TelemetryService;
use acp_proto::{StreamClosed, TELEMETRY_READY_METADATA_KEY, TelemetrySnapshot};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::body::Body;
use tonic::codegen::{Service, http};
use tonic::{Request, Response, Status, Streaming};

pub struct TelemetryHeaderServer<T>(Arc<T>);

impl<T> TelemetryHeaderServer<T> {
    pub fn new(handler: T) -> Self {
        Self(Arc::new(handler))
    }
}

impl<T> Clone for TelemetryHeaderServer<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> tonic::server::NamedService for TelemetryHeaderServer<T> {
    const NAME: &'static str = "acp.v1.TelemetryService";
}

impl<T: TelemetryService> Service<http::Request<Body>> for TelemetryHeaderServer<T> {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let handler = self.0.clone();
        Box::pin(async move {
            if request.uri().path() != "/acp.v1.TelemetryService/TelemetryStream" {
                return Ok(http::Response::builder()
                    .header("grpc-status", "12")
                    .header("content-type", "application/grpc")
                    .body(Body::empty())
                    .unwrap());
            }
            let codec = tonic_prost::ProstCodec::<StreamClosed, TelemetrySnapshot>::default();
            Ok(tonic::server::Grpc::new(codec)
                .streaming(TelemetryMethod(handler), request)
                .await)
        })
    }
}

struct TelemetryMethod<T>(Arc<T>);

impl<T: TelemetryService> tonic::server::StreamingService<TelemetrySnapshot>
    for TelemetryMethod<T>
{
    type Response = StreamClosed;
    type ResponseStream = HandlerResponse;
    type Future = Pin<Box<dyn Future<Output = Result<Response<HandlerResponse>, Status>> + Send>>;

    fn call(&mut self, request: Request<Streaming<TelemetrySnapshot>>) -> Self::Future {
        let handler = self.0.clone();
        Box::pin(async move {
            let (sender, receiver) = mpsc::channel(1);
            let task = tokio::spawn(async move {
                let result = handler
                    .telemetry_stream(request)
                    .await
                    .map(Response::into_inner);
                // Dropping the response cancels the reader below. A closed
                // receiver here means the client no longer needs final status.
                let _ = sender.send(result).await;
            });
            let mut response = Response::new(HandlerResponse {
                receiver: ReceiverStream::new(receiver),
                task,
            });
            response.metadata_mut().insert(
                TELEMETRY_READY_METADATA_KEY,
                tonic::metadata::MetadataValue::from_static("1"),
            );
            Ok(response)
        })
    }
}

struct HandlerResponse {
    receiver: ReceiverStream<Result<StreamClosed, Status>>,
    task: JoinHandle<()>,
}

impl Stream for HandlerResponse {
    type Item = Result<StreamClosed, Status>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().receiver).poll_next(cx)
    }
}

impl Drop for HandlerResponse {
    fn drop(&mut self) {
        self.task.abort();
    }
}
