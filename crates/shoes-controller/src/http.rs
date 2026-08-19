//! HTTP management API for the dynamic engine.
//!
//! Deliberately small: hyper 1.x + `service_fn`, no router crate. The API is a
//! control plane -- it is cold-path by construction, so clarity beats throughput.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::{error, info, warn};

use shoes_api::{ApiError, InboundSpec};
use shoes_engine::{Engine, EngineError};

/// Refuse request bodies larger than this. An inbound config is a few KiB at
/// most, even with inline PEM material.
const MAX_BODY_BYTES: u64 = 1024 * 1024;

type ApiResponse = Response<Full<Bytes>>;

pub struct ApiServer {
    engine: Engine,
    listen: SocketAddr,
}

impl ApiServer {
    pub fn new(engine: Engine, listen: SocketAddr) -> Self {
        Self { engine, listen }
    }

    /// Serves until the process is asked to stop. Never returns normally.
    pub async fn serve(self) -> std::io::Result<()> {
        let listener = tokio::net::TcpListener::bind(self.listen).await?;
        let engine = Arc::new(self.engine);

        info!("management API listening on http://{}", self.listen);

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    error!("management API accept failed: {e}");
                    continue;
                }
            };

            let engine = engine.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |req| {
                    let engine = engine.clone();
                    async move { Ok::<_, Infallible>(route(engine, req).await) }
                });

                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await
                {
                    warn!("management API connection from {peer} failed: {e}");
                }
            });
        }
    }
}

async fn route(engine: Arc<Engine>, req: Request<Incoming>) -> ApiResponse {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let response = match (&method, path.as_str()) {
        (&Method::GET, "/status") => json_ok(&engine.status()),
        (&Method::GET, "/inbounds") => json_ok(&engine.list_inbounds()),
        (&Method::POST, "/inbounds") => add_inbound(&engine, req).await,
        (&Method::DELETE, _) if path.starts_with("/inbounds/") => {
            let tag = percent_decode(&path["/inbounds/".len()..]);
            if tag.is_empty() {
                error_response(StatusCode::BAD_REQUEST, "missing inbound tag")
            } else {
                match engine.remove_inbound(&tag).await {
                    Ok(info) => json_ok(&info),
                    Err(e) => engine_error_response(e),
                }
            }
        }
        _ => error_response(StatusCode::NOT_FOUND, "no such endpoint"),
    };

    info!("{method} {path} -> {}", response.status().as_u16());
    response
}

async fn add_inbound(engine: &Engine, req: Request<Incoming>) -> ApiResponse {
    let body = match read_body(req).await {
        Ok(body) => body,
        Err(response) => return response,
    };

    let spec: InboundSpec = match serde_json::from_slice(&body) {
        Ok(spec) => spec,
        Err(e) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("could not parse request body: {e}"),
            );
        }
    };

    match engine.add_inbound(spec).await {
        Ok(info) => json_response(StatusCode::CREATED, &info),
        Err(e) => engine_error_response(e),
    }
}

async fn read_body(req: Request<Incoming>) -> Result<Bytes, ApiResponse> {
    let body = req.into_body();

    if let Some(hint) = body.size_hint().upper()
        && hint > MAX_BODY_BYTES
    {
        return Err(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("request body exceeds {MAX_BODY_BYTES} bytes"),
        ));
    }

    match body.collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(e) => Err(error_response(
            StatusCode::BAD_REQUEST,
            format!("could not read request body: {e}"),
        )),
    }
}

/// Maps engine failures onto HTTP statuses, keeping "caller's fault" separate
/// from "engine could not do it".
fn engine_error_response(error: EngineError) -> ApiResponse {
    let status = match &error {
        EngineError::InvalidConfig(_) => StatusCode::BAD_REQUEST,
        EngineError::DuplicateTag(_) | EngineError::AddressInUse { .. } => StatusCode::CONFLICT,
        EngineError::UnknownTag(_) => StatusCode::NOT_FOUND,
        EngineError::Unsupported(_) => StatusCode::UNPROCESSABLE_ENTITY,
        EngineError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    error_response(status, error.to_string())
}

fn json_ok<T: serde::Serialize>(value: &T) -> ApiResponse {
    json_response(StatusCode::OK, value)
}

fn json_response<T: serde::Serialize>(status: StatusCode, value: &T) -> ApiResponse {
    match serde_json::to_vec(value) {
        Ok(bytes) => Response::builder()
            .status(status)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(bytes)))
            .expect("static response builder cannot fail"),
        Err(e) => {
            error!("could not serialize response: {e}");
            plain_error(StatusCode::INTERNAL_SERVER_ERROR, "serialization failed")
        }
    }
}

fn error_response(status: StatusCode, message: impl Into<String>) -> ApiResponse {
    json_response(status, &ApiError::new(message))
}

fn plain_error(status: StatusCode, message: &str) -> ApiResponse {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(message.to_string())))
        .expect("static response builder cannot fail")
}

/// Minimal percent-decoding for the tag path segment.
///
/// Tags are caller-chosen identifiers, so `%20` and friends need to survive the
/// round trip. Invalid escapes are passed through verbatim rather than rejected.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = (bytes[index + 1] as char).to_digit(16);
            let low = (bytes[index + 2] as char).to_digit(16);
            if let (Some(high), Some(low)) = (high, low) {
                out.push((high * 16 + low) as u8);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}
