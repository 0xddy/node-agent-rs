//! Acceptance: Hysteria2's unauthenticated HTTP/3 camouflage site.

mod common;

use bytes::Bytes;
use common::hysteria2 as hy2;
use common::*;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

fn with_string_masquerade(address: std::net::SocketAddr, content: &str) -> serde_json::Value {
    let mut config = hysteria2_inbound(address, false);
    config["protocol"]["masquerade"] = json!({
        "type": "string",
        "content": content,
    });
    config
}

fn with_proxy_masquerade(
    address: std::net::SocketAddr,
    url: impl Into<String>,
    rewrite_host: bool,
) -> serde_json::Value {
    let url = url.into();
    let mut config = hysteria2_inbound(address, false);
    config["protocol"]["masquerade"] = json!({
        "type": "proxy",
        "url": url,
        "rewrite_host": rewrite_host,
    });
    config
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_masquerade_serves_probes_and_bad_auth_without_claiming_a_user() {
    let mut checks = Checks::new("hysteria2 fixed-response masquerade");
    let engine = engine().await;
    let address = free_addr();
    let config = with_string_masquerade(address, "<h1>Welcome</h1>");
    engine
        .add_inbound(dynamic("fixed", config.clone()))
        .await
        .expect("fixed-response masquerade should start");

    let response = hy2::request(
        address,
        http::Request::get("https://cover.example/landing")
            .body(Bytes::new())
            .unwrap(),
    )
    .await
    .expect("an ordinary HTTP/3 probe should receive the cover page");
    checks.eq(
        "the cover page returns 200",
        response.status().as_u16(),
        200,
    );
    checks.eq(
        "the provider-compatible content type is present",
        response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/html; charset=utf-8"),
    );
    checks.eq(
        "the configured content is returned verbatim",
        response.body().as_ref(),
        b"<h1>Welcome</h1>".as_slice(),
    );

    let head = hy2::request(
        address,
        http::Request::head("https://cover.example/landing")
            .body(Bytes::new())
            .unwrap(),
    )
    .await
    .expect("HEAD should receive the fixed response headers");
    checks.eq(
        "HEAD advertises the fixed content length",
        head.headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok()),
        Some("16"),
    );
    checks.that("HEAD does not send a response body", head.body().is_empty());

    let bad_auth = hy2::request(
        address,
        http::Request::post("https://hysteria/auth")
            .header("hysteria-auth", "not-a-user")
            .body(Bytes::new())
            .unwrap(),
    )
    .await
    .expect("a bad credential should be camouflaged rather than exposed");
    checks.eq(
        "bad authentication sees the same cover status",
        bad_auth.status().as_u16(),
        200,
    );
    checks.eq(
        "bad authentication sees the same cover body",
        bad_auth.body(),
        response.body(),
    );
    checks.eq(
        "neither probe created an accounted connection",
        engine.list_users("fixed").map(|users| users.len()).ok(),
        Some(0),
    );

    engine
        .add_user("fixed", password_user("alice", "alice-password"))
        .expect("alice should be accepted");
    checks.that(
        "a real client still receives the Hysteria2 233 response",
        hy2::Hysteria2Client::connect(address, "alice-password")
            .await
            .is_ok(),
    );

    let mut changed = config;
    changed["protocol"]["masquerade"]["content"] = json!("a different site");
    // Updates carry no users: the registry is already live and users change
    // through add_user/remove_user, so this reaches the listener-fixed guard.
    let reload = engine.update_inbound(classic("fixed", changed)).await;
    checks.detail(
        "changing a listener-baked masquerade is rejected by name",
        reload
            .as_ref()
            .err()
            .is_some_and(|error| error.to_string().contains("masquerade")),
        reload
            .err()
            .map(|error| error.to_string())
            .unwrap_or_else(|| "unexpected success".to_string()),
    );

    let plain = free_addr();
    engine
        .add_inbound(dynamic("plain", hysteria2_inbound(plain, false)))
        .await
        .expect("an inbound without masquerade should retain the old behavior");
    let response = hy2::request(
        plain,
        http::Request::get("https://cover.example/")
            .body(Bytes::new())
            .unwrap(),
    )
    .await
    .expect("the default rejection should be prompt");
    checks.eq(
        "absence of masquerade remains a 404",
        response.status().as_u16(),
        404,
    );

    let mut conflict = with_string_masquerade(free_addr(), "cover");
    conflict["protocol"]["obfs"] = json!({
        "type": "salamander",
        "password": "obfs-secret",
    });
    let conflict = engine.add_inbound(dynamic("conflict", conflict)).await;
    checks.detail(
        "obfs and masquerade cannot be enabled together",
        conflict
            .as_ref()
            .err()
            .is_some_and(|error| error.to_string().contains("obfs")),
        conflict
            .err()
            .map(|error| error.to_string())
            .unwrap_or_else(|| "unexpected success".to_string()),
    );

    checks.finish();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_valid_password_at_its_connection_limit_receives_the_masquerade() {
    let mut checks = Checks::new("hysteria2 admission camouflage");
    let engine = engine().await;
    let (origin, mut seen) = start_origin().await;
    let address = free_addr();
    engine
        .add_inbound(dynamic(
            "limited",
            with_proxy_masquerade(address, format!("http://{origin}/"), true),
        ))
        .await
        .expect("the Hysteria2 inbound should start");
    let mut alice = password_user("alice", "alice-password");
    alice.max_conns = Some(1);
    engine.add_user("limited", alice).unwrap();
    let occupied = hy2::Hysteria2Client::connect(address, "alice-password")
        .await
        .expect("the first connection should occupy alice's only slot");
    checks.that(
        "the first connection is registered",
        wait_for("alice's Hysteria2 connection", || {
            engine
                .get_user("limited", "alice")
                .is_ok_and(|user| user.conns == 1)
        })
        .await,
    );

    let request = |password: &'static str| {
        hy2::request(
            address,
            http::Request::post("https://hysteria/auth")
                .header("hysteria-auth", password)
                .header("Hysteria-CC-RX", "1048576")
                .body(Bytes::new())
                .unwrap(),
        )
    };
    let limited = request("alice-password")
        .await
        .expect("a valid but limited credential should be camouflaged");
    let unknown = request("unknown-password")
        .await
        .expect("an unknown credential should be camouflaged");
    checks.eq(
        "both receive the cover status",
        limited.status(),
        unknown.status(),
    );
    checks.eq(
        "both receive the cover body",
        limited.body(),
        unknown.body(),
    );
    checks.eq("the cover status is 201", limited.status().as_u16(), 201);
    let limited_upstream = seen
        .recv()
        .await
        .expect("the limited credential should reach the cover origin");
    let unknown_upstream = seen
        .recv()
        .await
        .expect("the unknown credential should reach the cover origin");
    checks.that(
        "a valid password refused by admission never reaches the cover origin",
        limited_upstream.hysteria_headers.is_empty(),
    );
    checks.that(
        "an unknown password never reaches the cover origin either",
        unknown_upstream.hysteria_headers.is_empty(),
    );
    checks.eq(
        "the refused connection was not authenticated",
        engine
            .get_user("limited", "alice")
            .map(|user| user.total_conns)
            .ok(),
        Some(1),
    );
    drop(occupied);
    checks.finish();
}

#[derive(Debug)]
struct SeenRequest {
    method: String,
    target: String,
    host: String,
    probe: String,
    hysteria_headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn start_origin() -> (std::net::SocketAddr, mpsc::Receiver<SeenRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (seen_tx, seen_rx) = mpsc::channel(4);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let seen_tx = seen_tx.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let header_end = loop {
                    let mut buffer = [0u8; 1024];
                    let read = socket.read(&mut buffer).await.unwrap();
                    if read == 0 {
                        return;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if let Some(index) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                        break index + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let mut lines = headers.split("\r\n");
                let first = lines.next().unwrap_or_default();
                let mut first = first.split_whitespace();
                let method = first.next().unwrap_or_default().to_string();
                let target = first.next().unwrap_or_default().to_string();
                let mut host = String::new();
                let mut probe = String::new();
                let mut hysteria_headers = Vec::new();
                let mut content_length = 0usize;
                for line in lines {
                    let Some((name, value)) = line.split_once(':') else {
                        continue;
                    };
                    let name = name.to_ascii_lowercase();
                    if name.starts_with("hysteria-") {
                        hysteria_headers.push((name.clone(), value.trim().to_string()));
                    }
                    match name.as_str() {
                        "host" => host = value.trim().to_string(),
                        "x-probe" => probe = value.trim().to_string(),
                        "content-length" => content_length = value.trim().parse().unwrap(),
                        _ => {}
                    }
                }
                while request.len() < header_end + content_length {
                    let mut buffer = [0u8; 1024];
                    let read = socket.read(&mut buffer).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                }
                let body = request[header_end..header_end + content_length].to_vec();
                let _ = seen_tx
                    .send(SeenRequest {
                        method,
                        target,
                        host,
                        probe,
                        hysteria_headers,
                        body,
                    })
                    .await;

                let response_body = b"origin response";
                let response = format!(
                    "HTTP/1.1 201 Created\r\nContent-Type: application/x-origin\r\nX-Origin: yes\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                    response_body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.write_all(response_body).await.unwrap();
                let _ = socket.shutdown().await;
            });
        }
    });
    (address, seen_rx)
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_masquerade_rewrites_url_and_controls_the_host_header() {
    let mut checks = Checks::new("hysteria2 proxy masquerade");
    let engine = engine().await;
    let (origin, mut seen) = start_origin().await;
    let target = format!("http://{origin}/base?fixed=1");

    let rewritten = free_addr();
    engine
        .add_inbound(dynamic(
            "rewrite",
            with_proxy_masquerade(rewritten, target.clone(), true),
        ))
        .await
        .expect("proxy masquerade with Host rewriting should start");
    let response = hy2::request(
        rewritten,
        http::Request::post("https://cover.example/asset?q=two")
            .header("x-probe", "preserved")
            .header(http::header::CONTENT_LENGTH, "12")
            .body(Bytes::from_static(b"request body"))
            .unwrap(),
    )
    .await
    .expect("the cover proxy should reach its origin");
    checks.eq(
        "the origin status is forwarded",
        response.status().as_u16(),
        201,
    );
    checks.eq(
        "the origin content type is forwarded",
        response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/x-origin"),
    );
    checks.eq(
        "the origin body is forwarded",
        response.body().as_ref(),
        b"origin response".as_slice(),
    );
    checks.that(
        "HTTP/1-only Connection is stripped before the HTTP/3 response",
        !response.headers().contains_key(http::header::CONNECTION),
    );

    let first = seen
        .recv()
        .await
        .expect("the origin should record the request");
    checks.eq("the method is preserved", first.method, "POST".to_string());
    checks.eq(
        "target and incoming paths/queries are joined",
        first.target,
        "/base/asset?fixed=1&q=two".to_string(),
    );
    checks.eq(
        "rewrite_host uses the upstream authority",
        first.host,
        origin.to_string(),
    );
    checks.eq(
        "end-to-end headers survive",
        first.probe,
        "preserved".to_string(),
    );
    checks.eq(
        "the request body is proxied",
        first.body,
        b"request body".to_vec(),
    );

    let preserved = free_addr();
    engine
        .add_inbound(dynamic(
            "preserve",
            with_proxy_masquerade(preserved, target, false),
        ))
        .await
        .expect("proxy masquerade preserving Host should start");
    hy2::request(
        preserved,
        http::Request::get("https://visitor.example/original")
            .body(Bytes::new())
            .unwrap(),
    )
    .await
    .expect("the second cover proxy should reach the same origin");
    let second = seen
        .recv()
        .await
        .expect("the origin should record the request");
    checks.eq(
        "rewrite_host=false preserves the visitor authority",
        second.host,
        "visitor.example".to_string(),
    );

    let unavailable = free_addr();
    let broken = free_addr();
    engine
        .add_inbound(dynamic(
            "broken",
            with_proxy_masquerade(broken, format!("http://{unavailable}/"), true),
        ))
        .await
        .expect("an unavailable origin is a runtime condition, not invalid config");
    let response = hy2::request(
        broken,
        http::Request::get("https://cover.example/")
            .body(Bytes::new())
            .unwrap(),
    )
    .await
    .expect("origin failure should still produce an HTTP response");
    checks.eq(
        "an unavailable origin becomes 502",
        response.status().as_u16(),
        502,
    );

    let invalid = engine
        .add_inbound(dynamic(
            "invalid",
            with_proxy_masquerade(free_addr(), "ftp://example.com/", true),
        ))
        .await;
    checks.detail(
        "non-HTTP proxy targets are rejected during configuration",
        invalid
            .as_ref()
            .err()
            .is_some_and(|error| error.to_string().contains("HTTP or HTTPS")),
        invalid
            .err()
            .map(|error| error.to_string())
            .unwrap_or_else(|| "unexpected success".to_string()),
    );

    checks.finish();
}
