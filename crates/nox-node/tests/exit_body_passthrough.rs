//! The exit relays upstream bodies exactly as the upstream sent them.
//!
//! Clients (the anon-rpc worker) ask upstreams for `accept-encoding: gzip` and
//! inflate replies themselves, so a compressed reply crosses the mixnet in a
//! fraction of the packets. That works only while the exit's HTTP client
//! leaves `content-encoding` alone: reqwest decodes bodies on its own once its
//! `gzip`, `brotli`, `deflate` or `zstd` feature is enabled anywhere in the
//! dependency graph. This test fails if that ever happens, so the change is
//! made on purpose (and the client side adjusted) rather than by accident.

use axum::http::header::{CONTENT_ENCODING, CONTENT_TYPE};
use axum::routing::post;
use axum::Router;
use std::time::Duration;

/// `gzip` of `{"jsonrpc":"2.0","id":1,"result":"0x10"}` (fixed bytes, so the
/// test needs no compression library of its own).
const GZIP_BODY: [u8; 59] = [
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xab, 0x56, 0xca, 0x2a, 0xce, 0xcf,
    0x2b, 0x2a, 0x48, 0x56, 0xb2, 0x52, 0x32, 0xd2, 0x33, 0x50, 0xd2, 0x51, 0xca, 0x4c, 0x51, 0xb2,
    0x32, 0xd4, 0x51, 0x2a, 0x4a, 0x2d, 0x2e, 0xcd, 0x29, 0x01, 0x8a, 0x1a, 0x54, 0x18, 0x1a, 0x28,
    0xd5, 0x02, 0x00, 0x1a, 0xd5, 0xbe, 0x45, 0x28, 0x00, 0x00, 0x00,
];

#[tokio::test]
async fn exit_http_client_returns_encoded_bodies_unchanged() {
    let router = Router::new().route(
        "/",
        post(|| async {
            (
                [
                    (CONTENT_ENCODING, "gzip"),
                    (CONTENT_TYPE, "application/json"),
                ],
                GZIP_BODY.to_vec(),
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    // Same builder defaults as the exit's pinned client (handlers/http.rs).
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("client");
    let response = client
        .post(format!("http://{addr}/"))
        .header("accept-encoding", "gzip")
        .body("{}")
        .send()
        .await
        .expect("request");

    assert_eq!(
        response
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("gzip"),
        "the exit must relay content-encoding as the upstream sent it"
    );
    let body = response.bytes().await.expect("body");
    assert_eq!(
        body.as_ref(),
        GZIP_BODY.as_slice(),
        "the exit must relay the compressed body byte for byte"
    );
}
