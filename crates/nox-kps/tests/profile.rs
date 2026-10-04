//! The strict KPS-HTTP/1 profile and the route allowlist: everything outside
//! it is refused before any byte reaches the node.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use common::{dial, exchange, raw_request, request, try_exchange, TestServer, Transport};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_requests_outside_the_profile_and_the_allowlist() {
    let t = TestServer::start(|_| {}).await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let ch = t.certhash();
    let host: &[(&str, &str)] = &[("Host", ch.as_str())];
    let packet = vec![0u8; 32_768];
    let too_big = vec![0u8; 32_769];

    let cases: Vec<(&str, Vec<u8>, u16)> = vec![
        ("unknown path", request("GET", "/admin", &ch, &[], b""), 404),
        (
            "node route outside the allowlist",
            request("GET", "/api/v1/ws", &ch, &[], b""),
            404,
        ),
        (
            "SSE route outside the allowlist",
            request("GET", "/api/v1/responses/stream?surb_ids=a", &ch, &[], b""),
            404,
        ),
        (
            "removed pending route",
            request("GET", "/api/v1/responses/pending", &ch, &[], b""),
            404,
        ),
        (
            "metrics are not exposed over KPS",
            request("GET", "/metrics", &ch, &[], b""),
            404,
        ),
        (
            "prefix of an allowed path",
            request("POST", "/api/v1/packets/extra", &ch, &[], b""),
            404,
        ),
        (
            "wrong method on an allowed path",
            request("GET", "/api/v1/packets", &ch, &[], b""),
            405,
        ),
        (
            "PUT on topology",
            request("PUT", "/topology", &ch, &[], b""),
            405,
        ),
        (
            "unknown method",
            raw_request("BREW", "/topology", host, b""),
            501,
        ),
        (
            "CONNECT",
            raw_request(
                "CONNECT",
                "127.0.0.1:15002",
                &[("Host", "127.0.0.1:15002")],
                b"",
            ),
            501,
        ),
        (
            "missing Host",
            raw_request("GET", "/topology", &[], b""),
            400,
        ),
        (
            "Transfer-Encoding",
            raw_request(
                "POST",
                "/api/v1/packets",
                &[("Host", ch.as_str()), ("Transfer-Encoding", "chunked")],
                b"0\r\n\r\n",
            ),
            400,
        ),
        (
            "Upgrade",
            raw_request(
                "GET",
                "/health",
                &[
                    ("Host", ch.as_str()),
                    ("Connection", "upgrade"),
                    ("Upgrade", "websocket"),
                ],
                b"",
            ),
            400,
        ),
        (
            "absolute-form target",
            raw_request("GET", "http://127.0.0.1:15002/health", host, b""),
            400,
        ),
        (
            "HTTP/1.0",
            b"GET /health HTTP/1.0\r\nHost: x\r\n\r\n".to_vec(),
            505,
        ),
        (
            "body without Content-Length",
            raw_request("POST", "/api/v1/packets", host, &packet),
            411,
        ),
        (
            "body over the route cap",
            request("POST", "/api/v1/packets", &ch, &[], &too_big),
            413,
        ),
        (
            "Content-Length over the route cap",
            raw_request(
                "POST",
                "/api/v1/packets",
                &[("Host", ch.as_str()), ("Content-Length", "99999999")],
                b"",
            ),
            413,
        ),
        (
            "body on a GET route",
            raw_request(
                "GET",
                "/topology",
                &[("Host", ch.as_str()), ("Content-Length", "3")],
                b"abc",
            ),
            400,
        ),
        (
            "body on metadata",
            raw_request(
                "GET",
                "/metadata.json",
                &[("Host", ch.as_str()), ("Content-Length", "3")],
                b"abc",
            ),
            400,
        ),
        (
            "invalid Content-Length",
            raw_request(
                "POST",
                "/api/v1/packets",
                &[("Host", ch.as_str()), ("Content-Length", "ten")],
                b"",
            ),
            400,
        ),
        (
            "conflicting Content-Length fields",
            raw_request(
                "POST",
                "/api/v1/packets",
                &[
                    ("Host", ch.as_str()),
                    ("Content-Length", "5"),
                    ("Content-Length", "6"),
                ],
                b"hello!",
            ),
            400,
        ),
        (
            "body shorter than Content-Length",
            raw_request(
                "POST",
                "/api/v1/packets",
                &[("Host", ch.as_str()), ("Content-Length", "100")],
                b"short",
            ),
            400,
        ),
        (
            "bundles disabled",
            request(
                "GET",
                &format!("/keccak/ab/{}", "c".repeat(62)),
                &ch,
                &[],
                b"",
            ),
            404,
        ),
    ];

    for (name, req, want) in cases {
        match try_exchange(conn.as_ref(), &req, Duration::from_secs(10)).await {
            Ok(res) => {
                assert_eq!(res.status, want, "{name}: {}", res.text());
                if name != "HTTP/1.0" {
                    assert_eq!(res.version, 1, "{name}: HTTP/1.1 response");
                }
                assert!(res.header("transfer-encoding").is_none(), "{name}");
                if want == 405 {
                    assert!(res.header("allow").is_some(), "{name}: 405 lists Allow");
                }
            }
            // hyper may refuse some malformed heads itself with a status of its
            // own and then reset; a reset is the profile's "abandon" outcome.
            Err(e) => panic!("{name}: expected HTTP {want}, got {e}"),
        }
    }
    assert_eq!(t.upstream.count(), 0, "no refused request reaches the node");

    // Identical duplicate Content-Length values carry one meaning; hyper merges
    // them (RFC 9112 §6.3 permits this) and the upstream request is rebuilt
    // with a single length, so no desync is possible.
    let res = exchange(
        conn.as_ref(),
        &raw_request(
            "POST",
            "/api/v1/packets",
            &[
                ("Host", ch.as_str()),
                ("Content-Length", "5"),
                ("Content-Length", "5"),
            ],
            b"hello",
        ),
    )
    .await;
    assert_eq!(res.status, 202);
    let seen = t.upstream.last();
    assert_eq!(seen.body.as_ref(), b"hello");
    assert_eq!(seen.headers.get_all("content-length").iter().count(), 1);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_header_blocks_are_refused() {
    let t = TestServer::start(|_| {}).await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let ch = t.certhash();

    // Just under the 16 KiB cap: served.
    let pad = "a".repeat(15_000);
    let res = exchange(
        conn.as_ref(),
        &request("GET", "/health", &ch, &[("X-Pad", &pad)], b""),
    )
    .await;
    assert_eq!(res.status, 200);

    // Over the cap: 431 (or hyper's own refusal and a reset).
    let pad = "a".repeat(20_000);
    let outcome = try_exchange(
        conn.as_ref(),
        &request("GET", "/health", &ch, &[("X-Pad", &pad)], b""),
        Duration::from_secs(10),
    )
    .await;
    match outcome {
        Ok(res) => assert_eq!(res.status, 431, "{}", res.text()),
        Err(e) => assert!(e.contains("read") || e.contains("empty"), "unexpected: {e}"),
    }

    // Many small fields: over the field-count cap.
    let fields: Vec<(String, String)> = (0..100).map(|i| (format!("x-f{i}"), "v".into())).collect();
    let mut headers: Vec<(&str, &str)> = vec![("Host", ch.as_str())];
    headers.extend(fields.iter().map(|(n, v)| (n.as_str(), v.as_str())));
    let outcome = try_exchange(
        conn.as_ref(),
        &raw_request("GET", "/health", &headers, b""),
        Duration::from_secs(10),
    )
    .await;
    match outcome {
        Ok(res) => assert_eq!(res.status, 431, "{}", res.text()),
        Err(e) => assert!(e.contains("read") || e.contains("empty"), "unexpected: {e}"),
    }
    // Only the first, valid request reached the node.
    assert_eq!(t.upstream.count(), 1);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_exchange_per_stream() {
    let t = TestServer::start(|_| {}).await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let ch = t.certhash();
    // Two requests written on one stream: only the first is answered.
    let mut two = request("GET", "/health", &ch, &[], b"");
    two.extend(request("GET", "/topology", &ch, &[], b""));
    let res = exchange(conn.as_ref(), &two).await;
    assert_eq!(res.status, 200);
    assert_eq!(res.text(), "ok");
    assert_eq!(
        t.upstream.count(),
        1,
        "the pipelined request is never forwarded"
    );
    t.stop().await;
}
