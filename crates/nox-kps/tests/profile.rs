//! The `nox-kps-http/1` profile, the fixed route allowlist and the per-route
//! request rules: everything outside them is refused before any byte reaches
//! the node.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

mod common;

use std::time::Duration;

use common::{
    claim_request, dial, exchange, packet, raw_request, request, try_exchange, TestServer,
    Transport, SURB_ID,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_requests_outside_the_profile_and_the_allowlist() {
    let t = TestServer::start(|raw| raw.limits.claim_max_surb_ids = 4).await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let ch = t.certhash();
    let host: &[(&str, &str)] = &[("Host", ch.as_str())];
    let octets = ("Content-Type", "application/octet-stream");
    let json = ("Content-Type", "application/json");
    let too_many: Vec<&str> = vec![SURB_ID; 5];

    let cases: Vec<(&str, Vec<u8>, u16)> = vec![
        ("unknown path", request("GET", "/admin", &ch, &[], b""), 404),
        (
            "websocket route",
            request("GET", "/api/v1/ws", &ch, &[], b""),
            404,
        ),
        (
            "SSE route",
            request("GET", "/api/v1/responses/stream?surb_ids=a", &ch, &[], b""),
            404,
        ),
        (
            "pending route",
            request("GET", "/api/v1/responses/pending", &ch, &[], b""),
            404,
        ),
        (
            "poll route",
            request(
                "GET",
                &format!("/api/v1/responses/{SURB_ID}"),
                &ch,
                &[],
                b"",
            ),
            404,
        ),
        (
            "node metrics",
            request("GET", "/metrics", &ch, &[], b""),
            404,
        ),
        (
            "prefix of an allowed path",
            request("POST", "/api/v1/packets/extra", &ch, &[], b""),
            404,
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
        (
            "GET on packets",
            request("GET", "/api/v1/packets", &ch, &[], b""),
            405,
        ),
        (
            "PUT on topology",
            request("PUT", "/topology", &ch, &[], b""),
            405,
        ),
        (
            "HEAD on topology",
            request("HEAD", "/topology", &ch, &[], b""),
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
            "Expect: 100-continue",
            raw_request(
                "POST",
                "/api/v1/packets",
                &[
                    ("Host", ch.as_str()),
                    octets,
                    ("Content-Length", "32768"),
                    ("Expect", "100-continue"),
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
            "packet without Content-Type",
            request("POST", "/api/v1/packets", &ch, &[], &packet(0)),
            415,
        ),
        (
            "packet as JSON",
            request("POST", "/api/v1/packets", &ch, &[json], &packet(0)),
            415,
        ),
        (
            "packet without Content-Length",
            raw_request(
                "POST",
                "/api/v1/packets",
                &[("Host", ch.as_str()), octets],
                &packet(0),
            ),
            411,
        ),
        (
            "packet one byte short",
            request(
                "POST",
                "/api/v1/packets",
                &ch,
                &[octets],
                &vec![0u8; 32_767],
            ),
            400,
        ),
        (
            "packet one byte long",
            request(
                "POST",
                "/api/v1/packets",
                &ch,
                &[octets],
                &vec![0u8; 32_769],
            ),
            413,
        ),
        (
            "Content-Length far over the cap",
            raw_request(
                "POST",
                "/api/v1/packets",
                &[
                    ("Host", ch.as_str()),
                    octets,
                    ("Content-Length", "99999999"),
                ],
                b"",
            ),
            413,
        ),
        (
            "invalid Content-Length",
            raw_request(
                "POST",
                "/api/v1/packets",
                &[("Host", ch.as_str()), octets, ("Content-Length", "ten")],
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
                    octets,
                    ("Content-Length", "5"),
                    ("Content-Length", "6"),
                ],
                b"hello!",
            ),
            400,
        ),
        (
            "claim as text",
            request(
                "POST",
                "/api/v1/responses/claim",
                &ch,
                &[("Content-Type", "text/plain")],
                b"{}",
            ),
            415,
        ),
        (
            "claim with a bad ID",
            request(
                "POST",
                "/api/v1/responses/claim",
                &ch,
                &[json],
                br#"{"surb_ids":["../../etc/passwd"]}"#,
            ),
            400,
        ),
        (
            "claim that is not JSON",
            request("POST", "/api/v1/responses/claim", &ch, &[json], b"surb"),
            400,
        ),
        (
            "claim with too many IDs",
            claim_request(&ch, &too_many),
            400,
        ),
        (
            "claim over the size cap",
            request(
                "POST",
                "/api/v1/responses/claim",
                &ch,
                &[json],
                &vec![b' '; 65_537],
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
            Err(e) => panic!("{name}: expected HTTP {want}, got {e}"),
        }
    }
    assert_eq!(t.upstream.count(), 0, "no refused request reaches the node");

    // A body shorter than its Content-Length is abandoned: reset, no response.
    let short = raw_request(
        "POST",
        "/api/v1/packets",
        &[("Host", ch.as_str()), octets, ("Content-Length", "32768")],
        b"short",
    );
    let outcome = try_exchange(conn.as_ref(), &short, Duration::from_secs(10)).await;
    assert!(outcome.is_err(), "short body is abandoned: {outcome:?}");
    assert_eq!(t.upstream.count(), 0);

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
                octets,
                ("Content-Length", "32768"),
                ("Content-Length", "32768"),
            ],
            &packet(5),
        ),
    )
    .await;
    assert_eq!(res.status, 202);
    let seen = t.upstream.last();
    assert_eq!(seen.body.len(), 32_768);
    assert_eq!(seen.headers.get_all("content-length").iter().count(), 1);

    let metrics = t.metrics_text().await;
    for kind in [
        "transfer_encoding",
        "upgrade",
        "expect",
        "packet_size",
        "content_type",
        "claim_body",
        "length_required",
        "body_length",
    ] {
        assert!(
            metrics.contains(&format!(
                "nox_kps_profile_violations_total{{kind=\"{kind}\"}}"
            )),
            "{kind} counted:\n{metrics}"
        );
    }
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
        &request("GET", "/topology", &ch, &[("X-Pad", &pad)], b""),
    )
    .await;
    assert_eq!(res.status, 200);

    // Over the cap: 431 (or hyper's own refusal and a reset).
    let pad = "a".repeat(20_000);
    let outcome = try_exchange(
        conn.as_ref(),
        &request("GET", "/topology", &ch, &[("X-Pad", &pad)], b""),
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
        &raw_request("GET", "/topology", &headers, b""),
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
    let mut two = request("GET", "/topology", &ch, &[], b"");
    two.extend(claim_request(&ch, &[SURB_ID]));
    let res = exchange(conn.as_ref(), &two).await;
    assert_eq!(res.status, 200);
    assert_eq!(
        t.upstream.count(),
        1,
        "the pipelined request is never forwarded"
    );
    assert_eq!(t.upstream.last().path_and_query, "/topology");
    t.stop().await;
}
