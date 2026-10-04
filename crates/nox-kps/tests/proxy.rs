//! End-to-end proxying over real KPS connections (QUIC and WebRTC) to a mock
//! of the node's loopback services.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::IpAddr;

use common::{dial, exchange, request, TestServer, Transport};

const PACKET_SIZE: usize = 32_768;

async fn packets_round_trip(transport: Transport) {
    let t = TestServer::start(|_| {}).await;
    let conn = dial(&t.addr(), transport).await;
    let packet: Vec<u8> = (0..PACKET_SIZE).map(|i| (i % 251) as u8).collect();
    let req = request(
        "POST",
        "/api/v1/packets",
        &t.certhash(),
        &[
            ("Content-Type", "application/octet-stream"),
            ("X-Forwarded-For", "6.6.6.6"),
            ("X-Real-IP", "6.6.6.6"),
            ("Forwarded", "for=6.6.6.6"),
            ("Cookie", "session=1"),
            ("Connection", "close, x-hop"),
            ("X-Hop", "1"),
        ],
        &packet,
    );
    let res = exchange(conn.as_ref(), &req).await;
    assert_eq!(res.status, 202, "{}: {}", transport.name(), res.text());
    assert_eq!(res.text(), format!("http-{:016x}", PACKET_SIZE));
    assert_eq!(res.header("x-nox-version"), Some("test-upstream"));
    assert!(
        res.header("set-cookie").is_none(),
        "upstream-only headers are dropped"
    );
    assert!(res.header("x-internal").is_none());
    assert!(
        res.header("content-length").is_some(),
        "responses carry Content-Length"
    );

    let seen = t.upstream.last();
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.path_and_query, "/api/v1/packets");
    assert_eq!(
        seen.body.as_ref(),
        packet.as_slice(),
        "packet bytes arrive intact"
    );
    assert_eq!(seen.headers["host"], t.upstream.addr.to_string());
    assert_eq!(seen.headers["content-type"], "application/octet-stream");
    let forwarded: Vec<_> = seen.headers.get_all("x-forwarded-for").iter().collect();
    assert_eq!(forwarded.len(), 1, "exactly one client IP value");
    let ip: IpAddr = forwarded[0].to_str().unwrap().parse().unwrap();
    assert_ne!(
        ip.to_string(),
        "6.6.6.6",
        "client-supplied value is replaced"
    );
    if transport == Transport::Quic {
        assert_eq!(
            ip.to_string(),
            "127.0.0.1",
            "QUIC source address of a loopback dial"
        );
    }
    for absent in ["x-real-ip", "forwarded", "cookie", "x-hop", "connection"] {
        assert!(
            seen.headers.get(absent).is_none(),
            "{absent} must not reach the node"
        );
    }
    conn.close().await.unwrap();
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn packets_are_proxied_over_quic() {
    packets_round_trip(Transport::Quic).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn packets_are_proxied_over_webrtc() {
    packets_round_trip(Transport::WebRtc).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_topology_and_health_are_proxied() {
    let t = TestServer::start(|_| {}).await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let ch = t.certhash();

    let claim = br#"{"surb_ids":["00112233445566778899aabbccddeeff"]}"#;
    let res = exchange(
        conn.as_ref(),
        &request(
            "POST",
            "/api/v1/responses/claim",
            &ch,
            &[("Content-Type", "application/json")],
            claim,
        ),
    )
    .await;
    assert_eq!(res.status, 200, "{}", res.text());
    assert_eq!(res.header("content-type"), Some("application/json"));
    let items: serde_json::Value = serde_json::from_slice(&res.body).unwrap();
    assert_eq!(items[0]["id"], "00112233445566778899aabbccddeeff");
    assert_eq!(
        t.upstream.last().headers["content-type"],
        "application/json"
    );

    let res = exchange(
        conn.as_ref(),
        &request(
            "POST",
            "/api/v1/responses/claim",
            &ch,
            &[("Content-Type", "application/json")],
            br#"{"surb_ids":[]}"#,
        ),
    )
    .await;
    assert_eq!(res.status, 204);
    assert!(res.body.is_empty());

    let res = exchange(conn.as_ref(), &request("GET", "/topology", &ch, &[], b"")).await;
    assert_eq!(res.status, 200);
    let topo: serde_json::Value = serde_json::from_slice(&res.body).unwrap();
    assert_eq!(topo["fingerprint"], "0x00");

    let res = exchange(conn.as_ref(), &request("GET", "/health", &ch, &[], b"")).await;
    assert_eq!(res.status, 200);
    assert_eq!(res.text(), "ok");

    // Query strings ride along to the allowlisted path.
    let res = exchange(
        conn.as_ref(),
        &request("GET", "/topology?fresh=1", &ch, &[], b""),
    )
    .await;
    assert_eq!(res.status, 200);
    assert_eq!(t.upstream.last().path_and_query, "/topology?fresh=1");

    // Many exchanges share one connection, one stream each.
    for _ in 0..20 {
        let res = exchange(conn.as_ref(), &request("GET", "/health", &ch, &[], b"")).await;
        assert_eq!(res.status, 200);
    }
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_streams_on_one_connection() {
    let t = TestServer::start(|_| {}).await;
    let conn: std::sync::Arc<dyn kps::Conn> =
        std::sync::Arc::from(dial(&t.addr(), Transport::Quic).await);
    let ch = t.certhash();
    let mut tasks = Vec::new();
    for i in 0..32u32 {
        let conn = std::sync::Arc::clone(&conn);
        let packet = vec![(i % 256) as u8; PACKET_SIZE];
        let req = request(
            "POST",
            "/api/v1/packets",
            &ch,
            &[("Content-Type", "application/octet-stream")],
            &packet,
        );
        tasks.push(tokio::spawn(async move {
            exchange(conn.as_ref(), &req).await.status
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap(), 202);
    }
    assert_eq!(t.upstream.count(), 32);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metadata_describes_the_endpoint() {
    let t = TestServer::start(|_| {}).await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let res = exchange(
        conn.as_ref(),
        &request("GET", "/metadata.json", &t.certhash(), &[], b""),
    )
    .await;
    assert_eq!(res.status, 200);
    assert_eq!(res.header("content-type"), Some("application/json"));
    let doc: serde_json::Value = serde_json::from_slice(&res.body).unwrap();
    assert_eq!(doc["protocol"], "kps-http/1");
    assert_eq!(doc["software"], "nox-kps");
    assert_eq!(doc["addresses"][0], t.server.addresses()[0]);
    assert!(doc["addresses"][0]
        .as_str()
        .unwrap()
        .ends_with(&t.certhash()));
    let caps = doc["capabilities"].as_array().unwrap();
    assert!(caps.iter().any(|c| c == "nox-packets"));
    assert!(
        !caps.iter().any(|c| c == "worker-bundles"),
        "bundles are off in this config"
    );
    assert_eq!(t.upstream.count(), 0, "served locally, never proxied");
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_failures_map_to_gateway_errors() {
    // A port with nothing listening.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);

    let t = TestServer::start(|raw| {
        raw.upstreams.topology = dead.clone();
        raw.proxy.upstream_timeout_ms = 500;
        raw.proxy.max_response_body_bytes = 1024;
        raw.proxy
            .forward_request_headers
            .push("x-mock-delay-ms".into());
        raw.proxy
            .forward_request_headers
            .push("x-mock-response-bytes".into());
        raw.routes
            .push(common::route("slow", "GET", "/slow", "ingress", 0));
        raw.routes
            .push(common::route("big", "GET", "/big", "ingress", 0));
    })
    .await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let ch = t.certhash();

    let res = exchange(conn.as_ref(), &request("GET", "/topology", &ch, &[], b"")).await;
    assert_eq!(res.status, 502, "{}", res.text());

    let res = exchange(
        conn.as_ref(),
        &request("GET", "/slow", &ch, &[("X-Mock-Delay-Ms", "2000")], b""),
    )
    .await;
    assert_eq!(res.status, 504, "{}", res.text());

    let res = exchange(
        conn.as_ref(),
        &request(
            "GET",
            "/big",
            &ch,
            &[("X-Mock-Response-Bytes", "4096")],
            b"",
        ),
    )
    .await;
    assert_eq!(res.status, 502, "{}", res.text());
    assert!(res.text().contains("exceeds"));

    let res = exchange(
        conn.as_ref(),
        &request(
            "GET",
            "/big",
            &ch,
            &[("X-Mock-Response-Bytes", "1000")],
            b"",
        ),
    )
    .await;
    assert_eq!(res.status, 200);
    assert_eq!(res.body.len(), 1000);

    let metrics = t.metrics_text().await;
    assert!(
        metrics.contains("nox_kps_upstream_errors_total{upstream=\"topology\",kind=\"connect\"} 1"),
        "{metrics}"
    );
    assert!(metrics.contains("kind=\"timeout\""));
    assert!(metrics.contains("kind=\"response_too_large\""));
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_status_codes_pass_through() {
    let t = TestServer::start(|_| {}).await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    // The mock answers 202 for packets of any size; a real node answers 400
    // for a wrong size, and that status would pass through the same way.
    let res = exchange(
        conn.as_ref(),
        &request(
            "POST",
            "/api/v1/packets",
            &t.certhash(),
            &[("Content-Type", "application/octet-stream")],
            b"short",
        ),
    )
    .await;
    assert_eq!(res.status, 202);
    assert_eq!(t.upstream.last().body.as_ref(), b"short");
    t.stop().await;
}
