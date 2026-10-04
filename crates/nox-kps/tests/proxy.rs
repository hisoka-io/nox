//! End-to-end proxying over real KPS connections (QUIC and WebRTC) to a mock
//! of the node's loopback services.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

mod common;

use std::net::IpAddr;
use std::time::{Duration, Instant};

use common::{
    claim_request, dial, exchange, packet, packet_request, request, TestServer, Transport, SURB_ID,
};
use nox_kps::config::{max_claim_response_bytes, LimitsConfig, MAX_REPLY_PAYLOAD_BYTES};

async fn packets_round_trip(transport: Transport) {
    let t = TestServer::start(|_| {}).await;
    let conn = dial(&t.addr(), transport).await;
    let body: Vec<u8> = (0..32_768).map(|i| (i % 251) as u8).collect();
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
            ("Accept", "*/*"),
        ],
        &body,
    );
    let res = exchange(conn.as_ref(), &req).await;
    assert_eq!(res.status, 202, "{}: {}", transport.name(), res.text());
    assert_eq!(res.text(), format!("http-{:016x}", 32_768));
    for absent in ["set-cookie", "x-internal", "x-nox-version"] {
        assert!(res.header(absent).is_none(), "{absent} is not relayed");
    }
    assert_eq!(
        res.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    assert!(
        res.header("content-length").is_some(),
        "responses carry Content-Length"
    );

    let seen = t.upstream.last();
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.path_and_query, "/api/v1/packets");
    assert_eq!(
        seen.body.as_ref(),
        body.as_slice(),
        "packet bytes arrive intact"
    );
    let mut names: Vec<&str> = seen.headers.keys().map(http::HeaderName::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["content-length", "content-type", "host", "x-real-ip"],
        "only these headers reach the node"
    );
    assert_eq!(seen.headers["host"], t.upstream.authority());
    assert_eq!(seen.headers["content-type"], "application/octet-stream");
    assert_eq!(seen.headers["content-length"], "32768");
    let real: Vec<_> = seen.headers.get_all("x-real-ip").iter().collect();
    assert_eq!(real.len(), 1, "exactly one client IP value");
    let ip: IpAddr = real[0].to_str().unwrap().parse().unwrap();
    assert_ne!(
        ip.to_string(),
        "6.6.6.6",
        "client-supplied value is replaced"
    );
    if transport == Transport::Quic {
        // QUIC: the UDP source of a loopback dial. WebRTC: the ICE candidate
        // the client nominated, which may be any local interface address.
        assert!(
            ip.is_loopback(),
            "the KPS source address of a loopback dial: {ip}"
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
async fn claim_topology_and_health() {
    let t = TestServer::start(|_| {}).await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let ch = t.certhash();

    let res = exchange(conn.as_ref(), &claim_request(&ch, &[SURB_ID])).await;
    assert_eq!(res.status, 200, "{}", res.text());
    assert_eq!(res.header("content-type"), Some("application/json"));
    let items: serde_json::Value = serde_json::from_slice(&res.body).unwrap();
    assert_eq!(items[0]["id"], SURB_ID);
    let seen = t.upstream.last();
    assert_eq!(seen.path_and_query, "/api/v1/responses/claim");
    assert_eq!(seen.headers["content-type"], "application/json");
    assert!(seen.headers.get("x-real-ip").is_some());

    // The SDK's content type may carry parameters.
    let body = format!(r#"{{"surb_ids":["{SURB_ID}"]}}"#);
    let res = exchange(
        conn.as_ref(),
        &request(
            "POST",
            "/api/v1/responses/claim",
            &ch,
            &[("Content-Type", "application/json; charset=utf-8")],
            body.as_bytes(),
        ),
    )
    .await;
    assert_eq!(res.status, 200);

    let res = exchange(conn.as_ref(), &claim_request(&ch, &[])).await;
    assert_eq!(res.status, 204);
    assert!(res.body.is_empty());
    assert!(
        res.header("content-length").is_none(),
        "204 carries no Content-Length"
    );

    let res = exchange(conn.as_ref(), &request("GET", "/topology", &ch, &[], b"")).await;
    assert_eq!(res.status, 200);
    let topo: serde_json::Value = serde_json::from_slice(&res.body).unwrap();
    assert_eq!(topo["fingerprint"], "0x00");
    assert!(
        t.upstream.last().headers.get("x-real-ip").is_none(),
        "shared fetches carry no client IP"
    );

    // Query strings never reach the node.
    let res = exchange(
        conn.as_ref(),
        &request("GET", "/topology?fresh=1", &ch, &[], b""),
    )
    .await;
    assert_eq!(res.status, 200);
    assert_eq!(t.upstream.last().path_and_query, "/topology");

    // /health is answered by nox-kps after probing the node's /health.
    let res = exchange(conn.as_ref(), &request("GET", "/health", &ch, &[], b"")).await;
    assert_eq!(res.status, 200);
    assert_eq!(res.text(), r#"{"status":"ok"}"#);
    assert_eq!(res.header("content-type"), Some("application/json"));
    assert_eq!(t.upstream.last().path_and_query, "/health");

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
    for i in 0..32u8 {
        let conn = std::sync::Arc::clone(&conn);
        let req = packet_request(&ch, &packet(i));
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
    let t = TestServer::start(|raw| {
        raw.node_address = "0x862D6B1105bdE9d64dC5182fe3CD9d09F6F37463".into();
    })
    .await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let res = exchange(
        conn.as_ref(),
        &request("GET", "/metadata.json", &t.certhash(), &[], b""),
    )
    .await;
    assert_eq!(res.status, 200);
    assert_eq!(res.header("content-type"), Some("application/json"));
    let doc: serde_json::Value = serde_json::from_slice(&res.body).unwrap();
    assert_eq!(doc["protocol"], "nox-kps-http/1");
    assert_eq!(doc["software"], "nox-kps");
    assert_eq!(doc["node"], "0x862d6b1105bde9d64dc5182fe3cd9d09f6f37463");
    assert_eq!(doc["addresses"][0], t.server.addresses()[0]);
    assert!(doc["addresses"][0]
        .as_str()
        .unwrap()
        .ends_with(&t.certhash()));
    assert_eq!(doc["limits"]["packetBytes"], 32_768);
    assert_eq!(doc["demo"], false);
    let caps: Vec<&str> = doc["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    assert_eq!(caps, ["metadata", "health", "packets", "claim", "topology"]);
    assert_eq!(t.upstream.count(), 0, "served locally, never proxied");
    t.stop().await;
}

/// A claim at the configured ID limit, every ID matching a full-size reply,
/// is relayed whole: the node has already deleted those replies, so a `502`
/// here would lose them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_claim_at_the_id_limit_is_relayed() {
    let t = TestServer::start(|_| {}).await;
    let limits = LimitsConfig::default();
    let max_ids = limits.claim_max_surb_ids;
    let cap = limits.claim_response_max_bytes;
    assert_eq!(
        (max_ids, cap),
        (128, 16 * 1024 * 1024),
        "the shipped defaults"
    );
    t.upstream.behaviour.lock().unwrap().full_size_claims = true;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let ch = t.certhash();

    let ids: Vec<String> = (0..max_ids).map(|i| format!("{i:032x}")).collect();
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    let res = exchange(conn.as_ref(), &claim_request(&ch, &refs)).await;
    assert_eq!(res.status, 200, "{}", res.text());
    assert!(res.body.len() <= max_claim_response_bytes(max_ids));
    assert!(res.body.len() <= cap);
    let items: Vec<serde_json::Value> = serde_json::from_slice(&res.body).unwrap();
    assert_eq!(items.len(), max_ids);
    assert_eq!(items[0]["id"], format!("reply-0-{}", ids[0]));
    assert_eq!(
        items[max_ids - 1]["data"].as_array().unwrap().len(),
        MAX_REPLY_PAYLOAD_BYTES
    );

    // One more ID is refused before the node sees it.
    let seen = t.upstream.count();
    let extra = format!("{max_ids:032x}");
    let mut over = refs.clone();
    over.push(&extra);
    let res = exchange(conn.as_ref(), &claim_request(&ch, &over)).await;
    assert_eq!(res.status, 400, "{}", res.text());
    assert!(
        res.text().contains("at most 128 SURB IDs"),
        "{}",
        res.text()
    );
    assert_eq!(t.upstream.count(), seen, "never reaches the node");

    let res = exchange(
        conn.as_ref(),
        &request("GET", "/metadata.json", &ch, &[], b""),
    )
    .await;
    let doc: serde_json::Value = serde_json::from_slice(&res.body).unwrap();
    assert_eq!(doc["limits"]["claimMaxSurbIds"], 128);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_failures_map_to_gateway_errors() {
    // A port with nothing listening.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = closed.local_addr().unwrap().to_string();
    drop(closed);

    let t = TestServer::start(|raw| {
        raw.upstream_topology = dead.clone();
        raw.limits.upstream_claim_timeout_ms = 500;
        raw.limits.claim_max_surb_ids = 1;
        raw.limits.claim_response_max_bytes = max_claim_response_bytes(1);
    })
    .await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let ch = t.certhash();

    let started = Instant::now();
    let res = exchange(conn.as_ref(), &request("GET", "/topology", &ch, &[], b"")).await;
    assert_eq!(res.status, 502, "{}", res.text());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "fails within the connect timeout"
    );

    t.upstream.set_delay("/api/v1/responses/claim", 2_000);
    let res = exchange(conn.as_ref(), &claim_request(&ch, &[SURB_ID])).await;
    assert_eq!(res.status, 504, "{}", res.text());
    t.upstream.set_delay("/api/v1/responses/claim", 0);

    t.upstream
        .set_body_bytes("/api/v1/responses/claim", max_claim_response_bytes(1) + 1);
    let res = exchange(conn.as_ref(), &claim_request(&ch, &[SURB_ID])).await;
    assert_eq!(res.status, 502, "{}", res.text());
    assert!(res.text().contains("exceeds"));

    t.upstream.set_body_bytes("/api/v1/responses/claim", 1000);
    let res = exchange(conn.as_ref(), &claim_request(&ch, &[SURB_ID])).await;
    assert_eq!(res.status, 200);
    assert_eq!(res.body.len(), 1000);

    // The node's health check failing turns /health into 503 degraded.
    t.upstream.set_status("/health", 500);
    let res = exchange(conn.as_ref(), &request("GET", "/health", &ch, &[], b"")).await;
    assert_eq!(res.status, 503);
    assert_eq!(
        res.text(),
        r#"{"status":"degraded","upstream":"ingress-unreachable"}"#
    );

    let metrics = t.metrics_text().await;
    for needle in [
        "nox_kps_upstream_errors_total{route=\"topology\",kind=\"connect\"} 1",
        "nox_kps_upstream_errors_total{route=\"claim\",kind=\"timeout\"} 1",
        "nox_kps_upstream_errors_total{route=\"claim\",kind=\"response_too_large\"} 1",
    ] {
        assert!(metrics.contains(needle), "missing {needle}:\n{metrics}");
    }
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_status_codes_pass_through() {
    let t = TestServer::start(|_| {}).await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    // The node answers 400 for a packet it cannot use, 429 when it limits.
    t.upstream.set_status("/api/v1/packets", 400);
    let res = exchange(conn.as_ref(), &packet_request(&t.certhash(), &packet(1))).await;
    assert_eq!(res.status, 400);
    t.upstream.set_status("/api/v1/packets", 429);
    let res = exchange(conn.as_ref(), &packet_request(&t.certhash(), &packet(1))).await;
    assert_eq!(res.status, 429);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn topology_and_health_are_shared_across_clients() {
    let t = TestServer::start(|raw| {
        raw.limits.topology_cache_ms = 60_000;
        raw.limits.health_cache_ms = 60_000;
    })
    .await;
    let ch = t.certhash();
    for transport in [Transport::Quic, Transport::WebRtc] {
        let conn = dial(&t.addr(), transport).await;
        for _ in 0..3 {
            let res = exchange(conn.as_ref(), &request("GET", "/topology", &ch, &[], b"")).await;
            assert_eq!(res.status, 200);
            assert_eq!(res.header("content-type"), Some("application/json"));
            let res = exchange(conn.as_ref(), &request("GET", "/health", &ch, &[], b"")).await;
            assert_eq!(res.status, 200);
        }
    }
    assert_eq!(
        t.upstream.count_path("/topology"),
        1,
        "one fetch serves every client"
    );
    assert_eq!(t.upstream.count_path("/health"), 1);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_ip_rate_limits_answer_429() {
    let t = TestServer::start(|raw| {
        raw.limits.packet_rate_per_ip = 1;
        raw.limits.packet_burst = 3;
        raw.limits.topology_rate_per_ip = 1;
        raw.limits.topology_burst = 1;
    })
    .await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let ch = t.certhash();
    let mut statuses = Vec::new();
    for i in 0..5u8 {
        let res = exchange(conn.as_ref(), &packet_request(&ch, &packet(i))).await;
        if res.status == 429 {
            assert_eq!(res.header("retry-after"), Some("1"));
        }
        statuses.push(res.status);
    }
    assert_eq!(statuses, [202, 202, 202, 429, 429]);
    assert_eq!(
        t.upstream.count_path("/api/v1/packets"),
        3,
        "limited requests never reach the node"
    );
    // Route classes have separate buckets; health is not rate limited.
    assert_eq!(
        exchange(conn.as_ref(), &request("GET", "/topology", &ch, &[], b""))
            .await
            .status,
        200
    );
    assert_eq!(
        exchange(conn.as_ref(), &request("GET", "/topology", &ch, &[], b""))
            .await
            .status,
        429
    );
    for _ in 0..5 {
        assert_eq!(
            exchange(conn.as_ref(), &request("GET", "/health", &ch, &[], b""))
                .await
                .status,
            200
        );
    }
    // The bucket refills at the configured rate.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert_eq!(
        exchange(conn.as_ref(), &packet_request(&ch, &packet(9)))
            .await
            .status,
        202
    );
    let metrics = t.metrics_text().await;
    assert!(
        metrics.contains("nox_kps_rate_limited_total{route=\"packets\"} 2"),
        "{metrics}"
    );
    assert!(
        metrics.contains("nox_kps_rate_limited_total{route=\"topology\"} 1"),
        "{metrics}"
    );
    t.stop().await;
}
