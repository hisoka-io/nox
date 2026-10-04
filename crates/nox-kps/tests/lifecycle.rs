//! Identity persistence across restarts, graceful shutdown, and the
//! metrics/health endpoint.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{base_config, dial, exchange, request, route, MockUpstream, TestServer, Transport, T};
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identity_is_stable_across_restarts() {
    let upstream = MockUpstream::start().await;
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("state").join("kps.key");

    let first = nox_kps::start(base_config(&upstream, &key_file).validate().unwrap())
        .await
        .unwrap();
    assert!(first.identity_created());
    let certhash = first.certhash().to_string();
    let pem_before = std::fs::read(&key_file).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file is private");
    }
    let conn = dial(&first.local_address(), Transport::Quic).await;
    assert_eq!(
        exchange(
            conn.as_ref(),
            &request("GET", "/health", &certhash, &[], b"")
        )
        .await
        .status,
        200
    );
    first.shutdown();
    timeout(T, first.wait()).await.unwrap();

    let second = nox_kps::start(base_config(&upstream, &key_file).validate().unwrap())
        .await
        .unwrap();
    assert!(!second.identity_created());
    assert_eq!(second.certhash(), certhash, "certhash survives a restart");
    assert_eq!(
        std::fs::read(&key_file).unwrap(),
        pem_before,
        "key file untouched"
    );
    assert!(second.addresses()[0].ends_with(&format!(":{certhash}")));
    // A client pinning the published certhash connects to the restarted server.
    for transport in [Transport::Quic, Transport::WebRtc] {
        let conn = dial(&second.local_address(), transport).await;
        assert_eq!(
            exchange(
                conn.as_ref(),
                &request("GET", "/health", &certhash, &[], b"")
            )
            .await
            .status,
            200
        );
    }
    second.shutdown();
    timeout(T, second.wait()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_certhash_is_refused_by_the_client() {
    let t = TestServer::start(|_| {}).await;
    let other = kps::Identity::generate().unwrap();
    let wrong = format!("127.0.0.1:{}:{}", t.server.port(), other.certhash);
    let quic = timeout(Duration::from_secs(10), kps::dial(&wrong))
        .await
        .unwrap();
    assert!(quic.is_err(), "QUIC pins the certificate hash");
    // The server never answers ICE checks keyed to another certhash, so the
    // WebRTC dial cannot complete: it errors or times out.
    let webrtc = timeout(Duration::from_secs(4), kps::dial_webrtc(&wrong)).await;
    assert!(
        !matches!(webrtc, Ok(Ok(_))),
        "WebRTC pins the certificate hash"
    );
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_lets_in_flight_exchanges_finish() {
    let t = TestServer::start(|raw| {
        raw.proxy
            .forward_request_headers
            .push("x-mock-delay-ms".into());
        raw.routes.push(route("slow", "GET", "/slow", "ingress", 0));
    })
    .await;
    let ch = t.certhash();
    let conn: Arc<dyn kps::Conn> = Arc::from(dial(&t.addr(), Transport::Quic).await);
    let slow = request("GET", "/slow", &ch, &[("X-Mock-Delay-Ms", "1000")], b"");
    let in_flight = {
        let conn = Arc::clone(&conn);
        tokio::spawn(async move { exchange(conn.as_ref(), &slow).await.status })
    };
    assert!(common::eventually(T, || t.upstream.count() == 1).await);

    let health_addr = t.server.metrics_addr().unwrap();
    t.server.shutdown();
    // Health turns 503 as soon as shutdown starts.
    let probe = nox_kps::metrics::probe_health(health_addr, Duration::from_secs(2)).await;
    assert!(probe.is_err(), "health reports shutting down");

    assert_eq!(
        in_flight.await.unwrap(),
        200,
        "in-flight exchange completes"
    );
    let addr = t.addr();
    timeout(T, t.server.wait())
        .await
        .expect("server stops after draining");
    // The listener is gone: new dials fail.
    let redial = timeout(Duration::from_secs(3), kps::dial(&addr)).await;
    assert!(
        !matches!(redial, Ok(Ok(_))),
        "listener closed after shutdown"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metrics_and_health_endpoint() {
    let t = TestServer::start(|_| {}).await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let ch = t.certhash();
    exchange(
        conn.as_ref(),
        &request("POST", "/api/v1/packets", &ch, &[], &[0u8; 32_768]),
    )
    .await;
    exchange(conn.as_ref(), &request("GET", "/nope", &ch, &[], b"")).await;

    nox_kps::metrics::probe_health(t.server.metrics_addr().unwrap(), Duration::from_secs(5))
        .await
        .unwrap();
    let text = t.metrics_text().await;
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    for needle in [
        "nox_kps_requests_total{route=\"nox-packets\",status=\"202\"} 1",
        "nox_kps_requests_total{route=\"unmatched\",status=\"404\"} 1",
        "nox_kps_connections_accepted_total 1",
        "nox_kps_connections_active 1",
        "nox_kps_streams_accepted_total 2",
        "nox_kps_request_duration_seconds_count{route=\"nox-packets\"} 1",
        "nox_kps_build_info{version=",
    ] {
        assert!(text.contains(needle), "missing {needle}:\n{text}");
    }
    assert!(
        !text.contains("127.0.0.1"),
        "metrics never carry client addresses"
    );
    t.stop().await;
}
