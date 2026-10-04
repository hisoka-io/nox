//! Identity persistence across restarts, graceful shutdown, and the admin
//! endpoint.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{
    admin_get, base_config, claim_request, dial, exchange, packet_request, request, MockUpstream,
    TestServer, Transport, SURB_ID, T,
};
use nox_kps::error::{IdentityError, StartError};
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identity_is_stable_across_restarts() {
    let upstream = MockUpstream::start().await;
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("state").join("kps.key");

    // run never creates a key.
    let refused = nox_kps::start(base_config(&upstream, &key_file).validate().unwrap()).await;
    assert!(
        matches!(
            refused,
            Err(StartError::Identity(IdentityError::Missing { .. }))
        ),
        "{refused:?}"
    );
    assert!(!key_file.exists());

    let created = nox_kps::identity::init(&key_file).unwrap();
    let certhash = created.certhash.clone();
    // run serves only the confirmed identity.
    let mut unconfirmed = base_config(&upstream, &key_file);
    unconfirmed.expected_certhash = String::new();
    let refused = nox_kps::start(unconfirmed.validate().unwrap()).await;
    assert!(
        matches!(
            refused,
            Err(StartError::Identity(
                IdentityError::ExpectedCerthashMissing { .. }
            ))
        ),
        "{refused:?}"
    );
    let mut wrong = base_config(&upstream, &key_file);
    wrong.expected_certhash = kps::Identity::generate().unwrap().certhash;
    let refused = nox_kps::start(wrong.validate().unwrap()).await;
    assert!(
        matches!(
            refused,
            Err(StartError::Identity(IdentityError::CerthashMismatch { .. }))
        ),
        "{refused:?}"
    );
    let pem_before = std::fs::read(&key_file).unwrap();
    for round in 0..3 {
        let server = nox_kps::start(base_config(&upstream, &key_file).validate().unwrap())
            .await
            .unwrap();
        assert_eq!(
            server.certhash(),
            certhash,
            "certhash survives restart {round}"
        );
        assert!(server.addresses()[0].ends_with(&format!(":{certhash}")));
        // A client pinning the published certhash connects to every restart.
        for transport in [Transport::Quic, Transport::WebRtc] {
            let conn = dial(&server.local_address(), transport).await;
            let res = exchange(
                conn.as_ref(),
                &request("GET", "/health", &certhash, &[], b""),
            )
            .await;
            assert_eq!(res.status, 200);
        }
        server.shutdown();
        timeout(T, server.wait()).await.unwrap();
    }
    assert_eq!(
        std::fs::read(&key_file).unwrap(),
        pem_before,
        "key file untouched"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_readable_by_others_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let upstream = MockUpstream::start().await;
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("kps.key");
    nox_kps::identity::init(&key_file).unwrap();
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o640)).unwrap();
    let refused = nox_kps::start(base_config(&upstream, &key_file).validate().unwrap()).await;
    assert!(
        matches!(
            refused,
            Err(StartError::Identity(IdentityError::Permissions { .. }))
        ),
        "{refused:?}"
    );
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
    // Two parallel connections from one client both serve exchanges.
    let a = dial(&t.addr(), Transport::Quic).await;
    let b = dial(&t.addr(), Transport::WebRtc).await;
    let req = request("GET", "/topology", &t.certhash(), &[], b"");
    let (ra, rb) = tokio::join!(exchange(a.as_ref(), &req), exchange(b.as_ref(), &req));
    assert_eq!((ra.status, rb.status), (200, 200));
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_lets_in_flight_exchanges_finish() {
    let t = TestServer::start(|_| {}).await;
    t.upstream.set_delay("/api/v1/responses/claim", 1_000);
    let ch = t.certhash();
    let conn: Arc<dyn kps::Conn> = Arc::from(dial(&t.addr(), Transport::Quic).await);
    let slow = claim_request(&ch, &[SURB_ID]);
    let in_flight = {
        let conn = Arc::clone(&conn);
        tokio::spawn(async move { exchange(conn.as_ref(), &slow).await.status })
    };
    assert!(common::eventually(T, || t.upstream.count() == 1).await);

    let admin = t.server.admin_addr();
    t.server.shutdown();
    // healthz turns 503 as soon as shutdown starts.
    let probe = nox_kps::metrics::probe_health(admin, Duration::from_secs(2)).await;
    assert!(probe.is_err(), "healthz reports shutting down");

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
async fn admin_endpoint_serves_metrics_and_healthz() {
    let t = TestServer::start(|_| {}).await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let ch = t.certhash();
    exchange(conn.as_ref(), &packet_request(&ch, &common::packet(3))).await;
    exchange(conn.as_ref(), &request("GET", "/nope", &ch, &[], b"")).await;

    nox_kps::metrics::probe_health(t.server.admin_addr(), Duration::from_secs(5))
        .await
        .unwrap();
    let healthz = admin_get(t.server.admin_addr(), "/healthz").await;
    assert!(healthz.starts_with("HTTP/1.1 200"), "{healthz}");
    assert!(
        healthz.contains(&format!("\"certhash\":\"{ch}\"")),
        "{healthz}"
    );

    let text = t.metrics_text().await;
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    for needle in [
        "nox_kps_streams_total{route=\"packets\",status=\"202\"} 1",
        "nox_kps_streams_total{route=\"unmatched\",status=\"404\"} 1",
        "nox_kps_connections_accepted_total 1",
        "nox_kps_connections_active 1",
        "nox_kps_request_duration_seconds_count{route=\"packets\"} 1",
        "nox_kps_bytes_total{route=\"packets\",direction=\"in\"} 32768",
        "nox_kps_build_info{version=",
    ] {
        assert!(text.contains(needle), "missing {needle}:\n{text}");
    }
    let body = text.split("\r\n\r\n").nth(1).unwrap_or_default();
    assert!(
        !body.contains("127.0.0.1"),
        "metrics never carry client addresses"
    );
    assert!(admin_get(t.server.admin_addr(), "/other")
        .await
        .starts_with("HTTP/1.1 404"));
    t.stop().await;
}
