//! Connection, stream, time and in-flight limits.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{
    claim_request, dial, eventually, exchange, request, try_exchange, TestServer, Transport,
    SURB_ID, T,
};
use kps::ErrorCode;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

const CLAIM: &str = "/api/v1/responses/claim";

fn closed_with(conn: &dyn kps::Conn, code: ErrorCode) -> bool {
    match conn.err() {
        Some(kps::Error::Stream(se)) => se.code == code,
        _ => false,
    }
}

async fn wait_for_metric(t: &TestServer, needle: &str) -> bool {
    for _ in 0..80 {
        if t.metrics_text().await.contains(needle) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_ip_connection_cap() {
    let t = TestServer::start(|raw| {
        raw.limits.max_connections = 10;
        raw.limits.max_connections_per_ip = 2;
    })
    .await;
    let ch = t.certhash();
    let health = request("GET", "/health", &ch, &[], b"");
    // QUIC only: a local WebRTC dial may nominate a non-loopback interface
    // address, which is a different client bucket.
    let a = dial(&t.addr(), Transport::Quic).await;
    assert_eq!(exchange(a.as_ref(), &health).await.status, 200);
    let b = dial(&t.addr(), Transport::Quic).await;
    assert_eq!(exchange(b.as_ref(), &health).await.status, 200);

    // The third connection completes the handshake, then is closed with
    // queue-full before any stream is served.
    let c = dial(&t.addr(), Transport::Quic).await;
    timeout(T, c.closed())
        .await
        .expect("refused connection is closed");
    assert!(
        closed_with(c.as_ref(), ErrorCode::QueueFull),
        "close code: {:?}",
        c.err()
    );
    assert!(try_exchange(c.as_ref(), &health, Duration::from_secs(2))
        .await
        .is_err());

    // Closing one admitted connection frees its slot.
    a.close().await.unwrap();
    assert!(
        wait_for_metric(&t, "nox_kps_connections_active 1").await,
        "server noticed the close"
    );
    let d = dial(&t.addr(), Transport::Quic).await;
    assert_eq!(exchange(d.as_ref(), &health).await.status, 200);

    let metrics = t.metrics_text().await;
    assert!(
        metrics.contains("nox_kps_connections_rejected_total{reason=\"per_ip_limit\"} 1"),
        "{metrics}"
    );
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn global_connection_cap() {
    let t = TestServer::start(|raw| {
        raw.limits.max_connections = 2;
        raw.limits.max_connections_per_ip = 2;
    })
    .await;
    let health = request("GET", "/health", &t.certhash(), &[], b"");
    let a = dial(&t.addr(), Transport::Quic).await;
    assert_eq!(exchange(a.as_ref(), &health).await.status, 200);
    let b = dial(&t.addr(), Transport::WebRtc).await;
    assert_eq!(exchange(b.as_ref(), &health).await.status, 200);
    let c = dial(&t.addr(), Transport::Quic).await;
    timeout(T, c.closed())
        .await
        .expect("refused connection is closed");
    assert!(
        closed_with(c.as_ref(), ErrorCode::QueueFull),
        "close code: {:?}",
        c.err()
    );
    let metrics = t.metrics_text().await;
    assert!(
        metrics.contains("nox_kps_connections_rejected_total{reason=\"global_limit\"} 1"),
        "{metrics}"
    );
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_connection_stream_cap() {
    let t = TestServer::start(|raw| raw.limits.max_streams_per_connection = 2).await;
    let ch = t.certhash();
    t.upstream.set_delay(CLAIM, 1_500);
    let conn: Arc<dyn kps::Conn> = Arc::from(dial(&t.addr(), Transport::Quic).await);
    let slow = claim_request(&ch, &[SURB_ID]);
    let mut held = Vec::new();
    for _ in 0..2 {
        let conn = Arc::clone(&conn);
        let slow = slow.clone();
        held.push(tokio::spawn(async move {
            exchange(conn.as_ref(), &slow).await.status
        }));
    }
    // Both slow exchanges are upstream (and hold their slots) before the third.
    assert!(eventually(T, || t.upstream.count() == 2).await);
    let started = Instant::now();
    let third = try_exchange(
        conn.as_ref(),
        &request("GET", "/topology", &ch, &[], b""),
        Duration::from_secs(5),
    )
    .await;
    assert!(
        third.is_err(),
        "third concurrent stream is reset: {third:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "reset is immediate"
    );
    for h in held {
        assert_eq!(h.await.unwrap(), 200);
    }
    // Slots are free again.
    let res = exchange(conn.as_ref(), &request("GET", "/topology", &ch, &[], b"")).await;
    assert_eq!(res.status, 200);
    let metrics = t.metrics_text().await;
    assert!(
        metrics.contains("nox_kps_streams_rejected_total{reason=\"per_connection_limit\"} 1"),
        "{metrics}"
    );
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_connections_are_closed() {
    let t = TestServer::start(|raw| raw.limits.conn_idle_timeout_secs = 1).await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let res = exchange(
        conn.as_ref(),
        &request("GET", "/topology", &t.certhash(), &[], b""),
    )
    .await;
    assert_eq!(res.status, 200);
    let started = Instant::now();
    timeout(Duration::from_secs(5), conn.closed())
        .await
        .expect("idle connection closed");
    let idle = started.elapsed();
    assert!(
        idle >= Duration::from_millis(800) && idle < Duration::from_millis(3_000),
        "closed after {idle:?}"
    );
    assert!(
        closed_with(conn.as_ref(), ErrorCode::Timeout),
        "close code: {:?}",
        conn.err()
    );
    assert!(wait_for_metric(&t, "nox_kps_connections_closed_total{reason=\"idle\"} 1").await);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn busy_connections_are_not_idle() {
    let t = TestServer::start(|raw| raw.limits.conn_idle_timeout_secs = 1).await;
    t.upstream.set_delay(CLAIM, 1_800);
    let conn = dial(&t.addr(), Transport::Quic).await;
    // One exchange that outlasts the idle timeout completes normally.
    let res = exchange(conn.as_ref(), &claim_request(&t.certhash(), &[SURB_ID])).await;
    assert_eq!(res.status, 200);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connections_end_at_their_maximum_lifetime() {
    let t = TestServer::start(|raw| {
        raw.limits.conn_idle_timeout_secs = 1;
        raw.limits.conn_max_lifetime_secs = 2;
    })
    .await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let started = Instant::now();
    let health = request("GET", "/health", &t.certhash(), &[], b"");
    // Keep the connection busy so only the lifetime can end it.
    while started.elapsed() < Duration::from_secs(5) {
        if try_exchange(conn.as_ref(), &health, Duration::from_secs(2))
            .await
            .is_err()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    timeout(Duration::from_secs(5), conn.closed())
        .await
        .expect("connection closed");
    let lived = started.elapsed();
    assert!(
        lived >= Duration::from_millis(1_800) && lived < Duration::from_millis(4_000),
        "closed after {lived:?}"
    );
    assert!(
        wait_for_metric(
            &t,
            "nox_kps_connections_closed_total{reason=\"lifetime\"} 1"
        )
        .await
    );
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_streams_are_reset_after_the_header_timeout() {
    let t = TestServer::start(|raw| {
        raw.limits.header_read_timeout_ms = 300;
        raw.limits.upstream_packet_timeout_ms = 1_000;
        raw.limits.upstream_claim_timeout_ms = 1_000;
        raw.limits.upstream_topology_timeout_ms = 1_000;
        raw.limits.stream_timeout_ms = 2_000;
    })
    .await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let mut stream = conn.open_stream().await.unwrap();
    // QUIC announces a stream with its first byte: send a partial head.
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"GET /hea")
        .await
        .unwrap();
    let started = Instant::now();
    let mut buf = Vec::new();
    let read = timeout(Duration::from_secs(5), stream.read_to_end(&mut buf))
        .await
        .expect("server acts");
    assert!(
        read.is_err() || buf.is_empty() || buf.starts_with(b"HTTP/1.1 408"),
        "stream is abandoned: {read:?} {buf:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(t.upstream.count(), 0);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_timeout_resets_slow_clients() {
    let t = TestServer::start(|raw| {
        raw.limits.header_read_timeout_ms = 500;
        raw.limits.upstream_packet_timeout_ms = 500;
        raw.limits.upstream_claim_timeout_ms = 500;
        raw.limits.upstream_topology_timeout_ms = 500;
        raw.limits.upstream_health_timeout_ms = 500;
        raw.limits.stream_timeout_ms = 1_000;
    })
    .await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let mut stream = conn.open_stream().await.unwrap();
    // A complete head promising a body that never arrives.
    let head = format!(
        "POST /api/v1/packets HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: 32768\r\n\r\n",
        t.certhash()
    );
    tokio::io::AsyncWriteExt::write_all(&mut stream, head.as_bytes())
        .await
        .unwrap();
    let started = Instant::now();
    let mut buf = Vec::new();
    let read = timeout(Duration::from_secs(5), stream.read_to_end(&mut buf))
        .await
        .expect("server acts");
    assert!(read.is_err(), "stream is reset, not answered: {read:?}");
    assert!(
        started.elapsed() >= Duration::from_millis(800)
            && started.elapsed() < Duration::from_secs(3)
    );
    assert_eq!(t.upstream.count(), 0);
    let metrics = t.metrics_text().await;
    assert!(
        metrics.contains("nox_kps_stream_failures_total{reason=\"stream_timeout\"} 1"),
        "{metrics}"
    );
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inflight_upstream_cap_answers_503() {
    let t = TestServer::start(|raw| raw.limits.max_inflight_upstream = 1).await;
    t.upstream.set_delay(CLAIM, 1_000);
    let ch = t.certhash();
    let conn: Arc<dyn kps::Conn> = Arc::from(dial(&t.addr(), Transport::Quic).await);
    let slow = claim_request(&ch, &[SURB_ID]);
    let first = {
        let conn = Arc::clone(&conn);
        tokio::spawn(async move { exchange(conn.as_ref(), &slow).await.status })
    };
    assert!(eventually(T, || t.upstream.count() == 1).await);
    let res = exchange(conn.as_ref(), &request("GET", "/topology", &ch, &[], b"")).await;
    assert_eq!(res.status, 503);
    assert_eq!(res.header("retry-after"), Some("1"));
    assert_eq!(first.await.unwrap(), 200);
    let res = exchange(conn.as_ref(), &request("GET", "/topology", &ch, &[], b"")).await;
    assert_eq!(res.status, 200);
    t.stop().await;
}
