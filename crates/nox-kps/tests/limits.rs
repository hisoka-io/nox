//! Connection, stream, time and in-flight limits.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{dial, eventually, exchange, request, route, try_exchange, TestServer, Transport, T};
use kps::ErrorCode;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

fn closed_with(conn: &dyn kps::Conn, code: ErrorCode) -> bool {
    match conn.err() {
        Some(kps::Error::Stream(se)) => se.code == code,
        _ => false,
    }
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
    let metrics_ok = {
        let mut ok = false;
        for _ in 0..80 {
            if t.metrics_text()
                .await
                .contains("nox_kps_connections_active 1")
            {
                ok = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        ok
    };
    assert!(metrics_ok, "server noticed the closed connection");
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
    let t = TestServer::start(|raw| {
        raw.limits.max_streams_per_connection = 2;
        raw.proxy
            .forward_request_headers
            .push("x-mock-delay-ms".into());
        raw.routes.push(route("slow", "GET", "/slow", "ingress", 0));
    })
    .await;
    let ch = t.certhash();
    let conn: Arc<dyn kps::Conn> = Arc::from(dial(&t.addr(), Transport::Quic).await);
    let slow = request("GET", "/slow", &ch, &[("X-Mock-Delay-Ms", "1500")], b"");
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
        &request("GET", "/health", &ch, &[], b""),
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
    assert_eq!(
        exchange(conn.as_ref(), &request("GET", "/health", &ch, &[], b""))
            .await
            .status,
        200
    );
    let metrics = t.metrics_text().await;
    assert!(
        metrics.contains("nox_kps_streams_rejected_total{reason=\"per_connection_limit\"} 1"),
        "{metrics}"
    );
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_connections_are_closed() {
    let t = TestServer::start(|raw| {
        raw.limits.connection_idle_timeout_ms = 400;
    })
    .await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    assert_eq!(
        exchange(
            conn.as_ref(),
            &request("GET", "/health", &t.certhash(), &[], b"")
        )
        .await
        .status,
        200
    );
    let started = Instant::now();
    timeout(Duration::from_secs(5), conn.closed())
        .await
        .expect("idle connection closed");
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert!(
        closed_with(conn.as_ref(), ErrorCode::Timeout),
        "close code: {:?}",
        conn.err()
    );
    let metrics = t.metrics_text().await;
    assert!(
        metrics.contains("nox_kps_connections_closed_total{reason=\"idle\"} 1"),
        "{metrics}"
    );
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn busy_connections_are_not_idle() {
    let t = TestServer::start(|raw| {
        raw.limits.connection_idle_timeout_ms = 400;
        raw.proxy
            .forward_request_headers
            .push("x-mock-delay-ms".into());
        raw.routes.push(route("slow", "GET", "/slow", "ingress", 0));
    })
    .await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    // One exchange that outlasts the idle timeout completes normally.
    let res = exchange(
        conn.as_ref(),
        &request(
            "GET",
            "/slow",
            &t.certhash(),
            &[("X-Mock-Delay-Ms", "1200")],
            b"",
        ),
    )
    .await;
    assert_eq!(res.status, 200);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_streams_are_reset_after_the_header_timeout() {
    let t = TestServer::start(|raw| {
        raw.limits.header_read_timeout_ms = 300;
        raw.proxy.upstream_timeout_ms = 1_000;
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
        raw.proxy.upstream_timeout_ms = 500;
        raw.limits.stream_timeout_ms = 1_000;
    })
    .await;
    let conn = dial(&t.addr(), Transport::Quic).await;
    let mut stream = conn.open_stream().await.unwrap();
    // A complete head promising a body that never arrives.
    let head = format!(
        "POST /api/v1/packets HTTP/1.1\r\nHost: {}\r\nContent-Length: 32768\r\n\r\n",
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
    let t = TestServer::start(|raw| {
        raw.proxy.max_inflight_upstream = 1;
        raw.proxy
            .forward_request_headers
            .push("x-mock-delay-ms".into());
        raw.routes.push(route("slow", "GET", "/slow", "ingress", 0));
    })
    .await;
    let ch = t.certhash();
    let conn: Arc<dyn kps::Conn> = Arc::from(dial(&t.addr(), Transport::Quic).await);
    let slow = request("GET", "/slow", &ch, &[("X-Mock-Delay-Ms", "1000")], b"");
    let first = {
        let conn = Arc::clone(&conn);
        tokio::spawn(async move { exchange(conn.as_ref(), &slow).await.status })
    };
    assert!(eventually(T, || t.upstream.count() == 1).await);
    let res = exchange(conn.as_ref(), &request("GET", "/health", &ch, &[], b"")).await;
    assert_eq!(res.status, 503);
    assert_eq!(res.header("retry-after"), Some("1"));
    assert_eq!(first.await.unwrap(), 200);
    assert_eq!(
        exchange(conn.as_ref(), &request("GET", "/health", &ch, &[], b""))
            .await
            .status,
        200
    );
    t.stop().await;
}
