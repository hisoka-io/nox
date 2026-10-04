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

/// Opens a stream whose request promises a body that never arrives, and waits
/// for the server to reset it at `stream_timeout_ms`.
async fn stalled_stream(conn: &dyn kps::Conn, certhash: &str) {
    let mut stream = conn.open_stream().await.unwrap();
    let head = format!(
        "POST /api/v1/packets HTTP/1.1\r\nHost: {certhash}\r\nContent-Type: application/octet-stream\r\nContent-Length: 32768\r\n\r\n"
    );
    tokio::io::AsyncWriteExt::write_all(&mut stream, head.as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    let read = timeout(Duration::from_secs(5), stream.read_to_end(&mut buf))
        .await
        .expect("server acts");
    assert!(read.is_err(), "stream is reset: {read:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_stream_timeouts_close_the_connection() {
    let t = TestServer::start(|raw| {
        raw.limits.header_read_timeout_ms = 500;
        raw.limits.upstream_packet_timeout_ms = 500;
        raw.limits.upstream_claim_timeout_ms = 500;
        raw.limits.upstream_topology_timeout_ms = 500;
        raw.limits.upstream_health_timeout_ms = 500;
        raw.limits.stream_timeout_ms = 800;
        raw.limits.max_stream_timeouts_per_connection = 2;
    })
    .await;
    let ch = t.certhash();
    let conn = dial(&t.addr(), Transport::Quic).await;
    // A completed exchange between timeouts resets the count.
    stalled_stream(conn.as_ref(), &ch).await;
    let ok = exchange(conn.as_ref(), &request("GET", "/topology", &ch, &[], b"")).await;
    assert_eq!(ok.status, 200);
    stalled_stream(conn.as_ref(), &ch).await;
    let ok = exchange(conn.as_ref(), &request("GET", "/topology", &ch, &[], b"")).await;
    assert_eq!(ok.status, 200, "one timeout in a row keeps the connection");
    // Two in a row: the connection is treated as stalled and closed.
    stalled_stream(conn.as_ref(), &ch).await;
    stalled_stream(conn.as_ref(), &ch).await;
    timeout(Duration::from_secs(5), conn.closed())
        .await
        .expect("stalled connection closed");
    assert!(
        closed_with(conn.as_ref(), ErrorCode::Timeout),
        "close code: {:?}",
        conn.err()
    );
    assert!(wait_for_metric(&t, "nox_kps_connections_closed_total{reason=\"stalled\"} 1").await);
    t.stop().await;
}

/// Reads one claim response slowly (`chunk` bytes, then `pause`), as a client
/// on a slow link does. Returns the bytes read, or the read error.
async fn slow_claim_read(
    t: &TestServer,
    chunk: usize,
    pause: Duration,
) -> Result<usize, std::io::Error> {
    let conn = dial(&t.addr(), Transport::Quic).await;
    let mut stream = conn.open_stream().await.unwrap();
    let req = claim_request(&t.certhash(), &[SURB_ID]);
    tokio::io::AsyncWriteExt::write_all(&mut stream, &req)
        .await
        .unwrap();
    stream.close_write().await.unwrap();
    let mut buf = vec![0u8; chunk];
    let mut total = 0usize;
    loop {
        let n = timeout(T, stream.read(&mut buf))
            .await
            .expect("read acts")?;
        if n == 0 {
            return Ok(total);
        }
        total += n;
        tokio::time::sleep(pause).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_responses_get_time_to_drain_on_slow_links() {
    const BODY: usize = 24 * 1024 * 1024;
    let start = |drain_rate: u64| {
        TestServer::start(move |raw| {
            raw.limits.header_read_timeout_ms = 500;
            raw.limits.upstream_packet_timeout_ms = 500;
            raw.limits.upstream_claim_timeout_ms = 500;
            raw.limits.upstream_topology_timeout_ms = 500;
            raw.limits.upstream_health_timeout_ms = 500;
            raw.limits.stream_timeout_ms = 1_000;
            raw.limits.claim_max_surb_ids = 1;
            raw.limits.claim_response_max_bytes = 32 * 1024 * 1024;
            raw.limits.response_min_drain_bytes_per_sec = drain_rate;
        })
    };
    // About 8 MiB/s: three seconds for the body, well past the 1 s stream
    // timeout. A 24 MiB body is larger than the QUIC stream window, so the
    // server is still writing when the base deadline passes.
    let (chunk, pause) = (256 * 1024, Duration::from_millis(30));

    // Sized for links of at least 4 MiB/s: the deadline grows by 6 s.
    let t = start(4 * 1024 * 1024).await;
    t.upstream.set_body_bytes(CLAIM, BODY);
    let started = Instant::now();
    let read = slow_claim_read(&t, chunk, pause)
        .await
        .expect("response drains");
    assert!(read > BODY, "head and body arrive ({read} bytes)");
    assert!(
        started.elapsed() > Duration::from_secs(1),
        "the read outlasted the base deadline"
    );
    let metrics = t.metrics_text().await;
    assert!(
        !metrics.contains("nox_kps_stream_failures_total{reason=\"stream_timeout\"} 1"),
        "{metrics}"
    );
    t.stop().await;

    // Sized for a 1 GiB/s link: the same slow read runs out of time.
    let t = start(1024 * 1024 * 1024).await;
    t.upstream.set_body_bytes(CLAIM, BODY);
    let read = slow_claim_read(&t, chunk, pause).await;
    assert!(read.is_err(), "the stream is reset mid-response: {read:?}");
    assert!(
        wait_for_metric(
            &t,
            "nox_kps_stream_failures_total{reason=\"stream_timeout\"} 1"
        )
        .await,
        "{}",
        t.metrics_text().await
    );
    t.stop().await;
}
