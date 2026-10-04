//! Soak: sequential 32 KiB exchanges on one long-lived KPS connection per
//! transport, counting stalls (no complete response within the stall
//! deadline). Ignored by default; run it explicitly:
//!
//! ```text
//! cargo test --release --test soak -- --ignored --nocapture
//! SOAK_REQUESTS=2000 SOAK_STALL_MS=5000 SOAK_OUT=soak.json cargo test --release --test soak -- --ignored --nocapture
//! SOAK_LARGE_BYTES=5242880 SOAK_LARGE_REQUESTS=20 cargo test --release --test soak soak_large -- --ignored --nocapture
//! ```
//!
//! Loopback has no loss and no delay, so these numbers bound nox-kps's own
//! behaviour; WAN stall rates come from the canary soak (TST-502).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

mod common;

use std::time::{Duration, Instant};

use common::{claim_request, dial, packet_request, try_exchange, TestServer, Transport, SURB_ID};
use nox_kps::config::max_claim_response_bytes;

const PAYLOAD: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// `POST /api/v1/packets` with a 32 KiB body, short response.
    Upload,
    /// `POST /api/v1/responses/claim` answered with a 32 KiB body.
    Download,
}

impl Direction {
    fn name(self) -> &'static str {
        match self {
            Self::Upload => "upload-32KiB",
            Self::Download => "download-32KiB",
        }
    }
}

#[derive(Debug, Default)]
struct Run {
    transport: &'static str,
    direction: &'static str,
    requests: usize,
    ok: usize,
    stalls: usize,
    errors: usize,
    redials: usize,
    latencies_ms: Vec<f64>,
    wall_secs: f64,
    first_errors: Vec<String>,
}

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn pct(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let i = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[i]
}

async fn soak(
    t: &TestServer,
    transport: Transport,
    direction: Direction,
    count: usize,
    stall: Duration,
) -> Run {
    let ch = t.certhash();
    let packet: Vec<u8> = (0..PAYLOAD).map(|i| (i % 251) as u8).collect();
    let req = match direction {
        Direction::Upload => packet_request(&ch, &packet),
        Direction::Download => claim_request(&ch, &[SURB_ID]),
    };
    let mut run = Run {
        transport: transport.name(),
        direction: direction.name(),
        requests: count,
        ..Run::default()
    };
    let mut conn = dial(&t.addr(), transport).await;
    let started = Instant::now();
    for _ in 0..count {
        let t0 = Instant::now();
        match try_exchange(conn.as_ref(), &req, stall).await {
            Ok(res) => {
                let good = match direction {
                    Direction::Upload => res.status == 202,
                    Direction::Download => res.status == 200 && res.body.len() == PAYLOAD,
                };
                if good {
                    run.ok += 1;
                    run.latencies_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
                } else {
                    run.errors += 1;
                    if run.first_errors.len() < 5 {
                        run.first_errors.push(format!(
                            "status {} body {} B",
                            res.status,
                            res.body.len()
                        ));
                    }
                }
            }
            Err(e) => {
                if e.starts_with("no response within") {
                    run.stalls += 1;
                } else {
                    run.errors += 1;
                }
                if run.first_errors.len() < 5 {
                    run.first_errors.push(e.clone());
                }
                // Keep going on the same connection when it is still alive;
                // otherwise dial again.
                let closed = tokio::time::timeout(Duration::from_millis(5), conn.closed())
                    .await
                    .is_ok();
                if closed {
                    conn = dial(&t.addr(), transport).await;
                    run.redials += 1;
                }
            }
        }
    }
    run.wall_secs = started.elapsed().as_secs_f64();
    let _ = conn.close().await;
    run
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running soak; run explicitly with --ignored"]
async fn soak_sequential_32k_requests() {
    let count: usize = env_or("SOAK_REQUESTS", 2000);
    let stall = Duration::from_millis(env_or("SOAK_STALL_MS", 5000));
    let t = TestServer::start(|raw| {
        raw.limits.packet_rate_per_ip = 1_000_000;
        raw.limits.packet_burst = 1_000_000;
        raw.limits.claim_rate_per_ip = 1_000_000;
        raw.limits.claim_burst = 1_000_000;
        raw.limits.header_read_timeout_ms = 10_000;
        raw.limits.stream_timeout_ms = 20_000;
        raw.limits.conn_idle_timeout_secs = 600;
    })
    .await;
    t.upstream
        .set_body_bytes("/api/v1/responses/claim", PAYLOAD);
    t.upstream.behaviour.lock().unwrap().skip_bodies = true;

    let mut runs = Vec::new();
    for transport in [Transport::Quic, Transport::WebRtc] {
        for direction in [Direction::Upload, Direction::Download] {
            let run = soak(&t, transport, direction, count, stall).await;
            println!(
                "soak {} {}: {} requests, {} ok, {} stalls (>{} ms), {} errors, {} redials, {:.1} s",
                run.transport,
                run.direction,
                run.requests,
                run.ok,
                run.stalls,
                stall.as_millis(),
                run.errors,
                run.redials,
                run.wall_secs
            );
            runs.push(run);
        }
    }

    println!();
    println!("| transport | direction | requests | ok | stalls | stall rate | errors | redials | p50 ms | p90 ms | p99 ms | max ms | req/s |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|---|");
    let mut json = Vec::new();
    for run in &mut runs {
        run.latencies_ms.sort_by(f64::total_cmp);
        let l = &run.latencies_ms;
        let stall_rate = run.stalls as f64 / run.requests as f64;
        println!(
            "| {} | {} | {} | {} | {} | {:.2}% | {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {:.0} |",
            run.transport,
            run.direction,
            run.requests,
            run.ok,
            run.stalls,
            stall_rate * 100.0,
            run.errors,
            run.redials,
            pct(l, 0.5),
            pct(l, 0.9),
            pct(l, 0.99),
            l.last().copied().unwrap_or(0.0),
            run.requests as f64 / run.wall_secs
        );
        if !run.first_errors.is_empty() {
            println!(
                "  first errors ({} {}): {:?}",
                run.transport, run.direction, run.first_errors
            );
        }
        json.push(serde_json::json!({
            "transport": run.transport,
            "direction": run.direction,
            "requests": run.requests,
            "ok": run.ok,
            "stalls": run.stalls,
            "stall_rate": stall_rate,
            "stall_deadline_ms": stall.as_millis() as u64,
            "errors": run.errors,
            "redials": run.redials,
            "p50_ms": pct(l, 0.5),
            "p90_ms": pct(l, 0.9),
            "p99_ms": pct(l, 0.99),
            "max_ms": l.last().copied().unwrap_or(0.0),
            "wall_secs": run.wall_secs,
            "first_errors": run.first_errors,
        }));
    }
    if let Ok(path) = std::env::var("SOAK_OUT") {
        std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
        println!("results written to {path}");
    }
    let metrics = t.metrics_text().await;
    for line in metrics.lines().filter(|l| {
        l.starts_with("nox_kps_stream_failures_total")
            || l.starts_with("nox_kps_streams_rejected_total")
    }) {
        println!("server: {line}");
    }
    t.stop().await;

    // Stalls are reported, not hidden. Every exchange that completed returned
    // the right status and size; set SOAK_MAX_STALL_RATE to also gate on stalls.
    for run in &runs {
        assert_eq!(
            run.errors, 0,
            "{} {}: {:?}",
            run.transport, run.direction, run.first_errors
        );
        if let Ok(max) = std::env::var("SOAK_MAX_STALL_RATE") {
            let max: f64 = max.parse().unwrap();
            assert!(
                run.stalls as f64 / run.requests as f64 <= max,
                "{} {} stall rate over {max}",
                run.transport,
                run.direction
            );
        }
    }
}

/// Large claim responses (the shape of a reply with many SURBs) over each
/// transport: the bulk-transfer case where the Rust WebRTC stack has stalled
/// in earlier benches.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running soak; run explicitly with --ignored"]
async fn soak_large_claim_bodies() {
    let size: usize = env_or("SOAK_LARGE_BYTES", 5 * 1024 * 1024);
    let count: usize = env_or("SOAK_LARGE_REQUESTS", 20);
    let stall = Duration::from_millis(env_or("SOAK_STALL_MS", 15_000));
    let t = TestServer::start(|raw| {
        raw.limits.claim_rate_per_ip = 1_000_000;
        raw.limits.claim_burst = 1_000_000;
        raw.limits.claim_max_surb_ids = 1;
        raw.limits.claim_response_max_bytes = size.max(max_claim_response_bytes(1));
        raw.limits.upstream_claim_timeout_ms = 20_000;
        raw.limits.conn_idle_timeout_secs = 600;
    })
    .await;
    t.upstream.set_body_bytes("/api/v1/responses/claim", size);
    t.upstream.behaviour.lock().unwrap().skip_bodies = true;
    let req = claim_request(&t.certhash(), &[SURB_ID]);
    let mut results = Vec::new();
    for transport in [Transport::Quic, Transport::WebRtc] {
        let mut conn = dial(&t.addr(), transport).await;
        let (mut ok, mut stalls, mut errors, mut redials) = (0usize, 0usize, Vec::new(), 0usize);
        let mut ms = Vec::new();
        // One character per exchange: '.' ok, 'S' stall (no response within
        // the deadline), 'C' the server closed the connection, 'E' a wrong
        // response. After 'S' or 'C' on a closed connection the client
        // redials, as the SDK does.
        let mut sequence = String::new();
        for _ in 0..count {
            if tokio::time::timeout(Duration::from_millis(5), conn.closed())
                .await
                .is_ok()
            {
                conn = dial(&t.addr(), transport).await;
                redials += 1;
            }
            let t0 = Instant::now();
            match try_exchange(conn.as_ref(), &req, stall).await {
                Ok(res) if res.status == 200 && res.body.len() == size => {
                    ok += 1;
                    sequence.push('.');
                    ms.push(t0.elapsed().as_secs_f64() * 1000.0);
                }
                Ok(res) => {
                    sequence.push('E');
                    errors.push(format!("status {} body {} B", res.status, res.body.len()));
                }
                Err(e) if e.starts_with("no response within") => {
                    sequence.push('S');
                    stalls += 1;
                }
                Err(_) => sequence.push('C'),
            }
        }
        println!("sequence {}: {sequence}", transport.name());
        ms.sort_by(f64::total_cmp);
        let mib_s = if ms.is_empty() {
            0.0
        } else {
            (size as f64 / 1_048_576.0) / (pct(&ms, 0.5) / 1000.0)
        };
        println!(
            "large {} {} B x {count}: {ok} ok, {stalls} stalls (>{} ms), {} errors, {redials} redials, p50 {:.1} ms, max {:.1} ms, ~{mib_s:.1} MiB/s",
            transport.name(),
            size,
            stall.as_millis(),
            errors.len(),
            pct(&ms, 0.5),
            ms.last().copied().unwrap_or(0.0),
        );
        results.push(serde_json::json!({
            "transport": transport.name(),
            "bytes": size,
            "requests": count,
            "ok": ok,
            "stalls": stalls,
            "redials": redials,
            "sequence": sequence,
            "errors": errors,
            "p50_ms": pct(&ms, 0.5),
            "max_ms": ms.last().copied().unwrap_or(0.0),
        }));
        assert!(errors.is_empty(), "{} errors: {errors:?}", transport.name());
        let _ = conn.close().await;
    }
    if let Ok(path) = std::env::var("SOAK_OUT") {
        std::fs::write(&path, serde_json::to_string_pretty(&results).unwrap()).unwrap();
        println!("results written to {path}");
    }
    let metrics = t.metrics_text().await;
    for line in metrics.lines().filter(|l| {
        l.starts_with("nox_kps_stream_failures_total")
            || l.starts_with("nox_kps_connections_closed_total")
            || l.starts_with("nox_kps_streams_active")
            || l.starts_with("nox_kps_connections_active")
            || l.starts_with("nox_kps_streams_total")
            || l.starts_with("nox_kps_bytes_total")
    }) {
        println!("server: {line}");
    }
    t.stop().await;
}

/// The large-claim WebRTC soak with nox-kps as a separate process, so each
/// end of the link logs to its own file: the webrtc-rs SCTP association has
/// no name, and in one process both ends log the same `[]` prefix. Used to
/// localize the wedge seen after 16 MiB responses.
///
/// ```text
/// SOAK_LARGE_BYTES=16777216 SOAK_LARGE_REQUESTS=20 SOAK_LOG_DIR=/tmp/wedge \
/// SOAK_SERVER_LOG='warn,nox_kps=debug,webrtc=debug,webrtc_sctp=trace,webrtc_data=debug' \
/// SOAK_CLIENT_LOG='warn,webrtc=debug,webrtc_sctp=trace,webrtc_data=debug' \
/// cargo test --release --test soak soak_large_split_process -- --ignored --nocapture
/// ```
///
/// Writes `server.log` (nox-kps stdout) and `client.log` (this process) to
/// `SOAK_LOG_DIR`, plus one `client.log` marker line per exchange.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "diagnostic soak; run explicitly with --ignored"]
async fn soak_large_split_process() {
    use std::process::{Command, Stdio};

    let size: usize = env_or("SOAK_LARGE_BYTES", 16 * 1024 * 1024);
    let count: usize = env_or("SOAK_LARGE_REQUESTS", 20);
    let stall = Duration::from_millis(env_or("SOAK_STALL_MS", 15_000));
    let log_dir = std::path::PathBuf::from(
        std::env::var("SOAK_LOG_DIR").unwrap_or_else(|_| "target/soak-split".to_string()),
    );
    std::fs::create_dir_all(&log_dir).unwrap();
    let server_filter = std::env::var("SOAK_SERVER_LOG").unwrap_or_else(|_| "info".to_string());
    let client_filter = std::env::var("SOAK_CLIENT_LOG").unwrap_or_else(|_| "info".to_string());

    let client_log = std::fs::File::create(log_dir.join("client.log")).unwrap();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&client_filter))
        .with_ansi(false)
        .with_writer(std::sync::Mutex::new(client_log))
        .init();

    let upstream = common::MockUpstream::start().await;
    upstream.set_body_bytes("/api/v1/responses/claim", size);
    upstream.behaviour.lock().unwrap().skip_bodies = true;

    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("kps.key");
    let certhash = nox_kps::identity::init(&key).unwrap().certhash;
    let port = {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let admin_port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let cfg = dir.path().join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            "listen = \"127.0.0.1:{port}\"\nadvertise = [\"127.0.0.1\"]\nallow_private_advertise = true\n\
             key_file = \"{}\"\nexpected_certhash = \"{certhash}\"\nkeccak_dir = \"\"\n\
             upstream_ingress = \"{up}\"\nupstream_topology = \"{up}\"\n\
             admin_listen = \"127.0.0.1:{admin_port}\"\nlog_format = \"text\"\nsummary_interval_secs = 0\n\
             [limits]\nclaim_rate_per_ip = 1000000\nclaim_burst = 1000000\nclaim_max_surb_ids = 1\n\
             claim_response_max_bytes = {cap}\nupstream_claim_timeout_ms = 20000\nconn_idle_timeout_secs = 600\n",
            key.display(),
            up = upstream.authority(),
            cap = size.max(max_claim_response_bytes(1)),
        ),
    )
    .unwrap();
    let server_log = std::fs::File::create(log_dir.join("server.log")).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nox-kps"))
        .args(["--config", cfg.to_str().unwrap(), "run"])
        .env("RUST_LOG", &server_filter)
        .stdout(Stdio::from(server_log.try_clone().unwrap()))
        .stderr(Stdio::from(server_log))
        .spawn()
        .unwrap();

    let addr = nox_kps::identity::format_address("127.0.0.1".parse().unwrap(), port, &certhash);
    let req = claim_request(&certhash, &[SURB_ID]);
    let mut conn = None;
    for _ in 0..100 {
        if let Ok(Ok(c)) =
            tokio::time::timeout(Duration::from_secs(5), kps::dial_webrtc(&addr)).await
        {
            conn = Some(c);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let conn = conn.expect("nox-kps accepts a WebRTC dial");
    let mut sequence = String::new();
    for i in 0..count {
        tracing::warn!(target: "soak", "exchange {i} begins");
        let t0 = Instant::now();
        let mark = match try_exchange(conn.as_ref(), &req, stall).await {
            Ok(res) if res.status == 200 && res.body.len() == size => '.',
            Ok(_) => 'E',
            Err(e) if e.starts_with("no response within") => 'S',
            Err(_) => 'C',
        };
        tracing::warn!(target: "soak", "exchange {i} ends: {mark} after {} ms", t0.elapsed().as_millis());
        sequence.push(mark);
    }
    println!("sequence webrtc (split process): {sequence}");
    let metrics = common::admin_get(
        format!("127.0.0.1:{admin_port}").parse().unwrap(),
        "/metrics",
    )
    .await;
    for line in metrics.lines().filter(|l| {
        l.starts_with("nox_kps_stream_failures_total")
            || l.starts_with("nox_kps_streams_total")
            || l.starts_with("nox_kps_streams_active")
    }) {
        println!("server: {line}");
    }
    let _ = child.kill();
    let _ = child.wait();
    println!("logs in {}", log_dir.display());
}
