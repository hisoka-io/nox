//! Soak: sequential 32 KiB exchanges on one long-lived KPS connection per
//! transport, counting stalls (no complete response within the stall
//! deadline). Ignored by default; run it explicitly:
//!
//! ```text
//! cargo test --release --test soak -- --ignored --nocapture
//! SOAK_REQUESTS=2000 SOAK_STALL_MS=5000 SOAK_OUT=soak.json cargo test --release --test soak -- --ignored --nocapture
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::{Duration, Instant};

use common::{dial, request, route, try_exchange, TestServer, Transport};

const PAYLOAD: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// `POST /api/v1/packets` with a 32 KiB body, short response.
    Upload,
    /// `GET /blob` answered with a 32 KiB body.
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
        Direction::Upload => request(
            "POST",
            "/api/v1/packets",
            &ch,
            &[("Content-Type", "application/octet-stream")],
            &packet,
        ),
        Direction::Download => request(
            "GET",
            "/blob",
            &ch,
            &[("X-Mock-Response-Bytes", "32768")],
            b"",
        ),
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
        raw.proxy
            .forward_request_headers
            .push("x-mock-response-bytes".into());
        raw.routes.push(route("blob", "GET", "/blob", "ingress", 0));
        raw.limits.header_read_timeout_ms = 10_000;
        raw.limits.stream_timeout_ms = 20_000;
        raw.limits.connection_idle_timeout_ms = 600_000;
    })
    .await;

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
