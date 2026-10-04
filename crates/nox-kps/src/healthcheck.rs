//! `nox-kps healthcheck`: the admin `/healthz` probe, and an optional end-to-end
//! probe that dials the local KPS listener over QUIC and fetches `/health`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::Settings;
use crate::error::HealthcheckError;
use crate::identity::{self, format_address};

/// Largest response head + body read by the KPS probe.
const KPS_PROBE_MAX_BYTES: u64 = 64 * 1024;

/// The admin address to probe: the configured one, with an unspecified IP
/// replaced by loopback.
#[must_use]
pub fn admin_target(settings: &Settings) -> SocketAddr {
    let mut addr = settings.admin_listen;
    if addr.ip().is_unspecified() {
        addr.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
    addr
}

/// The KPS address of this host's own listener (loopback when it binds all
/// interfaces).
pub fn local_kps_address(settings: &Settings) -> Result<String, HealthcheckError> {
    let identity = identity::load(&settings.key_file)?;
    let ip = match settings.listen.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        // A dual-stack [::] socket accepts IPv4 loopback too, which works on
        // hosts with IPv6 disabled.
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6 == Ipv6Addr::LOCALHOST => IpAddr::V6(v6),
        other => other,
    };
    Ok(format_address(
        ip,
        settings.listen.port(),
        &identity.certhash,
    ))
}

/// Dials `address` over QUIC and expects `200` from `GET /health`.
pub async fn probe_kps(address: &str, timeout: Duration) -> Result<(), HealthcheckError> {
    let target = format!("kps:{address}/health");
    let certhash = address.rsplit(':').next().unwrap_or_default().to_string();
    let probe = async {
        let conn = kps::dial(address)
            .await
            .map_err(|e| HealthcheckError::Dial {
                target: target.clone(),
                reason: e.to_string(),
            })?;
        let request_err = |e: &dyn std::fmt::Display| HealthcheckError::Request {
            target: target.clone(),
            reason: e.to_string(),
        };
        let mut stream = conn.open_stream().await.map_err(|e| request_err(&e))?;
        let head = format!("GET /health HTTP/1.1\r\nHost: {certhash}\r\n\r\n");
        stream
            .write_all(head.as_bytes())
            .await
            .map_err(|e| request_err(&e))?;
        stream.close_write().await.map_err(|e| request_err(&e))?;
        let mut response = Vec::new();
        (&mut stream)
            .take(KPS_PROBE_MAX_BYTES)
            .read_to_end(&mut response)
            .await
            .map_err(|e| request_err(&e))?;
        let _ = conn.close().await;
        let status = parse_status(&response).ok_or_else(|| HealthcheckError::Request {
            target: target.clone(),
            reason: "response has no HTTP/1.1 status line".to_string(),
        })?;
        if status == 200 {
            Ok(())
        } else {
            Err(HealthcheckError::Unhealthy {
                target: target.clone(),
                status,
            })
        }
    };
    tokio::time::timeout(timeout, probe)
        .await
        .map_err(|_| HealthcheckError::Timeout {
            target: format!("kps:{address}/health"),
            timeout_ms: timeout.as_millis(),
        })?
}

fn parse_status(response: &[u8]) -> Option<u16> {
    let line = response.split(|b| *b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.trim_end().splitn(3, ' ');
    if parts.next()? != "HTTP/1.1" {
        return None;
    }
    parts.next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_lines() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\n\r\n"), Some(200));
        assert_eq!(
            parse_status(b"HTTP/1.1 503 Service Unavailable\r\n"),
            Some(503)
        );
        assert_eq!(parse_status(b"HTTP/1.0 200 OK\r\n"), None);
        assert_eq!(parse_status(b""), None);
    }
}
