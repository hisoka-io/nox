//! The `nox-kps` binary: check-config, address, run (with SIGTERM) and
//! healthcheck.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use common::{dial, exchange, request, MockUpstream, Transport};

const BIN: &str = env!("CARGO_BIN_EXE_nox-kps");

fn nox_kps(args: &[&str]) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.args(args).env_clear().env("RUST_BACKTRACE", "0");
    cmd
}

fn output(mut cmd: impl std::borrow::BorrowMut<Command>) -> Output {
    cmd.borrow_mut().output().expect("binary runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn write_config(dir: &Path, body: &str) -> std::path::PathBuf {
    let path = dir.join("nox-kps.toml");
    std::fs::write(&path, body).unwrap();
    path
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn check_config_accepts_a_valid_file() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("kps.key");
    let cfg = write_config(
        dir.path(),
        &format!(
            "[kps]\nlisten = \"0.0.0.0:15005\"\npublic_ips = [\"203.0.113.5\"]\nidentity_key_file = \"{}\"\n",
            key.display()
        ),
    );
    let out = output(nox_kps(&[
        "--config",
        cfg.to_str().unwrap(),
        "check-config",
    ]));
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("configuration OK"), "{stdout}");
    assert!(
        stdout.contains("POST /api/v1/packets -> 127.0.0.1:15002"),
        "{stdout}"
    );
    assert!(stdout.contains("does not exist yet"), "{stdout}");
    assert!(!key.exists(), "check-config never creates the key");
}

#[test]
fn check_config_reports_every_invalid_field() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(
        dir.path(),
        "[limits]\nmax_connections = 0\n[proxy]\nclient_ip_header = \"host\"\n[upstreams]\ningress = \"http://10.0.0.1:15002\"\n",
    );
    let out = output(nox_kps(&[
        "--config",
        cfg.to_str().unwrap(),
        "check-config",
    ]));
    assert_eq!(out.status.code(), Some(2));
    let stderr = text(&out.stderr);
    for field in [
        "limits.max_connections",
        "proxy.client_ip_header",
        "upstreams.ingress",
    ] {
        assert!(stderr.contains(field), "{field} missing from: {stderr}");
    }
}

#[test]
fn an_explicit_config_path_must_exist() {
    let out = output(nox_kps(&[
        "--config",
        "/nonexistent/nox-kps.toml",
        "check-config",
    ]));
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("does not exist"));
}

#[test]
fn unknown_config_keys_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), "[limits]\nmax_conections = 5\n");
    let out = output(nox_kps(&[
        "--config",
        cfg.to_str().unwrap(),
        "check-config",
    ]));
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("max_conections"));
}

#[test]
fn environment_overrides_apply_to_the_binary() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("kps.key");
    let out = output(
        nox_kps(&["address"])
            .env(
                "NOX_KPS_CONFIG",
                write_config(dir.path(), "").to_str().unwrap(),
            )
            .env("NOX_KPS__KPS__LISTEN", "0.0.0.0:16005")
            .env("NOX_KPS__KPS__PUBLIC_IPS", "198.51.100.20,2001:db8::20")
            .env("NOX_KPS__KPS__IDENTITY_KEY_FILE", key.to_str().unwrap()),
    );
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    let lines: Vec<String> = text(&out.stdout).lines().map(str::to_string).collect();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[0].starts_with("198.51.100.20:16005:uEi"), "{lines:?}");
    assert!(
        lines[1].starts_with("[2001:db8::20]:16005:uEi"),
        "{lines:?}"
    );
}

#[test]
fn address_creates_the_identity_once_and_prints_a_stable_address() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("state").join("kps.key");
    let cfg = write_config(
        dir.path(),
        &format!(
            "[kps]\nlisten = \"[::]:15005\"\npublic_ips = [\"203.0.113.5\"]\nidentity_key_file = \"{}\"\n",
            key.display()
        ),
    );
    let first = output(nox_kps(&["--config", cfg.to_str().unwrap(), "address"]));
    assert!(first.status.success(), "stderr: {}", text(&first.stderr));
    let addr = text(&first.stdout).trim().to_string();
    assert!(addr.starts_with("203.0.113.5:15005:uEi"), "{addr}");
    assert!(text(&first.stderr).contains("created a new KPS identity key"));
    assert!(key.exists());
    let pem = std::fs::read_to_string(&key).unwrap();
    assert!(
        !text(&first.stdout).contains("PRIVATE"),
        "the key never reaches stdout"
    );
    assert!(!text(&first.stderr).contains(pem.lines().nth(1).unwrap()));

    let second = output(nox_kps(&["--config", cfg.to_str().unwrap(), "address"]));
    assert_eq!(
        text(&second.stdout).trim(),
        addr,
        "same certhash on every run"
    );
    assert!(!text(&second.stderr).contains("created"));

    let check = output(nox_kps(&[
        "--config",
        cfg.to_str().unwrap(),
        "check-config",
    ]));
    assert!(text(&check.stdout).contains(&format!("address: {addr}")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_serves_until_sigterm_and_healthcheck_tracks_it() {
    let upstream = MockUpstream::start().await;
    let dir = tempfile::tempdir().unwrap();
    let metrics_port = free_tcp_port();
    let cfg = write_config(
        dir.path(),
        &format!(
            "[kps]\nlisten = \"127.0.0.1:0\"\npublic_ips = [\"127.0.0.1\"]\nidentity_key_file = \"{}\"\n\
             [upstreams]\ningress = \"{}\"\ntopology = \"{}\"\n\
             [metrics]\nlisten = \"127.0.0.1:{metrics_port}\"\n\
             [shutdown]\ngrace_period_ms = 3000\nclose_linger_ms = 500\n",
            dir.path().join("kps.key").display(),
            upstream.url(),
            upstream.url()
        ),
    );
    let cfg_s = cfg.to_str().unwrap().to_string();
    let mut child = nox_kps(&["--config", &cfg_s])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let (tx, rx) = mpsc::channel::<String>();
    let stdout = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    let mut log = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    let address = loop {
        let line = rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_else(|_| panic!("no address logged; log so far:\n{}", log.join("\n")));
        log.push(line.clone());
        if let Some(addr) = line
            .split_whitespace()
            .find(|w| w.starts_with("127.0.0.1:") && w.contains(":uEi"))
        {
            break addr.to_string();
        }
    };
    assert!(
        log.iter().all(|l| !l.contains('\u{1b}')),
        "no ANSI escapes when not a terminal"
    );

    let certhash = address.rsplit(':').next().unwrap().to_string();
    let conn = dial(&address, Transport::Quic).await;
    let res = exchange(
        conn.as_ref(),
        &request("GET", "/topology", &certhash, &[], b""),
    )
    .await;
    assert_eq!(res.status, 200);

    let health = output(nox_kps(&["--config", &cfg_s, "healthcheck"]));
    assert!(
        health.status.success(),
        "healthcheck: {}",
        text(&health.stderr)
    );

    let killed = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "nox-kps did not stop after SIGTERM"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(status.success(), "clean exit after SIGTERM: {status:?}");
    while let Ok(line) = rx.recv_timeout(Duration::from_millis(500)) {
        log.push(line);
    }
    let all = log.join("\n");
    assert!(all.contains("nox-kps stopped"), "{all}");
    for secret in ["PRIVATE KEY", "BEGIN"] {
        assert!(!all.contains(secret), "logs never contain key material");
    }

    let health = output(nox_kps(&["--config", &cfg_s, "healthcheck"]));
    assert_eq!(
        health.status.code(),
        Some(1),
        "healthcheck fails once stopped"
    );
}
