//! The `nox-kps` binary: init, address, check-config, bundle, run (with
//! SIGTERM), healthcheck, and the privacy of its logs.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

mod common;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use common::{
    claim_request, dial, exchange, packet, packet_request, request, try_exchange, MockUpstream,
    Transport, SURB_ID,
};
use nox_kps::bundles::keccak256_hex;

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

fn write_config(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("nox-kps.toml");
    std::fs::write(&path, body).unwrap();
    path
}

/// A minimal valid config for a public test address.
fn public_config(dir: &Path, extra: &str) -> PathBuf {
    write_config(
        dir,
        &format!(
            "listen = \"0.0.0.0:15005\"\nadvertise = [\"203.0.113.5\"]\nkey_file = \"{}\"\nkeccak_dir = \"{}\"\n{extra}",
            dir.join("state").join("kps.key").display(),
            dir.join("keccak").display(),
        ),
    )
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn init_creates_the_identity_once_and_address_reprints_it() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = public_config(dir.path(), "");
    let cfg = cfg.to_str().unwrap();
    let key = dir.path().join("state").join("kps.key");

    let missing = output(nox_kps(&["--config", cfg, "address"]));
    assert_eq!(missing.status.code(), Some(2));
    assert!(
        text(&missing.stderr).contains("nox-kps init"),
        "{}",
        text(&missing.stderr)
    );
    assert!(!key.exists(), "address never creates a key");

    let first = output(nox_kps(&["--config", cfg, "init"]));
    assert!(first.status.success(), "stderr: {}", text(&first.stderr));
    let stdout = text(&first.stdout);
    let addr_line = stdout.lines().find(|l| l.starts_with("address: ")).unwrap();
    let addr = addr_line.trim_start_matches("address: ").to_string();
    assert!(addr.starts_with("203.0.113.5:15005:uEi"), "{stdout}");
    assert!(
        stdout.contains(&format!("metadataUrl: kps:{addr}/metadata.json")),
        "{stdout}"
    );
    let pem = std::fs::read_to_string(&key).unwrap();
    assert!(!stdout.contains("PRIVATE"), "the key never reaches stdout");
    assert!(!stdout.contains(pem.lines().nth(1).unwrap()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    let again = output(nox_kps(&["--config", cfg, "init"]));
    assert_eq!(again.status.code(), Some(2), "init refuses an existing key");
    assert!(text(&again.stderr).contains("already exists"));
    assert_eq!(std::fs::read_to_string(&key).unwrap(), pem);

    for _ in 0..3 {
        let out = output(nox_kps(&["--config", cfg, "address"]));
        assert!(out.status.success());
        assert!(
            text(&out.stdout).contains(&format!("address: {addr}")),
            "same certhash on every run"
        );
    }
}

#[test]
fn check_config_accepts_a_valid_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("keccak")).unwrap();
    let cfg = public_config(dir.path(), "");
    let out = output(nox_kps(&[
        "--config",
        cfg.to_str().unwrap(),
        "check-config",
    ]));
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("configuration OK"), "{stdout}");
    assert!(stdout.contains("POST /api/v1/packets"), "{stdout}");
    assert!(stdout.contains("127.0.0.1:15002"), "{stdout}");
    assert!(stdout.contains("does not exist yet"), "{stdout}");
    assert!(
        !dir.path().join("state").join("kps.key").exists(),
        "check-config never creates the key"
    );
}

#[test]
fn check_config_reports_every_invalid_field() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(
        dir.path(),
        "client_ip_header = \"host\"\nupstream_ingress = \"10.0.0.1:15002\"\n[limits]\nmax_connections = 0\n",
    );
    let out = output(nox_kps(&[
        "--config",
        cfg.to_str().unwrap(),
        "check-config",
    ]));
    assert_eq!(out.status.code(), Some(2));
    let stderr = text(&out.stderr);
    for field in [
        "advertise",
        "limits.max_connections",
        "client_ip_header",
        "upstream_ingress",
    ] {
        assert!(stderr.contains(field), "{field} missing from: {stderr}");
    }
}

#[test]
fn an_explicit_config_path_must_exist_and_unknown_keys_are_refused() {
    let out = output(nox_kps(&[
        "--config",
        "/nonexistent/nox-kps.toml",
        "check-config",
    ]));
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("does not exist"));
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
fn check_config_refuses_a_loose_key() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("keccak")).unwrap();
    let cfg = public_config(dir.path(), "");
    let cfg = cfg.to_str().unwrap();
    assert!(output(nox_kps(&["--config", cfg, "init"])).status.success());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let key = dir.path().join("state").join("kps.key");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let out = output(nox_kps(&["--config", cfg, "check-config"]));
        assert_eq!(out.status.code(), Some(2));
        assert!(
            text(&out.stderr).contains("chmod 600"),
            "{}",
            text(&out.stderr)
        );
    }
}

#[test]
fn environment_overrides_apply_to_the_binary() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("kps.key");
    let empty = write_config(dir.path(), "");
    let run = |args: &[&str]| {
        output(
            nox_kps(args)
                .env("NOX_KPS_CONFIG", empty.to_str().unwrap())
                .env("NOX_KPS__LISTEN", "0.0.0.0:16005")
                .env("NOX_KPS__ADVERTISE", "198.51.100.20,2001:db8::20")
                .env("NOX_KPS__ALLOW_PRIVATE_ADVERTISE", "true")
                .env("NOX_KPS__KEY_FILE", key.to_str().unwrap()),
        )
    };
    assert!(run(&["init"]).status.success());
    let out = run(&["address"]);
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    let lines: Vec<String> = text(&out.stdout)
        .lines()
        .filter(|l| l.starts_with("address: "))
        .map(str::to_string)
        .collect();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines[0].starts_with("address: 198.51.100.20:16005:uEi"),
        "{lines:?}"
    );
    assert!(
        lines[1].starts_with("address: [2001:db8::20]:16005:uEi"),
        "{lines:?}"
    );
}

#[test]
fn bundle_add_list_and_verify() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = public_config(dir.path(), "");
    let cfg = cfg.to_str().unwrap();
    assert!(output(nox_kps(&["--config", cfg, "init"])).status.success());
    let worker = dir.path().join("anon-rpc-worker.js");
    std::fs::write(&worker, b"(()=>{self.postMessage('nox')})();\n").unwrap();
    let hash = keccak256_hex(&std::fs::read(&worker).unwrap());

    let out = output(nox_kps(&[
        "--config",
        cfg,
        "bundle",
        "add",
        worker.to_str().unwrap(),
    ]));
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains(&format!("added: {hash}")), "{stdout}");
    let resolver = format!("/keccak/{}/{}", &hash[..2], &hash[2..]);
    assert!(
        stdout.lines().any(|l| l.starts_with("resolver: kps:203.0.113.5:15005:uEi") && l.ends_with(&resolver)),
        "{stdout}"
    );
    let again = output(nox_kps(&[
        "--config",
        cfg,
        "bundle",
        "add",
        worker.to_str().unwrap(),
    ]));
    assert!(text(&again.stdout).contains("already present"));

    let list = output(nox_kps(&["--config", cfg, "bundle", "list"]));
    assert!(list.status.success());
    let size = std::fs::metadata(&worker).unwrap().len();
    assert!(
        text(&list.stdout).contains(&format!("{hash} {size} bytes")),
        "{}",
        text(&list.stdout)
    );
    assert!(output(nox_kps(&["--config", cfg, "bundle", "verify"]))
        .status
        .success());

    // A tampered file fails verification.
    let fake = keccak256_hex(b"promised bytes");
    let shard = dir.path().join("keccak").join(&fake[..2]);
    std::fs::create_dir_all(&shard).unwrap();
    std::fs::write(shard.join(&fake[2..]), b"other bytes").unwrap();
    let verify = output(nox_kps(&["--config", cfg, "bundle", "verify"]));
    assert_eq!(verify.status.code(), Some(1));
    assert!(
        text(&verify.stderr).contains("MISMATCH"),
        "{}",
        text(&verify.stderr)
    );
}

struct Running {
    child: Child,
    lines: mpsc::Receiver<String>,
    log: Vec<String>,
}

impl Running {
    fn spawn(cfg: &str) -> Self {
        let mut child = nox_kps(&["--config", cfg, "run"])
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
        Self {
            child,
            lines: rx,
            log: Vec::new(),
        }
    }

    /// Waits for the first log line containing `needle`.
    fn wait_for(&mut self, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let line = self
                .lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|_| {
                    panic!("no {needle:?} logged; log so far:\n{}", self.log.join("\n"))
                });
            self.log.push(line.clone());
            if line.contains(needle) {
                return line;
            }
        }
    }

    async fn sigterm(mut self) -> Vec<String> {
        let killed = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(killed.success());
        let deadline = Instant::now() + Duration::from_secs(15);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "nox-kps did not stop after SIGTERM"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert!(status.success(), "clean exit after SIGTERM: {status:?}");
        while let Ok(line) = self.lines.recv_timeout(Duration::from_millis(500)) {
            self.log.push(line);
        }
        self.log
    }
}

/// Starts the binary against a mock upstream and returns (process, config, address).
async fn start_binary(
    dir: &Path,
    upstream: &MockUpstream,
    extra: &str,
) -> (Running, String, String) {
    let admin_port = free_tcp_port();
    let key = dir.join("kps.key");
    let cfg = write_config(
        dir,
        &format!(
            "listen = \"127.0.0.1:0\"\nadvertise = [\"127.0.0.1\"]\nallow_private_advertise = true\n\
             key_file = \"{}\"\nkeccak_dir = \"\"\n\
             upstream_ingress = \"{up}\"\nupstream_topology = \"{up}\"\n\
             admin_listen = \"127.0.0.1:{admin_port}\"\n{extra}\n\
             [shutdown]\ngrace_period_ms = 3000\nclose_linger_ms = 500\n",
            key.display(),
            up = upstream.authority(),
        ),
    );
    let cfg = cfg.to_str().unwrap().to_string();
    nox_kps::identity::init(&key).unwrap();
    let mut running = Running::spawn(&cfg);
    let line = running.wait_for(":uEi");
    let address = line
        .split(|c: char| c.is_whitespace() || c == '"')
        .find(|w| w.starts_with("127.0.0.1:") && w.contains(":uEi"))
        .unwrap_or_else(|| panic!("no address in {line}"))
        .to_string();
    (running, cfg, address)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_serves_until_sigterm_and_healthcheck_tracks_it() {
    let upstream = MockUpstream::start().await;
    let dir = tempfile::tempdir().unwrap();
    let (running, cfg, address) =
        start_binary(dir.path(), &upstream, "log_format = \"text\"").await;
    assert!(
        running.log.iter().all(|l| !l.contains('\u{1b}')),
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

    let health = output(nox_kps(&["--config", &cfg, "healthcheck"]));
    assert!(
        health.status.success(),
        "healthcheck: {}",
        text(&health.stderr)
    );
    let health = output(nox_kps(&["--config", &cfg, "healthcheck", "--kps"]));
    // listen port 0 cannot be dialed by the probe; it reads the port from config.
    assert_eq!(
        health.status.code(),
        Some(1),
        "port 0 is not dialable: {}",
        text(&health.stderr)
    );

    let log = running.sigterm().await.join("\n");
    assert!(log.contains("nox-kps stopped"), "{log}");
    for secret in ["PRIVATE KEY", "BEGIN"] {
        assert!(!log.contains(secret), "logs never contain key material");
    }
    let health = output(nox_kps(&["--config", &cfg, "healthcheck"]));
    assert_eq!(
        health.status.code(),
        Some(1),
        "healthcheck fails once stopped"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn healthcheck_kps_dials_the_listener_end_to_end() {
    let upstream = MockUpstream::start().await;
    let dir = tempfile::tempdir().unwrap();
    let port = {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.local_addr().unwrap().port()
    };
    let admin_port = free_tcp_port();
    let key = dir.path().join("kps.key");
    nox_kps::identity::init(&key).unwrap();
    let cfg = write_config(
        dir.path(),
        &format!(
            "listen = \"127.0.0.1:{port}\"\nadvertise = [\"127.0.0.1\"]\nallow_private_advertise = true\n\
             key_file = \"{}\"\nkeccak_dir = \"\"\nupstream_ingress = \"{up}\"\nupstream_topology = \"{up}\"\n\
             admin_listen = \"127.0.0.1:{admin_port}\"\n[limits]\nhealth_cache_ms = 0\n",
            key.display(),
            up = upstream.authority(),
        ),
    );
    let cfg = cfg.to_str().unwrap().to_string();
    let mut running = Running::spawn(&cfg);
    running.wait_for("admin endpoint");
    let ok = output(nox_kps(&["--config", &cfg, "healthcheck", "--kps"]));
    assert!(
        ok.status.success(),
        "healthcheck --kps: {}",
        text(&ok.stderr)
    );
    // The node's ingress failing makes the end-to-end probe fail.
    upstream.set_status("/health", 500);
    let bad = output(nox_kps(&["--config", &cfg, "healthcheck", "--kps"]));
    assert_eq!(bad.status.code(), Some(1));
    assert!(text(&bad.stderr).contains("503"), "{}", text(&bad.stderr));
    running.sigterm().await;
}

/// Logs at `info` carry no client addresses, request contents, SURB IDs or
/// key material, even across failures and refusals.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn info_logs_carry_no_client_data() {
    let upstream = MockUpstream::start().await;
    let dir = tempfile::tempdir().unwrap();
    let (running, _cfg, address) = start_binary(
        dir.path(),
        &upstream,
        "log_level = \"info\"\nsummary_interval_secs = 1\n[limits]\npacket_rate_per_ip = 1\npacket_burst = 2\nupstream_claim_timeout_ms = 300\n",
    )
    .await;
    let certhash = address.rsplit(':').next().unwrap().to_string();
    let marker = packet(0x5a);
    for transport in [Transport::Quic, Transport::WebRtc] {
        let conn = dial(&address, transport).await;
        for _ in 0..4 {
            let _ = try_exchange(
                conn.as_ref(),
                &packet_request(&certhash, &marker),
                Duration::from_secs(5),
            )
            .await;
        }
        let _ = exchange(conn.as_ref(), &claim_request(&certhash, &[SURB_ID])).await;
        let _ = exchange(
            conn.as_ref(),
            &request(
                "GET",
                "/nope",
                &certhash,
                &[("X-Real-IP", "198.51.100.77")],
                b"",
            ),
        )
        .await;
    }
    upstream.set_delay("/api/v1/responses/claim", 1_000);
    let conn = dial(&address, Transport::Quic).await;
    let res = exchange(conn.as_ref(), &claim_request(&certhash, &[SURB_ID])).await;
    assert_eq!(res.status, 504, "an upstream failure is logged at warn");
    tokio::time::sleep(Duration::from_millis(1_500)).await;

    let log = running.sigterm().await;
    let after_start: Vec<&String> = log
        .iter()
        .skip_while(|l| !l.contains("admin endpoint"))
        .skip(1)
        .collect();
    assert!(
        after_start.iter().any(|l| l.contains("summary")),
        "summaries are logged:\n{log:#?}"
    );
    assert!(
        after_start
            .iter()
            .any(|l| l.contains("upstream exchange failed")),
        "{log:#?}"
    );
    for line in &after_start {
        for forbidden in [
            "127.0.0.1",
            "198.51.100.77",
            SURB_ID,
            "ZZZZ",
            "PRIVATE",
            "x-real-ip",
        ] {
            assert!(
                !line.contains(forbidden),
                "{forbidden:?} leaked into: {line}"
            );
        }
    }
    // The upstream failure line names the route, the upstream and the time.
    let failure = after_start
        .iter()
        .find(|l| l.contains("upstream exchange failed"))
        .unwrap();
    assert!(
        failure.contains("route claim") && failure.contains("upstream_ingress"),
        "{failure}"
    );
}
