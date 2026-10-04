//! `nox-kps` command line: run the sidecar, check a config, print the KPS
//! address, or probe the local health endpoint.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use nox_kps::config::{summary, ConfigSource, RawConfig, Settings, DEFAULT_CONFIG_PATH};
use nox_kps::error::HealthcheckError;
use nox_kps::identity::{self, advertised_ips, format_address, is_non_public};
use nox_kps::metrics::probe_health;
use tracing::{error, info, warn};

/// Exit status for an invalid configuration.
const EXIT_CONFIG: u8 = 2;
/// Exit status when the server fails or the health probe fails.
const EXIT_FAILURE: u8 = 1;
/// How long `healthcheck` waits for an answer.
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Parser)]
#[command(
    name = "nox-kps",
    version,
    about = "KPS entry sidecar for Nox nodes: WebRTC + QUIC on one UDP port, proxied to the node's loopback ingress"
)]
struct Cli {
    /// TOML config file. Without this flag, /etc/nox-kps/config.toml is used
    /// when it exists; otherwise built-in defaults plus `NOX_KPS__*` variables.
    #[arg(short, long, env = "NOX_KPS_CONFIG")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the sidecar (default)
    Run,
    /// Validate the configuration and show the address it would publish
    CheckConfig,
    /// Print the KPS address(es) to publish, creating the identity key if needed
    Address,
    /// Exit 0 when the local /health endpoint answers 200 (container health checks)
    Healthcheck,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let source = match cli.config {
        Some(path) => ConfigSource::Explicit(path),
        None => ConfigSource::Default(PathBuf::from(DEFAULT_CONFIG_PATH)),
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("nox-kps: cannot start the async runtime: {e}");
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    match cli.command.unwrap_or(Command::Run) {
        Command::Run => runtime.block_on(run(&source)),
        Command::CheckConfig => check_config(&source),
        Command::Address => address(&source),
        Command::Healthcheck => runtime.block_on(healthcheck(&source)),
    }
}

fn load_settings(source: &ConfigSource) -> Result<Settings, ExitCode> {
    RawConfig::load(source)
        .and_then(|raw| raw.validate())
        .map_err(|e| {
            eprintln!("nox-kps: {e}");
            ExitCode::from(EXIT_CONFIG)
        })
}

async fn run(source: &ConfigSource) -> ExitCode {
    let settings = match load_settings(source) {
        Ok(s) => s,
        Err(code) => return code,
    };
    if let Err(e) = nox_kps::telemetry::init(&settings.log) {
        eprintln!("nox-kps: {e}");
        return ExitCode::from(EXIT_CONFIG);
    }
    match source {
        ConfigSource::Default(p) if !p.exists() => info!(
            "no config file at {}; using built-in defaults and NOX_KPS__* environment overrides",
            p.display()
        ),
        _ => info!(config = %source.path().display(), "configuration loaded"),
    }
    for (key, value) in summary(&settings) {
        info!("  {key}: {value}");
    }
    let listen = settings.listen;
    let server = match nox_kps::start(settings).await {
        Ok(server) => server,
        Err(e) => {
            error!("nox-kps failed to start: {e}");
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    info!(
        "KPS listener on UDP {} (port {}): WebRTC for browsers and QUIC for native clients",
        listen,
        server.port()
    );
    info!("publish these addresses (clients dial them directly; there is no DNS):");
    for addr in server.addresses() {
        info!("  {addr}");
    }
    if let Some(addr) = server.metrics_addr() {
        info!("metrics and health on http://{addr}/metrics and http://{addr}/health");
    }

    wait_for_signal().await;
    info!("shutdown requested; finishing in-flight exchanges");
    server.shutdown();
    server.wait().await;
    info!("nox-kps stopped");
    ExitCode::SUCCESS
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = term.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            Err(e) => {
                warn!(error = %e, "cannot listen for SIGTERM; stopping on Ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn check_config(source: &ConfigSource) -> ExitCode {
    let settings = match load_settings(source) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let origin = match source {
        ConfigSource::Default(p) if !p.exists() => {
            format!(
                "built-in defaults + environment (no file at {})",
                p.display()
            )
        }
        _ => source.path().display().to_string(),
    };
    println!("configuration OK: {origin}");
    for (key, value) in summary(&settings) {
        println!("  {key}: {value}");
    }
    match identity::read_existing(&settings.identity_key_file) {
        Ok(Some(id)) => {
            println!(
                "identity: {} (certhash {})",
                settings.identity_key_file.display(),
                id.certhash
            );
            if settings.listen.port() == 0 {
                println!("address: the UDP port is chosen at startup (kps.listen port 0)");
            } else {
                let adv = advertised_ips(&settings.public_ips, settings.listen);
                for ip in &adv.ips {
                    println!(
                        "address: {}",
                        format_address(*ip, settings.listen.port(), &id.certhash)
                    );
                }
            }
        }
        Ok(None) => println!(
            "identity: {} does not exist yet; it is created on first start (or with `nox-kps address`)",
            settings.identity_key_file.display()
        ),
        Err(e) => {
            eprintln!("nox-kps: {e}");
            return ExitCode::from(EXIT_CONFIG);
        }
    }
    if settings.public_ips.is_empty() {
        println!("note: kps.public_ips is empty; set it to the node's public IP for production");
    }
    for ip in settings.public_ips.iter().filter(|ip| is_non_public(**ip)) {
        println!("note: public IP {ip} is not publicly routable");
    }
    if let Some(b) = &settings.bundles {
        if !b.dir.is_dir() {
            eprintln!(
                "nox-kps: bundles.dir {} is not a directory",
                b.dir.display()
            );
            return ExitCode::from(EXIT_CONFIG);
        }
    }
    ExitCode::SUCCESS
}

fn address(source: &ConfigSource) -> ExitCode {
    let settings = match load_settings(source) {
        Ok(s) => s,
        Err(code) => return code,
    };
    if settings.listen.port() == 0 {
        eprintln!("nox-kps: kps.listen uses port 0; set a fixed UDP port to publish an address");
        return ExitCode::from(EXIT_CONFIG);
    }
    let loaded = match identity::load_or_create(&settings.identity_key_file) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("nox-kps: {e}");
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    if loaded.created {
        eprintln!(
            "created a new KPS identity key at {}; back it up with the node's secrets",
            settings.identity_key_file.display()
        );
    }
    let adv = advertised_ips(&settings.public_ips, settings.listen);
    if adv.detected {
        eprintln!("note: kps.public_ips is empty; printing detected addresses");
    }
    for ip in &adv.ips {
        println!(
            "{}",
            format_address(*ip, settings.listen.port(), &loaded.identity.certhash)
        );
    }
    ExitCode::SUCCESS
}

async fn healthcheck(source: &ConfigSource) -> ExitCode {
    let settings = match load_settings(source) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let result = match settings.metrics_listen {
        None => Err(HealthcheckError::Disabled),
        Some(mut addr) => {
            if addr.ip().is_unspecified() {
                addr.set_ip(std::net::IpAddr::from([127, 0, 0, 1]));
            }
            probe_health(addr, HEALTHCHECK_TIMEOUT).await
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nox-kps: unhealthy: {e}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}
