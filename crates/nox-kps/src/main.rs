//! `nox-kps` command line.
//!
//! ```text
//! nox-kps init            create the identity key once, print the addresses
//! nox-kps run             serve (the default)
//! nox-kps address         print <ip>:<port>:<certhash> and the metadataUrl string
//! nox-kps check-config    validate the configuration and the key file
//! nox-kps bundle add F    publish a worker bundle under its keccak-256 name
//! nox-kps bundle list     list the verified bundles and their kps: resolvers
//! nox-kps bundle verify   re-hash every bundle file; non-zero exit on a mismatch
//! nox-kps healthcheck     exit 0 when /healthz answers 200 (--kps: dial over QUIC too)
//! ```

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use nox_kps::bundles::{add_bundle, bundle_path, BundleSettings, BundleStore};
use nox_kps::config::{summary, ConfigSource, RawConfig, Settings, DEFAULT_CONFIG_PATH};
use nox_kps::healthcheck::{admin_target, local_kps_address, probe_kps};
use nox_kps::identity::{self, format_address, metadata_url};
use nox_kps::metrics::probe_health;
use tracing::{error, info, warn};

/// Exit status for an invalid configuration or key file.
const EXIT_CONFIG: u8 = 2;
/// Exit status when the server, a probe or a bundle check fails.
const EXIT_FAILURE: u8 = 1;

#[derive(Parser)]
#[command(
    name = "nox-kps",
    version,
    about = "KPS entry sidecar for Nox nodes: WebRTC + QUIC on one UDP port, proxied to the node's loopback ingress"
)]
struct Cli {
    /// TOML config file. Without this flag, /etc/nox-kps/config.toml is used
    /// when it exists; otherwise built-in defaults plus `NOX_KPS__*` variables.
    #[arg(short, long, env = "NOX_KPS_CONFIG", global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Create the identity key (once) and print the addresses to publish
    Init,
    /// Run the sidecar (default)
    Run,
    /// Print the KPS address(es) and the registry metadataUrl string
    Address,
    /// Validate the configuration and the identity key file
    CheckConfig,
    /// Manage worker bundles served at /keccak/<hh>/<62 hex>
    Bundle {
        #[command(subcommand)]
        action: BundleAction,
    },
    /// Exit 0 when the admin /healthz answers 200 (container health checks)
    Healthcheck {
        /// Also dial the local KPS listener over QUIC and GET /health end to end
        #[arg(long)]
        kps: bool,
    },
}

#[derive(Subcommand)]
enum BundleAction {
    /// Publish a file under its keccak-256 name (atomic, read-only)
    Add { file: PathBuf },
    /// List the bundles that verify, with their kps: resolver strings
    List,
    /// Re-hash every bundle file; exit 1 when any file does not match its name
    Verify,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let source = match cli.config {
        Some(path) => ConfigSource::Explicit(path),
        None => ConfigSource::Default(PathBuf::from(DEFAULT_CONFIG_PATH)),
    };
    let settings = match RawConfig::load(&source).and_then(|raw| raw.validate()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("nox-kps: {e}");
            return ExitCode::from(EXIT_CONFIG);
        }
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
        Command::Init => init(&settings),
        Command::Run => runtime.block_on(run(&source, settings)),
        Command::Address => address(&settings),
        Command::CheckConfig => check_config(&source, &settings),
        Command::Bundle { action } => bundle(&settings, &action),
        Command::Healthcheck { kps } => runtime.block_on(healthcheck(&settings, kps)),
    }
}

fn addresses(settings: &Settings, certhash: &str) -> Vec<String> {
    settings
        .advertise
        .iter()
        .map(|ip| format_address(*ip, settings.listen.port(), certhash))
        .collect()
}

fn print_addresses(settings: &Settings, certhash: &str) {
    for addr in addresses(settings, certhash) {
        println!("address: {addr}");
        println!("metadataUrl: {}", metadata_url(&addr));
    }
}

fn init(settings: &Settings) -> ExitCode {
    if settings.listen.port() == 0 {
        eprintln!("nox-kps: listen uses port 0; set a fixed UDP port before publishing an address");
        return ExitCode::from(EXIT_CONFIG);
    }
    match identity::init(&settings.key_file) {
        Ok(id) => {
            println!("created KPS identity {}", settings.key_file.display());
            println!("certhash: {}", id.certhash);
            println!("config line: expected_certhash = \"{}\"", id.certhash);
            print_addresses(settings, &id.certhash);
            println!(
                "back up the key file with the node's secrets; publish the metadataUrl with updateMetadataUrl"
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("nox-kps: {e}");
            ExitCode::from(EXIT_CONFIG)
        }
    }
}

fn address(settings: &Settings) -> ExitCode {
    if settings.listen.port() == 0 {
        eprintln!("nox-kps: listen uses port 0; set a fixed UDP port to publish an address");
        return ExitCode::from(EXIT_CONFIG);
    }
    match identity::read_existing(&settings.key_file) {
        Ok(Some(id)) => {
            print_addresses(settings, &id.certhash);
            ExitCode::SUCCESS
        }
        Ok(None) => {
            eprintln!(
                "nox-kps: no identity key at {}; create it with `nox-kps init`",
                settings.key_file.display()
            );
            ExitCode::from(EXIT_CONFIG)
        }
        Err(e) => {
            eprintln!("nox-kps: {e}");
            ExitCode::from(EXIT_CONFIG)
        }
    }
}

fn check_config(source: &ConfigSource, settings: &Settings) -> ExitCode {
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
    for (key, value) in summary(settings) {
        println!("  {key}: {value}");
    }
    match identity::read_existing(&settings.key_file) {
        Ok(Some(id)) => {
            if let Err(e) = identity::check_private(&settings.key_file) {
                eprintln!("nox-kps: {e}");
                return ExitCode::from(EXIT_CONFIG);
            }
            if let Some(expected) = settings.expected_certhash.as_deref() {
                if expected != id.certhash {
                    eprintln!(
                        "nox-kps: {}",
                        nox_kps::error::IdentityError::CerthashMismatch {
                            path: settings.key_file.clone(),
                            expected: expected.to_string(),
                            actual: id.certhash.clone(),
                        }
                    );
                    return ExitCode::from(EXIT_CONFIG);
                }
            }
            println!(
                "identity: {} (certhash {})",
                settings.key_file.display(),
                id.certhash
            );
            if settings.listen.port() == 0 {
                println!("address: the UDP port is chosen at startup (listen port 0)");
            } else {
                print_addresses(settings, &id.certhash);
            }
        }
        Ok(None) => println!(
            "identity: {} does not exist yet; create it once with `nox-kps init`",
            settings.key_file.display()
        ),
        Err(e) => {
            eprintln!("nox-kps: {e}");
            return ExitCode::from(EXIT_CONFIG);
        }
    }
    match nox_kps::preflight::scan_host() {
        Ok(findings) => {
            for finding in &findings {
                println!("warning: {}", nox_kps::preflight::describe(finding));
            }
        }
        Err(e) => println!("warning: cannot list network interfaces for the loopback check: {e}"),
    }
    if settings.expected_certhash.is_none() {
        println!(
            "note: expected_certhash is empty; `run` needs it (copy the certhash `init` printed)"
        );
    }
    if let Some(dir) = &settings.keccak_dir {
        if !dir.is_dir() {
            eprintln!(
                "nox-kps: keccak_dir {} is not a directory; create it or set keccak_dir = \"\"",
                dir.display()
            );
            return ExitCode::from(EXIT_CONFIG);
        }
    }
    ExitCode::SUCCESS
}

fn bundle_settings(settings: &Settings) -> Result<BundleSettings, ExitCode> {
    let Some(dir) = &settings.keccak_dir else {
        eprintln!("nox-kps: keccak_dir is empty; set it to manage worker bundles");
        return Err(ExitCode::from(EXIT_CONFIG));
    };
    Ok(BundleSettings {
        dir: dir.clone(),
        max_bundle_bytes: settings.limits.max_bundle_bytes,
        max_bundles: settings.limits.max_bundles,
        gzip: false,
    })
}

/// `kps:<address>/keccak/<hh>/<62 hex>` per advertised IP, when the identity exists.
fn resolvers(settings: &Settings, hash: &str) -> Vec<String> {
    match identity::read_existing(&settings.key_file) {
        Ok(Some(id)) => addresses(settings, &id.certhash)
            .iter()
            .map(|a| format!("kps:{a}{}", bundle_path(hash)))
            .collect(),
        _ => Vec::new(),
    }
}

fn bundle(settings: &Settings, action: &BundleAction) -> ExitCode {
    let bs = match bundle_settings(settings) {
        Ok(bs) => bs,
        Err(code) => return code,
    };
    match action {
        BundleAction::Add { file } => bundle_add(settings, &bs.dir, file, bs.max_bundle_bytes),
        BundleAction::List | BundleAction::Verify => {
            let (store, report) = match BundleStore::load(bs) {
                Ok(loaded) => loaded,
                Err(e) => {
                    eprintln!("nox-kps: {e}");
                    return ExitCode::from(EXIT_FAILURE);
                }
            };
            for hash in store.hashes() {
                let size = hex_to_array(&hash)
                    .and_then(|h| store.get(&h))
                    .map_or(0, |b| b.identity.len());
                println!("{hash} {size} bytes");
                for r in resolvers(settings, &hash) {
                    println!("  {r}");
                }
            }
            for path in &report.mismatched {
                eprintln!(
                    "MISMATCH {}: keccak-256 of the bytes differs from the file name",
                    path.display()
                );
            }
            for path in &report.skipped {
                eprintln!(
                    "SKIPPED {}: over limits.max_bundle_bytes or limits.max_bundles",
                    path.display()
                );
            }
            let failed = matches!(action, BundleAction::Verify)
                && !(report.mismatched.is_empty() && report.skipped.is_empty());
            if failed {
                ExitCode::from(EXIT_FAILURE)
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}

fn bundle_add(settings: &Settings, dir: &Path, file: &Path, max: usize) -> ExitCode {
    match add_bundle(dir, file, max) {
        Ok(added) => {
            let verb = if added.created {
                "added"
            } else {
                "already present"
            };
            println!("{verb}: {} ({})", added.hash, added.path.display());
            for r in resolvers(settings, &added.hash) {
                println!("resolver: {r}");
            }
            println!("running servers pick it up at the next rescan (limits.bundle_rescan_secs)");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("nox-kps: {e}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

fn hex_to_array(hash: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(hash, &mut out).ok()?;
    Some(out)
}

async fn run(source: &ConfigSource, settings: Settings) -> ExitCode {
    if let Err(e) = nox_kps::telemetry::init(&settings.log_filter, settings.log_format) {
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
        "KPS listener on UDP {listen} (port {}): WebRTC for browsers and QUIC for native clients",
        server.port()
    );
    info!(
        certhash = server.certhash(),
        "published addresses (clients dial them directly):"
    );
    for addr in server.addresses() {
        info!("  {addr}");
    }
    info!(
        "admin endpoint on http://{0}/metrics and http://{0}/healthz",
        server.admin_addr()
    );

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

async fn healthcheck(settings: &Settings, kps: bool) -> ExitCode {
    let timeout = settings.limits.healthcheck_timeout;
    if let Err(e) = probe_health(admin_target(settings), timeout).await {
        eprintln!("nox-kps: unhealthy: {e}");
        return ExitCode::from(EXIT_FAILURE);
    }
    if kps {
        let probe = match local_kps_address(settings) {
            Ok(addr) => probe_kps(&addr, timeout).await,
            Err(e) => Err(e),
        };
        if let Err(e) = probe {
            eprintln!("nox-kps: unhealthy: {e}");
            return ExitCode::from(EXIT_FAILURE);
        }
    }
    ExitCode::SUCCESS
}
