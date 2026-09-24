#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use clap::{Parser, Subcommand};
use nox_node::{NoxConfig, NoxNode};
use tracing::{error, info};
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    #[arg(long, env = "NOX_LOG_DIR")]
    log_dir: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    Keygen,
    /// Load and validate the config (file + `NOX__*` env), print the public
    /// identity it derives, and exit without starting the node.
    CheckConfig,
}

#[tokio::main]
#[allow(clippy::expect_used)]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Some(Command::Keygen) => return run_keygen(),
        Some(Command::CheckConfig) => return run_check_config(&args.config),
        None => {}
    }

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if let Some(ref log_dir) = args.log_dir {
        use tracing_appender::rolling::{RollingFileAppender, Rotation};

        let log_path = std::path::Path::new(log_dir);
        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::create_dir_all(log_path);

        let debug_appender = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix("debug.log")
            .max_log_files(3)
            .build(log_path)
            .expect("failed to create debug log appender");
        let info_appender = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix("info.log")
            .max_log_files(7)
            .build(log_path)
            .expect("failed to create info log appender");
        let warn_appender = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix("warn.log")
            .max_log_files(7)
            .build(log_path)
            .expect("failed to create warn log appender");
        let error_appender = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix("error.log")
            .max_log_files(14)
            .build(log_path)
            .expect("failed to create error log appender");

        let file_writer = debug_appender
            .with_max_level(tracing::Level::DEBUG)
            .and(info_appender.with_max_level(tracing::Level::INFO))
            .and(warn_appender.with_max_level(tracing::Level::WARN))
            .and(error_appender.with_max_level(tracing::Level::ERROR));

        let console_writer = std::io::stderr.with_max_level(tracing::Level::INFO);

        let combined = file_writer.and(console_writer);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(combined)
                    .with_ansi(false),
            )
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    info!(" NOX Relayer Node Booting...");

    let config = match NoxConfig::load(&args.config) {
        Ok(c) => {
            info!(" Configuration loaded.");
            c
        }
        Err(e) => {
            error!(" Config Load Failed: {}", e);
            return Err(anyhow::anyhow!("Config error: {e}"));
        }
    };

    if let Err(errors) = config.validate() {
        for e in &errors {
            error!("Config validation error: {}", e);
        }
        return Err(anyhow::anyhow!(
            "Configuration validation failed with {} error(s)",
            errors.len()
        ));
    }
    info!(" Configuration validated.");

    NoxNode::run(config).await
}

/// Prints only public values; private keys are parsed but never echoed.
fn run_check_config(config_path: &str) -> anyhow::Result<()> {
    use ethers::signers::{LocalWallet, Signer};
    use x25519_dalek::PublicKey as X25519PublicKey;

    // The loader treats the file as optional; a wrong mount would otherwise
    // validate the built-in defaults instead of the operator's file.
    if !std::path::Path::new(config_path).is_file() {
        anyhow::bail!("config file {config_path} not found");
    }
    let config = NoxConfig::load(config_path).map_err(|e| anyhow::anyhow!("Config error: {e}"))?;
    if let Err(errors) = config.validate() {
        for e in &errors {
            eprintln!("config error: {e}");
        }
        anyhow::bail!(
            "Configuration validation failed with {} error(s)",
            errors.len()
        );
    }

    for (name, path) in [
        ("db_path", &config.db_path),
        ("p2p_identity_path", &config.p2p_identity_path),
    ] {
        if !std::path::Path::new(path).is_absolute() {
            eprintln!(
                "warning: {name} = {path:?} is relative; the container runs as UID 10001 \
                 with no writable working directory, use a path under /var/lib/nox"
            );
        }
    }

    let sphinx_public = X25519PublicKey::from(&config.get_routing_key()?);
    println!("config: {config_path}");
    println!("node_role: {:?}", config.node_role);
    println!("chain_id: {}", config.chain_id);
    println!(
        "registry_contract_address: {}",
        config.registry_contract_address
    );
    println!("chain_start_block: {}", config.chain_start_block);
    println!(
        "bootstrap_topology_urls: {}",
        config.bootstrap_topology_urls.len()
    );
    println!(
        "sphinx_public_key: 0x{}",
        hex::encode(sphinx_public.as_bytes())
    );

    if config.p2p_private_key.is_empty() {
        println!(
            "p2p_peer_id: <from {} at startup>",
            config.p2p_identity_path
        );
    } else {
        let mut seed = hex::decode(&config.p2p_private_key)
            .map_err(|e| anyhow::anyhow!("p2p_private_key is not hex: {e}"))?;
        let keypair = libp2p::identity::Keypair::ed25519_from_bytes(&mut seed)
            .map_err(|e| anyhow::anyhow!("p2p_private_key is invalid: {e}"))?;
        println!("p2p_peer_id: {}", keypair.public().to_peer_id());
    }

    if !config.eth_wallet_private_key.is_empty() {
        let wallet: LocalWallet = config
            .eth_wallet_private_key
            .trim_start_matches("0x")
            .parse()
            .map_err(|e| anyhow::anyhow!("eth_wallet_private_key is invalid: {e}"))?;
        println!("eth_address: {:#x}", wallet.address());
    }

    if config.node_role.is_exit_capable() {
        println!(
            "nox_entry_point_address: {}",
            config.nox_entry_point_address
        );
        println!(
            "nox_reward_pool_address: {}",
            config.nox_reward_pool_address
        );
        println!("payment_adapters: {}", config.payment_adapters.len());
        println!("tokens: {}", config.tokens.len());
    }
    println!("configuration OK");
    Ok(())
}

fn run_keygen() -> anyhow::Result<()> {
    use ethers::signers::{LocalWallet, Signer};
    use rand::rngs::OsRng;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    let routing_secret = StaticSecret::random_from_rng(OsRng);
    let routing_private_hex = hex::encode(routing_secret.to_bytes());
    let sphinx_public = X25519PublicKey::from(&routing_secret);
    let sphinx_public_hex = hex::encode(sphinx_public.as_bytes());

    let p2p_keypair = libp2p::identity::Keypair::generate_ed25519();
    let p2p_peer_id = p2p_keypair.public().to_peer_id();
    let p2p_seed = match p2p_keypair.try_into_ed25519() {
        Ok(ed_kp) => hex::encode(&ed_kp.to_bytes()[..32]),
        Err(e) => return Err(anyhow::anyhow!("Ed25519 key extraction failed: {e}")),
    };

    let eth_key_bytes: [u8; 32] = rand::Rng::gen(&mut OsRng);
    let eth_private_hex = hex::encode(eth_key_bytes);
    let wallet = LocalWallet::from_bytes(&eth_key_bytes)
        .map_err(|e| anyhow::anyhow!("Wallet creation failed: {e}"))?;
    let eth_address = format!("{:#x}", wallet.address());

    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");

    println!("# NOX Node Keys");
    println!("# Generated: {now}");
    println!("# SAVE THIS OUTPUT. Private keys cannot be recovered.");
    println!("#");
    println!("# Paste the NOX__ lines into your .env file.");
    println!("# Share the public values when requesting registration.");
    println!();
    println!("# === Sphinx Routing Key (X25519) ===");
    println!("NOX__ROUTING_PRIVATE_KEY={routing_private_hex}");
    println!("# Public key (for registration): {sphinx_public_hex}");
    println!();
    println!("# === P2P Identity (Ed25519) ===");
    println!("NOX__P2P_PRIVATE_KEY={p2p_seed}");
    println!("# PeerId (for registration): {p2p_peer_id}");
    println!();
    println!("# === ETH Wallet (secp256k1) ===");
    println!("# Required for exit nodes. Relay nodes can leave empty.");
    println!("NOX__ETH_WALLET_PRIVATE_KEY={eth_private_hex}");
    println!("# Address (for registration): {eth_address}");

    Ok(())
}
