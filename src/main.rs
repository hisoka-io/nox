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
}

#[tokio::main]
#[allow(clippy::expect_used)]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if let Some(Command::Keygen) = args.command {
        return run_keygen();
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
