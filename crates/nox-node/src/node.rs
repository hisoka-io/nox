use crate::blockchain::executor::ChainExecutor;
use crate::blockchain::observer::ChainObserver;
use crate::blockchain::tx_manager::TransactionManager;
use crate::config::NoxConfig;
use crate::infra::event_bus::TokioEventBus;
use crate::infra::storage::SledRepository;
use crate::ingress::http_server::{IngressServer, IngressState};
use crate::ingress::response_buffer::ResponseBuffer;
use crate::ingress::response_router::ResponseRouter;
use crate::network::service::P2PService;
use crate::telemetry::adapter::MetricsAdapter;
use crate::telemetry::metrics::MetricsService;
use nox_core::events::NoxEvent;
use nox_core::models::topology::TopologySnapshot;
use nox_core::traits::{IEventPublisher, IEventSubscriber};

use crate::services::exit::ExitService;
use crate::services::mixing::{NoMixStrategy, PoissonMixStrategy};
use crate::services::network_manager::TopologyManager;
use crate::services::relayer::RelayerService;
use crate::services::traffic_shaping::TrafficShapingService;

use axum::{extract::State, middleware, routing::get, Json, Router};
use prometheus_client::encoding::text::encode;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;

#[derive(Clone)]
struct BenchAdminState {
    publisher: Arc<dyn IEventPublisher>,
}
use tracing::{error, info, warn};

pub struct NoxNode;

impl NoxNode {
    pub async fn run(config: NoxConfig) -> anyhow::Result<()> {
        info!("Starting NOX node (role: {:?})...", config.node_role);

        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let location = info.location().map_or_else(
                || "<unknown>".to_string(),
                |loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()),
            );
            let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = info.payload().downcast_ref::<String>() {
                s.clone()
            } else {
                "Box<dyn Any>".to_string()
            };
            // Use eprintln here because tracing may not be available during panic unwind
            eprintln!("PANIC at {location}: {payload}");
            default_hook(info);
        }));

        let shutdown_token = CancellationToken::new();
        let mut join_set = JoinSet::new();

        info!("Initializing Persistence Layer at {}...", config.db_path);
        let db = match SledRepository::new(&config.db_path) {
            Ok(d) => Arc::new(d),
            Err(e) => {
                error!("Database init failed: {}", e);
                return Err(anyhow::anyhow!(e));
            }
        };

        info!("Initializing Event Bus...");
        let event_bus = TokioEventBus::new(4096);
        let bus_publisher: Arc<dyn IEventPublisher> = Arc::new(event_bus.clone());
        let bus_subscriber: Arc<dyn IEventSubscriber> = Arc::new(event_bus.clone());

        let topology_manager = Arc::new(TopologyManager::with_cancel_token(
            db.clone(),
            bus_subscriber.clone(),
            None,
            shutdown_token.clone(),
        ));

        topology_manager.hydrate_from_storage().await;

        let node_id = format!("nox:{}", config.metrics_port);
        let bench_publisher = if config.benchmark_mode {
            Some(bus_publisher.clone())
        } else {
            None
        };
        let metrics_service = Self::spawn_metrics_with_admin(
            config.metrics_port,
            bus_subscriber.clone(),
            topology_manager.clone(),
            node_id,
            bench_publisher,
            config.min_pow_difficulty,
        );

        let start_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        metrics_service.node_start_time_seconds.set(start_epoch);

        let process_monitor =
            crate::telemetry::process::ProcessMonitor::new(metrics_service.clone(), start_epoch);
        process_monitor.record_build_info(
            env!("CARGO_PKG_VERSION"),
            &format!("{:?}", config.node_role),
        );
        join_set.spawn(async move {
            process_monitor.run().await;
        });

        let response_buffer = Arc::new(ResponseBuffer::new());
        if config.ingress_port > 0 {
            let ingress_state = Arc::new(IngressState {
                event_publisher: bus_publisher.clone(),
                response_buffer: response_buffer.clone(),
                metrics: metrics_service.clone(),
                long_poll_timeout: Duration::from_secs(30),
                min_pow_difficulty: config.min_pow_difficulty,
            });
            let ingress_router = IngressServer::router(ingress_state).layer(middleware::from_fn(
                crate::telemetry::version::version_header,
            ));
            let ingress_port = config.ingress_port;
            let ingress_shutdown = shutdown_token.clone();
            join_set.spawn(async move {
                let addr = SocketAddr::from(([0, 0, 0, 0], ingress_port));
                info!("HTTP Ingress: http://{}/api/v1/packets", addr);
                match tokio::net::TcpListener::bind(addr).await {
                    Ok(listener) => {
                        if let Err(e) = axum::serve(listener, ingress_router)
                            .with_graceful_shutdown(ingress_shutdown.cancelled_owned())
                            .await
                        {
                            error!("HTTP ingress server error: {}", e);
                        }
                    }
                    Err(e) => error!("Failed to bind ingress port {}: {}", ingress_port, e),
                }
            });

            let router = ResponseRouter::new(
                bus_subscriber.clone(),
                response_buffer,
                config.response_prune_interval_secs,
                metrics_service.clone(),
            )
            .with_cancel_token(shutdown_token.clone());
            join_set.spawn(async move {
                router.run().await;
            });
        }

        let chain_executor = if config.benchmark_mode {
            info!("Skipping Chain Executor (benchmark mode -- simulation exit service used).");
            None
        } else if config.node_role.is_exit_capable() {
            info!("Initializing Chain Executor (exit/full role)...");
            let cx = ChainExecutor::new(&config).await.map_err(|e| {
                anyhow::anyhow!("Failed to initialize Chain Executor (Wallet): {e}")
            })?;
            Some(Arc::new(cx))
        } else {
            info!("Skipping Chain Executor (relay role -- no wallet needed).");
            None
        };

        info!("Initializing P2P Transport...");
        let mut p2p_service = P2PService::new(
            &config,
            bus_publisher.clone(),
            bus_subscriber.clone(),
            db.clone(),
            metrics_service.clone(),
            topology_manager.clone(),
        )
        .await?
        .with_cancel_token(shutdown_token.clone());

        join_set.spawn(async move {
            p2p_service.run().await;
        });

        let topology_clone = topology_manager.clone();
        join_set.spawn(async move {
            topology_clone.run().await;
        });

        if !config.bootstrap_topology_urls.is_empty() {
            info!(
                "Attempting topology bootstrap from {} seed URL(s)...",
                config.bootstrap_topology_urls.len()
            );
            let bootstrap_result =
                Self::bootstrap_topology(&config.bootstrap_topology_urls, &topology_manager).await;
            match bootstrap_result {
                Ok(count) => info!("Topology bootstrap succeeded: {} nodes loaded", count),
                Err(e) => warn!(
                    "Topology bootstrap failed ({}). Falling back to ChainObserver replay.",
                    e
                ),
            }
        }

        if config.topology_api_port > 0 {
            let topo_api_tm = topology_manager.clone();
            let topo_api_port = config.topology_api_port;
            let topo_shutdown = shutdown_token.clone();
            join_set.spawn(async move {
                let app = Router::new()
                    .route("/topology", get(handle_topology_request))
                    .layer(permissive_cors_layer())
                    .layer(middleware::from_fn(
                        crate::telemetry::version::version_header,
                    ))
                    .with_state((topo_api_tm, config.min_pow_difficulty));
                let addr = SocketAddr::from(([0, 0, 0, 0], topo_api_port));
                info!("Public topology API: http://{}/topology", addr);
                match tokio::net::TcpListener::bind(addr).await {
                    Ok(listener) => {
                        if let Err(e) = axum::serve(listener, app)
                            .with_graceful_shutdown(topo_shutdown.cancelled_owned())
                            .await
                        {
                            error!("Public topology API server error: {}", e);
                        }
                    }
                    Err(e) => error!(
                        "Failed to bind public topology API port {}: {}",
                        topo_api_port, e
                    ),
                }
            });
        }

        let traffic_shaping = TrafficShapingService::new(
            config.clone(),
            topology_manager.clone(),
            bus_publisher.clone(),
            metrics_service.clone(),
        )
        .with_cancel_token(shutdown_token.clone());
        join_set.spawn(async move {
            traffic_shaping.run().await;
        });

        let mix_delay = config.relayer.mix_delay_ms;
        let mix_strategy: Arc<dyn nox_core::traits::IMixStrategy> = if mix_delay > 0.0 {
            Arc::new(PoissonMixStrategy::new(mix_delay))
        } else {
            Arc::new(NoMixStrategy)
        };
        let replay_db = {
            let bloom_path = std::path::Path::new(&config.db_path).join("bloom.bin");
            let filter = crate::infra::persistence::rotational_bloom::RotationalBloomFilter::new(
                config.relayer.bloom_capacity,
                0.001, // FP Rate
                std::time::Duration::from_secs(config.relayer.replay_window),
            )
            .with_file_persistence(&bloom_path);

            if let Err(e) = filter.restore_from_file().await {
                error!(
                    "Failed to restore replay filter from file: {e}. Starting with empty filter."
                );
            }

            info!(
                capacity = config.relayer.bloom_capacity,
                path = %bloom_path.display(),
                "Replay filter initialized (flat file persistence)"
            );

            Arc::new(filter)
        };
        let relayer_service = RelayerService::new(
            config.clone(),
            bus_subscriber.clone(),
            bus_publisher.clone(),
            replay_db,
            mix_strategy,
            metrics_service.clone(),
        )
        .with_cancel_token(shutdown_token.clone());
        join_set.spawn(async move {
            if let Err(e) = relayer_service.run().await {
                error!("Relayer failed to start: {}", e);
            }
        });

        let config_chain = config.clone();
        let publisher_chain = bus_publisher.clone();
        let db_chain = db.clone();
        let metrics_chain = metrics_service.clone();
        let observer_shutdown = shutdown_token.clone();
        join_set.spawn(async move {
            if config_chain.registry_contract_address
                == "0x0000000000000000000000000000000000000000"
            {
                warn!("Registry Contract Address not set. Chain Sync disabled.");
                return;
            }

            match ChainObserver::new(
                &config_chain,
                &config_chain.registry_contract_address,
                publisher_chain,
                db_chain,
                metrics_chain,
            ) {
                Ok(observer) => {
                    observer.with_cancel_token(observer_shutdown).start().await;
                }
                Err(e) => error!("Chain Observer failed: {}", e),
            }
        });

        {
            let compaction_db = db.clone();
            let compaction_shutdown = shutdown_token.clone();
            join_set.spawn(async move {
                const COMPACTION_INTERVAL: std::time::Duration =
                    std::time::Duration::from_secs(6 * 3600);
                loop {
                    tokio::select! {
                        () = tokio::time::sleep(COMPACTION_INTERVAL) => {
                            info!("Running periodic sled compaction...");
                            if let Err(e) = compaction_db.compact().await {
                                warn!("Sled compaction failed: {e}");
                            } else {
                                info!("Sled compaction completed.");
                            }
                        }
                        () = compaction_shutdown.cancelled() => {
                            break;
                        }
                    }
                }
            });
        }

        if config.benchmark_mode && config.node_role.is_exit_capable() {
            let has_rpc = !config.eth_rpc_url.is_empty();
            info!(
                rpc_proxy = has_rpc,
                "Initializing Exit Service in benchmark/simulation mode (HTTP + Echo{})...",
                if has_rpc { " + RPC" } else { "" }
            );
            let traffic_handler = Arc::new(crate::services::handlers::traffic::TrafficHandler {
                metrics: metrics_service.clone(),
            });
            let response_packer = Arc::new(
                crate::services::response_packer::ResponsePacker::new()
                    .with_metrics(metrics_service.clone()),
            );
            let pending_map = ExitService::new_pending_map();
            let surb_acc = ExitService::new_surb_accumulator();
            let stash = ExitService::make_stash_closure(
                pending_map.clone(),
                surb_acc.clone(),
                response_packer.clone(),
                bus_publisher.clone(),
            );
            let http_handler = Arc::new(
                crate::services::handlers::http::HttpHandler::new(
                    config.http.clone(),
                    response_packer.clone(),
                    bus_publisher.clone(),
                    metrics_service.clone(),
                )
                .with_stash_remaining(stash),
            );
            let echo_handler = Arc::new(crate::services::handlers::echo::EchoHandler::new(
                response_packer.clone(),
                bus_publisher.clone(),
            ));

            let exit_service = if has_rpc {
                let rpc_handler = crate::services::handlers::rpc::RpcHandler::new_simulation(
                    response_packer,
                    bus_publisher.clone(),
                    &config.eth_rpc_url,
                    metrics_service.clone(),
                )
                .map_err(|e| anyhow::anyhow!("Failed to create RPC handler: {e}"))?;

                ExitService::simulation_with_rpc(
                    bus_subscriber.clone(),
                    traffic_handler,
                    http_handler,
                    echo_handler,
                    Arc::new(rpc_handler),
                    metrics_service.clone(),
                )
            } else {
                ExitService::simulation(
                    bus_subscriber.clone(),
                    traffic_handler,
                    http_handler,
                    echo_handler,
                    metrics_service.clone(),
                )
            };

            let exit_service = exit_service
                .with_pending_replenishments(pending_map)
                .with_surb_accumulator(surb_acc)
                .with_publisher(bus_publisher.clone())
                .with_cancel_token(shutdown_token.clone());
            join_set.spawn(async move {
                exit_service.run().await;
            });
        } else if let Some(ref executor) = chain_executor {
            info!("Initializing Transaction Manager (exit/full role)...");
            let tx_manager = match TransactionManager::new(
                executor.clone(),
                db.clone(),
                metrics_service.clone(),
            )
            .await
            {
                Ok(m) => Arc::new(m.with_cancel_token(shutdown_token.clone())),
                Err(e) => return Err(anyhow::anyhow!("TxManager init failed: {e}")),
            };

            let tx_manager_monitor = tx_manager.clone();
            join_set.spawn(async move {
                tx_manager_monitor.run_monitor().await;
            });

            info!("Initializing Exit Service (exit/full role)...");
            let price_client = Arc::new(
                crate::price::client::PriceClient::new(&config.oracle_url)
                    .with_metrics(metrics_service.clone()),
            );

            let mut eth_handler =
                crate::services::handlers::ethereum::EthereumHandler::from_config(
                    executor.clone(),
                    tx_manager.clone(),
                    metrics_service.clone(),
                    config.min_profit_margin_percent,
                    price_client,
                    &config.nox_reward_pool_address,
                    config.max_broadcast_tx_size,
                )?;

            for token in &config.tokens {
                let addr = token
                    .address
                    .parse::<ethers::types::Address>()
                    .map_err(|e| {
                        anyhow::anyhow!("Invalid token address '{}': {e}", token.address)
                    })?;
                eth_handler.register_token(addr, &token.symbol, token.decimals, &token.price_id);
                info!(
                    address = %token.address,
                    symbol = %token.symbol,
                    decimals = token.decimals,
                    price_id = %token.price_id,
                    "Registered token in profitability engine"
                );
            }

            let ethereum_handler = Arc::new(eth_handler);
            let traffic_handler = Arc::new(crate::services::handlers::traffic::TrafficHandler {
                metrics: metrics_service.clone(),
            });

            let response_packer = Arc::new(
                crate::services::response_packer::ResponsePacker::new()
                    .with_metrics(metrics_service.clone()),
            );
            let pending_map = ExitService::new_pending_map();
            let surb_acc = ExitService::new_surb_accumulator();
            let stash = ExitService::make_stash_closure(
                pending_map.clone(),
                surb_acc.clone(),
                response_packer.clone(),
                bus_publisher.clone(),
            );

            let http_handler = Arc::new(
                crate::services::handlers::http::HttpHandler::new(
                    config.http.clone(),
                    response_packer.clone(),
                    bus_publisher.clone(),
                    metrics_service.clone(),
                )
                .with_stash_remaining(stash),
            );
            let echo_handler = Arc::new(crate::services::handlers::echo::EchoHandler::new(
                response_packer.clone(),
                bus_publisher.clone(),
            ));
            let rpc_handler = Arc::new(
                crate::services::handlers::rpc::RpcHandler::new(
                    executor.clone(),
                    response_packer.clone(),
                    bus_publisher.clone(),
                    &config.eth_rpc_url,
                    metrics_service.clone(),
                )
                .map_err(|e| anyhow::anyhow!("RPC handler init failed: {e}"))?,
            );

            let exit_service = ExitService::with_all_handlers(
                bus_subscriber.clone(),
                ethereum_handler,
                traffic_handler,
                Some(http_handler),
                Some(echo_handler),
                Some(rpc_handler),
                config.relayer.fragmentation.clone(),
                metrics_service.clone(),
            )
            .with_publisher(bus_publisher.clone())
            .with_pending_replenishments(pending_map)
            .with_surb_accumulator(surb_acc)
            .with_cancel_token(shutdown_token.clone());
            join_set.spawn(async move {
                exit_service.run().await;
            });
        } else {
            info!(
                "Skipping Transaction Manager and Exit Service (relay role -- no chain execution)."
            );
        }

        let startup_timestamp =
            match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => d.as_secs(),
                Err(e) => {
                    error!("System clock before UNIX_EPOCH: {e}");
                    0
                }
            };
        let startup_event = NoxEvent::NodeStarted {
            timestamp: startup_timestamp,
        };
        if let Err(e) = bus_publisher.publish(startup_event) {
            warn!(error = %e, "Failed to publish NodeStarted event (non-critical)");
        }

        let task_count = join_set.len();
        info!(
            "Node Ready (role: {:?}). {} services running.",
            config.node_role, task_count
        );

        #[cfg(unix)]
        {
            // Safety: SIGTERM handler registration only fails if called outside a Tokio runtime,
            // which is impossible here (we're inside NoxNode::run, an async fn).
            #[allow(clippy::expect_used)]
            let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to register SIGTERM handler -- requires Tokio runtime");
            tokio::select! {
                result = signal::ctrl_c() => {
                    match result {
                        Ok(()) => info!("Received SIGINT (ctrl+c)."),
                        Err(err) => error!("Unable to listen for shutdown signal: {}", err),
                    }
                }
                _ = sigterm.recv() => {
                    info!("Received SIGTERM.");
                }
                () = shutdown_token.cancelled() => {
                    info!("Shutdown initiated via cancellation token.");
                }
            }
        }
        #[cfg(not(unix))]
        {
            tokio::select! {
                result = signal::ctrl_c() => {
                    match result {
                        Ok(()) => info!("Received shutdown signal (ctrl+c)."),
                        Err(err) => error!("Unable to listen for shutdown signal: {}", err),
                    }
                }
                () = shutdown_token.cancelled() => {
                    info!("Shutdown initiated via cancellation token.");
                }
            }
        }

        shutdown_token.cancel();
        info!("Draining {} service tasks (30s timeout)...", join_set.len());

        let drain_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut completed = 0u32;
        let mut panicked = 0u32;

        loop {
            tokio::select! {
                result = join_set.join_next() => {
                    match result {
                        Some(Ok(())) => completed += 1,
                        Some(Err(e)) if e.is_panic() => {
                            panicked += 1;
                            error!("Service task panicked during shutdown: {}", e);
                        }
                        Some(Err(e)) => {
                            completed += 1;
                            warn!("Service task ended with error: {}", e);
                        }
                        None => {
                            break;
                        }
                    }
                }
                () = tokio::time::sleep_until(drain_deadline) => {
                    let remaining = join_set.len();
                    warn!(
                        "Shutdown timeout: {} tasks did not finish within 30s. Aborting them.",
                        remaining
                    );
                    join_set.abort_all();
                    while let Some(result) = join_set.join_next().await {
                        match result {
                            Err(e) if e.is_panic() => {
                                panicked += 1;
                                error!("Service task panicked: {}", e);
                            }
                            Ok(()) | Err(_) => completed += 1,
                        }
                    }
                    break;
                }
            }
        }

        if panicked > 0 {
            error!(
                "Shutdown complete: {} tasks finished, {} panicked.",
                completed, panicked
            );
        } else {
            info!(
                "Shutdown complete: all {} tasks finished cleanly.",
                completed
            );
        }

        Ok(())
    }
    async fn bootstrap_topology(
        seed_urls: &[String],
        topology_manager: &Arc<TopologyManager>,
    ) -> Result<usize, String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

        let mut last_error = String::new();
        for url in seed_urls {
            match client.get(url).send().await {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        last_error = format!("{url}: HTTP {}", resp.status());
                        warn!("Bootstrap seed {url} returned HTTP {}", resp.status());
                        continue;
                    }
                    match resp.json::<TopologySnapshot>().await {
                        Ok(snapshot) => {
                            let node_count = snapshot.nodes.len();
                            if node_count == 0 {
                                last_error = format!("{url}: empty snapshot");
                                warn!("Bootstrap seed {url} returned empty topology");
                                continue;
                            }
                            let addresses: Vec<String> =
                                snapshot.nodes.iter().map(|n| n.address.clone()).collect();
                            let computed =
                                TopologyManager::compute_topology_fingerprint(&addresses);
                            let expected = match hex::decode(&snapshot.fingerprint) {
                                Ok(bytes) => bytes,
                                Err(e) => {
                                    last_error = format!("{url}: invalid hex fingerprint: {e}");
                                    warn!("{}", last_error);
                                    continue;
                                }
                            };
                            if computed.as_slice() != expected.as_slice() {
                                last_error = format!(
                                    "{url}: fingerprint mismatch (computed={}, received={})",
                                    hex::encode(computed),
                                    snapshot.fingerprint
                                );
                                warn!("{}", last_error);
                                continue;
                            }
                            topology_manager.hydrate_from_snapshot(snapshot.nodes).await;
                            return Ok(node_count);
                        }
                        Err(e) => {
                            last_error = format!("{url}: JSON parse error: {e}");
                            warn!("Bootstrap seed {url}: failed to parse response: {e}");
                        }
                    }
                }
                Err(e) => {
                    last_error = format!("{url}: connection error: {e}");
                    warn!("Bootstrap seed {url}: connection failed: {e}");
                }
            }
        }
        Err(format!(
            "All {} seed URLs failed. Last: {last_error}",
            seed_urls.len()
        ))
    }

    pub fn spawn_metrics(
        port: u16,
        bus_subscriber: Arc<dyn IEventSubscriber>,
        topology_manager: Arc<TopologyManager>,
        node_id: String,
    ) -> MetricsService {
        Self::spawn_metrics_with_admin(port, bus_subscriber, topology_manager, node_id, None, 0)
    }

    /// Pass `Some(publisher)` to enable benchmark-only admin topology registration.
    pub fn spawn_metrics_with_admin(
        port: u16,
        bus_subscriber: Arc<dyn IEventSubscriber>,
        topology_manager: Arc<TopologyManager>,
        node_id: String,
        bench_publisher: Option<Arc<dyn IEventPublisher>>,
        pow_difficulty: u32,
    ) -> MetricsService {
        info!("Initializing Observability...");
        let metrics_service = MetricsService::new();
        let metrics_registry = metrics_service.get_registry();

        let sse_bus = bus_subscriber.clone();
        let metrics_adapter = MetricsAdapter::new(metrics_service.clone(), bus_subscriber);
        tokio::spawn(async move {
            metrics_adapter.run().await;
        });

        let metrics_addr = SocketAddr::from(([0, 0, 0, 0], port));
        let json_metrics = metrics_service.clone();
        let mut metrics_app = Router::new()
            .route(
                "/metrics",
                get(move || {
                    let registry = metrics_registry.clone();
                    async move {
                        let mut buffer = String::new();
                        let reg_lock = registry.lock();
                        if let Err(e) = encode(&mut buffer, &reg_lock) {
                            error!("Failed to encode metrics: {}", e);
                            return String::new();
                        }
                        buffer
                    }
                }),
            )
            .route(
                "/metrics/json",
                get(move || {
                    let m = json_metrics.clone();
                    async move { axum::Json(m.to_json()) }
                }),
            )
            .route("/topology", get(handle_topology_request))
            .route("/events", get(crate::telemetry::sse::handle_sse_events))
            .layer(axum::extract::Extension(node_id))
            .layer(axum::extract::Extension(sse_bus))
            .layer(permissive_cors_layer())
            .layer(middleware::from_fn(
                crate::telemetry::version::version_header,
            ))
            .with_state((topology_manager, pow_difficulty));

        if let Some(publisher) = bench_publisher {
            let admin_state = BenchAdminState { publisher };
            let admin_router = Router::new()
                .route(
                    "/admin/topology/register",
                    axum::routing::post(handle_admin_topology_register),
                )
                .with_state(admin_state);
            metrics_app = metrics_app.merge(admin_router);
            info!("Benchmark admin endpoint enabled: POST http://{metrics_addr}/admin/topology/register");
        }

        tokio::spawn(async move {
            info!(
                "API Endpoints: http://{}/metrics, http://{}/topology, http://{}/events",
                metrics_addr, metrics_addr, metrics_addr
            );
            match tokio::net::TcpListener::bind(metrics_addr).await {
                Ok(listener) => {
                    if let Err(e) = axum::serve(listener, metrics_app).await {
                        error!("HTTP server error: {}", e);
                    }
                }
                Err(e) => error!("Failed to bind HTTP port {}: {}", port, e),
            }
        });
        metrics_service
    }
}

async fn handle_topology_request(
    State((topology_manager, pow_difficulty)): State<(Arc<TopologyManager>, u32)>,
) -> Json<TopologySnapshot> {
    let nodes = topology_manager.get_all_nodes();
    let fingerprint = topology_manager.get_current_fingerprint();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Json(TopologySnapshot {
        nodes,
        fingerprint: hex::encode(fingerprint),
        timestamp,
        block_number: 0,
        pow_difficulty,
    })
}

#[derive(serde::Deserialize)]
struct AdminTopologyRegisterRequest {
    address: String,
    sphinx_key: String,
    url: String,
    #[serde(default = "default_stake")]
    stake: String,
    #[serde(default = "default_role_full")]
    role: u8,
    #[serde(default)]
    ingress_url: Option<String>,
    #[serde(default)]
    metadata_url: Option<String>,
}

fn default_stake() -> String {
    "1000".to_string()
}

fn default_role_full() -> u8 {
    3
}

async fn handle_admin_topology_register(
    State(state): State<BenchAdminState>,
    axum::extract::Json(req): axum::extract::Json<AdminTopologyRegisterRequest>,
) -> axum::http::StatusCode {
    match state.publisher.publish(NoxEvent::RelayerRegistered {
        address: req.address.clone(),
        sphinx_key: req.sphinx_key,
        url: req.url,
        stake: req.stake,
        role: req.role,
        ingress_url: req.ingress_url,
        metadata_url: req.metadata_url,
    }) {
        Ok(_receivers) => {
            info!(address = %req.address, "Admin: topology node registered");
            axum::http::StatusCode::CREATED
        }
        Err(e) => {
            error!(error = %e, "Admin: failed to publish RelayerRegistered");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

fn permissive_cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any)
}
