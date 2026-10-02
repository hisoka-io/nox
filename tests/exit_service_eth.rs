//! ExitService + Ethereum handler dispatch tests (requires `dev-node` feature).

#![cfg(feature = "dev-node")]

use ethers::prelude::*;
use nox_core::{
    models::payloads::{encode_payload, RelayerPayload, ServiceRequest},
    IEventPublisher, IEventSubscriber, IStorageRepository, NoxEvent, PaidQuoteRequestV2,
};
use nox_crypto::{PathHop, Surb};
use nox_node::{
    blockchain::{executor::ChainExecutor, tx_manager::TransactionManager},
    config::HttpConfig,
    price::client::PriceClient,
    services::{
        exit::ExitService,
        handlers::{echo::EchoHandler, ethereum::EthereumHandler, traffic::TrafficHandler},
        response_packer::ResponsePacker,
    },
    telemetry::metrics::MetricsService,
    NoxConfig, SledRepository, TokioEventBus,
};
use std::{str::FromStr, sync::Arc, time::Duration};
use tempfile::tempdir;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

const TEST_PRIVATE_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const TEST_POOL: &str = "0x1234567890123456789012345678901234567890";

async fn make_executor() -> Arc<ChainExecutor> {
    let mut cfg = NoxConfig::default();
    cfg.benchmark_mode = true;
    cfg.chain_id = 31337;
    cfg.eth_wallet_private_key = TEST_PRIVATE_KEY.to_string();
    Arc::new(ChainExecutor::new(&cfg).await.expect("executor"))
}

async fn make_tx_manager(exec: Arc<ChainExecutor>) -> Arc<TransactionManager> {
    let dir = tempdir().expect("tempdir");
    let storage = Arc::new(SledRepository::new(dir.path()).expect("sled"));
    Arc::new(
        TransactionManager::new(
            exec,
            storage,
            MetricsService::new(),
            nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
        )
        .await
        .expect("tx_manager"),
    )
}

async fn make_ethereum_handler(price_uri: &str) -> Arc<EthereumHandler> {
    let exec = make_executor().await;
    let tx_mgr = make_tx_manager(exec.clone()).await;
    let pool = Address::from_str(TEST_POOL).expect("pool address");
    Arc::new(EthereumHandler::new(
        exec,
        tx_mgr,
        MetricsService::new(),
        10,
        Arc::new(PriceClient::new(price_uri, Default::default()).expect("price client")),
        pool,
        128 * 1024,
    ))
}

async fn make_quote_handler(
    price_uri: &str,
) -> (Arc<EthereumHandler>, Arc<SledRepository>, tempfile::TempDir) {
    let entry_point = Address::from_low_u64_be(11);
    let adapter = Address::from_low_u64_be(12);
    let fee_asset = Address::from_low_u64_be(13);
    let pool = Address::from_low_u64_be(14);
    let mut config = NoxConfig::default();
    config.benchmark_mode = true;
    config.chain_id = 31_337;
    config.eth_wallet_private_key = TEST_PRIVATE_KEY.to_string();
    config.nox_entry_point_address = format!("{entry_point:?}");
    config.nox_reward_pool_address = format!("{pool:?}");
    config.quote_ttl_secs = 30;
    config.quote_network_fee_bps = 500;
    config.quote_maximum_transaction_gas = 2_000_000;
    config.quote_max_outstanding = 4;
    config.quote_max_pending_sponsored_gas = 8_000_000;
    config.quote_rolling_loss_limit_native = "100000000000000000".to_string();
    config.quote_rolling_loss_window_secs = 3_600;
    config.payment_adapters = vec![nox_node::config::PaymentAdapterConfig {
        address: format!("{adapter:?}"),
        fee_assets: vec![format!("{fee_asset:?}")],
        maximum_payment_gas: 600_000,
    }];
    let executor = Arc::new(ChainExecutor::new(&config).await.expect("executor"));
    let directory = tempdir().expect("tempdir");
    let storage = Arc::new(SledRepository::new(directory.path()).expect("sled"));
    let manager = Arc::new(
        TransactionManager::new(
            executor.clone(),
            storage.clone(),
            MetricsService::new(),
            nox_node::config::DEFAULT_REPLACEMENT_STEP_BPS,
        )
        .await
        .expect("tx manager"),
    );
    let prices = Arc::new(PriceClient::new(price_uri, Default::default()).expect("price client"));
    let mut handler = EthereumHandler::from_config(
        executor,
        manager,
        MetricsService::new(),
        10,
        prices,
        &config.nox_reward_pool_address,
        128 * 1024,
        "ethereum",
        18,
        nox_node::config::DEFAULT_GAS_LIMIT_BUFFER_BPS,
        nox_node::config::DEFAULT_INITIAL_FEE_BUFFER_BPS,
        &config.nox_entry_point_address,
    )
    .expect("handler")
    .with_quote_policy(&config)
    .expect("quote policy");
    handler.register_token(fee_asset, "USDC", 6, "usd-coin");
    (Arc::new(handler), storage, directory)
}

fn make_surbs(count: usize) -> Vec<Surb> {
    let mut rng = rand::thread_rng();
    let sk = X25519SecretKey::random_from_rng(&mut rng);
    let path = vec![PathHop {
        public_key: X25519PublicKey::from(&sk),
        address: "/ip4/127.0.0.1/tcp/9200".to_string(),
    }];
    (0..count)
        .map(|_| {
            let id: [u8; 16] = rand::random();
            Surb::new(&path, id, 0).expect("surb").0
        })
        .collect()
}

/// Build a full ExitService wired with the given EthereumHandler.
async fn make_exit_service_with_eth(
    eth: Arc<EthereumHandler>,
) -> (ExitService, Arc<TokioEventBus>) {
    let (svc, bus, _metrics) = make_exit_service_with_eth_and_metrics(eth).await;
    (svc, bus)
}

/// Like `make_exit_service_with_eth`, also returning the exit service metrics.
async fn make_exit_service_with_eth_and_metrics(
    eth: Arc<EthereumHandler>,
) -> (ExitService, Arc<TokioEventBus>, MetricsService) {
    let bus = Arc::new(TokioEventBus::new(256));
    let publisher: Arc<dyn IEventPublisher> = bus.clone();
    let subscriber: Arc<dyn IEventSubscriber> = bus.clone();

    let metrics = MetricsService::new();
    let packer = Arc::new(ResponsePacker::new());
    let echo = Arc::new(EchoHandler::new(packer.clone(), publisher.clone()));
    let traffic = Arc::new(TrafficHandler {
        metrics: metrics.clone(),
    });
    let http = Arc::new(nox_node::services::handlers::http::HttpHandler::new(
        HttpConfig::default(),
        packer.clone(),
        publisher.clone(),
        metrics.clone(),
    ));

    let svc = ExitService::with_handlers(
        subscriber,
        eth,
        traffic,
        http,
        echo,
        nox_node::config::FragmentationConfig::default(),
        metrics.clone(),
    )
    .with_publisher(publisher);

    (svc, bus, metrics)
}

/// Value of the exit dispatch counter for one handler label.
fn dispatched_count(metrics: &MetricsService, handler: &str) -> u64 {
    metrics
        .exit_payloads_dispatched_total
        .get_or_create(&vec![("handler".to_string(), handler.to_string())])
        .get()
}

/// A legacy `SubmitTransaction` payload is rejected and never reaches the Ethereum handler.
#[tokio::test]
async fn test_exit_service_rejects_legacy_submit_tx() {
    let price_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/ticker/price"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"price": "2000"})),
        )
        .mount(&price_server)
        .await;

    let eth = make_ethereum_handler(&price_server.uri()).await;
    let (svc, bus, metrics) = make_exit_service_with_eth_and_metrics(eth).await;
    let mut rx = bus.subscribe();

    let cancel = tokio_util::sync::CancellationToken::new();
    let svc = svc.with_cancel_token(cancel.clone());
    tokio::spawn(async move { svc.run().await });
    tokio::time::sleep(Duration::from_millis(10)).await;

    let to_bytes: [u8; 20] = hex::decode(&TEST_POOL[2..]).expect("hex decode")[..20]
        .try_into()
        .expect("20 bytes");
    let payload = RelayerPayload::SubmitTransaction {
        to: to_bytes,
        data: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };
    let payload_bytes = encode_payload(&payload).expect("encode");

    bus.publish(NoxEvent::PayloadDecrypted {
        packet_id: "pkt-submit-1".to_string(),
        payload: payload_bytes,
    })
    .expect("publish");

    tokio::time::sleep(Duration::from_millis(200)).await;
    cancel.cancel();

    assert_eq!(dispatched_count(&metrics, "legacy_rejected"), 1);
    assert_eq!(dispatched_count(&metrics, "ethereum"), 0);
    while let Ok(event) = rx.try_recv() {
        assert!(
            !matches!(event, NoxEvent::SendPacket { .. }),
            "a rejected legacy payload must not emit packets"
        );
    }
}

/// `AnonymousRequest` wrapping legacy `SubmitTransaction` is rejected, and the
/// rejection is still delivered via SURBs.
#[tokio::test]
async fn test_exit_service_anon_submit_tx_replies_with_rejection() {
    let price_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/ticker/price"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"price": "2000"})),
        )
        .mount(&price_server)
        .await;

    let eth = make_ethereum_handler(&price_server.uri()).await;
    let (svc, bus, metrics) = make_exit_service_with_eth_and_metrics(eth).await;
    let mut rx = bus.subscribe();

    let cancel = tokio_util::sync::CancellationToken::new();
    let svc = svc.with_cancel_token(cancel.clone());
    tokio::spawn(async move { svc.run().await });
    tokio::time::sleep(Duration::from_millis(10)).await;

    let to_bytes: [u8; 20] = hex::decode(&TEST_POOL[2..]).expect("hex decode")[..20]
        .try_into()
        .expect("20 bytes");
    let inner_req = ServiceRequest::SubmitTransaction {
        to: to_bytes,
        data: vec![0xCA, 0xFE],
    };
    let inner = encode_payload(&inner_req).expect("encode inner");
    let surbs = make_surbs(2);
    let payload = RelayerPayload::AnonymousRequest {
        inner,
        reply_surbs: surbs,
    };
    let payload_bytes = encode_payload(&payload).expect("encode outer");

    bus.publish(NoxEvent::PayloadDecrypted {
        packet_id: "pkt-anon-submit".to_string(),
        payload: payload_bytes,
    })
    .expect("publish");

    let got_send = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match rx.recv().await {
                Ok(NoxEvent::SendPacket { packet_id, .. }) if packet_id.starts_with("echo-") => {
                    return true;
                }
                Ok(_) => continue,
                Err(_) => return false,
            }
        }
    })
    .await
    .unwrap_or(false);

    assert!(
        got_send,
        "Expected SendPacket (echo- prefix) carrying the rejection"
    );
    cancel.cancel();
    assert_eq!(dispatched_count(&metrics, "legacy_rejected"), 1);
    assert_eq!(dispatched_count(&metrics, "ethereum"), 0);
}

#[tokio::test]
async fn paid_quote_without_reply_surb_does_not_reserve_capacity() {
    let price_server = MockServer::start().await;
    let observed_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    Mock::given(method("GET"))
        .and(path("/prices"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ethereum": { "price_e8": "300000000000", "observed_at_unix": observed_at_unix, "asset_id": "ethereum", "source": "test" },
            "usd-coin": { "price_e8": "100000000", "observed_at_unix": observed_at_unix, "asset_id": "usd-coin", "source": "test" }
        })))
        .mount(&price_server)
        .await;
    let (handler, storage, _directory) = make_quote_handler(&price_server.uri()).await;
    let (service, bus) = make_exit_service_with_eth(handler).await;
    let cancel = tokio_util::sync::CancellationToken::new();
    let service = service.with_cancel_token(cancel.clone());
    tokio::spawn(async move { service.run().await });
    tokio::time::sleep(Duration::from_millis(10)).await;

    let request = PaidQuoteRequestV2 {
        chain_id: 31_337,
        entry_point: Address::from_low_u64_be(11).0,
        client_intent_id: [2; 32],
        payment_adapter: Address::from_low_u64_be(12).0,
        payment_id: [4; 32],
        fee_asset: Address::from_low_u64_be(13).0,
        payment_gas_limit: 500_000,
        action_target: Address::from_low_u64_be(15).0,
        action_calldata_hash: [7; 32],
        action_gas_limit: 700_000,
        tracked_assets_hash: [8; 32],
        maximum_transaction_gas: 1_600_000,
        return_data_limit: 256,
        valid_until_unix: observed_at_unix + 60,
    };
    let payload = RelayerPayload::AnonymousRequest {
        inner: encode_payload(&ServiceRequest::PaidQuoteRequestV2(request)).expect("inner"),
        reply_surbs: Vec::new(),
    };
    bus.publish(NoxEvent::PayloadDecrypted {
        packet_id: "quote-without-surb".to_string(),
        payload: encode_payload(&payload).expect("outer"),
    })
    .expect("publish");
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(storage.scan(b"quote:execution:").await.unwrap().is_empty());
    assert!(storage.get(b"quote:outstanding").await.unwrap().is_none());
    assert!(storage.get(b"quote:pending-gas").await.unwrap().is_none());
    cancel.cancel();
}

/// `BroadcastSignedTransaction` returns a hash via SURBs in mock mode.
#[tokio::test]
async fn test_exit_service_broadcast_tx_sends_response_via_surbs() {
    let price_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/ticker/price"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"price": "2000"})),
        )
        .mount(&price_server)
        .await;

    let eth = make_ethereum_handler(&price_server.uri()).await;
    let (svc, bus) = make_exit_service_with_eth(eth).await;
    let mut rx = bus.subscribe();

    let cancel = tokio_util::sync::CancellationToken::new();
    let svc = svc.with_cancel_token(cancel.clone());
    tokio::spawn(async move { svc.run().await });
    tokio::time::sleep(Duration::from_millis(10)).await;

    let signed_tx = vec![0xAB; 32];
    let inner_req = ServiceRequest::BroadcastSignedTransaction {
        signed_tx,
        rpc_url: None,
        rpc_method: None,
    };
    let inner = encode_payload(&inner_req).expect("encode inner");
    let surbs = make_surbs(2);
    let payload = RelayerPayload::AnonymousRequest {
        inner,
        reply_surbs: surbs,
    };
    let payload_bytes = encode_payload(&payload).expect("encode outer");

    bus.publish(NoxEvent::PayloadDecrypted {
        packet_id: "pkt-broadcast".to_string(),
        payload: payload_bytes,
    })
    .expect("publish");

    let got_send = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match rx.recv().await {
                Ok(NoxEvent::SendPacket { packet_id, .. }) if packet_id.starts_with("echo-") => {
                    return true;
                }
                Ok(_) => continue,
                Err(_) => return false,
            }
        }
    })
    .await
    .unwrap_or(false);

    assert!(
        got_send,
        "Expected SendPacket (echo- prefix) for broadcast response"
    );
    cancel.cancel();
}

/// Simulation mode silently drops `SubmitTransaction` payloads.
#[tokio::test]
async fn test_exit_service_simulation_mode_drops_submit_tx() {
    let bus = Arc::new(TokioEventBus::new(256));
    let publisher: Arc<dyn IEventPublisher> = bus.clone();
    let subscriber: Arc<dyn IEventSubscriber> = bus.clone();

    let metrics = MetricsService::new();
    let packer = Arc::new(ResponsePacker::new());
    let echo = Arc::new(EchoHandler::new(packer.clone(), publisher.clone()));
    let traffic = Arc::new(TrafficHandler {
        metrics: metrics.clone(),
    });
    let http = Arc::new(nox_node::services::handlers::http::HttpHandler::new(
        HttpConfig::default(),
        packer.clone(),
        publisher.clone(),
        metrics.clone(),
    ));

    let svc =
        ExitService::simulation(subscriber, traffic, http, echo, metrics).with_publisher(publisher);

    let mut rx = bus.subscribe();
    let cancel = tokio_util::sync::CancellationToken::new();
    let svc = svc.with_cancel_token(cancel.clone());
    tokio::spawn(async move { svc.run().await });
    tokio::time::sleep(Duration::from_millis(10)).await;

    let to_bytes: [u8; 20] = hex::decode(&TEST_POOL[2..]).expect("hex decode")[..20]
        .try_into()
        .expect("20 bytes");
    let payload = RelayerPayload::SubmitTransaction {
        to: to_bytes,
        data: vec![0x01, 0x02],
    };
    let payload_bytes = encode_payload(&payload).expect("encode");

    bus.publish(NoxEvent::PayloadDecrypted {
        packet_id: "pkt-sim-drop".to_string(),
        payload: payload_bytes,
    })
    .expect("publish");

    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut got_send_packet = false;
    while let Ok(event) = rx.try_recv() {
        if matches!(event, NoxEvent::SendPacket { .. }) {
            got_send_packet = true;
        }
    }
    assert!(
        !got_send_packet,
        "Simulation mode must not emit SendPacket for SubmitTransaction"
    );
    cancel.cancel();
}
