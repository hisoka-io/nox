//! ExitService + Ethereum handler dispatch tests (requires `dev-node` feature).

#![cfg(feature = "dev-node")]

use ethers::prelude::*;
use nox_core::{
    models::payloads::{encode_payload, RelayerPayload, ServiceRequest},
    IEventPublisher, IEventSubscriber, NoxEvent,
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
        TransactionManager::new(exec, storage, MetricsService::new())
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
        Arc::new(PriceClient::new(price_uri)),
        pool,
        128 * 1024,
    ))
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
        metrics,
    )
    .with_publisher(publisher);

    (svc, bus)
}

/// `SubmitTransaction` dispatched to Ethereum handler succeeds in mock mode.
#[tokio::test]
async fn test_exit_service_submit_tx_dispatched_to_eth_handler() {
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
}

/// `AnonymousRequest` wrapping `SubmitTransaction` sends a response via SURBs.
#[tokio::test]
async fn test_exit_service_anon_submit_tx_sends_response_via_surbs() {
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
        "Expected SendPacket (echo- prefix) for paid tx response"
    );
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
