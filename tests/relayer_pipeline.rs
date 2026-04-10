use async_trait::async_trait;
use mockall::mock;
use mockall::predicate::*;
use nox_core::{
    EventBusError, IEventPublisher, IEventSubscriber, IMixStrategy, IReplayProtection,
    InfrastructureError, NoxEvent,
};
use nox_crypto::{build_multi_hop_packet, PathHop};
use nox_node::services::relayer::RelayerService;
use nox_node::NoxConfig;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use x25519_dalek::{PublicKey, StaticSecret};

// Define Mocks inline because crate doesn't export them
mock! {
    pub EventSubscriber {}
    #[async_trait]
    impl IEventSubscriber for EventSubscriber {
        fn subscribe(&self) -> broadcast::Receiver<NoxEvent>;
    }
}
mock! {
    pub EventPublisher {}
    #[async_trait]
    impl IEventPublisher for EventPublisher {
        fn publish(&self, event: NoxEvent) -> Result<usize, EventBusError>;
    }
}
mock! {
    pub MixStrategy {}
    impl IMixStrategy for MixStrategy {
        fn get_delay(&self) -> Duration;
    }
}
mock! {
    pub ReplayProtection {}
    #[async_trait]
    impl IReplayProtection for ReplayProtection {
        async fn check_and_tag(&self, tag: &[u8], ttl_seconds: u64) -> Result<bool, InfrastructureError>;
        async fn prune_expired(&self) -> Result<usize, InfrastructureError>;
    }
}

#[tokio::test]
async fn test_relayer_pipeline_flow() {
    let mut config = NoxConfig::default();
    config.relayer.worker_count = 1;
    config.relayer.queue_size = 10;
    let mut rng = rand::thread_rng();
    let node_sk = StaticSecret::random_from_rng(&mut rng);
    let node_pk = PublicKey::from(&node_sk);
    config.routing_private_key = hex::encode(node_sk.to_bytes());

    let (tx, _rx) = broadcast::channel(100);
    let rx_clone = tx.subscribe();

    let mut mock_subscriber = MockEventSubscriber::new();
    mock_subscriber
        .expect_subscribe()
        .times(1)
        .return_once(move || rx_clone);

    let mut mock_publisher = MockEventPublisher::new();
    mock_publisher
        .expect_publish()
        .times(2)
        .returning(|_| Ok(1));

    let mut mock_replay = MockReplayProtection::new();
    mock_replay
        .expect_check_and_tag()
        .returning(|_, _| Ok(false));

    let mut mock_mix = MockMixStrategy::new();
    mock_mix
        .expect_get_delay()
        .returning(|| Duration::from_millis(10));

    let payload = b"Hello Pipeline".to_vec();
    let path = vec![PathHop {
        public_key: node_pk,
        address: "0xEXIT".into(),
    }];
    let packet_data = build_multi_hop_packet(&path, &payload, 0).unwrap();

    let metrics = nox_node::telemetry::metrics::MetricsService::new();
    let service = RelayerService::new(
        config,
        Arc::new(mock_subscriber),
        Arc::new(mock_publisher),
        Arc::new(mock_replay),
        Arc::new(mock_mix),
        metrics,
    );

    let _handles = service.run().await;

    let event = NoxEvent::PacketReceived {
        packet_id: "test_pkt_1".to_string(),
        data: packet_data,
        size_bytes: 123,
    };
    tx.send(event).unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;
}
