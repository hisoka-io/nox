//! EgressStage unit tests: Forward/Exit routing and clean shutdown.

use nox_core::{events::NoxEvent, IEventPublisher, IEventSubscriber};
use nox_node::{
    services::relayer::{
        egress::EgressStage,
        worker::{MixMessage, MixMessageKind},
    },
    telemetry::metrics::MetricsService,
    TokioEventBus,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

fn make_message(kind: MixMessageKind) -> MixMessage {
    MixMessage {
        kind,
        delay: Duration::ZERO,
        packet_id: "egress-test-pkt".to_string(),
        original_processing_start: Instant::now(),
        #[cfg(feature = "hop-metrics")]
        hop_timings: None,
    }
}

/// `Forward` message produces a `SendPacket` event on the bus.
#[tokio::test]
async fn test_egress_forward_publishes_send_packet() {
    let bus = Arc::new(TokioEventBus::new(64));
    let publisher: Arc<dyn IEventPublisher> = bus.clone();
    let subscriber: Arc<dyn IEventSubscriber> = bus.clone();
    let mut rx = subscriber.subscribe();

    let (egress_tx, egress_rx) = mpsc::channel::<MixMessage>(8);
    let stage = EgressStage::new(egress_rx, publisher, MetricsService::new());
    tokio::spawn(stage.run());

    egress_tx
        .send(make_message(MixMessageKind::Forward {
            next_hop: "peer-forward".to_string(),
            packet: vec![0xDE, 0xAD, 0xBE, 0xEF],
        }))
        .await
        .expect("send");

    let event = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match rx.recv().await {
                Ok(NoxEvent::SendPacket {
                    next_hop_peer_id,
                    packet_id,
                    ..
                }) => return (next_hop_peer_id, packet_id),
                Ok(_) => continue,
                Err(_) => panic!("channel closed"),
            }
        }
    })
    .await
    .expect("timeout waiting for SendPacket");

    assert_eq!(event.0, "peer-forward");
    assert_eq!(event.1, "egress-test-pkt");
}

/// `Exit` message produces a `PayloadDecrypted` event on the bus.
#[tokio::test]
async fn test_egress_exit_publishes_payload_decrypted() {
    let bus = Arc::new(TokioEventBus::new(64));
    let publisher: Arc<dyn IEventPublisher> = bus.clone();
    let subscriber: Arc<dyn IEventSubscriber> = bus.clone();
    let mut rx = subscriber.subscribe();

    let (egress_tx, egress_rx) = mpsc::channel::<MixMessage>(8);
    let stage = EgressStage::new(egress_rx, publisher, MetricsService::new());
    tokio::spawn(stage.run());

    let payload_data = b"decrypted exit payload".to_vec();
    egress_tx
        .send(make_message(MixMessageKind::Exit {
            payload: payload_data.clone(),
        }))
        .await
        .expect("send");

    let event = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match rx.recv().await {
                Ok(NoxEvent::PayloadDecrypted { packet_id, payload }) => {
                    return (packet_id, payload);
                }
                Ok(_) => continue,
                Err(_) => panic!("channel closed"),
            }
        }
    })
    .await
    .expect("timeout waiting for PayloadDecrypted");

    assert_eq!(event.0, "egress-test-pkt");
    assert_eq!(event.1, payload_data);
}

/// Stage exits cleanly when the input channel is dropped.
#[tokio::test]
async fn test_egress_exits_when_channel_closed() {
    let bus = Arc::new(TokioEventBus::new(64));
    let publisher: Arc<dyn IEventPublisher> = bus.clone();

    let (egress_tx, egress_rx) = mpsc::channel::<MixMessage>(8);
    let stage = EgressStage::new(egress_rx, publisher, MetricsService::new());
    let handle = tokio::spawn(stage.run());

    // Drop the sender immediately -- the stage should exit.
    drop(egress_tx);

    tokio::time::timeout(Duration::from_millis(200), handle)
        .await
        .expect("stage did not exit after channel close")
        .expect("stage panicked");
}
