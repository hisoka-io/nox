//! MixStage unit tests: zero delay, non-zero delay, drain-on-close.

use nox_node::{
    services::relayer::{
        mix_loop::MixStage,
        worker::{MixMessage, MixMessageKind},
    },
    telemetry::metrics::MetricsService,
};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

fn make_mix_message(kind: MixMessageKind, delay: Duration) -> MixMessage {
    MixMessage {
        kind,
        delay,
        packet_id: "test-pkt".to_string(),
        original_processing_start: Instant::now(),
        #[cfg(feature = "hop-metrics")]
        hop_timings: None,
    }
}

fn forward_message(delay: Duration) -> MixMessage {
    make_mix_message(
        MixMessageKind::Forward {
            next_hop: "peer-1".to_string(),
            packet: vec![0xAB; 32],
        },
        delay,
    )
}

/// A message with zero delay passes through the stage without measurable pause.
#[tokio::test]
async fn test_mix_stage_zero_delay_passes_through() {
    let (mix_tx, mix_rx) = mpsc::channel::<MixMessage>(8);
    let (egress_tx, mut egress_rx) = mpsc::channel::<MixMessage>(8);

    let stage = MixStage::new(mix_rx, egress_tx, MetricsService::new());
    tokio::spawn(stage.run());

    mix_tx
        .send(forward_message(Duration::ZERO))
        .await
        .expect("send");
    drop(mix_tx);

    let msg = tokio::time::timeout(Duration::from_millis(500), egress_rx.recv())
        .await
        .expect("timeout waiting for egress message")
        .expect("channel closed");

    match msg.kind {
        MixMessageKind::Forward { next_hop, .. } => {
            assert_eq!(next_hop, "peer-1");
        }
        MixMessageKind::Exit { .. } => panic!("expected Forward"),
    }
}

/// A message with a 50 ms delay is NOT delivered within 10 ms but IS
/// delivered within 200 ms, verifying the delay queue holds it correctly.
#[tokio::test]
async fn test_mix_stage_nonzero_delay_is_held() {
    let (mix_tx, mix_rx) = mpsc::channel::<MixMessage>(8);
    let (egress_tx, mut egress_rx) = mpsc::channel::<MixMessage>(8);

    let stage = MixStage::new(mix_rx, egress_tx, MetricsService::new());
    tokio::spawn(stage.run());

    mix_tx
        .send(forward_message(Duration::from_millis(50)))
        .await
        .expect("send");

    // Should NOT arrive within 10 ms
    let early = tokio::time::timeout(Duration::from_millis(10), egress_rx.recv()).await;
    assert!(
        early.is_err(),
        "Message arrived too early before mix delay expired"
    );

    // Should arrive within 200 ms total
    let msg = tokio::time::timeout(Duration::from_millis(200), egress_rx.recv())
        .await
        .expect("timeout: message did not arrive after delay")
        .expect("channel closed");

    assert!(
        matches!(msg.kind, MixMessageKind::Forward { .. }),
        "expected Forward kind"
    );
}

/// When the ingress channel is dropped with messages still in the delay queue,
/// the stage drains remaining messages and then shuts down cleanly.
#[tokio::test]
async fn test_mix_stage_drains_on_sender_drop() {
    let (mix_tx, mix_rx) = mpsc::channel::<MixMessage>(8);
    let (egress_tx, mut egress_rx) = mpsc::channel::<MixMessage>(8);

    let stage = MixStage::new(mix_rx, egress_tx, MetricsService::new());
    let handle = tokio::spawn(stage.run());

    // Send two messages with short delays and close the input channel.
    mix_tx
        .send(forward_message(Duration::from_millis(20)))
        .await
        .expect("send 1");
    mix_tx
        .send(forward_message(Duration::from_millis(20)))
        .await
        .expect("send 2");
    drop(mix_tx);

    let mut received = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, egress_rx.recv()).await {
            Ok(Some(_)) => received += 1,
            Ok(None) => break, // egress closed -- stage exited
            Err(_) => break,
        }
    }

    assert_eq!(received, 2, "Both delayed messages must be drained");

    // Stage task should have exited cleanly.
    tokio::time::timeout(Duration::from_millis(200), handle)
        .await
        .expect("stage task did not exit in time")
        .expect("stage task panicked");
}
