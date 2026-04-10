use crate::telemetry::metrics::MetricsService;
use async_channel::Receiver;
use nox_core::traits::IMixStrategy;
use nox_crypto::sphinx::{into_result, ProcessResult, SphinxError, SphinxHeader};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tracing::warn;
use x25519_dalek::StaticSecret as X25519SecretKey;

/// Shared via `Arc`; `StaticSecret` zeroes key material on drop via `zeroize`.
type SharedNodeKey = Arc<X25519SecretKey>;

/// Message sent from Worker to Mix Stage
pub struct MixMessage {
    pub kind: MixMessageKind,
    pub delay: Duration,
    pub packet_id: String,
    pub original_processing_start: std::time::Instant,
    #[cfg(feature = "hop-metrics")]
    pub hop_timings: Option<nox_crypto::sphinx::HopTimings>,
}

pub enum MixMessageKind {
    Forward { next_hop: String, packet: Vec<u8> },
    Exit { payload: Vec<u8> },
}

pub struct WorkerStage {
    worker_rx: Receiver<(SphinxHeader, Vec<u8>, String)>,
    mix_tx: Sender<MixMessage>,
    node_sk: SharedNodeKey,
    mix_strategy: Arc<dyn IMixStrategy>,
    metrics: MetricsService,
}

impl WorkerStage {
    pub fn new(
        worker_rx: Receiver<(SphinxHeader, Vec<u8>, String)>,
        mix_tx: Sender<MixMessage>,
        node_sk: SharedNodeKey,
        mix_strategy: Arc<dyn IMixStrategy>,
        metrics: MetricsService,
    ) -> Self {
        Self {
            worker_rx,
            mix_tx,
            node_sk,
            mix_strategy,
            metrics,
        }
    }

    pub async fn run(self) {
        while let Ok((header, body, pid)) = self.worker_rx.recv().await {
            let start = std::time::Instant::now();

            match header.process(&self.node_sk, body) {
                Ok(output) => {
                    #[cfg(feature = "hop-metrics")]
                    let hop_timings = Some(output.1.clone());

                    let result = into_result(output);

                    let delay = self.mix_strategy.get_delay();

                    let kind = match result {
                        ProcessResult::Forward {
                            next_hop,
                            next_packet,
                            processed_body,
                            ..
                        } => {
                            let forwarded_bytes = next_packet.to_bytes(&processed_body);
                            MixMessageKind::Forward {
                                next_hop,
                                packet: forwarded_bytes,
                            }
                        }
                        ProcessResult::Exit { payload } => MixMessageKind::Exit { payload },
                    };

                    let msg = MixMessage {
                        kind,
                        delay,
                        packet_id: pid.clone(),
                        original_processing_start: start,
                        #[cfg(feature = "hop-metrics")]
                        hop_timings,
                    };

                    if self.mix_tx.send(msg).await.is_err() {
                        warn!("Mix channel closed, worker stopping.");
                        return;
                    }
                }
                Err(e) => {
                    warn!("Sphinx processing failed for {}: {}", pid, e);
                    let reason = match &e {
                        SphinxError::MacMismatch => "mac_fail",
                        SphinxError::Crypto(_) => "decrypt_fail",
                        _ => "malformed",
                    };
                    self.metrics
                        .sphinx_processing_errors_total
                        .get_or_create(&vec![("reason".to_string(), reason.to_string())])
                        .inc();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::mixing::PoissonMixStrategy;
    use crate::telemetry::metrics::MetricsService;
    use async_channel::bounded;
    use nox_crypto::sphinx::{build_multi_hop_packet, PathHop, SphinxHeader};
    use tokio::sync::mpsc;
    use x25519_dalek::PublicKey as X25519PublicKey;

    fn create_test_keys(count: usize) -> (Vec<X25519SecretKey>, Vec<X25519PublicKey>) {
        let mut rng = rand::thread_rng();
        let sks: Vec<X25519SecretKey> = (0..count)
            .map(|_| X25519SecretKey::random_from_rng(&mut rng))
            .collect();
        let pks: Vec<X25519PublicKey> = sks.iter().map(X25519PublicKey::from).collect();
        (sks, pks)
    }

    #[tokio::test]
    async fn test_worker_forward_packet() {
        let (sks, pks) = create_test_keys(3);

        // Build a 3-hop packet
        let path = vec![
            PathHop {
                public_key: pks[0],
                address: "node_0".into(),
            },
            PathHop {
                public_key: pks[1],
                address: "node_1".into(),
            },
            PathHop {
                public_key: pks[2],
                address: "EXIT".into(),
            },
        ];

        let payload = b"test_payload".to_vec();
        let packet = build_multi_hop_packet(&path, &payload, 0).expect("Build failed");

        // Parse into header + body
        let (header, body) = SphinxHeader::from_bytes(&packet).unwrap();

        // Setup worker channels
        let (worker_tx, worker_rx) = bounded::<(SphinxHeader, Vec<u8>, String)>(10);
        let (mix_tx, mut mix_rx) = mpsc::channel::<MixMessage>(10);
        let mix_strategy = Arc::new(PoissonMixStrategy::new(1.0));

        let metrics = MetricsService::new();
        let worker = WorkerStage::new(
            worker_rx,
            mix_tx,
            Arc::new(sks[0].clone()),
            mix_strategy,
            metrics,
        );

        // Send packet to worker
        worker_tx
            .send((header, body.to_vec(), "test_pid".into()))
            .await
            .unwrap();
        drop(worker_tx); // Close channel to allow worker to exit

        // Run worker
        worker.run().await;

        // Verify output
        let msg = mix_rx.recv().await.expect("Should receive message");
        assert_eq!(msg.packet_id, "test_pid");
        match msg.kind {
            MixMessageKind::Forward { next_hop, .. } => {
                assert_eq!(next_hop, "node_1");
            }
            _ => panic!("Expected Forward message"),
        }
    }

    #[tokio::test]
    async fn test_worker_exit_packet() {
        let (sks, pks) = create_test_keys(1);

        // Build a single-hop (exit) packet
        let path = vec![PathHop {
            public_key: pks[0],
            address: "EXIT".into(),
        }];

        let payload = b"exit_payload".to_vec();
        let packet = build_multi_hop_packet(&path, &payload, 0).expect("Build failed");

        let (header, body) = SphinxHeader::from_bytes(&packet).unwrap();

        let (worker_tx, worker_rx) = bounded::<(SphinxHeader, Vec<u8>, String)>(10);
        let (mix_tx, mut mix_rx) = mpsc::channel::<MixMessage>(10);
        let mix_strategy = Arc::new(PoissonMixStrategy::new(1.0));

        let metrics = MetricsService::new();
        let worker = WorkerStage::new(
            worker_rx,
            mix_tx,
            Arc::new(sks[0].clone()),
            mix_strategy,
            metrics,
        );

        worker_tx
            .send((header, body.to_vec(), "exit_pid".into()))
            .await
            .unwrap();
        drop(worker_tx);

        worker.run().await;

        let msg = mix_rx.recv().await.expect("Should receive message");
        assert_eq!(msg.packet_id, "exit_pid");
        match msg.kind {
            MixMessageKind::Exit { payload } => {
                assert!(payload.contains(&b'e'));
            }
            _ => panic!("Expected Exit message"),
        }
    }

    #[tokio::test]
    async fn test_worker_corrupted_packet_logged() {
        let (sks, _) = create_test_keys(1);
        let mut rng = rand::thread_rng();

        // Create a header with wrong key (will fail MAC validation)
        let wrong_sk = X25519SecretKey::random_from_rng(&mut rng);
        let wrong_pk = X25519PublicKey::from(&wrong_sk);

        let path = vec![PathHop {
            public_key: wrong_pk,
            address: "EXIT".into(),
        }];

        let payload = b"corrupted".to_vec();
        let packet = build_multi_hop_packet(&path, &payload, 0).expect("Build failed");

        let (header, body) = SphinxHeader::from_bytes(&packet).unwrap();

        let (worker_tx, worker_rx) = bounded::<(SphinxHeader, Vec<u8>, String)>(10);
        let (mix_tx, mut mix_rx) = mpsc::channel::<MixMessage>(10);
        let mix_strategy = Arc::new(PoissonMixStrategy::new(1.0));

        // Use the wrong secret key - sks[0] doesn't match wrong_pk
        let metrics = MetricsService::new();
        let worker = WorkerStage::new(
            worker_rx,
            mix_tx,
            Arc::new(sks[0].clone()),
            mix_strategy,
            metrics,
        );

        worker_tx
            .send((header, body.to_vec(), "corrupted_pid".into()))
            .await
            .unwrap();
        drop(worker_tx);

        worker.run().await;

        // Should NOT receive any message (corrupted packet is dropped)
        let result = mix_rx.try_recv();
        assert!(result.is_err(), "Corrupted packet should be dropped");
    }
}
