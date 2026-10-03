use crate::telemetry::metrics::MetricsService;
use async_channel::Receiver;
use nox_core::models::wire_id::{ReplyDelivery, ReplyHandle};
use nox_core::traits::{IMixStrategy, IReplayProtection};
use nox_crypto::sphinx::{into_result, ProcessResult, SphinxError, SphinxHeader};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tracing::{debug, error, warn};
use x25519_dalek::StaticSecret as X25519SecretKey;

/// Shared via `Arc`; `StaticSecret` zeroes key material on drop via `zeroize`.
type SharedNodeKey = Arc<X25519SecretKey>;

/// Node-local facts about an inbound packet, carried through the pipeline.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PacketMeta {
    /// Node-local packet ID.
    pub packet_id: String,
    /// Reply handle read from the inbound wire identifier.
    pub reply_handle: Option<ReplyHandle>,
    /// Libp2p peer ID of the sender, for packets received over P2P.
    pub prev_peer: Option<String>,
}

impl PacketMeta {
    /// Metadata for a packet with only a local ID.
    #[must_use]
    pub fn local(packet_id: impl Into<String>) -> Self {
        Self {
            packet_id: packet_id.into(),
            reply_handle: None,
            prev_peer: None,
        }
    }
}

/// Message sent from Worker to Mix Stage
pub struct MixMessage {
    pub kind: MixMessageKind,
    pub delay: Duration,
    pub packet_id: String,
    /// Reply handle the packet arrived with.
    pub reply_handle: Option<ReplyHandle>,
    /// Libp2p peer ID of the node the packet came from.
    pub prev_peer: Option<String>,
    /// Set for a format 2 reply delivered at this node (see [`ReplyDelivery`]).
    pub delivery: Option<ReplyDelivery>,
    pub original_processing_start: std::time::Instant,
    #[cfg(feature = "hop-metrics")]
    pub hop_timings: Option<nox_crypto::sphinx::HopTimings>,
}

pub enum MixMessageKind {
    Forward { next_hop: String, packet: Vec<u8> },
    Exit { payload: Vec<u8> },
}

/// Replay protection used by a worker: the shared filter and the tag TTL.
#[derive(Clone)]
pub struct ReplayGuard {
    pub db: Arc<dyn IReplayProtection>,
    pub window_secs: u64,
}

pub struct WorkerStage {
    worker_rx: Receiver<(SphinxHeader, Vec<u8>, PacketMeta)>,
    mix_tx: Sender<MixMessage>,
    node_sk: SharedNodeKey,
    replay: ReplayGuard,
    mix_strategy: Arc<dyn IMixStrategy>,
    metrics: MetricsService,
    reply_v2: bool,
}

/// What the format 2 reply flag means for one packet at this hop.
#[derive(Debug, PartialEq, Eq)]
struct ReplyRouting {
    reply_handle: Option<ReplyHandle>,
    delivery: Option<ReplyDelivery>,
}

/// Applies the format 2 reply flag.
///
/// A flagged packet never keeps a handle from its wire identifier: a relay
/// sends it on with a fresh identifier, and a final hop files it under its
/// delivery ID only, and only when it came over P2P. Unflagged packets keep
/// the format 1 behaviour.
fn reply_routing(
    flagged: bool,
    is_final_hop: bool,
    delivery_id: [u8; 16],
    meta_handle: Option<ReplyHandle>,
    prev_peer: Option<&String>,
) -> ReplyRouting {
    if !flagged {
        return ReplyRouting {
            reply_handle: meta_handle,
            delivery: None,
        };
    }
    let delivery = match (is_final_hop, prev_peer) {
        (true, Some(peer)) => Some(ReplyDelivery {
            id: delivery_id,
            source_peer: peer.clone(),
        }),
        _ => None,
    };
    ReplyRouting {
        reply_handle: None,
        delivery,
    }
}

impl WorkerStage {
    pub fn new(
        worker_rx: Receiver<(SphinxHeader, Vec<u8>, PacketMeta)>,
        mix_tx: Sender<MixMessage>,
        node_sk: SharedNodeKey,
        replay: ReplayGuard,
        mix_strategy: Arc<dyn IMixStrategy>,
        metrics: MetricsService,
    ) -> Self {
        Self {
            worker_rx,
            mix_tx,
            node_sk,
            replay,
            mix_strategy,
            metrics,
            reply_v2: true,
        }
    }

    /// Whether format 2 reply flags are honoured (`surb_formats`).
    #[must_use]
    pub fn with_reply_v2(mut self, enabled: bool) -> Self {
        self.reply_v2 = enabled;
        self
    }

    fn record_sphinx_error(&self, pid: &str, e: &SphinxError) {
        debug!("Sphinx processing failed for {}: {}", pid, e);
        let reason = match e {
            SphinxError::MacMismatch => "mac_fail",
            SphinxError::Crypto(_) => "decrypt_fail",
            _ => "malformed",
        };
        self.metrics
            .sphinx_processing_errors_total
            .get_or_create(&vec![("reason".to_string(), reason.to_string())])
            .inc();
    }

    /// Checks and records the replay tag. Returns `true` if the packet may be processed.
    async fn admit(&self, pid: &str, replay_tag: &[u8; 32]) -> bool {
        match self
            .replay
            .db
            .check_and_tag(replay_tag, self.replay.window_secs)
            .await
        {
            Ok(true) => {
                debug!("Duplicate packet detected: {}. Dropping.", pid);
                self.metrics
                    .ingest_dropped_total
                    .get_or_create(&vec![("reason".to_string(), "replay".to_string())])
                    .inc();
                self.metrics
                    .replay_checks_total
                    .get_or_create(&vec![("result".to_string(), "duplicate".to_string())])
                    .inc();
                false
            }
            Ok(false) => {
                self.metrics
                    .replay_checks_total
                    .get_or_create(&vec![("result".to_string(), "new".to_string())])
                    .inc();
                true
            }
            Err(e) => {
                error!("Replay DB error for {}: {:?}.", pid, e);
                self.metrics
                    .ingest_dropped_total
                    .get_or_create(&vec![("reason".to_string(), "replay_error".to_string())])
                    .inc();
                false
            }
        }
    }

    pub async fn run(self) {
        while let Ok((header, body, meta)) = self.worker_rx.recv().await {
            let pid = meta.packet_id;
            let start = std::time::Instant::now();

            // The replay tag comes from the per-hop shared secret, so it is checked
            // once the header has been verified.
            let verified = match header.verify(&self.node_sk) {
                Ok(verified) => verified,
                Err(e) => {
                    self.record_sphinx_error(&pid, &e);
                    continue;
                }
            };
            if !self.admit(&pid, &verified.replay_tag()).await {
                continue;
            }
            let flagged = self.reply_v2 && verified.reply_v2_flag();
            let delivery_id = verified.delivery_id();

            match verified.process(body) {
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

                    let routing = reply_routing(
                        flagged,
                        matches!(kind, MixMessageKind::Exit { .. }),
                        delivery_id,
                        meta.reply_handle,
                        meta.prev_peer.as_ref(),
                    );
                    if flagged {
                        if meta.reply_handle.is_some() {
                            self.metrics
                                .wire_handle_dropped_total
                                .get_or_create(&vec![("reason".into(), "reply_v2".into())])
                                .inc();
                        }
                        self.metrics
                            .reply_v2_packets_total
                            .get_or_create(&vec![(
                                "hop".into(),
                                if routing.delivery.is_some() {
                                    "final".into()
                                } else if matches!(kind, MixMessageKind::Exit { .. }) {
                                    "final_not_p2p".into()
                                } else {
                                    "relay".into()
                                },
                            )])
                            .inc();
                    }

                    let msg = MixMessage {
                        kind,
                        delay,
                        packet_id: pid.clone(),
                        reply_handle: routing.reply_handle,
                        prev_peer: meta.prev_peer.clone(),
                        delivery: routing.delivery,
                        original_processing_start: start,
                        #[cfg(feature = "hop-metrics")]
                        hop_timings,
                    };

                    if self.mix_tx.send(msg).await.is_err() {
                        warn!("Mix channel closed, worker stopping.");
                        return;
                    }
                }
                Err(e) => self.record_sphinx_error(&pid, &e),
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

    fn test_replay_guard() -> ReplayGuard {
        ReplayGuard {
            db: Arc::new(
                crate::infra::persistence::rotational_bloom::RotationalBloomFilter::new(
                    1000,
                    0.001,
                    Duration::from_mins(1),
                ),
            ),
            window_secs: 60,
        }
    }

    /// Runs one worker over `packets` and returns the packet IDs it emitted.
    async fn run_worker(
        sk: &X25519SecretKey,
        packets: Vec<(SphinxHeader, Vec<u8>, String)>,
    ) -> Vec<String> {
        let (worker_tx, worker_rx) = bounded::<(SphinxHeader, Vec<u8>, PacketMeta)>(16);
        let (mix_tx, mut mix_rx) = mpsc::channel::<MixMessage>(16);
        let worker = WorkerStage::new(
            worker_rx,
            mix_tx,
            Arc::new(sk.clone()),
            test_replay_guard(),
            Arc::new(PoissonMixStrategy::new(1.0)),
            MetricsService::new(),
        );
        for (header, body, pid) in packets {
            worker_tx
                .send((header, body, PacketMeta::local(pid)))
                .await
                .unwrap();
        }
        drop(worker_tx);
        worker.run().await;

        let mut emitted = Vec::new();
        while let Ok(msg) = mix_rx.try_recv() {
            emitted.push(msg.packet_id);
        }
        emitted
    }

    fn exit_packet(pk: X25519PublicKey) -> (SphinxHeader, Vec<u8>) {
        let path = vec![PathHop {
            public_key: pk,
            address: "EXIT".into(),
        }];
        let packet = build_multi_hop_packet(&path, b"replay", 0).expect("Build failed");
        let (header, body) = SphinxHeader::from_bytes(&packet).unwrap();
        (header, body.to_vec())
    }

    #[test]
    fn reply_routing_follows_the_flag() {
        let d = [4u8; 16];
        let h = Some([5u8; 16]);
        let peer = "peer".to_string();

        // Unflagged: format 1 behaviour, handle kept, no delivery.
        for final_hop in [true, false] {
            assert_eq!(
                reply_routing(false, final_hop, d, h, Some(&peer)),
                ReplyRouting {
                    reply_handle: h,
                    delivery: None
                }
            );
        }
        // Flagged relay hop: handle dropped.
        assert_eq!(
            reply_routing(true, false, d, h, Some(&peer)),
            ReplyRouting {
                reply_handle: None,
                delivery: None
            }
        );
        // Flagged final hop over P2P: delivery ID only.
        assert_eq!(
            reply_routing(true, true, d, h, Some(&peer)),
            ReplyRouting {
                reply_handle: None,
                delivery: Some(ReplyDelivery {
                    id: d,
                    source_peer: peer.clone()
                })
            }
        );
        // Flagged final hop not from P2P (HTTP ingress): nothing to file under.
        assert_eq!(
            reply_routing(true, true, d, h, None),
            ReplyRouting {
                reply_handle: None,
                delivery: None
            }
        );
    }

    #[tokio::test]
    async fn test_worker_drops_duplicate_with_changed_nonce() {
        let (sks, pks) = create_test_keys(1);
        let (header, body) = exit_packet(pks[0]);
        let mut renonced = header.clone();
        renonced.nonce = renonced.nonce.wrapping_add(1);

        let emitted = run_worker(
            &sks[0],
            vec![
                (header.clone(), body.clone(), "first".into()),
                (header, body.clone(), "same".into()),
                (renonced, body, "renonced".into()),
            ],
        )
        .await;
        assert_eq!(emitted, vec!["first".to_string()]);
    }

    #[tokio::test]
    async fn test_worker_mac_failure_does_not_consume_replay_tag() {
        let (sks, pks) = create_test_keys(1);
        let (header, body) = exit_packet(pks[0]);
        let mut forged = header.clone();
        forged.mac[0] ^= 0x01;

        let emitted = run_worker(
            &sks[0],
            vec![
                (forged, body.clone(), "forged".into()),
                (header, body, "genuine".into()),
            ],
        )
        .await;
        assert_eq!(emitted, vec!["genuine".to_string()]);
    }

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
        let (worker_tx, worker_rx) = bounded::<(SphinxHeader, Vec<u8>, PacketMeta)>(10);
        let (mix_tx, mut mix_rx) = mpsc::channel::<MixMessage>(10);
        let mix_strategy = Arc::new(PoissonMixStrategy::new(1.0));

        let metrics = MetricsService::new();
        let worker = WorkerStage::new(
            worker_rx,
            mix_tx,
            Arc::new(sks[0].clone()),
            test_replay_guard(),
            mix_strategy,
            metrics,
        );

        // Send packet to worker
        worker_tx
            .send((
                header,
                body.to_vec(),
                PacketMeta {
                    packet_id: "test_pid".into(),
                    reply_handle: Some([3u8; 16]),
                    prev_peer: Some("prev".into()),
                },
            ))
            .await
            .unwrap();
        drop(worker_tx); // Close channel to allow worker to exit

        // Run worker
        worker.run().await;

        // Verify output
        let msg = mix_rx.recv().await.expect("Should receive message");
        assert_eq!(msg.packet_id, "test_pid");
        assert_eq!(msg.reply_handle, Some([3u8; 16]));
        assert_eq!(msg.prev_peer.as_deref(), Some("prev"));
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

        let (worker_tx, worker_rx) = bounded::<(SphinxHeader, Vec<u8>, PacketMeta)>(10);
        let (mix_tx, mut mix_rx) = mpsc::channel::<MixMessage>(10);
        let mix_strategy = Arc::new(PoissonMixStrategy::new(1.0));

        let metrics = MetricsService::new();
        let worker = WorkerStage::new(
            worker_rx,
            mix_tx,
            Arc::new(sks[0].clone()),
            test_replay_guard(),
            mix_strategy,
            metrics,
        );

        worker_tx
            .send((header, body.to_vec(), PacketMeta::local("exit_pid")))
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

        let (worker_tx, worker_rx) = bounded::<(SphinxHeader, Vec<u8>, PacketMeta)>(10);
        let (mix_tx, mut mix_rx) = mpsc::channel::<MixMessage>(10);
        let mix_strategy = Arc::new(PoissonMixStrategy::new(1.0));

        // Use the wrong secret key - sks[0] doesn't match wrong_pk
        let metrics = MetricsService::new();
        let worker = WorkerStage::new(
            worker_rx,
            mix_tx,
            Arc::new(sks[0].clone()),
            test_replay_guard(),
            mix_strategy,
            metrics,
        );

        worker_tx
            .send((header, body.to_vec(), PacketMeta::local("corrupted_pid")))
            .await
            .unwrap();
        drop(worker_tx);

        worker.run().await;

        // Should NOT receive any message (corrupted packet is dropped)
        let result = mix_rx.try_recv();
        assert!(result.is_err(), "Corrupted packet should be dropped");
    }
}
