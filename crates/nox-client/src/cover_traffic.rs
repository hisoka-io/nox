//! Poisson-rate cover traffic: sends Dummy Sphinx packets to hide real request patterns.

use crate::topology_node::TopologyNode;
use nox_core::models::payloads::{encode_payload, RelayerPayload};
use nox_core::traits::transport::PacketTransport;
use nox_core::IEventPublisher;
use nox_core::NoxEvent;
use nox_crypto::sphinx::packet::PACKET_SIZE;
use nox_crypto::sphinx::{build_multi_hop_packet, PathHop};
use parking_lot::RwLock;
use rand_distr::{Distribution, Exp};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

/// Generates Poisson-distributed dummy packets to mask real traffic patterns.
pub struct CoverTrafficController {
    topology: Arc<RwLock<Vec<TopologyNode>>>,
    publisher: Arc<dyn IEventPublisher>,
    transport: Option<Arc<dyn PacketTransport>>,
    entry_url: Option<String>,
    pow_difficulty: u32,
    /// Average packets per second. 0 = disabled.
    lambda: f64,
    running: Arc<AtomicBool>,
}

impl CoverTrafficController {
    #[must_use]
    pub fn new(
        topology: Arc<RwLock<Vec<TopologyNode>>>,
        publisher: Arc<dyn IEventPublisher>,
        lambda: f64,
        pow_difficulty: u32,
    ) -> Self {
        Self {
            topology,
            publisher,
            transport: None,
            entry_url: None,
            pow_difficulty,
            lambda,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    #[must_use]
    pub fn with_transport(
        mut self,
        transport: Arc<dyn PacketTransport>,
        entry_url: String,
    ) -> Self {
        self.transport = Some(transport);
        self.entry_url = Some(entry_url);
        self
    }

    #[allow(clippy::must_use_candidate)]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Run the cover traffic loop. Blocks until `stop()` is called.
    pub async fn run(&self) {
        if self.lambda <= 0.0 {
            debug!("Cover traffic disabled (lambda=0)");
            return;
        }

        self.running.store(true, Ordering::Relaxed);

        let exp = match Exp::new(self.lambda) {
            Ok(e) => e,
            Err(e) => {
                warn!("Invalid lambda for cover traffic: {e}");
                return;
            }
        };

        let mut rng = rand::rngs::OsRng;
        let mut counter: u64 = 0;

        while self.running.load(Ordering::Relaxed) {
            let wait_secs: f64 = exp.sample(&mut rng);
            let wait = Duration::from_secs_f64(wait_secs.min(30.0));
            tokio::time::sleep(wait).await;

            if !self.running.load(Ordering::Relaxed) {
                break;
            }

            if let Err(e) = self.send_dummy(&mut counter).await {
                debug!("Cover traffic send failed: {e}");
            }
        }

        debug!("Cover traffic loop stopped after {counter} packets");
    }

    async fn send_dummy(&self, counter: &mut u64) -> Result<(), String> {
        let path = self.select_route()?;
        let payload = encode_payload(&RelayerPayload::Dummy {
            padding: vec![0u8; 32],
        })
        .map_err(|e| format!("encode: {e}"))?;

        let mut packet = build_multi_hop_packet(&path, &payload, self.pow_difficulty)
            .map_err(|e| format!("sphinx: {e}"))?;
        if packet.len() < PACKET_SIZE {
            packet.resize(PACKET_SIZE, 0);
        }

        *counter += 1;

        if let (Some(transport), Some(url)) = (&self.transport, &self.entry_url) {
            transport
                .send_packet(url, &packet)
                .await
                .map_err(|e| format!("transport: {e}"))?;
        } else {
            self.publisher
                .publish(NoxEvent::PacketReceived {
                    packet_id: format!("cover-{counter}"),
                    data: packet,
                    size_bytes: PACKET_SIZE,
                    reply_handle: None,
                    prev_peer: None,
                })
                .map_err(|e| format!("publish: {e}"))?;
        }

        debug!("Cover traffic packet #{counter} sent");
        Ok(())
    }

    fn select_route(&self) -> Result<Vec<PathHop>, String> {
        let topology = self.topology.read();
        let mut rng = rand::rngs::OsRng;
        crate::route::select_path(&topology, None, false, &mut rng)
            .map_err(|e| format!("Insufficient topology for cover traffic: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nox_core::traits::interfaces::EventBusError;

    struct NoopPublisher;
    impl IEventPublisher for NoopPublisher {
        fn publish(&self, _event: NoxEvent) -> Result<usize, EventBusError> {
            Ok(0)
        }
    }

    #[test]
    fn test_cover_traffic_disabled_when_lambda_zero() {
        let topology = Arc::new(RwLock::new(Vec::new()));
        let publisher = Arc::new(NoopPublisher);
        let controller = CoverTrafficController::new(topology, publisher, 0.0, 0);
        assert!(!controller.is_running());
    }

    #[test]
    fn test_cover_traffic_stop() {
        let topology = Arc::new(RwLock::new(Vec::new()));
        let publisher = Arc::new(NoopPublisher);
        let controller = CoverTrafficController::new(topology, publisher, 1.0, 0);
        controller.running.store(true, Ordering::Relaxed);
        assert!(controller.is_running());
        controller.stop();
        assert!(!controller.is_running());
    }
}
