//! Echoes back received data using provided SURBs (return path testing).

use crate::services::response_packer::{PackResult, ResponsePacker};
use async_trait::async_trait;
use nox_core::events::NoxEvent;
use nox_core::models::payloads::{RelayerPayload, ServiceRequest};
use nox_core::traits::service::{ServiceError, ServiceHandler};
use nox_core::traits::IEventPublisher;
use nox_crypto::sphinx::surb::Surb;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Max size for deserializing inner payloads from `AnonymousRequest` (7 MB).
const MAX_INNER_PAYLOAD_SIZE: u64 = 7 * 1024 * 1024;

pub struct EchoHandler {
    response_packer: Arc<ResponsePacker>,
    publisher: Arc<dyn IEventPublisher>,
}

impl EchoHandler {
    pub fn new(response_packer: Arc<ResponsePacker>, publisher: Arc<dyn IEventPublisher>) -> Self {
        Self {
            response_packer,
            publisher,
        }
    }

    pub fn handle_anonymous_request(
        &self,
        request_id: u64,
        inner: &[u8],
        surbs: Vec<Surb>,
    ) -> Result<PackResult, ServiceError> {
        let response_data = match nox_core::models::payloads::decode_payload_limited::<ServiceRequest>(
            inner,
            MAX_INNER_PAYLOAD_SIZE,
        ) {
            Ok(ServiceRequest::Echo { data }) => {
                info!(
                    request_id = request_id,
                    data_len = data.len(),
                    "Echo request received"
                );
                data
            }
            Ok(ServiceRequest::HttpRequest { .. }) => {
                warn!(
                    request_id = request_id,
                    "Echo handler received HTTP request"
                );
                return Err(ServiceError::ProcessingFailed(
                    "Echo handler cannot process HTTP requests".into(),
                ));
            }
            Ok(ServiceRequest::RpcRequest { .. }) => {
                warn!(request_id = request_id, "Echo handler received RPC request");
                return Err(ServiceError::ProcessingFailed(
                    "Echo handler cannot process RPC requests".into(),
                ));
            }
            Ok(ServiceRequest::SubmitTransaction { .. }) => {
                warn!(
                    request_id = request_id,
                    "Echo handler received SubmitTransaction request"
                );
                return Err(ServiceError::ProcessingFailed(
                    "Echo handler cannot process SubmitTransaction requests".into(),
                ));
            }
            Ok(ServiceRequest::BroadcastSignedTransaction { .. }) => {
                warn!(
                    request_id = request_id,
                    "Echo handler received BroadcastSignedTransaction request"
                );
                return Err(ServiceError::ProcessingFailed(
                    "Echo handler cannot process BroadcastSignedTransaction requests".into(),
                ));
            }
            Ok(ServiceRequest::ReplenishSurbs { .. }) => {
                return Err(ServiceError::ProcessingFailed(
                    "Echo handler cannot process ReplenishSurbs requests".into(),
                ));
            }
            Err(_) => {
                debug!(request_id = request_id, "Treating inner as raw echo data");
                inner.to_vec()
            }
        };

        let pack_result = self
            .response_packer
            .pack_response(request_id, &response_data, surbs)
            .map_err(|e| ServiceError::ProcessingFailed(e.to_string()))?;

        info!(
            request_id = request_id,
            packets = pack_result.packets.len(),
            "Echo response packed"
        );

        Ok(pack_result)
    }
}

#[async_trait]
impl ServiceHandler for EchoHandler {
    fn name(&self) -> &'static str {
        "echo"
    }

    async fn handle(&self, packet_id: &str, payload: &RelayerPayload) -> Result<(), ServiceError> {
        match payload {
            RelayerPayload::AnonymousRequest { inner, reply_surbs } => {
                let request_id = {
                    let mut hasher = DefaultHasher::new();
                    packet_id.hash(&mut hasher);
                    hasher.finish()
                };

                let pack_result =
                    self.handle_anonymous_request(request_id, inner, reply_surbs.clone())?;

                for packet in &pack_result.packets {
                    if let Err(e) = self.publisher.publish(NoxEvent::SendPacket {
                        next_hop_peer_id: packet.first_hop.clone(),
                        packet_id: format!("echo-{}-{}", request_id, hex::encode(packet.surb_id)),
                        data: packet.packet_bytes.clone(),
                    }) {
                        warn!(
                            request_id = request_id,
                            error = %e,
                            "Failed to publish echo response SendPacket -- reply lost"
                        );
                    }
                }

                if pack_result.remaining.is_some() {
                    warn!(
                        request_id = request_id,
                        "Echo response partially delivered (SURB exhaustion) -- remaining data dropped"
                    );
                }
                info!(
                    request_id = request_id,
                    "Echo response packets dispatched to network"
                );

                Ok(())
            }
            _ => Ok(()),
        }
    }
}
