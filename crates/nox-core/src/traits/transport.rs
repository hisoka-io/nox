//! Abstraction for sending Sphinx packets to entry nodes.

use async_trait::async_trait;

use crate::traits::interfaces::InfrastructureError;

#[async_trait]
pub trait PacketTransport: Send + Sync {
    async fn send_packet(&self, entry_url: &str, packet: &[u8]) -> Result<(), InfrastructureError>;

    async fn recv_response(
        &self,
        entry_url: &str,
        request_id: &str,
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>, InfrastructureError>;

    async fn recv_responses_batch(
        &self,
        _entry_url: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, InfrastructureError> {
        Ok(vec![])
    }
}
