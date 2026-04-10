use crate::models::payloads::RelayerPayload;
use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("Processing failed: {0}")]
    ProcessingFailed(String),
    #[error("Payload ignored")]
    Ignored,
}

#[async_trait]
pub trait ServiceHandler: Send + Sync {
    fn name(&self) -> &'static str;
    async fn handle(&self, packet_id: &str, payload: &RelayerPayload) -> Result<(), ServiceError>;
}
