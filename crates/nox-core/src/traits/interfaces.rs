use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::broadcast;

use crate::events::NoxEvent;

#[derive(Debug, Error)]
pub enum InfrastructureError {
    #[error("Database error: {0}")]
    Database(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Blockchain error: {0}")]
    Blockchain(String),
}

#[async_trait]
pub trait IStorageRepository: Send + Sync {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, InfrastructureError>;
    async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), InfrastructureError>;
    async fn exists(&self, key: &[u8]) -> Result<bool, InfrastructureError>;
    async fn delete(&self, key: &[u8]) -> Result<(), InfrastructureError>;
    async fn scan(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, InfrastructureError>;
}

#[async_trait]
pub trait IChainService: Send + Sync {
    async fn get_block_number(&self) -> Result<u64, InfrastructureError>;
}

#[async_trait]
pub trait INetworkService: Send + Sync {
    async fn start(&self) -> Result<(), InfrastructureError>;
    async fn broadcast(&self, topic: &str, msg: &[u8]) -> Result<(), InfrastructureError>;
}

#[derive(Debug, Error)]
pub enum EventBusError {
    #[error("Failed to broadcast event: {0}")]
    BroadcastFailed(String),
    #[error("Lagged receiver skipped {0} messages")]
    Lagged(u64),
}

#[async_trait]
pub trait IEventPublisher: Send + Sync {
    fn publish(&self, event: NoxEvent) -> Result<usize, EventBusError>;
}

pub trait IEventSubscriber: Send + Sync {
    fn subscribe(&self) -> broadcast::Receiver<NoxEvent>;
}

pub trait IEventBus: IEventPublisher + IEventSubscriber {}

#[async_trait]
pub trait IReplayProtection: Send + Sync {
    async fn check_and_tag(
        &self,
        tag: &[u8],
        ttl_seconds: u64,
    ) -> Result<bool, InfrastructureError>;
    async fn prune_expired(&self) -> Result<usize, InfrastructureError>;
}

pub trait IMixStrategy: Send + Sync {
    fn get_delay(&self) -> Duration;
}

#[async_trait]
pub trait IChainClient: Send + Sync {
    async fn submit_tx(&self, to: &str, data: &[u8]) -> Result<String, InfrastructureError>;
    async fn simulate_tx(&self, to: &str, data: &[u8]) -> Result<Vec<u8>, InfrastructureError>;
}

pub use darkpool_crypto::IPoseidonHasher;

/// No-op `IEventPublisher` that silently discards all events.
pub struct NoopPublisher;

impl NoopPublisher {
    #[must_use]
    pub fn arc() -> Arc<dyn IEventPublisher> {
        Arc::new(Self)
    }
}

impl IEventPublisher for NoopPublisher {
    fn publish(&self, _event: NoxEvent) -> Result<usize, EventBusError> {
        Ok(0)
    }
}

#[async_trait]
pub trait IProverService: Send + Sync {
    async fn prove(
        &self,
        circuit_name: &str,
        inputs: std::collections::HashMap<String, String>,
    ) -> Result<ZKProofData, InfrastructureError>;
}

#[derive(Debug, Clone)]
pub struct ZKProofData {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<String>,
}
