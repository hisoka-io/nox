use nox_core::{
    models::topology::RelayerNode,
    traits::{IStorageRepository, InfrastructureError},
};
use std::sync::Arc;
use tracing::{debug, info};

pub struct PeerRegistry {
    storage: Arc<dyn IStorageRepository>,
}

impl PeerRegistry {
    pub fn new(storage: Arc<dyn IStorageRepository>) -> Self {
        Self { storage }
    }

    pub async fn save_peer(&self, peer: &RelayerNode) -> Result<(), InfrastructureError> {
        let key = format!("peer:{}", peer.address);
        let value = serde_json::to_vec(peer)
            .map_err(|e| InfrastructureError::Database(format!("Serialization error: {e}")))?;

        self.storage.put(key.as_bytes(), &value).await?;
        debug!(peer_addr = %peer.address, "Peer persisted to registry");
        Ok(())
    }

    pub async fn load_peers(&self) -> Result<Vec<RelayerNode>, InfrastructureError> {
        let items = self.storage.scan(b"peer:").await?;
        let mut peers = Vec::new();

        for (_, val) in items {
            if let Ok(node) = serde_json::from_slice::<RelayerNode>(&val) {
                peers.push(node);
            }
        }

        info!("Loaded {} peers from registry", peers.len());
        Ok(peers)
    }

    pub async fn remove_peer(&self, address: &str) -> Result<(), InfrastructureError> {
        let key = format!("peer:{address}");
        self.storage.delete(key.as_bytes()).await
    }
}
