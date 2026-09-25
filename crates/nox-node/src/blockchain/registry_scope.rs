//! Binds persisted chain-derived state to the registry it was derived from.
//!
//! The observer cursor (`chain_observer:last_block`), the topology peers
//! (`peer:*`) and the P2P sessions (`session:*`, which carry a
//! `registry_verified` flag) are only meaningful for one `(chain_id, registry)`
//! pair. Pointing an existing data volume at a new registry must not resume the
//! old cursor or keep serving the old node set, so on startup the stored scope
//! is compared with the configured one and the registry-derived keys are dropped
//! on any mismatch. Identity keys (outside sled), the exit transaction outbox,
//! quotes and nonces are left untouched.

use crate::blockchain::executor::build_ethers_http1_provider;
use crate::blockchain::observer::LAST_BLOCK_KEY;
use ethers::prelude::*;
use ethers::types::transaction::eip2718::TypedTransaction;
use nox_core::traits::{IStorageRepository, InfrastructureError};
use tracing::{info, warn};

/// Storage key holding `"<chain_id>:<lowercase registry address>"`.
pub const REGISTRY_SCOPE_KEY: &[u8] = b"chain_observer:registry_scope";

/// Key prefixes whose values are derived from a specific registry.
const REGISTRY_DERIVED_PREFIXES: [&[u8]; 2] = [b"peer:", b"session:"];

/// `bytes4(keccak256("topologyFingerprint()"))`, identical on every `NoxRegistry` version.
const TOPOLOGY_FINGERPRINT_SELECTOR: [u8; 4] = [0x3c, 0xce, 0x4d, 0x3d];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryScopeOutcome {
    /// Empty database: the scope was recorded, nothing was dropped.
    Fresh,
    /// The database already belongs to the configured registry.
    Unchanged,
    /// Registry-derived state from another (or an unrecorded) scope was dropped.
    Reset {
        previous_scope: Option<String>,
        cleared_cursor: bool,
        dropped_keys: usize,
    },
}

/// Canonical scope string. Parsing normalises checksum casing and a missing `0x`.
pub fn registry_scope(
    chain_id: u64,
    registry_address: &str,
) -> Result<String, InfrastructureError> {
    let address = registry_address.trim().parse::<Address>().map_err(|e| {
        InfrastructureError::Blockchain(format!("Invalid registry address {registry_address}: {e}"))
    })?;
    Ok(format!("{chain_id}:{address:?}"))
}

/// Drops registry-derived keys unless the database is already scoped to
/// `(chain_id, registry_address)`, then records the configured scope.
///
/// A database written by a version that did not record a scope is treated as
/// foreign: its cursor and peers cannot be attributed to any registry, so they
/// are replayed from `chain_start_block` instead of trusted.
pub async fn enforce_registry_scope(
    storage: &dyn IStorageRepository,
    chain_id: u64,
    registry_address: &str,
) -> Result<RegistryScopeOutcome, InfrastructureError> {
    let current = registry_scope(chain_id, registry_address)?;
    let previous = storage
        .get(REGISTRY_SCOPE_KEY)
        .await?
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());

    if previous.as_deref() == Some(current.as_str()) {
        return Ok(RegistryScopeOutcome::Unchanged);
    }

    let cleared_cursor = storage.exists(LAST_BLOCK_KEY).await?;
    if cleared_cursor {
        storage.delete(LAST_BLOCK_KEY).await?;
    }

    let mut dropped_keys = 0usize;
    for prefix in REGISTRY_DERIVED_PREFIXES {
        for (key, _) in storage.scan(prefix).await? {
            storage.delete(&key).await?;
            dropped_keys += 1;
        }
    }

    // Written last: a crash before this point simply repeats the reset.
    storage.put(REGISTRY_SCOPE_KEY, current.as_bytes()).await?;

    if previous.is_none() && !cleared_cursor && dropped_keys == 0 {
        return Ok(RegistryScopeOutcome::Fresh);
    }
    Ok(RegistryScopeOutcome::Reset {
        previous_scope: previous,
        cleared_cursor,
        dropped_keys,
    })
}

/// Logs the outcome and flags the one configuration that would start with an
/// empty topology after a reset.
pub fn log_registry_scope_outcome(
    outcome: &RegistryScopeOutcome,
    scope: &str,
    chain_start_block: u64,
    has_bootstrap_urls: bool,
) {
    match outcome {
        RegistryScopeOutcome::Fresh => info!("Registry scope recorded: {scope}"),
        RegistryScopeOutcome::Unchanged => info!("Registry scope unchanged: {scope}"),
        RegistryScopeOutcome::Reset {
            previous_scope,
            cleared_cursor,
            dropped_keys,
        } => {
            warn!(
                previous = previous_scope.as_deref().unwrap_or("<unrecorded>"),
                current = %scope,
                cleared_cursor,
                dropped_keys,
                "Registry scope changed: dropped persisted observer cursor, peers and sessions"
            );
        }
    }
    if outcome != &RegistryScopeOutcome::Unchanged && chain_start_block == 0 && !has_bootstrap_urls
    {
        warn!(
            "chain_start_block is 0 and no bootstrap_topology_urls are set: the observer will \
             start at the latest block and miss every existing registration. Set \
             chain_start_block to the registry deployment block."
        );
    }
}

/// Reads `topologyFingerprint()` from the registry at the latest block.
pub async fn fetch_registry_fingerprint(
    rpc_url: &str,
    registry_address: &str,
) -> Result<[u8; 32], InfrastructureError> {
    let provider = build_ethers_http1_provider(rpc_url)?;
    let registry = registry_address.trim().parse::<Address>().map_err(|e| {
        InfrastructureError::Blockchain(format!("Invalid registry address {registry_address}: {e}"))
    })?;
    let call = TransactionRequest::new()
        .to(registry)
        .data(Bytes::from(TOPOLOGY_FINGERPRINT_SELECTOR.to_vec()));
    let output = provider
        .call(&TypedTransaction::Legacy(call), None)
        .await
        .map_err(|e| InfrastructureError::Blockchain(format!("topologyFingerprint(): {e}")))?;
    let bytes: [u8; 32] = output.as_ref().try_into().map_err(|_| {
        InfrastructureError::Blockchain(format!(
            "topologyFingerprint() returned {} bytes, expected 32",
            output.len()
        ))
    })?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::storage::SledRepository;
    use crate::services::network_manager::TopologyManager;
    use nox_core::models::topology::RelayerNode;
    use nox_core::IEventSubscriber;
    use std::sync::Arc;

    const OLD_REGISTRY: &str = "0x8626aF80db409BeD3C19871FAdf9b0Ce7Aa641Bc";
    const NEW_REGISTRY: &str = "0x1111111111111111111111111111111111111111";
    const CHAIN_ID: u64 = 421_614;

    async fn seed_registry_state(storage: &SledRepository) {
        storage
            .put(LAST_BLOCK_KEY, &312_313_531_u64.to_be_bytes())
            .await
            .unwrap();
        let node = RelayerNode::new(
            "0x74486dc1ac551e5cd3f4eef80727cc9d50d3abe9".to_string(),
            "11".repeat(32),
            "/ip4/127.0.0.1/tcp/15000".to_string(),
            "0".to_string(),
            1,
        );
        storage
            .put(
                b"peer:0x74486dc1ac551e5cd3f4eef80727cc9d50d3abe9",
                &serde_json::to_vec(&node).unwrap(),
            )
            .await
            .unwrap();
        storage
            .put(b"session:12D3KooWTest", b"{\"registry_verified\":true}")
            .await
            .unwrap();
    }

    async fn seed_exit_state(storage: &SledRepository) {
        storage.put(b"outbox:aa", b"{\"schema\":2}").await.unwrap();
        storage.put(b"tx:7", b"{\"schema\":2}").await.unwrap();
        storage
            .put(b"nonce:local", &8_u64.to_le_bytes())
            .await
            .unwrap();
        storage
            .put(b"quote:nonce", &3_u64.to_le_bytes())
            .await
            .unwrap();
    }

    async fn assert_exit_state_kept(storage: &SledRepository) {
        for key in [
            b"outbox:aa".as_slice(),
            b"tx:7",
            b"nonce:local",
            b"quote:nonce",
        ] {
            assert!(storage.exists(key).await.unwrap(), "{key:?} was dropped");
        }
    }

    fn open(dir: &tempfile::TempDir) -> SledRepository {
        SledRepository::new(dir.path()).expect("storage")
    }

    #[test]
    fn scope_is_case_and_prefix_insensitive() {
        let checksummed = registry_scope(CHAIN_ID, OLD_REGISTRY).unwrap();
        let lower = registry_scope(CHAIN_ID, &OLD_REGISTRY.to_lowercase()).unwrap();
        let bare = registry_scope(CHAIN_ID, OLD_REGISTRY.trim_start_matches("0x")).unwrap();
        assert_eq!(checksummed, lower);
        assert_eq!(checksummed, bare);
        assert_eq!(
            checksummed,
            "421614:0x8626af80db409bed3c19871fadf9b0ce7aa641bc"
        );
        assert!(registry_scope(CHAIN_ID, "not-an-address").is_err());
    }

    #[tokio::test]
    async fn fresh_database_records_scope() {
        let dir = tempfile::tempdir().unwrap();
        let storage = open(&dir);
        let outcome = enforce_registry_scope(&storage, CHAIN_ID, NEW_REGISTRY)
            .await
            .unwrap();
        assert_eq!(outcome, RegistryScopeOutcome::Fresh);
        assert_eq!(
            storage.get(REGISTRY_SCOPE_KEY).await.unwrap().unwrap(),
            registry_scope(CHAIN_ID, NEW_REGISTRY).unwrap().into_bytes()
        );
    }

    #[tokio::test]
    async fn same_scope_keeps_cursor_and_peers() {
        let dir = tempfile::tempdir().unwrap();
        let storage = open(&dir);
        enforce_registry_scope(&storage, CHAIN_ID, OLD_REGISTRY)
            .await
            .unwrap();
        seed_registry_state(&storage).await;

        let outcome = enforce_registry_scope(&storage, CHAIN_ID, &OLD_REGISTRY.to_lowercase())
            .await
            .unwrap();
        assert_eq!(outcome, RegistryScopeOutcome::Unchanged);
        assert!(storage.exists(LAST_BLOCK_KEY).await.unwrap());
        assert_eq!(storage.scan(b"peer:").await.unwrap().len(), 1);
        assert_eq!(storage.scan(b"session:").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn registry_change_drops_cursor_peers_and_sessions_only() {
        let dir = tempfile::tempdir().unwrap();
        let storage = open(&dir);
        enforce_registry_scope(&storage, CHAIN_ID, OLD_REGISTRY)
            .await
            .unwrap();
        seed_registry_state(&storage).await;
        seed_exit_state(&storage).await;

        let outcome = enforce_registry_scope(&storage, CHAIN_ID, NEW_REGISTRY)
            .await
            .unwrap();
        assert_eq!(
            outcome,
            RegistryScopeOutcome::Reset {
                previous_scope: Some(registry_scope(CHAIN_ID, OLD_REGISTRY).unwrap()),
                cleared_cursor: true,
                dropped_keys: 2,
            }
        );
        assert!(!storage.exists(LAST_BLOCK_KEY).await.unwrap());
        assert!(storage.scan(b"peer:").await.unwrap().is_empty());
        assert!(storage.scan(b"session:").await.unwrap().is_empty());
        assert_exit_state_kept(&storage).await;

        let again = enforce_registry_scope(&storage, CHAIN_ID, NEW_REGISTRY)
            .await
            .unwrap();
        assert_eq!(again, RegistryScopeOutcome::Unchanged);
    }

    #[tokio::test]
    async fn chain_change_with_same_registry_resets() {
        let dir = tempfile::tempdir().unwrap();
        let storage = open(&dir);
        enforce_registry_scope(&storage, CHAIN_ID, OLD_REGISTRY)
            .await
            .unwrap();
        seed_registry_state(&storage).await;

        let outcome = enforce_registry_scope(&storage, 31_337, OLD_REGISTRY)
            .await
            .unwrap();
        assert!(matches!(outcome, RegistryScopeOutcome::Reset { .. }));
        assert!(!storage.exists(LAST_BLOCK_KEY).await.unwrap());
    }

    /// A v0.2.5 volume has a cursor and peers but no recorded scope.
    #[tokio::test]
    async fn unscoped_legacy_database_is_reset() {
        let dir = tempfile::tempdir().unwrap();
        let storage = open(&dir);
        seed_registry_state(&storage).await;
        seed_exit_state(&storage).await;

        let outcome = enforce_registry_scope(&storage, CHAIN_ID, NEW_REGISTRY)
            .await
            .unwrap();
        assert_eq!(
            outcome,
            RegistryScopeOutcome::Reset {
                previous_scope: None,
                cleared_cursor: true,
                dropped_keys: 2,
            }
        );
        assert!(!storage.exists(LAST_BLOCK_KEY).await.unwrap());
        assert_exit_state_kept(&storage).await;
    }

    /// End to end with the topology manager: after a reset nothing from the old
    /// registry is hydrated, so the served topology and fingerprint start empty.
    #[tokio::test]
    async fn reset_database_hydrates_empty_topology() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(open(&dir));
        seed_registry_state(&storage).await;
        enforce_registry_scope(storage.as_ref(), CHAIN_ID, NEW_REGISTRY)
            .await
            .unwrap();

        let bus = Arc::new(crate::infra::event_bus::TokioEventBus::new(8));
        let subscriber: Arc<dyn IEventSubscriber> = bus;
        let manager = TopologyManager::new(storage, subscriber, None);
        manager.hydrate_from_storage().await;
        assert!(manager.get_all_nodes().is_empty());
        assert_eq!(manager.get_current_fingerprint(), [0_u8; 32]);
    }
}
