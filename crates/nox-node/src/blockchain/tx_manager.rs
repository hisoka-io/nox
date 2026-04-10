use ethers::prelude::*;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// Sled key under which the last-known-good local nonce is persisted.
/// Written after every successful TX send and after every `sync_nonce`.
/// Read on startup as a floor -- prevents nonce regression after a crash
/// where in-flight TXs have not yet appeared in the mempool.
const KEY_NONCE_LOCAL: &[u8] = b"nonce:local";

use crate::blockchain::executor::ChainExecutor;
use crate::infra::storage::SledRepository;
use crate::telemetry::metrics::MetricsService;
use nox_core::models::chain::{PendingTransaction, TxStatus};
use nox_core::traits::{IStorageRepository, InfrastructureError};

pub struct TransactionManager {
    executor: Arc<ChainExecutor>,
    storage: Arc<SledRepository>,
    // In-memory cache of pending TXs (Nonce -> Tx)
    pending_txs: Arc<Mutex<BTreeMap<u64, PendingTransaction>>>,
    // Nonce tracker -- uses tokio::sync::Mutex to ensure nonce is only
    // incremented AFTER successful send (prevents nonce gaps on failure)
    local_nonce: tokio::sync::Mutex<u64>,
    metrics: MetricsService,
    cancel_token: CancellationToken,
}

impl TransactionManager {
    pub async fn new(
        executor: Arc<ChainExecutor>,
        storage: Arc<SledRepository>,
        metrics: MetricsService,
    ) -> Result<Self, InfrastructureError> {
        let manager = Self {
            executor,
            storage,
            pending_txs: Arc::new(Mutex::new(BTreeMap::new())),
            local_nonce: tokio::sync::Mutex::new(0),
            metrics,
            cancel_token: CancellationToken::new(),
        };

        manager.hydrate_from_storage().await?;
        manager.sync_nonce().await?;

        Ok(manager)
    }

    #[must_use]
    pub fn with_cancel_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = token;
        self
    }

    /// Load pending transactions from DB on startup
    async fn hydrate_from_storage(&self) -> Result<(), InfrastructureError> {
        let items = self.storage.scan(b"tx:").await?;
        let mut pending = self.pending_txs.lock();

        for (_, val) in items {
            if let Ok(tx) = serde_json::from_slice::<PendingTransaction>(&val) {
                if tx.status == TxStatus::Pending {
                    pending.insert(tx.nonce, tx);
                }
            }
        }
        info!(
            "Hydrated {} pending transactions from storage.",
            pending.len()
        );
        Ok(())
    }

    /// Sync nonce with chain (max of chain pending nonce, local pending TXs, and persisted floor).
    ///
    /// The persisted floor prevents nonce regression after a crash where in-flight
    /// transactions exist in the mempool but haven't yet been returned by the
    /// `eth_getTransactionCount(pending)` query.
    async fn sync_nonce(&self) -> Result<(), InfrastructureError> {
        // Query chain with `pending` block tag (includes mempool TXs).
        let chain_nonce = self.executor.get_nonce().await?.as_u64();

        // Load persisted nonce floor from Sled (best-effort; 0 if absent or corrupt).
        let persisted_nonce = match self.storage.get(KEY_NONCE_LOCAL).await? {
            Some(bytes) if bytes.len() == 8 => {
                u64::from_le_bytes(bytes.try_into().map_err(|_| {
                    InfrastructureError::Database("Corrupt persisted nonce value".into())
                })?)
            }
            _ => 0u64,
        };

        // Scope the parking_lot lock so it's dropped before the tokio mutex await
        let next = {
            let mut pending = self.pending_txs.lock();

            // Prune confirmed transactions from memory (if nonce < chain_nonce)
            let mut to_remove = Vec::new();
            for (&nonce, _) in pending.iter() {
                if nonce < chain_nonce {
                    to_remove.push(nonce);
                }
            }
            for nonce in to_remove {
                pending.remove(&nonce);
            }

            // Next nonce = max(chain, max_pending + 1, persisted_floor)
            let max_pending = pending.keys().last().map_or(chain_nonce, |&n| n + 1);
            self.metrics.eth_tx_pending.set(pending.len() as i64);
            std::cmp::max(std::cmp::max(chain_nonce, max_pending), persisted_nonce)
        };

        let mut nonce_guard = self.local_nonce.lock().await;
        *nonce_guard = next;
        drop(nonce_guard);

        // Persist the synced nonce so future restarts have a floor.
        self.persist_nonce(next).await;

        info!(
            chain_nonce,
            persisted_nonce,
            next_local = next,
            "Nonce synced."
        );
        Ok(())
    }

    /// Persist the local nonce to Sled (best-effort -- failures are logged, not propagated).
    async fn persist_nonce(&self, nonce: u64) {
        if let Err(e) = self
            .storage
            .put(KEY_NONCE_LOCAL, &nonce.to_le_bytes())
            .await
        {
            warn!("Failed to persist local nonce {nonce} to Sled: {e}");
        }
    }

    /// Submit a new transaction
    pub async fn submit(
        &self,
        id: String,
        to: Address,
        data: Bytes,
        gas_limit: U256,
    ) -> Result<H256, InfrastructureError> {
        // 20% buffer to handle base fee fluctuations (especially on L2s
        // like Arbitrum where base fee can change between estimation and inclusion)
        let raw_gas_price = self.executor.get_gas_price().await?;
        let gas_price = raw_gas_price + raw_gas_price / 5;

        // Lock nonce, send TX, increment only on success.
        // Prevents nonce gaps: if send_raw fails, the nonce
        // is NOT incremented and the next submit() reuses it.
        let mut nonce_guard = self.local_nonce.lock().await;
        let nonce = *nonce_guard;

        let tx_request = TransactionRequest::new()
            .to(to)
            .data(data.clone())
            .gas(gas_limit)
            .gas_price(gas_price)
            .nonce(nonce);

        let tx_hash = match self.executor.send_raw(tx_request).await {
            Ok(hash) => {
                *nonce_guard += 1;
                hash
            }
            Err(e) => {
                // Nonce NOT incremented -- next submit() will retry with same nonce
                warn!(
                    "TX {} send failed at nonce {}: {}. Nonce not incremented.",
                    id, nonce, e
                );
                return Err(e);
            }
        };
        let next_nonce = *nonce_guard;
        drop(nonce_guard);

        // Persist updated nonce so a crash between here and the next sync_nonce
        // doesn't cause this node to re-use a nonce already in the mempool.
        self.persist_nonce(next_nonce).await;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        let record = PendingTransaction {
            id: id.clone(),
            to: format!("{to:?}"),
            data: data.to_vec(),
            nonce,
            gas_limit: gas_limit.to_string(),
            gas_price: gas_price.to_string(),
            tx_hash: format!("{tx_hash:?}"),
            first_sent_at: now,
            last_update_at: now,
            status: TxStatus::Pending,
        };

        self.persist_tx(&record).await?;

        {
            let mut pending = self.pending_txs.lock();
            pending.insert(nonce, record);
            self.metrics.eth_tx_pending.set(pending.len() as i64);
        }

        info!(
            "queued TX {} (Nonce: {}) with Hash {:?}",
            id, nonce, tx_hash
        );
        Ok(tx_hash)
    }

    async fn persist_tx(&self, tx: &PendingTransaction) -> Result<(), InfrastructureError> {
        let key = format!("tx:{}", tx.nonce); // Key by nonce for easy ordering in DB scan if needed
        let bytes =
            serde_json::to_vec(tx).map_err(|e| InfrastructureError::Database(e.to_string()))?;
        self.storage.put(key.as_bytes(), &bytes).await
    }

    /// Background Monitoring Loop
    pub async fn run_monitor(&self) {
        info!("Transaction Monitor Active.");
        loop {
            // Cancellation-aware sleep between monitor cycles
            tokio::select! {
                () = sleep(Duration::from_secs(12)) => {}
                () = self.cancel_token.cancelled() => {
                    info!("Transaction Monitor shutting down (cancellation token).");
                    return;
                }
            }

            let pending_nonces: Vec<u64> = {
                let guard = self.pending_txs.lock();
                guard.keys().copied().collect()
            };

            if pending_nonces.is_empty() {
                continue;
            }

            // Sync chain nonce to see what confirmed
            if let Err(e) = self.sync_nonce().await {
                warn!("Failed to sync nonce in monitor: {}", e);
                continue;
            }

            // Re-acquire lock to process remaining pending items (some might have been removed by sync_nonce)
            let mut to_bump = Vec::new();
            {
                let guard = self.pending_txs.lock();
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs();

                for nonce in pending_nonces {
                    if let Some(tx) = guard.get(&nonce) {
                        // Check if it's been pending too long (> 60s)
                        if now - tx.last_update_at > 60 {
                            to_bump.push(tx.clone());
                        }
                    }
                }
            }

            for tx in to_bump {
                let tx_id = tx.id.clone();
                let tx_nonce = tx.nonce;
                if let Err(e) = self.bump_transaction(tx).await {
                    error!(
                        "Failed to bump transaction id={} (nonce={}): {}",
                        tx_id, tx_nonce, e
                    );
                }
            }
        }
    }

    async fn bump_transaction(
        &self,
        mut tx: PendingTransaction,
    ) -> Result<(), InfrastructureError> {
        info!(" Speeding up TX {} (Nonce: {})", tx.id, tx.nonce);

        let old_price = U256::from_dec_str(&tx.gas_price).map_err(|e| {
            InfrastructureError::Blockchain(format!(
                "Cannot parse gas_price '{}' for tx {}: {e}",
                tx.gas_price, tx.id
            ))
        })?;
        let current_network_price = self.executor.get_gas_price().await?;

        // Target: Max(CurrentNetwork, Old * 1.2)
        let bump_price = old_price * 120 / 100;
        let new_price = std::cmp::max(bump_price, current_network_price);

        let to_addr = Address::from_str(&tx.to)
            .map_err(|e| InfrastructureError::Blockchain(format!("Invalid To Address: {e}")))?;

        let gas_lim = U256::from_dec_str(&tx.gas_limit)
            .map_err(|e| InfrastructureError::Blockchain(format!("Invalid Gas Limit: {e}")))?;

        let req = TransactionRequest::new()
            .to(to_addr)
            .data(Bytes::from(tx.data.clone()))
            .gas(gas_lim)
            .nonce(tx.nonce)
            .gas_price(new_price);

        let new_hash = self.executor.send_raw(req).await?;

        tx.gas_price = new_price.to_string();
        tx.tx_hash = format!("{new_hash:?}");
        tx.last_update_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        tx.status = TxStatus::Replaced;

        self.persist_tx(&tx).await?;

        {
            let mut pending = self.pending_txs.lock();
            pending.insert(tx.nonce, tx);
        }

        Ok(())
    }
}
