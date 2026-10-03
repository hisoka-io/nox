use crate::blockchain::executor::{ChainExecutor, OutboxBroadcastError};
use crate::blockchain::transaction_plan::{TransactionPlan, BASIS_POINTS};
use crate::config::MAX_BUFFER_BPS;
use crate::infra::storage::{decode_stored_transaction, CreateOutboxResult, SledRepository};
use crate::telemetry::metrics::MetricsService;
use ethers::prelude::*;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::utils::{keccak256, rlp::Rlp};
use nox_core::traits::{IStorageRepository, InfrastructureError};
use nox_core::{
    DecodedTransaction, ExecutionId, LegacyPendingTransaction, LegacyTxStatus,
    PendingTransactionV2, QuoteStatusV2, TxStatusV2,
};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};

const KEY_NONCE_LOCAL: &[u8] = b"nonce:local";
const MONITOR_INTERVAL_SECS: u64 = 12;
const REPLACEMENT_AGE_SECS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmittedTransaction {
    pub execution_id: ExecutionId,
    pub transaction_hash: H256,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SubmitError {
    #[error("execution {execution_id:?} already maps to {transaction_hash:?}")]
    Duplicate {
        execution_id: ExecutionId,
        transaction_hash: H256,
    },
    #[error("transaction gas plan rejected: {detail}")]
    GasPlan { detail: String },
    #[error("transaction outbox persistence failed: {detail}")]
    Persistence { detail: String },
    #[error("transaction signing failed: {detail}")]
    Signing { detail: String },
    #[error("transaction broadcast failed: {detail}")]
    Broadcast { detail: String },
    #[error("transaction broadcast outcome is ambiguous for {transaction_hash:?}: {detail}")]
    AmbiguousBroadcast {
        transaction_hash: H256,
        detail: String,
    },
    /// The signed nonce was consumed by another transaction from the exit wallet. The outbox
    /// record is retired and the transaction can never be mined.
    #[error("transaction nonce {nonce} was consumed by another transaction from the exit wallet")]
    NonceConsumed { nonce: u64 },
}

/// Wait before the final receipt lookup that decides a transaction was superseded.
const SUPERSEDED_SETTLE_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

/// How a nonce conflict reported by the RPC was resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NonceConflict {
    /// One of the stored hashes has a receipt.
    Terminal(TxStatusV2),
    /// The chain nonce moved past this transaction and none of its hashes was mined.
    Superseded,
    /// Not provable yet (for example, the conflicting transaction is still pending).
    Unresolved,
}

pub struct TransactionManager {
    executor: Arc<ChainExecutor>,
    storage: Arc<SledRepository>,
    pending_txs: Arc<Mutex<BTreeMap<u64, DecodedTransaction>>>,
    local_nonce: tokio::sync::Mutex<u64>,
    metrics: MetricsService,
    replacement_step_bps: u32,
    submission_blocked: AtomicBool,
    cancel_token: CancellationToken,
}

impl TransactionManager {
    pub(crate) fn quote_storage(&self) -> Arc<SledRepository> {
        self.storage.clone()
    }

    /// True while an unresolved outbox transaction pauses new paid submissions.
    #[must_use]
    pub fn is_submission_blocked(&self) -> bool {
        self.submission_blocked.load(Ordering::SeqCst)
    }

    fn block_submissions(&self) {
        self.submission_blocked.store(true, Ordering::SeqCst);
        self.metrics.eth_submission_blocked.set(1);
    }

    pub async fn new(
        executor: Arc<ChainExecutor>,
        storage: Arc<SledRepository>,
        metrics: MetricsService,
        replacement_step_bps: u32,
    ) -> Result<Self, InfrastructureError> {
        if replacement_step_bps == 0 || replacement_step_bps > MAX_BUFFER_BPS {
            return Err(InfrastructureError::Blockchain(format!(
                "replacement_step_bps must be in 1..={MAX_BUFFER_BPS}"
            )));
        }
        let manager = Self {
            executor,
            storage,
            pending_txs: Arc::new(Mutex::new(BTreeMap::new())),
            local_nonce: tokio::sync::Mutex::new(0),
            metrics,
            replacement_step_bps,
            submission_blocked: AtomicBool::new(false),
            cancel_token: CancellationToken::new(),
        };
        manager.hydrate_from_storage().await?;
        manager.sync_nonce().await?;
        manager.recover_prepared().await?;
        Ok(manager)
    }

    #[must_use]
    pub fn with_cancel_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = token;
        self
    }

    async fn hydrate_from_storage(&self) -> Result<(), InfrastructureError> {
        let records = self.storage.scan(b"tx:").await?;
        let mut hydrated = BTreeMap::new();
        for (_, bytes) in records {
            let decoded = decode_stored_transaction(&bytes)?;
            match &decoded {
                DecodedTransaction::V2(transaction)
                    if !matches!(transaction.status, TxStatusV2::Mined | TxStatusV2::Failed) =>
                {
                    hydrated.insert(transaction.nonce, decoded);
                }
                DecodedTransaction::Legacy(transaction)
                    if matches!(
                        transaction.status,
                        LegacyTxStatus::Pending | LegacyTxStatus::Replaced
                    ) =>
                {
                    hydrated.insert(transaction.nonce, decoded);
                }
                _ => {}
            }
        }
        self.metrics.eth_tx_pending.set(hydrated.len() as i64);
        *self.pending_txs.lock() = hydrated;
        Ok(())
    }

    async fn sync_nonce(&self) -> Result<(), InfrastructureError> {
        let chain_nonce = self.executor.get_nonce().await?.as_u64();
        let persisted_nonce = match self.storage.get(KEY_NONCE_LOCAL).await? {
            Some(bytes) if bytes.len() == 8 => {
                u64::from_le_bytes(bytes.try_into().map_err(|_| {
                    InfrastructureError::Database("corrupt persisted nonce floor".to_string())
                })?)
            }
            Some(_) => {
                return Err(InfrastructureError::Database(
                    "corrupt persisted nonce floor".to_string(),
                ))
            }
            None => 0,
        };
        let pending_floor = self
            .pending_txs
            .lock()
            .keys()
            .next_back()
            .copied()
            .and_then(|nonce| nonce.checked_add(1))
            .unwrap_or(0);
        *self.local_nonce.lock().await = chain_nonce.max(persisted_nonce).max(pending_floor);
        Ok(())
    }

    async fn recover_prepared(&self) -> Result<(), InfrastructureError> {
        let prepared: Vec<PendingTransactionV2> = self
            .pending_txs
            .lock()
            .values()
            .filter_map(|record| match record {
                DecodedTransaction::V2(transaction)
                    if matches!(
                        transaction.status,
                        TxStatusV2::Prepared | TxStatusV2::ReplacementPrepared
                    ) =>
                {
                    Some(transaction.clone())
                }
                _ => None,
            })
            .collect();
        for mut transaction in prepared {
            let expected_hash = parse_hash(&transaction.tx_hash)?;
            decode_raw(
                &transaction,
                self.executor.address(),
                self.executor.chain_id(),
            )?;
            if H256::from(keccak256(&transaction.raw_signed_tx)) != expected_hash {
                return Err(InfrastructureError::Database(
                    "stored raw transaction hash mismatch".to_string(),
                ));
            }
            match self
                .executor
                .broadcast_outbox_raw_signed_tx(&transaction.raw_signed_tx)
                .await
            {
                Ok(hash) if hash == expected_hash => {
                    transaction.status = match transaction.status {
                        TxStatusV2::Prepared => TxStatusV2::Submitted,
                        TxStatusV2::ReplacementPrepared => TxStatusV2::Replaced,
                        _ => {
                            return Err(InfrastructureError::Database(
                                "prepared recovery status changed unexpectedly".to_string(),
                            ))
                        }
                    };
                    transaction.last_update_at = unix_now()?;
                    self.storage.persist_v2_durably(&transaction).await?;
                    self.pending_txs
                        .lock()
                        .insert(transaction.nonce, DecodedTransaction::V2(transaction));
                }
                Ok(_) => {
                    return Err(InfrastructureError::Blockchain(
                        "recovered broadcast hash mismatch".to_string(),
                    ))
                }
                Err(OutboxBroadcastError::AlreadyKnown) => {
                    transaction.status = match transaction.status {
                        TxStatusV2::Prepared => TxStatusV2::Submitted,
                        TxStatusV2::ReplacementPrepared => TxStatusV2::Replaced,
                        _ => {
                            return Err(InfrastructureError::Database(
                                "prepared recovery status changed unexpectedly".to_string(),
                            ))
                        }
                    };
                    transaction.last_update_at = unix_now()?;
                    self.storage.persist_v2_durably(&transaction).await?;
                    self.pending_txs
                        .lock()
                        .insert(transaction.nonce, DecodedTransaction::V2(transaction));
                }
                Err(OutboxBroadcastError::Uncertain { .. }) => {
                    if let Some(status) = self.reconcile_hashes(&transaction).await? {
                        transaction.status = status;
                        transaction.last_update_at = unix_now()?;
                        self.storage.persist_v2_durably(&transaction).await?;
                        let mut pending = self.pending_txs.lock();
                        pending.remove(&transaction.nonce);
                        self.metrics.eth_tx_pending.set(pending.len() as i64);
                    } else {
                        self.block_submissions();
                        warn!("prepared transaction nonce is consumed but no stored hash is confirmed");
                    }
                }
                Err(OutboxBroadcastError::Rejected { .. }) => {
                    self.block_submissions();
                    warn!("prepared transaction received a pre-acceptance rejection; nonce remains reserved");
                }
                Err(
                    error @ (OutboxBroadcastError::NonceTooLow
                    | OutboxBroadcastError::ReplacementUnderpriced),
                ) => match self.resolve_nonce_conflict(&transaction).await {
                    NonceConflict::Terminal(status) => {
                        transaction.status = status;
                        transaction.last_update_at = unix_now()?;
                        self.storage.persist_v2_durably(&transaction).await?;
                        let mut pending = self.pending_txs.lock();
                        pending.remove(&transaction.nonce);
                        self.metrics.eth_tx_pending.set(pending.len() as i64);
                    }
                    NonceConflict::Superseded => {
                        self.retire_superseded(transaction).await?;
                        let mut nonce_guard = self.local_nonce.lock().await;
                        self.resync_nonce_floor(&mut nonce_guard).await;
                    }
                    NonceConflict::Unresolved => {
                        self.block_submissions();
                        warn!(
                            nonce = transaction.nonce,
                            error = %error,
                            "prepared transaction nonce is held by another transaction; waiting for it to settle"
                        );
                    }
                },
            }
        }
        self.refresh_submission_block();
        Ok(())
    }

    /// Decides what a "nonce too low" or "replacement underpriced" answer means for a stored
    /// transaction. Lookup failures leave the conflict unresolved, so nothing is retired on
    /// incomplete evidence.
    async fn resolve_nonce_conflict(&self, transaction: &PendingTransactionV2) -> NonceConflict {
        match self.reconcile_hashes(transaction).await {
            Ok(Some(status)) => return NonceConflict::Terminal(status),
            Ok(None) => {}
            Err(error) => {
                warn!(nonce = transaction.nonce, error = %error, "nonce conflict receipt lookup failed");
                return NonceConflict::Unresolved;
            }
        }
        let confirmed = match self.executor.get_confirmed_nonce().await {
            Ok(confirmed) => confirmed,
            Err(error) => {
                warn!(nonce = transaction.nonce, error = %error, "nonce conflict nonce lookup failed");
                return NonceConflict::Unresolved;
            }
        };
        if confirmed <= U256::from(transaction.nonce) {
            return NonceConflict::Unresolved;
        }
        // The nonce is mined. Wait for load-balanced RPC backends to catch up, then look
        // again in case it was this transaction that landed.
        tokio::time::sleep(SUPERSEDED_SETTLE_DELAY).await;
        match self.reconcile_hashes(transaction).await {
            Ok(Some(status)) => NonceConflict::Terminal(status),
            Ok(None) => NonceConflict::Superseded,
            Err(error) => {
                warn!(nonce = transaction.nonce, error = %error, "nonce conflict receipt lookup failed");
                NonceConflict::Unresolved
            }
        }
    }

    /// Retires a transaction whose nonce was mined by a different transaction from the same
    /// wallet (for example a claim signed outside the node). It can never be mined, so its
    /// quote is released without loss and the record leaves the pending set.
    async fn retire_superseded(
        &self,
        mut transaction: PendingTransactionV2,
    ) -> Result<(), InfrastructureError> {
        warn!(
            nonce = transaction.nonce,
            "exit wallet nonce was used by another transaction; retiring the outbox record"
        );
        if let Some(quote) = self.storage.load_quote(transaction.execution_id).await? {
            if quote.status != QuoteStatusV2::Outstanding {
                self.storage
                    .finalize_quote_durably(
                        transaction.execution_id,
                        QuoteStatusV2::Rejected,
                        U256::zero(),
                        unix_now()?,
                    )
                    .await?;
            }
        }
        transaction.status = TxStatusV2::Failed;
        transaction.last_update_at = unix_now()?;
        self.storage.persist_v2_durably(&transaction).await?;
        {
            let mut pending = self.pending_txs.lock();
            pending.remove(&transaction.nonce);
            self.metrics.eth_tx_pending.set(pending.len() as i64);
        }
        self.metrics
            .eth_tx_outcomes_total
            .get_or_create(&vec![
                ("type".into(), "paid_v2".into()),
                ("result".into(), "superseded".into()),
            ])
            .inc();
        Ok(())
    }

    /// Raises the local nonce to the chain's pending nonce when the wallet signed elsewhere.
    /// Never lowers it, and keeps the local value when the chain cannot be read.
    async fn resync_nonce_floor(&self, local_nonce: &mut u64) {
        let chain_nonce = match self.executor.get_nonce().await {
            Ok(nonce) if nonce <= U256::from(u64::MAX) => nonce.low_u64(),
            Ok(_) => {
                warn!("chain nonce exceeds u64; keeping local nonce");
                return;
            }
            Err(error) => {
                warn!(error = %error, "chain nonce lookup failed; keeping local nonce");
                return;
            }
        };
        if chain_nonce > *local_nonce {
            warn!(
                local_nonce = *local_nonce,
                chain_nonce, "exit wallet nonce advanced outside the node; resynchronising"
            );
            *local_nonce = chain_nonce;
        }
    }

    pub async fn submit_planned(
        &self,
        execution_id: ExecutionId,
        to: Address,
        data: Bytes,
        plan: TransactionPlan,
    ) -> Result<SubmittedTransaction, SubmitError> {
        validate_plan(&plan)?;
        let mut nonce_guard = self.local_nonce.lock().await;
        if self.submission_blocked.load(Ordering::SeqCst) {
            if let Some(transaction_hash) =
                self.pending_txs
                    .lock()
                    .values()
                    .find_map(|record| match record {
                        DecodedTransaction::V2(transaction)
                            if transaction.execution_id == execution_id =>
                        {
                            parse_hash_submit(&transaction.tx_hash).ok()
                        }
                        _ => None,
                    })
            {
                return Err(SubmitError::Duplicate {
                    execution_id,
                    transaction_hash,
                });
            }
            return Err(SubmitError::Persistence {
                detail: "submission blocked by unresolved prepared transaction".to_string(),
            });
        }
        self.resync_nonce_floor(&mut nonce_guard).await;
        let nonce = *nonce_guard;
        let raw_signed_tx = self
            .executor
            .sign_legacy_transaction(
                to,
                data.clone(),
                U256::from(nonce),
                plan.gas_limit,
                plan.initial_fee_per_gas,
            )
            .await
            .map_err(|error| SubmitError::Signing {
                detail: error.to_string(),
            })?;
        let transaction_hash = H256::from(keccak256(&raw_signed_tx));
        let now = unix_now().map_err(|error| SubmitError::Persistence {
            detail: error.to_string(),
        })?;
        let record = PendingTransactionV2 {
            execution_id,
            to: format!("{to:?}"),
            data_hash: keccak256(&data),
            nonce,
            gas_limit: plan.gas_limit.to_string(),
            gas_price: plan.initial_fee_per_gas.to_string(),
            maximum_fee_per_gas: plan.maximum_fee_per_gas.to_string(),
            raw_signed_tx: raw_signed_tx.to_vec(),
            tx_hash: format!("{transaction_hash:?}"),
            prior_transaction_hashes: Vec::new(),
            replacement_attempts: 0,
            first_sent_at: now,
            last_update_at: now,
            status: TxStatusV2::Prepared,
        };
        let next_nonce = nonce.checked_add(1).ok_or_else(|| SubmitError::GasPlan {
            detail: "nonce overflow".to_string(),
        })?;
        match self
            .storage
            .create_outbox_durably(execution_id, &record, next_nonce)
            .await
            .map_err(|error| SubmitError::Persistence {
                detail: error.to_string(),
            })? {
            CreateOutboxResult::Created => {
                *nonce_guard = next_nonce;
                self.pending_txs
                    .lock()
                    .insert(nonce, DecodedTransaction::V2(record.clone()));
            }
            CreateOutboxResult::Existing(existing) => {
                return Err(SubmitError::Duplicate {
                    execution_id,
                    transaction_hash: parse_hash_submit(&existing.tx_hash)?,
                });
            }
        }
        let broadcast_hash = match self
            .executor
            .broadcast_outbox_raw_signed_tx(&record.raw_signed_tx)
            .await
        {
            Ok(hash) if hash == transaction_hash => hash,
            Ok(_) => {
                self.block_submissions();
                return Err(SubmitError::AmbiguousBroadcast {
                    transaction_hash,
                    detail: "RPC returned a different transaction hash".to_string(),
                });
            }
            Err(OutboxBroadcastError::AlreadyKnown) => transaction_hash,
            Err(
                error @ (OutboxBroadcastError::NonceTooLow
                | OutboxBroadcastError::ReplacementUnderpriced),
            ) => {
                if self.resolve_nonce_conflict(&record).await == NonceConflict::Superseded {
                    if let Err(retire_error) = self.retire_superseded(record).await {
                        self.block_submissions();
                        return Err(SubmitError::AmbiguousBroadcast {
                            transaction_hash,
                            detail: retire_error.to_string(),
                        });
                    }
                    self.resync_nonce_floor(&mut nonce_guard).await;
                    self.refresh_submission_block();
                    return Err(SubmitError::NonceConsumed { nonce });
                }
                self.block_submissions();
                return Err(SubmitError::AmbiguousBroadcast {
                    transaction_hash,
                    detail: error.to_string(),
                });
            }
            Err(
                error @ (OutboxBroadcastError::Rejected { .. }
                | OutboxBroadcastError::Uncertain { .. }),
            ) => {
                self.block_submissions();
                return Err(SubmitError::AmbiguousBroadcast {
                    transaction_hash,
                    detail: error.to_string(),
                });
            }
        };
        if broadcast_hash == transaction_hash {
            let mut submitted = record;
            submitted.status = TxStatusV2::Submitted;
            submitted.last_update_at = match unix_now() {
                Ok(timestamp) => timestamp,
                Err(error) => {
                    self.block_submissions();
                    return Err(SubmitError::AmbiguousBroadcast {
                        transaction_hash,
                        detail: error.to_string(),
                    });
                }
            };
            if let Err(error) = self.storage.persist_v2_durably(&submitted).await {
                self.block_submissions();
                return Err(SubmitError::AmbiguousBroadcast {
                    transaction_hash,
                    detail: error.to_string(),
                });
            }
            self.pending_txs
                .lock()
                .insert(nonce, DecodedTransaction::V2(submitted));
            Ok(SubmittedTransaction {
                execution_id,
                transaction_hash,
            })
        } else {
            Err(SubmitError::Broadcast {
                detail: "broadcast hash validation failed".to_string(),
            })
        }
    }

    pub async fn run_monitor(&self) {
        loop {
            tokio::select! {
                () = sleep(Duration::from_secs(MONITOR_INTERVAL_SECS)) => {}
                () = self.cancel_token.cancelled() => return,
            }
            if let Err(error) = self.monitor_once().await {
                error!("transaction monitor failed: {error}");
            }
            self.refresh_gauges().await;
        }
    }

    /// Exports wallet balance and quote reservations. Failures only log.
    async fn refresh_gauges(&self) {
        match self.executor.check_gas_health().await {
            Ok((balance, low)) => {
                self.metrics
                    .eth_wallet_balance_gwei
                    .set(gwei_gauge(balance));
                self.metrics.eth_wallet_balance_low.set(i64::from(low));
            }
            Err(error) => warn!(error = %error, "wallet balance lookup failed"),
        }
        match self.storage.quote_counters().await {
            Ok(counters) => {
                self.metrics
                    .quote_outstanding
                    .set(i64::try_from(counters.outstanding).unwrap_or(i64::MAX));
                self.metrics
                    .quote_pending_sponsored_gas
                    .set(i64::try_from(counters.pending_sponsored_gas).unwrap_or(i64::MAX));
                self.metrics
                    .quote_rolling_loss_gwei
                    .set(gwei_gauge(counters.rolling_loss_native));
            }
            Err(error) => warn!(error = %error, "quote counter lookup failed"),
        }
    }

    async fn monitor_once(&self) -> Result<(), InfrastructureError> {
        self.recover_prepared().await?;
        let legacy_candidates: Vec<LegacyPendingTransaction> = self
            .pending_txs
            .lock()
            .values()
            .filter_map(|record| match record {
                DecodedTransaction::Legacy(transaction)
                    if matches!(
                        transaction.status,
                        LegacyTxStatus::Pending | LegacyTxStatus::Replaced
                    ) =>
                {
                    Some(transaction.clone())
                }
                _ => None,
            })
            .collect();
        for mut transaction in legacy_candidates {
            let transaction_hash = parse_hash(&transaction.tx_hash)?;
            if let Some(receipt) = self
                .executor
                .get_transaction_receipt(transaction_hash)
                .await?
            {
                transaction.status = if receipt.status == Some(U64::one()) {
                    LegacyTxStatus::Mined
                } else {
                    LegacyTxStatus::Failed
                };
                transaction.last_update_at = unix_now()?;
                self.storage
                    .persist_legacy_terminal_durably(&transaction)
                    .await?;
                let mut pending = self.pending_txs.lock();
                pending.remove(&transaction.nonce);
                self.metrics.eth_tx_pending.set(pending.len() as i64);
            }
        }
        self.refresh_submission_block();
        let wall_timestamp = unix_now()?;
        let chain_timestamp = self.executor.latest_block_timestamp().await?;
        self.storage
            .prune_expired_quotes_durably(chain_timestamp)
            .await?;
        let candidates: Vec<PendingTransactionV2> = self
            .pending_txs
            .lock()
            .values()
            .filter_map(|record| match record {
                DecodedTransaction::V2(transaction)
                    if matches!(
                        transaction.status,
                        TxStatusV2::Submitted | TxStatusV2::Replaced
                    ) && wall_timestamp.saturating_sub(transaction.last_update_at)
                        > REPLACEMENT_AGE_SECS =>
                {
                    Some(transaction.clone())
                }
                _ => None,
            })
            .collect();
        for mut transaction in candidates {
            if let Some(status) = self.reconcile_hashes(&transaction).await? {
                transaction.status = status;
                transaction.last_update_at = wall_timestamp;
                self.storage.persist_v2_durably(&transaction).await?;
                let mut pending = self.pending_txs.lock();
                pending.remove(&transaction.nonce);
                self.metrics.eth_tx_pending.set(pending.len() as i64);
                continue;
            }
            self.replace(transaction).await?;
        }
        Ok(())
    }

    async fn replace(
        &self,
        mut transaction: PendingTransactionV2,
    ) -> Result<(), InfrastructureError> {
        let decoded = decode_raw(
            &transaction,
            self.executor.address(),
            self.executor.chain_id(),
        )?;
        let current_price = U256::from_dec_str(&transaction.gas_price).map_err(|error| {
            InfrastructureError::Database(format!("stored gas price is invalid: {error}"))
        })?;
        let maximum_price =
            U256::from_dec_str(&transaction.maximum_fee_per_gas).map_err(|error| {
                InfrastructureError::Database(format!(
                    "stored maximum gas price is invalid: {error}"
                ))
            })?;
        let network = self.executor.get_gas_price().await?;
        let Some(required) = replacement_price(
            current_price,
            network,
            maximum_price,
            self.replacement_step_bps,
        )?
        else {
            return Ok(());
        };
        let raw = self
            .executor
            .sign_legacy_transaction(
                decoded.to,
                decoded.data,
                U256::from(transaction.nonce),
                decoded.gas_limit,
                required,
            )
            .await?;
        let prior_hash = transaction.tx_hash.clone();
        transaction.prior_transaction_hashes.push(prior_hash);
        transaction.replacement_attempts = transaction
            .replacement_attempts
            .checked_add(1)
            .ok_or_else(|| {
                InfrastructureError::Blockchain("replacement attempt counter overflow".to_string())
            })?;
        transaction.gas_price = required.to_string();
        transaction.raw_signed_tx = raw.to_vec();
        transaction.tx_hash = format!("{:?}", H256::from(keccak256(&raw)));
        transaction.last_update_at = unix_now()?;
        transaction.status = TxStatusV2::ReplacementPrepared;
        self.storage.persist_v2_durably(&transaction).await?;
        self.pending_txs.lock().insert(
            transaction.nonce,
            DecodedTransaction::V2(transaction.clone()),
        );
        let expected_hash = parse_hash(&transaction.tx_hash)?;
        match self
            .executor
            .broadcast_outbox_raw_signed_tx(&transaction.raw_signed_tx)
            .await
        {
            Ok(hash) if hash == expected_hash => {}
            Ok(_) => {
                self.block_submissions();
                return Err(InfrastructureError::Blockchain(
                    "replacement broadcast hash mismatch".to_string(),
                ));
            }
            Err(OutboxBroadcastError::AlreadyKnown) => {}
            Err(
                error @ (OutboxBroadcastError::Rejected { .. }
                | OutboxBroadcastError::Uncertain { .. }
                | OutboxBroadcastError::NonceTooLow
                | OutboxBroadcastError::ReplacementUnderpriced),
            ) => {
                if let Some(status) = self.reconcile_hashes(&transaction).await? {
                    transaction.status = status;
                    transaction.last_update_at = unix_now()?;
                    self.storage.persist_v2_durably(&transaction).await?;
                    let mut pending = self.pending_txs.lock();
                    pending.remove(&transaction.nonce);
                    self.metrics.eth_tx_pending.set(pending.len() as i64);
                    return Ok(());
                }
                self.block_submissions();
                return Err(InfrastructureError::Blockchain(format!(
                    "replacement outcome remains unresolved: {error}"
                )));
            }
        }
        self.metrics
            .eth_tx_outcomes_total
            .get_or_create(&vec![
                ("type".into(), "paid_v2".into()),
                ("result".into(), "replaced".into()),
            ])
            .inc();
        transaction.status = TxStatusV2::Replaced;
        transaction.last_update_at = unix_now()?;
        if let Err(error) = self.storage.persist_v2_durably(&transaction).await {
            self.block_submissions();
            return Err(error);
        }
        self.pending_txs
            .lock()
            .insert(transaction.nonce, DecodedTransaction::V2(transaction));
        Ok(())
    }

    fn refresh_submission_block(&self) {
        let has_unresolved = self.pending_txs.lock().values().any(|record| {
            matches!(
                record,
                DecodedTransaction::V2(PendingTransactionV2 {
                    status: TxStatusV2::Prepared | TxStatusV2::ReplacementPrepared,
                    ..
                })
            )
        });
        self.submission_blocked
            .store(has_unresolved, Ordering::SeqCst);
        self.metrics
            .eth_submission_blocked
            .set(i64::from(has_unresolved));
    }

    async fn reconcile_hashes(
        &self,
        transaction: &PendingTransactionV2,
    ) -> Result<Option<TxStatusV2>, InfrastructureError> {
        for encoded_hash in
            std::iter::once(&transaction.tx_hash).chain(transaction.prior_transaction_hashes.iter())
        {
            let hash = parse_hash(encoded_hash)?;
            if let Some(receipt) = self.executor.get_transaction_receipt(hash).await? {
                let (succeeded, loss) = sponsored_receipt_outcome(&receipt)?;
                if let Some(quote) = self.storage.load_quote(transaction.execution_id).await? {
                    if quote.status == QuoteStatusV2::Outstanding {
                        return Err(InfrastructureError::Database(
                            "terminal receipt found for a quote that was never inflight"
                                .to_string(),
                        ));
                    }
                    self.storage
                        .finalize_quote_durably(
                            transaction.execution_id,
                            if succeeded {
                                QuoteStatusV2::Confirmed
                            } else {
                                QuoteStatusV2::Reverted
                            },
                            loss,
                            unix_now()?,
                        )
                        .await?;
                }
                self.metrics
                    .eth_tx_outcomes_total
                    .get_or_create(&vec![
                        ("type".into(), "paid_v2".into()),
                        (
                            "result".into(),
                            if succeeded { "mined" } else { "reverted" }.into(),
                        ),
                    ])
                    .inc();
                return Ok(Some(if succeeded {
                    TxStatusV2::Mined
                } else {
                    TxStatusV2::Failed
                }));
            }
        }
        Ok(None)
    }
}

/// Wei to a gwei gauge value, saturating at `i64::MAX`.
fn gwei_gauge(wei: U256) -> i64 {
    let gwei = wei / U256::exp10(9);
    if gwei > U256::from(i64::MAX.unsigned_abs()) {
        i64::MAX
    } else {
        i64::try_from(gwei.low_u64()).unwrap_or(i64::MAX)
    }
}

fn sponsored_receipt_outcome(
    receipt: &TransactionReceipt,
) -> Result<(bool, U256), InfrastructureError> {
    match receipt.status {
        Some(status) if status == U64::one() => Ok((true, U256::zero())),
        Some(status) if status.is_zero() => {
            let gas_used = receipt.gas_used.ok_or_else(|| {
                InfrastructureError::Blockchain(
                    "reverted sponsored receipt is missing gas_used".to_string(),
                )
            })?;
            let effective_gas_price = receipt.effective_gas_price.ok_or_else(|| {
                InfrastructureError::Blockchain(
                    "reverted sponsored receipt is missing effective_gas_price".to_string(),
                )
            })?;
            gas_used
                .checked_mul(effective_gas_price)
                .map(|loss| (false, loss))
                .ok_or_else(|| {
                    InfrastructureError::Blockchain(
                        "reverted sponsored receipt cost overflow".to_string(),
                    )
                })
        }
        _ => Err(InfrastructureError::Blockchain(
            "transaction receipt has invalid status".to_string(),
        )),
    }
}

struct DecodedRaw {
    to: Address,
    data: Bytes,
    gas_limit: U256,
}

fn decode_raw(
    transaction: &PendingTransactionV2,
    expected_signer: Address,
    expected_chain_id: u64,
) -> Result<DecodedRaw, InfrastructureError> {
    if H256::from(keccak256(&transaction.raw_signed_tx)) != parse_hash(&transaction.tx_hash)? {
        return Err(InfrastructureError::Database(
            "stored raw transaction hash mismatch".to_string(),
        ));
    }
    let (typed, signature) = TypedTransaction::decode_signed(&Rlp::new(&transaction.raw_signed_tx))
        .map_err(|error| {
            InfrastructureError::Database(format!("stored signed transaction is invalid: {error}"))
        })?;
    let signer = signature.recover(typed.sighash()).map_err(|error| {
        InfrastructureError::Database(format!("stored signer recovery failed: {error}"))
    })?;
    let to = match typed.to() {
        Some(NameOrAddress::Address(address)) => address.to_owned(),
        _ => {
            return Err(InfrastructureError::Database(
                "stored target is not an address".to_string(),
            ))
        }
    };
    if format!("{to:?}") != transaction.to || signer != expected_signer {
        return Err(InfrastructureError::Database(
            "stored transaction identity mismatch".to_string(),
        ));
    }
    if typed.chain_id().map(|chain_id| chain_id.as_u64()) != Some(expected_chain_id) {
        return Err(InfrastructureError::Database(
            "stored chain ID mismatch".to_string(),
        ));
    }
    let data = typed.data().cloned().unwrap_or_default();
    if keccak256(&data) != transaction.data_hash {
        return Err(InfrastructureError::Database(
            "stored calldata hash mismatch".to_string(),
        ));
    }
    let gas_limit = typed
        .gas()
        .copied()
        .ok_or_else(|| InfrastructureError::Database("stored gas limit missing".to_string()))?;
    if gas_limit.to_string() != transaction.gas_limit
        || typed.nonce().copied() != Some(U256::from(transaction.nonce))
    {
        return Err(InfrastructureError::Database(
            "stored nonce or gas limit mismatch".to_string(),
        ));
    }
    if typed.gas_price().map(|price| price.to_string()) != Some(transaction.gas_price.clone()) {
        return Err(InfrastructureError::Database(
            "stored gas price mismatch".to_string(),
        ));
    }
    let maximum_fee = U256::from_dec_str(&transaction.maximum_fee_per_gas).map_err(|error| {
        InfrastructureError::Database(format!("stored maximum gas price is invalid: {error}"))
    })?;
    let current_fee = U256::from_dec_str(&transaction.gas_price).map_err(|error| {
        InfrastructureError::Database(format!("stored gas price is invalid: {error}"))
    })?;
    if current_fee > maximum_fee {
        return Err(InfrastructureError::Database(
            "stored gas price exceeds profitable ceiling".to_string(),
        ));
    }
    Ok(DecodedRaw {
        to,
        data,
        gas_limit,
    })
}

fn validate_plan(plan: &TransactionPlan) -> Result<(), SubmitError> {
    if plan.gas_limit.is_zero() || plan.initial_fee_per_gas.is_zero() {
        return Err(SubmitError::GasPlan {
            detail: "gas limit and initial fee must be positive".to_string(),
        });
    }
    if plan.initial_fee_per_gas > plan.maximum_fee_per_gas {
        return Err(SubmitError::GasPlan {
            detail: "initial fee exceeds maximum fee".to_string(),
        });
    }
    Ok(())
}

fn replacement_price(
    current_price: U256,
    network_price: U256,
    maximum_price: U256,
    step_bps: u32,
) -> Result<Option<U256>, InfrastructureError> {
    let stepped = current_price
        .checked_mul(U256::from(BASIS_POINTS + u128::from(step_bps)))
        .and_then(|value| value.checked_add(U256::from(BASIS_POINTS - 1)))
        .map(|value| value / U256::from(BASIS_POINTS))
        .ok_or_else(|| {
            InfrastructureError::Blockchain("replacement gas-price arithmetic overflow".to_string())
        })?;
    let required = stepped.max(network_price);
    Ok((required <= maximum_price).then_some(required))
}

fn parse_hash(encoded: &str) -> Result<H256, InfrastructureError> {
    H256::from_str(encoded).map_err(|error| {
        InfrastructureError::Database(format!("stored transaction hash is invalid: {error}"))
    })
}

fn parse_hash_submit(encoded: &str) -> Result<H256, SubmitError> {
    H256::from_str(encoded).map_err(|error| SubmitError::Persistence {
        detail: format!("stored transaction hash is invalid: {error}"),
    })
}

fn unix_now() -> Result<u64, InfrastructureError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| InfrastructureError::Database("system clock is before Unix epoch".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NoxConfig;

    async fn dependencies() -> (Arc<ChainExecutor>, Arc<SledRepository>, MetricsService) {
        let mut config = NoxConfig::default();
        config.chain_id = 31_337;
        config.eth_wallet_private_key =
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string();
        let executor = Arc::new(ChainExecutor::new(&config).await.expect("test executor"));
        let directory = tempfile::tempdir().expect("temporary directory");
        let storage = Arc::new(SledRepository::new(directory.keep()).expect("test storage"));
        (executor, storage, MetricsService::new())
    }

    #[tokio::test]
    async fn constructor_rejects_invalid_replacement_policy_before_rpc() {
        let (executor, storage, metrics) = dependencies().await;
        assert!(
            TransactionManager::new(executor.clone(), storage.clone(), metrics.clone(), 0)
                .await
                .is_err()
        );
        assert!(
            TransactionManager::new(executor, storage, metrics, MAX_BUFFER_BPS + 1)
                .await
                .is_err()
        );
    }

    #[test]
    fn replacement_step_is_exact_and_ceiling_blocks_higher_bid() {
        assert_eq!(
            replacement_price(U256::from(100), U256::from(110), U256::from(120), 2_000,).unwrap(),
            Some(U256::from(120)),
        );
        assert_eq!(
            replacement_price(U256::from(100), U256::from(121), U256::from(120), 2_000,).unwrap(),
            None,
        );
    }

    #[tokio::test]
    async fn signed_record_validation_binds_all_transaction_fields() {
        let (executor, _, _) = dependencies().await;
        let to = Address::from_low_u64_be(9);
        let data = Bytes::from(vec![1, 2, 3]);
        let raw = executor
            .sign_legacy_transaction(
                to,
                data.clone(),
                U256::from(4),
                U256::from(21_000),
                U256::from(10),
            )
            .await
            .unwrap();
        let base = PendingTransactionV2 {
            execution_id: [1; 32],
            to: format!("{to:?}"),
            data_hash: keccak256(&data),
            nonce: 4,
            gas_limit: "21000".to_string(),
            gas_price: "10".to_string(),
            maximum_fee_per_gas: "20".to_string(),
            raw_signed_tx: raw.to_vec(),
            tx_hash: format!("{:?}", H256::from(keccak256(&raw))),
            prior_transaction_hashes: Vec::new(),
            replacement_attempts: 0,
            first_sent_at: 1,
            last_update_at: 1,
            status: TxStatusV2::Prepared,
        };
        assert!(decode_raw(&base, executor.address(), executor.chain_id()).is_ok());

        let mut mutated = base.clone();
        mutated.to = format!("{:?}", Address::from_low_u64_be(10));
        assert!(decode_raw(&mutated, executor.address(), executor.chain_id()).is_err());
        let mut mutated = base.clone();
        mutated.data_hash = [0; 32];
        assert!(decode_raw(&mutated, executor.address(), executor.chain_id()).is_err());
        let mut mutated = base.clone();
        mutated.nonce += 1;
        assert!(decode_raw(&mutated, executor.address(), executor.chain_id()).is_err());
        let mut mutated = base.clone();
        mutated.gas_limit = "1".to_string();
        assert!(decode_raw(&mutated, executor.address(), executor.chain_id()).is_err());
        let mut mutated = base.clone();
        mutated.gas_price = "11".to_string();
        assert!(decode_raw(&mutated, executor.address(), executor.chain_id()).is_err());
        let mut mutated = base.clone();
        mutated.tx_hash = format!("0x{}", "00".repeat(32));
        assert!(decode_raw(&mutated, executor.address(), executor.chain_id()).is_err());
        let mut mutated = base.clone();
        mutated.maximum_fee_per_gas = "9".to_string();
        assert!(decode_raw(&mutated, executor.address(), executor.chain_id()).is_err());
        assert!(decode_raw(&base, Address::from_low_u64_be(11), executor.chain_id()).is_err());
        assert!(decode_raw(&base, executor.address(), executor.chain_id() + 1).is_err());
    }

    #[tokio::test]
    async fn durable_flush_failure_prevents_broadcast() {
        let anvil = ethers::utils::Anvil::new().spawn();
        let mut config = NoxConfig::default();
        config.eth_rpc_url = anvil.endpoint();
        config.chain_id = anvil.chain_id();
        config.eth_wallet_private_key = hex::encode(anvil.keys()[0].to_bytes());
        let executor = Arc::new(ChainExecutor::new(&config).await.unwrap());
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(SledRepository::new(directory.path()).unwrap());
        let manager = TransactionManager::new(
            executor.clone(),
            storage.clone(),
            MetricsService::new(),
            crate::config::DEFAULT_REPLACEMENT_STEP_BPS,
        )
        .await
        .unwrap();
        storage.inject_next_durable_flush_failure();
        let outcome = manager
            .submit_planned(
                [9; 32],
                Address::from_low_u64_be(101),
                Bytes::new(),
                TransactionPlan {
                    gas_limit: U256::from(21_000),
                    initial_fee_per_gas: U256::from(2_000_000_000_u64),
                    maximum_fee_per_gas: U256::from(3_000_000_000_u64),
                    chain_data_fee_native: U256::zero(),
                },
            )
            .await;
        assert!(matches!(outcome, Err(SubmitError::Persistence { .. })));
        let second = manager
            .submit_planned(
                [8; 32],
                Address::from_low_u64_be(102),
                Bytes::new(),
                TransactionPlan {
                    gas_limit: U256::from(21_000),
                    initial_fee_per_gas: U256::from(2_000_000_000_u64),
                    maximum_fee_per_gas: U256::from(3_000_000_000_u64),
                    chain_data_fee_native: U256::zero(),
                },
            )
            .await;
        assert!(matches!(second, Err(SubmitError::Persistence { .. })));
        assert_eq!(executor.get_nonce().await.unwrap(), U256::zero());
        assert_eq!(storage.scan(b"tx:").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn submitted_status_flush_failure_returns_original_ambiguous_hash() {
        let anvil = ethers::utils::Anvil::new().spawn();
        let mut config = NoxConfig::default();
        config.eth_rpc_url = anvil.endpoint();
        config.chain_id = anvil.chain_id();
        config.eth_wallet_private_key = hex::encode(anvil.keys()[0].to_bytes());
        let executor = Arc::new(ChainExecutor::new(&config).await.unwrap());
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(SledRepository::new(directory.path()).unwrap());
        let manager = TransactionManager::new(
            executor.clone(),
            storage.clone(),
            MetricsService::new(),
            crate::config::DEFAULT_REPLACEMENT_STEP_BPS,
        )
        .await
        .unwrap();
        storage.inject_durable_flush_failure_on_call(2);
        let outcome = manager
            .submit_planned(
                [6; 32],
                Address::from_low_u64_be(106),
                Bytes::new(),
                TransactionPlan {
                    gas_limit: U256::from(21_000),
                    initial_fee_per_gas: U256::from(2_000_000_000_u64),
                    maximum_fee_per_gas: U256::from(3_000_000_000_u64),
                    chain_data_fee_native: U256::zero(),
                },
            )
            .await;
        let records = storage.scan(b"tx:").await.unwrap();
        assert_eq!(records.len(), 1);
        let DecodedTransaction::V2(stored) = decode_stored_transaction(&records[0].1).unwrap()
        else {
            panic!("status-fault record must use schema 2");
        };
        assert!(matches!(
            outcome,
            Err(SubmitError::AmbiguousBroadcast {
                transaction_hash,
                ..
            }) if format!("{transaction_hash:?}") == stored.tx_hash
        ));
        assert_eq!(executor.get_nonce().await.unwrap(), U256::one());
    }

    #[tokio::test]
    async fn proven_rejection_preserves_prepared_nonce_and_blocks_next_execution() {
        let anvil = ethers::utils::Anvil::new().spawn();
        let mut config = NoxConfig::default();
        config.eth_rpc_url = anvil.endpoint();
        config.chain_id = anvil.chain_id();
        config.eth_wallet_private_key = hex::encode(anvil.keys()[0].to_bytes());
        let executor = Arc::new(ChainExecutor::new(&config).await.unwrap());
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(SledRepository::new(directory.path()).unwrap());
        let manager = TransactionManager::new(
            executor.clone(),
            storage.clone(),
            MetricsService::new(),
            crate::config::DEFAULT_REPLACEMENT_STEP_BPS,
        )
        .await
        .unwrap();
        let outcome = manager
            .submit_planned(
                [7; 32],
                Address::from_low_u64_be(107),
                Bytes::new(),
                TransactionPlan {
                    gas_limit: U256::one(),
                    initial_fee_per_gas: U256::from(2_000_000_000_u64),
                    maximum_fee_per_gas: U256::from(3_000_000_000_u64),
                    chain_data_fee_native: U256::zero(),
                },
            )
            .await;
        let records = storage.scan(b"tx:").await.unwrap();
        let DecodedTransaction::V2(stored) = decode_stored_transaction(&records[0].1).unwrap()
        else {
            panic!("failed-status fault record must use schema 2");
        };
        assert!(matches!(
            outcome,
            Err(SubmitError::AmbiguousBroadcast {
                transaction_hash,
                ..
            }) if format!("{transaction_hash:?}") == stored.tx_hash
        ));
        assert_eq!(records.len(), 1);
        assert_eq!(stored.status, TxStatusV2::Prepared);
        let second = manager
            .submit_planned(
                [8; 32],
                Address::from_low_u64_be(108),
                Bytes::new(),
                TransactionPlan {
                    gas_limit: U256::from(21_000),
                    initial_fee_per_gas: U256::from(2_000_000_000_u64),
                    maximum_fee_per_gas: U256::from(3_000_000_000_u64),
                    chain_data_fee_native: U256::zero(),
                },
            )
            .await;
        assert!(matches!(second, Err(SubmitError::Persistence { .. })));
        assert_eq!(executor.get_nonce().await.unwrap(), U256::zero());
        assert_eq!(storage.scan(b"tx:").await.unwrap().len(), 1);
    }

    #[test]
    fn only_top_level_revert_counts_as_unreimbursed_loss() {
        let successful = TransactionReceipt {
            status: Some(U64::one()),
            gas_used: Some(U256::from(21_000)),
            effective_gas_price: Some(U256::from(10)),
            ..Default::default()
        };
        assert_eq!(
            sponsored_receipt_outcome(&successful).unwrap(),
            (true, U256::zero())
        );

        let reverted = TransactionReceipt {
            status: Some(U64::zero()),
            gas_used: Some(U256::from(21_000)),
            effective_gas_price: Some(U256::from(10)),
            ..Default::default()
        };
        assert_eq!(
            sponsored_receipt_outcome(&reverted).unwrap(),
            (false, U256::from(210_000)),
        );
    }
}
