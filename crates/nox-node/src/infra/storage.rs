use async_trait::async_trait;
use ethers::types::U256;
use sled::Db;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{error, info, warn};

use nox_core::traits::{IReplayProtection, IStorageRepository, InfrastructureError};
use nox_core::{
    DecodedTransaction, ExecutionId, LegacyPendingTransaction, PendingTransactionV2, QuoteStatusV2,
    StoredQuoteV2, StoredTransactionV2,
};

#[derive(Debug, thiserror::Error)]
pub enum QuoteStoreError {
    #[error("quote execution or payment ID already exists")]
    DuplicateIdentity,
    #[error("quote execution ID is unknown")]
    Unknown,
    #[error("quote is expired")]
    Expired,
    #[error("quote is not outstanding")]
    NotOutstanding,
    #[error("outstanding quote limit reached")]
    OutstandingCapacity,
    #[error("pending sponsored gas limit reached")]
    PendingGasCapacity,
    #[error("rolling sponsored loss limit reached")]
    PendingLossLimit,
    #[error(transparent)]
    Storage(#[from] InfrastructureError),
}

fn quote_transaction_error(
    context: &str,
    error: sled::transaction::TransactionError<QuoteStoreError>,
) -> QuoteStoreError {
    match error {
        sled::transaction::TransactionError::Abort(error) => error,
        sled::transaction::TransactionError::Storage(error) => {
            QuoteStoreError::Storage(InfrastructureError::Database(format!("{context}: {error}")))
        }
    }
}

fn decode_u64(bytes: &[u8]) -> Result<u64, String> {
    let encoded: [u8; 8] = bytes
        .try_into()
        .map_err(|_| "stored counter must contain exactly eight bytes".to_string())?;
    Ok(u64::from_le_bytes(encoded))
}

/// Backoff schedule for transient sled IO errors. A single short retry is not
/// enough to ride out a disk that is briefly full, and escalating delays avoid
/// hot-looping against a filesystem that is genuinely out of space.
const RETRY_BACKOFF_MS: [u64; 3] = [100, 500, 2000];

/// Shared flag describing whether the storage layer is failing writes.
pub type DegradedFlag = Arc<AtomicBool>;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum CreateOutboxResult {
    Created,
    Existing(PendingTransactionV2),
}

pub fn decode_stored_transaction(bytes: &[u8]) -> Result<DecodedTransaction, InfrastructureError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        InfrastructureError::Database(format!("transaction record is malformed JSON: {error}"))
    })?;
    if value.get("schema").is_some() {
        let stored: StoredTransactionV2 = serde_json::from_value(value).map_err(|error| {
            InfrastructureError::Database(format!("v2 transaction record is malformed: {error}"))
        })?;
        if stored.schema != 2 {
            return Err(InfrastructureError::Database(format!(
                "unsupported transaction schema {}",
                stored.schema
            )));
        }
        Ok(DecodedTransaction::V2(stored.transaction))
    } else {
        serde_json::from_value(value)
            .map(DecodedTransaction::Legacy)
            .map_err(|error| {
                InfrastructureError::Database(format!(
                    "legacy transaction record is malformed: {error}"
                ))
            })
    }
}

#[derive(Clone)]
pub struct SledRepository {
    db: Db,
    /// Set once an IO error survives every retry. sled cannot rebuild its
    /// allocator in-process after a disk-full condition, so once this latches the
    /// node needs a restart to recover; surfacing it stops the failure from being
    /// an endless stream of warnings that nothing acts on.
    degraded: DegradedFlag,
    outbox_degraded: Arc<AtomicBool>,
    #[cfg(test)]
    durable_flush_calls: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    fail_durable_flush_call: Arc<std::sync::atomic::AtomicUsize>,
}

impl SledRepository {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, InfrastructureError> {
        let db = sled::open(path).map_err(|e| InfrastructureError::Database(e.to_string()))?;
        Ok(Self {
            db,
            degraded: Arc::new(AtomicBool::new(false)),
            outbox_degraded: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            durable_flush_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            fail_durable_flush_call: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    pub async fn next_quote_nonce_durably(&self) -> Result<u64, InfrastructureError> {
        let db = self.db.clone();
        let nonce = tokio::task::spawn_blocking(move || {
            db.transaction(|tree| {
                let current = tree
                    .get(b"quote:nonce")?
                    .map(|bytes| decode_u64(&bytes))
                    .transpose()
                    .map_err(sled::transaction::ConflictableTransactionError::Abort)?
                    .unwrap_or(0);
                let next = current.checked_add(1).ok_or_else(|| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        "quote nonce overflow".to_string(),
                    )
                })?;
                tree.insert(b"quote:nonce", &next.to_le_bytes())?;
                Ok::<_, sled::transaction::ConflictableTransactionError<String>>(next)
            })
            .map_err(|error| {
                InfrastructureError::Database(format!("quote nonce allocation failed: {error:?}"))
            })
        })
        .await
        .map_err(|error| {
            InfrastructureError::Database(format!("quote nonce task failed: {error}"))
        })??;
        self.durable_flush("quote nonce").await?;
        Ok(nonce)
    }

    pub async fn create_quote_durably(
        &self,
        record: &StoredQuoteV2,
        maximum_outstanding: u32,
        maximum_pending_gas: u64,
        rolling_loss_limit_native: U256,
        rolling_loss_window_secs: u64,
        now_unix: u64,
    ) -> Result<(), QuoteStoreError> {
        let db = self.db.clone();
        let record = record.clone();
        tokio::task::spawn_blocking(move || {
            let execution_key = format!("quote:execution:{}", hex::encode(record.execution_id));
            let payment_key = format!("quote:payment:{}", hex::encode(record.request.payment_id));
            let bytes = serde_json::to_vec(&record).map_err(|error| {
                QuoteStoreError::Storage(InfrastructureError::Database(format!(
                    "serialize quote record failed: {error}"
                )))
            })?;
            db.transaction(|tree| {
                let stored_window_start = tree
                    .get(b"quote:loss-window-start")?
                    .map(|value| decode_u64(&value))
                    .transpose()
                    .map_err(|error| {
                        sled::transaction::ConflictableTransactionError::Abort(
                            QuoteStoreError::Storage(InfrastructureError::Database(error)),
                        )
                    })?
                    .unwrap_or(now_unix);
                let window_expired =
                    now_unix.saturating_sub(stored_window_start) >= rolling_loss_window_secs;
                let rolling_loss = if window_expired {
                    U256::zero()
                } else {
                    tree.get(b"quote:rolling-loss")?
                        .map(|value| U256::from_big_endian(&value))
                        .unwrap_or_default()
                };
                if rolling_loss >= rolling_loss_limit_native {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        QuoteStoreError::PendingLossLimit,
                    ));
                }
                if tree.get(execution_key.as_bytes())?.is_some()
                    || tree.get(payment_key.as_bytes())?.is_some()
                {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        QuoteStoreError::DuplicateIdentity,
                    ));
                }
                let outstanding = tree
                    .get(b"quote:outstanding")?
                    .map(|value| decode_u64(&value))
                    .transpose()
                    .map_err(|error| {
                        sled::transaction::ConflictableTransactionError::Abort(
                            QuoteStoreError::Storage(InfrastructureError::Database(error)),
                        )
                    })?
                    .unwrap_or(0);
                if outstanding >= u64::from(maximum_outstanding) {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        QuoteStoreError::OutstandingCapacity,
                    ));
                }
                let pending_gas = tree
                    .get(b"quote:pending-gas")?
                    .map(|value| decode_u64(&value))
                    .transpose()
                    .map_err(|error| {
                        sled::transaction::ConflictableTransactionError::Abort(
                            QuoteStoreError::Storage(InfrastructureError::Database(error)),
                        )
                    })?
                    .unwrap_or(0);
                let next_pending = pending_gas
                    .checked_add(record.pending_sponsored_gas)
                    .ok_or_else(|| {
                        sled::transaction::ConflictableTransactionError::Abort(
                            QuoteStoreError::Storage(InfrastructureError::Database(
                                "pending sponsored gas overflow".to_string(),
                            )),
                        )
                    })?;
                if next_pending > maximum_pending_gas {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        QuoteStoreError::PendingGasCapacity,
                    ));
                }
                let next_outstanding = outstanding.checked_add(1).ok_or_else(|| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        QuoteStoreError::Storage(InfrastructureError::Database(
                            "outstanding quote counter overflow".to_string(),
                        )),
                    )
                })?;
                tree.insert(execution_key.as_bytes(), bytes.as_slice())?;
                tree.insert(payment_key.as_bytes(), record.execution_id.as_slice())?;
                tree.insert(b"quote:outstanding", &next_outstanding.to_le_bytes())?;
                tree.insert(b"quote:pending-gas", &next_pending.to_le_bytes())?;
                if window_expired {
                    tree.insert(b"quote:loss-window-start", &now_unix.to_le_bytes())?;
                    tree.insert(b"quote:rolling-loss", &[0_u8; 32])?;
                }
                Ok::<_, sled::transaction::ConflictableTransactionError<QuoteStoreError>>(())
            })
            .map_err(|error| quote_transaction_error("quote reservation failed", error))?;
            Ok::<(), QuoteStoreError>(())
        })
        .await
        .map_err(|error| {
            QuoteStoreError::Storage(InfrastructureError::Database(format!(
                "quote reservation task failed: {error}"
            )))
        })??;
        self.durable_flush("quote reservation")
            .await
            .map_err(QuoteStoreError::Storage)
    }

    pub async fn take_quote_durably(
        &self,
        execution_id: ExecutionId,
        now_unix: u64,
    ) -> Result<StoredQuoteV2, QuoteStoreError> {
        let db = self.db.clone();
        let record = tokio::task::spawn_blocking(move || {
            let key = format!("quote:execution:{}", hex::encode(execution_id));
            db.transaction(|tree| {
                let bytes = tree.get(key.as_bytes())?.ok_or_else(|| {
                    sled::transaction::ConflictableTransactionError::Abort(QuoteStoreError::Unknown)
                })?;
                let mut record: StoredQuoteV2 =
                    serde_json::from_slice(&bytes).map_err(|error| {
                        sled::transaction::ConflictableTransactionError::Abort(
                            QuoteStoreError::Storage(InfrastructureError::Database(format!(
                                "stored quote is malformed: {error}"
                            ))),
                        )
                    })?;
                if record.status != QuoteStatusV2::Outstanding {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        QuoteStoreError::NotOutstanding,
                    ));
                }
                if record.quote.valid_until_unix <= now_unix {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        QuoteStoreError::Expired,
                    ));
                }
                record.status = QuoteStatusV2::Inflight;
                let updated = serde_json::to_vec(&record).map_err(|error| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        QuoteStoreError::Storage(InfrastructureError::Database(format!(
                            "serialize inflight quote failed: {error}"
                        ))),
                    )
                })?;
                tree.insert(key.as_bytes(), updated)?;
                Ok::<_, sled::transaction::ConflictableTransactionError<QuoteStoreError>>(record)
            })
            .map_err(|error| quote_transaction_error("quote take failed", error))
        })
        .await
        .map_err(|error| {
            QuoteStoreError::Storage(InfrastructureError::Database(format!(
                "quote take task failed: {error}"
            )))
        })??;
        self.durable_flush("quote take")
            .await
            .map_err(QuoteStoreError::Storage)?;
        Ok(record)
    }

    pub async fn load_quote(
        &self,
        execution_id: ExecutionId,
    ) -> Result<Option<StoredQuoteV2>, InfrastructureError> {
        let key = format!("quote:execution:{}", hex::encode(execution_id));
        self.get(key.as_bytes())
            .await?
            .map(|bytes| {
                serde_json::from_slice(&bytes).map_err(|error| {
                    InfrastructureError::Database(format!("stored quote is malformed: {error}"))
                })
            })
            .transpose()
    }

    pub async fn load_outbox_by_execution(
        &self,
        execution_id: ExecutionId,
    ) -> Result<Option<PendingTransactionV2>, InfrastructureError> {
        let key = format!("outbox:{}", hex::encode(execution_id));
        self.get(key.as_bytes())
            .await?
            .map(|bytes| match decode_stored_transaction(&bytes)? {
                DecodedTransaction::V2(transaction) => Ok(transaction),
                DecodedTransaction::Legacy(_) => Err(InfrastructureError::Database(
                    "execution outbox points to a legacy transaction".to_string(),
                )),
            })
            .transpose()
    }

    pub async fn mark_quote_submitted_durably(
        &self,
        execution_id: ExecutionId,
    ) -> Result<(), InfrastructureError> {
        self.update_quote_status_durably(execution_id, QuoteStatusV2::Submitted, None, 0)
            .await
            .map(|_| ())
    }

    pub async fn finalize_quote_durably(
        &self,
        execution_id: ExecutionId,
        terminal_status: QuoteStatusV2,
        unreimbursed_loss_native: U256,
        now_unix: u64,
    ) -> Result<bool, InfrastructureError> {
        if !matches!(
            terminal_status,
            QuoteStatusV2::Confirmed
                | QuoteStatusV2::Reverted
                | QuoteStatusV2::Expired
                | QuoteStatusV2::Rejected
        ) {
            return Err(InfrastructureError::Database(
                "quote finalization requires a terminal status".to_string(),
            ));
        }
        self.update_quote_status_durably(
            execution_id,
            terminal_status,
            Some(unreimbursed_loss_native),
            now_unix,
        )
        .await
    }

    async fn update_quote_status_durably(
        &self,
        execution_id: ExecutionId,
        next_status: QuoteStatusV2,
        terminal_loss: Option<U256>,
        now_unix: u64,
    ) -> Result<bool, InfrastructureError> {
        let db = self.db.clone();
        let changed = tokio::task::spawn_blocking(move || {
            let key = format!("quote:execution:{}", hex::encode(execution_id));
            db.transaction(|tree| {
                let bytes = tree.get(key.as_bytes())?.ok_or_else(|| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        "quote execution ID is unknown".to_string(),
                    )
                })?;
                let mut record: StoredQuoteV2 =
                    serde_json::from_slice(&bytes).map_err(|error| {
                        sled::transaction::ConflictableTransactionError::Abort(format!(
                            "stored quote is malformed: {error}"
                        ))
                    })?;
                if matches!(
                    record.status,
                    QuoteStatusV2::Confirmed
                        | QuoteStatusV2::Reverted
                        | QuoteStatusV2::Expired
                        | QuoteStatusV2::Rejected
                ) {
                    return Ok::<_, sled::transaction::ConflictableTransactionError<String>>(false);
                }
                if terminal_loss.is_none() {
                    if record.status != QuoteStatusV2::Inflight {
                        return Err(sled::transaction::ConflictableTransactionError::Abort(
                            "only an inflight quote can become submitted".to_string(),
                        ));
                    }
                } else {
                    let outstanding = tree
                        .get(b"quote:outstanding")?
                        .map(|value| decode_u64(&value))
                        .transpose()
                        .map_err(sled::transaction::ConflictableTransactionError::Abort)?
                        .unwrap_or(0);
                    let pending = tree
                        .get(b"quote:pending-gas")?
                        .map(|value| decode_u64(&value))
                        .transpose()
                        .map_err(sled::transaction::ConflictableTransactionError::Abort)?
                        .unwrap_or(0);
                    let next_outstanding = outstanding.checked_sub(1).ok_or_else(|| {
                        sled::transaction::ConflictableTransactionError::Abort(
                            "outstanding quote counter underflow".to_string(),
                        )
                    })?;
                    let next_pending = pending
                        .checked_sub(record.pending_sponsored_gas)
                        .ok_or_else(|| {
                            sled::transaction::ConflictableTransactionError::Abort(
                                "pending sponsored gas counter underflow".to_string(),
                            )
                        })?;
                    tree.insert(b"quote:outstanding", &next_outstanding.to_le_bytes())?;
                    tree.insert(b"quote:pending-gas", &next_pending.to_le_bytes())?;

                    let loss = terminal_loss.unwrap_or_default();
                    if !loss.is_zero() {
                        let stored_start = tree
                            .get(b"quote:loss-window-start")?
                            .map(|value| decode_u64(&value))
                            .transpose()
                            .map_err(sled::transaction::ConflictableTransactionError::Abort)?
                            .unwrap_or(now_unix);
                        let window_expired = now_unix.saturating_sub(stored_start)
                            >= record.rolling_loss_window_secs;
                        let current_loss = if window_expired {
                            U256::zero()
                        } else {
                            tree.get(b"quote:rolling-loss")?
                                .map(|value| U256::from_big_endian(&value))
                                .unwrap_or_default()
                        };
                        let next_loss = current_loss.checked_add(loss).ok_or_else(|| {
                            sled::transaction::ConflictableTransactionError::Abort(
                                "rolling sponsored loss overflow".to_string(),
                            )
                        })?;
                        let mut encoded_loss = [0_u8; 32];
                        next_loss.to_big_endian(&mut encoded_loss);
                        tree.insert(b"quote:rolling-loss", encoded_loss.as_slice())?;
                        if window_expired {
                            tree.insert(b"quote:loss-window-start", &now_unix.to_le_bytes())?;
                        }
                    }
                }
                record.status = next_status.clone();
                let updated = serde_json::to_vec(&record).map_err(|error| {
                    sled::transaction::ConflictableTransactionError::Abort(format!(
                        "serialize quote status failed: {error}"
                    ))
                })?;
                tree.insert(key.as_bytes(), updated)?;
                Ok(true)
            })
            .map_err(|error| {
                InfrastructureError::Database(format!("quote status update failed: {error:?}"))
            })
        })
        .await
        .map_err(|error| {
            InfrastructureError::Database(format!("quote status task failed: {error}"))
        })??;
        self.durable_flush("quote status").await?;
        Ok(changed)
    }

    pub async fn prune_expired_quotes_durably(
        &self,
        now_unix: u64,
    ) -> Result<usize, InfrastructureError> {
        let records = self.scan(b"quote:execution:").await?;
        let mut pruned = 0_usize;
        for (_, bytes) in records {
            let record: StoredQuoteV2 = serde_json::from_slice(&bytes).map_err(|error| {
                InfrastructureError::Database(format!("stored quote is malformed: {error}"))
            })?;
            if record.status == QuoteStatusV2::Outstanding
                && record.quote.valid_until_unix <= now_unix
                && self
                    .finalize_quote_durably(
                        record.execution_id,
                        QuoteStatusV2::Expired,
                        U256::zero(),
                        now_unix,
                    )
                    .await?
            {
                pruned = pruned.checked_add(1).ok_or_else(|| {
                    InfrastructureError::Database("expired quote count overflow".to_string())
                })?;
            }
        }
        Ok(pruned)
    }

    /// True when writes are persistently failing and the node needs a restart.
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed) || self.outbox_degraded.load(Ordering::Relaxed)
    }

    /// Shared handle to the degraded flag, for health reporting.
    #[must_use]
    pub fn degraded_flag(&self) -> DegradedFlag {
        self.degraded.clone()
    }

    #[cfg(test)]
    pub(crate) fn inject_next_durable_flush_failure(&self) {
        self.inject_durable_flush_failure_on_call(1);
    }

    #[cfg(test)]
    pub(crate) fn inject_durable_flush_failure_on_call(&self, call_offset: usize) {
        let current = self.durable_flush_calls.load(Ordering::SeqCst);
        self.fail_durable_flush_call
            .store(current.saturating_add(call_offset), Ordering::SeqCst);
    }

    async fn durable_flush(&self, operation: &'static str) -> Result<(), InfrastructureError> {
        #[cfg(test)]
        {
            let call = self.durable_flush_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.fail_durable_flush_call.load(Ordering::SeqCst) == call {
                self.fail_durable_flush_call.store(0, Ordering::SeqCst);
                self.outbox_degraded.store(true, Ordering::SeqCst);
                self.degraded.store(true, Ordering::SeqCst);
                return Err(InfrastructureError::Database(format!(
                    "{operation} flush fault injected"
                )));
            }
        }
        if let Err(error) = self.db.flush_async().await {
            self.outbox_degraded.store(true, Ordering::SeqCst);
            self.degraded.store(true, Ordering::SeqCst);
            return Err(InfrastructureError::Database(format!(
                "{operation} flush failed: {error}"
            )));
        }
        Ok(())
    }

    pub async fn create_outbox_durably(
        &self,
        execution_id: ExecutionId,
        record: &PendingTransactionV2,
        next_nonce: u64,
    ) -> Result<CreateOutboxResult, InfrastructureError> {
        if self.outbox_degraded.load(Ordering::SeqCst) {
            return Err(InfrastructureError::Database(
                "durable outbox is degraded; restart after restoring storage".to_string(),
            ));
        }
        let db = self.db.clone();
        let record = record.clone();
        let existing = tokio::task::spawn_blocking(move || {
            let outbox_key = format!("outbox:{}", hex::encode(execution_id));
            let tx_key = format!("tx:{}", record.nonce);
            let stored = StoredTransactionV2 {
                schema: 2,
                transaction: record,
            };
            let bytes = serde_json::to_vec(&stored).map_err(|error| {
                InfrastructureError::Database(format!("serialize v2 outbox record failed: {error}"))
            })?;
            let transaction_result = db.transaction(|tree| {
                if let Some(existing) = tree.get(outbox_key.as_bytes())? {
                    return Ok::<_, sled::transaction::ConflictableTransactionError<()>>(Some(
                        existing.to_vec(),
                    ));
                }
                tree.insert(outbox_key.as_bytes(), bytes.as_slice())?;
                tree.insert(tx_key.as_bytes(), bytes.as_slice())?;
                tree.insert(b"nonce:local", &next_nonce.to_le_bytes())?;
                Ok(None)
            });
            transaction_result.map_err(|error| {
                InfrastructureError::Database(format!("atomic outbox creation failed: {error:?}"))
            })
        })
        .await
        .map_err(|error| InfrastructureError::Database(format!("outbox task failed: {error}")))??;
        self.durable_flush("durable outbox").await?;
        match existing {
            Some(bytes) => match decode_stored_transaction(&bytes)? {
                DecodedTransaction::V2(transaction) => {
                    Ok(CreateOutboxResult::Existing(transaction))
                }
                DecodedTransaction::Legacy(_) => Err(InfrastructureError::Database(
                    "execution outbox points to a legacy record".to_string(),
                )),
            },
            None => Ok(CreateOutboxResult::Created),
        }
    }

    pub async fn persist_v2_durably(
        &self,
        record: &PendingTransactionV2,
    ) -> Result<(), InfrastructureError> {
        if self.outbox_degraded.load(Ordering::SeqCst) {
            return Err(InfrastructureError::Database(
                "durable outbox is degraded; restart after restoring storage".to_string(),
            ));
        }
        let db = self.db.clone();
        let record = record.clone();
        tokio::task::spawn_blocking(move || {
            let outbox_key = format!("outbox:{}", hex::encode(record.execution_id));
            let tx_key = format!("tx:{}", record.nonce);
            let bytes = serde_json::to_vec(&StoredTransactionV2 {
                schema: 2,
                transaction: record,
            })
            .map_err(|error| {
                InfrastructureError::Database(format!("serialize v2 record failed: {error}"))
            })?;
            db.transaction(|tree| {
                tree.insert(outbox_key.as_bytes(), bytes.as_slice())?;
                tree.insert(tx_key.as_bytes(), bytes.as_slice())?;
                Ok::<_, sled::transaction::ConflictableTransactionError<()>>(())
            })
            .map_err(|error| {
                InfrastructureError::Database(format!("atomic v2 update failed: {error:?}"))
            })?;
            Ok(())
        })
        .await
        .map_err(|error| {
            InfrastructureError::Database(format!("v2 persistence task failed: {error}"))
        })??;
        self.durable_flush("durable v2").await?;
        Ok(())
    }

    pub async fn persist_legacy_terminal_durably(
        &self,
        record: &LegacyPendingTransaction,
    ) -> Result<(), InfrastructureError> {
        let key = format!("tx:{}", record.nonce);
        let bytes = serde_json::to_vec(record).map_err(|error| {
            InfrastructureError::Database(format!(
                "serialize legacy terminal record failed: {error}"
            ))
        })?;
        self.put(key.as_bytes(), &bytes).await?;
        self.durable_flush("legacy terminal transaction").await
    }

    /// Run a sled operation, retrying transient IO errors on an escalating
    /// backoff. Non-IO errors fail immediately. If every attempt fails the
    /// repository latches into a degraded state and logs once at ERROR.
    fn with_retry<T, F: Fn() -> Result<T, sled::Error>>(
        &self,
        op_name: &str,
        f: F,
    ) -> Result<T, InfrastructureError> {
        let mut last_err = match f() {
            Ok(val) => {
                self.clear_degraded();
                return Ok(val);
            }
            Err(e) => e,
        };

        for (attempt, backoff_ms) in RETRY_BACKOFF_MS.iter().enumerate() {
            if !matches!(last_err, sled::Error::Io(_)) {
                return Err(InfrastructureError::Database(last_err.to_string()));
            }
            warn!(
                "Sled {op_name}: transient IO error (attempt {}/{}), retrying in {backoff_ms}ms: {last_err}",
                attempt + 1,
                RETRY_BACKOFF_MS.len()
            );
            std::thread::sleep(Duration::from_millis(*backoff_ms));
            match f() {
                Ok(val) => {
                    self.clear_degraded();
                    return Ok(val);
                }
                Err(e) => last_err = e,
            }
        }

        if matches!(last_err, sled::Error::Io(_)) && !self.degraded.swap(true, Ordering::SeqCst) {
            error!(
                "Sled {op_name}: IO error persisted through {} retries: {last_err}. \
                 Storage is DEGRADED and writes are being lost. sled cannot rebuild its \
                 allocator in-process after a disk-full condition, so the node must be \
                 restarted once free space is available.",
                RETRY_BACKOFF_MS.len()
            );
        }

        Err(InfrastructureError::Database(last_err.to_string()))
    }

    /// Clear the degraded latch after a successful operation.
    fn clear_degraded(&self) {
        if self.outbox_degraded.load(Ordering::SeqCst) {
            return;
        }
        if self.degraded.swap(false, Ordering::SeqCst) {
            info!("Sled: storage recovered, writes are succeeding again");
        }
    }

    /// Flush and scan to trigger GC on old log segments. Call periodically.
    pub async fn compact(&self) -> Result<(), InfrastructureError> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            db.flush().map_err(|e| {
                InfrastructureError::Database(format!("Sled flush before compact failed: {e}"))
            })?;
            // sled 0.34 doesn't have an explicit compact() method on Db.
            // The best we can do is flush + iterate to trigger GC on old segments.
            // Force GC by scanning all entries (triggers internal page cache eviction).
            let count = db.len();
            tracing::debug!(entries = count, "Sled compaction: scanned all entries");
            Ok(())
        })
        .await
        .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }
}

#[async_trait]
impl IStorageRepository for SledRepository {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, InfrastructureError> {
        let repo = self.clone();
        let key = key.to_vec();
        tokio::task::spawn_blocking(move || {
            repo.with_retry("get", || {
                repo.db.get(&key).map(|opt| opt.map(|ivec| ivec.to_vec()))
            })
        })
        .await
        .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }

    async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), InfrastructureError> {
        let repo = self.clone();
        let key = key.to_vec();
        let value = value.to_vec();
        tokio::task::spawn_blocking(move || {
            repo.with_retry("put", || repo.db.insert(&key, value.as_slice()).map(|_| ()))
        })
        .await
        .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }

    async fn exists(&self, key: &[u8]) -> Result<bool, InfrastructureError> {
        let repo = self.clone();
        let key = key.to_vec();
        tokio::task::spawn_blocking(move || {
            repo.with_retry("exists", || repo.db.contains_key(&key))
        })
        .await
        .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }

    async fn delete(&self, key: &[u8]) -> Result<(), InfrastructureError> {
        let repo = self.clone();
        let key = key.to_vec();
        tokio::task::spawn_blocking(move || {
            repo.with_retry("delete", || repo.db.remove(&key).map(|_| ()))
        })
        .await
        .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }

    async fn scan(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, InfrastructureError> {
        let db = self.db.clone();
        let prefix = prefix.to_vec();
        tokio::task::spawn_blocking(move || {
            let mut results = Vec::new();
            for item in db.scan_prefix(&prefix) {
                let (k, v) = item.map_err(|e| InfrastructureError::Database(e.to_string()))?;
                results.push((k.to_vec(), v.to_vec()));
            }
            Ok(results)
        })
        .await
        .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }
}

#[async_trait]
impl IReplayProtection for SledRepository {
    async fn check_and_tag(
        &self,
        tag: &[u8],
        ttl_seconds: u64,
    ) -> Result<bool, InfrastructureError> {
        // Expiry stored in milliseconds to avoid rounding issues
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;
        let expiry = now + (ttl_seconds * 1000);
        let expiry_bytes = expiry.to_be_bytes();

        if let Some(existing) = self
            .db
            .get(tag)
            .map_err(|e| InfrastructureError::Database(e.to_string()))?
        {
            if existing.len() == 8 {
                let existing_expiry =
                    u64::from_be_bytes(existing.as_ref().try_into().map_err(|_| {
                        InfrastructureError::Database("Invalid expiry bytes".into())
                    })?);
                if existing_expiry < now {
                    // Expired, fall through to overwrite
                } else {
                    return Ok(true);
                }
            } else {
                return Ok(true);
            }
        }

        self.db
            .insert(tag, &expiry_bytes)
            .map_err(|e| InfrastructureError::Database(e.to_string()))?;

        Ok(false)
    }

    async fn prune_expired(&self) -> Result<usize, InfrastructureError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;
        let mut count = 0;

        for item in self.db.iter() {
            let (key, value) = item.map_err(|e| InfrastructureError::Database(e.to_string()))?;

            if value.len() == 8 {
                if let Ok(bytes) = value.as_ref().try_into() {
                    let expiry = u64::from_be_bytes(bytes);
                    if expiry < now {
                        self.db
                            .remove(key)
                            .map_err(|e| InfrastructureError::Database(e.to_string()))?;
                        count += 1;
                    }
                }
            }
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_storage_lifecycle() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_db");
        let repo = SledRepository::new(&db_path).unwrap();

        let key = b"test_key";
        let val = b"test_value";

        repo.put(key, val).await.unwrap();
        assert!(repo.exists(key).await.unwrap());

        let retrieved = repo.get(key).await.unwrap();
        assert_eq!(retrieved, Some(val.to_vec()));

        let missing = repo.get(b"missing").await.unwrap();
        assert_eq!(missing, None);
    }

    #[tokio::test]
    async fn test_replay_protection() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("replay_db");
        let repo = SledRepository::new(&db_path).unwrap();

        let tag = b"packet_hash_123";

        let is_replay = repo.check_and_tag(tag, 2).await.unwrap();
        assert!(!is_replay);

        let is_replay_2 = repo.check_and_tag(tag, 2).await.unwrap();
        assert!(is_replay_2);

        sleep(Duration::from_secs(3)).await;

        let is_replay_3 = repo.check_and_tag(tag, 2).await.unwrap();
        assert!(!is_replay_3);
    }

    #[tokio::test]
    async fn test_crud_lifecycle() {
        let dir = tempdir().unwrap();
        let repo = SledRepository::new(dir.path()).unwrap();

        repo.put(b"key1", b"val1").await.unwrap();
        assert!(repo.exists(b"key1").await.unwrap());

        let val = repo.get(b"key1").await.unwrap();
        assert_eq!(val, Some(b"val1".to_vec()));

        repo.delete(b"key1").await.unwrap();
        assert!(!repo.exists(b"key1").await.unwrap());
        assert_eq!(repo.get(b"key1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_prefix_scan() {
        let dir = tempdir().unwrap();
        let repo = SledRepository::new(dir.path()).unwrap();

        repo.put(b"peer:A", b"infoA").await.unwrap();
        repo.put(b"peer:B", b"infoB").await.unwrap();
        repo.put(b"other:C", b"infoC").await.unwrap();

        let peers = repo.scan(b"peer:").await.unwrap();
        assert_eq!(peers.len(), 2);

        assert_eq!(peers[0].0, b"peer:A");
        assert_eq!(peers[1].0, b"peer:B");
    }

    #[tokio::test]
    async fn test_pruning() {
        let dir = tempdir().unwrap();
        let repo = SledRepository::new(dir.path()).unwrap();

        repo.check_and_tag(b"old", 0).await.unwrap();

        // Wait to guarantee 'now' > 'expiry'
        sleep(Duration::from_secs(2)).await;

        repo.check_and_tag(b"fresh", 100).await.unwrap();

        let pruned = repo.prune_expired().await.unwrap();
        assert_eq!(pruned, 1, "Should prune exactly one expired item");

        assert!(!repo.exists(b"old").await.unwrap());
        assert!(repo.exists(b"fresh").await.unwrap());
    }

    fn test_repo() -> SledRepository {
        let dir = tempfile::tempdir().expect("tempdir");
        SledRepository::new(dir.path()).expect("open sled")
    }

    fn io_error(msg: &'static str) -> sled::Error {
        sled::Error::Io(std::io::Error::new(std::io::ErrorKind::Other, msg))
    }

    #[test]
    fn test_with_retry_succeeds_on_first_try() {
        let repo = test_repo();
        let result = repo.with_retry("test", || Ok::<_, sled::Error>(42));
        assert_eq!(result.unwrap(), 42);
        assert!(!repo.is_degraded());
    }

    #[test]
    fn test_with_retry_fails_on_non_io_error() {
        let repo = test_repo();
        let result: Result<(), _> = repo.with_retry("test", || {
            Err(sled::Error::CollectionNotFound(sled::IVec::from(
                b"missing" as &[u8],
            )))
        });
        assert!(result.is_err());
        // A logic error is not a storage fault, so the node must not be marked degraded.
        assert!(!repo.is_degraded());
    }

    #[test]
    fn test_with_retry_retries_io_error() {
        use std::sync::atomic::AtomicU32;
        let repo = test_repo();
        let call_count = AtomicU32::new(0);

        let result = repo.with_retry("test", || {
            let count = call_count.fetch_add(1, Ordering::Relaxed);
            if count == 0 {
                Err(io_error("transient disk error"))
            } else {
                Ok(99)
            }
        });
        assert_eq!(result.unwrap(), 99);
        assert_eq!(call_count.load(Ordering::Relaxed), 2);
        assert!(!repo.is_degraded());
    }

    #[test]
    fn test_persistent_io_error_latches_degraded() {
        use std::sync::atomic::AtomicU32;
        let repo = test_repo();
        let call_count = AtomicU32::new(0);

        let result: Result<(), _> = repo.with_retry("test", || {
            call_count.fetch_add(1, Ordering::Relaxed);
            Err(io_error("no space left on device"))
        });

        assert!(result.is_err());
        // Initial attempt plus one per backoff step.
        assert_eq!(
            call_count.load(Ordering::Relaxed) as usize,
            RETRY_BACKOFF_MS.len() + 1
        );
        assert!(
            repo.is_degraded(),
            "a wedged storage layer must be visible, not just logged"
        );
    }

    #[test]
    fn test_degraded_clears_after_recovery() {
        let repo = test_repo();

        let failed: Result<(), _> = repo.with_retry("test", || Err(io_error("disk full")));
        assert!(failed.is_err());
        assert!(repo.is_degraded());

        // Space comes back and the next operation succeeds.
        let ok = repo.with_retry("test", || Ok::<_, sled::Error>(1));
        assert_eq!(ok.unwrap(), 1);
        assert!(!repo.is_degraded());
    }

    #[test]
    fn test_degraded_flag_is_shared_across_clones() {
        let repo = test_repo();
        let flag = repo.degraded_flag();
        let clone = repo.clone();

        let failed: Result<(), _> = repo.with_retry("test", || Err(io_error("disk full")));
        assert!(failed.is_err());

        assert!(flag.load(Ordering::Relaxed));
        assert!(clone.is_degraded());
    }
}
