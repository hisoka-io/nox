use async_trait::async_trait;
use ethers::types::U256;
use sled::transaction::{ConflictableTransactionError, TransactionError, Transactional};
use sled::{Db, Tree};
use std::{
    path::{Path, PathBuf},
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

/// Snapshot of the quote reservation counters, read outside a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QuoteCounters {
    pub outstanding: u64,
    pub pending_sponsored_gas: u64,
    /// Loss recorded in the current window, as last written.
    pub rolling_loss_native: U256,
    pub loss_window_start: Option<u64>,
}

impl QuoteCounters {
    /// Cheap admission check with the same limits that `create_quote_durably` enforces
    /// atomically. Lets a quote be refused before any RPC, oracle or signing work.
    pub fn admit(
        &self,
        requested_gas: u64,
        maximum_outstanding: u32,
        maximum_pending_gas: u64,
        rolling_loss_limit_native: U256,
        rolling_loss_window_secs: u64,
        now_unix: u64,
    ) -> Result<(), QuoteStoreError> {
        let window_expired = self
            .loss_window_start
            .is_none_or(|start| now_unix.saturating_sub(start) >= rolling_loss_window_secs);
        if !window_expired && self.rolling_loss_native >= rolling_loss_limit_native {
            return Err(QuoteStoreError::PendingLossLimit);
        }
        if self.outstanding >= u64::from(maximum_outstanding) {
            return Err(QuoteStoreError::OutstandingCapacity);
        }
        match self.pending_sponsored_gas.checked_add(requested_gas) {
            Some(next) if next <= maximum_pending_gas => Ok(()),
            _ => Err(QuoteStoreError::PendingGasCapacity),
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

/// Name of the sled tree holding the exit transaction outbox (`outbox:*`) and
/// the per-nonce transaction records (`tx:*`).
///
/// Signed transaction records are tens of kilobytes each. Kept in the default
/// tree, they shared a leaf with small, frequently rewritten keys such as the
/// chain observer cursor, which pushed that leaf past sled's inline page limit
/// so every rewrite of it produced a new blob file. A dedicated tree keeps
/// those records in leaves that change only when a transaction does.
pub const OUTBOX_TREE: &[u8] = b"exit_outbox";

/// Name of the sled tree holding replay tags written through
/// [`IReplayProtection`]. Kept apart from the default tree so pruning expired
/// tags can never touch other eight-byte values such as the nonce floor or the
/// chain observer cursor.
pub const REPLAY_TREE: &[u8] = b"replay_tags";

/// Key prefixes stored in [`OUTBOX_TREE`] instead of the default tree.
pub const OUTBOX_KEY_PREFIXES: [&[u8]; 2] = [b"outbox:", b"tx:"];

/// True for keys that live in [`OUTBOX_TREE`].
#[must_use]
pub fn is_outbox_key(key: &[u8]) -> bool {
    OUTBOX_KEY_PREFIXES
        .iter()
        .any(|prefix| key.starts_with(prefix))
}

/// Records moved from the default tree into [`OUTBOX_TREE`] by one startup migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OutboxMigration {
    /// `outbox:*` records moved.
    pub outbox_records: usize,
    /// `tx:*` records moved.
    pub transaction_records: usize,
    /// Moved records that replaced a record already in [`OUTBOX_TREE`] under the
    /// same key. Only possible after a downgrade wrote to the default tree.
    pub replaced: usize,
}

impl OutboxMigration {
    #[must_use]
    pub fn moved(&self) -> usize {
        self.outbox_records.saturating_add(self.transaction_records)
    }
}

/// Moves every `outbox:*` and `tx:*` record from the default tree into the
/// outbox tree.
///
/// Each key moves in its own transaction across both trees, so a crash leaves
/// every record in exactly one tree and the next start finishes the job. A
/// second run finds nothing to move. When a key exists in both trees (a
/// downgraded binary wrote it to the default tree after an earlier move), the
/// default-tree copy is the newer write and replaces the outbox copy.
pub fn migrate_outbox_records(
    default_tree: &Tree,
    outbox: &Tree,
) -> Result<OutboxMigration, InfrastructureError> {
    let mut report = OutboxMigration::default();
    for prefix in OUTBOX_KEY_PREFIXES {
        let keys = default_tree
            .scan_prefix(prefix)
            .keys()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                InfrastructureError::Database(format!(
                    "outbox migration: scanning {} keys in the default tree failed: {error}",
                    String::from_utf8_lossy(prefix)
                ))
            })?;
        for key in keys {
            let moved = (default_tree, outbox)
                .transaction(|(default_tx, outbox_tx)| {
                    let Some(value) = default_tx.remove(&key)? else {
                        return Ok(None);
                    };
                    let previous = outbox_tx.insert(&key, value)?;
                    Ok::<_, ConflictableTransactionError<()>>(Some(previous.is_some()))
                })
                .map_err(|error: TransactionError<()>| {
                    InfrastructureError::Database(format!(
                        "outbox migration: moving key {} failed: {error:?}",
                        String::from_utf8_lossy(&key)
                    ))
                })?;
            let Some(replaced) = moved else {
                continue;
            };
            if key.starts_with(b"outbox:") {
                report.outbox_records = report.outbox_records.saturating_add(1);
            } else {
                report.transaction_records = report.transaction_records.saturating_add(1);
            }
            if replaced {
                report.replaced = report.replaced.saturating_add(1);
            }
        }
    }
    Ok(report)
}

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
    /// Directory sled was opened in.
    path: PathBuf,
    /// [`OUTBOX_TREE`]: every `outbox:*` and `tx:*` record.
    outbox: Tree,
    /// [`REPLAY_TREE`]: replay tags and their expiry.
    replay: Tree,
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
        let path = path.as_ref();
        crate::infra::compaction::ensure_no_interrupted_compaction(path)?;
        let db = sled::open(path).map_err(|e| {
            InfrastructureError::Database(format!("open sled at {}: {e}", path.display()))
        })?;
        let outbox = db.open_tree(OUTBOX_TREE).map_err(|e| {
            InfrastructureError::Database(format!(
                "open sled tree {}: {e}",
                String::from_utf8_lossy(OUTBOX_TREE)
            ))
        })?;
        let replay = db.open_tree(REPLAY_TREE).map_err(|e| {
            InfrastructureError::Database(format!(
                "open sled tree {}: {e}",
                String::from_utf8_lossy(REPLAY_TREE)
            ))
        })?;
        let migration = migrate_outbox_records(&db, &outbox)?;
        if migration.moved() > 0 {
            db.flush().map_err(|e| {
                InfrastructureError::Database(format!("flush after outbox migration: {e}"))
            })?;
            info!(
                outbox_records = migration.outbox_records,
                transaction_records = migration.transaction_records,
                replaced = migration.replaced,
                "Moved exit outbox records into the {} tree",
                String::from_utf8_lossy(OUTBOX_TREE)
            );
        }
        Ok(Self {
            db,
            path: path.to_path_buf(),
            outbox,
            replay,
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

    pub async fn quote_counters(&self) -> Result<QuoteCounters, InfrastructureError> {
        let counter = |bytes: Option<Vec<u8>>| -> Result<Option<u64>, InfrastructureError> {
            bytes
                .map(|value| decode_u64(&value).map_err(InfrastructureError::Database))
                .transpose()
        };
        let outstanding = counter(self.get(b"quote:outstanding").await?)?.unwrap_or(0);
        let pending_sponsored_gas = counter(self.get(b"quote:pending-gas").await?)?.unwrap_or(0);
        let loss_window_start = counter(self.get(b"quote:loss-window-start").await?)?;
        let rolling_loss_native = self
            .get(b"quote:rolling-loss")
            .await?
            .map(|value| U256::from_big_endian(&value))
            .unwrap_or_default();
        Ok(QuoteCounters {
            outstanding,
            pending_sponsored_gas,
            rolling_loss_native,
            loss_window_start,
        })
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
        let outbox = self.outbox.clone();
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
            let default_tree: &Tree = &db;
            let transaction_result =
                (default_tree, &outbox).transaction(|(default_tx, outbox_tx)| {
                    if let Some(existing) = outbox_tx.get(outbox_key.as_bytes())? {
                        return Ok::<_, ConflictableTransactionError<()>>(Some(existing.to_vec()));
                    }
                    outbox_tx.insert(outbox_key.as_bytes(), bytes.as_slice())?;
                    outbox_tx.insert(tx_key.as_bytes(), bytes.as_slice())?;
                    default_tx.insert(b"nonce:local", &next_nonce.to_le_bytes())?;
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
        let outbox = self.outbox.clone();
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
            outbox
                .transaction(|tree| {
                    tree.insert(outbox_key.as_bytes(), bytes.as_slice())?;
                    tree.insert(tx_key.as_bytes(), bytes.as_slice())?;
                    Ok::<_, ConflictableTransactionError<()>>(())
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

    /// Flushes buffered writes to disk and logs the default tree's entry count
    /// at DEBUG.
    ///
    /// This does not compact or garbage-collect anything: sled 0.34 has no
    /// compaction API. Rewritten pages are reclaimed by sled's own segment
    /// cleaner, and a blob file is removed only when the segment that last
    /// referenced it is reclaimed. Watch `nox_storage_size_on_disk_bytes` for
    /// growth.
    pub async fn compact(&self) -> Result<(), InfrastructureError> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            db.flush().map_err(|e| {
                InfrastructureError::Database(format!("Sled periodic flush failed: {e}"))
            })?;
            let count = db.len();
            tracing::debug!(entries = count, "Sled periodic flush complete");
            Ok(())
        })
        .await
        .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }
}

impl SledRepository {
    /// Bytes sled occupies on disk: the log file plus every blob file.
    pub async fn size_on_disk(&self) -> Result<u64, InfrastructureError> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            db.size_on_disk().map_err(|e| {
                InfrastructureError::Database(format!("Sled size_on_disk failed: {e}"))
            })
        })
        .await
        .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }

    /// Directory the database lives in.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn default_tree(&self) -> &Tree {
        &self.db
    }

    pub(crate) fn outbox_tree(&self) -> &Tree {
        &self.outbox
    }

    pub(crate) fn replay_tree(&self) -> &Tree {
        &self.replay
    }

    /// True once a durable outbox write failed; maintenance leaves the outbox
    /// alone until the node is restarted.
    pub(crate) fn is_outbox_degraded(&self) -> bool {
        self.outbox_degraded.load(Ordering::SeqCst)
    }

    /// Flushes to disk and latches the degraded flag on failure.
    pub(crate) async fn flush_durably(
        &self,
        operation: &'static str,
    ) -> Result<(), InfrastructureError> {
        self.durable_flush(operation).await
    }

    /// Tree that stores `key`.
    fn tree_for(&self, key: &[u8]) -> &Tree {
        if is_outbox_key(key) {
            &self.outbox
        } else {
            &self.db
        }
    }
}

/// Which trees a prefix scan has to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanScope {
    Default,
    Outbox,
    Both,
}

fn scan_scope(prefix: &[u8]) -> ScanScope {
    if is_outbox_key(prefix) {
        ScanScope::Outbox
    } else if OUTBOX_KEY_PREFIXES
        .iter()
        .any(|outbox_prefix| outbox_prefix.starts_with(prefix))
    {
        ScanScope::Both
    } else {
        ScanScope::Default
    }
}

fn collect_prefix(
    tree: &Tree,
    prefix: &[u8],
    results: &mut Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<(), InfrastructureError> {
    for item in tree.scan_prefix(prefix) {
        let (k, v) = item.map_err(|e| InfrastructureError::Database(e.to_string()))?;
        results.push((k.to_vec(), v.to_vec()));
    }
    Ok(())
}

#[async_trait]
impl IStorageRepository for SledRepository {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, InfrastructureError> {
        let repo = self.clone();
        let key = key.to_vec();
        tokio::task::spawn_blocking(move || {
            repo.with_retry("get", || {
                repo.tree_for(&key)
                    .get(&key)
                    .map(|opt| opt.map(|ivec| ivec.to_vec()))
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
            repo.with_retry("put", || {
                repo.tree_for(&key)
                    .insert(&key, value.as_slice())
                    .map(|_| ())
            })
        })
        .await
        .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }

    async fn exists(&self, key: &[u8]) -> Result<bool, InfrastructureError> {
        let repo = self.clone();
        let key = key.to_vec();
        tokio::task::spawn_blocking(move || {
            repo.with_retry("exists", || repo.tree_for(&key).contains_key(&key))
        })
        .await
        .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }

    async fn delete(&self, key: &[u8]) -> Result<(), InfrastructureError> {
        let repo = self.clone();
        let key = key.to_vec();
        tokio::task::spawn_blocking(move || {
            repo.with_retry("delete", || repo.tree_for(&key).remove(&key).map(|_| ()))
        })
        .await
        .map_err(|e| InfrastructureError::Database(format!("spawn_blocking join error: {e}")))?
    }

    async fn scan(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, InfrastructureError> {
        let db = self.db.clone();
        let outbox = self.outbox.clone();
        let prefix = prefix.to_vec();
        tokio::task::spawn_blocking(move || {
            let mut results = Vec::new();
            match scan_scope(&prefix) {
                ScanScope::Default => collect_prefix(&db, &prefix, &mut results)?,
                ScanScope::Outbox => collect_prefix(&outbox, &prefix, &mut results)?,
                ScanScope::Both => {
                    collect_prefix(&db, &prefix, &mut results)?;
                    collect_prefix(&outbox, &prefix, &mut results)?;
                    results.sort_by(|left, right| left.0.cmp(&right.0));
                }
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
        let now = unix_millis();
        let expiry = now.saturating_add(ttl_seconds.saturating_mul(1000));
        let expiry_bytes = expiry.to_be_bytes();

        if let Some(existing) = self
            .replay
            .get(tag)
            .map_err(|e| InfrastructureError::Database(e.to_string()))?
        {
            if existing.len() == 8 {
                let existing_expiry =
                    u64::from_be_bytes(existing.as_ref().try_into().map_err(|_| {
                        InfrastructureError::Database("Invalid expiry bytes".into())
                    })?);
                if existing_expiry >= now {
                    return Ok(true);
                }
            } else {
                return Ok(true);
            }
        }

        self.replay
            .insert(tag, &expiry_bytes)
            .map_err(|e| InfrastructureError::Database(e.to_string()))?;

        Ok(false)
    }

    /// Removes expired replay tags. Only [`REPLAY_TREE`] is scanned, so the
    /// nonce floor, quote counters and chain cursor (also eight-byte values)
    /// are never mistaken for expired tags.
    async fn prune_expired(&self) -> Result<usize, InfrastructureError> {
        let now = unix_millis();
        let mut count = 0;

        for item in &self.replay {
            let (key, value) = item.map_err(|e| InfrastructureError::Database(e.to_string()))?;
            let expired = <[u8; 8]>::try_from(value.as_ref())
                .is_ok_and(|bytes| u64::from_be_bytes(bytes) < now);
            if expired {
                self.replay
                    .remove(key)
                    .map_err(|e| InfrastructureError::Database(e.to_string()))?;
                count += 1;
            }
        }

        Ok(count)
    }
}

fn unix_millis() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
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

        assert!(!repo.replay.contains_key(b"old").unwrap());
        assert!(repo.replay.contains_key(b"fresh").unwrap());
    }

    /// Pruning replay tags used to scan the default tree and delete any
    /// eight-byte value that read as an expired timestamp, which matched the
    /// chain cursor and zero-valued counters.
    #[tokio::test]
    async fn replay_pruning_never_touches_other_eight_byte_values() {
        let repo = test_repo();
        repo.put(CURSOR_KEY, &315_000_000_u64.to_be_bytes())
            .await
            .unwrap();
        repo.put(b"nonce:local", &0_u64.to_le_bytes())
            .await
            .unwrap();
        repo.put(b"quote:outstanding", &0_u64.to_le_bytes())
            .await
            .unwrap();
        repo.check_and_tag(b"expired-tag", 0).await.unwrap();
        sleep(Duration::from_millis(1_100)).await;

        assert_eq!(repo.prune_expired().await.unwrap(), 1);
        for key in [CURSOR_KEY, b"nonce:local".as_slice(), b"quote:outstanding"] {
            assert!(repo.exists(key).await.unwrap(), "{key:?} was pruned");
        }
        assert!(!repo.db.contains_key(b"expired-tag").unwrap());
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

    fn counters(outstanding: u64, pending: u64, loss: u64, start: Option<u64>) -> QuoteCounters {
        QuoteCounters {
            outstanding,
            pending_sponsored_gas: pending,
            rolling_loss_native: U256::from(loss),
            loss_window_start: start,
        }
    }

    #[test]
    fn quote_admission_mirrors_reservation_limits() {
        let limit = U256::from(100);
        assert!(counters(0, 0, 0, None)
            .admit(10, 2, 20, limit, 60, 1_000)
            .is_ok());
        assert!(matches!(
            counters(2, 0, 0, None).admit(10, 2, 20, limit, 60, 1_000),
            Err(QuoteStoreError::OutstandingCapacity)
        ));
        assert!(matches!(
            counters(1, 15, 0, None).admit(10, 2, 20, limit, 60, 1_000),
            Err(QuoteStoreError::PendingGasCapacity)
        ));
        assert!(matches!(
            counters(0, u64::MAX, 0, None).admit(1, 2, u64::MAX, limit, 60, 1_000),
            Err(QuoteStoreError::PendingGasCapacity)
        ));
        assert!(matches!(
            counters(0, 0, 100, Some(990)).admit(10, 2, 20, limit, 60, 1_000),
            Err(QuoteStoreError::PendingLossLimit)
        ));
        // An expired loss window no longer blocks admission.
        assert!(counters(0, 0, 100, Some(900))
            .admit(10, 2, 20, limit, 60, 1_000)
            .is_ok());
    }

    #[tokio::test]
    async fn quote_counters_default_to_zero_and_read_stored_values() {
        let repo = test_repo();
        assert_eq!(
            repo.quote_counters().await.unwrap(),
            QuoteCounters::default()
        );

        repo.put(b"quote:outstanding", &3_u64.to_le_bytes())
            .await
            .unwrap();
        repo.put(b"quote:pending-gas", &4_000_u64.to_le_bytes())
            .await
            .unwrap();
        repo.put(b"quote:loss-window-start", &50_u64.to_le_bytes())
            .await
            .unwrap();
        let mut loss = [0_u8; 32];
        U256::from(7).to_big_endian(&mut loss);
        repo.put(b"quote:rolling-loss", &loss).await.unwrap();

        assert_eq!(
            repo.quote_counters().await.unwrap(),
            counters(3, 4_000, 7, Some(50))
        );
    }

    /// Signed transaction record of the size seen on the live fleet: the
    /// `raw_signed_tx` bytes serialise as a JSON number array of about 66 KB.
    fn large_v2_record(seed: u8, nonce: u64) -> PendingTransactionV2 {
        PendingTransactionV2 {
            execution_id: [seed; 32],
            to: "0x1111111111111111111111111111111111111111".to_string(),
            data_hash: [seed; 32],
            nonce,
            gas_limit: "21000".to_string(),
            gas_price: "1".to_string(),
            maximum_fee_per_gas: "1".to_string(),
            raw_signed_tx: vec![200_u8; 16_500],
            tx_hash: format!("0x{}", hex::encode([seed; 32])),
            prior_transaction_hashes: Vec::new(),
            replacement_attempts: 0,
            first_sent_at: 1,
            last_update_at: 1,
            status: nox_core::TxStatusV2::Mined,
        }
    }

    fn stored_bytes(record: &PendingTransactionV2) -> Vec<u8> {
        serde_json::to_vec(&StoredTransactionV2 {
            schema: 2,
            transaction: record.clone(),
        })
        .unwrap()
    }

    /// The record exactly as rc.3 to rc.5 wrote it: `raw_signed_tx` as a
    /// JSON array of numbers.
    fn legacy_encoded_bytes(record: &PendingTransactionV2) -> Vec<u8> {
        let mut value = serde_json::to_value(StoredTransactionV2 {
            schema: 2,
            transaction: record.clone(),
        })
        .unwrap();
        value["transaction"]["raw_signed_tx"] = serde_json::Value::Array(
            record
                .raw_signed_tx
                .iter()
                .map(|byte| serde_json::Value::from(*byte))
                .collect(),
        );
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn records_written_by_older_nodes_still_decode() {
        let record = large_v2_record(0x0c, 4);
        let legacy = legacy_encoded_bytes(&record);
        let DecodedTransaction::V2(decoded) = decode_stored_transaction(&legacy).unwrap() else {
            panic!("expected a v2 record");
        };
        assert_eq!(decoded.raw_signed_tx, record.raw_signed_tx);
        assert_eq!(decoded.tx_hash, record.tx_hash);

        let compact = stored_bytes(&record);
        let DecodedTransaction::V2(round_trip) = decode_stored_transaction(&compact).unwrap()
        else {
            panic!("expected a v2 record");
        };
        assert_eq!(round_trip.raw_signed_tx, record.raw_signed_tx);
        assert!(
            compact.len() * 10 < legacy.len() * 7,
            "compact {} bytes, legacy {} bytes",
            compact.len(),
            legacy.len()
        );

        let legacy_record = serde_json::json!({
            "id": "legacy",
            "to": "0x1111111111111111111111111111111111111111",
            "data": [1, 2, 3],
            "nonce": 9,
            "gas_limit": "21000",
            "gas_price": "1",
            "tx_hash": format!("0x{}", "ee".repeat(32)),
            "first_sent_at": 1,
            "last_update_at": 1,
            "status": "Mined"
        });
        let DecodedTransaction::Legacy(decoded) =
            decode_stored_transaction(&serde_json::to_vec(&legacy_record).unwrap()).unwrap()
        else {
            panic!("expected a legacy record");
        };
        assert_eq!(decoded.data, vec![1, 2, 3]);
    }

    const CURSOR_KEY: &[u8] = b"chain_observer:last_block";

    #[tokio::test]
    async fn migration_moves_outbox_records_and_is_idempotent() {
        let dir = tempdir().unwrap();
        let first = large_v2_record(0xaa, 1);
        let second = large_v2_record(0xbb, 2);
        let outbox_first = format!("outbox:{}", hex::encode(first.execution_id));
        let outbox_second = format!("outbox:{}", hex::encode(second.execution_id));
        {
            // The rc.3 layout: everything in the default tree.
            let db = sled::open(dir.path()).unwrap();
            db.insert(outbox_first.as_bytes(), stored_bytes(&first))
                .unwrap();
            db.insert(outbox_second.as_bytes(), stored_bytes(&second))
                .unwrap();
            db.insert(b"tx:1", stored_bytes(&first)).unwrap();
            db.insert(b"tx:2", stored_bytes(&second)).unwrap();
            db.insert(b"nonce:local", &3_u64.to_le_bytes()).unwrap();
            db.insert(CURSOR_KEY, &500_u64.to_be_bytes()).unwrap();
            db.insert(b"quote:nonce", &4_u64.to_le_bytes()).unwrap();
            db.flush().unwrap();
        }

        let repo = SledRepository::new(dir.path()).unwrap();
        for prefix in OUTBOX_KEY_PREFIXES {
            assert_eq!(repo.db.scan_prefix(prefix).count(), 0);
        }
        assert_eq!(
            repo.outbox.get(outbox_first.as_bytes()).unwrap().unwrap(),
            stored_bytes(&first)
        );
        assert_eq!(
            repo.outbox.get(b"tx:2").unwrap().unwrap(),
            stored_bytes(&second)
        );
        for key in [b"nonce:local".as_slice(), CURSOR_KEY, b"quote:nonce"] {
            assert!(repo.db.contains_key(key).unwrap(), "{key:?} moved");
            assert!(!repo.outbox.contains_key(key).unwrap(), "{key:?} copied");
        }

        // The repository API reads the moved records from their new tree.
        assert_eq!(repo.scan(b"tx:").await.unwrap().len(), 2);
        assert!(repo.exists(b"tx:1").await.unwrap());
        assert_eq!(
            repo.load_outbox_by_execution(first.execution_id)
                .await
                .unwrap()
                .unwrap()
                .nonce,
            1
        );

        // A second run finds nothing to move, in-process and across a reopen.
        assert_eq!(
            migrate_outbox_records(&repo.db, &repo.outbox).unwrap(),
            OutboxMigration::default()
        );
        drop(repo);
        let reopened = SledRepository::new(dir.path()).unwrap();
        assert_eq!(reopened.outbox.len(), 4);
        assert_eq!(
            migrate_outbox_records(&reopened.db, &reopened.outbox).unwrap(),
            OutboxMigration::default()
        );
        assert_eq!(reopened.scan(b"tx:").await.unwrap().len(), 2);
    }

    #[test]
    fn migration_reports_counts_and_keeps_the_newer_default_tree_copy() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let outbox = db.open_tree(OUTBOX_TREE).unwrap();
        outbox.insert(b"tx:7", b"older".as_slice()).unwrap();
        db.insert(b"tx:7", b"newer".as_slice()).unwrap();
        db.insert(b"tx:8", b"other".as_slice()).unwrap();
        db.insert(b"outbox:aa", b"record".as_slice()).unwrap();

        let report = migrate_outbox_records(&db, &outbox).unwrap();
        assert_eq!(
            report,
            OutboxMigration {
                outbox_records: 1,
                transaction_records: 2,
                replaced: 1,
            }
        );
        assert_eq!(report.moved(), 3);
        assert_eq!(outbox.get(b"tx:7").unwrap().unwrap(), b"newer".as_slice());
        assert!(db.get(b"tx:7").unwrap().is_none());
        assert_eq!(
            migrate_outbox_records(&db, &outbox).unwrap(),
            OutboxMigration::default()
        );
    }

    #[tokio::test]
    async fn repository_routes_outbox_keys_to_their_tree() {
        let repo = test_repo();
        repo.put(b"tx:4", b"record").await.unwrap();
        repo.put(b"outbox:cc", b"record").await.unwrap();
        repo.put(b"peer:a", b"node").await.unwrap();
        assert!(repo.db.get(b"tx:4").unwrap().is_none());
        assert!(repo.outbox.get(b"tx:4").unwrap().is_some());
        assert!(repo.outbox.get(b"peer:a").unwrap().is_none());

        assert_eq!(repo.scan(b"tx:").await.unwrap().len(), 1);
        assert_eq!(repo.scan(b"peer:").await.unwrap().len(), 1);
        // A prefix that spans both trees returns one ordered key space.
        let everything: Vec<Vec<u8>> = repo
            .scan(b"")
            .await
            .unwrap()
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        assert_eq!(
            everything,
            vec![b"outbox:cc".to_vec(), b"peer:a".to_vec(), b"tx:4".to_vec()]
        );
        assert_eq!(repo.scan(b"t").await.unwrap().len(), 1);

        repo.delete(b"tx:4").await.unwrap();
        assert!(!repo.exists(b"tx:4").await.unwrap());
    }

    #[tokio::test]
    async fn durable_outbox_writes_never_touch_the_default_tree() {
        let repo = test_repo();
        let first = large_v2_record(0x01, 0);
        let second = large_v2_record(0x02, 1);
        assert!(matches!(
            repo.create_outbox_durably(first.execution_id, &first, 1)
                .await
                .unwrap(),
            CreateOutboxResult::Created
        ));
        assert!(matches!(
            repo.create_outbox_durably(second.execution_id, &second, 2)
                .await
                .unwrap(),
            CreateOutboxResult::Created
        ));
        repo.persist_v2_durably(&second).await.unwrap();
        repo.put(CURSOR_KEY, &1_u64.to_be_bytes()).await.unwrap();

        for prefix in OUTBOX_KEY_PREFIXES {
            assert_eq!(repo.db.scan_prefix(prefix).count(), 0);
        }
        assert_eq!(repo.outbox.len(), 4);
        // The nonce floor is written in the same transaction, to the default tree.
        assert_eq!(
            repo.db.get(b"nonce:local").unwrap().unwrap(),
            2_u64.to_le_bytes().as_slice()
        );
        // The cursor's tree now holds only small keys.
        let default_tree_bytes: usize = repo
            .db
            .iter()
            .map(|item| item.map(|(key, value)| key.len() + value.len()).unwrap())
            .sum();
        assert!(
            default_tree_bytes < 1_024,
            "default tree holds {default_tree_bytes} bytes"
        );
        assert!(matches!(
            repo.create_outbox_durably(first.execution_id, &first, 3)
                .await
                .unwrap(),
            CreateOutboxResult::Existing(_)
        ));
    }

    fn blob_count(dir: &Path) -> usize {
        std::fs::read_dir(dir.join("blobs")).map_or(0, |entries| entries.count())
    }

    async fn rewrite_cursor(repo: &SledRepository, writes: u64) {
        for block in 0..writes {
            repo.put(CURSOR_KEY, &block.to_be_bytes()).await.unwrap();
            repo.db.flush_async().await.unwrap();
        }
    }

    /// Two large outbox records next to the cursor produced a new blob file on
    /// every consolidation of the cursor's leaf. With the records in their own
    /// tree, rewriting the cursor writes no blobs.
    #[tokio::test]
    async fn cursor_rewrites_do_not_create_blobs_next_to_outbox_records() {
        const WRITES: u64 = 60;

        let legacy_dir = tempdir().unwrap();
        let legacy = SledRepository::new(legacy_dir.path()).unwrap();
        for record in [large_v2_record(0x01, 0), large_v2_record(0x02, 1)] {
            let key = format!("outbox:{}", hex::encode(record.execution_id));
            legacy
                .db
                .insert(key.as_bytes(), legacy_encoded_bytes(&record))
                .unwrap();
        }
        legacy.db.flush_async().await.unwrap();
        let legacy_before = blob_count(legacy_dir.path());
        rewrite_cursor(&legacy, WRITES).await;
        assert!(
            blob_count(legacy_dir.path()) > legacy_before,
            "the rc.3 layout no longer reproduces blob growth; this test needs a new baseline"
        );

        let dir = tempdir().unwrap();
        let repo = SledRepository::new(dir.path()).unwrap();
        for record in [large_v2_record(0x01, 0), large_v2_record(0x02, 1)] {
            repo.create_outbox_durably(record.execution_id, &record, record.nonce + 1)
                .await
                .unwrap();
        }
        let before = blob_count(dir.path());
        rewrite_cursor(&repo, WRITES).await;
        assert_eq!(blob_count(dir.path()), before);
    }
}
