//! Unified client interface for the `DarkPool` protocol.
//! Combines key management, UTXO tracking, proof generation, and transport into a single API.

use ethers::prelude::*;
#[cfg(feature = "mixnet")]
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Address, U256};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::builder::TransactionBuilder;
#[cfg(feature = "mixnet")]
use crate::economics::PriceData;
use crate::identity::DarkAccount;
use crate::key_repository::KeyRepository;
use crate::merkle_tree::LocalMerkleTree;
use crate::note_factory::{ChangeNoteResult, NoteFactory, SpendingInputs};
#[cfg(feature = "mixnet")]
use crate::note_processor::WalletNote;
use crate::prover::ClientProver;
use crate::scan_engine::{ScanEngine, ScanResult};
use crate::utxo_store::{OwnedNote, UtxoStore};
use nox_core::traits::interfaces::IProverService;

#[cfg(feature = "mixnet")]
use nox_client::mixnet_client::{MixnetClient, MixnetClientError};

/// Privacy client errors
#[derive(Debug, Error)]
pub enum PrivacyClientError {
    #[error("Insufficient balance: need {needed}, have {have}")]
    InsufficientBalance { needed: U256, have: U256 },
    #[error("No spendable notes found")]
    NoSpendableNotes,
    #[error("Note selection failed: {0}")]
    NoteSelectionFailed(String),
    #[error("Proof generation failed: {0}")]
    ProofFailed(String),
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),
    #[error("Scan error: {0}")]
    ScanError(String),
    #[error("Provider error: {0}")]
    ProviderError(String),
    #[error("Tree sync mismatch: local root {local:?} != on-chain root {onchain:?}")]
    TreeMismatch { local: U256, onchain: U256 },
    #[error("Mixnet error: {0}")]
    MixnetError(String),
    #[error("Invalid memo: {0}")]
    InvalidMemo(String),
    #[error("Cryptographic operation failed: {0}")]
    CryptoFailed(String),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Gas fee {fee} exceeds payment note value {note_value}")]
    GasFeeExceedsNoteValue { fee: U256, note_value: U256 },
    #[error("Persistence error: {0}")]
    Persistence(#[from] crate::persistence::PersistenceError),
}

#[cfg(feature = "mixnet")]
impl From<MixnetClientError> for PrivacyClientError {
    fn from(e: MixnetClientError) -> Self {
        PrivacyClientError::MixnetError(e.to_string())
    }
}

pub type PrivacyClientConfig = crate::config::DarkPoolConfig;
pub use crate::config::PrivacyTxResult;

/// Determines how a transaction is submitted to the blockchain.
pub enum Transport<'a> {
    Direct,
    /// Gas payment ZK proof + mixnet submission. Change notes are discoverable
    /// via pre-registered ephemeral keys.
    #[cfg(feature = "mixnet")]
    PaidMixnet {
        client: &'a MixnetClient,
        payment_asset: Address,
        prices: &'a PriceData,
        relayer_address: Address,
    },
    /// User signs TX locally; exit node calls `eth_sendRawTransaction`.
    /// IP privacy via Sphinx routing, no gas notes needed.
    #[cfg(feature = "mixnet")]
    SignedBroadcast {
        client: &'a MixnetClient,
    },
    /// Phantom variant to avoid unused lifetime warning when mixnet feature is disabled.
    #[cfg(not(feature = "mixnet"))]
    #[doc(hidden)]
    _Phantom(std::marker::PhantomData<&'a ()>),
}

struct SubmitResult {
    tx_hash: H256,
    block_num: u64,
    gas_used: U256,
    payment_nullifier: Option<U256>,
    /// Used for local state sync; `eth_getLogs` returns 0 on Anvil for recently mined blocks.
    receipt_logs: Vec<ethers::types::Log>,
}

/// Main entry point for `DarkPool` operations. Queries can optionally route through the Mixnet.
pub struct PrivacyClient<M: Middleware + Clone + 'static> {
    signer: Arc<SignerMiddleware<M, LocalWallet>>,
    keys: KeyRepository,
    utxos: UtxoStore,
    tree: LocalMerkleTree,
    builder: TransactionBuilder,
    note_factory: NoteFactory,
    config: PrivacyClientConfig,
    last_synced_block: u64,
}

impl<M: Middleware + Clone + 'static> PrivacyClient<M> {
    pub async fn new(
        provider: Arc<M>,
        wallet: LocalWallet,
        dark_account: DarkAccount,
        config: PrivacyClientConfig,
        prover: Arc<dyn IProverService>,
    ) -> Result<Self, PrivacyClientError> {
        let timeout_ms = config.provider_timeout_ms;
        let chain_id =
            tokio::time::timeout(Duration::from_millis(timeout_ms), provider.get_chainid())
                .await
                .map_err(|_| {
                    PrivacyClientError::ProviderError(format!(
                        "get_chainid timed out after {timeout_ms}ms"
                    ))
                })?
                .map_err(|e| PrivacyClientError::ProviderError(format!("get_chainid: {e}")))?
                .as_u64();

        let wallet_with_chain = wallet.with_chain_id(chain_id);
        let signer = Arc::new(SignerMiddleware::new(
            (*provider).clone(),
            wallet_with_chain,
        ));

        if config.darkpool_address == Address::zero() {
            return Err(PrivacyClientError::Config(
                "darkpool_address is zero -- all transactions would be sent to the zero address"
                    .into(),
            ));
        }

        let mut keys = KeyRepository::new(dark_account, config.compliance_pk);
        // Pre-register a default lookahead window of incoming keys so that
        // the scan engine can detect transfers on the very first sync.
        // Without this, the recipient_key_map is empty and no transfer memos
        // can be matched until notes are found (chicken-and-egg problem).
        keys.advance_incoming_keys(crate::key_repository::DEFAULT_LOOKAHEAD);
        let client_prover = Arc::new(ClientProver::with_service(prover));

        let mut builder_config = config.builder_config.clone();
        builder_config.compliance_pk = config.compliance_pk;
        builder_config.darkpool_address = config.darkpool_address;
        let builder = TransactionBuilder::new(client_prover, builder_config);

        let note_factory = NoteFactory::new(config.compliance_pk);

        info!(
            "Privacy Client initialized. DarkPool: {:?}",
            config.darkpool_address
        );

        Ok(Self {
            signer,
            keys,
            utxos: UtxoStore::new(),
            tree: LocalMerkleTree::new(),
            builder,
            note_factory,
            config,
            last_synced_block: 0,
        })
    }

    /// Alias for [`new()`](Self::new).
    pub async fn with_prover(
        provider: Arc<M>,
        wallet: LocalWallet,
        dark_account: DarkAccount,
        config: PrivacyClientConfig,
        prover: Arc<dyn IProverService>,
    ) -> Result<Self, PrivacyClientError> {
        Self::new(provider, wallet, dark_account, config, prover).await
    }

    #[must_use]
    pub fn balance(&self, asset: Address) -> U256 {
        self.utxos.get_balance(asset)
    }

    #[must_use]
    pub fn merkle_root(&self) -> U256 {
        self.tree.root()
    }

    #[must_use]
    pub fn note_count(&self) -> usize {
        self.utxos.count()
    }

    pub fn receiving_key(&mut self) -> Result<(U256, U256), PrivacyClientError> {
        self.keys
            .get_public_incoming_key()
            .map_err(|e| PrivacyClientError::CryptoFailed(e.to_string()))
    }

    pub fn advance_keys(&mut self, count: u64) {
        self.keys.advance_ephemeral_keys(count);
        self.keys.advance_incoming_keys(count);
    }

    /// Atomic write (temp file + rename). Pending spends are not persisted.
    pub fn save_state(&self, path: &std::path::Path) -> Result<(), PrivacyClientError> {
        crate::persistence::save_wallet_state(path, &self.utxos, &self.tree, self.last_synced_block)
            .map_err(PrivacyClientError::Persistence)
    }

    /// Returns `Ok(true)` if loaded, `Ok(false)` if file doesn't exist (fresh wallet).
    pub fn load_state(&mut self, path: &std::path::Path) -> Result<bool, PrivacyClientError> {
        match crate::persistence::load_wallet_state(path)? {
            Some((utxos, tree, block)) => {
                self.utxos = utxos;
                self.tree = tree;
                self.last_synced_block = block;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Requires prior ERC-20 approval for the `DarkPool` contract.
    pub async fn deposit(
        &mut self,
        amount: U256,
        asset: Address,
    ) -> Result<PrivacyTxResult, PrivacyClientError> {
        info!("Depositing {} of {:?}", amount, asset);

        let deposit_result = self
            .note_factory
            .create_deposit_note(amount, asset, &mut self.keys)
            .map_err(|e| PrivacyClientError::ProofFailed(e.to_string()))?;

        let proof_bundle = self
            .builder
            .build_deposit(&deposit_result)
            .await
            .map_err(|e| PrivacyClientError::ProofFailed(e.to_string()))?;

        debug!(
            "Deposit proof generated. Commitment: {:?}",
            deposit_result.commitment
        );

        let tx = TransactionRequest::new()
            .to(self.config.darkpool_address)
            .data(proof_bundle.calldata.clone());

        let pending = self
            .timed_provider_call(
                "deposit send_transaction",
                self.signer.send_transaction(tx, None),
            )
            .await?;

        let receipt = self
            .timed_provider_call("deposit pending confirmation", pending)
            .await?
            .ok_or_else(|| {
                PrivacyClientError::TransactionFailed("No receipt received".to_string())
            })?;

        info!(
            "Deposit successful. TxHash: {:?}, Commitment: {:?}",
            receipt.transaction_hash, deposit_result.commitment
        );

        let leaf_index = self.tree.insert(deposit_result.commitment);

        let shared_secret = crate::crypto_helpers::derive_shared_secret_bjj(
            deposit_result.ephemeral_sk,
            self.config.compliance_pk,
        )
        .map_err(|e| PrivacyClientError::CryptoFailed(format!("ECDH failed: {e}")))?;

        let block_num = if let Some(b) = receipt.block_number {
            b.as_u64()
        } else {
            warn!(
                "Receipt missing block_number for tx {:?}, using last_synced_block={}",
                receipt.transaction_hash, self.last_synced_block
            );
            self.last_synced_block
        };

        self.utxos.add_note(
            OwnedNote {
                plaintext: deposit_result.note.clone(),
                commitment: deposit_result.commitment,
                leaf_index,
                spending_secret: shared_secret,
                is_transfer: false,
                received_block: block_num,
            },
            crate::crypto_helpers::derive_nullifier_path_a(deposit_result.note.nullifier),
        );

        self.last_synced_block = block_num;

        Ok(PrivacyTxResult {
            tx_hash: receipt.transaction_hash,
            new_commitments: vec![deposit_result.commitment],
            spent_nullifiers: vec![],
            gas_used: receipt.gas_used.unwrap_or_else(|| {
                warn!(
                    "Receipt missing gas_used for tx {:?}",
                    receipt.transaction_hash
                );
                U256::zero()
            }),
        })
    }

    pub async fn withdraw_with_transport(
        &mut self,
        transport: &Transport<'_>,
        amount: U256,
        asset: Address,
        recipient: Address,
        intent_hash: Option<U256>,
    ) -> Result<PrivacyTxResult, PrivacyClientError> {
        info!("Withdrawing {} of {:?} to {:?}", amount, asset, recipient);

        let balance = self.balance(asset);
        if balance < amount {
            return Err(PrivacyClientError::InsufficientBalance {
                needed: amount,
                have: balance,
            });
        }

        let selected = self
            .utxos
            .select_notes(asset, amount)
            .ok_or(PrivacyClientError::NoSpendableNotes)?;
        let note = (*selected
            .first()
            .ok_or(PrivacyClientError::NoSpendableNotes)?)
        .clone();
        let excluded: HashSet<U256> = selected.iter().map(|n| n.commitment).collect();
        drop(selected);

        let spending_inputs = self.create_spending_inputs(&note)?;
        let nullifier_hash = Self::derive_nullifier_hash(&note);

        for c in &excluded {
            self.utxos.mark_pending_spend(c);
        }

        let change_value = note.plaintext.value.saturating_sub(amount);
        let change_result = if change_value.is_zero() {
            None
        } else {
            Some(
                self.note_factory
                    .create_change_note(change_value, asset, &mut self.keys)
                    .map_err(|e| PrivacyClientError::ProofFailed(e.to_string()))?,
            )
        };

        self.ensure_synced_with_transport(transport).await?;

        let merkle_root = self.tree.root();
        let proof_bundle = self
            .builder
            .build_withdraw(
                &spending_inputs,
                amount,
                recipient,
                merkle_root,
                change_result.as_ref(),
                intent_hash,
                0,
            )
            .await
            .map_err(|e| PrivacyClientError::ProofFailed(e.to_string()))?;

        debug!("Withdraw proof generated for {} to {:?}", amount, recipient);

        let submit = self
            .submit_and_confirm(
                transport,
                proof_bundle.calldata.clone(),
                merkle_root,
                &excluded,
                U256::from(self.config.gas_limits.withdraw),
            )
            .await?;

        let mut new_commitments = vec![];
        if let Some(ref change) = change_result {
            new_commitments.push(change.commitment);
        }

        if submit.payment_nullifier.is_some() {
            // Gas payment change note is inserted on-chain BEFORE action output notes
            self.sync_from_receipt_logs(&submit.receipt_logs, submit.block_num)?;
        } else {
            if let Some(ref change) = change_result {
                self.register_self_note(change, submit.block_num)?;
            }
            self.last_synced_block = submit.block_num;
        }

        self.utxos.mark_spent(nullifier_hash);
        let mut spent_nullifiers = vec![nullifier_hash];
        if let Some(pn) = submit.payment_nullifier {
            self.utxos.mark_spent(pn);
            spent_nullifiers.push(pn);
        }

        for c in &excluded {
            self.utxos.clear_pending_spend(c);
        }

        Ok(PrivacyTxResult {
            tx_hash: submit.tx_hash,
            new_commitments,
            spent_nullifiers,
            gas_used: submit.gas_used,
        })
    }

    pub async fn split_with_transport(
        &mut self,
        transport: &Transport<'_>,
        amount_a: U256,
        amount_b: U256,
        asset: Address,
    ) -> Result<PrivacyTxResult, PrivacyClientError> {
        let total = amount_a + amount_b;
        info!("Splitting note: {} + {} of {:?}", amount_a, amount_b, asset);

        // Split circuit enforces strict conservation: input == output_a + output_b
        let note = self
            .utxos
            .select_note_exact(asset, total)
            .ok_or(PrivacyClientError::NoSpendableNotes)?
            .clone();
        let excluded: HashSet<U256> = [note.commitment].into_iter().collect();

        let spending_inputs = self.create_spending_inputs(&note)?;
        let nullifier_hash = Self::derive_nullifier_hash(&note);

        for c in &excluded {
            self.utxos.mark_pending_spend(c);
        }

        let (note_a, note_b) = self
            .note_factory
            .create_split_notes(amount_a, amount_b, asset, &mut self.keys)
            .map_err(|e| PrivacyClientError::ProofFailed(e.to_string()))?;

        self.ensure_synced_with_transport(transport).await?;

        let merkle_root = self.tree.root();
        let proof_bundle = self
            .builder
            .build_split(&spending_inputs, merkle_root, &note_a, &note_b, 0)
            .await
            .map_err(|e| PrivacyClientError::ProofFailed(e.to_string()))?;

        debug!(
            "Split proof generated. Outputs: {:?}, {:?}",
            note_a.commitment, note_b.commitment
        );

        let submit = self
            .submit_and_confirm(
                transport,
                proof_bundle.calldata.clone(),
                merkle_root,
                &excluded,
                U256::from(self.config.gas_limits.split),
            )
            .await?;

        if submit.payment_nullifier.is_some() {
            // Gas payment change note is inserted on-chain BEFORE action output notes
            self.sync_from_receipt_logs(&submit.receipt_logs, submit.block_num)?;
        } else {
            self.register_self_note(&note_a, submit.block_num)?;
            self.register_self_note(&note_b, submit.block_num)?;
            self.last_synced_block = submit.block_num;
        }

        self.utxos.mark_spent(nullifier_hash);
        let mut spent_nullifiers = vec![nullifier_hash];
        if let Some(pn) = submit.payment_nullifier {
            self.utxos.mark_spent(pn);
            spent_nullifiers.push(pn);
        }

        for c in &excluded {
            self.utxos.clear_pending_spend(c);
        }

        Ok(PrivacyTxResult {
            tx_hash: submit.tx_hash,
            new_commitments: vec![note_a.commitment, note_b.commitment],
            spent_nullifiers,
            gas_used: submit.gas_used,
        })
    }

    pub async fn join_with_transport(
        &mut self,
        transport: &Transport<'_>,
        asset: Address,
    ) -> Result<PrivacyTxResult, PrivacyClientError> {
        info!("Joining notes for {:?}", asset);

        let unspent: Vec<_> = self
            .utxos
            .get_unspent()
            .into_iter()
            .filter(|n| n.plaintext.asset_id == crate::crypto_helpers::address_to_field(asset))
            .cloned()
            .collect();
        if unspent.len() < 2 {
            return Err(PrivacyClientError::NoteSelectionFailed(
                "Need at least 2 notes to join".to_string(),
            ));
        }

        let note_a = &unspent[0];
        let note_b = &unspent[1];

        let excluded: HashSet<U256> = [note_a.commitment, note_b.commitment].into_iter().collect();

        let spending_inputs_a = self.create_spending_inputs(note_a)?;
        let spending_inputs_b = self.create_spending_inputs(note_b)?;
        let nullifier_a = Self::derive_nullifier_hash(note_a);
        let nullifier_b = Self::derive_nullifier_hash(note_b);

        for c in &excluded {
            self.utxos.mark_pending_spend(c);
        }

        let total_value = note_a.plaintext.value + note_b.plaintext.value;

        let output = self
            .note_factory
            .create_join_output_note(total_value, asset, &mut self.keys)
            .map_err(|e| PrivacyClientError::ProofFailed(e.to_string()))?;

        self.ensure_synced_with_transport(transport).await?;

        let merkle_root = self.tree.root();
        let proof_bundle = self
            .builder
            .build_join(
                &spending_inputs_a,
                &spending_inputs_b,
                merkle_root,
                &output,
                0,
            )
            .await
            .map_err(|e| PrivacyClientError::ProofFailed(e.to_string()))?;

        debug!("Join proof generated. Output: {:?}", output.commitment);

        let submit = self
            .submit_and_confirm(
                transport,
                proof_bundle.calldata.clone(),
                merkle_root,
                &excluded,
                U256::from(self.config.gas_limits.join),
            )
            .await?;

        if submit.payment_nullifier.is_some() {
            // Gas payment change note is inserted on-chain BEFORE action output notes
            self.sync_from_receipt_logs(&submit.receipt_logs, submit.block_num)?;
        } else {
            self.register_self_note(&output, submit.block_num)?;
            self.last_synced_block = submit.block_num;
        }

        self.utxos.mark_spent(nullifier_a);
        self.utxos.mark_spent(nullifier_b);
        let mut spent_nullifiers = vec![nullifier_a, nullifier_b];
        if let Some(pn) = submit.payment_nullifier {
            self.utxos.mark_spent(pn);
            spent_nullifiers.push(pn);
        }

        for c in &excluded {
            self.utxos.clear_pending_spend(c);
        }

        Ok(PrivacyTxResult {
            tx_hash: submit.tx_hash,
            new_commitments: vec![output.commitment],
            spent_nullifiers,
            gas_used: submit.gas_used,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn transfer_with_transport(
        &mut self,
        transport: &Transport<'_>,
        amount: U256,
        asset: Address,
        recipient_b: (U256, U256),
        recipient_p: (U256, U256),
        recipient_proof: crate::proof_inputs::DLEQProof,
    ) -> Result<PrivacyTxResult, PrivacyClientError> {
        use crate::crypto_helpers::random_bjj_scalar;
        use crate::proof_inputs::NotePlaintext;

        info!("Transferring {} of {:?}", amount, asset);

        let balance = self.balance(asset);
        if balance < amount {
            return Err(PrivacyClientError::InsufficientBalance {
                needed: amount,
                have: balance,
            });
        }

        let selected = self
            .utxos
            .select_notes(asset, amount)
            .ok_or(PrivacyClientError::NoSpendableNotes)?;
        let note = (*selected
            .first()
            .ok_or(PrivacyClientError::NoSpendableNotes)?)
        .clone();
        let excluded: HashSet<U256> = selected.iter().map(|n| n.commitment).collect();
        drop(selected);

        let spending_inputs = self.create_spending_inputs(&note)?;
        let nullifier_hash = Self::derive_nullifier_hash(&note);

        for c in &excluded {
            self.utxos.mark_pending_spend(c);
        }

        // Memo note: nullifier=0, secret=0 because recipient uses Path B for spending
        let memo_note = NotePlaintext {
            asset_id: crate::crypto_helpers::address_to_field(asset),
            value: amount,
            secret: U256::zero(),
            nullifier: U256::zero(),
            timelock: U256::zero(),
            hashlock: U256::zero(),
        };
        let memo_ephemeral_sk = random_bjj_scalar();

        let change_value = note.plaintext.value.saturating_sub(amount);
        let change_note = NotePlaintext::random(change_value, asset);
        let change_ephemeral_sk = random_bjj_scalar();

        self.ensure_synced_with_transport(transport).await?;

        let merkle_root = self.tree.root();
        let proof_bundle = self
            .builder
            .build_transfer(
                &spending_inputs,
                merkle_root,
                recipient_b,
                recipient_p,
                recipient_proof,
                memo_note,
                memo_ephemeral_sk,
                change_note.clone(),
                change_ephemeral_sk,
                0,
            )
            .await
            .map_err(|e| PrivacyClientError::ProofFailed(e.to_string()))?;

        debug!(
            "Transfer proof generated. Memo: {:?}, Change: {:?}",
            proof_bundle.memo_commitment, proof_bundle.change_commitment
        );

        let submit = self
            .submit_and_confirm(
                transport,
                proof_bundle.calldata.clone(),
                merkle_root,
                &excluded,
                U256::from(self.config.gas_limits.transfer),
            )
            .await?;

        let mut new_commitments = vec![proof_bundle.memo_commitment];
        if !change_value.is_zero() {
            new_commitments.push(proof_bundle.change_commitment);
        }

        if submit.payment_nullifier.is_some() {
            // Gas payment change note is inserted on-chain BEFORE action output notes
            self.sync_from_receipt_logs(&submit.receipt_logs, submit.block_num)?;
        } else {
            // Memo FIRST, then change (matches DarkPool.sol insertion order)
            self.tree.insert(proof_bundle.memo_commitment);

            if !change_value.is_zero() {
                let change_leaf_index = self.tree.insert(proof_bundle.change_commitment);

                let change_shared_secret = crate::crypto_helpers::derive_shared_secret_bjj(
                    change_ephemeral_sk,
                    self.config.compliance_pk,
                )
                .map_err(|e| PrivacyClientError::CryptoFailed(format!("ECDH failed: {e}")))?;

                self.utxos.add_note(
                    OwnedNote {
                        plaintext: change_note.clone(),
                        commitment: proof_bundle.change_commitment,
                        leaf_index: change_leaf_index,
                        spending_secret: change_shared_secret,
                        is_transfer: false,
                        received_block: submit.block_num,
                    },
                    crate::crypto_helpers::derive_nullifier_path_a(change_note.nullifier),
                );
            }

            self.last_synced_block = submit.block_num;
        }

        self.utxos.mark_spent(nullifier_hash);
        let mut spent_nullifiers = vec![nullifier_hash];
        if let Some(pn) = submit.payment_nullifier {
            self.utxos.mark_spent(pn);
            spent_nullifiers.push(pn);
        }

        for c in &excluded {
            self.utxos.clear_pending_spend(c);
        }

        Ok(PrivacyTxResult {
            tx_hash: submit.tx_hash,
            new_commitments,
            spent_nullifiers,
            gas_used: submit.gas_used,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn public_claim(
        &mut self,
        memo_id: U256,
        value: U256,
        asset: Address,
        timelock: U256,
        owner_pk: (U256, U256),
        salt: U256,
        recipient_sk: U256,
    ) -> Result<PrivacyTxResult, PrivacyClientError> {
        self.public_claim_with_transport(
            &Transport::Direct,
            memo_id,
            value,
            asset,
            timelock,
            owner_pk,
            salt,
            recipient_sk,
        )
        .await
    }

    /// `DarkPool.publicClaim()` verifies proof only (no `msg.sender` check), so it can be relayed.
    #[allow(clippy::too_many_arguments)]
    pub async fn public_claim_with_transport(
        &mut self,
        transport: &Transport<'_>,
        memo_id: U256,
        value: U256,
        asset: Address,
        timelock: U256,
        owner_pk: (U256, U256),
        salt: U256,
        recipient_sk: U256,
    ) -> Result<PrivacyTxResult, PrivacyClientError> {
        use crate::crypto_helpers::{address_to_field, calculate_public_memo_id};

        info!("Claiming public memo via transport: {:?}", memo_id);

        let asset_id = address_to_field(asset);
        let calculated_memo_id =
            calculate_public_memo_id(value, asset_id, timelock, owner_pk.0, owner_pk.1, salt);
        if calculated_memo_id != memo_id {
            return Err(PrivacyClientError::InvalidMemo(
                "Calculated memo ID does not match provided memo ID".to_string(),
            ));
        }

        let note_out_result = self
            .note_factory
            .create_change_note(value, asset, &mut self.keys)
            .map_err(|e| PrivacyClientError::ProofFailed(e.to_string()))?;

        self.ensure_synced_with_transport(transport).await?;

        let merkle_root = self.tree.root();

        let proof_bundle = self
            .builder
            .build_public_claim(
                memo_id,
                value,
                asset_id,
                timelock,
                owner_pk,
                salt,
                recipient_sk,
                &note_out_result,
            )
            .await
            .map_err(|e| PrivacyClientError::ProofFailed(e.to_string()))?;

        debug!(
            "Public claim proof generated. Output commitment: {:?}",
            proof_bundle.note_out.commitment
        );

        let excluded = HashSet::new();

        let submit = self
            .submit_and_confirm(
                transport,
                proof_bundle.calldata.clone(),
                merkle_root,
                &excluded,
                U256::from(self.config.gas_limits.public_claim),
            )
            .await?;

        if submit.payment_nullifier.is_some() {
            self.sync_from_receipt_logs(&submit.receipt_logs, submit.block_num)?;
        } else {
            self.register_self_note(&note_out_result, submit.block_num)?;
            self.last_synced_block = submit.block_num;
        }

        let mut spent_nullifiers = vec![];
        if let Some(pn) = submit.payment_nullifier {
            self.utxos.mark_spent(pn);
            spent_nullifiers.push(pn);
        }

        Ok(PrivacyTxResult {
            tx_hash: submit.tx_hash,
            new_commitments: vec![note_out_result.commitment],
            spent_nullifiers,
            gas_used: submit.gas_used,
        })
    }

    pub async fn sync(&mut self) -> Result<ScanResult, PrivacyClientError> {
        let current_block = self
            .timed_provider_call("sync get_block_number", self.signer.get_block_number())
            .await?
            .as_u64();

        if current_block <= self.last_synced_block {
            return Ok(ScanResult::default());
        }

        info!(
            "Syncing from block {} to {}",
            self.last_synced_block + 1,
            current_block
        );

        let taken_utxos = std::mem::take(&mut self.utxos);
        let taken_tree = std::mem::take(&mut self.tree);

        let provider_arc = Arc::new(self.signer.inner().clone());
        let mut scan_engine = ScanEngine::with_state(
            provider_arc,
            self.config.darkpool_address,
            self.keys.clone(),
            taken_utxos,
            taken_tree,
            self.config.compliance_pk,
            self.last_synced_block,
        );

        let result = match scan_engine
            .scan_blocks(self.last_synced_block + 1, current_block)
            .await
        {
            Ok(result) => result,
            Err(e) => {
                self.utxos = std::mem::take(scan_engine.utxos_mut());
                self.tree = std::mem::take(scan_engine.tree_mut());
                return Err(PrivacyClientError::ScanError(e.to_string()));
            }
        };

        self.utxos = std::mem::take(scan_engine.utxos_mut());
        self.tree = std::mem::take(scan_engine.tree_mut());
        self.last_synced_block = current_block;

        if !result.new_notes.is_empty() {
            self.advance_keys(10);
        }

        info!(
            "Sync complete: {} new notes, {} nullifiers spent",
            result.new_notes.len(),
            result.spent_nullifiers.len()
        );

        // Post-sync root verification: check that the local root is recognized
        // on-chain. This is non-fatal because the chain may have advanced past
        // our sync range (new leaves inserted after `current_block`). The pre-proof
        // check in `ensure_synced_with_transport` is the hard gate.
        if let Err(e) = self.verify_root_is_known().await {
            warn!("Post-sync root verification failed (may need re-sync): {e}");
        }

        Ok(result)
    }

    /// Syncs via mixnet when transport carries a mixnet client (avoids metadata leaks).
    #[cfg_attr(not(feature = "mixnet"), allow(unused_variables))]
    async fn ensure_synced_with_transport(
        &mut self,
        transport: &Transport<'_>,
    ) -> Result<(), PrivacyClientError> {
        #[cfg(feature = "mixnet")]
        match transport {
            Transport::PaidMixnet { client, .. } | Transport::SignedBroadcast { client } => {
                let current_block = client.block_number().await?;
                if current_block > self.last_synced_block {
                    let behind = current_block - self.last_synced_block;
                    warn!(
                        "Merkle tree is {} blocks behind chain tip ({} vs {}). Auto-syncing via mixnet.",
                        behind, self.last_synced_block, current_block
                    );
                    self.sync_via_mixnet(client).await?;
                }
                self.verify_root_is_known().await?;
                return Ok(());
            }
            Transport::Direct => {}
        }

        let current_block = self
            .timed_provider_call(
                "ensure_synced get_block_number",
                self.signer.get_block_number(),
            )
            .await?
            .as_u64();

        if current_block > self.last_synced_block {
            let behind = current_block - self.last_synced_block;
            warn!(
                "Merkle tree is {} blocks behind chain tip ({} vs {}). Auto-syncing before proof generation.",
                behind, self.last_synced_block, current_block
            );
            self.sync().await?;
        }

        self.verify_root_is_known().await?;
        Ok(())
    }

    /// Wraps provider calls with a timeout to prevent indefinite hangs.
    async fn timed_provider_call<T, E, F>(
        &self,
        op_name: &str,
        future: F,
    ) -> Result<T, PrivacyClientError>
    where
        F: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Display,
    {
        tokio::time::timeout(
            Duration::from_millis(self.config.provider_timeout_ms),
            future,
        )
        .await
        .map_err(|_| {
            PrivacyClientError::ProviderError(format!(
                "{op_name} timed out after {}ms",
                self.config.provider_timeout_ms
            ))
        })?
        .map_err(|e| PrivacyClientError::ProviderError(format!("{op_name}: {e}")))
    }

    /// Sync from TX receipt logs (bypasses `eth_getLogs` which returns 0 on Anvil).
    fn sync_from_receipt_logs(
        &mut self,
        logs: &[ethers::types::Log],
        block_num: u64,
    ) -> Result<ScanResult, PrivacyClientError> {
        if logs.is_empty() {
            warn!("Paid TX receipt has 0 logs -- TX may have reverted silently");
            return Ok(ScanResult::default());
        }

        let provider_arc = Arc::new(self.signer.inner().clone());
        let mut scan_engine = ScanEngine::with_state(
            provider_arc,
            self.config.darkpool_address,
            self.keys.clone(),
            std::mem::take(&mut self.utxos),
            std::mem::take(&mut self.tree),
            self.config.compliance_pk,
            self.last_synced_block,
        );

        let result = scan_engine
            .process_logs_directly(logs)
            .map_err(|e| PrivacyClientError::ScanError(e.to_string()))?;

        self.utxos = std::mem::take(scan_engine.utxos_mut());
        self.tree = std::mem::take(scan_engine.tree_mut());
        self.last_synced_block = block_num;

        if !result.new_notes.is_empty() {
            self.advance_keys(10);
        }

        info!(
            "Receipt log sync: {} new notes, {} nullifiers spent, {} commitments added",
            result.new_notes.len(),
            result.spent_nullifiers.len(),
            result.new_commitments.len()
        );

        Ok(result)
    }

    #[cfg(feature = "mixnet")]
    pub async fn sync_via_mixnet(
        &mut self,
        mixnet: &MixnetClient,
    ) -> Result<ScanResult, PrivacyClientError> {
        let current_block = mixnet.block_number().await?;

        if current_block <= self.last_synced_block {
            return Ok(ScanResult::default());
        }

        info!(
            "Syncing via mixnet from block {} to {}",
            self.last_synced_block + 1,
            current_block
        );

        let filter = Filter::new()
            .address(self.config.darkpool_address)
            .from_block(self.last_synced_block + 1)
            .to_block(current_block);

        let logs = mixnet.get_logs(&filter).await?;

        info!("Received {} logs via mixnet", logs.len());

        let provider_arc = Arc::new(self.signer.inner().clone());
        let mut scan_engine = ScanEngine::with_state(
            provider_arc,
            self.config.darkpool_address,
            self.keys.clone(),
            std::mem::take(&mut self.utxos),
            std::mem::take(&mut self.tree),
            self.config.compliance_pk,
            self.last_synced_block,
        );

        let result = scan_engine
            .process_logs_directly(&logs)
            .map_err(|e| PrivacyClientError::ScanError(e.to_string()))?;

        self.utxos = std::mem::take(scan_engine.utxos_mut());
        self.tree = std::mem::take(scan_engine.tree_mut());
        self.last_synced_block = current_block;

        if !result.new_notes.is_empty() {
            self.advance_keys(10);
        }

        info!(
            "Mixnet sync complete: {} new notes, {} nullifiers spent",
            result.new_notes.len(),
            result.spent_nullifiers.len()
        );

        Ok(result)
    }

    /// Direct-submission wrapper for [`withdraw_with_transport`](Self::withdraw_with_transport).
    pub async fn withdraw(
        &mut self,
        amount: U256,
        asset: Address,
        recipient: Address,
        intent_hash: Option<U256>,
    ) -> Result<PrivacyTxResult, PrivacyClientError> {
        self.withdraw_with_transport(&Transport::Direct, amount, asset, recipient, intent_hash)
            .await
    }

    /// Direct-submission wrapper for [`split_with_transport`](Self::split_with_transport).
    pub async fn split(
        &mut self,
        amount_a: U256,
        amount_b: U256,
        asset: Address,
    ) -> Result<PrivacyTxResult, PrivacyClientError> {
        self.split_with_transport(&Transport::Direct, amount_a, amount_b, asset)
            .await
    }

    /// Direct-submission wrapper for [`join_with_transport`](Self::join_with_transport).
    pub async fn join(&mut self, asset: Address) -> Result<PrivacyTxResult, PrivacyClientError> {
        self.join_with_transport(&Transport::Direct, asset).await
    }

    /// Direct-submission wrapper for [`transfer_with_transport`](Self::transfer_with_transport).
    pub async fn transfer(
        &mut self,
        amount: U256,
        asset: Address,
        recipient_b: (U256, U256),
        recipient_p: (U256, U256),
        recipient_proof: crate::proof_inputs::DLEQProof,
    ) -> Result<PrivacyTxResult, PrivacyClientError> {
        self.transfer_with_transport(
            &Transport::Direct,
            amount,
            asset,
            recipient_b,
            recipient_p,
            recipient_proof,
        )
        .await
    }

    /// Path A for self-created notes, Path B for received transfer notes.
    fn derive_nullifier_hash(note: &OwnedNote) -> U256 {
        if note.is_transfer {
            crate::crypto_helpers::derive_nullifier_path_b(
                note.spending_secret,
                note.commitment,
                note.leaf_index,
            )
        } else {
            crate::crypto_helpers::derive_nullifier_path_a(note.plaintext.nullifier)
        }
    }

    /// Insert a self-created note (Path A) into the Merkle tree and UTXO store.
    fn register_self_note(
        &mut self,
        note_result: &ChangeNoteResult,
        block_num: u64,
    ) -> Result<u64, PrivacyClientError> {
        let leaf_index = self.tree.insert(note_result.commitment);

        let shared_secret = crate::crypto_helpers::derive_shared_secret_bjj(
            note_result.ephemeral_sk,
            self.config.compliance_pk,
        )
        .map_err(|e| PrivacyClientError::CryptoFailed(format!("ECDH failed: {e}")))?;

        self.utxos.add_note(
            OwnedNote {
                plaintext: note_result.note.clone(),
                commitment: note_result.commitment,
                leaf_index,
                spending_secret: shared_secret,
                is_transfer: false,
                received_block: block_num,
            },
            crate::crypto_helpers::derive_nullifier_path_a(note_result.note.nullifier),
        );

        Ok(leaf_index)
    }

    /// Submit and confirm via the appropriate transport.
    #[cfg_attr(not(feature = "mixnet"), allow(unused_variables))]
    async fn submit_and_confirm(
        &mut self,
        transport: &Transport<'_>,
        calldata: Bytes,
        merkle_root: U256,
        excluded: &HashSet<U256>,
        gas_limit: U256,
    ) -> Result<SubmitResult, PrivacyClientError> {
        match transport {
            Transport::Direct => {
                let tx = TransactionRequest::new()
                    .to(self.config.darkpool_address)
                    .data(calldata);

                let pending = self
                    .timed_provider_call(
                        "submit send_transaction",
                        self.signer.send_transaction(tx, None),
                    )
                    .await?;

                let receipt = self
                    .timed_provider_call("submit pending confirmation", pending)
                    .await?
                    .ok_or_else(|| {
                        PrivacyClientError::TransactionFailed("No receipt received".to_string())
                    })?;

                info!(
                    "Transaction confirmed. TxHash: {:?}",
                    receipt.transaction_hash
                );

                let block_num = if let Some(b) = receipt.block_number {
                    b.as_u64()
                } else {
                    warn!(
                        "Receipt missing block_number for tx {:?}, using last_synced_block={}",
                        receipt.transaction_hash, self.last_synced_block
                    );
                    self.last_synced_block
                };
                let gas_used = receipt.gas_used.unwrap_or_else(|| {
                    warn!(
                        "Receipt missing gas_used for tx {:?}",
                        receipt.transaction_hash
                    );
                    U256::zero()
                });

                Ok(SubmitResult {
                    tx_hash: receipt.transaction_hash,
                    block_num,
                    gas_used,
                    payment_nullifier: None,
                    receipt_logs: vec![],
                })
            }
            #[cfg(feature = "mixnet")]
            Transport::PaidMixnet {
                client,
                payment_asset,
                prices,
                relayer_address,
            } => {
                // ZK verification gas varies hugely between Anvil and mainnet
                let simulated_gas = self
                    .timed_provider_call(
                        "action eth_estimateGas",
                        self.signer.estimate_gas(
                            &ethers::types::transaction::eip2718::TypedTransaction::Legacy(
                                TransactionRequest::new()
                                    .to(self.config.darkpool_address)
                                    .data(calldata.clone()),
                            ),
                            None,
                        ),
                    )
                    .await
                    .unwrap_or_else(|e| {
                        warn!(
                            "eth_estimateGas failed ({}), falling back to config gas_limit={}",
                            e, gas_limit
                        );
                        gas_limit
                    });

                // 20% buffer + gas_payment verification overhead
                let action_gas_buffered = simulated_gas + simulated_gas / U256::from(5);
                let total_gas = action_gas_buffered + simulated_gas;
                info!(
                    "Gas estimate: simulated={}, buffered={}, total_with_payment={}",
                    simulated_gas, action_gas_buffered, total_gas
                );

                let payment_note = self.select_payment_note_excluding(
                    *payment_asset,
                    prices,
                    excluded,
                    total_gas,
                )?;

                // Registered ephemeral key so scan engine can discover the change note
                let fee_estimate = self.builder.estimate_fee(total_gas, prices);
                let change_value = payment_note
                    .note
                    .value
                    .checked_sub(fee_estimate.fee_amount)
                    .ok_or(PrivacyClientError::GasFeeExceedsNoteValue {
                        fee: fee_estimate.fee_amount,
                        note_value: payment_note.note.value,
                    })?;
                let gas_change_note = self
                    .note_factory
                    .create_change_note(change_value, *payment_asset, &mut self.keys)
                    .map_err(|e| {
                        PrivacyClientError::ProofFailed(format!(
                            "Gas change note creation failed: {e}"
                        ))
                    })?;

                let bundle = self
                    .builder
                    .build_paid_action(
                        &payment_note,
                        merkle_root,
                        self.tree.get_path(payment_note.leaf_index).siblings_vec(),
                        self.config.darkpool_address,
                        calldata,
                        prices,
                        *relayer_address,
                        total_gas,
                        Some(gas_change_note),
                        0,
                    )
                    .await
                    .map_err(|e| PrivacyClientError::ProofFailed(e.to_string()))?;

                debug!(
                    "Paid action bundle built: fee={}, multicall_target={:?}",
                    bundle.gas_payment.fee_amount, bundle.multicall_target
                );

                let tx_hash = client
                    .submit_transaction(bundle.multicall_target, bundle.multicall_data.clone())
                    .await?;

                info!(
                    "Paid transaction submitted via mixnet. TxHash: {:?}",
                    tx_hash
                );

                let block_num = self.wait_for_receipt_via_mixnet(client, tx_hash).await?;

                // Direct receipt fetch: verify success + capture logs (eth_getLogs unreliable on Anvil)
                let receipt = self
                    .timed_provider_call(
                        "paid TX get_transaction_receipt",
                        self.signer.get_transaction_receipt(tx_hash),
                    )
                    .await?
                    .ok_or_else(|| {
                        PrivacyClientError::TransactionFailed(
                            "Paid TX receipt not found via direct provider".to_string(),
                        )
                    })?;

                if receipt.status != Some(U64::from(1)) {
                    return Err(PrivacyClientError::TransactionFailed(format!(
                        "Paid TX reverted on-chain (status={:?}, tx={:?})",
                        receipt.status, tx_hash
                    )));
                }

                info!(
                    "Paid TX confirmed: block={}, logs={}, gas_used={:?}",
                    block_num,
                    receipt.logs.len(),
                    receipt.gas_used
                );

                // Events may be at a different block than what the mixnet receipt reported
                let final_logs = if receipt.logs.is_empty() {
                    warn!(
                        "Receipt has 0 logs despite status=1 and gas_used={:?}. \
                         Direct receipt block={:?}. Checking surrounding blocks...",
                        receipt.gas_used, receipt.block_number
                    );

                    let search_from = block_num.saturating_sub(5);
                    let current = self
                        .timed_provider_call(
                            "paid TX fallback get_block_number",
                            self.signer.get_block_number(),
                        )
                        .await
                        .map(|b| b.as_u64())
                        .unwrap_or(block_num + 5);
                    let search_to = current.max(block_num + 5);

                    let wide_filter = Filter::new()
                        .address(self.config.darkpool_address)
                        .from_block(search_from)
                        .to_block(search_to);
                    match self
                        .timed_provider_call(
                            "paid TX fallback get_logs",
                            self.signer.get_logs(&wide_filter),
                        )
                        .await
                    {
                        Ok(all_logs) => {
                            info!(
                                "Blocks {}-{} have {} DarkPool logs",
                                search_from,
                                search_to,
                                all_logs.len()
                            );
                            for (i, log) in all_logs.iter().take(10).enumerate() {
                                info!(
                                    "  Log[{}]: block={:?}, addr={:?}, topics={}, tx={:?}",
                                    i,
                                    log.block_number,
                                    log.address,
                                    log.topics.len(),
                                    log.transaction_hash
                                );
                            }

                            let tx_logs: Vec<_> = all_logs
                                .into_iter()
                                .filter(|l| l.transaction_hash == Some(tx_hash))
                                .collect();

                            if tx_logs.is_empty() {
                                warn!(
                                    "No logs found for TX {:?} in blocks {}-{}",
                                    tx_hash, search_from, search_to
                                );
                                vec![]
                            } else {
                                info!(
                                    "Found {} logs for TX {:?} in wider search",
                                    tx_logs.len(),
                                    tx_hash
                                );
                                tx_logs
                            }
                        }
                        Err(e) => {
                            warn!("Failed to query wide log range: {}", e);
                            vec![]
                        }
                    }
                } else {
                    receipt.logs
                };

                Ok(SubmitResult {
                    tx_hash,
                    block_num,
                    gas_used: receipt.gas_used.unwrap_or_default(),
                    payment_nullifier: Some(payment_note.nullifier),
                    receipt_logs: final_logs,
                })
            }
            #[cfg(feature = "mixnet")]
            Transport::SignedBroadcast { client } => {
                let tx = TransactionRequest::new()
                    .to(self.config.darkpool_address)
                    .data(calldata);

                let mut typed_tx = TypedTransaction::Legacy(tx);
                self.signer
                    .fill_transaction(&mut typed_tx, None)
                    .await
                    .map_err(|e| {
                        PrivacyClientError::TransactionFailed(format!(
                            "fill_transaction for signed broadcast: {e}"
                        ))
                    })?;

                let signature = self
                    .signer
                    .signer()
                    .sign_transaction(&typed_tx)
                    .await
                    .map_err(|e| {
                        PrivacyClientError::TransactionFailed(format!(
                            "sign_transaction for signed broadcast: {e}"
                        ))
                    })?;

                let raw_tx = typed_tx.rlp_signed(&signature);
                let tx_hash = client.broadcast_signed_transaction(raw_tx).await?;

                info!(
                    "Signed broadcast submitted via mixnet. TxHash: {:?}",
                    tx_hash
                );

                let block_num = self.wait_for_receipt_via_mixnet(client, tx_hash).await?;

                let receipt = self
                    .timed_provider_call(
                        "signed_broadcast get_transaction_receipt",
                        self.signer.get_transaction_receipt(tx_hash),
                    )
                    .await?
                    .ok_or_else(|| {
                        PrivacyClientError::TransactionFailed(
                            "Signed broadcast receipt not found".into(),
                        )
                    })?;

                if receipt.status != Some(U64::from(1)) {
                    return Err(PrivacyClientError::TransactionFailed(format!(
                        "Signed broadcast TX reverted (status={:?}, tx={:?})",
                        receipt.status, tx_hash
                    )));
                }

                let block_num = receipt.block_number.map_or(block_num, |b| b.as_u64());
                let gas_used = receipt.gas_used.unwrap_or_default();

                Ok(SubmitResult {
                    tx_hash,
                    block_num,
                    gas_used,
                    payment_nullifier: None,
                    receipt_logs: vec![],
                })
            }
            #[cfg(not(feature = "mixnet"))]
            Transport::_Phantom(_) => unreachable!(),
        }
    }

    fn create_spending_inputs(
        &self,
        note: &OwnedNote,
    ) -> Result<SpendingInputs, PrivacyClientError> {
        let merkle_path = self.tree.get_path(note.leaf_index);
        Ok(SpendingInputs::from_owned_note(note, merkle_path))
    }

    #[cfg(feature = "mixnet")]
    async fn wait_for_receipt_via_mixnet(
        &self,
        mixnet: &MixnetClient,
        tx_hash: H256,
    ) -> Result<u64, PrivacyClientError> {
        let max_attempts = 30;
        let poll_interval = std::time::Duration::from_secs(2);

        for attempt in 0..max_attempts {
            match mixnet.get_transaction_receipt(tx_hash).await {
                Ok(Some(receipt)) => {
                    if let Some(block_num) = receipt.get("blockNumber") {
                        if let Some(hex_str) = block_num.as_str() {
                            match u64::from_str_radix(hex_str.trim_start_matches("0x"), 16) {
                                Ok(num) => return Ok(num),
                                Err(e) => {
                                    warn!(
                                        "Malformed blockNumber '{}' in receipt: {}. Falling back to current block.",
                                        hex_str, e
                                    );
                                }
                            }
                        }
                    }
                    return Ok(mixnet.block_number().await?);
                }
                Ok(None) => {
                    debug!(
                        "Waiting for receipt via mixnet (attempt {}/{})",
                        attempt + 1,
                        max_attempts
                    );
                    tokio::time::sleep(poll_interval).await;
                }
                Err(e) => {
                    warn!("Error fetching receipt via mixnet: {}", e);
                    tokio::time::sleep(poll_interval).await;
                }
            }
        }

        Err(PrivacyClientError::TransactionFailed(
            "Timed out waiting for receipt".to_string(),
        ))
    }

    /// Excludes `exclude` commitments to prevent double-spend when asset == `payment_asset`.
    #[cfg(feature = "mixnet")]
    fn select_payment_note_excluding(
        &self,
        payment_asset: Address,
        prices: &PriceData,
        exclude: &HashSet<U256>,
        gas_limit: U256,
    ) -> Result<WalletNote, PrivacyClientError> {
        use crate::economics::FeeManager;

        let fee_manager = FeeManager::default();
        let estimate = fee_manager.calculate_fee(gas_limit, prices);

        let payment_notes: Vec<_> = self
            .utxos
            .get_unspent_excluding(exclude)
            .into_iter()
            .filter(|n| {
                n.plaintext.asset_id == crate::crypto_helpers::address_to_field(payment_asset)
                    && n.plaintext.value >= estimate.fee_amount
            })
            .cloned()
            .collect();

        let selected = payment_notes
            .first()
            .ok_or(PrivacyClientError::NoteSelectionFailed(format!(
                "No note for gas payment (need {}, excluding {} notes). User may need to deposit more tokens or use a different payment asset.",
                estimate.fee_amount, exclude.len()
            )))?;

        Ok(self.owned_note_to_wallet_note(selected))
    }

    /// Derives nullifier using the correct path (A or B) based on note origin.
    #[cfg(feature = "mixnet")]
    fn owned_note_to_wallet_note(&self, owned: &OwnedNote) -> WalletNote {
        let nullifier = Self::derive_nullifier_hash(owned);

        WalletNote {
            note: owned.plaintext.clone(),
            commitment: owned.commitment,
            leaf_index: owned.leaf_index,
            nullifier,
            spending_secret: owned.spending_secret,
            is_transfer: owned.is_transfer,
            derivation_index: 0,
            spent: false,
        }
    }

    /// Post-sync sanity check: compares local root against `getCurrentRoot()` on-chain.
    pub async fn verify_root_matches_chain(&self) -> Result<(), PrivacyClientError> {
        let onchain_root = self.fetch_current_root().await?;
        let local_root = self.tree.root();

        if local_root != onchain_root {
            return Err(PrivacyClientError::TreeMismatch {
                local: local_root,
                onchain: onchain_root,
            });
        }

        debug!(root = ?local_root, "Local Merkle root matches on-chain root");
        Ok(())
    }

    /// Pre-proof check: verifies local root is in the contract's root history ring buffer.
    pub async fn verify_root_is_known(&self) -> Result<(), PrivacyClientError> {
        let local_root = self.tree.root();
        let is_known = self.fetch_is_known_root(local_root).await?;

        if !is_known {
            // Fetch the current root to provide a useful error message
            let onchain_root = self.fetch_current_root().await.unwrap_or(U256::zero());
            return Err(PrivacyClientError::TreeMismatch {
                local: local_root,
                onchain: onchain_root,
            });
        }

        debug!(root = ?local_root, "Local Merkle root is recognized on-chain");
        Ok(())
    }

    /// Selector `0x8270482d` = `getCurrentRoot()`, returns big-endian U256.
    async fn fetch_current_root(&self) -> Result<U256, PrivacyClientError> {
        let selector: [u8; 4] = [0x82, 0x70, 0x48, 0x2d]; // getCurrentRoot()

        let tx = TransactionRequest::new()
            .to(self.config.darkpool_address)
            .data(selector.to_vec());

        let result = self
            .timed_provider_call("getCurrentRoot", self.signer.call(&tx.into(), None))
            .await?;

        if result.len() < 32 {
            return Err(PrivacyClientError::ProviderError(format!(
                "getCurrentRoot returned {} bytes, expected 32",
                result.len()
            )));
        }

        Ok(U256::from_big_endian(&result[..32]))
    }

    /// Selector `0x6d9833e3` = `isKnownRoot(bytes32)`, returns ABI-encoded bool.
    async fn fetch_is_known_root(&self, root: U256) -> Result<bool, PrivacyClientError> {
        let selector: [u8; 4] = [0x6d, 0x98, 0x33, 0xe3]; // isKnownRoot(bytes32)

        let mut calldata = Vec::with_capacity(36);
        calldata.extend_from_slice(&selector);
        let mut root_bytes = [0u8; 32];
        root.to_big_endian(&mut root_bytes);
        calldata.extend_from_slice(&root_bytes);

        let tx = TransactionRequest::new()
            .to(self.config.darkpool_address)
            .data(calldata);

        let result = self
            .timed_provider_call("isKnownRoot", self.signer.call(&tx.into(), None))
            .await?;

        if result.len() < 32 {
            return Err(PrivacyClientError::ProviderError(format!(
                "isKnownRoot returned {} bytes, expected 32",
                result.len()
            )));
        }

        Ok(result[31] != 0)
    }

    #[must_use]
    pub fn utxos(&self) -> &UtxoStore {
        &self.utxos
    }

    #[must_use]
    pub fn tree(&self) -> &LocalMerkleTree {
        &self.tree
    }

    #[must_use]
    pub fn keys(&self) -> &KeyRepository {
        &self.keys
    }

    #[must_use]
    pub fn darkpool_address(&self) -> Address {
        self.config.darkpool_address
    }

    #[must_use]
    pub fn builder(&self) -> &TransactionBuilder {
        &self.builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privacy_client_config_default() {
        let config = PrivacyClientConfig::default();
        assert_eq!(config.darkpool_address, Address::zero());
        assert_eq!(config.start_block, 0);
    }

    #[test]
    fn test_privacy_tx_result() {
        let result = PrivacyTxResult {
            tx_hash: H256::zero(),
            new_commitments: vec![U256::from(1), U256::from(2)],
            spent_nullifiers: vec![U256::from(3)],
            gas_used: U256::from(21000),
        };

        assert_eq!(result.new_commitments.len(), 2);
        assert_eq!(result.spent_nullifiers.len(), 1);
    }
}
