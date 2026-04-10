//! Watches `DarkPool` events (`NewNote`, `NewPrivateMemo`, `NewPublicMemo`, `NullifierSpent`)
//! and syncs local note state via decryption and Merkle tree updates.

use ethers::prelude::*;
use ethers::types::{Address, Filter, Log, H256, U256};
use std::sync::{Arc, LazyLock};
use thiserror::Error;
use tiny_keccak::{Hasher, Keccak};
use tracing::{debug, info, warn};

use crate::crypto_helpers::{
    aes128_decrypt, bjj_scalar_mul, derive_nullifier_path_a, derive_nullifier_path_b,
    kdf_to_aes_key_iv, recipient_decrypt_3party, unpack_ciphertext_from_fields,
    unpack_note_plaintext,
};
use crate::key_repository::KeyRepository;
use crate::merkle_tree::LocalMerkleTree;
use crate::utxo_store::{OwnedNote, UtxoStore};

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("Provider error: {0}")]
    Provider(String),
    #[error("Decryption failed: {0}")]
    Decryption(String),
    #[error("Invalid event data: {0}")]
    InvalidEvent(String),
}

/// Discovered public memo, claimable via `public_claim()`
#[derive(Debug, Clone)]
pub struct PublicMemoInfo {
    pub memo_id: U256,
    pub owner_pk: (U256, U256),
    pub asset: Address,
    pub value: U256,
    pub timelock: U256,
    pub salt: U256,
}

#[derive(Debug, Default)]
pub struct ScanResult {
    pub new_notes: Vec<U256>,
    pub spent_nullifiers: Vec<U256>,
    pub blocks_processed: u64,
    pub new_commitments: Vec<U256>,
    pub new_public_memos: Vec<PublicMemoInfo>,
}

#[derive(Debug, Clone)]
pub enum DarkPoolEvent {
    NewNote {
        commitment: U256,
        ephemeral_pk: (U256, U256),
        packed_ciphertext: [U256; 7],
    },
    NewPrivateMemo {
        commitment: U256,
        transfer_tag: U256,
        ephemeral_pk: (U256, U256),
        packed_ciphertext: [U256; 7],
        /// `a * compliance_pk` -- Bob uses this with ivk for 3-party ECDH decryption
        int_bob: (U256, U256),
        /// `a * recipient_b` -- Carol uses this for compliance decryption
        int_carol: (U256, U256),
    },
    NewPublicMemo {
        memo_id: U256,
        owner_x: U256,
        owner_y: U256,
        asset: Address,
        value: U256,
        timelock: U256,
        salt: U256,
    },
    NullifierSpent {
        nullifier_hash: U256,
    },
}

pub struct ScanEngine<M: Middleware> {
    provider: Arc<M>,
    darkpool_address: Address,
    keys: KeyRepository,
    utxos: UtxoStore,
    tree: LocalMerkleTree,
    compliance_pk: (U256, U256),
    last_scanned_block: u64,
}

/// Compute keccak256 of a Solidity event signature string
fn keccak256_event_sig(sig: &str) -> H256 {
    let mut hasher = Keccak::v256();
    hasher.update(sig.as_bytes());
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    H256::from(output)
}

// Precomputed event signature hashes (see DarkPool.sol)
static SIG_NEW_NOTE: LazyLock<H256> =
    LazyLock::new(|| keccak256_event_sig("NewNote(uint256,bytes32,uint256,uint256,bytes32[7])"));
static SIG_NULLIFIER_SPENT: LazyLock<H256> =
    LazyLock::new(|| keccak256_event_sig("NullifierSpent(bytes32)"));
static SIG_NEW_PRIVATE_MEMO: LazyLock<H256> = LazyLock::new(|| {
    keccak256_event_sig("NewPrivateMemo(uint256,bytes32,uint256,uint256,uint256,bytes32[7],uint256,uint256,uint256,uint256)")
});
static SIG_NEW_PUBLIC_MEMO: LazyLock<H256> = LazyLock::new(|| {
    keccak256_event_sig("NewPublicMemo(bytes32,uint256,uint256,address,uint256,uint256,uint256)")
});

impl<M: Middleware + 'static> ScanEngine<M> {
    pub fn new(
        provider: Arc<M>,
        darkpool_address: Address,
        keys: KeyRepository,
        compliance_pk: (U256, U256),
    ) -> Self {
        Self {
            provider,
            darkpool_address,
            keys,
            utxos: UtxoStore::new(),
            tree: LocalMerkleTree::new(),
            compliance_pk,
            last_scanned_block: 0,
        }
    }

    pub fn with_state(
        provider: Arc<M>,
        darkpool_address: Address,
        keys: KeyRepository,
        utxos: UtxoStore,
        tree: LocalMerkleTree,
        compliance_pk: (U256, U256),
        last_block: u64,
    ) -> Self {
        Self {
            provider,
            darkpool_address,
            keys,
            utxos,
            tree,
            compliance_pk,
            last_scanned_block: last_block,
        }
    }

    pub async fn scan_blocks(
        &mut self,
        from_block: u64,
        to_block: u64,
    ) -> Result<ScanResult, ScanError> {
        let mut result = ScanResult::default();

        info!(
            "Scanning blocks {} to {} for DarkPool events at {:?}",
            from_block, to_block, self.darkpool_address
        );

        let filter = Filter::new()
            .address(self.darkpool_address)
            .from_block(from_block)
            .to_block(to_block);

        let logs = self
            .provider
            .get_logs(&filter)
            .await
            .map_err(|e| ScanError::Provider(e.to_string()))?;

        info!("Found {} logs from DarkPool", logs.len());

        for log in logs {
            let block_number = log.block_number.map_or(from_block, |b| b.as_u64());
            self.process_log(&log, block_number, &mut result)?;
        }

        result.blocks_processed = to_block.saturating_sub(from_block) + 1;
        self.last_scanned_block = to_block;

        info!(
            "Scan complete: {} new notes, {} nullifiers spent",
            result.new_notes.len(),
            result.spent_nullifiers.len()
        );

        Ok(result)
    }

    /// Discriminate a log by topic[0] signature hash and dispatch to the appropriate handler
    fn process_log(
        &mut self,
        log: &Log,
        block_number: u64,
        result: &mut ScanResult,
    ) -> Result<(), ScanError> {
        if log.topics.is_empty() {
            return Ok(());
        }

        let event_sig = log.topics[0];

        debug!(
            "Processing log: sig={:?}, topics={}, data_len={}",
            event_sig,
            log.topics.len(),
            log.data.len()
        );

        if event_sig == *SIG_NULLIFIER_SPENT {
            if log.topics.len() >= 2 {
                let nullifier_hash = U256::from_big_endian(log.topics[1].as_bytes());
                self.handle_nullifier_spent(nullifier_hash, result);
            }
        } else if event_sig == *SIG_NEW_PUBLIC_MEMO {
            if log.topics.len() >= 3 && log.data.len() >= 5 * 32 {
                let memo_id = U256::from_big_endian(log.topics[1].as_bytes());
                let owner_x = U256::from_big_endian(log.topics[2].as_bytes());
                info!(
                    "Processing NewPublicMemo: memo_id={:?}, owner_x={:?}",
                    memo_id, owner_x
                );

                if let Ok(event) = self.parse_new_public_memo_event(&log.data, memo_id, owner_x) {
                    self.handle_new_public_memo(event, result);
                }
            }
        } else if event_sig == *SIG_NEW_NOTE {
            if log.topics.len() >= 3 && log.data.len() >= 9 * 32 {
                let commitment = U256::from_big_endian(log.topics[2].as_bytes());
                info!("Processing NewNote: commitment={:?}", commitment);

                if let Ok(event) = self.parse_new_note_event(&log.data, commitment) {
                    self.handle_new_note(event, block_number, result)?;
                }
            }
        } else if event_sig == *SIG_NEW_PRIVATE_MEMO {
            if log.topics.len() >= 4 && log.data.len() >= 13 * 32 {
                let commitment = U256::from_big_endian(log.topics[2].as_bytes());
                let transfer_tag = U256::from_big_endian(log.topics[3].as_bytes());
                info!(
                    "Processing NewPrivateMemo: commitment={:?}, tag={:?}",
                    commitment, transfer_tag
                );

                if let Ok(event) =
                    self.parse_new_private_memo_event(&log.data, commitment, transfer_tag)
                {
                    self.handle_new_private_memo(event, block_number, result)?;
                }
            }
        } else {
            debug!(
                "Skipping unknown event: sig={:?}, topics={}, data_len={}",
                event_sig,
                log.topics.len(),
                log.data.len()
            );
        }

        Ok(())
    }

    /// Parse `NewNote` event from ABI-encoded log data
    fn parse_new_note_event(
        &self,
        data: &Bytes,
        commitment: U256,
    ) -> Result<DarkPoolEvent, ScanError> {
        if data.len() < 9 * 32 {
            return Err(ScanError::InvalidEvent("NewNote data too short".into()));
        }

        let bytes = data.as_ref();

        let epk_x = U256::from_big_endian(&bytes[0..32]);
        let epk_y = U256::from_big_endian(&bytes[32..64]);

        let mut packed_ciphertext = [U256::zero(); 7];
        for (i, item) in packed_ciphertext.iter_mut().enumerate() {
            let start = 64 + i * 32;
            *item = U256::from_big_endian(&bytes[start..start + 32]);
        }

        Ok(DarkPoolEvent::NewNote {
            commitment,
            ephemeral_pk: (epk_x, epk_y),
            packed_ciphertext,
        })
    }

    /// Parse `NewPrivateMemo` event from ABI-encoded log data
    fn parse_new_private_memo_event(
        &self,
        data: &Bytes,
        commitment: U256,
        transfer_tag: U256,
    ) -> Result<DarkPoolEvent, ScanError> {
        if data.len() < 13 * 32 {
            return Err(ScanError::InvalidEvent(
                "NewPrivateMemo data too short".into(),
            ));
        }

        let bytes = data.as_ref();

        let epk_x = U256::from_big_endian(&bytes[0..32]);
        let epk_y = U256::from_big_endian(&bytes[32..64]);

        let mut packed_ciphertext = [U256::zero(); 7];
        for (i, item) in packed_ciphertext.iter_mut().enumerate() {
            let start = 64 + i * 32;
            *item = U256::from_big_endian(&bytes[start..start + 32]);
        }

        let int_bob_x = U256::from_big_endian(&bytes[288..320]);
        let int_bob_y = U256::from_big_endian(&bytes[320..352]);

        let int_carol_x = U256::from_big_endian(&bytes[352..384]);
        let int_carol_y = U256::from_big_endian(&bytes[384..416]);

        Ok(DarkPoolEvent::NewPrivateMemo {
            commitment,
            transfer_tag,
            ephemeral_pk: (epk_x, epk_y),
            packed_ciphertext,
            int_bob: (int_bob_x, int_bob_y),
            int_carol: (int_carol_x, int_carol_y),
        })
    }

    /// Parse `NewPublicMemo` event from ABI-encoded log data
    fn parse_new_public_memo_event(
        &self,
        data: &Bytes,
        memo_id: U256,
        owner_x: U256,
    ) -> Result<DarkPoolEvent, ScanError> {
        if data.len() < 5 * 32 {
            return Err(ScanError::InvalidEvent(
                "NewPublicMemo data too short".into(),
            ));
        }

        let bytes = data.as_ref();

        let owner_y = U256::from_big_endian(&bytes[0..32]);
        // Address occupies the last 20 bytes of the 32-byte ABI word
        let asset = Address::from_slice(&bytes[44..64]);
        let value = U256::from_big_endian(&bytes[64..96]);
        let timelock = U256::from_big_endian(&bytes[96..128]);
        let salt = U256::from_big_endian(&bytes[128..160]);

        Ok(DarkPoolEvent::NewPublicMemo {
            memo_id,
            owner_x,
            owner_y,
            asset,
            value,
            timelock,
            salt,
        })
    }

    /// Public memos are not Merkle commitments; tracked for `public_claim()` discovery.
    fn handle_new_public_memo(&self, event: DarkPoolEvent, result: &mut ScanResult) {
        if let DarkPoolEvent::NewPublicMemo {
            memo_id,
            owner_x,
            owner_y,
            asset,
            value,
            timelock,
            salt,
        } = event
        {
            info!(
                "Discovered NewPublicMemo: memo_id={:?}, value={}, asset={:?}",
                memo_id, value, asset
            );
            result.new_public_memos.push(PublicMemoInfo {
                memo_id,
                owner_pk: (owner_x, owner_y),
                asset,
                value,
                timelock,
                salt,
            });
        }
    }

    fn handle_nullifier_spent(&mut self, nullifier_hash: U256, result: &mut ScanResult) {
        debug!("NullifierSpent: {:?}", nullifier_hash);

        if let Some(_spent_note) = self.utxos.mark_spent(nullifier_hash) {
            result.spent_nullifiers.push(nullifier_hash);
        }
    }

    fn handle_new_note(
        &mut self,
        event: DarkPoolEvent,
        block_number: u64,
        result: &mut ScanResult,
    ) -> Result<(), ScanError> {
        if let DarkPoolEvent::NewNote {
            commitment,
            ephemeral_pk,
            packed_ciphertext,
        } = event
        {
            let leaf_index = self.tree.insert(commitment);
            result.new_commitments.push(commitment);

            if let Some((ephemeral_sk, _key_index)) =
                self.keys.try_match_deposit(ephemeral_pk.0, ephemeral_pk.1)
            {
                match self.decrypt_deposit_note(
                    ephemeral_sk,
                    ephemeral_pk,
                    &packed_ciphertext,
                    commitment,
                    leaf_index,
                    block_number,
                ) {
                    Ok(note) => {
                        let nullifier_hash = derive_nullifier_path_a(note.plaintext.nullifier);
                        self.utxos.add_note(note, nullifier_hash);
                        result.new_notes.push(commitment);
                        info!("Received deposit note: commitment={:?}", commitment);
                    }
                    Err(e) => {
                        warn!("Failed to decrypt matched note: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    /// 3-party ECDH: `S = [ivk] * int_bob = a * b * c * G`
    fn handle_new_private_memo(
        &mut self,
        event: DarkPoolEvent,
        block_number: u64,
        result: &mut ScanResult,
    ) -> Result<(), ScanError> {
        if let DarkPoolEvent::NewPrivateMemo {
            commitment,
            transfer_tag,
            packed_ciphertext,
            int_bob,
            ..
        } = event
        {
            let leaf_index = self.tree.insert(commitment);
            result.new_commitments.push(commitment);

            if let Some((recipient_sk, derivation_index)) =
                self.keys.try_match_transfer(transfer_tag)
            {
                info!(
                    "Transfer tag matched! Attempting 3-party decryption for derivation_index={}",
                    derivation_index
                );

                match recipient_decrypt_3party(recipient_sk, int_bob, &packed_ciphertext) {
                    Ok((note, shared_secret)) => {
                        let nullifier_hash =
                            derive_nullifier_path_b(shared_secret, commitment, leaf_index);
                        let note_value = note.value;

                        let owned_note = OwnedNote {
                            plaintext: note,
                            commitment,
                            leaf_index,
                            spending_secret: shared_secret,
                            is_transfer: true,
                            received_block: block_number,
                        };

                        self.utxos.add_note(owned_note, nullifier_hash);
                        result.new_notes.push(commitment);
                        info!(
                            "Received transfer note: commitment={:?}, value={}",
                            commitment, note_value
                        );
                    }
                    Err(e) => {
                        warn!("Failed to decrypt transfer memo: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    fn decrypt_deposit_note(
        &self,
        ephemeral_sk: U256,
        _ephemeral_pk: (U256, U256),
        packed_ciphertext: &[U256; 7],
        commitment: U256,
        leaf_index: u64,
        block_number: u64,
    ) -> Result<OwnedNote, ScanError> {
        // ECDH: shared_secret = ([ephemeral_sk] * compliance_pk).x
        let shared_point = bjj_scalar_mul(ephemeral_sk, self.compliance_pk)
            .map_err(|e| ScanError::Decryption(e.to_string()))?;
        let shared_secret = shared_point.0;

        let (key, iv) = kdf_to_aes_key_iv(shared_secret);
        let ciphertext_bytes = unpack_ciphertext_from_fields(packed_ciphertext);
        let plaintext_bytes = aes128_decrypt(&ciphertext_bytes, &key, &iv)
            .map_err(|e| ScanError::Decryption(e.to_string()))?;
        let note = unpack_note_plaintext(&plaintext_bytes);

        Ok(OwnedNote {
            plaintext: note,
            commitment,
            leaf_index,
            spending_secret: shared_secret,
            is_transfer: false,
            received_block: block_number,
        })
    }

    #[must_use]
    pub fn utxos(&self) -> &UtxoStore {
        &self.utxos
    }

    pub fn utxos_mut(&mut self) -> &mut UtxoStore {
        &mut self.utxos
    }

    #[must_use]
    pub fn tree(&self) -> &LocalMerkleTree {
        &self.tree
    }

    pub fn tree_mut(&mut self) -> &mut LocalMerkleTree {
        &mut self.tree
    }

    #[must_use]
    pub fn keys(&self) -> &KeyRepository {
        &self.keys
    }

    pub fn keys_mut(&mut self) -> &mut KeyRepository {
        &mut self.keys
    }

    #[must_use]
    pub fn last_scanned_block(&self) -> u64 {
        self.last_scanned_block
    }

    #[must_use]
    pub fn root(&self) -> U256 {
        self.tree.root()
    }

    #[must_use]
    pub fn balance(&self, asset: Address) -> U256 {
        self.utxos.get_balance(asset)
    }

    pub fn advance_keys(&mut self, count: u64) {
        self.keys.advance_ephemeral_keys(count);
        self.keys.advance_incoming_keys(count);
    }

    /// Process pre-fetched logs (e.g. fetched via mixnet) without querying the provider.
    pub fn process_logs_directly(&mut self, logs: &[Log]) -> Result<ScanResult, ScanError> {
        let mut result = ScanResult::default();

        info!("Processing {} pre-fetched logs", logs.len());

        for log in logs {
            let block_number = log.block_number.map_or(0, |b| b.as_u64());
            self.process_log(log, block_number, &mut result)?;
        }

        info!(
            "Direct log processing complete: {} new notes, {} nullifiers spent, {} commitments",
            result.new_notes.len(),
            result.spent_nullifiers.len(),
            result.new_commitments.len()
        );

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_result_default() {
        let result = ScanResult::default();
        assert!(result.new_notes.is_empty());
        assert!(result.spent_nullifiers.is_empty());
        assert_eq!(result.blocks_processed, 0);
    }
}
