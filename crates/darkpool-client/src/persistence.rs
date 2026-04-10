//! Save/load wallet state (UTXOs, Merkle leaves, sync checkpoint) to JSON.

use ethers::types::U256;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{debug, info};

use crate::merkle_tree::LocalMerkleTree;
use crate::utxo_store::{OwnedNote, UtxoStore};

#[derive(Debug, Serialize, Deserialize)]
struct UtxoSnapshot {
    notes: Vec<(String, OwnedNote)>,
    spent_nullifiers: Vec<String>,
    nullifier_to_commitment: Vec<(String, String)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WalletState {
    version: u32,
    pub last_synced_block: u64,
    utxo_snapshot: UtxoSnapshot,
    merkle_leaves: Vec<String>,
}

const CURRENT_VERSION: u32 = 1;

fn u256_to_hex(v: &U256) -> String {
    format!("{v:#066x}")
}

fn hex_to_u256(s: &str) -> Result<U256, PersistenceError> {
    U256::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16)
        .map_err(|e| PersistenceError::Deserialization(format!("invalid U256 hex '{s}': {e}")))
}

#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Serialization(String),
    #[error("JSON deserialization error: {0}")]
    Deserialization(String),
    #[error("Version mismatch: file version {file} > supported {supported}")]
    VersionMismatch { file: u32, supported: u32 },
}

impl WalletState {
    #[must_use]
    pub fn capture(utxos: &UtxoStore, tree: &LocalMerkleTree, last_synced_block: u64) -> Self {
        let notes: Vec<_> = utxos
            .get_unspent()
            .into_iter()
            .map(|n| (u256_to_hex(&n.commitment), n.clone()))
            .collect();

        let spent_nullifiers: Vec<_> = utxos.spent_nullifiers_iter().map(u256_to_hex).collect();

        let nullifier_to_commitment: Vec<_> = utxos
            .nullifier_map_iter()
            .map(|(k, v)| (u256_to_hex(k), u256_to_hex(v)))
            .collect();

        let merkle_leaves: Vec<_> = tree.leaves().iter().map(u256_to_hex).collect();

        Self {
            version: CURRENT_VERSION,
            last_synced_block,
            utxo_snapshot: UtxoSnapshot {
                notes,
                spent_nullifiers,
                nullifier_to_commitment,
            },
            merkle_leaves,
        }
    }

    pub fn restore(self) -> Result<(UtxoStore, LocalMerkleTree, u64), PersistenceError> {
        if self.version > CURRENT_VERSION {
            return Err(PersistenceError::VersionMismatch {
                file: self.version,
                supported: CURRENT_VERSION,
            });
        }

        let mut utxos = UtxoStore::new();
        for (commitment_hex, note) in &self.utxo_snapshot.notes {
            let _commitment = hex_to_u256(commitment_hex)?;
            // Find the nullifier_hash for this commitment from the mapping
            let nullifier_hash = self
                .utxo_snapshot
                .nullifier_to_commitment
                .iter()
                .find(|(_, c)| c == commitment_hex)
                .map(|(n, _)| hex_to_u256(n))
                .transpose()?
                .unwrap_or(U256::zero());
            utxos.add_note(note.clone(), nullifier_hash);
        }
        for nullifier_hex in &self.utxo_snapshot.spent_nullifiers {
            let nullifier_hash = hex_to_u256(nullifier_hex)?;
            utxos.mark_spent(nullifier_hash);
        }

        let mut tree = LocalMerkleTree::new();
        let leaves: Vec<U256> = self
            .merkle_leaves
            .iter()
            .map(|h| hex_to_u256(h))
            .collect::<Result<Vec<_>, _>>()?;
        tree.load_from_leaves(&leaves);

        info!(
            notes = utxos.count(),
            leaves = tree.size(),
            block = self.last_synced_block,
            "Wallet state restored from snapshot"
        );

        Ok((utxos, tree, self.last_synced_block))
    }

    pub fn save_to_file(&self, path: &Path) -> Result<(), PersistenceError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| PersistenceError::Serialization(e.to_string()))?;

        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, json)?;
        std::fs::rename(&tmp_path, path)?;

        debug!(
            path = %path.display(),
            notes = self.utxo_snapshot.notes.len(),
            leaves = self.merkle_leaves.len(),
            block = self.last_synced_block,
            "Wallet state saved"
        );
        Ok(())
    }

    pub fn load_from_file(path: &Path) -> Result<Self, PersistenceError> {
        let json = std::fs::read_to_string(path)?;
        let state: Self = serde_json::from_str(&json)
            .map_err(|e| PersistenceError::Deserialization(e.to_string()))?;

        if state.version > CURRENT_VERSION {
            return Err(PersistenceError::VersionMismatch {
                file: state.version,
                supported: CURRENT_VERSION,
            });
        }

        info!(
            path = %path.display(),
            version = state.version,
            block = state.last_synced_block,
            "Wallet state loaded"
        );
        Ok(state)
    }
}

pub fn save_wallet_state(
    path: &Path,
    utxos: &UtxoStore,
    tree: &LocalMerkleTree,
    last_synced_block: u64,
) -> Result<(), PersistenceError> {
    let state = WalletState::capture(utxos, tree, last_synced_block);
    state.save_to_file(path)
}

/// Returns `None` if file doesn't exist.
pub fn load_wallet_state(
    path: &Path,
) -> Result<Option<(UtxoStore, LocalMerkleTree, u64)>, PersistenceError> {
    if !path.exists() {
        debug!(path = %path.display(), "No wallet state file found, starting fresh");
        return Ok(None);
    }

    let state = WalletState::load_from_file(path)?;
    let (utxos, tree, block) = state.restore()?;
    Ok(Some((utxos, tree, block)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_inputs::NotePlaintext;

    fn test_note(value: u64, commitment: U256, leaf_index: u64) -> OwnedNote {
        OwnedNote {
            plaintext: NotePlaintext {
                value: U256::from(value),
                asset_id: U256::from(1),
                secret: U256::from(42),
                nullifier: U256::from(leaf_index + 1000),
                timelock: U256::zero(),
                hashlock: U256::zero(),
            },
            commitment,
            leaf_index,
            spending_secret: U256::from(leaf_index + 2000),
            is_transfer: false,
            received_block: 100,
        }
    }

    #[test]
    fn test_roundtrip_empty_state() {
        let utxos = UtxoStore::new();
        let tree = LocalMerkleTree::new();

        let state = WalletState::capture(&utxos, &tree, 0);
        let (restored_utxos, restored_tree, block) = state.restore().unwrap();

        assert_eq!(restored_utxos.count(), 0);
        assert_eq!(restored_tree.size(), 0);
        assert_eq!(block, 0);
    }

    #[test]
    fn test_roundtrip_with_notes_and_leaves() {
        let mut utxos = UtxoStore::new();
        let mut tree = LocalMerkleTree::new();

        // Add some notes
        let note1 = test_note(100, U256::from(1), 0);
        let note2 = test_note(200, U256::from(2), 1);
        utxos.add_note(note1, U256::from(5001));
        utxos.add_note(note2, U256::from(5002));

        // Add some leaves
        tree.insert(U256::from(1));
        tree.insert(U256::from(2));
        tree.insert(U256::from(3));

        let original_root = tree.root();
        let original_balance = utxos.count();

        // Capture and restore
        let state = WalletState::capture(&utxos, &tree, 42);
        let (restored_utxos, restored_tree, block) = state.restore().unwrap();

        assert_eq!(restored_utxos.count(), original_balance);
        assert_eq!(restored_tree.root(), original_root);
        assert_eq!(restored_tree.size(), 3);
        assert_eq!(block, 42);
    }

    #[test]
    fn test_roundtrip_with_spent_nullifiers() {
        let mut utxos = UtxoStore::new();
        let tree = LocalMerkleTree::new();

        let note = test_note(500, U256::from(10), 0);
        let nullifier_hash = U256::from(9999);
        utxos.add_note(note, nullifier_hash);
        utxos.mark_spent(nullifier_hash);

        assert_eq!(utxos.count(), 0);
        assert!(utxos.is_spent(&nullifier_hash));

        let state = WalletState::capture(&utxos, &tree, 100);
        let (restored_utxos, _, _) = state.restore().unwrap();

        assert_eq!(restored_utxos.count(), 0);
        assert!(restored_utxos.is_spent(&nullifier_hash));
    }

    #[test]
    fn test_file_roundtrip() {
        let mut utxos = UtxoStore::new();
        let mut tree = LocalMerkleTree::new();

        utxos.add_note(test_note(100, U256::from(1), 0), U256::from(5001));
        tree.insert(U256::from(1));

        let dir = std::env::temp_dir().join("nox_test_persistence");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_state.json");

        // Save
        save_wallet_state(&path, &utxos, &tree, 50).unwrap();
        assert!(path.exists());

        // Load
        let loaded = load_wallet_state(&path).unwrap();
        assert!(loaded.is_some());
        let (r_utxos, r_tree, r_block) = loaded.unwrap();
        assert_eq!(r_utxos.count(), 1);
        assert_eq!(r_tree.root(), tree.root());
        assert_eq!(r_block, 50);

        // Cleanup
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_load_nonexistent_returns_none() {
        let path = Path::new("/tmp/nox_test_nonexistent_state.json");
        let result = load_wallet_state(path).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_version_mismatch() {
        let json = r#"{"version": 999, "last_synced_block": 0, "utxo_snapshot": {"notes": [], "spent_nullifiers": [], "nullifier_to_commitment": []}, "merkle_leaves": []}"#;
        let state: WalletState = serde_json::from_str(json).unwrap();
        let result = state.restore();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PersistenceError::VersionMismatch { .. }
        ));
    }

    #[test]
    fn test_pending_spends_not_persisted() {
        let mut utxos = UtxoStore::new();
        let tree = LocalMerkleTree::new();

        let note = test_note(100, U256::from(1), 0);
        utxos.add_note(note, U256::from(5001));
        utxos.mark_pending_spend(&U256::from(1));
        assert!(utxos.is_pending_spend(&U256::from(1)));

        let state = WalletState::capture(&utxos, &tree, 10);
        let (restored_utxos, _, _) = state.restore().unwrap();

        assert!(!restored_utxos.is_pending_spend(&U256::from(1)));
        assert_eq!(restored_utxos.count(), 1);
    }
}
