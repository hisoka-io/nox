//! In-memory UTXO management with nullifier tracking and note selection.

use ethers::types::{Address, U256};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use tracing::debug;

use crate::note_processor::WalletNote;
use crate::proof_inputs::NotePlaintext;

pub trait IUtxoRepository {
    type Error: std::error::Error;
    fn add_note(&self, note: WalletNote) -> Result<(), Self::Error>;
    fn get_unspent_notes(&self) -> Result<Vec<WalletNote>, Self::Error>;
    fn get_unspent_notes_by_asset(&self, asset_id: U256) -> Result<Vec<WalletNote>, Self::Error>;
    fn get_note_by_commitment(&self, commitment: U256) -> Result<Option<WalletNote>, Self::Error>;
    fn get_note_by_index(&self, leaf_index: u64) -> Result<Option<WalletNote>, Self::Error>;
    fn mark_spent_by_nullifier(&self, nullifier: U256) -> Result<bool, Self::Error>;
    fn get_balance(&self, asset_id: Option<U256>) -> Result<U256, Self::Error>;
    fn find_spendable_note(
        &self,
        amount: U256,
        asset_id: U256,
    ) -> Result<Option<WalletNote>, Self::Error>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnedNote {
    pub plaintext: NotePlaintext,
    pub commitment: U256,
    pub leaf_index: u64,
    pub spending_secret: U256,
    pub is_transfer: bool,
    pub received_block: u64,
}

impl OwnedNote {
    #[must_use]
    pub fn asset(&self) -> Address {
        let mut arr = [0u8; 32];
        self.plaintext.asset_id.to_big_endian(&mut arr);
        Address::from_slice(&arr[12..32])
    }

    #[must_use]
    pub fn value(&self) -> U256 {
        self.plaintext.value
    }
}

#[derive(Debug)]
pub struct UtxoStore {
    notes: HashMap<U256, OwnedNote>,
    spent_nullifiers: HashSet<U256>,
    nullifier_to_commitment: HashMap<U256, U256>,
    /// Prevents double-spend during concurrent proof generation.
    pending_spends: HashSet<U256>,
}

impl UtxoStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            notes: HashMap::new(),
            spent_nullifiers: HashSet::new(),
            nullifier_to_commitment: HashMap::new(),
            pending_spends: HashSet::new(),
        }
    }

    pub fn add_note(&mut self, note: OwnedNote, nullifier_hash: U256) {
        debug!(
            "Adding note: commitment={}, value={}, asset={:?}",
            note.commitment,
            note.value(),
            note.asset()
        );
        self.nullifier_to_commitment
            .insert(nullifier_hash, note.commitment);
        self.notes.insert(note.commitment, note);
    }

    pub fn mark_spent(&mut self, nullifier_hash: U256) -> Option<OwnedNote> {
        if self.spent_nullifiers.contains(&nullifier_hash) {
            return None;
        }

        self.spent_nullifiers.insert(nullifier_hash);

        if let Some(commitment) = self.nullifier_to_commitment.get(&nullifier_hash) {
            let note = self.notes.remove(commitment);
            if note.is_some() {
                debug!("Marked note spent: commitment={}", commitment);
            }
            note
        } else {
            None
        }
    }

    #[allow(clippy::must_use_candidate)]
    pub fn is_spent(&self, nullifier_hash: &U256) -> bool {
        self.spent_nullifiers.contains(nullifier_hash)
    }

    #[must_use]
    pub fn get_unspent(&self) -> Vec<&OwnedNote> {
        self.notes.values().collect()
    }

    #[must_use]
    pub fn get_unspent_by_asset(&self, asset: Address) -> Vec<&OwnedNote> {
        self.notes.values().filter(|n| n.asset() == asset).collect()
    }

    #[must_use]
    pub fn get_balance(&self, asset: Address) -> U256 {
        self.notes
            .values()
            .filter(|n| n.asset() == asset)
            .fold(U256::zero(), |acc, n| acc + n.value())
    }

    #[must_use]
    pub fn get_total_balance(&self) -> HashMap<Address, U256> {
        let mut balances = HashMap::new();
        for note in self.notes.values() {
            *balances.entry(note.asset()).or_insert(U256::zero()) += note.value();
        }
        balances
    }

    /// Largest-first selection. Excludes pending spends.
    #[must_use]
    pub fn select_notes(&self, asset: Address, amount: U256) -> Option<Vec<&OwnedNote>> {
        let mut available: Vec<&OwnedNote> = self
            .notes
            .values()
            .filter(|n| n.asset() == asset && !self.pending_spends.contains(&n.commitment))
            .collect();

        available.sort_by_key(|b| Reverse(b.value()));

        let mut selected = Vec::new();
        let mut total = U256::zero();

        for note in available {
            if total >= amount {
                break;
            }
            selected.push(note);
            total += note.value();
        }

        if total >= amount {
            Some(selected)
        } else {
            None
        }
    }

    /// Exact-value match (required for split circuits).
    #[must_use]
    pub fn select_note_exact(&self, asset: Address, value: U256) -> Option<&OwnedNote> {
        self.notes.values().find(|n| {
            n.asset() == asset && n.value() == value && !self.pending_spends.contains(&n.commitment)
        })
    }

    /// Largest-first, excluding specific commitments (prevents double-spend in paid ops).
    #[must_use]
    pub fn select_notes_excluding(
        &self,
        asset: Address,
        amount: U256,
        exclude: &HashSet<U256>,
    ) -> Option<Vec<&OwnedNote>> {
        let mut available: Vec<&OwnedNote> = self
            .notes
            .values()
            .filter(|n| {
                n.asset() == asset
                    && !exclude.contains(&n.commitment)
                    && !self.pending_spends.contains(&n.commitment)
            })
            .collect();

        available.sort_by_key(|b| Reverse(b.value()));

        let mut selected = Vec::new();
        let mut total = U256::zero();

        for note in available {
            if total >= amount {
                break;
            }
            selected.push(note);
            total += note.value();
        }

        if total >= amount {
            Some(selected)
        } else {
            None
        }
    }

    #[must_use]
    pub fn get_unspent_excluding(&self, exclude: &HashSet<U256>) -> Vec<&OwnedNote> {
        self.notes
            .values()
            .filter(|n| {
                !exclude.contains(&n.commitment) && !self.pending_spends.contains(&n.commitment)
            })
            .collect()
    }

    /// Smallest note >= amount.
    #[must_use]
    pub fn select_single_note(&self, asset: Address, amount: U256) -> Option<&OwnedNote> {
        self.notes
            .values()
            .filter(|n| {
                n.asset() == asset
                    && n.value() >= amount
                    && !self.pending_spends.contains(&n.commitment)
            })
            .min_by_key(|n| n.value())
    }

    #[must_use]
    pub fn get_by_commitment(&self, commitment: &U256) -> Option<&OwnedNote> {
        self.notes.get(commitment)
    }

    #[allow(clippy::must_use_candidate)]
    pub fn count(&self) -> usize {
        self.notes.len()
    }

    pub fn mark_pending_spend(&mut self, commitment: &U256) -> bool {
        self.pending_spends.insert(*commitment)
    }

    #[allow(clippy::must_use_candidate)]
    pub fn is_pending_spend(&self, commitment: &U256) -> bool {
        self.pending_spends.contains(commitment)
    }

    pub fn clear_pending_spend(&mut self, commitment: &U256) {
        self.pending_spends.remove(commitment);
    }

    pub fn clear_all_pending_spends(&mut self) {
        self.pending_spends.clear();
    }

    pub fn spent_nullifiers_iter(&self) -> impl Iterator<Item = &U256> {
        self.spent_nullifiers.iter()
    }

    pub fn nullifier_map_iter(&self) -> impl Iterator<Item = (&U256, &U256)> {
        self.nullifier_to_commitment.iter()
    }

    pub fn clear(&mut self) {
        self.notes.clear();
        self.spent_nullifiers.clear();
        self.nullifier_to_commitment.clear();
        self.pending_spends.clear();
    }
}

impl Default for UtxoStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_note(
        value: u64,
        asset: Address,
        commitment: U256,
        leaf_index: u64,
    ) -> OwnedNote {
        let mut asset_bytes = [0u8; 32];
        asset_bytes[12..32].copy_from_slice(asset.as_bytes());

        OwnedNote {
            plaintext: NotePlaintext {
                value: U256::from(value),
                asset_id: U256::from_big_endian(&asset_bytes),
                secret: U256::from(1),
                nullifier: U256::from(leaf_index + 1000),
                timelock: U256::zero(),
                hashlock: U256::zero(),
            },
            commitment,
            leaf_index,
            spending_secret: U256::from(leaf_index + 2000),
            is_transfer: false,
            received_block: 1,
        }
    }

    #[test]
    fn test_add_and_get_balance() {
        let mut store = UtxoStore::new();
        let asset = Address::random();

        let note1 = create_test_note(100, asset, U256::from(1), 0);
        let note2 = create_test_note(200, asset, U256::from(2), 1);

        store.add_note(note1, U256::from(1001));
        store.add_note(note2, U256::from(1002));

        assert_eq!(store.get_balance(asset), U256::from(300));
        assert_eq!(store.count(), 2);
    }

    #[test]
    fn test_mark_spent() {
        let mut store = UtxoStore::new();
        let asset = Address::random();

        let note = create_test_note(100, asset, U256::from(1), 0);
        let nullifier_hash = U256::from(1001);

        store.add_note(note, nullifier_hash);
        assert_eq!(store.get_balance(asset), U256::from(100));

        let spent = store.mark_spent(nullifier_hash);
        assert!(spent.is_some());
        assert_eq!(store.get_balance(asset), U256::from(0));
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_select_notes() {
        let mut store = UtxoStore::new();
        let asset = Address::random();

        store.add_note(
            create_test_note(50, asset, U256::from(1), 0),
            U256::from(1001),
        );
        store.add_note(
            create_test_note(30, asset, U256::from(2), 1),
            U256::from(1002),
        );
        store.add_note(
            create_test_note(100, asset, U256::from(3), 2),
            U256::from(1003),
        );

        let notes = store.select_notes(asset, U256::from(120)).unwrap();
        assert_eq!(notes.len(), 2);

        let selected = store.select_notes(asset, U256::from(200));
        assert!(selected.is_none());
    }

    #[test]
    fn test_select_single_note() {
        let mut store = UtxoStore::new();
        let asset = Address::random();

        store.add_note(
            create_test_note(50, asset, U256::from(1), 0),
            U256::from(1001),
        );
        store.add_note(
            create_test_note(100, asset, U256::from(2), 1),
            U256::from(1002),
        );
        store.add_note(
            create_test_note(200, asset, U256::from(3), 2),
            U256::from(1003),
        );

        let note = store.select_single_note(asset, U256::from(80)).unwrap();
        assert_eq!(note.value(), U256::from(100));

        let note = store.select_single_note(asset, U256::from(300));
        assert!(note.is_none());
    }

    #[test]
    fn test_multiple_assets() {
        let mut store = UtxoStore::new();
        let asset1 = Address::random();
        let asset2 = Address::random();

        store.add_note(
            create_test_note(100, asset1, U256::from(1), 0),
            U256::from(1001),
        );
        store.add_note(
            create_test_note(200, asset2, U256::from(2), 1),
            U256::from(1002),
        );

        assert_eq!(store.get_balance(asset1), U256::from(100));
        assert_eq!(store.get_balance(asset2), U256::from(200));

        let balances = store.get_total_balance();
        assert_eq!(balances.len(), 2);
    }

    #[test]
    fn test_nullifier_map_consistency() {
        let mut store = UtxoStore::new();
        let asset = Address::random();

        let note1 = create_test_note(100, asset, U256::from(10), 0);
        let note2 = create_test_note(200, asset, U256::from(20), 1);
        let null1 = U256::from(1001);
        let null2 = U256::from(1002);

        store.add_note(note1.clone(), null1);
        store.add_note(note2.clone(), null2);

        let map: Vec<_> = store.nullifier_map_iter().collect();
        assert_eq!(map.len(), 2);

        let commitments: Vec<_> = map.iter().map(|(_, &c)| c).collect();
        assert!(commitments.contains(&note1.commitment));
        assert!(commitments.contains(&note2.commitment));

        store.mark_spent(null1);
        assert_eq!(store.nullifier_map_iter().count(), 2);
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_select_notes_insufficient_balance_returns_none() {
        let mut store = UtxoStore::new();
        let asset = Address::random();

        store.add_note(
            create_test_note(50, asset, U256::from(1), 0),
            U256::from(1001),
        );
        store.add_note(
            create_test_note(30, asset, U256::from(2), 1),
            U256::from(1002),
        );

        assert!(store.select_notes(asset, U256::from(100)).is_none());
    }

    #[test]
    fn test_select_notes_exact_minimum() {
        let mut store = UtxoStore::new();
        let asset = Address::random();

        store.add_note(
            create_test_note(100, asset, U256::from(1), 0),
            U256::from(1001),
        );
        store.add_note(
            create_test_note(50, asset, U256::from(2), 1),
            U256::from(1002),
        );

        let notes = store.select_notes(asset, U256::from(100)).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].value(), U256::from(100));
    }
}
