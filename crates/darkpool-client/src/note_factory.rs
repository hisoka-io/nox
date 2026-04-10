//! Note creation with encryption, commitment computation, and nullifier derivation.

use ethers::types::{Address, U256};
use thiserror::Error;
use tracing::debug;

use crate::crypto_helpers::{
    derive_nullifier_path_a, derive_nullifier_path_b, encrypt_memo_note_3party,
    encrypt_note_for_deposit_aes, poseidon_hash, CryptoError,
};
use crate::key_repository::KeyRepository;
use crate::merkle_tree::MerklePath;
use crate::proof_inputs::NotePlaintext;
use crate::utxo_store::OwnedNote;

#[derive(Debug, Error)]
pub enum NoteFactoryError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Invalid parameters: {0}")]
    InvalidParams(String),
    #[error("Insufficient balance: need {need}, have {have}")]
    InsufficientBalance { need: U256, have: U256 },
}

#[derive(Debug, Clone)]
pub struct DepositNoteResult {
    pub note: NotePlaintext,
    pub ephemeral_sk: U256,
    pub ephemeral_pk: (U256, U256),
    pub packed_ciphertext: [U256; 7],
    pub commitment: U256,
}

#[derive(Debug, Clone)]
pub struct TransferNoteResult {
    pub memo_note: NotePlaintext,
    pub change_note: NotePlaintext,
    pub memo_ephemeral_sk: U256,
    pub memo_ephemeral_pk: (U256, U256),
    pub memo_packed_ciphertext: [U256; 7],
    pub memo_commitment: U256,
    pub int_bob: (U256, U256),
    pub int_carol: (U256, U256),
    pub change_ephemeral_sk: U256,
    pub change_ephemeral_pk: (U256, U256),
    pub change_packed_ciphertext: [U256; 7],
    pub change_commitment: U256,
    pub transfer_tag: U256,
}

#[derive(Debug, Clone)]
pub struct ChangeNoteResult {
    pub note: NotePlaintext,
    pub ephemeral_sk: U256,
    pub ephemeral_pk: (U256, U256),
    pub packed_ciphertext: [U256; 7],
    pub commitment: U256,
}

pub struct NoteFactory {
    compliance_pk: (U256, U256),
}

impl NoteFactory {
    #[must_use]
    pub fn new(compliance_pk: (U256, U256)) -> Self {
        Self { compliance_pk }
    }

    pub fn create_deposit_note(
        &self,
        value: U256,
        asset: Address,
        keys: &mut KeyRepository,
    ) -> Result<DepositNoteResult, NoteFactoryError> {
        let note = NotePlaintext::random(value, asset);
        let (ephemeral_sk, _nonce) = keys.next_ephemeral_params();
        let (packed_ciphertext, ephemeral_pk) =
            encrypt_note_for_deposit_aes(ephemeral_sk, self.compliance_pk, &note)?;
        let commitment = poseidon_hash(&packed_ciphertext);

        debug!(
            "Created deposit note: value={}, commitment={:?}",
            value, commitment
        );

        Ok(DepositNoteResult {
            note,
            ephemeral_sk,
            ephemeral_pk,
            packed_ciphertext,
            commitment,
        })
    }

    /// Create memo (to recipient via 3-party ECDH) + change (to self) notes.
    pub fn create_transfer_notes(
        &self,
        memo_value: U256,
        change_value: U256,
        asset: Address,
        recipient_b: (U256, U256),
        recipient_p: (U256, U256),
        keys: &mut KeyRepository,
    ) -> Result<TransferNoteResult, NoteFactoryError> {
        let memo_note = NotePlaintext::random(memo_value, asset);
        let change_note = NotePlaintext::random(change_value, asset);
        let (memo_ephemeral_sk, _) = keys.next_ephemeral_params();
        let (change_ephemeral_sk, _) = keys.next_ephemeral_params();

        let memo_result = encrypt_memo_note_3party(
            memo_ephemeral_sk,
            recipient_p,
            recipient_b,
            self.compliance_pk,
            &memo_note,
        )?;

        let (change_packed_ciphertext, change_ephemeral_pk) =
            encrypt_note_for_deposit_aes(change_ephemeral_sk, self.compliance_pk, &change_note)?;

        let memo_commitment = poseidon_hash(&memo_result.packed_ciphertext);
        let change_commitment = poseidon_hash(&change_packed_ciphertext);
        let transfer_tag = recipient_p.0;

        debug!(
            "Created transfer notes: memo_value={}, change_value={}, tag={:?}",
            memo_value, change_value, transfer_tag
        );

        Ok(TransferNoteResult {
            memo_note,
            change_note,
            memo_ephemeral_sk,
            memo_ephemeral_pk: memo_result.ephemeral_pk,
            memo_packed_ciphertext: memo_result.packed_ciphertext,
            memo_commitment,
            int_bob: memo_result.int_bob,
            int_carol: memo_result.int_carol,
            change_ephemeral_sk,
            change_ephemeral_pk,
            change_packed_ciphertext,
            change_commitment,
            transfer_tag,
        })
    }

    pub fn create_change_note(
        &self,
        value: U256,
        asset: Address,
        keys: &mut KeyRepository,
    ) -> Result<ChangeNoteResult, NoteFactoryError> {
        let result = self.create_deposit_note(value, asset, keys)?;

        Ok(ChangeNoteResult {
            note: result.note,
            ephemeral_sk: result.ephemeral_sk,
            ephemeral_pk: result.ephemeral_pk,
            packed_ciphertext: result.packed_ciphertext,
            commitment: result.commitment,
        })
    }

    pub fn create_split_notes(
        &self,
        value_a: U256,
        value_b: U256,
        asset: Address,
        keys: &mut KeyRepository,
    ) -> Result<(ChangeNoteResult, ChangeNoteResult), NoteFactoryError> {
        let note_a = self.create_change_note(value_a, asset, keys)?;
        let note_b = self.create_change_note(value_b, asset, keys)?;
        Ok((note_a, note_b))
    }

    pub fn create_join_output_note(
        &self,
        total_value: U256,
        asset: Address,
        keys: &mut KeyRepository,
    ) -> Result<ChangeNoteResult, NoteFactoryError> {
        self.create_change_note(total_value, asset, keys)
    }

    #[must_use]
    pub fn derive_nullifier_deposit(&self, note: &NotePlaintext) -> U256 {
        derive_nullifier_path_a(note.nullifier)
    }

    #[must_use]
    pub fn derive_nullifier_transfer(
        &self,
        shared_secret: U256,
        commitment: U256,
        leaf_index: u64,
    ) -> U256 {
        derive_nullifier_path_b(shared_secret, commitment, leaf_index)
    }
}

#[derive(Debug, Clone)]
pub struct SpendingInputs {
    pub note: NotePlaintext,
    pub shared_secret: U256,
    pub leaf_index: u64,
    pub merkle_path: MerklePath,
    pub hashlock_preimage: U256,
    pub nullifier_hash: U256,
}

impl SpendingInputs {
    #[must_use]
    pub fn from_owned_note(note: &OwnedNote, merkle_path: MerklePath) -> Self {
        let nullifier_hash = if note.is_transfer {
            derive_nullifier_path_b(note.spending_secret, note.commitment, note.leaf_index)
        } else {
            derive_nullifier_path_a(note.plaintext.nullifier)
        };

        Self {
            note: note.plaintext.clone(),
            shared_secret: note.spending_secret,
            leaf_index: note.leaf_index,
            merkle_path,
            hashlock_preimage: U256::zero(),
            nullifier_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DarkAccount;
    use crate::key_repository::KeyRepository;

    fn setup_test_keys() -> KeyRepository {
        let account = DarkAccount::from_seed(b"test_seed_12345");
        let compliance_pk = (U256::from(1), U256::from(2));
        let mut keys = KeyRepository::new(account, compliance_pk);
        keys.advance_ephemeral_keys(10);
        keys
    }

    #[test]
    fn test_create_deposit_note() {
        let compliance_pk = (
            U256::from_dec_str(
                "5299619240641551281634865583518297030282874472190772894086521144482721001553",
            )
            .unwrap(),
            U256::from_dec_str(
                "16950150798460657717958625567821834550301663161624707787222815936182638968203",
            )
            .unwrap(),
        );
        let mut keys = setup_test_keys();
        let factory = NoteFactory::new(compliance_pk);

        let result = factory
            .create_deposit_note(U256::from(1000), Address::zero(), &mut keys)
            .unwrap();

        assert_eq!(result.note.value, U256::from(1000));
        assert!(!result.commitment.is_zero());
        assert!(!result.ephemeral_pk.0.is_zero());
    }

    #[test]
    fn test_nullifier_derivation() {
        let compliance_pk = (U256::from(1), U256::from(2));
        let factory = NoteFactory::new(compliance_pk);

        let note = NotePlaintext {
            value: U256::from(100),
            asset_id: U256::from(1),
            secret: U256::from(12345),
            nullifier: U256::from(67890),
            timelock: U256::zero(),
            hashlock: U256::zero(),
        };

        let null_a = factory.derive_nullifier_deposit(&note);
        assert!(!null_a.is_zero());

        let null_b = factory.derive_nullifier_transfer(U256::from(111), U256::from(222), 5);
        assert!(!null_b.is_zero());
        assert_ne!(null_a, null_b);
    }

    #[test]
    fn test_create_change_note() {
        let compliance_pk = (
            U256::from_dec_str(
                "5299619240641551281634865583518297030282874472190772894086521144482721001553",
            )
            .unwrap(),
            U256::from_dec_str(
                "16950150798460657717958625567821834550301663161624707787222815936182638968203",
            )
            .unwrap(),
        );
        let mut keys = setup_test_keys();
        let factory = NoteFactory::new(compliance_pk);

        let result = factory
            .create_change_note(U256::from(500), Address::zero(), &mut keys)
            .unwrap();

        assert_eq!(result.note.value, U256::from(500));
        assert!(!result.commitment.is_zero());
    }

    #[test]
    fn test_create_split_notes() {
        let compliance_pk = (
            U256::from_dec_str(
                "5299619240641551281634865583518297030282874472190772894086521144482721001553",
            )
            .unwrap(),
            U256::from_dec_str(
                "16950150798460657717958625567821834550301663161624707787222815936182638968203",
            )
            .unwrap(),
        );
        let mut keys = setup_test_keys();
        let factory = NoteFactory::new(compliance_pk);

        let (note_a, note_b) = factory
            .create_split_notes(U256::from(300), U256::from(200), Address::zero(), &mut keys)
            .unwrap();

        assert_eq!(note_a.note.value, U256::from(300));
        assert_eq!(note_b.note.value, U256::from(200));
        assert_ne!(note_a.commitment, note_b.commitment);
    }

    #[test]
    fn test_note_factory_zero_value() {
        let compliance_pk = (
            U256::from_dec_str(
                "5299619240641551281634865583518297030282874472190772894086521144482721001553",
            )
            .unwrap(),
            U256::from_dec_str(
                "16950150798460657717958625567821834550301663161624707787222815936182638968203",
            )
            .unwrap(),
        );
        let mut keys = setup_test_keys();
        let factory = NoteFactory::new(compliance_pk);

        let result = factory
            .create_deposit_note(U256::zero(), Address::zero(), &mut keys)
            .unwrap();

        assert_eq!(result.note.value, U256::zero());
        assert!(!result.commitment.is_zero());
    }

    #[test]
    fn test_note_factory_same_input_different_epk() {
        let compliance_pk = (
            U256::from_dec_str(
                "5299619240641551281634865583518297030282874472190772894086521144482721001553",
            )
            .unwrap(),
            U256::from_dec_str(
                "16950150798460657717958625567821834550301663161624707787222815936182638968203",
            )
            .unwrap(),
        );
        let mut keys = setup_test_keys();
        let factory = NoteFactory::new(compliance_pk);

        let r1 = factory
            .create_deposit_note(U256::from(500), Address::zero(), &mut keys)
            .unwrap();
        let r2 = factory
            .create_deposit_note(U256::from(500), Address::zero(), &mut keys)
            .unwrap();

        assert_ne!(r1.ephemeral_pk, r2.ephemeral_pk);
        assert_ne!(r1.commitment, r2.commitment);
    }
}
