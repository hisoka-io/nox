//! Processes blockchain events to recover notes belonging to this wallet.
//! Path A (`NewNote`): deposits/change via ephemeral PK match.
//! Path B (`NewMemo`): transfers via tag match + 3-party ECDH.

use ethers::types::U256;
use tracing::trace;

use crate::crypto_helpers::{
    decrypt_note_from_fields, derive_nullifier_path_a, derive_nullifier_path_b,
    recipient_decrypt_3party,
};
use crate::key_repository::KeyRepository;
use crate::proof_inputs::NotePlaintext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    NewNote,
    NewMemo,
}

#[derive(Debug, Clone)]
pub struct UnprocessedEvent {
    pub event_type: EventType,
    pub block_number: u64,
    pub tx_hash: String,
    pub leaf_index: u64,
    pub commitment: U256,
    pub epk_x: U256,
    pub epk_y: U256,
    pub packed_ciphertext: [U256; 7],
    pub tag: Option<U256>,
    pub intermediate_bob_x: Option<U256>,
    pub intermediate_bob_y: Option<U256>,
}

#[derive(Debug, Clone)]
pub struct WalletNote {
    pub note: NotePlaintext,
    pub commitment: U256,
    pub leaf_index: u64,
    pub nullifier: U256,
    /// Path A: `ephemeral_sk`, Path B: `shared_secret`
    pub spending_secret: U256,
    pub is_transfer: bool,
    pub derivation_index: u64,
    pub spent: bool,
}

pub struct NoteProcessor<'a> {
    key_repo: &'a KeyRepository,
    compliance_pk: (U256, U256),
}

impl<'a> NoteProcessor<'a> {
    #[must_use]
    pub fn new(key_repo: &'a KeyRepository, compliance_pk: (U256, U256)) -> Self {
        Self {
            key_repo,
            compliance_pk,
        }
    }

    #[must_use]
    pub fn process(&self, event: &UnprocessedEvent) -> Option<WalletNote> {
        match event.event_type {
            EventType::NewNote => self.process_new_note(event),
            EventType::NewMemo => self.process_memo(event),
        }
    }

    fn process_new_note(&self, event: &UnprocessedEvent) -> Option<WalletNote> {
        let (ephemeral_sk, derivation_index) =
            self.key_repo.try_match_deposit(event.epk_x, event.epk_y)?;

        let note = match decrypt_note_from_fields(
            &event.packed_ciphertext,
            ephemeral_sk,
            self.compliance_pk,
        ) {
            Ok(n) => n,
            Err(e) => {
                trace!(
                    "NewNote decryption failed for leaf_index={}, block={}, tx={}: {:?}",
                    event.leaf_index,
                    event.block_number,
                    event.tx_hash,
                    e
                );
                return None;
            }
        };

        let nullifier = derive_nullifier_path_a(note.nullifier);

        Some(WalletNote {
            note,
            commitment: event.commitment,
            leaf_index: event.leaf_index,
            nullifier,
            spending_secret: ephemeral_sk,
            is_transfer: false,
            derivation_index,
            spent: false,
        })
    }

    fn process_memo(&self, event: &UnprocessedEvent) -> Option<WalletNote> {
        let tag = event.tag?;
        let int_bob_x = event.intermediate_bob_x?;
        let int_bob_y = event.intermediate_bob_y?;

        let (recipient_sk_mod, derivation_index) = self.key_repo.try_match_transfer(tag)?;
        let intermediate_point = (int_bob_x, int_bob_y);
        let (note, shared_secret) = match recipient_decrypt_3party(
            recipient_sk_mod,
            intermediate_point,
            &event.packed_ciphertext,
        ) {
            Ok((n, ss)) => (n, ss),
            Err(e) => {
                trace!(
                    "NewMemo decryption failed for leaf_index={}, block={}, tx={}: {:?}",
                    event.leaf_index,
                    event.block_number,
                    event.tx_hash,
                    e
                );
                return None;
            }
        };

        let nullifier = derive_nullifier_path_b(shared_secret, event.commitment, event.leaf_index);

        Some(WalletNote {
            note,
            commitment: event.commitment,
            leaf_index: event.leaf_index,
            nullifier,
            spending_secret: shared_secret,
            is_transfer: true,
            derivation_index,
            spent: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_helpers::{
        aes128_encrypt, encrypt_note_for_deposit_aes, fr_to_u256, kdf_to_aes_key_iv,
        pack_ciphertext_to_fields, pack_note_plaintext, random_field,
    };
    use crate::identity::DarkAccount;
    use darkpool_crypto::BASE8;

    fn create_compliance_keypair() -> (U256, (U256, U256)) {
        let compliance_sk_bytes = [0x42u8; 32];
        let compliance_pk_point = BASE8
            .mul_scalar(&compliance_sk_bytes)
            .expect("valid test key");
        let compliance_pk = (
            fr_to_u256(compliance_pk_point.x()),
            fr_to_u256(compliance_pk_point.y()),
        );
        (U256::from_big_endian(&compliance_sk_bytes), compliance_pk)
    }

    fn create_test_note() -> NotePlaintext {
        NotePlaintext {
            asset_id: U256::from(1),
            value: U256::from(1_000_000_000_000_000_000u64), // 1 ETH
            secret: random_field(),
            nullifier: random_field(),
            timelock: U256::zero(),
            hashlock: U256::zero(),
        }
    }

    #[test]
    fn test_path_a_deposit_decryption() {
        let account = DarkAccount::from_seed(b"test_path_a_seed");
        let (_, compliance_pk) = create_compliance_keypair();
        let mut key_repo = KeyRepository::new(account, compliance_pk);
        let (ephemeral_sk, _nonce) = key_repo.next_ephemeral_params();
        let note = create_test_note();

        let (packed_ciphertext, epk) =
            encrypt_note_for_deposit_aes(ephemeral_sk, compliance_pk, &note)
                .expect("encryption should succeed");
        let commitment = crate::crypto_helpers::poseidon_hash(&packed_ciphertext);

        let event = UnprocessedEvent {
            event_type: EventType::NewNote,
            block_number: 100,
            tx_hash: "0x1234".to_string(),
            leaf_index: 0,
            commitment,
            epk_x: epk.0,
            epk_y: epk.1,
            packed_ciphertext,
            tag: None,
            intermediate_bob_x: None,
            intermediate_bob_y: None,
        };

        let processor = NoteProcessor::new(&key_repo, compliance_pk);
        let wallet_note = processor
            .process(&event)
            .expect("should decrypt our deposit");
        assert_eq!(wallet_note.note.asset_id, note.asset_id);
        assert_eq!(wallet_note.note.value, note.value);
        assert_eq!(wallet_note.note.secret, note.secret);
        assert_eq!(wallet_note.note.nullifier, note.nullifier);
        assert!(!wallet_note.is_transfer);
        assert_eq!(wallet_note.derivation_index, 0);
        assert!(!wallet_note.spent);
    }

    #[test]
    fn test_path_a_unknown_epk_returns_none() {
        let account = DarkAccount::from_seed(b"test_path_a_unknown");
        let (_, compliance_pk) = create_compliance_keypair();
        let key_repo = KeyRepository::new(account, compliance_pk);

        let event = UnprocessedEvent {
            event_type: EventType::NewNote,
            block_number: 100,
            tx_hash: "0x1234".to_string(),
            leaf_index: 0,
            commitment: U256::from(12345),
            epk_x: U256::from(999999), // Unknown PK
            epk_y: U256::from(888888),
            packed_ciphertext: [U256::zero(); 7],
            tag: None,
            intermediate_bob_x: None,
            intermediate_bob_y: None,
        };

        let processor = NoteProcessor::new(&key_repo, compliance_pk);
        let result = processor.process(&event);

        assert!(result.is_none(), "Should not match unknown ephemeral PK");
    }

    #[test]
    fn test_path_b_transfer_decryption() {
        use num_bigint::BigUint;

        // Helper to reduce U256 mod subgroup order (matches KeyRepository)
        fn reduce_mod_subgroup(value: U256) -> U256 {
            let mut bytes = [0u8; 32];
            value.to_big_endian(&mut bytes);
            let bigint = BigUint::from_bytes_be(&bytes);
            let order = BigUint::parse_bytes(darkpool_crypto::SUBGROUP_ORDER.as_bytes(), 10)
                .expect("valid subgroup order");
            let reduced = bigint % order;
            let mut result_bytes = reduced.to_bytes_be();
            while result_bytes.len() < 32 {
                result_bytes.insert(0, 0);
            }
            U256::from_big_endian(&result_bytes)
        }

        let mut recipient_account = DarkAccount::from_seed(b"test_path_b_recipient");
        let (_, compliance_pk) = create_compliance_keypair();
        let mut key_repo = KeyRepository::new(recipient_account.clone(), compliance_pk);
        key_repo.advance_incoming_keys(5);

        // Recipient's ivk reduced mod subgroup order (matches KeyRepository internals)
        let recipient_ivk = recipient_account.get_incoming_viewing_key(0);
        let recipient_ivk_mod = reduce_mod_subgroup(recipient_ivk);

        let mut ivk_mod_bytes = [0u8; 32];
        recipient_ivk_mod.to_big_endian(&mut ivk_mod_bytes);
        ivk_mod_bytes.reverse();
        let recipient_pk_from_mod = BASE8.mul_scalar(&ivk_mod_bytes).expect("valid test key");

        let sender_r = U256::from(98765u64);
        let mut r_bytes = [0u8; 32];
        sender_r.to_big_endian(&mut r_bytes);
        r_bytes.reverse();

        let intermediate_bob_point = BASE8.mul_scalar(&r_bytes).expect("valid test key");
        let intermediate_bob = (
            fr_to_u256(intermediate_bob_point.x()),
            fr_to_u256(intermediate_bob_point.y()),
        );

        let sender_shared_point = recipient_pk_from_mod
            .mul_scalar(&r_bytes)
            .expect("valid test key");
        let sender_shared_secret = fr_to_u256(sender_shared_point.x());

        let note = create_test_note();
        let (key, iv) = kdf_to_aes_key_iv(sender_shared_secret);
        let plaintext = pack_note_plaintext(&note);

        let ciphertext = aes128_encrypt(&plaintext, &key, &iv);
        let packed_ciphertext = pack_ciphertext_to_fields(&ciphertext);

        use darkpool_crypto::PublicKey;
        let compliance_pk_point = PublicKey::new_unchecked(
            crate::crypto_helpers::u256_to_fr(compliance_pk.0),
            crate::crypto_helpers::u256_to_fr(compliance_pk.1),
        );
        let tag_point = compliance_pk_point
            .mul_scalar(&ivk_mod_bytes)
            .expect("valid test key");
        let tag = fr_to_u256(tag_point.x());

        let commitment = crate::crypto_helpers::poseidon_hash(&packed_ciphertext);

        let event = UnprocessedEvent {
            event_type: EventType::NewMemo,
            block_number: 200,
            tx_hash: "0x5678".to_string(),
            leaf_index: 10,
            commitment,
            epk_x: U256::zero(),
            epk_y: U256::zero(),
            packed_ciphertext,
            tag: Some(tag),
            intermediate_bob_x: Some(intermediate_bob.0),
            intermediate_bob_y: Some(intermediate_bob.1),
        };

        let processor = NoteProcessor::new(&key_repo, compliance_pk);
        let wallet_note = processor
            .process(&event)
            .expect("should decrypt transfer memo");
        assert_eq!(wallet_note.note.asset_id, note.asset_id);
        assert_eq!(wallet_note.note.value, note.value);
        assert!(wallet_note.is_transfer);
        assert!(!wallet_note.spent);
    }

    #[test]
    fn test_path_b_unknown_tag_returns_none() {
        let account = DarkAccount::from_seed(b"test_path_b_unknown");
        let (_, compliance_pk) = create_compliance_keypair();
        let key_repo = KeyRepository::new(account, compliance_pk);

        let event = UnprocessedEvent {
            event_type: EventType::NewMemo,
            block_number: 200,
            tx_hash: "0x5678".to_string(),
            leaf_index: 10,
            commitment: U256::from(12345),
            epk_x: U256::zero(),
            epk_y: U256::zero(),
            packed_ciphertext: [U256::zero(); 7],
            tag: Some(U256::from(99999)), // Unknown tag
            intermediate_bob_x: Some(U256::from(111)),
            intermediate_bob_y: Some(U256::from(222)),
        };

        let processor = NoteProcessor::new(&key_repo, compliance_pk);
        let result = processor.process(&event);

        assert!(result.is_none(), "Should not match unknown tag");
    }

    #[test]
    fn test_memo_missing_fields_returns_none() {
        let account = DarkAccount::from_seed(b"test_memo_missing");
        let (_, compliance_pk) = create_compliance_keypair();
        let key_repo = KeyRepository::new(account, compliance_pk);

        // Missing tag
        let event1 = UnprocessedEvent {
            event_type: EventType::NewMemo,
            block_number: 200,
            tx_hash: "0x5678".to_string(),
            leaf_index: 10,
            commitment: U256::from(12345),
            epk_x: U256::zero(),
            epk_y: U256::zero(),
            packed_ciphertext: [U256::zero(); 7],
            tag: None, // Missing!
            intermediate_bob_x: Some(U256::from(111)),
            intermediate_bob_y: Some(U256::from(222)),
        };

        let processor = NoteProcessor::new(&key_repo, compliance_pk);
        assert!(processor.process(&event1).is_none());

        // Missing intermediate point
        let event2 = UnprocessedEvent {
            event_type: EventType::NewMemo,
            block_number: 200,
            tx_hash: "0x5678".to_string(),
            leaf_index: 10,
            commitment: U256::from(12345),
            epk_x: U256::zero(),
            epk_y: U256::zero(),
            packed_ciphertext: [U256::zero(); 7],
            tag: Some(U256::from(12345)),
            intermediate_bob_x: None, // Missing!
            intermediate_bob_y: Some(U256::from(222)),
        };

        assert!(processor.process(&event2).is_none());
    }

    #[test]
    fn test_nullifier_path_a_deterministic() {
        let account = DarkAccount::from_seed(b"test_nullifier_a");
        let (_, compliance_pk) = create_compliance_keypair();
        let mut key_repo = KeyRepository::new(account, compliance_pk);

        // Create and encrypt a note
        let (ephemeral_sk, _nonce) = key_repo.next_ephemeral_params();
        let note = create_test_note();
        let (packed_ciphertext, epk) =
            encrypt_note_for_deposit_aes(ephemeral_sk, compliance_pk, &note).unwrap();
        let commitment = crate::crypto_helpers::poseidon_hash(&packed_ciphertext);

        // Process twice
        let event = UnprocessedEvent {
            event_type: EventType::NewNote,
            block_number: 100,
            tx_hash: "0x1234".to_string(),
            leaf_index: 0,
            commitment,
            epk_x: epk.0,
            epk_y: epk.1,
            packed_ciphertext,
            tag: None,
            intermediate_bob_x: None,
            intermediate_bob_y: None,
        };

        let processor = NoteProcessor::new(&key_repo, compliance_pk);
        let result1 = processor.process(&event).unwrap();
        let result2 = processor.process(&event).unwrap();

        // Nullifiers should be identical
        assert_eq!(result1.nullifier, result2.nullifier);
        // And should match derive_nullifier_path_a(note.nullifier)
        let expected_nullifier = derive_nullifier_path_a(note.nullifier);
        assert_eq!(result1.nullifier, expected_nullifier);
    }
}
