//! Typed structs for ZK proof generation, formatted for `NoirProver`.

use crate::crypto_helpers::to_noir_hex;
use ethers::types::{Address, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub trait ProverInput {
    /// Flat map of field name -> hex value for Prover.toml generation.
    fn to_prover_map(&self) -> HashMap<String, String>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotePlaintext {
    pub value: U256,
    pub asset_id: U256,
    pub secret: U256,
    pub nullifier: U256,
    pub timelock: U256,
    pub hashlock: U256,
}

impl NotePlaintext {
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn random(value: U256, asset: Address) -> Self {
        use rand::RngCore;
        let mut rng = rand::rngs::OsRng;

        let modulus = U256::from_dec_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        )
        .expect("BN254 scalar field modulus is a valid decimal string");

        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        let secret = U256::from_big_endian(&secret_bytes) % modulus;

        let mut nullifier_bytes = [0u8; 32];
        rng.fill_bytes(&mut nullifier_bytes);
        let nullifier = U256::from_big_endian(&nullifier_bytes) % modulus;

        Self {
            value,
            asset_id: address_to_field(asset),
            secret,
            nullifier,
            timelock: U256::zero(),
            hashlock: U256::zero(),
        }
    }

    pub fn add_to_map(&self, map: &mut HashMap<String, String>, prefix: &str) {
        map.insert(format!("{prefix}.value"), to_noir_hex(self.value));
        map.insert(format!("{prefix}.asset_id"), to_noir_hex(self.asset_id));
        map.insert(format!("{prefix}.secret"), to_noir_hex(self.secret));
        map.insert(format!("{prefix}.nullifier"), to_noir_hex(self.nullifier));
        map.insert(format!("{prefix}.timelock"), to_noir_hex(self.timelock));
        map.insert(format!("{prefix}.hashlock"), to_noir_hex(self.hashlock));
    }
}

pub type CompliancePk = (U256, U256);

#[derive(Debug, Clone)]
pub struct DepositInputs {
    pub note_plaintext: NotePlaintext,
    pub ephemeral_sk: U256,
    pub compliance_pk: CompliancePk,
}

impl DepositInputs {
    #[must_use]
    pub fn new(note: NotePlaintext, ephemeral_sk: U256, compliance_pk: CompliancePk) -> Self {
        Self {
            note_plaintext: note,
            ephemeral_sk,
            compliance_pk,
        }
    }
}

impl ProverInput for DepositInputs {
    fn to_prover_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();

        map.insert("ephemeral_sk".into(), to_noir_hex(self.ephemeral_sk));
        self.note_plaintext.add_to_map(&mut map, "note_plaintext");

        map.insert(
            "compliance_pubkey_x".into(),
            to_noir_hex(self.compliance_pk.0),
        );
        map.insert(
            "compliance_pubkey_y".into(),
            to_noir_hex(self.compliance_pk.1),
        );

        map
    }
}

#[derive(Debug, Clone)]
pub struct WithdrawInputs {
    pub withdraw_value: U256,
    pub recipient: Address,
    pub merkle_root: U256,
    pub current_timestamp: u64,
    pub intent_hash: U256,
    pub compliance_pk: CompliancePk,

    // Old note being spent
    pub old_note: NotePlaintext,
    pub old_shared_secret: U256,
    pub old_note_index: u64,
    pub old_note_path: Vec<U256>,
    pub hashlock_preimage: U256,

    // Change note
    pub change_note: NotePlaintext,
    pub change_ephemeral_sk: U256,
}

impl ProverInput for WithdrawInputs {
    fn to_prover_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();

        map.insert("withdraw_value".into(), to_noir_hex(self.withdraw_value));
        map.insert(
            "_recipient".into(),
            to_noir_hex(address_to_field(self.recipient)),
        );
        map.insert("merkle_root".into(), to_noir_hex(self.merkle_root));
        map.insert(
            "current_timestamp".into(),
            to_noir_hex(U256::from(self.current_timestamp)),
        );
        map.insert("_intent_hash".into(), to_noir_hex(self.intent_hash));
        map.insert(
            "compliance_pubkey_x".into(),
            to_noir_hex(self.compliance_pk.0),
        );
        map.insert(
            "compliance_pubkey_y".into(),
            to_noir_hex(self.compliance_pk.1),
        );

        self.old_note.add_to_map(&mut map, "old_note");
        map.insert(
            "old_shared_secret".into(),
            to_noir_hex(self.old_shared_secret),
        );
        map.insert(
            "old_note_index".into(),
            to_noir_hex(U256::from(self.old_note_index)),
        );
        map.insert(
            "old_note_path".into(),
            format_path_array(&self.old_note_path),
        );
        map.insert(
            "hashlock_preimage".into(),
            to_noir_hex(self.hashlock_preimage),
        );

        self.change_note.add_to_map(&mut map, "change_note");
        map.insert(
            "change_ephemeral_sk".into(),
            to_noir_hex(self.change_ephemeral_sk),
        );

        map
    }
}

#[derive(Debug, Clone)]
pub struct DLEQProof {
    pub u: (U256, U256),
    pub v: (U256, U256),
    pub z: U256,
}

impl DLEQProof {
    pub fn add_to_map(&self, map: &mut HashMap<String, String>, prefix: &str) {
        map.insert(format!("{prefix}.U.x"), to_noir_hex(self.u.0));
        map.insert(format!("{prefix}.U.y"), to_noir_hex(self.u.1));
        map.insert(format!("{prefix}.V.x"), to_noir_hex(self.v.0));
        map.insert(format!("{prefix}.V.y"), to_noir_hex(self.v.1));
        map.insert(format!("{prefix}.z"), to_noir_hex(self.z));
    }
}

#[derive(Debug, Clone)]
pub struct TransferInputs {
    pub merkle_root: U256,
    pub current_timestamp: u64,
    pub compliance_pk: CompliancePk,

    // Recipient BJJ points
    pub recipient_b: (U256, U256), // BabyJubJub Public Key
    pub recipient_p: (U256, U256), // Public Key on scalar field
    pub recipient_proof: DLEQProof,

    // Old note being spent
    pub old_note: NotePlaintext,
    pub old_shared_secret: U256,
    pub old_note_index: u64,
    pub old_note_path: Vec<U256>,
    pub hashlock_preimage: U256,

    // Memo note (to recipient)
    pub memo_note: NotePlaintext,
    pub memo_ephemeral_sk: U256,

    // Change note (to self)
    pub change_note: NotePlaintext,
    pub change_ephemeral_sk: U256,
}

impl ProverInput for TransferInputs {
    fn to_prover_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();

        map.insert("merkle_root".into(), to_noir_hex(self.merkle_root));
        map.insert(
            "current_timestamp".into(),
            to_noir_hex(U256::from(self.current_timestamp)),
        );
        map.insert(
            "compliance_pubkey_x".into(),
            to_noir_hex(self.compliance_pk.0),
        );
        map.insert(
            "compliance_pubkey_y".into(),
            to_noir_hex(self.compliance_pk.1),
        );

        map.insert("recipient_B.x".into(), to_noir_hex(self.recipient_b.0));
        map.insert("recipient_B.y".into(), to_noir_hex(self.recipient_b.1));
        map.insert("recipient_P.x".into(), to_noir_hex(self.recipient_p.0));
        map.insert("recipient_P.y".into(), to_noir_hex(self.recipient_p.1));

        self.recipient_proof.add_to_map(&mut map, "recipient_proof");

        self.old_note.add_to_map(&mut map, "old_note");
        map.insert(
            "old_shared_secret".into(),
            to_noir_hex(self.old_shared_secret),
        );
        map.insert(
            "old_note_index".into(),
            to_noir_hex(U256::from(self.old_note_index)),
        );
        map.insert(
            "old_note_path".into(),
            format_path_array(&self.old_note_path),
        );
        map.insert(
            "hashlock_preimage".into(),
            to_noir_hex(self.hashlock_preimage),
        );

        self.memo_note.add_to_map(&mut map, "memo_note");
        map.insert(
            "memo_ephemeral_sk".into(),
            to_noir_hex(self.memo_ephemeral_sk),
        );

        self.change_note.add_to_map(&mut map, "change_note");
        map.insert(
            "change_ephemeral_sk".into(),
            to_noir_hex(self.change_ephemeral_sk),
        );

        map
    }
}

#[derive(Debug, Clone)]
pub struct GasPaymentInputs {
    // Public inputs
    pub merkle_root: U256,
    pub current_timestamp: u64,
    pub payment_value: U256,
    pub payment_asset_id: U256,
    pub relayer_address: Address,
    pub execution_hash: U256,
    pub compliance_pk: CompliancePk,

    // Private inputs - Note being spent for gas
    pub old_note: NotePlaintext,
    pub old_shared_secret: U256,
    pub old_note_index: u64,
    pub old_note_path: Vec<U256>,
    pub hashlock_preimage: U256,

    // Private inputs - Change note
    pub change_note: NotePlaintext,
    pub change_ephemeral_sk: U256,
}

impl ProverInput for GasPaymentInputs {
    fn to_prover_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();

        map.insert("merkle_root".into(), to_noir_hex(self.merkle_root));
        map.insert(
            "current_timestamp".into(),
            to_noir_hex(U256::from(self.current_timestamp)),
        );
        map.insert("payment_value".into(), to_noir_hex(self.payment_value));
        map.insert(
            "payment_asset_id".into(),
            to_noir_hex(self.payment_asset_id),
        );
        map.insert(
            "_relayer_address".into(),
            to_noir_hex(address_to_field(self.relayer_address)),
        );
        map.insert("_execution_hash".into(), to_noir_hex(self.execution_hash));
        map.insert(
            "compliance_pubkey_x".into(),
            to_noir_hex(self.compliance_pk.0),
        );
        map.insert(
            "compliance_pubkey_y".into(),
            to_noir_hex(self.compliance_pk.1),
        );

        self.old_note.add_to_map(&mut map, "old_note");
        map.insert(
            "old_shared_secret".into(),
            to_noir_hex(self.old_shared_secret),
        );
        map.insert(
            "old_note_index".into(),
            to_noir_hex(U256::from(self.old_note_index)),
        );
        map.insert(
            "old_note_path".into(),
            format_path_array(&self.old_note_path),
        );
        map.insert(
            "hashlock_preimage".into(),
            to_noir_hex(self.hashlock_preimage),
        );

        self.change_note.add_to_map(&mut map, "change_note");
        map.insert(
            "change_ephemeral_sk".into(),
            to_noir_hex(self.change_ephemeral_sk),
        );

        map
    }
}

#[derive(Debug, Clone)]
pub struct JoinInputs {
    pub merkle_root: U256,
    pub current_timestamp: u64,
    pub compliance_pk: CompliancePk,

    // First input note
    pub note_a: NotePlaintext,
    pub secret_a: U256,
    pub index_a: u64,
    pub path_a: Vec<U256>,
    pub preimage_a: U256,

    // Second input note
    pub note_b: NotePlaintext,
    pub secret_b: U256,
    pub index_b: u64,
    pub path_b: Vec<U256>,
    pub preimage_b: U256,

    // Output note
    pub note_out: NotePlaintext,
    pub sk_out: U256,
}

impl ProverInput for JoinInputs {
    fn to_prover_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();

        map.insert("merkle_root".into(), to_noir_hex(self.merkle_root));
        map.insert(
            "current_timestamp".into(),
            to_noir_hex(U256::from(self.current_timestamp)),
        );
        map.insert(
            "compliance_pubkey_x".into(),
            to_noir_hex(self.compliance_pk.0),
        );
        map.insert(
            "compliance_pubkey_y".into(),
            to_noir_hex(self.compliance_pk.1),
        );

        self.note_a.add_to_map(&mut map, "note_a");
        map.insert("secret_a".into(), to_noir_hex(self.secret_a));
        map.insert("index_a".into(), to_noir_hex(U256::from(self.index_a)));
        map.insert("path_a".into(), format_path_array(&self.path_a));
        map.insert("preimage_a".into(), to_noir_hex(self.preimage_a));

        self.note_b.add_to_map(&mut map, "note_b");
        map.insert("secret_b".into(), to_noir_hex(self.secret_b));
        map.insert("index_b".into(), to_noir_hex(U256::from(self.index_b)));
        map.insert("path_b".into(), format_path_array(&self.path_b));
        map.insert("preimage_b".into(), to_noir_hex(self.preimage_b));

        self.note_out.add_to_map(&mut map, "note_out");
        map.insert("sk_out".into(), to_noir_hex(self.sk_out));

        map
    }
}

#[derive(Debug, Clone)]
pub struct SplitInputs {
    pub merkle_root: U256,
    pub current_timestamp: u64,
    pub compliance_pk: CompliancePk,

    // Input note
    pub note_in: NotePlaintext,
    pub secret_in: U256,
    pub index_in: u64,
    pub path_in: Vec<U256>,
    pub preimage_in: U256,

    // Output notes (Noir uses underscore: note_out_1, note_out_2)
    pub note_out_1: NotePlaintext,
    pub sk_out_1: U256,
    pub note_out_2: NotePlaintext,
    pub sk_out_2: U256,
}

impl ProverInput for SplitInputs {
    fn to_prover_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();

        map.insert("merkle_root".into(), to_noir_hex(self.merkle_root));
        map.insert(
            "current_timestamp".into(),
            to_noir_hex(U256::from(self.current_timestamp)),
        );
        map.insert(
            "compliance_pubkey_x".into(),
            to_noir_hex(self.compliance_pk.0),
        );
        map.insert(
            "compliance_pubkey_y".into(),
            to_noir_hex(self.compliance_pk.1),
        );

        self.note_in.add_to_map(&mut map, "note_in");
        map.insert("secret_in".into(), to_noir_hex(self.secret_in));
        map.insert("index_in".into(), to_noir_hex(U256::from(self.index_in)));
        map.insert("path_in".into(), format_path_array(&self.path_in));
        map.insert("preimage_in".into(), to_noir_hex(self.preimage_in));

        self.note_out_1.add_to_map(&mut map, "note_out_1");
        map.insert("sk_out_1".into(), to_noir_hex(self.sk_out_1));
        self.note_out_2.add_to_map(&mut map, "note_out_2");
        map.insert("sk_out_2".into(), to_noir_hex(self.sk_out_2));

        map
    }
}

#[derive(Debug, Clone)]
pub struct PublicClaimInputs {
    pub memo_id: U256,
    pub compliance_pk: CompliancePk,

    pub val: U256,
    pub asset_id: U256,
    pub timelock: U256,
    pub owner_x: U256,
    pub owner_y: U256,
    pub salt: U256,

    pub recipient_sk: U256,
    pub note_out: NotePlaintext,
    pub sk_out: U256,
}

impl ProverInput for PublicClaimInputs {
    fn to_prover_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();

        map.insert("memo_id".into(), to_noir_hex(self.memo_id));
        map.insert(
            "compliance_pubkey_x".into(),
            to_noir_hex(self.compliance_pk.0),
        );
        map.insert(
            "compliance_pubkey_y".into(),
            to_noir_hex(self.compliance_pk.1),
        );

        map.insert("val".into(), to_noir_hex(self.val));
        map.insert("asset_id".into(), to_noir_hex(self.asset_id));
        map.insert("timelock".into(), to_noir_hex(self.timelock));
        map.insert("owner_x".into(), to_noir_hex(self.owner_x));
        map.insert("owner_y".into(), to_noir_hex(self.owner_y));
        map.insert("salt".into(), to_noir_hex(self.salt));

        map.insert("recipient_sk".into(), to_noir_hex(self.recipient_sk));
        self.note_out.add_to_map(&mut map, "note_out");
        map.insert("sk_out".into(), to_noir_hex(self.sk_out));

        map
    }
}

#[must_use]
pub fn address_to_field(addr: Address) -> U256 {
    U256::from_big_endian(addr.as_bytes())
}

fn format_path_array(path: &[U256]) -> String {
    let items: Vec<_> = path
        .iter()
        .map(|p| format!("\"{}\"", to_noir_hex(*p)))
        .collect();
    format!("[{}]", items.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_note_plaintext_random() {
        let note = NotePlaintext::random(U256::from(1000), Address::zero());
        assert!(!note.secret.is_zero());
        assert!(!note.nullifier.is_zero());
    }

    #[test]
    fn test_deposit_inputs_to_map() {
        let note = NotePlaintext::random(U256::from(1000), Address::zero());
        let inputs = DepositInputs::new(note, U256::from(12345), (U256::from(1), U256::from(2)));

        let map = inputs.to_prover_map();
        assert!(map.contains_key("note_plaintext.value"));
        assert!(map.contains_key("ephemeral_sk"));

        let value = map.get("note_plaintext.value").unwrap();
        assert!(value.starts_with("0x"));
        assert_eq!(value.len(), 66); // 0x + 64 hex chars
    }

    #[test]
    fn test_format_path_array() {
        let path = vec![U256::from(1)];
        let formatted = format_path_array(&path);
        assert!(formatted.starts_with("[\"0x"));
    }

    #[test]
    fn test_proof_inputs_field_element_bounds() {
        let modulus = U256::from_dec_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        )
        .unwrap();

        let note = NotePlaintext::random(U256::from(999), Address::zero());
        let inputs = DepositInputs::new(note, U256::from(12345), (U256::from(7), U256::from(11)));

        let map = inputs.to_prover_map();

        for (key, hex_val) in &map {
            if let Some(stripped) = hex_val.strip_prefix("0x") {
                let num = U256::from_str_radix(stripped, 16)
                    .unwrap_or_else(|_| panic!("key {key} has non-hex value: {hex_val}"));
                assert!(num < modulus, "key {key} value {num} >= BN254 modulus");
            }
        }
    }

    #[test]
    fn test_deposit_inputs_map_has_required_keys() {
        let note = NotePlaintext::random(U256::from(1), Address::zero());
        let inputs = DepositInputs::new(note, U256::from(99), (U256::from(1), U256::from(2)));
        let map = inputs.to_prover_map();

        let required = [
            "note_plaintext.value",
            "note_plaintext.secret",
            "note_plaintext.nullifier",
            "ephemeral_sk",
            "compliance_pubkey_x",
            "compliance_pubkey_y",
        ];
        for key in required {
            assert!(map.contains_key(key), "missing required key: {key}");
        }
    }
}
