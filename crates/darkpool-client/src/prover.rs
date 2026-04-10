//! Typed proof generation methods for all `DarkPool` circuits, wrapping an `IProverService` backend.

use std::sync::Arc;

use nox_core::traits::interfaces::{IProverService, InfrastructureError, ZKProofData};

use crate::proof_inputs::{
    DepositInputs, GasPaymentInputs, JoinInputs, ProverInput, PublicClaimInputs, SplitInputs,
    TransferInputs, WithdrawInputs,
};

pub mod circuits {
    pub const DEPOSIT: &str = "deposit";
    pub const WITHDRAW: &str = "withdraw";
    pub const TRANSFER: &str = "transfer";
    pub const GAS_PAYMENT: &str = "gas_payment";
    pub const JOIN: &str = "join";
    pub const SPLIT: &str = "split";
    pub const PUBLIC_CLAIM: &str = "public_claim";
}

pub struct ClientProver {
    backend: Arc<dyn IProverService>,
}

impl ClientProver {
    #[must_use]
    pub fn with_service(backend: Arc<dyn IProverService>) -> Self {
        Self { backend }
    }

    pub async fn prove_deposit(
        &self,
        inputs: &DepositInputs,
    ) -> Result<ZKProofData, InfrastructureError> {
        self.backend
            .prove(circuits::DEPOSIT, inputs.to_prover_map())
            .await
    }

    pub async fn prove_withdraw(
        &self,
        inputs: &WithdrawInputs,
    ) -> Result<ZKProofData, InfrastructureError> {
        self.backend
            .prove(circuits::WITHDRAW, inputs.to_prover_map())
            .await
    }

    pub async fn prove_transfer(
        &self,
        inputs: &TransferInputs,
    ) -> Result<ZKProofData, InfrastructureError> {
        self.backend
            .prove(circuits::TRANSFER, inputs.to_prover_map())
            .await
    }

    pub async fn prove_gas_payment(
        &self,
        inputs: &GasPaymentInputs,
    ) -> Result<ZKProofData, InfrastructureError> {
        self.backend
            .prove(circuits::GAS_PAYMENT, inputs.to_prover_map())
            .await
    }

    pub async fn prove_join(
        &self,
        inputs: &JoinInputs,
    ) -> Result<ZKProofData, InfrastructureError> {
        self.backend
            .prove(circuits::JOIN, inputs.to_prover_map())
            .await
    }

    pub async fn prove_split(
        &self,
        inputs: &SplitInputs,
    ) -> Result<ZKProofData, InfrastructureError> {
        self.backend
            .prove(circuits::SPLIT, inputs.to_prover_map())
            .await
    }

    pub async fn prove_public_claim(
        &self,
        inputs: &PublicClaimInputs,
    ) -> Result<ZKProofData, InfrastructureError> {
        self.backend
            .prove(circuits::PUBLIC_CLAIM, inputs.to_prover_map())
            .await
    }

    pub async fn prove<T: ProverInput>(
        &self,
        circuit_name: &str,
        inputs: &T,
    ) -> Result<ZKProofData, InfrastructureError> {
        self.backend
            .prove(circuit_name, inputs.to_prover_map())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_inputs::{DLEQProof, NotePlaintext};
    use ethers::types::{Address, U256};

    fn create_test_note() -> NotePlaintext {
        NotePlaintext {
            value: U256::from(100),
            asset_id: U256::from(1),
            secret: U256::from(12345),
            nullifier: U256::from(67890),
            timelock: U256::zero(),
            hashlock: U256::zero(),
        }
    }

    fn create_compliance_pk() -> (U256, U256) {
        (U256::from(1), U256::from(2))
    }

    #[test]
    fn test_deposit_inputs_map_contains_required_keys() {
        let note = create_test_note();
        let inputs = DepositInputs::new(note, U256::from(999), create_compliance_pk());

        let map = inputs.to_prover_map();

        assert!(map.contains_key("ephemeral_sk"));
        assert!(map.contains_key("note_plaintext.value"));
        assert!(map.contains_key("note_plaintext.asset_id"));
        assert!(map.contains_key("note_plaintext.secret"));
        assert!(map.contains_key("note_plaintext.nullifier"));
        assert!(map.contains_key("note_plaintext.timelock"));
        assert!(map.contains_key("note_plaintext.hashlock"));
        assert!(map.contains_key("compliance_pubkey_x"));
        assert!(map.contains_key("compliance_pubkey_y"));
    }

    #[test]
    fn test_withdraw_inputs_map_contains_required_keys() {
        let old_note = create_test_note();
        let change_note = create_test_note();
        let merkle_path = vec![U256::zero(); 32];

        let inputs = WithdrawInputs {
            withdraw_value: U256::from(50),
            recipient: Address::zero(),
            merkle_root: U256::from(1111),
            current_timestamp: 0,
            intent_hash: U256::zero(),
            compliance_pk: create_compliance_pk(),
            old_note,
            old_shared_secret: U256::from(2222),
            old_note_index: 0,
            old_note_path: merkle_path,
            hashlock_preimage: U256::zero(),
            change_note,
            change_ephemeral_sk: U256::from(3333),
        };

        let map = inputs.to_prover_map();

        assert!(map.contains_key("withdraw_value"));
        assert!(map.contains_key("_recipient"));
        assert!(map.contains_key("merkle_root"));
        assert!(map.contains_key("current_timestamp"));
        assert!(map.contains_key("old_note.value"));
        assert!(map.contains_key("old_shared_secret"));
        assert!(map.contains_key("old_note_index"));
        assert!(map.contains_key("old_note_path"));
        assert!(map.contains_key("change_note.value"));
        assert!(map.contains_key("change_ephemeral_sk"));
    }

    #[test]
    fn test_transfer_inputs_map_contains_required_keys() {
        let old_note = create_test_note();
        let memo_note = create_test_note();
        let change_note = create_test_note();
        let merkle_path = vec![U256::zero(); 32];

        let inputs = TransferInputs {
            merkle_root: U256::from(1111),
            current_timestamp: 0,
            compliance_pk: create_compliance_pk(),
            recipient_b: (U256::from(100), U256::from(200)),
            recipient_p: (U256::from(300), U256::from(400)),
            recipient_proof: DLEQProof {
                u: (U256::from(1), U256::from(2)),
                v: (U256::from(3), U256::from(4)),
                z: U256::from(5),
            },
            old_note,
            old_shared_secret: U256::from(2222),
            old_note_index: 0,
            old_note_path: merkle_path,
            hashlock_preimage: U256::zero(),
            memo_note,
            memo_ephemeral_sk: U256::from(4444),
            change_note,
            change_ephemeral_sk: U256::from(5555),
        };

        let map = inputs.to_prover_map();

        assert!(map.contains_key("merkle_root"));
        assert!(map.contains_key("recipient_B.x"));
        assert!(map.contains_key("recipient_B.y"));
        assert!(map.contains_key("recipient_P.x"));
        assert!(map.contains_key("recipient_P.y"));
        assert!(map.contains_key("recipient_proof.U.x"));
        assert!(map.contains_key("recipient_proof.U.y"));
        assert!(map.contains_key("recipient_proof.V.x"));
        assert!(map.contains_key("recipient_proof.V.y"));
        assert!(map.contains_key("recipient_proof.z"));
        assert!(map.contains_key("memo_note.value"));
        assert!(map.contains_key("memo_ephemeral_sk"));
        assert!(map.contains_key("change_note.value"));
    }

    #[test]
    fn test_gas_payment_inputs_map_contains_required_keys() {
        let old_note = create_test_note();
        let change_note = create_test_note();
        let merkle_path = vec![U256::zero(); 32];

        let inputs = GasPaymentInputs {
            merkle_root: U256::from(1111),
            current_timestamp: 0,
            payment_value: U256::from(10),
            payment_asset_id: U256::from(1),
            relayer_address: Address::zero(),
            execution_hash: U256::from(9999),
            compliance_pk: create_compliance_pk(),
            old_note,
            old_shared_secret: U256::from(2222),
            old_note_index: 0,
            old_note_path: merkle_path,
            hashlock_preimage: U256::zero(),
            change_note,
            change_ephemeral_sk: U256::from(3333),
        };

        let map = inputs.to_prover_map();

        assert!(map.contains_key("merkle_root"));
        assert!(map.contains_key("current_timestamp"));
        assert!(map.contains_key("payment_value"));
        assert!(map.contains_key("payment_asset_id"));
        assert!(map.contains_key("_relayer_address"));
        assert!(map.contains_key("_execution_hash"));
        assert!(map.contains_key("old_note.value"));
        assert!(map.contains_key("old_shared_secret"));
        assert!(map.contains_key("old_note_index"));
        assert!(map.contains_key("old_note_path"));
        assert!(map.contains_key("hashlock_preimage"));
        assert!(map.contains_key("change_note.value"));
    }

    #[test]
    fn test_join_inputs_map_contains_required_keys() {
        let note_a = create_test_note();
        let note_b = create_test_note();
        let note_out = create_test_note();
        let path = vec![U256::zero(); 32];

        let inputs = JoinInputs {
            merkle_root: U256::from(1111),
            current_timestamp: 0,
            compliance_pk: create_compliance_pk(),
            note_a,
            secret_a: U256::from(111),
            index_a: 0,
            path_a: path.clone(),
            preimage_a: U256::zero(),
            note_b,
            secret_b: U256::from(222),
            index_b: 1,
            path_b: path,
            preimage_b: U256::zero(),
            note_out,
            sk_out: U256::from(333),
        };

        let map = inputs.to_prover_map();

        assert!(map.contains_key("merkle_root"));
        assert!(map.contains_key("note_a.value"));
        assert!(map.contains_key("secret_a"));
        assert!(map.contains_key("index_a"));
        assert!(map.contains_key("path_a"));
        assert!(map.contains_key("note_b.value"));
        assert!(map.contains_key("secret_b"));
        assert!(map.contains_key("index_b"));
        assert!(map.contains_key("path_b"));
        assert!(map.contains_key("note_out.value"));
        assert!(map.contains_key("sk_out"));
    }

    #[test]
    fn test_split_inputs_map_contains_required_keys() {
        let note_in = create_test_note();
        let note_out_1 = create_test_note();
        let note_out_2 = create_test_note();
        let path = vec![U256::zero(); 32];

        let inputs = SplitInputs {
            merkle_root: U256::from(1111),
            current_timestamp: 0,
            compliance_pk: create_compliance_pk(),
            note_in,
            secret_in: U256::from(111),
            index_in: 0,
            path_in: path,
            preimage_in: U256::zero(),
            note_out_1,
            sk_out_1: U256::from(222),
            note_out_2,
            sk_out_2: U256::from(333),
        };

        let map = inputs.to_prover_map();

        assert!(map.contains_key("merkle_root"));
        assert!(map.contains_key("note_in.value"));
        assert!(map.contains_key("secret_in"));
        assert!(map.contains_key("index_in"));
        assert!(map.contains_key("path_in"));
        assert!(map.contains_key("note_out_1.value"));
        assert!(map.contains_key("sk_out_1"));
        assert!(map.contains_key("note_out_2.value"));
        assert!(map.contains_key("sk_out_2"));
    }

    #[test]
    fn test_hex_formatting() {
        let note = create_test_note();
        let inputs = DepositInputs::new(note, U256::from(12345), create_compliance_pk());

        let map = inputs.to_prover_map();

        for value in map.values() {
            assert!(value.starts_with("0x"), "Value should start with 0x");
            assert_eq!(value.len(), 66, "Hex value should be 66 chars (0x + 64)");
        }
    }

    #[test]
    fn test_merkle_path_array_formatting() {
        let note = create_test_note();
        let change_note = create_test_note();
        let merkle_path = vec![U256::from(1), U256::from(2), U256::from(3)];

        let inputs = WithdrawInputs {
            withdraw_value: U256::from(50),
            recipient: Address::zero(),
            merkle_root: U256::from(1111),
            current_timestamp: 0,
            intent_hash: U256::zero(),
            compliance_pk: create_compliance_pk(),
            old_note: note,
            old_shared_secret: U256::from(2222),
            old_note_index: 0,
            old_note_path: merkle_path,
            hashlock_preimage: U256::zero(),
            change_note,
            change_ephemeral_sk: U256::from(3333),
        };

        let map = inputs.to_prover_map();
        let path_value = map.get("old_note_path").unwrap();

        assert!(path_value.starts_with("[\"0x"));
        assert!(path_value.ends_with("\"]"));
        assert!(path_value.contains(", "));
    }
}
