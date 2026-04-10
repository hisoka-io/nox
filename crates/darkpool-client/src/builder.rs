//! ZK proof generation and transaction encoding for `DarkPool` operations.

use ethers::abi::{encode, Token};
use ethers::types::{Address, Bytes, H256, U256};
use std::sync::{Arc, LazyLock};
use thiserror::Error;
use tracing::{debug, info};

/// BN254 scalar field modulus
#[allow(clippy::expect_used)]
static BN254_MODULUS: LazyLock<U256> = LazyLock::new(|| {
    U256::from_dec_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    )
    .expect("BN254 modulus constant is a valid decimal string")
});

use crate::crypto_helpers::field_to_address;
use crate::economics::{FeeConfig, FeeEstimate, FeeManager, PriceData};
use crate::note_factory::{ChangeNoteResult, DepositNoteResult, SpendingInputs};
use crate::note_processor::WalletNote;
use crate::proof_inputs::{
    DLEQProof, DepositInputs, GasPaymentInputs, JoinInputs, NotePlaintext, PublicClaimInputs,
    SplitInputs, TransferInputs, WithdrawInputs,
};
use crate::prover::ClientProver;
use nox_core::traits::interfaces::InfrastructureError;

#[derive(Debug, Error)]
pub enum BuilderError {
    #[error("Proof generation failed: {0}")]
    ProofGeneration(String),
    #[error("Insufficient funds: need {needed}, have {available}")]
    InsufficientFunds { needed: U256, available: U256 },
    #[error("No suitable note found for payment")]
    NoSuitableNote,
    #[error("Encoding error: {0}")]
    Encoding(String),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Infrastructure error: {0}")]
    Infrastructure(#[from] InfrastructureError),
}

/// A complete gas payment bundle ready for relay
#[derive(Debug, Clone)]
pub struct GasPaymentBundle {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<[u8; 32]>,
    pub public_inputs_hex: Vec<String>,
    pub nullifier_hash: H256,
    pub fee_amount: U256,
    /// Binds the payment to a specific action
    pub execution_hash: H256,
}

#[derive(Debug, Clone)]
pub struct MulticallBundle {
    pub gas_payment: GasPaymentBundle,
    pub multicall_data: Bytes,
    pub multicall_target: Address,
}

#[derive(Debug, Clone)]
pub struct DepositProofBundle {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<[u8; 32]>,
    pub deposit: DepositNoteResult,
    pub calldata: Bytes,
}

#[derive(Debug, Clone)]
pub struct WithdrawProofBundle {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<[u8; 32]>,
    pub nullifier_hash: H256,
    pub change_note: Option<ChangeNoteResult>,
    pub calldata: Bytes,
}

#[derive(Debug, Clone)]
pub struct TransferProofBundle {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<[u8; 32]>,
    pub nullifier_hash: H256,
    pub memo_commitment: U256,
    pub change_commitment: U256,
    /// For recipient scanning via `NewPrivateMemo` events
    pub transfer_tag: U256,
    pub calldata: Bytes,
}

#[derive(Debug, Clone)]
pub struct SplitProofBundle {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<[u8; 32]>,
    pub nullifier_hash: H256,
    pub note_out_1: ChangeNoteResult,
    pub note_out_2: ChangeNoteResult,
    pub calldata: Bytes,
}

#[derive(Debug, Clone)]
pub struct JoinProofBundle {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<[u8; 32]>,
    pub nullifier_hash_a: H256,
    pub nullifier_hash_b: H256,
    pub note_out: ChangeNoteResult,
    pub calldata: Bytes,
}

#[derive(Debug, Clone)]
pub struct PublicClaimProofBundle {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<[u8; 32]>,
    pub note_out: ChangeNoteResult,
    pub calldata: Bytes,
}

#[derive(Debug, Clone)]
pub struct BuilderConfig {
    pub fee_config: FeeConfig,
    pub darkpool_address: Address,
    pub multicall_address: Address,
    pub compliance_pk: (U256, U256),
}

impl Default for BuilderConfig {
    fn default() -> Self {
        Self {
            fee_config: FeeConfig::default(),
            darkpool_address: Address::zero(),
            multicall_address: Address::zero(),
            compliance_pk: (U256::zero(), U256::zero()),
        }
    }
}

pub struct TransactionBuilder {
    prover: Arc<ClientProver>,
    fee_manager: FeeManager,
    config: BuilderConfig,
}

impl TransactionBuilder {
    #[must_use]
    pub fn new(prover: Arc<ClientProver>, config: BuilderConfig) -> Self {
        Self {
            prover,
            fee_manager: FeeManager::new(config.fee_config.clone()),
            config,
        }
    }

    /// Build a gas payment proof for a relayed action.
    ///
    /// `pre_created_change`: when provided, the scan engine can discover the gas change note.
    /// `current_timestamp`: Unix seconds; the ZK circuit checks `>= note.timelock`. Pass 0 for no-timelock notes.
    #[allow(clippy::too_many_arguments)]
    pub async fn build_gas_payment(
        &self,
        note: &WalletNote,
        merkle_root: U256,
        merkle_path: Vec<U256>,
        payment_amount: U256,
        relayer_address: Address,
        execution_hash: H256,
        pre_created_change: Option<ChangeNoteResult>,
        current_timestamp: u64,
    ) -> Result<GasPaymentBundle, BuilderError> {
        info!(
            "Building gas payment proof: amount={}, note_value={}",
            payment_amount, note.note.value
        );

        if note.note.value < payment_amount {
            return Err(BuilderError::InsufficientFunds {
                needed: payment_amount,
                available: note.note.value,
            });
        }

        let (change_note, change_ephemeral_sk) = if let Some(change_result) = pre_created_change {
            (change_result.note, change_result.ephemeral_sk)
        } else {
            let change_value = note.note.value.checked_sub(payment_amount).ok_or(
                BuilderError::InsufficientFunds {
                    needed: payment_amount,
                    available: note.note.value,
                },
            )?;
            let asset_address = field_to_address(note.note.asset_id);
            (
                NotePlaintext::random(change_value, asset_address),
                generate_random_scalar(),
            )
        };

        let inputs = GasPaymentInputs {
            merkle_root,
            current_timestamp,
            payment_value: payment_amount,
            payment_asset_id: note.note.asset_id,
            relayer_address,
            execution_hash: U256::from_big_endian(execution_hash.as_bytes()),
            compliance_pk: self.config.compliance_pk,
            old_note: note.note.clone(),
            old_shared_secret: note.spending_secret,
            old_note_index: note.leaf_index,
            old_note_path: merkle_path,
            hashlock_preimage: U256::zero(),
            change_note,
            change_ephemeral_sk,
        };

        debug!("Generating gas payment ZK proof...");
        let proof_data = self
            .prover
            .prove_gas_payment(&inputs)
            .await
            .map_err(|e| BuilderError::ProofGeneration(e.to_string()))?;

        let public_inputs_bytes = convert_public_inputs_to_bytes32(&proof_data.public_inputs)?;
        let nullifier_hash = extract_gas_payment_nullifier(&public_inputs_bytes)?;

        info!(
            "Gas payment proof generated: {} bytes, {} public inputs",
            proof_data.proof.len(),
            public_inputs_bytes.len()
        );

        Ok(GasPaymentBundle {
            proof: proof_data.proof,
            public_inputs: public_inputs_bytes,
            public_inputs_hex: proof_data.public_inputs,
            nullifier_hash,
            fee_amount: payment_amount,
            execution_hash,
        })
    }

    /// Build a complete multicall bundle (gas payment proof + action) for relay.
    #[allow(clippy::too_many_arguments)]
    pub async fn build_paid_action(
        &self,
        note: &WalletNote,
        merkle_root: U256,
        merkle_path: Vec<U256>,
        action_target: Address,
        action_calldata: Bytes,
        prices: &PriceData,
        relayer_address: Address,
        gas_limit: U256,
        gas_change_note: Option<ChangeNoteResult>,
        current_timestamp: u64,
    ) -> Result<MulticallBundle, BuilderError> {
        if self.config.multicall_address.is_zero() {
            return Err(BuilderError::Config(
                "multicall_address is zero -- BuilderConfig.multicall_address must be set for paid actions".into(),
            ));
        }

        let fee_estimate = self.fee_manager.calculate_fee(gas_limit, prices);
        debug!(
            "Fee estimate: {} (gas: {}, premium: {}bps)",
            fee_estimate.fee_amount, fee_estimate.gas_limit, fee_estimate.premium_bps
        );

        let execution_hash =
            compute_execution_hash(&action_target, &action_calldata, &fee_estimate.fee_amount);

        let gas_payment = self
            .build_gas_payment(
                note,
                merkle_root,
                merkle_path,
                fee_estimate.fee_amount,
                relayer_address,
                execution_hash,
                gas_change_note,
                current_timestamp,
            )
            .await?;

        let multicall_data = encode_multicall(
            self.config.darkpool_address,
            &gas_payment.proof,
            &gas_payment.public_inputs,
            action_target,
            action_calldata,
        )?;

        Ok(MulticallBundle {
            gas_payment,
            multicall_data,
            multicall_target: self.config.multicall_address,
        })
    }

    /// Estimate fee for an action without generating proof
    #[must_use]
    pub fn estimate_fee(&self, gas_limit: U256, prices: &PriceData) -> FeeEstimate {
        self.fee_manager.calculate_fee(gas_limit, prices)
    }

    pub async fn build_deposit(
        &self,
        deposit_result: &DepositNoteResult,
    ) -> Result<DepositProofBundle, BuilderError> {
        info!(
            "Building deposit proof: value={}",
            deposit_result.note.value
        );

        let inputs = DepositInputs {
            note_plaintext: deposit_result.note.clone(),
            ephemeral_sk: deposit_result.ephemeral_sk,
            compliance_pk: self.config.compliance_pk,
        };

        let proof_data = self
            .prover
            .prove_deposit(&inputs)
            .await
            .map_err(|e| BuilderError::ProofGeneration(e.to_string()))?;

        let public_inputs = convert_public_inputs_to_bytes32(&proof_data.public_inputs)?;

        let calldata = encode_deposit_calldata(&proof_data.proof, &public_inputs);

        info!("Deposit proof generated: {} bytes", proof_data.proof.len());

        Ok(DepositProofBundle {
            proof: proof_data.proof,
            public_inputs,
            deposit: deposit_result.clone(),
            calldata,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn build_withdraw(
        &self,
        spending_inputs: &SpendingInputs,
        withdraw_value: U256,
        recipient: Address,
        merkle_root: U256,
        change_note: Option<&ChangeNoteResult>,
        intent_hash: Option<U256>,
        current_timestamp: u64,
    ) -> Result<WithdrawProofBundle, BuilderError> {
        info!(
            "Building withdraw proof: value={}, recipient={:?}",
            withdraw_value, recipient
        );

        let change = if let Some(cn) = change_note {
            cn.note.clone()
        } else {
            NotePlaintext::random(U256::zero(), Address::zero())
        };
        let change_sk = change_note.map_or_else(generate_random_scalar, |c| c.ephemeral_sk);

        let inputs = WithdrawInputs {
            withdraw_value,
            recipient,
            merkle_root,
            current_timestamp,
            intent_hash: intent_hash.unwrap_or(U256::zero()),
            compliance_pk: self.config.compliance_pk,
            old_note: spending_inputs.note.clone(),
            old_shared_secret: spending_inputs.shared_secret,
            old_note_index: spending_inputs.leaf_index,
            old_note_path: spending_inputs.merkle_path.siblings_vec(),
            hashlock_preimage: spending_inputs.hashlock_preimage,
            change_note: change,
            change_ephemeral_sk: change_sk,
        };

        let proof_data = self
            .prover
            .prove_withdraw(&inputs)
            .await
            .map_err(|e| BuilderError::ProofGeneration(e.to_string()))?;

        let public_inputs = convert_public_inputs_to_bytes32(&proof_data.public_inputs)?;
        let nullifier_hash = extract_withdraw_nullifier(&public_inputs)?;

        let calldata = encode_withdraw_calldata(&proof_data.proof, &public_inputs);

        info!("Withdraw proof generated: {} bytes", proof_data.proof.len());

        Ok(WithdrawProofBundle {
            proof: proof_data.proof,
            public_inputs,
            nullifier_hash,
            change_note: change_note.cloned(),
            calldata,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn build_transfer(
        &self,
        spending_inputs: &SpendingInputs,
        merkle_root: U256,
        recipient_b: (U256, U256),
        recipient_p: (U256, U256),
        recipient_proof: DLEQProof,
        memo_note: NotePlaintext,
        memo_ephemeral_sk: U256,
        change_note: NotePlaintext,
        change_ephemeral_sk: U256,
        current_timestamp: u64,
    ) -> Result<TransferProofBundle, BuilderError> {
        info!("Building transfer proof: memo_value={}", memo_note.value);

        let inputs = TransferInputs {
            merkle_root,
            current_timestamp,
            compliance_pk: self.config.compliance_pk,
            recipient_b,
            recipient_p,
            recipient_proof,
            old_note: spending_inputs.note.clone(),
            old_shared_secret: spending_inputs.shared_secret,
            old_note_index: spending_inputs.leaf_index,
            old_note_path: spending_inputs.merkle_path.siblings_vec(),
            hashlock_preimage: spending_inputs.hashlock_preimage,
            memo_note,
            memo_ephemeral_sk,
            change_note,
            change_ephemeral_sk,
        };

        let proof_data = self
            .prover
            .prove_transfer(&inputs)
            .await
            .map_err(|e| BuilderError::ProofGeneration(e.to_string()))?;

        let public_inputs = convert_public_inputs_to_bytes32(&proof_data.public_inputs)?;
        let nullifier_hash = extract_transfer_nullifier(&public_inputs)?;

        let calldata = encode_transfer_calldata(&proof_data.proof, &public_inputs);
        let (memo_commitment, change_commitment, transfer_tag) =
            extract_transfer_commitments(&proof_data.public_inputs)?;

        info!("Transfer proof generated: {} bytes", proof_data.proof.len());

        Ok(TransferProofBundle {
            proof: proof_data.proof,
            public_inputs,
            nullifier_hash,
            memo_commitment,
            change_commitment,
            transfer_tag,
            calldata,
        })
    }

    pub async fn build_split(
        &self,
        spending_inputs: &SpendingInputs,
        merkle_root: U256,
        note_out_1: &ChangeNoteResult,
        note_out_2: &ChangeNoteResult,
        current_timestamp: u64,
    ) -> Result<SplitProofBundle, BuilderError> {
        info!(
            "Building split proof: value_1={}, value_2={}",
            note_out_1.note.value, note_out_2.note.value
        );

        let inputs = SplitInputs {
            merkle_root,
            current_timestamp,
            compliance_pk: self.config.compliance_pk,
            note_in: spending_inputs.note.clone(),
            secret_in: spending_inputs.shared_secret,
            index_in: spending_inputs.leaf_index,
            path_in: spending_inputs.merkle_path.siblings_vec(),
            preimage_in: spending_inputs.hashlock_preimage,
            note_out_1: note_out_1.note.clone(),
            sk_out_1: note_out_1.ephemeral_sk,
            note_out_2: note_out_2.note.clone(),
            sk_out_2: note_out_2.ephemeral_sk,
        };

        let proof_data = self
            .prover
            .prove_split(&inputs)
            .await
            .map_err(|e| BuilderError::ProofGeneration(e.to_string()))?;

        let public_inputs = convert_public_inputs_to_bytes32(&proof_data.public_inputs)?;
        let nullifier_hash = extract_split_nullifier(&public_inputs)?;

        let calldata = encode_split_calldata(&proof_data.proof, &public_inputs);

        info!("Split proof generated: {} bytes", proof_data.proof.len());

        Ok(SplitProofBundle {
            proof: proof_data.proof,
            public_inputs,
            nullifier_hash,
            note_out_1: note_out_1.clone(),
            note_out_2: note_out_2.clone(),
            calldata,
        })
    }

    pub async fn build_join(
        &self,
        inputs_a: &SpendingInputs,
        inputs_b: &SpendingInputs,
        merkle_root: U256,
        note_out: &ChangeNoteResult,
        current_timestamp: u64,
    ) -> Result<JoinProofBundle, BuilderError> {
        info!(
            "Building join proof: value_a={} + value_b={} = {}",
            inputs_a.note.value, inputs_b.note.value, note_out.note.value
        );

        let inputs = JoinInputs {
            merkle_root,
            current_timestamp,
            compliance_pk: self.config.compliance_pk,
            note_a: inputs_a.note.clone(),
            secret_a: inputs_a.shared_secret,
            index_a: inputs_a.leaf_index,
            path_a: inputs_a.merkle_path.siblings_vec(),
            preimage_a: inputs_a.hashlock_preimage,
            note_b: inputs_b.note.clone(),
            secret_b: inputs_b.shared_secret,
            index_b: inputs_b.leaf_index,
            path_b: inputs_b.merkle_path.siblings_vec(),
            preimage_b: inputs_b.hashlock_preimage,
            note_out: note_out.note.clone(),
            sk_out: note_out.ephemeral_sk,
        };

        let proof_data = self
            .prover
            .prove_join(&inputs)
            .await
            .map_err(|e| BuilderError::ProofGeneration(e.to_string()))?;

        let public_inputs = convert_public_inputs_to_bytes32(&proof_data.public_inputs)?;

        let (nullifier_hash_a, nullifier_hash_b) = extract_join_nullifiers(&public_inputs)?;

        let calldata = encode_join_calldata(&proof_data.proof, &public_inputs);

        info!("Join proof generated: {} bytes", proof_data.proof.len());

        Ok(JoinProofBundle {
            proof: proof_data.proof,
            public_inputs,
            nullifier_hash_a,
            nullifier_hash_b,
            note_out: note_out.clone(),
            calldata,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn build_public_claim(
        &self,
        memo_id: U256,
        val: U256,
        asset_id: U256,
        timelock: U256,
        owner_pk: (U256, U256),
        salt: U256,
        recipient_sk: U256,
        note_out: &ChangeNoteResult,
    ) -> Result<PublicClaimProofBundle, BuilderError> {
        info!("Building public claim proof: memo_id={}", memo_id);

        let inputs = PublicClaimInputs {
            memo_id,
            compliance_pk: self.config.compliance_pk,
            val,
            asset_id,
            timelock,
            owner_x: owner_pk.0,
            owner_y: owner_pk.1,
            salt,
            recipient_sk,
            note_out: note_out.note.clone(),
            sk_out: note_out.ephemeral_sk,
        };

        let proof_data = self
            .prover
            .prove_public_claim(&inputs)
            .await
            .map_err(|e| BuilderError::ProofGeneration(e.to_string()))?;

        let public_inputs = convert_public_inputs_to_bytes32(&proof_data.public_inputs)?;
        let calldata = encode_public_claim_calldata(&proof_data.proof, &public_inputs);

        info!(
            "Public claim proof generated: {} bytes",
            proof_data.proof.len()
        );

        Ok(PublicClaimProofBundle {
            proof: proof_data.proof,
            public_inputs,
            note_out: note_out.clone(),
            calldata,
        })
    }
}

/// Convert hex string public inputs to bytes32 arrays
pub fn convert_public_inputs_to_bytes32(inputs: &[String]) -> Result<Vec<[u8; 32]>, BuilderError> {
    inputs
        .iter()
        .map(|input| {
            let hex_str = input.trim_start_matches("0x");
            let bytes = hex::decode(hex_str)
                .map_err(|e| BuilderError::Encoding(format!("Invalid hex: {e}")))?;

            if bytes.len() != 32 {
                return Err(BuilderError::Encoding(format!(
                    "Public input must be 32 bytes, got {}",
                    bytes.len()
                )));
            }

            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        })
        .collect()
}

/// Compute execution hash binding an action to a gas payment.
/// Result is reduced mod BN254 Fr so it's a valid ZK circuit field element.
pub fn compute_execution_hash(target: &Address, calldata: &Bytes, fee: &U256) -> H256 {
    use ethers::utils::keccak256;

    let mut data = Vec::new();
    data.extend_from_slice(target.as_bytes());
    data.extend_from_slice(calldata.as_ref());
    let mut fee_bytes = [0u8; 32];
    fee.to_big_endian(&mut fee_bytes);
    data.extend_from_slice(&fee_bytes);

    let hash = keccak256(&data);

    let hash_u256 = U256::from_big_endian(&hash);
    let reduced = hash_u256 % *BN254_MODULUS;

    let mut result_bytes = [0u8; 32];
    reduced.to_big_endian(&mut result_bytes);
    H256::from_slice(&result_bytes)
}

/// Reduces mod BJJ subgroup order L (~2^251), NOT BN254 Fr (~2^254).
/// Noir's `ScalarField::<63>` nibble decomposition requires values < 2^252.
fn generate_random_scalar() -> U256 {
    darkpool_crypto::random_bjj_scalar()
}

/// Encode a multicall bundle for the `RelayerMulticall` contract
pub fn encode_multicall(
    darkpool: Address,
    proof: &[u8],
    public_inputs: &[[u8; 32]],
    action_target: Address,
    action_calldata: Bytes,
) -> Result<Bytes, BuilderError> {
    // payRelayer selector: keccak256("payRelayer(bytes,bytes32[])")[:4]
    let proof_token = Token::Bytes(proof.to_vec());
    let inputs_token = Token::Array(
        public_inputs
            .iter()
            .map(|b| Token::FixedBytes(b.to_vec()))
            .collect(),
    );

    let pay_relayer_selector: [u8; 4] = [0x24, 0xfc, 0xf1, 0x31];
    let mut darkpool_calldata = pay_relayer_selector.to_vec();
    darkpool_calldata.extend(encode(&[proof_token, inputs_token]));

    let calls = vec![
        Token::Tuple(vec![
            Token::Address(darkpool),
            Token::Bytes(darkpool_calldata),
            Token::Uint(U256::zero()),
            Token::Bool(true),
        ]),
        Token::Tuple(vec![
            Token::Address(action_target),
            Token::Bytes(action_calldata.to_vec()),
            Token::Uint(U256::zero()),
            Token::Bool(true),
        ]),
    ];

    // multicall selector: 0xcffb5cd6
    let mut encoded = vec![0xcf, 0xfb, 0x5c, 0xd6];
    encoded.extend(encode(&[Token::Array(calls)]));

    Ok(Bytes::from(encoded))
}

/// No-op for `UltraHonk` proofs -- BB already outputs the correct format.
#[must_use]
pub fn format_proof_for_solidity(proof: &[u8]) -> Bytes {
    Bytes::from(proof.to_vec())
}

/// Alias for `convert_public_inputs_to_bytes32`
pub fn format_public_inputs_for_solidity(inputs: &[String]) -> Result<Vec<[u8; 32]>, BuilderError> {
    convert_public_inputs_to_bytes32(inputs)
}

/// Withdraw circuit: `nullifier_hash` at index 7.
fn extract_withdraw_nullifier(public_inputs: &[[u8; 32]]) -> Result<H256, BuilderError> {
    public_inputs
        .get(7)
        .map(|b| H256::from_slice(b))
        .ok_or_else(|| {
            BuilderError::Encoding(format!(
                "Withdraw public inputs too short: expected index 7, got length {}",
                public_inputs.len()
            ))
        })
}

/// Transfer circuit: `nullifier_hash` at index 8.
fn extract_transfer_nullifier(public_inputs: &[[u8; 32]]) -> Result<H256, BuilderError> {
    public_inputs
        .get(8)
        .map(|b| H256::from_slice(b))
        .ok_or_else(|| {
            BuilderError::Encoding(format!(
                "Transfer public inputs too short: expected index 8, got length {}",
                public_inputs.len()
            ))
        })
}

/// Join circuit: `nullifier_hash_a` at index 4, `nullifier_hash_b` at index 5.
fn extract_join_nullifiers(public_inputs: &[[u8; 32]]) -> Result<(H256, H256), BuilderError> {
    let a = public_inputs
        .get(4)
        .map(|b| H256::from_slice(b))
        .ok_or_else(|| {
            BuilderError::Encoding(format!(
                "Join public inputs too short: expected index 4, got length {}",
                public_inputs.len()
            ))
        })?;
    let b = public_inputs
        .get(5)
        .map(|b| H256::from_slice(b))
        .ok_or_else(|| {
            BuilderError::Encoding(format!(
                "Join public inputs too short: expected index 5, got length {}",
                public_inputs.len()
            ))
        })?;
    Ok((a, b))
}

/// Split circuit: `nullifier_hash` at index 4.
fn extract_split_nullifier(public_inputs: &[[u8; 32]]) -> Result<H256, BuilderError> {
    public_inputs
        .get(4)
        .map(|b| H256::from_slice(b))
        .ok_or_else(|| {
            BuilderError::Encoding(format!(
                "Split public inputs too short: expected index 4, got length {}",
                public_inputs.len()
            ))
        })
}

/// Gas payment circuit: `nullifier_hash` at index 8.
fn extract_gas_payment_nullifier(public_inputs: &[[u8; 32]]) -> Result<H256, BuilderError> {
    public_inputs
        .get(8)
        .map(|b| H256::from_slice(b))
        .ok_or_else(|| {
            BuilderError::Encoding(format!(
                "Gas payment public inputs too short: expected index 8, got length {}",
                public_inputs.len()
            ))
        })
}

/// Extract commitments from transfer circuit public inputs.
///
/// Layout: `[11-17]` `memo_packed_ct`, `[18]` `int_bob.x` (= `transfer_tag`), `[24-30]` `change_packed_ct`.
/// Commitments are Poseidon hashes of the packed ciphertexts.
fn extract_transfer_commitments(
    public_inputs_hex: &[String],
) -> Result<(U256, U256, U256), BuilderError> {
    use crate::crypto_helpers::poseidon_hash;

    if public_inputs_hex.len() < 31 {
        return Err(BuilderError::Encoding(format!(
            "Transfer proof needs at least 31 public inputs, got {}",
            public_inputs_hex.len()
        )));
    }

    let parse_hex = |idx: usize| -> Result<U256, BuilderError> {
        let hex_str = public_inputs_hex.get(idx).ok_or_else(|| {
            BuilderError::Encoding(format!("Missing public input at index {idx}"))
        })?;
        let clean = hex_str.trim_start_matches("0x");
        let padded = format!("{clean:0>64}");
        let bytes = hex::decode(&padded)
            .map_err(|e| BuilderError::Encoding(format!("Invalid hex at {idx}: {e}")))?;
        Ok(U256::from_big_endian(&bytes))
    };

    let memo_packed: Vec<U256> = (11..=17).map(parse_hex).collect::<Result<_, _>>()?;
    let change_packed: Vec<U256> = (24..=30).map(parse_hex).collect::<Result<_, _>>()?;

    let memo_commitment = poseidon_hash(&memo_packed);
    let change_commitment = poseidon_hash(&change_packed);
    let transfer_tag = parse_hex(18)?;

    Ok((memo_commitment, change_commitment, transfer_tag))
}

/// Encode ABI calldata for a `DarkPool` proof-verified function.
/// All share the shape: `function(bytes _proof, bytes32[] _publicInputs)`.
fn encode_calldata(fn_sig: &[u8], proof: &[u8], public_inputs: &[[u8; 32]]) -> Bytes {
    use ethers::utils::keccak256;

    let hash = keccak256(fn_sig);
    let selector = [hash[0], hash[1], hash[2], hash[3]];

    let proof_token = Token::Bytes(proof.to_vec());
    let inputs_token = Token::Array(
        public_inputs
            .iter()
            .map(|b| Token::FixedBytes(b.to_vec()))
            .collect(),
    );

    let mut calldata = selector.to_vec();
    calldata.extend(encode(&[proof_token, inputs_token]));

    Bytes::from(calldata)
}

fn encode_deposit_calldata(proof: &[u8], public_inputs: &[[u8; 32]]) -> Bytes {
    encode_calldata(b"deposit(bytes,bytes32[])", proof, public_inputs)
}

fn encode_withdraw_calldata(proof: &[u8], public_inputs: &[[u8; 32]]) -> Bytes {
    encode_calldata(b"withdraw(bytes,bytes32[])", proof, public_inputs)
}

fn encode_transfer_calldata(proof: &[u8], public_inputs: &[[u8; 32]]) -> Bytes {
    encode_calldata(b"privateTransfer(bytes,bytes32[])", proof, public_inputs)
}

fn encode_split_calldata(proof: &[u8], public_inputs: &[[u8; 32]]) -> Bytes {
    encode_calldata(b"split(bytes,bytes32[])", proof, public_inputs)
}

fn encode_join_calldata(proof: &[u8], public_inputs: &[[u8; 32]]) -> Bytes {
    encode_calldata(b"join(bytes,bytes32[])", proof, public_inputs)
}

fn encode_public_claim_calldata(proof: &[u8], public_inputs: &[[u8; 32]]) -> Bytes {
    encode_calldata(b"publicClaim(bytes,bytes32[])", proof, public_inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_hash() {
        let target = Address::zero();
        let calldata = Bytes::from(vec![1, 2, 3, 4]);
        let fee = U256::from(1000);

        let hash = compute_execution_hash(&target, &calldata, &fee);

        let hash2 = compute_execution_hash(&target, &calldata, &fee);
        assert_eq!(hash, hash2);

        let hash3 = compute_execution_hash(&target, &calldata, &U256::from(1001));
        assert_ne!(hash, hash3);
    }

    /// ~75% of raw keccak256 outputs overflow BN254 Fr; verify reduction is always applied.
    #[test]
    fn test_keccak256_bn254_reduction() {
        let bn254_modulus = *BN254_MODULUS;

        for i in 0u64..50 {
            let target = Address::from_slice(&{
                let mut b = [0u8; 20];
                b[..8].copy_from_slice(&i.to_le_bytes());
                b
            });
            let calldata = Bytes::from(i.to_le_bytes().to_vec());
            let fee = U256::from(i * 1_000_000u64);

            let hash = compute_execution_hash(&target, &calldata, &fee);
            let hash_as_u256 = U256::from_big_endian(hash.as_bytes());

            assert!(
                hash_as_u256 < bn254_modulus,
                "compute_execution_hash output {hash_as_u256} >= BN254_MODULUS for input i={i}"
            );
        }
    }

    #[test]
    fn test_convert_public_inputs() {
        let inputs = vec![
            "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000002".to_string(),
        ];

        let result = convert_public_inputs_to_bytes32(&inputs).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0][31], 1);
        assert_eq!(result[1][31], 2);
    }

    #[test]
    fn test_encode_multicall() {
        let darkpool = Address::random();
        let proof = vec![0u8; 100];
        let public_inputs = vec![[0u8; 32]; 5];
        let action_target = Address::random();
        let action_calldata = Bytes::from(vec![1, 2, 3, 4]);

        let result = encode_multicall(
            darkpool,
            &proof,
            &public_inputs,
            action_target,
            action_calldata,
        );

        assert!(result.is_ok());
        let encoded = result.unwrap();

        assert_eq!(&encoded[0..4], &[0xcf, 0xfb, 0x5c, 0xd6]);
    }
}
