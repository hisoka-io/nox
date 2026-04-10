//! NativeProver parity: validates Rust/barretenberg FFI proofs verify on Solidity HonkVerifier.

use ethers::prelude::*;
use ethers::utils::Anvil;
use nox_core::traits::interfaces::IProverService;
use nox_prover::NativeProver;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

abigen!(
    HonkVerifier,
    r#"[
        function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool)
    ]"#
);

const ARTIFACTS_PATH: &str = "artifacts";
const CIRCUITS_PATH: &str = "circuits";

fn read_bytecode_hex(path: &str) -> String {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read artifact at {path}: {e}"));
    let json: serde_json::Value = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse artifact JSON at {path}: {e}"));
    let bytecode = json["bytecode"]
        .as_str()
        .unwrap_or_else(|| panic!("Missing 'bytecode' field in {path}"));
    bytecode.strip_prefix("0x").unwrap_or(bytecode).to_string()
}

async fn deploy_verifier<M: Middleware + 'static>(client: Arc<M>, verifier_name: &str) -> Address {
    let verifier_path =
        format!("{ARTIFACTS_PATH}/contracts/verifiers/{verifier_name}.sol/HonkVerifier.json");
    let verifier_hex = read_bytecode_hex(&verifier_path);
    let verifier_bytes =
        hex::decode(&verifier_hex).unwrap_or_else(|e| panic!("Bad hex in HonkVerifier: {e}"));

    let verifier_tx = TransactionRequest::new().data(Bytes::from(verifier_bytes));
    let verifier_pending = client
        .send_transaction(verifier_tx, None)
        .await
        .expect("Failed to send HonkVerifier deploy tx");
    let verifier_receipt = verifier_pending
        .await
        .expect("HonkVerifier tx failed")
        .expect("No receipt for HonkVerifier");
    verifier_receipt
        .contract_address
        .expect("No contract address for HonkVerifier")
}

/// Gas payment circuit inputs from Noir test vectors.
fn build_gas_payment_test_inputs() -> HashMap<String, String> {
    let mut map = HashMap::new();

    map.insert(
        "merkle_root".into(),
        "0x0ff0308384a3c8925230730c05830475189887fb31eda2d5f9b41508b7457289".into(),
    );
    map.insert(
        "current_timestamp".into(),
        "0x0000000000000000000000000000000000000000000000000000000000000000".into(),
    );
    map.insert(
        "payment_value".into(),
        "0x000000000000000000000000000000000000000000000000000000000000000a".into(),
    );
    map.insert(
        "payment_asset_id".into(),
        "0x0000000000000000000000001234567890123456789012345678901234567890".into(),
    );
    map.insert(
        "_relayer_address".into(),
        "0x0000000000000000000000001111222233334444555566667777888899990000".into(),
    );
    map.insert(
        "_execution_hash".into(),
        "0x000000000000000000000000000000000000000000000000abcdef1234567890".into(),
    );
    map.insert(
        "compliance_pubkey_x".into(),
        "0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111".into(),
    );
    map.insert(
        "compliance_pubkey_y".into(),
        "0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8".into(),
    );

    map.insert(
        "old_note.asset_id".into(),
        "0x0000000000000000000000001234567890123456789012345678901234567890".into(),
    );
    map.insert(
        "old_note.value".into(),
        "0x0000000000000000000000000000000000000000000000000000000000000064".into(),
    );
    map.insert(
        "old_note.secret".into(),
        "0x000000000000000000000000000000000000000000000000000000000000007b".into(),
    );
    map.insert(
        "old_note.nullifier".into(),
        "0x00000000000000000000000000000000000000000000000000000000000001c8".into(),
    );
    map.insert(
        "old_note.timelock".into(),
        "0x0000000000000000000000000000000000000000000000000000000000000000".into(),
    );
    map.insert(
        "old_note.hashlock".into(),
        "0x0000000000000000000000000000000000000000000000000000000000000000".into(),
    );

    map.insert(
        "old_shared_secret".into(),
        "0x2d304122ed971f99abcbe36e64fbcd0e770267ad7005912908d66ee8089ccdbd".into(),
    );
    map.insert(
        "old_note_index".into(),
        "0x0000000000000000000000000000000000000000000000000000000000000000".into(),
    );

    let zero = "0x0000000000000000000000000000000000000000000000000000000000000000";
    let path_items: Vec<String> = (0..32).map(|_| format!("\"{zero}\"")).collect();
    map.insert(
        "old_note_path".into(),
        format!("[{}]", path_items.join(", ")),
    );

    map.insert(
        "hashlock_preimage".into(),
        "0x0000000000000000000000000000000000000000000000000000000000000000".into(),
    );

    map.insert(
        "change_note.asset_id".into(),
        "0x0000000000000000000000001234567890123456789012345678901234567890".into(),
    );
    map.insert(
        "change_note.value".into(),
        "0x000000000000000000000000000000000000000000000000000000000000005a".into(),
    );
    map.insert(
        "change_note.secret".into(),
        "0x0000000000000000000000000000000000000000000000000000000000000315".into(),
    );
    map.insert(
        "change_note.nullifier".into(),
        "0x00000000000000000000000000000000000000000000000000000000000003f3".into(),
    );
    map.insert(
        "change_note.timelock".into(),
        "0x0000000000000000000000000000000000000000000000000000000000000000".into(),
    );
    map.insert(
        "change_note.hashlock".into(),
        "0x0000000000000000000000000000000000000000000000000000000000000000".into(),
    );

    map.insert(
        "change_ephemeral_sk".into(),
        "0x009e0df938f67eb7d4f4fa0f9c25ed14e2b6e0712d086fb6c8d330ab44e25cf3".into(),
    );

    map
}

fn public_inputs_to_bytes32(inputs: &[String]) -> Vec<[u8; 32]> {
    inputs
        .iter()
        .map(|s| {
            let stripped = s.strip_prefix("0x").unwrap_or(s);
            let bytes = hex::decode(stripped)
                .unwrap_or_else(|e| panic!("Bad hex in public input '{s}': {e}"));
            assert_eq!(
                bytes.len(),
                32,
                "Public input must be 32 bytes, got {}",
                bytes.len()
            );
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        })
        .collect()
}

#[tokio::test]
#[ignore] // Requires: anvil, circuit artifacts, Hardhat artifacts, SRS auto-download
async fn test_native_prover_gas_payment_verifies_on_chain() {
    let circuits_dir = Path::new(CIRCUITS_PATH);
    assert!(
        circuits_dir.join("gas_payment.json").exists(),
        "Circuit artifact not found at {CIRCUITS_PATH}/gas_payment.json. Ensure circuit artifacts are present in circuits/"
    );

    let artifacts_dir = Path::new(ARTIFACTS_PATH);
    assert!(
        artifacts_dir
            .join("contracts/verifiers/GasPaymentVerifier.sol/HonkVerifier.json")
            .exists(),
        "Hardhat verifier artifact not found. Ensure full Hardhat artifacts are available at {ARTIFACTS_PATH}"
    );

    println!("[1/5] Starting Anvil...");
    // HonkVerifier contracts exceed EIP-170 24KB limit
    let anvil = Anvil::new().args(["--code-size-limit", "32768"]).spawn();
    let provider =
        Provider::<Http>::try_from(anvil.endpoint()).expect("Failed to connect to Anvil");
    let wallet: LocalWallet = anvil.keys()[0].clone().into();
    let wallet = wallet.with_chain_id(anvil.chain_id());
    let client = Arc::new(SignerMiddleware::new(provider, wallet));
    println!("  Anvil running at {}", anvil.endpoint());

    println!("[2/5] Deploying GasPaymentVerifier...");
    let verifier_address = deploy_verifier(client.clone(), "GasPaymentVerifier").await;
    println!("  GasPaymentVerifier at: {verifier_address:?}");

    println!("[3/5] Initializing NativeProver...");
    // barretenberg FFI may create internal runtimes -- use blocking thread
    let circuits_dir_owned = circuits_dir.to_path_buf();
    let prover = tokio::task::spawn_blocking(move || {
        NativeProver::new(&circuits_dir_owned).expect("Failed to initialize NativeProver")
    })
    .await
    .expect("NativeProver init task panicked");

    let inputs = build_gas_payment_test_inputs();
    println!(
        "  Built {} input fields for gas_payment circuit",
        inputs.len()
    );

    println!("[4/5] Generating proof...");
    let start = std::time::Instant::now();
    let proof_data = prover
        .prove("gas_payment", inputs)
        .await
        .expect("Proof generation failed");
    let elapsed = start.elapsed();

    println!(
        "  Proof generated in {:.2}s: {} proof bytes, {} public inputs",
        elapsed.as_secs_f64(),
        proof_data.proof.len(),
        proof_data.public_inputs.len()
    );

    assert_eq!(
        proof_data.public_inputs[8], // nullifier_hash
        "0x2b5e2e032c8c028717d5c04dbc403bad8e40126798465625f58460fcd3e9d418",
        "Nullifier hash mismatch"
    );
    assert_eq!(
        proof_data.public_inputs[9], // change_epk_x
        "0x2ee2ede1573fde24114afe66be1f17ab11c778b6a9745613c8bda41d2494a8ed",
        "Change EPK X mismatch"
    );
    assert_eq!(
        proof_data.public_inputs[10], // change_epk_y
        "0x080e4cc68fd214da6254485d6c92b95531db466075319cd462b2ce48ae6332d2",
        "Change EPK Y mismatch"
    );

    assert_eq!(
        proof_data.public_inputs.len(),
        18,
        "Expected 18 public inputs for gas_payment circuit, got {}",
        proof_data.public_inputs.len()
    );

    println!("[5/5] Verifying proof on-chain...");

    let verifier = HonkVerifier::new(verifier_address, client.clone());
    let public_inputs_bytes32 = public_inputs_to_bytes32(&proof_data.public_inputs);
    let proof_len = proof_data.proof.len();

    let result = verifier
        .verify(proof_data.proof.into(), public_inputs_bytes32)
        .call()
        .await
        .expect("On-chain verify() call failed");

    assert!(
        result,
        "PARITY FAILURE: NativeProver proof was rejected by Solidity HonkVerifier"
    );

    println!("=== PARITY TEST PASSED ===");
    println!("  NativeProver (Rust/barretenberg FFI) proof verified by Solidity HonkVerifier");
    println!(
        "  Proof generation: {:.2}s | Proof size: {} bytes | Public inputs: 18",
        elapsed.as_secs_f64(),
        proof_len, // raw proof bytes only
    );
}
