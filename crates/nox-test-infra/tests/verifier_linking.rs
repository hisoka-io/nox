//! Verifies that the vendored `HonkVerifier` artifacts actually deploy.
//!
//! Each `*Verifier.sol` also defines a `ZKTranscriptLib` with external
//! functions, so the compiled `HonkVerifier` carries an unlinked
//! `__$<34 hex>$__` library placeholder. Deploying that bytecode as-is fails
//! hex decoding. `ContractDeployer` deploys the library first and substitutes
//! its address; this test pins that behaviour.
//!
//! Deliberately lives in `nox-test-infra`, which does not depend on
//! `nox-prover`. The root-crate tests that cover the same ground link
//! barretenberg, which needs a newer glibc/libstdc++ than some dev machines
//! have, so they cannot run everywhere. This one only needs anvil.

use ethers::prelude::*;
use ethers::utils::Anvil;
use std::sync::Arc;

const VERIFIERS: &[&str] = &[
    "DepositVerifier",
    "WithdrawVerifier",
    "TransferVerifier",
    "JoinVerifier",
    "SplitVerifier",
    "PublicClaimVerifier",
    "GasPaymentVerifier",
];

/// Artifacts live at the workspace root, two levels above this crate.
fn artifacts_path() -> String {
    format!("{}/../../artifacts", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn vendored_verifier_bytecode_carries_a_library_placeholder() {
    // Guards the premise of the linking code: if upstream ever ships verifiers
    // with the library inlined, the substitution becomes dead and this test
    // says so rather than silently passing.
    let mut found = 0;
    for name in VERIFIERS {
        let path = format!(
            "{}/contracts/verifiers/{name}.sol/HonkVerifier.json",
            artifacts_path()
        );
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let json: serde_json::Value = serde_json::from_str(&raw).expect("valid artifact JSON");
        let bytecode = json["bytecode"].as_str().expect("bytecode field");

        assert!(
            std::path::Path::new(&format!(
                "{}/contracts/verifiers/{name}.sol/ZKTranscriptLib.json",
                artifacts_path()
            ))
            .exists(),
            "{name}: ZKTranscriptLib.json must be vendored alongside HonkVerifier.json"
        );

        if bytecode.contains("__$") {
            found += 1;
        }
    }
    assert_eq!(
        found,
        VERIFIERS.len(),
        "expected every vendored verifier to carry an unlinked library placeholder"
    );
}

#[tokio::test]
#[ignore = "requires anvil on PATH"]
async fn all_vendored_verifiers_deploy_with_linked_library() {
    // HonkVerifier exceeds the EIP-170 24KB limit.
    let anvil = Anvil::new().args(["--code-size-limit", "32768"]).spawn();
    let provider = Provider::<Http>::try_from(anvil.endpoint()).expect("connect to anvil");
    let wallet: LocalWallet = anvil.keys()[0].clone().into();
    let wallet = wallet.with_chain_id(anvil.chain_id());
    let client = Arc::new(SignerMiddleware::new(provider, wallet));

    let deployer =
        nox_test_infra::contracts::ContractDeployer::new(client.clone(), &artifacts_path());

    for name in VERIFIERS {
        let address = deployer
            .deploy_verifier(name)
            .await
            .unwrap_or_else(|e| panic!("{name} failed to deploy: {e:?}"));

        let code = client
            .get_code(address, None)
            .await
            .unwrap_or_else(|e| panic!("{name}: get_code failed: {e}"));

        assert!(
            !code.is_empty(),
            "{name} deployed to {address:?} but has no code"
        );
        println!("{name} deployed at {address:?} ({} bytes)", code.len());
    }
}
