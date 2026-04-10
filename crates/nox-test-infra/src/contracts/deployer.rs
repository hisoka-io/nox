//! Deploys all `DarkPool` protocol contracts to Anvil.

use ethers::abi::Abi;
use ethers::prelude::*;
use ethers::types::Bytes;
use regex::Regex;
use serde::Deserialize;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info};

use super::bindings::{DarkPool, MockERC20, NoxRewardPool, RelayerMulticall};

/// Hardhat library placeholder pattern: `__$<34 hex chars>$__`
#[allow(clippy::expect_used)]
static LIBRARY_PLACEHOLDER_RE: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new(r"__\$[a-fA-F0-9]{34}\$__").expect("Invalid regex"));

#[derive(Debug, Error)]
pub enum DeployError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Contract error: {0}")]
    Contract(String),
    #[error("Provider error: {0}")]
    Provider(String),
    #[error("Deployment failed: {0}")]
    DeploymentFailed(String),
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct HardhatArtifact {
    #[serde(rename = "contractName")]
    contract_name: String,
    abi: serde_json::Value,
    bytecode: String,
    #[serde(rename = "deployedBytecode")]
    deployed_bytecode: String,
    #[serde(rename = "linkReferences")]
    link_references: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct VerifierAddresses {
    pub deposit: Address,
    pub withdraw: Address,
    pub transfer: Address,
    pub join: Address,
    pub split: Address,
    pub public_claim: Address,
    pub gas_payment: Address,
}

pub struct DeployedContracts<M: Middleware> {
    pub darkpool: DarkPool<M>,
    pub reward_pool: NoxRewardPool<M>,
    pub multicall: RelayerMulticall<M>,
    pub token: MockERC20<M>,
    pub poseidon2_lib: Address,
    pub verifiers: VerifierAddresses,
}

pub struct CompliancePk {
    pub x: U256,
    pub y: U256,
}

pub struct ContractDeployer<M: Middleware> {
    client: Arc<M>,
    artifacts_path: String,
}

impl<M: Middleware + 'static> ContractDeployer<M> {
    pub fn new(client: Arc<M>, artifacts_path: &str) -> Self {
        Self {
            client,
            artifacts_path: artifacts_path.to_string(),
        }
    }

    pub async fn deploy_all(
        &self,
        compliance_pk: CompliancePk,
        owner: Address,
    ) -> Result<DeployedContracts<M>, DeployError> {
        info!("Starting contract deployment...");

        info!("  [1/10] Deploying Poseidon2 library...");
        let poseidon2_lib = self.deploy_poseidon2().await?;
        info!("         Poseidon2 deployed at: {:?}", poseidon2_lib);

        info!("  [2/10] Deploying DepositVerifier...");
        let deposit_verifier = self.deploy_verifier("DepositVerifier").await?;
        info!("         DepositVerifier at: {:?}", deposit_verifier);

        info!("  [3/10] Deploying WithdrawVerifier...");
        let withdraw_verifier = self.deploy_verifier("WithdrawVerifier").await?;
        info!("         WithdrawVerifier at: {:?}", withdraw_verifier);

        info!("  [4/10] Deploying TransferVerifier...");
        let transfer_verifier = self.deploy_verifier("TransferVerifier").await?;
        info!("         TransferVerifier at: {:?}", transfer_verifier);

        info!("  [5/10] Deploying JoinVerifier...");
        let join_verifier = self.deploy_verifier("JoinVerifier").await?;
        info!("         JoinVerifier at: {:?}", join_verifier);

        info!("  [6/10] Deploying SplitVerifier...");
        let split_verifier = self.deploy_verifier("SplitVerifier").await?;
        info!("         SplitVerifier at: {:?}", split_verifier);

        info!("  [7/10] Deploying PublicClaimVerifier...");
        let public_claim_verifier = self.deploy_verifier("PublicClaimVerifier").await?;
        info!(
            "         PublicClaimVerifier at: {:?}",
            public_claim_verifier
        );

        info!("  [8/10] Deploying GasPaymentVerifier...");
        let gas_payment_verifier = self.deploy_verifier("GasPaymentVerifier").await?;
        info!("         GasPaymentVerifier at: {:?}", gas_payment_verifier);

        let verifiers = VerifierAddresses {
            deposit: deposit_verifier,
            withdraw: withdraw_verifier,
            transfer: transfer_verifier,
            join: join_verifier,
            split: split_verifier,
            public_claim: public_claim_verifier,
            gas_payment: gas_payment_verifier,
        };

        info!("  [9/10] Deploying NoxRewardPool...");
        let reward_pool = NoxRewardPool::deploy(self.client.clone(), owner)
            .map_err(|e| DeployError::Contract(e.to_string()))?
            .send()
            .await
            .map_err(|e| DeployError::DeploymentFailed(e.to_string()))?;
        let reward_pool_addr = reward_pool.address();
        info!("         NoxRewardPool at: {:?}", reward_pool_addr);

        info!("  [10/10] Deploying DarkPool...");
        let darkpool = self
            .deploy_darkpool_with_lib(
                poseidon2_lib,
                &verifiers,
                reward_pool_addr,
                &compliance_pk,
                owner,
            )
            .await?;
        info!("         DarkPool at: {:?}", darkpool.address());

        info!("  [BONUS] Deploying MockERC20...");
        let token = MockERC20::deploy(
            self.client.clone(),
            ("Mock Token".to_string(), "MOCK".to_string(), 18u8),
        )
        .map_err(|e| DeployError::Contract(e.to_string()))?
        .send()
        .await
        .map_err(|e| DeployError::DeploymentFailed(e.to_string()))?;
        info!("         MockERC20 at: {:?}", token.address());

        reward_pool
            .set_asset_status(token.address(), true)
            .send()
            .await
            .map_err(|e| DeployError::Contract(e.to_string()))?;

        info!("  [BONUS] Deploying RelayerMulticall...");
        let multicall = RelayerMulticall::deploy(self.client.clone(), ())
            .map_err(|e| DeployError::Contract(e.to_string()))?
            .send()
            .await
            .map_err(|e| DeployError::DeploymentFailed(e.to_string()))?;
        info!("         RelayerMulticall at: {:?}", multicall.address());

        info!("All contracts deployed successfully!");

        Ok(DeployedContracts {
            darkpool,
            reward_pool,
            multicall,
            token,
            poseidon2_lib,
            verifiers,
        })
    }

    async fn deploy_poseidon2(&self) -> Result<Address, DeployError> {
        let artifact_path = format!(
            "{}/contracts/Poseidon/Poseidon2.sol/Poseidon2.json",
            self.artifacts_path
        );
        let bytecode = self.read_bytecode(&artifact_path)?;

        let tx = TransactionRequest::new().data(bytecode);
        let pending = self
            .client
            .send_transaction(tx, None)
            .await
            .map_err(|e| DeployError::Provider(e.to_string()))?;

        let receipt = pending
            .await
            .map_err(|e| DeployError::Provider(e.to_string()))?
            .ok_or_else(|| DeployError::DeploymentFailed("No receipt for Poseidon2".into()))?;

        receipt
            .contract_address
            .ok_or_else(|| DeployError::DeploymentFailed("No contract address in receipt".into()))
    }

    async fn deploy_verifier(&self, verifier_name: &str) -> Result<Address, DeployError> {
        let verifier_path = format!(
            "{}/contracts/verifiers/{}.sol/HonkVerifier.json",
            self.artifacts_path, verifier_name
        );
        let bytecode = self.read_bytecode(&verifier_path)?;

        let tx = TransactionRequest::new().data(bytecode);
        let pending = self
            .client
            .send_transaction(tx, None)
            .await
            .map_err(|e| DeployError::Provider(e.to_string()))?;

        let receipt = pending
            .await
            .map_err(|e| DeployError::Provider(e.to_string()))?
            .ok_or_else(|| {
                DeployError::DeploymentFailed(format!("No receipt for {verifier_name}"))
            })?;

        receipt.contract_address.ok_or_else(|| {
            DeployError::DeploymentFailed(format!("No contract address for {verifier_name}"))
        })
    }

    async fn deploy_darkpool_with_lib(
        &self,
        poseidon2_lib: Address,
        verifiers: &VerifierAddresses,
        reward_pool: Address,
        compliance_pk: &CompliancePk,
        owner: Address,
    ) -> Result<DarkPool<M>, DeployError> {
        let artifact_path = format!(
            "{}/contracts/DarkPool.sol/DarkPool.json",
            self.artifacts_path
        );
        let mut bytecode_hex = self.read_bytecode_raw(&artifact_path)?;

        let lib_addr_hex = format!("{poseidon2_lib:x}").to_lowercase();
        bytecode_hex = self.link_library(&bytecode_hex, "Poseidon2", &lib_addr_hex);

        let artifact: HardhatArtifact =
            serde_json::from_str(&std::fs::read_to_string(&artifact_path)?)?;
        let abi: Abi = serde_json::from_value(artifact.abi)?;

        let _constructor = abi
            .constructor()
            .ok_or_else(|| DeployError::Contract("DarkPool has no constructor".into()))?;

        let args = ethers::abi::encode(&[
            ethers::abi::Token::Address(verifiers.deposit),
            ethers::abi::Token::Address(verifiers.withdraw),
            ethers::abi::Token::Address(verifiers.transfer),
            ethers::abi::Token::Address(verifiers.join),
            ethers::abi::Token::Address(verifiers.split),
            ethers::abi::Token::Address(verifiers.public_claim),
            ethers::abi::Token::Address(verifiers.gas_payment),
            ethers::abi::Token::Address(reward_pool),
            ethers::abi::Token::Uint(compliance_pk.x),
            ethers::abi::Token::Uint(compliance_pk.y),
            ethers::abi::Token::Address(owner),
        ]);

        let mut deploy_data = hex::decode(&bytecode_hex)
            .map_err(|e| DeployError::Contract(format!("Invalid hex: {e}")))?;
        deploy_data.extend(args);

        let tx = TransactionRequest::new().data(Bytes::from(deploy_data));
        let pending = self
            .client
            .send_transaction(tx, None)
            .await
            .map_err(|e| DeployError::Provider(e.to_string()))?;

        let receipt = pending
            .await
            .map_err(|e| DeployError::Provider(e.to_string()))?
            .ok_or_else(|| DeployError::DeploymentFailed("No receipt for DarkPool".into()))?;

        let address = receipt.contract_address.ok_or_else(|| {
            DeployError::DeploymentFailed("No contract address for DarkPool".into())
        })?;

        Ok(DarkPool::new(address, self.client.clone()))
    }

    fn read_bytecode(&self, path: &str) -> Result<Bytes, DeployError> {
        let bytecode_hex = self.read_bytecode_raw(path)?;
        let bytes = hex::decode(&bytecode_hex)
            .map_err(|e| DeployError::Contract(format!("Invalid hex bytecode: {e}")))?;
        Ok(Bytes::from(bytes))
    }

    fn read_bytecode_raw(&self, path: &str) -> Result<String, DeployError> {
        let content = std::fs::read_to_string(path)?;
        let artifact: HardhatArtifact = serde_json::from_str(&content)?;
        let bytecode = artifact
            .bytecode
            .strip_prefix("0x")
            .unwrap_or(&artifact.bytecode);
        Ok(bytecode.to_string())
    }

    fn link_library(&self, bytecode: &str, lib_name: &str, lib_addr: &str) -> String {
        let padded_addr = format!("{lib_addr:0>40}");

        let result = LIBRARY_PLACEHOLDER_RE.replace_all(bytecode, padded_addr.as_str());
        debug!("Linked library '{}' -> {}", lib_name, padded_addr);

        result.into_owned()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_link_library() {
        let placeholder_re = regex::Regex::new(r"__\$[a-fA-F0-9]{34}\$__").unwrap();
        let padded_addr = format!("{:0>40}", "aabbccdd");

        let bytecode = "608060__$1234567890abcdef1234567890abcdef12$__4052";
        let linked = placeholder_re
            .replace_all(bytecode, padded_addr.as_str())
            .into_owned();

        assert!(!linked.contains("__$"));
        assert!(linked.contains("00000000000000000000000000000000aabbccdd"));
    }
}
