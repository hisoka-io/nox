//! `MockProver` -- Instant mock for tests. DO NOT USE IN PRODUCTION.
//!
//! Gated behind `#[cfg(any(test, feature = "mock-prover"))]`.

use async_trait::async_trait;
use nox_core::traits::interfaces::{IProverService, InfrastructureError, ZKProofData};
use std::collections::HashMap;
use tracing::info;

pub struct MockProver;

impl Default for MockProver {
    fn default() -> Self {
        Self::new()
    }
}

impl MockProver {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl IProverService for MockProver {
    async fn prove(
        &self,
        circuit_name: &str,
        _inputs: HashMap<String, String>,
    ) -> Result<ZKProofData, InfrastructureError> {
        info!("ZK (MOCK): Generated instant proof for {}", circuit_name);
        Ok(ZKProofData {
            proof: vec![0u8; 2048],
            public_inputs: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{validate_circuit_name, ALLOWED_CIRCUITS};

    #[tokio::test]
    async fn test_mock_prover_returns_non_empty_proof() {
        let prover = MockProver::new();
        let result = prover.prove("deposit", HashMap::new()).await.unwrap();
        assert!(!result.proof.is_empty());
    }

    #[tokio::test]
    async fn test_mock_prover_proof_size_is_2048_bytes() {
        let prover = MockProver::new();
        let result = prover.prove("deposit", HashMap::new()).await.unwrap();
        assert_eq!(result.proof.len(), 2048);
    }

    #[tokio::test]
    async fn test_mock_prover_all_allowed_circuits_succeed() {
        let prover = MockProver::new();
        for &circuit in ALLOWED_CIRCUITS {
            let result = prover.prove(circuit, HashMap::new()).await;
            assert!(
                result.is_ok(),
                "circuit '{circuit}' returned {}",
                result.unwrap_err()
            );
        }
    }

    #[tokio::test]
    async fn test_mock_prover_is_deterministic() {
        // MockProver returns all-zero bytes -- same call twice = identical result
        let prover = MockProver::new();
        let r1 = prover.prove("withdraw", HashMap::new()).await.unwrap();
        let r2 = prover.prove("withdraw", HashMap::new()).await.unwrap();
        assert_eq!(r1.proof, r2.proof);
    }

    #[tokio::test]
    async fn test_mock_prover_public_inputs_is_empty() {
        let prover = MockProver::new();
        let result = prover.prove("transfer", HashMap::new()).await.unwrap();
        assert!(result.public_inputs.is_empty());
    }

    #[tokio::test]
    async fn test_mock_prover_accepts_inputs_without_error() {
        let prover = MockProver::new();
        let mut inputs = HashMap::new();
        inputs.insert("key1".to_string(), "0x1234".to_string());
        inputs.insert("key2".to_string(), "0xabcd".to_string());
        let result = prover.prove("join", inputs).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_circuit_name_allowed() {
        for &circuit in ALLOWED_CIRCUITS {
            assert!(
                validate_circuit_name(circuit).is_ok(),
                "rejected '{circuit}'"
            );
        }
    }

    #[test]
    fn test_validate_circuit_name_unknown_rejected() {
        let result = validate_circuit_name("../etc/passwd");
        assert!(result.is_err());

        let result = validate_circuit_name("unknown_circuit");
        assert!(result.is_err());
    }
}
