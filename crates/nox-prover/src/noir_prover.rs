//! One-shot Node.js subprocess prover. Use `ProverWorker` for persistent subprocess.

use crate::{validate_circuit_name, WORKSPACE_ROOT};
use async_trait::async_trait;
use nox_core::traits::interfaces::{IProverService, InfrastructureError, ZKProofData};
use std::collections::HashMap;
use tempfile::tempdir;
use tokio::process::Command;
use tracing::{debug, error, info};

pub struct NoirProver;

impl Default for NoirProver {
    fn default() -> Self {
        Self::new()
    }
}

impl NoirProver {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn with_default_circuits() -> Self {
        Self
    }
}

#[async_trait]
impl IProverService for NoirProver {
    async fn prove(
        &self,
        circuit_name: &str,
        inputs: HashMap<String, String>,
    ) -> Result<ZKProofData, InfrastructureError> {
        self.prove_internal(circuit_name, inputs).await
    }
}

impl NoirProver {
    async fn prove_internal(
        &self,
        circuit_name: &str,
        inputs: HashMap<String, String>,
    ) -> Result<ZKProofData, InfrastructureError> {
        validate_circuit_name(circuit_name)?;

        // bb CLI and bb.js produce different VK hashes -- must use bb.js
        let workspace_root = WORKSPACE_ROOT
            .as_ref()
            .map_err(|e| InfrastructureError::Network(e.clone()))?;

        let tmp = tempdir().map_err(|e| InfrastructureError::Network(e.to_string()))?;
        let inputs_json_path = tmp.path().join("inputs.json");
        let output_dir = tmp.path().join("output");
        tokio::fs::create_dir(&output_dir)
            .await
            .map_err(|e| InfrastructureError::Network(e.to_string()))?;

        let json_inputs = Self::convert_inputs_to_json(&inputs);
        let json_str = serde_json::to_string_pretty(&json_inputs).map_err(|e| {
            InfrastructureError::Network(format!("Failed to serialize inputs: {e}"))
        })?;

        tokio::fs::write(&inputs_json_path, &json_str)
            .await
            .map_err(|e| {
                InfrastructureError::Network(format!("Failed to write inputs.json: {e}"))
            })?;

        debug!(
            "ZK: Generated inputs.json ({} bytes) at {:?}",
            json_str.len(),
            inputs_json_path
        );

        let script_path = workspace_root.join("scripts/prover/prove_cli.mjs");

        let script_str = script_path
            .to_str()
            .ok_or_else(|| InfrastructureError::Network("Non-UTF8 script path".to_string()))?;
        let inputs_str = inputs_json_path
            .to_str()
            .ok_or_else(|| InfrastructureError::Network("Non-UTF8 inputs path".to_string()))?;
        let output_str = output_dir
            .to_str()
            .ok_or_else(|| InfrastructureError::Network("Non-UTF8 output path".to_string()))?;

        debug!("ZK: Calling Node.js prover bridge for {}...", circuit_name);

        let node_output = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            Command::new("node")
                .arg(script_str)
                .arg(circuit_name)
                .arg(inputs_str)
                .arg(output_str)
                .output(),
        )
        .await
        .map_err(|_| {
            InfrastructureError::Network(format!(
                "ZKP subprocess timed out after 120s for circuit '{circuit_name}'"
            ))
        })?
        .map_err(|e| InfrastructureError::Network(format!("Node binary missing: {e}")))?;

        let stderr = String::from_utf8_lossy(&node_output.stderr);

        if !node_output.status.success() {
            let stdout = String::from_utf8_lossy(&node_output.stdout);
            error!(
                "ZK: Node prover failed:\nSTDOUT: {}\nSTDERR: {}",
                stdout, stderr
            );
            return Err(InfrastructureError::Network(format!(
                "Node prover error: {stderr}"
            )));
        }

        #[derive(serde::Deserialize)]
        struct ProverResult {
            success: bool,
            #[allow(dead_code)]
            verified: Option<bool>,
            proof_hex: Option<String>,
            #[allow(dead_code)]
            proof_size: Option<usize>,
            public_inputs: Option<Vec<String>>,
            #[allow(dead_code)]
            public_inputs_count: Option<usize>,
            error: Option<String>,
        }

        let result_path = output_dir.join("result.json");
        let result_str = tokio::fs::read_to_string(&result_path).await.map_err(|e| {
            InfrastructureError::Network(format!("Failed to read result.json: {e}"))
        })?;

        let result: ProverResult = serde_json::from_str(&result_str).map_err(|e| {
            InfrastructureError::Network(format!(
                "Failed to parse prover result: {e} (content was: {result_str})"
            ))
        })?;

        if !result.success {
            return Err(InfrastructureError::Network(format!(
                "Prover failed: {}",
                result.error.unwrap_or_else(|| "Unknown error".to_string())
            )));
        }

        let proof_hex = result.proof_hex.ok_or_else(|| {
            InfrastructureError::Network("Missing proof_hex in result".to_string())
        })?;
        let proof_bytes = hex::decode(proof_hex.trim_start_matches("0x")).map_err(|e| {
            InfrastructureError::Network(format!("Failed to decode proof hex: {e}"))
        })?;

        let public_inputs = result.public_inputs.ok_or_else(|| {
            InfrastructureError::Network("Missing public_inputs in result".to_string())
        })?;

        info!(
            "ZK: Successfully generated {} byte proof for {} with {} public inputs (via bb.js)",
            proof_bytes.len(),
            circuit_name,
            public_inputs.len()
        );

        Ok(ZKProofData {
            proof: proof_bytes,
            public_inputs,
        })
    }

    /// Convert flat dot-notation inputs to nested JSON for bb.js.
    #[must_use]
    pub fn convert_inputs_to_json(inputs: &HashMap<String, String>) -> serde_json::Value {
        let mut root = serde_json::Map::new();

        for (key, value) in inputs {
            let json_value = if value.starts_with('[') && value.ends_with(']') {
                serde_json::from_str(value)
                    .unwrap_or_else(|_| serde_json::Value::String(value.clone()))
            } else {
                serde_json::Value::String(value.clone())
            };

            let segments: Vec<&str> = key.split('.').collect();
            Self::insert_nested(&mut root, &segments, json_value);
        }

        serde_json::Value::Object(root)
    }

    fn insert_nested(
        map: &mut serde_json::Map<String, serde_json::Value>,
        segments: &[&str],
        value: serde_json::Value,
    ) {
        match segments.len() {
            0 => {}
            1 => {
                map.insert(segments[0].to_string(), value);
            }
            _ => {
                let child = map
                    .entry(segments[0].to_string())
                    .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
                if let serde_json::Value::Object(child_map) = child {
                    Self::insert_nested(child_map, &segments[1..], value);
                }
            }
        }
    }
}
