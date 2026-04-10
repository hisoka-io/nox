//! Persistent Node.js prover subprocess with cached WASM initialization.
//! Communicates via JSON-line protocol over stdin/stdout.

use crate::noir_prover::NoirProver;
use crate::{validate_circuit_name, WORKSPACE_ROOT};
use async_trait::async_trait;
use nox_core::traits::interfaces::{IProverService, InfrastructureError, ZKProofData};
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

pub struct ProverWorker {
    stdin: Mutex<tokio::process::ChildStdin>,
    stdout: Mutex<BufReader<tokio::process::ChildStdout>>,
    child: Mutex<tokio::process::Child>,
}

#[derive(serde::Deserialize)]
struct WorkerResponse {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    proof_hex: Option<String>,
    #[serde(default)]
    public_inputs: Option<Vec<String>>,
    #[serde(default)]
    error: Option<String>,
}

impl ProverWorker {
    /// Spawn a persistent prover worker process.
    pub async fn spawn(skip_verify: bool) -> Result<Self, InfrastructureError> {
        let workspace_root = WORKSPACE_ROOT
            .as_ref()
            .map_err(|e| InfrastructureError::Network(e.clone()))?;

        let script_path = workspace_root.join("scripts/prover/prove_worker.mjs");

        let mut cmd = Command::new("node");
        cmd.arg(&script_path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        if skip_verify {
            cmd.env("SKIP_VERIFY", "1");
        }

        let mut child = cmd.spawn().map_err(|e| {
            InfrastructureError::Network(format!(
                "Failed to spawn prover worker (node binary missing?): {e}"
            ))
        })?;

        let stdin = child.stdin.take().ok_or_else(|| {
            InfrastructureError::Network("Failed to capture worker stdin".to_string())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            InfrastructureError::Network("Failed to capture worker stdout".to_string())
        })?;
        let mut reader = BufReader::new(stdout);

        let mut ready_line = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            reader.read_line(&mut ready_line),
        )
        .await
        .map_err(|_| {
            InfrastructureError::Network(
                "Prover worker did not send ready signal within 30s".to_string(),
            )
        })?
        .map_err(|e| {
            InfrastructureError::Network(format!("Failed to read worker ready signal: {e}"))
        })?;

        let ready_resp: WorkerResponse = serde_json::from_str(ready_line.trim()).map_err(|e| {
            InfrastructureError::Network(format!(
                "Invalid worker ready signal: {e} (got: {ready_line})"
            ))
        })?;

        if ready_resp.status.as_deref() != Some("ready") {
            return Err(InfrastructureError::Network(format!(
                "Worker sent unexpected ready signal: {ready_line}"
            )));
        }

        info!("ProverWorker: persistent Node.js prover ready (skip_verify={skip_verify})");

        Ok(Self {
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(reader),
            child: Mutex::new(child),
        })
    }

    async fn prove_via_worker(
        &self,
        circuit_name: &str,
        inputs: HashMap<String, String>,
    ) -> Result<ZKProofData, InfrastructureError> {
        validate_circuit_name(circuit_name)?;

        let json_inputs = NoirProver::convert_inputs_to_json(&inputs);

        let cmd = serde_json::json!({
            "cmd": "prove",
            "circuit": circuit_name,
            "inputs": json_inputs,
        });

        let cmd_str = format!(
            "{}\n",
            serde_json::to_string(&cmd).map_err(|e| {
                InfrastructureError::Network(format!("Failed to serialize prove command: {e}"))
            })?
        );

        debug!(
            "ProverWorker: sending prove request for {circuit_name} ({} bytes)",
            cmd_str.len()
        );

        let mut stdin = self.stdin.lock().await;
        let mut stdout = self.stdout.lock().await;

        stdin.write_all(cmd_str.as_bytes()).await.map_err(|e| {
            InfrastructureError::Network(format!("Failed to write to worker stdin: {e}"))
        })?;
        stdin.flush().await.map_err(|e| {
            InfrastructureError::Network(format!("Failed to flush worker stdin: {e}"))
        })?;

        let mut response_line = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(120),
            stdout.read_line(&mut response_line),
        )
        .await
        .map_err(|_| {
            InfrastructureError::Network(format!(
                "ProverWorker timed out after 120s for circuit '{circuit_name}'"
            ))
        })?
        .map_err(|e| {
            InfrastructureError::Network(format!("Failed to read worker response: {e}"))
        })?;

        if response_line.is_empty() {
            return Err(InfrastructureError::Network(
                "ProverWorker process closed stdout unexpectedly (worker may have crashed)"
                    .to_string(),
            ));
        }

        let resp: WorkerResponse = serde_json::from_str(response_line.trim()).map_err(|e| {
            InfrastructureError::Network(format!(
                "Failed to parse worker response: {e} (got: {response_line})"
            ))
        })?;

        if !resp.success {
            return Err(InfrastructureError::Network(format!(
                "ProverWorker failed for '{}': {}",
                circuit_name,
                resp.error.unwrap_or_else(|| "Unknown error".to_string())
            )));
        }

        let proof_hex = resp.proof_hex.ok_or_else(|| {
            InfrastructureError::Network("Missing proof_hex in worker response".to_string())
        })?;
        let proof_bytes = hex::decode(proof_hex.trim_start_matches("0x")).map_err(|e| {
            InfrastructureError::Network(format!("Failed to decode proof hex: {e}"))
        })?;

        let public_inputs = resp.public_inputs.ok_or_else(|| {
            InfrastructureError::Network("Missing public_inputs in worker response".to_string())
        })?;

        info!(
            "ProverWorker: {} proof generated ({} bytes, {} public inputs)",
            circuit_name,
            proof_bytes.len(),
            public_inputs.len()
        );

        Ok(ZKProofData {
            proof: proof_bytes,
            public_inputs,
        })
    }

    pub async fn shutdown(&self) {
        let shutdown_cmd = "{\"cmd\":\"shutdown\"}\n";
        let mut stdin = self.stdin.lock().await;
        if let Err(e) = stdin.write_all(shutdown_cmd.as_bytes()).await {
            warn!("ProverWorker: failed to send shutdown command: {e}");
        }
        let _ = stdin.flush().await;

        let mut child = self.child.lock().await;
        match tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await {
            Ok(Ok(status)) => info!("ProverWorker: exited with {status}"),
            Ok(Err(e)) => warn!("ProverWorker: wait error: {e}"),
            Err(_) => {
                warn!("ProverWorker: did not exit within 5s, killing");
                let _ = child.kill().await;
            }
        }
    }
}

#[async_trait]
impl IProverService for ProverWorker {
    async fn prove(
        &self,
        circuit_name: &str,
        inputs: HashMap<String, String>,
    ) -> Result<ZKProofData, InfrastructureError> {
        self.prove_via_worker(circuit_name, inputs).await
    }
}
