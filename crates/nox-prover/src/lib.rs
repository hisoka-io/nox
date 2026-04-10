//! ZK proof generation for Noir circuits via native FFI, Node.js subprocess, or mock.

#[cfg(feature = "native-prover")]
mod native_prover;

mod noir_prover;
mod prover_worker;

#[cfg(any(test, feature = "mock-prover"))]
mod mock_prover;

#[cfg(feature = "native-prover")]
pub use native_prover::NativeProver;

pub use noir_prover::NoirProver;
pub use prover_worker::ProverWorker;

#[cfg(any(test, feature = "mock-prover"))]
pub use mock_prover::MockProver;

use nox_core::traits::interfaces::InfrastructureError;
use std::path::PathBuf;

/// Find the workspace root by looking for `Cargo.toml` with `[workspace]` or `.git`.
fn find_workspace_root() -> Result<PathBuf, std::io::Error> {
    let mut current = std::env::current_dir()?;

    loop {
        let cargo_toml = current.join("Cargo.toml");
        if cargo_toml.exists() {
            let content = std::fs::read_to_string(&cargo_toml)?;
            if content.contains("[workspace]") {
                return Ok(current);
            }
        }

        if current.join(".git").exists() {
            return Ok(current);
        }

        if !current.pop() {
            break;
        }
    }

    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let manifest_path = PathBuf::from(manifest_dir);
        if let Some(parent) = manifest_path.parent() {
            if let Some(grandparent) = parent.parent() {
                return Ok(grandparent.to_path_buf());
            }
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "Workspace root not found (no Cargo.toml with [workspace] or .git found)",
    ))
}

static WORKSPACE_ROOT: std::sync::LazyLock<Result<PathBuf, String>> =
    std::sync::LazyLock::new(|| {
        find_workspace_root().map_err(|e| format!("Failed to find workspace root: {e}"))
    });

/// Allowed circuit names (prevents path traversal/injection).
const ALLOWED_CIRCUITS: &[&str] = &[
    "deposit",
    "withdraw",
    "transfer",
    "join",
    "split",
    "public_claim",
    "gas_payment",
];

fn validate_circuit_name(circuit_name: &str) -> Result<(), InfrastructureError> {
    if ALLOWED_CIRCUITS.contains(&circuit_name) {
        Ok(())
    } else {
        Err(InfrastructureError::Network(format!(
            "Unknown circuit: '{circuit_name}'. Allowed: {ALLOWED_CIRCUITS:?}"
        )))
    }
}
