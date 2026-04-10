//! Native Rust ZK prover via `noir_rs` + barretenberg FFI.
//! Uses `prove_ultra_honk_keccak()` for EVM-compatible proofs.

use async_trait::async_trait;
use noir_rs::barretenberg::{
    prove::prove_ultra_honk_keccak, srs::setup_srs, verify::get_ultra_honk_keccak_verification_key,
};
use noir_rs::witness::from_vec_str_to_witness_map;
use nox_core::traits::interfaces::{IProverService, InfrastructureError, ZKProofData};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

const FIELD_ELEMENT_SIZE: usize = 32;
const PUBLIC_INPUT_COUNT_PREFIX_SIZE: usize = 4;

struct CircuitData {
    bytecode: String,
    abi_params: Vec<AbiParam>,
    #[allow(dead_code)]
    num_public_inputs: usize,
    vk: Vec<u8>,
}

#[derive(Debug, Clone)]
struct AbiParam {
    name: String,
    typ: AbiType,
    #[allow(dead_code)]
    visibility: AbiVisibility,
}

#[derive(Debug, Clone)]
enum AbiType {
    Field,
    Integer,
    Boolean,
    Struct(Vec<AbiField>),
    Array {
        length: usize,
        element: Box<AbiType>,
    },
    Tuple(Vec<AbiType>),
    String {
        length: usize,
    },
}

#[derive(Debug, Clone)]
struct AbiField {
    name: String,
    typ: AbiType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AbiVisibility {
    Public,
    Private,
}

pub struct NativeProver {
    circuits: HashMap<String, Arc<CircuitData>>,
}

impl NativeProver {
    /// Load circuit artifacts from `circuits_dir` (`{name}.json` from `nargo compile`).
    pub fn new(circuits_dir: &Path) -> Result<Self, InfrastructureError> {
        let circuit_names = super::ALLOWED_CIRCUITS;
        let mut circuits = HashMap::new();
        let srs_path: Option<&str> = None; // auto-download

        for name in circuit_names {
            let json_path = circuits_dir.join(format!("{name}.json"));
            if !json_path.exists() {
                warn!(
                    "NativeProver: circuit artifact not found: {}",
                    json_path.display()
                );
                continue;
            }

            let json_str = std::fs::read_to_string(&json_path).map_err(|e| {
                InfrastructureError::Network(format!(
                    "Failed to read circuit artifact {}: {e}",
                    json_path.display()
                ))
            })?;

            let json: serde_json::Value = serde_json::from_str(&json_str).map_err(|e| {
                InfrastructureError::Network(format!(
                    "Failed to parse circuit JSON {}: {e}",
                    json_path.display()
                ))
            })?;

            let bytecode = json["bytecode"]
                .as_str()
                .ok_or_else(|| {
                    InfrastructureError::Network(format!("Missing 'bytecode' field in {name}.json"))
                })?
                .to_string();

            // Parse ABI parameters
            let abi_params = Self::parse_abi_params(&json["abi"]["parameters"])?;
            let num_public_inputs = Self::count_public_inputs(&abi_params, &json["abi"]);

            // Setup SRS for this circuit.
            // Use explicit size (2^18 = 262144) to handle large circuits like split/transfer.
            // setup_srs_from_bytecode sometimes underestimates the required size.
            let min_srs_size: u32 = 1 << 18; // 262144 -- covers all circuits up to ~260K gates
            setup_srs(min_srs_size, srs_path).map_err(|e| {
                InfrastructureError::Network(format!("SRS setup failed for {name}: {e}"))
            })?;

            // Compute and cache VK
            let vk = get_ultra_honk_keccak_verification_key(&bytecode, true, false, None).map_err(
                |e| InfrastructureError::Network(format!("VK generation failed for {name}: {e}")),
            )?;

            info!(
                "NativeProver: loaded circuit '{}' ({} input fields, {} public, VK {} bytes)",
                name,
                Self::count_input_fields(&abi_params),
                num_public_inputs,
                vk.len()
            );

            circuits.insert(
                (*name).to_string(),
                Arc::new(CircuitData {
                    bytecode,
                    abi_params,
                    num_public_inputs,
                    vk,
                }),
            );
        }

        if circuits.is_empty() {
            return Err(InfrastructureError::Network(format!(
                "NativeProver: no circuit artifacts found in {}",
                circuits_dir.display()
            )));
        }

        info!("NativeProver: initialized with {} circuits", circuits.len());
        Ok(Self { circuits })
    }

    fn parse_abi_params(params: &serde_json::Value) -> Result<Vec<AbiParam>, InfrastructureError> {
        let arr = params.as_array().ok_or_else(|| {
            InfrastructureError::Network("ABI parameters is not an array".to_string())
        })?;

        arr.iter().map(Self::parse_one_param).collect()
    }

    fn parse_one_param(val: &serde_json::Value) -> Result<AbiParam, InfrastructureError> {
        let name = val["name"].as_str().unwrap_or("unknown").to_string();
        let visibility = match val["visibility"].as_str() {
            Some("public") => AbiVisibility::Public,
            _ => AbiVisibility::Private,
        };
        let typ = Self::parse_abi_type(&val["type"])?;
        Ok(AbiParam {
            name,
            typ,
            visibility,
        })
    }

    fn parse_abi_type(val: &serde_json::Value) -> Result<AbiType, InfrastructureError> {
        let kind = val["kind"].as_str().ok_or_else(|| {
            InfrastructureError::Network(format!("Missing 'kind' in ABI type: {val}"))
        })?;

        match kind {
            "field" => Ok(AbiType::Field),
            "integer" => Ok(AbiType::Integer),
            "boolean" => Ok(AbiType::Boolean),
            "string" => {
                let length = val["length"].as_u64().unwrap_or(0) as usize;
                Ok(AbiType::String { length })
            }
            "struct" => {
                let fields = val["fields"]
                    .as_array()
                    .ok_or_else(|| {
                        InfrastructureError::Network("struct missing fields array".to_string())
                    })?
                    .iter()
                    .map(|f| {
                        let fname = f["name"].as_str().unwrap_or("").to_string();
                        let ftype = Self::parse_abi_type(&f["type"])?;
                        Ok(AbiField {
                            name: fname,
                            typ: ftype,
                        })
                    })
                    .collect::<Result<Vec<_>, InfrastructureError>>()?;
                Ok(AbiType::Struct(fields))
            }
            "array" => {
                let length = val["length"].as_u64().unwrap_or(0) as usize;
                let element = Self::parse_abi_type(&val["type"])?;
                Ok(AbiType::Array {
                    length,
                    element: Box::new(element),
                })
            }
            "tuple" => {
                let fields = val["fields"]
                    .as_array()
                    .ok_or_else(|| {
                        InfrastructureError::Network("tuple missing fields array".to_string())
                    })?
                    .iter()
                    .map(Self::parse_abi_type)
                    .collect::<Result<Vec<_>, InfrastructureError>>()?;
                Ok(AbiType::Tuple(fields))
            }
            other => {
                warn!("NativeProver: unknown ABI type kind '{other}', treating as field");
                Ok(AbiType::Field)
            }
        }
    }

    fn count_input_fields(params: &[AbiParam]) -> usize {
        params.iter().map(|p| Self::type_width(&p.typ)).sum()
    }

    fn count_public_inputs(params: &[AbiParam], abi: &serde_json::Value) -> usize {
        let param_public: usize = params
            .iter()
            .filter(|p| p.visibility == AbiVisibility::Public)
            .map(|p| Self::type_width(&p.typ))
            .sum();

        // Return type is always public
        let return_public = if let Some(ret) = abi.get("return_type") {
            if let Ok(ret_type) = Self::parse_abi_type(&ret["abi_type"]) {
                Self::type_width(&ret_type)
            } else {
                0
            }
        } else {
            0
        };

        param_public + return_public
    }

    fn type_width(typ: &AbiType) -> usize {
        match typ {
            AbiType::Field | AbiType::Integer | AbiType::Boolean => 1,
            AbiType::String { length } => *length,
            AbiType::Struct(fields) => fields.iter().map(|f| Self::type_width(&f.typ)).sum(),
            AbiType::Array { length, element } => length * Self::type_width(element),
            AbiType::Tuple(fields) => fields.iter().map(Self::type_width).sum(),
        }
    }

    /// Flatten dot-notation inputs to ABI-ordered witness values.
    fn flatten_inputs(
        params: &[AbiParam],
        inputs: &HashMap<String, String>,
    ) -> Result<(HashMap<String, String>, Vec<String>), InfrastructureError> {
        // Pre-expand JSON array strings into indexed keys so flatten_type
        // can always use the simple `prefix.N` lookup path.
        let expanded = Self::expand_json_arrays(params, inputs)?;

        let mut values = Vec::new();

        for param in params {
            Self::collect_values(&param.name, &param.typ, &expanded, &mut values)?;
        }

        Ok((expanded, values))
    }

    /// Expand JSON array strings into indexed keys (e.g. `"key" -> "[...]"` to `"key.0"`, `"key.1"`).
    fn expand_json_arrays(
        params: &[AbiParam],
        inputs: &HashMap<String, String>,
    ) -> Result<HashMap<String, String>, InfrastructureError> {
        let mut expanded = inputs.clone();

        Self::expand_arrays_for_params(params, "", &mut expanded)?;

        Ok(expanded)
    }

    fn expand_arrays_for_params(
        params: &[AbiParam],
        parent_prefix: &str,
        expanded: &mut HashMap<String, String>,
    ) -> Result<(), InfrastructureError> {
        for param in params {
            let key = if parent_prefix.is_empty() {
                param.name.clone()
            } else {
                format!("{parent_prefix}.{}", param.name)
            };
            Self::expand_arrays_for_type(&key, &param.typ, expanded)?;
        }
        Ok(())
    }

    fn expand_arrays_for_type(
        key: &str,
        typ: &AbiType,
        expanded: &mut HashMap<String, String>,
    ) -> Result<(), InfrastructureError> {
        match typ {
            AbiType::Field | AbiType::Integer | AbiType::Boolean | AbiType::String { .. } => {}
            AbiType::Struct(fields) => {
                for field in fields {
                    let nested = format!("{key}.{}", field.name);
                    Self::expand_arrays_for_type(&nested, &field.typ, expanded)?;
                }
            }
            AbiType::Array { length, element } => {
                if let Some(arr_str) = expanded.get(key).cloned() {
                    if arr_str.starts_with('[') && arr_str.ends_with(']') {
                        let arr: Vec<String> = serde_json::from_str(&arr_str).map_err(|e| {
                            InfrastructureError::Network(format!(
                                "Failed to parse array input '{key}': {e}"
                            ))
                        })?;
                        if arr.len() != *length {
                            return Err(InfrastructureError::Network(format!(
                                "Array '{key}' has {} elements, expected {length}",
                                arr.len()
                            )));
                        }
                        expanded.remove(key);
                        for (i, val) in arr.into_iter().enumerate() {
                            expanded.insert(format!("{key}.{i}"), val);
                        }
                    }
                }
                for i in 0..*length {
                    let indexed = format!("{key}.{i}");
                    Self::expand_arrays_for_type(&indexed, element, expanded)?;
                }
            }
            AbiType::Tuple(fields) => {
                for (i, field_type) in fields.iter().enumerate() {
                    let indexed = format!("{key}.{i}");
                    Self::expand_arrays_for_type(&indexed, field_type, expanded)?;
                }
            }
        }
        Ok(())
    }

    fn collect_values(
        prefix: &str,
        typ: &AbiType,
        inputs: &HashMap<String, String>,
        values: &mut Vec<String>,
    ) -> Result<(), InfrastructureError> {
        match typ {
            AbiType::Field | AbiType::Integer | AbiType::Boolean => {
                let val = inputs.get(prefix).ok_or_else(|| {
                    InfrastructureError::Network(format!(
                        "Missing input field '{prefix}' (expected by circuit ABI)"
                    ))
                })?;
                values.push(val.clone());
            }
            AbiType::String { length } => {
                // String is an array of bytes
                for i in 0..*length {
                    let key = format!("{prefix}.{i}");
                    let val = inputs.get(&key).ok_or_else(|| {
                        InfrastructureError::Network(format!(
                            "Missing input field '{key}' (string byte {i})"
                        ))
                    })?;
                    values.push(val.clone());
                }
            }
            AbiType::Struct(fields) => {
                for field in fields {
                    let nested_key = format!("{prefix}.{}", field.name);
                    Self::collect_values(&nested_key, &field.typ, inputs, values)?;
                }
            }
            AbiType::Array { length, element } => {
                for i in 0..*length {
                    let indexed_key = format!("{prefix}.{i}");
                    Self::collect_values(&indexed_key, element, inputs, values)?;
                }
            }
            AbiType::Tuple(fields) => {
                for (i, field_type) in fields.iter().enumerate() {
                    let indexed_key = format!("{prefix}.{i}");
                    Self::collect_values(&indexed_key, field_type, inputs, values)?;
                }
            }
        }
        Ok(())
    }

    /// Split raw proof output: `[4B count BE][count * 32B public inputs][proof bytes]`.
    fn split_proof_output(raw: &[u8]) -> Result<(Vec<u8>, Vec<String>), InfrastructureError> {
        if raw.len() < PUBLIC_INPUT_COUNT_PREFIX_SIZE {
            return Err(InfrastructureError::Network(format!(
                "Proof output too short: {} bytes",
                raw.len()
            )));
        }

        let num_public: usize = u32::from_be_bytes(
            raw[..PUBLIC_INPUT_COUNT_PREFIX_SIZE]
                .try_into()
                .map_err(|_| {
                    InfrastructureError::Network(
                        "Failed to read public input count from proof".to_string(),
                    )
                })?,
        ) as usize;

        let pi_start = PUBLIC_INPUT_COUNT_PREFIX_SIZE;
        let pi_end = pi_start + num_public * FIELD_ELEMENT_SIZE;

        if raw.len() < pi_end {
            return Err(InfrastructureError::Network(format!(
                "Proof output too short for {} public inputs: {} bytes (need >= {})",
                num_public,
                raw.len(),
                pi_end
            )));
        }

        let mut public_inputs = Vec::with_capacity(num_public);
        for i in 0..num_public {
            let start = pi_start + i * FIELD_ELEMENT_SIZE;
            let end = start + FIELD_ELEMENT_SIZE;
            let hex_str = format!("0x{}", hex::encode(&raw[start..end]));
            public_inputs.push(hex_str);
        }

        let proof_bytes = raw[pi_end..].to_vec();

        Ok((proof_bytes, public_inputs))
    }
}

#[async_trait]
impl IProverService for NativeProver {
    async fn prove(
        &self,
        circuit_name: &str,
        inputs: HashMap<String, String>,
    ) -> Result<ZKProofData, InfrastructureError> {
        super::validate_circuit_name(circuit_name)?;

        let circuit = self.circuits.get(circuit_name).ok_or_else(|| {
            InfrastructureError::Network(format!(
                "Circuit '{circuit_name}' not loaded. Available: {:?}",
                self.circuits.keys().collect::<Vec<_>>()
            ))
        })?;

        let circuit = Arc::clone(circuit);
        let circuit_name_owned = circuit_name.to_string();

        let result = tokio::task::spawn_blocking(move || {
            let start = std::time::Instant::now();

            let (_expanded, flat_owned) = Self::flatten_inputs(&circuit.abi_params, &inputs)
                .map_err(|e| {
                    error!(
                        "NativeProver: witness flattening failed for '{}': {e}",
                        circuit_name_owned
                    );
                    e
                })?;

            debug!(
                "NativeProver: flattened {} inputs for '{}' ({} witness values)",
                inputs.len(),
                circuit_name_owned,
                flat_owned.len()
            );

            let flat_refs: Vec<&str> = flat_owned.iter().map(String::as_str).collect();
            let witness_map = from_vec_str_to_witness_map(flat_refs).map_err(|e| {
                InfrastructureError::Network(format!(
                    "Witness map construction failed for '{circuit_name_owned}': {e}"
                ))
            })?;

            let raw_proof = prove_ultra_honk_keccak(
                &circuit.bytecode,
                witness_map,
                circuit.vk.clone(),
                true,  // disable_zk = true (non-ZK verifier, smaller proofs)
                false, // low_memory_mode = false (desktop hardware)
                None,  // max_storage_usage (not needed)
            )
            .map_err(|e| {
                InfrastructureError::Network(format!(
                    "Proof generation failed for '{circuit_name_owned}': {e}"
                ))
            })?;

            let elapsed = start.elapsed();

            let (proof_bytes, public_inputs) = Self::split_proof_output(&raw_proof)?;

            info!(
                "NativeProver: '{}' proof generated in {:.2}s ({} bytes, {} public inputs)",
                circuit_name_owned,
                elapsed.as_secs_f64(),
                proof_bytes.len(),
                public_inputs.len()
            );

            Ok(ZKProofData {
                proof: proof_bytes,
                public_inputs,
            })
        })
        .await
        .map_err(|e| {
            InfrastructureError::Network(format!("Proof generation task panicked: {e}"))
        })??;

        Ok(result)
    }
}
