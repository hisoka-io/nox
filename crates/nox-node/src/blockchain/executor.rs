use alloy::consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy::eips::eip2718::Encodable2718;
use alloy::network::TxSignerSync;
use alloy::primitives::{keccak256, Address, Bytes, LogData, TxKind, B256, U256, U64};
use alloy::providers::Provider;
use alloy::rpc::json_rpc::ErrorPayload;
use alloy::rpc::types::trace::geth::{
    CallConfig, CallFrame, CallLogFrame, GethDebugTracingCallOptions, GethDebugTracingOptions,
};
use alloy::rpc::types::{Log, TransactionReceipt};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::transports::{RpcError, TransportError};
use nox_core::chain_rpc::{self, ChainProvider};
use std::borrow::Cow;
use std::str::FromStr;
#[cfg(feature = "dev-node")]
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::config::NoxConfig;
use nox_core::traits::InfrastructureError;

/// Provider for an operator-configured RPC URL (HTTP/1 only).
pub fn build_http1_provider(rpc_url: &str) -> Result<ChainProvider, InfrastructureError> {
    chain_rpc::http1_provider(rpc_url)
        .map_err(|error| InfrastructureError::Blockchain(error.to_string()))
}

/// Builds an HTTP/1 provider for a user-supplied RPC URL that already passed
/// the SSRF check. The client connects only to `pinned_ip` (the address that
/// was validated), never follows redirects and ignores proxy environment
/// variables, so a request cannot reach an address that was not validated.
pub fn build_pinned_http1_provider(
    url: &url::Url,
    pinned_ip: std::net::IpAddr,
) -> Result<ChainProvider, InfrastructureError> {
    chain_rpc::pinned_http1_provider(url, pinned_ip)
        .map_err(|error| InfrastructureError::Blockchain(error.to_string()))
}

/// Call object for `eth_call`, `eth_estimateGas` and `debug_traceCall`: a
/// legacy-typed request with the calldata under `data`, the field set the node
/// has always sent upstream.
#[must_use]
pub fn legacy_call_object(
    from: Option<Address>,
    to: Option<Address>,
    data: Option<&[u8]>,
    value: Option<U256>,
) -> serde_json::Value {
    let mut call = serde_json::Map::new();
    call.insert("type".into(), "0x00".into());
    if let Some(from) = from {
        call.insert("from".into(), format!("{from:?}").into());
    }
    if let Some(to) = to {
        call.insert("to".into(), format!("{to:?}").into());
    }
    if let Some(value) = value {
        call.insert("value".into(), format!("0x{value:x}").into());
    }
    if let Some(data) = data {
        call.insert("data".into(), format!("0x{}", hex::encode(data)).into());
    }
    serde_json::Value::Object(call)
}

/// Text of a JSON-RPC error object as clients receive it:
/// `(code: <code>, message: <message>, data: <data>)`.
#[must_use]
pub fn json_rpc_error_text(payload: &ErrorPayload) -> String {
    let data: Option<serde_json::Value> = payload
        .data
        .as_ref()
        .and_then(|raw| serde_json::from_str(raw.get()).ok());
    format!(
        "(code: {}, message: {}, data: {:?})",
        payload.code, payload.message, data
    )
}

/// Text of a provider error that is safe to return to an anonymous client.
///
/// A JSON-RPC error object from the upstream node (revert data, nonce errors)
/// is passed through. Transport and decoding errors are replaced by a fixed
/// message: their text can carry the upstream URL or raw response bodies.
#[must_use]
pub fn public_rpc_error(error: &TransportError) -> String {
    match error.as_error_resp() {
        Some(response) => json_rpc_error_text(response),
        None => "upstream RPC request failed".to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum OutboxBroadcastError {
    #[error("transaction is already known")]
    AlreadyKnown,
    #[error("transaction was rejected before acceptance: {detail}")]
    Rejected { detail: &'static str },
    #[error("transaction broadcast outcome is uncertain: {detail}")]
    Uncertain { detail: &'static str },
    /// The node already has a transaction at this nonce (mined or pending): the wallet
    /// signed elsewhere, or this transaction was mined earlier.
    #[error("transaction nonce is already used")]
    NonceTooLow,
    /// A different pending transaction holds this nonce at a higher gas price.
    #[error("another pending transaction holds this nonce")]
    ReplacementUnderpriced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SimulationBackendError {
    Unsupported {
        backend: &'static str,
    },
    Timeout {
        backend: &'static str,
    },
    Transport {
        backend: &'static str,
    },
    ResponseDecode {
        backend: &'static str,
    },
    ExecutionRejected {
        backend: &'static str,
    },
    EvidenceMalformed {
        backend: &'static str,
        field: &'static str,
    },
    IdentityMismatch {
        backend: &'static str,
        field: &'static str,
    },
    #[cfg_attr(
        not(feature = "dev-node"),
        allow(dead_code, reason = "receipt simulation is gated by dev-node")
    )]
    StateRestoration,
}

impl SimulationBackendError {
    #[must_use]
    const fn allows_fallback(self) -> bool {
        matches!(self, Self::Unsupported { .. })
    }

    #[cfg_attr(
        not(feature = "dev-node"),
        allow(dead_code, reason = "receipt simulation is gated by dev-node")
    )]
    const fn after_side_effect(self) -> Self {
        match self {
            Self::Unsupported { backend } => Self::ExecutionRejected { backend },
            terminal => terminal,
        }
    }

    fn into_infrastructure(self) -> InfrastructureError {
        let message = match self {
            Self::Unsupported { backend } => format!("{backend} method unsupported"),
            Self::Timeout { backend } => format!("{backend} RPC timeout"),
            Self::Transport { backend } => format!("{backend} RPC transport failure"),
            Self::ResponseDecode { backend } => format!("{backend} RPC response decode failure"),
            Self::ExecutionRejected { backend } => format!("{backend} execution rejected"),
            Self::EvidenceMalformed { backend, field } => {
                format!("{backend} evidence malformed: {field}")
            }
            Self::IdentityMismatch { backend, field } => {
                format!("{backend} identity mismatch: {field}")
            }
            Self::StateRestoration => "committed-receipt state restoration failed".into(),
        };
        InfrastructureError::Blockchain(message)
    }
}

fn classify_provider_error(
    error: &TransportError,
    backend: &'static str,
) -> SimulationBackendError {
    if matches!(error, RpcError::UnsupportedFeature(_))
        || error
            .as_error_resp()
            .is_some_and(|response| response.code == -32601)
    {
        return SimulationBackendError::Unsupported { backend };
    }
    if error.as_error_resp().is_some() {
        return SimulationBackendError::ExecutionRejected { backend };
    }
    if error.is_deser_error() || error.is_ser_error() {
        return SimulationBackendError::ResponseDecode { backend };
    }
    if error.is_transport_error() {
        return classify_http_failure(backend, chain_rpc::is_timeout(error));
    }
    SimulationBackendError::Transport { backend }
}

const fn classify_http_failure(backend: &'static str, timed_out: bool) -> SimulationBackendError {
    if timed_out {
        SimulationBackendError::Timeout { backend }
    } else {
        SimulationBackendError::Transport { backend }
    }
}

/// Backend provenance for simulated execution evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulationSource {
    SuccessfulCallTrace,
    CommittedReceipt,
    FlatSimulation,
}

/// Gas and logs returned by one simulation backend.
#[derive(Debug)]
pub struct SimulationEvidence {
    pub gas_used: u64,
    pub logs: Vec<Log>,
    pub source: SimulationSource,
}

/// Identity expected from a mined simulation transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedTransactionIdentity {
    pub transaction_hash: B256,
    pub from: Address,
    pub to: Address,
}

impl SimulationEvidence {
    /// Converts a successful mined receipt into committed simulation evidence.
    pub fn from_committed_receipt(
        receipt: TransactionReceipt,
        expected: ExpectedTransactionIdentity,
    ) -> Result<Self, InfrastructureError> {
        Self::from_committed_receipt_checked(receipt, expected)
            .map_err(SimulationBackendError::into_infrastructure)
    }

    fn from_committed_receipt_checked(
        receipt: TransactionReceipt,
        expected: ExpectedTransactionIdentity,
    ) -> Result<Self, SimulationBackendError> {
        if !receipt.status() {
            return Err(SimulationBackendError::ExecutionRejected {
                backend: "committed-receipt",
            });
        }
        if receipt.transaction_hash != expected.transaction_hash {
            return Err(SimulationBackendError::IdentityMismatch {
                backend: "committed-receipt",
                field: "transaction_hash",
            });
        }
        if receipt.from != expected.from {
            return Err(SimulationBackendError::IdentityMismatch {
                backend: "committed-receipt",
                field: "from",
            });
        }
        if receipt.to != Some(expected.to) {
            return Err(SimulationBackendError::IdentityMismatch {
                backend: "committed-receipt",
                field: "to",
            });
        }
        let block_hash = receipt
            .block_hash
            .ok_or(SimulationBackendError::EvidenceMalformed {
                backend: "committed-receipt",
                field: "block_hash",
            })?;
        let block_number =
            receipt
                .block_number
                .ok_or(SimulationBackendError::EvidenceMalformed {
                    backend: "committed-receipt",
                    field: "block_number",
                })?;
        let transaction_index =
            receipt
                .transaction_index
                .ok_or(SimulationBackendError::EvidenceMalformed {
                    backend: "committed-receipt",
                    field: "transaction_index",
                })?;

        for log in receipt.inner.logs() {
            if log.removed {
                return Err(SimulationBackendError::EvidenceMalformed {
                    backend: "committed-receipt",
                    field: "log.removed",
                });
            }
            require_log_identity(log.log_index, None, "log.log_index")?;
            require_log_identity(
                log.transaction_hash,
                Some(receipt.transaction_hash),
                "log.transaction_hash",
            )?;
            require_log_identity(
                log.transaction_index,
                Some(transaction_index),
                "log.transaction_index",
            )?;
            require_log_identity(log.block_hash, Some(block_hash), "log.block_hash")?;
            require_log_identity(log.block_number, Some(block_number), "log.block_number")?;
        }

        Ok(Self {
            gas_used: receipt.gas_used,
            logs: receipt.inner.logs().to_vec(),
            source: SimulationSource::CommittedReceipt,
        })
    }

    #[must_use]
    /// Returns only logs whose backend proves committed execution ancestry.
    pub fn legacy_payment_logs(&self) -> Option<&[Log]> {
        match self.source {
            SimulationSource::SuccessfulCallTrace | SimulationSource::CommittedReceipt => {
                Some(&self.logs)
            }
            SimulationSource::FlatSimulation => None,
        }
    }
}

fn require_log_identity<T: Copy + PartialEq>(
    actual: Option<T>,
    expected: Option<T>,
    field: &'static str,
) -> Result<(), SimulationBackendError> {
    let Some(actual) = actual else {
        return Err(SimulationBackendError::EvidenceMalformed {
            backend: "committed-receipt",
            field,
        });
    };
    if let Some(expected) = expected {
        if actual != expected {
            return Err(SimulationBackendError::IdentityMismatch {
                backend: "committed-receipt",
                field,
            });
        }
    }
    Ok(())
}

fn convert_trace_log(log: &CallLogFrame) -> Result<Log, SimulationBackendError> {
    let address = log
        .address
        .ok_or(SimulationBackendError::EvidenceMalformed {
            backend: "debug_traceCall",
            field: "log.address",
        })?;
    let topics = log
        .topics
        .clone()
        .ok_or(SimulationBackendError::EvidenceMalformed {
            backend: "debug_traceCall",
            field: "log.topics",
        })?;
    let data = log
        .data
        .clone()
        .ok_or(SimulationBackendError::EvidenceMalformed {
            backend: "debug_traceCall",
            field: "log.data",
        })?;

    Ok(unmined_log(address, topics, data))
}

/// Log with no block or transaction context (simulation output).
#[must_use]
pub fn unmined_log(address: Address, topics: Vec<B256>, data: Bytes) -> Log {
    Log {
        inner: alloy::primitives::Log {
            address,
            data: LogData::new_unchecked(topics, data),
        },
        ..Log::default()
    }
}

fn collect_committed_logs(frame: &CallFrame) -> Result<Vec<Log>, SimulationBackendError> {
    let mut committed = Vec::new();
    let mut pending = vec![(frame, true)];

    while let Some((current, ancestors_succeeded)) = pending.pop() {
        let frame_succeeded = ancestors_succeeded && current.error.is_none();

        for trace_log in &current.logs {
            let converted = convert_trace_log(trace_log)?;
            if frame_succeeded {
                committed.push(converted);
            }
        }

        pending.extend(
            current
                .calls
                .iter()
                .rev()
                .map(|child| (child, frame_succeeded)),
        );
    }

    Ok(committed)
}

fn validate_trace_identity(
    frame: &CallFrame,
    expected_from: Address,
    expected_to: Address,
    expected_input: &Bytes,
) -> Result<(), SimulationBackendError> {
    const BACKEND: &str = "debug_traceCall";

    if frame.typ != "CALL" {
        return Err(SimulationBackendError::IdentityMismatch {
            backend: BACKEND,
            field: "type",
        });
    }
    if frame.from != expected_from {
        return Err(SimulationBackendError::IdentityMismatch {
            backend: BACKEND,
            field: "from",
        });
    }
    if frame.to != Some(expected_to) {
        return Err(SimulationBackendError::IdentityMismatch {
            backend: BACKEND,
            field: "to",
        });
    }
    if frame.input != *expected_input {
        return Err(SimulationBackendError::IdentityMismatch {
            backend: BACKEND,
            field: "input",
        });
    }
    if frame.value != Some(U256::ZERO) {
        return Err(SimulationBackendError::IdentityMismatch {
            backend: BACKEND,
            field: "value",
        });
    }

    Ok(())
}

pub struct ChainExecutor {
    provider: ChainProvider,
    wallet: PrivateKeySigner,
    chain_id: u64,
    min_gas_balance: U256,
    /// Mock mode: skip all real blockchain operations (return dummy values).
    /// Only available with `dev-node` feature. Production binaries always have this as `false`.
    #[cfg(feature = "dev-node")]
    is_mock: bool,
}

/// The one field read from `eth_getBlockByNumber`.
#[derive(Debug, serde::Deserialize)]
struct BlockTimestamp {
    timestamp: U256,
}

impl ChainExecutor {
    pub async fn new(config: &NoxConfig) -> Result<Self, InfrastructureError> {
        let provider = build_http1_provider(&config.eth_rpc_url)?;

        // Determine mock mode -- only available with dev-node feature
        #[cfg(feature = "dev-node")]
        let is_mock = config.benchmark_mode;
        #[cfg(not(feature = "dev-node"))]
        let is_mock = false;

        let chain_id = if is_mock {
            // Mock Mode: Skip RPC
            config.chain_id
        } else if config.chain_id == 0 {
            let chain_id: U64 = provider
                .raw_request(Cow::Borrowed("eth_chainId"), ())
                .await
                .map_err(|e| {
                    InfrastructureError::Blockchain(format!("Failed to fetch ChainID: {e}"))
                })?;
            chain_id.to::<u64>()
        } else {
            config.chain_id
        };

        // Ephemeral fallback only in dev-node builds
        let wallet_str = Zeroizing::new(if config.eth_wallet_private_key.is_empty() {
            #[cfg(feature = "dev-node")]
            {
                if config.benchmark_mode {
                    warn!(
                        "No ETH wallet key provided. Generating ephemeral wallet (benchmark mode)."
                    );
                    hex::encode(PrivateKeySigner::random().to_bytes())
                } else {
                    return Err(InfrastructureError::Blockchain(
                        "eth_wallet_private_key is empty. Required for chain execution.".into(),
                    ));
                }
            }
            #[cfg(not(feature = "dev-node"))]
            {
                return Err(InfrastructureError::Blockchain(
                    "eth_wallet_private_key is empty. Required for chain execution.".into(),
                ));
            }
        } else {
            config.eth_wallet_private_key.clone()
        });

        let wallet = PrivateKeySigner::from_str(&wallet_str)
            .map_err(|e| InfrastructureError::Blockchain(format!("Invalid Private Key: {e}")))?;

        let min_gas_balance = nox_core::eth::parse_decimal_u256(&config.min_gas_balance)
            .unwrap_or_else(|_| U256::from(100_000_000_000_000_000u64)); // 0.1 ETH default

        if is_mock {
            warn!("ChainExecutor running in mock/benchmark mode");
        } else {
            info!(
                "Chain Executor Ready. Wallet: {:?} ChainID: {}",
                wallet.address(),
                chain_id
            );
        }

        Ok(Self {
            provider,
            wallet,
            chain_id,
            min_gas_balance,
            #[cfg(feature = "dev-node")]
            is_mock,
        })
    }

    pub async fn latest_block_timestamp(&self) -> Result<u64, InfrastructureError> {
        #[cfg(feature = "dev-node")]
        if self.is_mock {
            return SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .map_err(|_| {
                    InfrastructureError::Blockchain(
                        "system clock is before Unix epoch in benchmark mode".to_string(),
                    )
                });
        }

        let block: Option<BlockTimestamp> = self
            .provider
            .raw_request(Cow::Borrowed("eth_getBlockByNumber"), ("latest", false))
            .await
            .map_err(|error| {
                InfrastructureError::Blockchain(format!(
                    "latest block timestamp lookup failed: {error}"
                ))
            })?;
        let block = block.ok_or_else(|| {
            InfrastructureError::Blockchain(
                "latest block timestamp lookup returned no block".to_string(),
            )
        })?;
        u64::try_from(block.timestamp).map_err(|_| {
            InfrastructureError::Blockchain("latest block timestamp exceeds u64".to_string())
        })
    }

    /// Returns true if running in mock/benchmark mode.
    /// Always false in production builds (without `dev-node` feature).
    #[inline]
    fn is_mock(&self) -> bool {
        #[cfg(feature = "dev-node")]
        {
            self.is_mock
        }
        #[cfg(not(feature = "dev-node"))]
        {
            false
        }
    }

    /// Reads the wallet balance and warns when it is below `min_gas_balance`.
    /// Returns the balance and whether it is low.
    pub async fn check_gas_health(&self) -> Result<(U256, bool), InfrastructureError> {
        if self.is_mock() {
            return Ok((self.min_gas_balance, false));
        }

        let balance = self
            .provider
            .get_balance(self.wallet.address())
            .latest()
            .await
            .map_err(|e| InfrastructureError::Blockchain(format!("Failed to get balance: {e}")))?;

        let low = balance < self.min_gas_balance;
        if low {
            warn!(
                "LOW GAS BALANCE: {} wei (Threshold: {})",
                balance, self.min_gas_balance
            );
        }
        Ok((balance, low))
    }

    #[must_use]
    pub fn address(&self) -> Address {
        self.wallet.address()
    }

    #[must_use]
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Simulates a transaction for diagnostics and records backend provenance.
    pub async fn simulate_transaction_evidence(
        &self,
        to: Address,
        data: Bytes,
    ) -> Result<SimulationEvidence, InfrastructureError> {
        if self.is_mock() {
            return Ok(SimulationEvidence {
                gas_used: 100_000,
                logs: Vec::new(),
                source: SimulationSource::FlatSimulation,
            });
        }

        match self.simulate_via_eth_simulate(to, data.clone()).await {
            Ok(evidence) => {
                info!(
                    "eth_simulateV1 succeeded: gas_used={}, logs={}",
                    evidence.gas_used,
                    evidence.logs.len()
                );
                return Ok(evidence);
            }
            Err(error) if error.allows_fallback() => {
                info!("eth_simulateV1 method unsupported; trying committed evidence backends");
            }
            Err(error) => return Err(error.into_infrastructure()),
        }

        #[cfg(feature = "dev-node")]
        {
            match self.simulate_via_receipt(to, data.clone()).await {
                Ok(evidence) => {
                    info!(
                        "committed-receipt simulation succeeded: gas_used={}, logs={}",
                        evidence.gas_used,
                        evidence.logs.len()
                    );
                    return Ok(evidence);
                }
                Err(error) if error.allows_fallback() => {
                    info!("evm_snapshot method unsupported; trying debug_traceCall");
                }
                Err(error) => return Err(error.into_infrastructure()),
            }
        }

        self.simulate_via_trace(to, data)
            .await
            .map_err(SimulationBackendError::into_infrastructure)
    }

    /// Compatibility wrapper for callers that do not authorize payment.
    pub async fn simulate_transaction_with_logs(
        &self,
        to: Address,
        data: Bytes,
    ) -> Result<(u64, Vec<Log>), InfrastructureError> {
        let evidence = self.simulate_transaction_evidence(to, data).await?;
        Ok((evidence.gas_used, evidence.logs))
    }

    /// Simulates a legacy paid transaction using committed or ancestry-bearing logs.
    pub async fn simulate_legacy_paid_transaction(
        &self,
        to: Address,
        data: Bytes,
    ) -> Result<SimulationEvidence, InfrastructureError> {
        if self.is_mock() {
            return Err(InfrastructureError::Blockchain(
                "legacy paid simulation requires committed execution evidence".into(),
            ));
        }

        match self.simulate_via_eth_simulate(to, data.clone()).await {
            Ok(evidence) => {
                info!(
                    "discarded flat simulation logs for legacy payment evidence: gas_used={}, logs={}",
                    evidence.gas_used,
                    evidence.logs.len()
                );
            }
            Err(error) if error.allows_fallback() => {
                info!("eth_simulateV1 method unsupported for legacy paid simulation");
            }
            Err(error) => return Err(error.into_infrastructure()),
        }

        #[cfg(feature = "dev-node")]
        {
            match self.simulate_via_receipt(to, data.clone()).await {
                Ok(evidence) => return Ok(evidence),
                Err(error) if error.allows_fallback() => {
                    info!("evm_snapshot method unsupported for legacy payment evidence");
                }
                Err(error) => return Err(error.into_infrastructure()),
            }
        }

        self.simulate_via_trace(to, data)
            .await
            .map_err(SimulationBackendError::into_infrastructure)
    }

    /// Simulate via `eth_simulateV1` (stateless, single RPC call).
    ///
    /// This is the primary simulation strategy for dev nodes. It performs a
    /// stateless simulation and returns full event logs from all call depths
    /// (including nested cross-contract calls like `DarkPool -> NoxRewardPool`).
    ///
    /// Advantages over snapshot/revert:
    /// - Stateless: no snapshot/revert state management
    /// - Faster: 1 RPC call vs 5
    /// - Returns full nested logs (Anvil receipt.logs is empty with snapshot/revert)
    ///
    /// Available in all builds -- `eth_simulateV1` is a standard RPC method
    /// supported by Geth 1.14+, Arbitrum, Optimism, and most modern chains.
    async fn simulate_via_eth_simulate(
        &self,
        to: Address,
        data: Bytes,
    ) -> Result<SimulationEvidence, SimulationBackendError> {
        let from = self.wallet.address();

        // Build eth_simulateV1 request with state override for gas
        let params = serde_json::json!([
            {
                "blockStateCalls": [{
                    "stateOverrides": {
                        format!("{from:?}"): {
                            "balance": "0xDE0B6B3A7640000"
                        }
                    },
                    "calls": [{
                        "from": format!("{from:?}"),
                        "to": format!("{to:?}"),
                        "data": format!("0x{}", hex::encode(&data))
                    }]
                }],
                "validation": false,
                "traceTransfers": true
            },
            "latest"
        ]);

        let result: serde_json::Value = self
            .provider
            .raw_request(Cow::Borrowed("eth_simulateV1"), params)
            .await
            .map_err(|error| classify_provider_error(&error, "eth_simulateV1"))?;

        // Parse response: result[0]["calls"][0]
        let block = result
            .get(0)
            .ok_or(SimulationBackendError::EvidenceMalformed {
                backend: "eth_simulateV1",
                field: "response.blocks",
            })?;
        let call_result = block.get("calls").and_then(|calls| calls.get(0)).ok_or(
            SimulationBackendError::EvidenceMalformed {
                backend: "eth_simulateV1",
                field: "response.calls",
            },
        )?;

        // Check status (0x1 = success)
        let status = call_result
            .get("status")
            .and_then(serde_json::Value::as_str)
            .ok_or(SimulationBackendError::EvidenceMalformed {
                backend: "eth_simulateV1",
                field: "status",
            })?;
        if status != "0x1" {
            return Err(SimulationBackendError::ExecutionRejected {
                backend: "eth_simulateV1",
            });
        }

        // Extract gasUsed
        let gas_hex = call_result
            .get("gasUsed")
            .and_then(serde_json::Value::as_str)
            .ok_or(SimulationBackendError::EvidenceMalformed {
                backend: "eth_simulateV1",
                field: "gas_used",
            })?;
        let gas_digits =
            gas_hex
                .strip_prefix("0x")
                .ok_or(SimulationBackendError::EvidenceMalformed {
                    backend: "eth_simulateV1",
                    field: "gas_used",
                })?;
        let gas_used = u64::from_str_radix(gas_digits, 16).map_err(|_| {
            SimulationBackendError::EvidenceMalformed {
                backend: "eth_simulateV1",
                field: "gas_used",
            }
        })?;

        // Extract logs
        let logs = Self::parse_simulate_logs(call_result)?;

        debug!(
            "eth_simulateV1: gas_used={}, logs={}, status={}",
            gas_used,
            logs.len(),
            status
        );

        Ok(SimulationEvidence {
            gas_used,
            logs,
            source: SimulationSource::FlatSimulation,
        })
    }

    /// Parse event logs from an `eth_simulateV1` call result.
    fn parse_simulate_logs(
        call_result: &serde_json::Value,
    ) -> Result<Vec<Log>, SimulationBackendError> {
        let Some(logs) = call_result.get("logs") else {
            return Ok(Vec::new());
        };
        let logs_array = logs
            .as_array()
            .ok_or(SimulationBackendError::EvidenceMalformed {
                backend: "eth_simulateV1",
                field: "logs",
            })?;

        logs_array
            .iter()
            .map(|log_json| {
                let address_str = log_json
                    .get("address")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(SimulationBackendError::EvidenceMalformed {
                        backend: "eth_simulateV1",
                        field: "log.address",
                    })?;
                let address = nox_core::eth::parse_address(address_str).map_err(|_| {
                    SimulationBackendError::EvidenceMalformed {
                        backend: "eth_simulateV1",
                        field: "log.address",
                    }
                })?;

                let topics_json = log_json
                    .get("topics")
                    .and_then(serde_json::Value::as_array)
                    .ok_or(SimulationBackendError::EvidenceMalformed {
                        backend: "eth_simulateV1",
                        field: "log.topics",
                    })?;
                let topics: Vec<B256> = topics_json
                    .iter()
                    .map(|topic| {
                        let encoded =
                            topic
                                .as_str()
                                .ok_or(SimulationBackendError::EvidenceMalformed {
                                    backend: "eth_simulateV1",
                                    field: "log.topics",
                                })?;
                        nox_core::eth::parse_fixed_hex::<32>(encoded).map_err(|_| {
                            SimulationBackendError::EvidenceMalformed {
                                backend: "eth_simulateV1",
                                field: "log.topics",
                            }
                        })
                    })
                    .collect::<Result<_, _>>()?;

                let data_str = log_json
                    .get("data")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(SimulationBackendError::EvidenceMalformed {
                        backend: "eth_simulateV1",
                        field: "log.data",
                    })?;
                let data_hex = data_str.strip_prefix("0x").ok_or(
                    SimulationBackendError::EvidenceMalformed {
                        backend: "eth_simulateV1",
                        field: "log.data",
                    },
                )?;
                let data_bytes = hex::decode(data_hex).map_err(|_| {
                    SimulationBackendError::EvidenceMalformed {
                        backend: "eth_simulateV1",
                        field: "log.data",
                    }
                })?;

                Ok(unmined_log(address, topics, Bytes::from(data_bytes)))
            })
            .collect()
    }

    /// Simulate via snapshot -> send -> receipt -> revert.
    ///
    /// Fallback simulation strategy for dev nodes (Anvil, Hardhat).
    /// Sends a real signed transaction, mines it, extracts the receipt,
    /// then reverts state. Note: Anvil may return empty `receipt.logs`
    /// despite successful execution -- prefer `eth_simulateV1` instead.
    ///
    /// Gated behind `dev-node` feature -- excluded from production builds.
    #[cfg(feature = "dev-node")]
    async fn simulate_via_receipt(
        &self,
        to: Address,
        data: Bytes,
    ) -> Result<SimulationEvidence, SimulationBackendError> {
        let snapshot_id: U256 = self
            .provider
            .raw_request(Cow::Borrowed("evm_snapshot"), ())
            .await
            .map_err(|error| classify_provider_error(&error, "evm_snapshot"))?;

        // Anvil auto-mines by default
        let from = self.wallet.address();
        let result = async {
            let nonce: U256 = self
                .provider
                .raw_request(
                    Cow::Borrowed("eth_getTransactionCount"),
                    (format!("{from:?}"), "latest"),
                )
                .await
                .map_err(|error| classify_provider_error(&error, "committed-receipt send"))?;
            let gas_price: U256 = self
                .provider
                .raw_request(Cow::Borrowed("eth_gasPrice"), ())
                .await
                .map_err(|error| classify_provider_error(&error, "committed-receipt send"))?;
            let gas: U256 = self
                .provider
                .raw_request(
                    Cow::Borrowed("eth_estimateGas"),
                    (legacy_call_object(Some(from), Some(to), Some(&data), None),),
                )
                .await
                .map_err(|error| classify_provider_error(&error, "committed-receipt send"))?;
            let raw = self
                .sign_legacy_transaction(to, data.clone(), nonce, gas, gas_price)
                .await
                .map_err(|_| SimulationBackendError::ExecutionRejected {
                    backend: "committed-receipt send",
                })?;
            let tx_hash: B256 = self
                .provider
                .raw_request(
                    Cow::Borrowed("eth_sendRawTransaction"),
                    (format!("0x{}", hex::encode(&raw)),),
                )
                .await
                .map_err(|error| classify_provider_error(&error, "committed-receipt send"))?;

            let receipt = self
                .provider
                .get_transaction_receipt(tx_hash)
                .await
                .map_err(|error| classify_provider_error(&error, "committed-receipt lookup"))?
                .ok_or(SimulationBackendError::EvidenceMalformed {
                    backend: "committed-receipt",
                    field: "receipt",
                })?;

            SimulationEvidence::from_committed_receipt_checked(
                receipt,
                ExpectedTransactionIdentity {
                    transaction_hash: tx_hash,
                    from,
                    to,
                },
            )
        }
        .await
        .map_err(SimulationBackendError::after_side_effect);

        let reverted: bool = self
            .provider
            .raw_request(Cow::Borrowed("evm_revert"), [snapshot_id])
            .await
            .map_err(|_| SimulationBackendError::StateRestoration)?;
        if !reverted {
            return Err(SimulationBackendError::StateRestoration);
        }

        result
    }

    /// Simulate via `debug_traceCall` with `callTracer` + `withLog: true`.
    ///
    /// This is the fallback strategy for production Geth nodes that support
    /// `debug_traceCall` but not `evm_snapshot`. Anvil silently ignores
    /// the `withLog` config, so this only returns nested logs on Geth.
    async fn simulate_via_trace(
        &self,
        to: Address,
        data: Bytes,
    ) -> Result<SimulationEvidence, SimulationBackendError> {
        let from = self.wallet.address();
        let call = legacy_call_object(Some(from), Some(to), Some(&data), None);
        let options = GethDebugTracingCallOptions::new(GethDebugTracingOptions::call_tracer(
            CallConfig::default().with_log(),
        ));

        let trace: serde_json::Value = self
            .provider
            .raw_request(
                Cow::Borrowed("debug_traceCall"),
                (call.clone(), "latest", options),
            )
            .await
            .map_err(|error| classify_provider_error(&error, "debug_traceCall"))?;

        let frame: CallFrame = serde_json::from_value(trace).map_err(|_| {
            SimulationBackendError::EvidenceMalformed {
                backend: "debug_traceCall",
                field: "trace.variant",
            }
        })?;
        validate_trace_identity(&frame, from, to, &data)?;
        if frame.error.is_some() {
            return Err(SimulationBackendError::ExecutionRejected {
                backend: "debug_traceCall",
            });
        }
        let logs = collect_committed_logs(&frame)?;

        let gas_used = self
            .estimate_gas_raw(call)
            .await
            .map_err(|error| classify_provider_error(&error, "eth_estimateGas"))?;

        debug!(
            "debug_traceCall succeeded: gas_used={}, logs={}",
            gas_used,
            logs.len()
        );

        Ok(SimulationEvidence {
            gas_used,
            logs,
            source: SimulationSource::SuccessfulCallTrace,
        })
    }

    /// Simulation: Runs `eth_call` to check for reverts before spending gas.
    pub async fn simulate_transaction(
        &self,
        to: Address,
        data: Bytes,
    ) -> Result<u64, InfrastructureError> {
        if self.is_mock() {
            return Ok(100_000); // Dummy gas estimate
        }

        let call = legacy_call_object(Some(self.wallet.address()), Some(to), Some(&data), None);
        match self.estimate_gas_raw(call).await {
            Ok(gas) => Ok(gas),
            Err(e) => {
                // Log the raw error so we can see the revert reason (e.g. "execution reverted: ...")
                warn!("[ChainExecutor] Gas estimation failed: {:?}", e);
                Err(InfrastructureError::Blockchain(format!(
                    "Simulation failed: {e}"
                )))
            }
        }
    }

    // For Read-Only Queries
    pub async fn query_state(
        &self,
        to: Address,
        data: Bytes,
    ) -> Result<Bytes, InfrastructureError> {
        let call = legacy_call_object(None, Some(to), Some(&data), None);
        let result: Bytes = self
            .provider
            .raw_request(Cow::Borrowed("eth_call"), (call, "latest"))
            .await
            .map_err(|e| InfrastructureError::Blockchain(format!("Query failed: {e}")))?;
        Ok(result)
    }

    pub async fn get_gas_price(&self) -> Result<U256, InfrastructureError> {
        if self.is_mock() {
            return Ok(U256::from(10_000_000_000u64)); // 10 Gwei
        }
        self.provider
            .get_gas_price()
            .await
            .map(U256::from)
            .map_err(|e| InfrastructureError::Blockchain(format!("Failed to get gas price: {e}")))
    }

    pub async fn get_nonce(&self) -> Result<U256, InfrastructureError> {
        if self.is_mock() {
            return Ok(U256::ZERO);
        }

        self.provider
            .get_transaction_count(self.wallet.address())
            .pending()
            .await
            .map(U256::from)
            .map_err(|e| InfrastructureError::Blockchain(format!("Get nonce failed: {e}")))
    }

    /// Nonce of the next transaction in the latest block, ignoring the mempool.
    pub async fn get_confirmed_nonce(&self) -> Result<U256, InfrastructureError> {
        if self.is_mock() {
            return Ok(U256::ZERO);
        }

        self.provider
            .get_transaction_count(self.wallet.address())
            .latest()
            .await
            .map(U256::from)
            .map_err(|e| {
                InfrastructureError::Blockchain(format!("Get confirmed nonce failed: {e}"))
            })
    }

    /// Fetch the transaction receipt for a given tx hash.
    pub async fn get_transaction_receipt(
        &self,
        tx_hash: B256,
    ) -> Result<Option<TransactionReceipt>, InfrastructureError> {
        self.provider
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(|e| InfrastructureError::Blockchain(format!("Get receipt failed: {e}")))
    }

    /// Estimate gas for a transaction via `eth_estimateGas`.
    ///
    /// This returns the **accurate** gas limit for on-chain execution, unlike
    /// `eth_simulateV1`'s `gasUsed` which may not include full intrinsic costs
    /// (base TX cost, calldata gas). Use this for setting gas limits on
    /// transactions; use simulation gas for profitability analysis.
    pub async fn estimate_gas(&self, to: Address, data: Bytes) -> Result<u64, InfrastructureError> {
        if self.is_mock() {
            return Ok(100_000);
        }

        let call = legacy_call_object(Some(self.wallet.address()), Some(to), Some(&data), None);
        self.estimate_gas_raw(call)
            .await
            .map_err(|e| InfrastructureError::Blockchain(format!("Gas estimation failed: {e}")))
    }

    pub async fn build_cost_candidate(
        &self,
        to: Address,
        data: Bytes,
        gas_limit_buffer_bps: u32,
        initial_fee_buffer_bps: u32,
    ) -> Result<crate::blockchain::transaction_plan::CostCandidate, InfrastructureError> {
        use crate::blockchain::transaction_plan::{buffered, CostCandidate};

        let estimated_gas = self.estimate_gas(to, data).await?;
        let gas_limit = buffered(U256::from(estimated_gas), gas_limit_buffer_bps, "gas_limit")
            .map_err(|error| InfrastructureError::Blockchain(error.to_string()))?;
        let network_fee_per_gas = self.get_gas_price().await?;
        let initial_fee_per_gas = buffered(
            network_fee_per_gas,
            initial_fee_buffer_bps,
            "initial_fee_per_gas",
        )
        .map_err(|error| InfrastructureError::Blockchain(error.to_string()))?;
        Ok(CostCandidate {
            gas_limit,
            initial_fee_per_gas,
            chain_data_fee_native: U256::ZERO,
        })
    }

    /// `eth_estimateGas` for `call` with no block parameter (the node's default).
    async fn estimate_gas_raw(&self, call: serde_json::Value) -> Result<u64, TransportError> {
        let gas: U256 = self
            .provider
            .raw_request(Cow::Borrowed("eth_estimateGas"), (call,))
            .await?;
        u64::try_from(gas)
            .map_err(|_| TransportError::local_usage_str("eth_estimateGas result exceeds u64"))
    }

    /// Signs a legacy (EIP-155) transaction offline and returns its raw bytes.
    pub async fn sign_legacy_transaction(
        &self,
        to: Address,
        data: Bytes,
        nonce: U256,
        gas_limit: U256,
        gas_price: U256,
    ) -> Result<Bytes, InfrastructureError> {
        let field = |name: &str| {
            InfrastructureError::Blockchain(format!("offline signing failed: {name} out of range"))
        };
        let mut transaction = TxLegacy {
            chain_id: Some(self.chain_id),
            nonce: u64::try_from(nonce).map_err(|_| field("nonce"))?,
            gas_price: u128::try_from(gas_price).map_err(|_| field("gas price"))?,
            gas_limit: u64::try_from(gas_limit).map_err(|_| field("gas limit"))?,
            to: TxKind::Call(to),
            value: U256::ZERO,
            input: data,
        };
        let signature = self
            .wallet
            .sign_transaction_sync(&mut transaction)
            .map_err(|error| {
                InfrastructureError::Blockchain(format!("offline signing failed: {error}"))
            })?;
        let envelope = TxEnvelope::Legacy(transaction.into_signed(signature));
        Ok(Bytes::from(envelope.encoded_2718()))
    }

    /// 65-byte `r || s || v` signature (v = 27 or 28) over an execution digest.
    pub fn sign_execution_digest(&self, digest: B256) -> Result<Vec<u8>, InfrastructureError> {
        self.wallet
            .sign_hash_sync(&digest)
            .map(|signature| signature.as_bytes().to_vec())
            .map_err(|error| {
                InfrastructureError::Blockchain(format!("execution quote signing failed: {error}"))
            })
    }

    /// Broadcast a pre-signed raw transaction via `eth_sendRawTransaction`.
    ///
    /// Forwards already-signed bytes directly to the RPC node. The signer
    /// encoded in the raw bytes pays gas.
    pub async fn broadcast_raw_signed_tx(
        &self,
        raw_tx: &[u8],
    ) -> Result<B256, InfrastructureError> {
        self.broadcast_outbox_raw_signed_tx(raw_tx)
            .await
            .map_err(|error| InfrastructureError::Blockchain(error.to_string()))
    }

    pub(crate) async fn broadcast_outbox_raw_signed_tx(
        &self,
        raw_tx: &[u8],
    ) -> Result<B256, OutboxBroadcastError> {
        let expected_hash = keccak256(raw_tx);
        if self.is_mock() {
            return Ok(expected_hash);
        }

        let rpc_hash: B256 = self
            .provider
            .raw_request(
                Cow::Borrowed("eth_sendRawTransaction"),
                (format!("0x{}", hex::encode(raw_tx)),),
            )
            .await
            .map_err(classify_broadcast_provider_error)?;

        if rpc_hash != expected_hash {
            return Err(OutboxBroadcastError::Uncertain {
                detail: "RPC returned a mismatched transaction hash",
            });
        }
        Ok(rpc_hash)
    }
}

fn classify_broadcast_provider_error(error: TransportError) -> OutboxBroadcastError {
    let Some(response) = error.as_error_resp() else {
        return OutboxBroadcastError::Uncertain {
            detail: "transport, server, or response failure",
        };
    };
    let message = response.message.to_ascii_lowercase();
    if message.contains("already known") {
        return OutboxBroadcastError::AlreadyKnown;
    }
    if message.contains("nonce too low") || message.contains("nonce has already been used") {
        return OutboxBroadcastError::NonceTooLow;
    }
    if message.contains("replacement transaction underpriced") {
        return OutboxBroadcastError::ReplacementUnderpriced;
    }
    if let Some(classification) = [
        "intrinsic gas too low",
        "insufficient funds",
        "invalid sender",
        "invalid chain id",
        "exceeds block gas limit",
    ]
    .iter()
    .copied()
    .find(|classification| message.contains(classification))
    {
        return OutboxBroadcastError::Rejected {
            detail: classification,
        };
    }
    OutboxBroadcastError::Uncertain {
        detail: "unclassified JSON-RPC rejection",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::transports::TransportErrorKind;

    const TRACE_BACKEND: &str = "debug_traceCall";

    #[test]
    fn connection_reset_and_http_5xx_are_uncertain_broadcasts() {
        for detail in ["connection reset by peer", "HTTP status 503"] {
            assert_eq!(
                classify_broadcast_provider_error(TransportErrorKind::custom_str(detail)),
                OutboxBroadcastError::Uncertain {
                    detail: "transport, server, or response failure"
                }
            );
        }
    }

    async fn executor_with_rpc_url(rpc_url: &str) -> ChainExecutor {
        let provider = build_http1_provider(rpc_url).expect("test provider URL");
        let wallet = PrivateKeySigner::random();
        ChainExecutor {
            provider,
            wallet,
            chain_id: 31_337,
            min_gas_balance: U256::ZERO,
            #[cfg(feature = "dev-node")]
            is_mock: false,
        }
    }

    async fn one_shot_http_server(response: Option<&'static [u8]>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test RPC");
        let address = listener.local_addr().expect("test RPC address");
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept test RPC request");
            let mut request = [0_u8; 4096];
            let _ = socket.read(&mut request).await;
            if let Some(response) = response {
                socket
                    .write_all(response)
                    .await
                    .expect("write test RPC response");
            }
        });
        format!("http://{address}")
    }

    #[test]
    fn nonce_conflicts_are_classified() {
        let rpc_error = |message: &str| {
            TransportError::ErrorResp(ErrorPayload {
                code: -32000,
                message: message.to_string().into(),
                data: None,
            })
        };
        assert_eq!(
            classify_broadcast_provider_error(rpc_error(
                "nonce too low: address 0x1, tx: 5 state: 6"
            )),
            OutboxBroadcastError::NonceTooLow
        );
        assert_eq!(
            classify_broadcast_provider_error(rpc_error("replacement transaction underpriced")),
            OutboxBroadcastError::ReplacementUnderpriced
        );
        assert_eq!(
            classify_broadcast_provider_error(rpc_error("already known")),
            OutboxBroadcastError::AlreadyKnown
        );
    }

    #[tokio::test]
    async fn actual_http_5xx_and_eof_remain_uncertain() {
        let unavailable = one_shot_http_server(Some(
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ))
        .await;
        let eof = one_shot_http_server(None).await;
        for rpc_url in [unavailable, eof] {
            let executor = executor_with_rpc_url(&rpc_url).await;
            assert!(matches!(
                executor.broadcast_outbox_raw_signed_tx(&[1]).await,
                Err(OutboxBroadcastError::Uncertain { .. })
            ));
        }
    }

    fn reward_trace_log() -> CallLogFrame {
        let asset = Address::with_last_byte(2);
        let payer = Address::with_last_byte(3);
        CallLogFrame {
            address: Some(Address::with_last_byte(1)),
            topics: Some(vec![
                keccak256("RewardsDeposited(address,address,uint256)"),
                asset.into_word(),
                payer.into_word(),
            ]),
            data: Some(Bytes::from(U256::from(4).to_be_bytes::<32>().to_vec())),
            ..Default::default()
        }
    }

    fn reward_log() -> Log {
        unmined_log(
            Address::with_last_byte(1),
            vec![B256::with_last_byte(2)],
            Bytes::from(vec![3]),
        )
    }

    fn valid_trace() -> (CallFrame, Address, Address, Bytes) {
        let from = Address::with_last_byte(11);
        let to = Address::with_last_byte(12);
        let input = Bytes::from(vec![0xaa, 0xbb]);
        let frame = CallFrame {
            typ: "CALL".into(),
            from,
            to: Some(to),
            value: Some(U256::ZERO),
            input: input.clone(),
            ..Default::default()
        };
        (frame, from, to, input)
    }

    fn assert_trace_identity_field(frame: &CallFrame, field: &'static str) {
        let (_, from, to, input) = valid_trace();
        assert_eq!(
            validate_trace_identity(frame, from, to, &input),
            Err(SimulationBackendError::IdentityMismatch {
                backend: TRACE_BACKEND,
                field,
            })
        );
    }

    fn collect_logs_unconditionally(frame: &CallFrame) -> Result<Vec<Log>, SimulationBackendError> {
        let mut collected = Vec::new();
        let mut pending = vec![frame];
        while let Some(current) = pending.pop() {
            collected.extend(
                current
                    .logs
                    .iter()
                    .map(convert_trace_log)
                    .collect::<Result<Vec<_>, _>>()?,
            );
            pending.extend(current.calls.iter().rev());
        }
        Ok(collected)
    }

    #[test]
    fn caught_reverted_child_log_is_excluded() {
        let child = CallFrame {
            error: Some("execution reverted".into()),
            logs: vec![reward_trace_log()],
            ..Default::default()
        };
        let parent = CallFrame {
            calls: vec![child],
            ..Default::default()
        };

        assert!(collect_committed_logs(&parent)
            .expect("valid frame")
            .is_empty());
    }

    #[test]
    fn successful_nested_log_remains_eligible() {
        let child = CallFrame {
            logs: vec![reward_trace_log()],
            ..Default::default()
        };
        let parent = CallFrame {
            calls: vec![child],
            ..Default::default()
        };

        assert_eq!(
            collect_committed_logs(&parent).expect("valid frame").len(),
            1
        );
    }

    #[test]
    fn failed_ancestor_discards_successful_descendant_logs() {
        let descendant = CallFrame {
            logs: vec![reward_trace_log()],
            ..Default::default()
        };
        let parent = CallFrame {
            error: Some("execution reverted".into()),
            calls: vec![descendant],
            ..Default::default()
        };

        assert!(collect_committed_logs(&parent)
            .expect("valid frame")
            .is_empty());
    }

    #[test]
    fn malformed_trace_log_rejects_complete_evidence() {
        for malformed_log in [
            CallLogFrame {
                address: None,
                ..reward_trace_log()
            },
            CallLogFrame {
                topics: None,
                ..reward_trace_log()
            },
            CallLogFrame {
                data: None,
                ..reward_trace_log()
            },
        ] {
            let frame = CallFrame {
                logs: vec![malformed_log],
                ..Default::default()
            };

            assert!(collect_committed_logs(&frame).is_err());
        }
    }

    #[test]
    fn malformed_log_in_failed_subtree_rejects_complete_evidence() {
        let child = CallFrame {
            error: Some("execution reverted".into()),
            logs: vec![CallLogFrame {
                data: None,
                ..reward_trace_log()
            }],
            ..Default::default()
        };
        let parent = CallFrame {
            calls: vec![child],
            ..Default::default()
        };

        assert!(collect_committed_logs(&parent).is_err());
    }

    #[test]
    fn flat_simulation_logs_are_not_legacy_payment_evidence() {
        let flat = SimulationEvidence {
            gas_used: 21_000,
            logs: vec![reward_log()],
            source: SimulationSource::FlatSimulation,
        };
        let trace = SimulationEvidence {
            gas_used: 21_000,
            logs: vec![reward_log()],
            source: SimulationSource::SuccessfulCallTrace,
        };
        let receipt = SimulationEvidence {
            gas_used: 21_000,
            logs: vec![reward_log()],
            source: SimulationSource::CommittedReceipt,
        };

        assert_eq!(flat.legacy_payment_logs(), None);
        assert_eq!(trace.legacy_payment_logs().map(<[Log]>::len), Some(1));
        assert_eq!(receipt.legacy_payment_logs().map(<[Log]>::len), Some(1));
    }

    #[test]
    fn trace_identity_accepts_exact_call() {
        let (frame, from, to, input) = valid_trace();
        assert_eq!(validate_trace_identity(&frame, from, to, &input), Ok(()));
    }

    #[test]
    fn trace_identity_rejects_non_call_type() {
        let (mut frame, _, _, _) = valid_trace();
        frame.typ = "DELEGATECALL".into();
        assert_trace_identity_field(&frame, "type");
    }

    #[test]
    fn trace_identity_rejects_wrong_sender() {
        let (mut frame, _, _, _) = valid_trace();
        frame.from = Address::with_last_byte(13);
        assert_trace_identity_field(&frame, "from");
    }

    #[test]
    fn trace_identity_rejects_wrong_or_missing_target() {
        let (mut frame, _, _, _) = valid_trace();
        frame.to = Some(Address::with_last_byte(13));
        assert_trace_identity_field(&frame, "to");

        frame.to = None;
        assert_trace_identity_field(&frame, "to");
    }

    #[test]
    fn trace_identity_rejects_wrong_calldata() {
        let (mut frame, _, _, _) = valid_trace();
        frame.input = Bytes::from(vec![0xcc]);
        assert_trace_identity_field(&frame, "input");
    }

    #[test]
    fn trace_identity_rejects_nonzero_or_missing_value() {
        let (mut frame, _, _, _) = valid_trace();
        frame.value = Some(U256::from(1));
        assert_trace_identity_field(&frame, "value");

        frame.value = None;
        assert_trace_identity_field(&frame, "value");
    }

    #[test]
    fn old_collector_accepts_failed_subtree_log_that_production_rejects() {
        let child = CallFrame {
            error: Some("execution reverted".into()),
            logs: vec![reward_trace_log()],
            ..Default::default()
        };
        let parent = CallFrame {
            calls: vec![child],
            ..Default::default()
        };

        assert_eq!(
            collect_logs_unconditionally(&parent)
                .expect("historical collector input is valid")
                .len(),
            1
        );
        assert!(collect_committed_logs(&parent)
            .expect("production collector input is valid")
            .is_empty());
    }

    #[test]
    fn http_timeout_and_transport_failures_have_distinct_categories() {
        assert_eq!(
            classify_http_failure("eth_simulateV1", true),
            SimulationBackendError::Timeout {
                backend: "eth_simulateV1",
            }
        );
        assert_eq!(
            classify_http_failure("eth_simulateV1", false),
            SimulationBackendError::Transport {
                backend: "eth_simulateV1",
            }
        );
    }

    #[test]
    fn unsupported_after_side_effect_becomes_terminal() {
        assert_eq!(
            SimulationBackendError::Unsupported {
                backend: "committed-receipt send",
            }
            .after_side_effect(),
            SimulationBackendError::ExecutionRejected {
                backend: "committed-receipt send",
            }
        );
        assert_eq!(
            SimulationBackendError::StateRestoration
                .into_infrastructure()
                .to_string(),
            "Blockchain error: committed-receipt state restoration failed"
        );
    }

    #[test]
    fn provider_unsupported_variants_allow_fallback() {
        for provider_error in [
            TransportError::UnsupportedFeature("eth_simulateV1"),
            TransportError::ErrorResp(ErrorPayload {
                code: -32601,
                message: "the method eth_simulateV1 does not exist".into(),
                data: None,
            }),
        ] {
            assert_eq!(
                classify_provider_error(&provider_error, "eth_simulateV1"),
                SimulationBackendError::Unsupported {
                    backend: "eth_simulateV1",
                }
            );
        }
    }
}

#[cfg(test)]
mod user_rpc_provider_tests {
    use super::*;
    use axum::http::{header, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::post;
    use axum::{Json, Router};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const UNRESOLVABLE_HOST: &str = "rpc.nox-test.invalid";

    async fn serve(router: Router) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        addr
    }

    async fn counting_rpc_server(hits: Arc<AtomicUsize>) -> SocketAddr {
        serve(Router::new().route(
            "/",
            post(move |Json(request): Json<serde_json::Value>| {
                let hits = hits.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    Json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": request["id"],
                        "result": "0x2a",
                    }))
                }
            }),
        ))
        .await
    }

    fn user_url(port: u16) -> url::Url {
        url::Url::parse(&format!("http://{UNRESOLVABLE_HOST}:{port}/")).expect("valid URL")
    }

    #[tokio::test]
    async fn pinned_provider_connects_to_the_validated_address() {
        let hits = Arc::new(AtomicUsize::new(0));
        let target = counting_rpc_server(hits.clone()).await;

        let provider =
            build_pinned_http1_provider(&user_url(target.port()), IpAddr::V4(Ipv4Addr::LOCALHOST))
                .expect("provider");
        let result: serde_json::Value = provider
            .raw_request(Cow::Borrowed("eth_blockNumber"), ())
            .await
            .expect("pinned request reaches the validated address");

        assert_eq!(result, serde_json::json!("0x2a"));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pinned_provider_does_not_follow_redirects() {
        let hits = Arc::new(AtomicUsize::new(0));
        let target = counting_rpc_server(hits.clone()).await;
        let location = format!("http://{target}/");
        let redirector = serve(Router::new().route(
            "/",
            post(move || {
                let location = location.clone();
                async move {
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        [(header::LOCATION, location)],
                    )
                        .into_response()
                }
            }),
        ))
        .await;

        let provider = build_pinned_http1_provider(
            &user_url(redirector.port()),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .expect("provider");
        let error = provider
            .raw_request::<_, serde_json::Value>(Cow::Borrowed("eth_blockNumber"), ())
            .await
            .expect_err("a redirect must not be followed");

        assert_eq!(hits.load(Ordering::SeqCst), 0);
        assert_eq!(public_rpc_error(&error), "upstream RPC request failed");
    }

    #[tokio::test]
    async fn public_rpc_error_keeps_json_rpc_errors_and_hides_transport_text() {
        let reverting = serve(Router::new().route(
            "/",
            post(|Json(request): Json<serde_json::Value>| async move {
                Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "error": { "code": 3, "message": "execution reverted" },
                }))
            }),
        ))
        .await;
        let provider = build_pinned_http1_provider(
            &user_url(reverting.port()),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .expect("provider");
        let error = provider
            .raw_request::<_, serde_json::Value>(Cow::Borrowed("eth_call"), ())
            .await
            .expect_err("upstream returns a JSON-RPC error");
        assert!(public_rpc_error(&error).contains("execution reverted"));

        let html =
            serve(Router::new().route("/", post(|| async { "<html>internal admin page</html>" })))
                .await;
        let provider =
            build_pinned_http1_provider(&user_url(html.port()), IpAddr::V4(Ipv4Addr::LOCALHOST))
                .expect("provider");
        let error = provider
            .raw_request::<_, serde_json::Value>(Cow::Borrowed("eth_call"), ())
            .await
            .expect_err("a non JSON-RPC body is an error");
        let public = public_rpc_error(&error);
        assert!(!public.contains("internal admin page"), "{public}");
        assert!(!public.contains(UNRESOLVABLE_HOST), "{public}");
    }
}
