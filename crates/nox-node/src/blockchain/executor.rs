use ethers::prelude::*;
#[cfg(feature = "dev-node")]
use ethers::providers::MiddlewareError;
use ethers::providers::{ProviderError, RpcError};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{
    BlockId, BlockNumber, CallConfig, CallFrame, CallLogFrame, GethDebugBuiltInTracerConfig,
    GethDebugBuiltInTracerType, GethDebugTracerConfig, GethDebugTracerType,
    GethDebugTracingCallOptions, GethDebugTracingOptions, GethTrace, GethTraceFrame,
};
use std::str::FromStr;
#[cfg(feature = "dev-node")]
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::config::NoxConfig;
use nox_core::traits::InfrastructureError;

pub fn build_ethers_http1_provider(rpc_url: &str) -> Result<Provider<Http>, InfrastructureError> {
    let url = rpc_url.parse::<url::Url>().map_err(|error| {
        InfrastructureError::Blockchain(format!("invalid Ethers RPC URL: {error}"))
    })?;
    let client = reqwest_legacy::Client::builder()
        .http1_only()
        .build()
        .map_err(|error| {
            InfrastructureError::Blockchain(format!(
                "Ethers HTTP/1 client initialization failed: {error}"
            ))
        })?;
    Ok(Provider::new(Http::new_with_client(url, client)))
}

/// Builds an HTTP/1 provider for a user-supplied RPC URL that already passed
/// the SSRF check. The client connects only to `pinned_ip` (the address that
/// was validated), never follows redirects and ignores proxy environment
/// variables, so a request cannot reach an address that was not validated.
pub fn build_pinned_ethers_http1_provider(
    url: &url::Url,
    pinned_ip: std::net::IpAddr,
) -> Result<Provider<Http>, InfrastructureError> {
    let port = url.port_or_known_default().ok_or_else(|| {
        InfrastructureError::Blockchain("RPC URL has no port and no known default".to_string())
    })?;
    let mut builder = reqwest_legacy::Client::builder()
        .http1_only()
        .redirect(reqwest_legacy::redirect::Policy::none())
        .no_proxy();
    if let Some(url::Host::Domain(domain)) = url.host() {
        builder = builder.resolve(domain, std::net::SocketAddr::new(pinned_ip, port));
    }
    let client = builder.build().map_err(|error| {
        InfrastructureError::Blockchain(format!(
            "pinned Ethers HTTP/1 client initialization failed: {error}"
        ))
    })?;
    Ok(Provider::new(Http::new_with_client(url.clone(), client)))
}

/// Text of a provider error that is safe to return to an anonymous client.
///
/// A JSON-RPC error object from the upstream node (revert data, nonce errors)
/// is passed through. Transport and decoding errors are replaced by a fixed
/// message: their text can carry the upstream URL or raw response bodies.
#[must_use]
pub fn public_rpc_error(error: &ProviderError) -> String {
    match RpcError::as_error_response(error) {
        Some(response) => response.to_string(),
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

fn classify_provider_error(error: &ProviderError, backend: &'static str) -> SimulationBackendError {
    if matches!(
        error,
        ProviderError::UnsupportedRPC | ProviderError::UnsupportedNodeClient
    ) || RpcError::as_error_response(error).is_some_and(|response| response.code == -32601)
    {
        return SimulationBackendError::Unsupported { backend };
    }
    if RpcError::as_error_response(error).is_some() {
        return SimulationBackendError::ExecutionRejected { backend };
    }
    if RpcError::is_serde_error(error) {
        return SimulationBackendError::ResponseDecode { backend };
    }
    if let ProviderError::HTTPError(http_error) = error {
        return classify_http_failure(backend, http_error.is_timeout());
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

#[cfg(feature = "dev-node")]
fn classify_middleware_error<E: MiddlewareError<Inner = ProviderError>>(
    error: &E,
    backend: &'static str,
) -> SimulationBackendError {
    error
        .as_inner()
        .map_or(SimulationBackendError::Transport { backend }, |provider| {
            classify_provider_error(provider, backend)
        })
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
    pub transaction_hash: H256,
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
        if receipt.status != Some(U64::one()) {
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
        let gas_used = receipt
            .gas_used
            .ok_or(SimulationBackendError::EvidenceMalformed {
                backend: "committed-receipt",
                field: "gas_used",
            })?;

        for log in &receipt.logs {
            if log.removed != Some(false) {
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
                Some(receipt.transaction_index),
                "log.transaction_index",
            )?;
            require_log_identity(log.block_hash, Some(block_hash), "log.block_hash")?;
            require_log_identity(log.block_number, Some(block_number), "log.block_number")?;
        }

        Ok(Self {
            gas_used: gas_used.as_u64(),
            logs: receipt.logs,
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

    Ok(Log {
        address,
        topics,
        data,
        block_hash: None,
        block_number: None,
        transaction_hash: None,
        transaction_index: None,
        log_index: None,
        transaction_log_index: None,
        log_type: None,
        removed: None,
    })
}

fn collect_committed_logs(frame: &CallFrame) -> Result<Vec<Log>, SimulationBackendError> {
    let mut committed = Vec::new();
    let mut pending = vec![(frame, true)];

    while let Some((current, ancestors_succeeded)) = pending.pop() {
        let frame_succeeded = ancestors_succeeded && current.error.is_none();

        if let Some(frame_logs) = &current.logs {
            for trace_log in frame_logs {
                let converted = convert_trace_log(trace_log)?;
                if frame_succeeded {
                    committed.push(converted);
                }
            }
        }

        if let Some(calls) = &current.calls {
            pending.extend(calls.iter().rev().map(|child| (child, frame_succeeded)));
        }
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
    if frame.to != Some(NameOrAddress::Address(expected_to)) {
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
    if frame.value != Some(U256::zero()) {
        return Err(SimulationBackendError::IdentityMismatch {
            backend: BACKEND,
            field: "value",
        });
    }

    Ok(())
}

pub struct ChainExecutor {
    provider: Provider<Http>,
    wallet: LocalWallet,
    chain_id: u64,
    min_gas_balance: U256,
    /// Mock mode: skip all real blockchain operations (return dummy values).
    /// Only available with `dev-node` feature. Production binaries always have this as `false`.
    #[cfg(feature = "dev-node")]
    is_mock: bool,
}

impl ChainExecutor {
    pub async fn new(config: &NoxConfig) -> Result<Self, InfrastructureError> {
        let provider = build_ethers_http1_provider(&config.eth_rpc_url)?;

        // Determine mock mode -- only available with dev-node feature
        #[cfg(feature = "dev-node")]
        let is_mock = config.benchmark_mode;
        #[cfg(not(feature = "dev-node"))]
        let is_mock = false;

        let chain_id = if is_mock {
            // Mock Mode: Skip RPC
            config.chain_id
        } else if config.chain_id == 0 {
            provider
                .get_chainid()
                .await
                .map_err(|e| {
                    InfrastructureError::Blockchain(format!("Failed to fetch ChainID: {e}"))
                })?
                .as_u64()
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
                    let w = LocalWallet::new(&mut rand::rngs::OsRng);
                    hex::encode(w.signer().to_bytes())
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

        let wallet = LocalWallet::from_str(&wallet_str)
            .map_err(|e| InfrastructureError::Blockchain(format!("Invalid Private Key: {e}")))?
            .with_chain_id(chain_id);

        let min_gas_balance = U256::from_dec_str(&config.min_gas_balance)
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

        let block = self
            .provider
            .get_block(BlockNumber::Latest)
            .await
            .map_err(|error| {
                InfrastructureError::Blockchain(format!(
                    "latest block timestamp lookup failed: {error}"
                ))
            })?
            .ok_or_else(|| {
                InfrastructureError::Blockchain(
                    "latest block timestamp lookup returned no block".to_string(),
                )
            })?;
        if block.timestamp > U256::from(u64::MAX) {
            return Err(InfrastructureError::Blockchain(
                "latest block timestamp exceeds u64".to_string(),
            ));
        }
        Ok(block.timestamp.as_u64())
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
            .get_balance(self.wallet.address(), None)
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
            .request("eth_simulateV1", params)
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

        // Extract logs -> convert to ethers::types::Log
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

    /// Parse event logs from an `eth_simulateV1` call result into `ethers::types::Log`.
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
                let address = Address::from_str(address_str).map_err(|_| {
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
                let topics: Vec<H256> = topics_json
                    .iter()
                    .map(|topic| {
                        let encoded =
                            topic
                                .as_str()
                                .ok_or(SimulationBackendError::EvidenceMalformed {
                                    backend: "eth_simulateV1",
                                    field: "log.topics",
                                })?;
                        H256::from_str(encoded).map_err(|_| {
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

                Ok(Log {
                    address,
                    topics,
                    data: Bytes::from(data_bytes),
                    block_hash: None,
                    block_number: None,
                    transaction_hash: None,
                    transaction_index: None,
                    log_index: None,
                    transaction_log_index: None,
                    log_type: None,
                    removed: None,
                })
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
            .request("evm_snapshot", ())
            .await
            .map_err(|error| classify_provider_error(&error, "evm_snapshot"))?;

        // Anvil auto-mines by default
        let client = SignerMiddleware::new(self.provider.clone(), self.wallet.clone());
        let tx = TransactionRequest::new()
            .from(self.wallet.address())
            .to(to)
            .data(data.clone());

        let result = async {
            let pending = client
                .send_transaction(tx, None)
                .await
                .map_err(|error| classify_middleware_error(&error, "committed-receipt send"))?;
            let tx_hash = pending.tx_hash();

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
                    from: self.wallet.address(),
                    to,
                },
            )
        }
        .await
        .map_err(SimulationBackendError::after_side_effect);

        let reverted = self
            .provider
            .request::<_, bool>("evm_revert", [snapshot_id])
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
        let tx = TransactionRequest::new()
            .from(self.wallet.address())
            .to(to)
            .data(data.clone());

        let tracing_options = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::CallTracer,
            )),
            tracer_config: Some(GethDebugTracerConfig::BuiltInTracer(
                GethDebugBuiltInTracerConfig::CallTracer(CallConfig {
                    only_top_call: None,
                    with_log: Some(true),
                }),
            )),
            ..Default::default()
        };

        let options = GethDebugTracingCallOptions {
            tracing_options,
            state_overrides: None,
            block_overrides: None,
        };

        let typed_tx = TypedTransaction::Legacy(tx.clone());

        let trace = self
            .provider
            .debug_trace_call(
                typed_tx,
                Some(BlockId::Number(BlockNumber::Latest)),
                options,
            )
            .await
            .map_err(|error| classify_provider_error(&error, "debug_traceCall"))?;

        let logs = match trace {
            GethTrace::Known(GethTraceFrame::CallTracer(frame)) => {
                validate_trace_identity(&frame, self.wallet.address(), to, &data)?;
                if frame.error.is_some() {
                    return Err(SimulationBackendError::ExecutionRejected {
                        backend: "debug_traceCall",
                    });
                }
                collect_committed_logs(&frame)?
            }
            GethTrace::Known(
                GethTraceFrame::Default(_)
                | GethTraceFrame::NoopTracer(_)
                | GethTraceFrame::FourByteTracer(_)
                | GethTraceFrame::PreStateTracer(_),
            )
            | GethTrace::Unknown(_) => {
                return Err(SimulationBackendError::EvidenceMalformed {
                    backend: "debug_traceCall",
                    field: "trace.variant",
                });
            }
        };

        let gas_used = self
            .provider
            .estimate_gas(&TypedTransaction::Legacy(tx), None)
            .await
            .map_err(|error| classify_provider_error(&error, "eth_estimateGas"))?
            .as_u64();

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

        let tx = TransactionRequest::new()
            .from(self.wallet.address())
            .to(to)
            .data(data);

        match self
            .provider
            .estimate_gas(&TypedTransaction::Legacy(tx), None)
            .await
        {
            Ok(gas) => Ok(gas.as_u64()),
            Err(e) => {
                // Log the raw error so we can see the revert reason (e.g. "execution reverted: ...")
                warn!("[ChainExecutor] Gas estimation failed: {:?}", e);
                Err(InfrastructureError::Blockchain(format!(
                    "Simulation failed: {e}"
                )))
            }
        }
    }

    /// Execution: Signs and Broadcasts.
    pub async fn submit_transaction(
        &self,
        to: Address,
        data: Bytes,
        gas_limit: U256,
    ) -> Result<H256, InfrastructureError> {
        if self.is_mock() {
            let tx_hash = H256::random();
            info!("[MOCK] Transaction Broadcasted: {:?}", tx_hash);
            return Ok(tx_hash);
        }

        let client = SignerMiddleware::new(self.provider.clone(), self.wallet.clone());

        let gas_price = self
            .provider
            .get_gas_price()
            .await
            .map_err(|e| InfrastructureError::Blockchain(format!("Gas price failed: {e}")))?;

        // Add 3% tip for speed
        let adjusted_gas_price = gas_price * (100 + 3) / 100;

        let tx = TransactionRequest::new()
            .to(to)
            .value(0)
            .data(data)
            .gas(gas_limit)
            .gas_price(adjusted_gas_price);

        let pending_tx = client
            .send_transaction(tx, None)
            .await
            .map_err(|e| InfrastructureError::Blockchain(format!("Broadcast failed: {e}")))?;

        let tx_hash = pending_tx.tx_hash();
        info!(
            "Transaction Broadcasted: {:?} (Price: {} gwei)",
            tx_hash,
            adjusted_gas_price / 1_000_000_000
        );

        Ok(tx_hash)
    }

    // For Read-Only Queries
    pub async fn query_state(
        &self,
        to: Address,
        data: Bytes,
    ) -> Result<Bytes, InfrastructureError> {
        let tx = TransactionRequest::new().to(to).data(data);
        let result = self
            .provider
            .call(&TypedTransaction::Legacy(tx), None)
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
            .map_err(|e| InfrastructureError::Blockchain(format!("Failed to get gas price: {e}")))
    }

    pub async fn get_nonce(&self) -> Result<U256, InfrastructureError> {
        if self.is_mock() {
            return Ok(U256::zero());
        }

        self.provider
            .get_transaction_count(
                self.wallet.address(),
                Some(BlockId::Number(BlockNumber::Pending)),
            )
            .await
            .map_err(|e| InfrastructureError::Blockchain(format!("Get nonce failed: {e}")))
    }

    /// Nonce of the next transaction in the latest block, ignoring the mempool.
    pub async fn get_confirmed_nonce(&self) -> Result<U256, InfrastructureError> {
        if self.is_mock() {
            return Ok(U256::zero());
        }

        self.provider
            .get_transaction_count(
                self.wallet.address(),
                Some(BlockId::Number(BlockNumber::Latest)),
            )
            .await
            .map_err(|e| {
                InfrastructureError::Blockchain(format!("Get confirmed nonce failed: {e}"))
            })
    }

    /// Fetch the transaction receipt for a given tx hash.
    pub async fn get_transaction_receipt(
        &self,
        tx_hash: H256,
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

        let from = self.wallet.address();
        let tx = TransactionRequest::new().from(from).to(to).data(data);

        self.provider
            .estimate_gas(&TypedTransaction::Legacy(tx), None)
            .await
            .map(|g| g.as_u64())
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
            chain_data_fee_native: U256::zero(),
        })
    }

    pub async fn send_raw(&self, tx: TransactionRequest) -> Result<H256, InfrastructureError> {
        if self.is_mock() {
            return Ok(H256::random());
        }

        let client = SignerMiddleware::new(self.provider.clone(), self.wallet.clone());

        let pending = client
            .send_transaction(tx, None)
            .await
            .map_err(|e| InfrastructureError::Blockchain(format!("Send raw failed: {e}")))?;

        Ok(pending.tx_hash())
    }

    pub async fn sign_legacy_transaction(
        &self,
        to: Address,
        data: Bytes,
        nonce: U256,
        gas_limit: U256,
        gas_price: U256,
    ) -> Result<Bytes, InfrastructureError> {
        let transaction = TransactionRequest::new()
            .from(self.wallet.address())
            .to(to)
            .data(data)
            .nonce(nonce)
            .gas(gas_limit)
            .gas_price(gas_price)
            .chain_id(self.chain_id);
        let typed = TypedTransaction::Legacy(transaction);
        let signature = self
            .wallet
            .sign_transaction(&typed)
            .await
            .map_err(|error| {
                InfrastructureError::Blockchain(format!("offline signing failed: {error}"))
            })?;
        Ok(typed.rlp_signed(&signature))
    }

    pub fn sign_execution_digest(&self, digest: H256) -> Result<Vec<u8>, InfrastructureError> {
        self.wallet
            .sign_hash(digest)
            .map(|signature| signature.to_vec())
            .map_err(|error| {
                InfrastructureError::Blockchain(format!("execution quote signing failed: {error}"))
            })
    }

    /// Broadcast a pre-signed raw transaction via `eth_sendRawTransaction`.
    ///
    /// Unlike [`send_raw`](Self::send_raw) which signs via `SignerMiddleware`,
    /// this forwards already-signed bytes directly to the RPC node.
    /// The signer encoded in the raw bytes pays gas.
    pub async fn broadcast_raw_signed_tx(
        &self,
        raw_tx: &[u8],
    ) -> Result<H256, InfrastructureError> {
        self.broadcast_outbox_raw_signed_tx(raw_tx)
            .await
            .map_err(|error| InfrastructureError::Blockchain(error.to_string()))
    }

    pub(crate) async fn broadcast_outbox_raw_signed_tx(
        &self,
        raw_tx: &[u8],
    ) -> Result<H256, OutboxBroadcastError> {
        let expected_hash = H256::from(ethers::utils::keccak256(raw_tx));
        if self.is_mock() {
            return Ok(expected_hash);
        }

        let pending = self
            .provider
            .send_raw_transaction(Bytes::from(raw_tx.to_vec()))
            .await
            .map_err(classify_broadcast_provider_error)?;

        let rpc_hash = pending.tx_hash();
        if rpc_hash != expected_hash {
            return Err(OutboxBroadcastError::Uncertain {
                detail: "RPC returned a mismatched transaction hash",
            });
        }
        Ok(rpc_hash)
    }
}

fn classify_broadcast_provider_error(error: ProviderError) -> OutboxBroadcastError {
    let Some(response) = RpcError::as_error_response(&error) else {
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
    use ethers::types::CallLogFrame;

    const TRACE_BACKEND: &str = "debug_traceCall";

    #[test]
    fn connection_reset_and_http_5xx_are_uncertain_broadcasts() {
        for detail in ["connection reset by peer", "HTTP status 503"] {
            assert_eq!(
                classify_broadcast_provider_error(ProviderError::CustomError(detail.to_string())),
                OutboxBroadcastError::Uncertain {
                    detail: "transport, server, or response failure"
                }
            );
        }
    }

    async fn executor_with_rpc_url(rpc_url: &str) -> ChainExecutor {
        let provider = Provider::<Http>::try_from(rpc_url).expect("test provider URL");
        let wallet = LocalWallet::new(&mut rand::rngs::OsRng).with_chain_id(31_337_u64);
        ChainExecutor {
            provider,
            wallet,
            chain_id: 31_337,
            min_gas_balance: U256::zero(),
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
            ProviderError::JsonRpcClientError(Box::new(
                ethers::providers::HttpClientError::JsonRpcError(ethers::providers::JsonRpcError {
                    code: -32000,
                    message: message.to_string(),
                    data: None,
                }),
            ))
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
        let asset = Address::from_low_u64_be(2);
        let payer = Address::from_low_u64_be(3);
        let mut asset_topic = [0_u8; 32];
        asset_topic[12..].copy_from_slice(asset.as_bytes());
        let mut payer_topic = [0_u8; 32];
        payer_topic[12..].copy_from_slice(payer.as_bytes());
        let mut amount = [0_u8; 32];
        U256::from(4).to_big_endian(&mut amount);
        CallLogFrame {
            address: Some(Address::from_low_u64_be(1)),
            topics: Some(vec![
                H256::from(ethers::utils::keccak256(
                    "RewardsDeposited(address,address,uint256)",
                )),
                H256::from(asset_topic),
                H256::from(payer_topic),
            ]),
            data: Some(Bytes::from(amount.to_vec())),
        }
    }

    fn reward_log() -> Log {
        Log {
            address: Address::from_low_u64_be(1),
            topics: vec![H256::from_low_u64_be(2)],
            data: Bytes::from(vec![3]),
            ..Default::default()
        }
    }

    fn valid_trace() -> (CallFrame, Address, Address, Bytes) {
        let from = Address::from_low_u64_be(11);
        let to = Address::from_low_u64_be(12);
        let input = Bytes::from(vec![0xaa, 0xbb]);
        let frame = CallFrame {
            typ: "CALL".into(),
            from,
            to: Some(NameOrAddress::Address(to)),
            value: Some(U256::zero()),
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
            if let Some(logs) = &current.logs {
                collected.extend(
                    logs.iter()
                        .map(convert_trace_log)
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }
            if let Some(calls) = &current.calls {
                pending.extend(calls.iter().rev());
            }
        }
        Ok(collected)
    }

    #[test]
    fn caught_reverted_child_log_is_excluded() {
        let child = CallFrame {
            error: Some("execution reverted".into()),
            logs: Some(vec![reward_trace_log()]),
            ..Default::default()
        };
        let parent = CallFrame {
            calls: Some(vec![child]),
            ..Default::default()
        };

        assert!(collect_committed_logs(&parent)
            .expect("valid frame")
            .is_empty());
    }

    #[test]
    fn successful_nested_log_remains_eligible() {
        let child = CallFrame {
            logs: Some(vec![reward_trace_log()]),
            ..Default::default()
        };
        let parent = CallFrame {
            calls: Some(vec![child]),
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
            logs: Some(vec![reward_trace_log()]),
            ..Default::default()
        };
        let parent = CallFrame {
            error: Some("execution reverted".into()),
            calls: Some(vec![descendant]),
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
                logs: Some(vec![malformed_log]),
                ..Default::default()
            };

            assert!(collect_committed_logs(&frame).is_err());
        }
    }

    #[test]
    fn malformed_log_in_failed_subtree_rejects_complete_evidence() {
        let child = CallFrame {
            error: Some("execution reverted".into()),
            logs: Some(vec![CallLogFrame {
                data: None,
                ..reward_trace_log()
            }]),
            ..Default::default()
        };
        let parent = CallFrame {
            calls: Some(vec![child]),
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
        frame.from = Address::from_low_u64_be(13);
        assert_trace_identity_field(&frame, "from");
    }

    #[test]
    fn trace_identity_rejects_wrong_or_missing_target() {
        let (mut frame, _, _, _) = valid_trace();
        frame.to = Some(NameOrAddress::Address(Address::from_low_u64_be(13)));
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
        frame.value = Some(U256::one());
        assert_trace_identity_field(&frame, "value");

        frame.value = None;
        assert_trace_identity_field(&frame, "value");
    }

    #[test]
    fn old_collector_accepts_failed_subtree_log_that_production_rejects() {
        let child = CallFrame {
            error: Some("execution reverted".into()),
            logs: Some(vec![reward_trace_log()]),
            ..Default::default()
        };
        let parent = CallFrame {
            calls: Some(vec![child]),
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
            ProviderError::UnsupportedRPC,
            ProviderError::UnsupportedNodeClient,
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

        let provider = build_pinned_ethers_http1_provider(
            &user_url(target.port()),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .expect("provider");
        let result: serde_json::Value = provider
            .request("eth_blockNumber", ())
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

        let provider = build_pinned_ethers_http1_provider(
            &user_url(redirector.port()),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .expect("provider");
        let error = provider
            .request::<_, serde_json::Value>("eth_blockNumber", ())
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
        let provider = build_pinned_ethers_http1_provider(
            &user_url(reverting.port()),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .expect("provider");
        let error = provider
            .request::<_, serde_json::Value>("eth_call", ())
            .await
            .expect_err("upstream returns a JSON-RPC error");
        assert!(public_rpc_error(&error).contains("execution reverted"));

        let html =
            serve(Router::new().route("/", post(|| async { "<html>internal admin page</html>" })))
                .await;
        let provider = build_pinned_ethers_http1_provider(
            &user_url(html.port()),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .expect("provider");
        let error = provider
            .request::<_, serde_json::Value>("eth_call", ())
            .await
            .expect_err("a non JSON-RPC body is an error");
        let public = public_rpc_error(&error);
        assert!(!public.contains("internal admin page"), "{public}");
        assert!(!public.contains(UNRESOLVABLE_HOST), "{public}");
    }
}
