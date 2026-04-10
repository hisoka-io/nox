use ethers::prelude::*;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{
    BlockId, BlockNumber, CallConfig, CallFrame, GethDebugBuiltInTracerConfig,
    GethDebugBuiltInTracerType, GethDebugTracerConfig, GethDebugTracerType,
    GethDebugTracingCallOptions, GethDebugTracingOptions, GethTrace, GethTraceFrame,
};
use std::str::FromStr;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::config::NoxConfig;
use nox_core::traits::InfrastructureError;

pub struct ChainExecutor {
    provider: Provider<Http>,
    wallet: LocalWallet,
    _chain_id: u64,
    min_gas_balance: U256,
    /// Mock mode: skip all real blockchain operations (return dummy values).
    /// Only available with `dev-node` feature. Production binaries always have this as `false`.
    #[cfg(feature = "dev-node")]
    is_mock: bool,
}

impl ChainExecutor {
    pub async fn new(config: &NoxConfig) -> Result<Self, InfrastructureError> {
        let provider = Provider::<Http>::try_from(&config.eth_rpc_url)
            .map_err(|e| InfrastructureError::Blockchain(format!("Invalid RPC URL: {e}")))?;

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
            _chain_id: chain_id,
            min_gas_balance,
            #[cfg(feature = "dev-node")]
            is_mock,
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

    /// Check balance and warn if low.
    pub async fn check_gas_health(&self) -> Result<(), InfrastructureError> {
        if self.is_mock() {
            return Ok(());
        }

        let balance = self
            .provider
            .get_balance(self.wallet.address(), None)
            .await
            .map_err(|e| InfrastructureError::Blockchain(format!("Failed to get balance: {e}")))?;

        if balance < self.min_gas_balance {
            warn!(
                "LOW GAS BALANCE: {} wei (Threshold: {})",
                balance, self.min_gas_balance
            );
            // In v1, we might fire a SystemEvent::LowGas here
        }
        Ok(())
    }

    pub fn address(&self) -> Address {
        self.wallet.address()
    }

    /// Simulation with Logs: Executes the transaction in a sandboxed environment
    /// and extracts emitted events for profitability analysis.
    ///
    /// **Production**: `debug_traceCall` with `callTracer` + `withLog: true` (Geth).
    /// **Dev** (`--features dev-node`): tries `eth_simulateV1` first (stateless, returns
    /// full nested logs), then `evm_snapshot`/`evm_revert`, then `debug_traceCall`.
    /// Anvil silently ignores `withLog` in callTracer, so the first two strategies
    /// are required for full nested logs on dev nodes.
    pub async fn simulate_transaction_with_logs(
        &self,
        to: Address,
        data: Bytes,
    ) -> Result<(u64, Vec<Log>), InfrastructureError> {
        if self.is_mock() {
            return Ok((100_000, vec![]));
        }

        // Primary: eth_simulateV1 (stateless, returns full nested logs).
        // Works on Geth 1.14+, Arbitrum, and most modern L2s.
        match self.simulate_via_eth_simulate(to, data.clone()).await {
            Ok((gas, logs)) => {
                info!(
                    "Simulation via eth_simulateV1: gas_used={}, logs={}",
                    gas,
                    logs.len()
                );
                return Ok((gas, logs));
            }
            Err(e) => {
                info!("eth_simulateV1 unavailable: {e}. Trying fallbacks.");
            }
        }

        // Dev-only fallback: snapshot -> send -> receipt -> revert (Anvil/Hardhat)
        #[cfg(feature = "dev-node")]
        {
            match self.simulate_via_receipt(to, data.clone()).await {
                Ok((gas, logs)) => {
                    info!(
                        "Simulation via snapshot/revert: gas_used={}, logs={}",
                        gas,
                        logs.len()
                    );
                    return Ok((gas, logs));
                }
                Err(e) => {
                    info!("Snapshot/revert FAILED: {e}. Falling back to debug_traceCall.");
                }
            }
        }

        // Last resort: debug_traceCall with callTracer + withLog (Geth only)
        self.simulate_via_trace(to, data).await
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
    ) -> Result<(u64, Vec<Log>), InfrastructureError> {
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
            .map_err(|e| {
                InfrastructureError::Blockchain(format!("eth_simulateV1 RPC failed: {e}"))
            })?;

        // Parse response: result[0]["calls"][0]
        let block = result.get(0).ok_or_else(|| {
            InfrastructureError::Blockchain("eth_simulateV1: empty response array".into())
        })?;
        let call_result = block.get("calls").and_then(|c| c.get(0)).ok_or_else(|| {
            InfrastructureError::Blockchain("eth_simulateV1: no call results in response".into())
        })?;

        // Check status (0x1 = success)
        let status = call_result
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("0x0");
        if status != "0x1" {
            let return_data = call_result
                .get("returnData")
                .and_then(|r| r.as_str())
                .unwrap_or("0x");
            return Err(InfrastructureError::Blockchain(format!(
                "eth_simulateV1: call reverted (status={status}, returnData={return_data})"
            )));
        }

        // Extract gasUsed
        let gas_hex = call_result
            .get("gasUsed")
            .and_then(|g| g.as_str())
            .unwrap_or("0x0");
        let gas_used = u64::from_str_radix(gas_hex.trim_start_matches("0x"), 16).map_err(|e| {
            InfrastructureError::Blockchain(format!(
                "eth_simulateV1: invalid gasUsed '{gas_hex}': {e}"
            ))
        })?;

        // Extract logs -> convert to ethers::types::Log
        let logs = Self::parse_simulate_logs(call_result);

        // Diagnostic: log raw response when 0 logs despite success
        if logs.is_empty() {
            let raw_preview: String = serde_json::to_string(call_result)
                .unwrap_or_else(|_| "<serialization_error>".to_string())
                .chars()
                .take(2000)
                .collect();
            warn!(
                "eth_simulateV1: 0 logs despite status=0x1 (gas_used={}). \
                 Raw call_result preview: {}",
                gas_used, raw_preview
            );
        }

        debug!(
            "eth_simulateV1: gas_used={}, logs={}, status={}",
            gas_used,
            logs.len(),
            status
        );

        Ok((gas_used, logs))
    }

    /// Parse event logs from an `eth_simulateV1` call result into `ethers::types::Log`.
    fn parse_simulate_logs(call_result: &serde_json::Value) -> Vec<Log> {
        let Some(logs_array) = call_result.get("logs").and_then(|l| l.as_array()) else {
            return vec![];
        };

        logs_array
            .iter()
            .filter_map(|log_json| {
                let address_str = log_json.get("address")?.as_str()?;
                let address = Address::from_str(address_str).ok()?;

                let topics: Vec<H256> = log_json
                    .get("topics")?
                    .as_array()?
                    .iter()
                    .filter_map(|t| {
                        let s = t.as_str()?;
                        H256::from_str(s).ok()
                    })
                    .collect();

                let data_str = log_json
                    .get("data")
                    .and_then(|d| d.as_str())
                    .unwrap_or("0x");
                let data_hex = data_str.trim_start_matches("0x");
                let data_bytes = hex::decode(data_hex).unwrap_or_default();

                Some(Log {
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
    ) -> Result<(u64, Vec<Log>), InfrastructureError> {
        let snapshot_id: U256 = self
            .provider
            .request("evm_snapshot", ())
            .await
            .map_err(|e| {
                InfrastructureError::Blockchain(format!("evm_snapshot unavailable: {e}"))
            })?;

        // Anvil auto-mines by default
        let client = SignerMiddleware::new(self.provider.clone(), self.wallet.clone());
        let tx = TransactionRequest::new()
            .from(self.wallet.address())
            .to(to)
            .data(data);

        let result = async {
            let pending = client.send_transaction(tx, None).await.map_err(|e| {
                InfrastructureError::Blockchain(format!("Simulation tx send failed: {e}"))
            })?;
            let tx_hash = pending.tx_hash();

            let receipt = self
                .provider
                .get_transaction_receipt(tx_hash)
                .await
                .map_err(|e| {
                    InfrastructureError::Blockchain(format!(
                        "Failed to get simulation receipt: {e}"
                    ))
                })?
                .ok_or_else(|| {
                    InfrastructureError::Blockchain(
                        "No receipt for simulation tx (block not mined?)".into(),
                    )
                })?;

            // Check for revert
            if receipt.status == Some(U64::from(0)) {
                return Err(InfrastructureError::Blockchain(
                    "Simulation tx reverted on-chain (receipt.status=0)".into(),
                ));
            }

            let gas_used = receipt.gas_used.unwrap_or_default().as_u64();
            debug!(
                "Simulation receipt: tx={:?}, status={:?}, gas_used={}, logs={}",
                tx_hash,
                receipt.status,
                gas_used,
                receipt.logs.len()
            );

            if receipt.logs.is_empty() && receipt.status == Some(U64::from(1)) {
                warn!(
                    "Simulation receipt has 0 logs despite status=1 (gas_used={}). \
                     This is a known Anvil limitation with snapshot/revert. \
                     eth_simulateV1 should be preferred (runs first in dev-node mode).",
                    gas_used
                );
            }

            Ok((gas_used, receipt.logs))
        }
        .await;

        // ALWAYS revert state (even on error) -- fresh snapshot per cycle
        if let Err(e) = self
            .provider
            .request::<_, bool>("evm_revert", [snapshot_id])
            .await
        {
            warn!("evm_revert failed (state may be inconsistent): {e}");
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
    ) -> Result<(u64, Vec<Log>), InfrastructureError> {
        let tx = TransactionRequest::new()
            .from(self.wallet.address())
            .to(to)
            .data(data);

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

        match self
            .provider
            .debug_trace_call(
                typed_tx,
                Some(BlockId::Number(BlockNumber::Latest)),
                options,
            )
            .await
        {
            Ok(trace) => {
                let logs = match &trace {
                    GethTrace::Known(GethTraceFrame::CallTracer(frame)) => {
                        let extracted = ChainExecutor::flatten_logs(frame);
                        debug!(
                            "debug_traceCall: CallTracer frame. \
                             top_level_logs={}, nested_calls={}, extracted_logs={}",
                            frame.logs.as_ref().map_or(0, Vec::len),
                            frame.calls.as_ref().map_or(0, Vec::len),
                            extracted.len()
                        );
                        if extracted.is_empty() {
                            warn!(
                                "debug_traceCall returned 0 logs. \
                                 top_level_logs_present={}, nested_calls={}, \
                                 frame_type={}, frame_error={:?}. \
                                 If running on Anvil, this is expected (withLog not supported).",
                                frame.logs.is_some(),
                                frame.calls.as_ref().map_or(0, Vec::len),
                                frame.typ,
                                frame.error
                            );
                            if let Some(calls) = &frame.calls {
                                for (i, sub) in calls.iter().enumerate() {
                                    warn!(
                                        "  subcall[{}]: type={}, to={:?}, \
                                         logs={}, nested_calls={}, error={:?}",
                                        i,
                                        sub.typ,
                                        sub.to,
                                        sub.logs.as_ref().map_or(0, Vec::len),
                                        sub.calls.as_ref().map_or(0, Vec::len),
                                        sub.error
                                    );
                                }
                            }
                        }
                        extracted
                    }
                    GethTrace::Known(other_frame) => {
                        warn!(
                            "debug_traceCall: unexpected trace variant: {:?}. Returning 0 logs.",
                            std::mem::discriminant(other_frame)
                        );
                        vec![]
                    }
                    GethTrace::Unknown(raw_json) => {
                        warn!(
                            "debug_traceCall: Unknown trace (ethers-rs deserialization fell \
                             through to raw JSON). Preview: {}",
                            serde_json::to_string(raw_json)
                                .unwrap_or_else(|_| "<serialization_error>".to_string())
                                .chars()
                                .take(500)
                                .collect::<String>()
                        );
                        vec![]
                    }
                };

                let gas = self
                    .provider
                    .estimate_gas(&TypedTransaction::Legacy(tx), None)
                    .await
                    .map_err(|e| {
                        InfrastructureError::Blockchain(format!(
                            "Gas estimation failed (tx likely reverts): {e}"
                        ))
                    })?
                    .as_u64();

                Ok((gas, logs))
            }
            Err(e) => Err(InfrastructureError::Blockchain(format!(
                "debug_traceCall failed: {e}"
            ))),
        }
    }

    fn flatten_logs(frame: &CallFrame) -> Vec<Log> {
        let mut logs = vec![];
        if let Some(frame_logs) = &frame.logs {
            for l in frame_logs {
                logs.push(Log {
                    address: l.address.unwrap_or_default(),
                    topics: l.topics.clone().unwrap_or_default(),
                    data: l.data.clone().unwrap_or_default(),
                    // Defaults for simulated log
                    block_hash: None,
                    block_number: None,
                    transaction_hash: None,
                    transaction_index: None,
                    log_index: None,
                    transaction_log_index: None,
                    log_type: None,
                    removed: None,
                });
            }
        }
        if let Some(frame_calls) = &frame.calls {
            for sub in frame_calls {
                logs.extend(ChainExecutor::flatten_logs(sub));
            }
        }
        logs
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

    /// Broadcast a pre-signed raw transaction via `eth_sendRawTransaction`.
    ///
    /// Unlike [`send_raw`](Self::send_raw) which signs via `SignerMiddleware`,
    /// this forwards already-signed bytes directly to the RPC node.
    /// The user pays gas from their own wallet.
    pub async fn broadcast_raw_signed_tx(
        &self,
        raw_tx: &[u8],
    ) -> Result<H256, InfrastructureError> {
        if self.is_mock() {
            return Ok(H256::random());
        }

        let pending = self
            .provider
            .send_raw_transaction(Bytes::from(raw_tx.to_vec()))
            .await
            .map_err(|e| {
                InfrastructureError::Blockchain(format!("Broadcast signed TX failed: {e}"))
            })?;

        Ok(pending.tx_hash())
    }
}
