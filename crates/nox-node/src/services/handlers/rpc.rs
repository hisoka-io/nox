//! Anonymous JSON-RPC proxy via the mixnet.
//! Default provider path enforces a read-only method whitelist; user-supplied URLs allow any method.

use crate::blockchain::executor::ChainExecutor;
use crate::services::response_packer::{PackResult, ResponsePacker};
use crate::services::security;
use crate::telemetry::metrics::MetricsService;
use nox_core::events::NoxEvent;
use nox_core::models::payloads::{
    decode_payload_limited, RelayerPayload, RpcResponse, ServiceRequest,
};
use nox_core::traits::service::{ServiceError, ServiceHandler};
use nox_core::traits::IEventPublisher;
use nox_crypto::sphinx::surb::Surb;

/// Max size for deserializing inner payloads from `AnonymousRequest` (7 MB).
const MAX_INNER_PAYLOAD_SIZE: u64 = 7 * 1024 * 1024;
use async_trait::async_trait;
use ethers::prelude::*;
use ethers::types::transaction::eip2718::TypedTransaction;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use std::collections::HashSet;
use std::num::NonZeroU32;
use std::sync::Arc;
use tracing::{debug, info, warn};

type RpcRateLimiter = RateLimiter<NotKeyed, InMemoryState, governor::clock::DefaultClock>;

const RPC_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const MAX_LOG_BLOCK_RANGE: u64 = 2000;

pub struct RpcHandler {
    _executor: Option<Arc<ChainExecutor>>,
    response_packer: Arc<ResponsePacker>,
    publisher: Arc<dyn IEventPublisher>,
    allowed_methods: HashSet<String>,
    provider: Provider<Http>,
    rate_limiter: Arc<RpcRateLimiter>,
    metrics: MetricsService,
    allow_private_ips: bool,
}

impl RpcHandler {
    pub fn new(
        executor: Arc<ChainExecutor>,
        response_packer: Arc<ResponsePacker>,
        publisher: Arc<dyn IEventPublisher>,
        rpc_url: &str,
        metrics: MetricsService,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let provider = Provider::<Http>::try_from(rpc_url)?;

        let allowed_methods: HashSet<String> = [
            // Account & state queries
            "eth_call",
            "eth_getBalance",
            "eth_estimateGas",
            "eth_getCode",
            "eth_getStorageAt",
            "eth_getTransactionCount",
            "eth_getProof",
            // Block queries
            "eth_blockNumber",
            "eth_getBlockByNumber",
            "eth_getBlockByHash",
            "eth_getBlockTransactionCountByHash",
            "eth_getBlockTransactionCountByNumber",
            "eth_getBlockReceipts",
            // Transaction queries
            "eth_getTransactionReceipt",
            "eth_getTransactionByHash",
            "eth_getTransactionByBlockHashAndIndex",
            "eth_getTransactionByBlockNumberAndIndex",
            // Log queries
            "eth_getLogs",
            "eth_newFilter",
            "eth_getFilterChanges",
            "eth_getFilterLogs",
            "eth_uninstallFilter",
            // Chain info
            "eth_chainId",
            "eth_gasPrice",
            "eth_maxPriorityFeePerGas",
            "eth_feeHistory",
            "eth_syncing",
            "eth_protocolVersion",
            "net_version",
            "net_listening",
            "net_peerCount",
            "web3_clientVersion",
            // ERC-20 / token helpers (read-only via eth_call, but useful to whitelist)
            "eth_createAccessList",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();

        let quota = Quota::per_second(NonZeroU32::new(100).unwrap_or(NonZeroU32::MIN));
        let rate_limiter = Arc::new(RateLimiter::direct(quota));

        Ok(Self {
            _executor: Some(executor),
            response_packer,
            publisher,
            allowed_methods,
            provider,
            rate_limiter,
            metrics,
            allow_private_ips: false,
        })
    }

    pub fn with_whitelist(
        executor: Arc<ChainExecutor>,
        response_packer: Arc<ResponsePacker>,
        publisher: Arc<dyn IEventPublisher>,
        rpc_url: &str,
        allowed_methods: HashSet<String>,
        metrics: MetricsService,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let provider = Provider::<Http>::try_from(rpc_url)?;

        let quota = Quota::per_second(NonZeroU32::new(100).unwrap_or(NonZeroU32::MIN));
        let rate_limiter = Arc::new(RateLimiter::direct(quota));

        Ok(Self {
            _executor: Some(executor),
            response_packer,
            publisher,
            allowed_methods,
            provider,
            rate_limiter,
            metrics,
            allow_private_ips: false,
        })
    }

    /// Simulation mode: no `ChainExecutor`, proxies directly to `rpc_url`.
    pub fn new_simulation(
        response_packer: Arc<ResponsePacker>,
        publisher: Arc<dyn IEventPublisher>,
        rpc_url: &str,
        metrics: MetricsService,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let provider = Provider::<Http>::try_from(rpc_url)?;

        let allowed_methods: HashSet<String> = [
            "eth_call",
            "eth_getBalance",
            "eth_estimateGas",
            "eth_blockNumber",
            "eth_getTransactionReceipt",
            "eth_getTransactionByHash",
            "eth_getBlockByNumber",
            "eth_getBlockByHash",
            "eth_getLogs",
            "eth_chainId",
            "eth_gasPrice",
            "eth_getCode",
            "eth_getStorageAt",
            "eth_getTransactionCount",
            "eth_sendRawTransaction",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();

        let quota = Quota::per_second(NonZeroU32::new(100).unwrap_or(NonZeroU32::MIN));
        let rate_limiter = Arc::new(RateLimiter::direct(quota));

        Ok(Self {
            _executor: None,
            response_packer,
            publisher,
            allowed_methods,
            provider,
            rate_limiter,
            metrics,
            allow_private_ips: true,
        })
    }

    pub async fn handle_rpc_request(
        &self,
        request_id: u64,
        method: &str,
        params: &[u8],
        rpc_url: Option<&str>,
        surbs: Vec<Surb>,
    ) -> Result<PackResult, ServiceError> {
        if self.rate_limiter.check().is_err() {
            warn!(
                request_id = request_id,
                method = method,
                "RPC rate limit exceeded"
            );
            self.metrics.rpc_rate_limited_total.inc();
            self.metrics
                .rpc_requests_total
                .get_or_create(&vec![
                    ("method".into(), method.to_string()),
                    ("result".into(), "blocked".into()),
                ])
                .inc();
            let response = RpcResponse {
                id: request_id,
                result: Err("Rate limited: too many RPC requests".to_string()),
            };
            let response_bytes = bincode::serialize(&response)
                .map_err(|e| ServiceError::ProcessingFailed(e.to_string()))?;
            return self.pack_and_return(request_id, &response_bytes, surbs);
        }

        let params_value: serde_json::Value = if params.is_empty() {
            serde_json::Value::Array(vec![])
        } else {
            serde_json::from_slice(params)
                .map_err(|e| ServiceError::ProcessingFailed(format!("Invalid JSON params: {e}")))?
        };

        let result = if let Some(url) = rpc_url {
            info!(
                request_id = request_id,
                method = method,
                rpc_url = url,
                "Processing RPC request with user-supplied URL"
            );

            let (resolved_ip, validated_url) =
                match security::validate_url_ssrf(url, self.allow_private_ips).await {
                    Ok(result) => result,
                    Err(e) => {
                        warn!(
                            request_id = request_id,
                            error = %e,
                            "SSRF check blocked user-supplied RPC URL"
                        );
                        self.metrics.rpc_ssrf_blocks_total.inc();
                        self.metrics
                            .rpc_requests_total
                            .get_or_create(&vec![
                                ("method".into(), method.to_string()),
                                ("result".into(), "blocked".into()),
                            ])
                            .inc();
                        let response = RpcResponse {
                            id: request_id,
                            result: Err(format!("RPC URL blocked: {e}")),
                        };
                        let response_bytes = bincode::serialize(&response)
                            .map_err(|e| ServiceError::ProcessingFailed(e.to_string()))?;
                        return self.pack_and_return(request_id, &response_bytes, surbs);
                    }
                };

            // DNS rebinding: connect to resolved IP for HTTP (HTTPS needs hostname for TLS).
            let provider_url = if validated_url.scheme() == "http" {
                let mut ip_url = validated_url.clone();
                if ip_url.set_host(Some(&resolved_ip.to_string())).is_ok() {
                    ip_url.to_string()
                } else {
                    url.to_string()
                }
            } else {
                url.to_string()
            };

            let user_provider = Provider::<Http>::try_from(provider_url.as_str()).map_err(|e| {
                ServiceError::ProcessingFailed(format!("Failed to create provider for {url}: {e}"))
            })?;

            tokio::time::timeout(
                RPC_REQUEST_TIMEOUT,
                Self::execute_rpc_generic(&user_provider, method, params_value),
            )
            .await
            .unwrap_or_else(|_| Err("RPC request timed out".to_string()))
        } else {
            if !self.allowed_methods.contains(method) {
                warn!(
                    request_id = request_id,
                    method = method,
                    "RPC method not in whitelist"
                );
                let response = RpcResponse {
                    id: request_id,
                    result: Err(format!("Method '{method}' not allowed")),
                };
                let response_bytes = bincode::serialize(&response)
                    .map_err(|e| ServiceError::ProcessingFailed(e.to_string()))?;
                return self.pack_and_return(request_id, &response_bytes, surbs);
            }

            info!(
                request_id = request_id,
                method = method,
                params_len = params.len(),
                "Processing RPC request with default provider"
            );

            tokio::time::timeout(RPC_REQUEST_TIMEOUT, self.execute_rpc(method, params_value))
                .await
                .unwrap_or_else(|_| Err("RPC request timed out".to_string()))
        };

        let result_label = if result.is_ok() { "success" } else { "error" };
        self.metrics
            .rpc_requests_total
            .get_or_create(&vec![
                ("method".into(), method.to_string()),
                ("result".into(), result_label.into()),
            ])
            .inc();

        let response = RpcResponse {
            id: request_id,
            result: result.and_then(|v| {
                serde_json::to_vec(&v).map_err(|e| format!("JSON serialization failed: {e}"))
            }),
        };

        let response_bytes = bincode::serialize(&response)
            .map_err(|e| ServiceError::ProcessingFailed(e.to_string()))?;

        debug!(
            request_id = request_id,
            response_len = response_bytes.len(),
            success = response.result.is_ok(),
            "RPC response prepared"
        );

        self.pack_and_return(request_id, &response_bytes, surbs)
    }

    async fn execute_rpc_generic(
        provider: &Provider<Http>,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        provider
            .request::<serde_json::Value, serde_json::Value>(method, params)
            .await
            .map_err(|e| format!("RPC call failed: {e}"))
    }

    async fn execute_rpc(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let params_array = params.as_array().cloned().unwrap_or_default();

        match method {
            "eth_call" => self.handle_eth_call(&params_array).await,
            "eth_getBalance" => self.handle_eth_get_balance(&params_array).await,
            "eth_estimateGas" => self.handle_eth_estimate_gas(&params_array).await,
            "eth_blockNumber" => self.handle_eth_block_number().await,
            "eth_getTransactionReceipt" => {
                self.handle_eth_get_transaction_receipt(&params_array).await
            }
            "eth_getTransactionByHash" => {
                self.handle_eth_get_transaction_by_hash(&params_array).await
            }
            "eth_chainId" => self.handle_eth_chain_id().await,
            "eth_gasPrice" => self.handle_eth_gas_price().await,
            "eth_getLogs" => self.handle_eth_get_logs(&params_array).await,
            "eth_getCode" => self.handle_eth_get_code(&params_array).await,
            "eth_getStorageAt" => self.handle_eth_get_storage_at(&params_array).await,
            "eth_getTransactionCount" => self.handle_eth_get_transaction_count(&params_array).await,
            "eth_getBlockByNumber" => self.handle_eth_get_block_by_number(&params_array).await,
            "eth_getBlockByHash" => self.handle_eth_get_block_by_hash(&params_array).await,
            "eth_sendRawTransaction" => self.handle_eth_send_raw_transaction(&params_array).await,
            _ => Err(format!("Unimplemented method: {method}")),
        }
    }

    async fn handle_eth_call(
        &self,
        params: &[serde_json::Value],
    ) -> Result<serde_json::Value, String> {
        if params.is_empty() {
            return Err("eth_call requires at least 1 parameter".into());
        }

        let tx_obj = &params[0];
        let to = tx_obj["to"]
            .as_str()
            .ok_or("Missing 'to' field")?
            .parse::<Address>()
            .map_err(|e| format!("Invalid 'to' address: {e}"))?;

        let data = match tx_obj["data"].as_str() {
            Some(s) => {
                let hex_str = s.trim_start_matches("0x");
                hex::decode(hex_str).map_err(|e| format!("Invalid calldata hex: {e}"))?
            }
            None => vec![],
        };

        let tx = TransactionRequest::new().to(to).data(Bytes::from(data));

        let result = self
            .provider
            .call(&TypedTransaction::Legacy(tx), None)
            .await
            .map_err(|e| format!("eth_call failed: {e}"))?;

        Ok(serde_json::Value::String(format!(
            "0x{}",
            hex::encode(&result)
        )))
    }

    async fn handle_eth_get_balance(
        &self,
        params: &[serde_json::Value],
    ) -> Result<serde_json::Value, String> {
        if params.is_empty() {
            return Err("eth_getBalance requires at least 1 parameter".into());
        }

        let address = params[0]
            .as_str()
            .ok_or("First param must be address string")?
            .parse::<Address>()
            .map_err(|e| format!("Invalid address: {e}"))?;

        let balance = self
            .provider
            .get_balance(address, None)
            .await
            .map_err(|e| format!("eth_getBalance failed: {e}"))?;

        Ok(serde_json::Value::String(format!("0x{balance:x}")))
    }

    async fn handle_eth_estimate_gas(
        &self,
        params: &[serde_json::Value],
    ) -> Result<serde_json::Value, String> {
        if params.is_empty() {
            return Err("eth_estimateGas requires at least 1 parameter".into());
        }

        let tx_obj = &params[0];
        let mut tx = TransactionRequest::new();

        if let Some(to) = tx_obj["to"].as_str() {
            tx = tx.to(to
                .parse::<Address>()
                .map_err(|e| format!("Invalid 'to': {e}"))?);
        }
        if let Some(data) = tx_obj["data"].as_str() {
            let data_bytes = hex::decode(data.trim_start_matches("0x"))
                .map_err(|e| format!("Invalid calldata hex: {e}"))?;
            tx = tx.data(Bytes::from(data_bytes));
        }
        if let Some(value) = tx_obj["value"].as_str() {
            let value_u256 = U256::from_str_radix(value.trim_start_matches("0x"), 16)
                .map_err(|e| format!("Invalid 'value': {e}"))?;
            tx = tx.value(value_u256);
        }

        let gas = self
            .provider
            .estimate_gas(&TypedTransaction::Legacy(tx), None)
            .await
            .map_err(|e| format!("eth_estimateGas failed: {e}"))?;

        Ok(serde_json::Value::String(format!("0x{gas:x}")))
    }

    async fn handle_eth_block_number(&self) -> Result<serde_json::Value, String> {
        let block = self
            .provider
            .get_block_number()
            .await
            .map_err(|e| format!("eth_blockNumber failed: {e}"))?;

        Ok(serde_json::Value::String(format!("0x{:x}", block.as_u64())))
    }

    async fn handle_eth_get_transaction_receipt(
        &self,
        params: &[serde_json::Value],
    ) -> Result<serde_json::Value, String> {
        if params.is_empty() {
            return Err("eth_getTransactionReceipt requires 1 parameter".into());
        }

        let tx_hash = params[0]
            .as_str()
            .ok_or("First param must be tx hash string")?
            .parse::<H256>()
            .map_err(|e| format!("Invalid tx hash: {e}"))?;

        let receipt = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(|e| format!("eth_getTransactionReceipt failed: {e}"))?;

        match receipt {
            Some(r) => serde_json::to_value(r).map_err(|e| format!("Serialization failed: {e}")),
            None => Ok(serde_json::Value::Null),
        }
    }

    async fn handle_eth_get_transaction_by_hash(
        &self,
        params: &[serde_json::Value],
    ) -> Result<serde_json::Value, String> {
        if params.is_empty() {
            return Err("eth_getTransactionByHash requires 1 parameter".into());
        }

        let tx_hash = params[0]
            .as_str()
            .ok_or("First param must be tx hash string")?
            .parse::<H256>()
            .map_err(|e| format!("Invalid tx hash: {e}"))?;

        let tx = self
            .provider
            .get_transaction(tx_hash)
            .await
            .map_err(|e| format!("eth_getTransactionByHash failed: {e}"))?;

        match tx {
            Some(t) => serde_json::to_value(t).map_err(|e| format!("Serialization failed: {e}")),
            None => Ok(serde_json::Value::Null),
        }
    }

    async fn handle_eth_chain_id(&self) -> Result<serde_json::Value, String> {
        let chain_id = self
            .provider
            .get_chainid()
            .await
            .map_err(|e| format!("eth_chainId failed: {e}"))?;

        Ok(serde_json::Value::String(format!(
            "0x{:x}",
            chain_id.as_u64()
        )))
    }

    async fn handle_eth_gas_price(&self) -> Result<serde_json::Value, String> {
        let gas_price = self
            .provider
            .get_gas_price()
            .await
            .map_err(|e| format!("eth_gasPrice failed: {e}"))?;

        Ok(serde_json::Value::String(format!("0x{gas_price:x}")))
    }

    async fn handle_eth_get_logs(
        &self,
        params: &[serde_json::Value],
    ) -> Result<serde_json::Value, String> {
        if params.is_empty() {
            return Err("eth_getLogs requires 1 parameter".into());
        }

        let filter_obj = &params[0];
        let mut filter = Filter::new();

        if let Some(address) = filter_obj["address"].as_str() {
            filter = filter.address(
                address
                    .parse::<Address>()
                    .map_err(|e| format!("Invalid address: {e}"))?,
            );
        }
        if let Some(from_block) = filter_obj["fromBlock"].as_str() {
            let block = parse_block_number(from_block)?;
            filter = filter.from_block(block);
        }
        if let Some(to_block) = filter_obj["toBlock"].as_str() {
            let block = parse_block_number(to_block)?;
            filter = filter.to_block(block);
        }
        // Block range validation (Audit #166): prevent unbounded log queries.
        // Both fromBlock and toBlock MUST be numeric hex when provided.
        // If either is missing or non-numeric (e.g., "latest"), enforce the max range
        // by requiring the other bound to be within MAX_LOG_BLOCK_RANGE of it.
        {
            let from_num = filter_obj["fromBlock"]
                .as_str()
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());
            let to_num = filter_obj["toBlock"]
                .as_str()
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());
            if let (Some(from), Some(to)) = (from_num, to_num) {
                if to.saturating_sub(from) > MAX_LOG_BLOCK_RANGE {
                    return Err(format!(
                        "Block range too large: {} (max {MAX_LOG_BLOCK_RANGE})",
                        to - from
                    ));
                }
            } else {
                // At least one bound is non-numeric (e.g., "latest", "earliest", or missing).
                // Reject to prevent unbounded queries unless both are absent (which the
                // RPC node handles with its own limits).
                let has_from = filter_obj.get("fromBlock").is_some();
                let has_to = filter_obj.get("toBlock").is_some();
                if (has_from && from_num.is_none()) || (has_to && to_num.is_none()) {
                    return Err(format!(
                        "eth_getLogs requires numeric fromBlock/toBlock for range validation (max {MAX_LOG_BLOCK_RANGE} blocks)"
                    ));
                }
            }
        }

        if let Some(topics) = filter_obj["topics"].as_array() {
            for (i, topic) in topics.iter().enumerate() {
                if let Some(t) = topic.as_str() {
                    if !t.is_empty() {
                        let topic_hash = t
                            .parse::<H256>()
                            .map_err(|e| format!("Invalid topic: {e}"))?;
                        filter = match i {
                            0 => filter.topic0(topic_hash),
                            1 => filter.topic1(topic_hash),
                            2 => filter.topic2(topic_hash),
                            3 => filter.topic3(topic_hash),
                            _ => filter,
                        };
                    }
                }
            }
        }

        let logs = self
            .provider
            .get_logs(&filter)
            .await
            .map_err(|e| format!("eth_getLogs failed: {e}"))?;

        serde_json::to_value(logs).map_err(|e| format!("Serialization failed: {e}"))
    }

    async fn handle_eth_get_code(
        &self,
        params: &[serde_json::Value],
    ) -> Result<serde_json::Value, String> {
        if params.is_empty() {
            return Err("eth_getCode requires at least 1 parameter".into());
        }

        let address = params[0]
            .as_str()
            .ok_or("First param must be address string")?
            .parse::<Address>()
            .map_err(|e| format!("Invalid address: {e}"))?;

        let code = self
            .provider
            .get_code(address, None)
            .await
            .map_err(|e| format!("eth_getCode failed: {e}"))?;

        Ok(serde_json::Value::String(format!(
            "0x{}",
            hex::encode(&code)
        )))
    }

    async fn handle_eth_get_storage_at(
        &self,
        params: &[serde_json::Value],
    ) -> Result<serde_json::Value, String> {
        if params.len() < 2 {
            return Err("eth_getStorageAt requires at least 2 parameters".into());
        }

        let address = params[0]
            .as_str()
            .ok_or("First param must be address string")?
            .parse::<Address>()
            .map_err(|e| format!("Invalid address: {e}"))?;

        let slot = params[1]
            .as_str()
            .ok_or("Second param must be slot string")?
            .parse::<H256>()
            .map_err(|e| format!("Invalid slot: {e}"))?;

        let value = self
            .provider
            .get_storage_at(address, slot, None)
            .await
            .map_err(|e| format!("eth_getStorageAt failed: {e}"))?;

        Ok(serde_json::Value::String(format!(
            "0x{}",
            hex::encode(value.as_bytes())
        )))
    }

    async fn handle_eth_get_transaction_count(
        &self,
        params: &[serde_json::Value],
    ) -> Result<serde_json::Value, String> {
        if params.is_empty() {
            return Err("eth_getTransactionCount requires at least 1 parameter".into());
        }

        let address = params[0]
            .as_str()
            .ok_or("First param must be address string")?
            .parse::<Address>()
            .map_err(|e| format!("Invalid address: {e}"))?;

        let count = self
            .provider
            .get_transaction_count(address, None)
            .await
            .map_err(|e| format!("eth_getTransactionCount failed: {e}"))?;

        Ok(serde_json::Value::String(format!("0x{count:x}")))
    }

    async fn handle_eth_get_block_by_number(
        &self,
        params: &[serde_json::Value],
    ) -> Result<serde_json::Value, String> {
        if params.is_empty() {
            return Err("eth_getBlockByNumber requires at least 1 parameter".into());
        }

        let block_number = params[0]
            .as_str()
            .ok_or("First param must be block number string")?;

        let block_id = parse_block_number(block_number)?;
        let full_txs = params
            .get(1)
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        let block = if full_txs {
            self.provider
                .get_block_with_txs(block_id)
                .await
                .map_err(|e| format!("eth_getBlockByNumber failed: {e}"))?
                .and_then(|b| serde_json::to_value(b).ok())
        } else {
            self.provider
                .get_block(block_id)
                .await
                .map_err(|e| format!("eth_getBlockByNumber failed: {e}"))?
                .and_then(|b| serde_json::to_value(b).ok())
        };

        Ok(block.unwrap_or(serde_json::Value::Null))
    }

    async fn handle_eth_get_block_by_hash(
        &self,
        params: &[serde_json::Value],
    ) -> Result<serde_json::Value, String> {
        if params.is_empty() {
            return Err("eth_getBlockByHash requires at least 1 parameter".into());
        }

        let block_hash = params[0]
            .as_str()
            .ok_or("First param must be block hash string")?
            .parse::<H256>()
            .map_err(|e| format!("Invalid block hash: {e}"))?;

        let full_txs = params
            .get(1)
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        let block = if full_txs {
            self.provider
                .get_block_with_txs(block_hash)
                .await
                .map_err(|e| format!("eth_getBlockByHash failed: {e}"))?
                .and_then(|b| serde_json::to_value(b).ok())
        } else {
            self.provider
                .get_block(block_hash)
                .await
                .map_err(|e| format!("eth_getBlockByHash failed: {e}"))?
                .and_then(|b| serde_json::to_value(b).ok())
        };

        Ok(block.unwrap_or(serde_json::Value::Null))
    }

    async fn handle_eth_send_raw_transaction(
        &self,
        params: &[serde_json::Value],
    ) -> Result<serde_json::Value, String> {
        if params.is_empty() {
            return Err("eth_sendRawTransaction requires 1 parameter (signed tx hex)".into());
        }

        let raw_tx = params[0]
            .as_str()
            .ok_or("First param must be signed transaction hex string")?;

        let tx_bytes: Bytes = raw_tx
            .parse()
            .map_err(|e| format!("Invalid hex for raw transaction: {e}"))?;

        let pending_tx = self
            .provider
            .send_raw_transaction(tx_bytes)
            .await
            .map_err(|e| format!("eth_sendRawTransaction failed: {e}"))?;

        // Return the tx hash
        serde_json::to_value(pending_tx.tx_hash())
            .map_err(|e| format!("Failed to serialize tx hash: {e}"))
    }

    // Helper methods

    fn pack_and_return(
        &self,
        request_id: u64,
        response_bytes: &[u8],
        surbs: Vec<Surb>,
    ) -> Result<PackResult, ServiceError> {
        self.response_packer
            .pack_response(request_id, response_bytes, surbs)
            .map_err(|e| ServiceError::ProcessingFailed(e.to_string()))
    }
}

// Helper function to parse block number strings
fn parse_block_number(s: &str) -> Result<BlockNumber, String> {
    match s {
        "latest" => Ok(BlockNumber::Latest),
        "pending" => Ok(BlockNumber::Pending),
        "earliest" => Ok(BlockNumber::Earliest),
        "finalized" => Ok(BlockNumber::Finalized),
        "safe" => Ok(BlockNumber::Safe),
        _ => {
            let num = u64::from_str_radix(s.trim_start_matches("0x"), 16)
                .map_err(|e| format!("Invalid block number: {e}"))?;
            Ok(BlockNumber::Number(num.into()))
        }
    }
}

#[async_trait]
impl ServiceHandler for RpcHandler {
    fn name(&self) -> &'static str {
        "rpc"
    }

    async fn handle(&self, packet_id: &str, payload: &RelayerPayload) -> Result<(), ServiceError> {
        match payload {
            RelayerPayload::AnonymousRequest { inner, reply_surbs } => {
                // Try to decode as ServiceRequest::RpcRequest (size-bounded to prevent OOM)
                match decode_payload_limited::<ServiceRequest>(inner, MAX_INNER_PAYLOAD_SIZE) {
                    Ok(ServiceRequest::RpcRequest {
                        method,
                        params,
                        id,
                        rpc_url,
                    }) => {
                        let pack_result = self
                            .handle_rpc_request(
                                id,
                                &method,
                                &params,
                                rpc_url.as_deref(),
                                reply_surbs.clone(),
                            )
                            .await?;

                        // Dispatch all response packets to the network
                        for packet in &pack_result.packets {
                            if let Err(e) = self.publisher.publish(NoxEvent::SendPacket {
                                next_hop_peer_id: packet.first_hop.clone(),
                                packet_id: format!("rpc-{}-{}", id, hex::encode(packet.surb_id)),
                                data: packet.packet_bytes.clone(),
                            }) {
                                warn!(
                                    request_id = id,
                                    error = %e,
                                    "Failed to publish RPC response SendPacket -- reply lost"
                                );
                            }
                        }

                        // RPC handler does not yet support SURB replenishment --
                        // remaining data from the distress path is dropped.
                        if pack_result.remaining.is_some() {
                            warn!(
                                request_id = id,
                                method = method,
                                "RPC response partially delivered (SURB exhaustion) -- remaining data dropped"
                            );
                        }

                        info!(
                            request_id = id,
                            method = method,
                            "RPC response packets dispatched to network"
                        );

                        Ok(())
                    }
                    Ok(_) => {
                        // Not an RPC request, ignore
                        debug!(
                            packet_id = packet_id,
                            "RpcHandler received non-RPC ServiceRequest"
                        );
                        Ok(())
                    }
                    Err(e) => {
                        warn!(
                            packet_id = packet_id,
                            error = %e,
                            "Failed to deserialize AnonymousRequest inner"
                        );
                        Ok(())
                    }
                }
            }
            _ => {
                // Ignore other payload types
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nox_core::models::payloads::ServiceRequest;

    #[test]
    fn test_payload_roundtrip_with_rpc_url_none() {
        use nox_core::models::payloads::{decode_payload, encode_payload};
        let request = ServiceRequest::RpcRequest {
            method: "eth_blockNumber".to_string(),
            params: b"[]".to_vec(),
            id: 1,
            rpc_url: None,
        };

        let bytes = encode_payload(&request).unwrap();
        let decoded: ServiceRequest = decode_payload(&bytes).unwrap();

        match decoded {
            ServiceRequest::RpcRequest {
                method,
                params,
                id,
                rpc_url,
            } => {
                assert_eq!(method, "eth_blockNumber");
                assert_eq!(params, b"[]");
                assert_eq!(id, 1);
                assert!(rpc_url.is_none());
            }
            _ => panic!("Expected RpcRequest variant"),
        }
    }

    #[test]
    fn test_payload_roundtrip_with_rpc_url_some() {
        use nox_core::models::payloads::{decode_payload, encode_payload};
        let request = ServiceRequest::RpcRequest {
            method: "eth_sendTransaction".to_string(),
            params: b"[{}]".to_vec(),
            id: 42,
            rpc_url: Some("https://eth-mainnet.g.alchemy.com/v2/key123".to_string()),
        };

        let bytes = encode_payload(&request).unwrap();
        let decoded: ServiceRequest = decode_payload(&bytes).unwrap();

        match decoded {
            ServiceRequest::RpcRequest {
                method,
                params,
                id,
                rpc_url,
            } => {
                assert_eq!(method, "eth_sendTransaction");
                assert_eq!(params, b"[{}]");
                assert_eq!(id, 42);
                assert_eq!(
                    rpc_url,
                    Some("https://eth-mainnet.g.alchemy.com/v2/key123".to_string())
                );
            }
            _ => panic!("Expected RpcRequest variant"),
        }
    }

    #[test]
    fn test_method_whitelist_default() {
        let allowed: HashSet<String> = [
            "eth_call",
            "eth_getBalance",
            "eth_estimateGas",
            "eth_blockNumber",
            "eth_getTransactionReceipt",
            "eth_getTransactionByHash",
            "eth_getBlockByNumber",
            "eth_getBlockByHash",
            "eth_getLogs",
            "eth_chainId",
            "eth_gasPrice",
            "eth_getCode",
            "eth_getStorageAt",
            "eth_getTransactionCount",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();

        // Write methods must NOT be in the whitelist
        assert!(!allowed.contains("eth_sendTransaction"));
        assert!(!allowed.contains("eth_sendRawTransaction"));

        // Read-only methods must be present
        assert!(allowed.contains("eth_call"));
        assert!(allowed.contains("eth_getBalance"));
        assert!(allowed.contains("eth_blockNumber"));
        assert_eq!(allowed.len(), 14);
    }
}
