//! Ethereum TX handler: simulate, profitability-check, and submit on-chain.

use crate::blockchain::executor::ChainExecutor;
use crate::blockchain::tx_manager::TransactionManager;
use crate::price::client::PriceSource;
use crate::services::profitability::ProfitabilityCalculator;
use crate::services::security;
use crate::telemetry::metrics::MetricsService;
use async_trait::async_trait;
use ethers::prelude::*;
use nox_core::models::payloads::RelayerPayload;
use nox_core::traits::interfaces::InfrastructureError;
use nox_core::traits::service::{ServiceError, ServiceHandler};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Max RPC timeout for broadcast operations (matches RPC handler timeout).
const BROADCAST_RPC_TIMEOUT: Duration = Duration::from_secs(15);

const DEFAULT_BROADCAST_METHOD: &str = "eth_sendRawTransaction";

pub struct EthereumHandler {
    chain_executor: Arc<ChainExecutor>,
    tx_manager: Arc<TransactionManager>,
    profit_calc: ProfitabilityCalculator,
    metrics: MetricsService,
    max_broadcast_tx_size: usize,
}

impl EthereumHandler {
    pub fn new(
        chain_executor: Arc<ChainExecutor>,
        tx_manager: Arc<TransactionManager>,
        metrics: MetricsService,
        min_profit_margin_percent: u64,
        price_client: Arc<dyn PriceSource>,
        nox_reward_pool_address: Address,
        max_broadcast_tx_size: usize,
    ) -> Self {
        Self {
            chain_executor,
            tx_manager,
            metrics,
            profit_calc: ProfitabilityCalculator::new(
                min_profit_margin_percent,
                price_client,
                nox_reward_pool_address,
            ),
            max_broadcast_tx_size,
        }
    }

    pub fn register_token(&mut self, address: Address, symbol: &str, decimals: u8, price_id: &str) {
        self.profit_calc
            .register_token(address, symbol, decimals, price_id);
    }

    /// Returns the on-chain tx hash (unlike `ServiceHandler::handle` which returns `()`).
    pub async fn handle_paid_transaction(
        &self,
        packet_id: &str,
        to: Address,
        data: Bytes,
    ) -> Result<H256, ServiceError> {
        info!(
            "handle_paid_transaction: packet={}, to={:?}, data_len={}",
            packet_id,
            to,
            data.len()
        );

        // Retry simulation up to 3 times (RPC may lag after a recent block).
        let mut last_error = None;
        for sim_attempt in 0..3u32 {
            match self
                .chain_executor
                .simulate_transaction_with_logs(to, data.clone())
                .await
            {
                Ok((gas, logs)) => {
                    return self
                        .finalize_paid_transaction(packet_id, to, data, gas, logs)
                        .await;
                }
                Err(e) if sim_attempt < 2 => {
                    info!(
                        "Simulation attempt {}/3 failed for {}: {}. Retrying in 1s.",
                        sim_attempt + 1,
                        packet_id,
                        e
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    last_error = Some(e);
                }
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        let e = last_error.unwrap_or_else(|| {
            InfrastructureError::Network("All simulation attempts failed".into())
        });
        warn!(
            "Simulation failed for {} after 3 attempts: {}. Dropping packet.",
            packet_id, e
        );
        self.metrics
            .eth_simulation_reverts
            .get_or_create(&vec![("reason".into(), "revert".into())])
            .inc();
        Err(ServiceError::ProcessingFailed(format!(
            "Simulation failed: {e}"
        )))
    }

    async fn finalize_paid_transaction(
        &self,
        packet_id: &str,
        to: Address,
        data: Bytes,
        gas_estimate: u64,
        logs: Vec<ethers::types::Log>,
    ) -> Result<H256, ServiceError> {
        // dev-node skips profitability (Anvil ZK costs ~10M gas, always unprofitable).
        info!(
            "handle_paid_transaction: to={:?}, data_len={}, gas_estimate={}, logs={}, packet_id={}",
            to,
            data.len(),
            gas_estimate,
            logs.len(),
            packet_id
        );
        #[cfg(feature = "dev-node")]
        {
            info!(
                "Dev-node: skipping profitability check for {} (gas_estimate={}, logs={})",
                packet_id,
                gas_estimate,
                logs.len()
            );
        }

        #[cfg(feature = "dev-node")]
        let skip_profitability = true;
        #[cfg(not(feature = "dev-node"))]
        let skip_profitability = false;

        if skip_profitability {
            info!("Profitability bypassed for {} (dev-node mode)", packet_id);
        } else {
            let gas_price = self.chain_executor.get_gas_price().await.map_err(|e| {
                ServiceError::ProcessingFailed(format!("Cannot determine gas price: {e}"))
            })?;

            let profit_result = self
                .profit_calc
                .analyze(gas_estimate, gas_price, &logs)
                .await;

            self.metrics
                .tx_revenue_usd
                .observe(profit_result.revenue_usd);
            self.metrics.tx_cost_usd.observe(profit_result.cost_usd);
            if profit_result.margin.is_finite() {
                self.metrics
                    .profitability_margin_ratio
                    .observe(profit_result.margin);
            }

            if !profit_result.is_profitable {
                let reason = if profit_result.payment_found {
                    "unprofitable"
                } else {
                    "no_payment"
                };
                self.metrics
                    .profitability_outcomes_total
                    .get_or_create(&vec![("result".into(), reason.into())])
                    .inc();
                warn!(
                    "Unprofitable TX {}: Cost=${:.4}, Revenue=${:.4}, Margin={:.2}x",
                    packet_id,
                    profit_result.cost_usd,
                    profit_result.revenue_usd,
                    profit_result.margin
                );
                self.metrics
                    .eth_unprofitable_drops
                    .get_or_create(&vec![("type".into(), "paid".into())])
                    .inc();
                return Err(ServiceError::ProcessingFailed(format!(
                    "Unprofitable: cost=${:.4}, revenue=${:.4}, margin={:.2}x",
                    profit_result.cost_usd, profit_result.revenue_usd, profit_result.margin
                )));
            }

            self.metrics
                .profitability_outcomes_total
                .get_or_create(&vec![("result".into(), "profitable".into())])
                .inc();
            // Micro-dollar counters (u64, divide by 1_000_000 to get USD)
            self.metrics
                .cumulative_revenue_usd
                .inc_by((profit_result.revenue_usd * 1_000_000.0) as u64);
            self.metrics
                .cumulative_cost_usd
                .inc_by((profit_result.cost_usd * 1_000_000.0) as u64);

            info!(
                "Profitable TX {}: Cost=${:.4}, Revenue=${:.4}, Margin={:.2}x",
                packet_id, profit_result.cost_usd, profit_result.revenue_usd, profit_result.margin
            );
        }

        // 20% gas buffer (execution safety margin; unused gas refunded by EVM).
        let estimated_gas = self
            .chain_executor
            .estimate_gas(to, data.clone())
            .await
            .unwrap_or(gas_estimate);
        let gas_limit: U256 = (estimated_gas.saturating_mul(120) / 100).into();
        let tx_hash = self
            .tx_manager
            .submit(packet_id.to_string(), to, data, gas_limit)
            .await
            .map_err(|e| ServiceError::ProcessingFailed(e.to_string()))?;

        self.metrics
            .eth_transactions_submitted
            .get_or_create(&vec![])
            .inc();
        info!("TX {} submitted: {:?}", packet_id, tx_hash);

        match self.chain_executor.get_transaction_receipt(tx_hash).await {
            Ok(Some(receipt)) => {
                info!(
                    "TX {} receipt: status={:?}, gas_used={:?}, logs={}, block={:?}",
                    packet_id,
                    receipt.status,
                    receipt.gas_used,
                    receipt.logs.len(),
                    receipt.block_number
                );
                if receipt.logs.is_empty() {
                    warn!(
                        "TX {} has 0 logs despite status={:?}. Possible: calldata \
                         encoding issue or contract reverting inside try/catch.",
                        packet_id, receipt.status
                    );
                }
            }
            Ok(None) => {
                warn!("TX {} receipt not yet available on exit node", packet_id);
            }
            Err(e) => {
                warn!("TX {} receipt fetch failed: {}", packet_id, e);
            }
        }

        self.metrics
            .eth_transactions_submitted
            .get_or_create(&vec![("type".into(), "paid".into())])
            .inc();
        self.metrics
            .eth_tx_outcomes_total
            .get_or_create(&vec![
                ("type".into(), "paid".into()),
                ("result".into(), "submitted".into()),
            ])
            .inc();
        self.metrics.eth_tx_gas_used.observe(gas_estimate as f64);

        Ok(tx_hash)
    }

    /// No simulation or profitability check -- user pays their own gas.
    pub async fn handle_broadcast(
        &self,
        packet_id: &str,
        signed_tx: Vec<u8>,
        rpc_url: Option<String>,
        rpc_method: Option<String>,
    ) -> Result<Vec<u8>, ServiceError> {
        let method = rpc_method.as_deref().unwrap_or(DEFAULT_BROADCAST_METHOD);

        if signed_tx.is_empty() {
            return Err(ServiceError::ProcessingFailed(
                "Empty signed transaction".into(),
            ));
        }
        if signed_tx.len() > self.max_broadcast_tx_size {
            return Err(ServiceError::ProcessingFailed(format!(
                "Signed TX too large: {} bytes (max {})",
                signed_tx.len(),
                self.max_broadcast_tx_size
            )));
        }

        let response_bytes = if let Some(ref url) = rpc_url {
            let (resolved_ip, validated_url) =
                security::validate_url_ssrf(url, false).await.map_err(|e| {
                    warn!(
                        packet_id,
                        error = %e,
                        "SSRF check blocked broadcast RPC URL"
                    );
                    ServiceError::ProcessingFailed(format!("RPC URL blocked: {e}"))
                })?;

            // DNS rebinding: connect to resolved IP for HTTP (HTTPS needs hostname for TLS).
            let provider_url = if validated_url.scheme() == "http" {
                let mut ip_url = validated_url.clone();
                if ip_url.set_host(Some(&resolved_ip.to_string())).is_ok() {
                    ip_url.to_string()
                } else {
                    url.clone()
                }
            } else {
                url.clone()
            };

            let user_provider = Provider::<Http>::try_from(provider_url.as_str()).map_err(|e| {
                ServiceError::ProcessingFailed(format!("Failed to create provider for {url}: {e}"))
            })?;

            info!(
                packet_id,
                rpc_url = url,
                rpc_method = method,
                signed_tx_len = signed_tx.len(),
                "Broadcast via custom RPC URL"
            );

            let hex_tx = format!("0x{}", hex::encode(&signed_tx));
            let rpc_result = tokio::time::timeout(
                BROADCAST_RPC_TIMEOUT,
                user_provider.request::<_, serde_json::Value>(method, [hex_tx]),
            )
            .await;

            match rpc_result {
                Ok(Ok(value)) => serde_json::to_vec(&value).map_err(|e| {
                    ServiceError::ProcessingFailed(format!("Failed to serialize RPC response: {e}"))
                })?,
                Ok(Err(e)) => {
                    warn!(packet_id, error = %e, "Custom URL broadcast rejected");
                    return Err(ServiceError::ProcessingFailed(format!(
                        "Broadcast rejected: {e}"
                    )));
                }
                Err(_) => {
                    warn!(packet_id, "Custom URL broadcast timed out");
                    return Err(ServiceError::ProcessingFailed("Broadcast timed out".into()));
                }
            }
        } else if method != DEFAULT_BROADCAST_METHOD {
            warn!(
                packet_id,
                rpc_method = method,
                "Broadcast rejected: custom RPC method requires rpc_url"
            );
            return Err(ServiceError::ProcessingFailed(format!(
                "Custom RPC method '{method}' requires rpc_url (use BroadcastOptions with rpc_url)"
            )));
        } else {
            info!(
                packet_id,
                signed_tx_len = signed_tx.len(),
                "Broadcast via default provider (eth_sendRawTransaction)"
            );

            let broadcast_result = tokio::time::timeout(
                BROADCAST_RPC_TIMEOUT,
                self.chain_executor.broadcast_raw_signed_tx(&signed_tx),
            )
            .await;

            let tx_hash = match broadcast_result {
                Ok(Ok(hash)) => hash,
                Ok(Err(e)) => {
                    warn!(
                        packet_id,
                        error = %e,
                        "Broadcast signed TX rejected by RPC"
                    );
                    return Err(ServiceError::ProcessingFailed(format!(
                        "Broadcast rejected: {e}"
                    )));
                }
                Err(_) => {
                    warn!(packet_id, "Broadcast signed TX timed out");
                    return Err(ServiceError::ProcessingFailed("Broadcast timed out".into()));
                }
            };

            match self.chain_executor.get_transaction_receipt(tx_hash).await {
                Ok(Some(receipt)) => {
                    info!(
                        packet_id,
                        %tx_hash,
                        status = ?receipt.status,
                        gas_used = ?receipt.gas_used,
                        logs = receipt.logs.len(),
                        block = ?receipt.block_number,
                        "Broadcast TX receipt"
                    );
                }
                Ok(None) => {
                    info!(
                        packet_id,
                        %tx_hash,
                        "Broadcast TX in mempool (receipt not yet available)"
                    );
                }
                Err(e) => {
                    warn!(packet_id, %tx_hash, error = %e, "Broadcast TX receipt fetch failed");
                }
            }

            tx_hash.as_bytes().to_vec()
        };

        info!(
            packet_id,
            response_len = response_bytes.len(),
            rpc_method = method,
            custom_url = rpc_url.is_some(),
            "Broadcast signed transaction complete"
        );

        self.metrics
            .eth_transactions_submitted
            .get_or_create(&vec![("type".into(), "broadcast".into())])
            .inc();
        self.metrics
            .eth_tx_outcomes_total
            .get_or_create(&vec![
                ("type".into(), "broadcast".into()),
                ("result".into(), "submitted".into()),
            ])
            .inc();

        Ok(response_bytes)
    }

    pub fn from_config(
        chain_executor: Arc<ChainExecutor>,
        tx_manager: Arc<TransactionManager>,
        metrics: MetricsService,
        min_profit_margin_percent: u64,
        price_client: Arc<dyn PriceSource>,
        nox_reward_pool_address_str: &str,
        max_broadcast_tx_size: usize,
    ) -> Result<Self, ServiceError> {
        let nox_reward_pool_address =
            Address::from_str(nox_reward_pool_address_str).map_err(|_| {
                ServiceError::ProcessingFailed(format!(
                    "Invalid nox_reward_pool_address in config: {nox_reward_pool_address_str}"
                ))
            })?;

        Ok(Self::new(
            chain_executor,
            tx_manager,
            metrics,
            min_profit_margin_percent,
            price_client,
            nox_reward_pool_address,
            max_broadcast_tx_size,
        ))
    }
}

#[async_trait]
impl ServiceHandler for EthereumHandler {
    fn name(&self) -> &'static str {
        "ethereum"
    }

    async fn handle(&self, packet_id: &str, payload: &RelayerPayload) -> Result<(), ServiceError> {
        match payload {
            RelayerPayload::SubmitTransaction { to, data } => {
                let to_addr = Address::from(*to);

                let data_bytes = Bytes::from(data.clone());

                let mut sim_result: Option<(u64, Vec<ethers::types::Log>)> = None;
                #[allow(clippy::manual_let_else)]
                for sim_attempt in 0..3u32 {
                    match self
                        .chain_executor
                        .simulate_transaction_with_logs(to_addr, data_bytes.clone())
                        .await
                    {
                        Ok((g, l)) => {
                            sim_result = Some((g, l));
                            break;
                        }
                        Err(e) if sim_attempt < 2 => {
                            info!(
                                "Simulation attempt {}/3 failed for {}: {}. Retrying in 1s.",
                                sim_attempt + 1,
                                packet_id,
                                e
                            );
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                        Err(e) => {
                            warn!(
                                "Simulation failed for {} after 3 attempts: {}. Dropping packet.",
                                packet_id, e
                            );
                            self.metrics
                                .eth_simulation_reverts
                                .get_or_create(&vec![("reason".into(), "revert".into())])
                                .inc();
                            self.metrics
                                .eth_tx_outcomes_total
                                .get_or_create(&vec![
                                    ("type".into(), "submit".into()),
                                    ("result".into(), "sim_revert".into()),
                                ])
                                .inc();
                            // Return Ok() to signal "handled" (by dropping)
                            return Ok(());
                        }
                    }
                }
                let Some((gas_estimate, logs)) = sim_result else {
                    return Ok(());
                };

                #[cfg(feature = "dev-node")]
                let skip_profitability = true;
                #[cfg(not(feature = "dev-node"))]
                let skip_profitability = false;

                if skip_profitability {
                    info!(
                        "Dev-node: skipping profitability check for {} (gas_estimate={}, logs={})",
                        packet_id,
                        gas_estimate,
                        logs.len()
                    );
                } else {
                    let gas_price = self.chain_executor.get_gas_price().await.map_err(|e| {
                        ServiceError::ProcessingFailed(format!("Cannot determine gas price: {e}"))
                    })?;

                    let profit_result = self
                        .profit_calc
                        .analyze(gas_estimate, gas_price, &logs)
                        .await;

                    self.metrics
                        .tx_revenue_usd
                        .observe(profit_result.revenue_usd);
                    self.metrics.tx_cost_usd.observe(profit_result.cost_usd);
                    if profit_result.margin.is_finite() {
                        self.metrics
                            .profitability_margin_ratio
                            .observe(profit_result.margin);
                    }

                    if !profit_result.is_profitable {
                        let reason = if profit_result.payment_found {
                            "unprofitable"
                        } else {
                            "no_payment"
                        };
                        self.metrics
                            .profitability_outcomes_total
                            .get_or_create(&vec![("result".into(), reason.into())])
                            .inc();
                        warn!(
                            "Unprofitable TX {}: Cost=${:.4}, Revenue=${:.4}, Margin={:.2}x",
                            packet_id,
                            profit_result.cost_usd,
                            profit_result.revenue_usd,
                            profit_result.margin
                        );
                        self.metrics
                            .eth_unprofitable_drops
                            .get_or_create(&vec![("type".into(), "submit".into())])
                            .inc();
                        return Ok(());
                    }

                    self.metrics
                        .profitability_outcomes_total
                        .get_or_create(&vec![("result".into(), "profitable".into())])
                        .inc();
                    self.metrics
                        .cumulative_revenue_usd
                        .inc_by((profit_result.revenue_usd * 100.0) as u64);
                    self.metrics
                        .cumulative_cost_usd
                        .inc_by((profit_result.cost_usd * 100.0) as u64);

                    info!(
                        "Profitable TX {}: Cost=${:.4}, Revenue=${:.4}, Margin={:.2}x",
                        packet_id,
                        profit_result.cost_usd,
                        profit_result.revenue_usd,
                        profit_result.margin
                    );
                }

                // 20% gas buffer (execution safety; unused gas refunded by EVM).
                let estimated_gas = self
                    .chain_executor
                    .estimate_gas(to_addr, data_bytes.clone())
                    .await
                    .unwrap_or(gas_estimate);
                let gas_limit: U256 = (estimated_gas.saturating_mul(120) / 100).into();
                match self
                    .tx_manager
                    .submit(packet_id.to_string(), to_addr, data_bytes, gas_limit)
                    .await
                {
                    Ok(tx_hash) => {
                        info!("TX {} submitted: {:?}", packet_id, tx_hash);
                        self.metrics
                            .eth_transactions_submitted
                            .get_or_create(&vec![("type".into(), "submit".into())])
                            .inc();
                        self.metrics
                            .eth_tx_outcomes_total
                            .get_or_create(&vec![
                                ("type".into(), "submit".into()),
                                ("result".into(), "submitted".into()),
                            ])
                            .inc();
                        self.metrics.eth_tx_gas_used.observe(gas_estimate as f64);
                        Ok(())
                    }
                    Err(e) => Err(ServiceError::ProcessingFailed(e.to_string())),
                }
            }
            _ => Ok(()), // Ignore other payload types
        }
    }
}
