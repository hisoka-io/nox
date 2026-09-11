use crate::blockchain::transaction_plan::{CostCandidate, TransactionPlan, BASIS_POINTS};
use crate::price::client::FixedPriceSource;
use crate::services::token_registry::TokenRegistry;
use ethers::types::{Address, Log, H256, U256, U512};
use ethers::utils::keccak256;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfitAuthorization {
    pub plan: TransactionPlan,
    pub revenue_value_e8: U256,
    pub planned_initial_cost_value_e8: U256,
    pub maximum_cost_value_e8: U256,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProfitabilityError {
    #[error("no committed payment")]
    PaymentMissing,
    #[error("price unavailable for {asset_id}: {detail}")]
    PriceUnavailable { asset_id: String, detail: String },
    #[error("payment is below the required margin")]
    Unprofitable {
        revenue_value_e8: U256,
        maximum_cost_value_e8: U256,
    },
    #[error("profitability arithmetic failed: {detail}")]
    Arithmetic { detail: String },
}

pub struct ProfitabilityCalculator {
    margin_bps: u128,
    price_client: Arc<dyn FixedPriceSource>,
    token_registry: TokenRegistry,
    nox_reward_pool_address: Address,
    native_asset_price_id: String,
    native_asset_decimals: u8,
}

impl ProfitabilityCalculator {
    pub async fn quote_exit_fee(
        &self,
        fee_asset: Address,
        maximum_transaction_gas: U256,
        maximum_fee_per_gas: U256,
    ) -> Result<U256, ProfitabilityError> {
        let price_id = self
            .token_registry
            .get_price_id(fee_asset)
            .ok_or(ProfitabilityError::PaymentMissing)?;
        let decimals = self
            .token_registry
            .get_decimals(fee_asset)
            .ok_or(ProfitabilityError::PaymentMissing)?;
        let fee_quote = self
            .price_client
            .get_price(price_id)
            .await
            .map_err(|error| ProfitabilityError::PriceUnavailable {
                asset_id: price_id.to_string(),
                detail: error.to_string(),
            })?;
        validate_quote(price_id, &fee_quote)?;
        let native_quote = self
            .price_client
            .get_price(&self.native_asset_price_id)
            .await
            .map_err(|error| ProfitabilityError::PriceUnavailable {
                asset_id: self.native_asset_price_id.clone(),
                detail: error.to_string(),
            })?;
        validate_quote(&self.native_asset_price_id, &native_quote)?;
        let native_price_upper =
            native_quote
                .price_e8
                .checked_add(1)
                .ok_or_else(|| ProfitabilityError::Arithmetic {
                    detail: "native price upper rounding overflow".to_string(),
                })?;
        let maximum_cost_e8 = mul3_div_ceil(
            maximum_transaction_gas,
            maximum_fee_per_gas,
            U256::from(native_price_upper),
            pow10(self.native_asset_decimals)?,
        )?;
        let margin_weight =
            U256::from(BASIS_POINTS.checked_add(self.margin_bps).ok_or_else(|| {
                ProfitabilityError::Arithmetic {
                    detail: "quote margin basis-point addition overflow".to_string(),
                }
            })?);
        let required_revenue_e8 =
            mul_div_ceil(maximum_cost_e8, margin_weight, U256::from(BASIS_POINTS))?;
        mul_div_ceil(
            required_revenue_e8,
            pow10(decimals)?,
            U256::from(fee_quote.price_e8),
        )
    }

    pub async fn authorize_fee(
        &self,
        candidate: CostCandidate,
        fee_asset: Address,
        fee_amount: U256,
    ) -> Result<ProfitAuthorization, ProfitabilityError> {
        let mut asset_topic = [0_u8; 32];
        asset_topic[12..].copy_from_slice(fee_asset.as_bytes());
        let mut amount = [0_u8; 32];
        fee_amount.to_big_endian(&mut amount);
        self.authorize(
            candidate,
            &[Log {
                address: self.nox_reward_pool_address,
                topics: vec![
                    H256::from(keccak256(b"RewardsDeposited(address,address,uint256)")),
                    H256::from(asset_topic),
                    H256::zero(),
                ],
                data: amount.to_vec().into(),
                ..Default::default()
            }],
        )
        .await
    }

    pub async fn authorize_fee_with_maximum_fee_per_gas(
        &self,
        candidate: CostCandidate,
        fee_asset: Address,
        fee_amount: U256,
        maximum_fee_per_gas: U256,
    ) -> Result<ProfitAuthorization, ProfitabilityError> {
        let mut asset_topic = [0_u8; 32];
        asset_topic[12..].copy_from_slice(fee_asset.as_bytes());
        let mut amount = [0_u8; 32];
        fee_amount.to_big_endian(&mut amount);
        self.authorize_with_maximum_fee_per_gas(
            candidate,
            &[Log {
                address: self.nox_reward_pool_address,
                topics: vec![
                    H256::from(keccak256(b"RewardsDeposited(address,address,uint256)")),
                    H256::from(asset_topic),
                    H256::zero(),
                ],
                data: amount.to_vec().into(),
                ..Default::default()
            }],
            Some(maximum_fee_per_gas),
        )
        .await
    }

    pub fn new(
        min_profit_margin_percent: u64,
        price_client: Arc<dyn FixedPriceSource>,
        nox_reward_pool_address: Address,
    ) -> Self {
        Self::with_economics(
            u128::from(min_profit_margin_percent) * 100,
            price_client,
            nox_reward_pool_address,
            TokenRegistry::default(),
            "ethereum".to_string(),
            18,
        )
    }

    pub fn with_economics(
        margin_bps: u128,
        price_client: Arc<dyn FixedPriceSource>,
        nox_reward_pool_address: Address,
        token_registry: TokenRegistry,
        native_asset_price_id: String,
        native_asset_decimals: u8,
    ) -> Self {
        Self {
            margin_bps,
            price_client,
            token_registry,
            nox_reward_pool_address,
            native_asset_price_id,
            native_asset_decimals,
        }
    }

    pub async fn authorize(
        &self,
        candidate: CostCandidate,
        logs: &[Log],
    ) -> Result<ProfitAuthorization, ProfitabilityError> {
        self.authorize_with_maximum_fee_per_gas(candidate, logs, None)
            .await
    }

    async fn authorize_with_maximum_fee_per_gas(
        &self,
        candidate: CostCandidate,
        logs: &[Log],
        maximum_fee_cap: Option<U256>,
    ) -> Result<ProfitAuthorization, ProfitabilityError> {
        if candidate.gas_limit.is_zero() || candidate.initial_fee_per_gas.is_zero() {
            return Err(ProfitabilityError::Arithmetic {
                detail: "gas limit and initial fee must be positive".to_string(),
            });
        }

        let revenue_value_e8 = self.payment_revenue(logs).await?;
        let native_quote = self
            .price_client
            .get_price(&self.native_asset_price_id)
            .await
            .map_err(|error| ProfitabilityError::PriceUnavailable {
                asset_id: self.native_asset_price_id.clone(),
                detail: error.to_string(),
            })?;
        validate_quote(&self.native_asset_price_id, &native_quote)?;
        let native_price_upper_e8 =
            native_quote
                .price_e8
                .checked_add(1)
                .ok_or_else(|| ProfitabilityError::Arithmetic {
                    detail: "native price upper rounding overflow".to_string(),
                })?;
        let native_scale = pow10(self.native_asset_decimals)?;
        let chain_data_fee_value_e8 = mul_div_ceil(
            candidate.chain_data_fee_native,
            U256::from(native_price_upper_e8),
            native_scale,
        )?;
        let initial_gas_value_e8 = mul3_div_ceil(
            candidate.gas_limit,
            candidate.initial_fee_per_gas,
            U256::from(native_price_upper_e8),
            native_scale,
        )?;
        let initial_cost_value_e8 = initial_gas_value_e8
            .checked_add(chain_data_fee_value_e8)
            .ok_or_else(|| ProfitabilityError::Arithmetic {
                detail: "initial total cost overflow".to_string(),
            })?;
        let required_cost_weight =
            U256::from(BASIS_POINTS.checked_add(self.margin_bps).ok_or_else(|| {
                ProfitabilityError::Arithmetic {
                    detail: "margin basis-point addition overflow".to_string(),
                }
            })?);
        let revenue_weight = U512::from(revenue_value_e8) * U512::from(BASIS_POINTS);
        let cost_weight = U512::from(initial_cost_value_e8) * U512::from(required_cost_weight);
        if revenue_weight < cost_weight {
            return Err(ProfitabilityError::Unprofitable {
                revenue_value_e8,
                maximum_cost_value_e8: initial_cost_value_e8,
            });
        }

        let maximum_total_cost_e8 = mul_div_floor(
            revenue_value_e8,
            U256::from(BASIS_POINTS),
            required_cost_weight,
        )?;
        let maximum_gas_value_e8 = maximum_total_cost_e8
            .checked_sub(chain_data_fee_value_e8)
            .ok_or(ProfitabilityError::Unprofitable {
                revenue_value_e8,
                maximum_cost_value_e8: initial_cost_value_e8,
            })?;
        let affordable_fee_per_gas = maximum_fee_per_gas(
            maximum_gas_value_e8,
            native_scale,
            candidate.gas_limit,
            U256::from(native_price_upper_e8),
        )?;
        let maximum_fee_per_gas = maximum_fee_cap.map_or(affordable_fee_per_gas, |cap| {
            affordable_fee_per_gas.min(cap)
        });
        if candidate.initial_fee_per_gas > maximum_fee_per_gas {
            return Err(ProfitabilityError::Unprofitable {
                revenue_value_e8,
                maximum_cost_value_e8: initial_cost_value_e8,
            });
        }

        let maximum_gas_cost_value_e8 = mul3_div_ceil(
            candidate.gas_limit,
            maximum_fee_per_gas,
            U256::from(native_price_upper_e8),
            native_scale,
        )?;
        let maximum_cost_value_e8 = maximum_gas_cost_value_e8
            .checked_add(chain_data_fee_value_e8)
            .ok_or_else(|| ProfitabilityError::Arithmetic {
                detail: "maximum executable cost overflow".to_string(),
            })?;

        Ok(ProfitAuthorization {
            plan: TransactionPlan {
                gas_limit: candidate.gas_limit,
                initial_fee_per_gas: candidate.initial_fee_per_gas,
                maximum_fee_per_gas,
                chain_data_fee_native: candidate.chain_data_fee_native,
            },
            revenue_value_e8,
            planned_initial_cost_value_e8: initial_cost_value_e8,
            maximum_cost_value_e8,
        })
    }

    async fn payment_revenue(&self, logs: &[Log]) -> Result<U256, ProfitabilityError> {
        let rewards_topic = H256::from(keccak256(b"RewardsDeposited(address,address,uint256)"));
        let mut revenue = U256::zero();
        let mut payment_found = false;

        for log in logs {
            if log.address != self.nox_reward_pool_address
                || log.topics.len() != 3
                || log.topics[0] != rewards_topic
                || log.data.len() != 32
            {
                continue;
            }
            let asset = Address::from(log.topics[1]);
            let Some(price_id) = self.token_registry.get_price_id(asset) else {
                continue;
            };
            let Some(decimals) = self.token_registry.get_decimals(asset) else {
                continue;
            };
            let quote = self
                .price_client
                .get_price(price_id)
                .await
                .map_err(|error| ProfitabilityError::PriceUnavailable {
                    asset_id: price_id.to_string(),
                    detail: error.to_string(),
                })?;
            validate_quote(price_id, &quote)?;
            let amount = U256::from_big_endian(log.data.as_ref());
            let value = mul_div_floor(amount, U256::from(quote.price_e8), pow10(decimals)?)?;
            revenue = revenue
                .checked_add(value)
                .ok_or_else(|| ProfitabilityError::Arithmetic {
                    detail: "payment revenue overflow".to_string(),
                })?;
            payment_found = true;
        }

        if !payment_found {
            return Err(ProfitabilityError::PaymentMissing);
        }
        Ok(revenue)
    }

    pub fn register_token(&mut self, address: Address, symbol: &str, decimals: u8, price_id: &str) {
        self.token_registry.register(
            address,
            crate::services::token_registry::TokenInfo {
                symbol: symbol.to_string(),
                decimals,
                price_id: price_id.to_string(),
            },
        );
    }

    pub(crate) fn clear_tokens(&mut self) {
        self.token_registry.clear();
    }
}

fn validate_quote(
    requested_asset_id: &str,
    quote: &crate::price::client::PriceQuote,
) -> Result<(), ProfitabilityError> {
    if quote.price_e8 == 0 || quote.asset_id != requested_asset_id {
        return Err(ProfitabilityError::PriceUnavailable {
            asset_id: requested_asset_id.to_string(),
            detail: "price source returned a zero or mismatched quote".to_string(),
        });
    }
    Ok(())
}

fn pow10(decimals: u8) -> Result<U256, ProfitabilityError> {
    (0..decimals).try_fold(U256::one(), |value, _| {
        value
            .checked_mul(U256::from(10))
            .ok_or_else(|| ProfitabilityError::Arithmetic {
                detail: "decimal scale overflow".to_string(),
            })
    })
}

fn mul_div_floor(left: U256, right: U256, divisor: U256) -> Result<U256, ProfitabilityError> {
    if divisor.is_zero() {
        return Err(ProfitabilityError::Arithmetic {
            detail: "division by zero".to_string(),
        });
    }
    narrow(U512::from(left) * U512::from(right) / U512::from(divisor))
}

fn mul_div_ceil(left: U256, right: U256, divisor: U256) -> Result<U256, ProfitabilityError> {
    if divisor.is_zero() {
        return Err(ProfitabilityError::Arithmetic {
            detail: "division by zero".to_string(),
        });
    }
    let numerator = U512::from(left) * U512::from(right);
    let divisor = U512::from(divisor);
    let rounded = numerator
        .checked_add(divisor - U512::one())
        .ok_or_else(|| ProfitabilityError::Arithmetic {
            detail: "rounded numerator overflow".to_string(),
        })?;
    narrow(rounded / divisor)
}

fn mul3_div_ceil(
    first: U256,
    second: U256,
    third: U256,
    divisor: U256,
) -> Result<U256, ProfitabilityError> {
    if divisor.is_zero() {
        return Err(ProfitabilityError::Arithmetic {
            detail: "division by zero".to_string(),
        });
    }
    let numerator = U512::from(first)
        .checked_mul(U512::from(second))
        .and_then(|value| value.checked_mul(U512::from(third)))
        .ok_or_else(|| ProfitabilityError::Arithmetic {
            detail: "widened cost product overflow".to_string(),
        })?;
    let divisor = U512::from(divisor);
    let rounded = numerator
        .checked_add(divisor - U512::one())
        .ok_or_else(|| ProfitabilityError::Arithmetic {
            detail: "rounded widened numerator overflow".to_string(),
        })?;
    narrow(rounded / divisor)
}

fn maximum_fee_per_gas(
    maximum_gas_value_e8: U256,
    native_scale: U256,
    gas_limit: U256,
    native_price_upper_e8: U256,
) -> Result<U256, ProfitabilityError> {
    let numerator = U512::from(maximum_gas_value_e8)
        .checked_mul(U512::from(native_scale))
        .ok_or_else(|| ProfitabilityError::Arithmetic {
            detail: "maximum fee numerator overflow".to_string(),
        })?;
    let denominator = U512::from(gas_limit)
        .checked_mul(U512::from(native_price_upper_e8))
        .ok_or_else(|| ProfitabilityError::Arithmetic {
            detail: "maximum fee denominator overflow".to_string(),
        })?;
    if denominator.is_zero() {
        return Err(ProfitabilityError::Arithmetic {
            detail: "maximum fee denominator is zero".to_string(),
        });
    }
    narrow(numerator / denominator)
}

fn narrow(value: U512) -> Result<U256, ProfitabilityError> {
    if value > U512::from(U256::MAX) {
        return Err(ProfitabilityError::Arithmetic {
            detail: "U512 value exceeds U256".to_string(),
        });
    }
    let mut bytes = [0_u8; 64];
    value.to_big_endian(&mut bytes);
    Ok(U256::from_big_endian(&bytes[32..]))
}
