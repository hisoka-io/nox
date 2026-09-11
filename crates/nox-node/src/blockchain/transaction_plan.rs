use ethers::types::U256;
use thiserror::Error;

pub const BASIS_POINTS: u128 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostCandidate {
    pub gas_limit: U256,
    pub initial_fee_per_gas: U256,
    pub chain_data_fee_native: U256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionPlan {
    pub gas_limit: U256,
    pub initial_fee_per_gas: U256,
    pub maximum_fee_per_gas: U256,
    pub chain_data_fee_native: U256,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GasPlanError {
    #[error("gas-plan arithmetic overflow while applying {field}")]
    Arithmetic { field: &'static str },
    #[error("gas estimate is zero")]
    ZeroGasEstimate,
    #[error("gas price is zero")]
    ZeroGasPrice,
}

pub fn buffered(value: U256, buffer_bps: u32, field: &'static str) -> Result<U256, GasPlanError> {
    if value.is_zero() {
        return Err(if field == "gas_limit" {
            GasPlanError::ZeroGasEstimate
        } else {
            GasPlanError::ZeroGasPrice
        });
    }
    let numerator = value
        .checked_mul(U256::from(BASIS_POINTS + u128::from(buffer_bps)))
        .ok_or(GasPlanError::Arithmetic { field })?;
    Ok(numerator
        .checked_add(U256::from(BASIS_POINTS - 1))
        .ok_or(GasPlanError::Arithmetic { field })?
        / U256::from(BASIS_POINTS))
}
