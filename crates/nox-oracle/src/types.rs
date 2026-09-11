use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub const PRICE_SCALE: u128 = 100_000_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PriceParseError {
    #[error("price is empty")]
    Empty,
    #[error("price must be positive")]
    NonPositive,
    #[error("price has invalid decimal syntax")]
    InvalidSyntax,
    #[error("positive price is below E8 precision")]
    BelowPrecision,
    #[error("price exceeds E8 range")]
    Overflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PriceE8(u128);

impl PriceE8 {
    pub fn parse_decimal(input: &str) -> Result<Self, PriceParseError> {
        if input.is_empty() {
            return Err(PriceParseError::Empty);
        }
        if input.starts_with('-') {
            return Err(PriceParseError::NonPositive);
        }

        let (mantissa, exponent) = split_exponent(input)?;
        let (integer, fraction) = match mantissa.split_once('.') {
            Some((integer, fraction)) if !fraction.is_empty() => (integer, fraction),
            Some(_) => return Err(PriceParseError::InvalidSyntax),
            None => (mantissa, ""),
        };
        if integer.is_empty()
            || !integer.bytes().all(|byte| byte.is_ascii_digit())
            || !fraction.bytes().all(|byte| byte.is_ascii_digit())
            || (integer.len() > 1 && integer.starts_with('0'))
        {
            return Err(PriceParseError::InvalidSyntax);
        }

        let digits = integer
            .bytes()
            .chain(fraction.bytes())
            .try_fold(0_u128, |value, digit| {
                value.checked_mul(10)?.checked_add(u128::from(digit - b'0'))
            })
            .ok_or(PriceParseError::Overflow)?;
        if digits == 0 {
            return Err(PriceParseError::NonPositive);
        }

        let decimal_shift = i64::try_from(fraction.len()).map_err(|_| PriceParseError::Overflow)?;
        let scale_shift = 8_i64
            .checked_add(exponent)
            .and_then(|shift| shift.checked_sub(decimal_shift))
            .ok_or(PriceParseError::Overflow)?;
        let value = if scale_shift >= 0 {
            let shift = u32::try_from(scale_shift).map_err(|_| PriceParseError::Overflow)?;
            let multiplier = checked_pow10(shift).ok_or(PriceParseError::Overflow)?;
            digits
                .checked_mul(multiplier)
                .ok_or(PriceParseError::Overflow)?
        } else {
            let divisor_shift = scale_shift
                .checked_neg()
                .and_then(|shift| u32::try_from(shift).ok())
                .ok_or(PriceParseError::Overflow)?;
            match checked_pow10(divisor_shift) {
                Some(divisor) => digits / divisor,
                None => 0,
            }
        };
        if value == 0 {
            return Err(PriceParseError::BelowPrecision);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u128 {
        self.0
    }
}

fn split_exponent(input: &str) -> Result<(&str, i64), PriceParseError> {
    let mut parts = input.split(['e', 'E']);
    let mantissa = parts.next().ok_or(PriceParseError::InvalidSyntax)?;
    let Some(exponent_text) = parts.next() else {
        return Ok((mantissa, 0));
    };
    if parts.next().is_some() || exponent_text.is_empty() {
        return Err(PriceParseError::InvalidSyntax);
    }
    let exponent = exponent_text
        .parse::<i64>()
        .map_err(|_| PriceParseError::InvalidSyntax)?;
    Ok((mantissa, exponent))
}

fn checked_pow10(exponent: u32) -> Option<u128> {
    if exponent > 38 {
        return None;
    }
    (0..exponent).try_fold(1_u128, |value, _| value.checked_mul(10))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PriceEntry {
    pub price_e8: String,
    pub observed_at_unix: u64,
    pub asset_id: String,
    pub source: String,
}

pub type PriceCache = Arc<RwLock<HashMap<String, PriceEntry>>>;

#[derive(Debug, Clone)]
pub struct OracleConfig {
    pub assets: Vec<String>,
    pub update_interval_secs: u64,
    pub staleness_threshold_secs: i64,
}

impl Default for OracleConfig {
    fn default() -> Self {
        Self {
            assets: vec![
                "ethereum".to_string(),
                "usd-coin".to_string(),
                "bitcoin".to_string(),
            ],
            update_interval_secs: 60,
            staleness_threshold_secs: 300, // 5 minutes
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod fixed_price_tests {
    use super::*;

    #[test]
    fn parses_decimal_and_exponent_prices() {
        assert_eq!(
            PriceE8::parse_decimal("2500.123456789").unwrap().get(),
            250_012_345_678
        );
        assert_eq!(
            PriceE8::parse_decimal("1e3").unwrap().get(),
            100_000_000_000
        );
        assert_eq!(PriceE8::parse_decimal("1.25e-2").unwrap().get(), 1_250_000);
    }

    #[test]
    fn rejects_non_positive_and_below_precision_prices() {
        assert!(PriceE8::parse_decimal("").is_err());
        assert!(PriceE8::parse_decimal("0").is_err());
        assert!(PriceE8::parse_decimal("-1").is_err());
        assert!(PriceE8::parse_decimal("nan").is_err());
        assert!(PriceE8::parse_decimal("0.000000001").is_err());
        assert!(PriceE8::parse_decimal("01").is_err());
        assert!(PriceE8::parse_decimal("1.").is_err());
        assert!(PriceE8::parse_decimal("1e1000000").is_err());
    }
}
