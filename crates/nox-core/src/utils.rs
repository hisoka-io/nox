use ethers_core::types::U256;
use tiny_keccak::{Hasher, Keccak};
use tracing::warn;

/// Convert a U256 wei amount to an f64 ETH amount.
/// Loses precision above ~9 ETH (f64 mantissa limit). Display/estimation only.
#[must_use]
#[allow(clippy::expect_used)]
pub fn wei_to_eth_f64(wei: U256) -> f64 {
    let wei_str = wei.to_string();
    // expect: U256::to_string() always produces valid decimal; unwrap_or(0.0) would
    // silently make all TXs appear free, corrupting profitability decisions.
    let wei_f64: f64 = wei_str
        .parse()
        .expect("U256::to_string() always produces a valid decimal for f64::parse()");
    wei_f64 / 1_000_000_000_000_000_000.0
}

/// Convert a U256 token amount to an f64 with the given decimals.
/// Same f64 precision limitation as `wei_to_eth_f64`. Display/estimation only.
#[must_use]
#[allow(clippy::expect_used)]
pub fn token_to_f64(amount: U256, decimals: u32) -> f64 {
    let amt_str = amount.to_string();
    // expect: same rationale as wei_to_eth_f64 -- silent 0.0 corrupts revenue calculations.
    let amt_f64: f64 = amt_str
        .parse()
        .expect("U256::to_string() always produces a valid decimal for f64::parse()");
    let divisor = 10f64.powi(decimals as i32);
    amt_f64 / divisor
}

/// Compute the full XOR topology fingerprint from a list of Ethereum addresses.
#[must_use]
pub fn compute_topology_fingerprint(addresses: &[String]) -> [u8; 32] {
    let mut fingerprint = [0u8; 32];
    for address in addresses {
        fingerprint = xor_into_fingerprint(&fingerprint, address);
    }
    fingerprint
}

/// XOR a 32-byte address hash into the fingerprint.
/// Matches Solidity `topologyFingerprint ^ keccak256(abi.encodePacked(nodeAddress))`.
#[must_use]
pub fn xor_into_fingerprint(current: &[u8; 32], address: &str) -> [u8; 32] {
    match address_hash(address) {
        Ok(hash) => {
            let mut result = [0u8; 32];
            for i in 0..32 {
                result[i] = current[i] ^ hash[i];
            }
            result
        }
        Err(msg) => {
            warn!("{}", msg);
            *current
        }
    }
}

/// keccak256 of a raw 20-byte Ethereum address. Matches Solidity `abi.encodePacked`.
fn address_hash(address: &str) -> Result<[u8; 32], String> {
    let address_clean = address.trim_start_matches("0x");
    let address_bytes =
        hex::decode(address_clean).map_err(|e| format!("Invalid hex address {address}: {e}"))?;

    if address_bytes.len() != 20 {
        return Err(format!(
            "Invalid address length: {} (expected 20 bytes)",
            address_bytes.len()
        ));
    }

    let mut hasher = Keccak::v256();
    hasher.update(&address_bytes);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wei_conversion() {
        let one_eth = U256::from(1000000000000000000u64);
        assert!((wei_to_eth_f64(one_eth) - 1.0).abs() < 1e-9);

        let half_eth = U256::from(500000000000000000u64);
        assert!((wei_to_eth_f64(half_eth) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_token_conversion() {
        let one_usdc = U256::from(1000000u64); // 6 decimals
        assert!((token_to_f64(one_usdc, 6) - 1.0).abs() < 1e-9);

        let one_dai = U256::from(1000000000000000000u64); // 18 decimals
        assert!((token_to_f64(one_dai, 18) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_fingerprint_xor_commutative() {
        let addresses = vec![
            "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
        ];
        let fp1 = compute_topology_fingerprint(&addresses);

        let reversed = vec![addresses[1].clone(), addresses[0].clone()];
        let fp2 = compute_topology_fingerprint(&reversed);

        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_xor_self_inverse() {
        let addresses = vec![
            "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        ];
        let fp = compute_topology_fingerprint(&addresses);
        assert_eq!(fp, [0u8; 32]);
    }

    #[test]
    fn test_fingerprint_invalid_address_unchanged() {
        let fp = xor_into_fingerprint(&[0u8; 32], "not_hex");
        assert_eq!(fp, [0u8; 32]);
    }
}
