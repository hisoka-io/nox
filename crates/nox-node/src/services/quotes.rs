use ethers::abi::{encode, Token};
use ethers::types::{Address, H256, U256};
use ethers::utils::keccak256;
use nox_core::ExecutionQuoteV1;
use nox_core::{PaidQuoteRequestV2, PaidTransactionRejectionCodeV2};

use crate::config::NoxConfig;

const QUOTE_TYPE: &[u8] = b"ExecutionQuote(uint8 quoteVersion,uint256 chainId,address entryPoint,address exitAddress,bytes32 clientIntentId,address paymentAdapter,bytes32 paymentId,address feeAsset,uint256 exitFee,uint256 networkFee,uint256 paymentGasLimit,address actionTarget,bytes32 actionCalldataHash,uint256 actionGasLimit,bytes32 trackedAssetsHash,uint256 maximumTransactionGas,uint256 maximumFeePerGas,uint256 returnDataLimit,uint64 validAfterUnix,uint64 validUntilUnix,uint256 quoteNonce)";
const DOMAIN_TYPE: &[u8] =
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const ENTRY_POINT_GAS_RESERVE: u64 = 250_000;
const MAX_RETURN_DATA_LIMIT: u32 = 4_096;

#[derive(Debug, Clone)]
pub struct PaymentAdapterPolicy {
    pub address: Address,
    pub fee_assets: Vec<Address>,
    pub maximum_payment_gas: u64,
}

#[derive(Debug, Clone)]
pub struct QuotePolicy {
    pub ttl_secs: u64,
    pub network_fee_bps: u32,
    pub maximum_transaction_gas: u64,
    pub maximum_outstanding: u32,
    pub maximum_pending_sponsored_gas: u64,
    pub rolling_loss_limit_native: U256,
    pub rolling_loss_window_secs: u64,
    pub replacement_step_bps: u32,
    pub adapters: Vec<PaymentAdapterPolicy>,
}

impl QuotePolicy {
    pub fn from_config(config: &NoxConfig) -> Result<Self, String> {
        let adapters = config
            .payment_adapters
            .iter()
            .map(|adapter| {
                let address = adapter
                    .address
                    .parse::<Address>()
                    .map_err(|error| format!("invalid payment adapter address: {error}"))?;
                let fee_assets = adapter
                    .fee_assets
                    .iter()
                    .map(|asset| {
                        asset
                            .parse::<Address>()
                            .map_err(|error| format!("invalid payment adapter fee asset: {error}"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(PaymentAdapterPolicy {
                    address,
                    fee_assets,
                    maximum_payment_gas: adapter.maximum_payment_gas,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let rolling_loss_limit_native = U256::from_dec_str(&config.quote_rolling_loss_limit_native)
            .map_err(|error| format!("invalid rolling loss limit: {error}"))?;
        Ok(Self {
            ttl_secs: config.quote_ttl_secs,
            network_fee_bps: config.quote_network_fee_bps,
            maximum_transaction_gas: config.quote_maximum_transaction_gas,
            maximum_outstanding: config.quote_max_outstanding,
            maximum_pending_sponsored_gas: config.quote_max_pending_sponsored_gas,
            rolling_loss_limit_native,
            rolling_loss_window_secs: config.quote_rolling_loss_window_secs,
            replacement_step_bps: config.replacement_step_bps,
            adapters,
        })
    }

    pub fn validate_request(
        &self,
        request: &PaidQuoteRequestV2,
        expected_chain_id: u64,
        expected_entry_point: Address,
        chain_timestamp: u64,
    ) -> Result<(u64, u64), PaidTransactionRejectionCodeV2> {
        if request.chain_id != expected_chain_id {
            return Err(PaidTransactionRejectionCodeV2::WrongChain);
        }
        if Address::from(request.entry_point) != expected_entry_point
            || expected_entry_point.is_zero()
        {
            return Err(PaidTransactionRejectionCodeV2::WrongEntryPoint);
        }
        if request.client_intent_id == [0; 32]
            || request.payment_id == [0; 32]
            || request.action_calldata_hash == [0; 32]
            || Address::from(request.action_target).is_zero()
        {
            return Err(PaidTransactionRejectionCodeV2::MalformedRequest);
        }
        let adapter_address = Address::from(request.payment_adapter);
        let fee_asset = Address::from(request.fee_asset);
        let adapter = self
            .adapters
            .iter()
            .find(|adapter| adapter.address == adapter_address)
            .ok_or(PaidTransactionRejectionCodeV2::UnsupportedPaymentAdapter)?;
        if !adapter.fee_assets.contains(&fee_asset) {
            return Err(PaidTransactionRejectionCodeV2::UnsupportedFeeAsset);
        }
        if request.payment_gas_limit == 0
            || request.payment_gas_limit > adapter.maximum_payment_gas
            || request.action_gas_limit == 0
            || request.return_data_limit > MAX_RETURN_DATA_LIMIT
        {
            return Err(PaidTransactionRejectionCodeV2::GasCapExceeded);
        }
        let bounded_gas = request
            .payment_gas_limit
            .checked_add(request.action_gas_limit)
            .and_then(|gas| gas.checked_add(ENTRY_POINT_GAS_RESERVE))
            .ok_or(PaidTransactionRejectionCodeV2::GasCapExceeded)?;
        if bounded_gas > request.maximum_transaction_gas
            || request.maximum_transaction_gas > self.maximum_transaction_gas
        {
            return Err(PaidTransactionRejectionCodeV2::GasCapExceeded);
        }
        let exit_bound = chain_timestamp
            .checked_add(self.ttl_secs)
            .ok_or(PaidTransactionRejectionCodeV2::ExpiredQuote)?;
        let valid_until = request.valid_until_unix.min(exit_bound);
        if valid_until <= chain_timestamp {
            return Err(PaidTransactionRejectionCodeV2::ExpiredQuote);
        }
        Ok((request.maximum_transaction_gas, valid_until))
    }
}

#[must_use]
pub fn execution_quote_digest(quote: &ExecutionQuoteV1) -> H256 {
    let struct_hash = H256::from(keccak256(encode(&[
        Token::FixedBytes(keccak256(QUOTE_TYPE).to_vec()),
        Token::Uint(U256::from(quote.quote_version)),
        Token::Uint(u256(quote.chain_id)),
        Token::Address(Address::from(quote.entry_point)),
        Token::Address(Address::from(quote.exit_address)),
        Token::FixedBytes(quote.client_intent_id.to_vec()),
        Token::Address(Address::from(quote.payment_adapter)),
        Token::FixedBytes(quote.payment_id.to_vec()),
        Token::Address(Address::from(quote.fee_asset)),
        Token::Uint(u256(quote.exit_fee)),
        Token::Uint(u256(quote.network_fee)),
        Token::Uint(u256(quote.payment_gas_limit)),
        Token::Address(Address::from(quote.action_target)),
        Token::FixedBytes(quote.action_calldata_hash.to_vec()),
        Token::Uint(u256(quote.action_gas_limit)),
        Token::FixedBytes(quote.tracked_assets_hash.to_vec()),
        Token::Uint(u256(quote.maximum_transaction_gas)),
        Token::Uint(u256(quote.maximum_fee_per_gas)),
        Token::Uint(u256(quote.return_data_limit)),
        Token::Uint(U256::from(quote.valid_after_unix)),
        Token::Uint(U256::from(quote.valid_until_unix)),
        Token::Uint(u256(quote.quote_nonce)),
    ])));
    let domain_hash = H256::from(keccak256(encode(&[
        Token::FixedBytes(keccak256(DOMAIN_TYPE).to_vec()),
        Token::FixedBytes(keccak256(b"NoxEntryPoint").to_vec()),
        Token::FixedBytes(keccak256(b"1").to_vec()),
        Token::Uint(u256(quote.chain_id)),
        Token::Address(Address::from(quote.entry_point)),
    ])));
    let mut preimage = [0_u8; 66];
    preimage[..2].copy_from_slice(b"\x19\x01");
    preimage[2..34].copy_from_slice(domain_hash.as_bytes());
    preimage[34..].copy_from_slice(struct_hash.as_bytes());
    H256::from(keccak256(preimage))
}

fn u256(value: [u8; 32]) -> U256 {
    U256::from_big_endian(&value)
}

#[must_use]
pub fn u256_word(value: U256) -> [u8; 32] {
    let mut encoded = [0_u8; 32];
    value.to_big_endian(&mut encoded);
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(value: u64) -> [u8; 32] {
        let mut encoded = [0_u8; 32];
        U256::from(value).to_big_endian(&mut encoded);
        encoded
    }

    #[test]
    fn execution_quote_digest_matches_solidity_eip712_layout() {
        let quote = ExecutionQuoteV1 {
            quote_version: 1,
            chain_id: word(421_614),
            entry_point: [0x11; 20],
            exit_address: [0x22; 20],
            client_intent_id: [0x33; 32],
            payment_adapter: [0x44; 20],
            payment_id: [0x55; 32],
            fee_asset: [0x66; 20],
            exit_fee: word(77),
            network_fee: word(8),
            payment_gas_limit: word(500_000),
            action_target: [0x77; 20],
            action_calldata_hash: [0x88; 32],
            action_gas_limit: word(700_000),
            tracked_assets_hash: [0x99; 32],
            maximum_transaction_gas: word(1_450_000),
            maximum_fee_per_gas: word(123),
            return_data_limit: word(256),
            valid_after_unix: 1_799_999_900,
            valid_until_unix: 1_800_000_000,
            quote_nonce: word(1),
        };
        assert_eq!(
            format!("{:?}", execution_quote_digest(&quote)),
            "0x1ca9c5897f8242ac75faa99ea8d1830af6ca67fd93197b8b993919d87f2306a5",
        );
    }

    #[test]
    fn caller_transaction_cap_is_preserved_and_operator_ceiling_is_enforced() {
        let policy = QuotePolicy {
            ttl_secs: 30,
            network_fee_bps: 500,
            maximum_transaction_gas: 2_000_000,
            maximum_outstanding: 8,
            maximum_pending_sponsored_gas: 16_000_000,
            rolling_loss_limit_native: U256::from(1),
            rolling_loss_window_secs: 3_600,
            replacement_step_bps: 2_000,
            adapters: vec![PaymentAdapterPolicy {
                address: Address::from([3; 20]),
                fee_assets: vec![Address::from([5; 20])],
                maximum_payment_gas: 600_000,
            }],
        };
        let mut request = PaidQuoteRequestV2 {
            chain_id: 421_614,
            entry_point: [1; 20],
            client_intent_id: [2; 32],
            payment_adapter: [3; 20],
            payment_id: [4; 32],
            fee_asset: [5; 20],
            payment_gas_limit: 500_000,
            action_target: [6; 20],
            action_calldata_hash: [7; 32],
            action_gas_limit: 700_000,
            tracked_assets_hash: [8; 32],
            maximum_transaction_gas: 1_600_000,
            return_data_limit: 256,
            valid_until_unix: 1_800_000_000,
        };
        assert_eq!(
            policy
                .validate_request(&request, 421_614, Address::from([1; 20]), 1_799_999_900,)
                .unwrap()
                .0,
            1_600_000,
        );
        request.maximum_transaction_gas = 2_000_001;
        assert_eq!(
            policy.validate_request(&request, 421_614, Address::from([1; 20]), 1_799_999_900,),
            Err(PaidTransactionRejectionCodeV2::GasCapExceeded),
        );
    }

    #[test]
    fn quote_window_uses_chain_timestamp_when_wall_clock_is_ahead() {
        let policy = QuotePolicy {
            ttl_secs: 30,
            network_fee_bps: 500,
            maximum_transaction_gas: 2_000_000,
            maximum_outstanding: 8,
            maximum_pending_sponsored_gas: 16_000_000,
            rolling_loss_limit_native: U256::from(1),
            rolling_loss_window_secs: 3_600,
            replacement_step_bps: 2_000,
            adapters: vec![PaymentAdapterPolicy {
                address: Address::from([3; 20]),
                fee_assets: vec![Address::from([5; 20])],
                maximum_payment_gas: 600_000,
            }],
        };
        let request = PaidQuoteRequestV2 {
            chain_id: 421_614,
            entry_point: [1; 20],
            client_intent_id: [2; 32],
            payment_adapter: [3; 20],
            payment_id: [4; 32],
            fee_asset: [5; 20],
            payment_gas_limit: 500_000,
            action_target: [6; 20],
            action_calldata_hash: [7; 32],
            action_gas_limit: 700_000,
            tracked_assets_hash: [8; 32],
            maximum_transaction_gas: 1_600_000,
            return_data_limit: 256,
            valid_until_unix: 10_000,
        };
        let chain_timestamp = 100;
        let wall_timestamp = 1_000;
        assert!(wall_timestamp > chain_timestamp + policy.ttl_secs);
        assert_eq!(
            policy
                .validate_request(&request, 421_614, Address::from([1; 20]), chain_timestamp,)
                .unwrap(),
            (1_600_000, 130),
        );
    }
}
