//! Chain-facing outputs of the node, pinned as golden vectors in `tests/golden/chain/`.
//!
//! Covered: EIP-712 execution quote digests (the `execution_id`), exit signatures over them,
//! signed legacy (EIP-155) transaction bytes, peer identity signatures, wallet address
//! derivation, decimal and address parsing of operator config, gas-plan buffering,
//! profitability decisions, and the JSON-RPC requests the executor and the registry scope
//! check send upstream (method and params, compared as JSON values).
//!
//! The files were produced by the Ethereum library the node used before the current one and
//! must stay equal. To regenerate deliberately, run with `NOX_UPDATE_GOLDEN=1` and review the
//! diff.

use async_trait::async_trait;
use nox_core::ExecutionQuoteV1;
use nox_node::blockchain::executor::ChainExecutor;
use nox_node::blockchain::registry_scope::fetch_registry_fingerprint;
use nox_node::blockchain::transaction_plan::{buffered, CostCandidate};
use nox_node::config::{PaymentAdapterConfig, TokenConfig};
use nox_node::network::service::sign_peer_id;
use nox_node::price::client::{FixedPriceSource, PriceClientError, PriceQuote};
use nox_node::services::profitability::ProfitabilityCalculator;
use nox_node::services::quotes::{execution_quote_digest, QuotePolicy};
use nox_node::{NodeRole, NoxConfig};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// Conversions between plain bytes/strings and the Ethereum library types the node API takes.
mod eth {
    pub use ethers::types::{Address, Bytes, H256 as B256, U256};

    pub fn address(bytes: [u8; 20]) -> Address {
        Address::from(bytes)
    }

    pub fn address_hex(address: &Address) -> String {
        format!("0x{}", hex::encode(address.as_bytes()))
    }

    pub fn b256(bytes: [u8; 32]) -> B256 {
        B256::from(bytes)
    }

    pub fn b256_hex(value: &B256) -> String {
        format!("0x{}", hex::encode(value.as_bytes()))
    }

    pub fn bytes(value: &[u8]) -> Bytes {
        Bytes::from(value.to_vec())
    }

    pub fn u256(value: u128) -> U256 {
        U256::from(value)
    }

    pub fn u256_max() -> U256 {
        U256::MAX
    }

    pub fn u256_dec(value: &U256) -> String {
        value.to_string()
    }

    pub fn shl(value: U256, bits: usize) -> U256 {
        value << bits
    }
}

const KEYS: [&str; 3] = [
    "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x0000000000000000000000000000000000000000000000000000000000000001",
];

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/chain")
        .join(format!("{name}.json"))
}

fn check_golden(name: &str, actual: &Value) {
    let path = golden_path(name);
    if std::env::var_os("NOX_UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().expect("golden dir")).expect("create golden dir");
        let mut text = serde_json::to_string_pretty(actual).expect("encode golden");
        text.push('\n');
        std::fs::write(&path, text).expect("write golden");
        return;
    }
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("golden file {} missing: {error}", path.display()));
    let expected: Value = serde_json::from_str(&text).expect("decode golden");
    assert_eq!(
        actual,
        &expected,
        "golden {name} differs:\nactual = {}",
        serde_json::to_string_pretty(actual).expect("encode actual")
    );
}

fn word(value: u128) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out[16..].copy_from_slice(&value.to_be_bytes());
    out
}

fn quotes() -> Vec<ExecutionQuoteV1> {
    let base = ExecutionQuoteV1 {
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
    let live_like = ExecutionQuoteV1 {
        chain_id: word(421_614),
        entry_point: hex_array("ad911ca217c6dc779fce6a6538bdda3071c38e7e"),
        exit_address: hex_array("74486dc1ac551e5cd3f4eef80727cc9d50d3abe9"),
        payment_adapter: hex_array("fc874b702f8d59b60b35582855505f4f60ce766d"),
        fee_asset: hex_array("0f69cf1c9f4ff72471701036dd789c934458e630"),
        exit_fee: word(1_234_567_890_123_456_789),
        network_fee: word(61_728_394_506_172_840),
        maximum_fee_per_gas: word(20_000_000),
        quote_nonce: word(u128::from(u64::MAX) + 7),
        ..base.clone()
    };
    let extremes = ExecutionQuoteV1 {
        quote_version: u8::MAX,
        chain_id: [0xff; 32],
        entry_point: [0xff; 20],
        exit_address: [0; 20],
        client_intent_id: [0xff; 32],
        payment_adapter: [0x01; 20],
        payment_id: [0; 32],
        fee_asset: [0xfe; 20],
        exit_fee: [0xff; 32],
        network_fee: [0; 32],
        payment_gas_limit: [0xff; 32],
        action_target: [0x80; 20],
        action_calldata_hash: [0x7f; 32],
        action_gas_limit: [0; 32],
        tracked_assets_hash: [0xaa; 32],
        maximum_transaction_gas: [0xff; 32],
        maximum_fee_per_gas: [0xff; 32],
        return_data_limit: [0xff; 32],
        valid_after_unix: 0,
        valid_until_unix: u64::MAX,
        quote_nonce: [0xff; 32],
    };
    vec![base, live_like, extremes]
}

fn hex_array<const N: usize>(text: &str) -> [u8; N] {
    hex::decode(text).expect("hex").try_into().expect("length")
}

async fn offline_executor(key: &str, chain_id: u64) -> ChainExecutor {
    let mut config = NoxConfig::default();
    config.eth_rpc_url = "http://127.0.0.1:9".to_string();
    config.chain_id = chain_id;
    config.eth_wallet_private_key = key.to_string();
    ChainExecutor::new(&config).await.expect("executor")
}

#[test]
fn execution_quote_digests() {
    let digests: Vec<String> = quotes()
        .iter()
        .map(|quote| eth::b256_hex(&execution_quote_digest(quote)))
        .collect();
    check_golden("execution_quote_digests", &json!(digests));
}

#[tokio::test]
async fn exit_signatures_and_wallet_addresses() {
    let mut out = Vec::new();
    for key in KEYS {
        let executor = offline_executor(key, 421_614).await;
        let signatures: Vec<String> = quotes()
            .iter()
            .map(|quote| {
                let digest = execution_quote_digest(quote);
                hex::encode(executor.sign_execution_digest(digest).expect("sign"))
            })
            .collect();
        out.push(json!({
            "key": key,
            "address": eth::address_hex(&executor.address()),
            "execution_signatures": signatures,
        }));
    }
    check_golden("exit_signatures", &Value::Array(out));
}

#[tokio::test]
async fn signed_legacy_transactions() {
    let big_data: Vec<u8> = (0..300_u32).map(|index| (index * 7 % 256) as u8).collect();
    let cases: Vec<(u64, [u8; 20], Vec<u8>, eth::U256, eth::U256, eth::U256)> = vec![
        (
            421_614,
            [0x11; 20],
            Vec::new(),
            eth::u256(0),
            eth::u256(21_000),
            eth::u256(1_000_000_000),
        ),
        (
            421_614,
            hex_array("ad911ca217c6dc779fce6a6538bdda3071c38e7e"),
            hex::decode("deadbeef0000000000000000000000000000000000000000000000000000000000000001")
                .expect("hex"),
            eth::u256(7),
            eth::u256(1_450_000),
            eth::u256(100_000_000),
        ),
        (
            421_614,
            [0xff; 20],
            big_data,
            eth::u256(1 << 40),
            eth::u256(30_000_000),
            eth::u256((1_u128 << 64) + 5),
        ),
        (
            31_337,
            [0x00; 20],
            vec![0x00],
            eth::u256(127),
            eth::u256(128),
            eth::u256(255),
        ),
        (
            1,
            [0x80; 20],
            vec![0x80; 56],
            eth::u256(128),
            eth::u256(256),
            eth::u256(256),
        ),
    ];
    let mut out = Vec::new();
    for key in KEYS {
        for (chain_id, to, data, nonce, gas, price) in &cases {
            let executor = offline_executor(key, *chain_id).await;
            let raw = executor
                .sign_legacy_transaction(eth::address(*to), eth::bytes(data), *nonce, *gas, *price)
                .await
                .expect("sign transaction");
            out.push(json!({
                "key": key,
                "chain_id": chain_id,
                "nonce": eth::u256_dec(nonce),
                "raw": format!("0x{}", hex::encode(raw.as_ref())),
            }));
        }
    }
    check_golden("signed_legacy_transactions", &Value::Array(out));
}

#[test]
fn peer_identity_signatures() {
    let peer_ids: [Vec<u8>; 3] = [
        hex::decode("0024080112205a4e1d0b2bd1a4c5a6c6e0ff9d1dd2c1e0b8e8c1f2a3b4c5d6e7f8091a2b3c4d")
            .expect("hex"),
        Vec::new(),
        vec![0xab; 64],
    ];
    let mut out = Vec::new();
    for key in KEYS {
        for peer_id in &peer_ids {
            out.push(json!({
                "key": key,
                "peer_id": hex::encode(peer_id),
                "signature": sign_peer_id(peer_id, key).expect("sign peer id"),
            }));
        }
    }
    // Keys of the wrong length are left out: the previous library panicked on them.
    let invalid: Vec<Value> = ["zz", &"00".repeat(32), &"ff".repeat(32)]
        .iter()
        .map(|key| json!({"key": key, "ok": sign_peer_id(b"peer", key).is_ok()}))
        .collect();
    check_golden(
        "peer_identity_signatures",
        &json!({"valid": out, "invalid": invalid}),
    );
}

const DECIMAL_INPUTS: [&str; 12] = [
    "",
    "0",
    "1",
    "00012",
    "1_0",
    "0x10",
    " 1",
    "1 ",
    "-1",
    "abc",
    "115792089237316195423570985008687907853269984665640564039457584007913129639935",
    "115792089237316195423570985008687907853269984665640564039457584007913129639936",
];

const ADDRESS_INPUTS: [&str; 9] = [
    "0x74486dc1ac551e5cd3f4eef80727cc9d50d3abe9",
    "0x74486DC1AC551E5CD3F4EEF80727CC9D50D3ABE9",
    "0X74486dc1ac551e5cd3f4eef80727cc9d50d3abe9",
    "74486dc1ac551e5cd3f4eef80727cc9d50d3abe9",
    "0x74486Dc1ac551E5cd3F4EeF80727cC9d50d3aBe9",
    "0x74486dc1ac551e5cd3f4eef80727cc9d50d3abe",
    "0x74486dc1ac551e5cd3f4eef80727cc9d50d3abe9aa",
    "0x",
    "",
];

fn quote_policy_config() -> NoxConfig {
    let mut config = NoxConfig::default();
    config.payment_adapters = vec![PaymentAdapterConfig {
        address: "0xfc874b702f8d59b60b35582855505f4f60ce766d".to_string(),
        fee_assets: vec!["0x0f69cf1c9f4ff72471701036dd789c934458e630".to_string()],
        maximum_payment_gas: 600_000,
    }];
    config.quote_rolling_loss_limit_native = "1000".to_string();
    config
}

fn exit_config() -> NoxConfig {
    let mut config = quote_policy_config();
    config.node_role = NodeRole::Exit;
    config.routing_private_key = "11".repeat(32);
    config.eth_wallet_private_key = KEYS[0].to_string();
    config.registry_contract_address = "0xf7bff88a1412054a001dc4b8acbddad6f9b26cb6".to_string();
    config.nox_reward_pool_address = "0x0000000000000000000000000000000000000001".to_string();
    config.nox_entry_point_address = "0xad911ca217c6dc779fce6a6538bdda3071c38e7e".to_string();
    config.oracle_url = "http://127.0.0.1:15004".to_string();
    config.tokens = vec![TokenConfig {
        address: "0x0f69cf1c9f4ff72471701036dd789c934458e630".to_string(),
        symbol: "SOKA".to_string(),
        decimals: 18,
        price_id: "soka".to_string(),
    }];
    config
}

fn validation_errors(config: &NoxConfig) -> Value {
    match config.validate() {
        Ok(()) => json!([]),
        Err(errors) => json!(errors),
    }
}

#[test]
fn operator_config_parsing() {
    let rolling_loss: Vec<Value> = DECIMAL_INPUTS
        .iter()
        .map(|input| {
            let mut config = quote_policy_config();
            config.quote_rolling_loss_limit_native = (*input).to_string();
            let policy = QuotePolicy::from_config(&config)
                .map(|policy| eth::u256_dec(&policy.rolling_loss_limit_native));
            json!({"input": input, "quote_policy": policy.ok()})
        })
        .collect();
    let adapter_addresses: Vec<Value> = ADDRESS_INPUTS
        .iter()
        .map(|input| {
            let mut config = quote_policy_config();
            config.payment_adapters[0].address = (*input).to_string();
            let policy = QuotePolicy::from_config(&config)
                .map(|policy| eth::address_hex(&policy.adapters[0].address));
            json!({"input": input, "quote_policy": policy.ok()})
        })
        .collect();
    let base_errors = validation_errors(&exit_config());
    let rolling_loss_validation: Vec<Value> = DECIMAL_INPUTS
        .iter()
        .chain(["10", "a", "ff", "0x0"].iter())
        .map(|input| {
            let mut config = exit_config();
            config.quote_rolling_loss_limit_native = (*input).to_string();
            json!({"input": input, "errors": validation_errors(&config)})
        })
        .collect();
    let token_validation: Vec<Value> = ADDRESS_INPUTS
        .iter()
        .chain(["0x0000000000000000000000000000000000000000"].iter())
        .map(|input| {
            let mut config = exit_config();
            config.tokens[0].address = (*input).to_string();
            json!({"input": input, "errors": validation_errors(&config)})
        })
        .collect();
    check_golden(
        "operator_config_parsing",
        &json!({
            "quote_policy_rolling_loss": rolling_loss,
            "quote_policy_adapter_address": adapter_addresses,
            "validate_base": base_errors,
            "validate_rolling_loss": rolling_loss_validation,
            "validate_token_address": token_validation,
        }),
    );
}

#[test]
fn gas_plan_buffering() {
    let values = [
        eth::u256(0),
        eth::u256(1),
        eth::u256(21_000),
        eth::u256(9_999),
        eth::u256(123_456_789_012),
        eth::shl(eth::u256(1), 200),
        eth::u256_max(),
    ];
    let mut out = Vec::new();
    for value in values {
        for bps in [0_u32, 1, 2_000, 9_999, 10_000, u32::MAX] {
            for field in ["gas_limit", "initial_fee_per_gas"] {
                let result = buffered(value, bps, field);
                out.push(json!({
                    "value": eth::u256_dec(&value),
                    "bps": bps,
                    "field": field,
                    "result": result.as_ref().map(eth::u256_dec).map_err(ToString::to_string),
                }));
            }
        }
    }
    check_golden("gas_plan_buffering", &Value::Array(out));
}

struct Prices;

#[async_trait]
impl FixedPriceSource for Prices {
    async fn get_price(&self, asset_id: &str) -> Result<PriceQuote, PriceClientError> {
        let price_e8 = match asset_id {
            "ethereum" => 250_012_345_678,
            "usd-coin" => 99_987_654,
            "soka" => 3_333_333,
            _ => {
                return Err(PriceClientError::AssetNotFound {
                    asset_id: asset_id.to_string(),
                })
            }
        };
        Ok(PriceQuote {
            price_e8,
            observed_at_unix: 1,
            asset_id: asset_id.to_string(),
        })
    }
}

fn calculator(margin_bps: u128) -> ProfitabilityCalculator {
    let mut calculator = ProfitabilityCalculator::with_economics(
        margin_bps,
        Arc::new(Prices),
        eth::address([0x42; 20]),
        nox_node::services::token_registry::TokenRegistry::new(),
        "ethereum".to_string(),
        18,
    );
    calculator.register_token(eth::address([0x0a; 20]), "USDC", 6, "usd-coin");
    calculator.register_token(eth::address([0x0b; 20]), "SOKA", 18, "soka");
    calculator
}

#[tokio::test]
async fn profitability_decisions() {
    let candidates = [
        (21_000_u128, 10_000_000_u128, 0_u128),
        (1_450_000, 20_000_000, 0),
        (1_450_000, 20_000_000, 123_456_789_000),
        (30_000_000, 1_000_000_000, 5),
    ];
    let fees: [([u8; 20], u128); 4] = [
        ([0x0a; 20], 1_000_000),
        ([0x0a; 20], 250_000_000),
        ([0x0b; 20], 9_000_000_000_000_000_000),
        ([0x0c; 20], 1),
    ];
    let mut out = Vec::new();
    for margin in [0_u128, 1_000, 2_500] {
        let calculator = calculator(margin);
        for (gas_limit, fee, chain_data) in candidates {
            for (asset, amount) in fees {
                let candidate = CostCandidate {
                    gas_limit: eth::u256(gas_limit),
                    initial_fee_per_gas: eth::u256(fee),
                    chain_data_fee_native: eth::u256(chain_data),
                };
                let authorization = calculator
                    .authorize_fee(candidate.clone(), eth::address(asset), eth::u256(amount))
                    .await;
                let capped = calculator
                    .authorize_fee_with_maximum_fee_per_gas(
                        candidate,
                        eth::address(asset),
                        eth::u256(amount),
                        eth::u256(fee * 3),
                    )
                    .await;
                let render = |result: Result<
                    nox_node::services::profitability::ProfitAuthorization,
                    nox_node::services::profitability::ProfitabilityError,
                >| match result {
                    Ok(value) => json!({
                        "gas_limit": eth::u256_dec(&value.plan.gas_limit),
                        "initial_fee_per_gas": eth::u256_dec(&value.plan.initial_fee_per_gas),
                        "maximum_fee_per_gas": eth::u256_dec(&value.plan.maximum_fee_per_gas),
                        "chain_data_fee_native": eth::u256_dec(&value.plan.chain_data_fee_native),
                        "revenue_value_e8": eth::u256_dec(&value.revenue_value_e8),
                        "planned_initial_cost_value_e8": eth::u256_dec(&value.planned_initial_cost_value_e8),
                        "maximum_cost_value_e8": eth::u256_dec(&value.maximum_cost_value_e8),
                    }),
                    Err(nox_node::services::profitability::ProfitabilityError::Unprofitable {
                        revenue_value_e8,
                        maximum_cost_value_e8,
                    }) => json!({
                        "unprofitable": {
                            "revenue_value_e8": eth::u256_dec(&revenue_value_e8),
                            "maximum_cost_value_e8": eth::u256_dec(&maximum_cost_value_e8),
                        }
                    }),
                    Err(error) => json!({"error": error.to_string()}),
                };
                out.push(json!({
                    "margin_bps": margin,
                    "candidate": [gas_limit.to_string(), fee.to_string(), chain_data.to_string()],
                    "fee": [hex::encode(asset), amount.to_string()],
                    "authorize_fee": render(authorization),
                    "authorize_fee_capped": render(capped),
                }));
            }
        }
        for (asset, _) in fees {
            for (gas, fee_per_gas) in [(21_000_u128, 1_u128), (1_450_000, 20_000_000)] {
                let quote = calculator
                    .quote_exit_fee(eth::address(asset), eth::u256(gas), eth::u256(fee_per_gas))
                    .await;
                out.push(json!({
                    "margin_bps": margin,
                    "quote_exit_fee": [hex::encode(asset), gas.to_string(), fee_per_gas.to_string()],
                    "result": quote.as_ref().map(eth::u256_dec).map_err(ToString::to_string),
                }));
            }
        }
    }
    check_golden("profitability_decisions", &Value::Array(out));
}

/// Answers JSON-RPC calls from canned results and records every request.
#[derive(Clone)]
struct RecordingRpc {
    requests: Arc<Mutex<Vec<Value>>>,
    simulate_supported: bool,
}

const BLOCK_JSON: &str = r#"{
    "hash": "0x5e0dc2ac8bd6b2fba0d9b6e4d3b8e43be7d2a7d5e0b6b6c4b5a8d0b6f1e2d3c4",
    "parentHash": "0x1111111111111111111111111111111111111111111111111111111111111111",
    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
    "miner": "0xa4b000000000000000000073657175656e636572",
    "stateRoot": "0x2222222222222222222222222222222222222222222222222222222222222222",
    "transactionsRoot": "0x3333333333333333333333333333333333333333333333333333333333333333",
    "receiptsRoot": "0x4444444444444444444444444444444444444444444444444444444444444444",
    "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "difficulty": "0x1",
    "number": "0x12d9b1e0",
    "gasLimit": "0x4000000000000",
    "gasUsed": "0x0",
    "timestamp": "0x6a1b2c3d",
    "extraData": "0x",
    "mixHash": "0x5555555555555555555555555555555555555555555555555555555555555555",
    "nonce": "0x0000000000000001",
    "baseFeePerGas": "0x989680",
    "totalDifficulty": "0x1",
    "size": "0x2a0",
    "uncles": [],
    "transactions": []
}"#;

impl RecordingRpc {
    fn result_for(&self, method: &str, params: &Value) -> Result<Value, Value> {
        match method {
            "eth_chainId" => Ok(json!("0x66eee")),
            "eth_gasPrice" => Ok(json!("0x5f5e100")),
            "eth_getTransactionCount" => Ok(json!("0x7")),
            "eth_estimateGas" => Ok(json!("0x1d4c0")),
            "eth_getBalance" => Ok(json!("0xde0b6b3a7640000")),
            "eth_call" => Ok(json!(format!("0x{}", "ab".repeat(32)))),
            "eth_getBlockByNumber" => Ok(serde_json::from_str(BLOCK_JSON).expect("block json")),
            "eth_getTransactionReceipt" => Ok(Value::Null),
            "eth_sendRawTransaction" => {
                let raw = params[0].as_str().expect("raw tx param");
                let bytes = hex::decode(raw.trim_start_matches("0x")).expect("raw hex");
                let mut hasher = tiny_keccak::Keccak::v256();
                let mut hash = [0_u8; 32];
                tiny_keccak::Hasher::update(&mut hasher, &bytes);
                tiny_keccak::Hasher::finalize(hasher, &mut hash);
                Ok(json!(format!("0x{}", hex::encode(hash))))
            }
            "eth_simulateV1" if self.simulate_supported => Ok(json!([{
                "number": "0x12d9b1e1",
                "calls": [{
                    "status": "0x1",
                    "gasUsed": "0x2b6c4",
                    "returnData": "0x",
                    "logs": [
                        {
                            "address": "0xA487000000000000000000000000000000000361",
                            "topics": [
                                "0x1fe5a7ef1d3d4e0c9f2b2c6a0d1f2e3b4c5d6e7f8091a2b3c4d5e6f708192a3b",
                                "0x0000000000000000000000000f69cf1c9f4ff72471701036dd789c934458e630"
                            ],
                            "data": "0x00000000000000000000000000000000000000000000000000000000000003e8",
                            "blockNumber": "0x12d9b1e1",
                            "logIndex": "0x0"
                        },
                        {
                            "address": "0xad911ca217c6dc779fce6a6538bdda3071c38e7e",
                            "topics": [],
                            "data": "0x"
                        }
                    ]
                }]
            }])),
            "eth_simulateV1" => Err(json!({
                "code": -32601,
                "message": "the method eth_simulateV1 does not exist/is not available"
            })),
            "debug_traceCall" => {
                let call = &params[0];
                Ok(json!({
                    "type": "CALL",
                    "from": call["from"],
                    "to": call["to"],
                    "input": call.get("input").or_else(|| call.get("data")).cloned().unwrap_or(Value::Null),
                    "value": "0x0",
                    "gas": "0x1c9c380",
                    "gasUsed": "0x2b6c4",
                    "output": "0x",
                    "logs": [{
                        "address": "0xa487000000000000000000000000000000000361",
                        "topics": ["0x1fe5a7ef1d3d4e0c9f2b2c6a0d1f2e3b4c5d6e7f8091a2b3c4d5e6f708192a3b"],
                        "data": "0x01"
                    }],
                    "calls": [
                        {
                            "type": "CALL",
                            "from": call["to"],
                            "to": "0x0f69cf1c9f4ff72471701036dd789c934458e630",
                            "input": "0x",
                            "value": "0x0",
                            "gas": "0x1000",
                            "gasUsed": "0x10",
                            "error": "execution reverted",
                            "logs": [{
                                "address": "0x0f69cf1c9f4ff72471701036dd789c934458e630",
                                "topics": [],
                                "data": "0x02"
                            }]
                        },
                        {
                            "type": "CALL",
                            "from": call["to"],
                            "to": "0x0f69cf1c9f4ff72471701036dd789c934458e630",
                            "input": "0x",
                            "value": "0x0",
                            "gas": "0x1000",
                            "gasUsed": "0x10",
                            "logs": [{
                                "address": "0x0f69cf1c9f4ff72471701036dd789c934458e630",
                                "topics": ["0x2222222222222222222222222222222222222222222222222222222222222222"],
                                "data": "0x03"
                            }]
                        }
                    ]
                }))
            }
            other => Err(json!({"code": -32000, "message": format!("unexpected {other}")})),
        }
    }
}

impl Respond for RecordingRpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).expect("json-rpc body");
        let method = body["method"].as_str().expect("method").to_string();
        let params = body.get("params").cloned().unwrap_or(Value::Null);
        self.requests
            .lock()
            .expect("requests")
            .push(json!({"method": method, "params": params}));
        let mut response = json!({"jsonrpc": "2.0", "id": body["id"]});
        match self.result_for(&method, &params) {
            Ok(result) => response["result"] = result,
            Err(error) => response["error"] = error,
        }
        ResponseTemplate::new(200).set_body_json(response)
    }
}

async fn recording_server(simulate_supported: bool) -> (MockServer, RecordingRpc) {
    let server = MockServer::start().await;
    let rpc = RecordingRpc {
        requests: Arc::default(),
        simulate_supported,
    };
    Mock::given(wiremock::matchers::method("POST"))
        .respond_with(rpc.clone())
        .mount(&server)
        .await;
    (server, rpc)
}

fn take_requests(rpc: &RecordingRpc) -> Vec<Value> {
    std::mem::take(&mut *rpc.requests.lock().expect("requests"))
}

fn render_logs(logs: &[ethers::types::Log]) -> Value {
    json!(logs
        .iter()
        .map(|log| json!({
            "address": eth::address_hex(&log.address),
            "topics": log.topics.iter().map(eth::b256_hex).collect::<Vec<_>>(),
            "data": format!("0x{}", hex::encode(log.data.as_ref())),
        }))
        .collect::<Vec<_>>())
}

#[tokio::test]
async fn executor_upstream_requests() {
    let (server, rpc) = recording_server(true).await;
    let mut config = NoxConfig::default();
    config.eth_rpc_url = server.uri();
    config.chain_id = 0;
    config.eth_wallet_private_key = KEYS[1].to_string();
    let executor = ChainExecutor::new(&config).await.expect("executor");
    let target = eth::address(hex_array("ad911ca217c6dc779fce6a6538bdda3071c38e7e"));
    let calldata = eth::bytes(&hex::decode("c0ffee00112233").expect("hex"));

    let mut steps = Vec::new();
    steps.push(
        json!({"step": "new", "chain_id": executor.chain_id(), "requests": take_requests(&rpc)}),
    );

    let timestamp = executor.latest_block_timestamp().await.expect("timestamp");
    steps.push(json!({"step": "latest_block_timestamp", "result": timestamp, "requests": take_requests(&rpc)}));

    let (balance, low) = executor.check_gas_health().await.expect("gas health");
    steps.push(json!({"step": "check_gas_health", "result": [eth::u256_dec(&balance), low], "requests": take_requests(&rpc)}));

    let price = executor.get_gas_price().await.expect("gas price");
    steps.push(json!({"step": "get_gas_price", "result": eth::u256_dec(&price), "requests": take_requests(&rpc)}));

    let nonce = executor.get_nonce().await.expect("nonce");
    steps.push(json!({"step": "get_nonce", "result": eth::u256_dec(&nonce), "requests": take_requests(&rpc)}));

    let confirmed = executor
        .get_confirmed_nonce()
        .await
        .expect("confirmed nonce");
    steps.push(json!({"step": "get_confirmed_nonce", "result": eth::u256_dec(&confirmed), "requests": take_requests(&rpc)}));

    let gas = executor
        .estimate_gas(target, calldata.clone())
        .await
        .expect("estimate");
    steps.push(json!({"step": "estimate_gas", "result": gas, "requests": take_requests(&rpc)}));

    let candidate = executor
        .build_cost_candidate(target, calldata.clone(), 2_000, 1_500)
        .await
        .expect("candidate");
    steps.push(json!({
        "step": "build_cost_candidate",
        "result": [
            eth::u256_dec(&candidate.gas_limit),
            eth::u256_dec(&candidate.initial_fee_per_gas),
            eth::u256_dec(&candidate.chain_data_fee_native),
        ],
        "requests": take_requests(&rpc),
    }));

    let state = executor
        .query_state(target, calldata.clone())
        .await
        .expect("query");
    steps.push(json!({"step": "query_state", "result": format!("0x{}", hex::encode(state.as_ref())), "requests": take_requests(&rpc)}));

    let simulated = executor
        .simulate_transaction(target, calldata.clone())
        .await
        .expect("simulate");
    steps.push(json!({"step": "simulate_transaction", "result": simulated, "requests": take_requests(&rpc)}));

    let receipt = executor
        .get_transaction_receipt(eth::b256([0x77; 32]))
        .await
        .expect("receipt");
    steps.push(json!({"step": "get_transaction_receipt", "result": receipt.is_some(), "requests": take_requests(&rpc)}));

    let raw = executor
        .sign_legacy_transaction(
            target,
            calldata.clone(),
            eth::u256(7),
            eth::u256(120_000),
            eth::u256(100_000_000),
        )
        .await
        .expect("sign");
    let hash = executor
        .broadcast_raw_signed_tx(raw.as_ref())
        .await
        .expect("broadcast");
    steps.push(json!({"step": "broadcast_raw_signed_tx", "result": eth::b256_hex(&hash), "requests": take_requests(&rpc)}));

    let evidence = executor
        .simulate_transaction_evidence(target, calldata.clone())
        .await
        .expect("simulate evidence");
    steps.push(json!({
        "step": "simulate_transaction_evidence",
        "result": {"gas_used": evidence.gas_used, "source": format!("{:?}", evidence.source), "logs": render_logs(&evidence.logs)},
        "requests": take_requests(&rpc),
    }));

    let (trace_server, trace_rpc) = recording_server(false).await;
    config.eth_rpc_url = trace_server.uri();
    config.chain_id = 421_614;
    let trace_executor = ChainExecutor::new(&config).await.expect("executor");
    let traced = trace_executor
        .simulate_transaction_evidence(target, calldata.clone())
        .await
        .expect("trace evidence");
    steps.push(json!({
        "step": "simulate_transaction_evidence_trace_fallback",
        "result": {"gas_used": traced.gas_used, "source": format!("{:?}", traced.source), "logs": render_logs(&traced.logs)},
        "requests": take_requests(&trace_rpc),
    }));
    let legacy = trace_executor
        .simulate_legacy_paid_transaction(target, calldata)
        .await
        .expect("legacy evidence");
    steps.push(json!({
        "step": "simulate_legacy_paid_transaction",
        "result": {"gas_used": legacy.gas_used, "source": format!("{:?}", legacy.source), "logs": render_logs(&legacy.logs)},
        "requests": take_requests(&trace_rpc),
    }));

    let fingerprint = fetch_registry_fingerprint(
        &server.uri(),
        " 0xF7BFf88A1412054a001Dc4b8aCBddAd6F9b26cB6 ",
    )
    .await
    .expect("fingerprint");
    steps.push(json!({"step": "fetch_registry_fingerprint", "result": hex::encode(fingerprint), "requests": take_requests(&rpc)}));

    check_golden("executor_upstream_requests", &Value::Array(steps));
}
