#![cfg(feature = "dev-node")]

use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::{Log, TransactionReceipt, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::{SolCall, SolValue};
use alloy_node_bindings::Anvil;
use nox_node::blockchain::executor::{
    ChainExecutor, ExpectedTransactionIdentity, SimulationEvidence, SimulationSource,
};
use nox_node::NoxConfig;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use wiremock::matchers::method;
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

const EXPECTED_SOLC: &str = "0.8.30";
const CHAIN_ID: u64 = 31_337;

alloy::sol! {
    function mint(address to, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
    function setAssetStatus(address asset, bool status) external;
    function totalCollected(address asset) external view returns (uint256);
    function depositThenRevert(address pool, address asset, uint256 amount) external;
    function depositSuccessfully(address pool, address asset, uint256 amount) external;
    function catchPayment(address child, bytes callData) external returns (bool);
    function forwardPayment(address child, bytes callData) external returns (bool);
}

#[derive(Debug)]
struct JsonRpcMethod(&'static str);

impl Match for JsonRpcMethod {
    fn matches(&self, request: &Request) -> bool {
        serde_json::from_slice::<Value>(&request.body)
            .ok()
            .and_then(|body| {
                body.get("method")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .as_deref()
            == Some(self.0)
    }
}

fn rpc_success(body: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": body,
    }))
}

fn rpc_error(code: i64, message: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": code,
            "message": message,
        },
    }))
}

fn rpc_unavailable() -> ResponseTemplate {
    rpc_error(-32601, "method unavailable")
}

/// Creation bytecode of a Hardhat artifact in `abi/`.
fn load_artifact(name: &str) -> anyhow::Result<Bytes> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("abi")
        .join(format!("{name}.json"));
    let artifact: Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let bytecode = artifact
        .get("bytecode")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("artifact {} has no bytecode", path.display()))?;
    Ok(Bytes::from(hex::decode(bytecode.trim_start_matches("0x"))?))
}

/// Compiles the fixture with `solc --standard-json` (optimizer off, Shanghai)
/// and returns the creation bytecode of the child and the parent contract.
fn compile_fixture() -> anyhow::Result<(Bytes, Bytes)> {
    let version = Command::new("solc").arg("--version").output()?;
    let version = String::from_utf8_lossy(&version.stdout).into_owned();
    anyhow::ensure!(
        version.contains(&format!("Version: {EXPECTED_SOLC}+")),
        "PaymentTraceHarness requires solc {EXPECTED_SOLC}, observed {version}"
    );

    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("PaymentTraceHarness.sol");
    let input = json!({
        "language": "Solidity",
        "sources": {
            "PaymentTraceHarness.sol": { "content": std::fs::read_to_string(&fixture)? }
        },
        "settings": {
            "optimizer": { "enabled": false, "runs": 200 },
            "evmVersion": "shanghai",
            "outputSelection": { "*": { "*": ["evm.bytecode.object"] } }
        }
    });
    let mut child = Command::new("solc")
        .arg("--standard-json")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("solc stdin unavailable"))?
            .write_all(serde_json::to_string(&input)?.as_bytes())?;
    }
    let output: Value = serde_json::from_slice(&child.wait_with_output()?.stdout)?;
    let errors: Vec<&Value> = output["errors"]
        .as_array()
        .map(|errors| {
            errors
                .iter()
                .filter(|error| error["severity"] == "error")
                .collect()
        })
        .unwrap_or_default();
    anyhow::ensure!(
        errors.is_empty(),
        "PaymentTraceHarness compilation failed: {errors:?}"
    );
    let bytecode = |name: &str| -> anyhow::Result<Bytes> {
        let object = output["contracts"]["PaymentTraceHarness.sol"][name]["evm"]["bytecode"]
            ["object"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("compiled fixture has no {name}"))?;
        Ok(Bytes::from(hex::decode(object)?))
    };
    Ok((
        bytecode("RevertingPaymentChild")?,
        bytecode("CatchingPaymentParent")?,
    ))
}

async fn deploy_contract(
    client: &DynProvider,
    bytecode: Bytes,
    constructor: Vec<u8>,
) -> anyhow::Result<Address> {
    let mut code = bytecode.to_vec();
    code.extend(constructor);
    let receipt = client
        .send_transaction(TransactionRequest::default().with_deploy_code(code))
        .await?
        .get_receipt()
        .await?;
    receipt
        .contract_address
        .ok_or_else(|| anyhow::anyhow!("deployment produced no contract address"))
}

async fn send_identified_call<C: SolCall>(
    client: &DynProvider,
    to: Address,
    call: C,
) -> anyhow::Result<(B256, TransactionReceipt)> {
    let pending = client
        .send_transaction(
            TransactionRequest::default()
                .with_to(to)
                .with_input(call.abi_encode()),
        )
        .await?;
    let transaction_hash = *pending.tx_hash();
    let receipt = pending.get_receipt().await?;
    Ok((transaction_hash, receipt))
}

async fn send_call<C: SolCall>(
    client: &DynProvider,
    to: Address,
    call: C,
) -> anyhow::Result<TransactionReceipt> {
    Ok(send_identified_call(client, to, call).await?.1)
}

async fn view<C: SolCall>(client: &DynProvider, to: Address, call: C) -> anyhow::Result<C::Return> {
    let output = client
        .call(
            TransactionRequest::default()
                .with_to(to)
                .with_input(call.abi_encode()),
        )
        .await?;
    Ok(C::abi_decode_returns(&output)?)
}

fn assert_receipt_error(
    receipt: TransactionReceipt,
    expected: ExpectedTransactionIdentity,
    category: &str,
) {
    let error = SimulationEvidence::from_committed_receipt(receipt, expected)
        .expect_err("mutated receipt must be rejected")
        .to_string();
    assert_eq!(error, format!("Blockchain error: {category}"));
}

/// Applies `mutate` to the receipt's JSON form and reads it back.
fn mutated_receipt(
    receipt: &TransactionReceipt,
    mutate: impl FnOnce(&mut Value),
) -> TransactionReceipt {
    let mut value = serde_json::to_value(receipt).expect("receipt json");
    mutate(&mut value);
    serde_json::from_value(value).expect("mutated receipt json")
}

fn hex_word(byte: u8) -> Value {
    json!(format!("{:#x}", B256::with_last_byte(byte)))
}

fn hex_address(byte: u8) -> Value {
    json!(format!("{:#x}", Address::with_last_byte(byte)))
}

async fn token_balance(
    client: &DynProvider,
    token: Address,
    account: Address,
) -> anyhow::Result<U256> {
    view(client, token, balanceOfCall { account }).await
}

async fn total_collected(
    client: &DynProvider,
    pool: Address,
    asset: Address,
) -> anyhow::Result<U256> {
    view(client, pool, totalCollectedCall { asset }).await
}

fn reward_event_count(logs: &[Log], pool: Address) -> usize {
    let topic = keccak256("RewardsDeposited(address,address,uint256)");
    logs.iter()
        .filter(|log| log.address() == pool && log.topics().first() == Some(&topic))
        .count()
}

fn address_topic(address: Address) -> B256 {
    address.into_word()
}

fn amount_data(amount: U256) -> String {
    format!("0x{}", hex::encode(amount.to_be_bytes::<32>()))
}

fn rpc_log(reward_pool: Address, asset: Address, payer: Address, amount: U256) -> Value {
    json!({
        "address": format!("{reward_pool:#x}"),
        "topics": [
            format!("{:#x}", keccak256("RewardsDeposited(address,address,uint256)")),
            format!("{:#x}", address_topic(asset)),
            format!("{:#x}", address_topic(payer)),
        ],
        "data": amount_data(amount),
    })
}

async fn rpc_executor_at(rpc_url: String) -> anyhow::Result<ChainExecutor> {
    let wallet = PrivateKeySigner::random();
    let mut config = NoxConfig::default();
    config.eth_rpc_url = rpc_url;
    config.eth_wallet_private_key = hex::encode(wallet.to_bytes());
    config.chain_id = CHAIN_ID;
    config.min_gas_balance = "0".into();
    config.benchmark_mode = false;
    Ok(ChainExecutor::new(&config).await?)
}

async fn rpc_executor(server: &MockServer) -> anyhow::Result<ChainExecutor> {
    rpc_executor_at(server.uri()).await
}

async fn mount_flat_simulation(server: &MockServer, payment_log: Value) {
    Mock::given(method("POST"))
        .and(JsonRpcMethod("eth_simulateV1"))
        .respond_with(rpc_success(json!([{
            "calls": [{
                "status": "0x1",
                "gasUsed": "0x5208",
                "logs": [payment_log],
            }],
        }])))
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_snapshot_unavailable(server: &MockServer) {
    Mock::given(method("POST"))
        .and(JsonRpcMethod("evm_snapshot"))
        .respond_with(rpc_unavailable())
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_snapshot(server: &MockServer) {
    Mock::given(method("POST"))
        .and(JsonRpcMethod("evm_snapshot"))
        .respond_with(rpc_success(json!("0x1")))
        .expect(1)
        .mount(server)
        .await;
}

fn receipt_json(transaction_hash: B256, from: Address, to: Address, status: u64) -> Value {
    json!({
        "transactionHash": format!("{transaction_hash:#x}"),
        "transactionIndex": "0x0",
        "blockHash": format!("{:#x}", B256::with_last_byte(61)),
        "blockNumber": "0x1",
        "from": format!("{from:#x}"),
        "to": format!("{to:#x}"),
        "cumulativeGasUsed": "0x5208",
        "gasUsed": "0x5208",
        "contractAddress": null,
        "logs": [],
        "status": format!("{status:#x}"),
        "logsBloom": format!("0x{}", "00".repeat(256)),
        "type": "0x0",
        "effectiveGasPrice": "0x1",
    })
}

async fn mount_receipt_transaction(server: &MockServer, transaction_hash: B256, receipt: Value) {
    for (rpc_method, response) in [
        ("eth_getTransactionCount", json!("0x0")),
        ("eth_gasPrice", json!("0x1")),
        ("eth_estimateGas", json!("0x5208")),
        (
            "eth_sendRawTransaction",
            json!(format!("{transaction_hash:#x}")),
        ),
        ("eth_getTransactionReceipt", receipt),
    ] {
        Mock::given(method("POST"))
            .and(JsonRpcMethod(rpc_method))
            .respond_with(rpc_success(response))
            .expect(1)
            .mount(server)
            .await;
    }
}

async fn mount_successful_trace(server: &MockServer, from: Address, to: Address, input: &str) {
    Mock::given(method("POST"))
        .and(JsonRpcMethod("debug_traceCall"))
        .respond_with(rpc_success(json!({
            "type": "CALL",
            "from": format!("{from:#x}"),
            "to": format!("{to:#x}"),
            "value": "0x0",
            "gas": "0x5208",
            "gasUsed": "0x5208",
            "input": input,
            "output": "0x",
            "logs": [],
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("eth_estimateGas"))
        .respond_with(rpc_success(json!("0x5208")))
        .mount(server)
        .await;
}

fn receipt_rpc_methods() -> [&'static str; 8] {
    [
        "eth_simulateV1",
        "evm_snapshot",
        "eth_getTransactionCount",
        "eth_gasPrice",
        "eth_estimateGas",
        "eth_sendRawTransaction",
        "eth_getTransactionReceipt",
        "evm_revert",
    ]
}

fn request_method(request: &Request) -> String {
    serde_json::from_slice::<Value>(&request.body)
        .expect("recorded request must contain JSON")
        .get("method")
        .and_then(Value::as_str)
        .expect("recorded request must contain a method")
        .to_owned()
}

fn assert_rpc_methods(requests: &[Request], expected: &[&str]) {
    let actual = requests
        .iter()
        .fold(BTreeMap::new(), |mut counts, request| {
            *counts.entry(request_method(request)).or_insert(0_usize) += 1;
            counts
        });
    let expected = expected.iter().fold(BTreeMap::new(), |mut counts, method| {
        *counts.entry((*method).to_owned()).or_insert(0_usize) += 1;
        counts
    });
    assert_eq!(actual, expected);
}

fn assert_static_error<T: std::fmt::Debug>(
    failure: Result<T, nox_core::traits::InfrastructureError>,
    expected: &str,
) {
    let error = failure.expect_err("RPC regression must fail").to_string();
    assert_eq!(error, format!("Blockchain error: {expected}"));
    for sentinel in ["provider-sentinel", "0xfeedface", "private-payload"] {
        assert!(!error.contains(sentinel), "error exposed provider payload");
    }
}

#[tokio::test]
async fn caught_revert_receipt_has_no_committed_payment() -> anyhow::Result<()> {
    let (child_bytecode, parent_bytecode) = compile_fixture()?;
    let token_bytecode = load_artifact("MockERC20")?;
    let pool_bytecode = load_artifact("NoxRewardPool")?;

    let anvil = Anvil::new().spawn();
    let deployer = PrivateKeySigner::from_slice(&anvil.keys()[0].to_bytes())?;
    let deployer_address = deployer.address();
    let client = ProviderBuilder::new()
        .wallet(EthereumWallet::from(deployer))
        .connect_client(nox_core::chain_rpc::http1_rpc_client(&anvil.endpoint())?)
        .erased();

    let token = deploy_contract(
        &client,
        token_bytecode,
        // `uint8 decimals` is ABI-encoded as one 32-byte word, like a uint256.
        ("Fee Token".to_owned(), "FEE".to_owned(), U256::from(18)).abi_encode_params(),
    )
    .await?;
    let pool = deploy_contract(
        &client,
        pool_bytecode,
        (deployer_address,).abi_encode_params(),
    )
    .await?;
    let child = deploy_contract(&client, child_bytecode, Vec::new()).await?;
    let parent = deploy_contract(&client, parent_bytecode, Vec::new()).await?;

    send_call(
        &client,
        pool,
        setAssetStatusCall {
            asset: token,
            status: true,
        },
    )
    .await?;

    let payment = U256::from(10).pow(U256::from(18));
    send_call(
        &client,
        token,
        mintCall {
            to: child,
            amount: payment,
        },
    )
    .await?;

    let caught_calldata = depositThenRevertCall {
        pool,
        asset: token,
        amount: payment,
    }
    .abi_encode();
    let (caught_transaction_hash, caught_receipt) = send_identified_call(
        &client,
        parent,
        catchPaymentCall {
            child,
            callData: caught_calldata.into(),
        },
    )
    .await?;

    assert!(caught_receipt.status());
    assert_eq!(reward_event_count(caught_receipt.inner.logs(), pool), 0);
    assert_eq!(token_balance(&client, token, pool).await?, U256::ZERO);
    assert_eq!(total_collected(&client, pool, token).await?, U256::ZERO);
    assert_eq!(token_balance(&client, token, child).await?, payment);

    let caught_expected = ExpectedTransactionIdentity {
        transaction_hash: caught_transaction_hash,
        from: deployer_address,
        to: parent,
    };
    let caught_evidence =
        SimulationEvidence::from_committed_receipt(caught_receipt, caught_expected)?;
    assert_eq!(caught_evidence.source, SimulationSource::CommittedReceipt);
    assert!(caught_evidence
        .legacy_payment_logs()
        .expect("committed receipt is eligible")
        .is_empty());

    let successful_calldata = depositSuccessfullyCall {
        pool,
        asset: token,
        amount: payment,
    }
    .abi_encode();
    let (successful_transaction_hash, successful_receipt) = send_identified_call(
        &client,
        parent,
        forwardPaymentCall {
            child,
            callData: successful_calldata.into(),
        },
    )
    .await?;

    assert!(successful_receipt.status());
    assert_eq!(reward_event_count(successful_receipt.inner.logs(), pool), 1);
    assert_eq!(token_balance(&client, token, pool).await?, payment);
    assert_eq!(total_collected(&client, pool, token).await?, payment);
    assert_eq!(token_balance(&client, token, child).await?, U256::ZERO);

    let successful_expected = ExpectedTransactionIdentity {
        transaction_hash: successful_transaction_hash,
        from: deployer_address,
        to: parent,
    };

    // Receipt fields the RPC types model as required (`status`, `gasUsed`)
    // cannot be absent: such a receipt does not deserialize at all.
    for required in ["status", "gasUsed"] {
        let mut value = serde_json::to_value(&successful_receipt)?;
        value
            .as_object_mut()
            .expect("receipt object")
            .remove(required);
        assert!(serde_json::from_value::<TransactionReceipt>(value).is_err());
    }

    let receipt_mutations: [(&str, Value, &str); 7] = [
        (
            "status",
            json!("0x0"),
            "committed-receipt execution rejected",
        ),
        (
            "transactionHash",
            hex_word(91),
            "committed-receipt identity mismatch: transaction_hash",
        ),
        (
            "from",
            hex_address(92),
            "committed-receipt identity mismatch: from",
        ),
        ("to", Value::Null, "committed-receipt identity mismatch: to"),
        (
            "to",
            hex_address(97),
            "committed-receipt identity mismatch: to",
        ),
        (
            "blockHash",
            Value::Null,
            "committed-receipt evidence malformed: block_hash",
        ),
        (
            "blockNumber",
            Value::Null,
            "committed-receipt evidence malformed: block_number",
        ),
    ];
    for (field, replacement, category) in receipt_mutations {
        let mutated = mutated_receipt(&successful_receipt, |value| {
            value[field] = replacement;
        });
        assert_receipt_error(mutated, successful_expected, category);
    }

    let log_mutations: [(&str, Value, &str); 10] = [
        (
            "removed",
            json!(true),
            "committed-receipt evidence malformed: log.removed",
        ),
        (
            "logIndex",
            Value::Null,
            "committed-receipt evidence malformed: log.log_index",
        ),
        (
            "transactionHash",
            hex_word(93),
            "committed-receipt identity mismatch: log.transaction_hash",
        ),
        (
            "transactionHash",
            Value::Null,
            "committed-receipt evidence malformed: log.transaction_hash",
        ),
        (
            "transactionIndex",
            json!("0x5e"),
            "committed-receipt identity mismatch: log.transaction_index",
        ),
        (
            "transactionIndex",
            Value::Null,
            "committed-receipt evidence malformed: log.transaction_index",
        ),
        (
            "blockHash",
            hex_word(95),
            "committed-receipt identity mismatch: log.block_hash",
        ),
        (
            "blockHash",
            Value::Null,
            "committed-receipt evidence malformed: log.block_hash",
        ),
        (
            "blockNumber",
            json!("0x60"),
            "committed-receipt identity mismatch: log.block_number",
        ),
        (
            "blockNumber",
            Value::Null,
            "committed-receipt evidence malformed: log.block_number",
        ),
    ];
    for (field, replacement, category) in log_mutations {
        let mutated = mutated_receipt(&successful_receipt, |value| {
            value["logs"][0][field] = replacement;
        });
        let error = SimulationEvidence::from_committed_receipt(mutated, successful_expected)
            .expect_err("mutated receipt log must be rejected")
            .to_string();
        assert_eq!(
            error,
            format!("Blockchain error: {category}"),
            "unexpected category for mutated log field {field}"
        );
    }

    // A log without `removed` reads as not removed.
    let without_removed = mutated_receipt(&successful_receipt, |value| {
        value["logs"][0]
            .as_object_mut()
            .expect("log object")
            .remove("removed");
    });
    assert!(
        SimulationEvidence::from_committed_receipt(without_removed, successful_expected).is_ok()
    );

    let successful_evidence =
        SimulationEvidence::from_committed_receipt(successful_receipt, successful_expected)?;
    assert_eq!(
        successful_evidence.source,
        SimulationSource::CommittedReceipt
    );
    let successful_logs = successful_evidence
        .legacy_payment_logs()
        .expect("committed receipt is eligible");
    assert_eq!(reward_event_count(successful_logs, pool), 1);

    Ok(())
}

#[tokio::test]
async fn flat_payment_log_is_discarded_before_trace_evidence() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    let reward_pool = Address::with_last_byte(11);
    let asset = Address::with_last_byte(12);
    let payer = Address::with_last_byte(13);
    let flat_amount = U256::from(41);
    let trace_amount = U256::from(42);
    mount_flat_simulation(&server, rpc_log(reward_pool, asset, payer, flat_amount)).await;
    mount_snapshot_unavailable(&server).await;
    let executor = rpc_executor(&server).await?;

    Mock::given(method("POST"))
        .and(JsonRpcMethod("debug_traceCall"))
        .respond_with(rpc_success(json!({
            "type": "CALL",
            "from": format!("{:#x}", executor.address()),
            "to": format!("{:#x}", Address::with_last_byte(13)),
            "value": "0x0",
            "gas": "0x5208",
            "gasUsed": "0x5208",
            "input": "0x",
            "output": "0x",
            "logs": [rpc_log(reward_pool, asset, payer, trace_amount)],
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("eth_estimateGas"))
        .respond_with(rpc_success(json!("0x5208")))
        .expect(1)
        .mount(&server)
        .await;

    let evidence = executor
        .simulate_legacy_paid_transaction(Address::with_last_byte(13), Bytes::new())
        .await?;

    assert_eq!(evidence.source, SimulationSource::SuccessfulCallTrace);
    let payment_logs = evidence
        .legacy_payment_logs()
        .expect("call trace is eligible");
    assert_eq!(payment_logs.len(), 1);
    assert_eq!(payment_logs[0].address(), reward_pool);
    assert_eq!(payment_logs[0].topics()[1], address_topic(asset));
    assert_eq!(payment_logs[0].topics()[2], address_topic(payer));
    let trace_data = hex::decode(amount_data(trace_amount).trim_start_matches("0x"))?;
    assert_eq!(payment_logs[0].data().data.as_ref(), trace_data);
    let requests = server
        .received_requests()
        .await
        .ok_or_else(|| anyhow::anyhow!("mock server did not retain requests"))?;
    assert_rpc_methods(
        &requests,
        &[
            "eth_simulateV1",
            "evm_snapshot",
            "debug_traceCall",
            "eth_estimateGas",
        ],
    );
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn flat_only_payment_evidence_fails_closed_without_broadcast() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    mount_flat_simulation(
        &server,
        rpc_log(
            Address::with_last_byte(21),
            Address::with_last_byte(22),
            Address::with_last_byte(23),
            U256::from(43),
        ),
    )
    .await;
    mount_snapshot_unavailable(&server).await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("debug_traceCall"))
        .respond_with(rpc_unavailable())
        .expect(1)
        .mount(&server)
        .await;

    let executor = rpc_executor(&server).await?;
    let failure = executor
        .simulate_legacy_paid_transaction(Address::with_last_byte(22), Bytes::new())
        .await;

    assert!(failure.is_err(), "flat-only evidence must fail closed");
    let requests = server
        .received_requests()
        .await
        .ok_or_else(|| anyhow::anyhow!("mock server did not retain requests"))?;
    assert_rpc_methods(
        &requests,
        &["eth_simulateV1", "evm_snapshot", "debug_traceCall"],
    );
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn unsupported_flat_and_snapshot_backends_permit_trace_fallback() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("eth_simulateV1"))
        .respond_with(rpc_unavailable())
        .expect(1)
        .mount(&server)
        .await;
    mount_snapshot_unavailable(&server).await;
    let executor = rpc_executor(&server).await?;
    let target = Address::with_last_byte(31);
    let calldata = Bytes::from(vec![0xaa]);
    Mock::given(method("POST"))
        .and(JsonRpcMethod("debug_traceCall"))
        .respond_with(rpc_success(json!({
            "type": "CALL",
            "from": format!("{:#x}", executor.address()),
            "to": format!("{target:#x}"),
            "value": "0x0",
            "gas": "0x5208",
            "gasUsed": "0x5208",
            "input": "0xaa",
            "output": "0x",
            "logs": [],
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("eth_estimateGas"))
        .respond_with(rpc_success(json!("0x5208")))
        .expect(1)
        .mount(&server)
        .await;

    let evidence = executor
        .simulate_legacy_paid_transaction(target, calldata)
        .await?;
    assert_eq!(evidence.source, SimulationSource::SuccessfulCallTrace);
    let requests = server
        .received_requests()
        .await
        .ok_or_else(|| anyhow::anyhow!("mock server did not retain requests"))?;
    assert_rpc_methods(
        &requests,
        &[
            "eth_simulateV1",
            "evm_snapshot",
            "debug_traceCall",
            "eth_estimateGas",
        ],
    );
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn flat_execution_rejection_is_terminal_and_payload_free() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("eth_simulateV1"))
        .respond_with(rpc_success(json!([{
            "calls": [{
                "status": "0x0",
                "gasUsed": "0x5208",
                "returnData": "0xfeedface",
            }],
        }])))
        .expect(1)
        .mount(&server)
        .await;
    let executor = rpc_executor(&server).await?;

    let failure = executor
        .simulate_legacy_paid_transaction(Address::with_last_byte(32), Bytes::new())
        .await;
    assert_static_error(failure, "eth_simulateV1 execution rejected");
    let requests = server
        .received_requests()
        .await
        .ok_or_else(|| anyhow::anyhow!("mock server did not retain requests"))?;
    assert_rpc_methods(&requests, &["eth_simulateV1"]);
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn diagnostic_simulation_does_not_fallback_after_flat_rejection() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("eth_simulateV1"))
        .respond_with(rpc_success(json!([{
            "calls": [{
                "status": "0x0",
                "gasUsed": "0x5208",
                "returnData": "private-payload",
            }],
        }])))
        .expect(1)
        .mount(&server)
        .await;
    let executor = rpc_executor(&server).await?;

    let failure = executor
        .simulate_transaction_evidence(Address::with_last_byte(39), Bytes::new())
        .await;
    assert_static_error(failure, "eth_simulateV1 execution rejected");
    let requests = server
        .received_requests()
        .await
        .ok_or_else(|| anyhow::anyhow!("mock server did not retain requests"))?;
    assert_rpc_methods(&requests, &["eth_simulateV1"]);
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn malformed_flat_response_is_terminal() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("eth_simulateV1"))
        .respond_with(rpc_success(json!([])))
        .expect(1)
        .mount(&server)
        .await;
    let executor = rpc_executor(&server).await?;

    let failure = executor
        .simulate_legacy_paid_transaction(Address::with_last_byte(33), Bytes::new())
        .await;
    assert_static_error(
        failure,
        "eth_simulateV1 evidence malformed: response.blocks",
    );
    let requests = server
        .received_requests()
        .await
        .ok_or_else(|| anyhow::anyhow!("mock server did not retain requests"))?;
    assert_rpc_methods(&requests, &["eth_simulateV1"]);
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn malformed_flat_log_is_terminal() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("eth_simulateV1"))
        .respond_with(rpc_success(json!([{
            "calls": [{
                "status": "0x1",
                "gasUsed": "0x5208",
                "logs": [{
                    "address": format!("{:#x}", Address::with_last_byte(34)),
                    "topics": [],
                    "private-payload": "provider-sentinel",
                }],
            }],
        }])))
        .expect(1)
        .mount(&server)
        .await;
    let executor = rpc_executor(&server).await?;

    let failure = executor
        .simulate_legacy_paid_transaction(Address::with_last_byte(35), Bytes::new())
        .await;
    assert_static_error(failure, "eth_simulateV1 evidence malformed: log.data");
    let requests = server
        .received_requests()
        .await
        .ok_or_else(|| anyhow::anyhow!("mock server did not retain requests"))?;
    assert_rpc_methods(&requests, &["eth_simulateV1"]);
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn non_method_not_found_rpc_rejection_is_terminal() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("eth_simulateV1"))
        .respond_with(rpc_error(-32_000, "provider-sentinel 0xfeedface"))
        .expect(1)
        .mount(&server)
        .await;
    let executor = rpc_executor(&server).await?;

    let failure = executor
        .simulate_legacy_paid_transaction(Address::with_last_byte(36), Bytes::new())
        .await;
    assert_static_error(failure, "eth_simulateV1 execution rejected");
    let requests = server
        .received_requests()
        .await
        .ok_or_else(|| anyhow::anyhow!("mock server did not retain requests"))?;
    assert_rpc_methods(&requests, &["eth_simulateV1"]);
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn response_decode_failure_is_terminal_and_static() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("eth_simulateV1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw("{\"provider-sentinel\":\"0xfeedface\"", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let executor = rpc_executor(&server).await?;

    let failure = executor
        .simulate_legacy_paid_transaction(Address::with_last_byte(37), Bytes::new())
        .await;
    assert_static_error(failure, "eth_simulateV1 RPC response decode failure");
    let requests = server
        .received_requests()
        .await
        .ok_or_else(|| anyhow::anyhow!("mock server did not retain requests"))?;
    assert_rpc_methods(&requests, &["eth_simulateV1"]);
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn transport_failure_is_terminal_and_static() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("eth_simulateV1"))
        .respond_with_err(|_: &Request| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "provider-sentinel 0xfeedface",
            )
        })
        .expect(1)
        .mount(&server)
        .await;
    let executor = rpc_executor(&server).await?;

    let failure = executor
        .simulate_legacy_paid_transaction(Address::with_last_byte(38), Bytes::new())
        .await;
    assert_static_error(failure, "eth_simulateV1 RPC transport failure");
    let requests = server
        .received_requests()
        .await
        .ok_or_else(|| anyhow::anyhow!("mock server did not retain requests"))?;
    assert_rpc_methods(&requests, &["eth_simulateV1"]);
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn receipt_rejection_after_snapshot_is_terminal() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("eth_simulateV1"))
        .respond_with(rpc_unavailable())
        .expect(1)
        .mount(&server)
        .await;
    mount_snapshot(&server).await;
    let executor = rpc_executor(&server).await?;
    let target = Address::with_last_byte(41);
    let transaction_hash = B256::with_last_byte(42);
    mount_receipt_transaction(
        &server,
        transaction_hash,
        receipt_json(transaction_hash, executor.address(), target, 0),
    )
    .await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("evm_revert"))
        .respond_with(rpc_success(json!(true)))
        .expect(1)
        .mount(&server)
        .await;
    mount_successful_trace(&server, executor.address(), target, "0xaa").await;

    let failure = executor
        .simulate_legacy_paid_transaction(target, Bytes::from(vec![0xaa]))
        .await;
    assert_static_error(failure, "committed-receipt execution rejected");
    let requests = server
        .received_requests()
        .await
        .ok_or_else(|| anyhow::anyhow!("mock server did not retain requests"))?;
    assert_rpc_methods(&requests, &receipt_rpc_methods());
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn diagnostic_receipt_rejection_after_snapshot_is_terminal() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("eth_simulateV1"))
        .respond_with(rpc_unavailable())
        .expect(1)
        .mount(&server)
        .await;
    mount_snapshot(&server).await;
    let executor = rpc_executor(&server).await?;
    let target = Address::with_last_byte(48);
    let transaction_hash = B256::with_last_byte(49);
    mount_receipt_transaction(
        &server,
        transaction_hash,
        receipt_json(transaction_hash, executor.address(), target, 0),
    )
    .await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("evm_revert"))
        .respond_with(rpc_success(json!(true)))
        .expect(1)
        .mount(&server)
        .await;
    mount_successful_trace(&server, executor.address(), target, "0xee").await;

    let failure = executor
        .simulate_transaction_evidence(target, Bytes::from(vec![0xee]))
        .await;
    assert_static_error(failure, "committed-receipt execution rejected");
    let requests = server
        .received_requests()
        .await
        .ok_or_else(|| anyhow::anyhow!("mock server did not retain requests"))?;
    assert_rpc_methods(&requests, &receipt_rpc_methods());
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn restoration_rpc_error_overrides_valid_receipt() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("eth_simulateV1"))
        .respond_with(rpc_unavailable())
        .expect(1)
        .mount(&server)
        .await;
    mount_snapshot(&server).await;
    let executor = rpc_executor(&server).await?;
    let target = Address::with_last_byte(43);
    let transaction_hash = B256::with_last_byte(44);
    mount_receipt_transaction(
        &server,
        transaction_hash,
        receipt_json(transaction_hash, executor.address(), target, 1),
    )
    .await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("evm_revert"))
        .respond_with(rpc_error(-32_000, "provider-sentinel 0xfeedface"))
        .expect(1)
        .mount(&server)
        .await;
    mount_successful_trace(&server, executor.address(), target, "0xbb").await;

    let failure = executor
        .simulate_legacy_paid_transaction(target, Bytes::from(vec![0xbb]))
        .await;
    assert_static_error(failure, "committed-receipt state restoration failed");
    let requests = server
        .received_requests()
        .await
        .ok_or_else(|| anyhow::anyhow!("mock server did not retain requests"))?;
    assert_rpc_methods(&requests, &receipt_rpc_methods());
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn restoration_false_overrides_valid_receipt() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("eth_simulateV1"))
        .respond_with(rpc_unavailable())
        .expect(1)
        .mount(&server)
        .await;
    mount_snapshot(&server).await;
    let executor = rpc_executor(&server).await?;
    let target = Address::with_last_byte(45);
    let transaction_hash = B256::with_last_byte(46);
    mount_receipt_transaction(
        &server,
        transaction_hash,
        receipt_json(transaction_hash, executor.address(), target, 1),
    )
    .await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("evm_revert"))
        .respond_with(rpc_success(json!(false)))
        .expect(1)
        .mount(&server)
        .await;
    mount_successful_trace(&server, executor.address(), target, "0xcc").await;

    let failure = executor
        .simulate_legacy_paid_transaction(target, Bytes::from(vec![0xcc]))
        .await;
    assert_static_error(failure, "committed-receipt state restoration failed");
    let requests = server
        .received_requests()
        .await
        .ok_or_else(|| anyhow::anyhow!("mock server did not retain requests"))?;
    assert_rpc_methods(&requests, &receipt_rpc_methods());
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn unsupported_send_after_snapshot_is_terminal() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("eth_simulateV1"))
        .respond_with(rpc_unavailable())
        .expect(1)
        .mount(&server)
        .await;
    mount_snapshot(&server).await;
    let executor = rpc_executor(&server).await?;
    let target = Address::with_last_byte(47);
    for (rpc_method, response) in [
        ("eth_getTransactionCount", json!("0x0")),
        ("eth_gasPrice", json!("0x1")),
        ("eth_estimateGas", json!("0x5208")),
    ] {
        Mock::given(method("POST"))
            .and(JsonRpcMethod(rpc_method))
            .respond_with(rpc_success(response))
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("POST"))
        .and(JsonRpcMethod("eth_sendRawTransaction"))
        .respond_with(rpc_unavailable())
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(JsonRpcMethod("evm_revert"))
        .respond_with(rpc_success(json!(true)))
        .expect(1)
        .mount(&server)
        .await;
    mount_successful_trace(&server, executor.address(), target, "0xdd").await;

    let failure = executor
        .simulate_legacy_paid_transaction(target, Bytes::from(vec![0xdd]))
        .await;
    assert_static_error(failure, "committed-receipt send execution rejected");
    let requests = server
        .received_requests()
        .await
        .ok_or_else(|| anyhow::anyhow!("mock server did not retain requests"))?;
    assert_rpc_methods(
        &requests,
        &[
            "eth_simulateV1",
            "evm_snapshot",
            "eth_getTransactionCount",
            "eth_gasPrice",
            "eth_estimateGas",
            "eth_sendRawTransaction",
            "evm_revert",
        ],
    );
    server.verify().await;
    Ok(())
}
