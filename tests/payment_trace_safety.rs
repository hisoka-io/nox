#![cfg(feature = "dev-node")]

use ethers::abi::{Abi, Detokenize, Tokenize};
use ethers::prelude::*;
use ethers::utils::Anvil;
use ethers_solc::Solc;
use nox_node::blockchain::executor::{
    ChainExecutor, ExpectedTransactionIdentity, SimulationEvidence, SimulationSource,
};
use nox_node::NoxConfig;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use wiremock::matchers::method;
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

const EXPECTED_SOLC: (u64, u64, u64) = (0, 8, 30);
const CHAIN_ID: u64 = 31_337;

type TestClient = SignerMiddleware<Provider<Http>, LocalWallet>;

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

fn load_artifact(name: &str) -> anyhow::Result<(Abi, Bytes)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("abi")
        .join(format!("{name}.json"));
    let artifact: Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let abi = serde_json::from_value(
        artifact
            .get("abi")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("artifact {} has no ABI", path.display()))?,
    )?;
    let bytecode = artifact
        .get("bytecode")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("artifact {} has no bytecode", path.display()))?;
    let bytecode = hex::decode(bytecode.trim_start_matches("0x"))?;
    Ok((abi, Bytes::from(bytecode)))
}

fn compile_fixture() -> anyhow::Result<((Abi, Bytes), (Abi, Bytes))> {
    let solc = Solc::new("solc");
    let version = solc.version()?;
    anyhow::ensure!(
        (version.major, version.minor, version.patch) == EXPECTED_SOLC,
        "PaymentTraceHarness requires solc 0.8.30, observed {version}"
    );

    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("PaymentTraceHarness.sol");
    let output = solc.compile_source(&fixture)?;
    anyhow::ensure!(
        !output.has_error(),
        "PaymentTraceHarness compilation failed: {:?}",
        output.errors
    );

    let child = output
        .find("RevertingPaymentChild")
        .ok_or_else(|| anyhow::anyhow!("compiled fixture has no RevertingPaymentChild"))?
        .into_parts();
    let parent = output
        .find("CatchingPaymentParent")
        .ok_or_else(|| anyhow::anyhow!("compiled fixture has no CatchingPaymentParent"))?
        .into_parts();

    Ok((
        (
            child
                .0
                .ok_or_else(|| anyhow::anyhow!("RevertingPaymentChild has no ABI"))?,
            child
                .1
                .ok_or_else(|| anyhow::anyhow!("RevertingPaymentChild has no bytecode"))?,
        ),
        (
            parent
                .0
                .ok_or_else(|| anyhow::anyhow!("CatchingPaymentParent has no ABI"))?,
            parent
                .1
                .ok_or_else(|| anyhow::anyhow!("CatchingPaymentParent has no bytecode"))?,
        ),
    ))
}

async fn deploy_contract<T: Tokenize>(
    client: Arc<TestClient>,
    abi: Abi,
    bytecode: Bytes,
    constructor: T,
) -> anyhow::Result<Contract<TestClient>> {
    Ok(ContractFactory::new(abi, bytecode, client)
        .deploy(constructor)?
        .send()
        .await?)
}

async fn send_call<D: Detokenize>(
    call: ContractCall<TestClient, D>,
) -> anyhow::Result<TransactionReceipt> {
    let pending = call.send().await?;
    pending
        .await?
        .ok_or_else(|| anyhow::anyhow!("transaction produced no receipt"))
}

async fn send_identified_call<D: Detokenize>(
    call: ContractCall<TestClient, D>,
) -> anyhow::Result<(H256, TransactionReceipt)> {
    let pending = call.send().await?;
    let transaction_hash = pending.tx_hash();
    let receipt = pending
        .await?
        .ok_or_else(|| anyhow::anyhow!("transaction produced no receipt"))?;
    Ok((transaction_hash, receipt))
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

fn set_log_removed(log: &mut Log) {
    log.removed = Some(true);
}

fn clear_log_removed(log: &mut Log) {
    log.removed = None;
}

fn clear_log_index(log: &mut Log) {
    log.log_index = None;
}

fn replace_log_transaction_hash(log: &mut Log) {
    log.transaction_hash = Some(H256::from_low_u64_be(93));
}

fn clear_log_transaction_hash(log: &mut Log) {
    log.transaction_hash = None;
}

fn replace_log_transaction_index(log: &mut Log) {
    log.transaction_index = Some(U64::from(94));
}

fn clear_log_transaction_index(log: &mut Log) {
    log.transaction_index = None;
}

fn replace_log_block_hash(log: &mut Log) {
    log.block_hash = Some(H256::from_low_u64_be(95));
}

fn clear_log_block_hash(log: &mut Log) {
    log.block_hash = None;
}

fn replace_log_block_number(log: &mut Log) {
    log.block_number = Some(U64::from(96));
}

fn clear_log_block_number(log: &mut Log) {
    log.block_number = None;
}

async fn token_balance(token: &Contract<TestClient>, account: Address) -> anyhow::Result<U256> {
    Ok(token
        .method::<_, U256>("balanceOf", account)?
        .call()
        .await?)
}

async fn total_collected(pool: &Contract<TestClient>, asset: Address) -> anyhow::Result<U256> {
    Ok(pool
        .method::<_, U256>("totalCollected", asset)?
        .call()
        .await?)
}

fn reward_event_count(logs: &[Log], pool: Address) -> usize {
    let topic = H256::from(ethers::utils::keccak256(
        "RewardsDeposited(address,address,uint256)",
    ));
    logs.iter()
        .filter(|log| log.address == pool && log.topics.first() == Some(&topic))
        .count()
}

fn address_topic(address: Address) -> H256 {
    let mut topic = [0_u8; 32];
    topic[12..].copy_from_slice(address.as_bytes());
    H256::from(topic)
}

fn amount_data(amount: U256) -> String {
    let mut encoded = [0_u8; 32];
    amount.to_big_endian(&mut encoded);
    format!("0x{}", hex::encode(encoded))
}

fn rpc_log(reward_pool: Address, asset: Address, payer: Address, amount: U256) -> Value {
    json!({
        "address": format!("{reward_pool:#x}"),
        "topics": [
            format!("{:#x}", H256::from(ethers::utils::keccak256(
                "RewardsDeposited(address,address,uint256)",
            ))),
            format!("{:#x}", address_topic(asset)),
            format!("{:#x}", address_topic(payer)),
        ],
        "data": amount_data(amount),
    })
}

async fn rpc_executor_at(rpc_url: String) -> anyhow::Result<ChainExecutor> {
    let wallet = LocalWallet::new(&mut rand::rngs::OsRng);
    let mut config = NoxConfig::default();
    config.eth_rpc_url = rpc_url;
    config.eth_wallet_private_key = hex::encode(wallet.signer().to_bytes());
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

fn receipt_json(transaction_hash: H256, from: Address, to: Address, status: U64) -> Value {
    json!({
        "transactionHash": format!("{transaction_hash:#x}"),
        "transactionIndex": "0x0",
        "blockHash": format!("{:#x}", H256::from_low_u64_be(61)),
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

async fn mount_receipt_transaction(server: &MockServer, transaction_hash: H256, receipt: Value) {
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
    let ((child_abi, child_bytecode), (parent_abi, parent_bytecode)) = compile_fixture()?;
    let (token_abi, token_bytecode) = load_artifact("MockERC20")?;
    let (pool_abi, pool_bytecode) = load_artifact("NoxRewardPool")?;

    let anvil = Anvil::new().spawn();
    let provider = Provider::<Http>::try_from(anvil.endpoint())?;
    let deployer = LocalWallet::from(anvil.keys()[0].clone()).with_chain_id(anvil.chain_id());
    let client = Arc::new(SignerMiddleware::new(provider, deployer.clone()));

    let token = deploy_contract(
        client.clone(),
        token_abi,
        token_bytecode,
        ("Fee Token".to_owned(), "FEE".to_owned(), 18_u8),
    )
    .await?;
    let pool = deploy_contract(client.clone(), pool_abi, pool_bytecode, deployer.address()).await?;
    let child = deploy_contract(client.clone(), child_abi, child_bytecode, ()).await?;
    let parent = deploy_contract(client.clone(), parent_abi, parent_bytecode, ()).await?;

    send_call(pool.method::<_, ()>("setAssetStatus", (token.address(), true))?).await?;

    let payment = U256::exp10(18);
    send_call(token.method::<_, ()>("mint", (child.address(), payment))?).await?;

    let caught_calldata = child.encode(
        "depositThenRevert",
        (pool.address(), token.address(), payment),
    )?;
    let (caught_transaction_hash, caught_receipt) = send_identified_call(
        parent.method::<_, bool>("catchPayment", (child.address(), caught_calldata))?,
    )
    .await?;

    assert_eq!(caught_receipt.status, Some(U64::one()));
    assert_eq!(reward_event_count(&caught_receipt.logs, pool.address()), 0);
    assert_eq!(token_balance(&token, pool.address()).await?, U256::zero());
    assert_eq!(total_collected(&pool, token.address()).await?, U256::zero());
    assert_eq!(token_balance(&token, child.address()).await?, payment);

    let caught_expected = ExpectedTransactionIdentity {
        transaction_hash: caught_transaction_hash,
        from: deployer.address(),
        to: parent.address(),
    };
    let caught_evidence =
        SimulationEvidence::from_committed_receipt(caught_receipt, caught_expected)?;
    assert_eq!(caught_evidence.source, SimulationSource::CommittedReceipt);
    assert!(caught_evidence
        .legacy_payment_logs()
        .expect("committed receipt is eligible")
        .is_empty());

    let successful_calldata = child.encode(
        "depositSuccessfully",
        (pool.address(), token.address(), payment),
    )?;
    let (successful_transaction_hash, successful_receipt) = send_identified_call(
        parent.method::<_, bool>("forwardPayment", (child.address(), successful_calldata))?,
    )
    .await?;

    assert_eq!(successful_receipt.status, Some(U64::one()));
    assert_eq!(
        reward_event_count(&successful_receipt.logs, pool.address()),
        1
    );
    assert_eq!(token_balance(&token, pool.address()).await?, payment);
    assert_eq!(total_collected(&pool, token.address()).await?, payment);
    assert_eq!(token_balance(&token, child.address()).await?, U256::zero());

    let successful_expected = ExpectedTransactionIdentity {
        transaction_hash: successful_transaction_hash,
        from: deployer.address(),
        to: parent.address(),
    };

    let mut mutated = successful_receipt.clone();
    mutated.status = None;
    assert_receipt_error(
        mutated,
        successful_expected,
        "committed-receipt execution rejected",
    );
    let mut mutated = successful_receipt.clone();
    mutated.status = Some(U64::zero());
    assert_receipt_error(
        mutated,
        successful_expected,
        "committed-receipt execution rejected",
    );
    let mut mutated = successful_receipt.clone();
    mutated.transaction_hash = H256::from_low_u64_be(91);
    assert_receipt_error(
        mutated,
        successful_expected,
        "committed-receipt identity mismatch: transaction_hash",
    );
    let mut mutated = successful_receipt.clone();
    mutated.from = Address::from_low_u64_be(92);
    assert_receipt_error(
        mutated,
        successful_expected,
        "committed-receipt identity mismatch: from",
    );
    let mut mutated = successful_receipt.clone();
    mutated.to = None;
    assert_receipt_error(
        mutated,
        successful_expected,
        "committed-receipt identity mismatch: to",
    );
    let mut mutated = successful_receipt.clone();
    mutated.to = Some(Address::from_low_u64_be(97));
    assert_receipt_error(
        mutated,
        successful_expected,
        "committed-receipt identity mismatch: to",
    );
    let mut mutated = successful_receipt.clone();
    mutated.block_hash = None;
    assert_receipt_error(
        mutated,
        successful_expected,
        "committed-receipt evidence malformed: block_hash",
    );
    let mut mutated = successful_receipt.clone();
    mutated.block_number = None;
    assert_receipt_error(
        mutated,
        successful_expected,
        "committed-receipt evidence malformed: block_number",
    );
    let mut mutated = successful_receipt.clone();
    mutated.gas_used = None;
    assert_receipt_error(
        mutated,
        successful_expected,
        "committed-receipt evidence malformed: gas_used",
    );

    let log_mutations: [(&str, fn(&mut Log), &str); 11] = [
        (
            "removed",
            set_log_removed,
            "committed-receipt evidence malformed: log.removed",
        ),
        (
            "missing removed",
            clear_log_removed,
            "committed-receipt evidence malformed: log.removed",
        ),
        (
            "log_index",
            clear_log_index,
            "committed-receipt evidence malformed: log.log_index",
        ),
        (
            "transaction_hash",
            replace_log_transaction_hash,
            "committed-receipt identity mismatch: log.transaction_hash",
        ),
        (
            "missing transaction_hash",
            clear_log_transaction_hash,
            "committed-receipt evidence malformed: log.transaction_hash",
        ),
        (
            "transaction_index",
            replace_log_transaction_index,
            "committed-receipt identity mismatch: log.transaction_index",
        ),
        (
            "missing transaction_index",
            clear_log_transaction_index,
            "committed-receipt evidence malformed: log.transaction_index",
        ),
        (
            "block_hash",
            replace_log_block_hash,
            "committed-receipt identity mismatch: log.block_hash",
        ),
        (
            "missing block_hash",
            clear_log_block_hash,
            "committed-receipt evidence malformed: log.block_hash",
        ),
        (
            "block_number",
            replace_log_block_number,
            "committed-receipt identity mismatch: log.block_number",
        ),
        (
            "missing block_number",
            clear_log_block_number,
            "committed-receipt evidence malformed: log.block_number",
        ),
    ];
    for (field, mutate_log, category) in log_mutations {
        let mut mutated = successful_receipt.clone();
        mutate_log(
            mutated
                .logs
                .first_mut()
                .expect("successful receipt contains logs"),
        );
        let error = SimulationEvidence::from_committed_receipt(mutated, successful_expected)
            .expect_err("mutated receipt log must be rejected")
            .to_string();
        assert_eq!(
            error,
            format!("Blockchain error: {category}"),
            "unexpected category for mutated log field {field}"
        );
    }

    let successful_evidence =
        SimulationEvidence::from_committed_receipt(successful_receipt, successful_expected)?;
    assert_eq!(
        successful_evidence.source,
        SimulationSource::CommittedReceipt
    );
    let successful_logs = successful_evidence
        .legacy_payment_logs()
        .expect("committed receipt is eligible");
    assert_eq!(reward_event_count(successful_logs, pool.address()), 1);

    Ok(())
}

#[tokio::test]
async fn flat_payment_log_is_discarded_before_trace_evidence() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    let reward_pool = Address::from_low_u64_be(11);
    let asset = Address::from_low_u64_be(12);
    let payer = Address::from_low_u64_be(13);
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
            "to": format!("{:#x}", Address::from_low_u64_be(13)),
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
        .simulate_legacy_paid_transaction(Address::from_low_u64_be(13), Bytes::new())
        .await?;

    assert_eq!(evidence.source, SimulationSource::SuccessfulCallTrace);
    let payment_logs = evidence
        .legacy_payment_logs()
        .expect("call trace is eligible");
    assert_eq!(payment_logs.len(), 1);
    assert_eq!(payment_logs[0].address, reward_pool);
    assert_eq!(payment_logs[0].topics[1], address_topic(asset));
    assert_eq!(payment_logs[0].topics[2], address_topic(payer));
    let trace_data = hex::decode(amount_data(trace_amount).trim_start_matches("0x"))?;
    assert_eq!(payment_logs[0].data.as_ref(), trace_data);
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
            Address::from_low_u64_be(21),
            Address::from_low_u64_be(22),
            Address::from_low_u64_be(23),
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
        .simulate_legacy_paid_transaction(Address::from_low_u64_be(22), Bytes::new())
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
    let target = Address::from_low_u64_be(31);
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
        .simulate_legacy_paid_transaction(Address::from_low_u64_be(32), Bytes::new())
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
        .simulate_transaction_evidence(Address::from_low_u64_be(39), Bytes::new())
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
        .simulate_legacy_paid_transaction(Address::from_low_u64_be(33), Bytes::new())
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
                    "address": format!("{:#x}", Address::from_low_u64_be(34)),
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
        .simulate_legacy_paid_transaction(Address::from_low_u64_be(35), Bytes::new())
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
        .simulate_legacy_paid_transaction(Address::from_low_u64_be(36), Bytes::new())
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
        .simulate_legacy_paid_transaction(Address::from_low_u64_be(37), Bytes::new())
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
        .simulate_legacy_paid_transaction(Address::from_low_u64_be(38), Bytes::new())
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
    let target = Address::from_low_u64_be(41);
    let transaction_hash = H256::from_low_u64_be(42);
    mount_receipt_transaction(
        &server,
        transaction_hash,
        receipt_json(transaction_hash, executor.address(), target, U64::zero()),
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
    let target = Address::from_low_u64_be(48);
    let transaction_hash = H256::from_low_u64_be(49);
    mount_receipt_transaction(
        &server,
        transaction_hash,
        receipt_json(transaction_hash, executor.address(), target, U64::zero()),
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
    let target = Address::from_low_u64_be(43);
    let transaction_hash = H256::from_low_u64_be(44);
    mount_receipt_transaction(
        &server,
        transaction_hash,
        receipt_json(transaction_hash, executor.address(), target, U64::one()),
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
    let target = Address::from_low_u64_be(45);
    let transaction_hash = H256::from_low_u64_be(46);
    mount_receipt_transaction(
        &server,
        transaction_hash,
        receipt_json(transaction_hash, executor.address(), target, U64::one()),
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
    let target = Address::from_low_u64_be(47);
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
