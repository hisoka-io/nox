/// Verify Anvil's `debug_traceCall` behavior with `callTracer` + `withLog: true`.
use ethers::prelude::*;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{
    BlockId, BlockNumber, CallConfig, GethDebugBuiltInTracerConfig, GethDebugBuiltInTracerType,
    GethDebugTracerConfig, GethDebugTracerType, GethDebugTracingCallOptions,
    GethDebugTracingOptions, GethTrace, GethTraceFrame,
};
use ethers::utils::Anvil;
use std::sync::Arc;

/// Build initcode for a minimal contract that emits `Ping(uint256)` on any call.
fn build_event_test_initcode() -> Vec<u8> {
    let topic0 = ethers::utils::keccak256(b"Ping(uint256)");

    let mut runtime = Vec::new();
    runtime.push(0x60);
    runtime.push(0x2a); // PUSH1 42 (topic1)
    runtime.push(0x7f); // PUSH32 (topic0)
    runtime.extend_from_slice(&topic0);
    runtime.push(0x60);
    runtime.push(0x00); // PUSH1 0 (data size)
    runtime.push(0x60);
    runtime.push(0x00); // PUSH1 0 (data offset)
    runtime.push(0xa2); // LOG2
    runtime.push(0x00); // STOP

    let runtime_len = runtime.len() as u8;
    let prefix_len: u8 = 11;

    let mut initcode = Vec::new();
    initcode.push(0x60);
    initcode.push(runtime_len);
    initcode.push(0x80);
    initcode.push(0x60);
    initcode.push(prefix_len);
    initcode.push(0x60);
    initcode.push(0x00);
    initcode.push(0x39); // CODECOPY
    initcode.push(0x60);
    initcode.push(0x00);
    initcode.push(0xf3); // RETURN
    initcode.extend_from_slice(&runtime);
    initcode
}

#[tokio::test]
#[ignore = "Requires Foundry anvil binary"]
async fn test_anvil_debug_trace_call_with_logs() {
    let anvil = Anvil::new().args(["--steps-tracing"]).spawn();
    let provider = Provider::<Http>::try_from(anvil.endpoint()).unwrap();
    let wallet: LocalWallet = anvil.keys()[0].clone().into();
    let wallet = wallet.with_chain_id(anvil.chain_id());
    let client = Arc::new(SignerMiddleware::new(provider.clone(), wallet));

    let initcode = build_event_test_initcode();
    let deploy_tx = TransactionRequest::new()
        .data(Bytes::from(initcode))
        .gas(500_000u64);
    let pending: PendingTransaction<'_, Http> =
        client.send_transaction(deploy_tx, None).await.unwrap();
    let receipt = pending.await.unwrap().unwrap();
    let contract_addr = receipt
        .contract_address
        .expect("deploy should produce contract address");
    println!("EventTest deployed at: {contract_addr:?}");

    let call_tx = TransactionRequest::new().to(contract_addr).gas(100_000u64);
    let real_pending: PendingTransaction<'_, Http> =
        client.send_transaction(call_tx, None).await.unwrap();
    let real_receipt = real_pending.await.unwrap().unwrap();
    println!("Real tx receipt: {} logs", real_receipt.logs.len());
    for log in &real_receipt.logs {
        println!(
            "  addr={:?} topics={} data={} bytes",
            log.address,
            log.topics.len(),
            log.data.len()
        );
    }
    assert!(
        !real_receipt.logs.is_empty(),
        "Real tx must emit Ping event"
    );

    println!("\n=== TEST 1: callTracer + withLog:true ===");

    let trace_tx = TransactionRequest::new()
        .from(anvil.addresses()[0])
        .to(contract_addr);

    let options = GethDebugTracingCallOptions {
        tracing_options: GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::CallTracer,
            )),
            tracer_config: Some(GethDebugTracerConfig::BuiltInTracer(
                GethDebugBuiltInTracerConfig::CallTracer(CallConfig {
                    only_top_call: None,
                    with_log: Some(true),
                }),
            )),
            ..Default::default()
        },
        state_overrides: None,
        block_overrides: None,
    };

    let trace = provider
        .debug_trace_call(
            TypedTransaction::Legacy(trace_tx),
            Some(BlockId::Number(BlockNumber::Latest)),
            options,
        )
        .await
        .expect("debug_traceCall should not error");

    match &trace {
        GethTrace::Known(GethTraceFrame::CallTracer(frame)) => {
            println!("  type={}, error={:?}", frame.typ, frame.error);
            println!("  logs={:?}", frame.logs.as_ref().map(Vec::len));
            println!("  calls={:?}", frame.calls.as_ref().map(Vec::len));
            if let Some(logs) = &frame.logs {
                for (i, l) in logs.iter().enumerate() {
                    println!("  log[{i}]: addr={:?} topics={:?}", l.address, l.topics);
                }
                println!("  VERDICT: callTracer returns logs -- withLog WORKS!");
            } else {
                println!("  VERDICT: callTracer returns NO logs -- withLog NOT supported");
            }
        }
        GethTrace::Known(other) => {
            println!(
                "  non-CallTracer variant: {:?}",
                std::mem::discriminant(other)
            );
        }
        GethTrace::Unknown(json) => {
            let s = serde_json::to_string_pretty(json).unwrap_or_default();
            println!("  Unknown JSON:\n{}", &s[..s.len().min(500)]);
        }
    }

    println!("\n=== TEST 2: default tracer (structLogs) ===");

    let trace_tx2 = TransactionRequest::new()
        .from(anvil.addresses()[0])
        .to(contract_addr);

    let default_trace = provider
        .debug_trace_call(
            TypedTransaction::Legacy(trace_tx2),
            Some(BlockId::Number(BlockNumber::Latest)),
            GethDebugTracingCallOptions {
                tracing_options: GethDebugTracingOptions::default(),
                state_overrides: None,
                block_overrides: None,
            },
        )
        .await
        .expect("default trace should not error");

    match &default_trace {
        GethTrace::Known(GethTraceFrame::Default(frame)) => {
            let log_ops: Vec<_> = frame
                .struct_logs
                .iter()
                .filter(|s| s.op.starts_with("LOG"))
                .collect();
            println!("  total opcodes: {}", frame.struct_logs.len());
            println!("  LOG opcodes: {}", log_ops.len());
            for op in &log_ops {
                println!("    {} depth={}", op.op, op.depth);
            }
            if log_ops.is_empty() {
                println!("  VERDICT: default tracer has NO LOG opcodes");
            } else {
                println!("  VERDICT: default tracer captures LOG opcodes -- events extractable!");
            }
        }
        _ => println!("  unexpected variant"),
    }
}
