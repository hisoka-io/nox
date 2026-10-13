//! Integration tests for client-side features: SURB budgeting, adaptive EMA,
//! cover traffic controller, disconnect cleanup, RPC URL passthrough and the
//! topology PoW field.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unreadable_literal,
    clippy::uninlined_format_args
)]

use nox_client::surb_budget::{AdaptiveSurbBudget, SurbBudget, DEFAULT_RPC_SURBS};
use nox_client::{CoverTrafficController, MixnetClient, MixnetClientConfig};
use nox_core::models::topology::{RelayerNode, TopologySnapshot};
use nox_core::traits::interfaces::EventBusError;
use nox_core::{IEventPublisher, NoxEvent, ServiceRequest};
use nox_crypto::sphinx::packet::MAX_PAYLOAD_SIZE;
use parking_lot::RwLock;
use std::sync::Arc;

struct NoopPublisher;
impl IEventPublisher for NoopPublisher {
    fn publish(&self, _event: NoxEvent) -> Result<usize, EventBusError> {
        Ok(0)
    }
}

#[test]
fn test_fill_remaining_packet_small_request() {
    // 100-byte request leaves plenty of room, but fill is capped at DEFAULT_MEDIUM_SURBS.
    let count = SurbBudget::fill_remaining_packet(100);
    assert!(count > 0 && count <= 10);
}

#[test]
fn test_fill_remaining_packet_large_request() {
    // 30 KB request fills nearly the entire packet; few/no SURBs should fit.
    let count = SurbBudget::fill_remaining_packet(30_000);
    assert!(
        count <= 3,
        "got {count} SURBs for 30KB request, expected <= 3"
    );
}

#[test]
fn test_fill_remaining_packet_oversized_request() {
    // Request larger than MAX_PAYLOAD_SIZE: should return 0.
    let count = SurbBudget::fill_remaining_packet(MAX_PAYLOAD_SIZE + 1000);
    assert_eq!(count, 0);
}

#[test]
fn test_fill_remaining_packet_zero_request() {
    let count = SurbBudget::fill_remaining_packet(0);
    // Capped at DEFAULT_MEDIUM_SURBS even when the whole packet is available.
    assert_eq!(count, 10);
}

#[test]
fn test_fill_remaining_packet_consistency_monotonic() {
    // Larger requests should yield fewer or equal SURBs.
    let mut prev = SurbBudget::fill_remaining_packet(0);
    for size in (0..MAX_PAYLOAD_SIZE).step_by(500) {
        let current = SurbBudget::fill_remaining_packet(size);
        assert!(
            current <= prev || size == 0,
            "non-monotonic at size={size}: prev={prev}, current={current}"
        );
        prev = current;
    }
}

#[test]
fn test_adaptive_returns_default_rpc_when_no_history() {
    let adaptive = AdaptiveSurbBudget::new();
    let budget = adaptive.budget_for("eth_getBalance");
    assert_eq!(budget.surb_count(), DEFAULT_RPC_SURBS);
}

#[test]
fn test_adaptive_returns_learned_budget_after_3_samples() {
    let adaptive = AdaptiveSurbBudget::new();
    // Record 3 samples (EMA_MIN_SAMPLES) of a large response.
    for _ in 0..3 {
        adaptive.record("eth_getLogs", 500_000);
    }
    let budget = adaptive.budget_for("eth_getLogs");
    assert!(
        budget.surb_count() > DEFAULT_RPC_SURBS,
        "budget {} not above default after 3x 500KB samples",
        budget.surb_count()
    );
    assert!(
        budget.response_capacity() >= 500_000,
        "capacity {} too small for 500KB",
        budget.response_capacity()
    );
}

#[test]
fn test_adaptive_records_inflate_ema() {
    let adaptive = AdaptiveSurbBudget::new();
    // First sample: small
    adaptive.record("op", 1_000);
    // Not enough samples yet
    assert!(adaptive.estimate_bytes("op").is_none());

    // Second sample
    adaptive.record("op", 1_000);
    assert!(adaptive.estimate_bytes("op").is_none());

    // Third sample: now EMA kicks in
    adaptive.record("op", 1_000);
    let est = adaptive
        .estimate_bytes("op")
        .expect("should have estimate after 3 samples");
    // EMA with alpha=0.2 after 3 identical samples of 1000 should converge near 1000.
    // With 1.5x headroom: ~1500
    assert!(est >= 1_000, "estimate {est} should be >= 1000");
    assert!(est <= 2_000, "estimate {est} should be <= 2000");
}

#[test]
fn test_adaptive_different_operations_isolated() {
    let adaptive = AdaptiveSurbBudget::new();
    for _ in 0..5 {
        adaptive.record("small_op", 500);
        adaptive.record("large_op", 5_000_000);
    }

    let small = adaptive.budget_for("small_op");
    let large = adaptive.budget_for("large_op");

    assert!(
        large.surb_count() > small.surb_count(),
        "large_op ({}) got fewer SURBs than small_op ({})",
        large.surb_count(),
        small.surb_count()
    );
    assert_eq!(adaptive.tracked_operations(), 2);
}

#[test]
fn test_cover_traffic_controller_construction() {
    let topology = Arc::new(RwLock::new(Vec::new()));
    let publisher: Arc<dyn IEventPublisher> = Arc::new(NoopPublisher);
    let controller = CoverTrafficController::new(topology, publisher, 2.0, 0);
    assert!(!controller.is_running());
}

#[test]
fn test_cover_traffic_is_running_and_stop() {
    let topology = Arc::new(RwLock::new(Vec::new()));
    let publisher: Arc<dyn IEventPublisher> = Arc::new(NoopPublisher);
    let controller = CoverTrafficController::new(topology, publisher, 5.0, 0);

    // Initially not running
    assert!(!controller.is_running());

    // stop() on a not-running controller is safe
    controller.stop();
    assert!(!controller.is_running());
}

#[tokio::test]
async fn test_cover_traffic_lambda_zero_returns_immediately() {
    let topology = Arc::new(RwLock::new(Vec::new()));
    let publisher: Arc<dyn IEventPublisher> = Arc::new(NoopPublisher);
    let controller = CoverTrafficController::new(topology, publisher, 0.0, 0);

    // run() with lambda=0 should return immediately without setting running=true
    controller.run().await;
    assert!(!controller.is_running());
}

#[test]
fn test_disconnect_clears_pending_and_surbs() {
    let topology = Arc::new(RwLock::new(Vec::new()));
    let publisher: Arc<dyn IEventPublisher> = Arc::new(NoopPublisher);
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    let client = MixnetClient::new(topology, publisher, rx, MixnetClientConfig::default());

    // Fresh client has 0 pending
    assert_eq!(client.pending_count(), 0);

    // Disconnect on a fresh client should not panic
    client.disconnect();
    assert_eq!(client.pending_count(), 0);
}

#[test]
fn test_disconnect_idempotent() {
    let topology = Arc::new(RwLock::new(Vec::new()));
    let publisher: Arc<dyn IEventPublisher> = Arc::new(NoopPublisher);
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    let client = MixnetClient::new(topology, publisher, rx, MixnetClientConfig::default());

    // Multiple disconnects should be safe
    client.disconnect();
    client.disconnect();
    client.disconnect();
    assert_eq!(client.pending_count(), 0);
}

#[test]
fn test_rpc_request_service_request_roundtrip_with_url() {
    let request = ServiceRequest::RpcRequest {
        method: "eth_getBalance".to_string(),
        params: serde_json::to_vec(&serde_json::json!(["0xabc", "latest"]))
            .expect("serialize params"),
        id: 42,
        rpc_url: Some("https://custom-rpc.example.com".to_string()),
    };

    let encoded = nox_core::models::payloads::encode_payload(&request).expect("encode");
    let decoded: ServiceRequest =
        nox_core::models::payloads::decode_payload(&encoded).expect("decode");

    match decoded {
        ServiceRequest::RpcRequest {
            method,
            params,
            id,
            rpc_url,
        } => {
            assert_eq!(method, "eth_getBalance");
            assert_eq!(id, 42);
            assert_eq!(
                rpc_url.as_deref(),
                Some("https://custom-rpc.example.com"),
                "rpc_url lost during encode/decode"
            );
            let decoded_params: serde_json::Value =
                serde_json::from_slice(&params).expect("parse params");
            assert_eq!(decoded_params, serde_json::json!(["0xabc", "latest"]));
        }
        other => panic!("Expected RpcRequest, got {:?}", other),
    }
}

#[test]
fn test_rpc_request_roundtrip_without_url() {
    let request = ServiceRequest::RpcRequest {
        method: "eth_blockNumber".to_string(),
        params: serde_json::to_vec(&serde_json::json!([])).expect("serialize"),
        id: 1,
        rpc_url: None,
    };

    let encoded = nox_core::models::payloads::encode_payload(&request).expect("encode");
    let decoded: ServiceRequest =
        nox_core::models::payloads::decode_payload(&encoded).expect("decode");

    match decoded {
        ServiceRequest::RpcRequest { rpc_url, .. } => {
            assert!(rpc_url.is_none(), "rpc_url became Some after roundtrip");
        }
        other => panic!("Expected RpcRequest, got {:?}", other),
    }
}

#[test]
fn test_topology_snapshot_pow_difficulty_roundtrip() {
    let snapshot = TopologySnapshot {
        nodes: vec![RelayerNode::new(
            "0x1234".to_string(),
            "0xdead".to_string(),
            "/ip4/127.0.0.1/tcp/9000".to_string(),
            "1000".to_string(),
            3,
        )],
        fingerprint: "abc123".to_string(),
        timestamp: 1700000000,
        block_number: 100,
        pow_difficulty: 16,
        schema_version: 1,
        liveness: Vec::new(),
    };

    let json = serde_json::to_string(&snapshot).expect("serialize");
    let back: TopologySnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        back.pow_difficulty, 16,
        "pow_difficulty lost during serde roundtrip"
    );
    assert_eq!(back, snapshot);
}

#[test]
fn test_topology_snapshot_pow_difficulty_defaults_to_zero() {
    // Backward compat: older snapshots without pow_difficulty field
    let json = r#"{
        "nodes": [],
        "fingerprint": "abc",
        "timestamp": 1700000000,
        "block_number": 42
    }"#;
    let snapshot: TopologySnapshot = serde_json::from_str(json).expect("deserialize");
    assert_eq!(
        snapshot.pow_difficulty, 0,
        "missing pow_difficulty did not default to 0"
    );
}

#[test]
fn test_topology_snapshot_pow_difficulty_explicit_zero() {
    let json = r#"{
        "nodes": [],
        "fingerprint": "abc",
        "timestamp": 1700000000,
        "block_number": 42,
        "pow_difficulty": 0
    }"#;
    let snapshot: TopologySnapshot = serde_json::from_str(json).expect("deserialize");
    assert_eq!(snapshot.pow_difficulty, 0);
}

#[test]
fn test_topology_snapshot_pow_difficulty_high_value() {
    let snapshot = TopologySnapshot {
        nodes: vec![],
        fingerprint: "test".to_string(),
        timestamp: 0,
        block_number: 0,
        pow_difficulty: u32::MAX,
        schema_version: 1,
        liveness: Vec::new(),
    };
    let json = serde_json::to_string(&snapshot).expect("serialize");
    let back: TopologySnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.pow_difficulty, u32::MAX);
}

#[test]
fn test_surb_budget_fill_and_budget_for_same_request_agree() {
    // For a small request, fill_remaining_packet should give a count close to
    // what a SurbBudget with that response size would give.
    let inner = 200;
    let fill_count = SurbBudget::fill_remaining_packet(inner);
    assert!(fill_count > 0, "no SURBs fit for 200-byte request");

    // The fill count represents SURBs that fit in a single packet alongside the request.
    // This is a "free" bonus: no extra forward packets needed.
    let budget = SurbBudget::rpc();
    let fragments = budget.forward_fragments_needed(inner);
    assert_eq!(fragments, 1, "expected 1 forward fragment for 200-byte RPC");
}
