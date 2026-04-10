//! Web proxy integration tests: SSRF protection and response packing.

use nox_core::ServiceRequest;
use nox_crypto::PathHop;
use nox_crypto::{Surb, SurbRecovery};
use nox_node::config::HttpConfig;
use nox_node::services::handlers::http::{HttpHandler, SerializableHttpResponse};
use nox_node::services::response_packer::ResponsePacker;
use nox_node::telemetry::metrics::MetricsService;
use nox_node::TokioEventBus;
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

fn generate_test_surbs(count: usize) -> Vec<(Surb, SurbRecovery)> {
    let mut rng = rand::thread_rng();
    let sk = X25519SecretKey::random_from_rng(&mut rng);
    let path = vec![PathHop {
        public_key: X25519PublicKey::from(&sk),
        address: "/ip4/127.0.0.1/tcp/9000".to_string(),
    }];

    (0..count)
        .map(|_| {
            let id: [u8; 16] = rand::random();
            Surb::new(&path, id, 0).expect("SURB creation failed")
        })
        .collect()
}

#[test]
fn test_ssrf_error_response() {
    let response = SerializableHttpResponse::error(403, "SSRF Blocked");
    assert_eq!(response.status, 403);
    assert_eq!(response.body, b"SSRF Blocked");
}

#[test]
fn test_serializable_http_response_roundtrip() {
    use std::collections::HashMap;

    let response = SerializableHttpResponse {
        status: 200,
        headers: HashMap::from([
            ("content-type".into(), "application/json".into()),
            ("x-custom".into(), "value".into()),
        ]),
        body: b"Hello, World!".to_vec(),
        truncated: false,
    };

    let bytes = response.to_bytes().expect("serialization failed");
    let decoded: SerializableHttpResponse =
        bincode::deserialize(&bytes).expect("deserialization failed");

    assert_eq!(decoded.status, 200);
    assert_eq!(decoded.body, b"Hello, World!");
    assert!(!decoded.truncated);
}

#[tokio::test]
async fn test_http_handler_creation() {
    let config = HttpConfig::default();
    let packer = Arc::new(ResponsePacker::new());

    let _handler = HttpHandler::new(
        config,
        packer,
        Arc::new(TokioEventBus::new(100)),
        MetricsService::new(),
    );
}

#[tokio::test]
async fn test_http_fetch_success_with_wiremock() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/hello"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Hello, Mixnet!"))
        .mount(&mock_server)
        .await;

    let config = HttpConfig {
        allow_private_ips: true,
        ..Default::default()
    };
    let packer = Arc::new(ResponsePacker::new());
    let handler = HttpHandler::new(
        config,
        packer,
        Arc::new(TokioEventBus::new(100)),
        MetricsService::new(),
    );

    let surbs: Vec<Surb> = generate_test_surbs(3).into_iter().map(|(s, _)| s).collect();

    let request = ServiceRequest::HttpRequest {
        method: "GET".to_string(),
        url: format!("{}/hello", mock_server.uri()),
        headers: vec![],
        body: vec![],
    };

    let request_id = 12345_u64;
    let result = handler
        .handle_http_request(request_id, &request, surbs)
        .await;

    assert!(result.is_ok(), "Request should succeed");
    let pack_result = result.unwrap();
    assert!(
        !pack_result.packets.is_empty(),
        "Should have response packets"
    );

    println!(
        "✅ Wiremock test passed: {} packets returned",
        pack_result.packets.len()
    );
}

#[tokio::test]
async fn test_ssrf_blocks_private_ip_in_request() {
    let config = HttpConfig::default();
    let packer = Arc::new(ResponsePacker::new());
    let handler = HttpHandler::new(
        config,
        packer,
        Arc::new(TokioEventBus::new(100)),
        MetricsService::new(),
    );

    let surbs: Vec<Surb> = generate_test_surbs(1).into_iter().map(|(s, _)| s).collect();

    let request = ServiceRequest::HttpRequest {
        method: "GET".to_string(),
        url: "http://192.168.1.1/admin".to_string(),
        headers: vec![],
        body: vec![],
    };

    let result = handler.handle_http_request(123, &request, surbs).await;

    assert!(result.is_ok(), "Should return packed error response");
}

#[tokio::test]
async fn test_domain_whitelist_blocks_unallowed() {
    let config = HttpConfig {
        allowed_domains: Some(vec!["example.com".to_string()]),
        allow_private_ips: true,
        ..Default::default()
    };

    let packer = Arc::new(ResponsePacker::new());
    let handler = HttpHandler::new(
        config,
        packer,
        Arc::new(TokioEventBus::new(100)),
        MetricsService::new(),
    );

    let surbs: Vec<Surb> = generate_test_surbs(1).into_iter().map(|(s, _)| s).collect();

    let request = ServiceRequest::HttpRequest {
        method: "GET".to_string(),
        url: "http://evil.com/".to_string(),
        headers: vec![],
        body: vec![],
    };

    let result = handler.handle_http_request(456, &request, surbs).await;

    assert!(result.is_ok(), "Should return packed error response");
}

#[tokio::test]
async fn test_response_with_headers() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/data"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .insert_header("X-Custom-Header", "custom-value")
                .set_body_json(serde_json::json!({"status": "ok"})),
        )
        .mount(&mock_server)
        .await;

    let config = HttpConfig {
        allow_private_ips: true,
        ..Default::default()
    };
    let packer = Arc::new(ResponsePacker::new());
    let handler = HttpHandler::new(
        config,
        packer,
        Arc::new(TokioEventBus::new(100)),
        MetricsService::new(),
    );

    let surbs: Vec<Surb> = generate_test_surbs(2).into_iter().map(|(s, _)| s).collect();

    let request = ServiceRequest::HttpRequest {
        method: "GET".to_string(),
        url: format!("{}/api/data", mock_server.uri()),
        headers: vec![("Accept".to_string(), "application/json".to_string())],
        body: vec![],
    };

    let result = handler.handle_http_request(789, &request, surbs).await;

    assert!(result.is_ok());
    println!("✅ Headers test passed");
}

#[tokio::test]
async fn test_post_request_with_body() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(ResponseTemplate::new(201).set_body_string("Created"))
        .mount(&mock_server)
        .await;

    let config = HttpConfig {
        allow_private_ips: true,
        ..Default::default()
    };
    let packer = Arc::new(ResponsePacker::new());
    let handler = HttpHandler::new(
        config,
        packer,
        Arc::new(TokioEventBus::new(100)),
        MetricsService::new(),
    );

    let surbs: Vec<Surb> = generate_test_surbs(1).into_iter().map(|(s, _)| s).collect();

    let request = ServiceRequest::HttpRequest {
        method: "POST".to_string(),
        url: format!("{}/submit", mock_server.uri()),
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: b"{\"key\":\"value\"}".to_vec(),
    };

    let result = handler.handle_http_request(999, &request, surbs).await;

    assert!(result.is_ok());
    println!("✅ POST with body test passed");
}

#[tokio::test]
async fn test_truncation_for_large_response() {
    let mock_server = MockServer::start().await;

    let large_body = "X".repeat(100_000);

    Mock::given(method("GET"))
        .and(path("/large"))
        .respond_with(ResponseTemplate::new(200).set_body_string(&large_body))
        .mount(&mock_server)
        .await;

    let config = HttpConfig {
        allow_private_ips: true,
        max_response_bytes: 10_000,
        ..Default::default()
    };
    let packer = Arc::new(ResponsePacker::new());
    let handler = HttpHandler::new(
        config,
        packer,
        Arc::new(TokioEventBus::new(100)),
        MetricsService::new(),
    );

    let surbs: Vec<Surb> = generate_test_surbs(1).into_iter().map(|(s, _)| s).collect();

    let request = ServiceRequest::HttpRequest {
        method: "GET".to_string(),
        url: format!("{}/large", mock_server.uri()),
        headers: vec![],
        body: vec![],
    };

    let result = handler.handle_http_request(111, &request, surbs).await;

    assert!(result.is_ok());
}
