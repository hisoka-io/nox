//! HTTP ingress server for Sphinx packet injection and response delivery.
//!
//! ## Endpoints
//! - `POST /api/v1/packets` - Inject a raw Sphinx packet (body = raw bytes)
//! - `POST /api/v1/responses/claim` - Claim responses by SURB ID (session-safe)
//! - `GET /api/v1/responses/stream` - SSE stream for SURB responses (push-based)
//! - `GET /api/v1/responses/pending` - Fetch all pending responses (deprecated)
//! - `GET /api/v1/responses/:request_id` - Long-poll for a SURB response (30s timeout)
//! - `GET /health` - Returns 200 OK

use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::stream::Stream;
use nox_core::events::NoxEvent;
use nox_core::traits::interfaces::IEventPublisher;
use nox_crypto::sphinx::packet::PACKET_SIZE;
use nox_crypto::sphinx::SphinxHeader;
use serde::Deserialize;
use tower_http::cors::CorsLayer;
use tracing::{debug, warn};

use super::response_buffer::ResponseBuffer;
use crate::telemetry::metrics::MetricsService;

/// Shared state for the ingress HTTP server.
pub struct IngressState {
    /// Event publisher to inject packets into the node's internal event bus.
    pub event_publisher: Arc<dyn IEventPublisher>,
    /// Buffer for SURB responses awaiting client retrieval.
    pub response_buffer: Arc<ResponseBuffer>,
    /// Metrics service for observability.
    pub metrics: MetricsService,
    /// Maximum time to long-poll for a single response before returning 204.
    /// Production default: 30s. Tests should set this to 1-2s.
    pub long_poll_timeout: Duration,
    /// `PoW` difficulty required for externally submitted packets (HTTP ingress).
    /// Packets received via P2P are already validated by the entry node.
    pub min_pow_difficulty: u32,
}

/// HTTP ingress server wrapping an axum `Router`.
pub struct IngressServer;

impl IngressServer {
    pub fn router(state: Arc<IngressState>) -> Router {
        Router::new()
            .route("/api/v1/packets", post(inject_packet))
            .route("/api/v1/responses/claim", post(claim_responses))
            .route("/api/v1/responses/stream", get(stream_responses))
            .route("/api/v1/ws", get(ws_upgrade))
            .route("/api/v1/responses/pending", get(fetch_pending))
            .route("/api/v1/responses/:request_id", get(poll_response))
            .route("/health", get(health))
            .layer(CorsLayer::permissive())
            .with_state(state)
    }
}

#[derive(Deserialize)]
struct StreamQuery {
    surb_ids: String,
}

#[derive(Deserialize)]
struct ClaimRequest {
    /// SURB ID hex strings to claim. The buffer matches `packet_id` entries
    /// containing any of these substrings.
    surb_ids: Vec<String>,
}

/// `POST /api/v1/packets` -- Inject a raw Sphinx packet.
///
/// Validates size (must be exactly `PACKET_SIZE` bytes), then publishes
/// a `PacketReceived` event to the internal event bus.
async fn inject_packet(State(state): State<Arc<IngressState>>, body: Bytes) -> impl IntoResponse {
    // Validate size
    if body.len() != PACKET_SIZE {
        warn!(
            size = body.len(),
            expected = PACKET_SIZE,
            "Rejected packet: wrong size"
        );
        state
            .metrics
            .ingress_http_requests_total
            .get_or_create(&vec![
                ("endpoint".to_string(), "inject".to_string()),
                ("status".to_string(), "rejected".to_string()),
            ])
            .inc();
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "Packet must be exactly {PACKET_SIZE} bytes, got {}",
                body.len()
            ),
        );
    }

    // PoW check: only enforced here at the HTTP ingress boundary.
    // P2P-forwarded packets skip this because the entry node already validated.
    if state.min_pow_difficulty > 0 {
        match SphinxHeader::from_bytes(&body) {
            Ok((header, _)) => {
                if !header.verify_pow(state.min_pow_difficulty) {
                    state
                        .metrics
                        .ingress_http_requests_total
                        .get_or_create(&vec![
                            ("endpoint".to_string(), "inject".to_string()),
                            ("status".to_string(), "pow_rejected".to_string()),
                        ])
                        .inc();
                    return (
                        StatusCode::FORBIDDEN,
                        "Insufficient proof of work".to_string(),
                    );
                }
            }
            Err(e) => {
                warn!(error = %e, "HTTP ingress: invalid Sphinx header");
                state
                    .metrics
                    .ingress_http_requests_total
                    .get_or_create(&vec![
                        ("endpoint".to_string(), "inject".to_string()),
                        ("status".to_string(), "rejected".to_string()),
                    ])
                    .inc();
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid packet header: {e}"),
                );
            }
        }
    }

    // Generate packet ID for tracing
    let packet_id = format!("http-{:016x}", rand::random::<u64>());

    // Publish to internal event bus
    match state.event_publisher.publish(NoxEvent::PacketReceived {
        packet_id: packet_id.clone(),
        data: body.to_vec(),
        size_bytes: body.len(),
    }) {
        Ok(_) => {
            debug!(packet_id = %packet_id, "HTTP ingress: packet accepted");
            state
                .metrics
                .ingress_http_requests_total
                .get_or_create(&vec![
                    ("endpoint".to_string(), "inject".to_string()),
                    ("status".to_string(), "accepted".to_string()),
                ])
                .inc();
            (StatusCode::ACCEPTED, packet_id)
        }
        Err(e) => {
            warn!(error = %e, "HTTP ingress: failed to publish packet");
            state
                .metrics
                .ingress_http_requests_total
                .get_or_create(&vec![
                    ("endpoint".to_string(), "inject".to_string()),
                    ("status".to_string(), "error".to_string()),
                ])
                .inc();
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Event bus error: {e}"),
            )
        }
    }
}

/// `POST /api/v1/responses/claim` -- Claim SURB responses by SURB ID.
///
/// The client sends a JSON body with `surb_ids` -- the hex-encoded SURB IDs
/// it generated. Only responses whose `packet_id` contains a matching SURB ID
/// are returned and removed from the buffer; all other responses remain.
///
/// This is the session-safe alternative to `/pending` for multi-client setups.
///
/// Returns JSON array of `{"id": "...", "data": [bytes...]}`.
/// Returns 204 No Content if no matching responses are found.
async fn claim_responses(
    State(state): State<Arc<IngressState>>,
    Json(body): Json<ClaimRequest>,
) -> impl IntoResponse {
    state
        .metrics
        .ingress_http_requests_total
        .get_or_create(&vec![
            ("endpoint".to_string(), "claim".to_string()),
            ("status".to_string(), "accepted".to_string()),
        ])
        .inc();

    if body.surb_ids.is_empty() {
        return (StatusCode::NO_CONTENT, axum::Json(serde_json::Value::Null)).into_response();
    }

    let responses = state.response_buffer.claim_by_surb_ids(&body.surb_ids);
    if responses.is_empty() {
        return (StatusCode::NO_CONTENT, axum::Json(serde_json::Value::Null)).into_response();
    }

    let items: Vec<serde_json::Value> = responses
        .into_iter()
        .map(|(id, data)| serde_json::json!({ "id": id, "data": data }))
        .collect();

    debug!(
        count = items.len(),
        surb_ids = body.surb_ids.len(),
        "HTTP ingress: delivering claimed responses"
    );
    (StatusCode::OK, axum::Json(serde_json::json!(items))).into_response()
}

/// `GET /api/v1/responses/pending` -- Fetch all pending SURB responses.
///
/// Returns JSON array of `{"id": "...", "data": [bytes...]}`.
/// Returns 204 No Content if buffer is empty.
///
/// **Deprecated:** Prefer `POST /api/v1/responses/claim` with SURB IDs for
/// multi-client safety. This endpoint drains ALL responses regardless of
/// ownership -- use only in single-client-per-entry-node configurations.
async fn fetch_pending(State(state): State<Arc<IngressState>>) -> impl IntoResponse {
    state
        .metrics
        .ingress_http_requests_total
        .get_or_create(&vec![
            ("endpoint".to_string(), "pending".to_string()),
            ("status".to_string(), "accepted".to_string()),
        ])
        .inc();

    let responses = state.response_buffer.take_all();
    if responses.is_empty() {
        return (StatusCode::NO_CONTENT, axum::Json(serde_json::Value::Null)).into_response();
    }

    let items: Vec<serde_json::Value> = responses
        .into_iter()
        .map(|(id, data)| serde_json::json!({ "id": id, "data": data }))
        .collect();

    debug!(
        count = items.len(),
        "HTTP ingress: delivering batch responses"
    );
    (StatusCode::OK, axum::Json(serde_json::json!(items))).into_response()
}

/// `GET /api/v1/responses/:request_id` -- Long-poll for a SURB response.
///
/// Polls the `ResponseBuffer` every 100ms for up to `state.long_poll_timeout`.
/// Returns 200 with response bytes if found, or 204 No Content on timeout.
async fn poll_response(
    State(state): State<Arc<IngressState>>,
    Path(request_id): Path<String>,
) -> impl IntoResponse {
    let timeout = state.long_poll_timeout;
    let poll_interval = Duration::from_millis(100);
    let start = Instant::now();

    loop {
        if let Some(response) = state.response_buffer.take_response(&request_id) {
            debug!(
                request_id = %request_id,
                bytes = response.len(),
                elapsed_ms = start.elapsed().as_millis() as u64,
                "HTTP ingress: delivering SURB response"
            );
            state
                .metrics
                .ingress_http_requests_total
                .get_or_create(&vec![
                    ("endpoint".to_string(), "poll".to_string()),
                    ("status".to_string(), "accepted".to_string()),
                ])
                .inc();
            return (StatusCode::OK, response);
        }

        if start.elapsed() > timeout {
            debug!(request_id = %request_id, "HTTP ingress: response poll timed out");
            state
                .metrics
                .ingress_http_requests_total
                .get_or_create(&vec![
                    ("endpoint".to_string(), "poll".to_string()),
                    ("status".to_string(), "timeout".to_string()),
                ])
                .inc();
            return (StatusCode::NO_CONTENT, vec![]);
        }

        tokio::select! {
            () = state.response_buffer.notified() => {}
            () = tokio::time::sleep(poll_interval) => {}
        }
    }
}

/// `GET /health` -- Health check endpoint.
async fn health(State(state): State<Arc<IngressState>>) -> impl IntoResponse {
    state
        .metrics
        .ingress_http_requests_total
        .get_or_create(&vec![
            ("endpoint".to_string(), "health".to_string()),
            ("status".to_string(), "accepted".to_string()),
        ])
        .inc();
    (StatusCode::OK, "ok")
}

/// `GET /api/v1/ws` - WebSocket endpoint for bidirectional SURB response delivery.
///
/// Client messages:
///   `{"type":"subscribe","surb_ids":["id1","id2"]}`  - add SURB IDs to watch set
///   `{"type":"unsubscribe","surb_ids":["id1"]}`      - remove consumed SURB IDs
///
/// Server messages:
///   `{"type":"response","id":"echo-100-aabb","data":[1,2,3]}`  - SURB response
async fn ws_upgrade(
    State(state): State<Arc<IngressState>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    state
        .metrics
        .ingress_http_requests_total
        .get_or_create(&vec![
            ("endpoint".to_string(), "ws".to_string()),
            ("status".to_string(), "accepted".to_string()),
        ])
        .inc();
    ws.on_upgrade(|socket| ws_handler(socket, state))
}

async fn ws_handler(mut socket: WebSocket, state: Arc<IngressState>) {
    let mut subscribed: HashSet<String> = HashSet::new();
    let poll_interval = Duration::from_millis(100);
    let ping_interval = Duration::from_secs(15);
    let timeout = Duration::from_secs(300);
    let start = Instant::now();
    let mut last_ping = Instant::now();

    loop {
        if start.elapsed() > timeout {
            break;
        }

        // Send periodic ping to keep connection alive through proxies
        if last_ping.elapsed() >= ping_interval {
            if socket.send(Message::Ping(vec![])).await.is_err() {
                break;
            }
            last_ping = Instant::now();
        }

        // Check for client messages or response notification (non-blocking)
        tokio::select! {
            msg_result = socket.recv() => {
                match msg_result {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&text) {
                            let msg_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or("");
                            let ids: Vec<String> = msg
                                .get("surb_ids")
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|v| v.as_str().map(String::from))
                                        .collect()
                                })
                                .unwrap_or_default();

                            match msg_type {
                                "subscribe" => {
                                    subscribed.extend(ids);
                                }
                                "unsubscribe" => {
                                    for id in &ids {
                                        subscribed.remove(id);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                    Some(Ok(_)) => {}
                }
            }
            () = state.response_buffer.notified() => {}
            () = tokio::time::sleep(poll_interval) => {}
        }

        // Check response buffer for any matching SURBs
        if subscribed.is_empty() {
            continue;
        }

        let ids_vec: Vec<String> = subscribed.iter().cloned().collect();
        let responses = state.response_buffer.claim_by_surb_ids(&ids_vec);

        for (id, data) in responses {
            let msg = serde_json::json!({
                "type": "response",
                "id": id,
                "data": data,
            });

            if socket.send(Message::Text(msg.to_string())).await.is_err() {
                return;
            }

            // Remove consumed SURB IDs from subscription
            for sid in &ids_vec {
                if id.contains(sid.as_str()) {
                    subscribed.remove(sid);
                }
            }
        }
    }

    let _ = socket.close().await;
}

/// `GET /api/v1/responses/stream?surb_ids=id1,id2,...` - SSE stream for SURB responses.
///
/// Opens a persistent connection and pushes matching responses as SSE events.
/// Polls the response buffer every 100ms and sends any matches immediately.
/// The stream closes after 60s or when all SURB IDs have been consumed.
async fn stream_responses(
    State(state): State<Arc<IngressState>>,
    Query(query): Query<StreamQuery>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let surb_ids: Vec<String> = query
        .surb_ids
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let buffer = state.response_buffer.clone();

    state
        .metrics
        .ingress_http_requests_total
        .get_or_create(&vec![
            ("endpoint".to_string(), "stream".to_string()),
            ("status".to_string(), "accepted".to_string()),
        ])
        .inc();

    let stream = async_stream::stream! {
        let start = Instant::now();
        let timeout = Duration::from_secs(60);
        let poll_interval = Duration::from_millis(100);
        let mut remaining: Vec<String> = surb_ids;

        while !remaining.is_empty() && start.elapsed() < timeout {
            let responses = buffer.claim_by_surb_ids(&remaining);

            for (id, data) in &responses {
                let json = serde_json::json!({ "id": id, "data": data });
                yield Ok(Event::default().data(json.to_string()));

                remaining.retain(|sid| !id.contains(sid.as_str()));
            }

            if remaining.is_empty() {
                break;
            }

            tokio::select! {
                () = buffer.notified() => {}
                () = tokio::time::sleep(poll_interval) => {}
            }
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::Request;
    use nox_core::traits::interfaces::EventBusError;
    use tower::ServiceExt;

    /// Mock event publisher for testing.
    struct MockPublisher {
        should_fail: bool,
    }

    impl IEventPublisher for MockPublisher {
        fn publish(&self, _event: NoxEvent) -> Result<usize, EventBusError> {
            if self.should_fail {
                Err(EventBusError::BroadcastFailed("mock failure".into()))
            } else {
                Ok(1)
            }
        }
    }

    fn test_state(should_fail: bool) -> Arc<IngressState> {
        Arc::new(IngressState {
            event_publisher: Arc::new(MockPublisher { should_fail }),
            response_buffer: Arc::new(ResponseBuffer::new()),
            metrics: MetricsService::new(),
            long_poll_timeout: Duration::from_secs(30),
            min_pow_difficulty: 0,
        })
    }

    #[tokio::test]
    async fn test_inject_packet_accepted() {
        let state = test_state(false);
        let app = IngressServer::router(state);

        let body = vec![0u8; PACKET_SIZE];
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/packets")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_inject_packet_wrong_size() {
        let state = test_state(false);
        let app = IngressServer::router(state);

        let body = vec![0u8; 100]; // Too small
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/packets")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_inject_packet_bus_failure() {
        let state = test_state(true); // publisher fails
        let app = IngressServer::router(state);

        let body = vec![0u8; PACKET_SIZE];
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/packets")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_poll_response_found() {
        let state = test_state(false);
        state
            .response_buffer
            .store_response("req-42", vec![1, 2, 3]);
        let app = IngressServer::router(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/responses/req-42")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(body.as_ref(), &[1, 2, 3]);
    }

    #[tokio::test]
    async fn test_fetch_pending_empty() {
        let state = test_state(false);
        let app = IngressServer::router(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/responses/pending")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_fetch_pending_returns_all() {
        let state = test_state(false);
        state.response_buffer.store_response("r1", vec![1, 2]);
        state.response_buffer.store_response("r2", vec![3, 4]);
        let app = IngressServer::router(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/responses/pending")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(items.len(), 2);
    }

    #[tokio::test]
    async fn test_health() {
        let state = test_state(false);
        let app = IngressServer::router(state);

        let req = Request::builder()
            .method("GET")
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_stream_responses_delivers_matching() {
        let state = test_state(false);
        state
            .response_buffer
            .store_response("echo-100-aabb1122", vec![10, 20]);
        state
            .response_buffer
            .store_response("rpc-200-ccdd3344", vec![30, 40]);

        let app = IngressServer::router(state);
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/responses/stream?surb_ids=aabb1122")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "text/event-stream"
        );

        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            text.contains("aabb1122"),
            "SSE stream should contain the SURB ID"
        );
        assert!(
            text.contains("[10,20]"),
            "SSE stream should contain response data"
        );
        assert!(
            !text.contains("ccdd3344"),
            "SSE stream should not contain unmatched SURB"
        );
    }

    #[tokio::test]
    async fn test_stream_responses_empty_surbs() {
        let state = test_state(false);
        let app = IngressServer::router(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/responses/stream?surb_ids=")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            !text.contains("data:"),
            "Empty SURB list should produce no data events"
        );
    }

    #[tokio::test]
    async fn test_cors_headers_present() {
        let state = test_state(false);
        let app = IngressServer::router(state);

        let req = Request::builder()
            .method("OPTIONS")
            .uri("/api/v1/packets")
            .header("origin", "http://localhost:5173")
            .header("access-control-request-method", "POST")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key("access-control-allow-origin"));
    }

    #[tokio::test]
    async fn test_claim_responses_returns_matching() {
        let state = test_state(false);
        state
            .response_buffer
            .store_response("echo-100-aabb1122", vec![10, 20]);
        state
            .response_buffer
            .store_response("rpc-200-ccdd3344", vec![30, 40]);
        let app = IngressServer::router(state);

        let body = serde_json::json!({ "surb_ids": ["aabb1122"] });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/responses/claim")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(items.len(), 1);
    }

    #[tokio::test]
    async fn test_claim_responses_empty_surb_ids() {
        let state = test_state(false);
        state
            .response_buffer
            .store_response("echo-100-aabb1122", vec![10]);
        let app = IngressServer::router(state);

        let body = serde_json::json!({ "surb_ids": [] });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/responses/claim")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_claim_responses_no_match() {
        let state = test_state(false);
        state
            .response_buffer
            .store_response("echo-100-aabb1122", vec![10]);
        let app = IngressServer::router(state);

        let body = serde_json::json!({ "surb_ids": ["deadbeef"] });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/responses/claim")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_claim_does_not_steal_other_client_responses() {
        let state = test_state(false);
        // Client A's responses
        state
            .response_buffer
            .store_response("echo-1-aaaa0001", vec![1]);
        // Client B's responses
        state
            .response_buffer
            .store_response("echo-2-bbbb0002", vec![2]);
        let app = IngressServer::router(Arc::clone(&state));

        // Client A claims
        let body = serde_json::json!({ "surb_ids": ["aaaa0001"] });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/responses/claim")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Client B's response should still be in the buffer
        assert_eq!(state.response_buffer.len(), 1);
        assert!(state
            .response_buffer
            .take_response("echo-2-bbbb0002")
            .is_some());
    }
}
