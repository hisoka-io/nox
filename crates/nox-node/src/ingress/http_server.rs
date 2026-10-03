//! HTTP ingress server for Sphinx packet injection and response delivery.
//!
//! ## Endpoints
//! - `POST /api/v1/packets` - Inject a raw Sphinx packet (body = raw bytes)
//! - `POST /api/v1/responses/claim` - Claim responses by SURB ID (session-safe)
//! - `GET /api/v1/responses/stream` - SSE stream for SURB responses (push-based)
//! - `GET /api/v1/ws` - WebSocket stream for SURB responses
//! - `GET /api/v1/responses/pending` - Removed; returns 410 Gone
//! - `GET /api/v1/responses/:request_id` - Long-poll for a SURB response (30s timeout)
//! - `GET /health` - Returns 200 OK
//!
//! SURB IDs are exactly 32 hex characters and match exactly.

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
use tracing::{debug, warn};

use super::policy::{cors_layer, rate_limit, IngressRateLimiter};
use super::response_buffer::{
    parse_surb_id, surb_id_from_packet_id, ResponseBuffer, SurbId, SURB_ID_HEX_LEN,
};
use crate::config::IngressConfig;
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
    /// Router with the default ingress policy (see [`IngressConfig::default`]).
    pub fn router(state: Arc<IngressState>) -> Router {
        Self::router_with_policy(state, &IngressConfig::default())
    }

    /// Router with a per-client rate limit and CORS policy. The rate limit keys on
    /// the peer address, so serve it with
    /// `into_make_service_with_connect_info::<SocketAddr>()`; without peer
    /// information requests are not limited.
    pub fn router_with_policy(state: Arc<IngressState>, policy: &IngressConfig) -> Router {
        let mut router = Router::new()
            .route("/api/v1/packets", post(inject_packet))
            .route("/api/v1/responses/claim", post(claim_responses))
            .route("/api/v1/responses/stream", get(stream_responses))
            .route("/api/v1/ws", get(ws_upgrade))
            .route("/api/v1/responses/pending", get(pending_removed))
            .route("/api/v1/responses/:request_id", get(poll_response))
            .route("/health", get(health));
        if let Some(limiter) = IngressRateLimiter::from_config(policy, state.metrics.clone()) {
            router = router.layer(axum::middleware::from_fn_with_state(limiter, rate_limit));
        }
        router
            .layer(cors_layer(&policy.cors_allowed_origins))
            .with_state(state)
    }
}

#[derive(Deserialize)]
struct StreamQuery {
    surb_ids: String,
}

#[derive(Deserialize)]
struct ClaimRequest {
    /// SURB IDs to claim, each exactly 32 hex characters.
    surb_ids: Vec<String>,
}

/// Parses every ID or names the first invalid one.
fn parse_surb_ids(ids: &[String]) -> Result<Vec<SurbId>, String> {
    ids.iter()
        .enumerate()
        .map(|(i, id)| {
            parse_surb_id(id).ok_or_else(|| {
                format!("surb_ids[{i}] must be exactly {SURB_ID_HEX_LEN} hex characters")
            })
        })
        .collect()
}

/// Keeps the valid IDs, for streaming endpoints that have no error channel.
fn valid_surb_ids<'a>(ids: impl IntoIterator<Item = &'a str>) -> Vec<SurbId> {
    ids.into_iter().filter_map(parse_surb_id).collect()
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

/// Valid SURB IDs from a WebSocket `subscribe`/`unsubscribe` message; malformed ones are ignored.
fn ws_message_surb_ids(msg: &serde_json::Value) -> Vec<SurbId> {
    valid_surb_ids(
        msg.get("surb_ids")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str()),
    )
}

/// `POST /api/v1/responses/claim` -- Claim SURB responses by SURB ID.
///
/// The client sends a JSON body with `surb_ids` -- the hex-encoded SURB IDs
/// it generated (32 hex characters each). Only responses for exactly those
/// SURB IDs are returned and removed from the buffer; all others remain.
///
/// Returns JSON array of `{"id": "...", "data": [bytes...]}`.
/// Returns 204 No Content if no matching responses are found, and 400 if any
/// SURB ID is malformed.
async fn claim_responses(
    State(state): State<Arc<IngressState>>,
    Json(body): Json<ClaimRequest>,
) -> impl IntoResponse {
    let surb_ids = match parse_surb_ids(&body.surb_ids) {
        Ok(ids) => ids,
        Err(message) => {
            state
                .metrics
                .ingress_http_requests_total
                .get_or_create(&vec![
                    ("endpoint".to_string(), "claim".to_string()),
                    ("status".to_string(), "rejected".to_string()),
                ])
                .inc();
            return (StatusCode::BAD_REQUEST, message).into_response();
        }
    };

    state
        .metrics
        .ingress_http_requests_total
        .get_or_create(&vec![
            ("endpoint".to_string(), "claim".to_string()),
            ("status".to_string(), "accepted".to_string()),
        ])
        .inc();

    if surb_ids.is_empty() {
        return (StatusCode::NO_CONTENT, axum::Json(serde_json::Value::Null)).into_response();
    }

    let responses = state.response_buffer.claim_by_surb_ids(&surb_ids);
    if responses.is_empty() {
        return (StatusCode::NO_CONTENT, axum::Json(serde_json::Value::Null)).into_response();
    }

    let items: Vec<serde_json::Value> = responses
        .into_iter()
        .map(|(id, data)| serde_json::json!({ "id": id, "data": data }))
        .collect();

    debug!(
        count = items.len(),
        surb_ids = surb_ids.len(),
        "HTTP ingress: delivering claimed responses"
    );
    (StatusCode::OK, axum::Json(serde_json::json!(items))).into_response()
}

/// `GET /api/v1/responses/pending` -- Removed. Responses are claimed by SURB ID
/// (`POST /api/v1/responses/claim`, `/api/v1/ws` or `/api/v1/responses/stream`).
async fn pending_removed(State(state): State<Arc<IngressState>>) -> impl IntoResponse {
    state
        .metrics
        .ingress_http_requests_total
        .get_or_create(&vec![
            ("endpoint".to_string(), "pending".to_string()),
            ("status".to_string(), "rejected".to_string()),
        ])
        .inc();
    (
        StatusCode::GONE,
        "GET /api/v1/responses/pending was removed; claim responses by SURB ID with \
         POST /api/v1/responses/claim",
    )
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
    let mut subscribed: HashSet<SurbId> = HashSet::new();
    let poll_interval = Duration::from_millis(100);
    let ping_interval = Duration::from_secs(15);
    let timeout = Duration::from_mins(5);
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
                            let ids = ws_message_surb_ids(&msg);

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

        let ids_vec: Vec<SurbId> = subscribed.iter().copied().collect();
        let responses = state.response_buffer.claim_by_surb_ids(&ids_vec);

        for (id, data) in responses {
            // Remove the consumed SURB ID from the subscription
            if let Some(surb_id) = surb_id_from_packet_id(&id) {
                subscribed.remove(&surb_id);
            }

            let msg = serde_json::json!({
                "type": "response",
                "id": id,
                "data": data,
            });

            if socket.send(Message::Text(msg.to_string())).await.is_err() {
                return;
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
    let surb_ids = valid_surb_ids(query.surb_ids.split(',').map(str::trim));

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
        let timeout = Duration::from_mins(1);
        let poll_interval = Duration::from_millis(100);
        let mut remaining: Vec<SurbId> = surb_ids;

        while !remaining.is_empty() && start.elapsed() < timeout {
            let responses = buffer.claim_by_surb_ids(&remaining);

            for (id, data) in &responses {
                let json = serde_json::json!({ "id": id, "data": data });
                yield Ok(Event::default().data(json.to_string()));

                let consumed = surb_id_from_packet_id(id);
                remaining.retain(|sid| Some(*sid) != consumed);
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

    const SURB_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa1122";
    const SURB_B: &str = "cccccccccccccccccccccccccccc3344";

    async fn claim(app: Router, ids: serde_json::Value) -> (StatusCode, Vec<serde_json::Value>) {
        let body = serde_json::json!({ "surb_ids": ids });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/responses/claim")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let items = serde_json::from_slice(&bytes).unwrap_or_default();
        (status, items)
    }

    #[tokio::test]
    async fn test_pending_is_gone_and_leaves_buffer_intact() {
        let state = test_state(false);
        state
            .response_buffer
            .store_response(&format!("echo-1-{SURB_A}"), vec![1, 2]);
        state.response_buffer.store_response("r2", vec![3, 4]);
        let app = IngressServer::router(Arc::clone(&state));

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/responses/pending")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::GONE);
        assert_eq!(state.response_buffer.len(), 2);
    }

    #[tokio::test]
    async fn test_claim_rejects_malformed_surb_ids() {
        let state = test_state(false);
        state
            .response_buffer
            .store_response(&format!("reply-100-{SURB_A}"), vec![10]);
        state
            .response_buffer
            .store_response(&format!("rpc-200-{SURB_B}"), vec![20]);

        for bad in ["", "-", "rpc", "reply", "aabb1122", &SURB_A[1..]] {
            let app = IngressServer::router(Arc::clone(&state));
            let (status, _) = claim(app, serde_json::json!([bad])).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad:?} must be rejected");
        }
        let app = IngressServer::router(Arc::clone(&state));
        let (status, _) = claim(app, serde_json::json!([SURB_A, "-"])).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        assert_eq!(state.response_buffer.len(), 2);
    }

    #[tokio::test]
    async fn test_claim_matches_whole_surb_id_only() {
        let state = test_state(false);
        state
            .response_buffer
            .store_response(&format!("reply-100-{SURB_A}"), vec![10]);
        let app = IngressServer::router(Arc::clone(&state));

        let mut near = SURB_A.to_string();
        near.replace_range(31..32, "3");
        let (status, _) = claim(app, serde_json::json!([near])).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(state.response_buffer.len(), 1);
    }

    #[test]
    fn test_ws_subscription_ignores_malformed_ids() {
        let msg = serde_json::json!({
            "type": "subscribe",
            "surb_ids": ["", "-", "rpc", "reply", 7, SURB_A],
        });
        assert_eq!(
            ws_message_surb_ids(&msg),
            vec![parse_surb_id(SURB_A).unwrap()]
        );
        assert!(ws_message_surb_ids(&serde_json::json!({ "type": "subscribe" })).is_empty());
    }

    #[tokio::test]
    async fn test_stream_ignores_malformed_ids() {
        let state = test_state(false);
        state
            .response_buffer
            .store_response(&format!("echo-100-{SURB_A}"), vec![10, 20]);
        let app = IngressServer::router(Arc::clone(&state));

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/responses/stream?surb_ids=-,rpc,echo")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("data:"));
        assert_eq!(state.response_buffer.len(), 1);
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
            .store_response(&format!("echo-100-{SURB_A}"), vec![10, 20]);
        state
            .response_buffer
            .store_response(&format!("rpc-200-{SURB_B}"), vec![30, 40]);

        let app = IngressServer::router(state);
        let req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/responses/stream?surb_ids={SURB_A}"))
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
            text.contains(SURB_A),
            "SSE stream should contain the SURB ID"
        );
        assert!(
            text.contains("[10,20]"),
            "SSE stream should contain response data"
        );
        assert!(
            !text.contains(SURB_B),
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
            .store_response(&format!("echo-100-{SURB_A}"), vec![10, 20]);
        state
            .response_buffer
            .store_response(&format!("rpc-200-{SURB_B}"), vec![30, 40]);
        let app = IngressServer::router(state);

        let (status, items) = claim(app, serde_json::json!([SURB_A])).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], format!("echo-100-{SURB_A}"));
        assert_eq!(items[0]["data"], serde_json::json!([10, 20]));
    }

    #[tokio::test]
    async fn test_claim_responses_empty_surb_ids() {
        let state = test_state(false);
        state
            .response_buffer
            .store_response(&format!("echo-100-{SURB_A}"), vec![10]);
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
            .store_response(&format!("echo-100-{SURB_A}"), vec![10]);
        let app = IngressServer::router(state);

        let (status, _) = claim(app, serde_json::json!([SURB_B])).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_claim_does_not_steal_other_client_responses() {
        let state = test_state(false);
        // Client A's responses
        state
            .response_buffer
            .store_response(&format!("echo-1-{SURB_A}"), vec![1]);
        // Client B's responses
        state
            .response_buffer
            .store_response(&format!("echo-2-{SURB_B}"), vec![2]);
        let app = IngressServer::router(Arc::clone(&state));

        // Client A claims
        let (status, _) = claim(app, serde_json::json!([SURB_A])).await;
        assert_eq!(status, StatusCode::OK);

        // Client B's response should still be in the buffer
        assert_eq!(state.response_buffer.len(), 1);
        assert!(state
            .response_buffer
            .take_response(&format!("echo-2-{SURB_B}"))
            .is_some());
    }
}
