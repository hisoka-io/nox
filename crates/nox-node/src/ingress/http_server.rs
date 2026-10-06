//! HTTP ingress server for Sphinx packet injection and response delivery.
//!
//! ## Endpoints
//! - `POST /api/v1/packets` - Inject a raw Sphinx packet (body = raw bytes)
//! - `POST /api/v1/responses/claim` - Claim responses by SURB ID (session-safe).
//!   Optional v2 fields select a compact encoding, retain-until-ack and
//!   long-polling; see [`super::claim`] and `docs/claim-api.md`.
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
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
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

use super::claim::{
    base64_item, encode_base64_json, encode_batch, encode_json, ClaimEncoding, ClaimRequest,
    ClaimSettings, CLAIM_BATCH_CONTENT_TYPE, CLAIM_FEATURES, CLAIM_FEATURES_HEADER, CLAIM_VERSION,
    CLAIM_VERSION_HEADER, CLAIM_WAIT_MAX_HEADER,
};
use super::policy::{cors_layer, rate_limit, IngressRateLimiter};
use super::response_buffer::{
    parse_surb_id, surb_id_from_packet_id, ClaimMode, ClaimedReply, ResponseBuffer, SurbId,
    SURB_ID_HEX_LEN,
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
    /// Long-poll limits for `POST /api/v1/responses/claim`.
    pub claim: ClaimSettings,
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
    /// `base64` sends `{"id","data_b64","reclaimed"}` events instead of
    /// number arrays.
    #[serde(default)]
    encoding: Option<String>,
}

/// Parses every ID or names the first invalid one (`field` names the list).
fn parse_surb_ids(field: &str, ids: &[String]) -> Result<Vec<SurbId>, String> {
    ids.iter()
        .enumerate()
        .map(|(i, id)| {
            parse_surb_id(id).ok_or_else(|| {
                format!("{field}[{i}] must be exactly {SURB_ID_HEX_LEN} hex characters")
            })
        })
        .collect()
}

/// Counts one claim event (`reclaimed`, `acked`, `wait`, `wait_busy`, ...).
fn count_claim_event(state: &IngressState, event: &str, n: u64) {
    if n > 0 {
        state
            .metrics
            .ingress_claim_events_total
            .get_or_create(&vec![("event".to_string(), event.to_string())])
            .inc_by(n);
    }
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
        debug!(
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
                debug!(error = %e, "HTTP ingress: invalid Sphinx header");
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
        reply_handle: None,
        prev_peer: None,
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
/// SURB IDs are returned; all others remain.
///
/// v1 body (`{"surb_ids":[...]}`): returns a JSON array of
/// `{"id": "...", "data": [bytes...]}` and removes the returned replies.
/// Optional v2 fields (see [`ClaimRequest`]): `encoding` (`json`, `base64`,
/// `binary`; `Accept: application/vnd.nox.claim-batch` also selects binary),
/// `retain` (keep replies until acked or the claim grace passes), `ack`
/// (remove replies the client has; applied first) and `wait_ms` (long-poll,
/// only with `retain`).
///
/// Returns 204 No Content if no matching responses are found, and 400 if any
/// SURB ID is malformed. Every answer carries `x-nox-claim-version` and
/// `x-nox-claim-wait-max-ms`.
async fn claim_responses(
    State(state): State<Arc<IngressState>>,
    headers: HeaderMap,
    Json(body): Json<ClaimRequest>,
) -> axum::response::Response {
    let rejected = |state: &IngressState, message: String| {
        state
            .metrics
            .ingress_http_requests_total
            .get_or_create(&vec![
                ("endpoint".to_string(), "claim".to_string()),
                ("status".to_string(), "rejected".to_string()),
            ])
            .inc();
        with_claim_headers(
            &state.claim,
            (StatusCode::BAD_REQUEST, message).into_response(),
        )
    };
    let surb_ids = match parse_surb_ids("surb_ids", &body.surb_ids) {
        Ok(ids) => ids,
        Err(message) => return rejected(&state, message),
    };
    let ack_ids = match parse_surb_ids("ack", &body.ack) {
        Ok(ids) => ids,
        Err(message) => return rejected(&state, message),
    };

    state
        .metrics
        .ingress_http_requests_total
        .get_or_create(&vec![
            ("endpoint".to_string(), "claim".to_string()),
            ("status".to_string(), "accepted".to_string()),
        ])
        .inc();

    let acked = state.response_buffer.ack(&ack_ids);
    count_claim_event(&state, "acked", acked as u64);

    let encoding = body.encoding.as_deref().map_or_else(
        || {
            headers
                .get(header::ACCEPT)
                .and_then(|v| v.to_str().ok())
                .map_or(ClaimEncoding::Json, ClaimEncoding::from_accept)
        },
        ClaimEncoding::from_field,
    );
    let mode = if body.retain {
        ClaimMode::Retain
    } else {
        ClaimMode::Take
    };

    if surb_ids.is_empty() {
        return with_claim_headers(&state.claim, no_content());
    }

    // Long-poll only for retaining claims: a reply claimed for a client that
    // has gone away stays claimable for the grace instead of being lost.
    let requested_wait = if body.retain {
        Duration::from_millis(body.wait_ms).min(state.claim.wait_max)
    } else {
        Duration::ZERO
    };
    let wait_permit = if requested_wait.is_zero() {
        None
    } else {
        let permit = state.claim.wait_slots.clone().try_acquire_owned().ok();
        count_claim_event(
            &state,
            if permit.is_some() {
                "wait"
            } else {
                "wait_busy"
            },
            1,
        );
        permit
    };
    let wait = if wait_permit.is_some() {
        requested_wait
    } else {
        Duration::ZERO
    };

    let deadline = tokio::time::Instant::now() + wait;
    let limit = body.reply_limit();
    // Registered before the first check, so a reply stored in between still
    // wakes the wait. Only stores under these IDs wake it.
    let waiter = (!wait.is_zero()).then(|| state.response_buffer.waiter(&surb_ids));
    let replies = loop {
        let replies = state.response_buffer.claim_at_most(&surb_ids, mode, limit);
        if !replies.is_empty() || tokio::time::Instant::now() >= deadline {
            break replies;
        }
        let Some(waiter) = &waiter else {
            break replies;
        };
        tokio::select! {
            () = waiter.notified() => {}
            () = tokio::time::sleep_until(deadline) => {}
        }
    };
    drop(waiter);
    if replies.is_empty() {
        if !wait.is_zero() {
            count_claim_event(&state, "wait_timeout", 1);
        }
        return with_claim_headers(&state.claim, no_content());
    }

    let reclaimed = replies.iter().filter(|reply| reply.reclaimed).count();
    count_claim_event(&state, "reclaimed", reclaimed as u64);
    count_claim_event(&state, encoding.label(), replies.len() as u64);
    debug!(
        count = replies.len(),
        reclaimed,
        acked,
        surb_ids = surb_ids.len(),
        encoding = encoding.label(),
        retain = body.retain,
        "HTTP ingress: delivering claimed responses"
    );
    let response = match encoding {
        ClaimEncoding::Json => (StatusCode::OK, axum::Json(encode_json(&replies))).into_response(),
        ClaimEncoding::Base64 => {
            (StatusCode::OK, axum::Json(encode_base64_json(&replies))).into_response()
        }
        ClaimEncoding::Binary => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static(CLAIM_BATCH_CONTENT_TYPE),
            )],
            encode_batch(&replies),
        )
            .into_response(),
    };
    with_claim_headers(&state.claim, response)
}

fn no_content() -> axum::response::Response {
    (StatusCode::NO_CONTENT, axum::Json(serde_json::Value::Null)).into_response()
}

/// Adds the claim capability headers.
fn with_claim_headers(
    settings: &ClaimSettings,
    mut response: axum::response::Response,
) -> axum::response::Response {
    let headers = response.headers_mut();
    headers.insert(
        CLAIM_VERSION_HEADER,
        HeaderValue::from_static(CLAIM_VERSION),
    );
    headers.insert(
        CLAIM_WAIT_MAX_HEADER,
        HeaderValue::from(settings.wait_max.as_millis() as u64),
    );
    headers.insert(
        CLAIM_FEATURES_HEADER,
        HeaderValue::from_static(CLAIM_FEATURES),
    );
    response
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
///   A message with `"encoding":"base64"` switches later responses to base64.
///
/// Server messages:
///   `{"type":"response","id":"echo-100-aabb","data":[1,2,3]}`  - SURB response
///   `{"type":"response","id":"...","data_b64":"...","reclaimed":false}` - base64
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
    let mut base64 = false;
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
                            if let Some(encoding) = msg.get("encoding").and_then(|v| v.as_str()) {
                                base64 = ClaimEncoding::from_field(encoding) == ClaimEncoding::Base64;
                            }

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

            let msg = if base64 {
                let mut item = base64_item(&ClaimedReply {
                    id,
                    data,
                    reclaimed: false,
                });
                if let Some(fields) = item.as_object_mut() {
                    fields.insert("type".to_string(), serde_json::json!("response"));
                }
                item
            } else {
                serde_json::json!({
                    "type": "response",
                    "id": id,
                    "data": data,
                })
            };

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
    let base64 = query
        .encoding
        .as_deref()
        .is_some_and(|e| ClaimEncoding::from_field(e) == ClaimEncoding::Base64);

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
        let waiter = buffer.waiter(&surb_ids);
        let mut remaining: Vec<SurbId> = surb_ids;

        while !remaining.is_empty() && start.elapsed() < timeout {
            let responses = buffer.claim_by_surb_ids(&remaining);

            for (id, data) in &responses {
                let json = if base64 {
                    base64_item(&ClaimedReply { id: id.clone(), data: data.clone(), reclaimed: false })
                } else {
                    serde_json::json!({ "id": id, "data": data })
                };
                yield Ok(Event::default().data(json.to_string()));

                let consumed = surb_id_from_packet_id(id);
                remaining.retain(|sid| Some(*sid) != consumed);
            }

            if remaining.is_empty() {
                break;
            }

            tokio::select! {
                () = waiter.notified() => {}
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
            claim: ClaimSettings::default(),
        })
    }

    /// Files one reply through the `ResponseRouter`, the way a reply arriving
    /// over P2P is filed, and returns the ingress state that serves it.
    async fn state_with_routed_reply(surb: [u8; 16], data: Vec<u8>) -> Arc<IngressState> {
        state_with_routed(Some(surb), None, data).await
    }

    /// Files a format 2 reply under `delivery_id`, with a different handle
    /// planted next to it.
    async fn state_with_routed_v2_reply(delivery_id: [u8; 16], data: Vec<u8>) -> Arc<IngressState> {
        let delivery = nox_core::models::wire_id::ReplyDelivery {
            id: delivery_id,
            source_peer: "peer".into(),
        };
        state_with_routed(Some([0xee; 16]), Some(delivery), data).await
    }

    async fn state_with_routed(
        reply_handle: Option<[u8; 16]>,
        delivery: Option<nox_core::models::wire_id::ReplyDelivery>,
        data: Vec<u8>,
    ) -> Arc<IngressState> {
        use crate::infra::event_bus::TokioEventBus;
        use crate::ingress::response_router::ResponseRouter;
        use nox_core::traits::interfaces::IEventSubscriber;

        let state = test_state(false);
        let bus = TokioEventBus::new(16);
        let publisher: Arc<dyn IEventPublisher> = Arc::new(bus.clone());
        let subscriber: Arc<dyn IEventSubscriber> = Arc::new(bus);
        let router = ResponseRouter::new(
            subscriber,
            state.response_buffer.clone(),
            60,
            MetricsService::new(),
        );
        let handle = tokio::spawn(async move { router.run().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        publisher
            .publish(NoxEvent::PayloadDecrypted {
                packet_id: "5f0e3c1d2b4a69788796a5b4c3d2e1f0".into(),
                payload: data,
                reply_handle,
                delivery,
            })
            .unwrap();
        for _ in 0..50 {
            if !state.response_buffer.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        handle.abort();
        state
    }

    #[tokio::test]
    async fn test_claim_returns_reply_0_id_for_routed_v2_reply() {
        let delivery_id = [0x14u8; 16];
        let state = state_with_routed_v2_reply(delivery_id, vec![7, 8]).await;
        let app = IngressServer::router(state.clone());
        let (status, _) = claim(app, serde_json::json!([hex::encode([0xee; 16])])).await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "the planted handle is not a key"
        );
        let app = IngressServer::router(state);
        let (status, items) = claim(app, serde_json::json!([hex::encode(delivery_id)])).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0]["id"],
            format!("reply-0-{}", hex::encode(delivery_id))
        );
        assert_eq!(items[0]["data"], serde_json::json!([7, 8]));
    }

    #[tokio::test]
    async fn test_stream_returns_reply_0_id_for_routed_v2_reply() {
        let delivery_id = [0x24u8; 16];
        let state = state_with_routed_v2_reply(delivery_id, vec![9]).await;
        let app = IngressServer::router(state);
        let req = Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/responses/stream?surb_ids={}",
                hex::encode(delivery_id)
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            text.contains(&format!("\"id\":\"reply-0-{}\"", hex::encode(delivery_id))),
            "{text}"
        );
    }

    #[tokio::test]
    async fn test_ws_returns_reply_0_id_for_routed_v2_reply() {
        use futures::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message as WsMessage;

        let delivery_id = [0x34u8; 16];
        let state = state_with_routed_v2_reply(delivery_id, vec![5, 6]).await;
        let app = IngressServer::router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/api/v1/ws"))
            .await
            .unwrap();
        let subscribe =
            serde_json::json!({ "type": "subscribe", "surb_ids": [hex::encode(delivery_id)] });
        ws.send(WsMessage::Text(subscribe.to_string()))
            .await
            .unwrap();
        let text = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match ws.next().await {
                    Some(Ok(WsMessage::Text(text))) => return text,
                    Some(Ok(_)) => {}
                    other => panic!("websocket closed: {other:?}"),
                }
            }
        })
        .await
        .expect("response over websocket");
        let msg: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(msg["type"], "response");
        assert_eq!(msg["id"], format!("reply-0-{}", hex::encode(delivery_id)));
        assert_eq!(msg["data"], serde_json::json!([5, 6]));
        server.abort();
    }

    #[tokio::test]
    async fn test_claim_returns_reply_0_id_for_routed_reply() {
        let surb = [0x11u8; 16];
        let state = state_with_routed_reply(surb, vec![7, 8]).await;
        let app = IngressServer::router(state);
        let (status, items) = claim(app, serde_json::json!([hex::encode(surb)])).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], format!("reply-0-{}", hex::encode(surb)));
        assert_eq!(items[0]["data"], serde_json::json!([7, 8]));
    }

    #[tokio::test]
    async fn test_stream_returns_reply_0_id_for_routed_reply() {
        let surb = [0x22u8; 16];
        let state = state_with_routed_reply(surb, vec![9]).await;
        let app = IngressServer::router(state);
        let req = Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/responses/stream?surb_ids={}",
                hex::encode(surb)
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            text.contains(&format!("\"id\":\"reply-0-{}\"", hex::encode(surb))),
            "{text}"
        );
    }

    #[tokio::test]
    async fn test_ws_returns_reply_0_id_for_routed_reply() {
        use futures::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message as WsMessage;

        let surb = [0x33u8; 16];
        let state = state_with_routed_reply(surb, vec![5, 6]).await;
        let app = IngressServer::router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/api/v1/ws"))
            .await
            .unwrap();
        let subscribe = serde_json::json!({ "type": "subscribe", "surb_ids": [hex::encode(surb)] });
        ws.send(WsMessage::Text(subscribe.to_string()))
            .await
            .unwrap();
        let text = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match ws.next().await {
                    Some(Ok(WsMessage::Text(text))) => return text,
                    Some(Ok(_)) => {}
                    other => panic!("websocket closed: {other:?}"),
                }
            }
        })
        .await
        .expect("response over websocket");
        let msg: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(msg["type"], "response");
        assert_eq!(msg["id"], format!("reply-0-{}", hex::encode(surb)));
        assert_eq!(msg["data"], serde_json::json!([5, 6]));
        server.abort();
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

    async fn claim_v2(
        app: Router,
        body: serde_json::Value,
        accept: Option<&str>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/v1/responses/claim")
            .header("content-type", "application/json");
        if let Some(accept) = accept {
            req = req.header("accept", accept);
        }
        let req = req
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, headers, bytes.to_vec())
    }

    /// Decodes a binary claim batch into `(flags, id, data)` items.
    fn decode_batch(body: &[u8]) -> Vec<(u8, String, Vec<u8>)> {
        assert_eq!(body[0], 1, "batch version");
        let count = u16::from_be_bytes([body[1], body[2]]) as usize;
        let mut at = 3;
        let mut items = Vec::new();
        for _ in 0..count {
            let flags = body[at];
            let id_len = u16::from_be_bytes([body[at + 1], body[at + 2]]) as usize;
            at += 3;
            let id = String::from_utf8(body[at..at + id_len].to_vec()).unwrap();
            at += id_len;
            let len = u32::from_be_bytes(body[at..at + 4].try_into().unwrap()) as usize;
            at += 4;
            items.push((flags, id, body[at..at + len].to_vec()));
            at += len;
        }
        assert_eq!(at, body.len(), "no trailing bytes");
        items
    }

    #[tokio::test]
    async fn test_claim_v1_body_keeps_v1_answer_and_deletes() {
        let state = test_state(false);
        state
            .response_buffer
            .store_response(&format!("reply-0-{SURB_A}"), vec![1, 2, 3]);
        let app = IngressServer::router(Arc::clone(&state));
        let (status, headers, body) =
            claim_v2(app, serde_json::json!({ "surb_ids": [SURB_A] }), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["content-type"], "application/json");
        assert_eq!(headers[CLAIM_VERSION_HEADER], "2");
        assert_eq!(headers[CLAIM_WAIT_MAX_HEADER], "20000");
        let items: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            items,
            serde_json::json!([{ "id": format!("reply-0-{SURB_A}"), "data": [1, 2, 3] }])
        );
        assert!(state.response_buffer.is_empty(), "v1 claims delete");
    }

    #[tokio::test]
    async fn test_claim_binary_by_body_field_and_by_accept() {
        let state = test_state(false);
        let reply = vec![0xabu8; 31_716];
        state
            .response_buffer
            .store_response(&format!("reply-0-{SURB_A}"), reply.clone());
        state
            .response_buffer
            .store_response(&format!("reply-0-{SURB_B}"), vec![9]);

        let app = IngressServer::router(Arc::clone(&state));
        let (status, headers, body) = claim_v2(
            app,
            serde_json::json!({ "surb_ids": [SURB_A], "encoding": "binary" }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["content-type"], CLAIM_BATCH_CONTENT_TYPE);
        let items = decode_batch(&body);
        assert_eq!(items, vec![(0, format!("reply-0-{SURB_A}"), reply)]);
        assert!(
            body.len() < 31_716 + 64,
            "binary is about the payload size, JSON would be ~3.6x"
        );

        let app = IngressServer::router(Arc::clone(&state));
        let (_, headers, body) = claim_v2(
            app,
            serde_json::json!({ "surb_ids": [SURB_B] }),
            Some("application/vnd.nox.claim-batch"),
        )
        .await;
        assert_eq!(headers["content-type"], CLAIM_BATCH_CONTENT_TYPE);
        assert_eq!(decode_batch(&body)[0].2, vec![9]);
    }

    #[tokio::test]
    async fn test_claim_body_encoding_overrides_accept() {
        let state = test_state(false);
        state
            .response_buffer
            .store_response(&format!("reply-0-{SURB_A}"), vec![0xfb, 0xff]);
        let app = IngressServer::router(Arc::clone(&state));
        let (_, headers, body) = claim_v2(
            app,
            serde_json::json!({ "surb_ids": [SURB_A], "encoding": "base64" }),
            Some("application/vnd.nox.claim-batch"),
        )
        .await;
        assert_eq!(headers["content-type"], "application/json");
        let items: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(items[0]["data_b64"], "+/8=");
        assert_eq!(items[0]["reclaimed"], false);
    }

    #[tokio::test]
    async fn test_claim_retain_reclaim_then_ack() {
        let state = test_state(false);
        state
            .response_buffer
            .store_response(&format!("reply-0-{SURB_A}"), vec![5]);
        let body =
            serde_json::json!({ "surb_ids": [SURB_A], "encoding": "binary", "retain": true });

        let (_, _, first) = claim_v2(
            IngressServer::router(Arc::clone(&state)),
            body.clone(),
            None,
        )
        .await;
        assert_eq!(decode_batch(&first)[0].0, 0);
        // The first transfer was lost: the client claims again with the same ID.
        let (status, _, again) = claim_v2(
            IngressServer::router(Arc::clone(&state)),
            body.clone(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            decode_batch(&again)[0].0,
            CLAIM_ITEM_FLAG_RECLAIMED_FOR_TESTS
        );
        assert_eq!(decode_batch(&again)[0].2, vec![5]);

        let ack = serde_json::json!({ "surb_ids": [SURB_A], "ack": [SURB_A], "retain": true });
        let (status, _, _) = claim_v2(IngressServer::router(Arc::clone(&state)), ack, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "ack runs before the claim");
        assert!(state.response_buffer.is_empty());
        let metrics = state.metrics.ingress_claim_events_total.clone();
        let event = |name: &str| {
            metrics
                .get_or_create(&vec![("event".to_string(), name.to_string())])
                .get()
        };
        assert_eq!(event("reclaimed"), 1);
        assert_eq!(event("acked"), 1);
        assert_eq!(event("binary"), 2);
    }

    #[tokio::test]
    async fn test_claim_rejects_malformed_ack_ids() {
        let state = test_state(false);
        state
            .response_buffer
            .store_response(&format!("reply-0-{SURB_A}"), vec![5]);
        let (status, headers, body) = claim_v2(
            IngressServer::router(Arc::clone(&state)),
            serde_json::json!({ "surb_ids": [SURB_A], "ack": ["zz"] }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(headers[CLAIM_VERSION_HEADER], "2");
        assert!(String::from_utf8_lossy(&body).contains("ack[0]"));
        assert_eq!(state.response_buffer.len(), 1);
    }

    fn wait_state(wait_max_ms: u64, slots: usize) -> Arc<IngressState> {
        Arc::new(IngressState {
            event_publisher: Arc::new(MockPublisher { should_fail: false }),
            response_buffer: Arc::new(ResponseBuffer::new()),
            metrics: MetricsService::new(),
            long_poll_timeout: Duration::from_secs(30),
            min_pow_difficulty: 0,
            claim: ClaimSettings::new(Duration::from_millis(wait_max_ms), slots),
        })
    }

    #[tokio::test]
    async fn test_long_poll_times_out_with_204_after_the_capped_wait() {
        let state = wait_state(300, 4);
        let started = Instant::now();
        let (status, headers, _) = claim_v2(
            IngressServer::router(Arc::clone(&state)),
            serde_json::json!({ "surb_ids": [SURB_A], "retain": true, "wait_ms": 60_000 }),
            None,
        )
        .await;
        let elapsed = started.elapsed();
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(headers[CLAIM_WAIT_MAX_HEADER], "300");
        assert!(elapsed >= Duration::from_millis(290), "{elapsed:?}");
        assert!(
            elapsed < Duration::from_secs(5),
            "capped at wait_max: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn test_long_poll_returns_as_soon_as_a_reply_lands() {
        let state = wait_state(10_000, 4);
        let buffer = Arc::clone(&state.response_buffer);
        let store = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            buffer.store_response(&format!("reply-0-{SURB_A}"), vec![42]);
        });
        let started = Instant::now();
        let (status, _, body) = claim_v2(
            IngressServer::router(Arc::clone(&state)),
            serde_json::json!({ "surb_ids": [SURB_A], "retain": true, "wait_ms": 10_000, "encoding": "binary" }),
            None,
        )
        .await;
        store.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(decode_batch(&body)[0].2, vec![42]);
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(140), "{elapsed:?}");
        assert!(
            elapsed < Duration::from_secs(2),
            "woken by the store: {elapsed:?}"
        );
        assert_eq!(state.response_buffer.len(), 1, "retained until acked");
    }

    #[tokio::test]
    async fn test_long_poll_ignores_replies_for_other_ids() {
        let state = wait_state(10_000, 4);
        let buffer = Arc::clone(&state.response_buffer);
        let store = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            buffer.store_response(&format!("reply-0-{SURB_B}"), vec![1]);
            tokio::time::sleep(Duration::from_millis(150)).await;
            buffer.store_response(&format!("reply-0-{SURB_A}"), vec![2]);
        });
        let started = Instant::now();
        let (status, _, body) = claim_v2(
            IngressServer::router(Arc::clone(&state)),
            serde_json::json!({ "surb_ids": [SURB_A], "retain": true, "wait_ms": 10_000, "encoding": "binary" }),
            None,
        )
        .await;
        store.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(decode_batch(&body)[0].2, vec![2]);
        assert!(started.elapsed() >= Duration::from_millis(240));
        assert_eq!(
            state.response_buffer.waiter_registrations(),
            0,
            "the long-poll unregisters when it answers"
        );
    }

    #[tokio::test]
    async fn test_claim_max_replies_returns_the_first_arrival() {
        let state = test_state(false);
        state
            .response_buffer
            .store_response(&format!("reply-0-{SURB_B}"), vec![1]);
        std::thread::sleep(Duration::from_millis(2));
        state
            .response_buffer
            .store_response(&format!("reply-0-{SURB_A}"), vec![2]);
        let (status, headers, body) = claim_v2(
            IngressServer::router(Arc::clone(&state)),
            serde_json::json!({ "surb_ids": [SURB_A, SURB_B], "retain": true, "encoding": "binary", "max_replies": 1 }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[CLAIM_FEATURES_HEADER], CLAIM_FEATURES);
        let items = decode_batch(&body);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].1, format!("reply-0-{SURB_B}"));

        // Ack the reply that decoded the request and its sibling: the
        // sibling is dropped and nothing is left to send.
        let (status, _, _) = claim_v2(
            IngressServer::router(Arc::clone(&state)),
            serde_json::json!({ "surb_ids": [], "ack": [SURB_A, SURB_B], "retain": true }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(state.response_buffer.is_empty());
    }

    #[tokio::test]
    async fn test_ack_ahead_drops_a_sibling_that_arrives_later() {
        let state = test_state(false);
        let (status, _, _) = claim_v2(
            IngressServer::router(Arc::clone(&state)),
            serde_json::json!({ "surb_ids": [], "ack": [SURB_B], "retain": true }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        state
            .response_buffer
            .store_response(&format!("reply-0-{SURB_B}"), vec![9]);
        assert!(state.response_buffer.is_empty(), "acked ahead: dropped");
    }

    #[tokio::test]
    async fn test_wait_needs_retain_and_a_free_slot() {
        let state = wait_state(5_000, 1);
        let started = Instant::now();
        let (status, _, _) = claim_v2(
            IngressServer::router(Arc::clone(&state)),
            serde_json::json!({ "surb_ids": [SURB_A], "wait_ms": 5_000 }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "no wait without retain"
        );

        let _held = state.claim.wait_slots.clone().try_acquire_owned().unwrap();
        let started = Instant::now();
        let (status, _, _) = claim_v2(
            IngressServer::router(Arc::clone(&state)),
            serde_json::json!({ "surb_ids": [SURB_A], "retain": true, "wait_ms": 5_000 }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "no slot: answers at once"
        );
        let busy = state
            .metrics
            .ingress_claim_events_total
            .get_or_create(&vec![("event".to_string(), "wait_busy".to_string())])
            .get();
        assert_eq!(busy, 1);
    }

    #[tokio::test]
    async fn test_stream_base64_encoding() {
        let state = test_state(false);
        state
            .response_buffer
            .store_response(&format!("reply-0-{SURB_A}"), vec![0xfb, 0xff]);
        let app = IngressServer::router(state);
        let req = Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/responses/stream?surb_ids={SURB_A}&encoding=base64"
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("\"data_b64\":\"+/8=\""), "{text}");
    }

    const CLAIM_ITEM_FLAG_RECLAIMED_FOR_TESTS: u8 =
        crate::ingress::claim::CLAIM_ITEM_FLAG_RECLAIMED;
}
