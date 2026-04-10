//! Client for routing blockchain operations through the Nox mixnet with full IP privacy.

use crate::surb_budget::{
    AdaptiveSurbBudget, SurbBudget, DEFAULT_RPC_SURBS, USABLE_RESPONSE_PER_SURB,
};
use crate::topology_node::TopologyNode;
use ethers::types::{Address, Bytes, Filter, Log, H256, U256};
use nox_core::models::payloads::{decode_payload, encode_payload};

use futures_util::{SinkExt, StreamExt};
use nox_core::traits::transport::PacketTransport;
use nox_core::IEventPublisher;
use nox_core::NoxEvent;
use nox_core::{Fragment, Fragmenter, Reassembler, ReassemblerConfig};
use nox_core::{RelayerPayload, RpcResponse, ServiceRequest};
use nox_crypto::sphinx::packet::{MAX_PAYLOAD_SIZE, PACKET_SIZE};
use nox_crypto::sphinx::surb::{Surb, SurbError, SurbRecovery};
use nox_crypto::sphinx::{build_multi_hop_packet, PathHop, SphinxError};
use parking_lot::RwLock;
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{debug, info, warn};

/// Configuration for `MixnetClient`.
#[derive(Debug, Clone)]
pub struct MixnetClientConfig {
    pub timeout: Duration,
    pub pow_difficulty: u32,
    pub surbs_per_request: usize,
    /// Routes always start with this entry node if set.
    pub entry_node_pubkey: Option<[u8; 32]>,
    /// FEC parity ratio: 0.0=none, 0.3=30% extra parity SURBs (default), 1.0=100%.
    pub default_fec_ratio: f64,
    /// HTTP poll interval (ms) for SURB responses from entry node.
    pub http_poll_interval_ms: u64,
}

impl Default for MixnetClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(300),
            pow_difficulty: 0,
            surbs_per_request: 10,
            entry_node_pubkey: None,
            default_fec_ratio: 0.3,
            http_poll_interval_ms: 25,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BroadcastOptions {
    /// `None` uses exit node's default. SSRF-validated by exit node.
    pub rpc_url: Option<String>,
    /// `None` defaults to `eth_sendRawTransaction`.
    pub rpc_method: Option<String>,
    /// Hint for SURB budget; 0 uses default RPC budget.
    pub expected_response_bytes: usize,
    /// `None` uses `MixnetClientConfig::default_fec_ratio`.
    pub fec_ratio: Option<f64>,
}

/// Errors for `MixnetClient` operations.
#[derive(Debug, Error)]
pub enum MixnetClientError {
    #[error("Request timed out")]
    Timeout,
    #[error("No route available: {0}")]
    NoRoute(String),
    #[error("Packet construction failed: {0}")]
    PacketConstruction(String),
    #[error("SURB construction failed: {0}")]
    SurbConstruction(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("RPC error: {0}")]
    RpcError(String),
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Fragmentation error: {0}")]
    Fragmentation(String),
    #[error("Channel closed")]
    ChannelClosed,
    #[error("Invalid response format")]
    InvalidResponse,
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("SURB budget exceeds forward capacity: {0} fragments needed, max {1}")]
    BudgetExceeded(usize, u32),
    #[error("Transaction rejected by exit node: {0}")]
    TransactionFailed(String),
}

impl From<SphinxError> for MixnetClientError {
    fn from(e: SphinxError) -> Self {
        MixnetClientError::PacketConstruction(e.to_string())
    }
}

impl From<SurbError> for MixnetClientError {
    fn from(e: SurbError) -> Self {
        MixnetClientError::SurbConstruction(e.to_string())
    }
}

impl From<nox_core::InfrastructureError> for MixnetClientError {
    fn from(e: nox_core::InfrastructureError) -> Self {
        MixnetClientError::PacketConstruction(e.to_string())
    }
}

const FORWARD_FRAGMENT_CHUNK_SIZE: usize = MAX_PAYLOAD_SIZE - 32;
/// Max replenishment rounds before giving up (matches SDK).
const MAX_REPLENISHMENT_ROUNDS: u32 = 50;
/// Stall timeout: if no new fragments arrive for this long, trigger replenishment.
const STALL_TIMEOUT: Duration = Duration::from_secs(8);

struct PendingRequest {
    response_tx: oneshot::Sender<Result<Vec<u8>, MixnetClientError>>,
    reassembler: Reassembler,
    created_at: Instant,
    /// Track fragment count for stall detection.
    last_fragment_count: u32,
    last_progress_at: Instant,
    replenishment_rounds: u32,
}

type ResponseReceiver = Arc<RwLock<Option<mpsc::Receiver<(String, Vec<u8>)>>>>;
type SurbRegistry = Arc<RwLock<HashMap<[u8; 16], (u64, SurbRecovery)>>>;
type WsSubscribeSender = Arc<RwLock<Option<mpsc::Sender<Vec<String>>>>>;

pub struct MixnetClient {
    topology: Arc<RwLock<Vec<TopologyNode>>>,
    entry_publisher: Arc<dyn IEventPublisher>,
    transport: Option<Arc<dyn PacketTransport>>,
    entry_url: Option<String>,
    response_rx: ResponseReceiver,
    pending_requests: Arc<RwLock<HashMap<u64, PendingRequest>>>,
    surb_registry: SurbRegistry,
    ws_subscribe_tx: WsSubscribeSender,
    /// `Relaxed` ordering: monotonic counter for unique IDs, no cross-thread deps.
    request_counter: AtomicU64,
    config: MixnetClientConfig,
    packets_sent: AtomicU64,
    responses_received: AtomicU64,
    pub adaptive_budget: AdaptiveSurbBudget,
    /// `request_id` -> path for `NeedMoreSurbs` replenishment.
    replenishment_paths: Arc<RwLock<HashMap<u64, Vec<PathHop>>>>,
}

impl MixnetClient {
    pub fn new(
        topology: Arc<RwLock<Vec<TopologyNode>>>,
        entry_publisher: Arc<dyn IEventPublisher>,
        response_rx: mpsc::Receiver<(String, Vec<u8>)>,
        config: MixnetClientConfig,
    ) -> Self {
        Self {
            topology,
            entry_publisher,
            transport: None,
            entry_url: None,
            response_rx: Arc::new(RwLock::new(Some(response_rx))),
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            surb_registry: Arc::new(RwLock::new(HashMap::new())),
            ws_subscribe_tx: Arc::new(RwLock::new(None)),
            request_counter: AtomicU64::new(0),
            config,
            packets_sent: AtomicU64::new(0),
            responses_received: AtomicU64::new(0),
            adaptive_budget: AdaptiveSurbBudget::new(),
            replenishment_paths: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[must_use]
    pub fn with_transport(
        mut self,
        transport: Arc<dyn PacketTransport>,
        entry_url: String,
    ) -> Self {
        self.transport = Some(transport);
        self.entry_url = Some(entry_url);
        self
    }

    /// Spawned as a background task to process incoming SURB responses.
    pub async fn run_response_loop(&self) {
        let Some(rx) = self.response_rx.write().take() else {
            warn!("Response loop already running or receiver taken");
            return;
        };

        info!("MixnetClient response loop started");

        let cleanup_interval = tokio::time::interval(Duration::from_secs(5));

        // Try WebSocket for production mode, fall back to HTTP polling
        let ws_url = self
            .entry_url
            .as_ref()
            .map(|u| u.replace("http://", "ws://").replace("https://", "wss://") + "/api/v1/ws");

        let ws_stream = if let Some(ref url) = ws_url {
            match tokio_tungstenite::connect_async(url).await {
                Ok((stream, _)) => {
                    info!("WebSocket connected to {url}");
                    Some(stream)
                }
                Err(e) => {
                    warn!("WebSocket connection failed ({e}), falling back to HTTP polling");
                    None
                }
            }
        } else {
            None
        };

        if let Some(ws) = ws_stream {
            self.run_ws_response_loop(rx, ws, cleanup_interval).await;
        } else {
            self.run_poll_response_loop(rx, cleanup_interval).await;
        }
    }

    async fn run_ws_response_loop(
        &self,
        mut rx: mpsc::Receiver<(String, Vec<u8>)>,
        ws: tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        mut cleanup_interval: tokio::time::Interval,
    ) {
        let (mut ws_tx, mut ws_rx) = ws.split();

        // Subscribe all active SURBs
        let ids: Vec<_> = self.surb_registry.read().keys().map(hex::encode).collect();
        if !ids.is_empty() {
            let msg = serde_json::json!({"type": "subscribe", "surb_ids": ids});
            let _ = ws_tx.send(WsMessage::Text(msg.to_string())).await;
        }

        // Channel for new SURB subscriptions from request creation
        let (sub_tx, mut sub_rx) = mpsc::channel::<Vec<String>>(64);
        *self.ws_subscribe_tx.write() = Some(sub_tx);

        loop {
            tokio::select! {
                msg = rx.recv() => {
                    if let Some((packet_id, data)) = msg {
                        self.handle_response(&packet_id, &data).await;
                    } else {
                        break;
                    }
                }
                ws_msg = ws_rx.next() => {
                    match ws_msg {
                        Some(Ok(WsMessage::Text(text))) => {
                            if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&text) {
                                if msg.get("type").and_then(|v| v.as_str()) == Some("response") {
                                    if let (Some(id), Some(data)) = (
                                        msg.get("id").and_then(|v| v.as_str()),
                                        msg.get("data").and_then(|v| v.as_array()),
                                    ) {
                                        let bytes: Vec<_> = data.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect();
                                        self.handle_response(id, &bytes).await;
                                    }
                                }
                            }
                        }
                        Some(Ok(WsMessage::Close(_))) | None => {
                            warn!("WebSocket closed, stopping response loop");
                            break;
                        }
                        _ => {}
                    }
                }
                new_ids = sub_rx.recv() => {
                    if let Some(ids) = new_ids {
                        let msg = serde_json::json!({"type": "subscribe", "surb_ids": ids});
                        let _ = ws_tx.send(WsMessage::Text(msg.to_string())).await;
                    }
                }
                _ = cleanup_interval.tick() => {
                    self.cleanup_stale_requests();
                }
            }
        }
    }

    async fn run_poll_response_loop(
        &self,
        mut rx: mpsc::Receiver<(String, Vec<u8>)>,
        mut cleanup_interval: tokio::time::Interval,
    ) {
        let poll_ms = self.config.http_poll_interval_ms;
        let mut http_poll_interval = tokio::time::interval(Duration::from_millis(poll_ms));

        loop {
            tokio::select! {
                msg = rx.recv() => {
                    if let Some((packet_id, data)) = msg {
                        self.handle_response(&packet_id, &data).await;
                    } else {
                        warn!("MixnetClient response channel closed");
                        break;
                    }
                }
                _ = http_poll_interval.tick(), if self.transport.is_some() => {
                    if let (Some(transport), Some(url)) = (&self.transport, &self.entry_url) {
                        match transport.recv_responses_batch(url).await {
                            Ok(responses) if responses.len() > 10 => {
                                self.handle_responses_parallel(responses).await;
                            }
                            Ok(responses) => {
                                for (id, data) in responses {
                                    self.handle_response(&id, &data).await;
                                }
                            }
                            Err(e) => {
                                warn!("HTTP batch poll failed: {e}");
                            }
                        }
                    }
                }
                _ = cleanup_interval.tick() => {
                    self.cleanup_stale_requests();
                    self.check_stalled_requests().await;
                }
            }
        }
    }

    /// Parallel batch: decrypt via rayon, then feed fragments into reassemblers.
    async fn handle_responses_parallel(&self, responses: Vec<(String, Vec<u8>)>) {
        type DecryptedItem = ([u8; 16], u64, Vec<u8>, String);
        let decrypted: Vec<Option<DecryptedItem>> = {
            let registry = self.surb_registry.read();
            use rayon::prelude::*;
            responses
                .par_iter()
                .map(|(packet_id, data)| {
                    let surb_id_hex = Self::extract_surb_id(packet_id)?;
                    let (request_id, recovery) = registry.get(&surb_id_hex)?;
                    let plain = recovery.decrypt(data).ok()?;
                    Some((surb_id_hex, *request_id, plain, packet_id.clone()))
                })
                .collect()
        };

        for (surb_id, request_id, decrypted_data, packet_id) in decrypted.into_iter().flatten() {
            match decode_payload::<RelayerPayload>(&decrypted_data) {
                Ok(RelayerPayload::ServiceResponse { fragment, .. }) => {
                    self.surb_registry.write().remove(&surb_id);
                    self.responses_received.fetch_add(1, Ordering::Relaxed);
                    self.process_response_fragment(request_id, fragment);
                }
                Ok(RelayerPayload::NeedMoreSurbs { .. }) => {
                    self.surb_registry.write().remove(&surb_id);
                    self.responses_received.fetch_add(1, Ordering::Relaxed);
                    self.handle_response(&packet_id, &decrypted_data).await;
                }
                _ => {
                    debug!("Parallel batch: unknown payload type, skipping");
                }
            }
        }
    }

    /// SURBs consumed only after decrypted data parses (prevents false-positive consumption).
    async fn handle_response(&self, packet_id: &str, data: &[u8]) {
        // O(1) fast path: parse SURB ID from packet_id to avoid trial decryption
        let match_result = if let Some(surb_id_hex) = Self::extract_surb_id(packet_id) {
            let registry = self.surb_registry.read();
            if let Some((request_id, recovery)) = registry.get(&surb_id_hex) {
                match recovery.decrypt(data) {
                    Ok(decrypted) => Some((surb_id_hex, *request_id, decrypted)),
                    Err(_) => None,
                }
            } else {
                None
            }
        } else {
            // Fallback: trial decryption (event-bus path without SURB ID in packet_id)
            let registry = self.surb_registry.read();
            let mut found = None;
            for (surb_id, (request_id, recovery)) in registry.iter() {
                if let Ok(decrypted) = recovery.decrypt(data) {
                    found = Some((*surb_id, *request_id, decrypted));
                    break;
                }
            }
            found
        };

        let Some((surb_id, request_id, decrypted)) = match_result else {
            let pending_count = self.pending_requests.read().len();
            if pending_count > 0 {
                debug!(
                    "SURB response could not be matched/decrypted (data_len={}, pending_count={})",
                    data.len(),
                    pending_count
                );
            } else {
                debug!(
                    "Received response but no pending requests (data_len={})",
                    data.len()
                );
            }
            return;
        };

        match decode_payload::<RelayerPayload>(&decrypted) {
            Ok(RelayerPayload::ServiceResponse {
                request_id: _resp_request_id,
                fragment,
            }) => {
                // Use request_id from SURB registry (mixnet-level), not ServiceResponse's
                self.surb_registry.write().remove(&surb_id);
                self.responses_received.fetch_add(1, Ordering::Relaxed);
                self.process_response_fragment(request_id, fragment);
            }
            Ok(RelayerPayload::NeedMoreSurbs {
                request_id: signal_request_id,
                fragments_remaining,
            }) => {
                self.surb_registry.write().remove(&surb_id);
                self.responses_received.fetch_add(1, Ordering::Relaxed);
                warn!(
                    request_id = signal_request_id,
                    fragments_remaining = fragments_remaining,
                    "Exit node ran out of SURBs -- sending replenishment batch"
                );
                let replenish_request_id = signal_request_id;
                let path_opt = self
                    .replenishment_paths
                    .read()
                    .get(&replenish_request_id)
                    .cloned();
                if let Some(path) = path_opt {
                    let total_surbs = (fragments_remaining as usize).max(DEFAULT_RPC_SURBS);
                    let surbs_per_packet = 40usize; // ~700 B/SURB x 40 = 28 KB < 31 KB payload
                    let max_packets_per_burst = 10usize; // matches SDK
                    let packets_needed = total_surbs
                        .div_ceil(surbs_per_packet)
                        .min(max_packets_per_burst);

                    info!(
                        request_id = replenish_request_id,
                        total_surbs,
                        packets_needed,
                        "Burst replenishment: sending {} packets with {} SURBs total",
                        packets_needed,
                        total_surbs,
                    );

                    let publisher = self.entry_publisher.clone();
                    let transport = self.transport.clone();
                    let entry_url = self.entry_url.clone();
                    let pow = self.config.pow_difficulty;
                    let counter_base = self
                        .request_counter
                        .fetch_add(packets_needed as u64, Ordering::Relaxed);

                    let mut built_packets: Vec<Vec<u8>> = Vec::with_capacity(packets_needed);
                    let mut surbs_allocated = 0;
                    for pkt_idx in 0..packets_needed {
                        let batch_size = surbs_per_packet.min(total_surbs - surbs_allocated);
                        if batch_size == 0 {
                            break;
                        }
                        match self.create_surbs(&path, replenish_request_id, batch_size) {
                            Ok(fresh_surbs) => {
                                surbs_allocated += batch_size;
                                let inner = encode_payload(&ServiceRequest::ReplenishSurbs {
                                    request_id: replenish_request_id,
                                    surbs: fresh_surbs,
                                })
                                .unwrap_or_default();
                                let replenish_payload = RelayerPayload::AnonymousRequest {
                                    inner,
                                    reply_surbs: vec![],
                                };
                                match encode_payload(&replenish_payload) {
                                    Ok(bytes) if bytes.len() < MAX_PAYLOAD_SIZE - 1 => {
                                        match build_multi_hop_packet(&path, &bytes, pow) {
                                            Ok(mut pkt) => {
                                                if pkt.len() < PACKET_SIZE {
                                                    pkt.resize(PACKET_SIZE, 0);
                                                }
                                                built_packets.push(pkt);
                                            }
                                            Err(e) => {
                                                warn!(
                                                    pkt_idx,
                                                    "Replenishment packet {} build failed: {e}",
                                                    pkt_idx
                                                );
                                            }
                                        }
                                    }
                                    Ok(too_large) => {
                                        warn!(
                                            pkt_idx,
                                            payload_len = too_large.len(),
                                            "Replenishment packet {} payload too large ({} bytes), skipping",
                                            pkt_idx, too_large.len()
                                        );
                                    }
                                    Err(e) => {
                                        warn!(
                                            pkt_idx,
                                            "Replenishment packet {} encode failed: {e}", pkt_idx
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(
                                    request_id = replenish_request_id,
                                    pkt_idx,
                                    "Failed to create replenishment SURBs for packet {pkt_idx}: {e}"
                                );
                            }
                        }
                    }

                    if !built_packets.is_empty() {
                        let path_clone = path.clone();
                        tokio::spawn(async move {
                            let _ = &path_clone;
                            let batch_size = 5;
                            let batch_delay = Duration::from_millis(200);
                            for (i, pkt) in built_packets.into_iter().enumerate() {
                                // Pace: pause between batches to avoid overwhelming entry node
                                if i > 0 && i % batch_size == 0 {
                                    tokio::time::sleep(batch_delay).await;
                                }
                                let pkt_id = format!("replenish-{}", counter_base + i as u64);
                                if let (Some(ref tr), Some(ref url)) = (&transport, &entry_url) {
                                    let _ = tr.send_packet(url, &pkt).await;
                                } else {
                                    let _ = publisher.publish(NoxEvent::PacketReceived {
                                        packet_id: pkt_id,
                                        data: pkt.clone(),
                                        size_bytes: pkt.len(),
                                    });
                                }
                            }
                        });
                    }
                } else {
                    warn!(
                        request_id = replenish_request_id,
                        "NeedMoreSurbs received but no path stashed for replenishment"
                    );
                }
            }
            Ok(_) => {
                self.surb_registry.write().remove(&surb_id);
                self.responses_received.fetch_add(1, Ordering::Relaxed);
                debug!("Received non-ServiceResponse payload, ignoring");
            }
            Err(e) => {
                // Backward compat: try raw RpcResponse
                if let Ok(rpc_response) = bincode::deserialize::<RpcResponse>(&decrypted) {
                    self.surb_registry.write().remove(&surb_id);
                    self.responses_received.fetch_add(1, Ordering::Relaxed);
                    match rpc_response.result {
                        Ok(data) => self.complete_request(request_id, Ok(data)),
                        Err(err) => {
                            self.complete_request(
                                request_id,
                                Err(MixnetClientError::RpcError(err)),
                            );
                        }
                    }
                } else {
                    debug!(
                        "Decrypted data failed to parse, keeping SURB (data_len={}): {}",
                        decrypted.len(),
                        e
                    );
                }
            }
        }
    }

    /// Parse SURB ID from `"reply-{request_id}-{32hex_surb_id}"` format.
    fn extract_surb_id(packet_id: &str) -> Option<[u8; 16]> {
        let rest = packet_id.strip_prefix("reply-")?;
        let last_dash = rest.rfind('-')?;
        let hex_part = &rest[last_dash + 1..];
        if hex_part.len() != 32 {
            return None;
        }
        let mut id = [0u8; 16];
        for i in 0..16 {
            id[i] = u8::from_str_radix(&hex_part[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(id)
    }

    fn process_response_fragment(&self, request_id: u64, fragment: Fragment) {
        if let Some(ref fec) = fragment.fec {
            debug!(
                request_id = request_id,
                sequence = fragment.sequence,
                total = fragment.total_fragments,
                data_shards = fec.data_shard_count,
                parity_shards = fragment.total_fragments - fec.data_shard_count,
                is_parity = fragment.sequence >= fec.data_shard_count,
                "Received FEC-protected fragment"
            );
        }

        let mut pending = self.pending_requests.write();
        let Some(request) = pending.get_mut(&request_id) else {
            debug!(request_id = request_id, "Fragment for unknown request");
            return;
        };

        request.last_fragment_count += 1;
        request.last_progress_at = Instant::now();

        match request.reassembler.add_fragment(fragment) {
            Ok(Some(assembled_data)) => {
                let Some(request) = pending.remove(&request_id) else {
                    warn!(
                        request_id = request_id,
                        "Request disappeared between get_mut and remove"
                    );
                    return;
                };
                drop(pending);
                self.cleanup_surbs_for_request(request_id);

                if let Ok(rpc_response) = bincode::deserialize::<RpcResponse>(&assembled_data) {
                    match rpc_response.result {
                        Ok(data) => {
                            let _ = request.response_tx.send(Ok(data));
                            info!(request_id = request_id, "RPC response reassembled");
                        }
                        Err(err) => {
                            let _ = request
                                .response_tx
                                .send(Err(MixnetClientError::RpcError(err)));
                        }
                    }
                } else {
                    debug!(
                        request_id = request_id,
                        data_len = assembled_data.len(),
                        "Response is not RpcResponse, forwarding raw bytes"
                    );
                    let _ = request.response_tx.send(Ok(assembled_data));
                }
            }
            Ok(None) => {
                debug!(
                    request_id = request_id,
                    progress = ?request.reassembler.message_progress(request_id),
                    "Fragment received, awaiting more"
                );
            }
            Err(e) => {
                warn!(request_id = request_id, error = %e, "Fragment reassembly error");
            }
        }
    }

    fn complete_request(&self, request_id: u64, result: Result<Vec<u8>, MixnetClientError>) {
        let mut pending = self.pending_requests.write();
        if let Some(request) = pending.remove(&request_id) {
            let _ = request.response_tx.send(result);
            debug!(request_id = request_id, "Request completed");
        }
        drop(pending);
        self.cleanup_surbs_for_request(request_id);
    }

    fn cleanup_surbs_for_request(&self, request_id: u64) {
        let mut registry = self.surb_registry.write();
        registry.retain(|_, (rid, _)| *rid != request_id);
        self.replenishment_paths.write().remove(&request_id);
    }

    /// Check for stalled requests and trigger replenishment if fragments stopped arriving.
    async fn check_stalled_requests(&self) {
        let stalled: Vec<(u64, u32)> = {
            let mut pending = self.pending_requests.write();
            let now = Instant::now();
            let mut stalled = Vec::new();
            for (id, req) in pending.iter_mut() {
                if req.last_fragment_count > 0
                    && now.duration_since(req.last_progress_at) > STALL_TIMEOUT
                    && req.replenishment_rounds < MAX_REPLENISHMENT_ROUNDS
                {
                    req.replenishment_rounds += 1;
                    req.last_progress_at = now; // reset to avoid rapid re-triggering
                    stalled.push((*id, req.replenishment_rounds));
                }
            }
            stalled
        };

        for (request_id, round) in stalled {
            let path_opt = self.replenishment_paths.read().get(&request_id).cloned();
            if let Some(path) = path_opt {
                let surbs_per_packet = 40usize;
                let total_surbs = DEFAULT_RPC_SURBS * 2; // send a moderate burst
                let packets_needed = total_surbs.div_ceil(surbs_per_packet);

                warn!(
                    request_id,
                    round,
                    packets = packets_needed,
                    "Stall detected -- sending replenishment round {round}"
                );

                let publisher = self.entry_publisher.clone();
                let transport = self.transport.clone();
                let entry_url = self.entry_url.clone();
                let pow = self.config.pow_difficulty;
                let counter_base = self
                    .request_counter
                    .fetch_add(packets_needed as u64, Ordering::Relaxed);

                let mut built_packets = Vec::new();
                let mut surbs_allocated = 0;
                for _ in 0..packets_needed {
                    let batch_size = surbs_per_packet.min(total_surbs - surbs_allocated);
                    if batch_size == 0 {
                        break;
                    }
                    if let Ok(fresh_surbs) = self.create_surbs(&path, request_id, batch_size) {
                        surbs_allocated += batch_size;
                        let inner = encode_payload(&ServiceRequest::ReplenishSurbs {
                            request_id,
                            surbs: fresh_surbs,
                        })
                        .unwrap_or_default();
                        let replenish_payload = RelayerPayload::AnonymousRequest {
                            inner,
                            reply_surbs: vec![],
                        };
                        if let Ok(bytes) = encode_payload(&replenish_payload) {
                            if bytes.len() < MAX_PAYLOAD_SIZE - 1 {
                                if let Ok(mut pkt) = build_multi_hop_packet(&path, &bytes, pow) {
                                    if pkt.len() < PACKET_SIZE {
                                        pkt.resize(PACKET_SIZE, 0);
                                    }
                                    built_packets.push(pkt);
                                }
                            }
                        }
                    }
                }

                if !built_packets.is_empty() {
                    tokio::spawn(async move {
                        let batch_size = 5;
                        let batch_delay = Duration::from_millis(200);
                        for (i, pkt) in built_packets.into_iter().enumerate() {
                            if i > 0 && i % batch_size == 0 {
                                tokio::time::sleep(batch_delay).await;
                            }
                            let pkt_id = format!("stall-replenish-{}", counter_base + i as u64);
                            if let (Some(ref tr), Some(ref url)) = (&transport, &entry_url) {
                                let _ = tr.send_packet(url, &pkt).await;
                            } else {
                                let _ = publisher.publish(NoxEvent::PacketReceived {
                                    packet_id: pkt_id,
                                    data: pkt.clone(),
                                    size_bytes: pkt.len(),
                                });
                            }
                        }
                    });
                }
            }
        }
    }

    fn cleanup_stale_requests(&self) {
        let now = Instant::now();
        let timeout = self.config.timeout;

        let mut pending = self.pending_requests.write();
        let stale_ids: Vec<_> = pending
            .iter()
            .filter(|(_, req)| now.duration_since(req.created_at) > timeout)
            .map(|(id, _)| *id)
            .collect();

        for &id in &stale_ids {
            if let Some(request) = pending.remove(&id) {
                let _ = request.response_tx.send(Err(MixnetClientError::Timeout));
                warn!(request_id = id, "Request timed out");
            }
        }
        drop(pending);

        for &id in &stale_ids {
            self.cleanup_surbs_for_request(id);
        }
    }

    fn select_route(&self) -> Result<Vec<PathHop>, MixnetClientError> {
        let topology = self.topology.read();

        use nox_core::models::topology::layers_for_role;

        let entries: Vec<_> = topology
            .iter()
            .filter(|n| layers_for_role(n.role).contains(&0))
            .collect();
        let mixes: Vec<_> = topology
            .iter()
            .filter(|n| layers_for_role(n.role).contains(&1))
            .collect();
        let exits: Vec<_> = topology
            .iter()
            .filter(|n| layers_for_role(n.role).contains(&2) && (n.role == 2 || n.role == 3))
            .collect();

        if entries.is_empty() && self.config.entry_node_pubkey.is_none() {
            return Err(MixnetClientError::NoRoute(
                "No entry nodes available".into(),
            ));
        }
        if exits.is_empty() {
            return Err(MixnetClientError::NoRoute(
                "No exit-capable nodes available (layer=2, role=Exit|Full)".into(),
            ));
        }

        let mut rng = rand::rngs::OsRng;
        let mut path = Vec::new();

        let entry = if let Some(ref configured_pk) = self.config.entry_node_pubkey {
            // Search all nodes: TopologyManager may reassign layers by address hash
            topology
                .iter()
                .find(|n| n.public_key == *configured_pk)
                .ok_or_else(|| {
                    MixnetClientError::NoRoute("Configured entry node not found in topology".into())
                })?
        } else {
            entries
                .choose(&mut rng)
                .ok_or_else(|| MixnetClientError::NoRoute("Entry node list became empty".into()))?
        };
        path.push(PathHop {
            public_key: x25519_dalek::PublicKey::from(entry.public_key),
            address: entry.address.clone(),
        });

        // Exclude entry node and exit-role nodes from mix candidates.
        // Exit nodes in the mix slot create paths like [entry, exit, exit] where the
        // exit node tries to forward to itself via libp2p, which silently fails.
        if !mixes.is_empty() {
            let eligible_mixes: Vec<_> = mixes
                .iter()
                .filter(|n| n.public_key != entry.public_key)
                .copied()
                .collect();
            let mix_only: Vec<_> = eligible_mixes
                .iter()
                .filter(|n| !exits.iter().any(|e| e.public_key == n.public_key))
                .copied()
                .collect();
            let mix_pool = if mix_only.is_empty() {
                &eligible_mixes
            } else {
                &mix_only
            };
            if let Some(mix) = mix_pool.choose(&mut rng) {
                path.push(PathHop {
                    public_key: x25519_dalek::PublicKey::from(mix.public_key),
                    address: mix.address.clone(),
                });
            } else {
                warn!("No eligible mix nodes (all are the entry node); using 2-hop path");
            }
        }

        let used_keys: Vec<_> = path.iter().map(|h| h.public_key.to_bytes()).collect();
        let eligible_exits: Vec<_> = exits
            .iter()
            .filter(|n| !used_keys.contains(&n.public_key))
            .copied()
            .collect();
        let exit = if let Some(e) = eligible_exits.choose(&mut rng) {
            e
        } else {
            exits
                .choose(&mut rng)
                .ok_or_else(|| MixnetClientError::NoRoute("Exit node list became empty".into()))?
        };
        path.push(PathHop {
            public_key: x25519_dalek::PublicKey::from(exit.public_key),
            address: exit.address.clone(),
        });

        Ok(path)
    }

    fn get_first_hop(&self, path: &[PathHop]) -> String {
        path.first().map(|h| h.address.clone()).unwrap_or_default()
    }

    async fn send_request_with_budget(
        &self,
        payload: RelayerPayload,
        budget: SurbBudget,
        fec_ratio: f64,
    ) -> Result<Vec<u8>, MixnetClientError> {
        let t0 = Instant::now();

        // Smart SURB fill: if request fits in 1 packet, pack remaining space with SURBs.
        // Use the larger of budget-calculated or packet-fill count.
        let budget_surbs = budget.surb_count_with_fec(fec_ratio);
        let inner_bytes = match &payload {
            RelayerPayload::AnonymousRequest { inner, .. } => inner.len(),
            _ => 0,
        };
        let fill_surbs = SurbBudget::fill_remaining_packet(inner_bytes);
        let surb_count = budget_surbs.max(fill_surbs);

        let path = self.select_route()?;

        let request_id: u64 = rand::random();
        let surbs = self.create_surbs(&path, request_id, surb_count)?;
        let t_surbs = t0.elapsed();

        let payload_with_surbs = match payload {
            RelayerPayload::AnonymousRequest { inner, .. } => RelayerPayload::AnonymousRequest {
                inner,
                reply_surbs: surbs,
            },
            other => other,
        };

        let payload_bytes =
            encode_payload(&payload_with_surbs).map_err(MixnetClientError::Serialization)?;

        // Register pending request BEFORE sending (avoids race).
        // Buffer sized to expected response + 20% headroom for FEC/framing.
        let reassembler_buffer = {
            let expected = budget.expected_response_bytes;
            let derived = expected + expected / 5;
            let default_bytes = ReassemblerConfig::default().max_buffer_bytes;
            derived.max(default_bytes)
        };
        let reassembler_config = ReassemblerConfig {
            max_buffer_bytes: reassembler_buffer,
            ..ReassemblerConfig::default()
        };
        let (response_tx, response_rx) = oneshot::channel();
        {
            let mut pending = self.pending_requests.write();
            pending.insert(
                request_id,
                PendingRequest {
                    response_tx,
                    reassembler: Reassembler::new(reassembler_config),
                    created_at: Instant::now(),
                    last_fragment_count: 0,
                    last_progress_at: Instant::now(),
                    replenishment_rounds: 0,
                },
            );
        }
        self.replenishment_paths
            .write()
            .insert(request_id, path.clone());

        let first_hop = self.get_first_hop(&path);
        let counter_id = self.request_counter.fetch_add(1, Ordering::Relaxed);

        if payload_bytes.len() < MAX_PAYLOAD_SIZE - 1 {
            let packet = build_multi_hop_packet(&path, &payload_bytes, self.config.pow_difficulty)?;

            if let (Some(transport), Some(url)) = (&self.transport, &self.entry_url) {
                transport.send_packet(url, &packet).await.map_err(|e| {
                    MixnetClientError::PacketConstruction(format!("HTTP transport: {e}"))
                })?;
            } else {
                self.entry_publisher
                    .publish(NoxEvent::PacketReceived {
                        packet_id: format!("mixnet-{counter_id}"),
                        data: packet,
                        size_bytes: payload_bytes.len(),
                    })
                    .map_err(|_| MixnetClientError::ChannelClosed)?;
            }

            self.packets_sent.fetch_add(1, Ordering::Relaxed);

            debug!(
                request_id = request_id,
                first_hop = %first_hop,
                surbs = surb_count,
                payload_size = payload_bytes.len(),
                "Sent single packet via mixnet"
            );
        } else {
            let fragmenter = Fragmenter::new();
            let fragments = fragmenter
                .fragment(request_id, &payload_bytes, FORWARD_FRAGMENT_CHUNK_SIZE)
                .map_err(|e| MixnetClientError::Fragmentation(e.to_string()))?;

            let num_fragments = fragments.len();

            for (i, frag) in fragments.into_iter().enumerate() {
                let frag_payload = RelayerPayload::Fragment { frag };
                let frag_bytes =
                    encode_payload(&frag_payload).map_err(MixnetClientError::Serialization)?;

                let packet =
                    build_multi_hop_packet(&path, &frag_bytes, self.config.pow_difficulty)?;

                if let (Some(transport), Some(url)) = (&self.transport, &self.entry_url) {
                    transport.send_packet(url, &packet).await.map_err(|e| {
                        MixnetClientError::PacketConstruction(format!("HTTP transport: {e}"))
                    })?;
                } else {
                    self.entry_publisher
                        .publish(NoxEvent::PacketReceived {
                            packet_id: format!("mixnet-{counter_id}-frag-{i}"),
                            data: packet,
                            size_bytes: frag_bytes.len(),
                        })
                        .map_err(|_| MixnetClientError::ChannelClosed)?;
                }
            }

            self.packets_sent
                .fetch_add(num_fragments as u64, Ordering::Relaxed);

            info!(
                request_id = request_id,
                first_hop = %first_hop,
                surbs = surb_count,
                fragments = num_fragments,
                total_bytes = payload_bytes.len(),
                "Sent fragmented request via mixnet"
            );
        }

        let t_sent = t0.elapsed();

        let result = match tokio::time::timeout(self.config.timeout, response_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(MixnetClientError::ChannelClosed),
            Err(_) => {
                self.pending_requests.write().remove(&request_id);
                self.cleanup_surbs_for_request(request_id);
                Err(MixnetClientError::Timeout)
            }
        };
        let t_total = t0.elapsed();
        info!(
            request_id,
            surb_gen_ms = t_surbs.as_millis() as u64,
            send_ms = t_sent.saturating_sub(t_surbs).as_millis() as u64,
            wait_ms = t_total.saturating_sub(t_sent).as_millis() as u64,
            total_ms = t_total.as_millis() as u64,
            surb_count,
            "Request timing breakdown"
        );
        result
    }

    /// Return path: forward path reversed, excluding exit node.
    fn create_surbs(
        &self,
        forward_path: &[PathHop],
        request_id: u64,
        surb_count: usize,
    ) -> Result<Vec<Surb>, MixnetClientError> {
        let return_path: Vec<_> = if forward_path.len() > 1 {
            forward_path[..forward_path.len() - 1]
                .iter()
                .rev()
                .cloned()
                .collect()
        } else {
            forward_path.iter().rev().cloned().collect()
        };

        let pow = self.config.pow_difficulty;
        type SurbResult = Result<([u8; 16], Surb, SurbRecovery), SurbError>;
        let results: Vec<SurbResult> = {
            use rayon::prelude::*;
            (0..surb_count)
                .into_par_iter()
                .map(|_| {
                    let surb_id: [u8; 16] = rand::random();
                    let (surb, recovery) = Surb::new(&return_path, surb_id, pow)?;
                    Ok((surb_id, surb, recovery))
                })
                .collect()
        };

        let mut surbs = Vec::with_capacity(surb_count);
        let mut new_ids = Vec::with_capacity(surb_count);
        let mut registry = self.surb_registry.write();
        for result in results {
            let (surb_id, surb, recovery) = result?;
            new_ids.push(hex::encode(surb_id));
            registry.insert(surb_id, (request_id, recovery));
            surbs.push(surb);
        }
        drop(registry);

        if let Some(tx) = self.ws_subscribe_tx.read().as_ref() {
            let _ = tx.try_send(new_ids);
        }

        Ok(surbs)
    }

    pub async fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, MixnetClientError> {
        self.rpc_call_to(method, params, None).await
    }

    /// RPC call targeting a custom RPC URL (SSRF-validated by exit node).
    pub async fn rpc_call_to(
        &self,
        method: &str,
        params: serde_json::Value,
        rpc_url: Option<String>,
    ) -> Result<serde_json::Value, MixnetClientError> {
        let budget = self.adaptive_budget.budget_for(method);
        let result = self
            .rpc_call_with_budget_and_url(method, params, budget, rpc_url)
            .await;
        if let Ok(ref val) = result {
            let size = serde_json::to_vec(val).map(|v| v.len()).unwrap_or(0);
            self.adaptive_budget.record(method, size);
        }
        result
    }

    pub async fn rpc_call_with_budget(
        &self,
        method: &str,
        params: serde_json::Value,
        budget: SurbBudget,
    ) -> Result<serde_json::Value, MixnetClientError> {
        self.rpc_call_with_budget_and_url(method, params, budget, None)
            .await
    }

    pub async fn rpc_call_with_budget_and_url(
        &self,
        method: &str,
        params: serde_json::Value,
        budget: SurbBudget,
        rpc_url: Option<String>,
    ) -> Result<serde_json::Value, MixnetClientError> {
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed);

        let params_bytes = serde_json::to_vec(&params)
            .map_err(|e| MixnetClientError::Serialization(e.to_string()))?;

        let service_request = ServiceRequest::RpcRequest {
            method: method.to_string(),
            params: params_bytes,
            id: request_id,
            rpc_url,
        };

        let inner = encode_payload(&service_request).map_err(MixnetClientError::Serialization)?;

        let payload = RelayerPayload::AnonymousRequest {
            inner,
            reply_surbs: vec![],
        };

        let response_bytes = self
            .send_request_with_budget(payload, budget, self.config.default_fec_ratio)
            .await?;

        serde_json::from_slice(&response_bytes).map_err(|e| MixnetClientError::Parse(e.to_string()))
    }

    fn build_get_logs_params(filter: &Filter) -> serde_json::Value {
        let address_value = filter.address.as_ref().map(|a| match a {
            ethers::types::ValueOrArray::Value(addr) => serde_json::json!(format!("{:?}", addr)),
            ethers::types::ValueOrArray::Array(addrs) => {
                let addrs_str: Vec<_> = addrs.iter().map(|a| format!("{a:?}")).collect();
                serde_json::json!(addrs_str)
            }
        });

        let topics_value: Vec<_> = filter
            .topics
            .iter()
            .map(|t| match t {
                Some(topic) => match topic {
                    ethers::types::ValueOrArray::Value(Some(h)) => {
                        serde_json::json!(format!("{:?}", h))
                    }
                    ethers::types::ValueOrArray::Value(None) => serde_json::Value::Null,
                    ethers::types::ValueOrArray::Array(arr) => {
                        let hashes: Vec<_> = arr
                            .iter()
                            .filter_map(|h| h.map(|x| format!("{x:?}")))
                            .collect();
                        serde_json::json!(hashes)
                    }
                },
                None => serde_json::Value::Null,
            })
            .collect();

        let mut filter_obj = serde_json::Map::new();

        if let Some(addr) = address_value {
            filter_obj.insert("address".to_string(), addr);
        }

        if let Some(from) = filter.block_option.get_from_block() {
            if let Some(num) = from.as_number() {
                filter_obj.insert(
                    "fromBlock".to_string(),
                    serde_json::json!(format!("0x{:x}", num)),
                );
            }
        }

        if let Some(to) = filter.block_option.get_to_block() {
            if let Some(num) = to.as_number() {
                filter_obj.insert(
                    "toBlock".to_string(),
                    serde_json::json!(format!("0x{:x}", num)),
                );
            }
        }

        if !topics_value.is_empty() && !topics_value.iter().all(serde_json::Value::is_null) {
            filter_obj.insert("topics".to_string(), serde_json::json!(topics_value));
        }

        serde_json::json!([filter_obj])
    }

    pub async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>, MixnetClientError> {
        let params = Self::build_get_logs_params(filter);
        // Use adaptive budget if available, otherwise heuristic from block range
        let budget = {
            let adaptive = self.adaptive_budget.budget_for("eth_getLogs");
            if adaptive.expected_response_bytes > 0 {
                adaptive
            } else {
                Self::estimate_log_budget(filter)
            }
        };
        let result = self
            .rpc_call_with_budget("eth_getLogs", params, budget)
            .await?;

        let logs: Vec<Log> =
            serde_json::from_value(result).map_err(|e| MixnetClientError::Parse(e.to_string()))?;
        let response_size = serde_json::to_vec(&logs).map(|v| v.len()).unwrap_or(0);
        self.adaptive_budget.record("eth_getLogs", response_size);
        Ok(logs)
    }

    pub async fn get_logs_with_budget(
        &self,
        filter: &Filter,
        budget: SurbBudget,
    ) -> Result<Vec<Log>, MixnetClientError> {
        let params = Self::build_get_logs_params(filter);
        let result = self
            .rpc_call_with_budget("eth_getLogs", params, budget)
            .await?;

        serde_json::from_value(result).map_err(|e| MixnetClientError::Parse(e.to_string()))
    }

    /// Heuristic: ~2 events/block * ~500 bytes/event for `DarkPool` contract.
    fn estimate_log_budget(filter: &Filter) -> SurbBudget {
        let block_range = match (
            filter
                .block_option
                .get_from_block()
                .and_then(ethers::types::BlockNumber::as_number),
            filter
                .block_option
                .get_to_block()
                .and_then(ethers::types::BlockNumber::as_number),
        ) {
            (Some(from), Some(to)) => to.saturating_sub(from).as_u64(),
            _ => return SurbBudget::rpc(),
        };

        let estimated_bytes = (block_range as usize) * 2 * 500;

        if estimated_bytes <= USABLE_RESPONSE_PER_SURB * DEFAULT_RPC_SURBS {
            SurbBudget::rpc()
        } else {
            SurbBudget::for_response_size(estimated_bytes)
        }
    }

    pub async fn submit_transaction(
        &self,
        to: Address,
        data: Bytes,
    ) -> Result<H256, MixnetClientError> {
        let service_request = ServiceRequest::SubmitTransaction {
            to: to.0,
            data: data.to_vec(),
        };

        let inner = encode_payload(&service_request).map_err(MixnetClientError::Serialization)?;

        let wrapper = RelayerPayload::AnonymousRequest {
            inner,
            reply_surbs: vec![],
        };

        let budget = self.adaptive_budget.budget_for("submit_transaction");
        let response_bytes = self
            .send_request_with_budget(wrapper, budget, self.config.default_fec_ratio)
            .await?;

        self.adaptive_budget
            .record("submit_transaction", response_bytes.len());
        Self::parse_tx_hash_response(&response_bytes)
    }

    pub async fn broadcast_signed_transaction(
        &self,
        raw_tx: Bytes,
    ) -> Result<H256, MixnetClientError> {
        let service_request = ServiceRequest::BroadcastSignedTransaction {
            signed_tx: raw_tx.to_vec(),
            rpc_url: None,
            rpc_method: None,
        };

        let inner = encode_payload(&service_request).map_err(MixnetClientError::Serialization)?;

        let wrapper = RelayerPayload::AnonymousRequest {
            inner,
            reply_surbs: vec![],
        };

        let budget = self.adaptive_budget.budget_for("broadcast_tx");
        let response_bytes = self
            .send_request_with_budget(wrapper, budget, self.config.default_fec_ratio)
            .await?;

        self.adaptive_budget
            .record("broadcast_tx", response_bytes.len());
        Self::parse_tx_hash_response(&response_bytes)
    }

    /// Broadcast with custom RPC target, method, and response budget.
    pub async fn broadcast_signed_transaction_with_options(
        &self,
        raw_tx: Bytes,
        options: BroadcastOptions,
    ) -> Result<Vec<u8>, MixnetClientError> {
        let service_request = ServiceRequest::BroadcastSignedTransaction {
            signed_tx: raw_tx.to_vec(),
            rpc_url: options.rpc_url,
            rpc_method: options.rpc_method,
        };

        let inner = encode_payload(&service_request).map_err(MixnetClientError::Serialization)?;

        let wrapper = RelayerPayload::AnonymousRequest {
            inner,
            reply_surbs: vec![],
        };

        let budget = if options.expected_response_bytes > 0 {
            SurbBudget::for_response_size(options.expected_response_bytes)
        } else {
            self.adaptive_budget.budget_for("broadcast_tx")
        };

        let fec_ratio = options.fec_ratio.unwrap_or(self.config.default_fec_ratio);
        let result = self
            .send_request_with_budget(wrapper, budget, fec_ratio)
            .await;
        if let Ok(ref data) = result {
            self.adaptive_budget.record("broadcast_tx", data.len());
        }
        result
    }

    /// Check `tx_error:` prefix BEFORE interpreting as raw hash (errors can be >32 bytes).
    fn parse_tx_hash_response(response_bytes: &[u8]) -> Result<H256, MixnetClientError> {
        if let Ok(s) = std::str::from_utf8(response_bytes) {
            if let Some(msg) = s.strip_prefix("tx_error:") {
                return Err(MixnetClientError::TransactionFailed(msg.to_string()));
            }
        }

        if response_bytes.len() >= 32 {
            Ok(H256::from_slice(&response_bytes[..32]))
        } else {
            let hex_str = std::str::from_utf8(response_bytes)
                .map_err(|e| MixnetClientError::Parse(e.to_string()))?
                .trim_start_matches("0x");

            hex_str
                .parse::<H256>()
                .map_err(|e| MixnetClientError::Parse(e.to_string()))
        }
    }

    pub async fn estimate_gas(&self, to: Address, data: Bytes) -> Result<U256, MixnetClientError> {
        let params = serde_json::json!([{
            "to": format!("{:?}", to),
            "data": format!("0x{}", hex::encode(data.as_ref()))
        }]);

        let result = self.rpc_call("eth_estimateGas", params).await?;

        let hex_str = result
            .as_str()
            .ok_or(MixnetClientError::InvalidResponse)?
            .trim_start_matches("0x");

        U256::from_str_radix(hex_str, 16).map_err(|e| MixnetClientError::Parse(e.to_string()))
    }

    pub async fn block_number(&self) -> Result<u64, MixnetClientError> {
        let result = self
            .rpc_call("eth_blockNumber", serde_json::json!([]))
            .await?;

        let hex_str = result
            .as_str()
            .ok_or(MixnetClientError::InvalidResponse)?
            .trim_start_matches("0x");

        u64::from_str_radix(hex_str, 16).map_err(|e| MixnetClientError::Parse(e.to_string()))
    }

    pub async fn get_transaction_receipt(
        &self,
        tx_hash: H256,
    ) -> Result<Option<serde_json::Value>, MixnetClientError> {
        let params = serde_json::json!([format!("{:?}", tx_hash)]);

        let result = self.rpc_call("eth_getTransactionReceipt", params).await?;

        if result.is_null() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    /// Round-trip latency test: exit node echoes data back via SURBs.
    pub async fn send_echo(&self, data: Vec<u8>) -> Result<Vec<u8>, MixnetClientError> {
        let service_request = ServiceRequest::Echo { data };

        let inner = encode_payload(&service_request).map_err(MixnetClientError::Serialization)?;

        let payload = RelayerPayload::AnonymousRequest {
            inner,
            reply_surbs: vec![],
        };

        let budget = self.adaptive_budget.budget_for("echo");
        let result = self
            .send_request_with_budget(payload, budget, self.config.default_fec_ratio)
            .await;
        if let Ok(ref data) = result {
            self.adaptive_budget.record("echo", data.len());
        }
        result
    }

    /// HTTP proxy via mixnet. Returns bincode `SerializableHttpResponse`.
    pub async fn send_http_request(
        &self,
        url: &str,
        method: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        expected_response_bytes: usize,
    ) -> Result<Vec<u8>, MixnetClientError> {
        let service_request = ServiceRequest::HttpRequest {
            method: method.to_string(),
            url: url.to_string(),
            headers,
            body,
        };

        let inner = encode_payload(&service_request).map_err(MixnetClientError::Serialization)?;

        let payload = RelayerPayload::AnonymousRequest {
            inner,
            reply_surbs: vec![],
        };

        // Use explicit size hint if provided, else check adaptive, else default 512KB
        let budget = if expected_response_bytes > 0 {
            SurbBudget::for_response_size(expected_response_bytes)
        } else {
            let adaptive = self.adaptive_budget.budget_for("http_request");
            if adaptive.expected_response_bytes > 0 {
                adaptive
            } else {
                SurbBudget::for_response_size(512 * 1024)
            }
        };

        let result = self
            .send_request_with_budget(payload, budget, self.config.default_fec_ratio)
            .await;
        if let Ok(ref data) = result {
            self.adaptive_budget.record("http_request", data.len());
        }
        result
    }

    pub fn packets_sent(&self) -> u64 {
        self.packets_sent.load(Ordering::Relaxed)
    }

    pub fn responses_received(&self) -> u64 {
        self.responses_received.load(Ordering::Relaxed)
    }

    pub fn pending_count(&self) -> usize {
        self.pending_requests.read().len()
    }

    /// Graceful shutdown: reject all pending requests and clean up SURBs.
    pub fn disconnect(&self) {
        let mut pending = self.pending_requests.write();
        let ids: Vec<_> = pending.keys().copied().collect();
        for id in &ids {
            if let Some(req) = pending.remove(id) {
                let _ = req.response_tx.send(Err(MixnetClientError::ChannelClosed));
            }
        }
        drop(pending);

        self.surb_registry.write().clear();
        self.replenishment_paths.write().clear();

        info!(
            rejected = ids.len(),
            "MixnetClient disconnected: pending requests rejected, SURBs cleared"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nox_core::traits::interfaces::{EventBusError, InfrastructureError};

    struct NoopPublisher;

    impl IEventPublisher for NoopPublisher {
        fn publish(&self, _event: NoxEvent) -> Result<usize, EventBusError> {
            Ok(0)
        }
    }

    struct NoopTransport;

    #[async_trait::async_trait]
    impl PacketTransport for NoopTransport {
        async fn send_packet(&self, _url: &str, _packet: &[u8]) -> Result<(), InfrastructureError> {
            Ok(())
        }

        async fn recv_response(
            &self,
            _url: &str,
            _request_id: &str,
            _timeout: std::time::Duration,
        ) -> Result<Vec<u8>, InfrastructureError> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_config_default() {
        let config = MixnetClientConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(300));
        assert_eq!(config.pow_difficulty, 0);
        assert_eq!(config.surbs_per_request, 10);
        assert!((config.default_fec_ratio - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn test_surb_id_generation() {
        let id1: [u8; 16] = rand::random();
        let id2: [u8; 16] = rand::random();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_adaptive_budget_default_is_rpc() {
        let adaptive = AdaptiveSurbBudget::new();
        let budget = adaptive.budget_for("unknown_op");
        assert_eq!(budget.surb_count(), DEFAULT_RPC_SURBS);
    }

    #[test]
    fn test_estimate_log_budget_small_range() {
        let filter = Filter::new().from_block(100u64).to_block(110u64);
        let budget = MixnetClient::estimate_log_budget(&filter);
        assert_eq!(budget.surb_count(), DEFAULT_RPC_SURBS);
    }

    #[test]
    fn test_estimate_log_budget_large_range() {
        let filter = Filter::new().from_block(100u64).to_block(10_100u64);
        let budget = MixnetClient::estimate_log_budget(&filter);
        let count = budget.surb_count();
        assert!(
            count > DEFAULT_RPC_SURBS,
            "Expected > {} SURBs for 10k block range, got {}",
            DEFAULT_RPC_SURBS,
            count
        );
        assert!(budget.response_capacity() >= 10_000_000);
    }

    #[test]
    fn test_estimate_log_budget_unknown_range() {
        let filter = Filter::new();
        let budget = MixnetClient::estimate_log_budget(&filter);
        assert_eq!(budget.surb_count(), DEFAULT_RPC_SURBS);
    }

    #[test]
    fn test_default_has_no_transport() {
        let topology = Arc::new(RwLock::new(Vec::new()));
        let bus = Arc::new(NoopPublisher);
        let (_tx, rx) = mpsc::channel(1);
        let client = MixnetClient::new(topology, bus, rx, MixnetClientConfig::default());
        assert!(client.transport.is_none());
        assert!(client.entry_url.is_none());
    }

    #[test]
    fn test_with_transport_sets_fields() {
        let topology = Arc::new(RwLock::new(Vec::new()));
        let bus = Arc::new(NoopPublisher);
        let (_tx, rx) = mpsc::channel(1);
        let client = MixnetClient::new(topology, bus, rx, MixnetClientConfig::default())
            .with_transport(Arc::new(NoopTransport), "http://entry:8080".to_string());
        assert!(client.transport.is_some());
        assert_eq!(client.entry_url.as_deref(), Some("http://entry:8080"));
    }

    #[test]
    fn test_select_route_empty_topology_returns_no_route() {
        let topology = Arc::new(RwLock::new(Vec::new()));
        let bus = Arc::new(NoopPublisher);
        let (_tx, rx) = mpsc::channel(1);
        let client = MixnetClient::new(topology, bus, rx, MixnetClientConfig::default());

        let result = client.select_route();
        assert!(
            matches!(result, Err(MixnetClientError::NoRoute(_))),
            "expected NoRoute, got {result:?}"
        );
    }

    fn make_topo_node(pk: [u8; 32], url: &str, layer: u8, role: u8) -> TopologyNode {
        TopologyNode {
            id: hex::encode(pk),
            address: url.to_string(),
            public_key: pk,
            layer,
            eth_address: ethers::types::Address::zero(),
            role,
        }
    }

    #[test]
    fn test_select_route_no_exit_nodes_returns_no_route() {
        let entry = make_topo_node([1u8; 32], "http://entry:8080", 0, 1);
        let mix = make_topo_node([2u8; 32], "http://mix:8081", 1, 1);

        let topology = Arc::new(RwLock::new(vec![entry, mix]));
        let bus = Arc::new(NoopPublisher);
        let (_tx, rx) = mpsc::channel(1);
        let client = MixnetClient::new(topology, bus, rx, MixnetClientConfig::default());

        let result = client.select_route();
        assert!(
            matches!(result, Err(MixnetClientError::NoRoute(_))),
            "expected NoRoute when no exit nodes, got {result:?}"
        );
    }

    #[test]
    fn test_select_route_succeeds_with_full_topology() {
        let entry = make_topo_node([1u8; 32], "http://e:8080", 0, 1);
        let mix = make_topo_node([2u8; 32], "http://m:8081", 1, 1);
        let exit = make_topo_node([3u8; 32], "http://x:8082", 2, 2);

        let topology = Arc::new(RwLock::new(vec![entry, mix, exit]));
        let bus = Arc::new(NoopPublisher);
        let (_tx, rx) = mpsc::channel(1);
        let client = MixnetClient::new(topology, bus, rx, MixnetClientConfig::default());

        let result = client.select_route();
        assert!(result.is_ok(), "expected Ok route, got {result:?}");
        let path = result.unwrap();
        assert!(
            path.len() >= 2 && path.len() <= 3,
            "expected 2-3 hops, got {}",
            path.len()
        );
    }

    #[test]
    fn test_extract_surb_id_valid_format() {
        let id = MixnetClient::extract_surb_id("reply-1234567890-abcdef0123456789abcdef0123456789");
        assert!(id.is_some());
        assert_eq!(id.unwrap()[0], 0xab);
        assert_eq!(id.unwrap()[15], 0x89);
    }

    #[test]
    fn test_extract_surb_id_wrong_prefix_returns_none() {
        let id = MixnetClient::extract_surb_id("send-1234-abcdef0123456789abcdef0123456789");
        assert!(id.is_none(), "non-reply prefix should return None");
    }

    #[test]
    fn test_extract_surb_id_too_short() {
        let id = MixnetClient::extract_surb_id("reply-1234-abcdef");
        assert!(id.is_none());
    }

    #[test]
    fn test_extract_surb_id_no_dashes() {
        let id = MixnetClient::extract_surb_id("nodashes");
        assert!(id.is_none());
    }

    #[test]
    fn test_extract_surb_id_invalid_hex() {
        let id = MixnetClient::extract_surb_id("reply-1234-ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ");
        assert!(id.is_none());
    }

    #[test]
    fn test_extract_surb_id_exact_32_chars() {
        let hex32 = "0123456789abcdef0123456789abcdef";
        assert_eq!(hex32.len(), 32);
        let id = MixnetClient::extract_surb_id(&format!("reply-999-{hex32}"));
        assert!(id.is_some());
    }

    #[test]
    fn test_forward_fragment_chunk_size_constant() {
        const { assert!(FORWARD_FRAGMENT_CHUNK_SIZE > 30_000) };
        const { assert!(FORWARD_FRAGMENT_CHUNK_SIZE < 35_000) };
    }

    #[test]
    fn test_config_timeout_is_300s() {
        let config = MixnetClientConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(300));
    }

    #[test]
    fn test_config_poll_interval_is_25ms() {
        let config = MixnetClientConfig::default();
        assert_eq!(config.http_poll_interval_ms, 25);
    }
}
