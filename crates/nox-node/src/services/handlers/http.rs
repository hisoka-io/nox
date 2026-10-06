//! Secure HTTP proxy for anonymous web requests via SURBs.
//! SSRF protection, DNS rebinding mitigation, optional domain whitelist.

use crate::config::HttpConfig;
use crate::services::response_packer::{PackResult, ResponsePacker, SURB_PAYLOAD_SIZE};
use crate::services::security;
use crate::telemetry::metrics::MetricsService;
use async_trait::async_trait;
use nox_core::events::NoxEvent;
use nox_core::models::payloads::{RelayerPayload, ServiceRequest};
use nox_core::models::wire_id::{reply_wire_id, PacketOrigin};
use nox_core::traits::service::{ServiceError, ServiceHandler};
use nox_core::traits::IEventPublisher;
use nox_crypto::sphinx::surb::Surb;
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Max size for deserializing inner payloads from `AnonymousRequest` (7 MB).
const MAX_INNER_PAYLOAD_SIZE: u64 = 7 * 1024 * 1024;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::debug;
use url::Url;

const USER_AGENT: &str = "Nox-Proxy/1.0";
/// Idle connections kept per upstream host.
const POOL_MAX_IDLE_PER_HOST: usize = 4;
/// TCP keepalive probe interval on upstream connections.
const TCP_KEEPALIVE: Duration = Duration::from_secs(30);
/// A missing HTTP/2 PING answer closes the connection after this long.
const HTTP2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on one warm-up request.
const WARM_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableHttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub truncated: bool,
}

impl SerializableHttpResponse {
    #[must_use]
    pub fn error(status: u16, message: &str) -> Self {
        Self {
            status,
            headers: HashMap::new(),
            body: message.as_bytes().to_vec(),
            truncated: false,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, HandlerError> {
        bincode::serialize(self).map_err(|e| HandlerError::Serialization(e.to_string()))
    }
}

#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("SSRF blocked: {0}")]
    SsrfBlocked(#[from] security::SsrfError),

    #[error("Request failed: {0}")]
    RequestFailed(String),

    #[error("Response too large: {size} bytes")]
    ResponseTooLarge { size: usize },

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Packer error: {0}")]
    PackerError(String),

    #[error("Pack failed: {0}")]
    PackFailed(String),
}

use crate::services::response_packer::{ContinuationState, PendingResponseState};

pub type StashRemainingFn = Arc<dyn Fn(u64, PendingResponseState) + Send + Sync>;

/// Upstream origin a pinned client serves: scheme, host and port.
type OriginKey = (String, String, u16);

/// A client pinned to the validated addresses of one upstream origin. It
/// keeps that origin's TCP+TLS connections (HTTP/2 where offered) warm
/// across requests.
struct PinnedUpstream {
    client: Client,
    /// Every address it may connect to, each one validated (sorted).
    ips: Vec<IpAddr>,
    /// `scheme://host:port/`, the target of warm-up requests.
    origin: String,
    last_used: Instant,
}

pub struct HttpHandler {
    config: HttpConfig,
    packer: Arc<ResponsePacker>,
    publisher: Arc<dyn IEventPublisher>,
    metrics: MetricsService,
    stash_remaining: Option<StashRemainingFn>,
    /// Pinned clients by origin. A client is reused while every address the
    /// host resolves to is one it was pinned to.
    client_cache: parking_lot::Mutex<HashMap<OriginKey, PinnedUpstream>>,
}

impl HttpHandler {
    pub fn new(
        config: HttpConfig,
        packer: Arc<ResponsePacker>,
        publisher: Arc<dyn IEventPublisher>,
        metrics: MetricsService,
    ) -> Self {
        Self {
            config,
            packer,
            publisher,
            metrics,
            stash_remaining: None,
            client_cache: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn with_stash_remaining(mut self, stash: StashRemainingFn) -> Self {
        self.stash_remaining = Some(stash);
        self
    }

    pub async fn handle_http_request(
        &self,
        request_id: u64,
        request: &ServiceRequest,
        surbs: Vec<Surb>,
    ) -> Result<PackResult, HandlerError> {
        let ServiceRequest::HttpRequest {
            method,
            url: url_str,
            headers,
            body,
        } = request
        else {
            return self.pack_error_response(
                request_id,
                502,
                "Invalid request type for HTTP handler",
                surbs,
            );
        };

        // Parse URL
        let url =
            Url::parse(url_str).map_err(|e| HandlerError::InvalidUrl(format!("{url_str}: {e}")))?;

        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return self.pack_error_response(
                request_id,
                400,
                &format!("Unsupported scheme: {scheme}"),
                surbs,
            );
        }

        let host = url
            .host_str()
            .ok_or_else(|| HandlerError::InvalidUrl("No host in URL".into()))?;

        let port = url
            .port_or_known_default()
            .unwrap_or(if scheme == "https" { 443 } else { 80 });

        let resolved_ips = match security::resolve_hostname_all(host, port).await {
            Ok(ips) => ips,
            Err(e) => {
                debug!(request_id = request_id, error = %e, "DNS resolution failed");
                return self.pack_error_response(
                    request_id,
                    502,
                    &format!("DNS resolution failed: {e}"),
                    surbs,
                );
            }
        };

        // Every address the host resolves to must pass: the pinned client may
        // connect to any of them.
        if let Some(e) = resolved_ips
            .iter()
            .find_map(|ip| security::is_ip_allowed(*ip, self.config.allow_private_ips).err())
        {
            debug!(request_id = request_id, error = %e, "SSRF check blocked request");
            self.metrics
                .http_proxy_requests_total
                .get_or_create(&vec![("result".into(), "ssrf_blocked".into())])
                .inc();
            return self.pack_error_response(
                request_id,
                403,
                &format!("Request blocked: {e}"),
                surbs,
            );
        }

        if let Err(e) = security::is_domain_allowed(host, &self.config.allowed_domains) {
            debug!(request_id = request_id, error = %e, "Domain whitelist blocked request");
            return self.pack_error_response(
                request_id,
                403,
                &format!("Domain not allowed: {host}"),
                surbs,
            );
        }

        debug!(
            request_id = request_id,
            method = %method,
            host = %host,
            addresses = resolved_ips.len(),
            "HTTP request validated"
        );

        // DNS-pinned request: preserves TLS/SNI while preventing rebinding.
        let pinned_client = match self.pinned_client(scheme, host, port, &resolved_ips) {
            Ok(client) => client,
            Err(e) => {
                debug!(request_id = request_id, error = %e, "Pinned HTTP client build failed");
                self.metrics
                    .http_proxy_requests_total
                    .get_or_create(&vec![("result".into(), "error".into())])
                    .inc();
                return self.pack_error_response(
                    request_id,
                    500,
                    "Exit HTTP client unavailable",
                    surbs,
                );
            }
        };

        let req_method = method
            .parse::<reqwest::Method>()
            .map_err(|_| HandlerError::RequestFailed(format!("Invalid HTTP method: {method}")))?;

        let mut req_builder = pinned_client.request(req_method, url.as_str());

        for (key, value) in headers {
            let key_lower = key.to_lowercase();
            if key_lower == "host" || key_lower == "user-agent" {
                continue;
            }
            req_builder = req_builder.header(key, value);
        }

        if !body.is_empty() {
            req_builder = req_builder.body(body.clone());
        }

        let response = match req_builder.send().await {
            Ok(resp) => resp,
            Err(e) => {
                debug!(request_id = request_id, error = %e, "HTTP request failed");
                self.metrics
                    .http_proxy_requests_total
                    .get_or_create(&vec![("result".into(), "error".into())])
                    .inc();
                return self.pack_error_response(
                    request_id,
                    502,
                    &format!("Upstream request failed: {e}"),
                    surbs,
                );
            }
        };

        let status = response.status().as_u16();
        let mut response_headers = HashMap::new();
        for (key, value) in response.headers() {
            if let Ok(v) = value.to_str() {
                response_headers.insert(key.as_str().to_string(), v.to_string());
            }
        }

        let max_bytes = self.config.max_response_bytes;

        let content_length = response
            .content_length()
            .map(|cl| cl.min(max_bytes as u64) as usize);

        // Streaming path for large (>10 MB) responses: pipelines download+packing.
        if let Some(body_len) = content_length {
            if body_len > 10 * 1024 * 1024 && surbs.len() > 2 {
                return self
                    .handle_streaming_response(
                        request_id,
                        status,
                        response_headers,
                        response,
                        body_len,
                        surbs,
                    )
                    .await;
            }
        }

        let mut body_bytes: Vec<u8> = Vec::new();
        let mut truncated = false;
        let mut stream = response;

        loop {
            match stream.chunk().await {
                Ok(Some(chunk)) => {
                    let remaining = max_bytes.saturating_sub(body_bytes.len());
                    if remaining == 0 {
                        truncated = true;
                        break;
                    }
                    if chunk.len() > remaining {
                        body_bytes.extend_from_slice(&chunk[..remaining]);
                        truncated = true;
                        break;
                    }
                    body_bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => {
                    debug!(request_id = request_id, error = %e, "Failed to read response body chunk");
                    return self.pack_error_response(
                        request_id,
                        502,
                        &format!("Failed to read response: {e}"),
                        surbs,
                    );
                }
            }
        }

        let body = body_bytes;

        if truncated {
            debug!(
                request_id = request_id,
                original_size = body.len(),
                max_size = self.config.max_response_bytes,
                "Response truncated"
            );
        }

        let http_response = SerializableHttpResponse {
            status,
            headers: response_headers,
            body,
            truncated,
        };

        self.metrics
            .http_proxy_requests_total
            .get_or_create(&vec![("result".into(), "success".into())])
            .inc();

        self.pack_response(request_id, &http_response, surbs)
    }

    /// Pipelines download + encrypt + dispatch instead of buffering the full body.
    async fn handle_streaming_response(
        &self,
        request_id: u64,
        status: u16,
        headers: HashMap<String, String>,
        mut response: reqwest::Response,
        body_len: usize,
        mut surbs: Vec<Surb>,
    ) -> Result<PackResult, HandlerError> {
        use nox_core::protocol::fragmentation::FRAGMENT_OVERHEAD;

        let usable = SURB_PAYLOAD_SIZE.saturating_sub(FRAGMENT_OVERHEAD);

        let header_response = SerializableHttpResponse {
            status,
            headers,
            body: Vec::new(), // placeholder -- we'll replace the body bytes inline
            truncated: false,
        };
        let header_prefix = bincode::serialize(&header_response)
            .map_err(|e| HandlerError::Serialization(e.to_string()))?;
        // bincode Vec<u8> = u64 len + bytes. Trim trailing `u64(0) + bool(false)` (9 bytes).
        let prefix_without_body = &header_prefix[..header_prefix.len() - 9];
        let body_len_bytes = (body_len as u64).to_le_bytes();
        let truncated_byte = [0u8]; // false

        let total_serialized = prefix_without_body.len() + 8 + body_len + truncated_byte.len();
        let total_fragments = total_serialized.div_ceil(usable) as u32;

        debug!(
            request_id,
            body_len,
            total_fragments,
            surbs_available = surbs.len(),
            "Streaming response: {} fragments for {} bytes",
            total_fragments,
            body_len
        );

        let mut header_bytes = Vec::with_capacity(prefix_without_body.len() + 8);
        header_bytes.extend_from_slice(prefix_without_body);
        header_bytes.extend_from_slice(&body_len_bytes);

        let needs_replenishment = (total_fragments as usize) > surbs.len();
        let distress_surb = if needs_replenishment && surbs.len() >= 2 {
            surbs.pop()
        } else {
            None
        };

        let mut buffer = header_bytes;
        let mut sequence: u32 = 0;
        let mut body_read: usize = 0;
        let mut packets_dispatched: usize = 0;
        let max_bytes = self.config.max_response_bytes;

        const ENCRYPT_BATCH: usize = 20;
        let mut pending_chunks: Vec<(Vec<u8>, Surb, u32)> = Vec::with_capacity(ENCRYPT_BATCH);

        let flush_batch = |pending: &mut Vec<(Vec<u8>, Surb, u32)>,
                           packer: &ResponsePacker,
                           publisher: &Arc<dyn IEventPublisher>,
                           req_id: u64,
                           total_frags: u32|
         -> Result<usize, HandlerError> {
            if pending.is_empty() {
                return Ok(0);
            }
            use rayon::prelude::*;
            let results: Vec<Result<_, _>> = pending
                .par_iter()
                .map(|(chunk, surb, seq)| {
                    packer
                        .pack_single_fragment(req_id, chunk, surb, *seq, total_frags)
                        .map_err(|e| HandlerError::PackFailed(e.to_string()))
                })
                .collect();

            let mut dispatched = 0;
            for result in results {
                let packed = result?;
                let _ = publisher.publish(NoxEvent::SendPacket {
                    next_hop_peer_id: packed.first_hop.clone(),
                    packet_id: reply_wire_id(&packed.surb_id),
                    reply_handle: packed.reply_handle(),
                    data: packed.packet_bytes,
                    origin: PacketOrigin::Originated,
                });
                dispatched += 1;
            }
            pending.clear();
            Ok(dispatched)
        };

        let mut surbs_exhausted = false;
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    let remaining = max_bytes.saturating_sub(body_read);
                    if remaining == 0 {
                        break;
                    }
                    let take = chunk.len().min(remaining);
                    buffer.extend_from_slice(&chunk[..take]);
                    body_read += take;

                    if !surbs_exhausted {
                        while buffer.len() >= usable && sequence < total_fragments {
                            if surbs.is_empty() {
                                surbs_exhausted = true;
                                break;
                            }
                            let surb = surbs.remove(0);
                            let fragment_data: Vec<u8> = buffer.drain(..usable).collect();
                            pending_chunks.push((fragment_data, surb, sequence));
                            sequence += 1;
                        }
                    }

                    if pending_chunks.len() >= ENCRYPT_BATCH {
                        packets_dispatched += flush_batch(
                            &mut pending_chunks,
                            &self.packer,
                            &self.publisher,
                            request_id,
                            total_fragments,
                        )?;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    debug!(request_id, error = %e, "Streaming body read failed");
                    break;
                }
            }
        }

        buffer.push(0u8); // truncated = false

        while !buffer.is_empty() && !surbs.is_empty() && sequence < total_fragments {
            let surb = surbs.remove(0);
            let take = buffer.len().min(usable);
            let fragment_data: Vec<u8> = buffer.drain(..take).collect();
            pending_chunks.push((fragment_data, surb, sequence));
            sequence += 1;
        }

        packets_dispatched += flush_batch(
            &mut pending_chunks,
            &self.packer,
            &self.publisher,
            request_id,
            total_fragments,
        )?;

        if let Some(distress) = distress_surb {
            let fragments_remaining = total_fragments - sequence;
            if fragments_remaining > 0 {
                debug!(
                    request_id,
                    packets_dispatched,
                    fragments_remaining,
                    total_fragments,
                    "Streaming partial -- sending NeedMoreSurbs distress signal"
                );

                let distress_packet = self
                    .packer
                    .pack_distress_signal(request_id, fragments_remaining, distress)
                    .map_err(|e| HandlerError::PackFailed(e.to_string()))?;
                let _ = self.publisher.publish(NoxEvent::SendPacket {
                    next_hop_peer_id: distress_packet.first_hop.clone(),
                    packet_id: reply_wire_id(&distress_packet.surb_id),
                    reply_handle: distress_packet.reply_handle(),
                    data: distress_packet.packet_bytes,
                    origin: PacketOrigin::Originated,
                });
                let _ = packets_dispatched + 1; // suppress unused assignment warning

                if let Some(ref stash) = self.stash_remaining {
                    let total_serialized_len =
                        prefix_without_body.len() + 8 + body_len + truncated_byte.len();
                    stash(
                        request_id,
                        PendingResponseState {
                            remaining_data: buffer,
                            continuation: ContinuationState {
                                original_total_fragments: total_fragments,
                                fragments_already_sent: sequence,
                                original_data_len: total_serialized_len,
                            },
                        },
                    );
                }

                self.metrics
                    .http_proxy_requests_total
                    .get_or_create(&vec![("result".into(), "partial_need_more_surbs".into())])
                    .inc();

                return Ok(PackResult {
                    packets: vec![],
                    remaining: None, // Already stashed via callback
                });
            }
        }

        self.metrics
            .http_proxy_requests_total
            .get_or_create(&vec![("result".into(), "success".into())])
            .inc();

        debug!(
            request_id,
            packets_dispatched, total_fragments, "Streaming response complete"
        );

        Ok(PackResult {
            packets: vec![],
            remaining: None,
        })
    }

    fn pack_response(
        &self,
        request_id: u64,
        response: &SerializableHttpResponse,
        surbs: Vec<Surb>,
    ) -> Result<PackResult, HandlerError> {
        let response_bytes = response.to_bytes()?;

        self.packer
            .pack_response(request_id, &response_bytes, surbs)
            .map_err(|e| HandlerError::PackerError(e.to_string()))
    }

    fn pack_error_response(
        &self,
        request_id: u64,
        status: u16,
        message: &str,
        surbs: Vec<Surb>,
    ) -> Result<PackResult, HandlerError> {
        let error_response = SerializableHttpResponse::error(status, message);
        self.pack_response(request_id, &error_response, surbs)
    }
}

#[async_trait]
impl ServiceHandler for HttpHandler {
    fn name(&self) -> &'static str {
        "http"
    }

    async fn handle(&self, packet_id: &str, payload: &RelayerPayload) -> Result<(), ServiceError> {
        match payload {
            RelayerPayload::AnonymousRequest { inner, reply_surbs } => {
                let request: ServiceRequest = nox_core::models::payloads::decode_payload_limited(
                    inner,
                    MAX_INNER_PAYLOAD_SIZE,
                )
                .map_err(ServiceError::ProcessingFailed)?;

                let request_id = {
                    let bytes = packet_id.as_bytes();
                    let mut arr = [0u8; 8];
                    let len = bytes.len().min(8);
                    arr[..len].copy_from_slice(&bytes[..len]);
                    u64::from_le_bytes(arr)
                };

                match &request {
                    ServiceRequest::HttpRequest { .. } => {
                        let pack_result = self
                            .handle_http_request(request_id, &request, reply_surbs.clone())
                            .await
                            .map_err(|e| ServiceError::ProcessingFailed(e.to_string()))?;

                        // Pacing: 20 packets then 5ms yield prevents yamux saturation.
                        const DISPATCH_BATCH: usize = 20;
                        const BATCH_DELAY_MS: u64 = 5;
                        let total_batches = pack_result.packets.len().div_ceil(DISPATCH_BATCH);

                        for (batch_idx, chunk) in
                            pack_result.packets.chunks(DISPATCH_BATCH).enumerate()
                        {
                            for packet in chunk {
                                if let Err(e) = self.publisher.publish(NoxEvent::SendPacket {
                                    next_hop_peer_id: packet.first_hop.clone(),
                                    packet_id: reply_wire_id(&packet.surb_id),
                                    data: packet.packet_bytes.clone(),
                                    reply_handle: packet.reply_handle(),
                                    origin: PacketOrigin::Originated,
                                }) {
                                    debug!(
                                        request_id = request_id,
                                        error = %e,
                                        "Failed to publish HTTP response SendPacket -- reply lost"
                                    );
                                }
                            }
                            if batch_idx + 1 < total_batches {
                                tokio::time::sleep(std::time::Duration::from_millis(
                                    BATCH_DELAY_MS,
                                ))
                                .await;
                            }
                        }

                        if let Some(remaining) = pack_result.remaining {
                            if let Some(ref stash) = self.stash_remaining {
                                debug!(
                                    request_id = request_id,
                                    remaining_bytes = remaining.remaining_data.len(),
                                    seq_offset = remaining.continuation.fragments_already_sent,
                                    "Stashing remaining response state for SURB replenishment"
                                );
                                stash(request_id, remaining);
                            }
                        }

                        debug!(
                            request_id = request_id,
                            "HTTP response packets dispatched to network"
                        );
                        Ok(())
                    }
                    _ => Ok(()),
                }
            }
            _ => Ok(()),
        }
    }
}

impl HttpHandler {
    /// The cached client for this origin when it was pinned to every address
    /// in `resolved_ips` (all already validated); otherwise a new client
    /// pinned to exactly `resolved_ips`, which replaces it.
    fn pinned_client(
        &self,
        scheme: &str,
        host: &str,
        port: u16,
        resolved_ips: &[IpAddr],
    ) -> Result<Client, reqwest::Error> {
        let key: OriginKey = (scheme.to_string(), host.to_string(), port);
        {
            let mut cache = self.client_cache.lock();
            if let Some(entry) = cache.get_mut(&key) {
                if resolved_ips
                    .iter()
                    .all(|ip| entry.ips.binary_search(ip).is_ok())
                {
                    entry.last_used = Instant::now();
                    return Ok(entry.client.clone());
                }
            }
        }
        let addrs: Vec<SocketAddr> = resolved_ips
            .iter()
            .map(|ip| SocketAddr::new(*ip, port))
            .collect();
        let client = build_pinned_client(host, &addrs, &self.config)?;
        debug!(host = %host, addresses = addrs.len(), "New pinned upstream client");
        let mut cache = self.client_cache.lock();
        if !cache.contains_key(&key) && cache.len() >= self.config.max_cached_hosts.max(1) {
            let oldest = cache
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                cache.remove(&oldest);
            }
        }
        let mut ips = resolved_ips.to_vec();
        ips.sort_unstable();
        cache.insert(
            key,
            PinnedUpstream {
                client: client.clone(),
                ips,
                origin: format!("{scheme}://{}/", host_with_port(host, port)),
                last_used: Instant::now(),
            },
        );
        Ok(client)
    }

    /// Sends `HEAD /` to every upstream origin used within
    /// `warm_recent_secs`, through its pinned client, so its pooled
    /// connection stays open between requests. Returns how many answered.
    pub async fn warm_recent_upstreams(&self) -> usize {
        let recent = Duration::from_secs(self.config.warm_recent_secs);
        let targets: Vec<(Client, String)> = self
            .client_cache
            .lock()
            .values()
            .filter(|entry| entry.last_used.elapsed() < recent)
            .map(|entry| (entry.client.clone(), entry.origin.clone()))
            .collect();
        let mut answered = 0;
        for (client, origin) in targets {
            match client
                .head(&origin)
                .timeout(WARM_REQUEST_TIMEOUT)
                .send()
                .await
            {
                Ok(_) => answered += 1,
                Err(e) => debug!(error = %e, "Upstream warm-up request failed"),
            }
        }
        answered
    }

    /// Runs [`HttpHandler::warm_recent_upstreams`] every `warm_interval_secs`
    /// until the handler is dropped. Does nothing when the interval is 0.
    pub fn spawn_upstream_warmer(handler: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        let interval = Duration::from_secs(handler.config.warm_interval_secs);
        if interval.is_zero() {
            return None;
        }
        let weak: Weak<Self> = Arc::downgrade(handler);
        Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(handler) = weak.upgrade() else {
                    break;
                };
                let answered = handler.warm_recent_upstreams().await;
                debug!(answered, "Upstream warm-up round");
            }
        }))
    }

    /// Number of upstream origins with a pinned client.
    #[must_use]
    pub fn cached_upstreams(&self) -> usize {
        self.client_cache.lock().len()
    }
}

/// `host:port`, with IPv6 literals in brackets.
fn host_with_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Client for one validated host: connects only to `pinned_addrs`, never
/// follows redirects and ignores proxy environment variables. Idle
/// connections stay pooled for `pool_idle_timeout_secs`; HTTP/2 connections
/// are kept alive with PINGs.
fn build_pinned_client(
    host: &str,
    pinned_addrs: &[SocketAddr],
    config: &HttpConfig,
) -> Result<Client, reqwest::Error> {
    let mut builder = Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(config.request_timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve_to_addrs(host, pinned_addrs)
        .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST)
        .pool_idle_timeout(Duration::from_secs(config.pool_idle_timeout_secs))
        .tcp_keepalive(TCP_KEEPALIVE)
        .tcp_nodelay(true);
    if config.http2_keep_alive_interval_secs > 0 {
        builder = builder
            .http2_keep_alive_interval(Duration::from_secs(config.http2_keep_alive_interval_secs))
            .http2_keep_alive_timeout(HTTP2_KEEP_ALIVE_TIMEOUT)
            .http2_keep_alive_while_idle(true);
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serializable_http_response() {
        let response = SerializableHttpResponse {
            status: 200,
            headers: HashMap::from([("content-type".into(), "text/plain".into())]),
            body: b"Hello World".to_vec(),
            truncated: false,
        };

        let bytes = response.to_bytes().unwrap();
        let decoded: SerializableHttpResponse = bincode::deserialize(&bytes).unwrap();

        assert_eq!(decoded.status, 200);
        assert_eq!(decoded.body, b"Hello World");
    }

    async fn serve(router: axum::Router) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        addr
    }

    fn test_handler(config: HttpConfig) -> HttpHandler {
        HttpHandler::new(
            config,
            Arc::new(ResponsePacker::new()),
            Arc::new(crate::infra::event_bus::TokioEventBus::new(16)),
            MetricsService::new(),
        )
    }

    #[test]
    fn pinned_clients_are_reused_per_origin_while_addresses_match() {
        let handler = test_handler(HttpConfig {
            max_cached_hosts: 2,
            ..HttpConfig::default()
        });
        let a: IpAddr = "203.0.113.1".parse().expect("ip");
        let b: IpAddr = "203.0.113.2".parse().expect("ip");
        let c: IpAddr = "203.0.113.3".parse().expect("ip");

        handler
            .pinned_client("https", "rpc.example", 443, &[b, a])
            .expect("client");
        // Same set in another order, and a subset: the cached client.
        handler
            .pinned_client("https", "rpc.example", 443, &[a, b])
            .expect("client");
        handler
            .pinned_client("https", "rpc.example", 443, &[b])
            .expect("client");
        assert_eq!(handler.cached_upstreams(), 1);
        let ips = |h: &HttpHandler| {
            h.client_cache
                .lock()
                .get(&("https".to_string(), "rpc.example".to_string(), 443))
                .map(|e| e.ips.clone())
        };
        assert_eq!(ips(&handler), Some(vec![a, b]));

        // A new address replaces the client, pinned to exactly the new set.
        handler
            .pinned_client("https", "rpc.example", 443, &[c])
            .expect("client");
        assert_eq!(ips(&handler), Some(vec![c]));

        // Other origins; the least recently used one is dropped at the cap.
        handler
            .pinned_client("https", "other.example", 443, &[a])
            .expect("client");
        handler
            .pinned_client("http", "rpc.example", 80, &[a])
            .expect("client");
        assert_eq!(handler.cached_upstreams(), 2);
        assert_eq!(ips(&handler), None, "the oldest origin was evicted");
    }

    #[tokio::test]
    async fn warm_up_sends_head_to_recently_used_upstreams() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let heads = Arc::new(AtomicUsize::new(0));
        let counted = heads.clone();
        let upstream = serve(axum::Router::new().route(
            "/",
            axum::routing::head(move || {
                let counted = counted.clone();
                async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    axum::http::StatusCode::OK
                }
            }),
        ))
        .await;
        let handler = test_handler(HttpConfig {
            allow_private_ips: true,
            ..HttpConfig::default()
        });
        handler
            .pinned_client("http", "warm.invalid", upstream.port(), &[upstream.ip()])
            .expect("client");
        assert_eq!(handler.warm_recent_upstreams().await, 1);
        assert_eq!(heads.load(Ordering::SeqCst), 1);

        let idle = test_handler(HttpConfig {
            allow_private_ips: true,
            warm_recent_secs: 0,
            ..HttpConfig::default()
        });
        idle.pinned_client("http", "warm.invalid", upstream.port(), &[upstream.ip()])
            .expect("client");
        assert_eq!(idle.warm_recent_upstreams().await, 0, "not used recently");
    }

    #[tokio::test]
    async fn pinned_client_returns_redirects_instead_of_following_them() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let hits = Arc::new(AtomicUsize::new(0));
        let counted = hits.clone();
        let target = serve(axum::Router::new().route(
            "/",
            axum::routing::any(move || {
                let counted = counted.clone();
                async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    "reached"
                }
            }),
        ))
        .await;
        let location = format!("http://{target}/");
        let redirector = serve(axum::Router::new().route(
            "/",
            axum::routing::any(move || {
                let location = location.clone();
                async move {
                    (
                        axum::http::StatusCode::TEMPORARY_REDIRECT,
                        [(axum::http::header::LOCATION, location)],
                    )
                }
            }),
        ))
        .await;

        let host = "exit-test.invalid";
        let client = build_pinned_client(host, &[redirector], &HttpConfig::default())
            .expect("pinned client");
        let response = client
            .post(format!("http://{host}:{}/", redirector.port()))
            .body("payload")
            .send()
            .await
            .expect("request reaches the pinned address");

        assert_eq!(response.status().as_u16(), 307);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }
}
