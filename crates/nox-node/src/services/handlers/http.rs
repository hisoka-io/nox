//! Secure HTTP proxy for anonymous web requests via SURBs.
//! SSRF protection, DNS rebinding mitigation, optional domain whitelist.

use crate::config::HttpConfig;
use crate::services::response_packer::{PackResult, ResponsePacker, SURB_PAYLOAD_SIZE};
use crate::services::security;
use crate::telemetry::metrics::MetricsService;
use async_trait::async_trait;
use nox_core::events::NoxEvent;
use nox_core::models::payloads::{RelayerPayload, ServiceRequest};
use nox_core::traits::service::{ServiceError, ServiceHandler};
use nox_core::traits::IEventPublisher;
use nox_crypto::sphinx::surb::Surb;
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Max size for deserializing inner payloads from `AnonymousRequest` (7 MB).
const MAX_INNER_PAYLOAD_SIZE: u64 = 7 * 1024 * 1024;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, warn};
use url::Url;

const USER_AGENT: &str = "Nox-Proxy/1.0";

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

pub struct HttpHandler {
    config: HttpConfig,
    packer: Arc<ResponsePacker>,
    publisher: Arc<dyn IEventPublisher>,
    metrics: MetricsService,
    stash_remaining: Option<StashRemainingFn>,
    /// Keyed by `(host, resolved_ip)`. Reuses TCP+TLS sessions across requests.
    client_cache: parking_lot::Mutex<HashMap<(String, std::net::IpAddr), Client>>,
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

        let resolved_ip = match security::resolve_hostname(host, port).await {
            Ok(ip) => ip,
            Err(e) => {
                warn!(request_id = request_id, error = %e, "DNS resolution failed");
                return self.pack_error_response(
                    request_id,
                    502,
                    &format!("DNS resolution failed: {e}"),
                    surbs,
                );
            }
        };

        if let Err(e) = security::is_ip_allowed(resolved_ip, self.config.allow_private_ips) {
            warn!(request_id = request_id, error = %e, "SSRF check blocked request");
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
            warn!(request_id = request_id, error = %e, "Domain whitelist blocked request");
            return self.pack_error_response(
                request_id,
                403,
                &format!("Domain not allowed: {host}"),
                surbs,
            );
        }

        info!(
            request_id = request_id,
            method = %method,
            host = %host,
            resolved_ip = %resolved_ip,
            "HTTP request validated"
        );

        // DNS-pinned request: preserves TLS/SNI while preventing rebinding.
        let cache_key = (host.to_string(), resolved_ip);
        let pinned_client = {
            let mut cache = self.client_cache.lock();
            if cache.len() > 256 && !cache.contains_key(&cache_key) {
                let keys: Vec<_> = cache.keys().take(128).cloned().collect();
                for k in keys {
                    cache.remove(&k);
                }
            }
            cache
                .entry(cache_key)
                .or_insert_with(|| {
                    let socket_addr = std::net::SocketAddr::new(resolved_ip, port);
                    Client::builder()
                        .user_agent(USER_AGENT)
                        .timeout(Duration::from_secs(self.config.request_timeout_secs))
                        .redirect(reqwest::redirect::Policy::none())
                        .resolve(host, socket_addr)
                        .pool_max_idle_per_host(4)
                        .pool_idle_timeout(Duration::from_secs(90))
                        .tcp_keepalive(Duration::from_secs(30))
                        .build()
                        .unwrap_or_else(|_| Client::new())
                })
                .clone()
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
                warn!(request_id = request_id, error = %e, "HTTP request failed");
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
                    warn!(request_id = request_id, error = %e, "Failed to read response body chunk");
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

        info!(
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
                    packet_id: format!("reply-{}-{}", req_id, hex::encode(packed.surb_id)),
                    data: packed.packet_bytes,
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
                    warn!(request_id, error = %e, "Streaming body read failed");
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
                info!(
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
                    packet_id: format!(
                        "distress-{}-{}",
                        request_id,
                        hex::encode(distress_packet.surb_id)
                    ),
                    data: distress_packet.packet_bytes,
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

        info!(
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
                                    packet_id: format!(
                                        "reply-{}-{}",
                                        request_id,
                                        hex::encode(packet.surb_id)
                                    ),
                                    data: packet.packet_bytes.clone(),
                                }) {
                                    warn!(
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

                        info!(
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
}
