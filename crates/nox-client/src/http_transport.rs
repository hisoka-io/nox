//! HTTP-based `PacketTransport`: POST packets to entry nodes, GET long-poll for SURB responses.

use async_trait::async_trait;
use nox_core::traits::interfaces::InfrastructureError;
use nox_core::traits::transport::PacketTransport;
use reqwest::Client;
use std::time::Duration;
use tracing::{debug, warn};

const MAX_SEND_RETRIES: u32 = 3;
const INITIAL_RETRY_DELAY_MS: u64 = 100;

pub struct HttpPacketTransport {
    client: Client,
}

impl Default for HttpPacketTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpPacketTransport {
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }

    #[must_use]
    pub fn with_client(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl PacketTransport for HttpPacketTransport {
    async fn send_packet(&self, entry_url: &str, packet: &[u8]) -> Result<(), InfrastructureError> {
        let url = format!("{entry_url}/api/v1/packets");
        let packet_vec = packet.to_vec();

        for attempt in 0..=MAX_SEND_RETRIES {
            let resp = self.client.post(&url).body(packet_vec.clone()).send().await;

            match resp {
                Ok(r) if r.status().is_success() => {
                    debug!("Sent packet to {url} (status={})", r.status());
                    return Ok(());
                }
                Ok(r) if r.status().is_server_error() && attempt < MAX_SEND_RETRIES => {
                    let status = r.status();
                    warn!(attempt, "Entry node returned {status}, retrying...");
                    let delay = INITIAL_RETRY_DELAY_MS * (1 << attempt);
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                Ok(r) => {
                    let status = r.status();
                    let body = r.text().await.unwrap_or_else(|_| "<no body>".to_string());
                    return Err(InfrastructureError::Network(format!(
                        "Entry node rejected packet: HTTP {status} -- {body}"
                    )));
                }
                Err(e) if attempt < MAX_SEND_RETRIES && e.is_timeout() => {
                    warn!(attempt, "send_packet timeout, retrying...");
                    let delay = INITIAL_RETRY_DELAY_MS * (1 << attempt);
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                Err(e) => {
                    return Err(InfrastructureError::Network(format!(
                        "HTTP send_packet failed: {e}"
                    )));
                }
            }
        }

        Err(InfrastructureError::Network(
            "send_packet: exhausted all retries".into(),
        ))
    }

    async fn recv_response(
        &self,
        entry_url: &str,
        request_id: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>, InfrastructureError> {
        let url = format!("{entry_url}/api/v1/responses/{request_id}");

        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let resp = tokio::time::timeout(Duration::from_secs(35), self.client.get(&url).send())
                .await
                .map_err(|_| {
                    InfrastructureError::Network(format!(
                        "Response poll timed out for request {request_id}"
                    ))
                })?
                .map_err(|e| {
                    InfrastructureError::Network(format!("HTTP recv_response failed: {e}"))
                })?;

            if resp.status().as_u16() == 200 {
                let bytes = resp.bytes().await.map_err(|e| {
                    InfrastructureError::Network(format!("Failed to read response body: {e}"))
                })?;
                debug!(
                    request_id = request_id,
                    bytes = bytes.len(),
                    "Received SURB response via HTTP"
                );
                return Ok(bytes.to_vec());
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(InfrastructureError::Network(format!(
                    "Response poll timed out for request {request_id} (client-side deadline)"
                )));
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    async fn recv_responses_batch(
        &self,
        entry_url: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, InfrastructureError> {
        let url = format!("{entry_url}/api/v1/responses/pending");

        let resp =
            self.client.get(&url).send().await.map_err(|e| {
                InfrastructureError::Network(format!("HTTP batch fetch failed: {e}"))
            })?;

        if resp.status().as_u16() == 204 {
            return Ok(vec![]);
        }

        let items: Vec<BatchResponseItem> = resp.json().await.map_err(|e| {
            InfrastructureError::Network(format!("Failed to parse batch response JSON: {e}"))
        })?;

        debug!(count = items.len(), "Fetched batch SURB responses via HTTP");
        Ok(items.into_iter().map(|item| (item.id, item.data)).collect())
    }
}

#[derive(serde::Deserialize)]
struct BatchResponseItem {
    id: String,
    data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_transport_creation() {
        let transport = HttpPacketTransport::new();
        assert!(std::mem::size_of_val(&transport) > 0);
    }

    #[test]
    fn test_default_trait() {
        let _transport = HttpPacketTransport::default();
    }

    #[test]
    fn test_batch_response_item_deserialization() {
        let json = r#"[{"id":"surb-42","data":[1,2,3,4]}]"#;
        let items: Vec<BatchResponseItem> = serde_json::from_str(json).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "surb-42");
        assert_eq!(items[0].data, vec![1, 2, 3, 4]);
    }
}
