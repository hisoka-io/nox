//! JSON-RPC transport for the chain providers of the node and the client.
//!
//! Requests go over HTTP/1.1 only (the HTTP/2 stack is never negotiated) with
//! native TLS. A reply is decoded as a JSON-RPC response whatever its HTTP
//! status, so an upstream error object on a 4xx/5xx reply still reaches the
//! caller as a JSON-RPC error. Every request carries a timeout and every reply
//! body is read up to a byte limit ([`ChainRpcLimits`]).

use alloy::primitives::{Address, Bytes};
use alloy::providers::{Provider, RootProvider};
use alloy::rpc::client::RpcClient;
use alloy::rpc::json_rpc::{RequestPacket, ResponsePacket};
use alloy::sol_types::SolCall;
use alloy::transports::utils::guess_local_url;
use alloy::transports::{TransportError, TransportErrorKind, TransportFut};
use reqwest::Url;
use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::task::{Context, Poll};
use std::time::Duration;

/// Provider type used for every chain RPC endpoint.
pub type ChainProvider = RootProvider;

/// Default whole-request timeout of a chain RPC call (connect, send, and read
/// the full reply).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Default largest reply body read from a chain RPC endpoint (16 MiB).
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Timeout and reply size limit applied to every request of one chain RPC
/// client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainRpcLimits {
    /// Whole-request timeout, from connect until the last reply byte.
    pub request_timeout: Duration,
    /// Largest reply body accepted; a longer body is refused while it streams.
    pub max_response_bytes: usize,
}

impl Default for ChainRpcLimits {
    fn default() -> Self {
        Self {
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainRpcError {
    #[error("invalid RPC URL: {0}")]
    InvalidUrl(String),
    #[error("RPC URL has no port and no known default")]
    MissingPort,
    #[error("HTTP/1 RPC client initialization failed: {0}")]
    Client(String),
    /// The reply body is longer than [`ChainRpcLimits::max_response_bytes`].
    /// Reading stopped at the limit; the body itself is never kept or shown.
    #[error("RPC reply body exceeds the {limit}-byte response limit; raise the RPC response size limit only for a trusted upstream")]
    ResponseTooLarge { limit: usize },
}

/// HTTP/1 JSON-RPC transport over a configured `reqwest` client.
#[derive(Debug, Clone)]
pub struct Http1Transport {
    client: reqwest::Client,
    url: Url,
    max_response_bytes: usize,
}

impl Http1Transport {
    async fn send(self, request: RequestPacket) -> Result<ResponsePacket, TransportError> {
        let body = serde_json::to_vec(&request).map_err(TransportError::ser_err)?;
        let response = self
            .client
            .post(self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(TransportErrorKind::custom)?;
        let body = read_limited(response, self.max_response_bytes).await?;
        serde_json::from_slice(&body)
            .map_err(|error| TransportError::deser_err(error, String::from_utf8_lossy(&body)))
    }
}

/// Reads a reply body chunk by chunk and stops as soon as it would pass
/// `limit` bytes, so a large or endless body is never buffered whole.
async fn read_limited(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, TransportError> {
    let too_large = || TransportErrorKind::custom(ChainRpcError::ResponseTooLarge { limit });
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(TransportErrorKind::custom)? {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

impl tower::Service<RequestPacket> for Http1Transport {
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        Box::pin(self.clone().send(request))
    }
}

fn rpc_client(client: reqwest::Client, url: Url, limits: ChainRpcLimits) -> RpcClient {
    let is_local = guess_local_url(url.as_str());
    RpcClient::new(
        Http1Transport {
            client,
            url,
            max_response_bytes: limits.max_response_bytes,
        },
        is_local,
    )
}

/// JSON-RPC client for an operator-configured RPC URL, for providers that add
/// layers (signing, fillers) on top of the transport.
pub fn http1_rpc_client(rpc_url: &str, limits: ChainRpcLimits) -> Result<RpcClient, ChainRpcError> {
    let url = rpc_url
        .parse::<Url>()
        .map_err(|error| ChainRpcError::InvalidUrl(error.to_string()))?;
    let client = reqwest::Client::builder()
        .use_native_tls()
        .http1_only()
        .timeout(limits.request_timeout)
        .build()
        .map_err(|error| ChainRpcError::Client(error.to_string()))?;
    Ok(rpc_client(client, url, limits))
}

/// Provider for an operator-configured RPC URL.
pub fn http1_provider(
    rpc_url: &str,
    limits: ChainRpcLimits,
) -> Result<ChainProvider, ChainRpcError> {
    http1_rpc_client(rpc_url, limits).map(RootProvider::new)
}

/// Provider for a user-supplied RPC URL that already passed the SSRF check.
/// The client connects only to `pinned_ip` (the address that was validated),
/// never follows redirects and ignores proxy environment variables, so a
/// request cannot reach an address that was not validated.
pub fn pinned_http1_provider(
    url: &Url,
    pinned_ip: IpAddr,
    limits: ChainRpcLimits,
) -> Result<ChainProvider, ChainRpcError> {
    let port = url
        .port_or_known_default()
        .ok_or(ChainRpcError::MissingPort)?;
    let mut builder = reqwest::Client::builder()
        .use_native_tls()
        .http1_only()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(limits.request_timeout);
    if let Some(url::Host::Domain(domain)) = url.host() {
        builder = builder.resolve(domain, SocketAddr::new(pinned_ip, port));
    }
    let client = builder
        .build()
        .map_err(|error| ChainRpcError::Client(error.to_string()))?;
    Ok(RootProvider::new(rpc_client(client, url.clone(), limits)))
}

/// Whether a transport error is an HTTP client timeout
/// ([`ChainRpcLimits::request_timeout`]).
#[must_use]
pub fn is_timeout(error: &TransportError) -> bool {
    match error {
        TransportError::Transport(TransportErrorKind::Custom(inner)) => inner
            .downcast_ref::<reqwest::Error>()
            .is_some_and(reqwest::Error::is_timeout),
        _ => false,
    }
}

/// Whether a transport error is a reply refused for passing
/// [`ChainRpcLimits::max_response_bytes`].
#[must_use]
pub fn is_response_too_large(error: &TransportError) -> bool {
    match error {
        TransportError::Transport(TransportErrorKind::Custom(inner)) => matches!(
            inner.downcast_ref::<ChainRpcError>(),
            Some(ChainRpcError::ResponseTooLarge { .. })
        ),
        _ => false,
    }
}

/// `eth_call` of a contract function at `block` (latest when `None`), sent as
/// a legacy-typed call object with the calldata under `data`.
pub async fn eth_call<C: SolCall>(
    provider: &ChainProvider,
    to: Address,
    call: &C,
    block: Option<u64>,
) -> Result<C::Return, TransportError> {
    let object = serde_json::json!({
        "type": "0x00",
        "to": format!("{to:?}"),
        "data": format!("0x{}", hex::encode(call.abi_encode())),
    });
    let block = block.map_or_else(|| "latest".to_string(), crate::eth::block_quantity);
    let output: Bytes = provider
        .raw_request(Cow::Borrowed("eth_call"), (object, block))
        .await?;
    C::abi_decode_returns(&output).map_err(|error| {
        TransportError::local_usage_str(&format!(
            "{} returned undecodable data: {error}",
            C::SIGNATURE
        ))
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use alloy::providers::Provider;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const LIMIT: usize = 4096;
    const SHORT_TIMEOUT: Duration = Duration::from_millis(300);

    #[derive(Clone, Copy)]
    enum Reply {
        /// A JSON-RPC result for the request id.
        Normal,
        /// A body one byte over the limit, with a Content-Length header.
        OversizedDeclared,
        /// An endless body with no length, read until the limit trips.
        OversizedStreamed,
        /// No reply at all.
        Silent,
        /// Headers, then a body that never finishes.
        StalledBody,
    }

    /// Reads one HTTP request and returns its JSON-RPC id.
    async fn read_request(stream: &mut TcpStream) -> serde_json::Value {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        let header_end = loop {
            let read = stream.read(&mut chunk).await.expect("read request");
            assert!(read > 0, "client closed before sending a request");
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let headers = String::from_utf8_lossy(&buffer[..header_end]).to_ascii_lowercase();
        let length: usize = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .map(|value| value.trim().parse().expect("content length"))
            .expect("request has a content length");
        while buffer.len() < header_end + length {
            let read = stream.read(&mut chunk).await.expect("read body");
            buffer.extend_from_slice(&chunk[..read]);
        }
        let request: serde_json::Value =
            serde_json::from_slice(&buffer[header_end..header_end + length]).expect("json request");
        request["id"].clone()
    }

    async fn serve(reply: Reply) -> Url {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let id = read_request(&mut stream).await;
                    match reply {
                        Reply::Normal => {
                            let body =
                                serde_json::json!({"jsonrpc": "2.0", "id": id, "result": "0x1"})
                                    .to_string();
                            let head = format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(head.as_bytes()).await;
                            let _ = stream.write_all(body.as_bytes()).await;
                        }
                        Reply::OversizedDeclared => {
                            let head =
                                format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", LIMIT + 1);
                            let _ = stream.write_all(head.as_bytes()).await;
                            let _ = stream.write_all(&vec![b'x'; LIMIT + 1]).await;
                        }
                        Reply::OversizedStreamed => {
                            let _ = stream
                                .write_all(b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n")
                                .await;
                            let filler = vec![b'x'; 512];
                            while stream.write_all(&filler).await.is_ok() {}
                        }
                        Reply::Silent => {
                            tokio::time::sleep(Duration::from_secs(30)).await;
                        }
                        Reply::StalledBody => {
                            let _ = stream
                                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n{")
                                .await;
                            tokio::time::sleep(Duration::from_secs(30)).await;
                        }
                    }
                });
            }
        });
        format!("http://127.0.0.1:{port}").parse().expect("url")
    }

    fn limits() -> ChainRpcLimits {
        ChainRpcLimits {
            request_timeout: SHORT_TIMEOUT,
            max_response_bytes: LIMIT,
        }
    }

    async fn chain_id(provider: &ChainProvider) -> Result<String, TransportError> {
        provider
            .raw_request::<_, String>(Cow::Borrowed("eth_chainId"), ())
            .await
    }

    fn assert_too_large(error: &TransportError) {
        assert!(
            is_response_too_large(error),
            "expected size refusal, got {error}"
        );
        assert!(!is_timeout(error));
        let text = error.to_string();
        assert!(text.contains(&format!("{LIMIT}-byte")), "{text}");
        assert!(
            !text.contains("xxxx"),
            "error must not echo the body: {text}"
        );
    }

    #[tokio::test]
    async fn normal_reply_is_unchanged() {
        let url = serve(Reply::Normal).await;
        let provider = http1_provider(url.as_str(), limits()).expect("provider");
        assert_eq!(chain_id(&provider).await.expect("reply"), "0x1");
        let pinned = pinned_http1_provider(&url, IpAddr::V4(Ipv4Addr::LOCALHOST), limits())
            .expect("pinned provider");
        assert_eq!(chain_id(&pinned).await.expect("reply"), "0x1");
    }

    #[tokio::test]
    async fn reply_over_the_limit_is_refused_by_length() {
        let url = serve(Reply::OversizedDeclared).await;
        let provider = http1_provider(url.as_str(), limits()).expect("provider");
        assert_too_large(&chain_id(&provider).await.expect_err("too large"));
    }

    #[tokio::test]
    async fn streamed_reply_over_the_limit_is_refused_while_reading() {
        let url = serve(Reply::OversizedStreamed).await;
        let provider = pinned_http1_provider(&url, IpAddr::V4(Ipv4Addr::LOCALHOST), limits())
            .expect("pinned provider");
        let error = tokio::time::timeout(Duration::from_secs(5), chain_id(&provider))
            .await
            .expect("refused before the outer timeout")
            .expect_err("too large");
        assert_too_large(&error);
    }

    #[tokio::test]
    async fn silent_upstream_times_out() {
        let url = serve(Reply::Silent).await;
        let provider = http1_provider(url.as_str(), limits()).expect("provider");
        let error = tokio::time::timeout(Duration::from_secs(5), chain_id(&provider))
            .await
            .expect("client timeout fires first")
            .expect_err("timeout");
        assert!(is_timeout(&error), "expected timeout, got {error}");
    }

    #[tokio::test]
    async fn stalled_body_times_out() {
        let url = serve(Reply::StalledBody).await;
        let provider = pinned_http1_provider(&url, IpAddr::V4(Ipv4Addr::LOCALHOST), limits())
            .expect("pinned provider");
        let error = tokio::time::timeout(Duration::from_secs(5), chain_id(&provider))
            .await
            .expect("client timeout fires first")
            .expect_err("timeout");
        assert!(is_timeout(&error), "expected timeout, got {error}");
    }
}
