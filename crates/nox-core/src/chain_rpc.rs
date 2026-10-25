//! JSON-RPC transport for the chain providers of the node and the client.
//!
//! Requests go over HTTP/1.1 only (the HTTP/2 stack is never negotiated) with
//! native TLS. A reply is decoded as a JSON-RPC response whatever its HTTP
//! status, so an upstream error object on a 4xx/5xx reply still reaches the
//! caller as a JSON-RPC error.

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

/// Provider type used for every chain RPC endpoint.
pub type ChainProvider = RootProvider;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainRpcError {
    #[error("invalid RPC URL: {0}")]
    InvalidUrl(String),
    #[error("RPC URL has no port and no known default")]
    MissingPort,
    #[error("HTTP/1 RPC client initialization failed: {0}")]
    Client(String),
}

/// HTTP/1 JSON-RPC transport over a configured `reqwest` client.
#[derive(Debug, Clone)]
pub struct Http1Transport {
    client: reqwest::Client,
    url: Url,
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
        let body = response.bytes().await.map_err(TransportErrorKind::custom)?;
        serde_json::from_slice(&body)
            .map_err(|error| TransportError::deser_err(error, String::from_utf8_lossy(&body)))
    }
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

fn rpc_client(client: reqwest::Client, url: Url) -> RpcClient {
    let is_local = guess_local_url(url.as_str());
    RpcClient::new(Http1Transport { client, url }, is_local)
}

/// JSON-RPC client for an operator-configured RPC URL, for providers that add
/// layers (signing, fillers) on top of the transport.
pub fn http1_rpc_client(rpc_url: &str) -> Result<RpcClient, ChainRpcError> {
    let url = rpc_url
        .parse::<Url>()
        .map_err(|error| ChainRpcError::InvalidUrl(error.to_string()))?;
    let client = reqwest::Client::builder()
        .use_native_tls()
        .http1_only()
        .build()
        .map_err(|error| ChainRpcError::Client(error.to_string()))?;
    Ok(rpc_client(client, url))
}

/// Provider for an operator-configured RPC URL.
pub fn http1_provider(rpc_url: &str) -> Result<ChainProvider, ChainRpcError> {
    http1_rpc_client(rpc_url).map(RootProvider::new)
}

/// Provider for a user-supplied RPC URL that already passed the SSRF check.
/// The client connects only to `pinned_ip` (the address that was validated),
/// never follows redirects and ignores proxy environment variables, so a
/// request cannot reach an address that was not validated.
pub fn pinned_http1_provider(url: &Url, pinned_ip: IpAddr) -> Result<ChainProvider, ChainRpcError> {
    let port = url
        .port_or_known_default()
        .ok_or(ChainRpcError::MissingPort)?;
    let mut builder = reqwest::Client::builder()
        .use_native_tls()
        .http1_only()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();
    if let Some(url::Host::Domain(domain)) = url.host() {
        builder = builder.resolve(domain, SocketAddr::new(pinned_ip, port));
    }
    let client = builder
        .build()
        .map_err(|error| ChainRpcError::Client(error.to_string()))?;
    Ok(RootProvider::new(rpc_client(client, url.clone())))
}

/// Whether a transport error is an HTTP client timeout.
#[must_use]
pub fn is_timeout(error: &TransportError) -> bool {
    match error {
        TransportError::Transport(TransportErrorKind::Custom(inner)) => inner
            .downcast_ref::<reqwest::Error>()
            .is_some_and(reqwest::Error::is_timeout),
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
