//! Shared HTTP client settings for upstream price providers.

use crate::error::ProviderError;
use reqwest::Client;
use std::time::Duration;

/// Upper bound on one upstream price request, connect through body.
pub const DEFAULT_PROVIDER_TIMEOUT: Duration = Duration::from_secs(10);

/// Descriptive User-Agent. Some public price APIs refuse requests without one.
pub const PROVIDER_USER_AGENT: &str = concat!(
    "nox-price-server/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/hisoka-io/nox)"
);

/// Builds the client shared by all providers: descriptive User-Agent and a total timeout.
pub fn provider_client(timeout: Duration) -> Result<Client, ProviderError> {
    Client::builder()
        .user_agent(PROVIDER_USER_AGENT)
        .timeout(timeout)
        .build()
        .map_err(ProviderError::Network)
}

/// Client used by the convenience constructors. Falls back to a client that still carries
/// the User-Agent if the TLS backend cannot be configured with a timeout.
#[must_use]
pub fn default_provider_client() -> Client {
    provider_client(DEFAULT_PROVIDER_TIMEOUT).unwrap_or_else(|_| {
        Client::builder()
            .user_agent(PROVIDER_USER_AGENT)
            .build()
            .unwrap_or_default()
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn provider_client_sends_descriptive_user_agent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header("user-agent", PROVIDER_USER_AGENT))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let client = provider_client(DEFAULT_PROVIDER_TIMEOUT).unwrap();
        let status = client.get(server.uri()).send().await.unwrap().status();
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn provider_client_times_out_on_a_hung_upstream() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&server)
            .await;

        let client = provider_client(Duration::from_millis(200)).unwrap();
        let error = client.get(server.uri()).send().await.unwrap_err();
        assert!(error.is_timeout(), "expected timeout, got {error}");
    }
}
