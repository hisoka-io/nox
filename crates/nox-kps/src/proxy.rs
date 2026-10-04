//! Forwarding allowlisted exchanges to the node's loopback HTTP services.
//!
//! The upstream request is built from scratch: method and path from the
//! route, the client's body, an allowlist of request headers, and the
//! client-IP header set from the KPS connection's observed source address.
//! Nothing else the client sent (forwarding headers, hop-by-hop headers,
//! `Host`) reaches the node. The response is buffered up to a cap and copied
//! back with an allowlist of headers and an exact `Content-Length`.

use std::net::IpAddr;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderValue};
use http::uri::PathAndQuery;
use http::{request, Request, Response, StatusCode, Uri, Version};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};

use crate::config::{ProxySettings, Route};
use crate::error::ProxyError;

/// A pooled HTTP/1.1 client for the loopback upstreams.
#[derive(Debug, Clone)]
pub struct UpstreamClient {
    client: Client<HttpConnector, Full<Bytes>>,
    settings: ProxySettings,
}

/// The parts of an upstream response relayed to the client.
#[derive(Debug)]
pub struct UpstreamResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl UpstreamClient {
    #[must_use]
    pub fn new(settings: ProxySettings) -> Self {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(settings.connect_timeout));
        connector.set_nodelay(true);
        connector.enforce_http(true);
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(settings.pool_idle_timeout)
            .pool_max_idle_per_host(settings.pool_max_idle)
            .build(connector);
        Self { client, settings }
    }

    #[must_use]
    pub fn settings(&self) -> &ProxySettings {
        &self.settings
    }

    /// Sends one exchange to `route.upstream`, bounded by the upstream timeout
    /// (connect, request and the whole response body).
    pub async fn forward(
        &self,
        route: &Route,
        client: &request::Parts,
        body: Bytes,
        client_ip: IpAddr,
    ) -> Result<UpstreamResponse, ProxyError> {
        let req = build_upstream_request(route, client, body, client_ip, &self.settings)?;
        let upstream = route.upstream.name.clone();
        let exchange = async {
            let res = self.client.request(req).await.map_err(|e| {
                if e.is_connect() {
                    ProxyError::Connect {
                        upstream: upstream.clone(),
                        authority: route.upstream.authority.to_string(),
                        reason: error_chain(&e),
                    }
                } else {
                    ProxyError::Upstream {
                        upstream: upstream.clone(),
                        reason: error_chain(&e),
                    }
                }
            })?;
            let (parts, incoming) = res.into_parts();
            let limit = self.settings.max_response_body_bytes;
            let body = Limited::new(incoming, limit)
                .collect()
                .await
                .map_err(|e| {
                    if e.downcast_ref::<http_body_util::LengthLimitError>()
                        .is_some()
                    {
                        ProxyError::ResponseTooLarge {
                            upstream: upstream.clone(),
                            limit,
                        }
                    } else {
                        ProxyError::Upstream {
                            upstream: upstream.clone(),
                            reason: e.to_string(),
                        }
                    }
                })?
                .to_bytes();
            Ok(UpstreamResponse {
                status: parts.status,
                headers: filter_response_headers(&parts.headers, &self.settings),
                body,
            })
        };
        tokio::time::timeout(self.settings.timeout, exchange)
            .await
            .map_err(|_| ProxyError::Timeout {
                upstream: route.upstream.name.clone(),
                timeout_ms: self.settings.timeout.as_millis(),
            })?
    }
}

/// The request sent upstream. Only the route's upstream, the client's path
/// and query, allowlisted headers, the body and the client-IP header are
/// carried over.
pub fn build_upstream_request(
    route: &Route,
    client: &request::Parts,
    body: Bytes,
    client_ip: IpAddr,
    settings: &ProxySettings,
) -> Result<Request<Full<Bytes>>, ProxyError> {
    let build_err = |reason: String| ProxyError::BuildRequest {
        upstream: route.upstream.name.clone(),
        reason,
    };
    let path_and_query = match client.uri.query() {
        Some(q) => format!("{}?{q}", route.path),
        None => route.path.clone(),
    };
    let path_and_query: PathAndQuery = path_and_query
        .parse()
        .map_err(|e: http::uri::InvalidUri| build_err(e.to_string()))?;
    let uri = Uri::builder()
        .scheme(route.upstream.scheme.clone())
        .authority(route.upstream.authority.clone())
        .path_and_query(path_and_query)
        .build()
        .map_err(|e| build_err(e.to_string()))?;

    let mut req = Request::new(Full::new(body));
    *req.method_mut() = route.method.clone();
    *req.uri_mut() = uri;
    *req.version_mut() = Version::HTTP_11;
    let headers = req.headers_mut();
    headers.insert(header::HOST, route.upstream.host_header.clone());
    for name in &settings.forward_request_headers {
        for value in client.headers.get_all(name) {
            headers.append(name.clone(), value.clone());
        }
    }
    let ip = HeaderValue::from_str(&client_ip.to_canonical().to_string())
        .map_err(|e| build_err(e.to_string()))?;
    headers.insert(settings.client_ip_header.clone(), ip);
    Ok(req)
}

/// Upstream headers relayed to the client: the configured allowlist only.
/// Framing headers are always set by nox-kps itself.
#[must_use]
pub fn filter_response_headers(upstream: &HeaderMap, settings: &ProxySettings) -> HeaderMap {
    let mut out = HeaderMap::new();
    for name in &settings.forward_response_headers {
        for value in upstream.get_all(name) {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

/// Builds the client-facing response from an upstream answer.
#[must_use]
pub fn into_client_response(upstream: UpstreamResponse) -> Response<Full<Bytes>> {
    let mut res = Response::new(Full::new(upstream.body));
    *res.status_mut() = upstream.status;
    *res.headers_mut() = upstream.headers;
    res
}

fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut msg = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        source = s.source();
    }
    msg
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use http::Method;

    use super::*;
    use crate::config::RawConfig;

    fn settings_and_route(name: &str) -> (ProxySettings, Route) {
        let s = RawConfig::default().validate().unwrap();
        let route = s.routes.iter().find(|r| r.name == name).unwrap().clone();
        (s.proxy, route)
    }

    fn client_parts(uri: &str, headers: &[(&str, &str)]) -> request::Parts {
        let mut b = Request::builder().method(Method::POST).uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    #[test]
    fn rebuilds_the_request_with_only_allowed_headers() {
        let (settings, route) = settings_and_route("nox-packets");
        let parts = client_parts(
            "/api/v1/packets",
            &[
                ("host", "uEiCerthash"),
                ("content-type", "application/octet-stream"),
                ("x-forwarded-for", "6.6.6.6"),
                ("x-real-ip", "6.6.6.6"),
                ("forwarded", "for=6.6.6.6"),
                ("cookie", "a=b"),
                ("connection", "x-secret"),
                ("x-secret", "1"),
                ("content-length", "4"),
            ],
        );
        let req = build_upstream_request(
            &route,
            &parts,
            Bytes::from_static(b"body"),
            "203.0.113.9".parse().unwrap(),
            &settings,
        )
        .unwrap();
        assert_eq!(req.method(), Method::POST);
        assert_eq!(
            req.uri().to_string(),
            "http://127.0.0.1:15002/api/v1/packets"
        );
        let h = req.headers();
        assert_eq!(h.get("host").unwrap(), "127.0.0.1:15002");
        assert_eq!(h.get("content-type").unwrap(), "application/octet-stream");
        assert_eq!(h.get_all("x-forwarded-for").iter().count(), 1);
        assert_eq!(h.get("x-forwarded-for").unwrap(), "203.0.113.9");
        for absent in [
            "x-real-ip",
            "forwarded",
            "cookie",
            "connection",
            "x-secret",
            "content-length",
        ] {
            assert!(h.get(absent).is_none(), "{absent} must not be forwarded");
        }
    }

    #[test]
    fn client_ip_is_canonical_and_ipv6_is_unbracketed() {
        let (settings, route) = settings_and_route("nox-topology");
        let parts = client_parts("/topology?fresh=1", &[]);
        let req = build_upstream_request(
            &route,
            &parts,
            Bytes::new(),
            "::ffff:198.51.100.4".parse().unwrap(),
            &settings,
        )
        .unwrap();
        assert_eq!(
            req.headers().get("x-forwarded-for").unwrap(),
            "198.51.100.4"
        );
        assert_eq!(
            req.uri().to_string(),
            "http://127.0.0.1:15003/topology?fresh=1"
        );
        let req = build_upstream_request(
            &route,
            &parts,
            Bytes::new(),
            "2001:db8::9".parse().unwrap(),
            &settings,
        )
        .unwrap();
        assert_eq!(req.headers().get("x-forwarded-for").unwrap(), "2001:db8::9");
    }

    #[test]
    fn response_headers_are_allowlisted() {
        let (settings, _) = settings_and_route("nox-packets");
        let mut upstream = HeaderMap::new();
        upstream.insert("content-type", HeaderValue::from_static("application/json"));
        upstream.insert("x-nox-version", HeaderValue::from_static("0.4.0-rc.4"));
        upstream.insert("retry-after", HeaderValue::from_static("1"));
        upstream.insert("set-cookie", HeaderValue::from_static("s=1"));
        upstream.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        upstream.insert("content-length", HeaderValue::from_static("99"));
        upstream.insert("access-control-allow-origin", HeaderValue::from_static("*"));
        let out = filter_response_headers(&upstream, &settings);
        assert_eq!(out.len(), 3);
        assert!(out.get("set-cookie").is_none());
        assert!(out.get("transfer-encoding").is_none());
        assert!(out.get("content-length").is_none());
    }
}
