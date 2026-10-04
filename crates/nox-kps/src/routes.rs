//! The route allowlist (PROTOCOL.md §4). It is fixed in code: an operator
//! cannot expose another node route through configuration.
//!
//! | Method | Path | Handled by |
//! |---|---|---|
//! | POST | `/api/v1/packets` | `upstream_ingress` |
//! | POST | `/api/v1/responses/claim` | `upstream_ingress` |
//! | GET | `/topology` | `upstream_topology` (shared cache) |
//! | GET | `/health` | nox-kps (probes `upstream_ingress /health`) |
//! | GET | `/metadata.json` | nox-kps |
//! | GET | `/keccak/<hh>/<62 hex>` | nox-kps bundle store |
//!
//! Unknown paths are `404`, a known path with another method is `405` with
//! `Allow`, and an unknown method is `501`.

use http::Method;

/// Path prefix of the worker-bundle resolver routes (anon-rpc SPEC §4.2).
pub const BUNDLE_PATH_PREFIX: &str = "/keccak/";

/// One allowlisted route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Route {
    Packets,
    Claim,
    Topology,
    Health,
    Metadata,
    Bundle,
}

impl Route {
    /// Every route, in the order `/metadata.json` lists capabilities.
    pub const ALL: [Route; 6] = [
        Route::Metadata,
        Route::Health,
        Route::Packets,
        Route::Claim,
        Route::Topology,
        Route::Bundle,
    ];

    /// Label for metrics and the `/metadata.json` capability list.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Packets => "packets",
            Self::Claim => "claim",
            Self::Topology => "topology",
            Self::Health => "health",
            Self::Metadata => "metadata",
            Self::Bundle => "worker-bundles",
        }
    }

    /// The one method the route serves.
    #[must_use]
    pub fn method(self) -> Method {
        match self {
            Self::Packets | Self::Claim => Method::POST,
            Self::Topology | Self::Health | Self::Metadata | Self::Bundle => Method::GET,
        }
    }

    /// Upstream path for proxied routes.
    #[must_use]
    pub fn upstream_path(self) -> Option<&'static str> {
        match self {
            Self::Packets => Some("/api/v1/packets"),
            Self::Claim => Some("/api/v1/responses/claim"),
            Self::Topology => Some("/topology"),
            Self::Health => Some("/health"),
            Self::Metadata | Self::Bundle => None,
        }
    }
}

/// Result of a route lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    Found(Route),
    /// The path exists with another method; carries the `Allow` value.
    MethodNotAllowed(&'static str),
    NotFound,
}

/// Methods recognised at all; anything else is `501`.
pub const KNOWN_METHODS: &[Method] = &[
    Method::GET,
    Method::HEAD,
    Method::POST,
    Method::PUT,
    Method::DELETE,
    Method::OPTIONS,
    Method::PATCH,
    Method::TRACE,
];

/// Exact-match lookup. `bundles_enabled` controls whether `/keccak/` paths
/// exist at all. Bundle path syntax is checked by the bundle handler, which
/// answers `404` for anything that is not `<hh>/<62 hex>`.
#[must_use]
pub fn lookup(method: &Method, path: &str, bundles_enabled: bool) -> Lookup {
    let route = match path {
        "/api/v1/packets" => Route::Packets,
        "/api/v1/responses/claim" => Route::Claim,
        "/topology" => Route::Topology,
        "/health" => Route::Health,
        "/metadata.json" => Route::Metadata,
        p if bundles_enabled && p.starts_with(BUNDLE_PATH_PREFIX) => Route::Bundle,
        _ => return Lookup::NotFound,
    };
    // HEAD is GET without a body for the locally served documents.
    let head_ok = *method == Method::HEAD && matches!(route, Route::Metadata | Route::Bundle);
    if *method == route.method() || head_ok {
        Lookup::Found(route)
    } else {
        Lookup::MethodNotAllowed(match route {
            Route::Packets | Route::Claim => "POST",
            Route::Topology | Route::Health => "GET",
            Route::Metadata | Route::Bundle => "GET, HEAD",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_matches_only() {
        let found = |m: Method, p: &str| lookup(&m, p, true);
        assert_eq!(
            found(Method::POST, "/api/v1/packets"),
            Lookup::Found(Route::Packets)
        );
        assert_eq!(
            found(Method::POST, "/api/v1/responses/claim"),
            Lookup::Found(Route::Claim)
        );
        assert_eq!(
            found(Method::GET, "/topology"),
            Lookup::Found(Route::Topology)
        );
        assert_eq!(found(Method::GET, "/health"), Lookup::Found(Route::Health));
        assert_eq!(
            found(Method::GET, "/metadata.json"),
            Lookup::Found(Route::Metadata)
        );
        assert_eq!(
            found(Method::HEAD, "/metadata.json"),
            Lookup::Found(Route::Metadata)
        );
        assert_eq!(
            found(Method::GET, "/keccak/ab/cd"),
            Lookup::Found(Route::Bundle)
        );
        for path in [
            "/api/v1/packets/",
            "/api/v1/packet",
            "/api/v1/ws",
            "/api/v1/responses/stream",
            "/api/v1/responses/pending",
            "/api/v1/responses/0011",
            "/metrics",
            "/API/V1/PACKETS",
            "/topology/",
            "/",
            "",
        ] {
            assert_eq!(found(Method::GET, path), Lookup::NotFound, "{path}");
            assert_eq!(found(Method::POST, path), Lookup::NotFound, "{path}");
        }
    }

    #[test]
    fn wrong_method_lists_the_allowed_one() {
        assert_eq!(
            lookup(&Method::GET, "/api/v1/packets", true),
            Lookup::MethodNotAllowed("POST")
        );
        assert_eq!(
            lookup(&Method::HEAD, "/topology", true),
            Lookup::MethodNotAllowed("GET")
        );
        assert_eq!(
            lookup(&Method::POST, "/keccak/ab/cd", true),
            Lookup::MethodNotAllowed("GET, HEAD")
        );
    }

    #[test]
    fn bundle_paths_exist_only_when_enabled() {
        assert_eq!(
            lookup(&Method::GET, "/keccak/ab/cd", false),
            Lookup::NotFound
        );
    }

    #[test]
    fn labels_are_stable() {
        let labels: Vec<_> = Route::ALL.iter().map(|r| r.label()).collect();
        assert_eq!(
            labels,
            [
                "metadata",
                "health",
                "packets",
                "claim",
                "topology",
                "worker-bundles"
            ]
        );
    }
}
