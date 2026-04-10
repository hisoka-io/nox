use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use chrono::Utc;
use std::collections::HashMap;

use crate::types::{OracleConfig, PriceCache, PriceEntry};

#[derive(Clone)]
pub struct PriceServerState {
    pub cache: PriceCache,
    pub config: OracleConfig,
}

pub fn router(state: PriceServerState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/prices", get(get_prices))
        .with_state(state)
}

async fn health_check(State(state): State<PriceServerState>) -> (StatusCode, String) {
    let cache = state.cache.read().await;
    if cache.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, "No data yet".to_string());
    }

    let now = Utc::now();
    let staleness_limit = chrono::Duration::seconds(state.config.staleness_threshold_secs);

    let is_healthy = cache
        .values()
        .any(|entry| now.signed_duration_since(entry.last_updated) < staleness_limit);

    if is_healthy {
        (StatusCode::OK, "Healthy".to_string())
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "Stale Data".to_string())
    }
}

async fn get_prices(State(state): State<PriceServerState>) -> Json<HashMap<String, PriceEntry>> {
    let cache = state.cache.read().await;
    Json(cache.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use chrono::{Duration, Utc};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    fn make_state(entries: Vec<(&str, f64, chrono::DateTime<Utc>)>) -> PriceServerState {
        let mut map = HashMap::new();
        for (asset, price, timestamp) in entries {
            map.insert(
                asset.to_string(),
                PriceEntry {
                    price,
                    last_updated: timestamp,
                    source: "test".to_string(),
                },
            );
        }
        PriceServerState {
            cache: Arc::new(RwLock::new(map)),
            config: OracleConfig::default(),
        }
    }

    #[tokio::test]
    async fn test_health_fresh_data() {
        let state = make_state(vec![("ethereum", 3000.0, Utc::now())]);
        let app = router(state);

        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Healthy");
    }

    #[tokio::test]
    async fn test_health_stale_data() {
        // staleness_threshold_secs defaults to 300 (5 min). Set timestamp 10 min ago.
        let stale_time = Utc::now() - Duration::seconds(600);
        let state = make_state(vec![("ethereum", 3000.0, stale_time)]);
        let app = router(state);

        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Stale Data");
    }

    #[tokio::test]
    async fn test_health_empty_cache() {
        let state = make_state(vec![]);
        let app = router(state);

        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"No data yet");
    }

    #[tokio::test]
    async fn test_prices_endpoint() {
        let now = Utc::now();
        let state = make_state(vec![("ethereum", 3000.0, now), ("bitcoin", 60000.0, now)]);
        let app = router(state);

        let resp = app
            .oneshot(Request::get("/prices").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let prices: HashMap<String, PriceEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(prices.len(), 2);
        assert!((prices["ethereum"].price - 3000.0).abs() < f64::EPSILON);
        assert!((prices["bitcoin"].price - 60000.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_prices_empty() {
        let state = make_state(vec![]);
        let app = router(state);

        let resp = app
            .oneshot(Request::get("/prices").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let prices: HashMap<String, PriceEntry> = serde_json::from_slice(&body).unwrap();
        assert!(prices.is_empty());
    }

    #[tokio::test]
    async fn test_health_mixed_fresh_and_stale() {
        let stale_time = Utc::now() - Duration::seconds(600);
        let state = make_state(vec![
            ("ethereum", 3000.0, stale_time), // stale
            ("bitcoin", 60000.0, Utc::now()), // fresh
        ]);
        let app = router(state);

        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        // At least one fresh price -> healthy
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
