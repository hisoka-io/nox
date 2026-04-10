//! Cluster discovery API for local simulation (`GET /cluster`). Not used in production.

use axum::{extract::State, routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{error, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: String,
    pub address: String,
    pub role: u8,
    pub layer: u8,
    pub admin_port: u16,
    pub ingress_port: u16,
    pub p2p_addr: String,
}

pub type ClusterState = Arc<RwLock<Vec<NodeInfo>>>;

#[derive(Debug, Serialize)]
struct ClusterResponse {
    node_count: usize,
    nodes: Vec<NodeInfo>,
}

async fn handle_cluster(State(state): State<ClusterState>) -> Json<ClusterResponse> {
    let nodes = state.read().await.clone();
    let node_count = nodes.len();
    Json(ClusterResponse { node_count, nodes })
}

pub async fn spawn_cluster_api(port: u16) -> ClusterState {
    let state: ClusterState = Arc::new(RwLock::new(Vec::new()));

    let app = Router::new()
        .route("/cluster", get(handle_cluster))
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::predicate(|origin, _| {
                    origin
                        .to_str()
                        .map(|s| {
                            let lower = s.to_lowercase();
                            lower.starts_with("http://localhost")
                                || lower.starts_with("http://127.0.0.1")
                                || lower.starts_with("https://localhost")
                                || lower.starts_with("https://127.0.0.1")
                        })
                        .unwrap_or(false)
                }))
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .with_state(state.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Cluster discovery API: http://{}/cluster", addr);

    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => {
                if let Err(e) = axum::serve(listener, app).await {
                    error!("Cluster API server error: {}", e);
                }
            }
            Err(e) => error!("Failed to bind cluster API port {}: {}", port, e),
        }
    });

    state
}
