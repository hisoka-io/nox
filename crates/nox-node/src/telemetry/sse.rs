//! SSE streaming endpoint (`GET /events`). Privacy-safe: no raw packet data or IDs.

use axum::extract::Extension;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::stream::{self, Stream};
use nox_core::events::NoxEvent;
use nox_core::traits::IEventSubscriber;
use serde::Serialize;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SsePayload {
    NodeStarted {
        timestamp: u64,
        node_id: String,
    },
    PeerConnected {
        peer_id: String,
        node_id: String,
    },
    PeerDisconnected {
        peer_id: String,
        node_id: String,
    },
    TopologyAdd {
        address: String,
        role: u8,
        stake: String,
        node_id: String,
    },
    TopologyRemove {
        address: String,
        node_id: String,
    },
    PacketProcessed {
        duration_ms: u64,
        node_id: String,
    },
}

fn to_sse(nox: &NoxEvent, node_id: &str) -> Option<Event> {
    let (event_type, payload) = match nox {
        NoxEvent::NodeStarted { timestamp } => (
            "node_started",
            SsePayload::NodeStarted {
                timestamp: *timestamp,
                node_id: node_id.to_string(),
            },
        ),
        NoxEvent::PeerConnected { peer_id } => (
            "peer_connected",
            SsePayload::PeerConnected {
                peer_id: peer_id.clone(),
                node_id: node_id.to_string(),
            },
        ),
        NoxEvent::PeerDisconnected { peer_id } => (
            "peer_disconnected",
            SsePayload::PeerDisconnected {
                peer_id: peer_id.clone(),
                node_id: node_id.to_string(),
            },
        ),
        NoxEvent::RelayerRegistered {
            address,
            role,
            stake,
            ..
        } => (
            "topology_add",
            SsePayload::TopologyAdd {
                address: address.clone(),
                role: *role,
                stake: stake.clone(),
                node_id: node_id.to_string(),
            },
        ),
        NoxEvent::RelayerRemoved { address } => (
            "topology_remove",
            SsePayload::TopologyRemove {
                address: address.clone(),
                node_id: node_id.to_string(),
            },
        ),
        NoxEvent::PacketProcessed { duration_ms, .. } => (
            "packet_processed",
            SsePayload::PacketProcessed {
                duration_ms: *duration_ms,
                node_id: node_id.to_string(),
            },
        ),
        NoxEvent::PacketReceived { .. }
        | NoxEvent::SendPacket { .. }
        | NoxEvent::PayloadDecrypted { .. }
        | NoxEvent::HopTimingsRecorded { .. }
        | NoxEvent::RelayerKeyRotated { .. }
        | NoxEvent::RelayerRoleUpdated { .. }
        | NoxEvent::RelayerUrlUpdated { .. }
        | NoxEvent::RelayerSlashed { .. }
        | NoxEvent::RegistryPaused { .. }
        | NoxEvent::RegistryUnpaused { .. } => return None,
    };

    let data = serde_json::to_string(&payload).ok()?;
    Some(Event::default().event(event_type).data(data))
}

fn make_sse_stream(
    rx: tokio::sync::broadcast::Receiver<NoxEvent>,
    node_id: String,
) -> impl Stream<Item = Result<Event, Infallible>> {
    stream::unfold((rx, node_id), |(mut rx, node_id)| async {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if let Some(sse_event) = to_sse(&event, &node_id) {
                        return Some((Ok(sse_event), (rx, node_id)));
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    return None;
                }
            }
        }
    })
}

pub async fn handle_sse_events(
    Extension(bus): Extension<Arc<dyn IEventSubscriber>>,
    Extension(node_id): Extension<String>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = bus.subscribe();
    Sse::new(make_sse_stream(rx, node_id)).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(30))
            .text("ping"),
    )
}
