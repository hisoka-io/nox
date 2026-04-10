use libp2p::connection_limits::{self, ConnectionLimits};
use libp2p::request_response::ProtocolSupport;
use libp2p::StreamProtocol;
use libp2p::{gossipsub, identify, ping, request_response, swarm::NetworkBehaviour};
use serde::{Deserialize, Serialize};

use nox_core::models::handshake::Handshake;
use nox_core::models::topology::TopologySnapshot;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SphinxPacket {
    pub id: String,
    pub data: Vec<u8>,
}

/// Multiplexed over a single `RequestResponse` protocol for handshakes,
/// Sphinx packets, session resumption, and topology exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SystemMessage {
    Handshake(Handshake),
    Packet(SphinxPacket),
    HandshakeAck {
        accepted: bool,
        reason: Option<String>,
        /// Present only on successful handshake.
        session_ticket: Option<Vec<u8>>,
    },
    SessionResume {
        ticket: Vec<u8>,
    },
    Ack,
    TopologyRequest,
    TopologyResponse(TopologySnapshot),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipMessage {
    pub topic: String,
    pub content: Vec<u8>,
}

#[derive(NetworkBehaviour)]
pub struct NoxBehaviour {
    pub ping: ping::Behaviour,
    pub identify: identify::Behaviour,
    pub gossipsub: gossipsub::Behaviour,
    pub direct_message: request_response::cbor::Behaviour<SystemMessage, SystemMessage>,
    pub connection_limits: connection_limits::Behaviour,
}

impl NoxBehaviour {
    pub fn new(
        local_key: libp2p::identity::Keypair,
        config: &crate::config::NetworkConfig,
    ) -> Result<Self, String> {
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(std::time::Duration::from_secs(config.gossip_heartbeat_secs))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .map_err(|e| format!("GossipSub config build failed: {e}"))?;

        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        )
        .map_err(|e| format!("GossipSub behaviour init failed: {e}"))?;

        let rr_config = request_response::Config::default()
            .with_max_concurrent_streams(config.max_concurrent_streams);
        let direct_message = request_response::cbor::Behaviour::new(
            [(StreamProtocol::new("/nox/packet/1"), ProtocolSupport::Full)],
            rr_config,
        );

        let identify = identify::Behaviour::new(identify::Config::new(
            "/nox/1.0.0".into(),
            local_key.public(),
        ));

        let ping = ping::Behaviour::new(
            ping::Config::new()
                .with_interval(std::time::Duration::from_secs(config.ping_interval_secs))
                .with_timeout(std::time::Duration::from_secs(config.ping_timeout_secs)),
        );

        let limits = ConnectionLimits::default()
            .with_max_established(Some(config.max_connections))
            .with_max_established_per_peer(Some(config.max_connections_per_peer));
        let connection_limits = connection_limits::Behaviour::new(limits);

        Ok(Self {
            ping,
            identify,
            gossipsub,
            direct_message,
            connection_limits,
        })
    }
}
