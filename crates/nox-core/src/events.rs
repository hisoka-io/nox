use crate::models::wire_id::{PacketOrigin, ReplyHandle};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NoxEvent {
    NodeStarted {
        timestamp: u64,
    },

    /// A Sphinx packet to process. `packet_id` is node-local; it is only
    /// equal to the identifier on the wire in passthrough mode.
    PacketReceived {
        packet_id: String,
        data: Vec<u8>,
        size_bytes: usize,
        /// Reply handle read from the inbound wire identifier, if any.
        #[serde(default)]
        reply_handle: Option<ReplyHandle>,
        /// Libp2p peer ID of the sender, for packets received over P2P.
        #[serde(default)]
        prev_peer: Option<String>,
    },

    /// A Sphinx packet for the network layer, which picks the wire identifier.
    SendPacket {
        next_hop_peer_id: String,
        packet_id: String,
        data: Vec<u8>,
        /// Reply handle the packet may carry to the next hop.
        #[serde(default)]
        reply_handle: Option<ReplyHandle>,
        #[serde(default)]
        origin: PacketOrigin,
    },

    PayloadDecrypted {
        packet_id: String,
        payload: Vec<u8>,
        /// Reply handle the packet arrived with, if any.
        #[serde(default)]
        reply_handle: Option<ReplyHandle>,
    },

    PeerConnected {
        peer_id: String,
    },

    PeerDisconnected {
        peer_id: String,
    },

    RelayerRegistered {
        address: String,
        sphinx_key: String,
        url: String,
        stake: String,
        /// On-chain node role: 1=Relay, 2=Exit, 3=Full. Defaults to 3 for backward compatibility.
        role: u8,
        /// HTTPS ingress URL for client SDK packet submission (`None` for nodes without HTTP ingress).
        ingress_url: Option<String>,
        /// Extended metadata JSON URL (`None` if not set).
        metadata_url: Option<String>,
    },

    RelayerRemoved {
        address: String,
    },

    /// A node's Sphinx routing key was rotated on-chain.
    RelayerKeyRotated {
        address: String,
        new_sphinx_key: String,
    },

    /// A node's role was updated on-chain (1=Relay, 2=Exit, 3=Full).
    RelayerRoleUpdated {
        address: String,
        new_role: u8,
    },

    /// A node's URL was updated on-chain.
    RelayerUrlUpdated {
        address: String,
        new_url: String,
    },

    /// A node was slashed on-chain.
    RelayerSlashed {
        address: String,
        amount: String,
        slasher: String,
    },

    /// `NoxRegistry` contract was paused.
    RegistryPaused {
        by: String,
    },

    /// `NoxRegistry` contract was unpaused.
    RegistryUnpaused {
        by: String,
    },

    PacketProcessed {
        packet_id: String,
        duration_ms: u64,
    },

    /// Per-hop Sphinx processing timing breakdown (only emitted with `hop-metrics` feature).
    /// Nanosecond-precision timings for ECDH, key derivation, MAC, routing/body decryption, blinding.
    HopTimingsRecorded {
        packet_id: String,
        ecdh_ns: u64,
        key_derive_ns: u64,
        mac_verify_ns: u64,
        routing_decrypt_ns: u64,
        body_decrypt_ns: u64,
        blinding_ns: u64,
        total_sphinx_ns: u64,
    },

    /// A node's full profile, re-read from the registry after an on-chain
    /// profile change (URL, ingress, metadata, key, role, stake or freeze).
    RelayerProfileSynced {
        address: String,
        sphinx_key: String,
        url: String,
        ingress_url: Option<String>,
        metadata_url: Option<String>,
        stake: String,
        role: u8,
        frozen: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_json_roundtrip(event: &NoxEvent) {
        let json = serde_json::to_string(event).expect("serialize");
        let decoded: NoxEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*event, decoded);
    }

    fn assert_bincode_roundtrip(event: &NoxEvent) {
        let bytes = bincode::serialize(event).expect("serialize");
        let decoded: NoxEvent = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(*event, decoded);
    }

    #[test]
    fn roundtrip_node_started() {
        let event = NoxEvent::NodeStarted {
            timestamp: 1709980000,
        };
        assert_json_roundtrip(&event);
        assert_bincode_roundtrip(&event);
    }

    #[test]
    fn roundtrip_packet_received() {
        let event = NoxEvent::PacketReceived {
            packet_id: "pkt-001".into(),
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            size_bytes: 4,
            reply_handle: Some([7u8; 16]),
            prev_peer: Some("12D3KooWprev".into()),
        };
        assert_json_roundtrip(&event);
        assert_bincode_roundtrip(&event);
    }

    #[test]
    fn roundtrip_send_packet() {
        let event = NoxEvent::SendPacket {
            next_hop_peer_id: "peer-abc".into(),
            packet_id: "pkt-002".into(),
            data: vec![1, 2, 3],
            reply_handle: Some([9u8; 16]),
            origin: PacketOrigin::Relayed {
                prev_peer: Some("12D3KooWprev".into()),
            },
        };
        assert_json_roundtrip(&event);
        assert_bincode_roundtrip(&event);
    }

    #[test]
    fn roundtrip_payload_decrypted() {
        let event = NoxEvent::PayloadDecrypted {
            packet_id: "pkt-003".into(),
            payload: b"hello world".to_vec(),
            reply_handle: None,
        };
        assert_json_roundtrip(&event);
        assert_bincode_roundtrip(&event);
    }

    #[test]
    fn roundtrip_peer_connected() {
        let event = NoxEvent::PeerConnected {
            peer_id: "12D3KooW...".into(),
        };
        assert_json_roundtrip(&event);
        assert_bincode_roundtrip(&event);
    }

    #[test]
    fn roundtrip_peer_disconnected() {
        let event = NoxEvent::PeerDisconnected {
            peer_id: "12D3KooW...".into(),
        };
        assert_json_roundtrip(&event);
        assert_bincode_roundtrip(&event);
    }

    #[test]
    fn roundtrip_relayer_registered() {
        let event = NoxEvent::RelayerRegistered {
            address: "0x1234".into(),
            sphinx_key: "0xabcd".into(),
            url: "https://node.example.com".into(),
            stake: "100000".into(),
            role: 3,
            ingress_url: Some("https://nox-1.hisoka.io".into()),
            metadata_url: None,
        };
        assert_json_roundtrip(&event);
        assert_bincode_roundtrip(&event);
    }

    #[test]
    fn roundtrip_relayer_removed() {
        let event = NoxEvent::RelayerRemoved {
            address: "0x5678".into(),
        };
        assert_json_roundtrip(&event);
        assert_bincode_roundtrip(&event);
    }

    #[test]
    fn roundtrip_relayer_key_rotated() {
        let event = NoxEvent::RelayerKeyRotated {
            address: "0x1234".into(),
            new_sphinx_key: "aabbccdd".into(),
        };
        assert_json_roundtrip(&event);
        assert_bincode_roundtrip(&event);
    }

    #[test]
    fn roundtrip_relayer_role_updated() {
        let event = NoxEvent::RelayerRoleUpdated {
            address: "0x1234".into(),
            new_role: 2,
        };
        assert_json_roundtrip(&event);
        assert_bincode_roundtrip(&event);
    }

    #[test]
    fn roundtrip_relayer_url_updated() {
        let event = NoxEvent::RelayerUrlUpdated {
            address: "0x1234".into(),
            new_url: "http://new-node.example.com:8080".into(),
        };
        assert_json_roundtrip(&event);
        assert_bincode_roundtrip(&event);
    }

    #[test]
    fn roundtrip_relayer_slashed() {
        let event = NoxEvent::RelayerSlashed {
            address: "0x1234".into(),
            amount: "500000".into(),
            slasher: "0x5678".into(),
        };
        assert_json_roundtrip(&event);
        assert_bincode_roundtrip(&event);
    }

    #[test]
    fn roundtrip_relayer_profile_synced() {
        let event = NoxEvent::RelayerProfileSynced {
            address: "0xabc".into(),
            sphinx_key: "11".repeat(32),
            url: "/ip4/1.2.3.4/tcp/9000".into(),
            ingress_url: Some("https://nox.example".into()),
            metadata_url: None,
            stake: "0".into(),
            role: 2,
            frozen: true,
        };
        assert_json_roundtrip(&event);
        assert_bincode_roundtrip(&event);
    }

    #[test]
    fn roundtrip_registry_paused() {
        let event = NoxEvent::RegistryPaused {
            by: "0xadmin".into(),
        };
        assert_json_roundtrip(&event);
        assert_bincode_roundtrip(&event);
    }

    #[test]
    fn roundtrip_registry_unpaused() {
        let event = NoxEvent::RegistryUnpaused {
            by: "0xadmin".into(),
        };
        assert_json_roundtrip(&event);
        assert_bincode_roundtrip(&event);
    }

    #[test]
    fn roundtrip_packet_processed() {
        let event = NoxEvent::PacketProcessed {
            packet_id: "pkt-004".into(),
            duration_ms: 42,
        };
        assert_json_roundtrip(&event);
        assert_bincode_roundtrip(&event);
    }

    #[test]
    fn roundtrip_hop_timings_recorded() {
        let event = NoxEvent::HopTimingsRecorded {
            packet_id: "pkt-005".into(),
            ecdh_ns: 100_000,
            key_derive_ns: 50_000,
            mac_verify_ns: 30_000,
            routing_decrypt_ns: 20_000,
            body_decrypt_ns: 40_000,
            blinding_ns: 10_000,
            total_sphinx_ns: 250_000,
        };
        assert_json_roundtrip(&event);
        assert_bincode_roundtrip(&event);
    }

    #[test]
    fn packet_events_without_new_fields_decode_with_defaults() {
        let json = r#"{"SendPacket":{"next_hop_peer_id":"p","packet_id":"x","data":[1]}}"#;
        let event: NoxEvent = serde_json::from_str(json).expect("deserialize");
        assert_eq!(
            event,
            NoxEvent::SendPacket {
                next_hop_peer_id: "p".into(),
                packet_id: "x".into(),
                data: vec![1],
                reply_handle: None,
                origin: PacketOrigin::Originated,
            }
        );
        let json = r#"{"PayloadDecrypted":{"packet_id":"x","payload":[]}}"#;
        let event: NoxEvent = serde_json::from_str(json).expect("deserialize");
        assert!(matches!(
            event,
            NoxEvent::PayloadDecrypted {
                reply_handle: None,
                ..
            }
        ));
    }

    #[test]
    fn all_variants_covered() {
        // Compile-time exhaustiveness check: if a variant is added to NoxEvent
        // without a test, this match will fail to compile.
        let events: Vec<NoxEvent> = vec![
            NoxEvent::NodeStarted { timestamp: 0 },
            NoxEvent::PacketReceived {
                packet_id: String::new(),
                data: vec![],
                size_bytes: 0,
                reply_handle: None,
                prev_peer: None,
            },
            NoxEvent::SendPacket {
                next_hop_peer_id: String::new(),
                packet_id: String::new(),
                data: vec![],
                reply_handle: None,
                origin: PacketOrigin::Originated,
            },
            NoxEvent::PayloadDecrypted {
                packet_id: String::new(),
                payload: vec![],
                reply_handle: None,
            },
            NoxEvent::PeerConnected {
                peer_id: String::new(),
            },
            NoxEvent::PeerDisconnected {
                peer_id: String::new(),
            },
            NoxEvent::RelayerRegistered {
                address: String::new(),
                sphinx_key: String::new(),
                url: String::new(),
                stake: String::new(),
                role: 0,
                ingress_url: None,
                metadata_url: None,
            },
            NoxEvent::RelayerRemoved {
                address: String::new(),
            },
            NoxEvent::RelayerKeyRotated {
                address: String::new(),
                new_sphinx_key: String::new(),
            },
            NoxEvent::RelayerRoleUpdated {
                address: String::new(),
                new_role: 0,
            },
            NoxEvent::RelayerUrlUpdated {
                address: String::new(),
                new_url: String::new(),
            },
            NoxEvent::RelayerSlashed {
                address: String::new(),
                amount: String::new(),
                slasher: String::new(),
            },
            NoxEvent::RegistryPaused { by: String::new() },
            NoxEvent::RegistryUnpaused { by: String::new() },
            NoxEvent::PacketProcessed {
                packet_id: String::new(),
                duration_ms: 0,
            },
            NoxEvent::HopTimingsRecorded {
                packet_id: String::new(),
                ecdh_ns: 0,
                key_derive_ns: 0,
                mac_verify_ns: 0,
                routing_decrypt_ns: 0,
                body_decrypt_ns: 0,
                blinding_ns: 0,
                total_sphinx_ns: 0,
            },
        ];
        for event in &events {
            assert_json_roundtrip(event);
            assert_bincode_roundtrip(event);
        }
    }
}
