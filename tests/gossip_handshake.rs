//! Handshake protocol integration tests: SystemMessage serialization variants.

use nox_core::{Capabilities, Handshake};
use nox_node::network::behaviour::{SphinxPacket, SystemMessage};

#[test]
fn test_system_message_handshake_variant() {
    let hs = Handshake::new(
        "key2".to_string(),
        Capabilities::RELAY,
        "0xtest".to_string(),
    );

    let msg = SystemMessage::Handshake(hs.clone());

    let bytes = serde_json::to_vec(&msg).unwrap();
    let parsed: SystemMessage = serde_json::from_slice(&bytes).unwrap();

    match parsed {
        SystemMessage::Handshake(parsed_hs) => {
            assert_eq!(parsed_hs.routing_key, hs.routing_key);
            assert_eq!(parsed_hs.capabilities, hs.capabilities);
        }
        _ => panic!("Expected Handshake variant"),
    }
}

#[test]
fn test_system_message_packet_variant() {
    let packet = SphinxPacket {
        id: "packet_123".to_string(),
        data: vec![1, 2, 3, 4, 5],
    };

    let msg = SystemMessage::Packet(packet.clone());

    let bytes = serde_json::to_vec(&msg).unwrap();
    let parsed: SystemMessage = serde_json::from_slice(&bytes).unwrap();

    match parsed {
        SystemMessage::Packet(p) => {
            assert_eq!(p.id, packet.id);
            assert_eq!(p.data, packet.data);
        }
        _ => panic!("Expected Packet variant"),
    }
}

#[test]
fn test_handshake_ack_with_session_ticket() {
    let ticket: Vec<u8> = (0..32).collect();
    let msg = SystemMessage::HandshakeAck {
        accepted: true,
        reason: None,
        session_ticket: Some(ticket.clone()),
    };

    let bytes = serde_json::to_vec(&msg).unwrap();
    let parsed: SystemMessage = serde_json::from_slice(&bytes).unwrap();

    match parsed {
        SystemMessage::HandshakeAck {
            accepted,
            reason,
            session_ticket,
        } => {
            assert!(accepted);
            assert!(reason.is_none());
            assert_eq!(session_ticket.unwrap(), ticket);
        }
        _ => panic!("Expected HandshakeAck variant"),
    }
}

#[test]
fn test_handshake_ack_without_session_ticket() {
    let msg = SystemMessage::HandshakeAck {
        accepted: false,
        reason: Some("Incompatible version".to_string()),
        session_ticket: None,
    };

    let bytes = serde_json::to_vec(&msg).unwrap();
    let parsed: SystemMessage = serde_json::from_slice(&bytes).unwrap();

    match parsed {
        SystemMessage::HandshakeAck {
            accepted,
            reason,
            session_ticket,
        } => {
            assert!(!accepted);
            assert_eq!(reason.unwrap(), "Incompatible version");
            assert!(session_ticket.is_none());
        }
        _ => panic!("Expected HandshakeAck variant"),
    }
}

#[test]
fn test_session_resume_variant() {
    let ticket: Vec<u8> = (0..32).collect();
    let msg = SystemMessage::SessionResume {
        ticket: ticket.clone(),
    };

    let bytes = serde_json::to_vec(&msg).unwrap();
    let parsed: SystemMessage = serde_json::from_slice(&bytes).unwrap();

    match parsed {
        SystemMessage::SessionResume {
            ticket: parsed_ticket,
        } => {
            assert_eq!(parsed_ticket, ticket);
            assert_eq!(parsed_ticket.len(), 32);
        }
        _ => panic!("Expected SessionResume variant"),
    }
}
