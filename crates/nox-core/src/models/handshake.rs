//! Protocol handshake for version/capability exchange between nodes.

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

/// Current protocol version.
/// v2: Removed `identity_key` (BJJ) from handshake -- unused dead code.
/// v3: Added `eth_address` for on-chain registration verification (ISSUE-005).
/// v4: Added `payload_version_min`/`payload_version_max` for wire-format versioning.
/// v5: Added `identity_sig` -- secp256k1 signature proving ownership of `eth_address`.
pub const PROTOCOL_VERSION: u32 = 5;

/// Minimum protocol version this node will accept from peers.
/// v5 is mandatory: all peers must provide `identity_sig` proving ETH key ownership.
pub const MIN_SUPPORTED_VERSION: u32 = 5;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct Capabilities: u32 {
        const RELAY     = 0b0000_0001;
        const EXIT_NODE = 0b0000_0010;
        const STORAGE   = 0b0000_0100;
        const ALL = Self::RELAY.bits() | Self::EXIT_NODE.bits() | Self::STORAGE.bits();
    }
}

impl Default for Capabilities {
    fn default() -> Self {
        Self::RELAY
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handshake {
    pub version: u32,
    pub capabilities: Capabilities,
    /// X25519 routing public key (hex-encoded), used for Sphinx packet encryption.
    pub routing_key: String,
    /// v3+: Ethereum address for on-chain `NoxRegistry` verification.
    #[serde(default)]
    pub eth_address: Option<String>,
    #[serde(default = "default_payload_version")]
    pub payload_version_min: u8,
    #[serde(default = "default_payload_version")]
    pub payload_version_max: u8,
    /// v5+: secp256k1 signature proving ownership of `eth_address`.
    /// 65 bytes [r(32) || s(32) || v(1)], hex-encoded.
    #[serde(default)]
    pub identity_sig: Option<String>,
}

fn default_payload_version() -> u8 {
    1
}

impl Handshake {
    #[must_use]
    pub fn new(routing_key: String, capabilities: Capabilities, eth_address: String) -> Self {
        use crate::models::payloads::PAYLOAD_VERSION;
        Self {
            version: PROTOCOL_VERSION,
            capabilities,
            routing_key,
            eth_address: Some(eth_address),
            payload_version_min: PAYLOAD_VERSION,
            payload_version_max: PAYLOAD_VERSION,
            identity_sig: None,
        }
    }

    #[must_use]
    pub fn with_identity_sig(mut self, sig_hex: String) -> Self {
        self.identity_sig = Some(sig_hex);
        self
    }

    #[must_use]
    pub fn is_compatible(&self) -> bool {
        self.version >= MIN_SUPPORTED_VERSION && self.version <= PROTOCOL_VERSION
    }

    #[must_use]
    pub fn has_capability(&self, cap: Capabilities) -> bool {
        self.capabilities.contains(cap)
    }
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub connected_at: std::time::Instant,
    pub capabilities: Capabilities,
    pub routing_key: String,
    pub eth_address: Option<String>,
    pub registry_verified: bool,
}

impl PeerInfo {
    #[must_use]
    pub fn from_handshake(handshake: &Handshake, registry_verified: bool) -> Self {
        Self {
            connected_at: std::time::Instant::now(),
            capabilities: handshake.capabilities,
            routing_key: handshake.routing_key.clone(),
            eth_address: handshake.eth_address.clone(),
            registry_verified,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_creation() {
        let hs = Handshake::new(
            "routing_key_hex".to_string(),
            Capabilities::RELAY | Capabilities::EXIT_NODE,
            "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        );

        assert_eq!(hs.version, PROTOCOL_VERSION);
        assert!(hs.has_capability(Capabilities::RELAY));
        assert!(hs.has_capability(Capabilities::EXIT_NODE));
        assert!(!hs.has_capability(Capabilities::STORAGE));
        assert_eq!(
            hs.eth_address.as_deref(),
            Some("0x1234567890abcdef1234567890abcdef12345678")
        );
    }

    #[test]
    fn test_version_compatibility() {
        let hs = Handshake::new("key".to_string(), Capabilities::RELAY, "0xaddr".to_string());
        assert!(hs.is_compatible());

        // Versions below v5 should be incompatible (MIN_SUPPORTED_VERSION = 5)
        let mut old_hs = hs.clone();
        old_hs.version = 4;
        assert!(!old_hs.is_compatible());

        // Current version should be compatible
        let mut current_hs = hs.clone();
        current_hs.version = PROTOCOL_VERSION;
        assert!(current_hs.is_compatible());

        // Version above current should be incompatible
        let mut future_hs = hs.clone();
        future_hs.version = PROTOCOL_VERSION + 1;
        assert!(!future_hs.is_compatible());
    }

    #[test]
    fn test_capabilities_bitflags() {
        let caps = Capabilities::RELAY | Capabilities::EXIT_NODE;
        assert!(caps.contains(Capabilities::RELAY));
        assert!(caps.contains(Capabilities::EXIT_NODE));
        assert!(!caps.contains(Capabilities::STORAGE));
    }

    #[test]
    fn test_serialization() {
        let hs = Handshake::new(
            "def456".to_string(),
            Capabilities::ALL,
            "0xabcdef".to_string(),
        );

        let json = serde_json::to_string(&hs).unwrap();
        let parsed: Handshake = serde_json::from_str(&json).unwrap();

        assert_eq!(hs, parsed);
    }

    #[test]
    fn test_legacy_deserialization() {
        // Old handshake formats still deserialize (missing fields default).
        // Note: v2/v3/v4 peers would be REJECTED by is_compatible() since MIN_SUPPORTED_VERSION=5,
        // but deserialization itself must not fail.
        let json = r#"{"version":2,"capabilities":"RELAY","routing_key":"abc123"}"#;
        let parsed: Handshake = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.version, 2);
        assert!(parsed.eth_address.is_none());
        assert!(parsed.identity_sig.is_none());
        assert!(!parsed.is_compatible()); // v2 < MIN_SUPPORTED_VERSION(5)

        let json =
            r#"{"version":3,"capabilities":"RELAY","routing_key":"abc123","eth_address":"0xabc"}"#;
        let parsed: Handshake = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.version, 3);
        assert_eq!(parsed.eth_address.as_deref(), Some("0xabc"));
        assert!(parsed.identity_sig.is_none());
        assert!(!parsed.is_compatible()); // v3 < MIN_SUPPORTED_VERSION(5)
    }

    #[test]
    fn test_v5_handshake_has_identity_sig() {
        let hs = Handshake::new("key".to_string(), Capabilities::RELAY, "0xaddr".to_string())
            .with_identity_sig("deadbeef".to_string());
        assert_eq!(hs.version, PROTOCOL_VERSION);
        assert_eq!(hs.identity_sig.as_deref(), Some("deadbeef"));
        assert!(hs.is_compatible());
    }

    #[test]
    fn test_peer_info_from_handshake() {
        let hs = Handshake::new(
            "routing_key".to_string(),
            Capabilities::RELAY,
            "0xaddr".to_string(),
        );
        let info = PeerInfo::from_handshake(&hs, true);
        assert!(info.registry_verified);
        assert_eq!(info.eth_address.as_deref(), Some("0xaddr"));

        let info_unverified = PeerInfo::from_handshake(&hs, false);
        assert!(!info_unverified.registry_verified);
    }
}
