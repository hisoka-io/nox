use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayerNode {
    pub address: String,
    pub sphinx_key: String,
    /// P2P multiaddr (e.g., /ip4/1.2.3.4/tcp/9000)
    pub url: String,
    /// String to preserve U256 precision
    pub stake: String,
    pub last_seen: u64,
    pub is_privileged: bool,
    /// 0=Entry, 1=Mix, 2=Exit
    pub layer: u8,
    /// 1=Relay, 2=Exit, 3=Full. Defaults to 3 for backward compat.
    #[serde(default = "default_role")]
    pub role: u8,
    /// HTTPS ingress URL for client SDK packet submission. Separate from `url` (P2P multiaddr).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress_url: Option<String>,
    /// Extended metadata JSON URL for version, region, capabilities, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_url: Option<String>,
}

fn default_role() -> u8 {
    3
}

/// Maps on-chain role to allowed topology layers.
/// Role 1 (Relay) -> [0,1]; Role 2 (Exit) / 3 (Full) -> [0,1,2].
#[must_use]
pub fn layers_for_role(role: u8) -> &'static [u8] {
    match role {
        1 => &[0, 1],
        _ => &[0, 1, 2],
    }
}

impl RelayerNode {
    #[must_use]
    pub fn new(address: String, sphinx_key: String, url: String, stake: String, role: u8) -> Self {
        let is_privileged = Self::parse_stake(&stake).is_some_and(|s| s == 0);
        Self {
            address,
            sphinx_key,
            url,
            stake,
            last_seen: 0,
            is_privileged,
            layer: 0,
            role,
            ingress_url: None,
            metadata_url: None,
        }
    }

    #[must_use]
    pub fn with_ingress_url(mut self, ingress_url: String) -> Self {
        self.ingress_url = Some(ingress_url);
        self
    }

    /// Parse stake string to u128 for numeric comparison.
    #[must_use]
    pub fn parse_stake(stake_str: &str) -> Option<u128> {
        stake_str.parse::<u128>().ok()
    }

    #[allow(clippy::must_use_candidate)]
    pub fn stake_value(&self) -> u128 {
        Self::parse_stake(&self.stake).unwrap_or(0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopologySnapshot {
    pub nodes: Vec<RelayerNode>,
    /// XOR(keccak256(addr) for each node), hex-encoded
    pub fingerprint: String,
    pub timestamp: u64,
    pub block_number: u64,
    /// `PoW` difficulty required by the network. Clients use this instead of guessing.
    #[serde(default)]
    pub pow_difficulty: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(addr: &str, stake: &str, role: u8) -> RelayerNode {
        RelayerNode::new(
            addr.to_string(),
            "0xdead".to_string(),
            "/ip4/127.0.0.1/tcp/9000".to_string(),
            stake.to_string(),
            role,
        )
    }

    #[test]
    fn test_new_sets_defaults() {
        let node = make_node("0xabc", "1000", 3);
        assert_eq!(node.address, "0xabc");
        assert_eq!(node.sphinx_key, "0xdead");
        assert_eq!(node.stake, "1000");
        assert_eq!(node.role, 3);
        assert_eq!(node.layer, 0);
        assert_eq!(node.last_seen, 0);
        assert!(!node.is_privileged);
        assert!(node.ingress_url.is_none());
    }

    #[test]
    fn test_new_privileged_when_stake_zero() {
        let node = make_node("0xabc", "0", 1);
        assert!(
            node.is_privileged,
            "Zero-stake nodes are privileged (admin)"
        );
    }

    #[test]
    fn test_new_not_privileged_when_stake_nonzero() {
        let node = make_node("0xabc", "100", 2);
        assert!(!node.is_privileged);
    }

    #[test]
    fn test_new_not_privileged_when_stake_unparseable() {
        let node = make_node("0xabc", "not_a_number", 1);
        assert!(!node.is_privileged, "Unparseable stake is not privileged");
    }

    #[test]
    fn test_with_ingress_url() {
        let node =
            make_node("0xabc", "1000", 3).with_ingress_url("http://1.2.3.4:8080".to_string());
        assert_eq!(node.ingress_url.as_deref(), Some("http://1.2.3.4:8080"));
    }

    #[test]
    fn test_parse_stake_valid() {
        assert_eq!(RelayerNode::parse_stake("42"), Some(42));
        assert_eq!(RelayerNode::parse_stake("0"), Some(0));
        assert_eq!(
            RelayerNode::parse_stake("340282366920938463463374607431768211455"),
            Some(u128::MAX),
        );
    }

    #[test]
    fn test_parse_stake_invalid() {
        assert_eq!(RelayerNode::parse_stake(""), None);
        assert_eq!(RelayerNode::parse_stake("abc"), None);
        assert_eq!(RelayerNode::parse_stake("-1"), None);
    }

    #[test]
    fn test_stake_value_returns_parsed() {
        let node = make_node("0xabc", "9999", 1);
        assert_eq!(node.stake_value(), 9999);
    }

    #[test]
    fn test_stake_value_returns_zero_on_failure() {
        let node = make_node("0xabc", "garbage", 1);
        assert_eq!(node.stake_value(), 0);
    }

    #[test]
    fn test_relayer_node_json_roundtrip() {
        let node =
            make_node("0xabc", "500", 2).with_ingress_url("http://localhost:8080".to_string());
        let json = serde_json::to_string(&node).expect("serialize");
        let back: RelayerNode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(node, back);
    }

    #[test]
    fn test_relayer_node_deserialize_missing_role_defaults_to_full() {
        // Nodes registered before role support omit `role` field.
        let json = r#"{
            "address": "0xabc",
            "sphinx_key": "0xdead",
            "url": "/ip4/127.0.0.1/tcp/9000",
            "stake": "1000",
            "last_seen": 0,
            "is_privileged": false,
            "layer": 0
        }"#;
        let node: RelayerNode = serde_json::from_str(json).expect("deserialize");
        assert_eq!(node.role, 3, "Missing role should default to 3 (Full)");
    }

    #[test]
    fn test_relayer_node_deserialize_missing_ingress_url_defaults_to_none() {
        let json = r#"{
            "address": "0xabc",
            "sphinx_key": "0xdead",
            "url": "/ip4/127.0.0.1/tcp/9000",
            "stake": "1000",
            "last_seen": 0,
            "is_privileged": false,
            "layer": 0,
            "role": 2
        }"#;
        let node: RelayerNode = serde_json::from_str(json).expect("deserialize");
        assert!(node.ingress_url.is_none());
    }

    #[test]
    fn test_topology_snapshot_json_roundtrip() {
        let snapshot = TopologySnapshot {
            nodes: vec![make_node("0x1", "100", 1), make_node("0x2", "200", 2)],
            fingerprint: "abcdef1234567890".to_string(),
            timestamp: 1700000000,
            block_number: 42,
            pow_difficulty: 0,
        };
        let json = serde_json::to_string(&snapshot).expect("serialize");
        let back: TopologySnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(snapshot, back);
    }

    #[test]
    fn test_layers_for_role_relay() {
        assert_eq!(layers_for_role(1), &[0, 1]);
    }

    #[test]
    fn test_layers_for_role_exit() {
        assert_eq!(layers_for_role(2), &[0, 1, 2]);
    }

    #[test]
    fn test_layers_for_role_full() {
        assert_eq!(layers_for_role(3), &[0, 1, 2]);
    }

    #[test]
    fn test_layers_for_role_unknown_defaults_to_all() {
        assert_eq!(layers_for_role(0), &[0, 1, 2]);
        assert_eq!(layers_for_role(255), &[0, 1, 2]);
    }

    #[test]
    fn test_ingress_url_not_serialized_when_none() {
        let node = make_node("0xabc", "100", 1);
        let json = serde_json::to_string(&node).expect("serialize");
        assert!(
            !json.contains("ingress_url"),
            "ingress_url should be skipped when None"
        );
    }
}
