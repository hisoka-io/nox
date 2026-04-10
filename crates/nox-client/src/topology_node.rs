//! Topology node representation for Sphinx routing.

use ethers::types::Address;

use nox_core::RelayerNode;

#[derive(Debug, Clone)]
pub struct TopologyNode {
    pub id: String,
    pub address: String,
    pub public_key: [u8; 32],
    pub layer: u8, // 0=Entry, 1=Mix, 2=Exit
    pub eth_address: Address,
    /// 1=Relay, 2=Exit, 3=Full
    pub role: u8,
}

impl TopologyNode {
    pub fn from_relayer_node(node: &RelayerNode) -> Result<Self, String> {
        let sphinx_bytes = hex::decode(&node.sphinx_key)
            .map_err(|e| format!("Invalid sphinx key hex for {}: {e}", node.address))?;

        if sphinx_bytes.len() != 32 {
            return Err(format!(
                "Sphinx key wrong length for {}: {} (expected 32)",
                node.address,
                sphinx_bytes.len()
            ));
        }

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&sphinx_bytes);

        let eth_address: Address = node
            .address
            .parse()
            .map_err(|e| format!("Invalid eth address {}: {e}", node.address))?;

        Ok(Self {
            id: node.address.clone(),
            address: node.url.clone(),
            public_key,
            layer: node.layer,
            eth_address,
            role: node.role,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_relayer_node_valid() {
        let node = RelayerNode {
            address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            sphinx_key: "aa".repeat(32),
            url: "/ip4/127.0.0.1/tcp/9000".to_string(),
            stake: "1000".to_string(),
            last_seen: 0,
            is_privileged: false,
            layer: 2,
            role: 2,
            ingress_url: None,
            metadata_url: None,
        };

        let topo = TopologyNode::from_relayer_node(&node).unwrap();
        assert_eq!(topo.layer, 2);
        assert_eq!(topo.role, 2);
        assert_eq!(topo.public_key, [0xaa; 32]);
        assert_eq!(topo.address, "/ip4/127.0.0.1/tcp/9000");
        assert_eq!(topo.id, node.address);
    }

    #[test]
    fn test_from_relayer_node_invalid_key_hex() {
        let node = RelayerNode {
            address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            sphinx_key: "not_hex".to_string(),
            url: "/ip4/127.0.0.1/tcp/9000".to_string(),
            stake: "1000".to_string(),
            last_seen: 0,
            is_privileged: false,
            layer: 0,
            role: 3,
            ingress_url: None,
            metadata_url: None,
        };

        let result = TopologyNode::from_relayer_node(&node);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid sphinx key hex"));
    }

    #[test]
    fn test_from_relayer_node_wrong_key_length() {
        let node = RelayerNode {
            address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            sphinx_key: "aabb".to_string(), // 2 bytes, not 32
            url: "/ip4/127.0.0.1/tcp/9000".to_string(),
            stake: "1000".to_string(),
            last_seen: 0,
            is_privileged: false,
            layer: 0,
            role: 3,
            ingress_url: None,
            metadata_url: None,
        };

        let result = TopologyNode::from_relayer_node(&node);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("wrong length"));
    }

    #[test]
    fn test_from_relayer_node_invalid_address() {
        let node = RelayerNode {
            address: "not_an_address".to_string(),
            sphinx_key: "aa".repeat(32),
            url: "/ip4/127.0.0.1/tcp/9000".to_string(),
            stake: "1000".to_string(),
            last_seen: 0,
            is_privileged: false,
            layer: 0,
            role: 3,
            ingress_url: None,
            metadata_url: None,
        };

        let result = TopologyNode::from_relayer_node(&node);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid eth address"));
    }
}
