//! Path selection shared by the request client and the cover traffic loop.
//!
//! A normal path is `[entry, mix, exit]` on three distinct Sphinx keys. Relays
//! (role 1) fill the entry and mix slots; an exit-capable node (role 2 or 3)
//! fills one of those slots only when no eligible relay is left for it. When no
//! three-hop path exists, selection fails unless short paths are allowed.

use crate::topology_node::TopologyNode;
use nox_core::models::topology::layers_for_role;
use nox_crypto::sphinx::PathHop;
use rand::seq::SliceRandom;
use rand::Rng;

/// Hops in a full path: entry, mix, exit.
pub const FULL_PATH_HOPS: usize = 3;

fn is_exit_capable(node: &TopologyNode) -> bool {
    layers_for_role(node.role).contains(&2) && (node.role == 2 || node.role == 3)
}

fn hop(node: &TopologyNode) -> PathHop {
    PathHop {
        public_key: x25519_dalek::PublicKey::from(node.public_key),
        address: node.address.clone(),
    }
}

/// Picks a relay for an entry or mix slot, falling back to an exit-capable node
/// only when no relay with an unused key remains. `reserve_exit` keeps at least
/// one exit-capable node with an unused key free for the exit slot.
fn pick_relay_slot<'a, R: Rng>(
    topology: &'a [TopologyNode],
    layer: u8,
    used: &[[u8; 32]],
    reserve_exit: bool,
    rng: &mut R,
) -> Option<&'a TopologyNode> {
    let unused = |n: &&TopologyNode| !used.contains(&n.public_key);
    let relays: Vec<&TopologyNode> = topology
        .iter()
        .filter(|n| !is_exit_capable(n) && layers_for_role(n.role).contains(&layer))
        .filter(unused)
        .collect();
    if let Some(node) = relays.choose(rng) {
        return Some(node);
    }
    let mut exits: Vec<&TopologyNode> = topology
        .iter()
        .filter(|n| is_exit_capable(n) && layers_for_role(n.role).contains(&layer))
        .filter(unused)
        .collect();
    // Exits sharing a key count once.
    exits.sort_by_key(|n| n.public_key);
    exits.dedup_by_key(|n| n.public_key);
    let needed = if reserve_exit { 2 } else { 1 };
    if exits.len() < needed {
        return None;
    }
    exits.choose(rng).copied()
}

/// Selects a path through `topology`.
///
/// Returns `Err` with a reason when no path on three distinct keys exists. With
/// `allow_short_paths`, a missing mix yields `[entry, exit]` instead; entry and
/// exit keys must still differ.
pub fn select_path<R: Rng>(
    topology: &[TopologyNode],
    entry_pubkey: Option<&[u8; 32]>,
    allow_short_paths: bool,
    rng: &mut R,
) -> Result<Vec<PathHop>, String> {
    if !topology.iter().any(is_exit_capable) {
        return Err("No exit-capable nodes available (layer=2, role=Exit|Full)".into());
    }

    let entry = match entry_pubkey {
        // Search all nodes: TopologyManager may reassign layers by address hash.
        Some(pk) => topology
            .iter()
            .find(|n| n.public_key == *pk)
            .ok_or("Configured entry node not found in topology")?,
        None => pick_relay_slot(topology, 0, &[], true, rng)
            .ok_or("No entry node with a distinct exit available")?,
    };
    let mut used = vec![entry.public_key];

    let mix = pick_relay_slot(topology, 1, &used, true, rng);
    if let Some(mix) = mix {
        used.push(mix.public_key);
    } else if !allow_short_paths {
        return Err(format!(
            "No mix node with a key distinct from the entry and exit (need {FULL_PATH_HOPS} distinct keys)"
        ));
    }

    let exits: Vec<&TopologyNode> = topology
        .iter()
        .filter(|n| is_exit_capable(n) && !used.contains(&n.public_key))
        .collect();
    let exit = exits
        .choose(rng)
        .ok_or("No exit node with a key distinct from the entry and mix")?;

    let mut path = vec![hop(entry)];
    if let Some(mix) = mix {
        path.push(hop(mix));
    }
    path.push(hop(exit));
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Address;

    fn node(pk: u8, layer: u8, role: u8) -> TopologyNode {
        TopologyNode {
            id: format!("n{pk}"),
            address: format!("http://n{pk}:8080"),
            public_key: [pk; 32],
            layer,
            eth_address: Address::ZERO,
            role,
        }
    }

    fn keys(path: &[PathHop]) -> Vec<[u8; 32]> {
        path.iter().map(|h| h.public_key.to_bytes()).collect()
    }

    fn fleet_like() -> Vec<TopologyNode> {
        vec![
            node(1, 0, 1),
            node(2, 0, 1),
            node(3, 1, 1),
            node(4, 1, 1),
            node(5, 2, 2),
            node(6, 2, 2),
        ]
    }

    #[test]
    fn normal_topology_gives_three_distinct_hops_relays_first() {
        let topo = fleet_like();
        let mut rng = rand::rngs::OsRng;
        for _ in 0..200 {
            let path = select_path(&topo, None, false, &mut rng).expect("route");
            let k = keys(&path);
            assert_eq!(k.len(), FULL_PATH_HOPS);
            assert!(k[0] != k[1] && k[1] != k[2] && k[0] != k[2]);
            assert!(k[0][0] <= 4 && k[1][0] <= 4, "exit used as entry or mix");
            assert!(k[2][0] >= 5, "relay used as exit");
        }
    }

    #[test]
    fn empty_mix_layer_returns_no_route() {
        // One relay and one exit: no third key for the mix slot.
        let topo = vec![node(1, 0, 1), node(5, 2, 2)];
        let mut rng = rand::rngs::OsRng;
        assert!(select_path(&topo, None, false, &mut rng).is_err());
    }

    #[test]
    fn entry_only_topology_returns_no_route() {
        let topo = vec![node(1, 0, 1), node(2, 0, 1)];
        let mut rng = rand::rngs::OsRng;
        assert!(select_path(&topo, None, false, &mut rng).is_err());
        assert!(select_path(&topo, None, true, &mut rng).is_err());
    }

    #[test]
    fn duplicate_keys_return_no_route() {
        // Three entries, but only two distinct keys.
        let topo = vec![node(1, 0, 1), node(1, 1, 1), node(5, 2, 2)];
        let mut rng = rand::rngs::OsRng;
        assert!(select_path(&topo, None, false, &mut rng).is_err());

        let same_exit = vec![node(1, 0, 1), node(2, 1, 1), node(2, 2, 2)];
        assert!(select_path(&same_exit, None, false, &mut rng).is_err());
    }

    #[test]
    fn short_path_only_when_allowed() {
        let topo = vec![node(1, 0, 1), node(5, 2, 2)];
        let mut rng = rand::rngs::OsRng;
        let path = select_path(&topo, None, true, &mut rng).expect("short route");
        assert_eq!(keys(&path), vec![[1; 32], [5; 32]]);
    }

    #[test]
    fn exit_fills_mix_only_without_relays() {
        // One relay, two exits: the second exit takes the mix slot.
        let topo = vec![node(1, 0, 1), node(5, 2, 2), node(6, 2, 2)];
        let mut rng = rand::rngs::OsRng;
        for _ in 0..50 {
            let k = keys(&select_path(&topo, None, false, &mut rng).expect("route"));
            assert_eq!(k[0], [1; 32]);
            assert!(k[1] != k[2]);
        }
    }

    #[test]
    fn all_full_nodes_topology_routes() {
        let topo = vec![node(1, 0, 3), node(2, 1, 3), node(3, 2, 3)];
        let mut rng = rand::rngs::OsRng;
        let k = keys(&select_path(&topo, None, false, &mut rng).expect("route"));
        assert_eq!(k.len(), FULL_PATH_HOPS);
        let mut sorted = k.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), FULL_PATH_HOPS);
    }

    #[test]
    fn configured_entry_is_used_and_excluded_later() {
        let topo = fleet_like();
        let mut rng = rand::rngs::OsRng;
        for _ in 0..50 {
            let k = keys(&select_path(&topo, Some(&[3; 32]), false, &mut rng).expect("route"));
            assert_eq!(k[0], [3; 32]);
            assert!(k[1] != [3; 32] && k[2] != [3; 32]);
        }
        assert!(select_path(&topo, Some(&[9; 32]), false, &mut rng).is_err());
    }

    #[test]
    fn no_exit_returns_no_route() {
        let topo = vec![node(1, 0, 1), node(2, 1, 1)];
        let mut rng = rand::rngs::OsRng;
        assert!(select_path(&topo, None, true, &mut rng).is_err());
    }
}
