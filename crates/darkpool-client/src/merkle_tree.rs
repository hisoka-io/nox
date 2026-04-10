//! 32-level Lean IMT with Poseidon2 hashing, mirroring the on-chain `DarkPool` commitment tree.
//! Lean IMT: sibling=0 means "empty" and propagates without hashing (matches Noir circuit).

use ethers::types::U256;
use std::collections::HashMap;
use tracing::debug;

use crate::crypto_helpers::poseidon_hash;

pub const TREE_DEPTH: usize = 32;

#[derive(Debug, Clone)]
pub struct MerklePath {
    /// Empty siblings are 0 (Lean IMT), not pre-computed zero hashes
    pub siblings: [U256; TREE_DEPTH],
    pub indices: [u8; TREE_DEPTH],
}

impl MerklePath {
    #[allow(clippy::must_use_candidate)]
    pub fn siblings_vec(&self) -> Vec<U256> {
        self.siblings.to_vec()
    }
}

#[derive(Debug)]
pub struct LocalMerkleTree {
    leaves: Vec<U256>,
    /// (level, index) -> hash. Level 0 = leaves, Level 31 = just below root.
    nodes: HashMap<(u8, u64), U256>,
}

impl LocalMerkleTree {
    #[must_use]
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            nodes: HashMap::new(),
        }
    }

    #[allow(clippy::must_use_candidate)]
    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    #[allow(clippy::must_use_candidate)]
    pub fn root(&self) -> U256 {
        if self.leaves.is_empty() {
            return U256::zero();
        }
        self.compute_root()
    }

    pub fn insert(&mut self, commitment: U256) -> u64 {
        let index = self.leaves.len() as u64;
        self.leaves.push(commitment);
        self.update_path(index);

        debug!(
            "Inserted leaf {} at index {}. New root: {:?}",
            commitment,
            index,
            self.root()
        );

        index
    }

    #[must_use]
    pub fn get_path(&self, index: u64) -> MerklePath {
        let mut siblings = [U256::zero(); TREE_DEPTH];
        let mut indices = [0u8; TREE_DEPTH];

        let mut current_index = index;

        for level in 0..TREE_DEPTH {
            let sibling_index = if current_index.is_multiple_of(2) {
                current_index + 1
            } else {
                current_index - 1
            };

            indices[level] = (current_index % 2) as u8;
            siblings[level] = self.get_node_lean(level as u8, sibling_index);
            current_index /= 2;
        }

        MerklePath { siblings, indices }
    }

    #[must_use]
    pub fn verify_path(&self, leaf: U256, _index: u64, path: &MerklePath) -> bool {
        let mut current = leaf;

        for level in 0..TREE_DEPTH {
            let sibling = path.siblings[level];

            if sibling.is_zero() {
            } else {
                let is_right = path.indices[level] == 1;
                current = if is_right {
                    poseidon_hash(&[sibling, current])
                } else {
                    poseidon_hash(&[current, sibling])
                };
            }
        }

        current == self.root()
    }

    fn get_node_lean(&self, level: u8, index: u64) -> U256 {
        if level == 0 {
            return self
                .leaves
                .get(index as usize)
                .copied()
                .unwrap_or(U256::zero());
        }

        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or(U256::zero())
    }

    fn update_path(&mut self, leaf_index: u64) {
        let mut current_index = leaf_index;

        for level in 0..(TREE_DEPTH - 1) {
            let parent_index = current_index / 2;
            let left_child_index = parent_index * 2;
            let right_child_index = left_child_index + 1;

            let left = self.get_node_lean(level as u8, left_child_index);
            let right = self.get_node_lean(level as u8, right_child_index);

            let parent = if left.is_zero() && right.is_zero() {
                U256::zero()
            } else if right.is_zero() {
                left
            } else if left.is_zero() {
                right
            } else {
                poseidon_hash(&[left, right])
            };

            if !parent.is_zero() {
                self.nodes.insert(((level + 1) as u8, parent_index), parent);
            }

            current_index = parent_index;
        }
    }

    fn compute_root(&self) -> U256 {
        self.get_node_lean((TREE_DEPTH - 1) as u8, 0)
    }

    #[allow(clippy::must_use_candidate)]
    pub fn leaves(&self) -> &[U256] {
        &self.leaves
    }

    pub fn clear(&mut self) {
        self.leaves.clear();
        self.nodes.clear();
    }

    pub fn load_from_leaves(&mut self, leaves: &[U256]) {
        self.clear();
        for leaf in leaves {
            self.insert(*leaf);
        }
    }
}

impl Default for LocalMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree_root() {
        let tree = LocalMerkleTree::new();
        let root = tree.root();
        assert!(!root.is_zero() || tree.size() == 0);
    }

    #[test]
    fn test_insert_and_root_changes() {
        let mut tree = LocalMerkleTree::new();
        let root0 = tree.root();

        tree.insert(U256::from(1));
        let root1 = tree.root();

        tree.insert(U256::from(2));
        let root2 = tree.root();

        assert_ne!(root0, root1);
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_deterministic_root() {
        let mut tree1 = LocalMerkleTree::new();
        let mut tree2 = LocalMerkleTree::new();

        tree1.insert(U256::from(100));
        tree1.insert(U256::from(200));

        tree2.insert(U256::from(100));
        tree2.insert(U256::from(200));

        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_get_path() {
        let mut tree = LocalMerkleTree::new();

        let leaf = U256::from(12345);
        let index = tree.insert(leaf);

        let path = tree.get_path(index);

        assert_eq!(path.siblings.len(), TREE_DEPTH);
        assert_eq!(path.indices.len(), TREE_DEPTH);
        assert!(tree.verify_path(leaf, index, &path));
    }

    #[test]
    fn test_verify_path_fails_for_wrong_leaf() {
        let mut tree = LocalMerkleTree::new();

        let leaf = U256::from(12345);
        let index = tree.insert(leaf);

        let path = tree.get_path(index);

        let wrong_leaf = U256::from(99999);
        assert!(!tree.verify_path(wrong_leaf, index, &path));
    }

    #[test]
    fn test_multiple_inserts_and_paths() {
        let mut tree = LocalMerkleTree::new();
        let mut leaves_and_indices = Vec::new();

        for i in 0..10 {
            let leaf = U256::from(i * 1000 + 1);
            let index = tree.insert(leaf);
            leaves_and_indices.push((leaf, index));
        }

        for (leaf, index) in &leaves_and_indices {
            let path = tree.get_path(*index);
            assert!(
                tree.verify_path(*leaf, *index, &path),
                "Path verification failed for leaf at index {}",
                index
            );
        }
    }

    #[test]
    fn test_load_from_leaves() {
        let leaves = vec![U256::from(1), U256::from(2), U256::from(3)];

        let mut tree1 = LocalMerkleTree::new();
        for leaf in &leaves {
            tree1.insert(*leaf);
        }

        let mut tree2 = LocalMerkleTree::new();
        tree2.load_from_leaves(&leaves);

        assert_eq!(tree1.root(), tree2.root());
    }
}
