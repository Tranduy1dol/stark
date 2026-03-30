use ark_ff::PrimeField;

use crate::crypto::hasher::{hash, hash_slice};

#[derive(Debug, Clone)]
pub struct MerkleProof<F: PrimeField> {
    pub index: usize,
    pub leaf_val: F,
    pub auth_path: Vec<F>,
    pub root: F,
}

#[derive(Debug, Clone)]
pub struct MerkleTree<F: PrimeField> {
    internal_nodes: Vec<Vec<F>>,
    pub leaves: Vec<F>,
    depth: usize,
}

impl<F: PrimeField> MerkleTree<F> {
    pub fn new(mut leaves: Vec<F>) -> Self {
        let new_len = leaves.len().next_power_of_two();
        let depth = new_len.ilog2() as usize;

        let first_level = leaves.iter().map(hash).collect::<Vec<_>>();

        let mut internal_nodes = vec![first_level];

        for i in 0..depth {
            let next_level = internal_nodes[i].chunks(2).map(hash_slice).collect();
            internal_nodes.push(next_level);
        }

        leaves.resize(new_len, F::ZERO);

        Self {
            internal_nodes,
            leaves,
            depth,
        }
    }

    pub fn root(&self) -> F {
        self.internal_nodes.last().unwrap()[0]
    }

    pub fn generate_proof(&self, index: usize) -> MerkleProof<F> {
        let leaf_val = self.leaves[index];
        let mut hash_proof = Vec::with_capacity(self.depth);
        let mut curr_index = index;
        for i in 0..self.depth {
            let neighbour = if curr_index.is_multiple_of(2) {
                self.internal_nodes[i][curr_index + 1]
            } else {
                self.internal_nodes[i][curr_index - 1]
            };
            hash_proof.push(neighbour);
            curr_index /= 2;
        }

        MerkleProof {
            index,
            leaf_val,
            auth_path: hash_proof,
            root: self.root(),
        }
    }
}

pub fn verify_merkle_proof<F: PrimeField>(proof: &MerkleProof<F>) -> bool {
    let mut curr_idx = proof.index;
    let mut curr_hash = hash(&proof.leaf_val);

    for i in 0..proof.auth_path.len() {
        let neighbour = proof.auth_path[i];

        if curr_idx.is_multiple_of(2) {
            curr_hash = hash_slice(&[curr_hash, neighbour]);
        } else {
            curr_hash = hash_slice(&[neighbour, curr_hash]);
        }

        curr_idx /= 2;
    }

    curr_hash == proof.root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Fq;

    #[test]
    fn test_merkle_commit_and_verify() {
        let leaves: Vec<Fq> = (0..8).map(|i| Fq::from(i as u64)).collect();
        let tree = MerkleTree::new(leaves.clone());
        let root = tree.root();

        for i in 0..8 {
            let proof = tree.generate_proof(i);
            assert!(verify_merkle_proof(&proof));
            assert_eq!(proof.root, root);
        }
    }

    #[test]
    fn test_merkle_tampered_proof_fails() {
        let leaves: Vec<Fq> = (0..4).map(|i| Fq::from(i as u64)).collect();
        let tree = MerkleTree::new(leaves);

        let mut proof = tree.generate_proof(0);
        proof.leaf_val += Fq::from(1u64); // tamper
        assert!(!verify_merkle_proof(&proof));
    }
}
