use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};

// D-07: Domain-separation prefixes prevent second-preimage attacks where a
// crafted internal node could be confused with a leaf.
const LEAF_DOMAIN: u8 = 0x00;
const NODE_DOMAIN: u8 = 0x01;

/// Hash two child nodes into a parent node (internal node hash).
fn hash_node(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([NODE_DOMAIN]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Hash a leaf value into a leaf node.
fn hash_leaf(leaf: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_DOMAIN]);
    hasher.update(leaf.as_bytes());
    hasher.finalize().into()
}

fn main() {
    // -----------------------------------------------------------------------
    // 1. PUBLIC INPUTS
    //    These values are committed to the public journal and verified by the
    //    receiving peer.
    // -----------------------------------------------------------------------
    let topic: String = env::read();
    let expected_merkle_root: [u8; 32] = env::read();

    // D-01: The sender's libp2p PeerId is a public input committed to the
    //       journal.  The verifier MUST check this against the authenticated
    //       GossipSub message.source so that a valid receipt cannot be
    //       re-broadcast with a different self-declared peer_id.
    let sender_peer_id: String = env::read();

    // -----------------------------------------------------------------------
    // 2. PRIVATE INPUTS
    //    These remain securely locked inside the VM and are never exposed
    //    in the journal or in any public output.
    // -----------------------------------------------------------------------
    let my_secret_password: String = env::read();
    let merkle_path: Vec<[u8; 32]> = env::read();
    // true  → the sibling sits to the RIGHT of current_hash
    // false → the sibling sits to the LEFT  of current_hash
    let path_indices: Vec<bool> = env::read();

    if merkle_path.len() != path_indices.len() {
        panic!("SEC-FAULT: Merkle path length ({}) != indices length ({}).",
               merkle_path.len(), path_indices.len());
    }

    // -----------------------------------------------------------------------
    // 3. GATEKEEPER: Merkle inclusion proof
    // -----------------------------------------------------------------------
    // Step A: Hash the private secret to get the leaf commitment.
    let mut current_hash: [u8; 32] = hash_leaf(&my_secret_password);

    // Step B: Traverse the Merkle path upward to reconstruct the root.
    for (sibling, is_right_sibling) in merkle_path.iter().zip(path_indices.iter()) {
        current_hash = if *is_right_sibling {
            hash_node(&current_hash, sibling) // current | sibling
        } else {
            hash_node(sibling, &current_hash) // sibling | current
        };
    }

    // Step C: The reconstructed root must equal the approved on-chain root.
    if current_hash != expected_merkle_root {
        panic!("Unauthorized: Merkle inclusion proof failed. \
                Secret is not a member of the current allowlist.");
    }

    // -----------------------------------------------------------------------
    // 4. PUBLIC COMMITMENT
    //    Commit ALL three values so the verifier can check each one.
    //    - topic:          prevents cross-topic receipt replay
    //    - root:           prevents stale/forged credential acceptance
    //    - sender_peer_id: D-01 fix — binds the proof to a specific sender
    // -----------------------------------------------------------------------
    env::commit(&(topic, expected_merkle_root, sender_peer_id));
}