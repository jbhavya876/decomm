use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};

/// Helper function to combine two hashes and hash them together
fn hash_node(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn main() {
    // --- 1. PUBLIC INPUTS ---
    // These are known to the whole network. 
    let topic: String = env::read();
    let expected_merkle_root: [u8; 32] = env::read();

    // --- 2. PRIVATE INPUTS ---
    // These remain securely locked inside the VM memory and are never exposed.
    let my_secret_password: String = env::read();
    let merkle_path: Vec<[u8; 32]> = env::read();
    // A boolean array: true if the sibling is on the right, false if on the left
    let path_indices: Vec<bool> = env::read();

    if merkle_path.len() != path_indices.len() {
        panic!("SEC-FAULT: Merkle path and indices length mismatch.");
    }

    // --- 3. THE GATEKEEPER LOGIC ---
    // Step A: Hash our secret password to get our initial "Leaf Node"
    let mut current_hash: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(my_secret_password.as_bytes());
        hasher.finalize().into()
    };

    // Step B: Traverse the Merkle path up to the root
    for i in 0..merkle_path.len() {
        let sibling = merkle_path[i];
        let is_right_sibling = path_indices[i];

        if is_right_sibling {
            current_hash = hash_node(&current_hash, &sibling);
        } else {
            current_hash = hash_node(&sibling, &current_hash);
        }
    }

    // Step C: Verify our calculated root matches the public approved root
    if current_hash != expected_merkle_root {
        panic!("Unauthorized: Merkle inclusion proof failed. Your credential is not in the allowlist.");
    }

    // --- 4. THE PUBLIC COMMITMENT ---
    // We commit a tuple containing BOTH the topic and the root.
    // When Node B receives this proof, they will read the journal to guarantee 
    // this message is intended for "alterblock-global" AND that the sender 
    // was validated against the correct, current version of the Merkle Root.
    env::commit(&(topic, expected_merkle_root));
}