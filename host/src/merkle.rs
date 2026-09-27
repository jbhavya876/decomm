use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use tracing::info;

const ANCHOR_STATE_PUBKEY: &str = "F2vD6mCsHB18wbFqNYnwcRZTzV1K2i9eziTet4Tk6kg9";
/// The on-chain program that owns the NetworkState account.
/// D-07: We verify account.owner == this before trusting the root bytes.
const PROGRAM_ID: &str = "8P5tdCSpXPev51dhXRX7w7U7GvFSTc7Jfbt3c6UxyMhG";

// D-07: Domain-separation prefixes.  Must be kept in sync with
// methods/guest/src/main.rs — they share the same logical Merkle tree.
const LEAF_DOMAIN: u8 = 0x00;
const NODE_DOMAIN: u8 = 0x01;

/// Internal-node hash: SHA-256(0x01 || left || right).
pub fn hash_node(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([NODE_DOMAIN]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Leaf hash: SHA-256(0x00 || value).
pub fn hash_leaf(leaf: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_DOMAIN]);
    hasher.update(leaf.as_bytes());
    hasher.finalize().into()
}

/// Fetch the current Merkle root from the live Solana devnet account.
///
/// D-07 hardening applied:
///   - Verifies account.owner == PROGRAM_ID before reading any bytes.
///   - Checks the Anchor 8-byte discriminator is non-zero.
///   - Minimum length guard prevents out-of-bounds slice.
pub fn fetch_onchain_root() -> Result<[u8; 32], &'static str> {
    info!("🌐 Querying Solana for active Network State...");

    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
    let client = RpcClient::new(rpc_url);

    let state_str = std::env::var("DECOMM_STATE_PUBKEY")
        .unwrap_or_else(|_| ANCHOR_STATE_PUBKEY.to_string());
    let prog_str = std::env::var("DECOMM_PROGRAM_ID")
        .unwrap_or_else(|_| PROGRAM_ID.to_string());

    let state_pubkey =
        Pubkey::from_str(&state_str).map_err(|_| "Invalid NetworkState pubkey.")?;
    let program_pubkey =
        Pubkey::from_str(&prog_str).map_err(|_| "Invalid Program ID format.")?;

    match client.get_account(&state_pubkey) {
        Ok(account) => {
            // D-07: Ownership check — reject if the account belongs to any other program.
            if account.owner != program_pubkey {
                return Err("SEC-FAULT: NetworkState account is not owned by the AlterBlock \
                            program.  Possible account substitution attack.");
            }

            let data = &account.data;

            if data.len() < 40 {
                return Err("Account data too small: expected ≥ 40 bytes \
                            (8-byte discriminator + 32-byte Merkle root).");
            }

            // D-07: Sanity-check the Anchor discriminator (first 8 bytes) is non-zero.
            // A zero discriminator indicates an uninitialised or zeroed account.
            if data[0..8] == [0u8; 8] {
                return Err("SEC-FAULT: Anchor discriminator is all-zero.  \
                            Account may be uninitialised.");
            }

            let mut root = [0u8; 32];
            root.copy_from_slice(&data[8..40]);
            info!("✅ On-chain Merkle root fetched and owner-verified.");
            Ok(root)
        }
        Err(_) => Err("Failed to fetch account data from Solana devnet.  \
                       Contract may not be deployed yet, or network is unreachable."),
    }
}

/// Read the member secret from the `DECOMM_MEMBER_SECRET` environment variable.
///
/// D-02: The secret MUST NOT be hardcoded.  Store it in a `.env` file or
/// system keystore that is git-ignored.
///
/// # Errors
/// Returns a descriptive error if the variable is absent or empty so the node
/// fails loudly at startup rather than silently authenticating with a burned secret.
pub fn get_member_secret() -> Result<String, String> {
    match std::env::var("DECOMM_MEMBER_SECRET") {
        Ok(secret) if !secret.trim().is_empty() => Ok(secret),
        Ok(_) => Err(
            "DECOMM_MEMBER_SECRET is set but empty.  \
             Provide your private member secret."
                .to_string(),
        ),
        Err(_) => Err(
            "DECOMM_MEMBER_SECRET environment variable is not set.\n\
             Set it to your private member secret before starting decomm:\n\
               export DECOMM_MEMBER_SECRET='<your-secret>'\n\
             ⚠️  Never commit this value to the repository."
                .to_string(),
        ),
    }
}

/// Build the Merkle proof path and direction indices for `member_secret`.
///
/// The tree layout (index 1 is the member being proved):
/// ```text
///       root
///      /    \
///    n01    n23
///   /   \  /   \
///  L0   L1 L2  L3
/// ```
/// where L1 = hash_leaf(member_secret).
///
/// Path for L1: [L0, n23], indices: [false (L0 is left sibling), true (n23 is right sibling)]
///
/// NOTE: The tree structure is still a demo fixture.  A production deployment
/// must load the witness from a protected per-user credential file and never
/// reconstruct it from known constants.  The on-chain root must be rotated with
/// `update_root` whenever the tree or the hashing scheme changes.
pub fn get_merkle_path_and_indices(member_secret: &str) -> (Vec<[u8; 32]>, Vec<bool>) {
    let leaves = [
        hash_leaf("dummy-peer-0"),
        hash_leaf(member_secret),
        hash_leaf("dummy-peer-2"),
        hash_leaf("dummy-peer-3"),
    ];

    let node_23 = hash_node(&leaves[2], &leaves[3]);

    // Proof for leaf[1] (the member):
    //   Step 0: sibling = leaves[0], on the LEFT  → index false
    //   Step 1: sibling = node_23,   on the RIGHT → index true
    let path = vec![leaves[0], node_23];
    let indices = vec![false, true];

    (path, indices)
}

/// Compute the expected Merkle root for a given member secret.
/// Useful for the initial `initialize` call and for `anchor test` verification.
#[allow(dead_code)]
pub fn compute_root_for_secret(member_secret: &str) -> [u8; 32] {
    let (path, indices) = get_merkle_path_and_indices(member_secret);
    let mut current = hash_leaf(member_secret);
    for (sibling, is_right) in path.iter().zip(indices.iter()) {
        current = if *is_right {
            hash_node(&current, sibling)
        } else {
            hash_node(sibling, &current)
        };
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_separation() {
        // A leaf hash must differ from a node hash even with the same bytes.
        let leaf = hash_leaf("same-bytes");
        // Construct a "node" from two zero halves that happen to concatenate to data — 
        // just verify the domain prefixes produce different hashes.
        let node = hash_node(&[0u8; 16], &[0u8; 16]);
        assert_ne!(leaf, node, "leaf and node hashes must be distinct");
    }

    #[test]
    fn test_hash_node_order_matters() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(
            hash_node(&a, &b),
            hash_node(&b, &a),
            "hash_node(a,b) must differ from hash_node(b,a)"
        );
    }

    #[test]
    fn test_merkle_path_round_trip() {
        let secret = "test-member-secret-for-unit-test";
        let (path, indices) = get_merkle_path_and_indices(secret);
        let computed_root = compute_root_for_secret(secret);

        // The path must reconstruct the same root.
        let mut current = hash_leaf(secret);
        for (sibling, is_right) in path.iter().zip(indices.iter()) {
            current = if *is_right {
                hash_node(&current, sibling)
            } else {
                hash_node(sibling, &current)
            };
        }
        assert_eq!(current, computed_root, "path must reconstruct the root");
    }

    #[test]
    fn test_wrong_secret_fails_proof() {
        let real_secret = "correct-secret";
        let (path, indices) = get_merkle_path_and_indices(real_secret);
        let real_root = compute_root_for_secret(real_secret);

        // Attempt to prove with the wrong secret.
        let mut current = hash_leaf("wrong-secret");
        for (sibling, is_right) in path.iter().zip(indices.iter()) {
            current = if *is_right {
                hash_node(&current, sibling)
            } else {
                hash_node(sibling, &current)
            };
        }
        assert_ne!(
            current, real_root,
            "a wrong secret must not produce the correct root"
        );
    }

    #[test]
    fn test_demo_secret_matches_devnet_root() {
        let root = compute_root_for_secret("alterblock-zk-secret");
        let expected_devnet_root: [u8; 32] = [
            160, 163, 89, 24, 0, 224, 207, 102, 69, 110, 31, 30,
            216, 204, 154, 24, 115, 226, 115, 57, 233, 165, 69, 225,
            82, 150, 242, 163, 66, 237, 58, 170
        ];
        assert_eq!(root, expected_devnet_root, "alterblock-zk-secret must match on-chain root");
    }

    #[test]
    #[ignore = "requires live Solana devnet RPC connectivity"]
    fn test_fetch_onchain_root_live() {
        let live_root = fetch_onchain_root().expect("Live Solana devnet fetch must succeed");
        let expected = compute_root_for_secret("alterblock-zk-secret");
        assert_eq!(live_root, expected, "Live on-chain root must match domain-separated computed root");
    }
}