use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use tracing::{info, error};

const ANCHOR_STATE_PUBKEY: &str = "F2vD6mCsHB18wbFqNYnwcRZTzV1K2i9eziTet4Tk6kg9";

pub fn hash_node(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

pub fn hash_leaf(leaf: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(leaf.as_bytes());
    hasher.finalize().into()
}

/// Connects to Solana Devnet to fetch the official, live Merkle Root.
pub fn fetch_onchain_root() -> Result<[u8; 32], &'static str> {
    info!("🌐 Querying Solana Devnet for active Network State...");
    
    let rpc_url = "https://api.devnet.solana.com";
    let client = RpcClient::new(rpc_url.to_string());
    
    let pubkey = match Pubkey::from_str(ANCHOR_STATE_PUBKEY) {
        Ok(pk) => pk,
        Err(_) => return Err("Invalid Solana Pubkey format."),
    };

    // Note: If ANCHOR_STATE_PUBKEY is 1111... it will return empty data.
    // We will catch this in the main loop until we deploy the real contract.
    match client.get_account_data(&pubkey) {
        Ok(data) => {
            if data.len() < 40 {
                return Err("Account data too small to contain Anchor discriminator + 32-byte root");
            }
            // Skip the 8-byte Anchor discriminator, extract the 32-byte Root
            let mut root = [0u8; 32];
            root.copy_from_slice(&data[8..40]);
            Ok(root)
        }
        Err(_) => Err("Failed to fetch account data. Contract may not be deployed yet."),
    }
}

/// Builds the local path for the ZKVM, but defers the Root to the blockchain.
pub fn get_zk_circuit_variables() -> ([u8; 32], Vec<[u8; 32]>, Vec<bool>) {
    let leaves = [
        hash_leaf("dummy-secret-0"),
        hash_leaf("alterblock-zk-secret"), 
        hash_leaf("dummy-secret-2"),
        hash_leaf("dummy-secret-3"),
    ];

    let node_01 = hash_node(&leaves[0], &leaves[1]);
    let node_23 = hash_node(&leaves[2], &leaves[3]);
    let calculated_local_root = hash_node(&node_01, &node_23);

    let path = vec![leaves[0], node_23];
    let indices = vec![false, true];

    println!("🔑 TRUE LOCAL ROOT: {:?}", calculated_local_root);
    let official_root = match fetch_onchain_root() {
        Ok(onchain_root) => {
            info!("✅ Successfully synced state from Solana.");
            onchain_root
        },
        Err(e) => {
            error!("⚠️ Solana Sync Failed: {}. Falling back to local state.", e);
            calculated_local_root
        }
    };

    (official_root, path, indices)
}