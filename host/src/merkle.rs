use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use tracing::info;

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


pub fn fetch_onchain_root() -> Result<[u8; 32], &'static str> {
    info!("🌐 Querying Solana Devnet for active Network State...");

    let rpc_url = "https://api.devnet.solana.com";
    let client = RpcClient::new(rpc_url.to_string());

    let pubkey = match Pubkey::from_str(ANCHOR_STATE_PUBKEY) {
        Ok(pk) => pk,
        Err(_) => return Err("Invalid Solana Pubkey format."),
    };

    match client.get_account_data(&pubkey) {
        Ok(data) => {
            if data.len() < 40 {
                return Err("Account data too small to contain Anchor discriminator + 32-byte root");
            }
            let mut root = [0u8; 32];
            root.copy_from_slice(&data[8..40]);
            Ok(root)
        }
        Err(_) => Err("Failed to fetch account data. Contract may not be deployed yet."),
    }
}

pub fn get_merkle_path_and_indices() -> (Vec<[u8; 32]>, Vec<bool>) {
    let leaves = [
        hash_leaf("dummy-secret-0"),
        hash_leaf("alterblock-zk-secret"),
        hash_leaf("dummy-secret-2"),
        hash_leaf("dummy-secret-3"),
    ];

    let node_23 = hash_node(&leaves[2], &leaves[3]);

    let path = vec![leaves[0], node_23];
    let indices = vec![false, true];

    (path, indices)
}