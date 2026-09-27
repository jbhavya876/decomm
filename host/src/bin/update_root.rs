use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{read_keypair_file, Signer},
    transaction::Transaction,
};
use std::str::FromStr;

const LEAF_DOMAIN: u8 = 0x00;
const NODE_DOMAIN: u8 = 0x01;

fn hash_node(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([NODE_DOMAIN]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn hash_leaf(leaf: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_DOMAIN]);
    hasher.update(leaf.as_bytes());
    hasher.finalize().into()
}

fn compute_root(member_secret: &str) -> [u8; 32] {
    let leaves = [
        hash_leaf("dummy-peer-0"),
        hash_leaf(member_secret),
        hash_leaf("dummy-peer-2"),
        hash_leaf("dummy-peer-3"),
    ];
    let node_01 = hash_node(&leaves[0], &leaves[1]);
    let node_23 = hash_node(&leaves[2], &leaves[3]);
    hash_node(&node_01, &node_23)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
    let client = RpcClient::new(rpc_url);

    let default_keypair_path = std::env::var("HOME")
        .map(|h| format!("{h}/.config/solana/id.json"))
        .unwrap_or_else(|_| "~/.config/solana/id.json".to_string());
    let keypair_path = std::env::var("SOLANA_KEYPAIR_PATH")
        .unwrap_or(default_keypair_path);

    let admin_keypair = read_keypair_file(&keypair_path)
        .map_err(|e| format!("Failed to read {keypair_path}: {e}"))?;

    let program_id = Pubkey::from_str(
        &std::env::var("DECOMM_PROGRAM_ID")
            .unwrap_or_else(|_| "8P5tdCSpXPev51dhXRX7w7U7GvFSTc7Jfbt3c6UxyMhG".to_string()),
    )?;
    let state_pubkey = Pubkey::from_str(
        &std::env::var("DECOMM_STATE_PUBKEY")
            .unwrap_or_else(|_| "F2vD6mCsHB18wbFqNYnwcRZTzV1K2i9eziTet4Tk6kg9".to_string()),
    )?;


    let secret = std::env::var("DECOMM_MEMBER_SECRET")
        .unwrap_or_else(|_| "alterblock-zk-secret".to_string());
    let new_root = compute_root(&secret);
    println!("🔑 Member secret: '{}'", secret);
    println!("🌲 New domain-separated Merkle root: {:?}", new_root);

    // Anchor instruction discriminator: sha256("global:update_root")[:8]
    let mut hasher = Sha256::new();
    hasher.update(b"global:update_root");
    let disc = &hasher.finalize()[..8];

    let mut ix_data = Vec::with_capacity(40);
    ix_data.extend_from_slice(disc);
    ix_data.extend_from_slice(&new_root);

    let accounts = vec![
        AccountMeta::new(state_pubkey, false),
        AccountMeta::new_readonly(admin_keypair.pubkey(), true),
    ];

    let ix = Instruction::new_with_bytes(program_id, &ix_data, accounts);

    println!("📡 Fetching latest blockhash from Solana Devnet...");
    let recent_blockhash = client.get_latest_blockhash()?;

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&admin_keypair.pubkey()),
        &[&admin_keypair],
        recent_blockhash,
    );

    println!("🚀 Broadcasting update_root transaction...");
    let sig = client.send_and_confirm_transaction(&tx)?;
    println!("✅ Successfully updated on-chain root!");
    println!("📜 Transaction signature: {}", sig);

    println!("🔍 Querying updated on-chain account state...");
    let account = client.get_account(&state_pubkey)?;
    let onchain_root = &account.data[8..40];
    println!("🌲 On-chain root verified: {:?}", onchain_root);
    assert_eq!(onchain_root, &new_root);
    println!("🎉 Verified on-chain root matches new root perfectly!");

    Ok(())
}
