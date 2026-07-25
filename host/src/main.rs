mod identity;
mod merkle;
mod protocol;

use clap::Parser;
use futures::StreamExt;
use libp2p::{
    gossipsub, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, SwarmBuilder,
};
use std::collections::{HashSet, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::time::Duration;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::identity::NodeIdentity;
use crate::protocol::{AuthPayload, NetworkPayload, PqcCiphertextShare, PqcPublicKeyShare, SecureMessage};
use methods::{METHOD_ELF, METHOD_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};

use pqcrypto_kyber::kyber1024::{decapsulate, encapsulate, Ciphertext, PublicKey};
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    dial: Option<String>,
}

#[derive(NetworkBehaviour)]
struct ChatBehaviour {
    gossipsub: gossipsub::Behaviour,
}

fn spawn_zk_auth_task(
    tx: mpsc::UnboundedSender<AuthPayload>,
    topic_name: String,
    my_peer_id: String,
    anchored_root_cache: std::sync::Arc<std::sync::Mutex<Option<[u8; 32]>>>,
) {
    tokio::spawn(async move {
        println!("⏳ Background Prover: Fetching fresh Solana state & generating ZK Visa...");
        
        let root = {
            let fetch_result = tokio::task::spawn_blocking(crate::merkle::fetch_onchain_root).await;
            match fetch_result {
                Ok(Ok(fresh_root)) => {
                    *anchored_root_cache.lock().unwrap() = Some(fresh_root);
                    fresh_root
                }
                Ok(Err(_)) => {
                    match *anchored_root_cache.lock().unwrap() {
                        Some(cached_root) => cached_root,
                        None => return,
                    }
                }
                Err(_) => return,
            }
        };

        let receipt_result = tokio::task::spawn_blocking(move || {
            let (path, indices) = crate::merkle::get_merkle_path_and_indices();
            let env = ExecutorEnv::builder()
                .write(&topic_name).unwrap()
                .write(&root).unwrap()
                .write(&"alterblock-zk-secret".to_string()).unwrap()
                .write(&path).unwrap()
                .write(&indices).unwrap()
                .build()
                .unwrap();
            let prover = default_prover();
            prover.prove(env, METHOD_ELF).expect("Proof failed").receipt
        }).await;

        if let Ok(receipt) = receipt_result {
            println!("✅ Background Prover: ZK Visa generated successfully.");
            let auth = AuthPayload {
                peer_id: my_peer_id,
                zkp_receipt: receipt,
            };
            let _ = tx.send(auth);
        }
    });
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let node_identity = NodeIdentity::generate();

    println!("📡 Fetching Genesis State from Solana Devnet...");
    match crate::merkle::fetch_onchain_root() {
        Ok(root) => {
            *node_identity.anchored_root.lock().unwrap() = Some(root);
            println!("✅ Anchored Merkle root from Solana Devnet.");
        }
        Err(e) => {
            error!("❌ Critical: Failed to sync genesis state: {}", e);
            return Err(e.into());
        }
    }

    let message_id_fn = |message: &gossipsub::Message| {
        let mut s = DefaultHasher::new();
        message.data.hash(&mut s);
        gossipsub::MessageId::from(s.finish().to_string())
    };

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .message_id_fn(message_id_fn)
        .max_transmit_size(10 * 1024 * 1024)
        .build()
        .expect("Valid config");

    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(node_identity.p2p_keypair.clone()),
        gossipsub_config,
    ).expect("Correct config");

    let behaviour = ChatBehaviour { gossipsub };
    let mut swarm = SwarmBuilder::with_existing_identity(node_identity.p2p_keypair)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    let topic_name = "alterblock-global";
    let topic = gossipsub::IdentTopic::new(topic_name);
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    if let Some(to_dial) = args.dial {
        let addr: Multiaddr = to_dial.parse()?;
        info!("Dialing peer at {}", addr);
        swarm.dial(addr)?;
    }

    let (auth_tx, mut auth_rx) = mpsc::unbounded_channel::<AuthPayload>();
    let mut authorized_peers: HashSet<String> = HashSet::new();

    let mut stdin = BufReader::new(io::stdin()).lines();
    println!("💬 Secure Network Booting... Waiting for PQC & ZK Handshake before allowing chat.");

    loop {
        tokio::select! {
            Ok(Some(line)) = stdin.next_line() => {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    let session_key_opt = { *node_identity.active_session_key.lock().unwrap() };
                    
                    if let Some(session_key) = session_key_opt {
                        let secure_msg = SecureMessage::encrypt(trimmed, &session_key);
                        let payload = NetworkPayload::EncryptedChat(secure_msg);
                        
                        match bincode::serialize(&payload) {
                            Ok(bytes) => {
                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes) {
                                    error!("❌ Failed to publish message: {:?}", e);
                                }
                            }
                            Err(e) => error!("❌ Serialization failed: {:?}", e),
                        }
                    } else {
                        println!("⚠️ Cannot send message yet. Post-Quantum handshake not completed!");
                    }
                }
            }

            Some(auth_payload) = auth_rx.recv() => {
                let payload = NetworkPayload::Auth(auth_payload);
                if let Ok(bytes) = bincode::serialize(&payload) {
                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes) {
                        error!("❌ Failed to broadcast ZK Visa: {:?}", e);
                    } else {
                        println!("📤 Broadcasted ZK Visa to the mesh network.");
                    }
                }
            }

            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => info!("Node listening on: {address}"),
                
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    info!("✅ TCP Connection established with: {}", peer_id);
                }

                SwarmEvent::Behaviour(ChatBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed {
                    peer_id,
                    topic: subscribed_topic,
                })) => {
                    if subscribed_topic.as_str() == topic_name {
                        let my_id = node_identity.peer_id.to_string();
                        let their_id = peer_id.to_string();

                        if my_id > their_id {
                            println!("🔗 Mesh linked! I am KEM Initiator. Broadcasting Kyber Public Key...");
                            let pub_share = PqcPublicKeyShare {
                                peer_id: my_id,
                                public_key_bytes: node_identity.pqc_public_key.as_bytes().to_vec(),
                            };
                            let payload = NetworkPayload::PublicKeyShare(pub_share);
                            let bytes = bincode::serialize(&payload).unwrap();
                            let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes);
                        } else {
                            println!("🔗 Mesh linked! I am KEM Responder. Waiting for Kyber Public Key...");
                        }
                    }
                }

                SwarmEvent::Behaviour(ChatBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message,
                    ..
                })) => {
                    match bincode::deserialize::<NetworkPayload>(&message.data) {

                        Ok(NetworkPayload::PublicKeyShare(share)) => {
                            if share.peer_id != node_identity.peer_id.to_string() {
                                println!("🔄 Received Kyber PK from {}. Encapsulating...", share.peer_id);
                                if let Ok(pk) = PublicKey::from_bytes(&share.public_key_bytes) {
                                    let (shared_secret, ciphertext) = encapsulate(&pk);

                                    let mut secret_bytes = [0u8; 32];
                                    secret_bytes.copy_from_slice(shared_secret.as_bytes());
                                    *node_identity.active_session_key.lock().unwrap() = Some(secret_bytes);

                                    let ct_share = PqcCiphertextShare {
                                        target_peer_id: share.peer_id.clone(),
                                        ciphertext_bytes: ciphertext.as_bytes().to_vec(),
                                    };
                                    let bytes = bincode::serialize(&NetworkPayload::CiphertextShare(ct_share)).unwrap();
                                    let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes);
                                    
                                    spawn_zk_auth_task(
                                        auth_tx.clone(),
                                        topic_name.to_string(),
                                        node_identity.peer_id.to_string(),
                                        node_identity.anchored_root.clone(),
                                    );
                                }
                            }
                        }

                        Ok(NetworkPayload::CiphertextShare(share)) => {
                            if share.target_peer_id == node_identity.peer_id.to_string() {
                                println!("🔄 Received Kyber Ciphertext. Decapsulating...");
                                if let Ok(ct) = Ciphertext::from_bytes(&share.ciphertext_bytes) {
                                    let shared_secret = decapsulate(&ct, &node_identity.pqc_secret_key);

                                    let mut secret_bytes = [0u8; 32];
                                    secret_bytes.copy_from_slice(shared_secret.as_bytes());
                                    *node_identity.active_session_key.lock().unwrap() = Some(secret_bytes);

                                    spawn_zk_auth_task(
                                        auth_tx.clone(),
                                        topic_name.to_string(),
                                        node_identity.peer_id.to_string(),
                                        node_identity.anchored_root.clone(),
                                    );
                                }
                            }
                        }

                        Ok(NetworkPayload::Auth(auth)) => {
                            if auth.peer_id != node_identity.peer_id.to_string() {
                                println!("🔄 Received ZK Visa from {}. Verifying proof...", auth.peer_id);
                                
                                if auth.zkp_receipt.verify(METHOD_ID).is_ok() {
                                    let (journal_topic, journal_root): (String, [u8; 32]) =
                                        auth.zkp_receipt.journal.decode().unwrap();

                                    if journal_topic != topic_name {
                                        error!("🚨 SEC-FAULT: Proof valid, wrong topic '{}'", journal_topic);
                                        continue;
                                    }

                                    let anchored = *node_identity.anchored_root.lock().unwrap();
                                    match anchored {
                                        Some(onchain_root) if journal_root == onchain_root => {
                                            println!("✅ ZK Visa accepted! Peer {} is fully authorized.", auth.peer_id);
                                            authorized_peers.insert(auth.peer_id);
                                        }
                                        Some(_) => error!("🚨 SEC-FAULT: Stale/forged credential. Root mismatch."),
                                        None => error!("🚨 SEC-FAULT: No anchored root available."),
                                    }
                                } else {
                                    error!("🚨 SEC-FAULT: Invalid STARK proof from {}.", auth.peer_id);
                                }
                            }
                        }

                        Ok(NetworkPayload::EncryptedChat(secure_msg)) => {
                            let sender_id = message.source.map(|p| p.to_string()).unwrap_or_else(|| peer_id.to_string());
                            
                            if !authorized_peers.contains(&sender_id) {
                                error!("🚨 Access Denied: Received chat from unauthorized peer {}.", sender_id);
                                continue;
                            }

                            let session_key_opt = { *node_identity.active_session_key.lock().unwrap() };
                            if let Some(session_key) = session_key_opt {
                                match secure_msg.decrypt(&session_key) {
                                    Ok(plaintext) => {
                                        println!("\n[🔒 Verified & PQC E2EE | {}]: {}", sender_id, plaintext);
                                    }
                                    Err(e) => error!("🚨 Decryption failed: {}", e),
                                }
                            }
                        }

                        Err(_) => error!("🚨 WARNING: Malformed binary payload dropped."),
                    }
                }
                _ => {}
            }
        }
    }
}