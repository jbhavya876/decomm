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
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tracing::{error, info};

use crate::identity::NodeIdentity;
use crate::protocol::{NetworkPayload, PqcCiphertextShare, PqcPublicKeyShare, SecureMessage};
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let node_identity = NodeIdentity::generate();

    println!("📡 Fetching Genesis State validation from Solana Devnet...");
    
    match crate::merkle::fetch_onchain_root() {
        Ok(root) => {
            println!("✅ Successfully synced state from Solana.");
            info!("Validated Genesis Root from Ledger: {:?}", root);
        }
        Err(e) => {
            error!("❌ Critical: Failed to sync genesis state from blockchain: {}", e);
            println!("Fallback: System halting due to missing consensus state.");
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

    let mut stdin = BufReader::new(io::stdin()).lines();
    println!("💬 Secure Network Booting... Waiting for PQC Handshake before allowing chat.");

    loop {
        tokio::select! {
            // --- A: OUTGOING MESSAGES (THE PROVER & ENCRYPTOR) ---
            Ok(Some(line)) = stdin.next_line() => {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    
                    // 1. Check if the PQC Handshake has completed!
                    let session_key_opt = { *node_identity.active_session_key.lock().unwrap() };
                    
                    if let Some(session_key) = session_key_opt {
                        println!("⏳ Executing guest program and generating real STARK Proof...");
                        println!("⚠️  (This will take significant compute time...)");
                        
                        let (root, path, indices) = merkle::get_zk_circuit_variables();
                        let env = ExecutorEnv::builder()
                            .write(&topic_name.to_string()).unwrap()
                            .write(&root).unwrap()
                            .write(&"alterblock-zk-secret".to_string()).unwrap()
                            .write(&path).unwrap()
                            .write(&indices).unwrap()
                            .build()
                            .unwrap();

                        let prover = default_prover();
                        
                        // Start the precise timer for STARK generation
                        let start_time = std::time::Instant::now();
                        
                        let prove_info = prover.prove(env, METHOD_ELF).expect("Failed to generate ZK Proof");
                        
                        // Stop the timer
                        let elapsed = start_time.elapsed();
                        
                        // Measure the payload weight of the resulting receipt
                        let receipt_bytes = bincode::serialize(&prove_info.receipt).unwrap().len();

                        println!("✅ REAL Proof Generated!");
                        println!("⏱️  Proving Time: {:.2?}", elapsed);
                        println!("🔐 Receipt Payload Size: {} bytes", receipt_bytes);
                        println!("Encrypting with Kyber1024 Session Key...");

                        // 2. Encrypt using the dynamic session key
                        let secure_msg = SecureMessage::encrypt(trimmed, prove_info.receipt, &session_key);
                        
                        // 3. Wrap in the Master Routing Payload
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
            
            // --- B: INCOMING NETWORK EVENTS (ROUTING & VERIFICATION) ---
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => info!("Node listening on: {address}"),
                
                // STEP 1: Transport layer connects
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    info!("✅ TCP Connection established with: {}", peer_id);
                    println!("⏳ Waiting for Gossipsub mesh to link...");
                }
                
                // STEP 2: Routing layer links -> The Decentralized Tie-Breaker
                SwarmEvent::Behaviour(ChatBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed {
                    peer_id,
                    topic: subscribed_topic,
                })) => {
                    if subscribed_topic.as_str() == topic_name {
                        let my_id = node_identity.peer_id.to_string();
                        let their_id = peer_id.to_string();

                        // Tie-Breaker: Only the node with the "larger" ID broadcasts the Public Key
                        if my_id > their_id {
                            println!("🔗 Mesh linked! I am the KEM Initiator. Broadcasting Kyber Public Key...");
                            
                            let pub_share = PqcPublicKeyShare {
                                peer_id: my_id,
                                public_key_bytes: node_identity.pqc_public_key.as_bytes().to_vec(),
                            };
                            let payload = NetworkPayload::PublicKeyShare(pub_share);
                            let bytes = bincode::serialize(&payload).expect("Failed to serialize key");
                            
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes) {
                                error!("❌ Failed to broadcast public key: {:?}", e);
                            }
                        } else {
                            println!("🔗 Mesh linked! I am the KEM Responder. Waiting for Kyber Public Key...");
                        }
                    }
                }
                
                SwarmEvent::Behaviour(ChatBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message,
                    ..
                })) => {
                    // DESERIALIZE USING THE MASTER ROUTER ENUM
                    match bincode::deserialize::<NetworkPayload>(&message.data) {
                        
                        // --- KEM HANDSHAKE PART 1: RECEIVED PUBLIC KEY ---
                        Ok(NetworkPayload::PublicKeyShare(share)) => {
                            if share.peer_id != node_identity.peer_id.to_string() {
                                println!("🔄 Received Kyber Public Key from {}. Encapsulating secret...", share.peer_id);
                                
                                if let Ok(pk) = PublicKey::from_bytes(&share.public_key_bytes) {
                                    // Math: The return order is strictly (SharedSecret, Ciphertext)
                                    let (shared_secret, ciphertext) = encapsulate(&pk);
                                    
                                    // Save the true 32-byte secret to our thread-safe state
                                    let mut secret_bytes = [0u8; 32];
                                    secret_bytes.copy_from_slice(shared_secret.as_bytes());
                                    *node_identity.active_session_key.lock().unwrap() = Some(secret_bytes);
                                    
                                    println!("🔐 Session key negotiated (Encapsulator). Sending Ciphertext back...");
                                    
                                    let ct_share = PqcCiphertextShare {
                                        target_peer_id: share.peer_id.clone(),
                                        // Now we are actually sending the 1568-byte ciphertext over the wire
                                        ciphertext_bytes: ciphertext.as_bytes().to_vec(),
                                    };
                                    let payload = NetworkPayload::CiphertextShare(ct_share);
                                    let bytes = bincode::serialize(&payload).unwrap();
                                    swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes).unwrap();
                                }
                            }
                        }
                        
                        // --- KEM HANDSHAKE PART 2: RECEIVED CIPHERTEXT ---
                        Ok(NetworkPayload::CiphertextShare(share)) => {
                            if share.target_peer_id == node_identity.peer_id.to_string() {
                                println!("🔄 Received Kyber Ciphertext. Decapsulating...");
                                
                                if let Ok(ct) = Ciphertext::from_bytes(&share.ciphertext_bytes) {
                                    // Math: Use our local Secret Key to unlock the ciphertext and derive the shared secret
                                    let shared_secret = decapsulate(&ct, &node_identity.pqc_secret_key);
                                    
                                    // Save the 32-byte secret to our thread-safe state
                                    let mut secret_bytes = [0u8; 32];
                                    secret_bytes.copy_from_slice(shared_secret.as_bytes());
                                    *node_identity.active_session_key.lock().unwrap() = Some(secret_bytes);
                                    
                                    println!("🔐 Session key negotiated (Decapsulator). Post-Quantum Secure Channel Live!");
                                }
                            }
                        }
                        
                        // --- SECURE CHAT: VERIFY & DECRYPT ---
                        Ok(NetworkPayload::EncryptedChat(secure_msg)) => {
                            let session_key_opt = { *node_identity.active_session_key.lock().unwrap() };
                            
                            if let Some(session_key) = session_key_opt {
                                // 1. Verify the Zero-Knowledge Merkle Proof
                                if secure_msg.zkp_receipt.verify(METHOD_ID).is_ok() {
                                    let (journal_topic, _): (String, [u8; 32]) = secure_msg.zkp_receipt.journal.decode().unwrap();
                                    if journal_topic == topic_name {
                                        
                                        // 2. Decrypt with the negotiated Post-Quantum key
                                        match secure_msg.decrypt(&session_key) {
                                            Ok(plaintext) => println!("\n[🔒 Verified & PQC E2EE | {}]: {}", peer_id, plaintext),
                                            Err(e) => error!("🚨 Decryption failed: {}", e),
                                        }
                                        
                                    } else {
                                        error!("🚨 SEC-FAULT: Proof valid, wrong topic: {}", journal_topic);
                                    }
                                } else {
                                    error!("🚨 SEC-FAULT: Invalid ZK Proof from {}.", peer_id);
                                }
                            } else {
                                error!("🚨 Received encrypted message, but PQC session key is not established yet!");
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