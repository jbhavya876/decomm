mod identity;
mod merkle;
mod protocol;

use clap::Parser;
use futures::StreamExt;
use hkdf::Hkdf;
use libp2p::{
    gossipsub, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, SwarmBuilder,
};
use sha2::Sha256;
use std::collections::{HashMap, HashSet, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::time::Duration;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::identity::NodeIdentity;
use crate::protocol::{
    AuthPayload, NetworkPayload, PqcCiphertextShare, PqcPublicKeyShare, SecureMessage,
};
use methods::{METHOD_ELF, METHOD_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};

use pqcrypto_kyber::kyber1024::{decapsulate, encapsulate, Ciphertext, PublicKey};
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, help = "Multiaddr of a peer to dial, e.g. /ip4/127.0.0.1/tcp/12345")]
    dial: Option<String>,
    #[arg(short, long, help = "Port to listen on (defaults to 0 for OS-assigned port)")]
    port: Option<u16>,
}

// ---------------------------------------------------------------------------
// libp2p network behaviour
// ---------------------------------------------------------------------------

#[derive(NetworkBehaviour)]
struct ChatBehaviour {
    gossipsub: gossipsub::Behaviour,
}

// ---------------------------------------------------------------------------
// D-04: HKDF key derivation
//
// Raw KEM output is used directly as a cipher key in the original code.
// HKDF-SHA256 extracts entropy and binds the key to both participants and the
// ciphertext transcript, preventing cross-session key reuse.
//
// `initiator_id` = the peer that broadcast the Kyber public key.
// `responder_id` = the peer that encapsulated (sent the ciphertext back).
// `ct_bytes`     = the Kyber ciphertext bytes, included for transcript binding.
// ---------------------------------------------------------------------------
fn derive_session_key(
    kem_shared_secret: &[u8],
    initiator_id: &str,
    responder_id: &str,
    ct_bytes: &[u8],
) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, kem_shared_secret);
    let mut okm = [0u8; 32];
    // Info string binds the key to the two parties and the ciphertext.
    // Both sides must compute this with the same (initiator, responder) order.
    let mut info: Vec<u8> = b"decomm-v1-session-key:".to_vec();
    info.extend_from_slice(initiator_id.as_bytes());
    info.extend_from_slice(b":");
    info.extend_from_slice(responder_id.as_bytes());
    info.extend_from_slice(b":");
    info.extend_from_slice(ct_bytes);

    hk.expand(&info, &mut okm)
        .expect("HKDF expand failed — OKM length is a compile-time constant");
    okm
}

// ---------------------------------------------------------------------------
// D-01, D-02: Background ZK prover task
//
// Spawned after a successful KEM handshake.  Fetches a fresh on-chain root,
// then generates a STARK receipt inside a blocking thread to avoid starving
// the async runtime.  The receipt commits (topic, root, sender_peer_id) so
// the verifier can bind it to the authenticated GossipSub message.source.
// ---------------------------------------------------------------------------
fn spawn_zk_auth_task(
    tx: mpsc::UnboundedSender<AuthPayload>,
    topic_name: String,
    // D-01: The node's own authenticated PeerId — committed into the journal.
    my_peer_id: String,
    // D-02: Private member secret read from the environment, not the source.
    member_secret: String,
    anchored_root_cache: std::sync::Arc<std::sync::Mutex<Option<[u8; 32]>>>,
) {
    tokio::spawn(async move {
        println!("⏳ Background Prover: Fetching fresh Solana state & generating ZK Visa...");

        // Attempt a live Solana fetch; fall back to the in-memory cache if the
        // RPC is temporarily unavailable (the F-01 fix: only use a *previously
        // verified on-chain root*, never a locally computed one).
        let root = {
            let fetch_result =
                tokio::task::spawn_blocking(crate::merkle::fetch_onchain_root).await;
            match fetch_result {
                Ok(Ok(fresh_root)) => {
                    *anchored_root_cache.lock().unwrap() = Some(fresh_root);
                    fresh_root
                }
                Ok(Err(e)) => {
                    warn!("⚠️  Solana fetch failed in prover: {e}");
                    match *anchored_root_cache.lock().unwrap() {
                        Some(cached) => {
                            warn!("⚠️  Using cached on-chain root for ZK proof.");
                            cached
                        }
                        None => {
                            error!("❌ No cached root available.  Cannot generate ZK proof.");
                            return;
                        }
                    }
                }
                Err(e) => {
                    error!("❌ spawn_blocking panicked during Solana fetch: {e}");
                    return;
                }
            }
        };

        let display_id = my_peer_id.clone();
        let receipt_result = tokio::task::spawn_blocking(move || -> Result<_, String> {
            let (path, indices) =
                crate::merkle::get_merkle_path_and_indices(&member_secret);

            // Input order must match the guest's env::read() sequence:
            //   1. topic          (public  — committed to journal)
            //   2. root           (public  — committed to journal)
            //   3. sender_peer_id (public  — D-01: committed to journal)
            //   4. member_secret  (private — never leaves the VM)
            //   5. merkle_path    (private)
            //   6. path_indices   (private)
            let env = ExecutorEnv::builder()
                .write(&topic_name)
                .map_err(|e| format!("Failed to write topic: {e}"))?
                .write(&root)
                .map_err(|e| format!("Failed to write root: {e}"))?
                .write(&my_peer_id)
                .map_err(|e| format!("Failed to write peer_id: {e}"))?
                .write(&member_secret)
                .map_err(|e| format!("Failed to write secret: {e}"))?
                .write(&path)
                .map_err(|e| format!("Failed to write path: {e}"))?
                .write(&indices)
                .map_err(|e| format!("Failed to write indices: {e}"))?
                .build()
                .map_err(|e| format!("ExecutorEnv build failed: {e}"))?;

            let prover = default_prover();
            let receipt = prover
                .prove(env, METHOD_ELF)
                .map_err(|e| format!("STARK proving failed: {e}"))?
                .receipt;
            Ok(receipt)
        })
        .await;

        match receipt_result {
            Ok(Ok(receipt)) => {
                println!("✅ Background Prover: ZK Visa generated successfully.");
                let auth = AuthPayload {
                    display_peer_id: display_id,
                    zkp_receipt: receipt,
                };
                if tx.send(auth).is_err() {
                    error!("❌ Failed to deliver ZK receipt to main loop (channel closed).");
                }
            }
            Ok(Err(e)) => {
                // D-08: These were previously silent panics.  Now reported clearly.
                error!("❌ ZK proof generation failed: {e}");
                println!("❌ ZK Visa generation failed — this node cannot authorize.  \
                          Check DECOMM_MEMBER_SECRET and Solana connectivity.");
            }
            Err(e) => {
                error!("❌ spawn_blocking task panicked: {e}");
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    // D-02: Read the member secret from the environment at startup.
    // Fail loudly and immediately rather than silently using a burned secret.
    let member_secret = match crate::merkle::get_member_secret() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ {e}");
            std::process::exit(1);
        }
    };

    let node_identity = NodeIdentity::generate();

    println!("📡 Fetching Genesis State from Solana Devnet...");
    match crate::merkle::fetch_onchain_root() {
        Ok(root) => {
            *node_identity.anchored_root.lock().unwrap() = Some(root);
            println!("✅ Anchored Merkle root from Solana Devnet (owner-verified).");
        }
        Err(e) => {
            error!("❌ Critical: Failed to sync genesis state: {e}");
            return Err(e.into());
        }
    }

    // GossipSub configuration.
    // D-05 note: message_id_fn now includes message.source and sequence_number
    // so two identical ciphertexts from different senders or at different sequence
    // positions do not collide in the deduplication cache.
    let message_id_fn = |message: &gossipsub::Message| {
        let mut s = DefaultHasher::new();
        message.source.hash(&mut s);
        message.sequence_number.hash(&mut s);
        message.data.hash(&mut s);
        gossipsub::MessageId::from(s.finish().to_string())
    };

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .message_id_fn(message_id_fn)
        .max_transmit_size(10 * 1024 * 1024)
        .build()
        .expect("Valid gossipsub config");

    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(node_identity.p2p_keypair.clone()),
        gossipsub_config,
    )
    .expect("Correct gossipsub config");

    let behaviour = ChatBehaviour { gossipsub };
    let mut swarm = SwarmBuilder::with_existing_identity(node_identity.p2p_keypair.clone())
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    let topic_name = "alterblock-global";
    let topic = gossipsub::IdentTopic::new(topic_name);
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    let listen_port = args.port.unwrap_or(0);
    swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{listen_port}").parse()?)?;

    if let Some(to_dial) = args.dial {
        let addr: Multiaddr = to_dial.parse()?;
        info!("Dialing peer at {addr}");
        swarm.dial(addr)?;
    }

    let (auth_tx, mut auth_rx) = mpsc::unbounded_channel::<AuthPayload>();

    // D-03: Per-peer authorization set and per-peer last-seen sequence numbers.
    let mut authorized_peers: HashSet<String> = HashSet::new();
    // D-06: Track the last accepted seq per sender to reject replays.
    let mut peer_last_seq: HashMap<String, u64> = HashMap::new();

    let mut stdin = BufReader::new(io::stdin()).lines();
    println!("💬 Secure Network Booting... Waiting for PQC & ZK Handshake before allowing chat.");

    loop {
        tokio::select! {
            // ------------------------------------------------------------------
            // Stdin: outgoing chat message
            // ------------------------------------------------------------------
            Ok(Some(line)) = stdin.next_line() => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                // D-03: Encrypt to all authorized peers individually.
                // For this two-peer prototype we still have one session key per
                // remote peer; pick the first available one.
                let session_keys_snapshot = {
                    node_identity.session_keys.lock().unwrap().clone()
                };

                let my_id = node_identity.peer_id.to_string();
                let seq = {
                    let mut seq = node_identity.send_seq.lock().unwrap();
                    *seq = seq.wrapping_add(1);
                    *seq
                };

                // Send to all peers that share a session key and are authorized.
                let mut sent = false;
                for (peer_id, session_key) in &session_keys_snapshot {
                    if authorized_peers.contains(peer_id) {
                        // D-06: seq and my_id are bound into the AEAD associated data.
                        let secure_msg = SecureMessage::encrypt(trimmed, session_key, &my_id, seq);
                        let payload = NetworkPayload::EncryptedChat(secure_msg);
                        match bincode::serialize(&payload) {
                            Ok(bytes) => {
                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes) {
                                    error!("❌ Failed to publish message: {e:?}");
                                } else {
                                    sent = true;
                                }
                            }
                            Err(e) => error!("❌ Serialization failed: {e:?}"),
                        }
                        break; // For the two-peer demo, one key suffices.
                    }
                }
                if !sent {
                    println!("⚠️  Cannot send: no authorized peer with an established session key yet.");
                }
            }

            // ------------------------------------------------------------------
            // Internal: ZK receipt ready — broadcast it
            // ------------------------------------------------------------------
            Some(auth_payload) = auth_rx.recv() => {
                let payload = NetworkPayload::Auth(auth_payload);
                match bincode::serialize(&payload) {
                    Ok(bytes) => {
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes) {
                            error!("❌ Failed to broadcast ZK Visa: {e:?}");
                        } else {
                            println!("📤 Broadcasted ZK Visa to the mesh network.");
                        }
                    }
                    Err(e) => error!("❌ Failed to serialize ZK Visa: {e:?}"),
                }
            }

            // ------------------------------------------------------------------
            // libp2p swarm events
            // ------------------------------------------------------------------
            event = swarm.select_next_some() => match event {

                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("📡 Node listening on: {address}");
                    info!("Node listening on: {address}");
                }

                SwarmEvent::ConnectionEstablished { peer_id, .. } =>
                    info!("✅ TCP Connection established with: {peer_id}"),

                // --------------------------------------------------------------
                // GossipSub: peer subscribed — initiate KEM if we are the higher ID
                // --------------------------------------------------------------
                SwarmEvent::Behaviour(ChatBehaviourEvent::Gossipsub(
                    gossipsub::Event::Subscribed { peer_id, topic: subscribed_topic },
                )) => {
                    if subscribed_topic.as_str() == topic_name {
                        let my_id = node_identity.peer_id.to_string();
                        let their_id = peer_id.to_string();

                        if my_id > their_id {
                            println!("🔗 Mesh linked! I am KEM Initiator. Broadcasting Kyber Public Key...");
                            let pub_share = PqcPublicKeyShare {
                                peer_id: my_id,
                                public_key_bytes: node_identity.pqc_public_key.as_bytes().to_vec(),
                            };
                            match bincode::serialize(&NetworkPayload::PublicKeyShare(pub_share)) {
                                Ok(bytes) => {
                                    let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes);
                                }
                                Err(e) => error!("❌ Failed to serialize public key share: {e:?}"),
                            }
                        } else {
                            println!("🔗 Mesh linked! I am KEM Responder. Waiting for Kyber Public Key...");
                        }
                    }
                }

                // --------------------------------------------------------------
                // GossipSub: incoming message
                // --------------------------------------------------------------
                SwarmEvent::Behaviour(ChatBehaviourEvent::Gossipsub(
                    gossipsub::Event::Message { propagation_source, message, .. },
                )) => {
                    // The authenticated source of this message (signed by their libp2p key).
                    // For replay/impersonation protection we use this, not any self-declared field.
                    let auth_source: String = match message.source {
                        Some(src) => src.to_string(),
                        None => {
                            // Strict validation mode should prevent unsigned messages, but be safe.
                            warn!("⚠️  Dropped message with no source from propagation peer {propagation_source}");
                            continue;
                        }
                    };

                    // Skip our own messages reflected by the mesh.
                    if auth_source == node_identity.peer_id.to_string() {
                        continue;
                    }

                    match bincode::deserialize::<NetworkPayload>(&message.data) {

                        // ----------------------------------------------------------
                        // KEM step 1: Initiator's public key — we are the Responder
                        // ----------------------------------------------------------
                        Ok(NetworkPayload::PublicKeyShare(share)) => {
                            // D-03: The declared peer_id must match the GossipSub-signed source.
                            if share.peer_id != auth_source {
                                error!(
                                    "🚨 SEC-FAULT: PublicKeyShare peer_id '{}' != authenticated \
                                     source '{auth_source}'.  Dropping.",
                                    share.peer_id
                                );
                                continue;
                            }
                            let initiator_id = share.peer_id.clone();

                            println!("🔄 Received Kyber PK from {initiator_id}. Encapsulating...");
                            match PublicKey::from_bytes(&share.public_key_bytes) {
                                Ok(pk) => {
                                    let (shared_secret, ciphertext) = encapsulate(&pk);
                                    let my_id = node_identity.peer_id.to_string();

                                    // D-04: HKDF over raw KEM output, binding both peer IDs + ciphertext.
                                    let session_key = derive_session_key(
                                        shared_secret.as_bytes(),
                                        &initiator_id,  // the initiator
                                        &my_id,         // we are the responder
                                        ciphertext.as_bytes(),
                                    );

                                    // D-03: Store per-peer, keyed by initiator's authenticated ID.
                                    node_identity
                                        .session_keys
                                        .lock()
                                        .unwrap()
                                        .insert(initiator_id.clone(), session_key);

                                    let ct_share = PqcCiphertextShare {
                                        sender_peer_id: my_id.clone(),
                                        target_peer_id: initiator_id.clone(),
                                        ciphertext_bytes: ciphertext.as_bytes().to_vec(),
                                    };
                                    match bincode::serialize(&NetworkPayload::CiphertextShare(ct_share)) {
                                        Ok(bytes) => {
                                            let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes);
                                        }
                                        Err(e) => error!("❌ Failed to serialize ciphertext share: {e:?}"),
                                    }

                                    // Start ZK proof generation concurrently.
                                    spawn_zk_auth_task(
                                        auth_tx.clone(),
                                        topic_name.to_string(),
                                        my_id,
                                        member_secret.clone(),
                                        node_identity.anchored_root.clone(),
                                    );
                                }
                                Err(e) => {
                                    error!("❌ Failed to deserialize Kyber public key: {e:?}");
                                }
                            }
                        }

                        // ----------------------------------------------------------
                        // KEM step 2: Responder's ciphertext — we are the Initiator
                        // ----------------------------------------------------------
                        Ok(NetworkPayload::CiphertextShare(share)) => {
                            if share.target_peer_id != node_identity.peer_id.to_string() {
                                // Not addressed to us — ignore silently.
                                continue;
                            }

                            // D-03: Verify the CT actually came from who it claims.
                            if share.sender_peer_id != auth_source {
                                error!(
                                    "🚨 SEC-FAULT: CiphertextShare sender_peer_id '{}' != \
                                     authenticated source '{auth_source}'.  Dropping.",
                                    share.sender_peer_id
                                );
                                continue;
                            }
                            let responder_id = share.sender_peer_id.clone();

                            println!("🔄 Received Kyber Ciphertext from {responder_id}. Decapsulating...");
                            match Ciphertext::from_bytes(&share.ciphertext_bytes) {
                                Ok(ct) => {
                                    let shared_secret =
                                        decapsulate(&ct, &node_identity.pqc_secret_key);
                                    let my_id = node_identity.peer_id.to_string();

                                    // D-04: HKDF — same call as responder but with roles consistent:
                                    //   initiator = us (my_id), responder = them (responder_id).
                                    let session_key = derive_session_key(
                                        shared_secret.as_bytes(),
                                        &my_id,          // we are the initiator
                                        &responder_id,   // they are the responder
                                        ct.as_bytes(),
                                    );

                                    // D-03: Store per-peer.
                                    node_identity
                                        .session_keys
                                        .lock()
                                        .unwrap()
                                        .insert(responder_id.clone(), session_key);

                                    spawn_zk_auth_task(
                                        auth_tx.clone(),
                                        topic_name.to_string(),
                                        my_id,
                                        member_secret.clone(),
                                        node_identity.anchored_root.clone(),
                                    );
                                }
                                Err(e) => {
                                    error!("❌ Failed to deserialize Kyber ciphertext: {e:?}");
                                }
                            }
                        }

                        // ----------------------------------------------------------
                        // ZK receipt: membership proof from a remote peer
                        // ----------------------------------------------------------
                        Ok(NetworkPayload::Auth(auth)) => {
                            println!(
                                "🔄 Received ZK Visa from {}. Verifying STARK proof...",
                                auth.display_peer_id
                            );

                            // Step 1: Cryptographically verify the STARK proof.
                            match auth.zkp_receipt.verify(METHOD_ID) {
                                Err(e) => {
                                    error!("🚨 SEC-FAULT: Invalid STARK proof from {auth_source}: {e}");
                                    continue;
                                }
                                Ok(()) => {}
                            }

                            // Step 2: Decode the public journal.
                            // D-01 fix: Journal now includes (topic, root, sender_peer_id).
                            let (journal_topic, journal_root, journal_peer_id): (String, [u8; 32], String) =
                                match auth.zkp_receipt.journal.decode() {
                                    Ok(v) => v,
                                    Err(e) => {
                                        error!("🚨 SEC-FAULT: Failed to decode ZK journal: {e}");
                                        continue;
                                    }
                                };

                            // Step 3: Topic must match this network's topic.
                            if journal_topic != topic_name {
                                error!(
                                    "🚨 SEC-FAULT: Proof valid but for wrong topic '{journal_topic}'."
                                );
                                continue;
                            }

                            // Step 4: Root in the proof must match our on-chain anchor.
                            let anchored = *node_identity.anchored_root.lock().unwrap();
                            match anchored {
                                Some(onchain_root) if journal_root != onchain_root => {
                                    error!("🚨 SEC-FAULT: Stale/forged credential — root mismatch.");
                                    continue;
                                }
                                None => {
                                    error!("🚨 SEC-FAULT: No anchored root available.");
                                    continue;
                                }
                                _ => {}
                            }

                            // Step 5: D-01 — The peer ID in the journal must equal the
                            // GossipSub-authenticated source.  This prevents replaying a
                            // valid receipt with a different self-declared identity.
                            if journal_peer_id != auth_source {
                                error!(
                                    "🚨 SEC-FAULT: Journal peer_id '{journal_peer_id}' != \
                                     authenticated GossipSub source '{auth_source}'.  \
                                     Possible receipt replay attack — dropping."
                                );
                                continue;
                            }

                            println!("✅ ZK Visa accepted! Peer {auth_source} is fully authorized.");
                            authorized_peers.insert(auth_source);
                        }

                        // ----------------------------------------------------------
                        // Encrypted chat message
                        // ----------------------------------------------------------
                        Ok(NetworkPayload::EncryptedChat(secure_msg)) => {
                            // D-03: sender is the authenticated GossipSub source.
                            let sender_id = auth_source;

                            if !authorized_peers.contains(&sender_id) {
                                error!(
                                    "🚨 Access Denied: Received chat from unauthorized peer {sender_id}."
                                );
                                continue;
                            }

                            // D-06: Replay protection — reject messages at or below last seen seq.
                            let last_seq = peer_last_seq.get(&sender_id).copied().unwrap_or(0);
                            if secure_msg.seq <= last_seq {
                                warn!(
                                    "⚠️  Dropped replayed message from {sender_id}: \
                                     seq {} ≤ last seen {last_seq}.",
                                    secure_msg.seq
                                );
                                continue;
                            }
                            peer_last_seq.insert(sender_id.clone(), secure_msg.seq);

                            // D-03: Look up the per-peer session key.
                            let session_key_opt = {
                                node_identity.session_keys.lock().unwrap().get(&sender_id).copied()
                            };
                            match session_key_opt {
                                Some(session_key) => {
                                    // D-06: Pass sender_id so AEAD AD can be reconstructed.
                                    match secure_msg.decrypt(&session_key, &sender_id) {
                                        Ok(plaintext) => {
                                            println!(
                                                "\n[🔒 Verified & PQC E2EE | {}]: {}",
                                                sender_id, plaintext
                                            );
                                        }
                                        Err(e) => error!("🚨 Decryption failed: {e}"),
                                    }
                                }
                                None => {
                                    warn!(
                                        "⚠️  Authorized peer {sender_id} sent a message \
                                         but has no session key.  Handshake may be incomplete."
                                    );
                                }
                            }
                        }

                        Err(_) => {
                            error!("🚨 WARNING: Malformed binary payload from {propagation_source} — dropped.");
                        }
                    }
                }

                _ => {}
            }
        }
    }
}