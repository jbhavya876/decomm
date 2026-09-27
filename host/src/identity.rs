use libp2p::identity::Keypair as Libp2pKeypair;
use libp2p::PeerId;
use pqcrypto_kyber::kyber1024::{keypair, PublicKey, SecretKey};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::info;

/// All cryptographic state for a single Decomm node.
///
/// D-03 change: `active_session_key` (a single global slot) is replaced with
/// `session_keys`, a per-peer map keyed by the remote peer's libp2p PeerId
/// string.  This prevents a third peer from silently overwriting the session
/// key established with the first peer.
pub struct NodeIdentity {
    /// Ed25519 keypair used for libp2p transport authentication and GossipSub
    /// message signing.  This is the authoritative routing identity.
    pub p2p_keypair: Libp2pKeypair,
    /// The PeerId derived from the Ed25519 public key above.
    pub peer_id: PeerId,
    /// Kyber1024 public key broadcast during the KEM handshake.
    pub pqc_public_key: PublicKey,
    /// Kyber1024 secret key used for decapsulation.  Never leaves this struct.
    pub pqc_secret_key: SecretKey,

    /// D-03: Per-peer session keys.
    ///
    /// Key   = remote peer's PeerId string (authenticated via GossipSub Signed mode).
    /// Value = 32-byte ChaCha20-Poly1305 session key derived via HKDF from the
    ///         raw KEM shared secret (see D-04 fix in main.rs).
    pub session_keys: Arc<Mutex<HashMap<String, [u8; 32]>>>,

    /// The most recently verified on-chain Merkle root, fetched from Solana devnet.
    /// `None` until the first successful fetch.
    pub anchored_root: Arc<Mutex<Option<[u8; 32]>>>,

    /// D-06: Monotonically increasing sequence number for outgoing chat messages.
    /// Included as AEAD associated data to make each ciphertext unique and to
    /// allow the remote side to reject replayed messages.
    pub send_seq: Arc<Mutex<u64>>,
}

impl NodeIdentity {
    /// Generate fresh ephemeral cryptographic identities.
    ///
    /// Keys are generated from the OS CSPRNG and are not persisted to disk;
    /// they live only for the duration of this process.
    pub fn generate() -> Self {
        let p2p_keypair = Libp2pKeypair::generate_ed25519();
        let peer_id = PeerId::from(p2p_keypair.public());
        let (pqc_public_key, pqc_secret_key) = keypair();

        info!("🔐 Generated Hybrid Cryptographic Identity");
        info!("   -> Routing PeerId : {peer_id}");
        info!("   -> PQC Algorithm  : Kyber1024 (pre-standard; see AUDIT.md D-04)");

        Self {
            p2p_keypair,
            peer_id,
            pqc_public_key,
            pqc_secret_key,
            session_keys: Arc::new(Mutex::new(HashMap::new())),
            anchored_root: Arc::new(Mutex::new(None)),
            send_seq: Arc::new(Mutex::new(0)),
        }
    }
}