use libp2p::identity::Keypair as Libp2pKeypair;
use libp2p::PeerId;
use pqcrypto_kyber::kyber1024::{keypair, PublicKey, SecretKey};
use std::sync::{Arc, Mutex};
use tracing::info;

pub struct NodeIdentity {
    pub p2p_keypair: Libp2pKeypair,
    pub peer_id: PeerId,
    pub pqc_public_key: PublicKey,
    pub pqc_secret_key: SecretKey,
    pub active_session_key: Arc<Mutex<Option<[u8; 32]>>>, 
}

impl NodeIdentity {
    pub fn generate() -> Self {
        let p2p_keypair = Libp2pKeypair::generate_ed25519();
        let peer_id = PeerId::from(p2p_keypair.public());
        let (pqc_public_key, pqc_secret_key) = keypair();

        info!("🔐 Generated Hybrid Cryptographic Identity");
        info!("   -> Routing PeerId: {}", peer_id);
        info!("   -> PQC Keypair: Kyber1024 active");

        Self {
            p2p_keypair,
            peer_id,
            pqc_public_key,
            pqc_secret_key,
            active_session_key: Arc::new(Mutex::new(None)), 
        }
    }
}