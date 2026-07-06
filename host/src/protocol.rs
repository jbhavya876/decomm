use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};

/// The fully secure payload sent over the Gossipsub network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureMessage {
    /// The Zero-Knowledge Proof guaranteeing network access
    pub zkp_receipt: Receipt,
    /// The End-to-End encrypted chat data
    pub ciphertext: Vec<u8>,
    /// The unique cryptographic nonce required to decrypt this specific message
    pub nonce: Vec<u8>,
}

/// Step 1 of the Handshake: Node A shares its Public Key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcPublicKeyShare {
    pub peer_id: String,
    pub public_key_bytes: Vec<u8>, 
}

/// Step 2 of the Handshake: Node B sends back the encapsulated secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcCiphertextShare {
    pub target_peer_id: String,
    pub ciphertext_bytes: Vec<u8>,
}

/// The master routing wrapper for our P2P network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkPayload {
    PublicKeyShare(PqcPublicKeyShare),
    CiphertextShare(PqcCiphertextShare),
    EncryptedChat(SecureMessage),
}

impl SecureMessage {
    /// Encrypts the plaintext using the dynamically provided session key
    pub fn encrypt(plaintext: &str, receipt: Receipt, session_key: &[u8; 32]) -> Self {
        let key = Key::from_slice(session_key);
        let cipher = ChaCha20Poly1305::new(key);
        
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).expect("Encryption failed");

        Self {
            zkp_receipt: receipt,
            ciphertext,
            nonce: nonce.to_vec(),
        }
    }

    /// Decrypts the ciphertext using the dynamically provided session key
    pub fn decrypt(&self, session_key: &[u8; 32]) -> Result<String, &'static str> {
        let key = Key::from_slice(session_key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&self.nonce);
        
        match cipher.decrypt(nonce, self.ciphertext.as_ref()) {
            Ok(plaintext_bytes) => Ok(String::from_utf8_lossy(&plaintext_bytes).into_owned()),
            Err(_) => Err("Decryption failed. Invalid key or tampered ciphertext."),
        }
    }
}