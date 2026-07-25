use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcPublicKeyShare {
    pub peer_id: String,
    pub public_key_bytes: Vec<u8>, 
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcCiphertextShare {
    pub target_peer_id: String,
    pub ciphertext_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthPayload {
    pub peer_id: String,
    pub zkp_receipt: Receipt,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureMessage {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkPayload {
    PublicKeyShare(PqcPublicKeyShare),
    CiphertextShare(PqcCiphertextShare),
    Auth(AuthPayload), 
    EncryptedChat(SecureMessage),
}

impl SecureMessage {
    pub fn encrypt(plaintext: &str, session_key: &[u8; 32]) -> Self {
        let key = Key::from_slice(session_key);
        let cipher = ChaCha20Poly1305::new(key);
        
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).expect("Encryption failed");

        Self {
            ciphertext,
            nonce: nonce.to_vec(),
        }
    }

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