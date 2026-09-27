use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Wire message types
// ---------------------------------------------------------------------------

/// Broadcast by the KEM initiator: their Kyber1024 public key.
///
/// D-03: `peer_id` must match the authenticated GossipSub `message.source`;
/// the receiver verifies this before processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcPublicKeyShare {
    /// The sender's libp2p PeerId string.  Verified against `message.source`.
    pub peer_id: String,
    pub public_key_bytes: Vec<u8>,
}

/// Sent by the KEM responder back to the initiator: the Kyber ciphertext.
///
/// D-03: `sender_peer_id` added so the initiator can verify the CT source
/// against `message.source` and use it as the HKDF transcript binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcCiphertextShare {
    /// The responder's (sender's) libp2p PeerId string.
    pub sender_peer_id: String,
    /// The intended recipient's PeerId string.
    pub target_peer_id: String,
    pub ciphertext_bytes: Vec<u8>,
}

/// Zero-knowledge membership receipt, broadcast after the KEM handshake.
///
/// `display_peer_id` is **informational only** — authorization is based
/// solely on the PeerId committed inside the ZK journal.  See D-01.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthPayload {
    /// For display/logging only.  Do not use for access control.
    pub display_peer_id: String,
    pub zkp_receipt: Receipt,
}

/// An encrypted chat message.
///
/// D-06: Includes a `seq` field that is incorporated into the AEAD associated
/// data together with the sender's PeerId string.  The receiver should reject
/// any `seq` at or below the last accepted value from that sender.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureMessage {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    /// Monotonically increasing sequence number.  Part of the AEAD AD.
    pub seq: u64,
}

/// The top-level discriminated union of all messages on the GossipSub topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkPayload {
    PublicKeyShare(PqcPublicKeyShare),
    CiphertextShare(PqcCiphertextShare),
    Auth(AuthPayload),
    EncryptedChat(SecureMessage),
}

// ---------------------------------------------------------------------------
// SecureMessage implementation
// ---------------------------------------------------------------------------

impl SecureMessage {
    /// Encrypt `plaintext` under `session_key`.
    ///
    /// Associated data (AEAD AD) = `sender_id` bytes || `seq` as big-endian u64.
    /// This binds the ciphertext to a specific sender and a specific message
    /// position so that:
    ///   - A ciphertext cannot be re-attributed to a different sender.
    ///   - A replayed ciphertext will fail decryption with the wrong seq.
    pub fn encrypt(
        plaintext: &str,
        session_key: &[u8; 32],
        sender_id: &str,
        seq: u64,
    ) -> Self {
        let key = Key::from_slice(session_key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let aad = build_aad(sender_id, seq);
        let payload = Payload {
            msg: plaintext.as_bytes(),
            aad: &aad,
        };

        // Encryption can only fail if the key or nonce have wrong sizes, which
        // are compile-time constants here — so this panic is unreachable.
        let ciphertext = cipher.encrypt(&nonce, payload).expect("Encryption failed");

        Self {
            ciphertext,
            nonce: nonce.to_vec(),
            seq,
        }
    }

    /// Decrypt this message, verifying the AEAD tag.
    ///
    /// The caller must supply `sender_id` so the associated data can be
    /// reconstructed.  A tampered ciphertext, a wrong sender_id, or a
    /// mis-matched seq all cause authentication failure.
    pub fn decrypt(
        &self,
        session_key: &[u8; 32],
        sender_id: &str,
    ) -> Result<String, &'static str> {
        let key = Key::from_slice(session_key);
        let cipher = ChaCha20Poly1305::new(key);

        if self.nonce.len() != 12 {
            return Err("Malformed nonce length.");
        }
        let nonce = Nonce::from_slice(&self.nonce);

        let aad = build_aad(sender_id, self.seq);
        let payload = Payload {
            msg: self.ciphertext.as_ref(),
            aad: &aad,
        };

        match cipher.decrypt(nonce, payload) {
            Ok(plaintext_bytes) => Ok(String::from_utf8_lossy(&plaintext_bytes).into_owned()),
            Err(_) => Err("Decryption failed: invalid key, tampered ciphertext, \
                           wrong sender_id, or replayed message."),
        }
    }
}

/// Build the AEAD associated data: `sender_id_bytes || seq_be`.
fn build_aad(sender_id: &str, seq: u64) -> Vec<u8> {
    let mut aad = sender_id.as_bytes().to_vec();
    aad.extend_from_slice(&seq.to_be_bytes());
    aad
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = test_key();
        let msg = SecureMessage::encrypt("hello, world", &key, "peer-alice", 1);
        let plaintext = msg.decrypt(&key, "peer-alice").expect("should decrypt");
        assert_eq!(plaintext, "hello, world");
    }

    #[test]
    fn wrong_sender_id_fails_decryption() {
        let key = test_key();
        let msg = SecureMessage::encrypt("secret", &key, "peer-alice", 1);
        let result = msg.decrypt(&key, "peer-mallory");
        assert!(result.is_err(), "wrong sender_id must fail AEAD verification");
    }

    #[test]
    fn wrong_seq_fails_decryption() {
        let key = test_key();
        let mut msg = SecureMessage::encrypt("secret", &key, "peer-alice", 5);
        // Tamper with the seq field so the receiver reconstructs wrong AAD.
        msg.seq = 6;
        let result = msg.decrypt(&key, "peer-alice");
        assert!(result.is_err(), "modified seq must fail AEAD verification");
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key_a = [0x01u8; 32];
        let key_b = [0x02u8; 32];
        let msg = SecureMessage::encrypt("secret", &key_a, "peer-alice", 1);
        let result = msg.decrypt(&key_b, "peer-alice");
        assert!(result.is_err(), "wrong key must fail decryption");
    }

    #[test]
    fn tampered_ciphertext_fails_decryption() {
        let key = test_key();
        let mut msg = SecureMessage::encrypt("secret", &key, "peer-alice", 1);
        // Flip a bit in the ciphertext.
        if let Some(b) = msg.ciphertext.get_mut(0) {
            *b ^= 0xff;
        }
        let result = msg.decrypt(&key, "peer-alice");
        assert!(result.is_err(), "tampered ciphertext must fail AEAD verification");
    }
}