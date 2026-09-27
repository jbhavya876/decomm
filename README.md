# Decomm

**Decentralized, access-controlled communication with post-quantum encryption and zero-knowledge membership proofs.**

Decomm is a production-grade prototype for private group communication. Peers discover each other over a libp2p GossipSub mesh, establish post-quantum forward secrecy via Kyber1024, encrypt messages with ChaCha20-Poly1305 AEAD, and prove authorized membership using a RISC Zero STARK proof—without revealing their secret identity or allowlist pre-image.

The global membership allowlist is anchored on Solana Devnet via an Anchor program. Peers dynamically fetch and verify the on-chain Merkle root, accepting communication only from peers presenting valid, unreplayable zero-knowledge proofs.

---

## 🔒 Security Audit & Hardening Status

Decomm has undergone an independent security review documented in [`AUDIT.md`](AUDIT.md). All findings (**D-01 through D-08**) have been remediated, verified, and hardened:

- **D-01 (High) — Proof Replay & Identity Theft Defense**: The RISC Zero guest circuit binds `(topic, root, sender_peer_id)` directly into the public journal. The receiving peer cryptographically validates that the receipt journal's peer ID matches the libp2p sender, preventing proof eavesdropping and replay attacks.
- **D-02 (High) — Second-Preimage Defense via Domain Separation**: Merkle tree hashing uses strict domain prefixes (`0x00` for leaf hashes, `0x01` for internal node hashes) to prevent leaf-node collision and second-preimage attacks.
- **D-04 (Medium) — Cryptographic Key Derivation**: Replaced raw KEM slicing with HKDF-SHA256 key derivation. The derivation binds both peer IDs and the encapsulated ciphertext into the session key material.
- **D-05 (Low) — Deterministic Networking**: Added `--port` CLI argument and explicit local listen address logging for predictable multiaddr dialing and firewall traversal.
- **D-06 (Low) — Deterministic Build Reproducibility**: Tracked `Cargo.lock` files across workspace packages for verifiable dependencies and dependency vulnerability scanning.
- **D-07 (Low) — Solana Program Ownership Verification**: The on-chain state fetcher strictly verifies that the `NetworkState` account is owned by the expected AlterBlock Anchor program ID, preventing spoofed rogue account attacks.
- **D-08 (Low) — Monotonic Sequence & Replay Rejection**: ChaCha20-Poly1305 AEAD incorporates strictly monotonic 64-bit sequence numbering and sender peer ID in the Additional Authenticated Data (AAD), rejecting message reordering, duplication, and reflection attacks.

---

## 🌟 Key Capabilities

- **Decentralized P2P Networking** — Built on `libp2p` 0.56 with TCP transport, Noise authentication, Yamux multiplexing, and cryptographically signed GossipSub mesh.
- **Post-Quantum Cryptography (PQC)** — Kyber1024 key encapsulation mechanism (KEM) resistant to retrospective store-now-decrypt-later attacks by quantum adversaries.
- **Authenticated Symmetric Encryption** — ChaCha20-Poly1305 AEAD with unique 96-bit nonces, 64-bit sequence counters, and peer ID binding in AAD.
- **Zero-Knowledge Membership (ZKP)** — RISC Zero zkVM guest circuit proves private secret inclusion in a 4-leaf Merkle tree without revealing secret pre-images.
- **On-Chain Anchor State** — Solana smart contract manages authorized Merkle roots with admin-gated rotation instructions.
- **Pure-System Execution** — Runs with `disable-dev-mode` strictly enforced; all proofs are genuine cryptographic STARKs.

---

## 🏗️ Architecture

```text
                     Solana Devnet
              AlterBlock NetworkState Account
              (PDA / Program-Owned Account)
                             │ Current Merkle Root
                             ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                         Decomm Node                         │
 │                                                             │
 │  1. Fetch & verify on-chain Merkle root                     │
 │  2. Libp2p GossipSub Discovery ─── TCP Handshake            │
 │  3. Kyber1024 KEM ─── HKDF-SHA256 ─── Shared Session Key    │
 │  4. RISC Zero zkVM ── STARK Prover ── ZK Visa Generation   │
 │  5. GossipSub zk-auth-plane ───────── ZK Visa Verification  │
 │  6. Unlocked Session ──────────────── ChaCha20-Poly1305 E2EE│
 └─────────────────────────────────────────────────────────────┘
```

### Protocol Authentication Lifecycle

1. **State Initialization**: The node queries Solana Devnet for the `NetworkState` account and cryptographically verifies its program owner.
2. **KEM Exchange**: Upon discovering a peer on the GossipSub mesh, nodes determine role (Initiator / Responder) by comparing peer IDs. Initiator sends its Kyber1024 public key; Responder encapsulates and returns the ciphertext. Both derive identical 256-bit symmetric keys via HKDF-SHA256.
3. **ZK Visa Proving**: In the background, each node executes the RISC Zero guest method with its private secret and Merkle path, producing a STARK receipt binding its Peer ID, the topic, and the on-chain Merkle root.
4. **Visa Verification**: Nodes broadcast their ZK Visas across the `zk-auth-plane` topic. Receiving peers verify the receipt against `METHOD_ID`, ensure the journal matches the sender's Peer ID, and confirm the root matches current on-chain state.
5. **Secure Encrypted Chat**: Once mutual verification succeeds, the chat plane unlocks. Messages are encrypted with ChaCha20-Poly1305 using monotonic sequence numbers.

---

## 📁 Repository Layout

| Directory | Purpose |
| :--- | :--- |
| [`host/`](host) | Main Rust node binary (`p2p-chat`), libp2p swarm, cryptographic handshake, and CLI interface. |
| [`host/src/bin/update_root.rs`](host/src/bin/update_root.rs) | Admin utility to compute domain-separated Merkle roots and submit update transactions to Solana. |
| [`methods/guest/`](methods/guest) | RISC Zero guest zkVM circuit verifying Merkle inclusion and committing public inputs. |
| [`methods/`](methods) | Build script and compilation wrapper embedding the guest ELF and `METHOD_ID`. |
| [`alterblock_contracts/`](alterblock_contracts) | Solana Anchor program (`alterblock_contracts`) managing on-chain Merkle roots. |
| [`alterblock_contracts/tests/`](alterblock_contracts/tests) | TypeScript Mocha test suite verifying contract initialization, updates, and unauthorized rejection. |
| [`AUDIT.md`](AUDIT.md) | Security audit report and remediation details. |

---

## 🚀 Quick Start

### Prerequisites

- **Rust**: Version 1.89+ (the host uses Rust edition 2024; run `rustup update stable`).
- **Memory / Swap**: Generating real STARK proofs on CPU utilizes multi-threaded polynomial calculations. Having **8 GB+ of virtual memory** (RAM + swap) is recommended (e.g., configure a 4 GB swapfile on WSL2).
- **Solana CLI & Anchor** (optional, for contract development): Solana CLI v2.0+ and Anchor v0.32+.

### Build the Workspace

```bash
git clone https://github.com/jbhavya876/decomm.git
cd decomm
cargo build -p p2p-chat
```

### Running a Two-Node Live Session

Open two separate terminal windows:

#### Terminal 1 — Start Node 1 (Responder)
```bash
cargo run -p p2p-chat -- --port 50001
```
Node 1 outputs its listen multiaddress, e.g.:
```text
📡 Node listening on: /ip4/127.0.0.1/tcp/50001
```

#### Terminal 2 — Start Node 2 (Initiator dialing Node 1)
```bash
cargo run -p p2p-chat -- --port 50002 --dial /ip4/127.0.0.1/tcp/50001/p2p/<NODE_1_PEER_ID>
```

#### Interactive Chat
Once connected, both nodes execute Kyber KEM and compute their STARK proof:
```text
🔗 Mesh linked! I am KEM Initiator. Broadcasting Kyber Public Key...
🔄 Received Kyber Ciphertext... Decapsulating...
⏳ Background Prover: Fetching fresh Solana state & generating ZK Visa...
✅ Background Prover: ZK Visa generated successfully.
📤 Broadcasted ZK Visa to the mesh network.
✅ ZK Visa accepted! Peer ... is fully authorized.
```
Type any message in either terminal and press **Enter** to chat over the post-quantum encrypted channel:
```text
[🔒 Verified & PQC E2EE | 12D3KooW...]: Hello from Node 1 over quantum-resistant ZK channel!
```

---

## ⚙️ Configuration & Environment Variables

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `SOLANA_RPC_URL` | `https://api.devnet.solana.com` | Solana JSON-RPC endpoint (supports devnet or local test validator). |
| `DECOMM_MEMBER_SECRET` | `alterblock-zk-secret` | Private member secret pre-image used to construct the Merkle path. |
| `DECOMM_STATE_PUBKEY` | `F2vD6mCsHB18wbFqNYnwcRZTzV1K2i9eziTet4Tk6kg9` | Base58 address of the on-chain `NetworkState` account. |
| `DECOMM_PROGRAM_ID` | `8P5tdCSpXPev51dhXRX7w7U7GvFSTc7Jfbt3c6UxyMhG` | Base58 Program ID of the Anchor contract for ownership verification. |
| `SOLANA_KEYPAIR_PATH` | `~/.config/solana/id.json` | Path to Solana wallet keypair (used by `update_root`). |

---

## 🛠️ Testing & Verification

### Run Rust Unit & Cryptographic Tests

Executes all 10 unit tests covering domain separation, Merkle path resolution, AEAD tampering detection, sequence numbering replay guards, and wrong-peer AAD rejections:

```bash
cargo test -p p2p-chat
```

To run the live on-chain root query test against Solana:
```bash
SOLANA_RPC_URL=https://api.devnet.solana.com cargo test -p p2p-chat -- --ignored
```

### Run Anchor Smart Contract Tests

```bash
cd alterblock_contracts
anchor test
```
Verifies:
1. `initialize` — Creates the `NetworkState` account with the domain-separated genesis Merkle root.
2. `update_root` (authorized) — Allows the recorded admin authority to rotate the Merkle root.
3. `update_root` (unauthorized) — Strictly rejects updates from non-admin signers.

### Updating the On-Chain Root

To calculate and deploy a new Merkle root for a custom member secret:

```bash
DECOMM_MEMBER_SECRET="my-custom-secret" cargo run -p p2p-chat --bin update_root
```

---

## 📜 License

Decomm is licensed under the [MIT License](LICENSE).
