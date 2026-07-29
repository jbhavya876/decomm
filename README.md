# Decomm

**Decentralized, access-controlled communication with post-quantum encryption and zero-knowledge membership proofs.**

Decomm is a proof-of-concept terminal chat network for private groups. Nodes discover each other over a libp2p GossipSub mesh, establish a shared secret with Kyber1024, encrypt messages with ChaCha20-Poly1305, and use a RISC Zero proof to show that they belong to the current allowlist—without broadcasting the allowlist secret itself.

The allowlist is represented by a Merkle root stored in a Solana devnet program. A peer accepts a proof only when its committed topic and Merkle root match the locally fetched on-chain state.

> **Prototype notice:** Decomm is an experimental demonstration, not production-ready secure messaging. Identities and session keys are ephemeral; the membership witness is currently demo data in source; and the protocol has not received a security audit. Do not use it for sensitive conversations.

## What it demonstrates

- **Decentralized networking** — TCP, Noise, Yamux, and signed GossipSub via `libp2p`.
- **Post-quantum key establishment** — Kyber1024 encapsulation establishes a 32-byte shared session secret.
- **Authenticated encryption** — Chat payloads use ChaCha20-Poly1305 with a fresh random nonce per message.
- **Private membership checks** — a RISC Zero guest verifies a Merkle-inclusion witness and produces a receipt instead of revealing the member secret.
- **On-chain authorization state** — an Anchor program keeps the current Merkle root on Solana devnet; an administrator can rotate it to grant or revoke access.
- **Replay-resistant authorization context** — the zero-knowledge journal commits to both the network topic and the root used during proof generation.

## Architecture

```text
                 Solana devnet
       AlterBlock NetworkState account
                 │ current Merkle root
                 ▼
┌──────────────────────────────────────────────────────────────┐
│                        Decomm node                            │
│                                                              │
│  libp2p GossipSub ── Kyber1024 handshake ── session key      │
│         │                                      │              │
│         └──── RISC Zero membership receipt ────┴─> encrypted chat
│                                                              │
│  Receipt proves: private secret ∈ Merkle tree,               │
│                  for `alterblock-global`,                    │
│                  against the current on-chain root.           │
└──────────────────────────────────────────────────────────────┘
```

## Repository layout

| Path | Purpose |
| --- | --- |
| [`host/`](host) | Decomm CLI node: networking, handshake, proof verification, and message encryption. |
| [`methods/guest/`](methods/guest) | RISC Zero guest program that verifies Merkle inclusion and commits the topic/root. |
| [`methods/`](methods) | Builds and embeds the guest method for the host prover. |
| [`alterblock_contracts/`](alterblock_contracts) | Anchor/Solana program holding the network Merkle root and admin authority. |

## How a connection is authorized

1. Each node starts by fetching the active root from the configured Solana devnet account.
2. When two peers subscribe to `alterblock-global`, one broadcasts its Kyber public key.
3. The other peer encapsulates a shared secret and returns the Kyber ciphertext; both sides derive the same session key.
4. Each node generates a RISC Zero receipt showing its private membership secret hashes into the approved Merkle root.
5. Peers verify the receipt, topic, and root. A verified peer is added to the authorized set.
6. Chat traffic is encrypted locally and messages from unauthorized senders are rejected.

## Quick start

### Prerequisites

- Rust and Cargo (the workspace uses Rust edition 2024 for the host)
- A working RISC Zero 3.x build environment for compiling/proving the guest method
- Network access to Solana devnet (`https://api.devnet.solana.com`)

Clone the repository and build the workspace:

```bash
git clone <your-fork-or-repository-url> decomm
cd decomm
cargo build --workspace
```

Start the first node:

```bash
cargo run -p p2p-chat
```

It prints a `Node listening on:` address such as `/ip4/0.0.0.0/tcp/####`. In another terminal, start a second node and dial the first node using its reachable address:

```bash
cargo run -p p2p-chat -- --dial /ip4/127.0.0.1/tcp/<port>
```

After the Kyber exchange and RISC Zero receipt verification complete, type a message and press Enter. The terminal reports the handshake and authorization progress; incoming messages are displayed only after the sender has been authorized.

### Expected flow

```text
Fetching Genesis State from Solana Devnet...
Secure Network Booting... Waiting for PQC & ZK Handshake before allowing chat.
Mesh linked! ... Kyber Public Key...
Background Prover: ... generating ZK Visa...
ZK Visa accepted! Peer ... is fully authorized.
```

If a node cannot fetch the configured account or the local demo witness no longer matches the on-chain root, it intentionally refuses to continue authorization.

## Verified engineering metrics

These measurements were recorded on a **CPU-only WSL2** environment with full cryptographic compilation: LLVM optimization enabled and RISC Zero development mode disabled. They are integration benchmarks for this proof of concept, not a throughput guarantee for every machine or network.

| Measurement | Observed result | What it measures |
| --- | ---: | --- |
| Guest execution | ~3.82 ms | RISC-V guest execution while the emulator captures its execution trace. |
| STARK proving | ~20.03 s | Local CPU generation of the full polynomial STARK proof. |
| Receipt payload | 244,554 bytes | Uncompressed composite STARK receipt transmitted for authorization. |
| Receipt verification | < 100 ms | Mathematical verification by the receiving peer. |

The relatively substantial proving time and receipt size are expected trade-offs of producing and carrying a full cryptographic proof locally, rather than using a simulated or development-mode result. Future work can reduce the per-message cost through session-level proof caching and proof compression/wrapping, such as Groth16.

## Smart contract

The Anchor program lives in [`alterblock_contracts/`](alterblock_contracts). It stores:

- `current_merkle_root: [u8; 32]`
- `admin: Pubkey`

`initialize` creates the network state, while `update_root` is restricted to the recorded administrator. The current host is configured to read the `NetworkState` account at `F2vD6mCsHB18wbFqNYnwcRZTzV1K2i9eziTet4Tk6kg9` on Solana devnet.

To work on the program, install the Solana and Anchor toolchains, then from that directory run the relevant Anchor command, for example:

```bash
cd alterblock_contracts
anchor build
anchor test
```

The program configuration targets devnet; review [`Anchor.toml`](alterblock_contracts/Anchor.toml) and the test account keys before deploying or updating state.

## Development notes

- The chat topic is currently fixed to `alterblock-global`.
- The Merkle witness and member secret in the host are deliberately hardcoded for the demo. A real deployment needs protected per-user credentials and a witness-update flow.
- Keys are generated at process startup and are not persisted.
- The implementation uses one active session key, so it is designed for demonstrating the protocol with a small peer set—not as a multi-party messaging product.
- Solana devnet is an external dependency; availability or account state changes can prevent startup.

## License

Decomm is released under the [MIT License](LICENSE).
