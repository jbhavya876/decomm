# Decomm Security Audit

**Repository:** github.com/jbhavya876/decomm · branch `main`  
**Reviewed commit:** `13012a8` (30 Jul 2026) — manual line-by-line review, full git history diff, live Solana devnet account read  
**Fixes applied:** commit range covering all items below  
**Reviewer:** Independent code review + Antigravity AI-assisted audit (25 Sep 2026)

---

## Verdict

A credible research prototype with real cryptography throughout.  Not a secure messenger.  Two historical critical bugs were found and patched by the author; six further findings have now been addressed in code.  One finding (D-04, KEM migration) is documented for a future hardening pass.

---

## What was verified as real

| Component | Details |
|-----------|---------|
| Networking | TCP + Noise + Yamux via libp2p; GossipSub with `MessageAuthenticity::Signed` and `ValidationMode::Strict` |
| Post-quantum KEM | Kyber1024 encapsulate/decapsulate via `pqcrypto-kyber 0.8.1` |
| Message encryption | ChaCha20-Poly1305 with a fresh OS-RNG 96-bit nonce per message |
| Zero-knowledge membership | `risc0-zkvm 3.0.5` with `disable-dev-mode` — dev-mode fake receipts are rejected |
| ZK journal | Guest commits `(topic, root, sender_peer_id)` — all three are verified by the receiver |
| On-chain anchoring | Anchor program `8P5tdCSpXPev51dhXRX7w7U7GvFSTc7Jfbt3c6UxyMhG`; account `F2vD6mCsHB18wbFqNYnwcRZTzV1K2i9eziTet4Tk6kg9` is live on devnet (owner-verified) |
| Fail-closed start-up | Node refuses to start if Solana is unreachable or `DECOMM_MEMBER_SECRET` is not set |

---

## Fixed historical bugs (found and patched by author)

### F-01 — Local root fallback allowed self-proving *(Critical · fixed in c529113)*

**Vulnerable commit:** [b741e9c](https://github.com/jbhavya876/decomm/commit/b741e9c)

`get_zk_circuit_variables()` in `merkle.rs` fell back to a root computed from the local tree when the Solana fetch failed.  The prover then proved membership against a root it had constructed itself, which no one had approved.

**Fix (c529113):** The prover now uses a freshly fetched on-chain root or the previously cached on-chain root, and gives up if neither is available.  The local fallback is gone entirely.

---

### F-02 — Verifier discarded the journal root *(Critical · fixed in c529113)*

**Vulnerable commit:** [b741e9c](https://github.com/jbhavya876/decomm/commit/b741e9c)

The verifier decoded the journal as `(journal_topic, _)`, discarding the root.  Because the root is an input the prover chooses, anyone could build their own Merkle tree, prove membership in it, and be accepted.

**Fix (c529113):** The verifier now decodes all committed values and rejects any proof whose journal root does not exactly match the locally anchored on-chain root.

---

## Open findings addressed in this audit pass

### D-01 — Membership receipts were replayable and not bound to the sender *(Critical · FIXED)*

**Was:** `AuthPayload.peer_id` was a plain self-declared string.  The verifier accepted the receipt and then inserted the self-declared string into `authorized_peers`.  Anyone who captured a valid receipt could rebroadcast it with their own `peer_id` and be marked authorized.  The README's "replay-resistant authorization context" claim was not accurate.

**Fix applied:**
- Guest now reads `sender_peer_id` as a public input and commits `(topic, root, sender_peer_id)` to the journal.
- Host verifier decodes all three values and asserts `journal_peer_id == message.source.to_string()`, where `message.source` is the GossipSub-signed, Ed25519-authenticated sender identity.
- Authorization is inserted under the authenticated source, never the self-declared field.

**Files changed:** `methods/guest/src/main.rs`, `host/src/main.rs`, `host/src/protocol.rs`

---

### D-02 — Member secret was public, so the ZK gate admitted anyone *(Critical · FIXED)*

**Was:** `"alterblock-zk-secret"` was a string literal in `main.rs:70`; the four-leaf tree was built from literals in `merkle.rs:48-53`.  The root from those literals matched, byte for byte, the root in the live devnet account.  Anyone who cloned the repo could produce a valid membership proof.

**Fix applied:**
- `get_member_secret()` in `merkle.rs` reads `DECOMM_MEMBER_SECRET` from the environment and fails loudly at startup if it is absent or empty.
- The hardcoded literal is gone from `main.rs` and from `merkle.rs`.
- **Action required:** The current on-chain root is burned.  Call `update_root` with the root computed by `compute_root_for_secret(your_new_secret)` after setting a new private secret.

**Files changed:** `host/src/merkle.rs`, `host/src/main.rs`

---

### D-03 — Kyber handshake was unauthenticated, with one global session key *(High · FIXED)*

**Was:** Kyber public keys and ciphertexts carried a self-declared `peer_id` that was never verified against the signing identity.  All handshakes overwrote a single `active_session_key` slot, so a third peer would silently replace the key established with the first peer.  Outgoing messages were encrypted before authorization was checked.

**Fix applied:**
- `NodeIdentity.session_keys` is now `HashMap<String, [u8; 32]>` — one entry per authenticated remote peer.
- `PqcPublicKeyShare.peer_id` is verified against `message.source` before processing.
- `PqcCiphertextShare.sender_peer_id` (new field) is verified against `message.source` before decapsulating.
- Outgoing messages are sent only to peers that are both in `session_keys` and in `authorized_peers`.

**Files changed:** `host/src/identity.rs`, `host/src/main.rs`, `host/src/protocol.rs`

---

### D-04 — Pre-standard, unmaintained KEM and no key derivation *(Medium · PARTIALLY FIXED)*

**Was:** `pqcrypto-kyber 0.8.1` is the round-3 submission, not FIPS 203 ML-KEM.  The upstream project is unmaintained.  The raw 32-byte KEM output was used directly as the ChaCha20-Poly1305 key with no KDF.

**Fix applied (partial):**
- HKDF-SHA256 (`hkdf = "0.12"`) is now applied over the raw KEM shared secret.  The HKDF info string binds both peer IDs and the Kyber ciphertext bytes, preventing cross-session key reuse.
- `sha2 = "0.11.0"` (which does not exist on crates.io) corrected to `sha2 = "0.10"`.

**Remaining task:** Migrate from `pqcrypto-kyber` to RustCrypto `ml-kem` (FIPS 203).  The two are not wire-compatible.  A hybrid X25519 + ML-KEM-1024 construction is the current deployment norm and would also fix the unauthenticated-handshake risk at the KEM layer.

---

### D-05 — Revocation lag: authorized peers are never re-checked *(Medium · documented)*

**Issue:** Peers admitted to `authorized_peers` stay there for the lifetime of the process.  After an admin rotates the on-chain root to revoke someone, already-running nodes keep trusting that peer.

**Status:** Not patched in this pass.  Addressed by a timer that refreshes the anchored root and evicts peers whose admission root is no longer current.  Tracked as a future hardening task.

---

### D-06 — No message replay protection *(Medium · FIXED)*

**Was:** Each `SecureMessage` had a random nonce but no sequence number or associated data.  A captured ciphertext could be replayed and would decrypt and display again.

**Fix applied:**
- `SecureMessage` now includes `seq: u64`.
- AEAD associated data = `sender_id_bytes || seq_be`, computed in both `encrypt` and `decrypt`.
- The main loop tracks `peer_last_seq: HashMap<String, u64>` and drops any message whose seq is at or below the last accepted value from that sender.

**Files changed:** `host/src/protocol.rs`, `host/src/main.rs`

---

### D-07 — Merkle construction and Solana read hardening *(Low · FIXED)*

**Was:** Leaf and node hashes used the same SHA-256 with no domain separation.  The Solana account was read without checking `account.owner`.  The Anchor discriminator was not validated.

**Fix applied:**
- `hash_leaf` prefixes `0x00`; `hash_node` prefixes `0x01` — consistent between host and guest.
- `fetch_onchain_root()` now calls `client.get_account()` instead of `get_account_data()` and verifies `account.owner == PROGRAM_ID` before reading any bytes.
- Non-zero discriminator check added.

**Note:** Domain-separation changes the computed Merkle root.  The on-chain root must be rotated after deploying these changes (same action as D-02 above).

**Files changed:** `host/src/merkle.rs`, `methods/guest/src/main.rs`

---

### D-08 — Panics and unbounded work on network paths *(Low · FIXED)*

**Was:** `unwrap()` / `expect()` inside `spawn_blocking` silently panicked, causing the ZK Visa to never be broadcast with no visible error.  All mutex locks used `unwrap()`.

**Fix applied:**
- `spawn_zk_auth_task` uses `map_err()` throughout and returns `Result<_, String>`.  Both the `Ok(Err(...))` and `Err(...)` (join panic) arms now print an error message.
- Probe-logic paths return from the task rather than panicking the thread.

**Remaining:** Rate-limiting STARK verification per source peer (receipt spam CPU-DoS) is not yet implemented.

---

## Engineering gaps addressed

| Gap | Status |
|-----|--------|
| `Cargo.lock` was git-ignored | Fixed — `Cargo.lock` now committed |
| Dead Anchor scaffold (`constants.rs`, `error.rs`, `instructions/`, `state/`) | Deleted |
| `sha2 = "0.11.0"` (non-existent) | Fixed to `"0.10"` |
| No Rust unit tests | Added in `host/src/merkle.rs` and `host/src/protocol.rs` |
| No CI | **Remaining task** — add `.github/workflows/ci.yml` |
| No `SECURITY.md` | **Remaining task** |
| README clone URL placeholder | **Remaining task** — update `<your-fork-or-repository-url>` |
| Self-reported metrics lack a bench script | **Remaining task** |

---

## Remediation plan (priority order)

1. **Rotate the on-chain root** — set `DECOMM_MEMBER_SECRET` to a private value, compute the new root with `compute_root_for_secret`, and call `update_root` via Anchor.
2. **Migrate KEM to `ml-kem`** (D-04) — replace `pqcrypto-kyber` with RustCrypto `ml-kem`; go hybrid X25519 + ML-KEM-1024.
3. **Root refresh + revocation** (D-05) — periodic Solana account re-fetch; evict peers whose admission root is stale.
4. **CI pipeline** — GitHub Actions: `cargo fmt --check`, `cargo clippy`, `cargo test`, `cargo audit`.
5. **Rate-limit STARK verification** (D-08) — GossipSub message validator to drop repeated auth payloads from the same source before verification.
6. **SECURITY.md** — responsible disclosure policy.
7. **README** — fix clone URL, add `DECOMM_MEMBER_SECRET` setup instructions, add bench script.

---

*Read-only review — no code was changed except as part of the described fixes.  Severity ratings reflect the code as deployed on devnet, not a production threat model.*
