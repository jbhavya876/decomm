import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { AlterblockContracts } from "../target/types/alterblock_contracts";
import { Keypair, SystemProgram } from "@solana/web3.js";
import assert from "assert";

// ---------------------------------------------------------------------------
// Run against a local test validator:
//   anchor localnet &
//   anchor test --skip-local-validator
//
// D-07: Tests now verify the stored root value and the admin-only guard.
// ---------------------------------------------------------------------------
describe("alterblock_contracts", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const program = anchor.workspace.AlterblockContracts as Program<AlterblockContracts>;
  const provider = anchor.getProvider() as anchor.AnchorProvider;

  // Fresh keypair for each test run — does not depend on a pre-deployed account.
  const networkStateKp = Keypair.generate();

  // The Merkle root that matches "alterblock-zk-secret" in the two-peer demo
  // (domain-separated SHA-256 tree — see host/src/merkle.rs compute_root_for_secret).
  // NOTE: after D-02 / D-07 fixes the hashing scheme changed.  Run
  //   cargo run -p p2p-chat -- --print-root   (or add a small helper binary)
  // to compute the correct root for your DECOMM_MEMBER_SECRET.
  const DEMO_ROOT = [
    160, 163, 89, 24, 0, 224, 207, 102, 69, 110, 31, 30,
    216, 204, 154, 24, 115, 226, 115, 57, 233, 165, 69, 225,
    82, 150, 242, 163, 66, 237, 58, 170
  ];

  // ---------------------------------------------------------------------------
  // Test 1: initialize
  // ---------------------------------------------------------------------------
  it("Initializes a NetworkState account with the genesis root", async () => {
    const tx = await program.methods
      .initialize(DEMO_ROOT)
      .accounts({
        networkState: networkStateKp.publicKey,
        admin: provider.wallet.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([networkStateKp])
      .rpc();

    console.log("initialize tx:", tx);

    // Verify the account was created with the correct root.
    const state = await program.account.networkState.fetch(networkStateKp.publicKey);
    assert.deepStrictEqual(
      Array.from(state.currentMerkleRoot),
      DEMO_ROOT,
      "stored root must match the genesis root"
    );
    assert.strictEqual(
      state.admin.toBase58(),
      provider.wallet.publicKey.toBase58(),
      "admin must be the deployer"
    );
  });

  // ---------------------------------------------------------------------------
  // Test 2: update_root (authorized)
  // ---------------------------------------------------------------------------
  it("Updates the Merkle Root when called by the admin", async () => {
    const newRoot = Array.from({ length: 32 }, (_, i) => (i + 1) % 256);

    const tx = await program.methods
      .updateRoot(newRoot)
      .accounts({
        networkState: networkStateKp.publicKey,
        admin: provider.wallet.publicKey,
      })
      .rpc();

    console.log("update_root tx:", tx);

    const state = await program.account.networkState.fetch(networkStateKp.publicKey);
    assert.deepStrictEqual(
      Array.from(state.currentMerkleRoot),
      newRoot,
      "stored root must reflect the update"
    );
  });

  // ---------------------------------------------------------------------------
  // Test 3: update_root (unauthorized) — security-critical rejection path
  // ---------------------------------------------------------------------------
  it("Rejects update_root from a non-admin signer", async () => {
    const attacker = Keypair.generate();
    const attackerRoot = Array(32).fill(0xff);

    try {
      await program.methods
        .updateRoot(attackerRoot)
        .accounts({
          networkState: networkStateKp.publicKey,
          admin: attacker.publicKey,
        })
        .signers([attacker])
        .rpc();

      assert.fail("Expected the transaction to be rejected");
    } catch (err: any) {
      // Anchor wraps the on-chain error; check it contains our custom code.
      const msg: string = err.toString();
      const isUnauthorized =
        msg.includes("Unauthorized") ||
        msg.includes("Error Code") ||
        msg.includes("6000");
      assert.ok(
        isUnauthorized,
        `Expected an Unauthorized error, got: ${msg}`
      );
      console.log("✅ Non-admin update correctly rejected.");
    }
  });
});