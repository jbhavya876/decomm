import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { AlterblockContracts } from "../target/types/alterblock_contracts";
import { PublicKey } from "@solana/web3.js";

describe("alterblock_contracts", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const program = anchor.workspace.AlterblockContracts as Program<AlterblockContracts>;
  const provider = anchor.getProvider();

  const networkStatePubkey = new PublicKey("F2vD6mCsHB18wbFqNYnwcRZTzV1K2i9eziTet4Tk6kg9");

  it("Updates the Merkle Root to grant access!", async () => {
    const trueRoot = [60, 4, 200, 184, 69, 131, 45, 205, 175, 199, 73, 30, 168, 206, 232, 67, 228, 227, 217, 181, 207, 53, 71, 188, 114, 77, 241, 124, 198, 40, 132, 244];

    const tx = await program.methods
      .updateRoot(trueRoot)
      .accounts({
        networkState: networkStatePubkey,
        admin: provider.publicKey,
      })
      .rpc();

    console.log("\n=======================================================");
    console.log("✅ ON-CHAIN ROOT UPDATED - ACCESS GRANTED!");
    console.log("🔗 Transaction Signature:", tx);
    console.log("=======================================================\n");
  });
});