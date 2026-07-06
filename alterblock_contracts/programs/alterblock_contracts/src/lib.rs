use anchor_lang::prelude::*;

// Anchor will automatically replace this with your real program ID when you deploy
declare_id!("8P5tdCSpXPev51dhXRX7w7U7GvFSTc7Jfbt3c6UxyMhG"); 

#[program]
pub mod alterblock_contracts {
    use super::*;

    /// Initializes the network state with the Genesis Merkle Root.
    pub fn initialize(ctx: Context<Initialize>, initial_root: [u8; 32]) -> Result<()> {
        let state = &mut ctx.accounts.network_state;
        
        // Lock in the root and assign the deployer as the Network Admin
        state.current_merkle_root = initial_root;
        state.admin = ctx.accounts.admin.key();
        
        msg!("AlterBlock Network Initialized. Genesis Root locked.");
        Ok(())
    }

    /// Updates the Merkle Root to grant/revoke network access.
    pub fn update_root(ctx: Context<UpdateRoot>, new_root: [u8; 32]) -> Result<()> {
        let state = &mut ctx.accounts.network_state;
        
        // Security Gatekeeper: Only the Admin can update the network state
        require!(state.admin == ctx.accounts.admin.key(), ErrorCode::Unauthorized);
        
        state.current_merkle_root = new_root;
        msg!("AlterBlock Network State Updated. New Merkle Root broadcasted.");
        
        Ok(())
    }
}

// --- ACCOUNT VALIDATION INSTRUCTIONS ---

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init, 
        payer = admin, 
        // Space calculation: 8 bytes (Discriminator) + 32 bytes (Root) + 32 bytes (Pubkey)
        space = 8 + 32 + 32 
    )]
    pub network_state: Account<'info, NetworkState>,
    
    #[account(mut)]
    pub admin: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateRoot<'info> {
    #[account(mut)]
    pub network_state: Account<'info, NetworkState>,
    pub admin: Signer<'info>,
}

// --- THE ON-CHAIN STATE ---

#[account]
pub struct NetworkState {
    pub current_merkle_root: [u8; 32],
    pub admin: Pubkey,
}

// --- CUSTOM ERRORS ---

#[error_code]
pub enum ErrorCode {
    #[msg("SEC-FAULT: You are not authorized to update the AlterBlock network state.")]
    Unauthorized,
}