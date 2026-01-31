use anchor_lang::prelude::*;

declare_id!("AMAI1dentityProgramXXXXXXXXXXXXXXXXXXXXXX");

/// AMAI Identity Program for Solana
///
/// Soulbound agent identities with on-chain trust scores.
/// Trust mechanics:
/// - Score range: 0-10000 (representing 0.00-100.00)
/// - Initial score: 5000 (50.00)
/// - Updated by authorized oracles based on platform confirmations
/// - Logistic curve prevents gaming at extremes
///
/// Versioning:
/// - Program version tracked for upgrade compatibility
/// - Each agent records the program version at registration time
/// - Agents can query current vs their registration version

#[program]
pub mod amai_identity {
    use super::*;

    /// Initialize the program state
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let state = &mut ctx.accounts.program_state;
        state.authority = ctx.accounts.authority.key();
        state.total_agents = 0;
        state.current_version = PROGRAM_VERSION_NUMBER;
        state.bump = ctx.bumps.program_state;
        Ok(())
    }

    /// Register a new agent identity
    pub fn mint_agent(
        ctx: Context<MintAgent>,
        name: String,
        service_endpoint: String,
    ) -> Result<()> {
        require!(name.len() > 0 && name.len() <= 64, ErrorCode::InvalidNameLength);
        require!(service_endpoint.len() <= 256, ErrorCode::InvalidEndpointLength);

        let agent = &mut ctx.accounts.agent;
        let state = &mut ctx.accounts.program_state;

        agent.owner = ctx.accounts.owner.key();
        agent.name = name.clone();
        agent.service_endpoint = service_endpoint.clone();
        agent.trust_score = INITIAL_TRUST_SCORE;
        agent.action_count = 0;
        agent.confirmed_count = 0;
        agent.created_at = Clock::get()?.unix_timestamp;
        agent.last_active = Clock::get()?.unix_timestamp;
        agent.is_active = true;
        agent.token_id = state.total_agents + 1;
        agent.registration_version = state.current_version;
        agent.bump = ctx.bumps.agent;

        state.total_agents += 1;

        emit!(AgentMinted {
            token_id: agent.token_id,
            owner: agent.owner,
            name,
            service_endpoint,
            program_version: state.current_version,
        });

        emit!(TrustScoreUpdated {
            token_id: agent.token_id,
            old_score: 0,
            new_score: INITIAL_TRUST_SCORE,
            reason: "initial".to_string(),
        });

        Ok(())
    }

    /// Update trust score (oracle only)
    pub fn update_trust_score(
        ctx: Context<OracleAction>,
        new_score: u64,
        reason: String,
    ) -> Result<()> {
        require!(new_score <= MAX_TRUST_SCORE, ErrorCode::ScoreExceedsMax);

        let agent = &mut ctx.accounts.agent;
        require!(agent.is_active, ErrorCode::AgentNotActive);

        let old_score = agent.trust_score;
        agent.trust_score = new_score;
        agent.last_active = Clock::get()?.unix_timestamp;

        emit!(TrustScoreUpdated {
            token_id: agent.token_id,
            old_score,
            new_score,
            reason,
        });

        Ok(())
    }

    /// Apply trust delta using logistic curve
    pub fn apply_trust_delta(
        ctx: Context<OracleAction>,
        delta: i64,
        reason: String,
    ) -> Result<()> {
        let agent = &mut ctx.accounts.agent;
        require!(agent.is_active, ErrorCode::AgentNotActive);

        let old_score = agent.trust_score;
        let new_score: u64;

        if delta >= 0 {
            // Positive delta - harder to gain at high scores
            let headroom = MAX_TRUST_SCORE - old_score;
            let scaled_delta = ((delta as u64) * headroom) / MAX_TRUST_SCORE;
            new_score = old_score + scaled_delta;
        } else {
            // Negative delta - harder to lose at low scores
            let abs_delta = (-delta) as u64;
            let scaled_delta = (abs_delta * old_score) / MAX_TRUST_SCORE;
            new_score = if old_score > scaled_delta { old_score - scaled_delta } else { 0 };
        }

        agent.trust_score = new_score;
        agent.last_active = Clock::get()?.unix_timestamp;

        emit!(TrustScoreUpdated {
            token_id: agent.token_id,
            old_score,
            new_score,
            reason,
        });

        Ok(())
    }

    /// Record an action
    pub fn record_action(ctx: Context<OracleAction>) -> Result<()> {
        let agent = &mut ctx.accounts.agent;
        require!(agent.is_active, ErrorCode::AgentNotActive);

        agent.action_count += 1;
        agent.last_active = Clock::get()?.unix_timestamp;

        emit!(ActionRecorded {
            token_id: agent.token_id,
            action_count: agent.action_count,
        });

        Ok(())
    }

    /// Record a platform confirmation
    pub fn record_confirmation(ctx: Context<OracleAction>) -> Result<()> {
        let agent = &mut ctx.accounts.agent;
        require!(agent.is_active, ErrorCode::AgentNotActive);

        agent.confirmed_count += 1;
        agent.last_active = Clock::get()?.unix_timestamp;

        emit!(ActionConfirmed {
            token_id: agent.token_id,
            confirmed_count: agent.confirmed_count,
        });

        Ok(())
    }

    /// Update service endpoint (owner only)
    pub fn update_service_endpoint(
        ctx: Context<OwnerAction>,
        new_endpoint: String,
    ) -> Result<()> {
        require!(new_endpoint.len() <= 256, ErrorCode::InvalidEndpointLength);

        let agent = &mut ctx.accounts.agent;
        require!(agent.is_active, ErrorCode::AgentNotActive);

        agent.service_endpoint = new_endpoint;
        agent.last_active = Clock::get()?.unix_timestamp;

        Ok(())
    }

    /// Deactivate agent (authority only)
    pub fn deactivate_agent(ctx: Context<AuthorityAction>) -> Result<()> {
        let agent = &mut ctx.accounts.agent;
        require!(agent.is_active, ErrorCode::AgentAlreadyInactive);

        agent.is_active = false;

        emit!(AgentDeactivated {
            token_id: agent.token_id,
        });

        Ok(())
    }

    /// Add an authorized oracle
    pub fn authorize_oracle(ctx: Context<ManageOracle>) -> Result<()> {
        let oracle = &mut ctx.accounts.oracle;
        oracle.address = ctx.accounts.oracle_address.key();
        oracle.is_authorized = true;
        oracle.bump = ctx.bumps.oracle;

        emit!(OracleAuthorized {
            oracle: oracle.address,
        });

        Ok(())
    }

    /// Revoke oracle authorization
    pub fn revoke_oracle(ctx: Context<RevokeOracle>) -> Result<()> {
        let oracle = &mut ctx.accounts.oracle;
        oracle.is_authorized = false;

        emit!(OracleRevoked {
            oracle: oracle.address,
        });

        Ok(())
    }

    /// Update program version (authority only) - for upgrades
    pub fn update_version(ctx: Context<UpdateVersion>, new_version: u64) -> Result<()> {
        require!(new_version > ctx.accounts.program_state.current_version, ErrorCode::VersionMustIncrease);

        let old_version = ctx.accounts.program_state.current_version;
        ctx.accounts.program_state.current_version = new_version;

        emit!(VersionUpdated {
            old_version,
            new_version,
        });

        Ok(())
    }
}

// Constants
pub const TRUST_PRECISION: u64 = 100;
pub const MAX_TRUST_SCORE: u64 = 100 * TRUST_PRECISION; // 10000 = 100.00
pub const INITIAL_TRUST_SCORE: u64 = 50 * TRUST_PRECISION; // 5000 = 50.00

// Version constants: MAJOR * 1_000_000 + MINOR * 1_000 + PATCH
pub const PROGRAM_VERSION: &str = "1.0.0";
pub const PROGRAM_VERSION_NUMBER: u64 = 1_000_000; // 1.0.0

// Account structures
#[account]
#[derive(Default)]
pub struct ProgramState {
    pub authority: Pubkey,
    pub total_agents: u64,
    pub current_version: u64,
    pub bump: u8,
}

#[account]
pub struct Agent {
    pub owner: Pubkey,
    pub name: String,
    pub service_endpoint: String,
    pub trust_score: u64,
    pub action_count: u64,
    pub confirmed_count: u64,
    pub created_at: i64,
    pub last_active: i64,
    pub is_active: bool,
    pub token_id: u64,
    pub registration_version: u64,
    pub bump: u8,
}

#[account]
#[derive(Default)]
pub struct Oracle {
    pub address: Pubkey,
    pub is_authorized: bool,
    pub bump: u8,
}

// Context structures
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 8 + 8 + 1, // Added 8 bytes for current_version
        seeds = [b"state"],
        bump
    )]
    pub program_state: Account<'info, ProgramState>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(name: String, service_endpoint: String)]
pub struct MintAgent<'info> {
    #[account(
        mut,
        seeds = [b"state"],
        bump = program_state.bump
    )]
    pub program_state: Account<'info, ProgramState>,
    #[account(
        init,
        payer = owner,
        space = 8 + 32 + (4 + 64) + (4 + 256) + 8 + 8 + 8 + 8 + 8 + 1 + 8 + 8 + 1, // Added 8 for registration_version
        seeds = [b"agent", owner.key().as_ref()],
        bump
    )]
    pub agent: Account<'info, Agent>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct OracleAction<'info> {
    #[account(mut)]
    pub agent: Account<'info, Agent>,
    #[account(
        seeds = [b"oracle", oracle_signer.key().as_ref()],
        bump = oracle.bump,
        constraint = oracle.is_authorized @ ErrorCode::OracleNotAuthorized
    )]
    pub oracle: Account<'info, Oracle>,
    pub oracle_signer: Signer<'info>,
}

#[derive(Accounts)]
pub struct OwnerAction<'info> {
    #[account(
        mut,
        constraint = agent.owner == owner.key() @ ErrorCode::NotAgentOwner
    )]
    pub agent: Account<'info, Agent>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct AuthorityAction<'info> {
    #[account(mut)]
    pub agent: Account<'info, Agent>,
    #[account(
        seeds = [b"state"],
        bump = program_state.bump,
        constraint = program_state.authority == authority.key() @ ErrorCode::NotAuthority
    )]
    pub program_state: Account<'info, ProgramState>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct ManageOracle<'info> {
    #[account(
        seeds = [b"state"],
        bump = program_state.bump,
        constraint = program_state.authority == authority.key() @ ErrorCode::NotAuthority
    )]
    pub program_state: Account<'info, ProgramState>,
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 1 + 1,
        seeds = [b"oracle", oracle_address.key().as_ref()],
        bump
    )]
    pub oracle: Account<'info, Oracle>,
    /// CHECK: The oracle address being authorized
    pub oracle_address: AccountInfo<'info>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevokeOracle<'info> {
    #[account(
        seeds = [b"state"],
        bump = program_state.bump,
        constraint = program_state.authority == authority.key() @ ErrorCode::NotAuthority
    )]
    pub program_state: Account<'info, ProgramState>,
    #[account(
        mut,
        seeds = [b"oracle", oracle.address.as_ref()],
        bump = oracle.bump
    )]
    pub oracle: Account<'info, Oracle>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateVersion<'info> {
    #[account(
        mut,
        seeds = [b"state"],
        bump = program_state.bump,
        constraint = program_state.authority == authority.key() @ ErrorCode::NotAuthority
    )]
    pub program_state: Account<'info, ProgramState>,
    pub authority: Signer<'info>,
}

// Events
#[event]
pub struct AgentMinted {
    pub token_id: u64,
    pub owner: Pubkey,
    pub name: String,
    pub service_endpoint: String,
    pub program_version: u64,
}

#[event]
pub struct TrustScoreUpdated {
    pub token_id: u64,
    pub old_score: u64,
    pub new_score: u64,
    pub reason: String,
}

#[event]
pub struct ActionRecorded {
    pub token_id: u64,
    pub action_count: u64,
}

#[event]
pub struct ActionConfirmed {
    pub token_id: u64,
    pub confirmed_count: u64,
}

#[event]
pub struct AgentDeactivated {
    pub token_id: u64,
}

#[event]
pub struct OracleAuthorized {
    pub oracle: Pubkey,
}

#[event]
pub struct OracleRevoked {
    pub oracle: Pubkey,
}

#[event]
pub struct VersionUpdated {
    pub old_version: u64,
    pub new_version: u64,
}

// Error codes
#[error_code]
pub enum ErrorCode {
    #[msg("Name must be between 1 and 64 characters")]
    InvalidNameLength,
    #[msg("Service endpoint must be at most 256 characters")]
    InvalidEndpointLength,
    #[msg("Trust score exceeds maximum (10000)")]
    ScoreExceedsMax,
    #[msg("Agent is not active")]
    AgentNotActive,
    #[msg("Agent is already inactive")]
    AgentAlreadyInactive,
    #[msg("Oracle is not authorized")]
    OracleNotAuthorized,
    #[msg("Not the agent owner")]
    NotAgentOwner,
    #[msg("Not the program authority")]
    NotAuthority,
    #[msg("New version must be greater than current version")]
    VersionMustIncrease,
}
