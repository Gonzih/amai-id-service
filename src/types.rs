use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identity identifier (UUID v4)
pub type IdentityId = Uuid;

/// API key for authentication (256-bit hex)
pub type ApiKey = String;

/// On-chain address (0x prefixed)
pub type Address = String;

/// Identity status in lifecycle
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityStatus {
    /// Registered but not minted on-chain
    Pending,
    /// Minted and verified on-chain
    Active,
    /// Suspended (trust violation)
    Suspended,
    /// Permanently deactivated
    Revoked,
}

/// Tier based on bonding level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityTier {
    /// Tier I: Standard (unbonded or <100 AMAI)
    Standard,
    /// Tier II: Verified (100-1000 AMAI bonded)
    Verified,
    /// Tier III: Sovereign (>1000 AMAI bonded)
    Sovereign,
}

/// Core identity record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Unique identifier
    pub id: IdentityId,
    /// Human-readable name (unique)
    pub name: String,
    /// Optional description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// API key hash (not exposed in responses)
    #[serde(skip_serializing)]
    pub api_key_hash: String,
    /// On-chain wallet address (after mint)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_address: Option<Address>,
    /// On-chain NFT token ID (after mint)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_id: Option<u64>,
    /// Current status
    pub status: IdentityStatus,
    /// Current tier
    pub tier: IdentityTier,
    /// Trust score (60.0 - 99.9)
    pub trust_score: f64,
    /// Total messages sent
    pub messages_sent: u64,
    /// Total messages received
    pub messages_received: u64,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last activity timestamp
    pub last_active: DateTime<Utc>,
    /// Metadata (arbitrary JSON)
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Message between identities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Unique message ID
    pub id: Uuid,
    /// Sender identity ID
    pub from: IdentityId,
    /// Recipient identity ID
    pub to: IdentityId,
    /// Message content
    pub content: String,
    /// Message type
    pub message_type: MessageType,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Delivery status
    pub delivered: bool,
    /// Read status
    pub read: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    /// Plain text message
    #[default]
    Text,
    /// Task request
    TaskRequest,
    /// Task response
    TaskResponse,
    /// Trust attestation
    Attestation,
    /// System notification
    System,
}

/// Mint instructions returned after registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintInstructions {
    /// Contract address to call
    pub contract_address: Address,
    /// Chain ID (8453 for Base mainnet, 84532 for Base Sepolia)
    pub chain_id: u64,
    /// Function to call
    pub function: String,
    /// ABI-encoded calldata (hex)
    pub calldata: String,
    /// Estimated gas
    pub estimated_gas: u64,
    /// Verification code (must be included in mint)
    pub verification_code: String,
    /// Expiry timestamp
    pub expires_at: DateTime<Utc>,
}

// ============ API Request/Response Types ============

/// Registration request
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// Desired name (alphanumeric + underscore, 3-32 chars)
    pub name: String,
    /// Optional description
    pub description: Option<String>,
    /// Optional metadata
    pub metadata: Option<serde_json::Value>,
}

/// Registration response
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub identity: Identity,
    /// Plain API key (only returned once!)
    pub api_key: ApiKey,
    /// Instructions to mint on-chain
    pub mint_instructions: MintInstructions,
}

/// Supported blockchain networks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Chain {
    /// Base Sepolia testnet (chain_id: 84532)
    BaseSepolia,
    /// Base mainnet (chain_id: 8453)
    BaseMainnet,
    /// Solana devnet
    SolanaDevnet,
    /// Solana mainnet
    SolanaMainnet,
}

impl Chain {
    /// Get chain ID for EVM chains, None for Solana
    pub fn chain_id(&self) -> Option<u64> {
        match self {
            Chain::BaseSepolia => Some(84532),
            Chain::BaseMainnet => Some(8453),
            Chain::SolanaDevnet | Chain::SolanaMainnet => None,
        }
    }

    /// Check if this is an EVM chain
    pub fn is_evm(&self) -> bool {
        matches!(self, Chain::BaseSepolia | Chain::BaseMainnet)
    }

    /// Check if this is Solana
    pub fn is_solana(&self) -> bool {
        matches!(self, Chain::SolanaDevnet | Chain::SolanaMainnet)
    }

    /// Check if this is a testnet
    pub fn is_testnet(&self) -> bool {
        matches!(self, Chain::BaseSepolia | Chain::SolanaDevnet)
    }
}

/// Verify mint request
#[derive(Debug, Deserialize)]
pub struct VerifyMintRequest {
    /// Transaction hash (EVM) or signature (Solana)
    pub tx_hash: String,
    /// Wallet address that minted
    pub wallet_address: Address,
    /// Chain where mint occurred
    pub chain: Chain,
    /// Contract address used for minting
    pub contract_address: String,
}

/// Contract verification result
#[derive(Debug, Clone, Serialize)]
pub struct ContractVerification {
    /// Whether the contract is valid
    pub valid: bool,
    /// Contract version number (e.g., 1000000 for 1.0.0)
    pub version: u64,
    /// Human-readable version string
    pub version_string: String,
    /// Chain the contract is on
    pub chain: Chain,
    /// Contract address
    pub contract_address: String,
    /// Error message if invalid
    pub error: Option<String>,
}

/// Verify mint response
#[derive(Debug, Serialize)]
pub struct VerifyMintResponse {
    pub identity: Identity,
    pub token_id: u64,
    /// Contract verification details
    pub contract: ContractVerification,
}

/// Send message request
#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    /// Recipient identity ID or name
    pub to: String,
    /// Message content
    pub content: String,
    /// Message type (default: Text)
    #[serde(default)]
    pub message_type: MessageType,
}

/// Get messages query params
#[derive(Debug, Deserialize, Default)]
pub struct GetMessagesQuery {
    /// Filter by sender
    pub from: Option<IdentityId>,
    /// Only unread
    pub unread: Option<bool>,
    /// Limit (default 50, max 100)
    pub limit: Option<u32>,
    /// Offset for pagination
    pub offset: Option<u32>,
}

/// Update identity request
#[derive(Debug, Deserialize)]
pub struct UpdateIdentityRequest {
    /// New description
    pub description: Option<String>,
    /// New metadata (merged with existing)
    pub metadata: Option<serde_json::Value>,
}

/// Standard API response wrapper
#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            hint: None,
        }
    }

    pub fn error(message: impl Into<String>) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(message.into()),
            hint: None,
        }
    }

    pub fn error_with_hint(message: impl Into<String>, hint: impl Into<String>) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(message.into()),
            hint: Some(hint.into()),
        }
    }
}

/// WebSocket message from server
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsServerMessage {
    Message { data: Message },
    Status { identity_id: IdentityId, online: bool },
    Error { message: String },
    Pong,
}

/// WebSocket message from client
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsClientMessage {
    Ping,
    Ack { message_id: Uuid },
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub uptime_seconds: u64,
    pub identities_count: usize,
    pub active_connections: usize,
    pub last_persist: Option<DateTime<Utc>>,
}

/// Public stats response
#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub total_identities: usize,
    pub active_identities: usize,
    pub pending_identities: usize,
    pub total_messages: u64,
    pub active_connections: usize,
}

/// Identity list item (public view)
#[derive(Debug, Serialize)]
pub struct IdentityPublic {
    pub id: IdentityId,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub status: IdentityStatus,
    pub tier: IdentityTier,
    pub trust_score: f64,
    pub created_at: DateTime<Utc>,
}

impl From<&Identity> for IdentityPublic {
    fn from(i: &Identity) -> Self {
        Self {
            id: i.id,
            name: i.name.clone(),
            description: i.description.clone(),
            status: i.status.clone(),
            tier: i.tier.clone(),
            trust_score: i.trust_score,
            created_at: i.created_at,
        }
    }
}

// ============ Action Log API Types ============

/// Agent action report request
#[derive(Debug, Deserialize)]
pub struct ReportActionRequest {
    /// Action type/category
    pub action_type: String,
    /// Outcome of the action
    pub outcome: ActionOutcomeInput,
    /// Platform reference ID (for correlation with platform confirmation)
    #[serde(default)]
    pub platform_ref: Option<String>,
    /// Agent's stated intent (why they took this action)
    #[serde(default)]
    pub intent: Option<String>,
    /// Agent's reasoning (how they decided)
    #[serde(default)]
    pub reasoning: Option<String>,
    /// Action payload/details
    #[serde(default)]
    pub payload: Option<serde_json::Value>,
}

/// Platform action confirmation request
#[derive(Debug, Deserialize)]
pub struct ConfirmActionRequest {
    /// Identity ID of the agent
    pub identity_id: IdentityId,
    /// Action type/category
    pub action_type: String,
    /// Outcome of the action
    pub outcome: ActionOutcomeInput,
    /// Platform reference ID (for correlation)
    pub platform_ref: String,
    /// When the action occurred
    pub timestamp: DateTime<Utc>,
    /// Action payload/details
    #[serde(default)]
    pub payload: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionOutcomeInput {
    Success,
    Failure,
    Pending,
    Disputed,
}

/// Action entry response
#[derive(Debug, Serialize)]
pub struct ActionEntryResponse {
    pub entry_id: Uuid,
    pub seq: u64,
    pub matched_agent_report: Option<bool>,
}

/// Action log query params
#[derive(Debug, Deserialize, Default)]
pub struct ActionLogQuery {
    /// Limit (default 50, max 100)
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
    /// Only entries since this sequence
    pub since_seq: Option<u64>,
}

/// Action log response
#[derive(Debug, Serialize)]
pub struct ActionLogResponse {
    pub entries: Vec<ActionEntryPublic>,
    pub total: usize,
    pub has_more: bool,
}

/// Public action entry
#[derive(Debug, Serialize)]
pub struct ActionEntryPublic {
    pub seq: u64,
    pub id: Uuid,
    pub source: String,
    pub action_type: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_ref: Option<String>,
    pub timestamp: DateTime<Utc>,
}

// ============ Platform API Types ============

/// Platform registration request
#[derive(Debug, Deserialize)]
pub struct RegisterPlatformRequest {
    /// Platform name
    pub name: String,
    /// Description
    #[serde(default)]
    pub description: Option<String>,
    /// Webhook URL for notifications
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Allowed action types this platform can confirm
    #[serde(default)]
    pub allowed_actions: Vec<String>,
}

/// Platform entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Platform {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing)]
    pub api_key_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    #[serde(skip_serializing)]
    pub webhook_secret: String,
    pub allowed_actions: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// Platform registration response
#[derive(Debug, Serialize)]
pub struct RegisterPlatformResponse {
    pub platform_id: String,
    pub api_key: String,
    pub webhook_secret: String,
}

// ============ Oracle API Types ============

/// Oracle snapshot response
#[derive(Debug, Serialize)]
pub struct SnapshotResponse {
    pub id: Uuid,
    pub last_seq: u64,
    pub entry_count: usize,
    pub discrepancies_found: usize,
    pub adjustments_made: usize,
    pub timestamp: DateTime<Utc>,
}

/// Snapshots list response
#[derive(Debug, Serialize)]
pub struct SnapshotsResponse {
    pub snapshots: Vec<SnapshotResponse>,
}
