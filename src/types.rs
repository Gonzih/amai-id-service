//! Core types for AMAI Identity Service
//!
//! This module defines the data structures used throughout the service.
//! Identity is based on cryptographic keys (Ed25519/GPG), not blockchain.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identity identifier (UUID v4)
pub type IdentityId = Uuid;

/// Key ID format: fingerprint of the public key
pub type KeyId = String;

// ============ Identity Types ============

/// Identity status in lifecycle
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityStatus {
    /// Key registered but not yet verified
    Pending,
    /// Key verified and active
    Active,
    /// Suspended (trust violation or key compromise)
    Suspended,
    /// Permanently revoked
    Revoked,
}

/// Key algorithm type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    /// Ed25519 (recommended)
    Ed25519,
    /// RSA (GPG compatible)
    Rsa,
}

/// Public key record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// Key ID (fingerprint)
    pub kid: KeyId,
    /// Key type
    pub key_type: KeyType,
    /// PEM-encoded public key
    pub public_key_pem: String,
    /// SHA256 fingerprint (hex)
    pub fingerprint: String,
    /// When this key was registered
    pub created_at: DateTime<Utc>,
    /// Is this the primary signing key
    pub is_primary: bool,
    /// Key status
    pub revoked: bool,
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
    /// Current status
    pub status: IdentityStatus,
    /// Trust score (0.0 - 100.0)
    pub trust_score: f64,
    /// Total actions recorded
    pub actions_count: u64,
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
    /// Public keys (not serialized in responses, fetched separately)
    #[serde(skip)]
    pub keys: Vec<PublicKey>,
    /// Current soulchain head hash
    pub soulchain_hash: Option<String>,
    /// Current soulchain sequence number
    pub soulchain_seq: u64,
}

// ============ Soulchain Types ============

/// A single entry in the soulchain (Keybase-style)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoulchainLink {
    /// Sequence number (1-indexed, monotonic)
    pub seqno: u64,
    /// SHA256 hash of previous link (null for first)
    pub prev: Option<String>,
    /// SHA256 hash of this link's body
    pub curr: String,
    /// Link body
    pub body: SoulchainBody,
    /// Signature of the body (base64)
    pub sig: String,
    /// Key ID that signed this link
    pub signing_kid: KeyId,
    /// Timestamp
    pub ctime: DateTime<Utc>,
}

/// Soulchain link body types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SoulchainBody {
    /// First link: key registration
    Eldest {
        kid: KeyId,
        key_type: KeyType,
        public_key_pem: String,
    },
    /// Add additional key
    AddKey {
        kid: KeyId,
        key_type: KeyType,
        public_key_pem: String,
    },
    /// Revoke a key
    RevokeKey { kid: KeyId },
    /// Action report
    Action {
        action_type: String,
        outcome: ActionOutcome,
        payload: serde_json::Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        intent: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        platform_ref: Option<String>,
    },
    /// Identity update
    Update {
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        metadata: Option<serde_json::Value>,
    },
}

/// Action outcome
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionOutcome {
    Success,
    Failure,
    Pending,
}

// ============ Message Types ============

/// Message between identities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Unique message ID
    pub id: Uuid,
    /// Sender identity ID
    pub from: IdentityId,
    /// Recipient identity ID
    pub to: IdentityId,
    /// Message content (should be signed by sender)
    pub content: String,
    /// Signature of content (base64)
    pub signature: String,
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
    #[default]
    Text,
    TaskRequest,
    TaskResponse,
    Attestation,
    System,
}

// ============ API Request/Response Types ============

/// Registration request - agent provides their public key
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// Desired name (alphanumeric + underscore, 3-32 chars)
    pub name: String,
    /// Public key (PEM format)
    pub public_key: String,
    /// Key type
    pub key_type: KeyType,
    /// Optional description
    pub description: Option<String>,
    /// Optional metadata
    pub metadata: Option<serde_json::Value>,
    /// Signature of registration payload (proves key ownership)
    pub signature: String,
    /// Timestamp (for replay protection)
    pub timestamp: DateTime<Utc>,
    /// Nonce (for replay protection)
    pub nonce: String,
}

/// Registration response
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub identity: IdentityPublic,
    /// Challenge to sign for verification (optional additional step)
    pub challenge: Option<String>,
}

/// Signed request wrapper - all authenticated requests use this
#[derive(Debug, Deserialize)]
pub struct SignedRequest<T> {
    /// The actual request payload
    pub payload: T,
    /// Signature of JSON-serialized payload (base64)
    pub signature: String,
    /// Key ID used for signing
    pub kid: KeyId,
    /// Timestamp (for replay protection)
    pub timestamp: DateTime<Utc>,
    /// Nonce (for replay protection)
    pub nonce: String,
}

/// Update identity request
#[derive(Debug, Deserialize)]
pub struct UpdateIdentityRequest {
    pub description: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Report action request
#[derive(Debug, Deserialize)]
pub struct ReportActionRequest {
    pub action_type: String,
    pub outcome: ActionOutcome,
    #[serde(default)]
    pub platform_ref: Option<String>,
    #[serde(default)]
    pub intent: Option<String>,
    #[serde(default)]
    pub payload: Option<serde_json::Value>,
}

/// Send message request
#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    /// Recipient identity ID or name
    pub to: String,
    /// Message content
    pub content: String,
    /// Signature of content
    pub content_signature: String,
    #[serde(default)]
    pub message_type: MessageType,
}

/// Get messages query params
#[derive(Debug, Deserialize, Default)]
pub struct GetMessagesQuery {
    pub from: Option<IdentityId>,
    pub unread: Option<bool>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// Add key request
#[derive(Debug, Deserialize)]
pub struct AddKeyRequest {
    pub public_key: String,
    pub key_type: KeyType,
}

/// Revoke key request
#[derive(Debug, Deserialize)]
pub struct RevokeKeyRequest {
    pub kid: KeyId,
}

// ============ Response Types ============

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
}

impl ApiResponse<()> {
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
            hint: None,
        }
    }

    pub fn error_with_hint(message: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
            hint: Some(hint.into()),
        }
    }
}

/// Identity public view (safe for API responses)
#[derive(Debug, Clone, Serialize)]
pub struct IdentityPublic {
    pub id: IdentityId,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub status: IdentityStatus,
    pub trust_score: f64,
    pub actions_count: u64,
    pub soulchain_seq: u64,
    pub created_at: DateTime<Utc>,
    pub last_active: DateTime<Utc>,
}

impl From<&Identity> for IdentityPublic {
    fn from(i: &Identity) -> Self {
        Self {
            id: i.id,
            name: i.name.clone(),
            description: i.description.clone(),
            status: i.status.clone(),
            trust_score: i.trust_score,
            actions_count: i.actions_count,
            soulchain_seq: i.soulchain_seq,
            created_at: i.created_at,
            last_active: i.last_active,
        }
    }
}

/// Public key info for API responses
#[derive(Debug, Clone, Serialize)]
pub struct PublicKeyInfo {
    pub kid: KeyId,
    pub key_type: KeyType,
    pub fingerprint: String,
    pub created_at: DateTime<Utc>,
    pub is_primary: bool,
    pub revoked: bool,
}

impl From<&PublicKey> for PublicKeyInfo {
    fn from(k: &PublicKey) -> Self {
        Self {
            kid: k.kid.clone(),
            key_type: k.key_type.clone(),
            fingerprint: k.fingerprint.clone(),
            created_at: k.created_at,
            is_primary: k.is_primary,
            revoked: k.revoked,
        }
    }
}

/// Keys response
#[derive(Debug, Serialize)]
pub struct KeysResponse {
    pub identity_id: IdentityId,
    pub name: String,
    pub keys: Vec<PublicKeyInfo>,
    pub soulchain_hash: Option<String>,
    pub soulchain_seq: u64,
}

/// Soulchain response
#[derive(Debug, Serialize)]
pub struct SoulchainResponse {
    pub identity_id: IdentityId,
    pub links: Vec<SoulchainLink>,
    pub total: usize,
    pub has_more: bool,
}

/// Action entry response
#[derive(Debug, Serialize)]
pub struct ActionEntryResponse {
    pub seqno: u64,
    pub soulchain_hash: String,
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub identities_count: usize,
    pub active_connections: usize,
}

/// Public stats response
#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub total_identities: usize,
    pub active_identities: usize,
    pub pending_identities: usize,
    pub total_soulchain_entries: u64,
    pub total_messages: u64,
}

// ============ WebSocket Types ============

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsServerMessage {
    Message {
        data: Message,
    },
    Status {
        identity_id: IdentityId,
        online: bool,
    },
    Error {
        message: String,
    },
    Pong,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsClientMessage {
    Ping,
    Ack { message_id: Uuid },
}

// ============ Platform Types ============

/// Platform registration request
#[derive(Debug, Deserialize)]
pub struct RegisterPlatformRequest {
    pub name: String,
    pub public_key: String,
    pub key_type: KeyType,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub allowed_actions: Vec<String>,
    /// Signature proving key ownership
    pub signature: String,
    pub timestamp: DateTime<Utc>,
    pub nonce: String,
}

/// Platform entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Platform {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub kid: KeyId,
    pub public_key_pem: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    pub allowed_actions: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// Platform registration response
#[derive(Debug, Serialize)]
pub struct RegisterPlatformResponse {
    pub platform_id: String,
    pub kid: KeyId,
}

/// Platform action confirmation request
#[derive(Debug, Deserialize)]
pub struct ConfirmActionRequest {
    pub identity_id: IdentityId,
    pub action_type: String,
    pub outcome: ActionOutcome,
    pub platform_ref: String,
    pub timestamp: DateTime<Utc>,
    #[serde(default)]
    pub payload: Option<serde_json::Value>,
}
