//! Authentication and validation for AMAI Identity Service
//!
//! All requests are authenticated via cryptographic signatures.
//! No API keys - agents prove identity by signing with their private key.

use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::Serialize;

use crate::crypto::{generate_kid, parse_public_key, verify_signature};
use crate::error::{ApiError, ApiResult};
use crate::types::{KeyType, PublicKey, SignedRequest};

/// Nonce store for replay protection
pub struct NonceStore {
    /// Used nonces with expiry time
    nonces: DashMap<String, DateTime<Utc>>,
    /// Expiry duration
    expiry: Duration,
}

impl NonceStore {
    pub fn new(expiry_secs: u64) -> Self {
        Self {
            nonces: DashMap::new(),
            expiry: Duration::seconds(expiry_secs as i64),
        }
    }

    /// Check if nonce was already used, and mark it as used if not
    pub fn check_and_mark(&self, nonce: &str) -> bool {
        let now = Utc::now();

        // Clean up expired nonces
        self.nonces.retain(|_, expiry| *expiry > now);

        // Check if nonce exists
        if self.nonces.contains_key(nonce) {
            return false; // Replay detected
        }

        // Mark nonce as used
        self.nonces.insert(nonce.to_string(), now + self.expiry);
        true
    }

    /// Get count of stored nonces (for stats)
    pub fn len(&self) -> usize {
        self.nonces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nonces.is_empty()
    }
}

/// Verify a signed request
pub fn verify_signed_request<T: Serialize>(
    req: &SignedRequest<T>,
    public_key: &PublicKey,
    nonce_store: &NonceStore,
    max_clock_skew: u64,
) -> ApiResult<()> {
    // 1. Check timestamp freshness
    let now = Utc::now();
    let skew = Duration::seconds(max_clock_skew as i64);

    if req.timestamp < now - skew {
        return Err(ApiError::TimestampInvalid);
    }
    if req.timestamp > now + skew {
        return Err(ApiError::TimestampInvalid);
    }

    // 2. Check nonce hasn't been used
    if !nonce_store.check_and_mark(&req.nonce) {
        return Err(ApiError::ReplayDetected);
    }

    // 3. Check key ID matches
    if req.kid != public_key.kid {
        return Err(ApiError::signature("Key ID mismatch"));
    }

    // 4. Check key is not revoked
    if public_key.revoked {
        return Err(ApiError::signature("Key has been revoked"));
    }

    // 5. Verify signature
    let payload_json =
        serde_json::to_string(&req.payload).map_err(|e| ApiError::internal(e.to_string()))?;

    let parsed_key = parse_public_key(&public_key.public_key_pem, &public_key.key_type)
        .map_err(|e| ApiError::signature(e.to_string()))?;

    verify_signature(&parsed_key, payload_json.as_bytes(), &req.signature)
        .map_err(|e| ApiError::signature(e.to_string()))?;

    Ok(())
}

/// Create a new public key record from PEM
pub fn create_public_key(
    public_key_pem: &str,
    key_type: KeyType,
    is_primary: bool,
) -> ApiResult<PublicKey> {
    // Validate key can be parsed
    let _ = parse_public_key(public_key_pem, &key_type)
        .map_err(|e| ApiError::bad_request(format!("Invalid public key: {}", e)))?;

    let kid = generate_kid(public_key_pem);
    let fingerprint = crate::crypto::compute_fingerprint(public_key_pem);

    Ok(PublicKey {
        kid,
        key_type,
        public_key_pem: public_key_pem.to_string(),
        fingerprint,
        created_at: Utc::now(),
        is_primary,
        revoked: false,
    })
}

/// Parameters for registration signature verification
pub struct RegistrationParams<'a> {
    pub name: &'a str,
    pub public_key_pem: &'a str,
    pub key_type: &'a KeyType,
    pub signature: &'a str,
    pub timestamp: &'a DateTime<Utc>,
    pub nonce: &'a str,
}

/// Verify registration signature (proves ownership of private key)
pub fn verify_registration_signature(
    params: &RegistrationParams<'_>,
    nonce_store: &NonceStore,
    max_clock_skew: u64,
) -> ApiResult<()> {
    // Check timestamp
    let now = Utc::now();
    let skew = Duration::seconds(max_clock_skew as i64);

    if *params.timestamp < now - skew || *params.timestamp > now + skew {
        return Err(ApiError::TimestampInvalid);
    }

    // Check nonce
    if !nonce_store.check_and_mark(params.nonce) {
        return Err(ApiError::ReplayDetected);
    }

    // Build message to verify: name|timestamp|nonce
    let message = format!(
        "{}|{}|{}",
        params.name,
        params.timestamp.to_rfc3339(),
        params.nonce
    );

    // Parse and verify
    let parsed_key = parse_public_key(params.public_key_pem, params.key_type)
        .map_err(|e| ApiError::bad_request(format!("Invalid public key: {}", e)))?;

    verify_signature(&parsed_key, message.as_bytes(), params.signature)
        .map_err(|e| ApiError::signature(format!("Registration signature invalid: {}", e)))?;

    Ok(())
}

// ============ Validation Functions ============

/// Validate identity name
pub fn validate_name(name: &str) -> Result<(), &'static str> {
    if name.len() < 3 {
        return Err("Name must be at least 3 characters");
    }
    if name.len() > 32 {
        return Err("Name must be at most 32 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("Name must contain only alphanumeric characters, underscores, and hyphens");
    }
    if name.starts_with('_') || name.starts_with('-') {
        return Err("Name cannot start with underscore or hyphen");
    }
    if name.ends_with('_') || name.ends_with('-') {
        return Err("Name cannot end with underscore or hyphen");
    }
    Ok(())
}

/// Validate description
pub fn validate_description(desc: &str) -> Result<(), &'static str> {
    if desc.len() > 500 {
        return Err("Description must be at most 500 characters");
    }
    Ok(())
}

/// Validate metadata size
pub fn validate_metadata(metadata: &serde_json::Value) -> Result<(), &'static str> {
    let json = serde_json::to_string(metadata).unwrap_or_default();
    if json.len() > 10240 {
        return Err("Metadata must be at most 10KB");
    }
    Ok(())
}

/// Validate message content
pub fn validate_message_content(content: &str) -> Result<(), &'static str> {
    if content.is_empty() {
        return Err("Message content cannot be empty");
    }
    if content.len() > 65536 {
        return Err("Message content must be at most 64KB");
    }
    Ok(())
}

/// Validate action type
pub fn validate_action_type(action_type: &str) -> Result<(), &'static str> {
    if action_type.is_empty() {
        return Err("Action type cannot be empty");
    }
    if action_type.len() > 64 {
        return Err("Action type must be at most 64 characters");
    }
    if !action_type
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == ':')
    {
        return Err(
            "Action type must contain only alphanumeric characters, underscores, dots, and colons",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_store() {
        let store = NonceStore::new(60);

        // First use should succeed
        assert!(store.check_and_mark("nonce1"));

        // Second use should fail (replay)
        assert!(!store.check_and_mark("nonce1"));

        // Different nonce should succeed
        assert!(store.check_and_mark("nonce2"));
    }

    #[test]
    fn test_validate_name() {
        assert!(validate_name("valid_name").is_ok());
        assert!(validate_name("Agent-001").is_ok());
        assert!(validate_name("ab").is_err()); // too short
        assert!(validate_name(&"a".repeat(33)).is_err()); // too long
        assert!(validate_name("invalid!name").is_err()); // invalid char
        assert!(validate_name("_invalid").is_err()); // starts with _
        assert!(validate_name("invalid-").is_err()); // ends with -
    }

    #[test]
    fn test_validate_description() {
        assert!(validate_description("Short description").is_ok());
        assert!(validate_description(&"a".repeat(500)).is_ok());
        assert!(validate_description(&"a".repeat(501)).is_err());
    }

    #[test]
    fn test_validate_action_type() {
        assert!(validate_action_type("trade.execute").is_ok());
        assert!(validate_action_type("action_type").is_ok());
        assert!(validate_action_type("platform:action").is_ok());
        assert!(validate_action_type("").is_err());
        assert!(validate_action_type("invalid action").is_err()); // space
        assert!(validate_action_type(&"a".repeat(65)).is_err()); // too long
    }
}
