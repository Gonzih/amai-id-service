use rand::Rng;
use sha2::{Digest, Sha256};

/// Generate a new API key with prefix
pub fn generate_api_key(prefix: &str) -> String {
    let mut rng = rand::thread_rng();
    let random_bytes: [u8; 32] = rng.gen();
    let hex = hex::encode(random_bytes);
    format!("{}{}", prefix, hex)
}

/// Hash an API key for storage
pub fn hash_api_key(api_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate verification code for minting
pub fn generate_verification_code() -> String {
    let mut rng = rand::thread_rng();
    let random_bytes: [u8; 16] = rng.gen();
    format!("AMAI-{}", hex::encode(random_bytes).to_uppercase())
}

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
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err("Name must contain only alphanumeric characters and underscores");
    }
    if name.starts_with('_') || name.ends_with('_') {
        return Err("Name cannot start or end with underscore");
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
    if content.len() > 10240 {
        return Err("Message content must be at most 10KB");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_api_key() {
        let key = generate_api_key("amai_sk_");
        assert!(key.starts_with("amai_sk_"));
        assert_eq!(key.len(), 8 + 64); // prefix + 32 bytes hex
    }

    #[test]
    fn test_hash_api_key() {
        let key = "amai_sk_test123";
        let hash1 = hash_api_key(key);
        let hash2 = hash_api_key(key);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA256 hex
    }

    #[test]
    fn test_validate_name() {
        assert!(validate_name("valid_name").is_ok());
        assert!(validate_name("Agent001").is_ok());
        assert!(validate_name("ab").is_err()); // too short
        assert!(validate_name("a".repeat(33).as_str()).is_err()); // too long
        assert!(validate_name("invalid-name").is_err()); // invalid char
        assert!(validate_name("_invalid").is_err()); // starts with _
    }

    #[test]
    fn test_verification_code() {
        let code = generate_verification_code();
        assert!(code.starts_with("AMAI-"));
        assert_eq!(code.len(), 5 + 32); // prefix + 16 bytes hex
    }
}
