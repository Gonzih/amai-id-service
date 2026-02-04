//! Cryptographic operations for AMAI Identity Service
//!
//! Provides Ed25519 and RSA signature verification, key parsing,
//! and fingerprint generation.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::sha2::Sha256;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256 as Sha256Hasher};

use crate::types::KeyType;

/// Result type for crypto operations
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Crypto operation errors
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid public key format: {0}")]
    InvalidPublicKey(String),
    #[error("Invalid signature format: {0}")]
    InvalidSignature(String),
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Unsupported key type")]
    UnsupportedKeyType,
    #[error("Base64 decode error: {0}")]
    Base64Error(String),
}

/// Parsed public key (either Ed25519 or RSA)
pub enum ParsedPublicKey {
    Ed25519(VerifyingKey),
    Rsa(RsaPublicKey),
}

/// Parse a PEM-encoded public key
pub fn parse_public_key(pem: &str, key_type: &KeyType) -> CryptoResult<ParsedPublicKey> {
    match key_type {
        KeyType::Ed25519 => parse_ed25519_public_key(pem),
        KeyType::Rsa => parse_rsa_public_key(pem),
    }
}

/// Parse Ed25519 public key from PEM or raw base64
pub fn parse_ed25519_public_key(pem: &str) -> CryptoResult<ParsedPublicKey> {
    // Try to extract the key bytes from PEM format
    let key_bytes = if pem.contains("-----BEGIN") {
        // PEM format - extract the base64 content
        let lines: Vec<&str> = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let b64 = lines.join("");
        let der = BASE64
            .decode(&b64)
            .map_err(|e| CryptoError::Base64Error(e.to_string()))?;

        // Ed25519 public key in PKCS#8/SPKI format has a header
        // The actual key is the last 32 bytes
        if der.len() >= 32 {
            der[der.len() - 32..].to_vec()
        } else {
            return Err(CryptoError::InvalidPublicKey(
                "Ed25519 key too short".into(),
            ));
        }
    } else {
        // Raw base64
        BASE64
            .decode(pem.trim())
            .map_err(|e| CryptoError::Base64Error(e.to_string()))?
    };

    if key_bytes.len() != 32 {
        return Err(CryptoError::InvalidPublicKey(format!(
            "Ed25519 key must be 32 bytes, got {}",
            key_bytes.len()
        )));
    }

    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidPublicKey("Invalid key length".into()))?;

    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

    Ok(ParsedPublicKey::Ed25519(verifying_key))
}

/// Parse RSA public key from PEM
pub fn parse_rsa_public_key(pem: &str) -> CryptoResult<ParsedPublicKey> {
    let public_key = RsaPublicKey::from_public_key_pem(pem)
        .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

    Ok(ParsedPublicKey::Rsa(public_key))
}

/// Verify a signature against a message
pub fn verify_signature(
    public_key: &ParsedPublicKey,
    message: &[u8],
    signature_b64: &str,
) -> CryptoResult<()> {
    let sig_bytes = BASE64
        .decode(signature_b64)
        .map_err(|e| CryptoError::Base64Error(e.to_string()))?;

    match public_key {
        ParsedPublicKey::Ed25519(key) => {
            if sig_bytes.len() != 64 {
                return Err(CryptoError::InvalidSignature(format!(
                    "Ed25519 signature must be 64 bytes, got {}",
                    sig_bytes.len()
                )));
            }
            let sig_array: [u8; 64] = sig_bytes
                .try_into()
                .map_err(|_| CryptoError::InvalidSignature("Invalid signature length".into()))?;
            let signature = Ed25519Signature::from_bytes(&sig_array);

            key.verify(message, &signature)
                .map_err(|_| CryptoError::VerificationFailed)?;
        }
        ParsedPublicKey::Rsa(key) => {
            let verifying_key = RsaVerifyingKey::<Sha256>::new(key.clone());
            let signature = RsaSignature::try_from(sig_bytes.as_slice())
                .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;

            verifying_key
                .verify(message, &signature)
                .map_err(|_| CryptoError::VerificationFailed)?;
        }
    }

    Ok(())
}

/// Compute SHA256 fingerprint of a public key (hex encoded)
pub fn compute_fingerprint(public_key_pem: &str) -> String {
    let mut hasher = Sha256Hasher::new();
    hasher.update(public_key_pem.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a Key ID from a public key
pub fn generate_kid(public_key_pem: &str) -> String {
    let fingerprint = compute_fingerprint(public_key_pem);
    // Use first 16 chars of fingerprint as kid
    format!("kid_{}", &fingerprint[..16])
}

/// Compute SHA256 hash of data (hex encoded)
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256Hasher::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Generate a random nonce (32 bytes, hex encoded)
pub fn generate_nonce() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_ed25519_sign_verify() {
        // Generate a keypair
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Create message
        let message = b"test message";

        // Sign
        use ed25519_dalek::Signer;
        let signature = signing_key.sign(message);
        let sig_b64 = BASE64.encode(signature.to_bytes());

        // Verify
        let parsed = ParsedPublicKey::Ed25519(verifying_key);
        assert!(verify_signature(&parsed, message, &sig_b64).is_ok());

        // Wrong message should fail
        let wrong_message = b"wrong message";
        assert!(verify_signature(&parsed, wrong_message, &sig_b64).is_err());
    }

    #[test]
    fn test_fingerprint() {
        let pem = "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----";
        let fp = compute_fingerprint(pem);
        assert_eq!(fp.len(), 64); // SHA256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn test_generate_kid() {
        let pem = "test_key";
        let kid = generate_kid(pem);
        assert!(kid.starts_with("kid_"));
        assert_eq!(kid.len(), 4 + 16); // "kid_" + 16 hex chars
    }

    #[test]
    fn test_sha256_hex() {
        let data = b"hello";
        let hash = sha256_hex(data);
        assert_eq!(hash.len(), 64);
        // Known SHA256 of "hello"
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_generate_nonce() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        assert_eq!(nonce1.len(), 64);
        assert_ne!(nonce1, nonce2); // Should be different
    }
}
