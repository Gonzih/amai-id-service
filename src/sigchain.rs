//! Sigchain implementation (Keybase-style cryptographic chain)
//!
//! Each identity has a sigchain - an append-only list of cryptographically
//! linked entries. Every entry is signed by the identity's key and includes
//! the hash of the previous entry, creating an immutable audit log.

use std::collections::HashMap;
use std::path::PathBuf;

use chrono::Utc;
use tokio::sync::RwLock;

use crate::crypto::{parse_public_key, sha256_hex, verify_signature};
use crate::error::{ApiError, ApiResult};
use crate::types::{
    ActionOutcome, IdentityId, KeyId, KeyType, PublicKey, SigchainBody, SigchainLink,
};

/// Sigchain storage for all identities
pub struct SigchainStore {
    /// Sigchains indexed by identity ID
    chains: RwLock<HashMap<IdentityId, Vec<SigchainLink>>>,
    /// Storage directory
    storage_dir: PathBuf,
}

impl SigchainStore {
    pub fn new(storage_dir: PathBuf) -> Self {
        Self {
            chains: RwLock::new(HashMap::new()),
            storage_dir,
        }
    }

    /// Get current sigchain length for an identity
    pub async fn get_seqno(&self, identity_id: &IdentityId) -> u64 {
        let chains = self.chains.read().await;
        chains.get(identity_id).map(|c| c.len() as u64).unwrap_or(0)
    }

    /// Get current head hash
    pub async fn get_head_hash(&self, identity_id: &IdentityId) -> Option<String> {
        let chains = self.chains.read().await;
        chains
            .get(identity_id)
            .and_then(|c| c.last())
            .map(|link| link.curr.clone())
    }

    /// Get sigchain links for an identity
    pub async fn get_links(
        &self,
        identity_id: &IdentityId,
        limit: usize,
        offset: usize,
    ) -> Vec<SigchainLink> {
        let chains = self.chains.read().await;
        chains
            .get(identity_id)
            .map(|c| {
                c.iter()
                    .rev() // Most recent first
                    .skip(offset)
                    .take(limit)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get total count
    pub async fn total_entries(&self) -> u64 {
        let chains = self.chains.read().await;
        chains.values().map(|c| c.len() as u64).sum()
    }

    /// Append a new link to the sigchain
    ///
    /// This verifies the signature and hash chain before appending.
    pub async fn append(
        &self,
        identity_id: &IdentityId,
        body: SigchainBody,
        signature: String,
        signing_key: &PublicKey,
    ) -> ApiResult<SigchainLink> {
        let mut chains = self.chains.write().await;
        let chain = chains.entry(*identity_id).or_insert_with(Vec::new);

        // Get prev hash and seqno
        let (prev, seqno) = if let Some(last) = chain.last() {
            (Some(last.curr.clone()), last.seqno + 1)
        } else {
            (None, 1)
        };

        // First link must be Eldest
        if seqno == 1 && !matches!(body, SigchainBody::Eldest { .. }) {
            return Err(ApiError::sigchain("First sigchain link must be 'eldest'"));
        }

        // Create the link body JSON for hashing
        let body_json =
            serde_json::to_string(&body).map_err(|e| ApiError::internal(e.to_string()))?;

        // Compute body hash
        let curr = sha256_hex(body_json.as_bytes());

        // Verify signature of the body
        let parsed_key = parse_public_key(&signing_key.public_key_pem, &signing_key.key_type)
            .map_err(|e| ApiError::signature(e.to_string()))?;

        verify_signature(&parsed_key, body_json.as_bytes(), &signature)
            .map_err(|e| ApiError::signature(format!("Sigchain signature invalid: {}", e)))?;

        let link = SigchainLink {
            seqno,
            prev,
            curr,
            body,
            sig: signature,
            signing_kid: signing_key.kid.clone(),
            ctime: Utc::now(),
        };

        chain.push(link.clone());

        Ok(link)
    }

    /// Verify entire sigchain integrity
    pub async fn verify_chain(
        &self,
        identity_id: &IdentityId,
        keys: &[PublicKey],
    ) -> ApiResult<()> {
        let chains = self.chains.read().await;
        let chain = chains
            .get(identity_id)
            .ok_or_else(|| ApiError::not_found("Sigchain not found"))?;

        let mut expected_prev: Option<String> = None;

        for (i, link) in chain.iter().enumerate() {
            // Check seqno
            if link.seqno != (i + 1) as u64 {
                return Err(ApiError::sigchain(format!(
                    "Seqno mismatch at index {}: expected {}, got {}",
                    i,
                    i + 1,
                    link.seqno
                )));
            }

            // Check prev hash
            if link.prev != expected_prev {
                return Err(ApiError::sigchain(format!(
                    "Hash chain broken at seqno {}",
                    link.seqno
                )));
            }

            // Verify body hash
            let body_json =
                serde_json::to_string(&link.body).map_err(|e| ApiError::internal(e.to_string()))?;
            let computed_hash = sha256_hex(body_json.as_bytes());
            if computed_hash != link.curr {
                return Err(ApiError::sigchain(format!(
                    "Body hash mismatch at seqno {}",
                    link.seqno
                )));
            }

            // Find signing key
            let signing_key = keys
                .iter()
                .find(|k| k.kid == link.signing_kid)
                .ok_or_else(|| {
                    ApiError::sigchain(format!(
                        "Signing key {} not found for seqno {}",
                        link.signing_kid, link.seqno
                    ))
                })?;

            // Verify signature
            let parsed_key = parse_public_key(&signing_key.public_key_pem, &signing_key.key_type)
                .map_err(|e| ApiError::sigchain(e.to_string()))?;

            verify_signature(&parsed_key, body_json.as_bytes(), &link.sig).map_err(|e| {
                ApiError::sigchain(format!(
                    "Signature verification failed at seqno {}: {}",
                    link.seqno, e
                ))
            })?;

            expected_prev = Some(link.curr.clone());
        }

        Ok(())
    }

    /// Save sigchain to disk
    pub async fn save(&self, identity_id: &IdentityId) -> anyhow::Result<()> {
        let chains = self.chains.read().await;
        if let Some(chain) = chains.get(identity_id) {
            let path = self.storage_dir.join(format!("{}.json", identity_id));
            tokio::fs::create_dir_all(&self.storage_dir).await?;
            let json = serde_json::to_string_pretty(chain)?;
            tokio::fs::write(path, json).await?;
        }
        Ok(())
    }

    /// Load sigchain from disk
    pub async fn load(&self, identity_id: &IdentityId) -> anyhow::Result<()> {
        let path = self.storage_dir.join(format!("{}.json", identity_id));
        if path.exists() {
            let json = tokio::fs::read_to_string(&path).await?;
            let chain: Vec<SigchainLink> = serde_json::from_str(&json)?;
            let mut chains = self.chains.write().await;
            chains.insert(*identity_id, chain);
        }
        Ok(())
    }

    /// Load all sigchains from disk
    pub async fn load_all(&self) -> anyhow::Result<usize> {
        if !self.storage_dir.exists() {
            return Ok(0);
        }

        let mut count = 0;
        let mut entries = tokio::fs::read_dir(&self.storage_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    if let Ok(id) = stem.parse::<IdentityId>() {
                        let json = tokio::fs::read_to_string(&path).await?;
                        if let Ok(chain) = serde_json::from_str::<Vec<SigchainLink>>(&json) {
                            let mut chains = self.chains.write().await;
                            chains.insert(id, chain);
                            count += 1;
                        }
                    }
                }
            }
        }

        Ok(count)
    }

    /// Save all sigchains
    pub async fn save_all(&self) -> anyhow::Result<()> {
        let chains = self.chains.read().await;
        tokio::fs::create_dir_all(&self.storage_dir).await?;

        for (id, chain) in chains.iter() {
            let path = self.storage_dir.join(format!("{}.json", id));
            let json = serde_json::to_string_pretty(chain)?;
            tokio::fs::write(path, json).await?;
        }

        Ok(())
    }
}

/// Helper to create sigchain body for action
pub fn action_body(
    action_type: String,
    outcome: ActionOutcome,
    payload: serde_json::Value,
    intent: Option<String>,
    platform_ref: Option<String>,
) -> SigchainBody {
    SigchainBody::Action {
        action_type,
        outcome,
        payload,
        intent,
        platform_ref,
    }
}

/// Helper to create eldest (first key registration) body
pub fn eldest_body(kid: KeyId, key_type: KeyType, public_key_pem: String) -> SigchainBody {
    SigchainBody::Eldest {
        kid,
        key_type,
        public_key_pem,
    }
}

/// Helper to create add key body
pub fn add_key_body(kid: KeyId, key_type: KeyType, public_key_pem: String) -> SigchainBody {
    SigchainBody::AddKey {
        kid,
        key_type,
        public_key_pem,
    }
}

/// Helper to create revoke key body
pub fn revoke_key_body(kid: KeyId) -> SigchainBody {
    SigchainBody::RevokeKey { kid }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_sigchain_store_basic() {
        let dir = tempdir().unwrap();
        let store = SigchainStore::new(dir.path().to_path_buf());

        let id = IdentityId::new_v4();

        // Initially empty
        assert_eq!(store.get_seqno(&id).await, 0);
        assert!(store.get_head_hash(&id).await.is_none());
    }

    #[tokio::test]
    async fn test_total_entries() {
        let dir = tempdir().unwrap();
        let store = SigchainStore::new(dir.path().to_path_buf());

        assert_eq!(store.total_entries().await, 0);
    }
}
