//! Application state for AMAI Identity Service

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Notify};
use tokio::time::interval;
use uuid::Uuid;

use crate::auth::{
    create_public_key, validate_description, validate_metadata, validate_name,
    verify_registration_signature, NonceStore, RegistrationParams,
};
use crate::config::Config;
use crate::error::{ApiError, ApiResult};
use crate::soulchain::{eldest_body, SoulchainStore};
use crate::types::*;

/// Global application state
pub struct AppState {
    /// All identities indexed by ID
    pub identities: DashMap<IdentityId, Identity>,
    /// Identity name -> ID lookup
    pub name_index: DashMap<String, IdentityId>,
    /// Key ID -> Identity ID lookup
    pub kid_index: DashMap<KeyId, IdentityId>,
    /// Public keys indexed by KID
    pub keys: DashMap<KeyId, PublicKey>,
    /// Pending messages per identity
    pub messages: DashMap<IdentityId, Vec<Message>>,
    /// Broadcast channel for real-time updates
    pub broadcast: broadcast::Sender<WsServerMessage>,
    /// Active WebSocket connection count per identity
    pub connection_count: DashMap<IdentityId, usize>,
    /// Total messages sent
    pub total_messages: AtomicU64,
    /// Soulchain storage
    pub soulchain: SoulchainStore,
    /// Registered platforms
    pub platforms: DashMap<String, Platform>,
    /// Platform KID -> platform ID lookup
    pub platform_kid_index: DashMap<KeyId, String>,
    /// Nonce store for replay protection
    pub nonces: NonceStore,
    /// Configuration
    pub config: Config,
    /// Start time for uptime calculation
    pub start_time: Instant,
    /// Persistence dirty flag
    dirty: AtomicBool,
    /// Notify for immediate save
    persist_notify: Notify,
    /// Shutdown flag
    shutdown: AtomicBool,
    /// Last persist time
    pub last_persist: std::sync::RwLock<Option<DateTime<Utc>>>,
}

impl AppState {
    pub fn new(config: Config) -> Arc<Self> {
        let (tx, _) = broadcast::channel(1024);
        let soulchain_dir = config.soulchain_dir();

        Arc::new(Self {
            identities: DashMap::new(),
            name_index: DashMap::new(),
            kid_index: DashMap::new(),
            keys: DashMap::new(),
            messages: DashMap::new(),
            broadcast: tx,
            connection_count: DashMap::new(),
            total_messages: AtomicU64::new(0),
            soulchain: SoulchainStore::new(soulchain_dir),
            platforms: DashMap::new(),
            platform_kid_index: DashMap::new(),
            nonces: NonceStore::new(config.nonce_expiry),
            config,
            start_time: Instant::now(),
            dirty: AtomicBool::new(false),
            persist_notify: Notify::new(),
            shutdown: AtomicBool::new(false),
            last_persist: std::sync::RwLock::new(None),
        })
    }

    /// Load state from disk
    pub async fn load_from_disk(self: &Arc<Self>) -> anyhow::Result<()> {
        let path = self.config.state_file_path();

        if path.exists() {
            let json = tokio::fs::read_to_string(&path).await?;
            let snapshot: StateSnapshot = serde_json::from_str(&json)?;

            for (id, mut identity) in snapshot.identities {
                for key in identity.keys.drain(..) {
                    self.kid_index.insert(key.kid.clone(), id);
                    self.keys.insert(key.kid.clone(), key);
                }
                self.name_index.insert(identity.name.to_lowercase(), id);
                self.identities.insert(id, identity);
            }

            for (id, msgs) in snapshot.messages {
                self.messages.insert(id, msgs);
            }

            for platform in snapshot.platforms {
                self.platform_kid_index
                    .insert(platform.kid.clone(), platform.id.clone());
                self.platforms.insert(platform.id.clone(), platform);
            }

            self.total_messages
                .store(snapshot.total_messages, Ordering::SeqCst);

            tracing::info!(
                "Loaded state: {} identities, {} keys, {} platforms",
                self.identities.len(),
                self.keys.len(),
                self.platforms.len()
            );
        } else {
            tracing::info!("No existing state file, starting fresh");
        }

        // Load soulchains
        match self.soulchain.load_all().await {
            Ok(count) => tracing::info!("Loaded {} soulchains", count),
            Err(e) => tracing::warn!("Failed to load soulchains: {}", e),
        }

        Ok(())
    }

    /// Start background persistence worker
    pub fn spawn_persister(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let state = Arc::clone(self);
        let persist_interval = state.config.persist_interval;

        tokio::spawn(async move {
            let mut ticker = interval(persist_interval);

            loop {
                if state.shutdown.load(Ordering::SeqCst) {
                    tracing::info!("Persister shutting down, final save...");
                    if let Err(e) = state.save_all().await {
                        tracing::error!("Failed final persist: {}", e);
                    }
                    break;
                }

                tokio::select! {
                    _ = ticker.tick() => {
                        if state.dirty.swap(false, Ordering::SeqCst) {
                            if let Err(e) = state.save_all().await {
                                tracing::error!("Failed to persist state: {}", e);
                            }
                        }
                    }
                    _ = state.persist_notify.notified() => {
                        state.dirty.store(false, Ordering::SeqCst);
                        if let Err(e) = state.save_all().await {
                            tracing::error!("Failed to persist state: {}", e);
                        }
                    }
                }
            }
        })
    }

    /// Signal shutdown
    pub fn signal_shutdown(&self) {
        tracing::info!("Shutdown signaled");
        self.shutdown.store(true, Ordering::SeqCst);
        self.persist_notify.notify_one();
    }

    /// Check if shutdown was requested
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Save all state
    pub async fn save_all(&self) -> anyhow::Result<()> {
        self.save_to_disk().await?;
        self.soulchain.save_all().await?;
        Ok(())
    }

    /// Save state to disk
    async fn save_to_disk(&self) -> anyhow::Result<()> {
        let mut identities_with_keys = Vec::new();

        for r in self.identities.iter() {
            let mut identity = r.value().clone();
            identity.keys = self
                .keys
                .iter()
                .filter(|k| {
                    self.kid_index
                        .get(k.key())
                        .map(|v| *v == identity.id)
                        .unwrap_or(false)
                })
                .map(|k| k.value().clone())
                .collect();
            identities_with_keys.push((*r.key(), identity));
        }

        let snapshot = StateSnapshot {
            identities: identities_with_keys,
            messages: self
                .messages
                .iter()
                .map(|r| (*r.key(), r.value().clone()))
                .collect(),
            platforms: self.platforms.iter().map(|r| r.value().clone()).collect(),
            total_messages: self.total_messages.load(Ordering::SeqCst),
            saved_at: Utc::now(),
        };

        let json = serde_json::to_string_pretty(&snapshot)?;
        tokio::fs::create_dir_all(&self.config.data_dir).await?;

        let path = self.config.state_file_path();
        let temp_path = path.with_extension("tmp");
        tokio::fs::write(&temp_path, &json).await?;
        tokio::fs::rename(&temp_path, &path).await?;

        *self.last_persist.write().unwrap() = Some(Utc::now());
        tracing::info!("State persisted: {} identities", snapshot.identities.len());
        Ok(())
    }

    fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::SeqCst);
    }

    // ============ Identity Operations ============

    /// Register new identity with public key
    pub async fn register(&self, req: RegisterRequest) -> ApiResult<RegisterResponse> {
        validate_name(&req.name)
            .map_err(|e| ApiError::bad_request_with_hint(e, "Name: 3-32 alphanumeric chars"))?;

        if let Some(ref desc) = req.description {
            validate_description(desc).map_err(|e| ApiError::BadRequest(e.into()))?;
        }

        if let Some(ref metadata) = req.metadata {
            validate_metadata(metadata).map_err(|e| ApiError::BadRequest(e.into()))?;
        }

        let name_lower = req.name.to_lowercase();
        if self.name_index.contains_key(&name_lower) {
            return Err(ApiError::Conflict("Name already taken".into()));
        }

        // Verify registration signature
        let params = RegistrationParams {
            name: &req.name,
            public_key_pem: &req.public_key,
            key_type: &req.key_type,
            signature: &req.signature,
            timestamp: &req.timestamp,
            nonce: &req.nonce,
        };
        verify_registration_signature(&params, &self.nonces, self.config.max_clock_skew)?;

        let public_key = create_public_key(&req.public_key, req.key_type.clone(), true)?;

        let id = Uuid::new_v4();
        let now = Utc::now();

        let identity = Identity {
            id,
            name: req.name.clone(),
            description: req.description,
            status: IdentityStatus::Active,
            trust_score: 60.0,
            actions_count: 0,
            messages_sent: 0,
            messages_received: 0,
            created_at: now,
            last_active: now,
            metadata: req.metadata.unwrap_or(serde_json::Value::Null),
            keys: vec![],
            soulchain_hash: None,
            soulchain_seq: 0,
        };

        // Create eldest soulchain link
        let eldest = eldest_body(
            public_key.kid.clone(),
            public_key.key_type.clone(),
            public_key.public_key_pem.clone(),
        );

        let link = self
            .soulchain
            .append(&id, eldest, req.signature.clone(), &public_key)
            .await?;

        let mut identity = identity;
        identity.soulchain_hash = Some(link.curr.clone());
        identity.soulchain_seq = link.seqno;

        self.identities.insert(id, identity.clone());
        self.name_index.insert(name_lower, id);
        self.kid_index.insert(public_key.kid.clone(), id);
        self.keys.insert(public_key.kid.clone(), public_key);
        self.messages.insert(id, Vec::new());

        self.mark_dirty();
        tracing::info!("Registered identity: {} ({})", req.name, id);

        Ok(RegisterResponse {
            identity: IdentityPublic::from(&identity),
            challenge: None,
        })
    }

    /// Authenticate by key ID
    pub fn authenticate(&self, kid: &KeyId) -> ApiResult<Identity> {
        let id = self
            .kid_index
            .get(kid)
            .map(|r| *r.value())
            .ok_or(ApiError::Unauthorized)?;
        let identity = self
            .identities
            .get(&id)
            .map(|r| r.value().clone())
            .ok_or(ApiError::Unauthorized)?;
        let key = self.keys.get(kid).ok_or(ApiError::Unauthorized)?;
        if key.revoked {
            return Err(ApiError::signature("Key has been revoked"));
        }
        Ok(identity)
    }

    /// Get identity by ID
    pub fn get_identity(&self, id: &IdentityId) -> ApiResult<Identity> {
        self.identities
            .get(id)
            .map(|r| r.value().clone())
            .ok_or_else(|| ApiError::NotFound("Identity not found".into()))
    }

    /// Resolve identity ID from ID string or name
    pub fn resolve_identity(&self, id_or_name: &str) -> ApiResult<IdentityId> {
        if let Ok(id) = Uuid::parse_str(id_or_name) {
            if self.identities.contains_key(&id) {
                return Ok(id);
            }
        }
        let name_lower = id_or_name.to_lowercase();
        self.name_index
            .get(&name_lower)
            .map(|r| *r.value())
            .ok_or_else(|| ApiError::NotFound("Identity not found".into()))
    }

    /// Get public key by KID
    pub fn get_key(&self, kid: &KeyId) -> ApiResult<PublicKey> {
        self.keys
            .get(kid)
            .map(|r| r.value().clone())
            .ok_or_else(|| ApiError::NotFound("Key not found".into()))
    }

    /// Get all keys for an identity
    pub fn get_identity_keys(&self, id: &IdentityId) -> Vec<PublicKey> {
        self.keys
            .iter()
            .filter(|k| {
                self.kid_index
                    .get(k.key())
                    .map(|v| *v == *id)
                    .unwrap_or(false)
            })
            .map(|k| k.value().clone())
            .collect()
    }

    /// List identities
    pub fn list_identities(&self, limit: usize, offset: usize) -> Vec<IdentityPublic> {
        self.identities
            .iter()
            .skip(offset)
            .take(limit)
            .map(|r| IdentityPublic::from(r.value()))
            .collect()
    }

    /// Get health info
    pub fn health(&self) -> HealthResponse {
        HealthResponse {
            status: "healthy".into(),
            version: self.config.version.clone(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            identities_count: self.identities.len(),
            active_connections: self.connection_count.iter().map(|r| *r.value()).sum(),
        }
    }

    /// Get public stats
    pub async fn stats(&self) -> StatsResponse {
        let active = self
            .identities
            .iter()
            .filter(|r| r.value().status == IdentityStatus::Active)
            .count();
        let pending = self
            .identities
            .iter()
            .filter(|r| r.value().status == IdentityStatus::Pending)
            .count();

        StatsResponse {
            total_identities: self.identities.len(),
            active_identities: active,
            pending_identities: pending,
            total_soulchain_entries: self.soulchain.total_entries().await,
            total_messages: self.total_messages.load(Ordering::SeqCst),
        }
    }

    pub fn connection_opened(&self, id: &IdentityId) {
        *self.connection_count.entry(*id).or_insert(0) += 1;
    }

    pub fn connection_closed(&self, id: &IdentityId) {
        if let Some(mut count) = self.connection_count.get_mut(id) {
            if *count > 0 {
                *count -= 1;
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct StateSnapshot {
    identities: Vec<(IdentityId, Identity)>,
    messages: Vec<(IdentityId, Vec<Message>)>,
    #[serde(default)]
    platforms: Vec<Platform>,
    total_messages: u64,
    saved_at: DateTime<Utc>,
}
