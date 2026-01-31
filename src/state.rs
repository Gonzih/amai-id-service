use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Notify};
use tokio::time::interval;
use uuid::Uuid;

use crate::auth::{generate_api_key, generate_verification_code, hash_api_key};
use crate::config::Config;
use crate::error::{ApiError, ApiResult};
use crate::types::*;

/// Global application state
pub struct AppState {
    /// All identities indexed by ID
    pub identities: DashMap<IdentityId, Identity>,
    /// Identity name → ID lookup
    pub name_index: DashMap<String, IdentityId>,
    /// API key hash → ID lookup
    pub api_key_index: DashMap<String, IdentityId>,
    /// Pending messages per identity
    pub messages: DashMap<IdentityId, Vec<Message>>,
    /// Broadcast channel for real-time updates
    pub broadcast: broadcast::Sender<WsServerMessage>,
    /// Active WebSocket connection count per identity
    pub connection_count: DashMap<IdentityId, usize>,
    /// Total messages sent (for stats)
    pub total_messages: AtomicU64,
    /// Configuration
    pub config: Config,
    /// Start time for uptime calculation
    pub start_time: Instant,
    /// Persistence dirty flag
    dirty: AtomicBool,
    /// Notify for immediate save
    persist_notify: Notify,
    /// Last persist time
    pub last_persist: std::sync::RwLock<Option<DateTime<Utc>>>,
}

impl AppState {
    pub fn new(config: Config) -> Arc<Self> {
        let (tx, _) = broadcast::channel(1024);

        Arc::new(Self {
            identities: DashMap::new(),
            name_index: DashMap::new(),
            api_key_index: DashMap::new(),
            messages: DashMap::new(),
            broadcast: tx,
            connection_count: DashMap::new(),
            total_messages: AtomicU64::new(0),
            config,
            start_time: Instant::now(),
            dirty: AtomicBool::new(false),
            persist_notify: Notify::new(),
            last_persist: std::sync::RwLock::new(None),
        })
    }

    /// Load state from disk if exists
    pub async fn load_from_disk(self: &Arc<Self>) -> anyhow::Result<()> {
        let path = self.config.state_file_path();

        if !path.exists() {
            tracing::info!("No existing state file, starting fresh");
            return Ok(());
        }

        let json = tokio::fs::read_to_string(&path).await?;
        let snapshot: StateSnapshot = serde_json::from_str(&json)?;

        for (id, identity) in snapshot.identities {
            self.name_index.insert(identity.name.clone(), id);
            self.api_key_index.insert(identity.api_key_hash.clone(), id);
            self.identities.insert(id, identity);
        }

        for (id, msgs) in snapshot.messages {
            self.messages.insert(id, msgs);
        }

        self.total_messages
            .store(snapshot.total_messages, Ordering::SeqCst);

        tracing::info!(
            "Loaded state: {} identities, {} message queues",
            self.identities.len(),
            self.messages.len()
        );

        Ok(())
    }

    /// Start background persistence worker
    pub fn spawn_persister(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let state = Arc::clone(self);
        let persist_interval = state.config.persist_interval;

        tokio::spawn(async move {
            let mut ticker = interval(persist_interval);

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if state.dirty.swap(false, Ordering::SeqCst) {
                            if let Err(e) = state.save_to_disk().await {
                                tracing::error!("Failed to persist state: {}", e);
                            }
                        }
                    }
                    _ = state.persist_notify.notified() => {
                        state.dirty.store(false, Ordering::SeqCst);
                        if let Err(e) = state.save_to_disk().await {
                            tracing::error!("Failed to persist state: {}", e);
                        }
                    }
                }
            }
        })
    }

    /// Save state to disk
    async fn save_to_disk(&self) -> anyhow::Result<()> {
        let snapshot = StateSnapshot {
            identities: self
                .identities
                .iter()
                .map(|r| (*r.key(), r.value().clone()))
                .collect(),
            messages: self
                .messages
                .iter()
                .map(|r| (*r.key(), r.value().clone()))
                .collect(),
            total_messages: self.total_messages.load(Ordering::SeqCst),
            saved_at: Utc::now(),
        };

        let json = serde_json::to_string_pretty(&snapshot)?;

        // Ensure data directory exists
        tokio::fs::create_dir_all(&self.config.data_dir).await?;

        // Atomic write (write to temp, rename)
        let path = self.config.state_file_path();
        let temp_path = path.with_extension("tmp");
        tokio::fs::write(&temp_path, &json).await?;
        tokio::fs::rename(&temp_path, &path).await?;

        *self.last_persist.write().unwrap() = Some(Utc::now());

        tracing::info!(
            "State persisted: {} identities, {} message queues",
            snapshot.identities.len(),
            snapshot.messages.len()
        );

        Ok(())
    }

    /// Mark state as dirty
    fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::SeqCst);
    }

    /// Register new identity
    pub fn register(&self, req: RegisterRequest) -> ApiResult<RegisterResponse> {
        // Check name uniqueness
        let name_lower = req.name.to_lowercase();
        if self.name_index.contains_key(&name_lower) {
            return Err(ApiError::Conflict("Name already taken".into()));
        }

        // Generate identity
        let id = Uuid::new_v4();
        let api_key = generate_api_key(&self.config.api_key_prefix);
        let api_key_hash = hash_api_key(&api_key);
        let verification_code = generate_verification_code();

        let now = Utc::now();
        let identity = Identity {
            id,
            name: req.name.clone(),
            description: req.description,
            api_key_hash: api_key_hash.clone(),
            wallet_address: None,
            token_id: None,
            status: IdentityStatus::Pending,
            tier: IdentityTier::Standard,
            trust_score: 60.0,
            messages_sent: 0,
            messages_received: 0,
            created_at: now,
            last_active: now,
            metadata: req.metadata.unwrap_or(serde_json::Value::Null),
        };

        // Generate mint instructions
        let mint_instructions = MintInstructions {
            contract_address: self.config.identity_contract.clone(),
            chain_id: self.config.chain_id,
            function: "mintIdentity(string,bytes32)".into(),
            calldata: format!(
                "0x{:0>64}{:0>64}",
                hex::encode(req.name.as_bytes()),
                hex::encode(verification_code.as_bytes())
            ),
            estimated_gas: 150000,
            verification_code: verification_code.clone(),
            expires_at: now + ChronoDuration::hours(24),
        };

        // Store
        self.identities.insert(id, identity.clone());
        self.name_index.insert(name_lower, id);
        self.api_key_index.insert(api_key_hash, id);
        self.messages.insert(id, Vec::new());

        self.mark_dirty();

        Ok(RegisterResponse {
            identity,
            api_key,
            mint_instructions,
        })
    }

    /// Authenticate by API key
    pub fn authenticate(&self, api_key: &str) -> ApiResult<Identity> {
        let hash = hash_api_key(api_key);
        let id = self
            .api_key_index
            .get(&hash)
            .map(|r| *r.value())
            .ok_or(ApiError::Unauthorized)?;
        let identity = self
            .identities
            .get(&id)
            .map(|r| r.value().clone())
            .ok_or(ApiError::Unauthorized)?;
        Ok(identity)
    }

    /// Get identity by ID
    pub fn get_identity(&self, id: &IdentityId) -> ApiResult<Identity> {
        self.identities
            .get(id)
            .map(|r| r.value().clone())
            .ok_or_else(|| ApiError::NotFound("Identity not found".into()))
    }

    /// Get identity by name
    pub fn get_identity_by_name(&self, name: &str) -> ApiResult<Identity> {
        let name_lower = name.to_lowercase();
        let id = self
            .name_index
            .get(&name_lower)
            .map(|r| *r.value())
            .ok_or_else(|| ApiError::NotFound("Identity not found".into()))?;
        self.get_identity(&id)
    }

    /// Resolve identity ID from ID string or name
    pub fn resolve_identity(&self, id_or_name: &str) -> ApiResult<IdentityId> {
        // Try parsing as UUID first
        if let Ok(id) = Uuid::parse_str(id_or_name) {
            if self.identities.contains_key(&id) {
                return Ok(id);
            }
        }

        // Try as name
        let name_lower = id_or_name.to_lowercase();
        self.name_index
            .get(&name_lower)
            .map(|r| *r.value())
            .ok_or_else(|| ApiError::NotFound("Identity not found".into()))
    }

    /// Update identity
    pub fn update_identity(&self, id: &IdentityId, req: UpdateIdentityRequest) -> ApiResult<Identity> {
        let mut identity = self
            .identities
            .get_mut(id)
            .ok_or_else(|| ApiError::NotFound("Identity not found".into()))?;

        if let Some(desc) = req.description {
            identity.description = Some(desc);
        }

        if let Some(metadata) = req.metadata {
            // Merge metadata if both are objects, otherwise replace
            match (&mut identity.metadata, metadata) {
                (serde_json::Value::Object(existing), serde_json::Value::Object(new)) => {
                    existing.extend(new);
                }
                (existing, new) => {
                    *existing = new;
                }
            }
        }

        identity.last_active = Utc::now();
        self.mark_dirty();

        Ok(identity.clone())
    }

    /// Verify mint transaction
    pub async fn verify_mint(
        &self,
        id: &IdentityId,
        _req: VerifyMintRequest,
    ) -> ApiResult<VerifyMintResponse> {
        // TODO: Implement actual blockchain verification
        // For now, simulate successful verification

        let mut identity = self
            .identities
            .get_mut(id)
            .ok_or_else(|| ApiError::NotFound("Identity not found".into()))?;

        if identity.status != IdentityStatus::Pending {
            return Err(ApiError::BadRequest(
                "Identity already verified or not pending".into(),
            ));
        }

        // Simulate getting token_id from blockchain
        let token_id = (self.identities.len() as u64) + 1;

        identity.status = IdentityStatus::Active;
        identity.wallet_address = Some(_req.wallet_address);
        identity.token_id = Some(token_id);
        identity.last_active = Utc::now();

        self.mark_dirty();

        Ok(VerifyMintResponse {
            identity: identity.clone(),
            token_id,
        })
    }

    /// Send message
    pub fn send_message(&self, from: &IdentityId, req: SendMessageRequest) -> ApiResult<Message> {
        // Validate sender is active
        let sender = self.get_identity(from)?;
        if sender.status != IdentityStatus::Active {
            return Err(ApiError::Forbidden(
                "Sender identity is not active".into(),
            ));
        }

        // Resolve recipient
        let to_id = self.resolve_identity(&req.to)?;
        let recipient = self.get_identity(&to_id)?;

        if recipient.status != IdentityStatus::Active {
            return Err(ApiError::BadRequest(
                "Recipient identity is not active".into(),
            ));
        }

        // Create message
        let message = Message {
            id: Uuid::new_v4(),
            from: *from,
            to: to_id,
            content: req.content,
            message_type: req.message_type,
            timestamp: Utc::now(),
            delivered: false,
            read: false,
        };

        // Store message
        self.messages
            .entry(to_id)
            .or_insert_with(Vec::new)
            .push(message.clone());

        // Update sender stats
        if let Some(mut sender) = self.identities.get_mut(from) {
            sender.messages_sent += 1;
            sender.last_active = Utc::now();
        }

        // Update recipient stats
        if let Some(mut recipient) = self.identities.get_mut(&to_id) {
            recipient.messages_received += 1;
        }

        self.total_messages.fetch_add(1, Ordering::SeqCst);
        self.mark_dirty();

        // Broadcast to connected clients
        let _ = self.broadcast.send(WsServerMessage::Message {
            data: message.clone(),
        });

        Ok(message)
    }

    /// Get messages for identity
    pub fn get_messages(&self, id: &IdentityId, query: GetMessagesQuery) -> Vec<Message> {
        let messages = self.messages.get(id);
        let Some(messages) = messages else {
            return Vec::new();
        };

        let mut result: Vec<Message> = messages
            .iter()
            .filter(|m| {
                if let Some(from) = query.from {
                    if m.from != from {
                        return false;
                    }
                }
                if query.unread == Some(true) && m.read {
                    return false;
                }
                true
            })
            .cloned()
            .collect();

        // Sort by timestamp descending
        result.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Apply pagination
        let offset = query.offset.unwrap_or(0) as usize;
        let limit = query.limit.unwrap_or(50).min(100) as usize;

        result.into_iter().skip(offset).take(limit).collect()
    }

    /// Mark message as read
    pub fn mark_message_read(&self, owner: &IdentityId, message_id: &Uuid) -> ApiResult<()> {
        let mut messages = self
            .messages
            .get_mut(owner)
            .ok_or_else(|| ApiError::NotFound("No messages found".into()))?;

        let msg = messages
            .iter_mut()
            .find(|m| &m.id == message_id)
            .ok_or_else(|| ApiError::NotFound("Message not found".into()))?;

        msg.read = true;
        msg.delivered = true;
        self.mark_dirty();

        Ok(())
    }

    /// Delete message
    pub fn delete_message(&self, owner: &IdentityId, message_id: &Uuid) -> ApiResult<()> {
        let mut messages = self
            .messages
            .get_mut(owner)
            .ok_or_else(|| ApiError::NotFound("No messages found".into()))?;

        let pos = messages
            .iter()
            .position(|m| &m.id == message_id)
            .ok_or_else(|| ApiError::NotFound("Message not found".into()))?;

        messages.remove(pos);
        self.mark_dirty();

        Ok(())
    }

    /// Get health info
    pub fn health(&self) -> HealthResponse {
        HealthResponse {
            status: "healthy".into(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            identities_count: self.identities.len(),
            active_connections: self.connection_count.iter().map(|r| *r.value()).sum(),
            last_persist: *self.last_persist.read().unwrap(),
        }
    }

    /// Get public stats
    pub fn stats(&self) -> StatsResponse {
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
            total_messages: self.total_messages.load(Ordering::SeqCst),
            active_connections: self.connection_count.iter().map(|r| *r.value()).sum(),
        }
    }

    /// List identities (paginated)
    pub fn list_identities(&self, limit: usize, offset: usize) -> Vec<IdentityPublic> {
        self.identities
            .iter()
            .skip(offset)
            .take(limit)
            .map(|r| IdentityPublic::from(r.value()))
            .collect()
    }

    /// Track WebSocket connection
    pub fn connection_opened(&self, id: &IdentityId) {
        *self.connection_count.entry(*id).or_insert(0) += 1;
    }

    /// Track WebSocket disconnection
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
    total_messages: u64,
    saved_at: DateTime<Utc>,
}
