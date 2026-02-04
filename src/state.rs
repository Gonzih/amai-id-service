use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Notify};
use tokio::time::interval;
use uuid::Uuid;

use crate::action_log::{ActionLog, ActionOutcome, ActionEntry, OracleSnapshot};
use crate::auth::{generate_api_key, generate_verification_code, hash_api_key};
use crate::config::{Config, format_version};
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
    /// Append-only action log (Kafka-like)
    pub action_log: ActionLog,
    /// Registered platforms
    pub platforms: DashMap<String, Platform>,
    /// Platform API key hash → platform ID lookup
    pub platform_key_index: DashMap<String, String>,
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

        Arc::new(Self {
            identities: DashMap::new(),
            name_index: DashMap::new(),
            api_key_index: DashMap::new(),
            messages: DashMap::new(),
            broadcast: tx,
            connection_count: DashMap::new(),
            total_messages: AtomicU64::new(0),
            action_log: ActionLog::new(),
            platforms: DashMap::new(),
            platform_key_index: DashMap::new(),
            config,
            start_time: Instant::now(),
            dirty: AtomicBool::new(false),
            persist_notify: Notify::new(),
            shutdown: AtomicBool::new(false),
            last_persist: std::sync::RwLock::new(None),
        })
    }

    /// Load state from disk if exists
    pub async fn load_from_disk(self: &Arc<Self>) -> anyhow::Result<()> {
        let path = self.config.state_file_path();

        if path.exists() {
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

            for platform in snapshot.platforms {
                self.platform_key_index
                    .insert(platform.api_key_hash.clone(), platform.id.clone());
                self.platforms.insert(platform.id.clone(), platform);
            }

            self.total_messages
                .store(snapshot.total_messages, Ordering::SeqCst);

            tracing::info!(
                "Loaded state: {} identities, {} message queues, {} platforms",
                self.identities.len(),
                self.messages.len(),
                self.platforms.len()
            );
        } else {
            tracing::info!("No existing state file, starting fresh");
        }

        // Load action log
        let action_log_path = self.config.action_log_path();
        if let Err(e) = self.action_log.load_from_file(&action_log_path).await {
            tracing::warn!("Failed to load action log: {}", e);
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
                // Check for shutdown
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

    /// Signal shutdown - triggers final persistence
    pub fn signal_shutdown(&self) {
        tracing::info!("Shutdown signaled");
        self.shutdown.store(true, Ordering::SeqCst);
        self.persist_notify.notify_one();
    }

    /// Check if shutdown was requested
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Save all state (identities, messages, platforms, action log)
    pub async fn save_all(&self) -> anyhow::Result<()> {
        self.save_to_disk().await?;
        self.action_log
            .save_to_file(&self.config.action_log_path())
            .await?;
        Ok(())
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
            platforms: self
                .platforms
                .iter()
                .map(|r| r.value().clone())
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
            "State persisted: {} identities, {} message queues, {} platforms",
            snapshot.identities.len(),
            snapshot.messages.len(),
            snapshot.platforms.len()
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
    ///
    /// Validates that:
    /// 1. The contract address matches our deployed contract for the specified chain
    /// 2. The chain is supported
    /// 3. The transaction exists (TODO: actual blockchain verification)
    pub fn verify_mint(
        &self,
        id: &IdentityId,
        req: VerifyMintRequest,
    ) -> ApiResult<VerifyMintResponse> {
        // Validate chain is supported
        let chain_config = self.config.get_chain_config(req.chain).ok_or_else(|| {
            ApiError::BadRequest(format!(
                "Chain {:?} is not supported. Supported chains: {:?}",
                req.chain,
                self.config.chains.keys().collect::<Vec<_>>()
            ))
        })?;

        // Validate contract address matches our deployed contract
        let contract_valid = chain_config
            .contract_address
            .eq_ignore_ascii_case(&req.contract_address);

        if !contract_valid {
            let contract_verification = ContractVerification {
                valid: false,
                version: 0,
                version_string: "unknown".into(),
                chain: req.chain,
                contract_address: req.contract_address.clone(),
                error: Some(format!(
                    "Invalid contract address. Expected: {}, got: {}",
                    chain_config.contract_address, req.contract_address
                )),
            };

            return Err(ApiError::BadRequest(format!(
                "Contract verification failed: {}",
                contract_verification.error.as_ref().unwrap()
            )));
        }

        // TODO: Implement actual blockchain verification
        // For EVM: call eth_getTransactionReceipt and verify:
        //   - Transaction exists and succeeded
        //   - Logs contain AgentMinted event
        //   - Event data matches (owner, tokenId)
        // For Solana: call getTransaction and verify:
        //   - Transaction exists and succeeded
        //   - Contains AgentMinted event
        //   - Event data matches

        // Get token_id before acquiring mutable reference
        let token_id = (self.identities.len() as u64) + 1;

        let mut identity = self
            .identities
            .get_mut(id)
            .ok_or_else(|| ApiError::NotFound("Identity not found".into()))?;

        if identity.status != IdentityStatus::Pending {
            return Err(ApiError::BadRequest(
                "Identity already verified or not pending".into(),
            ));
        }

        identity.status = IdentityStatus::Active;
        identity.wallet_address = Some(req.wallet_address);
        identity.token_id = Some(token_id);
        identity.last_active = Utc::now();

        // Build contract verification result
        let contract_verification = ContractVerification {
            valid: true,
            version: chain_config.contract_version,
            version_string: format_version(chain_config.contract_version),
            chain: req.chain,
            contract_address: chain_config.contract_address.clone(),
            error: None,
        };

        let result = VerifyMintResponse {
            identity: identity.clone(),
            token_id,
            contract: contract_verification,
        };

        drop(identity); // Release lock before mark_dirty
        self.mark_dirty();

        tracing::info!(
            "Mint verified: identity={}, chain={:?}, contract={}, version={}",
            id,
            req.chain,
            chain_config.contract_address,
            format_version(chain_config.contract_version)
        );

        Ok(result)
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
    #[serde(default)]
    platforms: Vec<Platform>,
    total_messages: u64,
    saved_at: DateTime<Utc>,
}

// ============ Platform Methods ============

impl AppState {
    /// Register a new platform
    pub fn register_platform(&self, req: RegisterPlatformRequest) -> ApiResult<RegisterPlatformResponse> {
        let name_lower = req.name.to_lowercase();

        // Check name uniqueness
        if self.platforms.iter().any(|p| p.value().name.to_lowercase() == name_lower) {
            return Err(ApiError::Conflict("Platform name already taken".into()));
        }

        let id = format!("plat_{}", &Uuid::new_v4().to_string()[..12]);
        let api_key = generate_api_key("amai_pk_");
        let api_key_hash = hash_api_key(&api_key);
        let webhook_secret = format!("whsec_{}", &Uuid::new_v4().to_string().replace("-", ""));

        let platform = Platform {
            id: id.clone(),
            name: req.name,
            description: req.description,
            api_key_hash: api_key_hash.clone(),
            webhook_url: req.webhook_url,
            webhook_secret: webhook_secret.clone(),
            allowed_actions: req.allowed_actions,
            created_at: Utc::now(),
        };

        self.platforms.insert(id.clone(), platform);
        self.platform_key_index.insert(api_key_hash, id.clone());
        self.mark_dirty();

        Ok(RegisterPlatformResponse {
            platform_id: id,
            api_key,
            webhook_secret,
        })
    }

    /// Authenticate platform by API key
    pub fn authenticate_platform(&self, api_key: &str) -> ApiResult<Platform> {
        let hash = hash_api_key(api_key);
        let id = self
            .platform_key_index
            .get(&hash)
            .map(|r| r.value().clone())
            .ok_or(ApiError::Unauthorized)?;
        let platform = self
            .platforms
            .get(&id)
            .map(|r| r.value().clone())
            .ok_or(ApiError::Unauthorized)?;
        Ok(platform)
    }

    /// Record agent action
    pub async fn record_agent_action(
        &self,
        identity_id: IdentityId,
        req: ReportActionRequest,
    ) -> ActionEntry {
        let outcome = match req.outcome {
            ActionOutcomeInput::Success => ActionOutcome::Success,
            ActionOutcomeInput::Failure => ActionOutcome::Failure,
            ActionOutcomeInput::Pending => ActionOutcome::Pending,
            ActionOutcomeInput::Disputed => ActionOutcome::Disputed,
        };

        self.mark_dirty();

        self.action_log
            .record_agent_action(
                identity_id,
                req.action_type,
                outcome,
                req.payload.unwrap_or(serde_json::Value::Null),
                req.intent,
                req.reasoning,
                req.platform_ref,
            )
            .await
    }

    /// Record platform confirmation
    pub async fn record_platform_confirmation(
        &self,
        platform: &Platform,
        req: ConfirmActionRequest,
    ) -> ApiResult<ActionEntry> {
        // Verify identity exists
        if !self.identities.contains_key(&req.identity_id) {
            return Err(ApiError::NotFound("Identity not found".into()));
        }

        // Check if platform can confirm this action type
        if !platform.allowed_actions.is_empty()
            && !platform.allowed_actions.contains(&req.action_type)
        {
            return Err(ApiError::Forbidden(format!(
                "Platform not allowed to confirm action type: {}",
                req.action_type
            )));
        }

        let outcome = match req.outcome {
            ActionOutcomeInput::Success => ActionOutcome::Success,
            ActionOutcomeInput::Failure => ActionOutcome::Failure,
            ActionOutcomeInput::Pending => ActionOutcome::Pending,
            ActionOutcomeInput::Disputed => ActionOutcome::Disputed,
        };

        self.mark_dirty();

        Ok(self
            .action_log
            .record_platform_confirmation(
                req.identity_id,
                platform.id.clone(),
                req.action_type,
                outcome,
                req.payload.unwrap_or(serde_json::Value::Null),
                req.platform_ref,
                req.timestamp,
            )
            .await)
    }

    /// Get action log entries for an identity
    pub async fn get_action_log(
        &self,
        identity_id: &IdentityId,
        limit: usize,
        offset: usize,
    ) -> Vec<ActionEntry> {
        self.action_log.get_by_identity(identity_id, limit, offset).await
    }

    /// Create oracle snapshot
    pub async fn create_oracle_snapshot(&self) -> OracleSnapshot {
        self.mark_dirty();
        self.action_log.create_snapshot().await
    }

    /// Get oracle snapshots
    pub async fn get_oracle_snapshots(&self, limit: usize) -> Vec<OracleSnapshot> {
        self.action_log.get_snapshots(limit).await
    }

    /// Inject mock data for demo purposes (only if no existing data)
    pub async fn inject_mock_data(self: &Arc<Self>) {
        // Only inject if empty
        if !self.identities.is_empty() {
            tracing::info!("State already has data, skipping mock injection");
            return;
        }

        tracing::info!("Injecting mock data for demo...");

        let mock_agents = vec![
            ("nexus-prime", "Primary orchestration agent for high-frequency trading", IdentityStatus::Active, IdentityTier::Sovereign, 94.2, Some("0x742d35Cc6634C0532925a3b844Bc9e7595f8fBa1")),
            ("sentinel-alpha", "Security monitoring and threat detection agent", IdentityStatus::Active, IdentityTier::Verified, 87.5, Some("0x8ba1f109551bD432803012645Ac136ddd64DBA72")),
            ("arbiter-v2", "Cross-chain arbitrage execution agent", IdentityStatus::Active, IdentityTier::Verified, 82.1, Some("0x2546BcD3c84621e976D8185a91A922aE77ECEc30")),
            ("yield-hunter", "DeFi yield optimization agent", IdentityStatus::Active, IdentityTier::Standard, 78.9, Some("0xbDA5747bFD65F08deb54cb465eB87D40e51B197E")),
            ("data-oracle", "Real-time market data aggregation agent", IdentityStatus::Active, IdentityTier::Standard, 75.3, Some("0xdD2FD4581271e230360230F9337D5c0430Bf44C0")),
            ("risk-guardian", "Portfolio risk assessment agent", IdentityStatus::Pending, IdentityTier::Verified, 60.0, None),
            ("liquidity-bot", "AMM liquidity provision agent", IdentityStatus::Pending, IdentityTier::Standard, 60.0, None),
            ("rebalancer-x", "Portfolio rebalancing automation agent", IdentityStatus::Pending, IdentityTier::Standard, 60.0, None),
        ];

        let now = Utc::now();

        for (i, (name, desc, status, tier, trust, wallet)) in mock_agents.iter().enumerate() {
            let id = Uuid::new_v4();
            let api_key_hash = hash_api_key(&format!("mock_key_{}", name));

            let identity = Identity {
                id,
                name: name.to_string(),
                description: Some(desc.to_string()),
                api_key_hash: api_key_hash.clone(),
                wallet_address: wallet.map(|w| w.to_string()),
                token_id: if wallet.is_some() { Some((i + 1) as u64) } else { None },
                status: status.clone(),
                tier: tier.clone(),
                trust_score: *trust,
                messages_sent: if *status == IdentityStatus::Active { (i * 12 + 5) as u64 } else { 0 },
                messages_received: if *status == IdentityStatus::Active { (i * 8 + 3) as u64 } else { 0 },
                created_at: now - ChronoDuration::days((30 - i * 3) as i64),
                last_active: now - ChronoDuration::hours((i * 2) as i64),
                metadata: serde_json::json!({
                    "capabilities": ["trading", "monitoring", "execution"],
                    "version": "1.0.0"
                }),
            };

            self.identities.insert(id, identity.clone());
            self.name_index.insert(name.to_lowercase(), id);
            self.api_key_index.insert(api_key_hash, id);
            self.messages.insert(id, Vec::new());

            // Add mock actions for active agents
            if *status == IdentityStatus::Active {
                let action_types = vec!["trade_execute", "position_update", "risk_check", "data_fetch"];
                for j in 0..5 {
                    self.action_log
                        .record_agent_action(
                            id,
                            action_types[j % action_types.len()].to_string(),
                            ActionOutcome::Success,
                            serde_json::json!({"mock": true, "seq": j}),
                            Some(format!("Automated {} operation", action_types[j % action_types.len()])),
                            None,
                            Some(format!("ref_{}_{}", name, j)),
                        )
                        .await;
                }
            }
        }

        // Register mock platform
        let platform_id = "plat_demo_trading".to_string();
        let platform_key_hash = hash_api_key("mock_platform_key");
        let platform = Platform {
            id: platform_id.clone(),
            name: "Demo Trading Platform".to_string(),
            description: Some("Mock trading platform for demonstration".to_string()),
            api_key_hash: platform_key_hash.clone(),
            webhook_url: Some("https://demo.amai.net/webhooks".to_string()),
            webhook_secret: "whsec_demo_secret_12345".to_string(),
            allowed_actions: vec!["trade_execute".to_string(), "position_update".to_string()],
            created_at: now - ChronoDuration::days(30),
        };

        self.platforms.insert(platform_id.clone(), platform);
        self.platform_key_index.insert(platform_key_hash, platform_id);

        // Set message count
        self.total_messages.store(47, std::sync::atomic::Ordering::SeqCst);

        self.mark_dirty();

        tracing::info!(
            "Mock data injected: {} agents, {} actions, 1 platform",
            self.identities.len(),
            self.action_log.len().await
        );
    }
}
