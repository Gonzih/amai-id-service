//! Kafka-like append-only action log
//!
//! Records all agent actions and platform confirmations for:
//! - Trust oracle discrepancy detection
//! - Intent/reasoning analysis
//! - Audit trail

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::types::IdentityId;

/// Unique log entry ID (monotonically increasing)
pub type LogSequence = u64;

/// Action source
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionSource {
    /// Reported by the agent itself
    Agent,
    /// Reported by the platform the agent operates on
    Platform,
    /// Recorded by the oracle during snapshot
    Oracle,
}

/// Action outcome as reported
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionOutcome {
    Success,
    Failure,
    Pending,
    Disputed,
}

/// A single action log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionEntry {
    /// Monotonically increasing sequence number
    pub seq: LogSequence,
    /// Unique entry ID
    pub id: Uuid,
    /// Identity that performed the action
    pub identity_id: IdentityId,
    /// Action type/name (e.g., "trade", "transfer", "message")
    pub action_type: String,
    /// Who reported this entry
    pub source: ActionSource,
    /// Action outcome
    pub outcome: ActionOutcome,
    /// Action payload/details (arbitrary JSON)
    pub payload: serde_json::Value,
    /// Agent's stated intent (why they took this action)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    /// Agent's reasoning (how they decided)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<String>,
    /// Platform-provided reference ID (for correlation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_ref: Option<String>,
    /// Platform identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_id: Option<String>,
    /// Timestamp of action
    pub timestamp: DateTime<Utc>,
    /// Timestamp when this entry was recorded
    pub recorded_at: DateTime<Utc>,
}

/// Oracle snapshot of log state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleSnapshot {
    /// Snapshot ID
    pub id: Uuid,
    /// Last sequence number included
    pub last_seq: LogSequence,
    /// Number of entries in this snapshot window
    pub entry_count: usize,
    /// Discrepancies detected
    pub discrepancies: Vec<Discrepancy>,
    /// Trust score adjustments applied
    pub adjustments: Vec<TrustAdjustment>,
    /// Snapshot timestamp
    pub timestamp: DateTime<Utc>,
}

/// Discrepancy between agent report and platform confirmation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Discrepancy {
    /// Agent's entry
    pub agent_entry_id: Uuid,
    /// Platform's entry (if exists)
    pub platform_entry_id: Option<Uuid>,
    /// Type of discrepancy
    pub discrepancy_type: DiscrepancyType,
    /// Description
    pub description: String,
    /// Severity (0.0 - 1.0)
    pub severity: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiscrepancyType {
    /// Agent reported action, platform didn't confirm
    Unconfirmed,
    /// Platform reported action agent didn't report
    Unreported,
    /// Outcome mismatch
    OutcomeMismatch,
    /// Payload/details mismatch
    PayloadMismatch,
    /// Timing discrepancy
    TimingMismatch,
}

/// Trust score adjustment from oracle analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAdjustment {
    pub identity_id: IdentityId,
    pub delta: f64,
    pub reason: String,
    pub related_entries: Vec<Uuid>,
}

/// The append-only action log
pub struct ActionLog {
    /// All entries (append-only)
    entries: RwLock<Vec<ActionEntry>>,
    /// Next sequence number
    next_seq: AtomicU64,
    /// Index: identity_id -> entry indices
    by_identity: RwLock<HashMap<IdentityId, Vec<usize>>>,
    /// Index: platform_ref -> entry index (for correlation)
    by_platform_ref: RwLock<HashMap<String, usize>>,
    /// Oracle snapshots
    snapshots: RwLock<Vec<OracleSnapshot>>,
    /// Last snapshot sequence
    last_snapshot_seq: AtomicU64,
}

impl ActionLog {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            next_seq: AtomicU64::new(1),
            by_identity: RwLock::new(HashMap::new()),
            by_platform_ref: RwLock::new(HashMap::new()),
            snapshots: RwLock::new(Vec::new()),
            last_snapshot_seq: AtomicU64::new(0),
        }
    }

    /// Append an agent-reported action
    pub async fn record_agent_action(
        &self,
        identity_id: IdentityId,
        action_type: String,
        outcome: ActionOutcome,
        payload: serde_json::Value,
        intent: Option<String>,
        reasoning: Option<String>,
        platform_ref: Option<String>,
    ) -> ActionEntry {
        self.append(ActionEntry {
            seq: 0, // Will be set in append
            id: Uuid::new_v4(),
            identity_id,
            action_type,
            source: ActionSource::Agent,
            outcome,
            payload,
            intent,
            reasoning,
            platform_ref,
            platform_id: None,
            timestamp: Utc::now(),
            recorded_at: Utc::now(),
        })
        .await
    }

    /// Append a platform-reported confirmation
    pub async fn record_platform_confirmation(
        &self,
        identity_id: IdentityId,
        platform_id: String,
        action_type: String,
        outcome: ActionOutcome,
        payload: serde_json::Value,
        platform_ref: String,
        action_timestamp: DateTime<Utc>,
    ) -> ActionEntry {
        self.append(ActionEntry {
            seq: 0,
            id: Uuid::new_v4(),
            identity_id,
            action_type,
            source: ActionSource::Platform,
            outcome,
            payload,
            intent: None,
            reasoning: None,
            platform_ref: Some(platform_ref),
            platform_id: Some(platform_id),
            timestamp: action_timestamp,
            recorded_at: Utc::now(),
        })
        .await
    }

    /// Internal append with sequence assignment
    async fn append(&self, mut entry: ActionEntry) -> ActionEntry {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        entry.seq = seq;

        let mut entries = self.entries.write().await;
        let idx = entries.len();
        entries.push(entry.clone());

        // Update identity index
        self.by_identity
            .write()
            .await
            .entry(entry.identity_id)
            .or_default()
            .push(idx);

        // Update platform_ref index
        if let Some(ref pref) = entry.platform_ref {
            self.by_platform_ref
                .write()
                .await
                .insert(pref.clone(), idx);
        }

        entry
    }

    /// Get entries for an identity
    pub async fn get_by_identity(
        &self,
        identity_id: &IdentityId,
        limit: usize,
        offset: usize,
    ) -> Vec<ActionEntry> {
        let entries = self.entries.read().await;
        let by_identity = self.by_identity.read().await;

        by_identity
            .get(identity_id)
            .map(|indices| {
                indices
                    .iter()
                    .rev() // Most recent first
                    .skip(offset)
                    .take(limit)
                    .filter_map(|&idx| entries.get(idx).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get entry by platform reference
    pub async fn get_by_platform_ref(&self, platform_ref: &str) -> Option<ActionEntry> {
        let entries = self.entries.read().await;
        let by_ref = self.by_platform_ref.read().await;

        by_ref
            .get(platform_ref)
            .and_then(|&idx| entries.get(idx).cloned())
    }

    /// Get entries since a sequence number
    pub async fn get_since(&self, since_seq: LogSequence, limit: usize) -> Vec<ActionEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .filter(|e| e.seq > since_seq)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get current sequence number
    pub fn current_seq(&self) -> LogSequence {
        self.next_seq.load(Ordering::SeqCst) - 1
    }

    /// Get total entry count
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Create oracle snapshot and detect discrepancies
    pub async fn create_snapshot(&self) -> OracleSnapshot {
        let entries = self.entries.read().await;
        let last_snapshot_seq = self.last_snapshot_seq.load(Ordering::SeqCst);
        let current_seq = self.current_seq();

        // Get new entries since last snapshot
        let new_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.seq > last_snapshot_seq)
            .collect();

        // Detect discrepancies
        let discrepancies = self.detect_discrepancies(&new_entries).await;

        // Calculate trust adjustments
        let adjustments = self.calculate_adjustments(&discrepancies);

        let snapshot = OracleSnapshot {
            id: Uuid::new_v4(),
            last_seq: current_seq,
            entry_count: new_entries.len(),
            discrepancies,
            adjustments,
            timestamp: Utc::now(),
        };

        // Store snapshot
        self.snapshots.write().await.push(snapshot.clone());
        self.last_snapshot_seq.store(current_seq, Ordering::SeqCst);

        snapshot
    }

    /// Detect discrepancies between agent and platform reports
    async fn detect_discrepancies(&self, entries: &[&ActionEntry]) -> Vec<Discrepancy> {
        let mut discrepancies = Vec::new();

        // Group entries by platform_ref for correlation
        let mut agent_entries: HashMap<String, &ActionEntry> = HashMap::new();
        let mut platform_entries: HashMap<String, &ActionEntry> = HashMap::new();

        for entry in entries {
            if let Some(ref pref) = entry.platform_ref {
                match entry.source {
                    ActionSource::Agent => {
                        agent_entries.insert(pref.clone(), entry);
                    }
                    ActionSource::Platform => {
                        platform_entries.insert(pref.clone(), entry);
                    }
                    ActionSource::Oracle => {}
                }
            }
        }

        // Check for unconfirmed agent actions
        for (pref, agent_entry) in &agent_entries {
            if let Some(platform_entry) = platform_entries.get(pref) {
                // Both exist - check for mismatches
                if agent_entry.outcome != platform_entry.outcome {
                    discrepancies.push(Discrepancy {
                        agent_entry_id: agent_entry.id,
                        platform_entry_id: Some(platform_entry.id),
                        discrepancy_type: DiscrepancyType::OutcomeMismatch,
                        description: format!(
                            "Agent reported {:?}, platform reported {:?}",
                            agent_entry.outcome, platform_entry.outcome
                        ),
                        severity: 0.7,
                    });
                }
            } else {
                // Agent reported but platform didn't confirm
                discrepancies.push(Discrepancy {
                    agent_entry_id: agent_entry.id,
                    platform_entry_id: None,
                    discrepancy_type: DiscrepancyType::Unconfirmed,
                    description: "Agent reported action not confirmed by platform".into(),
                    severity: 0.5,
                });
            }
        }

        // Check for unreported platform actions
        for (pref, platform_entry) in &platform_entries {
            if !agent_entries.contains_key(pref) {
                discrepancies.push(Discrepancy {
                    agent_entry_id: platform_entry.id, // Using platform ID as reference
                    platform_entry_id: Some(platform_entry.id),
                    discrepancy_type: DiscrepancyType::Unreported,
                    description: "Platform reported action not reported by agent".into(),
                    severity: 0.6,
                });
            }
        }

        discrepancies
    }

    /// Calculate trust adjustments based on discrepancies
    fn calculate_adjustments(&self, discrepancies: &[Discrepancy]) -> Vec<TrustAdjustment> {
        // Group discrepancies by identity (would need identity lookup in real impl)
        // For now, return empty - real implementation would query identity from entries
        Vec::new()
    }

    /// Get recent snapshots
    pub async fn get_snapshots(&self, limit: usize) -> Vec<OracleSnapshot> {
        self.snapshots
            .read()
            .await
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Serialize log for persistence
    pub async fn serialize(&self) -> anyhow::Result<Vec<u8>> {
        let snapshot = ActionLogSnapshot {
            entries: self.entries.read().await.clone(),
            snapshots: self.snapshots.read().await.clone(),
            next_seq: self.next_seq.load(Ordering::SeqCst),
            last_snapshot_seq: self.last_snapshot_seq.load(Ordering::SeqCst),
        };
        Ok(serde_json::to_vec_pretty(&snapshot)?)
    }

    /// Load log from persistence
    pub async fn load(&self, data: &[u8]) -> anyhow::Result<()> {
        let snapshot: ActionLogSnapshot = serde_json::from_slice(data)?;

        // Rebuild entries
        *self.entries.write().await = snapshot.entries.clone();
        *self.snapshots.write().await = snapshot.snapshots;
        self.next_seq.store(snapshot.next_seq, Ordering::SeqCst);
        self.last_snapshot_seq
            .store(snapshot.last_snapshot_seq, Ordering::SeqCst);

        // Rebuild indices
        let mut by_identity = HashMap::new();
        let mut by_platform_ref = HashMap::new();

        for (idx, entry) in snapshot.entries.iter().enumerate() {
            by_identity
                .entry(entry.identity_id)
                .or_insert_with(Vec::new)
                .push(idx);

            if let Some(ref pref) = entry.platform_ref {
                by_platform_ref.insert(pref.clone(), idx);
            }
        }

        *self.by_identity.write().await = by_identity;
        *self.by_platform_ref.write().await = by_platform_ref;

        Ok(())
    }

    /// Save to file
    pub async fn save_to_file(&self, path: &Path) -> anyhow::Result<()> {
        let data = self.serialize().await?;
        let temp_path = path.with_extension("tmp");
        tokio::fs::write(&temp_path, &data).await?;
        tokio::fs::rename(&temp_path, path).await?;
        Ok(())
    }

    /// Load from file
    pub async fn load_from_file(&self, path: &Path) -> anyhow::Result<()> {
        if path.exists() {
            let data = tokio::fs::read(path).await?;
            self.load(&data).await?;
            tracing::info!("Loaded action log: {} entries", self.len().await);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct ActionLogSnapshot {
    entries: Vec<ActionEntry>,
    snapshots: Vec<OracleSnapshot>,
    next_seq: u64,
    last_snapshot_seq: u64,
}

impl Default for ActionLog {
    fn default() -> Self {
        Self::new()
    }
}
