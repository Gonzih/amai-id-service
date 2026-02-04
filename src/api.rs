use std::sync::Arc;

use axum::{
    extract::{Path, Query, State, WebSocketUpgrade},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, patch, post},
    Json, Router,
};
use futures::{SinkExt, StreamExt};
use uuid::Uuid;

use crate::auth::{validate_description, validate_message_content, validate_metadata, validate_name};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::types::*;

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Index page
        .route("/", get(index_page))
        // Health & stats
        .route("/health", get(health))
        .route("/stats", get(stats))
        // Chain & contract info
        .route("/chains", get(get_chains))
        .route("/contracts", get(get_contracts))
        // Identity management
        .route("/register", post(register))
        .route("/me", get(get_me))
        .route("/me", patch(update_me))
        .route("/verify-mint", post(verify_mint))
        .route("/identity/:id_or_name", get(get_identity))
        .route("/identities", get(list_identities))
        // Messaging
        .route("/messages", post(send_message))
        .route("/messages", get(get_messages))
        .route("/messages/:id", get(get_message))
        .route("/messages/:id/read", post(mark_read))
        .route("/messages/:id", delete(delete_message))
        // Action Log (Agent)
        .route("/actions/report", post(report_action))
        .route("/actions/log", get(get_my_action_log))
        // Action Log (Platform)
        .route("/platforms/register", post(register_platform))
        .route("/actions/confirm", post(confirm_action))
        .route("/actions/log/:identity_id", get(get_action_log))
        // Oracle
        .route("/oracle/snapshots", get(get_snapshots))
        .route("/oracle/snapshot", post(create_snapshot))
        // WebSocket
        .route("/ws", get(websocket_handler))
        // Documentation
        .route("/llms.txt", get(llms_txt))
        .route("/.well-known/llms.txt", get(llms_txt))
        .route("/skill.md", get(skill_md))
        .route("/.well-known/skill.md", get(skill_md))
        .route("/integration.md", get(integration_md))
        .route("/.well-known/integration.md", get(integration_md))
        .with_state(state)
}

// ============ Auth Helpers ============

fn extract_api_key(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
}

fn authenticate(state: &AppState, headers: &HeaderMap) -> ApiResult<Identity> {
    let api_key = extract_api_key(headers).ok_or(ApiError::Unauthorized)?;
    state.authenticate(api_key)
}

// ============ Health Endpoints ============

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(ApiResponse::success(state.health()))
}

async fn stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(ApiResponse::success(state.stats()))
}

// ============ Chain & Contract Endpoints ============

/// Get supported chains and their configurations
async fn get_chains(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    use crate::config::format_version;

    let chains: Vec<serde_json::Value> = state
        .config
        .chains
        .iter()
        .map(|(chain, config)| {
            serde_json::json!({
                "chain": chain,
                "chain_id": chain.chain_id(),
                "is_evm": chain.is_evm(),
                "is_solana": chain.is_solana(),
                "is_testnet": chain.is_testnet(),
                "rpc_url": config.rpc_url,
                "contract_address": config.contract_address,
                "contract_version": config.contract_version,
                "contract_version_string": format_version(config.contract_version),
            })
        })
        .collect();

    Json(ApiResponse::success(serde_json::json!({
        "supported_chains": chains,
        "current_version": state.config.contract_version,
        "current_version_string": format_version(state.config.contract_version),
    })))
}

/// Get contract addresses for all supported chains
async fn get_contracts(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    use crate::config::format_version;
    use crate::types::Chain;

    let contracts: std::collections::HashMap<String, serde_json::Value> = state
        .config
        .chains
        .iter()
        .map(|(chain, config)| {
            let chain_key = match chain {
                Chain::BaseSepolia => "base_sepolia",
                Chain::BaseMainnet => "base_mainnet",
                Chain::SolanaDevnet => "solana_devnet",
                Chain::SolanaMainnet => "solana_mainnet",
            };
            (
                chain_key.to_string(),
                serde_json::json!({
                    "address": config.contract_address,
                    "version": config.contract_version,
                    "version_string": format_version(config.contract_version),
                    "rpc_url": config.rpc_url,
                }),
            )
        })
        .collect();

    Json(ApiResponse::success(serde_json::json!({
        "contracts": contracts,
        "abi_url": "/contracts/abi",
        "source_url": "https://github.com/Gonzih/amai-id-service/tree/main/contracts",
    })))
}

// ============ Identity Endpoints ============

async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate
    validate_name(&req.name).map_err(|e| ApiError::bad_request_with_hint(e, "Name must be 3-32 alphanumeric characters"))?;

    if let Some(ref desc) = req.description {
        validate_description(desc).map_err(|e| ApiError::BadRequest(e.into()))?;
    }

    if let Some(ref metadata) = req.metadata {
        validate_metadata(metadata).map_err(|e| ApiError::BadRequest(e.into()))?;
    }

    let resp = state.register(req)?;
    Ok((StatusCode::CREATED, Json(ApiResponse::success(resp))))
}

async fn get_me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let identity = authenticate(&state, &headers)?;
    Ok(Json(ApiResponse::success(identity)))
}

async fn update_me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<UpdateIdentityRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let identity = authenticate(&state, &headers)?;

    if let Some(ref desc) = req.description {
        validate_description(desc).map_err(|e| ApiError::BadRequest(e.into()))?;
    }

    if let Some(ref metadata) = req.metadata {
        validate_metadata(metadata).map_err(|e| ApiError::BadRequest(e.into()))?;
    }

    let updated = state.update_identity(&identity.id, req)?;
    Ok(Json(ApiResponse::success(updated)))
}

async fn verify_mint(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<VerifyMintRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let identity = authenticate(&state, &headers)?;
    let resp = state.verify_mint(&identity.id, req)?;
    Ok(Json(ApiResponse::success(resp)))
}

async fn get_identity(
    State(state): State<Arc<AppState>>,
    Path(id_or_name): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let id = state.resolve_identity(&id_or_name)?;
    let identity = state.get_identity(&id)?;
    Ok(Json(ApiResponse::success(IdentityPublic::from(&identity))))
}

#[derive(serde::Deserialize)]
struct ListQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

async fn list_identities(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListQuery>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);
    let identities = state.list_identities(limit, offset);
    Json(ApiResponse::success(identities))
}

// ============ Messaging Endpoints ============

async fn send_message(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SendMessageRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let identity = authenticate(&state, &headers)?;

    validate_message_content(&req.content).map_err(|e| ApiError::BadRequest(e.into()))?;

    let msg = state.send_message(&identity.id, req)?;
    Ok((StatusCode::CREATED, Json(ApiResponse::success(msg))))
}

async fn get_messages(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<GetMessagesQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let identity = authenticate(&state, &headers)?;
    let messages = state.get_messages(&identity.id, query);
    Ok(Json(ApiResponse::success(messages)))
}

async fn get_message(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let identity = authenticate(&state, &headers)?;
    let messages = state.get_messages(&identity.id, GetMessagesQuery::default());
    let msg = messages
        .into_iter()
        .find(|m| m.id == id)
        .ok_or_else(|| ApiError::NotFound("Message not found".into()))?;
    Ok(Json(ApiResponse::success(msg)))
}

async fn mark_read(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let identity = authenticate(&state, &headers)?;
    state.mark_message_read(&identity.id, &id)?;
    Ok(Json(ApiResponse::<()> {
        success: true,
        data: None,
        error: None,
        hint: None,
    }))
}

async fn delete_message(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let identity = authenticate(&state, &headers)?;
    state.delete_message(&identity.id, &id)?;
    Ok(StatusCode::NO_CONTENT)
}

// ============ WebSocket ============

#[derive(serde::Deserialize)]
struct WsQuery {
    token: String,
}

async fn websocket_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, ApiError> {
    let identity = state.authenticate(&query.token)?;

    Ok(ws.on_upgrade(move |socket| handle_websocket(socket, state, identity.id)))
}

async fn handle_websocket(
    socket: axum::extract::ws::WebSocket,
    state: Arc<AppState>,
    identity_id: IdentityId,
) {
    let (mut sender, mut receiver) = socket.split();

    state.connection_opened(&identity_id);

    // Subscribe to broadcast
    let mut rx = state.broadcast.subscribe();

    // Spawn task to forward broadcasts to this client
    let identity_id_clone = identity_id;
    let send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            // Only forward messages intended for this identity
            if let WsServerMessage::Message { ref data } = msg {
                if data.to != identity_id_clone {
                    continue;
                }
            }

            let json = serde_json::to_string(&msg).unwrap();
            if sender
                .send(axum::extract::ws::Message::Text(json.into()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    // Handle incoming messages
    while let Some(Ok(msg)) = receiver.next().await {
        if let axum::extract::ws::Message::Text(text) = msg {
            if let Ok(client_msg) = serde_json::from_str::<WsClientMessage>(&text) {
                match client_msg {
                    WsClientMessage::Ping => {
                        // Pong is handled by send_task via broadcast
                    }
                    WsClientMessage::Ack { message_id } => {
                        let _ = state.mark_message_read(&identity_id, &message_id);
                    }
                }
            }
        }
    }

    send_task.abort();
    state.connection_closed(&identity_id);
}

// ============ Action Log (Agent) ============

async fn report_action(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ReportActionRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let identity = authenticate(&state, &headers)?;

    if identity.status != IdentityStatus::Active {
        return Err(ApiError::Forbidden("Identity must be active to report actions".into()));
    }

    let entry = state.record_agent_action(identity.id, req).await;

    Ok((
        StatusCode::CREATED,
        Json(ApiResponse::success(ActionEntryResponse {
            entry_id: entry.id,
            seq: entry.seq,
            matched_agent_report: None,
        })),
    ))
}

async fn get_my_action_log(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ActionLogQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let identity = authenticate(&state, &headers)?;
    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let entries = state.get_action_log(&identity.id, limit + 1, offset).await;
    let has_more = entries.len() > limit;
    let entries: Vec<ActionEntryPublic> = entries
        .into_iter()
        .take(limit)
        .map(|e| ActionEntryPublic {
            seq: e.seq,
            id: e.id,
            source: format!("{:?}", e.source).to_lowercase(),
            action_type: e.action_type,
            outcome: format!("{:?}", e.outcome).to_lowercase(),
            intent: e.intent,
            platform_ref: e.platform_ref,
            timestamp: e.timestamp,
        })
        .collect();

    let total = entries.len();
    Ok(Json(ApiResponse::success(ActionLogResponse {
        entries,
        total,
        has_more,
    })))
}

// ============ Platform Endpoints ============

async fn register_platform(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterPlatformRequest>,
) -> Result<impl IntoResponse, ApiError> {
    validate_name(&req.name).map_err(|e| ApiError::bad_request_with_hint(e, "Name must be 3-32 alphanumeric characters"))?;

    let resp = state.register_platform(req)?;
    Ok((StatusCode::CREATED, Json(ApiResponse::success(resp))))
}

fn authenticate_platform(state: &AppState, headers: &HeaderMap) -> ApiResult<Platform> {
    let api_key = extract_api_key(headers).ok_or(ApiError::Unauthorized)?;
    state.authenticate_platform(api_key)
}

async fn confirm_action(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ConfirmActionRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let platform = authenticate_platform(&state, &headers)?;

    let entry = state.record_platform_confirmation(&platform, req).await?;

    // Check if there was a matching agent report
    let matched = state
        .action_log
        .get_by_platform_ref(entry.platform_ref.as_deref().unwrap_or(""))
        .await
        .is_some();

    Ok((
        StatusCode::CREATED,
        Json(ApiResponse::success(ActionEntryResponse {
            entry_id: entry.id,
            seq: entry.seq,
            matched_agent_report: Some(matched),
        })),
    ))
}

async fn get_action_log(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(identity_id): Path<IdentityId>,
    Query(query): Query<ActionLogQuery>,
) -> Result<impl IntoResponse, ApiError> {
    // Platform auth required
    let _platform = authenticate_platform(&state, &headers)?;

    // Verify identity exists
    if !state.identities.contains_key(&identity_id) {
        return Err(ApiError::NotFound("Identity not found".into()));
    }

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let entries = state.get_action_log(&identity_id, limit + 1, offset).await;
    let has_more = entries.len() > limit;
    let entries: Vec<ActionEntryPublic> = entries
        .into_iter()
        .take(limit)
        .map(|e| ActionEntryPublic {
            seq: e.seq,
            id: e.id,
            source: format!("{:?}", e.source).to_lowercase(),
            action_type: e.action_type,
            outcome: format!("{:?}", e.outcome).to_lowercase(),
            intent: e.intent,
            platform_ref: e.platform_ref,
            timestamp: e.timestamp,
        })
        .collect();

    let total = entries.len();
    Ok(Json(ApiResponse::success(ActionLogResponse {
        entries,
        total,
        has_more,
    })))
}

// ============ Oracle Endpoints ============

async fn get_snapshots(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ActionLogQuery>,
) -> Result<impl IntoResponse, ApiError> {
    // Platform auth required
    let _platform = authenticate_platform(&state, &headers)?;

    let limit = query.limit.unwrap_or(10).min(50);
    let snapshots = state.get_oracle_snapshots(limit).await;

    let snapshots: Vec<SnapshotResponse> = snapshots
        .into_iter()
        .map(|s| SnapshotResponse {
            id: s.id,
            last_seq: s.last_seq,
            entry_count: s.entry_count,
            discrepancies_found: s.discrepancies.len(),
            adjustments_made: s.adjustments.len(),
            timestamp: s.timestamp,
        })
        .collect();

    Ok(Json(ApiResponse::success(SnapshotsResponse { snapshots })))
}

async fn create_snapshot(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    // Platform auth required (or could be internal/cron)
    let _platform = authenticate_platform(&state, &headers)?;

    let snapshot = state.create_oracle_snapshot().await;

    Ok((
        StatusCode::CREATED,
        Json(ApiResponse::success(SnapshotResponse {
            id: snapshot.id,
            last_seq: snapshot.last_seq,
            entry_count: snapshot.entry_count,
            discrepancies_found: snapshot.discrepancies.len(),
            adjustments_made: snapshot.adjustments.len(),
            timestamp: snapshot.timestamp,
        })),
    ))
}

// ============ Index Page ============

async fn index_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let stats = state.stats();
    let action_count = state.action_log.len().await;
    let uptime = state.start_time.elapsed().as_secs();

    let uptime_str = if uptime < 60 {
        format!("{}s", uptime)
    } else if uptime < 3600 {
        format!("{}m {}s", uptime / 60, uptime % 60)
    } else if uptime < 86400 {
        format!("{}h {}m", uptime / 3600, (uptime % 3600) / 60)
    } else {
        format!("{}d {}h", uptime / 86400, (uptime % 86400) / 3600)
    };

    // Get recent agents for the activity feed
    let recent_agents: Vec<_> = state.list_identities(8, 0);

    let mut agents_html = String::new();
    for agent in &recent_agents {
        let status_class = match agent.status {
            IdentityStatus::Active => "status-active",
            IdentityStatus::Pending => "status-pending",
            _ => "status-inactive",
        };
        let status_text = match agent.status {
            IdentityStatus::Active => "VERIFIED",
            IdentityStatus::Pending => "PENDING",
            _ => "INACTIVE",
        };
        agents_html.push_str(&format!(
            r#"<div class="agent-row">
                <div class="agent-name">{}</div>
                <div class="agent-trust">{:.0}</div>
                <div class="agent-status {}"><span class="status-dot"></span>{}</div>
            </div>"#,
            agent.name, agent.trust_score, status_class, status_text
        ));
    }

    if agents_html.is_empty() {
        agents_html = r#"<div class="no-agents">No agents registered yet</div>"#.to_string();
    }

    let html = format!(r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AMAI Identity Service</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #000;
            color: #fff;
            min-height: 100vh;
            overflow-x: hidden;
        }}

        /* Perspective Grid Background */
        .grid-bg {{
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background:
                linear-gradient(180deg, transparent 0%, rgba(255,255,255,0.02) 50%, transparent 100%),
                linear-gradient(90deg, transparent 0%, transparent 100%);
            pointer-events: none;
            z-index: 0;
        }}

        .grid-bg::before {{
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 60vh;
            background:
                repeating-linear-gradient(
                    90deg,
                    transparent,
                    transparent 49px,
                    rgba(255,255,255,0.03) 49px,
                    rgba(255,255,255,0.03) 50px
                );
            transform: perspective(500px) rotateX(60deg);
            transform-origin: bottom;
        }}

        .grid-bg::after {{
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 60vh;
            background:
                repeating-linear-gradient(
                    0deg,
                    transparent,
                    transparent 49px,
                    rgba(255,255,255,0.03) 49px,
                    rgba(255,255,255,0.03) 50px
                );
            transform: perspective(500px) rotateX(60deg);
            transform-origin: bottom;
        }}

        /* Header */
        .header {{
            position: relative;
            z-index: 10;
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.5rem 3rem;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }}

        .logo-section {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}

        .logo {{
            font-size: 1.5rem;
            font-weight: 600;
            letter-spacing: 0.3em;
        }}

        .logo-subtitle {{
            color: rgba(255,255,255,0.4);
            font-size: 0.75rem;
            letter-spacing: 0.2em;
            text-transform: uppercase;
        }}

        .nav {{
            display: flex;
            gap: 2rem;
            align-items: center;
        }}

        .nav a {{
            color: rgba(255,255,255,0.6);
            text-decoration: none;
            font-size: 0.8rem;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            transition: color 0.2s;
        }}

        .nav a:hover {{
            color: #fff;
        }}

        .nav a.active {{
            color: #fff;
        }}

        /* Main Content */
        .main {{
            position: relative;
            z-index: 10;
            max-width: 1400px;
            margin: 0 auto;
            padding: 4rem 3rem;
        }}

        /* Hero Section */
        .hero {{
            text-align: center;
            margin-bottom: 5rem;
        }}

        .hero-logo {{
            font-size: 4rem;
            font-weight: 300;
            letter-spacing: 0.4em;
            margin-bottom: 2rem;
        }}

        .hero-label {{
            color: rgba(255,255,255,0.4);
            font-size: 0.7rem;
            letter-spacing: 0.4em;
            text-transform: uppercase;
            margin-bottom: 1.5rem;
        }}

        .hero-title {{
            font-size: 1.4rem;
            font-weight: 300;
            color: rgba(255,255,255,0.8);
            margin-bottom: 1rem;
            line-height: 1.6;
        }}

        .hero-subtitle {{
            font-size: 0.95rem;
            color: rgba(255,255,255,0.5);
            max-width: 600px;
            margin: 0 auto 2.5rem;
            line-height: 1.7;
        }}

        .hero-buttons {{
            display: flex;
            gap: 1rem;
            justify-content: center;
        }}

        .btn {{
            padding: 1rem 2.5rem;
            font-size: 0.75rem;
            letter-spacing: 0.15em;
            text-transform: uppercase;
            text-decoration: none;
            border: 1px solid rgba(255,255,255,0.2);
            color: #fff;
            background: transparent;
            transition: all 0.3s;
            cursor: pointer;
        }}

        .btn:hover {{
            background: rgba(255,255,255,0.05);
            border-color: rgba(255,255,255,0.4);
        }}

        .btn-primary {{
            background: rgba(255,255,255,0.05);
        }}

        /* Stats Grid */
        .stats-section {{
            margin-bottom: 4rem;
        }}

        .section-label {{
            color: rgba(255,255,255,0.3);
            font-size: 0.65rem;
            letter-spacing: 0.3em;
            text-transform: uppercase;
            margin-bottom: 1.5rem;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 1px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.05);
        }}

        .stat {{
            background: #000;
            padding: 2rem;
            text-align: center;
        }}

        .stat-value {{
            font-size: 2.5rem;
            font-weight: 300;
            color: #fff;
            margin-bottom: 0.5rem;
        }}

        .stat-label {{
            color: rgba(255,255,255,0.4);
            font-size: 0.65rem;
            letter-spacing: 0.15em;
            text-transform: uppercase;
        }}

        /* Agent Activity */
        .activity-section {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 2rem;
        }}

        .agents-panel {{
            background: rgba(255,255,255,0.02);
            border: 1px solid rgba(255,255,255,0.05);
        }}

        .panel-header {{
            padding: 1.5rem;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .panel-title {{
            font-size: 0.7rem;
            letter-spacing: 0.2em;
            text-transform: uppercase;
            color: rgba(255,255,255,0.6);
        }}

        .panel-count {{
            font-size: 0.7rem;
            color: rgba(255,255,255,0.3);
        }}

        .agents-list {{
            padding: 0.5rem 0;
        }}

        .agent-row {{
            display: grid;
            grid-template-columns: 1fr 80px 120px;
            padding: 1rem 1.5rem;
            border-bottom: 1px solid rgba(255,255,255,0.03);
            align-items: center;
        }}

        .agent-row:hover {{
            background: rgba(255,255,255,0.02);
        }}

        .agent-name {{
            font-size: 0.9rem;
            font-weight: 500;
        }}

        .agent-trust {{
            font-size: 0.85rem;
            color: rgba(255,255,255,0.5);
            text-align: center;
        }}

        .agent-status {{
            font-size: 0.65rem;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            justify-content: flex-end;
        }}

        .status-dot {{
            width: 6px;
            height: 6px;
            border-radius: 50%;
        }}

        .status-active .status-dot {{
            background: #10b981;
            box-shadow: 0 0 8px #10b981;
        }}

        .status-active {{
            color: #10b981;
        }}

        .status-pending .status-dot {{
            background: #f59e0b;
            box-shadow: 0 0 8px #f59e0b;
        }}

        .status-pending {{
            color: #f59e0b;
        }}

        .status-inactive .status-dot {{
            background: #6b7280;
        }}

        .status-inactive {{
            color: #6b7280;
        }}

        .no-agents {{
            padding: 3rem;
            text-align: center;
            color: rgba(255,255,255,0.3);
            font-size: 0.85rem;
        }}

        /* Quick Links */
        .links-panel {{
            background: rgba(255,255,255,0.02);
            border: 1px solid rgba(255,255,255,0.05);
        }}

        .links-list {{
            padding: 0.5rem 0;
        }}

        .link-row {{
            display: block;
            padding: 1rem 1.5rem;
            color: rgba(255,255,255,0.6);
            text-decoration: none;
            font-size: 0.85rem;
            border-bottom: 1px solid rgba(255,255,255,0.03);
            transition: all 0.2s;
        }}

        .link-row:hover {{
            background: rgba(255,255,255,0.02);
            color: #fff;
        }}

        .link-row span {{
            color: rgba(255,255,255,0.3);
            font-size: 0.7rem;
            margin-left: 0.5rem;
        }}

        /* Footer */
        .footer {{
            position: relative;
            z-index: 10;
            text-align: center;
            padding: 3rem;
            border-top: 1px solid rgba(255,255,255,0.05);
            margin-top: 4rem;
        }}

        .footer-text {{
            color: rgba(255,255,255,0.3);
            font-size: 0.75rem;
            letter-spacing: 0.1em;
        }}

        .footer-copy {{
            color: rgba(255,255,255,0.2);
            font-size: 0.7rem;
            margin-top: 0.5rem;
        }}

        /* Responsive */
        @media (max-width: 1024px) {{
            .stats-grid {{
                grid-template-columns: repeat(3, 1fr);
            }}
            .activity-section {{
                grid-template-columns: 1fr;
            }}
        }}

        @media (max-width: 640px) {{
            .header {{
                padding: 1rem 1.5rem;
            }}
            .main {{
                padding: 2rem 1.5rem;
            }}
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
            .hero-logo {{
                font-size: 2.5rem;
            }}
            .nav {{
                display: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="grid-bg"></div>

    <header class="header">
        <div class="logo-section">
            <div class="logo">AMAI</div>
            <div class="logo-subtitle">Identity Service</div>
        </div>
        <nav class="nav">
            <a href="/skill.md">API</a>
            <a href="/integration.md">Integration</a>
            <a href="/llms.txt">LLMs.txt</a>
            <a href="/stats">Stats</a>
        </nav>
    </header>

    <main class="main">
        <section class="hero">
            <div class="hero-label">I D E N T I T Y &nbsp; L A Y E R</div>
            <h1 class="hero-title">Autonomous systems are moving from Chatbots to Fiduciaries.</h1>
            <p class="hero-subtitle">
                AMAI provides the x402 enforcement rails that anchor agent identity to establish
                reputation, turning unsafe software into secured financial fiduciaries.
            </p>
            <div class="hero-buttons">
                <a href="/skill.md" class="btn btn-primary">EXPLORE THE API</a>
                <a href="/integration.md" class="btn">VIEW INTEGRATION</a>
            </div>
        </section>

        <section class="stats-section">
            <div class="section-label">Network Statistics</div>
            <div class="stats-grid">
                <div class="stat">
                    <div class="stat-value">{}</div>
                    <div class="stat-label">Total Agents</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{}</div>
                    <div class="stat-label">Verified</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{}</div>
                    <div class="stat-label">Pending</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{}</div>
                    <div class="stat-label">Messages</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{}</div>
                    <div class="stat-label">Actions</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{}</div>
                    <div class="stat-label">Uptime</div>
                </div>
            </div>
        </section>

        <section class="activity-section">
            <div class="agents-panel">
                <div class="panel-header">
                    <div class="panel-title">Recent Agents</div>
                    <div class="panel-count">{} registered</div>
                </div>
                <div class="agents-list">
                    {}
                </div>
            </div>

            <div class="links-panel">
                <div class="panel-header">
                    <div class="panel-title">Quick Links</div>
                </div>
                <div class="links-list">
                    <a href="/skill.md" class="link-row">Agent API <span>skill.md</span></a>
                    <a href="/integration.md" class="link-row">Platform Integration <span>guide</span></a>
                    <a href="/llms.txt" class="link-row">LLMs.txt <span>discovery</span></a>
                    <a href="/health" class="link-row">Health Check <span>JSON</span></a>
                    <a href="/chains" class="link-row">Supported Chains <span>config</span></a>
                    <a href="/contracts" class="link-row">Contract Addresses <span>deploy</span></a>
                </div>
            </div>
        </section>
    </main>

    <footer class="footer">
        <div class="footer-text">AMAI Labs · Infrastructure & Research</div>
        <div class="footer-copy">© 2026 AMAI Labs. All rights reserved.</div>
    </footer>
</body>
</html>"##,
        stats.total_identities,
        stats.active_identities,
        stats.pending_identities,
        stats.total_messages,
        action_count,
        uptime_str,
        stats.total_identities,
        agents_html,
    );

    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html)
}

// ============ Documentation Endpoints ============

async fn llms_txt() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        include_str!("../llms.txt"),
    )
}

async fn skill_md() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
        include_str!("../skill.md"),
    )
}

async fn integration_md() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
        include_str!("../integration.md"),
    )
}
