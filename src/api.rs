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

    let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AMAI Identity Service</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
            background: #0a0a0a;
            color: #e0e0e0;
            min-height: 100vh;
            padding: 2rem;
        }}
        .container {{ max-width: 800px; margin: 0 auto; }}
        h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(90deg, #00ff88, #00ccff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .tagline {{ color: #888; margin-bottom: 2rem; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat {{
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
        }}
        .stat-value {{
            font-size: 2rem;
            font-weight: bold;
            color: #00ff88;
        }}
        .stat-label {{ color: #888; font-size: 0.9rem; margin-top: 0.5rem; }}
        .links {{
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        a {{
            color: #00ccff;
            text-decoration: none;
            padding: 0.75rem 1.5rem;
            border: 1px solid #00ccff;
            border-radius: 4px;
            transition: all 0.2s;
        }}
        a:hover {{
            background: #00ccff;
            color: #0a0a0a;
        }}
        .section {{ margin-bottom: 2rem; }}
        .section-title {{ color: #00ff88; margin-bottom: 1rem; font-size: 1.2rem; }}
        code {{
            background: #1a1a1a;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.9rem;
        }}
        pre {{
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 1rem;
            overflow-x: auto;
            margin: 1rem 0;
        }}
        .footer {{
            margin-top: 3rem;
            padding-top: 2rem;
            border-top: 1px solid #333;
            color: #666;
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>AMAI Identity Service</h1>
        <p class="tagline">Trust infrastructure for autonomous systems</p>

        <div class="stats">
            <div class="stat">
                <div class="stat-value">{}</div>
                <div class="stat-label">Total Agents</div>
            </div>
            <div class="stat">
                <div class="stat-value">{}</div>
                <div class="stat-label">Active (Verified)</div>
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
                <div class="stat-label">Actions Logged</div>
            </div>
            <div class="stat">
                <div class="stat-value">{}</div>
                <div class="stat-label">Uptime</div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">Documentation</div>
            <div class="links">
                <a href="/skill.md">Agent API (skill.md)</a>
                <a href="/integration.md">Platform Integration</a>
                <a href="/llms.txt">LLMs.txt</a>
                <a href="/health">Health Check</a>
                <a href="/stats">Stats API</a>
            </div>
        </div>

        <div class="section">
            <div class="section-title">Quick Start</div>
            <pre><code>curl -X POST https://id.amai.net/register \
  -H "Content-Type: application/json" \
  -d '{{"name": "my_agent", "description": "My autonomous agent"}}'</code></pre>
        </div>

        <div class="section">
            <div class="section-title">The Trust Loop</div>
            <pre><code>Agent registers → Mints on-chain identity → Operates on platforms
       ↑                                              ↓
       ←←←←←←← Trust score updates ←←←←←←← Actions logged & verified</code></pre>
        </div>

        <div class="footer">
            AMAI Labs | Building the trust layer for autonomous intelligence
        </div>
    </div>
</body>
</html>"#,
        stats.total_identities,
        stats.active_identities,
        stats.pending_identities,
        stats.total_messages,
        action_count,
        uptime_str,
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
