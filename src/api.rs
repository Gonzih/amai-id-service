//! HTTP API for AMAI Identity Service

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};

use crate::error::ApiError;
use crate::state::AppState;
use crate::types::*;

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index_page))
        .route("/health", get(health))
        .route("/stats", get(stats))
        .route("/register", post(register))
        .route("/verify", post(verify_signature_endpoint))
        .route("/identity/:id_or_name", get(get_identity))
        .route("/identity/:id_or_name/keys", get(get_identity_keys))
        .route("/identity/:id_or_name/messages", post(send_message))
        .route("/identity/:id_or_name/messages/inbox", post(get_messages_auth))
        .route("/llms.txt", get(llms_txt))
        .route("/.well-known/llms.txt", get(llms_txt))
        .route("/skill.md", get(skill_md))
        .route("/assets/amai-logo.png", get(logo_png))
        .with_state(state)
}

// ============ Health Endpoints ============

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(ApiResponse::success(state.health()))
}

async fn stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(ApiResponse::success(state.stats().await))
}

// ============ Identity Endpoints ============

async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let resp = state.register(req).await?;
    Ok((StatusCode::CREATED, Json(ApiResponse::success(resp))))
}

async fn get_identity(
    State(state): State<Arc<AppState>>,
    Path(id_or_name): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let id = state.resolve_identity(&id_or_name)?;
    let identity = state.get_identity(&id)?;
    Ok(Json(ApiResponse::success(IdentityPublic::from(&identity))))
}

async fn get_identity_keys(
    State(state): State<Arc<AppState>>,
    Path(id_or_name): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let id = state.resolve_identity(&id_or_name)?;
    let identity = state.get_identity(&id)?;
    let keys = state.get_identity_keys(&id);

    Ok(Json(ApiResponse::success(KeysResponse {
        identity_id: id,
        name: identity.name,
        keys: keys.iter().map(PublicKeyInfo::from).collect(),
        soulchain_hash: identity.soulchain_hash,
        soulchain_seq: identity.soulchain_seq,
    })))
}

// ============ Verify Endpoint (Inter-Service Auth) ============

/// Request body for signature verification.
/// Other microservices call this to authenticate agents.
#[derive(serde::Deserialize)]
struct VerifyRequest {
    /// The payload that was signed (raw JSON string or any string)
    payload: String,
    /// Base64-encoded signature of the payload
    signature: String,
    /// Key ID used for signing
    kid: String,
    /// Timestamp for freshness check
    timestamp: chrono::DateTime<chrono::Utc>,
    /// Nonce for replay protection
    nonce: String,
}

/// Successful verification response
#[derive(serde::Serialize)]
struct VerifyResponse {
    verified: bool,
    identity_id: IdentityId,
    name: String,
    kid: String,
    trust_score: f64,
}

async fn verify_signature_endpoint(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // 1. Check timestamp freshness
    let now = chrono::Utc::now();
    let skew = chrono::Duration::seconds(state.config.max_clock_skew as i64);
    if req.timestamp < now - skew || req.timestamp > now + skew {
        return Err(ApiError::TimestampInvalid);
    }

    // 2. Check nonce for replay
    if !state.nonces.check_and_mark(&req.nonce) {
        return Err(ApiError::ReplayDetected);
    }

    // 3. Look up key and identity
    let key = state.get_key(&req.kid)?;
    if key.revoked {
        return Err(ApiError::signature("Key has been revoked"));
    }
    let identity = state.authenticate(&req.kid)?;

    // 4. Verify signature against payload bytes
    let parsed_key = crate::crypto::parse_public_key(&key.public_key_pem, &key.key_type)
        .map_err(|e| ApiError::signature(e.to_string()))?;
    crate::crypto::verify_signature(&parsed_key, req.payload.as_bytes(), &req.signature)
        .map_err(|e| ApiError::signature(format!("Signature verification failed: {}", e)))?;

    Ok(Json(ApiResponse::success(VerifyResponse {
        verified: true,
        identity_id: identity.id,
        name: identity.name,
        kid: req.kid,
        trust_score: identity.trust_score,
    })))
}

// ============ Messaging Endpoints ============

#[derive(serde::Deserialize)]
struct SendMessageBody {
    /// Message content
    content: String,
    /// Signature of content by sender's key
    content_signature: String,
    /// Sender's key ID
    kid: String,
    #[serde(default)]
    message_type: MessageType,
}

async fn send_message(
    State(state): State<Arc<AppState>>,
    Path(recipient): Path<String>,
    Json(body): Json<SendMessageBody>,
) -> Result<impl IntoResponse, ApiError> {
    // Authenticate sender by key ID
    let sender = state.authenticate(&body.kid)?;

    // Resolve recipient
    let recipient_id = state.resolve_identity(&recipient)?;

    // Send the message
    let message = state.send_message(
        sender.id,
        recipient_id,
        body.content,
        body.content_signature,
        body.message_type,
    )?;

    Ok((StatusCode::CREATED, Json(ApiResponse::success(message))))
}

#[derive(serde::Deserialize)]
struct GetMessagesBody {
    /// Key ID to authenticate
    kid: String,
    /// Signature of the identity name being accessed (proves ownership)
    signature: String,
    /// Nonce for replay protection
    nonce: String,
    /// Optional filters
    from: Option<String>,
    unread: Option<bool>,
    limit: Option<usize>,
    offset: Option<usize>,
}

async fn get_messages_auth(
    State(state): State<Arc<AppState>>,
    Path(id_or_name): Path<String>,
    Json(body): Json<GetMessagesBody>,
) -> Result<impl IntoResponse, ApiError> {
    // Authenticate - verify the requester owns this identity
    let identity = state.authenticate(&body.kid)?;
    let requested_id = state.resolve_identity(&id_or_name)?;

    // Must be requesting own messages
    if identity.id != requested_id {
        return Err(ApiError::Unauthorized);
    }

    // Verify nonce hasn't been used
    if !state.nonces.check_and_mark(&body.nonce) {
        return Err(ApiError::ReplayDetected);
    }

    // Verify signature of the identity name (proves they want to access this mailbox)
    let key = state.get_key(&body.kid)?;
    let parsed_key = crate::crypto::parse_public_key(&key.public_key_pem, &key.key_type)
        .map_err(|e| ApiError::signature(e.to_string()))?;
    crate::crypto::verify_signature(&parsed_key, id_or_name.as_bytes(), &body.signature)
        .map_err(|e| ApiError::signature(format!("Invalid signature: {}", e)))?;

    let from_id = if let Some(from) = body.from {
        Some(state.resolve_identity(&from)?)
    } else {
        None
    };

    let limit = body.limit.unwrap_or(50).min(100);
    let offset = body.offset.unwrap_or(0);
    let unread_only = body.unread.unwrap_or(false);

    let messages = state.get_messages(&requested_id, from_id, unread_only, limit, offset);
    Ok(Json(ApiResponse::success(messages)))
}

// ============ Index Page ============

async fn index_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let stats = state.stats().await;

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AMAI Identity Service</title>
    <meta name="description" content="Cryptographic identity for autonomous agents. Soul-Bound Keys and Soulchain reputation.">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: system-ui, -apple-system, sans-serif; background: #000; color: #fff; min-height: 100vh; display: flex; flex-direction: column; }}
        .header {{ padding: 1rem 1.5rem; border-bottom: 1px solid rgba(255,255,255,0.1); }}
        .header-content {{ max-width: 900px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; }}
        .header-left {{ font-size: 0.65rem; letter-spacing: 0.3em; text-transform: uppercase; color: rgba(255,255,255,0.4); }}
        .header-right {{ display: flex; gap: 1.5rem; }}
        .header-right a {{ font-size: 0.65rem; letter-spacing: 0.15em; text-transform: uppercase; color: rgba(255,255,255,0.6); text-decoration: none; transition: color 0.2s; }}
        .header-right a:hover {{ color: rgba(255,255,255,0.9); }}
        .main {{ flex: 1; display: flex; align-items: center; justify-content: center; padding: 2rem; }}
        .container {{ max-width: 600px; text-align: center; }}
        .logo {{ height: 3rem; width: auto; margin-bottom: 1.5rem; filter: brightness(1.1); }}
        @media (min-width: 768px) {{ .logo {{ height: 5rem; }} }}
        .subtitle {{ font-size: 0.65rem; letter-spacing: 0.3em; text-transform: uppercase; color: rgba(255,255,255,0.4); margin-bottom: 1rem; }}
        .tagline {{ color: rgba(255,255,255,0.7); font-size: 0.9rem; font-weight: 300; line-height: 1.6; margin-bottom: 0.75rem; }}
        .tagline-small {{ color: rgba(255,255,255,0.5); font-size: 0.8rem; font-weight: 300; line-height: 1.6; margin-bottom: 2.5rem; }}
        .stats {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.5rem; margin-bottom: 2.5rem; }}
        .stat {{ text-align: center; }}
        .stat-value {{ font-size: 2rem; font-weight: 300; color: #fff; }}
        .stat-label {{ font-size: 0.6rem; letter-spacing: 0.15em; text-transform: uppercase; color: rgba(255,255,255,0.4); margin-top: 0.5rem; }}
        .links {{ display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap; }}
        .links a {{ font-size: 0.75rem; color: rgba(255,255,255,0.7); text-decoration: none; padding: 0.75rem 1.5rem; border: 1px solid rgba(255,255,255,0.2); transition: all 0.2s; letter-spacing: 0.15em; text-transform: uppercase; }}
        .links a:hover {{ color: #fff; border-color: rgba(255,255,255,0.4); background: rgba(255,255,255,0.05); }}
        .footer {{ padding: 1.5rem; border-top: 1px solid rgba(255,255,255,0.1); text-align: center; }}
        .footer p {{ font-size: 0.7rem; color: rgba(255,255,255,0.3); letter-spacing: 0.1em; }}
        .footer p + p {{ margin-top: 0.25rem; font-size: 0.6rem; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="header-left">AMAI Labs · Identity Service</div>
            <div class="header-right">
                <a href="/skill.md">API</a>
                <a href="/llms.txt">LLMs.txt</a>
                <a href="/stats">Stats</a>
            </div>
        </div>
    </div>
    <div class="main">
        <div class="container">
            <div class="subtitle">Identity Infrastructure</div>
            <img src="/assets/amai-logo.png" alt="AMAI" class="logo">
            <p class="tagline">Cryptographic identity for autonomous agents.</p>
            <p class="tagline-small">Soul-Bound Keys anchor persistent identity. Soulchain builds immutable reputation.</p>
            <div class="stats">
                <div class="stat"><div class="stat-value">{}</div><div class="stat-label">Agents</div></div>
                <div class="stat"><div class="stat-value">{}</div><div class="stat-label">Active</div></div>
                <div class="stat"><div class="stat-value">{}</div><div class="stat-label">Soulchain Entries</div></div>
            </div>
            <div class="links">
                <a href="/skill.md">Explore API</a>
                <a href="https://amai.net">AMAI Labs</a>
            </div>
        </div>
    </div>
    <footer class="footer">
        <p>AMAI Labs · Infrastructure & Research</p>
        <p>&copy; 2026 AMAI Labs</p>
    </footer>
</body>
</html>"##,
        stats.total_identities, stats.active_identities, stats.total_soulchain_entries,
    );

    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html)
}

// ============ Documentation ============

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

async fn logo_png() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "image/png")],
        include_bytes!("../amai-logo.png").as_slice(),
    )
}
