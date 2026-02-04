//! HTTP API for AMAI Identity Service

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
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
        .route("/identity/:id_or_name", get(get_identity))
        .route("/identity/:id_or_name/keys", get(get_identity_keys))
        .route("/identities", get(list_identities))
        .route("/llms.txt", get(llms_txt))
        .route("/.well-known/llms.txt", get(llms_txt))
        .route("/skill.md", get(skill_md))
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

// ============ Index Page ============

async fn index_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let stats = state.stats().await;
    let uptime = state.start_time.elapsed().as_secs();

    let uptime_str = if uptime < 60 {
        format!("{}s", uptime)
    } else if uptime < 3600 {
        format!("{}m", uptime / 60)
    } else if uptime < 86400 {
        format!("{}h", uptime / 3600)
    } else {
        format!("{}d", uptime / 86400)
    };

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AMAI Identity Service</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: system-ui, sans-serif; background: #000; color: #fff; min-height: 100vh; padding: 2rem; }}
        .container {{ max-width: 800px; margin: 0 auto; }}
        h1 {{ font-size: 2rem; letter-spacing: 0.3em; margin-bottom: 1rem; }}
        .tagline {{ color: #666; margin-bottom: 2rem; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }}
        .stat {{ background: #111; padding: 1.5rem; text-align: center; border: 1px solid #222; }}
        .stat-value {{ font-size: 2rem; font-weight: 300; }}
        .stat-label {{ color: #666; font-size: 0.8rem; margin-top: 0.5rem; text-transform: uppercase; letter-spacing: 0.1em; }}
        .links {{ display: flex; gap: 1rem; flex-wrap: wrap; }}
        a {{ color: #fff; text-decoration: none; padding: 0.75rem 1.5rem; border: 1px solid #333; }}
        a:hover {{ background: #111; }}
        .footer {{ margin-top: 3rem; color: #444; font-size: 0.8rem; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>AMAI</h1>
        <p class="tagline">Cryptographic identity for autonomous agents</p>
        <div class="stats">
            <div class="stat"><div class="stat-value">{}</div><div class="stat-label">Agents</div></div>
            <div class="stat"><div class="stat-value">{}</div><div class="stat-label">Active</div></div>
            <div class="stat"><div class="stat-value">{}</div><div class="stat-label">Soulchain Entries</div></div>
            <div class="stat"><div class="stat-value">{}</div><div class="stat-label">Uptime</div></div>
        </div>
        <div class="links">
            <a href="/skill.md">API Documentation</a>
            <a href="/llms.txt">LLMs.txt</a>
            <a href="/health">Health</a>
            <a href="/stats">Stats</a>
        </div>
        <div class="footer">AMAI Labs - Identity for Autonomous Agents</div>
    </div>
</body>
</html>"##,
        stats.total_identities, stats.active_identities, stats.total_soulchain_entries, uptime_str,
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
