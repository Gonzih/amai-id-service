use std::sync::Arc;

use axum::http::Method;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod auth;
mod config;
mod error;
mod state;
mod types;

use config::Config;
use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "id_service=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env();
    tracing::info!("Starting AMAI Identity Service");
    tracing::info!("Host: {}:{}", config.host, config.port);
    tracing::info!("Data dir: {:?}", config.data_dir);
    tracing::info!("Chain ID: {}", config.chain_id);

    // Create state
    let state = AppState::new(config.clone());

    // Load existing state from disk
    if let Err(e) = state.load_from_disk().await {
        tracing::warn!("Failed to load state from disk: {}", e);
    }

    // Spawn persistence worker
    let _persister = state.spawn_persister();

    // CORS configuration
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
        .allow_headers(Any)
        .allow_origin(Any);

    // Create router
    let app = api::create_router(Arc::clone(&state))
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    // Create listener
    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Listening on {}", addr);

    // Run server
    axum::serve(listener, app).await?;

    Ok(())
}
