use std::sync::Arc;

use axum::http::Method;
use tokio::signal;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use id_service::config::Config;
use id_service::state::AppState;
use id_service::api;

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

    // Inject mock data if state is empty (demo mode)
    state.inject_mock_data().await;

    // Spawn persistence worker
    let persister = state.spawn_persister();

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

    // Run server with graceful shutdown
    let state_for_shutdown = Arc::clone(&state);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(state_for_shutdown))
        .await?;

    // Wait for persister to finish final save
    tracing::info!("Waiting for final persistence...");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), persister).await;

    tracing::info!("Shutdown complete");
    Ok(())
}

/// Listens for shutdown signals (SIGTERM, SIGINT)
async fn shutdown_signal(state: Arc<AppState>) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, initiating graceful shutdown");
        }
        _ = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown");
        }
    }

    // Signal the state to save everything
    state.signal_shutdown();
}
