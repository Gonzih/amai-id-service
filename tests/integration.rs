//! Integration tests for AMAI Identity Service

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::Method;
use tower_http::cors::{Any, CorsLayer};

use id_service::{api, AppState, Config};

mod helpers {
    use super::*;
    use tempfile::tempdir;

    pub async fn spawn_test_server() -> (SocketAddr, Arc<AppState>) {
        let dir = tempdir().unwrap();
        let config = Config {
            data_dir: dir.keep(),
            host: "127.0.0.1".into(),
            port: 0, // Random port
            ..Config::default()
        };

        let state = AppState::new(config);

        let cors = CorsLayer::new()
            .allow_methods([Method::GET, Method::POST])
            .allow_headers(Any)
            .allow_origin(Any);

        let app = api::create_router(Arc::clone(&state)).layer(cors);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Give server time to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        (addr, state)
    }
}

#[tokio::test]
async fn test_health_endpoint() {
    let (addr, _state) = helpers::spawn_test_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/health", addr))
        .send()
        .await
        .unwrap();

    assert!(resp.status().is_success());

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["status"], "healthy");
}

#[tokio::test]
async fn test_stats_endpoint() {
    let (addr, _state) = helpers::spawn_test_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/stats", addr))
        .send()
        .await
        .unwrap();

    assert!(resp.status().is_success());

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["total_identities"], 0);
}

#[tokio::test]
async fn test_list_identities_empty() {
    let (addr, _state) = helpers::spawn_test_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/identities", addr))
        .send()
        .await
        .unwrap();

    assert!(resp.status().is_success());

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert!(body["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_get_identity_not_found() {
    let (addr, _state) = helpers::spawn_test_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/identity/nonexistent", addr))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_index_page() {
    let (addr, _state) = helpers::spawn_test_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/", addr))
        .send()
        .await
        .unwrap();

    assert!(resp.status().is_success());

    let body = resp.text().await.unwrap();
    assert!(body.contains("AMAI"));
    assert!(body.contains("Cryptographic identity"));
}

#[tokio::test]
async fn test_llms_txt() {
    let (addr, _state) = helpers::spawn_test_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/llms.txt", addr))
        .send()
        .await
        .unwrap();

    assert!(resp.status().is_success());

    let body = resp.text().await.unwrap();
    assert!(body.contains("AMAI Identity Service"));
}

#[tokio::test]
async fn test_skill_md() {
    let (addr, _state) = helpers::spawn_test_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/skill.md", addr))
        .send()
        .await
        .unwrap();

    assert!(resp.status().is_success());

    let body = resp.text().await.unwrap();
    assert!(body.contains("API"));
}
