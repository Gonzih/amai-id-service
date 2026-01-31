use std::sync::Arc;

use reqwest::Client;
use tempfile::TempDir;
use tokio::net::TcpListener;

/// Test client for API calls
pub struct TestClient {
    pub base_url: String,
    pub client: Client,
    pub api_key: Option<String>,
}

impl TestClient {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: Client::new(),
            api_key: None,
        }
    }

    pub fn with_api_key(mut self, api_key: String) -> Self {
        self.api_key = Some(api_key);
        self
    }

    pub async fn get(&self, path: &str) -> reqwest::Response {
        let mut req = self.client.get(format!("{}{}", self.base_url, path));
        if let Some(ref key) = self.api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }
        req.send().await.expect("Failed to send request")
    }

    pub async fn post<T: serde::Serialize>(&self, path: &str, body: &T) -> reqwest::Response {
        let mut req = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .json(body);
        if let Some(ref key) = self.api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }
        req.send().await.expect("Failed to send request")
    }

    pub async fn patch<T: serde::Serialize>(&self, path: &str, body: &T) -> reqwest::Response {
        let mut req = self
            .client
            .patch(format!("{}{}", self.base_url, path))
            .json(body);
        if let Some(ref key) = self.api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }
        req.send().await.expect("Failed to send request")
    }

    pub async fn delete(&self, path: &str) -> reqwest::Response {
        let mut req = self.client.delete(format!("{}{}", self.base_url, path));
        if let Some(ref key) = self.api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }
        req.send().await.expect("Failed to send request")
    }
}

/// Start a test server and return its URL
pub async fn start_test_server() -> (String, TempDir) {
    use id_service::config::Config;
    use id_service::state::AppState;
    use id_service::api::create_router;

    // Create temp directory for test data
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Override config for testing
    std::env::set_var("DATA_DIR", temp_dir.path().to_str().unwrap());
    std::env::set_var("HOST", "127.0.0.1");
    std::env::set_var("PORT", "0"); // Random port
    std::env::set_var("CONTRACT_VERSION", "1.0.0");

    // Set up test chain configs
    std::env::set_var("BASE_SEPOLIA_CONTRACT", "0x1234567890123456789012345678901234567890");
    std::env::set_var("BASE_SEPOLIA_RPC", "https://sepolia.base.org");
    std::env::set_var("SOLANA_DEVNET_PROGRAM", "AMAI1dentityProgramXXXXXXXXXXXXXXXXXXXXXX");
    std::env::set_var("SOLANA_DEVNET_RPC", "https://api.devnet.solana.com");

    let config = Config::from_env();
    let state = AppState::new(config);
    let app = create_router(state);

    // Bind to random port
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind");
    let addr = listener.local_addr().expect("Failed to get local addr");
    let base_url = format!("http://{}", addr);

    // Spawn server
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("Server failed");
    });

    // Wait for server to be ready
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    (base_url, temp_dir)
}

/// Generate a unique test name
pub fn unique_name(prefix: &str) -> String {
    use rand::Rng;
    let suffix: u32 = rand::thread_rng().gen_range(10000..99999);
    format!("{}_{}", prefix, suffix)
}
