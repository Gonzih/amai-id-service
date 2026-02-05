//! Integration tests for AMAI Identity Service

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::Method;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
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

    /// Test agent with Soul-Bound Key
    pub struct TestAgent {
        pub name: String,
        pub signing_key: SigningKey,
        pub identity_id: Option<String>,
        pub kid: Option<String>,
    }

    impl TestAgent {
        pub fn new(name: &str) -> Self {
            let signing_key = SigningKey::generate(&mut OsRng);
            Self {
                name: name.to_string(),
                signing_key,
                identity_id: None,
                kid: None,
            }
        }

        pub fn public_key_pem(&self) -> String {
            let public_key = self.signing_key.verifying_key();
            let public_bytes = public_key.to_bytes();
            // Simple PEM format for Ed25519 public key
            let b64 = base64::engine::general_purpose::STANDARD.encode(public_bytes);
            format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
                b64
            )
        }

        pub fn sign(&self, message: &[u8]) -> String {
            let signature = self.signing_key.sign(message);
            base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
        }

        pub async fn register(&mut self, client: &reqwest::Client, base_url: &str) -> serde_json::Value {
            let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%S+00:00").to_string();
            let nonce = format!("{:064x}", rand::random::<u128>());

            let message = format!("{}|{}|{}", self.name, timestamp, nonce);
            let signature = self.sign(message.as_bytes());

            let payload = serde_json::json!({
                "name": self.name,
                "public_key": self.public_key_pem(),
                "key_type": "ed25519",
                "signature": signature,
                "timestamp": timestamp,
                "nonce": nonce
            });

            let resp = client
                .post(format!("{}/register", base_url))
                .json(&payload)
                .send()
                .await
                .unwrap();

            let body: serde_json::Value = resp.json().await.unwrap();

            if body["success"].as_bool().unwrap_or(false) {
                self.identity_id = body["data"]["identity"]["id"].as_str().map(String::from);
            }

            body
        }

        pub async fn get_keys(&mut self, client: &reqwest::Client, base_url: &str) -> serde_json::Value {
            let resp = client
                .get(format!("{}/identity/{}/keys", base_url, self.name))
                .send()
                .await
                .unwrap();

            let body: serde_json::Value = resp.json().await.unwrap();

            if body["success"].as_bool().unwrap_or(false) {
                self.kid = body["data"]["keys"][0]["kid"].as_str().map(String::from);
            }

            body
        }

        pub async fn send_message(
            &self,
            client: &reqwest::Client,
            base_url: &str,
            to_name: &str,
            content: &str,
        ) -> serde_json::Value {
            let content_signature = self.sign(content.as_bytes());

            let payload = serde_json::json!({
                "content": content,
                "content_signature": content_signature,
                "kid": self.kid.as_ref().unwrap(),
                "message_type": "text"
            });

            let resp = client
                .post(format!("{}/identity/{}/messages", base_url, to_name))
                .json(&payload)
                .send()
                .await
                .unwrap();

            resp.json().await.unwrap()
        }

        pub async fn get_messages(&self, client: &reqwest::Client, base_url: &str) -> serde_json::Value {
            let signature = self.sign(self.name.as_bytes());
            let nonce = format!("{:064x}", rand::random::<u128>());

            let payload = serde_json::json!({
                "kid": self.kid.as_ref().unwrap(),
                "signature": signature,
                "nonce": nonce
            });

            let resp = client
                .post(format!("{}/identity/{}/messages/inbox", base_url, self.name))
                .json(&payload)
                .send()
                .await
                .unwrap();

            resp.json().await.unwrap()
        }
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

// ============ E2E Tests: Registration ============

#[tokio::test]
async fn test_agent_registration() {
    let (addr, _state) = helpers::spawn_test_server().await;
    let base_url = format!("http://{}", addr);
    let client = reqwest::Client::new();

    let mut agent = helpers::TestAgent::new("test_agent_alpha");
    let result = agent.register(&client, &base_url).await;

    assert_eq!(result["success"], true);
    assert!(agent.identity_id.is_some());
    assert_eq!(result["data"]["identity"]["name"], "test_agent_alpha");
    assert_eq!(result["data"]["identity"]["status"], "active");
}

#[tokio::test]
async fn test_duplicate_registration_rejected() {
    let (addr, _state) = helpers::spawn_test_server().await;
    let base_url = format!("http://{}", addr);
    let client = reqwest::Client::new();

    // First registration should succeed
    let mut agent1 = helpers::TestAgent::new("duplicate_test");
    let result1 = agent1.register(&client, &base_url).await;
    assert_eq!(result1["success"], true);

    // Second registration with same name should fail
    let mut agent2 = helpers::TestAgent::new("duplicate_test");
    let result2 = agent2.register(&client, &base_url).await;
    assert_eq!(result2["success"], false);
}

#[tokio::test]
async fn test_identity_lookup() {
    let (addr, _state) = helpers::spawn_test_server().await;
    let base_url = format!("http://{}", addr);
    let client = reqwest::Client::new();

    let mut agent = helpers::TestAgent::new("lookup_test");
    agent.register(&client, &base_url).await;

    // Lookup by name
    let resp = client
        .get(format!("{}/identity/lookup_test", base_url))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["name"], "lookup_test");
}

#[tokio::test]
async fn test_key_exchange() {
    let (addr, _state) = helpers::spawn_test_server().await;
    let base_url = format!("http://{}", addr);
    let client = reqwest::Client::new();

    let mut agent = helpers::TestAgent::new("key_test");
    agent.register(&client, &base_url).await;

    let keys = agent.get_keys(&client, &base_url).await;
    assert_eq!(keys["success"], true);
    assert!(agent.kid.is_some());
    assert_eq!(keys["data"]["keys"][0]["key_type"], "ed25519");
}

// ============ E2E Tests: Messaging ============

#[tokio::test]
async fn test_agent_messaging_basic() {
    let (addr, _state) = helpers::spawn_test_server().await;
    let base_url = format!("http://{}", addr);
    let client = reqwest::Client::new();

    // Create two agents
    let mut alice = helpers::TestAgent::new("alice_msg");
    let mut bob = helpers::TestAgent::new("bob_msg");

    alice.register(&client, &base_url).await;
    bob.register(&client, &base_url).await;

    alice.get_keys(&client, &base_url).await;
    bob.get_keys(&client, &base_url).await;

    // Alice sends message to Bob
    let result = alice
        .send_message(&client, &base_url, "bob_msg", "Hello Bob!")
        .await;
    assert_eq!(result["success"], true);

    // Bob checks inbox
    let inbox = bob.get_messages(&client, &base_url).await;
    assert_eq!(inbox["success"], true);
    let messages = inbox["data"].as_array().unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["content"], "Hello Bob!");
}

#[tokio::test]
async fn test_agent_messaging_conversation() {
    let (addr, _state) = helpers::spawn_test_server().await;
    let base_url = format!("http://{}", addr);
    let client = reqwest::Client::new();

    // Create two agents
    let mut agent_a = helpers::TestAgent::new("conv_agent_a");
    let mut agent_b = helpers::TestAgent::new("conv_agent_b");

    agent_a.register(&client, &base_url).await;
    agent_b.register(&client, &base_url).await;

    agent_a.get_keys(&client, &base_url).await;
    agent_b.get_keys(&client, &base_url).await;

    // Multiple messages back and forth
    let messages_to_send = [
        ("conv_agent_a", "conv_agent_b", "Hey B, starting a task"),
        ("conv_agent_b", "conv_agent_a", "Acknowledged, processing"),
        ("conv_agent_a", "conv_agent_b", "Any updates?"),
        ("conv_agent_b", "conv_agent_a", "Task complete, result: 42"),
        ("conv_agent_a", "conv_agent_b", "Thanks, verified"),
    ];

    for (from, to, content) in messages_to_send {
        let sender = if from == "conv_agent_a" { &agent_a } else { &agent_b };
        let result = sender.send_message(&client, &base_url, to, content).await;
        assert_eq!(result["success"], true, "Failed to send: {}", content);
    }

    // Agent A should have 2 messages from B
    let inbox_a = agent_a.get_messages(&client, &base_url).await;
    assert_eq!(inbox_a["success"], true);
    let msgs_a = inbox_a["data"].as_array().unwrap();
    assert_eq!(msgs_a.len(), 2);

    // Agent B should have 3 messages from A
    let inbox_b = agent_b.get_messages(&client, &base_url).await;
    assert_eq!(inbox_b["success"], true);
    let msgs_b = inbox_b["data"].as_array().unwrap();
    assert_eq!(msgs_b.len(), 3);
}

#[tokio::test]
async fn test_inbox_requires_authentication() {
    let (addr, _state) = helpers::spawn_test_server().await;
    let base_url = format!("http://{}", addr);
    let client = reqwest::Client::new();

    // Create agent
    let mut agent = helpers::TestAgent::new("auth_test");
    agent.register(&client, &base_url).await;
    agent.get_keys(&client, &base_url).await;

    // Create attacker trying to access agent's inbox
    let mut attacker = helpers::TestAgent::new("attacker");
    attacker.register(&client, &base_url).await;
    attacker.get_keys(&client, &base_url).await;

    // Attacker signs with wrong message (attacker's name instead of target's name)
    let attacker_signature = attacker.sign("auth_test".as_bytes());
    let nonce = format!("{:064x}", rand::random::<u128>());

    let payload = serde_json::json!({
        "kid": attacker.kid.as_ref().unwrap(),  // Attacker's kid
        "signature": attacker_signature,
        "nonce": nonce
    });

    let resp = client
        .post(format!("{}/identity/auth_test/messages/inbox", base_url))
        .json(&payload)
        .send()
        .await
        .unwrap();

    // Should fail - attacker's kid doesn't match auth_test identity
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_message_types() {
    let (addr, _state) = helpers::spawn_test_server().await;
    let base_url = format!("http://{}", addr);
    let client = reqwest::Client::new();

    let mut sender = helpers::TestAgent::new("type_sender");
    let mut receiver = helpers::TestAgent::new("type_receiver");

    sender.register(&client, &base_url).await;
    receiver.register(&client, &base_url).await;

    sender.get_keys(&client, &base_url).await;
    receiver.get_keys(&client, &base_url).await;

    // Send different message types
    let types = ["text", "task_request", "task_response", "attestation"];

    for msg_type in types {
        let content_signature = sender.sign(format!("test {}", msg_type).as_bytes());
        let payload = serde_json::json!({
            "content": format!("test {}", msg_type),
            "content_signature": content_signature,
            "kid": sender.kid.as_ref().unwrap(),
            "message_type": msg_type
        });

        let resp = client
            .post(format!("{}/identity/type_receiver/messages", base_url))
            .json(&payload)
            .send()
            .await
            .unwrap();

        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["success"], true, "Failed for type: {}", msg_type);
    }

    // Verify all received
    let inbox = receiver.get_messages(&client, &base_url).await;
    assert_eq!(inbox["data"].as_array().unwrap().len(), 4);
}

// ============ Verify Endpoint Tests ============

#[tokio::test]
async fn test_verify_valid_signature() {
    let (addr, _state) = helpers::spawn_test_server().await;
    let base_url = format!("http://{}", addr);
    let client = reqwest::Client::new();

    let mut agent = helpers::TestAgent::new("verify-agent");
    let reg = agent.register(&client, &base_url).await;
    assert_eq!(reg["success"], true);
    agent.get_keys(&client, &base_url).await;

    // Sign a payload and verify via /verify
    let payload_str = r#"{"action":"trade","symbol":"BTC/USDT"}"#;
    let signature = agent.sign(payload_str.as_bytes());
    let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%S+00:00").to_string();
    let nonce = format!("{:064x}", rand::random::<u128>());

    let verify_req = serde_json::json!({
        "payload": payload_str,
        "signature": signature,
        "kid": agent.kid.as_ref().unwrap(),
        "timestamp": timestamp,
        "nonce": nonce
    });

    let resp = client
        .post(format!("{}/verify", base_url))
        .json(&verify_req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["verified"], true);
    assert_eq!(body["data"]["name"], "verify-agent");
    assert_eq!(body["data"]["kid"], agent.kid.as_ref().unwrap().as_str());
    assert!(body["data"]["identity_id"].is_string());
    assert!(body["data"]["trust_score"].as_f64().unwrap() > 0.0);
}

#[tokio::test]
async fn test_verify_invalid_signature() {
    let (addr, _state) = helpers::spawn_test_server().await;
    let base_url = format!("http://{}", addr);
    let client = reqwest::Client::new();

    let mut agent = helpers::TestAgent::new("verify-bad-sig");
    agent.register(&client, &base_url).await;
    agent.get_keys(&client, &base_url).await;

    // Sign one payload but send a different one
    let wrong_sig = agent.sign(b"different payload");
    let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%S+00:00").to_string();
    let nonce = format!("{:064x}", rand::random::<u128>());

    let verify_req = serde_json::json!({
        "payload": "actual payload that was not signed",
        "signature": wrong_sig,
        "kid": agent.kid.as_ref().unwrap(),
        "timestamp": timestamp,
        "nonce": nonce
    });

    let resp = client
        .post(format!("{}/verify", base_url))
        .json(&verify_req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], false);
}

#[tokio::test]
async fn test_verify_replay_rejected() {
    let (addr, _state) = helpers::spawn_test_server().await;
    let base_url = format!("http://{}", addr);
    let client = reqwest::Client::new();

    let mut agent = helpers::TestAgent::new("verify-replay");
    agent.register(&client, &base_url).await;
    agent.get_keys(&client, &base_url).await;

    let payload_str = "test replay";
    let signature = agent.sign(payload_str.as_bytes());
    let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%S+00:00").to_string();
    let nonce = format!("{:064x}", rand::random::<u128>());

    let verify_req = serde_json::json!({
        "payload": payload_str,
        "signature": signature,
        "kid": agent.kid.as_ref().unwrap(),
        "timestamp": timestamp,
        "nonce": nonce
    });

    // First request should succeed
    let resp = client
        .post(format!("{}/verify", base_url))
        .json(&verify_req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Same nonce should be rejected (replay)
    let resp = client
        .post(format!("{}/verify", base_url))
        .json(&verify_req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}
