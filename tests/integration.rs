mod common;

use common::{start_test_server, unique_name, TestClient};
use serde_json::{json, Value};
use serial_test::serial;

// ============ Health & Stats Tests ============

#[tokio::test]
#[serial]
async fn test_health_endpoint() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url);

    let resp = client.get("/health").await;
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    // Health returns success: true, data contains status
    assert!(body["success"].as_bool().unwrap_or(true)); // May be plain or wrapped
}

#[tokio::test]
#[serial]
async fn test_stats_endpoint() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url);

    let resp = client.get("/stats").await;
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    assert!(body["success"].as_bool().unwrap());
    assert!(body["data"]["total_identities"].is_number());
    assert!(body["data"]["active_identities"].is_number());
}

#[tokio::test]
#[serial]
async fn test_index_page() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url);

    let resp = client.get("/").await;
    assert_eq!(resp.status(), 200);

    let body = resp.text().await.unwrap();
    assert!(body.contains("AMAI Identity Service"));
}

// ============ Chain & Contract Tests ============

#[tokio::test]
#[serial]
async fn test_chains_endpoint() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url);

    let resp = client.get("/chains").await;
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    assert!(body["success"].as_bool().unwrap());
    assert!(body["data"]["supported_chains"].is_array());
    assert!(body["data"]["current_version"].is_number());
    assert!(body["data"]["current_version_string"].is_string());
}

#[tokio::test]
#[serial]
async fn test_contracts_endpoint() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url);

    let resp = client.get("/contracts").await;
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    assert!(body["success"].as_bool().unwrap());
    assert!(body["data"]["contracts"].is_object());
}

// ============ Registration Tests ============

#[tokio::test]
#[serial]
async fn test_register_identity() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url);

    let name = unique_name("testagent");
    let resp = client
        .post(
            "/register",
            &json!({
                "name": name,
                "description": "Test agent for integration tests"
            }),
        )
        .await;

    // 200 or 201 both acceptable for creation
    assert!(resp.status().is_success());

    let body: Value = resp.json().await.unwrap();
    assert!(body["success"].as_bool().unwrap());
    assert_eq!(body["data"]["identity"]["name"], name);
    assert_eq!(body["data"]["identity"]["status"], "pending");
    assert!(body["data"]["api_key"].is_string());
    assert!(body["data"]["mint_instructions"]["contract_address"].is_string());
}

#[tokio::test]
#[serial]
async fn test_register_duplicate_name() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url);

    let name = unique_name("dupagent");

    // First registration
    let resp = client
        .post("/register", &json!({ "name": name }))
        .await;
    assert!(resp.status().is_success());

    // Second registration with same name
    let resp = client
        .post("/register", &json!({ "name": name }))
        .await;
    assert_eq!(resp.status(), 409); // Conflict
}

#[tokio::test]
#[serial]
async fn test_register_invalid_name() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url);

    // Too short
    let resp = client.post("/register", &json!({ "name": "ab" })).await;
    assert_eq!(resp.status(), 400);

    // Invalid characters
    let resp = client
        .post("/register", &json!({ "name": "test@agent!" }))
        .await;
    assert_eq!(resp.status(), 400);
}

// ============ Authentication Tests ============

#[tokio::test]
#[serial]
async fn test_get_me_authenticated() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url.clone());

    // Register first
    let name = unique_name("authagent");
    let resp = client
        .post("/register", &json!({ "name": name }))
        .await;
    let body: Value = resp.json().await.unwrap();
    let api_key = body["data"]["api_key"].as_str().unwrap().to_string();

    // Get /me with API key
    let auth_client = TestClient::new(base_url).with_api_key(api_key);
    let resp = auth_client.get("/me").await;
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["data"]["name"], name);
}

#[tokio::test]
#[serial]
async fn test_get_me_unauthenticated() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url);

    let resp = client.get("/me").await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
#[serial]
async fn test_get_me_invalid_key() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url).with_api_key("invalid_key".to_string());

    let resp = client.get("/me").await;
    assert_eq!(resp.status(), 401);
}

// ============ Identity Lookup Tests ============

#[tokio::test]
#[serial]
async fn test_get_identity_by_id() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url);

    // Register
    let name = unique_name("lookupagent");
    let resp = client
        .post("/register", &json!({ "name": name }))
        .await;
    let body: Value = resp.json().await.unwrap();
    let id = body["data"]["identity"]["id"].as_str().unwrap();

    // Lookup by ID
    let resp = client.get(&format!("/identity/{}", id)).await;
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["data"]["name"], name);
}

#[tokio::test]
#[serial]
async fn test_get_identity_by_name() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url);

    // Register
    let name = unique_name("namelookup");
    client
        .post("/register", &json!({ "name": name }))
        .await;

    // Lookup by name
    let resp = client.get(&format!("/identity/{}", name)).await;
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["data"]["name"], name);
}

#[tokio::test]
#[serial]
async fn test_get_identity_not_found() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url);

    let resp = client.get("/identity/nonexistent").await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
#[serial]
async fn test_list_identities() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url);

    // Register a few identities
    for i in 0..3 {
        let name = unique_name(&format!("listagent{}", i));
        client.post("/register", &json!({ "name": name })).await;
    }

    let resp = client.get("/identities").await;
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    assert!(body["data"].is_array());
    assert!(body["data"].as_array().unwrap().len() >= 3);
}

// ============ Update Identity Tests ============

#[tokio::test]
#[serial]
async fn test_update_identity() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url.clone());

    // Register
    let name = unique_name("updateagent");
    let resp = client
        .post("/register", &json!({ "name": name }))
        .await;
    let body: Value = resp.json().await.unwrap();
    let api_key = body["data"]["api_key"].as_str().unwrap().to_string();

    // Update
    let auth_client = TestClient::new(base_url).with_api_key(api_key);
    let resp = auth_client
        .patch(
            "/me",
            &json!({
                "description": "Updated description"
            }),
        )
        .await;
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["data"]["description"], "Updated description");
}

// ============ Mint Verification Tests ============

#[tokio::test]
#[serial]
async fn test_verify_mint_valid_contract() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url.clone());

    // Register
    let name = unique_name("mintagent");
    let resp = client
        .post("/register", &json!({ "name": name }))
        .await;
    let body: Value = resp.json().await.unwrap();
    let api_key = body["data"]["api_key"].as_str().unwrap().to_string();

    // Verify mint with correct contract
    let auth_client = TestClient::new(base_url).with_api_key(api_key);
    let resp = auth_client
        .post(
            "/verify-mint",
            &json!({
                "tx_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "wallet_address": "0xabcdef1234567890abcdef1234567890abcdef12",
                "chain": "base_sepolia",
                "contract_address": "0x1234567890123456789012345678901234567890"
            }),
        )
        .await;
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    assert!(body["success"].as_bool().unwrap());
    assert_eq!(body["data"]["identity"]["status"], "active");
    assert!(body["data"]["contract"]["valid"].as_bool().unwrap());
    assert_eq!(body["data"]["contract"]["version"], 1000000);
    assert_eq!(body["data"]["contract"]["version_string"], "1.0.0");
}

#[tokio::test]
#[serial]
async fn test_verify_mint_invalid_contract() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url.clone());

    // Register
    let name = unique_name("badmintagent");
    let resp = client
        .post("/register", &json!({ "name": name }))
        .await;
    let body: Value = resp.json().await.unwrap();
    let api_key = body["data"]["api_key"].as_str().unwrap().to_string();

    // Verify mint with wrong contract address
    let auth_client = TestClient::new(base_url).with_api_key(api_key);
    let resp = auth_client
        .post(
            "/verify-mint",
            &json!({
                "tx_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "wallet_address": "0xabcdef1234567890abcdef1234567890abcdef12",
                "chain": "base_sepolia",
                "contract_address": "0x0000000000000000000000000000000000000000"
            }),
        )
        .await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
#[serial]
async fn test_verify_mint_unsupported_chain() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url.clone());

    // Register
    let name = unique_name("chainagent");
    let resp = client
        .post("/register", &json!({ "name": name }))
        .await;
    let body: Value = resp.json().await.unwrap();
    let api_key = body["data"]["api_key"].as_str().unwrap().to_string();

    // Verify mint with unsupported chain (mainnet not configured)
    let auth_client = TestClient::new(base_url).with_api_key(api_key);
    let resp = auth_client
        .post(
            "/verify-mint",
            &json!({
                "tx_hash": "0x1234",
                "wallet_address": "0xabcd",
                "chain": "base_mainnet",
                "contract_address": "0x1234"
            }),
        )
        .await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
#[serial]
async fn test_verify_mint_solana() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url.clone());

    // Register
    let name = unique_name("solanaagent");
    let resp = client
        .post("/register", &json!({ "name": name }))
        .await;
    let body: Value = resp.json().await.unwrap();
    let api_key = body["data"]["api_key"].as_str().unwrap().to_string();

    // Verify mint on Solana
    let auth_client = TestClient::new(base_url).with_api_key(api_key);
    let resp = auth_client
        .post(
            "/verify-mint",
            &json!({
                "tx_hash": "5UfDuX7WXYZiWZPNGLqvdMKJWHxqLLCYNPqrNnqVoMTLgLqYKXDWkQAhxTAv9PAq",
                "wallet_address": "DaGqKhv3Tymup8e2Z3aAmWkchAmTvE3STYEj4hCAtLGz",
                "chain": "solana_devnet",
                "contract_address": "AMAI1dentityProgramXXXXXXXXXXXXXXXXXXXXXX"
            }),
        )
        .await;
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    assert!(body["data"]["contract"]["valid"].as_bool().unwrap());
    assert_eq!(body["data"]["contract"]["chain"], "solana_devnet");
}

// ============ Messaging Tests ============

#[tokio::test]
#[serial]
async fn test_send_message() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url.clone());

    // Register sender
    let sender_name = unique_name("sender");
    let resp = client
        .post("/register", &json!({ "name": sender_name }))
        .await;
    let body: Value = resp.json().await.unwrap();
    let sender_key = body["data"]["api_key"].as_str().unwrap().to_string();

    // Verify sender (must be active to send)
    let sender_client = TestClient::new(base_url.clone()).with_api_key(sender_key.clone());
    sender_client
        .post(
            "/verify-mint",
            &json!({
                "tx_hash": "0x1234",
                "wallet_address": "0xsender",
                "chain": "base_sepolia",
                "contract_address": "0x1234567890123456789012345678901234567890"
            }),
        )
        .await;

    // Register recipient
    let recipient_name = unique_name("recipient");
    let resp = client
        .post("/register", &json!({ "name": recipient_name }))
        .await;
    let body: Value = resp.json().await.unwrap();
    let recipient_key = body["data"]["api_key"].as_str().unwrap().to_string();

    // Verify recipient
    let recipient_client = TestClient::new(base_url.clone()).with_api_key(recipient_key.clone());
    recipient_client
        .post(
            "/verify-mint",
            &json!({
                "tx_hash": "0x5678",
                "wallet_address": "0xrecipient",
                "chain": "base_sepolia",
                "contract_address": "0x1234567890123456789012345678901234567890"
            }),
        )
        .await;

    // Send message
    let resp = sender_client
        .post(
            "/messages",
            &json!({
                "to": recipient_name,
                "content": "Hello from integration test!"
            }),
        )
        .await;
    assert!(resp.status().is_success()); // 200 or 201

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["data"]["content"], "Hello from integration test!");
}

#[tokio::test]
#[serial]
async fn test_get_messages() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url.clone());

    // Register and verify recipient
    let name = unique_name("msgrecipient");
    let resp = client.post("/register", &json!({ "name": name })).await;
    let body: Value = resp.json().await.unwrap();
    let api_key = body["data"]["api_key"].as_str().unwrap().to_string();

    let auth_client = TestClient::new(base_url).with_api_key(api_key);

    // Get messages (should be empty initially)
    let resp = auth_client.get("/messages").await;
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    assert!(body["data"].is_array());
}

// ============ Action Log Tests ============

#[tokio::test]
#[serial]
async fn test_report_action() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url.clone());

    // Register and verify
    let name = unique_name("actionagent");
    let resp = client.post("/register", &json!({ "name": name })).await;
    let body: Value = resp.json().await.unwrap();
    let api_key = body["data"]["api_key"].as_str().unwrap().to_string();

    let auth_client = TestClient::new(base_url.clone()).with_api_key(api_key);
    auth_client
        .post(
            "/verify-mint",
            &json!({
                "tx_hash": "0x1234",
                "wallet_address": "0xaction",
                "chain": "base_sepolia",
                "contract_address": "0x1234567890123456789012345678901234567890"
            }),
        )
        .await;

    // Report action
    let resp = auth_client
        .post(
            "/actions/report",
            &json!({
                "action_type": "transfer",
                "outcome": "success",
                "platform_ref": "test_platform_ref_123",
                "intent": "Transfer 100 tokens",
                "reasoning": "User requested token transfer",
                "payload": {
                    "amount": 100,
                    "token": "USDC"
                }
            }),
        )
        .await;

    let status = resp.status();
    let body_text = resp.text().await.unwrap();

    // Debug output
    eprintln!("Report action: status={}, body={}", status, body_text);

    assert!(status.is_success(), "Expected success, got {} with body {}", status, body_text);
    let body: Value = serde_json::from_str(&body_text).unwrap();
    assert!(body["data"]["seq"].is_number());
}

#[tokio::test]
#[serial]
async fn test_get_action_log() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url.clone());

    // Register and verify
    let name = unique_name("logagent");
    let resp = client.post("/register", &json!({ "name": name })).await;
    let body: Value = resp.json().await.unwrap();
    let api_key = body["data"]["api_key"].as_str().unwrap().to_string();

    let auth_client = TestClient::new(base_url).with_api_key(api_key);
    auth_client
        .post(
            "/verify-mint",
            &json!({
                "tx_hash": "0x1234",
                "wallet_address": "0xlog",
                "chain": "base_sepolia",
                "contract_address": "0x1234567890123456789012345678901234567890"
            }),
        )
        .await;

    // Get action log
    let resp = auth_client.get("/actions/log").await;
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    assert!(body["data"]["entries"].is_array());
}

// ============ Documentation Endpoints ============

#[tokio::test]
#[serial]
async fn test_llms_txt() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url);

    let resp = client.get("/llms.txt").await;
    assert_eq!(resp.status(), 200);

    let body = resp.text().await.unwrap();
    assert!(body.contains("AMAI"));
}

#[tokio::test]
#[serial]
async fn test_skill_md() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url);

    let resp = client.get("/skill.md").await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
#[serial]
async fn test_integration_md() {
    let (base_url, _temp) = start_test_server().await;
    let client = TestClient::new(base_url);

    let resp = client.get("/integration.md").await;
    assert_eq!(resp.status(), 200);
}
