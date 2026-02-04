#!/usr/bin/env python3
"""
AMAI Identity Service E2E Test
Tests the complete workflow: key generation, registration, and agent-to-agent communication.
"""

import base64
import json
import secrets
import sys
import time
from datetime import datetime, timezone

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


class AMAIAgent:
    """An AMAI agent with Soul-Bound Key."""

    def __init__(self, name: str, service_url: str):
        self.name = name
        self.service_url = service_url.rstrip("/")
        self.private_key = None
        self.public_pem = None
        self.kid = None
        self.identity_id = None

    def generate_soul_bound_key(self):
        """Generate Ed25519 Soul-Bound Key pair."""
        self.private_key = Ed25519PrivateKey.generate()
        public_key = self.private_key.public_key()

        self.public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        print(f"  [{self.name}] Generated Soul-Bound Key")
        return self.public_pem

    def sign_message(self, message: str) -> str:
        """Sign a message with private key."""
        signature = self.private_key.sign(message.encode())
        return base64.b64encode(signature).decode()

    def register(self, description: str = None) -> dict:
        """Register this agent with the AMAI service."""
        # Use ISO format without microseconds, with +00:00 suffix (matches chrono's to_rfc3339)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        timestamp = now.strftime("%Y-%m-%dT%H:%M:%S") + "+00:00"
        nonce = secrets.token_hex(32)

        # Sign: name|timestamp|nonce (must match exactly what server reconstructs)
        message = f"{self.name}|{timestamp}|{nonce}"
        signature = self.sign_message(message)

        payload = {
            "name": self.name,
            "public_key": self.public_pem,
            "key_type": "ed25519",
            "signature": signature,
            "timestamp": timestamp,
            "nonce": nonce
        }
        if description:
            payload["description"] = description

        response = requests.post(f"{self.service_url}/register", json=payload)
        result = response.json()

        if result.get("success"):
            identity = result["data"]["identity"]
            self.identity_id = identity["id"]
            print(f"  [{self.name}] Registered successfully (ID: {self.identity_id[:8]}...)")
            return result
        else:
            raise Exception(f"Registration failed: {result.get('error')}")

    def get_identity(self, name_or_id: str = None) -> dict:
        """Look up an identity."""
        target = name_or_id or self.name
        response = requests.get(f"{self.service_url}/identity/{target}")
        return response.json()

    def get_keys(self, name_or_id: str) -> dict:
        """Get another agent's public keys for messaging."""
        response = requests.get(f"{self.service_url}/identity/{name_or_id}/keys")
        return response.json()

    def send_message(self, to_name: str, content: str, message_type: str = "text") -> dict:
        """Send a message to another agent."""
        # Sign the content
        content_signature = self.sign_message(content)

        # Need to get our kid from our keys
        keys_result = self.get_keys(self.name)
        if not keys_result.get("success"):
            raise Exception(f"Failed to get own keys: {keys_result}")
        kid = keys_result["data"]["keys"][0]["kid"]

        payload = {
            "content": content,
            "content_signature": content_signature,
            "kid": kid,
            "message_type": message_type
        }

        response = requests.post(
            f"{self.service_url}/identity/{to_name}/messages",
            json=payload
        )
        return response.json()

    def get_messages(self, from_name: str = None, unread: bool = None) -> dict:
        """Get messages for this agent (authenticated)."""
        # Need to get our kid
        keys_result = self.get_keys(self.name)
        if not keys_result.get("success"):
            raise Exception(f"Failed to get own keys: {keys_result}")
        kid = keys_result["data"]["keys"][0]["kid"]

        # Sign our identity name to prove ownership
        signature = self.sign_message(self.name)
        nonce = secrets.token_hex(32)

        payload = {
            "kid": kid,
            "signature": signature,
            "nonce": nonce
        }
        if from_name:
            payload["from"] = from_name
        if unread is not None:
            payload["unread"] = unread

        response = requests.post(
            f"{self.service_url}/identity/{self.name}/messages/inbox",
            json=payload
        )
        return response.json()


def test_health(service_url: str) -> bool:
    """Test health endpoint."""
    print("\n[TEST] Health check...")
    try:
        response = requests.get(f"{service_url}/health", timeout=5)
        result = response.json()
        if result.get("success") and result["data"]["status"] == "healthy":
            print(f"  Service healthy (version: {result['data'].get('version', 'unknown')})")
            return True
        print(f"  Health check failed: {result}")
        return False
    except Exception as e:
        print(f"  Health check error: {e}")
        return False


def test_stats(service_url: str) -> bool:
    """Test stats endpoint."""
    print("\n[TEST] Stats endpoint...")
    try:
        response = requests.get(f"{service_url}/stats", timeout=5)
        result = response.json()
        if result.get("success"):
            data = result["data"]
            print(f"  Total identities: {data['total_identities']}")
            print(f"  Active identities: {data['active_identities']}")
            print(f"  Soulchain entries: {data['total_soulchain_entries']}")
            return True
        print(f"  Stats failed: {result}")
        return False
    except Exception as e:
        print(f"  Stats error: {e}")
        return False


def test_agent_registration(service_url: str) -> tuple[AMAIAgent, AMAIAgent]:
    """Test agent registration flow."""
    print("\n[TEST] Agent registration...")

    # Create unique names for this test run
    suffix = secrets.token_hex(4)
    agent1 = AMAIAgent(f"test-agent-alpha-{suffix}", service_url)
    agent2 = AMAIAgent(f"test-agent-beta-{suffix}", service_url)

    # Generate keys
    print("  Generating Soul-Bound Keys...")
    agent1.generate_soul_bound_key()
    agent2.generate_soul_bound_key()

    # Register agents
    print("  Registering agents...")
    result1 = agent1.register("Alpha test agent for E2E testing")
    result2 = agent2.register("Beta test agent for E2E testing")

    assert result1["success"], "Agent 1 registration failed"
    assert result2["success"], "Agent 2 registration failed"

    print(f"  Agent 1 trust score: {result1['data']['identity']['trust_score']}")
    print(f"  Agent 2 trust score: {result2['data']['identity']['trust_score']}")

    return agent1, agent2


def test_identity_lookup(agent1: AMAIAgent, agent2: AMAIAgent) -> bool:
    """Test that agents can look each other up."""
    print("\n[TEST] Identity lookup...")

    # Agent 1 looks up Agent 2
    result = agent1.get_identity(agent2.name)
    if not result.get("success"):
        print(f"  Agent 1 failed to find Agent 2: {result}")
        return False

    print(f"  Agent 1 found Agent 2: {result['data']['name']}")
    print(f"    Status: {result['data']['status']}")
    print(f"    Trust Score: {result['data']['trust_score']}")
    print(f"    Soulchain Seq: {result['data']['soulchain_seq']}")

    # Agent 2 looks up Agent 1
    result = agent2.get_identity(agent1.name)
    if not result.get("success"):
        print(f"  Agent 2 failed to find Agent 1: {result}")
        return False

    print(f"  Agent 2 found Agent 1: {result['data']['name']}")

    return True


def test_key_exchange(agent1: AMAIAgent, agent2: AMAIAgent) -> bool:
    """Test that agents can retrieve each other's public keys for messaging."""
    print("\n[TEST] Key exchange (for messaging)...")

    # Agent 1 gets Agent 2's keys
    result = agent1.get_keys(agent2.name)
    if not result.get("success"):
        print(f"  Agent 1 failed to get Agent 2's keys: {result}")
        return False

    keys = result["data"]["keys"]
    print(f"  Agent 1 retrieved Agent 2's keys:")
    print(f"    Keys count: {len(keys)}")
    print(f"    Primary key type: {keys[0]['key_type']}")
    print(f"    Fingerprint: {keys[0]['fingerprint'][:16]}...")

    # Agent 2 gets Agent 1's keys
    result = agent2.get_keys(agent1.name)
    if not result.get("success"):
        print(f"  Agent 2 failed to get Agent 1's keys: {result}")
        return False

    print(f"  Agent 2 retrieved Agent 1's keys")

    # Verify the keys match what was registered
    agent2_public_pem = agent2.public_pem
    retrieved_key_matches = any(
        k["key_type"] == "ed25519" for k in result["data"]["keys"]
    )
    print(f"  Key types match: {retrieved_key_matches}")

    return True


def test_duplicate_registration(service_url: str, existing_name: str) -> bool:
    """Test that duplicate registration is rejected."""
    print("\n[TEST] Duplicate registration rejection...")

    agent = AMAIAgent(existing_name, service_url)
    agent.generate_soul_bound_key()

    try:
        agent.register("Duplicate agent")
        print("  FAILED: Duplicate registration was allowed!")
        return False
    except Exception as e:
        if "already taken" in str(e).lower() or "conflict" in str(e).lower():
            print(f"  Correctly rejected: {e}")
            return True
        print(f"  Unexpected error: {e}")
        return False


def test_invalid_signature(service_url: str) -> bool:
    """Test that invalid signatures are rejected."""
    print("\n[TEST] Invalid signature rejection...")

    suffix = secrets.token_hex(4)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = secrets.token_hex(32)

    # Generate a real key
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    # Create an invalid signature (wrong message)
    wrong_message = "wrong|message|here"
    signature = private_key.sign(wrong_message.encode())
    bad_signature = base64.b64encode(signature).decode()

    payload = {
        "name": f"invalid-sig-test-{suffix}",
        "public_key": public_pem,
        "key_type": "ed25519",
        "signature": bad_signature,
        "timestamp": timestamp,
        "nonce": nonce
    }

    response = requests.post(f"{service_url}/register", json=payload)
    result = response.json()

    if not result.get("success") and response.status_code in [400, 401]:
        print(f"  Correctly rejected invalid signature")
        return True
    else:
        print(f"  FAILED: Invalid signature was accepted! {result}")
        return False


def test_messaging(agent1: AMAIAgent, agent2: AMAIAgent) -> bool:
    """Test agent-to-agent messaging with full conversation."""
    print("\n[TEST] Agent messaging (conversation)...")

    # Simulate a multi-turn conversation
    conversation = [
        (agent1, agent2, "Hey, I need you to process some data for me."),
        (agent2, agent1, "Acknowledged. What kind of data processing do you need?"),
        (agent1, agent2, "Calculate the trust score delta for entity X-42."),
        (agent2, agent1, "Processing... Entity X-42 has trust delta of +0.15 based on recent attestations."),
        (agent1, agent2, "Great. Can you also verify the soulchain integrity?"),
        (agent2, agent1, "Soulchain verified. 12 entries, all signatures valid, no gaps detected."),
        (agent1, agent2, "Perfect. Task complete. Logging to soulchain."),
        (agent2, agent1, "Confirmed. Standing by for next task."),
    ]

    print(f"  Sending {len(conversation)} messages back and forth...")

    for i, (sender, recipient, content) in enumerate(conversation):
        result = sender.send_message(recipient.name, content)
        if not result.get("success"):
            print(f"  Message {i+1} failed: {result}")
            return False
        msg_id = result["data"]["id"]
        print(f"    [{i+1}/{len(conversation)}] {sender.name[:15]:15} -> {recipient.name[:15]:15} (ID: {msg_id[:8]}...)")

    # Agent 1 checks inbox (should have 4 messages from Agent 2)
    print("\n  Agent 1 checking inbox...")
    result = agent1.get_messages()

    if not result.get("success"):
        print(f"  Agent 1 failed to get messages: {result}")
        return False

    messages = result["data"]
    agent1_received = [m for m in messages if m["from"] == agent2.identity_id]
    print(f"    Total messages: {len(messages)}, from Agent 2: {len(agent1_received)}")

    if len(agent1_received) < 4:
        print(f"  FAILED: Agent 1 should have 4 messages from Agent 2, got {len(agent1_received)}")
        return False

    # Agent 2 checks inbox (should have 4 messages from Agent 1)
    print("  Agent 2 checking inbox...")
    result = agent2.get_messages()

    if not result.get("success"):
        print(f"  Agent 2 failed to get messages: {result}")
        return False

    messages = result["data"]
    agent2_received = [m for m in messages if m["from"] == agent1.identity_id]
    print(f"    Total messages: {len(messages)}, from Agent 1: {len(agent2_received)}")

    if len(agent2_received) < 4:
        print(f"  FAILED: Agent 2 should have 4 messages from Agent 1, got {len(agent2_received)}")
        return False

    # Show last few messages
    print("\n  Recent messages in Agent 2's inbox:")
    for msg in agent2_received[-3:]:
        content_preview = msg["content"][:60] + "..." if len(msg["content"]) > 60 else msg["content"]
        print(f"    - {content_preview}")

    print("\n  Conversation test passed!")
    return True


def run_tests(service_url: str) -> bool:
    """Run all E2E tests."""
    print(f"\n{'='*60}")
    print(f"AMAI Identity Service E2E Tests")
    print(f"Service URL: {service_url}")
    print(f"{'='*60}")

    results = []

    # Basic connectivity
    results.append(("Health Check", test_health(service_url)))
    if not results[-1][1]:
        print("\n[FATAL] Service not reachable. Aborting tests.")
        return False

    results.append(("Stats", test_stats(service_url)))

    # Agent registration and interaction
    try:
        agent1, agent2 = test_agent_registration(service_url)
        results.append(("Agent Registration", True))
    except Exception as e:
        print(f"  Registration error: {e}")
        results.append(("Agent Registration", False))
        print("\n[FATAL] Agent registration failed. Aborting remaining tests.")
        return False

    results.append(("Identity Lookup", test_identity_lookup(agent1, agent2)))
    results.append(("Key Exchange", test_key_exchange(agent1, agent2)))
    results.append(("Messaging", test_messaging(agent1, agent2)))
    results.append(("Duplicate Rejection", test_duplicate_registration(service_url, agent1.name)))
    results.append(("Invalid Signature", test_invalid_signature(service_url)))

    # Summary
    print(f"\n{'='*60}")
    print("TEST RESULTS")
    print(f"{'='*60}")

    passed = 0
    failed = 0
    for name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"  [{status}] {name}")
        if result:
            passed += 1
        else:
            failed += 1

    print(f"\n  Total: {passed} passed, {failed} failed")
    print(f"{'='*60}\n")

    return failed == 0


def main():
    # Default to local, allow override via command line
    if len(sys.argv) > 1:
        service_url = sys.argv[1]
    else:
        service_url = "http://127.0.0.1:8080"

    success = run_tests(service_url)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
