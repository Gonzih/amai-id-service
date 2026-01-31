#!/usr/bin/env python3
"""Generate mock data for AMAI Identity Service."""

import requests
import random
import time

BASE_URL = "https://id.amai.net"

# Agent name prefixes and suffixes for variety
PREFIXES = [
    "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta",
    "neural", "quantum", "cyber", "flux", "nova", "apex", "prime", "core",
    "trade", "arb", "yield", "defi", "nft", "dao", "oracle", "bridge"
]

SUFFIXES = [
    "bot", "agent", "system", "node", "runner", "worker", "executor", "solver",
    "v1", "v2", "pro", "max", "ultra", "x", "ai", "ml"
]

DESCRIPTIONS = [
    "DeFi arbitrage bot",
    "Yield optimization agent",
    "Cross-chain bridge operator",
    "NFT trading system",
    "Liquidity provider bot",
    "Market maker agent",
    "DAO governance participant",
    "Oracle data provider",
    "MEV searcher",
    "Portfolio rebalancer",
    "Risk assessment agent",
    "Collateral manager",
    "Flash loan executor",
    "Perpetual trading bot",
    "Options market maker"
]

ACTION_TYPES = ["trade", "transfer", "stake", "unstake", "swap", "bridge", "mint", "burn", "vote", "claim"]
OUTCOMES = ["success", "success", "success", "success", "failure", "pending"]  # Weighted toward success

INTENTS = [
    "Arbitrage opportunity detected between DEX pools",
    "Rebalancing portfolio to target allocation",
    "Yield optimization across lending protocols",
    "Liquidation protection - adding collateral",
    "Taking profit on position",
    "Hedging exposure with derivatives",
    "Providing liquidity to earn fees",
    "Governance vote on protocol upgrade",
    "Claiming accumulated rewards",
    "Bridge assets for better yield"
]

REASONING = [
    "Price differential exceeds gas costs by 2x",
    "Risk-adjusted return is favorable",
    "On-chain metrics show bullish momentum",
    "TVL increasing, APY stable",
    "Volatility within acceptable range",
    "Correlation analysis suggests low risk",
    "Historical data supports this action",
    "Smart contract audit passed",
    "Liquidity depth sufficient for trade size",
    "Gas prices optimal for execution"
]


def generate_agent_name():
    return f"{random.choice(PREFIXES)}_{random.choice(SUFFIXES)}_{random.randint(100, 999)}"


def register_agent():
    name = generate_agent_name()
    description = random.choice(DESCRIPTIONS)

    resp = requests.post(f"{BASE_URL}/register", json={
        "name": name,
        "description": description,
        "metadata": {
            "version": f"{random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
            "chain": random.choice(["base", "ethereum", "arbitrum", "optimism"]),
            "created_by": "mock_generator"
        }
    })

    if resp.status_code == 201:
        data = resp.json()["data"]
        print(f"✓ Registered: {name}")
        return data["api_key"], data["identity"]["id"], name
    else:
        print(f"✗ Failed to register {name}: {resp.text}")
        return None, None, None


def verify_agent(api_key, identity_id):
    """Simulate mint verification to make agent active."""
    resp = requests.post(
        f"{BASE_URL}/verify-mint",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "tx_hash": f"0x{random.randbytes(32).hex()}",
            "wallet_address": f"0x{random.randbytes(20).hex()}"
        }
    )

    if resp.status_code == 200:
        print(f"  → Verified (active)")
        return True
    else:
        print(f"  → Verification failed: {resp.text}")
        return False


def report_action(api_key):
    """Report a random action."""
    resp = requests.post(
        f"{BASE_URL}/actions/report",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "action_type": random.choice(ACTION_TYPES),
            "outcome": random.choice(OUTCOMES),
            "platform_ref": f"ref_{random.randint(10000, 99999)}",
            "intent": random.choice(INTENTS),
            "reasoning": random.choice(REASONING),
            "payload": {
                "amount": f"{random.uniform(0.1, 100):.4f}",
                "token": random.choice(["ETH", "USDC", "AMAI", "WBTC"]),
                "gas_used": random.randint(21000, 500000)
            }
        }
    )

    if resp.status_code == 201:
        return True
    return False


def send_message(api_key, to_name):
    """Send a message to another agent."""
    messages = [
        "Quote request for 1 ETH",
        "Liquidity check",
        "Price feed update",
        "Collaboration proposal",
        "Task completion confirmation",
        "Status ping",
        "Data sync request"
    ]

    resp = requests.post(
        f"{BASE_URL}/messages",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "to": to_name,
            "content": random.choice(messages),
            "message_type": random.choice(["text", "task_request", "attestation"])
        }
    )

    return resp.status_code == 201


def main():
    print("=" * 50)
    print("AMAI Mock Data Generator")
    print("=" * 50)
    print()

    agents = []
    num_agents = 18

    # Register agents
    print(f"Registering {num_agents} agents...")
    print("-" * 30)

    for i in range(num_agents):
        api_key, identity_id, name = register_agent()
        if api_key:
            agents.append({"api_key": api_key, "id": identity_id, "name": name})
        time.sleep(0.1)  # Small delay to avoid rate limiting

    print()
    print(f"Registered {len(agents)} agents")
    print()

    # Verify some agents (make them active)
    print("Verifying agents (simulating on-chain mint)...")
    print("-" * 30)

    num_to_verify = int(len(agents) * 0.7)  # Verify ~70%
    for agent in agents[:num_to_verify]:
        verify_agent(agent["api_key"], agent["id"])
        time.sleep(0.1)

    print()
    print(f"Verified {num_to_verify} agents")
    print()

    # Report actions for verified agents
    print("Generating action logs...")
    print("-" * 30)

    action_count = 0
    for agent in agents[:num_to_verify]:
        num_actions = random.randint(5, 25)
        for _ in range(num_actions):
            if report_action(agent["api_key"]):
                action_count += 1
        print(f"  {agent['name']}: {num_actions} actions")
        time.sleep(0.1)

    print()
    print(f"Generated {action_count} action log entries")
    print()

    # Send messages between agents
    print("Generating messages...")
    print("-" * 30)

    message_count = 0
    verified_agents = agents[:num_to_verify]
    for agent in verified_agents:
        num_messages = random.randint(2, 8)
        for _ in range(num_messages):
            recipient = random.choice([a for a in verified_agents if a["name"] != agent["name"]])
            if send_message(agent["api_key"], recipient["name"]):
                message_count += 1
        time.sleep(0.1)

    print(f"Generated {message_count} messages")
    print()

    # Final stats
    print("=" * 50)
    print("Fetching final stats...")
    print("=" * 50)

    resp = requests.get(f"{BASE_URL}/stats")
    if resp.status_code == 200:
        stats = resp.json()["data"]
        print(f"""
Stats:
  Total Identities: {stats['total_identities']}
  Active:           {stats['active_identities']}
  Pending:          {stats['pending_identities']}
  Total Messages:   {stats['total_messages']}
""")

    print("Done!")


if __name__ == "__main__":
    main()
