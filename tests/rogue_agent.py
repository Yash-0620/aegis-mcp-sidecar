import requests
import json

# --- CONFIGURATION ---
# Replace this with the actual Agent ID from your Aegis Dashboard
AGENT_ID = "FinanceTest2_live_093225d1cc4f3ab4a86e22b3d140c76c"  # <--- UPDATE THIS WITH YOUR AGENT ID

CONTROL_PLANE_URL = "https://aegis-live-node.onrender.com"
SIDECAR_URL = "http://localhost:8080/mcp"

print(f"--- 1. MINTING CRYPTOGRAPHIC TOKEN FOR {AGENT_ID} ---")
mint_res = requests.post(f"{CONTROL_PLANE_URL}/mint", json={"agent_id": AGENT_ID})

if mint_res.status_code != 200:
    print(f"Fatal Error: Could not mint token. Check Agent ID. Response: {mint_res.text}")
    exit()

aegis_token = mint_res.json().get("token")
print(f"SUCCESS: Minted Ed25519 Token: {aegis_token[:20]}...\n")

# --- THE MALICIOUS PAYLOAD ---
# We are simulating an LLM hallucinating a massive $50,000 refund
payload = {
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "stripe:refund:write",
        "arguments": {
            "amount": 5000,
            "transaction_id": "tx_malicious_999"
        }
    }
}

headers = {
    "Content-Type": "application/json",
    "X-Aegis-IBCT": aegis_token  # <--- WE ARE NOW AUTHENTICATED
}

print("--- 2. FIRING ROGUE AGENT STRIKE AT SIDECAR ---")
print("Target: Stripe Refund | Amount: $50,000")
strike_res = requests.post(SIDECAR_URL, headers=headers, json=payload)

print(f"\n--- 3. SIDECAR RESPONSE (Status: {strike_res.status_code}) ---")
try:
    print(json.dumps(strike_res.json(), indent=2))
except ValueError:
    print("[Target Server Response]:")
    print(strike_res.text[:200] + "...\n(Target server returned HTML, not JSON. Aegis successfully allowed traffic through!)")