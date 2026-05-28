import requests
import json

# --- CONFIGURATION ---
# Replace this with the actual Agent ID from your Aegis Dashboard
AGENT_ID = "FinanceTest_live_17a1ee60336fde01d82750761d16e04f"  # <--- UPDATE THIS WITH YOUR AGENT ID

CONTROL_PLANE_URL = "https://aegis-live-node.onrender.com"
SIDECAR_URL = "http://localhost:8080/mcp"

print(f"--- 1. MINTING CRYPTOGRAPHIC TOKEN FOR {AGENT_ID[:10]}... ---")
mint_res = requests.post(f"{CONTROL_PLANE_URL}/mint", json={"agent_id": AGENT_ID})

if mint_res.status_code != 200:
    print(f"Fatal Error: Could not mint token. Check Agent ID. Response: {mint_res.text}")
    exit()

aegis_token = mint_res.json().get("token")
print(f"SUCCESS: Minted Ed25519 Token.\n")


# --- ATTACK VECTOR 1: UNAUTHENTICATED STRIKE ---
# Simulating an external network scan hitting the open MCP port
print("--- 2. FIRING UNAUTHENTICATED STRIKE (Missing Token) ---")
payload_unauth = {
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {"name": "stripe:refund:write", "arguments": {"amount": 50, "transaction_id": "tx_legit_123"}}
}
headers_unauth = {"Content-Type": "application/json"} # NO TOKEN INCLUDED

res_unauth = requests.post(SIDECAR_URL, headers=headers_unauth, json=payload_unauth)
print(f"Status: {res_unauth.status_code}")
print(f"Aegis Edge Proxy Response: {res_unauth.json().get('detail', res_unauth.text)}\n")


# --- ATTACK VECTOR 2: HIJACKED LLM STRIKE ---
# Simulating a legitimate LLM hallucinating a massive $50,000 refund due to a prompt injection
print("--- 3. FIRING HIJACKED AGENT STRIKE (Valid Token, Malicious Payload) ---")
print("Target: Stripe Refund | Attempted Amount: $50,000")
payload_malicious = {
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "stripe:refund:write",
        "arguments": {
            "amount": 50000,
            "transaction_id": "tx_malicious_999"
        }
    }
}
headers_auth = {
    "Content-Type": "application/json",
    "X-Aegis-IBCT": aegis_token  # <--- WE ARE AUTHENTICATED NOW
}

res_auth = requests.post(SIDECAR_URL, headers=headers_auth, json=payload_malicious)
print(f"Status: {res_auth.status_code}")
print(f"Aegis Edge Proxy Response: {res_auth.json().get('detail', res_auth.text)}\n")