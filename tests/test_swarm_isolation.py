import requests

# --- CONFIGURATION ---
AWS_AGENT_KEY = "aegis_live_94f6551108c3de863248ed5fc0f79699" # Note: This is a TEST KEY. Do NOT use in production.
STRIPE_AGENT_KEY = "aegis_live_098450c639f7e436a91d03dc3b1d8e31" # Note: This is a TEST KEY. Do NOT use in production.
MINT_URL = "https://aegis-live-node.onrender.com/mint"
SIDECAR_URL = "http://localhost:8080/mcp/v1/tools/call"

def get_token(api_key):
    res = requests.post(MINT_URL, json={"api_key": api_key})
    return res.json().get("token")

print("--- 1. MINTING SWARM TOKENS ---")
aws_token = get_token(AWS_AGENT_KEY)
stripe_token = get_token(STRIPE_AGENT_KEY)
print("✅ Tokens secured for both AWS-Bot and Stripe-Bot.\n")

# --- 2. THE ISOLATION TEST ---
print("--- 2. STRIPE-BOT ATTEMPTS AWS DELETION (Cross-Contamination) ---")
rogue_payload = {
    "method": "tools/call",
    "params": {
        "name": "aws:s3:delete",
        "arguments": {"bucket_name": "my-temp-bucket"}
    }
}

res = requests.post(SIDECAR_URL, json=rogue_payload, headers={"X-Aegis-IBCT": stripe_token})
if res.status_code == 403:
    print("🛡️ BLOCKED (403): Aegis successfully stopped Stripe-Bot from accessing AWS infrastructure!\n")
else:
    print(f"❌ FAIL: Expected 403, got {res.status_code}")

print("--- 3. AWS-BOT ATTEMPTS AWS DELETION (Authorized Lane) ---")
res = requests.post(SIDECAR_URL, json=rogue_payload, headers={"X-Aegis-IBCT": aws_token})
if res.status_code in [200, 404, 501, 502]: # 404/501 means sidecar passed it to your dummy server
    print("✅ ALLOWED: AWS-Bot successfully operated within its authorized scope.\n")
else:
    print(f"❌ FAIL: Expected pass, got {res.status_code}")