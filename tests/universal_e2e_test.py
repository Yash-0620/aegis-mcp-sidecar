import requests
import json

# --- 1. CONFIGURATION ---
# Replace this with the exact API key you generated on your dashboard!
API_KEY = "aegis_live_8f14d7fb289fd25652cbc43c28e1b96a" # <--- UPDATE THIS WITH YOUR API KEY 

# Replace this if your tool scope is named differently in the UI
TARGET_TOOL = "github:repo:delete" 

# Your URLs (adjust if your backend is running on Render instead of localhost)
CONTROL_PLANE_MINT_URL = "https://aegis-live-node.onrender.com/mint" 
SIDECAR_URL = "https://aegis-live-node.onrender.com/mcp/v1/tools/call"

print("--- 1. REQUESTING TOKEN FROM CONTROL PLANE ---")
try:
    # We send the API Key to the Control Plane just like a real SDK would
    mint_response = requests.post(CONTROL_PLANE_MINT_URL, json={"api_key": API_KEY})
    
    if mint_response.status_code != 200:
        print(f"❌ Minting Failed: {mint_response.json()}")
        exit(1)
        
    token = mint_response.json().get("token")
    print("✅ Successfully minted Ed25519 Token from the database!")
    
except Exception as e:
    print(f"❌ Connection Error to Control Plane: {e}")
    exit(1)


# --- 2. FIRE PAYLOAD TO SIDECAR ---
print(f"\n--- 2. FIRING PAYLOAD TO SIDECAR FOR {TARGET_TOOL} ---")

headers = {
    "X-Aegis-IBCT": token,
    "Content-Type": "application/json"
}

# NOTE: Adjust the "arguments" below to test the specific 
# JSON-Schema Mathematical Bounds you created on the dashboard!
test_payload = {
    "method": "tools/call",
    "params": {
        "name": TARGET_TOOL,
        "arguments": {
            "repository_name": "test-dev-repo", # Change this to test your Regex/Max Limits
            "force": True
        }
    }
}

try:
    res = requests.post(SIDECAR_URL, json=test_payload, headers=headers)
    
    if res.status_code == 422:
        print(f"🛡️ BLOCKED (Status 422): Sidecar intercepted schema violation!")
        print(f"Forensics: {res.json().get('validation_error')}")
    elif res.status_code in [200, 502]:
        print(f"✅ ALLOWED (Status {res.status_code}): Sidecar validated the schema and forwarded the traffic.")
    else:
        print(f"⚠️ Unexpected Status: {res.status_code} - {res.text}")
        
except Exception as e:
     print(f"❌ Connection Error to Sidecar: {e}")