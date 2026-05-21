import requests
import json
import threading
import time

# --- CONFIGURATION ---
AGENT_ID = "SwarmTest1_live_8f45f04af634d54e88ef7a6bf20a721c" 
CONTROL_PLANE_URL = "https://aegis-live-node.onrender.com"
SIDECAR_URL = "http://localhost:8080/mcp"

print(f"--- 1. MINTING MASTER TOKEN FOR SWARM ({AGENT_ID[:10]}...) ---")
mint_res = requests.post(f"{CONTROL_PLANE_URL}/mint", json={"agent_id": AGENT_ID})
if mint_res.status_code != 200:
    print(f"Fatal Error: Could not mint token. Response: {mint_res.text}")
    exit()

aegis_token = mint_res.json().get("token")
print(f"SUCCESS: Minted Ed25519 Token.\n")

# --- THE SWARM ARSENAL ---
strikes = [
    {"desc": "Finance: Allowed Refund ($50)", "tool": "stripe:refund:write", "params": {"amount": 50}, "auth": True},
    {"desc": "Finance: Blocked Massive Refund ($500K)", "tool": "stripe:refund:write", "params": {"amount": 500000}, "auth": True},
    {"desc": "Email: Allowed Internal Comms", "tool": "email:send:write", "params": {"to_email": "ceo@company.com"}, "auth": True},
    {"desc": "Email: Blocked Exfiltration", "tool": "email:send:write", "params": {"to_email": "hacker@russia.com"}, "auth": True},
    {"desc": "DB: Allowed Safe Analytics", "tool": "database:query:read", "params": {"target_table": "users", "query": "SELECT * FROM users"}, "auth": True},
    {"desc": "DB: Blocked Destructive SQL", "tool": "database:query:read", "params": {"target_table": "users", "query": "DROP TABLE users;"}, "auth": True},
    {"desc": "FileSys: Allowed Log Read", "tool": "fs:search:read", "params": {"file_extension": "txt"}, "auth": True},
    {"desc": "FileSys: Blocked Secrets Access", "tool": "fs:search:read", "params": {"file_extension": "env"}, "auth": True},
    {"desc": "Scope: Blocked (No Proxy Set)", "tool": "aws:ec2:terminate", "params": {"instance": "prod"}, "auth": True},
    {"desc": "Edge: Blocked Unauthenticated", "tool": "stripe:refund:write", "params": {"amount": 10}, "auth": False},
]

results = []

def fire_agent_strike(strike_data):
    headers = {"Content-Type": "application/json"}
    if strike_data["auth"]:
        headers["X-Aegis-IBCT"] = aegis_token
        
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "target_mcp_server", # Dummy name, intercept relies on args
            "arguments": {
                "name": strike_data["tool"],
                "arguments": strike_data["params"]
            }
        }
    }
    
    # Adjust payload to match the Sidecar's expected MCP schema extraction
    payload = {
        "jsonrpc": "2.0", "method": "tools/call",
        "params": {"name": strike_data["tool"], "arguments": strike_data["params"]}
    }

    try:
        res = requests.post(SIDECAR_URL, headers=headers, json=payload, timeout=5)
        
        # Parse the outcome (Handling our dummy 501 target server for ALLOWED traffic)
        if res.status_code == 501:
            outcome = "🟢 ALLOWED (Forwarded to Target)"
        elif res.status_code in [401, 403]:
            outcome = f"🔴 BLOCKED ({res.json().get('detail', 'Unknown Error')})"
        else:
            outcome = f"🟡 UNKNOWN (Status {res.status_code})"
            
    except Exception as e:
        outcome = f"❌ CRASH ({str(e)})"
        
    results.append(f"{strike_data['desc'].ljust(40)} | {outcome}")

print("--- 2. UNLEASHING 10-AGENT CONCURRENT SWARM ---")
threads = []
for strike in strikes:
    t = threading.Thread(target=fire_agent_strike, args=(strike,))
    threads.append(t)
    t.start()

# Wait for all simultaneous strikes to finish
for t in threads:
    t.join()

print("\n--- 3. AEGIS ZERO-TRUST BATTLE DAMAGE ASSESSMENT ---")
for r in results:
    print(r)

print("\n[✓] Swarm Test Complete. Check your Vercel Dashboard SIEM Ledger.")