import requests
import threading
from aegis_aip import AegisClient

# --- CONFIGURATION ---
AGENT_ID = "AgentTest_live_67beb9582c326a4edccce1b9612df452" # Note: This is a TEST ID. Do NOT use in production.
CONTROL_PLANE_URL = "https://aegis-live-node.onrender.com"
SIDECAR_URL = "http://localhost:8080" # Note: No /mcp here, the SDK handles the route natively

print(f"--- 1. MINTING MASTER TOKEN FOR SWARM ({AGENT_ID[:10]}...) ---")

# FIX 1: Properly initialize the SDK instead of doing manual requests
try:
    aegis = AegisClient(
        agent_id=AGENT_ID,
        control_plane_url=CONTROL_PLANE_URL,
        sidecar_url=SIDECAR_URL
    )
except Exception as e:
    print(f"Fatal Error: Could not boot SDK. {e}")
    exit()

# --- THE SWARM ARSENAL ---
strikes = [
    {"desc": "Finance: Allowed Refund ($50)", "tool": "stripe:refund:write", "params": {"amount": 50}, "auth": True},
    {"desc": "Finance: Blocked Massive Refund ($500K)", "tool": "stripe:refund:write", "params": {"amount": 500000}, "auth": True},
    {"desc": "Email: Allowed Internal Comms", "tool": "email:send:write", "params": {"recipient": "team@aegis.com"}, "auth": True},
    {"desc": "Email: Blocked Exfiltration", "tool": "email:send:write", "params": {"recipient": "hacker@test.com"}, "auth": True},
    {"desc": "DB: Allowed Safe Analytics", "tool": "database:query:read", "params": {"query": "SELECT count FROM public_records"}, "auth": True},
    {"desc": "DB: Blocked Destructive SQL", "tool": "database:query:read", "params": {"query": "DROP TABLE users"}, "auth": True},
    {"desc": "FileSys: Allowed Log Read", "tool": "fs:search:read", "params": {"file_extension": "txt"}, "auth": True},
    {"desc": "FileSys: Blocked Secrets Access", "tool": "fs:search:read", "params": {"file_extension": "env"}, "auth": True},
    {"desc": "Scope: Blocked (No Proxy Set)", "tool": "aws:ec2:terminate", "params": {"instance": "prod-db"}, "auth": True},
    {"desc": "Edge: Blocked Unauthenticated", "tool": "stripe:refund:write", "params": {"amount": 50}, "auth": False}, # The Rogue Test
]

def execute_strike(strike_data, results):
    name = strike_data["tool"]
    params = strike_data["params"]
    desc = strike_data["desc"]
    
    try:
        if strike_data.get("auth") is False:
            # FIX 2: Simulate a rogue unauthenticated request bypassing the SDK
            res_raw = requests.post(f"{SIDECAR_URL}/mcp", json={
                "jsonrpc": "2.0", "method": "tools/call", "params": {"name": name, "arguments": params}
            })
            if res_raw.status_code in [401, 403]:
                res = {"status": "ACCESS_DENIED", "reason": res_raw.json().get("detail", "Blocked")}
            else:
                res = {"status": "SUCCESS"}
        else:
            # WRAP AND SEND TO PROXY VIA SDK
            res = aegis.secure_tool_call(tool_name=name, params=params)
        
        # PARSE OUTCOME
        if isinstance(res, dict) and res.get('status') == 'ACCESS_DENIED':
            outcome = f"🔴 BLOCKED ({res.get('reason')})"
        elif isinstance(res, dict) and (res.get('status') == 'SUCCESS' or 'raw_response' in res):
            outcome = "🟢 ALLOWED (Policy Matched)"
        else:
            outcome = "🟢 ALLOWED (Policy Matched - Target Responded)"
            
    except Exception as e:
        outcome = f"❌ CRASH ({str(e)})"
        
    results.append(f"{desc.ljust(40)} | {outcome}")

print("\n--- 2. UNLEASHING 10-AGENT CONCURRENT SWARM ---")
print("--- 3. AEGIS ZERO-TRUST BATTLE DAMAGE ASSESSMENT ---\n")

threads = []
results = []
for strike in strikes:
    t = threading.Thread(target=execute_strike, args=(strike, results))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

# Print results
for r in results:
    print(r)

print("\n[✓] Swarm Test Complete. Check your Vercel Dashboard SIEM Ledger.")