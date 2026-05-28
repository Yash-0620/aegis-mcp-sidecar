import requests
import threading

# --- CONFIGURATION ---
# PASTE YOUR TWO DISTINCT AGENT IDs HERE
AGENT_FINANCE_ID = "FinanceTest_live_17a1ee60336fde01d82750761d16e04f" # Note: This is a TEST ID. REPLACE WITH YOUR ACTUAL AGENT ID in production.
AGENT_DATA_ID = "AgentTest_live_67beb9582c326a4edccce1b9612df452"  # Note: This is a TEST ID. REPLACE WITH YOUR ACTUAL AGENT ID in production.

CONTROL_PLANE_URL = "https://aegis-live-node.onrender.com"
SIDECAR_URL = "http://localhost:8080/mcp"

def mint_token(agent_id, name):
    print(f"--- MINTING TOKEN FOR {name} ({agent_id[:10]}...) ---")
    res = requests.post(f"{CONTROL_PLANE_URL}/mint", json={"agent_id": agent_id})
    if res.status_code != 200:
        print(f"Fatal Error minting for {name}: {res.text}")
        exit()
    return res.json().get("token")

# Mint isolated tokens
token_finance = mint_token(AGENT_FINANCE_ID, "FinanceBot")
token_data = mint_token(AGENT_DATA_ID, "DataBot")
print("SUCCESS: Both cryptographic identities established.\n")

# --- THE CROSS-CONTAMINATION MATRIX ---
# We intentionally make agents try to do each other's jobs
strikes = [
    # FinanceBot Actions
    {"agent": "FinanceBot", "token": token_finance, "desc": "Allowed Stripe Refund", "tool": "stripe:refund:write", "params": {"amount": 50}},
    {"agent": "FinanceBot", "token": token_finance, "desc": "ILLEGAL DB Access (Cross-Contamination Test)", "tool": "database:query:read", "params": {"target_table": "users", "query": "SELECT * FROM users"}},
    
    # DataBot Actions
    {"agent": "DataBot", "token": token_data, "desc": "Allowed DB Access", "tool": "database:query:read", "params": {"target_table": "users", "query": "SELECT * FROM users"}},
    {"agent": "DataBot", "token": token_data, "desc": "ILLEGAL Stripe Access (Cross-Contamination Test)", "tool": "stripe:refund:write", "params": {"amount": 50}},
    
    # Unauthenticated / Rogue
    {"agent": "Anonymous", "token": None, "desc": "No Token Strike", "tool": "database:query:read", "params": {"target_table": "users", "query": "SELECT * FROM users"}}
]

results = []

def fire_isolated_strike(strike_data):
    headers = {"Content-Type": "application/json"}
    if strike_data["token"]:
        headers["X-Aegis-IBCT"] = strike_data["token"]
        
    payload = {
        "jsonrpc": "2.0", "method": "tools/call",
        "params": {"name": strike_data["tool"], "arguments": strike_data["params"]}
    }

    try:
        res = requests.post(SIDECAR_URL, headers=headers, json=payload, timeout=5)
        # FIX: Updated to align with the new Ed25519 Edge Proxy response codes
        if res.status_code == 200:
            outcome = "🟢 ALLOWED (Target Reached)"
        elif res.status_code in [401, 403]:
            outcome = f"🔴 BLOCKED ({res.json().get('detail', 'Unknown Error')})"
        else:
            outcome = f"🟡 UNKNOWN (Status {res.status_code})"
    except Exception as e:
        outcome = f"❌ CRASH ({str(e)})"
        
    results.append(f"[{strike_data['agent'].ljust(12)}] {strike_data['desc'].ljust(48)} | {outcome}")

print("--- UNLEASHING CONCURRENT MULTI-AGENT SWARM ---")
threads = []
for _ in range(3): # Fire the matrix 3 times concurrently (15 total requests) to stress-test memory isolation
    for strike in strikes:
        t = threading.Thread(target=fire_isolated_strike, args=(strike,))
        threads.append(t)
        t.start()

for t in threads:
    t.join()

print("\n--- AEGIS ISOLATION AUDIT RESULTS ---")
for r in sorted(results): # Sort to group by Agent for easy reading
    print(r)

print("\n[✓] Multi-Agent Cross-Contamination Test Complete.")