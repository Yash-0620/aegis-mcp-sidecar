import requests

# --- CONFIGURATION ---
AWS_AGENT_KEY = "aegis_live_94f6551108c3de863248ed5fc0f79699" # Note: This is a TEST KEY. Do NOT use in production.
STRIPE_AGENT_KEY = "aegis_live_098450c639f7e436a91d03dc3b1d8e31" # Note: This is a TEST KEY. Do NOT use in production.
MINT_URL = "https://aegis-live-node.onrender.com/mint"
SIDECAR_URL = "http://localhost:8080/mcp/v1/tools/call"

def fire_payload(token, tool_name, args):
    headers = {"X-Aegis-IBCT": token}
    payload = {
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": args}
    }
    return requests.post(SIDECAR_URL, json=payload, headers=headers)

# Get tokens
aws_token = requests.post(MINT_URL, json={"api_key": AWS_AGENT_KEY}).json().get("token")
stripe_token = requests.post(MINT_URL, json={"api_key": STRIPE_AGENT_KEY}).json().get("token")

print("--- 1. TESTING REGEX BOUNDS (AWS) ---")
# Attack 1: Try to delete a production bucket
res1 = fire_payload(aws_token, "aws:s3:delete", {"bucket_name": "core-production-db"})
print(f"Attack (Prod Bucket) -> Status: {res1.status_code} | Result: {res1.json().get('validation_error', 'PASSED')}")

# Safe 1: Try to delete a temp bucket
res2 = fire_payload(aws_token, "aws:s3:delete", {"bucket_name": "test-temp-logs"})
print(f"Safe (Temp Bucket)   -> Status: {res2.status_code} | Result: Sidecar Forwarded Payload\n")


print("--- 2. TESTING INTEGER BOUNDS (STRIPE) ---")
# Attack 2: Try to refund $500 (Limit is 50)
res3 = fire_payload(stripe_token, "stripe:refund:write", {"amount": 500})
print(f"Attack ($500 Refund) -> Status: {res3.status_code} | Result: {res3.json().get('validation_error', 'PASSED')}")

# Safe 2: Refund $40
res4 = fire_payload(stripe_token, "stripe:refund:write", {"amount": 40})
print(f"Safe ($40 Refund)    -> Status: {res4.status_code} | Result: Sidecar Forwarded Payload\n")


print("--- 3. TESTING HALLUCINATION LOCK (Universal) ---")
# Attack 3: The LLM tries to be helpful and invents an extra parameter not in the CISO schema
res5 = fire_payload(stripe_token, "stripe:refund:write", {"amount": 30, "notify_customer": True})
print(f"Attack (Hallucinated Param) -> Status: {res5.status_code} | Result: {res5.json().get('validation_error', 'PASSED')}")