import os
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

app = FastAPI(title="Aegis Zero-Trust MCP Sidecar")

# Configuration
TARGET_MCP_URL = os.getenv("TARGET_MCP_URL", "http://localhost:8000") 
AEGIS_CONTROL_PLANE = os.getenv("AEGIS_CONTROL_PLANE_URL", "https://aegis-live-node.onrender.com")
AGENT_ID = os.getenv("AEGIS_AGENT_ID")

if not AGENT_ID:
    raise RuntimeError("[AEGIS ERROR] AEGIS_AGENT_ID environment variable is missing.")

print(f"--- INITIALIZING AEGIS SIDECAR FOR {AGENT_ID[:10]}... ---", flush=True)

# --- ASYNC SIEM TELEMETRY ---
async def log_threat_to_siem(threat_reason: str, tool_name: str = "unknown"):
    payload = {
        "agent_id": AGENT_ID,
        "action": tool_name,
        "reason": threat_reason
    }
    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(f"{AEGIS_CONTROL_PLANE}/telemetry/log_threat", json=payload)
            print(f"--- TELEMETRY SYNC TO CONTROL PLANE: {res.status_code} ---", flush=True)
    except Exception as e:
        print(f"--- TELEMETRY CRITICAL EXCEPTION: {str(e)} ---", flush=True)

# --- REVERSE PROXY ROUTER ---
@app.api_route("/{path:path}", methods=["GET", "POST", "OPTIONS"])
async def mcp_reverse_proxy(request: Request, path: str):
    aegis_token = request.headers.get("X-Aegis-IBCT")
    
    # 1. Unauthenticated Network Edge Check
    if not aegis_token and request.method == "POST":
        reason = "Missing X-Aegis-IBCT authorization token."
        await log_threat_to_siem(reason, "unauthorized_access")
        raise HTTPException(status_code=401, detail=f"[AEGIS BLOCKED] {reason}")

    # 2. Authenticated Protocol Evaluation
    if request.method == "POST":
        try:
            body = await request.json()
            if "method" in body and body["method"] == "tools/call":
                tool_name = body.get("params", {}).get("name")
                tool_args = body.get("params", {}).get("arguments", {})
                
                # Ask Render Control Plane to evaluate the math bounds using the provided token
                eval_payload = {
                    "token": aegis_token,
                    "tool_name": tool_name,
                    "params": tool_args
                }
                
                async with httpx.AsyncClient() as eval_client:
                    eval_res = await eval_client.post(f"{AEGIS_CONTROL_PLANE}/execute", json=eval_payload)
                    eval_data = eval_res.json()
                    
                    # THE FIX: Explicitly check if the Bouncer blocked it
                    if eval_data.get("status") in ["BLOCKED", "ACCESS_DENIED"]:
                        reason = eval_data.get("reason", "Unknown Policy Violation")
                        # The Control Plane already logs it to Supabase during `/execute`, 
                        # so we just drop the connection here.
                        raise HTTPException(status_code=403, detail=reason)
                        
        except ValueError: 
            pass # Not JSON, let the target MCP server handle it

    # 3. Forward Clean Traffic
    client = httpx.AsyncClient(base_url=TARGET_MCP_URL)
    req = client.build_request(request.method, request.url.path, headers=request.headers.raw, content=await request.body())
    response = await client.send(req, stream=True)
    return StreamingResponse(response.aiter_raw(), status_code=response.status_code, headers=response.headers, background=BackgroundTask(client.aclose))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)