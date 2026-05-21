import os
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask
from aegis_aip import AegisClient

app = FastAPI(title="Aegis Zero-Trust MCP Sidecar")

# Configuration
TARGET_MCP_URL = os.getenv("TARGET_MCP_URL", "http://localhost:8000") 
AEGIS_CONTROL_PLANE = os.getenv("AEGIS_CONTROL_PLANE_URL", "https://aegis-live-node.onrender.com")
AGENT_ID = os.getenv("AEGIS_AGENT_ID")

if not AGENT_ID:
    raise RuntimeError("[AEGIS ERROR] AEGIS_AGENT_ID environment variable is missing.")

# --- BOOT SEQUENCE ---
print(f"--- INITIALIZING AEGIS SIDECAR ---", flush=True)
try:
    aegis = AegisClient(agent_id=AGENT_ID, control_plane_url=AEGIS_CONTROL_PLANE)
    print("--- AEGIS AUTHENTICATION SUCCESSFUL ---", flush=True)
except Exception as e:
    raise RuntimeError(f"[AEGIS FATAL] Failed to authenticate sidecar: {e}")

# --- ASYNC SIEM TELEMETRY (Routed securely via Aegis Cloud) ---
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
    
    if not aegis_token and request.method == "POST":
        reason = "Missing X-Aegis-IBCT authorization token."
        await log_threat_to_siem(reason, "unauthorized_access")
        raise HTTPException(status_code=401, detail=f"[AEGIS BLOCKED] {reason}")

    if request.method == "POST":
        try:
            body = await request.json()
            if "method" in body and body["method"] == "tools/call":
                tool_name = body.get("params", {}).get("name")
                tool_args = body.get("params", {}).get("arguments", {})
                try:
                    aegis.secure_tool_call(tool_name=tool_name, params=tool_args)
                except Exception as e:
                    reason = str(e)
                    await log_threat_to_siem(reason, tool_name)
                    raise HTTPException(status_code=403, detail=f"[AEGIS BLOCKED] {reason}")
        except ValueError: pass 

    client = httpx.AsyncClient(base_url=TARGET_MCP_URL)
    req = client.build_request(request.method, request.url.path, headers=request.headers.raw, content=await request.body())
    response = await client.send(req, stream=True)
    return StreamingResponse(response.aiter_raw(), status_code=response.status_code, headers=response.headers, background=BackgroundTask(client.aclose))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)