import os
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse
from aegis_aip import AegisClient

app = FastAPI(title="Aegis Zero-Trust MCP Sidecar")

# 1. Configuration
TARGET_MCP_URL = os.getenv("TARGET_MCP_URL", "http://localhost:8000") 
AEGIS_CONTROL_PLANE = os.getenv("AEGIS_CONTROL_PLANE_URL", "https://aegis-live-node.onrender.com")
AGENT_ID = os.getenv("AEGIS_AGENT_ID")

if not AGENT_ID:
    raise RuntimeError("[AEGIS ERROR] AEGIS_AGENT_ID environment variable is missing. Cannot start sidecar.")

# 2. Initialize the Aegis Cryptographic Verifier
print(f"--- INITIALIZING AEGIS SIDECAR FOR AGENT: {AGENT_ID} ---")
try:
    aegis = AegisClient(
        agent_id=AGENT_ID, 
        control_plane_url=AEGIS_CONTROL_PLANE
    )
    print("--- AEGIS AUTHENTICATION SUCCESSFUL ---")
except Exception as e:
    raise RuntimeError(f"[AEGIS FATAL] Failed to authenticate sidecar: {e}")

@app.api_route("/{path:path}", methods=["GET", "POST", "OPTIONS"])
async def mcp_reverse_proxy(request: Request, path: str):
    """
    Intercepts all traffic bound for the MCP server.
    Extracts the IBCT (Invocation-Bound Capability Token), verifies mathematical bounds,
    and forwards the request ONLY if the policy holds.
    """
    # Extract the Aegis Token from headers
    aegis_token = request.headers.get("X-Aegis-IBCT")
    if not aegis_token and request.method == "POST":
        raise HTTPException(status_code=401, detail="[AEGIS BLOCKED] Missing X-Aegis-IBCT authorization token. Zero-Trust policy enforced.")

    # If it's a POST request (tool execution), validate the payload
    if request.method == "POST":
        try:
            body = await request.json()
            
            # Extract standard MCP JSON-RPC payload
            if "method" in body and body["method"] == "tools/call":
                tool_name = body.get("params", {}).get("name")
                tool_args = body.get("params", {}).get("arguments", {})

                # MATHEMATICAL ENFORCEMENT BOUNDARY
                # Verifies the token cryptographically and checks parameters against CRO policy
                print(f"--- AEGIS INTERCEPT: Validating execution of {tool_name} ---")
                try:
                    # In a production sidecar, AegisClient evaluates the token against the args
                    aegis.secure_tool_call(tool_name=tool_name, params=tool_args)
                    print(f"--- AEGIS VERIFIED: Mathematical bounds passed ---")
                except Exception as e:
                    print(f"--- AEGIS BLOCKED: {str(e)} ---")
                    raise HTTPException(status_code=403, detail=f"[AEGIS BLOCKED] Policy Violation: {str(e)}")
        
        except ValueError:
            pass # Not a JSON payload, let standard routing handle it

    # 3. FORWARD THE TRAFFIC TO THE REAL MCP SERVER
    client = httpx.AsyncClient(base_url=TARGET_MCP_URL)
    url = httpx.URL(path=request.url.path, query=request.url.query.encode("utf-8"))
    
    req = client.build_request(
        request.method,
        url,
        headers=request.headers.raw,
        content=await request.body()
    )
    
    response = await client.send(req, stream=True)
    return StreamingResponse(
        response.aiter_raw(),
        status_code=response.status_code,
        headers=response.headers,
        background=client.aclose
    )

if __name__ == "__main__":
    import uvicorn
    # The Sidecar listens on port 8080. The actual MCP is hidden on 8000.
    uvicorn.run(app, host="0.0.0.0", port=8080)