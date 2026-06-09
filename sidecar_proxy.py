import json
import os
import jwt
from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.responses import JSONResponse, StreamingResponse
import httpx
from jsonschema import validate, ValidationError
import asyncio

app = FastAPI(title="Aegis Zero-Trust Universal Sidecar")

# --- 1. Embedded Trust Root ---
AEGIS_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAjW1Lg7SRz2/K8ASyRhk9svTaJj7rtpTudllj7vCUIHU=
-----END PUBLIC KEY-----"""

# --- CONFIGURATION ---
TARGET_MCP_URL = os.environ.get("TARGET_MCP_URL", "http://localhost:8000")
TELEMETRY_URL = "https://aegis-live-node.onrender.com/telemetry/log_threat"


# --- 2. Telemetry & Cryptography Core ---
async def log_telemetry(jwt_payload: dict, action: str, target: str, reason: str, status: str = "BLOCKED"):
    """Fire-and-forget telemetry for both Blocks and Allows."""
    async with httpx.AsyncClient() as client:
        try:
            await client.post(TELEMETRY_URL, json={
                "user_id": jwt_payload.get("user_id", "Unknown-User"), 
                "agent_id": jwt_payload.get("agent_id", "Unknown-Agent"), 
                "action": action,
                "target": target,  
                "reason": reason,
                "status": status
            }, timeout=2.0)
        except Exception as e:
            print(f"[Telemetry Warning] Could not sync telemetry: {e}")


def verify_and_decode_token(token: str) -> dict:
    """Mathematically verifies the token signature at the edge using Ed25519."""
    try:
        return jwt.decode(token, AEGIS_PUBLIC_KEY, algorithms=["EdDSA"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token signature has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=403, detail="Cryptographic signature verification failed")


# --- 3. Global Telemetry Middleware (The 404 Ghost Catcher) ---
@app.middleware("http")
async def global_telemetry_logger(request: Request, call_next):
    """
    Catches requests that fail at the ASGI routing layer (e.g., 404 Not Found)
    and forcibly extracts the token to bypass Supabase RLS for the UI.
    """
    response = await call_next(request)
    
    # Catch Ghost Requests (404) or Method Not Allowed (405)
    if response.status_code in [404, 405]:
        
        # 1. We MUST try to extract the token to attribute the attack to the correct CISO dashboard
        token = request.headers.get("X-Aegis-IBCT")
        if not token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        # 2. Extract claims purely to grab the user_id for UI routing
        claims = {}
        if token:
            try:
                # We decode without verifying signature ONLY because the request is already blocked (404).
                # We just need to know whose dashboard to send the warning to.
                claims = jwt.decode(token, options={"verify_signature": False})
            except Exception:
                pass # If the token is complete garbage, fail gracefully
                
        # 3. Fire telemetry with the CISO's identity attached
        asyncio.create_task(log_telemetry(
            jwt_payload=claims, 
            action=f"INVALID_ROUTE: {request.url.path}", 
            target="Sidecar Edge", 
            reason=f"{response.status_code} - Payload fired at invalid proxy endpoint", 
            status="BLOCKED"
        ))
        
    return response

# --- 4. The SSE Handshake Forwarder ---
@app.get("/sse")
async def sse_handshake_forwarder(request: Request):
    """
    Passes the initial Cursor SSE handshake straight through to the isolated target MCP.
    """
    target_url = f"{TARGET_MCP_URL}/sse"
    client = httpx.AsyncClient()
    
    try:
        # Build and send the GET request to the hidden target server
        req = client.build_request("GET", target_url)
        r = await client.send(req, stream=True)
        
        # Stream the raw SSE connection back to Cursor
        return StreamingResponse(r.aiter_raw(), headers=dict(r.headers))
    except Exception as e:
        return JSONResponse(
            status_code=502, 
            content={"error": "Failed to establish SSE handshake with isolated target", "details": str(e)}
        )

# --- 5. The MCP JSON-RPC Forwarder ---
@app.post("/messages/")
async def mcp_message_forwarder(request: Request):
    """
    Forwards MCP JSON-RPC messages (POST /messages/) to the target.
    """
    target_url = f"{TARGET_MCP_URL}/messages/"
    body = await request.json()
    
    async with httpx.AsyncClient() as client:
        # Forward the POST request to the internal Postgres MCP server
        response = await client.post(
            target_url,
            json=body,
            params=request.query_params, # Important: keeps the session_id
            headers={"Content-Type": "application/json"}
        )
        return Response(content=response.content, status_code=response.status_code)


# --- 6. The Universal Validation Interceptor ---
@app.post("/mcp/v1/tools/call")
async def intercept_tool_call(request: Request):
    """
    Universal network-layer interceptor. Handles ANY tool call format
    by analyzing the mathematical shape of the JSON parameters.
    """
    
    # 1. Extract the Invocation-Bound Capability Token (IBCT)
    token = request.headers.get("X-Aegis-IBCT")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

    if not token:
        asyncio.create_task(log_telemetry({}, "Auth", "Sidecar Edge", "Missing Security Context", "BLOCKED"))
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "Missing Security Context", "message": "X-Aegis-IBCT or Bearer Token required"}
        )

    # 2. Extract and cryptographically verify claims locally
    try:
        claims = verify_and_decode_token(token)
    except HTTPException as e:
        asyncio.create_task(log_telemetry({}, "Auth", "Sidecar Edge", e.detail, "BLOCKED"))
        return JSONResponse(status_code=e.status_code, content={"error": "Security violation", "message": e.detail})

    allowed_scopes = claims.get("allowed_scopes", [])
    schema_bounds = claims.get("schema_bounds", {})

    # 3. Parse the incoming JSON payload
    try:
        body = await request.json()
    except json.JSONDecodeError:
        asyncio.create_task(log_telemetry(claims, "Payload", "Sidecar Edge", "Malformed JSON request", "BLOCKED"))
        return JSONResponse(status_code=400, content={"error": "Invalid payload", "message": "Malformed JSON request"})

    params = body.get("params", {})
    tool_name = params.get("name")
    tool_arguments = params.get("arguments", {})

    if not tool_name:
        asyncio.create_task(log_telemetry(claims, "Protocol", "Sidecar Edge", "Missing target tool name", "BLOCKED"))
        return JSONResponse(status_code=400, content={"error": "Invalid protocol", "message": "Missing target tool name"})

    # 4. Scope Guard: Is the AI Agent permitted to talk to this tool?
    if tool_name not in allowed_scopes:
        asyncio.create_task(log_telemetry(claims, tool_name, "Target API", "Scope Violation - Tool not authorized", "BLOCKED"))
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "Scope Violation", 
                "message": f"Agent identity lacks authorization scope for tool: '{tool_name}'"
            }
        )

    # 5. Schema Guard: Does the payload match the mathematical constraints?
    tool_schema = schema_bounds.get(tool_name)
    
    if not tool_schema:
        asyncio.create_task(log_telemetry(claims, tool_name, "Target API", "Policy Misconfiguration - No Schema Bounds", "BLOCKED"))
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "Policy Misconfiguration", 
                "message": f"No JSON-Schema bounds defined for authorized scope: '{tool_name}'. Failing closed."
            }
        )

    target_str = json.dumps(tool_arguments)[:200]

    try:
        # PURE MATHEMATICAL VALIDATION
        validate(instance=tool_arguments, schema=tool_schema)
    except ValidationError as e:
        asyncio.create_task(log_telemetry(claims, tool_name, target_str, f"Schema breach: {e.message}", "BLOCKED"))
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "Aegis Bounded Containment Breach",
                "message": "The AI tool payload structurally violated the CISO security schema.",
                "validation_error": e.message
            }
        )
    
    # FIRE TELEMETRY: ALLOWED (Schema Passed)
    asyncio.create_task(log_telemetry(claims, tool_name, target_str, "Mathematical bounds verified", "ALLOWED"))

    # --- 6. Secure Routing ---
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{TARGET_MCP_URL}/mcp/v1/tools/call",  # FIXED: Variable name corrected
                json=body,
                headers={"Content-Type": "application/json"},
                timeout=5.0 
            )
            return Response(content=response.content, status_code=response.status_code, headers=dict(response.headers))
        except httpx.RequestError as e:
            # Optionally log the infrastructure failure as well
            asyncio.create_task(log_telemetry(claims, tool_name, target_str, f"Infrastructure Error: {str(e)}", "ERROR"))
            return JSONResponse(
                status_code=status.HTTP_502_BAD_GATEWAY,
                content={"error": "Infrastructure Error", "message": f"Could not route payload to target MCP server: {str(e)}"}
            )
