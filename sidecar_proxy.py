import json
import os
import re
import time
import jwt
import asyncio
from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.responses import JSONResponse, StreamingResponse
import httpx
from jsonschema import validate, ValidationError

app = FastAPI(title="Aegis Zero-Trust Universal Sidecar")

# --- 1. Embedded Trust Root & Config ---
AEGIS_PUBLIC_KEY = os.environ.get("AEGIS_PUBLIC_KEY", """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAjW1Lg7SRz2/K8ASyRhk9svTaJj7rtpTudllj7vCUIHU=
-----END PUBLIC KEY-----""")

TARGET_MCP_URL = os.environ.get("TARGET_MCP_URL", "http://localhost:8000")
TELEMETRY_URL = "https://aegis-live-node.onrender.com/telemetry/log_threat"
CONTROL_PLANE_MINT_URL = os.environ.get("AEGIS_CONTROL_PLANE_URL", "https://aegis-live-node.onrender.com") + "/mint"

# --- 2. Memory State ---
TOKEN_CACHE = {}      # Caches API Key -> JWT exchanges for <2ms latency
SESSION_AUTH_MAP = {} # Binds Cursor's raw session ID to the API Key

# --- 3. Telemetry & Cryptography Core ---
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

async def exchange_api_key_for_jwt(api_key: str) -> str:
    current_time = time.time()
    if api_key in TOKEN_CACHE:
        cached = TOKEN_CACHE[api_key]
        if cached["expires_at"] > current_time:
            return cached["token"]
            
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(CONTROL_PLANE_MINT_URL, json={"api_key": api_key}, timeout=3.0)
            if response.status_code == 200:
                token = response.json().get("token")
                TOKEN_CACHE[api_key] = {"token": token, "expires_at": current_time + 240}
                return token
            else:
                raise HTTPException(status_code=401, detail="Invalid API Key exchanged")
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=f"Control Plane unreachable: {str(e)}")

# --- 4. Global Telemetry Middleware ---
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

# --- 5. The Buffered SSE Handshake Forwarder (Gzip Patched) ---
@app.get("/sse")
async def sse_handshake_forwarder(request: Request):
    api_key = request.query_params.get("apiKey")
    target_url = f"{TARGET_MCP_URL}/sse"
    
    # Safely extract all headers
    headers = dict(request.headers)
    headers["host"] = request.headers.get("host", "localhost:8080")
    
    # 1. Purge all possible casing variations of the encoding header
    for key in list(headers.keys()):
        if key.lower() == "accept-encoding":
            del headers[key]
            
    # 2. EXPLICITLY force plain text to override httpx defaults
    headers["Accept-Encoding"] = "identity"
        
    client = httpx.AsyncClient()
    try:
        req = client.build_request("GET", target_url, headers=headers)
        r = await client.send(req, stream=True)
        
        async def event_stream_interceptor():
            buffer = ""
            async for chunk in r.aiter_raw():
                try:
                    text = chunk.decode("utf-8", errors="ignore")
                    buffer += text
                    if api_key and ("sessionId=" in buffer or "session_id=" in buffer):
                        match = re.search(r'(?:sessionId|session_id)=([a-zA-Z0-9_-]+)', buffer)
                        if match:
                            session_id = match.group(1)
                            if session_id not in SESSION_AUTH_MAP:
                                SESSION_AUTH_MAP[session_id] = api_key
                                print(f"[Aegis Auth] Successfully Bound Session {session_id} to API Key", flush=True)
                except Exception:
                    pass
                yield chunk

        return StreamingResponse(event_stream_interceptor(), headers=dict(r.headers))
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": "SSE Handshake Failed", "details": str(e)})

# --- 6. The Facade JSON-RPC Forwarder ---
@app.post("/messages/")
async def mcp_message_forwarder(request: Request):
    body = await request.json()
    
    # --- 1. BYOA AUTH EXCHANGE ---
    token = request.headers.get("X-Aegis-IBCT")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            raw_key = auth_header.split(" ")[1]
        else:
            session_id = request.query_params.get("sessionId") or request.query_params.get("session_id")
            raw_key = SESSION_AUTH_MAP.get(session_id)

        if raw_key:
            if len(raw_key.split(".")) != 3: 
                try:
                    token = await exchange_api_key_for_jwt(raw_key)
                except HTTPException as e:
                    asyncio.create_task(log_telemetry({}, "Auth", "Sidecar Edge", f"Key Exchange Failed: {e.detail}", "BLOCKED"))
                    return JSONResponse(status_code=e.status_code, content={"error": "Security violation", "message": e.detail})
            else:
                token = raw_key

    if not token:
        asyncio.create_task(log_telemetry({}, "Auth", "Sidecar Edge", "Missing Security Context", "BLOCKED"))
        return JSONResponse(status_code=401, content={"error": "Unauthorized", "message": "API Key required."})

    # --- 2. CRYPTOGRAPHIC VERIFICATION ---
    try:
        claims = verify_and_decode_token(token)
    except HTTPException as e:
        asyncio.create_task(log_telemetry({}, "Auth", "Sidecar Edge", e.detail, "BLOCKED"))
        return JSONResponse(status_code=e.status_code, content={"error": "Security violation", "message": e.detail})

    # --- 3. THE V2 INTERNAL PIPE (Mathematical Guard) ---
    if body.get("method") == "tools/call":
        params = body.get("params", {})
        tool_name = params.get("name")
        tool_arguments = params.get("arguments", {})
        
        allowed_scopes = claims.get("allowed_scopes", [])
        schema_bounds = claims.get("schema_bounds", {})
        
        if tool_name not in allowed_scopes:
            asyncio.create_task(log_telemetry(claims, tool_name, "Target API", "Scope Violation", "BLOCKED"))
            return JSONResponse(status_code=403, content={"error": "Scope Violation"})
            
        tool_schema = schema_bounds.get(tool_name)
        if not tool_schema:
            asyncio.create_task(log_telemetry(claims, tool_name, "Target API", "Policy Misconfiguration", "BLOCKED"))
            return JSONResponse(status_code=403, content={"error": "Policy Misconfiguration"})
            
        target_str = json.dumps(tool_arguments)[:200]
        try:
            validate(instance=tool_arguments, schema=tool_schema)
            asyncio.create_task(log_telemetry(claims, tool_name, target_str, "Mathematical bounds verified", "ALLOWED"))
        except ValidationError as e:
            asyncio.create_task(log_telemetry(claims, tool_name, target_str, f"Schema breach: {e.message}", "BLOCKED"))
            return JSONResponse(
                status_code=422,
                content={"error": "Aegis Containment Breach", "validation_error": e.message}
            )

    # --- 4. SECURE ROUTING ---
    target_url = f"{TARGET_MCP_URL}/messages/"
    async with httpx.AsyncClient() as client:
        response = await client.post(
            target_url,
            json=body,
            params=request.query_params,
            headers={"Content-Type": "application/json"}
        )
        return Response(content=response.content, status_code=response.status_code, headers=dict(response.headers))

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
