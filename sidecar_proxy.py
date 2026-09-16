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
from contextlib import asynccontextmanager
import uuid

# --- GLOBAL CONNECTION POOL ---
http_client: httpx.AsyncClient = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client
    # Initialize a persistent, highly concurrent connection pool
    limits = httpx.Limits(max_keepalive_connections=100, max_connections=100)
    # 5-second timeout, but the TCP connections stay warm
    http_client = httpx.AsyncClient(limits=limits, timeout=5.0)
    print("[Aegis Network] Persistent Connection Pool Initialized.", flush=True)
    
    yield # Server runs here
    
    # Clean up gracefully on shutdown
    await http_client.aclose()
    print("[Aegis Network] Connection Pool Closed.", flush=True)

app = FastAPI(title="Aegis Zero-Trust Universal Sidecar", lifespan=lifespan)

# --- 1. Embedded Trust Root & Config ---
AEGIS_PUBLIC_KEY = os.environ.get("AEGIS_PUBLIC_KEY", """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAjW1Lg7SRz2/K8ASyRhk9svTaJj7rtpTudllj7vCUIHU=
-----END PUBLIC KEY-----""")

TARGET_MCP_URL = os.environ.get("TARGET_MCP_URL", "http://localhost:8000")
TELEMETRY_URL = "https://aegis-live-node.onrender.com/telemetry/log_threat"
CONTROL_PLANE_MINT_URL = os.environ.get("AEGIS_CONTROL_PLANE_URL", "https://aegis-live-node.onrender.com") + "/mint"

# --- UNIVERSAL OIDC IDENTITY CONFIGURATION ---
EXTERNAL_IDP_SECRET = os.environ.get("EXTERNAL_IDP_SECRET") 
REQUIRE_EXTERNAL_AUTH = os.environ.get("REQUIRE_EXTERNAL_AUTH", "false").lower() == "true"

# --- 2. Memory State ---
TOKEN_CACHE = {}       # Caches API Key -> JWT exchanges for <2ms latency
SESSION_AUTH_MAP = {}  # Binds Cursor's raw session ID to the API Key
NONCE_CACHE: dict[str, float] = {} # { jti: expiry_timestamp } for Replay Prevention

# --- 3. Telemetry & Cryptography Core ---
def clean_expired_nonces():
    """TTL Eviction: Clears expired JTIs from memory to prevent memory leaks."""
    now = time.time()
    expired = [k for k, exp in list(NONCE_CACHE.items()) if exp < now]
    for k in expired:
        del NONCE_CACHE[k]

async def log_telemetry(jwt_payload: dict, action: str, target: dict | str, reason: str, status: str = "BLOCKED"):
    """Handles both stdout enterprise logging and Aegis UI telemetry sync."""
    correlation_id = f"req_{uuid.uuid4().hex[:8]}"
    resource_context = target if isinstance(target, dict) else {"raw_target": str(target)}
    
    stdout_log = {
        "correlation_id": correlation_id,
        "requesting_identity": jwt_payload.get("agent_id", jwt_payload.get("sub", jwt_payload.get("user_id", "Unknown-Agent"))),
        "tool_action": action,
        "resource_context": resource_context,
        "policy_decision": "DENY" if status == "BLOCKED" else "PERMIT",
        "reason": reason
    }
    print(json.dumps(stdout_log), flush=True)
    
    global http_client
    try:
        await http_client.post(TELEMETRY_URL, json={
            "user_id": jwt_payload.get("user_id", "Unknown-User"), 
            "agent_id": jwt_payload.get("agent_id", jwt_payload.get("sub", "Unknown-Agent")), 
            "action": action,
            "target": str(target)[:200],
            "reason": reason,
            "status": status
        })
    except Exception:
        pass

def verify_and_decode_token(token: str) -> dict:
    """Mathematically verifies token signature, expiration, and replay prevention at the edge."""
    try:
        # We explicitly require the 'exp' claim for deterministic bounding
        claims = jwt.decode(token, AEGIS_PUBLIC_KEY, algorithms=["EdDSA"], options={"require": ["exp"]})
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token signature has expired")
    except jwt.MissingRequiredClaimError:
        raise HTTPException(status_code=403, detail="Cryptographic signature verification failed: Missing 'exp' claim")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=403, detail="Cryptographic signature verification failed")

    # JTI Replay Prevention Check
    jti = claims.get("jti")
    if jti:
        clean_expired_nonces()
        if jti in NONCE_CACHE:
            raise HTTPException(status_code=409, detail="Replay Attack Detected: Capability token has already been consumed")
        # Cache the JTI with its expiration timestamp
        NONCE_CACHE[jti] = float(claims.get("exp", time.time() + 300))

    return claims

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

def extract_and_validate_external_identity(request: Request):
    """
    Agnostic OIDC validation. Returns (caller_identity, error_response).
    This ensures Aegis can generically pin capabilities to identities (like Entra ID, Okta, etc.)
    without hardcoding specific providers or breaking BYOA fallback logic.
    """
    if not EXTERNAL_IDP_SECRET:
        return None, None
        
    # To avoid breaking BYOA (where Authorization is the Aegis Key), 
    # we only process External IDP if X-Aegis-IBCT is explicitly provided.
    if not request.headers.get("X-Aegis-IBCT"):
        return None, None

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        ext_token = auth_header.split(" ")[1]
        try:
            # Agnostic to specific IDP algorithms, supporting common standard symmetric/asymmetric
            ext_claims = jwt.decode(ext_token, EXTERNAL_IDP_SECRET, algorithms=["HS256", "RS256", "RS384", "RS512"])
            return ext_claims.get("sub"), None
        except jwt.PyJWTError as e:
            if REQUIRE_EXTERNAL_AUTH:
                return None, JSONResponse(status_code=401, content={"error": "Unauthorized", "message": f"Invalid External Identity JWT: {str(e)}"})
    elif REQUIRE_EXTERNAL_AUTH:
        return None, JSONResponse(status_code=401, content={"error": "Unauthorized", "message": "Missing Authorization header for external identity"})
    
    return None, None

# --- 4. Global Telemetry Middleware ---
@app.middleware("http")
async def global_telemetry_logger(request: Request, call_next):
    """Catches requests that fail at the ASGI routing layer (e.g., 404 Not Found)"""
    response = await call_next(request)
    
    if response.status_code in [404, 405]:
        token = request.headers.get("X-Aegis-IBCT")
        if not token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
        claims = {}
        if token:
            try:
                claims = jwt.decode(token, options={"verify_signature": False})
            except Exception:
                pass 
                
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
    
    headers = dict(request.headers)
    headers["host"] = request.headers.get("host", "localhost:8080")
    
    for key in list(headers.keys()):
        if key.lower() == "accept-encoding":
            del headers[key]
            
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

    # --- 1.5 EXTERNAL OIDC IDENTITY & PINNING ---
    caller_identity, error_response = extract_and_validate_external_identity(request)
    if error_response:
        return error_response

    # --- 2. CRYPTOGRAPHIC VERIFICATION ---
    try:
        claims = verify_and_decode_token(token)
    except HTTPException as e:
        asyncio.create_task(log_telemetry({}, "Auth", "Sidecar Edge", e.detail, "BLOCKED"))
        return JSONResponse(status_code=e.status_code, content={"error": "Security violation", "message": e.detail})

    # Check Pinning
    pinned_sub = claims.get("sub")
    if pinned_sub and EXTERNAL_IDP_SECRET and caller_identity:
        if pinned_sub != caller_identity:
            asyncio.create_task(log_telemetry(claims, "Auth", "Sidecar Edge", "Capability Theft Detected", "BLOCKED"))
            return JSONResponse(status_code=403, content={"error": "Capability Theft Detected", "message": f"IBCT pinned to '{pinned_sub}', invoked by '{caller_identity}'"})

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
            
        try:
            validate(instance=tool_arguments, schema=tool_schema)
            asyncio.create_task(log_telemetry(claims, tool_name, tool_arguments, "Mathematical bounds verified", "ALLOWED"))
        except ValidationError as e:
            asyncio.create_task(log_telemetry(claims, tool_name, tool_arguments, f"Schema breach: {e.message}", "BLOCKED"))
            return JSONResponse(
                status_code=422,
                content={"error": "Aegis Containment Breach", "validation_error": e.message}
            )

    # --- 4. SECURE ROUTING (Using Warm Connection Pool) ---
    global http_client
    target_url = f"{TARGET_MCP_URL}/messages/"
    
    headers_to_forward = {"Content-Type": "application/json"}
    if caller_identity:
        headers_to_forward["x-aegis-identity"] = caller_identity
    elif claims.get("agent_id"):
        headers_to_forward["x-aegis-identity"] = claims.get("agent_id")
        
    if request.headers.get("x-correlation-id"):
        headers_to_forward["x-correlation-id"] = request.headers.get("x-correlation-id")

    try:
        response = await http_client.post(
            target_url,
            json=body,
            params=request.query_params,
            headers=headers_to_forward
        )
        return Response(content=response.content, status_code=response.status_code, headers=dict(response.headers))
    except httpx.RequestError as e:
        asyncio.create_task(log_telemetry(claims, "Network", "Target API", f"Infrastructure Error: {str(e)}", "ERROR"))
        return JSONResponse(
            status_code=502,
            content={"error": "Infrastructure Error", "message": f"Could not route payload: {str(e)}"}
        )

# --- 7. The Universal Validation Interceptor ---
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

    # --- 1.5 EXTERNAL OIDC IDENTITY & PINNING ---
    caller_identity, error_response = extract_and_validate_external_identity(request)
    if error_response:
        return error_response

    # 2. Extract and cryptographically verify claims locally
    try:
        claims = verify_and_decode_token(token)
    except HTTPException as e:
        asyncio.create_task(log_telemetry({}, "Auth", "Sidecar Edge", e.detail, "BLOCKED"))
        return JSONResponse(status_code=e.status_code, content={"error": "Security violation", "message": e.detail})

    # Check Pinning
    pinned_sub = claims.get("sub")
    if pinned_sub and EXTERNAL_IDP_SECRET and caller_identity:
        if pinned_sub != caller_identity:
            asyncio.create_task(log_telemetry(claims, "Auth", "Sidecar Edge", "Capability Theft Detected", "BLOCKED"))
            return JSONResponse(status_code=403, content={"error": "Capability Theft Detected", "message": f"IBCT pinned to '{pinned_sub}', invoked by '{caller_identity}'"})

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
            content={"error": "Scope Violation", "message": f"Agent identity lacks authorization scope for tool: '{tool_name}'"}
        )

    # 5. Schema Guard: Does the payload match the mathematical constraints?
    tool_schema = schema_bounds.get(tool_name)
    if not tool_schema:
        asyncio.create_task(log_telemetry(claims, tool_name, "Target API", "Policy Misconfiguration - No Schema Bounds", "BLOCKED"))
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": "Policy Misconfiguration", "message": f"No JSON-Schema bounds defined for authorized scope: '{tool_name}'. Failing closed."}
        )

    target_str = json.dumps(tool_arguments)[:200]
    try:
        # PURE MATHEMATICAL VALIDATION
        validate(instance=tool_arguments, schema=tool_schema)
    except ValidationError as e:
        asyncio.create_task(log_telemetry(claims, tool_name, target_str, f"Schema breach: {e.message}", "BLOCKED"))
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"error": "Aegis Bounded Containment Breach", "message": "The AI tool payload structurally violated the CISO security schema.", "validation_error": e.message}
        )
        
    asyncio.create_task(log_telemetry(claims, tool_name, target_str, "Mathematical bounds verified", "ALLOWED"))

    # --- 6. Secure Routing ---
    global http_client
    
    headers_to_forward = {"Content-Type": "application/json"}
    if caller_identity:
        headers_to_forward["x-aegis-identity"] = caller_identity
    elif claims.get("agent_id"):
        headers_to_forward["x-aegis-identity"] = claims.get("agent_id")
        
    if request.headers.get("x-correlation-id"):
        headers_to_forward["x-correlation-id"] = request.headers.get("x-correlation-id")

    try:
        response = await http_client.post(
            f"{TARGET_MCP_URL}/mcp/v1/tools/call",
            json=body,
            headers=headers_to_forward
        )
        return Response(content=response.content, status_code=response.status_code, headers=dict(response.headers))
    except httpx.RequestError as e:
        asyncio.create_task(log_telemetry(claims, tool_name, target_str, f"Infrastructure Error: {str(e)}", "ERROR"))
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={"error": "Infrastructure Error", "message": f"Could not route payload: {str(e)}"}
        )
