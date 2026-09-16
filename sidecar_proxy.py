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
    limits = httpx.Limits(max_keepalive_connections=100, max_connections=100)
    http_client = httpx.AsyncClient(limits=limits, timeout=5.0)
    print("[Aegis Network] Persistent Connection Pool Initialized.", flush=True)
    yield
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
REQUIRED_EXTERNAL_ROLE = os.environ.get("REQUIRED_EXTERNAL_ROLE")

# --- 2. Memory State ---
TOKEN_CACHE = {}       
SESSION_AUTH_MAP = {}  
NONCE_CACHE: dict[str, float] = {} 

# --- 3. Telemetry & Cryptography Core ---
def clean_expired_nonces():
    now = time.time()
    expired = [k for k, exp in list(NONCE_CACHE.items()) if exp < now]
    for k in expired:
        del NONCE_CACHE[k]

def get_unverified_claims(request: Request) -> dict:
    """Extracts payload without verifying so we can log to the correct CISO dashboard on auth failures."""
    token = request.headers.get("X-Aegis-IBCT")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
    if token:
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except Exception:
            pass
    return {}

async def log_telemetry(jwt_payload: dict, action: str, target: dict | str, reason: str, status: str = "BLOCKED"):
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
    if http_client:
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
    try:
        claims = jwt.decode(token, AEGIS_PUBLIC_KEY, algorithms=["EdDSA"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token signature has expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=403, detail=f"Cryptographic signature verification failed: {str(e)}")

    jti = claims.get("jti")
    if jti:
        clean_expired_nonces()
        if jti in NONCE_CACHE:
            raise HTTPException(status_code=409, detail="Replay Attack Detected: Capability token has already been consumed")
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
    if not EXTERNAL_IDP_SECRET:
        return None, None

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        ext_token = auth_header.split(" ")[1]
        try:
            # verify_aud=False prevents crashes when external tokens have audiences we don't care about
            ext_claims = jwt.decode(ext_token, EXTERNAL_IDP_SECRET, algorithms=["HS256", "RS256", "RS384", "RS512"], options={"verify_aud": False, "verify_iss": False})
            
            if REQUIRED_EXTERNAL_ROLE:
                roles = ext_claims.get("roles", [])
                if REQUIRED_EXTERNAL_ROLE not in roles:
                    err_msg = f"Caller lacks required role: {REQUIRED_EXTERNAL_ROLE}"
                    asyncio.create_task(log_telemetry(get_unverified_claims(request), "Authentication", "Proxy", err_msg, "BLOCKED"))
                    return None, JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"error": "Forbidden", "message": err_msg})
            return ext_claims.get("sub"), None
        except jwt.PyJWTError as e:
            if REQUIRE_EXTERNAL_AUTH:
                err_msg = f"Invalid Identity JWT: {str(e)}"
                asyncio.create_task(log_telemetry(get_unverified_claims(request), "Authentication", "Proxy", err_msg, "BLOCKED"))
                return None, JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"error": "Unauthorized", "message": err_msg})
    elif REQUIRE_EXTERNAL_AUTH:
        err_msg = "Missing Authorization header"
        asyncio.create_task(log_telemetry(get_unverified_claims(request), "Authentication", "Proxy", err_msg, "BLOCKED"))
        return None, JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"error": "Unauthorized", "message": err_msg})
    
    return None, None

# --- 4. Global Telemetry Middleware ---
@app.middleware("http")
async def global_telemetry_logger(request: Request, call_next):
    response = await call_next(request)
    if response.status_code in [404, 405]:
        claims = get_unverified_claims(request)
        asyncio.create_task(log_telemetry(claims, f"INVALID_ROUTE: {request.url.path}", "Sidecar Edge", f"{response.status_code} - Invalid route", "BLOCKED"))
    return response

# --- 5. SSE Handshake Forwarder ---
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

# --- 6. Facade JSON-RPC Forwarder ---
@app.post("/messages/")
async def mcp_message_forwarder(request: Request):
    body = await request.json()
    
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
                    asyncio.create_task(log_telemetry(get_unverified_claims(request), "Auth", "Proxy", f"Key Exchange Failed: {e.detail}", "BLOCKED"))
                    return JSONResponse(status_code=e.status_code, content={"error": "Security violation", "message": e.detail})
            else:
                token = raw_key
    if not token:
        asyncio.create_task(log_telemetry({}, "Auth", "Proxy", "Missing API Key", "BLOCKED"))
        return JSONResponse(status_code=401, content={"error": "Unauthorized", "message": "API Key required."})

    caller_identity, error_response = extract_and_validate_external_identity(request)
    if error_response:
        return error_response

    try:
        claims = verify_and_decode_token(token)
    except HTTPException as e:
        asyncio.create_task(log_telemetry(get_unverified_claims(request), "Capability Breach", "Proxy", e.detail, "BLOCKED"))
        return JSONResponse(status_code=e.status_code, content={"error": "Security violation", "message": e.detail})

    pinned_sub = claims.get("sub")
    if pinned_sub and EXTERNAL_IDP_SECRET and caller_identity:
        if pinned_sub != caller_identity:
            err_msg = f"IBCT pinned to '{pinned_sub}', invoked by '{caller_identity}'"
            asyncio.create_task(log_telemetry(claims, "Auth", "Proxy", f"Capability Theft: {err_msg}", "BLOCKED"))
            return JSONResponse(status_code=403, content={"error": "Capability Theft Detected", "message": err_msg})

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
            return JSONResponse(status_code=422, content={"error": "Aegis Containment Breach", "validation_error": e.message})

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
        response = await http_client.post(target_url, json=body, params=request.query_params, headers=headers_to_forward)
        return Response(content=response.content, status_code=response.status_code, headers=dict(response.headers))
    except httpx.RequestError as e:
        asyncio.create_task(log_telemetry(claims, "Network", "Target API", f"Infrastructure Error: {str(e)}", "ERROR"))
        return JSONResponse(status_code=502, content={"error": "Infrastructure Error", "message": str(e)})

# --- 7. Universal Validation Interceptor ---
@app.post("/mcp/v1/tools/call")
async def intercept_tool_call(request: Request):
    token = request.headers.get("X-Aegis-IBCT")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
    if not token:
        err_msg = "X-Aegis-IBCT or Bearer Token required"
        asyncio.create_task(log_telemetry({}, "Authentication", "Proxy", err_msg, "BLOCKED"))
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"error": "Missing Security Context", "message": err_msg})

    caller_identity, error_response = extract_and_validate_external_identity(request)
    if error_response:
        return error_response

    try:
        claims = verify_and_decode_token(token)
    except HTTPException as e:
        asyncio.create_task(log_telemetry(get_unverified_claims(request), "Capability Verification", "Proxy", e.detail, "BLOCKED"))
        return JSONResponse(status_code=e.status_code, content={"error": "Capability Breach", "message": e.detail})

    pinned_sub = claims.get("sub")
    if pinned_sub and EXTERNAL_IDP_SECRET and caller_identity:
        if pinned_sub != caller_identity:
            err_msg = f"IBCT pinned to '{pinned_sub}', invoked by '{caller_identity}'"
            asyncio.create_task(log_telemetry(claims, "Authentication", "Proxy", f"Capability Theft Detected: {err_msg}", "BLOCKED"))
            return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"error": "Capability Theft Detected", "message": err_msg})

    allowed_scopes = claims.get("allowed_scopes", [])
    schema_bounds = claims.get("schema_bounds", {})

    try:
        body = await request.json()
    except json.JSONDecodeError:
        asyncio.create_task(log_telemetry(claims, "Payload Processing", "Proxy", "Malformed JSON", "BLOCKED"))
        return JSONResponse(status_code=400, content={"error": "Invalid payload", "message": "Malformed JSON"})

    params = body.get("params") or body
    tool_name = params.get("name")
    tool_arguments = params.get("arguments", {})

    if not tool_name:
        asyncio.create_task(log_telemetry(claims, "Payload Processing", "Proxy", "Missing target tool name", "BLOCKED"))
        return JSONResponse(status_code=400, content={"error": "Invalid protocol", "message": "Missing target tool name"})

    if tool_name not in allowed_scopes:
        err_msg = f"Tool '{tool_name}' not in allowed scopes"
        asyncio.create_task(log_telemetry(claims, tool_name, "Target API", f"Scope Violation: {err_msg}", "BLOCKED"))
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"error": "Scope Violation", "message": err_msg})

    tool_schema = schema_bounds.get(tool_name)
    if not tool_schema:
        err_msg = f"No Schema Bounds for '{tool_name}'"
        asyncio.create_task(log_telemetry(claims, tool_name, "Target API", f"Policy Misconfiguration: {err_msg}", "BLOCKED"))
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"error": "Policy Misconfiguration", "message": err_msg})

    try:
        validate(instance=tool_arguments, schema=tool_schema)
    except ValidationError as e:
        asyncio.create_task(log_telemetry(claims, tool_name, tool_arguments, f"Schema breach: {e.message}", "BLOCKED"))
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"error": "Aegis Containment Breach", "validation_error": e.message})

    asyncio.create_task(log_telemetry(claims, tool_name, tool_arguments, "Mathematical bounds verified", "ALLOWED"))

    global http_client
    headers_to_forward = {"Content-Type": "application/json"}
    if caller_identity:
        headers_to_forward["x-aegis-identity"] = caller_identity
    elif claims.get("agent_id"):
        headers_to_forward["x-aegis-identity"] = claims.get("agent_id")
        
    if request.headers.get("x-correlation-id"):
        headers_to_forward["x-correlation-id"] = request.headers.get("x-correlation-id")

    try:
        response = await http_client.post(f"{TARGET_MCP_URL}/mcp/v1/tools/call", json=body, headers=headers_to_forward)
        return Response(content=response.content, status_code=response.status_code, headers=dict(response.headers))
    except httpx.RequestError as e:
        asyncio.create_task(log_telemetry(claims, tool_name, "Target API", f"Infrastructure Error: {str(e)}", "ERROR"))
        return JSONResponse(status_code=502, content={"error": "Infrastructure Error", "message": str(e)})
