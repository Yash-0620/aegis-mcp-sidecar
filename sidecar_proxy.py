import json
import os
import jwt
from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
import httpx
from jsonschema import validate, ValidationError
import asyncio

app = FastAPI(title="Aegis Zero-Trust Universal Sidecar")

# --- 1. Embedded Trust Root ---
# As planned, the public key is hardcoded directly at the edge repository.
# Any token not signed by our control plane's matching private key fails instantly.
AEGIS_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAjW1Lg7SRz2/K8ASyRhk9svTaJj7rtpTudllj7vCUIHU=
-----END PUBLIC KEY-----"""

# The internal network address where the actual, unprotected MCP server is listening.
# This port is isolated and invisible to the outside network.
# --- CONFIGURATION ---
TARGET_MCP_URL = os.environ.get("TARGET_MCP_URL", "http://localhost:8000")
TELEMETRY_URL = "https://aegis-live-node.onrender.com/telemetry/log_threat"

# --- 2. The Cryptographic Bouncer Core ---
def verify_and_decode_token(token: str) -> dict:
    """
    Mathematically verifies the token signature at the edge using Ed25519.
    Zero network latency—no calls back to the control plane.
    """
    try:
        payload = jwt.decode(token, AEGIS_PUBLIC_KEY, algorithms=["EdDSA"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token signature has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=403, detail="Cryptographic signature verification failed")
    

async def log_telemetry(jwt_payload: dict, action: str, target: str, reason: str, status: str = "BLOCKED"):
    """Fire-and-forget telemetry for both Blocks and Allows."""
    async with httpx.AsyncClient() as client:
        try:
            await client.post(TELEMETRY_URL, json={
                "agent_id": jwt_payload.get("agent_id", "Unknown"), # Grabbing agent_id from the decoded token
                "action": action,
                "target": target,  
                "reason": reason,
                "status": status
            }, timeout=2.0)
        except Exception as e:
            print(f"[Telemetry Warning] Could not sync telemetry: {e}")

# --- 3. The Universal Validation Interceptor ---
@app.post("/mcp/v1/tools/call")
async def intercept_tool_call(request: Request):
    """
    Universal network-layer interceptor. Handles ANY tool call format
    by analyzing the mathematical shape of the JSON parameters.
    """
    # 1. Extract the Invocation-Bound Capability Token (IBCT)
    token = request.headers.get("X-Aegis-IBCT")
    if not token:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "Missing Security Context", "message": "X-Aegis-IBCT header required"}
        )

    # 2. Extract and cryptographically verify claims locally
    try:
        claims = verify_and_decode_token(token)
        agent_id = claims.get("agent_id", "Unknown-Agent")
    except HTTPException as e:
        return JSONResponse(status_code=e.status_code, content={"error": "Security violation", "message": e.detail})

    allowed_scopes = claims.get("allowed_scopes", [])
    schema_bounds = claims.get("schema_bounds", {})

    # 3. Parse the incoming JSON payload from the AI Agent
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse(status_code=400, content={"error": "Invalid payload", "message": "Malformed JSON request"})

    # Extract target tool details using standard MCP JSON-RPC mapping
    # Example format: { "method": "tools/call", "params": { "name": "github:repo:delete", "arguments": {...} } }
    params = body.get("params", {})
    tool_name = params.get("name")
    tool_arguments = params.get("arguments", {})

    if not tool_name:
        return JSONResponse(status_code=400, content={"error": "Invalid protocol", "message": "Missing target tool name"})

    # 4. Scope Guard: Is the AI Agent even permitted to talk to this tool?
    if tool_name not in allowed_scopes:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "Scope Violation", 
                "message": f"Agent identity lacks authorization scope for tool: '{tool_name}'"
            }
        )

    # 5. Schema Guard: Does the payload match the mathematical constraints?
    # Retrieve the specific JSON-Schema that the CISO applied to this scope
    tool_schema = schema_bounds.get(tool_name)
    
    if not tool_schema:
        # Fail-Closed Rule: If a scope is granted but no validation schema is present, deny execution.
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "Policy Misconfiguration", 
                "message": f"No JSON-Schema bounds defined for authorized scope: '{tool_name}'. Failing closed."
            }
        )

    try:
        # PURE MATHEMATICAL VALIDATION
        # Validates fields, data types, string minimum/maximum lengths, regex patterns, enum lists, and values.
        validate(instance=tool_arguments, schema=tool_schema)
    except ValidationError as e:
        # FIRE TELEMETRY: BLOCKED
        target_str = json.dumps(tool_arguments)[:200] # Safe capture of the attempted payload
        asyncio.create_task(log_telemetry(claims, tool_name, target_str, f"Schema breach: {e.message}", "BLOCKED"))
        
        # Bounded containment hit: The LLM attempted an action that violates the structural safety envelope.
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "Aegis Bounded Containment Breach",
                "message": "The AI tool payload structurally violated the CISO security schema.",
                "validation_error": e.message
            }
        )
    
        # FIRE TELEMETRY: ALLOWED
    target_str = json.dumps(tool_arguments)[:200]
    asyncio.create_task(log_telemetry(claims, tool_name, target_str, "Mathematical bounds verified", "ALLOWED"))

    # --- 6. Secure Routing ---
    # The payload is safe, authenticated, and structurally verified. Forward it to the target MCP Server.
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{TARGET_MCP_SERVER_URL}/mcp/v1/tools/call",
                json=body,
                headers={"Content-Type": "application/json"},
                timeout=5.0 # Keep latency overhead tight
            )
            return Response(content=response.content, status_code=response.status_code, headers=dict(response.headers))
        except httpx.RequestError as e:
            return JSONResponse(
                status_code=status.HTTP_502_BAD_GATEWAY,
                content={"error": "Infrastructure Error", "message": f"Could not route payload to target MCP server: {str(e)}"}
            )
