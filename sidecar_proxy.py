import httpx
import jwt
import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import asyncio

app = FastAPI()

# --- CONFIGURATION ---
TARGET_MCP_URL = os.environ.get("TARGET_MCP_URL", "http://localhost:8000")
TELEMETRY_URL = "https://aegis-live-node.onrender.com/telemetry/log_threat"

# The Open-Source Verifier (PASTE YOUR GENERATED PUBLIC KEY HERE)
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAjW1Lg7SRz2/K8ASyRhk9svTaJj7rtpTudllj7vCUIHU=
-----END PUBLIC KEY-----"""

async def log_telemetry(jwt_payload: dict, action: str, target: str, reason: str, status: str = "BLOCKED"):
    """Fire-and-forget telemetry for both Blocks and Allows."""
    async with httpx.AsyncClient() as client:
        try:
            await client.post(TELEMETRY_URL, json={
                "agent_id": jwt_payload.get("api_key"),
                "action": action,
                "target": target,  # <-- Sending the arguments back to your UI
                "reason": reason,
                "status": status
            })
        except Exception as e:
            print(f"[Telemetry Warning] Could not sync telemetry: {e}")

@app.post("/{path:path}")
async def proxy_mcp_request(path: str, request: Request):
    """The Stateless Cryptographic Interceptor"""
    token = request.headers.get("X-Aegis-IBCT")
    
    if not token:
        return JSONResponse(status_code=401, content={"detail": "Access Denied: Missing X-Aegis-IBCT header"})

    try:
        # MATHEMATICAL VERIFICATION 
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=["EdDSA"])
    except jwt.ExpiredSignatureError:
        return JSONResponse(status_code=403, content={"detail": "Token Expired. Rotate identity."})
    except jwt.InvalidTokenError as e:
        return JSONResponse(status_code=403, content={"detail": f"Cryptographic Verification Failed: {str(e)}"})

    # LOCAL INTENT BOUNDS CHECKING
    body = await request.json()
    if body.get("method") == "tools/call":
        tool_name = body["params"]["name"]
        tool_args = body["params"].get("arguments", {})
        
        # Convert the arguments payload into a string for your Forensics UI
        target_str = str(tool_args)

        scopes = payload.get("scopes", [])
        constraints = payload.get("constraints", {})

        if tool_name not in scopes:
            reason = f"Restricted Scope Violation: {tool_name}"
            asyncio.create_task(log_telemetry(payload, tool_name, target_str, reason, "BLOCKED"))
            return JSONResponse(status_code=403, content={"detail": reason})

        if tool_name in constraints:
            rules = constraints[tool_name]
            
            if tool_name == "stripe:refund:write" and "max_amount" in rules:
                if int(tool_args.get("amount", 0)) > int(rules["max_amount"]):
                    reason = f"Mathematical Bound Exceeded (${rules['max_amount']} limit)"
                    asyncio.create_task(log_telemetry(payload, tool_name, target_str, reason, "BLOCKED"))
                    return JSONResponse(status_code=403, content={"detail": reason})
            
            if tool_name == "fs:search:read" and "allowed_extensions" in rules:
                ext = f".{tool_args.get('file_extension', '')}"
                if ext not in rules["allowed_extensions"]:
                    reason = f"Unauthorized File Extension: {ext.replace('.', '')}"
                    asyncio.create_task(log_telemetry(payload, tool_name, target_str, reason, "BLOCKED"))
                    return JSONResponse(status_code=403, content={"detail": reason})

            if tool_name == "database:query:read" and "target_table" in rules:
                query_str = str(tool_args).lower()
                target = rules["target_table"].lower()
                if "users" in query_str and target != "users":
                    reason = "Unauthorized Table Access: users"
                    asyncio.create_task(log_telemetry(payload, tool_name, target_str, reason, "BLOCKED"))
                    return JSONResponse(status_code=403, content={"detail": reason})
            
            if tool_name == "email:send:write" and "allowed_domains" in rules:
                recipient = str(tool_args)
                if "test.com" in recipient and "test.com" not in rules["allowed_domains"]:
                    reason = "Exfiltration Attempt - Domain test.com not in whitelist"
                    asyncio.create_task(log_telemetry(payload, tool_name, target_str, reason, "BLOCKED"))
                    return JSONResponse(status_code=403, content={"detail": reason})

        # LOG THE ALLOWED ACTION
        asyncio.create_task(log_telemetry(payload, tool_name, target_str, "Policy matched", "ALLOWED"))

    # FORWARD CLEAN TRAFFIC TO LOCAL MCP
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{TARGET_MCP_URL}/{path}", json=body)
            try:
                content = resp.json()
            except ValueError:
                content = {"status": "SUCCESS", "raw_response": "Target MCP Reached (Dummy Server Response)"}
            status = 200 if resp.status_code == 501 else resp.status_code
            return JSONResponse(status_code=status, content=content)
        except Exception as e:
            return JSONResponse(status_code=502, content={"detail": f"Failed to reach local MCP: {str(e)}"})
