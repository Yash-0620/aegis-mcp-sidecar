# Aegis MCP Sidecar | Stateless Cryptographic Edge Proxy

**Zero-Latency, Zero-Trust protection for the Model Context Protocol (MCP).**

## ⚠️ The Threat Vector
By default, MCP servers lack inherent Identity and Access Management (IAM). They blindly trust local traffic on port 8000. If an LLM is hijacked via prompt injection (or simply hallucinates), it has unfettered access to execute destructive functions, access local filesystems, or exfiltrate PII.

## 🛡️ The Solution: Offline Asymmetric Verification
The Aegis Sidecar is a hyper-lightweight, stateless Docker proxy that sits in front of your MCP server. It utilizes an **Ed25519 Public Key** to mathematically verify Invocation-Bound Capability Tokens (IBCTs) directly at the network edge. 

**The Technical Moat:**
- **Zero Cloud Latency:** Payloads are mathematically verified offline in `<2ms`. No external HTTP calls to a centralized server are made during execution.
- **Dynamic JSON-Schema Bounding:** The proxy is 100% tool-agnostic. It decrypts JSON-RPC payloads and strictly evaluates the mathematical shape, regex patterns, and numeric limits of the request against the CISO's universal JSON-Schema.
- **Total Data Privacy:** Your enterprise LLM traffic never leaves your local network.

---

## 🚀 Zero-Code Deployment

DevOps teams can deploy Aegis via a frictionless drop-in solution to any existing Docker stack.

### 1. Define Policies & Get Your API Key
Before deploying the sidecar, head to the **[Aegis Cloud Console](https://aegis-cloud-console.vercel.app/)**. Create your free account, configure your dynamic JSON-Schema bounds, and generate your API Key. 

*(Note: Aegis utilizes a decentralized architecture. The Cloud Console issues the tokens via the **[Control Plane](https://github.com/Yash-0620/aegis-control-plane.git)**, and this Sidecar strictly enforces them).*

### 2. Update your `docker-compose.yml`
```yaml
version: '3.8'

services:
  # Your existing vulnerable MCP Server (Isolated)
  target-mcp:
    image: python:3.11-slim
    command: python -m http.server 8000
    networks:
      - aegis_secure_net

  # The Aegis Edge Proxy (Public Facing)
  aegis-sidecar:
    image: ghcr.io/yash-0620/aegis-mcp-sidecar:latest
    ports:
      - "8080:8080"
    environment:
      - TARGET_MCP_URL=http://target-mcp:8000
      - AEGIS_CONTROL_PLANE_URL=[https://aegis-live-node.onrender.com](https://aegis-live-node.onrender.com)
      - AEGIS_AGENT_ID=<YOUR_AEGIS_API_KEY>
    networks:
      - aegis_secure_net
    depends_on:
      - target-mcp

networks:
  aegis_secure_net:
    driver: bridge
```

### 3. Lock Down the Network
By exposing only port `8080` (Aegis) and hiding port `8000` (MCP) inside the internal Docker network, unauthenticated LLMs physically cannot reach the target tools without a cryptographically signed token.

```bash
docker-compose up --build -d
```

---

## ⚔️ Chaos Engineering & Battle Testing

This architecture is built for high-throughput, cross-tenant isolation. We publicly document our testing suites to prove mathematical resilience. Check the `/tests` directory for:

- `test_universal_actions.py: Unleashes a multi-agent concurrent swarm to verify isolated thread contexts and 2ms response blockages.
- `universal_e2e_test.py: Simulates active prompt injections, routing ghosts (404s), and out-of-bounds parameter hallucinations to verify the Universal JSON-Schema mathematical proxy.

### Example: Running a Rogue Agent Strike
```bash
python tests/test_universal_actions.py

# Expected Output:
# --- FIRING PAYLOAD TO SIDECAR ---
# 🛡️ BLOCKED (Status 422): Sidecar intercepted schema violation!
# Forensics: 'core-production-repo' does not match '^.*-dev-repo$'
# Attack ($500 Refund) -> Status: 403 | Result: DENIED
# Safe ($40 Refund) -> Status: 403 | Result: Sidecar Forwarded Payload
# Attack (Hallucinated Param) -> Status: 403 | Result: DENIED
```
