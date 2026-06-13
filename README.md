# Aegis MCP Sidecar | Deterministic Authorization for AI Agents

**Zero-Latency, Zero-Trust protection for the Model Context Protocol (MCP).**

Deploy autonomous AI agents with cryptographically enforced permissions.

## ⚠️ The Problem
Organizations increasingly want AI agents to perform real actions: query databases, execute workflows, manage infrastructure, and interact with internal tools.

The challenge is not generating actions.

The challenge is trusting those actions.

Most AI systems rely on prompt-level instructions and application-layer guardrails. As agents gain access to production systems, teams need deterministic controls that define exactly what an agent is allowed to do.

## 🛡️ The Solution: Offline Asymmetric Verification
Aegis is a stateless authorization sidecar for the Model Context Protocol (MCP).

Instead of trusting the LLM, Aegis evaluates every tool invocation at the network edge using cryptographic identity verification and policy enforcement.

The sidecar sits in front of any MCP server and enforces explicit permissions before actions are executed.

This enables organizations to safely move from AI assistants to AI operators.

**Core Architecture:**
- Ed25519 Identity-Bound Capability Tokens (IBCTs)
- Stateless edge authorization
- Dynamic JSON-Schema policy enforcement
- Tool-agnostic MCP compatibility
- Offline verification (<2ms)
- No runtime dependency on external authorization services


**Why It Matters:**
Without deterministic authorization, organizations often keep agents trapped behind human approval workflows.

Aegis provides a cryptographically enforced control layer that allows teams to safely grant agents access to real-world tools and infrastructure while maintaining strict operational boundaries.


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
