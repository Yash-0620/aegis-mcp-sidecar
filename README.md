# Aegis MCP Sidecar | Stateless Cryptographic Edge Proxy

**Zero-Latency, Zero-Trust protection for the Model Context Protocol (MCP).**

## ⚠️ The Threat Vector
By default, MCP servers lack inherent Identity and Access Management (IAM). They blindly trust local traffic on port 8000. If an LLM is hijacked via prompt injection (or simply hallucinates), it has unfettered access to execute destructive functions, access local filesystems, or exfiltrate PII.

## 🛡️ The Solution: Offline Asymmetric Verification
The Aegis Sidecar is a hyper-lightweight, stateless Docker proxy that sits in front of your MCP server. It utilizes an **Ed25519 Public Key** to mathematically verify Invocation-Bound Capability Tokens (IBCTs) directly at the network edge. 

**The Technical Moat:**
- **Zero Cloud Latency:** Payloads are mathematically verified offline in `<2ms`. No external HTTP calls to a centralized server are made during execution.
- **Deep Payload Inspection:** The proxy decrypts JSON-RPC payloads and enforces granular constraints (e.g., limiting Stripe refunds to under $500, restricting filesystem access to `.txt` files).
- **Total Data Privacy:** Your enterprise LLM traffic never leaves your local network.

---

## 🚀 Zero-Code Deployment

DevOps teams can deploy Aegis via a frictionless, 3-line drop-in solution to any existing Docker stack.

### 1. Define Policies & Get Your API Key
Before deploying the sidecar, head to the **[Aegis Cloud Console](https://aegis-cloud-console.vercel.app/)**. Create your free account, configure your agent's cryptographic bounds, and generate your API Key. 

*(Note: Aegis utilizes a decentralized architecture. The Cloud Console issues the tokens via the **[Control Plane](https://github.com/your-org/aegis-control-plane.git)**, and this Sidecar strictly enforces them).*

### 2. Update your `docker-compose.yml`
```yaml
services:
  # Your existing vulnerable MCP Server
  target-mcp:
    image: python:3.11-slim
    command: python -m http.server 8000

  # The Aegis Edge Proxy (Drop-in)
  aegis-sidecar:
    image: aegis-mcp-sidecar:latest
    ports:
      - "8080:8080"
    environment:
      - TARGET_MCP_URL=http://target-mcp:8000
    depends_on:
      - target-mcp
```

### 3. Lock Down the Network
By exposing only port `8080` (Aegis) and hiding port `8000` (MCP) inside the internal Docker network, unauthenticated LLMs physically cannot reach the target tools without a cryptographically signed token.

```bash
docker-compose up --build -d
```

---

## ⚔️ Chaos Engineering & Battle Testing

This architecture is built for high-throughput, cross-tenant isolation. We publicly document our testing suites to prove mathematical resilience. Check the `/tests` directory for:

- `swarm_test.py`: Unleashes a 10-agent concurrent swarm to verify isolated thread contexts and 2ms response blockages.
- `rogue_agent.py`: Simulates active prompt injections, unauthenticated network strikes, and massive out-of-bounds parameter hallucinations (e.g., attempting a $50,000 refund).

### Example: Running a Rogue Agent Strike
```bash
python tests/rogue_agent.py

# Expected Output:
# --- FIRING HIJACKED AGENT STRIKE ---
# Target: Stripe Refund | Attempted Amount: $50,000
# Status: 403
# Aegis Edge Proxy Response: Mathematical Bound Exceeded ($500 limit)
```
