# AAK-AZURE-MCP-NOAUTH-001

**Azure MCP server published without auth middleware on `/mcp/*` routes**

| Field | Value |
|---|---|
| Severity | HIGH |
| Category | `MCP_CONFIG` |
| Shipped | v0.3.6 |
| Scanner | `agent_audit_kit/scanners/mcp_server_auth.py` |
| CWE | CWE-306 |
| OWASP MCP | MCP02:2025 |
| OWASP Agentic | ASI04 |
| AICM | IAM-01, IAM-16 |
| CVE | CVE-2026-32211 (CVSS 9.1) |
| Sister rule | [AAK-AZURE-MCP-001](./AAK-AZURE-MCP-001.md) (consumer-side) |

## What it catches

Repository publishes an Azure-MCP-shaped server (`@azure/mcp-server`,
`azure-mcp-server` Python package, or `mcp-server-azure` keywords in
`pyproject.toml` / `package.json`) and exposes one or more `/mcp/*`
route handlers (FastAPI / Flask / Express / Fastify / Hono) without an
auth marker (`@require_auth`, `verify_jwt`, `DefaultAzureCredential`,
`Authorization` header check, mTLS, `passport.authenticate`,
`bearerStrategy`) anywhere in the same file.

## Why a sister rule

v0.3.5's AAK-AZURE-MCP-001 detects the *consumer* side: agents whose
`.mcp.json` points at an Azure MCP endpoint without auth. This rule is
the upstream pair so server authors ship secure defaults.

## Remediation

Add an auth middleware to every `/mcp/*` route:

```python
from fastapi import FastAPI, Header

app = FastAPI()

@app.post("/mcp/tools/run")
async def run_tool(payload: dict, Authorization: str = Header(...)) -> dict:
    verify_jwt(Authorization)
    return {"ok": True, "result": payload}
```

Reject unauthenticated requests with HTTP 401 *before* dispatching to
the MCP handler. Prefer Azure-AD managed identities or workload
identity federation over static API keys.
