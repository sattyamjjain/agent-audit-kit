# AAK-AZURE-MCP-001

**Azure MCP server consumed without authentication**

| Field | Value |
|---|---|
| Severity | HIGH |
| Category | `MCP_CONFIG` |
| Shipped | v0.3.5 (2026-04-25) |
| Scanner | `agent_audit_kit/scanners/supply_chain.py` (extension) |
| CWE | CWE-306 (Missing Authentication for Critical Function) |
| OWASP MCP | MCP02:2025 |
| OWASP Agentic | ASI04 |
| AICM | IAM-01, IAM-16 |
| CVE | [CVE-2026-32211](https://dev.to/michael_onyekwere/cve-2026-32211-what-the-azure-mcp-server-flaw-means-for-your-agent-security-14db) (CVSS 9.1) |
| Incident | MSRC-2026-04-03-AZUREMCP |

## What it catches

An `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`,
`.amazonq/mcp.json`, `mcp.json`, or any file under `.azure-mcp/`
references an Azure MCP endpoint (host matches `*.azure.com`,
`*.azurewebsites.net`, `*.cognitiveservices.azure.com`,
`*.openai.azure.com`, or contains `azure-mcp` / `azure_mcp`) without
one of the recognised auth markers:

- `Authorization` header
- `client_certificate` / `client_cert` / `mtls` marker
- `api_key` / `x-functions-key` field
- `DefaultAzureCredential` / `ManagedIdentity` / `WorkloadIdentity`
- `azure_ad` / `bearer_token`

CVE-2026-32211 documented the server-side default of zero auth on the
MCP endpoint; downstream agents must add a transport-layer credential
or risk session-hijack / tool-impersonation by anyone reachable on the
network.

## What it does NOT catch

- Server-side AAK does not currently scan the Azure MCP server's own
  config — the consumer-side check above is the load-bearing
  detection. Server operators should bump to the patched version per
  the MSRC advisory.
- `.mcp.json` files that build the auth header at runtime via
  `headers_from_env: true` or similar non-standard schemes — the
  scanner cannot prove a header arrives at request time. Add an
  explicit `Authorization` placeholder in the JSON to silence.

## Remediation

Add an `Authorization` header sourced from a managed identity token,
mTLS cert, or vault-issued API key:

```json
{
  "mcpServers": {
    "azure-data": {
      "url": "https://my-mcp.azurewebsites.net/mcp",
      "transport": "http",
      "headers": {
        "Authorization": "Bearer ${AZURE_AD_TOKEN}"
      }
    }
  }
}
```

For production deployments, prefer Azure-AD managed identities or
workload-identity federation over static API keys.
