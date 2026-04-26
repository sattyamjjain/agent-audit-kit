# AAK-MCP-MARKETPLACE-CONFIG-FETCH-001

**MCP server config fetched from a marketplace URL and spawned**

| Field | Value |
|---|---|
| Severity | CRITICAL |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.3.6 (2026-04-26) |
| Scanner | `agent_audit_kit/scanners/mcp_marketplace_fetch.py` |
| CWE | CWE-829 + CWE-78 |
| OWASP MCP | MCP05:2025, MCP09:2025 |
| OWASP Agentic | ASI10 |
| AICM | AIS-08, STA-02 |
| Incidents | OX-MCP-2026-04-25, CLOUDFLARE-MCP-DEFENDER-2026-04-25 |

## What it catches

A function fetches a remote URL (`requests.get`, `httpx.get`,
`urllib.request.urlopen`, `fetch`) and pipes the JSON / text return
value into `StdioServerParameters(...)` /
`new StdioClientTransport({...})` in the same function or one frame
deep.

Cloudflare's MCP-defender reframe (2026-04-25) called this out as the
highest-risk single-line bug in the wild. A marketplace compromise
becomes client-side RCE on every consumer at the next refresh.

## Detection

Python AST:

1. For each function, collect calls sorted by source line.
2. First fetch-call (`requests`/`httpx`/`urllib`/`urlopen`) sets a
   `fetch_seen` flag and captures the URL constant if any.
3. A subsequent `StdioServerParameters` / `StdioClientTransport` call
   in the same function fires the rule.

TypeScript: regex pass for `await fetch(...)` followed within 2KB by
`new Stdio*Transport`.

## Suppression

Add to `.aak-mcp-marketplace-trust.yml`:

```yaml
trust:
  - url: "https://internal-registry.corp.example/mcp/manifest"
    justification: "Internal artifact registry; signatures verified separately."
```

Trust entries without a non-empty `justification:` do **not** suppress.

## Remediation

Cache the response, sign it, verify the signature on load, and pin
`command` to a constant binary path regardless of what the manifest
says:

```python
def load_pinned() -> StdioServerParameters:
    return StdioServerParameters(command="/usr/bin/server-a", args=[])
```
