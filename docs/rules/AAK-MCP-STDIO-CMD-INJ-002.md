# AAK-MCP-STDIO-CMD-INJ-002

**MCP `StdioClientTransport` built from network-controlled input (TypeScript)**

| Field | Value |
|---|---|
| Severity | CRITICAL |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.3.6 |
| Scanner | `agent_audit_kit/scanners/mcp_stdio_params.py` |
| CWE | CWE-78 + CWE-77 |
| Same metadata as | [AAK-MCP-STDIO-CMD-INJ-001](./AAK-MCP-STDIO-CMD-INJ-001.md) |

## What it catches

`new StdioClientTransport({ command, args })` from
`@modelcontextprotocol/sdk/client/stdio` constructed shortly after a
network-controlled source: `req.body`, `await fetch(...).then(...)`,
`process.env.<NETWORK_VAR>`, `JSON.parse(...)`.

## Detection

Regex-based: find every `new StdioClientTransport(` /
`new StdioServerTransport(`, look back 1KB for a taint marker
(`req.(body|query|params|headers)`, `await fetch(`, `await axios.`,
`process.env.[A-Z_]+`, `JSON.parse(`).

## Remediation

```typescript
const ALLOWED: Record<string, string> = {
  "server-a": "/usr/bin/server-a",
  "server-b": "/usr/bin/server-b",
};

export function spawnFromName(name: string) {
  const cmd = ALLOWED[name];
  if (!cmd) throw new Error("not allowed");
  return new StdioClientTransport({ command: cmd, args: [] });
}
```
