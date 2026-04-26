# AAK-MCP-STDIO-CMD-INJ-001

**MCP `StdioServerParameters` built from network-controlled input (Python)**

| Field | Value |
|---|---|
| Severity | CRITICAL |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.3.6 (2026-04-26) |
| Scanner | `agent_audit_kit/scanners/mcp_stdio_params.py` |
| CWE | CWE-78 + CWE-77 |
| OWASP MCP | MCP01:2025, MCP05:2025 |
| OWASP Agentic | ASI02, ASI10 |
| AICM | AIS-08, IAM-05 |
| CVEs | CVE-2026-30615, 30617, 30623, 22252, 22688, 33224, 40933, 6980 |
| Incident | OX-MCP-2026-04-25 |

## What it catches

A Python function calls `StdioServerParameters(command=..., args=...)`
from `mcp.client.stdio` / `modelcontextprotocol.client` while also
reading from a network-controlled source (`request.json()`,
`flask.request.*`, `fastapi.Request.*`, `os.environ[<var>]`,
`json.loads(<network>)`, `yaml.safe_load(<network>)`). The OX MCP
April-2026 disclosure aggregated 8 CVEs to this exact shape: the SDK
executes whatever ends up in `command`/`args` verbatim.

This rule is the SDK-named-API config-side counterpart to
[AAK-STDIO-001](./AAK-STDIO-001.md), which detects the broader
`subprocess(shell=True)` sink shape. Both fire on overlapping inputs;
do not collapse them.

## Detection

The Python pass walks the AST and orders calls by source line so
`StdioServerParameters` invoked after a tainted source is detected even
when the validator and call are nested at different AST depths. Per
function:

1. Collect every `Call` node, sort by `(lineno, col_offset)`.
2. For each call, check if `_attr_chain(call.func)` ends in
   `StdioServerParameters`.
3. Scan the enclosing function source for any of:
   `request.(json|form|args|data|values|headers|files)`,
   `flask.request.*`, `fastapi.Request.*`,
   `requests.<verb>(...).json()`, `httpx.<verb>(...).json()`,
   `urllib.request.urlopen(`, `os.environ`, `json.loads`,
   `yaml.safe_load`, `yaml.load`.
4. If no marker fires, accept the cross-frame hint: function arg named
   `body` / `payload` / `req` / `request` / `event` / `data` / `config`.

## Remediation

Pin `command` to a constant binary path. Look up server choice in a
server-side allow-list keyed by tenant identity, never by a free-form
string in the request:

```python
ALLOWED_BINARIES = {"server-a": "/usr/bin/server-a", "server-b": "/usr/bin/server-b"}

def spawn(name: str) -> StdioServerParameters:
    if name not in ALLOWED_BINARIES:
        raise ValueError("not allowed")
    return StdioServerParameters(command=ALLOWED_BINARIES[name], args=[])
```

## Sister rules

- [AAK-MCP-STDIO-CMD-INJ-002](./AAK-MCP-STDIO-CMD-INJ-002.md) — TypeScript variant
- [AAK-MCP-STDIO-CMD-INJ-003](./AAK-MCP-STDIO-CMD-INJ-003.md) — Java variant
- [AAK-MCP-STDIO-CMD-INJ-004](./AAK-MCP-STDIO-CMD-INJ-004.md) — Rust variant (regex-only)
- [AAK-MCP-MARKETPLACE-CONFIG-FETCH-001](./AAK-MCP-MARKETPLACE-CONFIG-FETCH-001.md) — single-line marketplace-fetch shape
