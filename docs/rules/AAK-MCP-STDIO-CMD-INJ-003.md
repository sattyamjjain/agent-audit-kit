# AAK-MCP-STDIO-CMD-INJ-003

**MCP `StdioServerParameters.Builder()` built from network-controlled input (Java)**

| Field | Value |
|---|---|
| Severity | CRITICAL |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.3.6 |
| Scanner | `agent_audit_kit/scanners/mcp_stdio_params.py` (regex pass) |
| Same metadata as | [AAK-MCP-STDIO-CMD-INJ-001](./AAK-MCP-STDIO-CMD-INJ-001.md) |

## What it catches

`StdioServerParameters.Builder().command(...).args(...).build()` from
`io.modelcontextprotocol.sdk.client.stdio` after a network-controlled
source: `request.getParameter(`, `HttpServletRequest`,
`RestTemplate.getForObject(`, `WebClient.<verb>(`,
`new ObjectMapper().readValue(`, `System.getenv(`.

## Detection

Match `StdioServerParameters.Builder()` opener; require `.build()`
within the next 4KB (chain confirmed); look back 2KB **and** scan the
forward chain for a taint marker. Nested-paren handling is bypassed by
splitting the regex into opener + terminator + window scan.

## Remediation

```java
private static final Map<String, String> ALLOWED =
    Map.of("server-a", "/usr/bin/server-a");

public StdioServerParameters spawn(String name) {
    String cmd = ALLOWED.get(name);
    if (cmd == null) throw new IllegalArgumentException("not allowed");
    return StdioServerParameters.Builder()
            .command(cmd)
            .args(new String[]{})
            .build();
}
```
