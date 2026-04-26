# AAK-MCP-STDIO-CMD-INJ-004

**MCP STDIO `Command::new(...)` from network-controlled input (Rust)**

| Field | Value |
|---|---|
| Severity | CRITICAL |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.3.6 |
| Scanner | `agent_audit_kit/scanners/mcp_stdio_params.py` (regex pass) |
| Same metadata as | [AAK-MCP-STDIO-CMD-INJ-001](./AAK-MCP-STDIO-CMD-INJ-001.md) |

## Caveat

**Regex-only pass until #22 lands tree-sitter-rust.** Expect ~10%
false-positive rate on macro-heavy codebases. Document false positives
on the issue tracker so the AST migration test corpus grows.

## What it catches

`tokio::process::Command::new(...)` or `std::process::Command::new(...)`
(or bare `Command::new(...)` when the file `use`-imports them) inside
a module that imports `mcp_sdk` / `modelcontextprotocol` /
`mcp::client::stdio` after a network-controlled source: `reqwest::get`,
`reqwest::Client`, `serde_json::from_str`, `serde_json::from_slice`,
`std::env::var`, `hyper::body`, `actix_web::web::Json`,
`axum::extract::Json`.

## Detection

Three steps:

1. File must import an MCP SDK (`mcp_sdk` / `modelcontextprotocol` /
   `mcp::client::stdio`).
2. File must have at least one `Command::new(...)` (qualified or bare
   with a matching `use` declaration).
3. Look back 2KB from the `Command::new(...)` for a taint marker.

## Remediation

```rust
use tokio::process::Command;

pub fn spawn_pinned() -> Command {
    Command::new("/usr/bin/server-a")
}
```
