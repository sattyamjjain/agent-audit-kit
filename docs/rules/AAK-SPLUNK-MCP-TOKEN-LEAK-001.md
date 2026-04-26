# AAK-SPLUNK-MCP-TOKEN-LEAK-001

**`splunk-mcp-server` configured to write tokens to `_internal` / `_audit`**

| Field | Value |
|---|---|
| Severity | HIGH |
| Category | `SECRET_EXPOSURE` |
| Shipped | v0.3.6 |
| Scanner | `agent_audit_kit/scanners/splunk_mcp_config.py` |
| CWE | CWE-532 + CWE-200 |
| OWASP MCP | MCP08:2025 |
| OWASP Agentic | ASI04 |
| CVE | CVE-2026-20205 (config variant) |

## What it catches

Distinct from v0.3.4's
[AAK-SPLUNK-TOKLOG-001](./AAK-SPLUNK-TOKLOG-001.md) which detects
token-shaped values flowing into log sinks at runtime. This rule fires
on the *configuration* that makes the runtime leak inevitable: a
`splunk-mcp-server` config file (`inputs.conf`, `splunk-mcp.yaml`,
or any file under `splunk-mcp/`) that routes a token-bearing
sourcetype (`splunk_session`, `mcp_auth`, `bearer`, `access_token`,
`session_token`, `jwt`) into the `_internal`, `_audit`, or
`_introspection` index.

## Detection

Two passes — files matching `splunk-mcp-*` paths get both:

1. **YAML structured pass.** `yaml.safe_load`, walk
   `inputs[]`/`sourcetypes[]`, fire when an entry pairs a token-bearing
   sourcetype with `_internal` / `_audit` / `_introspection`.
2. **Line-pair regex pass.** `sourcetype = splunk_session` AND
   `index = _internal` (or any of the two regexes) anywhere in the
   file. Catches `inputs.conf`-format files and mixed YAML.

## Remediation

```yaml
inputs:
  - sourcetype: mcp_session_redacted     # not splunk_session
    index: mcp_audit                      # not _internal
    path: /var/log/mcp/session.log
```

Route token-bearing inputs through a redaction stage before the Splunk
forwarder. Bump `splunk-mcp-server >= 1.0.3`.
