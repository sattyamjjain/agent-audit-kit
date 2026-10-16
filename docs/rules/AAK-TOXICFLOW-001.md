# AAK-TOXICFLOW-001

**Toxic flow: sensitive source paired with external sink**

| Field | Value |
|---|---|
| Severity | HIGH |
| Category | `TOOL_POISONING` |
| Shipped | v0.3.5 (2026-04-25) — **feature-flagged** |
| Scanner | `agent_audit_kit/scanners/toxic_flow.py` |
| Data | `agent_audit_kit/data/toxic_flow_pairs.yml` |
| OWASP MCP | none |
| OWASP Agentic | ASI02 (Tool Misuse and Exploitation) |
| AICM | AIS-12, CCC-08 |
| Origin | [Snyk Agent Scan](https://github.com/snyk/agent-scan) parity |

## Feature-flag status

This rule is **off by default**. Set `AAK_TOXIC_FLOW=1` in the
environment to opt in. It pairs sources and sinks from a static list,
so it over-reports on a project that legitimately does both; the
deny-graph design review that would replace the list has not happened.

## What it catches

An agent project exposes both a sensitive source tool (filesystem
read, secrets read, database query) and an external sink tool
(HTTP POST, email send, git push, shell exec). Even if each tool is
individually safe, the LLM can chain them — the canonical exfiltration
pattern is `read_file -> http.post`.

The scanner builds a per-scan tool graph from:

- MCP server names + arg strings in `.mcp.json` /
  `.cursor/mcp.json` / `.vscode/mcp.json` / `.amazonq/mcp.json` /
  `mcp.json`
- Function names of `@tool` / `@mcp.tool` / `@server.tool` decorated
  Python functions in the repo, bare or with empty parentheses

A pair is reported against the config that declared its first configured
tool or, when every tool in it is a repo function, at the `def` of its
first tool.

Tool identifiers are matched against `agent_audit_kit/data/toxic_flow_pairs.yml`
which lists known source families (`fs_read`, `secrets_read`,
`db_query`) and sink families (`http_post`, `email_send`, `git_push`,
`shell_exec`) plus the pairs that fire.

## Suppression

Add the source/sink pair to `.aak-toxic-flow-trust.yml` with a
non-empty `justification:`:

```yaml
trust:
  - source: fs_read
    sink: http_post
    justification: "Documented data-export feature; sink is allow-listed in egress proxy."
```

A trust entry without a justification does **not** suppress (we want
the audit trail to carry the reason, not just the decision).

## What it does NOT catch

- Implicit toxic flows where the LLM bridges two non-tool capabilities
  (e.g. system-prompt context + a shell pipe). Prompt-level controls
  belong elsewhere.
- Pairs not yet enumerated in `toxic_flow_pairs.yml`. Submit a PR
  with the new family + cite the canonical incident.
- Tools declared in other languages (TS / Java / Rust): only Python
  decorators are read.

## Remediation

Three knobs, in priority order:

1. **Remove the pairing.** Drop the source or the sink if the agent
   does not actually need both at once.
2. **Scope the source.** Restrict `fs_read` / `db_query` to a
   directory or schema the sink cannot reach.
3. **Allow-list with justification.** Add the pair to
   `.aak-toxic-flow-trust.yml` and document the egress controls that
   make the chain safe.
