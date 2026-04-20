# AgentAuditKit rule schema

The rule schema is versioned so consumers (SARIF, `rules.json`, PR
summaries, external dashboards) can stay compatible as new fields land.

Current version: **`SCHEMA_VERSION = 2`** (v0.3.2, 2026-04-20).

Each v0.3.0 release bumps `SCHEMA_VERSION` when — and only when —
`RuleDefinition` grows new structured fields. Unknown fields must be
tolerated by older readers.

## Stable fields (v1)

| Field | Type | Notes |
|---|---|---|
| `rule_id` | `str` | Primary key, `AAK-XXX-NNN`. |
| `title` | `str` | One-line human headline. |
| `description` | `str` | One-paragraph rationale. |
| `severity` | `"critical" \| "high" \| "medium" \| "low" \| "info"` | |
| `category` | `str` | Free-form category code, e.g. `mcp-config`. |
| `remediation` | `str` | Actionable fix text shown in SARIF help. |
| `sarif_name` | `str` | PascalCase name used by GH Code Scanning. |
| `cve_references` | `list[str]` | `CVE-YYYY-NNNNN` entries. |
| `owasp_mcp_references` | `list[str]` | e.g. `MCP01:2025`. |
| `owasp_agentic_references` | `list[str]` | e.g. `ASI02` (OWASP Agentic Top 10 2026). |
| `adversa_references` | `list[str]` | Adversa AI MCP Top 25. |
| `auto_fixable` | `bool` | Whether `agent-audit-kit fix --cve` can auto-remediate. |

## v2 additions (v0.3.2)

| Field | Type | Notes |
|---|---|---|
| `incident_references` | `list[str]` | Incident IDs of the form `<VENDOR>-<DATE>`. Covers disclosed incidents that never got a CVE. Today: `VERCEL-2026-04-19`, `OX-MCP-2026-04-15`. |
| `aicm_references` | `list[str]` | CSA AI Controls Matrix control IDs. Consumed by `agent-audit-kit report --compliance aicm`. |

## SARIF tag encoding

Each non-empty reference list projects into a SARIF `rules[].properties.tags`
entry:

| Reference field | Tag prefix |
|---|---|
| `cve_references` | `CVE-YYYY-NNNNN` (as-is) |
| `owasp_agentic_references` | `OWASP-Agentic-<id>` |
| `adversa_references` | `Adversa-<id>` |
| `incident_references` | `incident-<id>` |
| `aicm_references` | `AICM-<id>` |

## Compatibility guarantees

- **Older readers** — must ignore unknown fields on the bundle. The
  canonical `rules.json` writer (`agent_audit_kit.bundle`) uses
  `dataclasses.asdict` so every field lands in the bundle.
- **Rule deletion** — never. Retire via a deprecation shim that re-maps
  to the replacement rule ID; the old ID must keep firing until the
  next major version.
- **Reference-list renames** — forbidden; add a new field instead and
  set `SCHEMA_VERSION += 1` in a release that carries both.
