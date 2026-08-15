# State of MCP Security 2026 — coverage & corpus (report seed)

> **Seed, not the final report.** The coverage table below is generated from the
> committed rule registry (`agent-audit-kit --emit-coverage`); the corpus section
> is stubbed and cross-links the live data run. Regenerate with
> `python -c "from agent_audit_kit.output.coverage_map import render_json; open('docs/coverage.json','w').write(render_json())"`.

AgentAuditKit ships **<!-- rule-count:total -->304<!-- /rule-count --> deterministic rules**,
each mapped — rule by rule — to the framework control it evidences. The full,
machine-readable crosswalk is [`docs/coverage.json`](coverage.json); the live
per-framework counts (severity, OWASP MCP Top-10, OWASP Agentic Top-10 2026, NSA
MCP CSI, EU AI Act, CVEs covered) come from there so this doc never drifts.

## Coverage, mapped to frameworks

```bash
agent-audit-kit --emit-coverage --format md    # human table
agent-audit-kit --emit-coverage --format json  # == docs/coverage.json
```

Every rule carries: `id`, `title`, `severity`, the **CVE(s)** it covers, its
**OWASP MCP Top-10 (2025)** slot, its **OWASP Agentic Top-10 (2026)** slot, the
**NSA MCP Security CSI** control (U/OO/6030316-26, 2026-05-20) it evidences, and
the **EU AI Act** article it maps to. `docs/coverage.json` groups and counts by
each framework. The NSA-CSI + OWASP-Agentic view is also in
[`docs/crosswalk/nsa-csi-owasp-agentic.md`](crosswalk/nsa-csi-owasp-agentic.md).

## We scanned N public MCP servers — here is what breaks

A reproducible, offline data run over **2,303 distinct public MCP server configs**
(a GitHub crawl plus the official MCP Registry's latest-version servers, deduped by
content) already exists — see
[`research/state-of-mcp-2026/REPORT.md`](../research/state-of-mcp-2026/REPORT.md)
and the raw [`results.json`](../research/state-of-mcp-2026/results.json). Headline
from that run: **52.3% (1,205/2,303) declare a remote server with no authentication,
0% use RFC 9728 Protected-Resource-Metadata discovery, and 100% (421/421) of
inline-auth remote configs hardcode a static credential.**

> **Stub for the next corpus run.** Re-run the harness and drop the refreshed
> "what breaks" table here: top misconfigurations by config-hit-rate, grade
> distribution (A–F), auth-posture split (no-auth / bearer / OAuth 2.1 / unknown),
> and transport split (stdio / SSE / streamable-HTTP). The frozen baseline for
> before/after is [`mcp-security-baseline-v1.0`](research/mcp-security-baseline-v1.0.md).

## Evidence anchors (verified live 2026-07-24)

- **MCP final spec, 2026-07-28** — the largest revision since launch: stateless
  core (removes `initialize` + `Mcp-Session-Id`), per-request `_meta` metadata
  transport, MCP Apps (server-rendered HTML in a sandboxed iframe), the Tasks
  extension (tool calls answered with task handles), and full JSON Schema 2020-12
  tool schemas. [RC announcement](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/).
- **NSA MCP Security CSI** — *Model Context Protocol (MCP): Security Design
  Considerations for AI-Driven Automation*, U/OO/6030316-26 (NSA AISC, 2026-05-20).
  All 9 recommendation sections are crosswalked in `docs/coverage.json`.
- **CVE-2026-35394** — `mobile-mcp` < 0.0.50: `mobile_open_url` passes a
  caller-supplied URL to Android's intent system with no scheme validation →
  arbitrary intents (USSD, calls, SMS, content-provider access). NVD **8.8 HIGH**.
  Fixed 0.0.50.
- **CVE-2026-25536** — `@modelcontextprotocol/sdk` (TypeScript) 1.10.0–1.25.3:
  cross-client response-data leak when one `Server`/transport instance is reused
  across connections (stateless `StreamableHTTPServerTransport`). NVD **7.1 HIGH**.
  Fixed 1.26.0.
- **CVE-2026-12957** — Amazon Q Developer auto-loaded `.amazonq/mcp.json` from an
  opened repository and launched its MCP servers with the developer's full
  environment → code execution + AWS credential theft (Wiz, 2026-06-26). CVSS
  **8.5**; fixed in language server 1.65.0 (adds a consent prompt). AAK already
  scans `.amazonq/mcp.json` for exactly this untrusted-config class.

*(Deliberately not anchored: CVE-2026-65056 — not NVD-verifiable as of the
2026-07-23 triage note.)*

## 2026-07-28 MCP-final surfaces — crosswalk status

The crosswalk reserves a slot for each 2026-07-28 surface so a rule slots in
without a schema change. Slots and their live status are in
`docs/coverage.json` → `reserved_surfaces_2026_07_28`:

| Surface | Reference | Status |
|---------|-----------|--------|
| Stateless `_meta`-per-request | MCP final 2026-07-28 (metadata transport) | **reserved** (no rule yet) |
| MCP Apps sandboxed iframes | SEP-1865 | **covered** (`AAK-MCP-APPS-001/002`) |
| Tasks handles | SEP-2663 | **covered** (`AAK-TASKS-001..004`) |
| JSON-Schema-2020-12 tool schemas | MCP final 2026-07-28 | **reserved** (no rule yet) |

No rules are invented for the reserved surfaces here — the slots are reserved so
the crosswalk is ready when detection lands.
