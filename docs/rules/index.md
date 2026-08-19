# Rule reference

Per-rule pages for the AAK rule registry. The canonical source of truth
is `agent_audit_kit/rules/builtin.py` — these pages exist to give
operators a click-through reference with the full description, the
remediation recipe, and the linked CVE/OWASP/AICM mapping.

The pages are written by hand for high-traffic rules (CVE-driven, public
SLA) and from `RuleDefinition` data for the rest. v0.3.5 ships the
first batch — expect coverage to fill in over subsequent releases.

## v0.3.84 (2026-08-19) — net-new

| Rule | Severity | Class | CVE / source |
|---|---|---|---|
| [AAK-COMPOSE-001](./skill-composition.md#aak-compose-001--an-ordered-path-to-egress-high) | HIGH | COMPOSITION | CompoSkill [arXiv:2608.16246](https://arxiv.org/abs/2608.16246) |
| [AAK-COMPOSE-002](./skill-composition.md#aak-compose-002--an-undeclared-shared-path-high) | HIGH | COMPOSITION | ColluSkill [arXiv:2608.09732](https://arxiv.org/abs/2608.09732) |
| [AAK-COMPOSE-003](./skill-composition.md#aak-compose-003--a-manifest-narrower-than-its-code-medium) | MEDIUM | COMPOSITION | CompoSkill [arXiv:2608.16246](https://arxiv.org/abs/2608.16246) |

## v0.3.43 (2026-07-04) — net-new

| Rule | Severity | Class | CVE / source |
|---|---|---|---|
| [AAK-MCP-AUTH-PATHTRAVERSAL-001](./AAK-MCP-AUTH-PATHTRAVERSAL-001.md) | CRITICAL | MCP_CONFIG | [CVE-2026-52830](https://nvd.nist.gov/vuln/detail/CVE-2026-52830) |

## v0.3.5 (2026-04-25) — net-new

| Rule | Severity | Class | CVE / source |
|---|---|---|---|
| [AAK-LANGCHAIN-SSRF-REDIR-001](./AAK-LANGCHAIN-SSRF-REDIR-001.md) | HIGH | TRANSPORT_SECURITY | [CVE-2026-41481](https://nvd.nist.gov/vuln/detail/CVE-2026-41481) |
| [AAK-SSRF-TOCTOU-001](./AAK-SSRF-TOCTOU-001.md) | MEDIUM | TRANSPORT_SECURITY | [CVE-2026-41488](https://nvd.nist.gov/vuln/detail/CVE-2026-41488) |
| [AAK-AZURE-MCP-001](./AAK-AZURE-MCP-001.md) | HIGH | MCP_CONFIG | [CVE-2026-32211](https://dev.to/michael_onyekwere/cve-2026-32211-what-the-azure-mcp-server-flaw-means-for-your-agent-security-14db) |
| [AAK-TOXICFLOW-001](./AAK-TOXICFLOW-001.md) | HIGH | TOOL_POISONING | Snyk Agent Scan parity (feature-flagged) |

## Coverage

Full rule list with one-line descriptions: [docs/rules.md](../rules.md).

OWASP Agentic Top 10 2026 mapping: [docs/owasp-agentic-coverage.md](../owasp-agentic-coverage.md).

OWASP MCP Top 10 mapping: [docs/owasp-mapping.md](../owasp-mapping.md).
