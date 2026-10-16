# Per-rule pages

Every rule in the AAK registry has a page: what it detects, how to fix it, what
it does not catch, which scanner implements it, and which CVEs and standards it
maps to. The canonical source of truth is `agent_audit_kit/rules/builtin.py`.
The "more info" link on a finding in GitHub code scanning (the SARIF `helpUri`)
opens the page for that rule. On the published site this page also carries two
lists, which are added when the site is built and so are not in this file:
[All rules](#all-rules), every rule in the registry grouped by category, and
[Retired rules](#retired-rules), the rules that have left the registry, whose
pages stay so that the link in an alert raised before they went still opens.

Most pages are generated from the registry when this site is built, so they
cannot say something the scanner does not. The CVE-driven and high-traffic rules
also have a hand-written deep dive, listed in the release tables on this page.
That text is shown on the rule's page exactly as written, with the registry
reference appended to it.

## v0.3.84 (2026-08-19) — net-new

| Rule | Severity | Class | CVE / source |
|---|---|---|---|
| [AAK-COMPOSE-001: an ordered path to egress](./skill-composition.md#aak-compose-001-an-ordered-path-to-egress-high) | HIGH | COMPOSITION | CompoSkill [arXiv:2608.16246](https://arxiv.org/abs/2608.16246) |
| [AAK-COMPOSE-002: an undeclared shared path](./skill-composition.md#aak-compose-002-an-undeclared-shared-path-high) | HIGH | COMPOSITION | ColluSkill [arXiv:2608.09732](https://arxiv.org/abs/2608.09732) |
| [AAK-COMPOSE-003: a manifest narrower than its code](./skill-composition.md#aak-compose-003-a-manifest-narrower-than-its-code-medium) | MEDIUM | COMPOSITION | CompoSkill [arXiv:2608.16246](https://arxiv.org/abs/2608.16246) |

## v0.3.43 (2026-07-04) — net-new

| Rule | Severity | Class | CVE / source |
|---|---|---|---|
| [AAK-MCP-AUTH-PATHTRAVERSAL-001](./AAK-MCP-AUTH-PATHTRAVERSAL-001.md) | CRITICAL | MCP_CONFIG | [CVE-2026-52830](https://nvd.nist.gov/vuln/detail/CVE-2026-52830) |

## v0.3.5 (2026-04-25) — net-new

| Rule | Severity | Class | CVE / source |
|---|---|---|---|
| [AAK-LANGCHAIN-SSRF-REDIR-001](./AAK-LANGCHAIN-SSRF-REDIR-001.md) | HIGH | TRANSPORT_SECURITY | [CVE-2026-41481](https://nvd.nist.gov/vuln/detail/CVE-2026-41481) |
| [AAK-SSRF-TOCTOU-001](./AAK-SSRF-TOCTOU-001.md) | MEDIUM | TRANSPORT_SECURITY | [CVE-2026-41488](https://nvd.nist.gov/vuln/detail/CVE-2026-41488) |
| [AAK-AZURE-MCP-001](./AAK-AZURE-MCP-001.md) | HIGH | MCP_CONFIG | [CVE-2026-32211](https://nvd.nist.gov/vuln/detail/CVE-2026-32211) |
| [AAK-TOXICFLOW-001](./AAK-TOXICFLOW-001.md) | HIGH | TOOL_POISONING | Snyk Agent Scan parity (feature-flagged) |

## Coverage

- [OWASP Agentic Top 10 2026 coverage](../owasp-agentic-coverage.md)
- [OWASP MCP Top 10 mapping](../owasp-mapping.md)
- [Rule counts by category, and what the scanner reads](https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/rules.md) (on GitHub)
