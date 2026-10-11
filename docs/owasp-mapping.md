# OWASP Mapping

> **This page moved.** It used to carry a hand-maintained copy of the OWASP
> coverage tables, and it drifted badly: every MCP slot understated its real
> count by roughly four times (MCP01 said 14 against a live 78, MCP05 said 10
> against 55) and MCP08 was missing altogether. Hand-copying a number the
> registry already knows is how that happens, so the copy is gone rather than
> corrected.

Coverage is generated from the live rule registry by `scripts/gen_coverage.py`,
which CI regenerates and fails on staleness:

- **[OWASP Top 10 for Agentic Applications (ASI01-ASI10) → AAK rules](coverage/owasp-agentic-top10.md)**, Version 2026 (December 2025)
- **[OWASP MCP Top 10 (MCP01:2025-MCP10:2025) → AAK rules](coverage/owasp-mcp-top10.md)**, v0.1, the 2025 edition (beta)
- **[OWASP Agentic Skills Top 10 (AST01-AST10) → AAK rules](coverage/owasp-agentic-skills-top10.md)**, 1.0 (2026), partial by design; the page says which categories a static scan cannot decide

The ids and titles come from `agent_audit_kit/output/owasp_report.py`, where
each table records the version, source and date it was verified against, and
`tests/test_owasp_taxonomy_pins.py` holds them there.

## The October 2026 correction

Through 0.6.20 the MCP table in `owasp_report.py` used OWASP's `MCPnn:2025`
labels with AAK's own numbering. Seven of the ten ids named a different risk
than OWASP's list does: AAK's MCP05 read "Tool Poisoning", while OWASP's MCP05
is Command Injection & Execution and its Tool Poisoning is MCP03. The README's
Agentic table had a similar problem in its titles (ASI03 read "Memory
Poisoning", ASI10 "Supply-Chain"). Every rule reference was re-assigned by what
the rule detects, not by number, so a finding's OWASP id now means what OWASP
says it means. The `:2025` suffix itself was never the problem: it is OWASP's
own label, and the 2025 numbering is the only one the MCP project has
published.

How references are assigned:

- **MCP Top 10** ids go on rules that inspect part of an MCP deployment: a
  server, client, tool, SDK, gateway or proxy, their code, config, packages or
  published metadata, or the host settings that admit MCP servers and govern
  which tools they may call. Lifecycle hooks, routines, IDE tasks, CI workflows,
  instruction files, skills, plugins, A2A and non-MCP agent packages carry
  Agentic references only.
- **Agentic Top 10** ids go wherever the risk applies, following the document's
  own placement notes (tool-descriptor poisoning is ASI02, with ASI04 when the
  tool is malicious at source; privilege escalation and credential misuse are
  ASI03; code execution is ASI05).
- A rule may name an entry because it detects the missing control the entry
  prescribes (a quota, a scope, an audit trail). ASI08 and ASI10 are covered
  mostly this way.
- A rule that detects something no entry names carries no OWASP id. Statutory
  rules (EU AI Act, ADMT, state privacy) and spec-migration rules are the main
  cases.
- SSRF sits under MCP05, whose text covers API requests built from untrusted
  input. That is AAK's reading: the MCP project's SSRF question
  ([OWASP issue 20](https://github.com/OWASP/www-project-mcp-top-10/issues/20)) is
  open.

For a scan-time view of your own project, run:

```bash
agent-audit-kit scan . --owasp-report
```
