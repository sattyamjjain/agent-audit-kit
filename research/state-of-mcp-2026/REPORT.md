# The State of MCP Security 2026

> **Moved.** The canonical, current data report is **[`PREVALENCE.md`](PREVALENCE.md)**
> — an expanded, content-deduplicated scan of **664 distinct public MCP server
> configs** (v0.3.42, 225 rules, fully offline), with the score-calibration
> distribution (issue #23), the OWASP-MCP-Top-10 hit rate, the top-10 findings,
> methodology, honest limitations, and the exact reproduce command. Raw
> aggregate: [`results.json`](results.json).

## The one-line version

We scanned **664 distinct public MCP configs** offline and deterministically.
**26.1% ship a critical-severity flaw**, the **median config scores a B** and the
**top 10% score an A**, and **24.2% declare a remote server with no
authentication**. Full report → **[`PREVALENCE.md`](PREVALENCE.md)**.

## Why offline + deterministic matters

Two properties hosted scanners can't match, and exactly what makes this report
trustworthy:

1. **Offline & deterministic** — zero network calls, no LLM; the same corpus
   yields the same `results.json`, byte-for-byte. A report you can re-run and
   check, not a vibe.
2. **Compliance-evidence, not just findings** — the same scan emits SARIF plus
   auditor-ready PDF evidence mapped to 13 frameworks.

Scan your own in 30s, fully offline: `pip install agent-audit-kit && agent-audit-kit scan .`

---

*The earlier marketing draft at
[`../../launch/state-of-mcp-security-2026.md`](../../launch/state-of-mcp-security-2026.md)
is superseded. Launch-ready copy is in
[`../../docs/DISTRIBUTION-CHECKLIST.md`](../../docs/DISTRIBUTION-CHECKLIST.md).
The prior 571-config run of this report is in git history.*
