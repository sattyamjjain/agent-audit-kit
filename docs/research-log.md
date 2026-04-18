# Research log

Per `CLAUDE_PROMPT.md` §10: every session that authors a new rule logs
the date, topic, URLs consulted, and the conclusion here.

Format:
```
## YYYY-MM-DD — <topic>

**Sources:**
- <url 1>
- <url 2>

**Conclusion:** one paragraph.
**Rules shipped:** AAK-XXX-NNN, AAK-XXX-MMM.
```

---

## 2026-04-18 — 2026 CVE wave baseline for v0.3.0

**Sources:**
- https://nvd.nist.gov/vuln/detail/CVE-2025-59536
- https://nvd.nist.gov/vuln/detail/CVE-2026-33032
- https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-h6c2-x2m2-mwhf
- https://nvd.nist.gov/vuln/detail/CVE-2026-34070
- https://nvd.nist.gov/vuln/detail/CVE-2025-68664
- MCP spec 2025-11-25 (Streamable HTTP + OAuth 2.1 mandatory + Tasks SEP-1686)
- Snyk ToxicSkills dataset overview (Q1 2026)
- 2,614-server MCP survey (82% path traversal) — referenced in
  ROADMAP_2026.md §2.2; primary source held privately.

**Conclusion:** CVE-2026-33032 is the clean template for the AAK-MCP-011..020
family — shared handler, one authenticated route and one unauthenticated
route, empty default allowlist. CVE-2025-59536 defines the AAK-HOOK-RCE
family — project-local settings.local.json executing before the trust
dialog. CVE-2026-34070 is the AAK-LANGCHAIN path-traversal anchor;
CVE-2025-68664 covers the serialization-injection chain.

OAuth 2.1 rules do not need individual CVEs — MCP spec 2025-11-25 itself
is the authoritative advisory.

Skill-poisoning and marketplace-manifest rules use the OWASP MCP Top 10
entries MCP03 (Supply Chain) and MCP05 (Tool Poisoning) as authoritative
sources, plus the Snyk ToxicSkills research as the 1,467-payload corpus
reference.

**Rules shipped:** AAK-MCP-011..020, AAK-SSRF-001..005, AAK-OAUTH-001..005,
AAK-HOOK-RCE-001..003, AAK-LANGCHAIN-001..003, AAK-MARKETPLACE-001..004,
AAK-ROUTINE-001..003, AAK-A2A-008..012, AAK-TASKS-001..003,
AAK-SKILL-001..005. Plus AAK-INTERNAL-SCANNER-FAIL meta rule.

Note: where a rule description names a specific CVE, that CVE is
recorded in the rule's `cve_references` list and in CHANGELOG.cves.md.
Where a rule is derived from a class-of-attacks pattern (OWASP MCP Top
10 entries, MCP spec, CWE), the rule cites the spec/OWASP ID and does
NOT fabricate a CVE number.
