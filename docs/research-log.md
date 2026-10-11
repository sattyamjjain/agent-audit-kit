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
reference. (Corrected 2026-10-12: those were AAK's own numbers, not OWASP's.
OWASP's MCP03 is Tool Poisoning and its MCP04 is Software Supply Chain Attacks
& Dependency Tampering; skills and plugins now carry no MCP id at all. See the
2026-10-12 entry.)

**Rules shipped:** AAK-MCP-011..020, AAK-SSRF-001..005, AAK-OAUTH-001..005,
AAK-HOOK-RCE-001..003, AAK-LANGCHAIN-001..003, AAK-MARKETPLACE-001..004,
AAK-ROUTINE-001..003, AAK-A2A-008..012, AAK-TASKS-001..003,
AAK-SKILL-001..005. Plus AAK-INTERNAL-SCANNER-FAIL meta rule.

Note: where a rule description names a specific CVE, that CVE is
recorded in the rule's `cve_references` list and in CHANGELOG.cves.md.
Where a rule is derived from a class-of-attacks pattern (OWASP MCP Top
10 entries, MCP spec, CWE), the rule cites the spec/OWASP ID and does
NOT fabricate a CVE number.

---

## 2026-06-01 — CVE-2026-33032 duplicate-rule proposal declined (2nd time)

**Sources:**
- https://nvd.nist.gov/vuln/detail/CVE-2026-33032 (re-verified 2026-06-01)
- `agent_audit_kit/rules/builtin.py` — `AAK-MCPWN-001`, `AAK-MCP-011`,
  `AAK-MCP-012`, `AAK-MCP-020` all carry `CVE-2026-33032` in
  `cve_references`
- `agent_audit_kit/scanners/mcp_middleware.py` — dedicated scanner for
  the MCPwn twin-route asymmetry
- `CHANGELOG.cves.md:150` — ledger: CVE-2026-33032 → `AAK-MCPWN-001`
  (primary) + `AAK-MCP-011/012/020` (secondary), shipped 2026-04-20
- `CHANGELOG.md:738` — first decline of the same duplicate proposal
  ("`AAK-MCP-067`", 2026-05-17)

**Conclusion:** A second prompt proposed adding a new MCP STDIO
command-injection rule citing CVE-2026-33032. Declined for two
independent reasons:

1. **Already covered** — the CVE is in `cve_references` on 4 production
   rules + a dedicated scanner; the per-CVE ledger in
   `CHANGELOG.cves.md` records `AAK-MCPWN-001` as the primary mapping
   shipped 2026-04-20. The same duplicate was already declined on
   2026-05-17 (CHANGELOG.md:738).
2. **CVE mis-characterisation** — NVD classes CVE-2026-33032 as
   **CWE-306 (Missing Authentication for Critical Function)**: an
   unauthenticated `/mcp_message` endpoint paired with an authed
   `/mcp` endpoint in nginx-ui ≤ 2.3.5, with an empty default IP
   allowlist. It is **not** a STDIO command-injection. STDIO
   command-injection across the Ox 2026-05-01 disclosure cluster is
   already covered by `AAK-MCP-STDIO-CMD-INJ-001..004` and cites
   different CVEs (CVE-2025-65720, CVE-2026-22252, CVE-2026-26015,
   CVE-2026-30615, CVE-2026-30617, CVE-2026-30623, CVE-2026-33224,
   CVE-2026-40933, CVE-2026-6980, et al.). Filing a STDIO rule under
   CVE-2026-33032 would encode a false CVE-to-attack mapping.

**Rules shipped:** none (intentional no-op).

**Minor follow-up noted, not actioned:** NVD's CVE-2026-33032 page does
not surface a KEV listing in its summary block; `AAK-MCPWN-001`'s
description claims *"VulnCheck KEV-listed on 2026-04-13"*. KEV is
maintained by CISA / VulnCheck separately from NVD and may simply not
render on NVD's page; if a future verification finds the rule's KEV
claim is wrong, refresh the description in a dedicated chore PR.

---

## 2026-10-12 — OWASP ids re-read from the sources; every rule reference re-assigned

**Sources:**
- https://github.com/OWASP/www-project-mcp-top-10 — `index.md` and the ten
  `2025/MCP*.md` entry pages at commit 165fe0f78ef104459237b4a8e0f6e78db9b02391
  (2026-07-29); full commit history from 2025-06-18; pull requests 21, 41, 49
  and 57 and issue 20 in that repository
- https://owasp.org/www-project-mcp-top-10/ (redirects to
  owasp.org/projects/mcp-top-10), as rendered on 2026-10-12
- OWASP Top 10 for Agentic Applications 2026, the official PDF behind
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
  (title "OWASP Top 10 for Agentic Applications 2026 12.6.docx", 57 pages,
  created 2025-12-10; cover "Version 2026, December 2025")
- https://github.com/OWASP/www-project-agentic-skills-top-10 — `ast01.md` to
  `ast10.md`, `top10.md`, `index.md` (version badge 1.0-2026)

**Conclusion:** The `MCPnn:2025` label is OWASP's own and current: the MCP project
has published one numbering, unchanged since 2025-11-21, and calls it v0.1 (beta).
AAK's table used those labels with its own order, so seven of ten ids named a
different risk (AAK's MCP05 read Tool Poisoning; OWASP's MCP05 is Command Injection
& Execution and its Tool Poisoning is MCP03). The README's Agentic titles were
wrong at eight of ten. OWASP renamed MCP06 to Intent Flow Subversion in its pull
request 21; its README, `tab_top10.md` and the owasp.org render still show the
old Prompt Injection via Contextual Payloads title. The project has no SSRF entry
(its issue 20 is open; its pull request 41 placing SSRF under MCP05 was closed
unmerged), so AAK's SSRF rules sit
under MCP05 as AAK's reading of that entry's "API requests built from untrusted
input". Every rule's references were re-assigned by what it detects, and the
official tables are pinned in `tests/test_owasp_taxonomy_pins.py`.

**Rules shipped:** none. References changed on 350 of the 395 rules, including the 7 CVE pins #962 added while this was in review.
