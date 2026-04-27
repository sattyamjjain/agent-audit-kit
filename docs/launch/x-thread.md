# X (Twitter) launch thread — 8 tweets

Post same Tuesday as HN, ~1h after HN submission.

---

**1/ Hook — lead with the worst-graded major server (name-redacted).**

> Scanned 500 public MCP servers this week. The worst-graded major
> server ran /mcp_message with no auth middleware while /mcp had one.
> Same handler, one route bypasses.
>
> This is the CVE-2026-33032 pattern. 30+ CVEs like it in Jan–Feb 2026.
>
> Thread 🧵

[attach screenshot of per-server grade card, name redacted]

---

**2/ What we built**

> agent-audit-kit — OSS static scanner for MCP-connected AI agents.
>
> 124 deterministic rules. SARIF → GitHub Security tab.
> Compliance evidence for EU AI Act Article 15, SOC 2, ISO 27001/42001,
> HIPAA, NIST AI RMF.
>
> No account, no cloud, no LLM calls. `pip install agent-audit-kit`.

---

**3/ Why it matters**

> EU AI Act high-risk obligations apply Aug 2 2026. Your agent pipeline
> needs cybersecurity evidence — Art. 15(1) accuracy + robustness +
> cybersecurity.
>
> A grep against your code isn't evidence. A scanner that maps findings
> to the article IS. That's the wedge.

---

**4/ The leaderboard**

> We publish the MCP Security Index weekly.
>
> • Per-server grade cards (A–F)
> • 90-day coordinated disclosure before findings go public
> • Full data: mcp-security-index.com
>
> Maintainer-fix earlier? We publish the fix the day it lands with
> credit.

---

**5/ 48-hour CVE-to-rule SLA**

> We publicly commit: every disclosed MCP CVE gets rule coverage
> within 48h of NVD disclosure. Tracked in CHANGELOG.cves.md.
>
> Sigstore-signed rule bundles, so enterprise users can pin + verify
> without a vendor account.

---

**6/ Scoped for 2026 reality**

> • AAK-MCP-OAUTH-* — MCP spec 2025-11-25 mandatory PKCE+S256
> • AAK-HOOK-RCE-* — CVE-2025-59536 family
> • AAK-SKILL-* — ToxicSkills dataset (1,467 poison payloads)
> • AAK-MARKETPLACE-* — .claude-plugin/marketplace.json
> • AAK-ROUTINE-* — Claude Code Routines (Apr 14)
> • AAK-TASKS-* — MCP Tasks primitive (SEP-1686)

---

**7/ Why deterministic**

> Reproducible CI runs.
> No data leaves the repo (air-gap friendly for defense/finance/healthcare).
> An EU AI Act auditor can read the rule. They cannot read an LLM.
>
> We keep an optional --llm-scan flag for semantic tool-description
> checks. The moat is deterministic.

---

**8/ Get it**

> • Repo: github.com/sattyamjjain/agent-audit-kit
> • Leaderboard: mcp-security-index.com
> • VS Code Marketplace: agent-audit-kit
> • GitHub Action: uses: sattyamjjain/agent-audit-kit@v0.3.8
>
> Apache 2.0. No strings.

---

## Do / don't

- ✅ Post during 12:00–17:00 UTC (paper arXiv:2511.04453 optimal window).
- ✅ Reply to every serious question.
- ✅ Tag @OWASP when discussing MCP Top 10 coverage.
- ❌ Don't name-call specific vulnerable servers in the thread. Lead
     with the class of issue, not the victim.
- ❌ Don't use emoji-heavy "launch" templates. Technical audience.
