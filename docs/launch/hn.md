# Show HN draft

**Title (≤80 chars):**
> Show HN: We scanned 500 MCP servers for 2026 CVEs — here's the leaderboard

**URL:**
> https://mcp-security-index.com/ (the index, not the repo)

**Text body:** leave blank (URL post — HN prefers clean URL submissions).

**When to submit:** Tuesday, 13:00 UTC. Do NOT submit on a Friday.

## First comment (post immediately after submission)

> Hi HN, maintainer here.
>
> Why this exists: MCP — Anthropic's Model Context Protocol — has turned
> into the lingua franca for AI-agent tool calls. 10,000+ servers now,
> 30+ CVEs filed in Jan–Feb 2026 alone. 82% of a 2,614-server survey had
> path traversal issues. 36.7% of a separate 7,000-server survey had SSRF.
> Snyk bought Invariant Labs in June 2025 and owns "scan your MCP
> pipeline" commercially, but nothing open-source gave you **compliance-
> evidence output** — SARIF + OWASP MCP Top 10 + EU AI Act Article 15
> + SOC 2 + ISO 27001 / 42001 + HIPAA + NIST AI RMF in one scan.
>
> agent-audit-kit is that. 124 deterministic rules. Zero cloud
> dependencies, no auth required. Apache 2.0.
>
> The leaderboard: we run the scanner weekly against 500 public MCP
> servers and publish per-server grade cards. Findings are embargoed
> 90 days per our disclosure policy. The goal is to apply the same
> "npm audit" public-feedback pressure to the MCP ecosystem.
>
> Happy to answer anything — rules, scoring, the 2026 CVE wave, why
> deterministic > LLM-assisted, why we're not chasing Snyk on
> multi-model analysis.

## Canned answers (expect these questions)

- **"How is this different from Snyk Agent Scan?"**
  → No auth, no cloud, compliance-evidence output, India DPDP +
  Singapore framework + EU AI Act Article 55. Deterministic, so CI
  runs are reproducible. 48h CVE-to-rule SLA we publicly track.
- **"Does it use an LLM?"**
  → No. The moat is deterministic rules. We keep an optional
  `--llm-scan` flag for semantic tool-description checks, but the core
  124 rules are regex + AST patterns that run in <50 ms on a normal
  project.
- **"What's your false-positive rate?"**
  → We scan 500 public MCP servers weekly. Ground-truth is unknown
  for most of them. The published index includes per-finding detail
  so maintainers can challenge — we update rules, not findings.
- **"Why not upstream to Snyk?"**
  → Snyk's scanner is not OSS. Our rule bundles are Sigstore-signed
  and downloadable (`rules.json`), so enterprise users can pin +
  verify without a vendor account.
- **"Where does the rule set come from?"**
  → NVD keyword feed for the `CVE-*-*` specific rules (see
  CHANGELOG.cves.md). OWASP MCP Top 10 and OWASP Agentic 2026 for the
  general rules. MCP spec 2025-11-25 for OAuth 2.1 requirements.
- **"Why deterministic?"**
  → Three reasons. (1) Reproducible CI. (2) No data leaves the repo
  — important for defense, finance, healthcare. (3) Auditor
  evidence: when an EU AI Act auditor asks "how do you know the rule
  fired correctly?", we can show them the pattern. An LLM can't.

## Do / don't

- ✅ Stay in the thread for 4 hours after submission.
- ✅ Answer every top-level comment.
- ✅ Link to the 90-day disclosure policy when someone asks about
  finding a specific server by name.
- ❌ Do not rush to write "thanks!" on every upvote — engage substantively.
- ❌ Do not submit on a Friday or weekend.
- ❌ Do not use the literal "Show HN:" prefix if you'd rather lead
  with the data hook; per the Launch-Day Diffusion paper (arXiv
  2511.04453), "Show HN:" has no statistical lift after controlling for
  time-of-day.
