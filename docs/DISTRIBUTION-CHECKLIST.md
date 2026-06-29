# Distribution Checklist — State of MCP Security 2026

A manual launch checklist for the data report
([`research/state-of-mcp-2026/REPORT.md`](../research/state-of-mcp-2026/REPORT.md)).
**Nothing here is automated** — every item is a human action. Post deliberately,
one surface at a time, and respond to replies.

Canonical numbers to quote (from `results.json`, do not round up):
**571 distinct configs · 25.7% with a critical finding · ~29% grade A ·
top misconfig = `npx`/`uvx` fetch-and-execute (43%) · 24% no-auth remote.**
Static, offline, deterministic — reproduce command is in the report.

---

## Surfaces (in suggested order)

### 1. Show HN — Tue/Wed ~8–9am ET
- [ ] Title (research-framed, not a tool pitch):
      **"I scanned 571 public MCP servers — here's what's exposed"**
- [ ] First comment (post as author, immediately): one paragraph — method
      (offline deterministic scan), the headline stat, the honest caveats
      (sample skews to public repos; static over/under-counts), and a link to
      the reproduce command. Say plainly it's not a replacement for runtime
      tools (Snyk `agent-scan`) — this is the static/CI/offline angle.
- [ ] Do NOT gate the dataset behind email. Do NOT say "the MCP ecosystem" —
      say "571 configs". Reply to every comment for the first ~3 hours.

### 2. r/netsec — research framing ONLY
- [ ] Title: **"The State of MCP Security 2026: 571 public MCP configs scanned
      (data + reproducible methodology)"**
- [ ] Lead with dataset + method + the reproducible harness link; put the tool
      name in the body, not the title (r/netsec removes product posts — this
      passes as original research because it is). Link `REPORT.md` + `results.json`.

### 3. awesome-mcp-security PR
- [ ] Confirm AAK isn't already listed; add one factual line under the
      tools/SAST section, following that repo's `CONTRIBUTING.md` (dated
      template, alphabetical/new-on-top as required).
- [ ] Line: *"agent-audit-kit — offline SAST scanner for MCP/agent pipelines;
      OWASP Agentic + MCP Top-10; SARIF + compliance reports."*
      (Note: an entry already exists in `Puliczek/awesome-mcp-security` PR — check status before re-submitting.)

### 4. OWASP GenAI / MCP Top 10 working group
- [ ] `github.com/OWASP/www-project-mcp-top-10` (Phase-3 beta — accepts
      real-world data). Open a Discussion first, not a cold PR.
- [ ] Offer the dataset as evidence for the **unauthenticated-transport** and
      **supply-chain / fetch-and-execute** categories (strongest, externally
      corroborated by Knostic 119-of-119 + this report's 24% no-auth / 43% npx).
- [ ] Contribute *data*, not a tool plug. Permalink to the merged report commit.

### 5. Cross-references
- [ ] Once Show HN + r/netsec are live, cross-reference them for credibility.
- [ ] Drop the report link in any MCP registry / directory listing that allows
      a "security" note (PulseMCP, Glama) — passive, not spammy.

---

## Guardrails
- One launch problem-essay drafted separately; keep claims to what `results.json`
  supports. External figures stay attributed to their sources (MCP Registry,
  Knostic, the 2,614-server survey).
- No paywall, no email gate, no cloud upload of anyone's configs — the whole
  pitch is offline/deterministic; don't undercut it.
- If a maintainer whose config is graded asks for a fix window, honor the 90-day
  coordinated-disclosure policy (`docs/disclosure-policy.md`).
