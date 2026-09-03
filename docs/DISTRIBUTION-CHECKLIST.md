# Distribution Checklist — State of MCP Security 2026

Manual launch checklist + **ready-to-post copy** for the data report
([`research/state-of-mcp-2026/REPORT.md`](../research/state-of-mcp-2026/REPORT.md),
with score-calibration detail in
[`PREVALENCE.md`](../research/state-of-mcp-2026/PREVALENCE.md)).
**Nothing here auto-posts.** Copy, sanity-check the links, post one surface at a
time, reply to comments.

**Canonical numbers (from `results.json` — do not round):**
2,303 distinct configs · 52.6% (1,212) with a critical finding · median grade B
(top 10% A) · top misconfig = remote server with **no authentication**
(`AAK-MCP-001`, critical, 52.1%) · 52.1% (1,200) no-auth remote · 19.5% (450)
`npx`/`uvx` fetch-and-execute · 99.8% trip OWASP MCP07 (authorization).
Static, offline, deterministic.

Report link: `https://github.com/sattyamjjain/agent-audit-kit/blob/main/research/state-of-mcp-2026/REPORT.md`

---

## 1. Show HN — post Tue or Wed, ~8–9am ET

**Title:**
```
Show HN: I scanned 2,303 public MCP server configs — 52% expose a remote server with no auth
```

**First comment (post immediately, as author):**
```
I run an open-source static scanner for MCP/agent configs (agent-audit-kit,
MIT). I took 2,303 distinct public MCP configs — a GitHub crawl plus the official
MCP Registry's latest-version servers — and scanned each one offline and
deterministically: no cloud, no LLM, same input gives the same result.

Headline: 52.1% (1,200 of 2,303) declare a remote server with no authentication —
that's the single most common finding, and it's critical-severity. 52.6% carry at
least one critical finding overall; the median config still grades a B. It lines
up with Knostic's separate finding that 119 of 119 exposed servers they probed
allowed unauthenticated tool-listing. The next most common issue is more boring
and fixable: 19.5% launch their server with npx/uvx and no pinned version.

I tried to keep it honest: the sample skews to public repos and registry
latest-version entries, static analysis over- and under-counts, auth posture is
inferred from declared config (not a live probe), and I say "2,303 configs", not
"the MCP ecosystem". Full method + the exact command to reproduce it is in the
report.

Not trying to replace runtime tools like Snyk agent-scan — this is the
static/CI/offline angle. You can scan your own in 30s: pip install
agent-audit-kit && agent-audit-kit scan .

Report: <report link>
Repo: https://github.com/sattyamjjain/agent-audit-kit
```

- [ ] Posted Tue/Wed AM. Do NOT gate the data behind email. Reply for ~3h.

---

## 2. r/netsec — research framing, tool name in body not title

**Title:**
```
The State of MCP Security 2026: 2,303 public MCP configs scanned (data + reproducible method)
```

**Body:**
```
MCP servers are proliferating and the config hygiene is rough. I scanned 2,303
distinct public MCP configs — a GitHub crawl plus the official MCP Registry's
latest-version servers — with an offline, deterministic static analyzer and
aggregated the results.

Headline: 52.1% (1,200 of 2,303) declare a remote server with no authentication
(critical severity, the single most common finding); 52.6% carry at least one
critical finding; median grade B. Mapped to the OWASP MCP Top 10, 99.8% trip
MCP07 (authorization / excessive permissions). Other common issues: npx/uvx
fetch-and-execute at launch (19.5%), secret inlined in the config env block
(3.0%).

Method and raw aggregate (results.json) are committed; there's an exact
reproduce command (`make report`, offline + byte-deterministic). The scanner is
open source (agent-audit-kit, MIT); I've kept the caveats in the report (sample
skew, static over/under-count, inferred-from-config auth posture, N=2,303 is a
sample).

Report + data + method: <report link>
```

- [ ] r/netsec removes product posts — this passes as original research because
      it is. Link `REPORT.md` + `results.json`; keep the tool name out of the title.

---

## 3. OWASP GenAI / MCP Top 10 working group

Target: `github.com/OWASP/www-project-mcp-top-10` (Phase-3 beta, accepts
real-world data). Open a Discussion first, not a cold PR.

**One-paragraph note:**
```
Sharing real-world prevalence data that may be useful evidence for the MCP Top
10. I statically scanned 2,303 distinct public MCP server configs (offline,
deterministic; method + raw results committed and reproducible). Mapped to the
current list: 99.8% of configs trip MCP07 (authorization/excessive perms), and
52.1% declare a remote server with no authentication (critical, the single most
common finding) — which corroborates Knostic's 119-of-119 unauthenticated-tool-
listing finding from the deployment side. 19.5% trip the supply-chain/untrusted-
execution risk (npx/uvx unpinned launch). Happy to contribute the dataset or a
category-by-category breakdown. Report: <report link>
```

- [ ] Contribute *data*, not a tool plug. Permalink to the merged report commit.

---

## 4. awesome-mcp-security PR

- [ ] `Puliczek/awesome-mcp-security` already has an agent-audit-kit entry (PR
      submitted earlier). **Check its status first** — if merged, do nothing; if
      open, nudge; only submit elsewhere if genuinely absent.
- [ ] If adding to another list, one factual line, follow that repo's
      CONTRIBUTING (dated template / alphabetical / new-on-top as required):
      *"agent-audit-kit — offline SAST scanner for MCP/agent pipelines; OWASP
      Agentic + MCP Top-10; SARIF + compliance reports."*

---

## 5. Cross-references (after 1 & 2 are live)
- [ ] Cross-link Show HN ↔ r/netsec for credibility.
- [ ] Drop the report link where a "security" note is welcome (PulseMCP, Glama)
      — passive, not spammy.

---

## Guardrails
- Every number must trace to `results.json`. External figures stay attributed
  (Knostic, the 2,614-server survey).
- No paywall, no email gate, no cloud upload of anyone's configs — the pitch is
  offline/deterministic; don't undercut it.
- If a maintainer whose config is graded asks for a fix window, honor the 90-day
  coordinated-disclosure policy (`docs/disclosure-policy.md`).
- Replace `<report link>` with the real URL before posting.
