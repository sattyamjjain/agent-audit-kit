# AgentAuditKit — Kill-Criteria & Mission

> Private strategy note. **Do not commit to the public repo** — it names the
> market reality (Snyk) and an acqui-hire/services monetization path candidly.
> Written 2026-06-22. Review on each kill-date below.

The point of this doc: hold the **mission** with determination, hold the
**wedge** loosely. Pre-commit to the evidence that would prove the current bet
wrong, *with dates*, so a pivot is a scheduled decision and not an ego fight.

---

## Top-level mission (idea-agnostic)

**Make MCP-connected / agentic AI safe to deploy in production.**

This survives any pivot. The scanner, the rules, the index, the SLA — all of it
is replaceable. The mission is not.

---

## Current idea / wedge (the specific bet, as of 2026-06-22)

A **deterministic, fully-offline, MIT-licensed CVE-response scanner** for
MCP/agent configs — the "`npm audit` for AI agents" — that wins by:

1. **Speed of coverage** — a public CVE→rule SLA (claimed 48h), 225 rules / 79
   scanners, named-CVE anchors the day they drop.
2. **Trust through neutrality** — zero cloud, zero telemetry, auditor-ready
   SARIF, a signed rule bundle, plus a public **MCP Security Index** (per-server
   grades) and the **State of MCP Security** prevalence report.
3. **Distribution, not licensing** — the OSS is the top of funnel. The bet is
   *not* a standalone paid SaaS (that niche is being commoditized by free Snyk
   `agent-scan`, post Invariant acquisition). The intended payoff is **author
   value**: acqui-hire / a senior AI-security role / advisory + integration
   services, earned from credibility and distribution.

**Implicit assumptions this bet rests on (each maps to a kill-criterion):**
- (A) Free, offline, deterministic OSS will actually *accrue* developer trust
  and adoption faster than incumbents can absorb the niche.
- (B) Distribution + credibility *converts* into author-level outcomes.
- (C) "Fastest deterministic CVE→rule coverage" is a *defensible* difference,
  not something a free incumbent matches in one release cycle.

---

## Kill-criteria (falsifiable, dated)

> Each is phrased so a neutral observer could check it on the date and get a
> yes/no. Fill the `[baseline]` blanks today so the deltas are honest.
> A kill fires a **wedge pivot**, never a mission pivot.

### K1 — Adoption isn't compounding → the OSS-as-distribution wedge is wrong
**Date: 30 Sep 2026.**
Baseline today: `[___ GitHub stars]`, `[___ weekly PyPI downloads]`.
**Kill if, on 30 Sep 2026, ALL three hold:**
- GitHub stars < **400** (and < ~2× today's baseline), AND
- weekly PyPI downloads < **500** sustained over the trailing 4 weeks, AND
- **zero unsolicited external signal** — no PR, issue, or rule contribution from
  someone you didn't personally recruit; not listed in any registry/awesome-list
  you didn't add yourself.

→ *Pivot:* the value isn't in a CLI devs install. Move the wedge to the
**hosted MCP Security Index** as the product (the neutral grade/disclosure
source), or to a single high-pain runtime guard. Keep the rules engine as the
backend, drop "install our CLI" as the front door.

### K2 — Credibility doesn't convert → the "monetize the author" path is mispriced
**Date: 31 Oct 2026** (≈8 weeks after the data-report + Show HN launch).
**Kill if, on 31 Oct 2026, BOTH hold:**
- The **State of MCP Security** report got no real pickup — no HN front page, no
  cite by OWASP/a security vendor/a journalist/a registry, < **3** independent
  inbound links you didn't place; AND
- **zero qualified inbound** traceable to AAK — no acqui-hire/role conversation,
  no advisory or paid-integration inquiry, no maintainer-grant or sponsorship
  offer.

→ *Pivot:* credibility-first isn't paying. Switch to a **direct revenue motion**
(paid managed scanning + signed compliance reports for 2–3 design-partner teams)
to test willingness-to-pay directly, or fold AAK in as a credential behind a
different vehicle. Mission unchanged.

### K3 — The difference gets commoditized → the determinism/SLA moat is gone
**Date: 30 Nov 2026.**
**Kill if, on 30 Nov 2026, EITHER holds:**
- A free incumbent (Snyk `agent-scan`, GitHub, or an MCP registry's built-in
  scan) ships **deterministic, offline MCP-config CVE coverage** that matches
  AAK on the CVEs that matter, within ~1 release cycle of disclosure; OR
- You **cannot operationally sustain the 48h CVE→rule SLA** — e.g., the release
  gate keeps coverage merged-but-unshipped (today: ~6 rules / versions
  0.3.35–0.3.40 stuck behind 15 open `sla-48h` issues). A public SLA you don't
  actually meet is worse than no SLA.

→ *Pivot:* move up the stack to what they won't commoditize — the **neutral
cross-vendor index + coordinated-disclosure ledger** as the trusted source of
record, or runtime enforcement. And either *fix the release pipeline this week*
or *drop the 48h claim* — don't ship a promise you can't keep.

---

## Leading indicators (watch monthly; don't wait for the kill-date blind)
- Stars/downloads slope (compounding vs flat), ratio of unsolicited to seeded.
- Inbound quality: vague interest vs a concrete "can you scan our fleet" ask.
- CVE→merge→**release** latency (merge is not coverage until it ships).
- Whether anyone cites the Index/report without prompting.

## What does NOT move, regardless of pivots
- The mission (line at top).
- Offline / deterministic / no-telemetry / auditor-ready — the trust posture is
  the durable asset; never trade it for growth hacks.
- Honesty in claims (no inflated counts, no SLA you can't meet) — the entire bet
  is credibility; one dishonest headline costs more than it buys.

## Decision rule
On each date: if the criterion is met, **pivot the wedge that week** — write the
next wedge + its own kill-criteria here. If not met, keep going for one more
cycle. Determination on the mission; ruthlessness on the wedge.
