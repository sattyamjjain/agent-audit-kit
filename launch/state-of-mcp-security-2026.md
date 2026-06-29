# The State of MCP Security 2026

> **⚠️ Superseded — earlier marketing draft.** The canonical, reproducible report is
> **[`research/state-of-mcp-2026/REPORT.md`](../research/state-of-mcp-2026/REPORT.md)**
> (raw aggregate: [`results.json`](../research/state-of-mcp-2026/results.json)),
> regenerated against the current engine (v0.3.41, 225 rules): **571 distinct
> configs, 25.7% with a critical finding, ~29% grade A.** Some derived figures in
> the body below are from an earlier run — trust REPORT.md for any number you quote.

## We scanned 571 public MCP server configs. 1 in 4 ships a critical flaw.

> **Marketing draft.** Headline framing is final; for exact reproducible figures use the canonical report linked above.

---

### TL;DR

- We took **571 distinct publicly committed `.mcp.json` configuration files** from GitHub and ran
  [AgentAuditKit](https://github.com/sattyamjjain/agent-audit-kit) (v0.3.41, 225 rules, fully
  offline, MIT) over each one.
- **Nearly every config (568/571, 99.5%) produced at least one finding** — but most configs' *worst*
  issue is advisory. The security-relevant story is sharper:
  - **147 configs (26%) contain at least one CRITICAL issue.**
  - **289 configs (51%) contain at least one HIGH-severity issue.**
  - Totals: **259 critical · 867 high · 2,119 medium · 586 low** (3,833 findings).
- The MCP config is, first, a **supply-chain and authentication** problem:
  - **236 remote MCP servers are declared with no authentication** (the single biggest critical driver).
  - **586 server entries pull packages that are not pinned to an exact version** — the rug-pull surface.
  - **565 servers use `npx`/`uvx` to fetch-and-execute remote code at launch** — you run whatever the registry serves that day.
- We are **deliberately honest about what is *not* a vulnerability**: the most common single
  finding (1,282×, medium — "no deny-by-default attestation") is an *advisory posture* signal,
  not an exploit, and we exclude it from the headline. So is "no version pin in `args`" (low).

---

### Why we did this

MCP went from an Anthropic proposal (Nov 2024) to a cross-vendor de-facto standard in ~18
months, and developers now commit `.mcp.json` files straight into public repos. Plenty of
people have *talked* about MCP risk (tool poisoning, rug pulls, the STDIO RCE class, the
no-auth servers). Nobody had published **prevalence data on a real corpus** of how those
risks actually show up in configs in the wild. So we measured it.

### Method

- **Corpus.** 571 distinct `.mcp.json` files containing an `mcpServers` block, discovered
  via the GitHub Code Search API and downloaded (crawled 2026; latest pass 2026-06-13). 631
  files were downloaded; 59 byte-identical duplicates and 1 unparseable file were removed,
  leaving 571 unique configs. Each is a real config from a real public repository.
- **Tool.** AgentAuditKit v0.3.41 — 225 deterministic rules, no LLM, no cloud, no telemetry;
  every config scanned in isolation. The exact rule set is in the
  [signed bundle](https://github.com/sattyamjjain/agent-audit-kit) (`rules.json`).
- **Reproducible.** The crawler and scanner are open source and stdlib-only. Anyone can
  re-run the whole pipeline (see *Reproduce this*) and get the same per-config results on the
  same files.

**Honesty caveats — read these before quoting any number:**

1. **The sample skews to discoverable, popular public repos** (Code Search ranks by relevance
   + stars). It is not a uniform random sample of the ~9,400 distinct MCP servers estimated to
   exist; treat it as "configs people actually publish," not "all MCP servers."
2. **Static analysis both over- and under-counts.** A flagged pattern is *not* proof of an
   exploit in context, and a clean scan is not proof of safety. We report what the rules
   match, not adjudicated CVEs.
3. **N = 571 is a sample**, not the whole ecosystem (~9,400 distinct servers are estimated to exist). We say "571 configs," never "the MCP
   ecosystem." (Widen the corpus before publishing — the method scales to thousands.)
4. **We separate exploitable findings from advisory/posture signals** (below). Reporting
   posture rules as "vulnerabilities" would inflate the story; we don't.

---

### What we found

#### The exploitable issues (these are the story)

| Issue | Rule | Severity | Findings |
|---|---|:---:|---:|
| Remote MCP server with **no authentication** | `AAK-MCP-001` | **CRITICAL** | 236 |
| Server command runs with **shell expansion** (injection) | `AAK-MCP-002` | **CRITICAL** | 11 |
| Package **not pinned to an exact version** (rug-pull surface) | `AAK-SUPPLY-001` | HIGH | 586 |
| `npx`/`uvx` **fetch-and-execute remote code** at launch | `AAK-MCP-005` | MEDIUM | 565 |
| Server **env exposes secrets** to the tool process | `AAK-MCP-003` | HIGH | 137 |
| **stdio launcher injection** (shell interpreter + injectable argv; CVE-2026-40933 class) | `AAK-MCP-STDIO-LAUNCHER-INJECT-001` | HIGH | 72 |
| Server URL points at **localhost / internal network** (SSRF surface) | `AAK-MCP-009` | HIGH | 50 |
| Deprecated **SSE transport** | `AAK-TRANSPORT-003` | MEDIUM | 30 |

**Per-config:** 26% (147/571) have ≥1 critical; 51% (289/571) have ≥1 high.

The two things worth fixing **today**, in order:

1. **Pin every server package to an exact version (or a hash).** 586 unpinned entries + 565
   `npx`/`uvx` fetch-and-execute entries mean most of these configs run code whose contents
   can change between two launches without the config changing at all. That is the rug-pull /
   supply-chain exposure in one sentence.
2. **Never expose a mutating remote MCP server without authentication.** 236 servers in this
   corpus are reachable-and-driveable by anyone who can hit the endpoint.

#### What we deliberately did *not* count as "security issues"

- **`AAK-MCP-ATTEST-001` (1,282×, medium — "admitted without attestation")** is AAK's
  forward-looking *deny-by-default attestation* posture check. It fires on nearly every server
  because attestation simply isn't an ecosystem norm yet. It's a real roadmap signal, but it
  is **not an exploit**, so it's excluded from the headline. (This is why "99.5% of configs had
  a finding" is technically true but misleading on its own — most configs' worst issue is this
  advisory.)
- **"No version pin in `args`" (`AAK-MCP-007`, 586×, low)** is advisory hygiene, not a vuln.
- **Hardcoded secrets *in the JSON itself* were rare** here — 3 configs. The real secret risk
  in MCP is **env passthrough** (`AAK-MCP-003`, 137×), not literal keys in the config. We
  report that honestly rather than borrowing the louder "secrets sprawl" headline.

---

### What it means

- **The MCP config file is a supply-chain artifact first, an auth boundary second.** Treat a
  `.mcp.json` the way you'd treat a `package.json` with `postinstall` scripts: pin it, review
  it, and don't let it fetch-and-run arbitrary remote code on every launch.
- **"It's local, so it's fine" is the wrong mental model.** stdio launcher-injection and
  internal-network URLs show the local-dev surface is exploitable too.
- **Most teams have no gate for any of this.** None of these checks run in a default CI
  pipeline today — which is the gap a deterministic, offline scanner fills.

### Check your own setup (30 seconds, fully offline)

```bash
pip install agent-audit-kit
agent-audit-kit scan .          # scans your .mcp.json, .claude/, Cursor/Windsurf/etc.
```

SARIF output drops straight into the GitHub Security tab; there's a GitHub Action and a
pre-commit hook. No account, no cloud, nothing leaves your machine.

### Responsible disclosure

This report publishes **aggregate statistics only**. Per-server grade cards on the public
[MCP Security Index](https://sattyamjjain.github.io/agent-audit-kit/) follow a **90-day
coordinated-disclosure** policy; a maintainer who fixes earlier gets published the day the fix
lands, with credit. See [`docs/disclosure-policy.md`](../docs/disclosure-policy.md).

### Reproduce this

```bash
git clone https://github.com/sattyamjjain/agent-audit-kit && cd agent-audit-kit
pip install -e .
export GITHUB_TOKEN=$(gh auth token)          # higher search rate limit
python benchmarks/crawler.py --limit 500 --output benchmarks/results.json
# crawler downloads public .mcp.json files, scans each with the live engine, and aggregates.
```

Everything is MIT-licensed and the rule bundle is Sigstore-signed, so you can verify exactly
which 225 rules produced these numbers.

---
---

# ▼ LAUNCH COPY (not part of the published post — for HN / Reddit / X)

## Show HN — post Tue/Wed 8–9am ET, respond to every comment within 15 min for 3h

**Title options (pick one):**
- `Show HN: We scanned 571 public MCP server configs – 1 in 4 has a critical flaw`
- `Show HN: The State of MCP Security – open dataset + scanner (26% ship a critical issue)`
- `Show HN: Half of public MCP configs have a high-severity issue – here's the data`

**First comment (post immediately, as the author):**
> Solo maintainer here. I took 571 publicly-committed `.mcp.json` files from GitHub and ran an
> open-source, fully-offline scanner (AgentAuditKit, MIT, 225 rules) over each. Headline: **26%
> ship ≥1 critical issue, 51% ship ≥1 high.** The critical drivers are boring and fixable —
> remote servers with no auth, and packages that aren't version-pinned (so they fetch-and-run
> whatever the registry serves that day).
>
> I tried hard to be honest about limits: the corpus skews to popular public repos, static
> analysis isn't an exploit proof, and I explicitly *excluded* our own advisory "no attestation"
> rule from the headline even though it fires on ~every server — calling that a "vulnerability"
> would be dishonest. Full method + caveats + reproduce-it-yourself in the post.
>
> Not trying to replace Snyk's mcp-scan for live tool analysis — this is the static/CI/offline
> angle. The scanner runs with zero network and drops SARIF into GitHub's Security tab. Happy to
> dig into any finding or take the methodology apart.

**Don't:** gate the dataset behind email; claim "the MCP ecosystem" (say "571 configs"); post
before the corpus N in the post matches the crawl you actually ran; sound like an LLM in replies.

## r/netsec — research framing ONLY (no "check out my tool")

**Title:** `The State of MCP Security 2026: we scanned 571 public MCP server configs (data + methodology)`

Lead with the dataset and method, link the reproducible crawler, put the tool name in the body
not the title. r/netsec removes product posts; this passes as original research because it is.

## r/devops & r/selfhosted — tool-framed, utility-first

`Open-source GitHub Action that scans your MCP/agent configs for no-auth servers, unpinned
supply chain, and shell-injection — SARIF to the Security tab, runs offline.`

## X / LinkedIn thread (6 posts)

1. We scanned 571 public MCP server configs. 1 in 4 ships a critical security flaw. 🧵
2. 26% have ≥1 CRITICAL · 51% have ≥1 HIGH (259 critical + 867 high findings across 571 configs).
3. The #1 critical: 236 remote MCP servers with NO authentication. If you can reach it, you can drive its tools.
4. The systemic one: 586 server entries pull packages that aren't version-pinned, and 565 use npx/uvx to fetch-and-run code at launch. That's the rug-pull surface.
5. Honesty note: we excluded our own advisory "no attestation" rule (fires on ~every server) from the headline. Reporting it as a vuln would be dishonest.
6. Scan your own in 30s, fully offline: `pip install agent-audit-kit && agent-audit-kit scan .` — MIT, SARIF, GitHub Action. Method + data: [link]

## Where to submit
- Show HN + r/netsec (same day, cross-reference for credibility)
- OWASP GenAI / MCP Top 10 working group (offer the dataset as evidence)
- Submit AAK to PulseMCP / Glama as a security tool; PR into `Puliczek/awesome-mcp-security`
- Black Hat EU Arsenal (CFP ~Jun 19) and OWASP Global AppSec USA (CFP ~Jun 29) — the data is the hook
