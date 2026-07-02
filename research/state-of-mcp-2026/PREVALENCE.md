# State of MCP Security 2026 — Prevalence & Score Calibration

## We scanned 664 distinct public MCP server configs with an offline static scanner. 1 in 4 ships a critical-severity flaw, the median config scores a **B**, and the top 10% score an **A**.

> **Reproducible data report** (empirical sequel to the [State-of-MCP-Security
> harness](REPORT.md), issue #23). Every "measured" number below comes from
> running [AgentAuditKit](https://github.com/sattyamjjain/agent-audit-kit)
> (v0.3.42, 225 rules, fully offline, MIT) over a content-deduplicated corpus of
> public MCP configs. Raw aggregate: [`results.json`](results.json). External
> figures are attributed to their sources, not measured by us.
>
> **On the corpus size.** The target was ~1,000. GitHub Code Search hard-caps a
> single query at 1,000 results, and the primary `.mcp.json` query dedupes to
> ~571 distinct configs. Sweeping four more MCP-config filenames
> (`mcp.json`, `claude_desktop_config.json`, `cline_mcp_settings.json`,
> `mcp_settings.json`) widened it to **664 distinct configs** before returns
> plateaued. We report the real N — 664 — not the round target.

---

## Three headline numbers

1. **26.1% (173/664) of public MCP configs contain a critical-severity finding.**
2. **The median public MCP config scores a B; the top 10% score an A.**
   (This is the empirical score-calibration anchor issue #23 asked for. The
   roadmap *guessed* "median C-, top 10% B+" — the real distribution skews
   higher, because the single most common finding is a *medium* advisory, not a
   critical.)
3. **24.2% (161/664) declare a remote server with no authentication** — the
   no-auth exposure rate, corroborating Knostic's 119-of-119 unauthenticated
   tool-listing finding from the deployment side.

---

## Score distribution (A–F) — the calibration

| Grade | Configs | Share | Cumulative |
|:-----:|--------:|------:|-----------:|
| **A** | 199 | 30.0% | 30.0% |
| **B** | 242 | 36.4% | 66.4% |
| **C** | 89 | 13.4% | 79.8% |
| **D** | 49 | 7.4% | 87.2% |
| **F** | 85 | 12.8% | 100% |

- **Median grade: B** (the 332nd config falls inside the B band).
- **Top 10% (best ~66 configs): all grade A.**
- **~1 in 5 (20.2%) land at D or F.**

The grade is AAK's penalty-based score (start at 100; deduct 20/CRITICAL,
10/HIGH, 5/MEDIUM, 2/LOW), identical to `aak score`. **Calibration takeaway for
#23:** the current penalties already produce a sane spread (a clear A/B mode with
a real D/F tail) — the median lands at B, not the "C-" the roadmap assumed, so
the hand-picked penalties are, if anything, slightly *lenient* on the common
medium-severity advisory findings. No penalty re-weighting is done in this report
(that's a follow-up); this run gives it the empirical floor it lacked.

---

## Severity + category prevalence

**All findings:** 295 critical · 316 high · 2,604 medium · 640 low.
**Per-config:** 26.1% have ≥1 critical; 24.5% have ≥1 high.

| AAK category | Configs with ≥1 finding | Share |
|---|--:|--:|
| MCP configuration | 660 | 99.4% |
| Secret exposure | 70 | 10.5% |
| Transport security | 20 | 3.0% |
| Tool poisoning / agent-config / legal | 1 each | ~0.2% |

### OWASP MCP Top 10 — configs tripping each risk

| OWASP MCP | Configs | Share |
|---|--:|--:|
| **MCP07:2025** — Insufficient Authorization / Excessive Permissions | 660 | 99.4% |
| **MCP10:2025** — Supply-chain / untrusted package execution | 290 | 43.7% |
| **MCP03:2025** — Tool/launch integrity | 290 | 43.7% |
| **MCP04:2025** — Command injection surface | 205 | 30.9% |
| **MCP01:2025** — Token / secret mismanagement | 71 | 10.7% |
| **MCP09:2025** — Transport security | 44 | 6.6% |

---

## Top 10 most-common findings (advisory-posture rules excluded)

| # | Rule | Severity | Configs | Share |
|--:|---|:---:|--:|--:|
| 1 | `AAK-MCP-005` — `npx`/`uvx` fetch-and-execute remote packages | MEDIUM | 290 | 43.7% |
| 2 | `AAK-MCP-006` — command uses a relative path | MEDIUM | 175 | 26.4% |
| 3 | `AAK-MCP-001` — remote MCP server without authentication | **CRITICAL** | 161 | 24.2% |
| 4 | `AAK-SECRET-007` — secret in MCP server env block | MEDIUM | 70 | 10.5% |
| 5 | `AAK-MCP-003` — env exposes secrets to the tool process | HIGH | 70 | 10.5% |
| 6 | `AAK-MCP-STDIO-LAUNCHER-INJECT-001` — stdio server launches a shell interpreter with an exec flag / interpolated argv | HIGH | 49 | 7.4% |
| 7 | `AAK-MCP-009` — server URL points at localhost / internal network | HIGH | 44 | 6.6% |
| 8 | `AAK-TRANSPORT-003` — deprecated SSE transport | MEDIUM | 16 | 2.4% |
| 9 | `AAK-MCP-004` — excessive number of MCP servers declared | HIGH | 12 | 1.8% |
| 10 | `AAK-MCP-002` — command runs with shell expansion | **CRITICAL** | 9 | 1.4% |

Two advisory-posture rules are **excluded** so the story isn't inflated (tracked
in `results.json` under `excluded_advisory_rules`): `AAK-MCP-ATTEST-001`
(deny-by-default attestation — fires on ~every server) and `AAK-MCP-007` (no
version pin in `args`, LOW). The two fixes that matter: **pin what you launch**
(43.7% fetch-and-run unpinned) and **authenticate mutating remote servers**
(24.2% have no auth).

---

## Methodology

- **Corpus.** MCP config files discovered via GitHub Code Search across five
  filename queries (`.mcp.json`, `mcp.json`, `claude_desktop_config.json`,
  `cline_mcp_settings.json`, `mcp_settings.json`), deduplicated by repo+path at
  crawl time and again by file **content** at scan time — 748 downloaded files →
  **664 distinct** (83 byte-identical duplicates + 1 unparseable removed).
- **Scanner.** AgentAuditKit **v0.3.42, 225 rules**, no cloud/LLM/telemetry. Each
  config scanned in isolation via the same `run_scan` + `compute_score` the CLI
  and MCP Security Index use. Deterministic: same corpus → identical
  `results.json`.
- **Public metadata only.** We scan committed configuration files. No live
  server probing, no exploitation, no credential use. Rate-limited crawl,
  respects GitHub API limits.

### Reproducibility

- **Ruleset:** the exact 225 rules are the committed, Sigstore-signable
  [`rules.json`](../../rules.json) bundle at this repo's HEAD.
- **Corpus:** regenerate with the committed crawler + the same five queries (the
  command below). We deliberately do **not** publish a per-server list mapping
  repos to grades/findings — that would de-anonymize specific servers, against
  the repo's 90-day coordinated-disclosure policy. The report is aggregate-only.

```bash
git clone https://github.com/sattyamjjain/agent-audit-kit && cd agent-audit-kit
pip install -e .
export GITHUB_TOKEN=$(gh auth token)
python benchmarks/crawler.py --limit 1200 --output benchmarks/results.json   # 5-query sweep
python research/state-of-mcp-2026/run_report.py \
    --corpus benchmarks/data --out research/state-of-mcp-2026/results.json
```

Scan your own in 30s, fully offline: `pip install agent-audit-kit && agent-audit-kit scan .`

---

## Limitations (read before quoting)

1. **Public-metadata static scan, not runtime.** A matched pattern is not proof
   of exploitability in context; a clean scan is not proof of safety.
2. **N of unreachable servers.** Downloads fail for private/deleted repos and
   rate-limited fetches; those are dropped, so 664 is "distinct public configs we
   could fetch and parse," not "all MCP servers."
3. **Sample skews to discoverable public repos** (Code Search ranks by relevance
   + stars). Not a uniform random sample of the ~9,652 registered servers.
4. **External figures are as-reported** by the cited third parties (MCP Registry
   9,652 servers 2026-05-24; Knostic 1,862 exposed / 119-of-119 unauthenticated;
   the 2,614-server 82%-path-traversal survey). Only the 664-config scan is ours.
5. **No CVEs/advisories were filed for this report.** A static match on a
   committed config is not live-exploitation proof, and disclosing a specific
   server is a deliberate, per-maintainer coordinated-disclosure decision — not
   something to automate off an aggregate scan. Genuine exposures surface through
   the [MCP Security Index](https://sattyamjjain.github.io/agent-audit-kit/) under
   the 90-day policy.

---

## Distribution (drafts — post manually, nothing here auto-posts)

Replace `<report link>` with the permalink before posting. Quote 664, never 1,000.

**Show HN** (Tue/Wed ~8–9am ET):
```
Show HN: I scanned 664 public MCP server configs — 1 in 4 has a critical flaw
```
> First comment: I run an open-source, offline static scanner for MCP/agent
> configs (agent-audit-kit, MIT). I scanned 664 distinct public .mcp.json files
> deterministically — no cloud, no LLM. 26% have a critical issue; the median
> config grades a B, the top 10% an A. The two big ones are boring and fixable:
> 44% launch with npx/uvx and no pinned version, and 24% declare a remote server
> with no auth (matches Knostic's separate 119-of-119 unauthenticated finding).
> Honest caveats: sample skews to public repos, static analysis over/under-counts,
> and I say "664 configs", not "the MCP ecosystem". Method + reproduce command in
> the report. Not a runtime tool — this is the static/CI/offline angle.
> Report: <report link> · Repo: github.com/sattyamjjain/agent-audit-kit

**r/netsec** (research framing; tool name in body, not title):
```
The State of MCP Security 2026: 664 public MCP configs scanned (data + reproducible method)
```
> Scanned 664 distinct public MCP configs with an offline deterministic static
> analyzer. 26% critical; median grade B. Mapped to OWASP MCP Top 10: 99% trip
> MCP07 (authorization), 44% the supply-chain risk (npx/uvx unpinned launch), 24%
> no-auth remote. Raw results.json + exact reproduce command committed. Scanner is
> MIT (agent-audit-kit). Caveats in the report (sample skew, static
> over/under-count, N=664 is a sample). <report link>

**OWASP GenAI / MCP Top 10 working group** (`github.com/OWASP/www-project-mcp-top-10`, Phase-3 beta — open a Discussion, contribute data not a tool plug):
> Sharing real-world prevalence data as possible evidence for the MCP Top 10. I
> statically scanned 664 distinct public MCP configs (offline, deterministic,
> reproducible; raw results committed). Mapped to the current list: 99.4% trip
> MCP07 (authorization/excessive perms), 43.7% the supply-chain/untrusted-execution
> risk (npx/uvx unpinned launch), and 24.2% declare a remote server with no auth —
> corroborating Knostic's 119-of-119 unauthenticated-tool-listing finding from the
> deployment side. Happy to contribute the dataset or a category-by-category
> breakdown. <report link>
