# State of MCP Security 2026 — Prevalence & Score Calibration

## We scanned 2,303 distinct public MCP server configs with an offline static scanner. More than 1 in 2 declares a remote server with no authentication, more than half ship a critical-severity flaw, the median config scores a **B**, and the top 10% score an **A**.

> **Reproducible data report** (empirical companion to the
> [State-of-MCP-Security report](REPORT.md), issue #23). Every "measured" number
> below comes from running
> [AgentAuditKit](https://github.com/sattyamjjain/agent-audit-kit) (fully offline,
> deterministic, MIT; the exact ruleset is the committed
> [`rules.json`](../../rules.json) bundle at this repo's HEAD) over a
> content-deduplicated corpus of public MCP configs. Raw aggregate:
> [`results.json`](results.json). External figures are attributed to their
> sources, not measured by us.
>
> **On the corpus.** Two provenance-tracked sources — a GitHub Code Search crawl of
> public MCP config files and the official MCP Registry's latest-version servers —
> deduplicated by file **content**: **2,303 distinct configs**. This is the same
> corpus [`REPORT.md`](REPORT.md) documents; the split and provenance are in the
> Methodology section below. We report the real N — 2,303 — not a round target.

---

## Three headline numbers

1. **<!-- report:noauth-pct -->52.1<!-- /report -->% (<!-- report:noauth-n -->1,200<!-- /report -->/2,303) of public MCP configs declare a remote server with no
   authentication** — a *critical*-severity posture (`AAK-MCP-001`) and the single
   most common finding in the corpus. It corroborates Knostic's 119-of-119
   unauthenticated tool-listing finding from the deployment side.
2. **<!-- report:critical-pct -->52.6<!-- /report -->% (<!-- report:critical-n -->1,212<!-- /report -->/2,303) contain at least one critical-severity finding** — driven
   almost entirely by that no-auth remote-server class.
3. **The median public MCP config scores a B; the top 10% score an A.**
   (This is the empirical score-calibration anchor issue #23 asked for. The
   roadmap *guessed* "median C-, top 10% B+" — the real distribution skews higher,
   because most configs carry one dominant critical posture rather than a long tail
   of findings.)

---

## Score distribution (A–F) — the calibration

| Grade | Configs | Share | Cumulative |
|:-----:|--------:|------:|-----------:|
| **A** | 632 | 27.4% | 27.4% |
| **B** | 1,426 | 61.9% | 89.4% |
| **C** | 111 | 4.8% | 94.2% |
| **D** | 49 | 2.1% | 96.3% |
| **F** | 85 | 3.7% | 100% |

- **Median grade: B** (the 1,152nd config falls inside the B band: cumulative
  A = 632 is below the midpoint, A+B = 2,058 is above it).
- **Top 10% (best ~230 configs): all grade A** (A alone holds 632).
- **5.8% (134) land at D or F.**

The grade is AAK's penalty-based score (start at 100; deduct 20/CRITICAL,
10/HIGH, 5/MEDIUM, 2/LOW), identical to `aak score`. **Calibration takeaway for
#23:** the current penalties produce a sane spread — a clear A/B mode with a real
D/F tail — and the median lands at B, not the "C-" the roadmap assumed. What moved
the story since the earlier crawl-only corpus is not the penalty weights but the
corpus: adding the MCP Registry surfaced how dominant the no-auth remote-server
posture is. No penalty re-weighting is done in this report (that's a follow-up).

---

## Severity + category prevalence

**All findings:** 1,338 critical · 318 high · 4,426 medium · 1,221 low.
**Per-config:** 52.8% have ≥1 critical; 7.2% have ≥1 high.

| AAK category | Configs with ≥1 finding | Share |
|---|--:|--:|
| MCP configuration | 2,299 | 99.8% |
| Secret exposure | 70 | 3.0% |
| Transport security | 42 | 1.8% |
| Tool poisoning / agent-config | 1 each | ~0.0% |

### OWASP MCP Top 10 — configs tripping each risk

| OWASP MCP | Configs | Share |
|---|--:|--:|
| **MCP07:2025** — Insufficient Authorization / Excessive Permissions | 2,299 | 99.8% |
| **MCP01:2025** — Token / secret mismanagement | 489 | 21.2% |
| **MCP03:2025** — Tool/launch integrity | 450 | 19.5% |
| **MCP10:2025** — Supply-chain / untrusted package execution | 450 | 19.5% |
| **MCP04:2025** — Command injection surface | 209 | 9.1% |
| **MCP09:2025** — Transport security | 44 | 1.9% |

---

## Top 10 most-common findings (advisory-posture rules excluded)

| # | Rule | Severity | Configs | Share |
|--:|---|:---:|--:|--:|
| 1 | `AAK-MCP-001` — remote MCP server without authentication | **CRITICAL** | <!-- report:noauth-n -->1,200<!-- /report --> | <!-- report:noauth-pct -->52.1<!-- /report -->% |
| 2 | `AAK-MCP-005` — `npx`/`uvx` fetch-and-execute remote packages | MEDIUM | 450 | 19.5% |
| 3 | `AAK-OAUTH-008` — MCP OAuth surface with no RFC 9728 PRM discovery | LOW | <!-- report:oauth008-n -->424<!-- /report --> | <!-- report:oauth008-pct -->18.4<!-- /report -->% |
| 4 | `AAK-MCP-006` — command uses a relative path | MEDIUM | 179 | 7.8% |
| 5 | `AAK-MCP-003` — env exposes secrets to the tool process | HIGH | 70 | 3.0% |
| 6 | `AAK-SECRET-007` — secret in MCP server env block | MEDIUM | 70 | 3.0% |
| 7 | `AAK-MCP-STDIO-LAUNCHER-INJECT-001` — stdio server launches a shell interpreter with an exec flag / interpolated argv | HIGH | 49 | 2.1% |
| 8 | `AAK-MCP-009` — server URL points at localhost / internal network | HIGH | 44 | 1.9% |
| 9 | `AAK-TRANSPORT-003` — deprecated SSE transport | MEDIUM | 36 | 1.6% |
| 10 | `AAK-MCP-004` — excessive number of MCP servers declared | HIGH | 12 | 0.5% |

Two advisory-posture rules are **excluded** so the story isn't inflated (tracked
in `results.json` under `excluded_advisory_rules`): `AAK-MCP-ATTEST-001`
(deny-by-default attestation — fires on ~every server) and `AAK-MCP-007` (no
version pin in `args`, LOW). The two fixes that matter, in order: **authenticate
remote servers** (<!-- report:noauth-pct -->52.1<!-- /report -->% declare one with no auth) and **pin what you launch**
(19.5% `npx`/`uvx`-fetch-and-run unpinned).

---

## Methodology

- **Corpus.** MCP config files from two provenance-tracked sources — a GitHub Code
  Search crawl across five filename queries (`.mcp.json`, `mcp.json`,
  `claude_desktop_config.json`, `cline_mcp_settings.json`, `mcp_settings.json`) and
  the official MCP Registry's latest-version servers — deduplicated by repo+path at
  crawl time and again by file **content** at scan time.
  <!-- corpus-provenance: 664 is the crawl-source subtotal in the deduped corpus, NOT the headline N (2,303) --> In-corpus split: **664 crawled + 1,639 registry = 2,303 distinct**, from **2,389 candidates** (85 byte-identical duplicates + 1 unparseable removed).
- **Scanner.** AgentAuditKit, offline and deterministic — no cloud, LLM, or
  telemetry. Each config scanned in isolation via the same `run_scan` +
  `compute_score` the CLI and MCP Security Index use. Deterministic: same corpus →
  byte-identical `results.json`.
- **Public metadata only.** We scan committed configuration files and public
  registry metadata. No live server probing, no exploitation, no credential use.
  Rate-limited crawl, respects GitHub API limits.

### Reproducibility

- **Ruleset:** the committed, Sigstore-signable [`rules.json`](../../rules.json)
  bundle at this repo's HEAD.
- **Corpus:** regenerate `results.json` from the committed manifest, offline and
  deterministically. We deliberately do **not** publish a per-server list mapping
  repos to grades/findings — that would de-anonymize specific servers, against the
  repo's 90-day coordinated-disclosure policy. The report is aggregate-only.

```bash
git clone https://github.com/sattyamjjain/agent-audit-kit && cd agent-audit-kit
pip install -e .
make report          # refreshes results.json from the committed manifest, offline + deterministic
# refreshing the corpus itself (the one network step) is separate:
python research/state-of-mcp-2026/fetch_registry.py --target 5000
```

At the published run the registry walk collected **1,641 distinct latest-version
servers** (`corpus/registry-manifest.json` → `distinct_latest_servers`, `fetched_at`
**2026-07-26**). `--target 5000` is deliberately larger than that so the walk runs to
cursor-exhaustion rather than stopping early; the MCP Registry grows over time, so a
later rerun that returns a larger N is registry growth, not a broken command.

Scan your own in 30s, fully offline: `pip install agent-audit-kit && agent-audit-kit scan .`

---

## Limitations (read before quoting)

1. **Public-metadata static scan, not runtime.** A matched pattern is not proof
   of exploitability in context; a clean scan is not proof of safety. Auth posture
   is inferred from declared config, not a live probe.
2. **N of unreachable servers.** Downloads fail for private/deleted repos and
   rate-limited fetches; those are dropped, so 2,303 is "distinct public configs we
   could fetch and parse," not "all MCP servers."
3. **Sample skews to discoverable public repos + registry latest-version entries**
   (Code Search ranks by relevance + stars; the registry crawl is a 40-page
   snapshot). Not a uniform random sample of all registered servers.
4. **External figures are as-reported** by the cited third parties (Knostic 1,862
   exposed / 119-of-119 unauthenticated; the 2,614-server 82%-path-traversal
   survey). Only the 2,303-config scan is ours.
5. **No CVEs/advisories were filed for this report.** A static match on a
   committed config is not live-exploitation proof, and disclosing a specific
   server is a deliberate, per-maintainer coordinated-disclosure decision — not
   something to automate off an aggregate scan. Genuine exposures surface through
   the [MCP Security Index](https://sattyamjjain.github.io/agent-audit-kit/) under
   the 90-day policy.

---

## Distribution

Ready-to-post launch copy lives in one place —
[`docs/DISTRIBUTION-CHECKLIST.md`](../../docs/DISTRIBUTION-CHECKLIST.md) — and every
quantitative token there is substituted from `results.json`. This report is the
data; the checklist is the copy. Nothing here or there auto-posts.
