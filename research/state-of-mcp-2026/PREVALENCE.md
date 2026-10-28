# State of MCP Security 2026 — Prevalence & Score Calibration

## We scanned <!-- report:corpus -->2,303<!-- /report --> distinct public MCP server configs with an offline static scanner. More than 1 in 2 declares a remote server with no authentication, more than half ship a critical-severity flaw, the median config scores a **<!-- report:median-grade -->B<!-- /report -->**, and the top 10% score an **<!-- report:top-decile-grade -->A<!-- /report -->**.

> **Reproducible data report** (empirical companion to the
> [State-of-MCP-Security report](REPORT.md), issue #23). Every "measured" number
> below comes from running
> [AgentAuditKit](https://github.com/sattyamjjain/agent-audit-kit) (fully offline,
> deterministic, Apache-2.0; the exact ruleset is the committed
> [`rules.json`](../../rules.json) bundle at this repo's HEAD) over a
> content-deduplicated corpus of public MCP configs, and is the figure of report
> version 1.2. Raw aggregate: [`results.json`](results.json). External figures are
> attributed to their sources, not measured by us.
>
> **On the corpus.** Two provenance-tracked sources — a GitHub Code Search crawl of
> public MCP config files and the official MCP Registry's latest-version servers —
> deduplicated by file **content**: **<!-- report:corpus -->2,303<!-- /report --> distinct configs**. This is the same
> corpus [`REPORT.md`](REPORT.md) documents; the split and provenance are in the
> Methodology section below. We report the real N — <!-- report:corpus -->2,303<!-- /report --> — not a round target.

---

## Three headline numbers

1. **<!-- report:noauth-pct -->50.6<!-- /report -->% (<!-- report:noauth-n -->1,166<!-- /report -->/<!-- report:corpus -->2,303<!-- /report -->) of public MCP configs declare a remote server with no
   authentication** — a *critical*-severity posture (`AAK-MCP-001`) and the single
   most common finding in the corpus. It corroborates Knostic's 119-of-119
   unauthenticated tool-listing finding from the deployment side.
2. **<!-- report:critical-pct -->51.5<!-- /report -->% (<!-- report:critical-n -->1,185<!-- /report -->/<!-- report:corpus -->2,303<!-- /report -->) contain at least one critical-severity finding** — driven
   almost entirely by that no-auth remote-server class.
3. **The median public MCP config scores a <!-- report:median-grade -->B<!-- /report -->; the top 10% score an <!-- report:top-decile-grade -->A<!-- /report -->.**
   (This is the empirical score-calibration anchor issue #23 asked for. The
   roadmap *guessed* "median C-, top 10% B+" — the real distribution skews higher,
   because most configs carry one dominant critical posture rather than a long tail
   of findings.)

---

## Score distribution (A–F) — the calibration

| Grade | Configs | Share | Cumulative |
|:-----:|--------:|------:|-----------:|
| **A** | <!-- report:grade-a -->788<!-- /report --> | <!-- report:grade-a-pct -->34.2<!-- /report -->% | <!-- report:grade-a-cum -->34.2<!-- /report -->% |
| **B** | <!-- report:grade-b -->1,280<!-- /report --> | <!-- report:grade-b-pct -->55.6<!-- /report -->% | <!-- report:grade-b-cum -->89.8<!-- /report -->% |
| **C** | <!-- report:grade-c -->96<!-- /report --> | <!-- report:grade-c-pct -->4.2<!-- /report -->% | <!-- report:grade-c-cum -->94.0<!-- /report -->% |
| **D** | <!-- report:grade-d -->52<!-- /report --> | <!-- report:grade-d-pct -->2.3<!-- /report -->% | <!-- report:grade-d-cum -->96.2<!-- /report -->% |
| **F** | <!-- report:grade-f -->87<!-- /report --> | <!-- report:grade-f-pct -->3.8<!-- /report -->% | 100% |

- **Median grade: <!-- report:median-grade -->B<!-- /report -->**, the grade of config <!-- report:median-rank -->1,152<!-- /report --> of <!-- report:corpus -->2,303<!-- /report --> ranked best
  first (cumulative A = <!-- report:grade-a -->788<!-- /report -->, A+B = <!-- report:grade-ab-n -->2,068<!-- /report -->).
- **Top 10% (the best <!-- report:top-decile-n -->230<!-- /report --> configs): none below <!-- report:top-decile-grade -->A<!-- /report -->** (A alone holds <!-- report:grade-a -->788<!-- /report -->).
- **<!-- report:grade-df-pct -->6.0<!-- /report -->% (<!-- report:grade-df-n -->139<!-- /report -->) land at D or F.**

The grade is AAK's penalty-based score (start at 100; deduct 20/CRITICAL,
10/HIGH, 5/MEDIUM, 2/LOW), identical to `aak score`. **Calibration takeaway for
#23:** the current penalties produce a sane spread — a clear A/B mode with a real
D/F tail — and the median lands at <!-- report:median-grade -->B<!-- /report -->, not the "C-" the roadmap assumed. What moved
the story since the earlier crawl-only corpus is not the penalty weights but the
corpus: adding the MCP Registry surfaced how dominant the no-auth remote-server
posture is. No penalty re-weighting is done in this report (that's a follow-up).

---

## Severity + category prevalence

**All findings:** <!-- report:findings-critical -->1,293<!-- /report --> critical · <!-- report:findings-high -->208<!-- /report --> high · <!-- report:findings-medium -->4,930<!-- /report --> medium · <!-- report:findings-low -->652<!-- /report --> low.
**Per-config:** <!-- report:critical-pct -->51.5<!-- /report -->% have ≥1 critical; <!-- report:high-pct -->4.8<!-- /report -->% have ≥1 high.

<!-- report:category-table -->

| AAK category | Configs with ≥1 finding | Share |
|---|--:|--:|
| MCP Configuration | 2,300 | 99.9% |
| Supply Chain | 288 | 12.5% |
| Transport Security | 53 | 2.3% |
| Legal Compliance | 8 | 0.3% |
| Secret Exposure | 4 | 0.2% |
| Composition | 1 | 0.0% |
| Tool Poisoning | 1 | 0.0% |

<!-- /report -->

### OWASP MCP Top 10 — configs tripping each risk

Each rule carries the OWASP MCP Top 10 ids (v0.1, the 2025 edition) of the risks
it detects, under the titles OWASP gives them. A config trips a risk when one of
its findings carries the id; the two advisory-posture rules below are left out, as
in the top-ten table. Before report version 1.1 this table used AAK's own labels
for the ids, in a different order, so the two do not compare row for row.

<!-- report:owasp-mcp-table -->

| OWASP MCP Top 10 | Risk | Configs | Share |
|---|---|--:|--:|
| **MCP07:2025** | Insufficient Authentication & Authorization | 1,595 | 69.3% |
| **MCP01:2025** | Token Mismanagement & Secret Exposure | 455 | 19.8% |
| **MCP04:2025** | Software Supply Chain Attacks & Dependency Tampering | 453 | 19.7% |
| **MCP05:2025** | Command Injection & Execution | 213 | 9.2% |
| **MCP02:2025** | Privilege Escalation via Scope Creep | 14 | 0.6% |
| **MCP09:2025** | Shadow MCP Servers | 3 | 0.1% |
| **MCP10:2025** | Context Injection & Over-Sharing | 2 | 0.1% |
| **MCP03:2025** | Tool Poisoning | 1 | 0.0% |

<!-- /report -->

---

## Top 10 most-common findings (advisory-posture rules excluded)

<!-- report:top-misconfig-table -->

| # | Rule | Finding | Severity | Configs | Share |
|--:|---|---|:---:|--:|--:|
| 1 | `AAK-MCP-001` | Remote MCP server without authentication | **CRITICAL** | 1,166 | 50.6% |
| 2 | `AAK-MCP-005` | MCP server uses npx/uvx to fetch and execute remote packages | MEDIUM | 450 | 19.5% |
| 3 | `AAK-OAUTH-008` | MCP OAuth surface with no RFC 9728 Protected Resource Metadata discovery | LOW | 424 | 18.4% |
| 4 | `AAK-SUPPLY-001` | MCP server package not pinned to exact version | MEDIUM | 284 | 12.3% |
| 5 | `AAK-MCP-006` | MCP server command uses relative path | MEDIUM | 179 | 7.8% |
| 6 | `AAK-MCP-STDIO-LAUNCHER-INJECT-001` | MCP stdio server launches a shell-style interpreter with an exec flag or interpolated args | HIGH | 49 | 2.1% |
| 7 | `AAK-TRANSPORT-003` | Deprecated SSE transport in use | MEDIUM | 47 | 2.0% |
| 8 | `AAK-MCP-003` | MCP server environment exposes secrets | HIGH | 30 | 1.3% |
| 9 | `AAK-MCP-SERENA-CVE-2026-49471-001` | Serena MCP toolkit < 1.5.2 (unauthenticated dashboard → DNS-rebinding RCE) | HIGH | 19 | 0.8% |
| 10 | `AAK-MCP-004` | Excessive number of MCP servers declared | HIGH | 12 | 0.5% |

<!-- /report -->

Two advisory-posture rules are **excluded** so the story isn't inflated (tracked
in `results.json` under `excluded_advisory_rules`): `AAK-MCP-ATTEST-001`
(deny-by-default attestation — fires on ~every server) and `AAK-MCP-007` (no
version pin in `args`, LOW). The two fixes that matter, in order: **authenticate
remote servers** (<!-- report:noauth-pct -->50.6<!-- /report -->% declare one with no auth) and **pin what you launch**
(<!-- report:supply001-pct -->12.3<!-- /report -->% launch a package with no pinned version, and <!-- report:mcp005-pct -->19.5<!-- /report -->% fetch and execute one
through `npx`/`uvx` at launch).

---

## Methodology

- **Corpus.** MCP config files from two provenance-tracked sources — a GitHub Code
  Search crawl across five filename queries (`.mcp.json`, `mcp.json`,
  `claude_desktop_config.json`, `cline_mcp_settings.json`, `mcp_settings.json`) and
  the official MCP Registry's latest-version servers — deduplicated by repo+path at
  crawl time and again by file **content** at scan time.
  <!-- corpus-provenance: 664 is the crawl-source subtotal in the deduped corpus, NOT the headline N (2,303) --> In-corpus split: **<!-- report:corpus-crawl -->664<!-- /report --> crawled + <!-- report:corpus-registry -->1,639<!-- /report --> registry = <!-- report:corpus -->2,303<!-- /report --> distinct**, from **<!-- report:corpus-candidates -->2,389<!-- /report --> candidates** (<!-- report:corpus-duplicates -->85<!-- /report --> byte-identical duplicates + <!-- report:corpus-unparseable -->1<!-- /report --> unparseable removed).
- **Registry configs.** Each registry server becomes one scannable config: its
  remote endpoint with the names of the headers it declares, or its package
  launched at the version the registry record states (`npx -y <package>@<version>`,
  `uvx <package>@<version>`).
- **Scanner.** AgentAuditKit, offline and deterministic — no cloud, LLM, or
  telemetry. Each config is written alone as `.mcp.json`, the name every scanner
  reads, and scanned via the same `run_scan` + `compute_score` the CLI and MCP
  Security Index use. Deterministic: same corpus → byte-identical `results.json`.
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

At the published run the registry walk collected **<!-- report:registry-servers -->1,641<!-- /report --> distinct latest-version
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
   rate-limited fetches; those are dropped, so <!-- report:corpus -->2,303<!-- /report --> is "distinct public configs we
   could fetch and parse," not "all MCP servers."
3. **Sample skews to discoverable public repos + registry latest-version entries**
   (Code Search ranks by relevance + stars; the registry crawl is a 40-page
   snapshot). Not a uniform random sample of all registered servers.
4. **External figures are as-reported** by the cited third parties (Knostic 1,862
   exposed / 119-of-119 unauthenticated; the 2,614-server 82%-path-traversal
   survey). Only the <!-- report:corpus -->2,303<!-- /report -->-config scan is ours.
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
