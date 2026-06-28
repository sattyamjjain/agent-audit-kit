# The State of MCP Security 2026

## We scanned 571 public MCP server configs with an offline static scanner. 1 in 4 ships a critical-severity flaw, and only ~29% earn an "A".

> **Reproducible data report.** Every number under "What we measured" comes from
> running [AgentAuditKit](https://github.com/sattyamjjain/agent-audit-kit)
> (v0.3.41, 225 rules, fully offline, MIT) over a content-deduplicated corpus of
> public MCP configs. The raw aggregate is committed alongside this file as
> [`results.json`](results.json); the exact command to regenerate it is in
> *Reproduce this*. External figures (next section) are attributed to their
> sources, not measured by us.

---

## Why this matters now (verified external anchors)

The Model Context Protocol went from proposal to cross-vendor default in ~18
months, and the exposed surface is already large and under-secured:

- **The official MCP Registry listed 9,652 servers as of 2026-05-24** — the
  ecosystem is now thousands of independently-published servers, not a handful.
  *(Source: official MCP Registry export, 2026-05-24.)*
- **Knostic found 1,862 MCP servers exposed on the public internet, and 119 of
  119 they probed allowed unauthenticated tool-listing** — i.e. every exposed
  server they tested would hand its tool catalog to an anonymous caller.
  *(Source: Knostic research.)*
- **A 2,614-server survey found 82% had path-traversal issues.** *(Source: the
  2,614-server MCP survey.)*

These say the *population* is big and the *authentication/path* hygiene is poor.
This report adds the missing piece: **what the configuration files people
actually commit look like, measured deterministically.**

### Where AgentAuditKit fits (two defensible wedges)

1. **Offline & deterministic.** Every figure here was produced with zero network
   calls and no LLM — the same corpus yields the same findings, byte-for-byte.
   That is what makes a *report* reproducible and an *audit* defensible.
2. **Compliance-evidence, not just findings.** The same scan emits SARIF for the
   GitHub Security tab plus auditor-ready PDF evidence mapped to 13 frameworks
   (EU AI Act, SOC 2, ISO 27001/42001, HIPAA, NIST AI RMF, and regional regimes).

---

## What we measured

- **Corpus:** 631 publicly-committed MCP config files discovered via GitHub Code
  Search (seeded to overlap the MCP Registry export + mcp.so top-N), then
  content-deduplicated — **59 byte-identical duplicates and 1 unparseable file
  removed, leaving 571 distinct configs.**
- **Tool:** AgentAuditKit v0.3.41 — 225 deterministic rules, no cloud, no
  telemetry. Each config scanned in isolation via the same `run_scan` +
  `compute_score` the CLI and the MCP Security Index use.

### Headline

- **147 of 571 configs (25.7%) contain at least one CRITICAL-severity finding.**
- **143 of 571 (25.0%) contain at least one HIGH-severity finding.**
- Across all configs: **259 critical · 280 high · 2,256 medium · 586 low**
  findings.

### Grade distribution (A–F)

| Grade | Configs | Share |
|:-----:|--------:|------:|
| **A** | 165 | 28.9% |
| **B** | 213 | 37.3% |
| **C** | 78 | 13.7% |
| **D** | 45 | 7.9% |
| **F** | 70 | 12.3% |

**~1 in 5 configs (20.1%) land at D or F.** The grade is AAK's penalty-based
score (start at 100, deduct per finding severity), identical to `aak score`.

### Where the findings cluster (per-category hit rate)

| Category | Configs with ≥1 finding | Share |
|---|--:|--:|
| MCP configuration | 567 | 99.3% |
| Secret exposure | 63 | 11.0% |
| Transport security | 18 | 3.2% |
| Tool poisoning / agent-config / legal | 1 each | ~0.2% |

The story is overwhelmingly a **configuration** story: launch/transport/auth
hygiene in the `.mcp.json` itself, not exotic tool-poisoning.

### Top 5 misconfigurations (advisory-posture rules excluded)

| Rule | Severity | Configs | Share |
|---|:---:|--:|--:|
| `AAK-MCP-005` — server uses `npx`/`uvx` to fetch-and-execute remote packages | MEDIUM | 248 | 43.4% |
| `AAK-MCP-006` — server command uses a relative path | MEDIUM | 149 | 26.1% |
| `AAK-MCP-001` — remote MCP server without authentication | **CRITICAL** | 136 | 23.8% |
| `AAK-MCP-003` — server environment exposes secrets to the tool process | HIGH | 63 | 11.0% |
| `AAK-SECRET-007` — secret in MCP server environment block | MEDIUM | 63 | 11.0% |

The two things worth fixing **today**: (1) **pin what you launch** — 43% of
configs `npx`/`uvx` fetch-and-run whatever the registry serves that moment; (2)
**authenticate mutating remote servers** — ~1 in 4 declares a remote server with
no auth, which aligns with Knostic's 119-of-119 unauthenticated finding from the
*deployment* side.

### What we deliberately did NOT count

To avoid inflating the story, two advisory-posture rules are **excluded** from
the "top misconfigurations" table (they are tracked in `results.json` under
`excluded_advisory_rules`):

- `AAK-MCP-ATTEST-001` (deny-by-default attestation) — fires on nearly every
  server because attestation isn't an ecosystem norm yet; a roadmap signal, not
  an exploit.
- `AAK-MCP-007` (no version pin in `args`, LOW) — advisory hygiene.

---

## Honesty caveats (read before quoting)

1. **The sample skews to discoverable public repos** (Code Search ranks by
   relevance + stars). It is "configs people publish," not a uniform random
   sample of the ~9,652 registered servers.
2. **Static analysis both over- and under-counts.** A matched pattern is not
   proof of exploitability in context; a clean scan is not proof of safety.
3. **N = 571 is a sample.** We say "571 configs," never "the MCP ecosystem."
4. **External figures are as-reported** by the cited third parties (MCP Registry,
   Knostic, the 2,614-server survey); only the 571-config scan is our own
   measurement.

---

## Reproduce this

```bash
git clone https://github.com/sattyamjjain/agent-audit-kit && cd agent-audit-kit
pip install -e .

# 1. Acquire the corpus (reuses the existing crawler)
export GITHUB_TOKEN=$(gh auth token)
python benchmarks/crawler.py --limit 500 --output benchmarks/results.json

# 2. Scan + aggregate (reuses agent_audit_kit.engine.run_scan + scoring.compute_score)
python research/state-of-mcp-2026/run_report.py \
    --corpus benchmarks/data \
    --out research/state-of-mcp-2026/results.json
```

The harness contains **no scanner** — it calls the same `run_scan` /
`compute_score` the product ships. Output is deterministic for a fixed corpus.

## Methodology note: novel-pattern discovery

This harness reports the **prevalence of patterns AAK already has rules for** —
it cannot, by construction, surface a misconfiguration class for which no rule
exists. Discovering genuinely *uncovered* patterns is a manual corpus-inspection
follow-up; any that hold up will be filed as `cve-response`/finding issues and
turned into rules separately. No speculative findings were filed for this report.

---

*Marketing/launch copy for this report lives in
[`launch/state-of-mcp-security-2026.md`](../../launch/state-of-mcp-security-2026.md);
this file is the rigorous, reproducible source of record.*
