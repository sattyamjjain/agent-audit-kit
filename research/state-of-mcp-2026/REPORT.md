# The State of MCP Security 2026

## We scanned 571 public MCP server configs with an offline static scanner. 1 in 4 ships a critical-severity flaw, and only ~29% earn an "A".

> **Reproducible data report.** Every number under "What we measured" comes from
> running [AgentAuditKit](https://github.com/sattyamjjain/agent-audit-kit)
> (v0.3.42, 225 rules, fully offline, MIT) over a content-deduplicated corpus of
> public MCP configs. The raw aggregate is committed alongside this file as
> [`results.json`](results.json); the command to regenerate it is in
> *How we scan*. External figures (next section) are attributed to their
> sources, not measured by us.

---

## Executive summary

- We statically scanned **571 distinct public MCP server configuration files**.
  **147 (25.7%) contain at least one critical-severity finding**; only **165
  (28.9%) earn an "A"** and **115 (20.1%) land at D or F**.
- The single most common problem is **fetch-and-execute at launch**: **43.4% of
  configs** start their server with `npx`/`uvx`, running whatever the registry
  serves that moment (no pinned version, no hash).
- The most common *critical* problem is **missing authentication on a remote
  server** — **23.8% of configs** — which matches, from the deployment side,
  Knostic's finding that **119 of 119** exposed servers they probed allowed
  unauthenticated tool-listing.
- Mapped to the OWASP MCP Top 10, **99.3% of configs** trip **MCP07:2025
  (Insufficient Authorization / Excessive Permissions)** — this is an
  authorization-and-launch-hygiene story, not exotic tool-poisoning.
- It's fixable with a linter in CI, not a new exploit: **pin what you launch**
  and **require a credential on anything mutating**.

---

## Why this matters now (verified external anchors)

The Model Context Protocol went from proposal to cross-vendor default in ~18
months, and the exposed surface is already large and under-secured:

- **The official MCP Registry listed 9,652 servers as of 2026-05-24** — the
  ecosystem is now thousands of independently-published servers, not a handful.
  *(Source: official MCP Registry export, 2026-05-24.)*
- **Knostic found 1,862 MCP servers exposed on the public internet, and 119 of
  119 they probed allowed unauthenticated tool-listing** — every exposed server
  they tested would hand its tool catalog to an anonymous caller.
  *(Source: Knostic research.)*
- **A 2,614-server survey found 82% had path-traversal issues.**
  *(Source: the 2,614-server MCP survey.)*

Those say the *population* is big and the *auth/path* hygiene is poor. This
report adds the missing piece: **what the configuration files people actually
commit look like, measured deterministically.**

---

## What we measured

- **Corpus.** 631 publicly-committed MCP config files discovered via GitHub Code
  Search (seeded to overlap the MCP Registry export + mcp.so top-N), then
  content-deduplicated — **59 byte-identical duplicates and 1 unparseable file
  removed, leaving 571 distinct configs.**
- **Scanner.** AgentAuditKit **v0.3.42, 225 rules** — no cloud, no telemetry, no
  LLM. Each config is scanned in isolation through the same `run_scan` +
  `compute_score` the CLI and the public MCP Security Index use. Deterministic:
  the same corpus produces the same `results.json`, byte-for-byte.

### Headline

- **147 of 571 (25.7%) have ≥1 CRITICAL finding.**
- **143 of 571 (25.0%) have ≥1 HIGH finding.**
- All findings: **259 critical · 280 high · 2,256 medium · 586 low.**

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

### OWASP MCP Top 10 — configs tripping each risk

| OWASP MCP | Configs | Share |
|---|--:|--:|
| **MCP07:2025** — Insufficient Authorization / Excessive Permissions | 567 | 99.3% |
| **MCP10:2025** — Supply-chain / untrusted package execution | 248 | 43.4% |
| **MCP03:2025** — Tool/launch integrity | 248 | 43.4% |
| **MCP04:2025** — Command injection surface | 174 | 30.5% |
| **MCP01:2025** — Token / secret mismanagement | 64 | 11.2% |
| **MCP09:2025** — Transport security | 38 | 6.7% |

### Top 5 misconfigurations (advisory-posture rules excluded)

| Rule | Severity | Configs | Share |
|---|:---:|--:|--:|
| `AAK-MCP-005` — server uses `npx`/`uvx` to fetch-and-execute remote packages | MEDIUM | 248 | 43.4% |
| `AAK-MCP-006` — server command uses a relative path | MEDIUM | 149 | 26.1% |
| `AAK-MCP-001` — remote MCP server without authentication | **CRITICAL** | 136 | 23.8% |
| `AAK-MCP-003` — server environment exposes secrets to the tool process | HIGH | 63 | 11.0% |
| `AAK-SECRET-007` — secret in MCP server environment block | MEDIUM | 63 | 11.0% |

Two advisory-posture rules are **excluded** from this table so the story isn't
inflated (tracked in `results.json` under `excluded_advisory_rules`):
`AAK-MCP-ATTEST-001` (deny-by-default attestation — fires on nearly every server
because attestation isn't an ecosystem norm yet) and `AAK-MCP-007` (no version
pin in `args`, LOW — advisory hygiene).

---

## Case studies (CVE-class, anonymized)

The snippets below are **illustrative, anonymized reconstructions** of the most
common patterns — not any specific scanned repo (per our 90-day
coordinated-disclosure policy, only aggregates are published). Each maps a top
finding to the disclosed CVE class it mirrors.

### 1. Unauthenticated remote server (`AAK-MCP-001`, 23.8% · CRITICAL)
CVE class: **Azure-MCP no-auth (CVE-2026-32211), GitLab/Nocturne/AgenticMail
no-auth cluster (CVE-2026-44895/44830/50287).**

```jsonc
{ "mcpServers": { "gateway": {
    "url": "http://0.0.0.0:8080/mcp"    // network-bound, no Authorization header
} } }
```
A mutation-capable RPC endpoint reachable by anyone on the network. This is the
config-side mirror of Knostic's 119-of-119 unauthenticated tool-listing.
**Fix:** require a bearer/mTLS credential; bind `127.0.0.1` behind an
authenticating proxy.

### 2. Fetch-and-execute at launch (`AAK-MCP-005`, 43.4% · supply chain)
CVE class: **untrusted-package / rug-pull execution (MCP10:2025); the OX MCP
STDIO command-injection cluster.**

```jsonc
{ "mcpServers": { "tools": {
    "command": "npx", "args": ["-y", "some-mcp-server@latest"]   // unpinned, fetched every start
} } }
```
`@latest` (or no version) means the server runs whatever the registry serves at
launch — the contents can change between two starts without the config changing.
**Fix:** pin an exact version or a hash; vendor the package.

### 3. Secret in the environment block (`AAK-MCP-003` HIGH + `AAK-SECRET-007`, 11% each)
CVE class: **credential exposure / token mismanagement (MCP01:2025); the
splunk-mcp token-cleartext class (CVE-2026-20205).**

```jsonc
{ "mcpServers": { "svc": {
    "command": "svc-mcp",
    "env": { "API_TOKEN": "sk-live-REDACTED..." }   // long-lived secret in committed config
} } }
```
A real credential in a file that lands in git history and every clone.
**Fix:** reference an env var or secret manager; never inline the value.

---

## How we scan (offline, reproducible)

AgentAuditKit exists because of two properties hosted scanners can't match, and
they're exactly what makes this report trustworthy:

1. **Offline & deterministic.** Zero network calls, no LLM in the loop. Your
   code, configs, and secrets never leave the machine, and the same input always
   yields the same finding. A report you can re-run and check, not a vibe.
2. **Compliance-evidence, not just findings.** The same scan emits SARIF for the
   GitHub Security tab plus auditor-ready PDF evidence mapped to 13 frameworks
   (EU AI Act, SOC 2, ISO 27001/42001, HIPAA, NIST AI RMF, and regional regimes)
   — what you hand an auditor, not just a list.

### Reproduce this yourself

```bash
# Scan your own MCP/agent configs in 30s, fully offline:
pip install agent-audit-kit
agent-audit-kit scan .

# Regenerate this exact report:
git clone https://github.com/sattyamjjain/agent-audit-kit && cd agent-audit-kit
pip install -e .
export GITHUB_TOKEN=$(gh auth token)                                   # higher search rate limit
python benchmarks/crawler.py --limit 500 --output benchmarks/results.json   # acquire corpus
python research/state-of-mcp-2026/run_report.py \                      # scan + aggregate
    --corpus benchmarks/data --out research/state-of-mcp-2026/results.json
```

The harness contains **no scanner** — it calls the same `run_scan` /
`compute_score` the product ships. Output is deterministic for a fixed corpus.

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
5. **The harness reports prevalence of patterns AAK already has rules for** — it
   cannot, by construction, surface a class for which no rule exists. Discovering
   genuinely uncovered patterns is a manual follow-up; any that hold up get filed
   as issues and turned into rules separately. No speculative findings here.

---

*The earlier marketing draft at
[`launch/state-of-mcp-security-2026.md`](../../launch/state-of-mcp-security-2026.md)
is superseded; this file is the canonical, reproducible source of record.
Launch-ready copy is in [`docs/DISTRIBUTION-CHECKLIST.md`](../../docs/DISTRIBUTION-CHECKLIST.md).*
