# agent-audit-kit — Roadmap to Top 1% (April 2026)

> **Historical snapshot — authored 2026-04-12, not updated.** This is the April
> 2026 plan, kept because the reasoning is still useful and deleting it would be
> the dishonest version. Read it as a record of what was intended, not as a
> statement of where the project is.
>
> Its headline goal — "1,000+ GitHub stars and reference-implementation status
> for the OWASP MCP Top 10 project within 90 days" — was not met. Four months on
> the repo has 13 stars, and no such status was granted. The counts in the
> opening line (v0.2.0, 77 rules, 11 categories, 13 scanner modules) are the
> April figures and are deliberately left alone; for current state see
> [`README.md`](README.md) and [`docs/rules.md`](docs/rules.md).
>
> Same treatment as [`DEEP_ANALYSIS.md`](DEEP_ANALYSIS.md), which carries the
> equivalent banner for v0.2.0.

**Starting point (Apr 2026):** v0.2.0 · 77 rules across 11 categories · 13 scanner modules · SARIF + OWASP + compliance output · GitHub Action ready · single-digit stars.
**Goal:** 1,000+ GitHub stars and reference-implementation status for the OWASP MCP Top 10 project within 90 days.

Read [`launch/MARKET-RESEARCH-2026-04-12.md`](launch/MARKET-RESEARCH-2026-04-12.md) first — the April 2026 competitive/ecosystem landscape this roadmap is built on.

---

## 1. The positioning problem

"npm audit for AI agents" is the right metaphor but it's no longer available as an uncontested claim. Since June 2025, **Snyk acquired Invariant Labs and rebranded MCP-Scan as `snyk/agent-scan`**, now the dominant OSS MCP scanner. Cisco shipped `cisco-ai-defense/mcp-scanner`. Semgrep's Multimodal SAST landed in 2026. Three more smaller OSS scanners (`riseandignite/mcp-shield`, `mcpshield/mcpshield`, `HeadyZhang/agent-audit` with 49 rules) appeared in Q1 2026.

The three things `agent-audit-kit` ships that the field does **not** do well:

1. **Compliance-evidence output** — your scanner already ships SARIF + OWASP mapping + an explicit compliance report mapping findings to EU AI Act, SOC 2, ISO 27001, HIPAA, NIST AI RMF. `snyk/agent-scan` ships findings; it doesn't ship compliance evidence. With the EU AI Act high-risk obligations applying **August 2, 2026**, this is your strongest commercial wedge.
2. **Pinning + drift verification** (`pin` / `verify` commands) — SHA-256 tool-surface fingerprint with pin file. Nobody else pins *and* re-verifies with an audit trail.
3. **India PII + regional compliance** — the forthcoming India DPDP Act + your Aadhaar / PAN / UPI / IFSC pack = APAC wedge.

**Recommended tagline:** *"Static security + compliance evidence for MCP-connected agents — scan, pin, verify, report. SARIF + OWASP MCP Top 10 + EU AI Act Article 15 out of the box."*

---

## 2. Critical gaps vs April 2026 state of the art

### 2.1 Dead code and correctness (ship before launch)

Carried over from the earlier `DEEP_ANALYSIS.md` plus the new market context:

1. **Exception handling around `engine.run_scan`** — today a single bad scanner crashes the whole scan. Add per-scanner try/except that emits an `AAK-INTERNAL-SCANNER-FAIL` INFO finding and continues.
2. **TypeScript/Rust scanners: rename done, AST rewrite still open** — the two modules were renamed to `typescript_pattern_scan.py` / `rust_pattern_scan.py` (v0.3.0, with back-compat shims) and the docs no longer describe them as "taint analysis", so the source now matches the marketing (they are honest regex pattern scanners). The remaining half — a real tree-sitter AST rewrite that models source→sink reachability for TS/Rust — stays open as **issue #22**; do not restart it here.
   >
   > **Annotation, 2026-09-08 — #22 is closed, and it did not deliver what this line describes.** Same treatment as the banner: the sentence above is left as written because it records what was intended in April. Issue #22 was closed as completed on **2026-08-15**, after being scoped down from "replace all regex scanners with tree-sitter taint tracing across TS/JS, Python, Rust, Go" to a single slice — a tree-sitter TypeScript/JavaScript taint pass for `AAK-MCP-STDIO-CMD-INJ-002` alone. That slice shipped and is `agent_audit_kit/scanners/_ts_stdio_taint.py`: it replaces the proximity decision with reachability over a real parse for that one rule, keeps `tree_sitter` optional with a proximity fallback, and changes nothing about what the rule reports.
   >
   > Rust was never in the shipped slice and is still a regex pattern scan — `rust_pattern_scan.py` says so in its own docstring: "It does NOT model flow from user-controlled sources." So the "TS/Rust" reachability rewrite named above is **not** what #22 delivered, and no open issue tracks the rest of it. Read this item as: one rule got real taint, the general rewrite did not happen, and nobody is currently on it.
3. **LLM-assisted scanner** (`llm_scan.py`) — today depends on Ollama silently. Wire it into Claude / OpenAI / Gemini with a `--llm claude-haiku-4-5` CLI flag and make it explicit-opt-in, not silent.

### 2.2 Must-add coverage for 2026 threat landscape

| Rule family | Rationale | Notes |
|---|---|---|
| **AAK-MCP-011 through 020** — auth bypass | 30 CVEs in 60 days (Jan–Feb 2026); CVE-2026-33032 (Nginx-UI) is the template | Detect: missing `Authorization` check, wildcard CORS, query-param auth tokens, path-traversal on resource handlers |
| **AAK-MCP-SSRF** — SSRF in MCP handlers | 36.7% of 7,000 surveyed servers vulnerable | Detect: outbound-HTTP call with user-controlled URL, no SSRF allowlist |
| **AAK-MCP-OAUTH-misconfig** | OAuth 2.1 now mandatory per `2025-11-25` | Detect: missing PKCE, wildcard redirect URIs, token passthrough |
| **AAK-HOOK-RCE** | CVE-2025-59536 Claude Code hooks | Detect: hooks executing unquoted user input, `shell=True` in hook scripts |
| **AAK-LANGCHAIN-PATH-TRAVERSAL** | CVE-2026-34070, CVE-2025-68664, CVE-2025-67644 (March 2026) | Rule pack for LangChain/LangGraph vulnerable versions |
| **AAK-MARKETPLACE-MANIFEST** | `.claude-plugin/marketplace.json` is now the canonical format | Detect: missing signatures, unpinned git refs, postinstall scripts, overly broad MCP server permissions |
| **AAK-ROUTINE-SCHEDULED** | Claude Code Routines (Apr 14) run non-interactively | Detect: scheduled prompts that include tool permissions broader than the on-demand path |
| **AAK-A2A-*** | A2A protocol at 150+ orgs | Peer-authentication missing, capability overshare in agent cards, self-signed A2A certs |
| **AAK-MCP-TASKS-LEAK** | New Tasks primitive introduces long-lived async state | Detect: tasks that persist credentials, no TTL, missing cancellation |
| **AAK-SKILL-POISON** | Anthropic skills 2.0; 1,467 malicious payloads in ToxicSkills | Detect: `SKILL.md` with suspicious post-install commands, data-exfil primitives |

Every one of these rules ships with (a) a fixture under `tests/fixtures/`, (b) a one-paragraph remediation, and (c) an OWASP mapping. Rule packs are marketing; each one is a blog post.

### 2.3 Features that widen the moat

1. **Disclosed-CVE rule coverage** — triage newly disclosed MCP CVEs and turn them into rules as they land, surfaced automatically by the NVD watcher (`.github/workflows/cve-watcher.yml`) and logged in a public `CHANGELOG.cves.md` (e.g. "CVE-2026-33032 → AAK-MCP-012, 2026-03-16"). No public deadline is promised — a solo maintainer can't carry an unbounded clock — but the ledger makes actual coverage and timing transparent.
2. **Compliance-report v2** — today you map to EU AI Act / SOC 2 / ISO 27001 / HIPAA / NIST AI RMF. Add:
   - **ISO/IEC 42001** AI Management System evidence block.
   - **Singapore Agentic AI Governance Framework** (Jan 2026, first national).
   - **India DPDP Act 2023** mapping for the India PII pack.
   - **EU AI Act Article 55** (GPAI systemic risk).
   - Output an **auditor-ready PDF** (via your `pdf` skill) with findings grouped by control.
3. **`agent-audit-kit fix --cve`** auto-remediation — for a subset of rules, generate a PR that upgrades a vulnerable dependency or rewrites an insecure MCP config. `npm audit fix` parity.
4. **Continuous drift mode** — `agent-audit-kit watch` daemon that re-runs `verify` on a cron and emits a Slack/Discord alert when pinned tool surface changes. Pairs with agent-airlock's runtime honeypot.
5. **Snyk-parity test corpus** — run against Snyk's public ToxicSkills dataset and publish head-to-head numbers. 90–100% recall / 0% FP is Snyk's claim; meet or beat it on OSS.
6. **VS Code extension** — inline findings in `mcp.json`, `.mcp/*.json`, `marketplace.json`. Extends your existing `vscode-extension/` subtree.
7. **JetBrains plugin** — JetBrains AI agent-mode is preview in 2026. Be there.
8. **GitHub Security Advisories integration** — post findings as repository security advisories, not just SARIF.
9. **Signed rule bundles** — sign the rule definitions with Sigstore so enterprise users can pin a specific rule-set version and verify supply chain. Differentiator vs Snyk's proprietary rules.
10. **`agent-audit-kit score` calibration** — today the 100 → deduct-per-severity grade lacks an empirical floor. Calibrate by scanning 1,000 public MCP servers (there are 10,000+ now) and publish a distribution: "the median public MCP server scores C-; the top 10% score B+".

### 2.4 Positioning against Snyk

Your honest answer to "why not Snyk Agent Scan?":

1. **Fully OSS, no auth required** — Snyk requires an account and phones home.
2. **Compliance-evidence output** — Snyk ships findings only.
3. **Deterministic rules** — Snyk's multi-model analysis is non-deterministic, so CI runs aren't reproducible.
4. **Regional compliance** — India DPDP, Singapore framework, EU AI Act Article 55.
5. **Zero cloud dependencies** — air-gap friendly. Relevant for defense, finance, healthcare.
6. **Pin + drift** — Snyk doesn't verify over time.

---

## 3. Milestones and timeline

### Week 0 (fixes + v0.3.0 cut)

- Land the four correctness fixes (dead rules, scanner exception handling, TypeScript/Rust rename or rewrite, explicit LLM flag).
- Ship the 10 new 2026-CVE rule families as v0.3.0.
- Publish the public CVE-response ledger (`CHANGELOG.cves.md`) — coverage transparency, no clock commitment.
- Scan 1,000 public MCP servers and compute the grade distribution. This is a blog post.
- Run ToxicSkills head-to-head; publish numbers.

### Week 1 (launch)

- **Tuesday, 13:00 UTC** — HN submission. Title: *"We scanned 1,000 public MCP servers. 82% fail path-traversal checks. Here's the scanner and rule set."* This is the "own the data" play. The URL is the grade-distribution post, not the repo.
- Same day: `/r/netsec`, `/r/ClaudeAI`, `/r/LocalLLaMA`.
- Twitter thread: 10 tweets, one per OWASP MCP Top 10 category, each with a real public-server example (name-redacted).
- Submit proposal to OWASP MCP Top 10 project to become the reference OSS scanner.

### Weeks 2–4

- Ship VS Code extension MVP.
- Ship the auditor-ready PDF compliance report.
- `agent-audit-kit fix --cve` auto-remediation.
- Weekly rule-pack releases aligned with each new MCP CVE.
- Talk proposal: BlackHat Arsenal / DEF CON AI Village.

### Weeks 5–8

- Ship JetBrains plugin.
- Ship continuous drift mode.
- Sign release artifacts (Sigstore) and rule bundles.
- Engage three design partners (target: one US bank, one Indian fintech, one EU healthcare company — each needs different compliance report variants).

### Weeks 9–12

- Submit as an OWASP flagship tool. MCP Top 10 reference OSS status is the trust signal that unlocks enterprise adoption.
- Coordinate disclosure with 5 popular public MCP servers you've found issues in. Each coordinated disclosure is a co-authored security advisory and a press opportunity.
- Launch the "**MCP Security Index**" at `aak.report` or similar — a continuously-updated grade distribution across the top 1,000 public MCP servers, with a per-server grade card. Your Aider-leaderboard-equivalent.

---

## 4. What to measure

| Metric | Baseline | 30-day | 90-day | 1-year |
|---|---|---|---|---|
| GitHub stars | ~3 | 200 | 2,000 | 10,000 |
| PyPI downloads/month | <30 | 3,000 | 40,000 | 400,000 |
| Rules | 77 | 100 | 140 | 200 |
| Disclosed MCP CVEs with rule coverage | n/a | majority covered | same | same |
| GitHub Action usage | 0 | 20 | 250 | 3,000 |
| Published MCP Security Index grades | 0 | 1,000 servers | 5,000 | all 10,000+ |
| Coordinated CVE disclosures | 0 | 1 | 5 | 20 |
| OWASP project status | none | reference-tool candidate | reference tool | flagship |

---

## 5. What *not* to do

- **Don't try to out-Snyk Snyk** on multi-model analysis. You don't have the training budget. Own deterministic + compliance + pin/verify + OSS-first + regional.
- **Don't drop the GitHub Action.** It is the primary distribution vehicle. SARIF upload → GitHub Security tab → every user's security team sees your findings. This is Trivy / Semgrep / Gitleaks's playbook.
- **Don't ship auto-fix for rules where the fix is non-trivial.** `--cve` should refuse to auto-fix when the fix requires code-review-level changes. False confidence kills scanners.
- **Don't gate anything behind an account.** Zero-friction install is your wedge vs Snyk.

---

## 6. The CEO-readable one-pager

> *AgentAuditKit* scans your AI-agent pipeline for 100+ security and compliance issues — from tool-poisoning and prompt-injection to insecure MCP configs and missing OAuth 2.1 enforcement. It produces SARIF for GitHub Security, an OWASP MCP Top 10 scorecard, and auditor-ready compliance evidence mapped to EU AI Act Article 15, SOC 2, ISO 27001 / 42001, HIPAA, NIST AI RMF, Singapore Agentic AI Governance, and India DPDP. We publish the MCP Security Index, grading the top 10,000 public MCP servers weekly, and we ship rule coverage for disclosed MCP CVEs. Used by engineering teams that need to show an auditor that their agents are safe — before the EU AI Act high-risk obligations apply on August 2, 2026.
