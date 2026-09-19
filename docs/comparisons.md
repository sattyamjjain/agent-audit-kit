# How agent-audit-kit compares

_Context for decision-makers evaluating MCP / AI-agent static scanners._

**Reviewed 2026-09-16.** One date for the whole page: it previously carried
three (an April 2026 framing line, a `Last reviewed` under the market section
and a `Last updated` in the footer), which drifted apart and left a reader no
way to tell which claim was checked when. Competitor facts on this page were
re-verified against the live repositories on that date; where a figure could
not be sourced it says so rather than carrying a number nobody can check.

Verifiable claims only. If you find a claim here that no longer holds,
file an issue and we will correct it (best-effort — no fixed clock).

## At a glance

| | agent-audit-kit | Microsoft AGT | Snyk Agent Scan (ex Invariant) | Semgrep Multimodal SAST | Lakera Guard |
|---|---|---|---|---|---|
| License | Apache-2.0 | MIT | Apache-2.0 | Proprietary + OSS rules | Proprietary |
| Scope | Static scanner + compliance evidence | Runtime governance (policy engine + mesh) | Static + runtime (post-acquisition) | Multimodal SAST | Runtime guardrail |
| Account / cloud required | No | No (but Azure-native paths) | Yes ([its README](https://github.com/snyk/agent-scan#quick-start): sign up, `export SNYK_TOKEN=` "before running any scan") | Optional | Yes |
| Cloud round-trip | No | No | Yes — its README's ["Analysis and Validation"](https://github.com/snyk/agent-scan#how-it-works) says it "validates discovered components with local checks and the Agent Scan API" and sends MCP server configurations, tool names and descriptions, and skill content, with secrets redacted before transmission | Optional | Yes |
| Compliance-evidence PDF | **Yes** (EU AI Act, SOC 2, ISO 27001+42001, HIPAA, NIST AI RMF, Singapore, India DPDP, **Alabama DPPA**, **Tennessee SB 1580**, **Colorado SB 26-189 ADMT**, **EU AI Act Art. 50**) | No (runtime policies, no audit PDFs) | No (findings only) | No | No |
| Regional / US-state compliance | Yes (India DPDP, Singapore, Alabama, Tennessee) | No | No | No | No |
| Signed rule bundle | Yes (Sigstore) | Partial (SLSA provenance on releases) | No — it GPG-signs release checksums and ships an SBOM, but there is no rule set on disk to sign | No | No |
| Deterministic (reproducible CI) | **Yes** | Yes (sub-ms policy enforcement) | No — analysis runs through the Agent Scan API against a dated API model, so a result depends on service state as well as the commit | Partial | No |
| Public CVE-to-rule ledger | **Yes** (CHANGELOG.cves.md) | No (internal cadence) | No | No | No |
| MCP Security Index / leaderboard | **Yes** — server count and last-snapshot date are [stated once in the README](../README.md#mcp-security-index), which `scripts/index_cadence.py` writes from the published `history.json` | No | No | No | No |
| Pin + drift verification of tool surface | **Yes** | Yes (via Agent Runtime rings) | Partial — it models a `ServerSignature` of the tool surface and sends it for analysis, but ships no pin/verify command to fail a build on drift | No | No |
| OWASP Agentic Top 10 coverage | 10/10 | 10/10 | Not advertised (no OWASP mapping in its README or `docs/`, checked 2026-09-16) | Partial | Partial |

## Microsoft Agent Governance Toolkit (Apr 2 2026)

Microsoft [open-sourced AGT](https://github.com/microsoft/agent-governance-toolkit)
under MIT license on April 2 2026, with broad coverage on Apr 16
([Help Net Security](https://www.helpnetsecurity.com/2026/04/03/microsoft-ai-agent-governance-toolkit/),
[InfoWorld](https://www.infoworld.com/article/4155591/microsofts-new-agent-governance-toolkit-targets-top-owasp-risks-for-ai-agents.html)).
It is the first major-vendor entry to claim 10/10 OWASP Agentic Top 10
coverage with deterministic sub-millisecond policy enforcement.

**AGT is an ally in positioning, not a head-on competitor.** It
validates the category we've been shipping for months; different tool,
different layer:

- **agent-audit-kit** runs at CI time and ship time. It's a **static
  scanner + compliance evidence** generator. You run it on a repo to
  catch issues before deployment and to produce auditor-ready PDFs
  (EU AI Act Art. 15, ISO 42001, Alabama DPPA, Tennessee SB 1580, Colorado SB 26-189 ADMT, etc.).
- **Microsoft AGT** runs at **runtime**. Agent OS (policy engine),
  Agent Mesh (A2A comms), Agent Runtime (dynamic execution rings),
  Agent SRE (reliability), Agent Compliance (automated evidence
  collection), Agent Marketplace, Agent Lightning (RL training
  governance). It enforces policies as agents execute.

Use both: `agent-audit-kit` tells an auditor your design is sound;
Microsoft AGT tells them your runtime actually behaved. Differentiation
is the compliance-evidence PDF stack (EU/US state-by-state), the
**public CVE-to-rule ledger**, the signed rule bundle,
and the MCP Security Index leaderboard — none of which are AGT goals.

Microsoft AGT ships Python / TypeScript / Rust / Go / .NET. Integrations
already operational in Dify, LlamaIndex, OpenAI Agents SDK, Haystack,
LangGraph, PydanticAI. agent-audit-kit integrates with AGT findings on
the roadmap (a future `--runtime-policies microsoft-agt` flag can
cross-check our static rules against a deployed AGT policy set).

## SnapLogic AI Gateway + Trusted Agent Identity (Apr 16 2026)

[SnapLogic announced](https://www.globenewswire.com/news-release/2026/04/16/3275117/0/en/SnapLogic-Announces-AI-Gateway-and-Trusted-Agent-Identity-to-Power-the-Era-of-Digital-Labor.html)
enterprise iPaaS primitives for agent identity + governance. Signal: "agent
identity" is now a vendor-category, not a feature. agent-audit-kit's
`pin` + `verify` commands already cover the "is this the agent I
expected?" question for MCP tool surface; SnapLogic extends the same
idea to cross-enterprise RPA / iPaaS flows. Complementary, not
competing.

## What we are NOT better at

- **Multi-model analysis.** Snyk's acquisition of Invariant Labs
  bought them a proprietary corpus + a multi-model pipeline. Their
  ToxicSkills recall numbers (claimed 90–100%) are out of reach for a
  deterministic scanner. If you need semantic coverage on skills you
  don't author, you want both: Snyk for that and agent-audit-kit for
  compliance evidence + pin/verify + a public CVE-to-rule ledger.

- **Hosted dashboards.** We ship SARIF for GitHub Security tab. If you
  want a hosted triage dashboard, a commercial product is easier.

- **Vulnerability research.** We ship detection for disclosed MCP CVEs on a
  best-effort basis, tracked in a public ledger. We do NOT originate CVE research — that's Invariant, Palo Alto
  Unit 42, HiddenLayer, Check Point, etc.

## Finding things, and proving you looked

This page used to split the field into OSS and commercial. That split no
longer describes anything: the largest scanner in the category is free and
Apache-2.0, and is developed faster than this one. Sorting by licence sorts
by the wrong axis.

The distinction that survives is between a scanner that **finds** things and
a scanner that also produces the **evidence an auditor accepts**. Those are
different products that happen to read the same files. Most tools in this
category do the finding, and do it well. Reach for the evidence kind only
when somebody is going to ask you to show your work.

### When the evidence is the deliverable

Pick agent-audit-kit when a scan result has to survive being looked at by
somebody who was not in the room:

- **A dated obligation already applies to you.** EU AI Act Article 50
  transparency has applied since 2026-08-02 and was not deferred. Colorado
  SB 26-189 ADMT developer documentation is due from 2027-01-01. India DPDP,
  Singapore's Agentic AI Governance Framework, Alabama and Tennessee each
  have a pack here. The competitor's README, docs and source tree mention
  none of these; that is not a criticism of it, it is a different product.
- **The answer has to be reproducible.** The same commit scanned twice must
  produce byte-identical output, because "it flagged that last month" is
  only usable as evidence if you can re-run it and get the same file. A
  scanner whose analysis happens behind a versioned service API cannot
  promise that, however good the analysis is.
- **Nothing may leave the repository.** Air-gapped review, or a legal
  position that repository content is not sent to a third party for
  processing.
- **You need to prove the rule set itself.** A signed rule bundle, a public
  CVE-to-rule ledger, and a rule set your security team can read, fork and
  diff. A service's detections can be excellent and still not be auditable
  artifacts.
- **You need a drift primitive, not a drift feeling.** `pin` writes the tool
  surface to a file you commit; `verify` fails the build when it changes.

### When something else is the better tool

- **You want the widest agent and skill discovery.** Snyk Agent Scan
  enumerates more agent surfaces than this project does, across system,
  user, project and extension scope. If the question is "what is installed
  on these machines", start there.
- **You want fleet monitoring, a vendor SLA, or a hosted triage
  dashboard.** AAK emits SARIF and stops; someone else runs the dashboard.
- **You want semantic judgement of skills and tool descriptions.** That is
  a model-shaped problem and a deterministic scanner is the wrong shape for
  it. Run both; they disagree in useful ways.

### Why this gets more true in 2027 and 2028, not less

The EU AI Act's high-risk obligations were the deadline everyone planned
around. [Regulation (EU) 2026/1744](https://eur-lex.europa.eu/eli/reg/2026/1744/oj),
the Digital Omnibus on AI, entered into force on 2026-07-27 and moved them:
Annex III standalone high-risk systems to **2027-12-02**, Annex I
product-embedded systems to **2028-08-02**. Article 50 transparency stayed
where it was, on 2026-08-02.

Read that as a schedule, not a reprieve. The obligations did not get
smaller, they got later, and what they ask for at the end of them is
documentation: intended purpose, risk management, robustness evidence,
records that a human can audit. Detection coverage is what you need this
quarter. The evidence stack is what you need on those two dates, and it is
the part that cannot be assembled retroactively from a scanner that did not
keep records.

## The honest state of the market

The OSS agent-security-scanner category is crowded (May 2025–Apr 2026):
`snyk/agent-scan`, `cisco-ai-defense/mcp-scanner`, `riseandignite/mcp-shield`,
`mcpshield/mcpshield`, `affaan-m/agentshield`, `HeadyZhang/agent-audit`,
plus Semgrep's Multimodal SAST.

Those five gaps were re-checked on 2026-09-16 against `snyk/agent-scan`,
the largest of them, since asserting a category is empty is only worth
doing if somebody re-runs it. Four survived the check and one did not.

Still **empty**, with nothing in that repository's README, docs or `src/`
tree answering to it:

- **compliance evidence mapped to specific regulatory articles** — no
  mention of the EU AI Act, SOC 2, ISO 27001/42001, HIPAA or NIST in the
  README at all.
- **deterministic reproducibility** — structurally unavailable rather than
  merely absent: analysis is performed by the Agent Scan API against a
  dated API model (`models/api/v20260710.py`), so the same input scanned
  twice depends on service state, not only on the commit.
- **a public CVE-to-rule ledger** — no CVE, advisory or ledger surface.
- **a public leaderboard** — none published.

**Withdrawn:** *a pinning + drift primitive* no longer belongs on that
list. `snyk/agent-scan` models a `ServerSignature` — protocol version,
capabilities, `serverInfo`, prompts, resources and tool descriptions —
which is exactly the surface a drift check needs, and it transmits it for
analysis. What it does not ship is a user-facing pin/verify workflow: the
CLI offers `scan`, `inspect` and `help`, and nothing writes a signature to
a file you commit and later fail a build against. So the accurate claim is
narrower than the one this page used to make, and it is the narrower one
that is kept: the ingredient exists there, the local fail-on-drift
primitive does not.

agent-audit-kit occupies what is left, which is smaller than this page
previously implied.

---

## Feature matrix vs the OSS scanners

_Merged here from `docs/comparison.md` in v0.3.86. Three comparison pages
coexisted, the README linked only this one, and the other two drifted unread._

### AgentAuditKit vs Competitors

| Feature | AgentAuditKit | mcp-scan | Snyk Agent | Agent Audit | Microsoft AGT |
|---------|:---:|:---:|:---:|:---:|:---:|
| **Rules** | <!-- rule-count:total -->357<!-- /rule-count --> | ~10 | 20 codes (v0.5.x) / 15 risks (v0.6+) [†](#snyk-rule-count) | 57 | N/A (runtime) |
| MCP config scanning | Yes | No | Yes | No | No |
| Hook injection detection | Yes | No | No | No | No |
| Trust boundary analysis | Yes | No | No | No | Yes |
| Secret exposure scanning | Yes | No | Yes | No | No |
| Supply chain analysis | Yes | No | Yes | No | No |
| Agent instruction scanning | Yes | No | No | No | No |
| Tool poisoning detection | Yes | Yes | Yes | No | No |
| Tool pinning / rug pull | Yes | Yes | Partial (captures a tool-surface signature; no pin/verify command) | No | No |
| Taint analysis (@tool) | Yes | No | No | Yes | No |
| A2A protocol scanning | Yes | No | No | No | No |
| Multi-agent discovery | Yes | No | Yes | No | No |
| OWASP Agentic Top 10 | 10/10 | 0/10 | Not advertised | 10/10 | 10/10 |
| OWASP MCP Top 10 | 10/10 | Partial | Not advertised | 0/10 | 0/10 |
| Compliance frameworks | <!-- framework-count:total -->14<!-- /framework-count --> | 0 | 0 | 0 | 3 |
| SARIF output | Yes | No | Yes | No | No |
| Auto-fix mode | Yes | No | No | No | No |
| Security scoring | Yes | No | No | No | No |
| Pre-commit hook | Yes | No | No | No | No |
| GitHub Action | Yes | No | Yes | No | No |
| Runtime proxy | Yes | No | No | No | Yes |
| Offline / no network | Yes | No | No | Yes | Yes |
| Zero dependencies | Yes* | No | No | No | No |

*Only click + pyyaml required.

<a id="snyk-rule-count"></a>† **Snyk Agent Scan, counted on 2026-09-16, and
the two numbers are not the same kind of thing as AAK's.** This cell used to
say `~15` with no source recorded. Counting method, so the next person can
re-run it: `snyk/agent-scan` ships two version lines and documents each
separately. [`docs/issue-codes.md`](https://github.com/snyk/agent-scan/blob/main/docs/issue-codes.md)
enumerates **20** distinct v0.5.x issue codes (5 `E###` + 15 `W###`, deduplicated
from the heading badges) across five families;
[`docs/risks.md`](https://github.com/snyk/agent-scan/blob/main/docs/risks.md)
names **15** v0.6-and-later risk indicators. So the old `~15` was roughly right
for one of the two lines and unsourced and ambiguous between them.

Read the row with that caveat rather than as a score. A Snyk issue code is a
family (`W015 Untrusted content detected`); an AAK rule ID is one detection
with its own remediation and framework mapping, which is why 352 sits next to
20 without meaning "23x better". The detection logic is also not in the
repository to inspect: `src/agent_scan/` is discovery adapters, a CLI, an MCP
client, API models and redaction, and the README's
["Analysis and Validation"](https://github.com/snyk/agent-scan#how-it-works)
says analysis runs through the Agent Scan API. The codes are the published
surface of a service, not a rule set you can read, fork or diff.

### When to Use Each

- **AgentAuditKit**: Comprehensive static + config scanning, compliance reporting, CI/CD integration
- **mcp-scan**: Quick tool description poisoning check via cloud API
- **Snyk Agent Scan**: the broadest agent and skill discovery in the category, free and Apache-2.0, actively developed (3,055 stars, last push 2026-09-16 on the day this page was checked). It enumerates far more agent surfaces than AAK does — fourteen agents across system, user, project and extension scope — and adds a background MDM mode that reports to a Snyk Evo instance. It wants a `SNYK_TOKEN` and sends component data to its API for analysis. Reach for it when coverage breadth and fleet monitoring are the job. AAK's argument against it is not breadth of detection, and this page should not pretend otherwise: it is deterministic reproducibility, the compliance-evidence stack, the public CVE-to-rule ledger, the signed rule bundle, and the pin/verify drift primitive.
- **Agent Audit**: Academic-quality taint analysis for LangChain/CrewAI code
- **Microsoft AGT**: Runtime policy enforcement with execution rings

These tools are complementary. Use AgentAuditKit alongside runtime tools for defense-in-depth.

---

## GitLab Agentic SAST 18.11 (2026-04-17)

_Merged here from `docs/comparison-gitlab-agentic-sast.md` in v0.3.86._

GitLab 18.11 (2026-04-17) shipped Agentic SAST behind the Ultimate
tier. This is a no-marketing, dated-source comparison so AAK
consumers can pick the right tool for their stack.

| Dimension | AgentAuditKit | GitLab Agentic SAST 18.11 |
|---|---|---|
| License | Apache-2.0, OSS | Proprietary, Ultimate-tier paywall |
| Distribution | PyPI + Marketplace + Docker + VS Code ext | GitLab CI / Premium offering only |
| Rule count | <!-- rule-count:total -->357<!-- /rule-count --> | Not publicly disclosed |
| OWASP Agentic Top 10 mapping | Per-rule, public JSON manifest | Claimed; mapping not published |
| MCP Top 10 mapping | Per-rule | Not advertised |
| AICM (CSA) mapping | Yes | Not advertised |
| Out-of-band corpus refresh | `aak corpus update` (signed) | No equivalent — rules ship on product release cadence |
| SARIF diff (regression-only gating) | `aak diff --baseline ... --current ...` | Not advertised |
| VS Code extension | Yes (open-source) | No |
| PR-title indirect prompt injection | AAK-PRTITLE-IPI-001 (CVSS 9.4) | Not advertised in 18.11 changelog |
| MCP function-hijacking detection | AAK-MCP-FHI-001 (arXiv 2604.20994) | Not advertised |
| Atlassian MCP CVEs | AAK-MCP-ATLASSIAN-CVE-2026-27825/27826 | Generic SAST may catch; no per-CVE rule |
| Sigstore-attested releases | Yes | Not applicable |
| Self-scan / dogfood gate | `.github/workflows/self-scan.yml` (PR-blocking) | Not applicable to a managed product |

### Where GitLab is genuinely stronger

- **DAST + IAST integration**: GitLab integrates SAST + DAST + IAST in
  one pipeline. AAK is SAST + supply-chain only.
- **Multi-tenant org-level dashboards**: GitLab's Vulnerability Reports
  aggregate across the org. AAK ships SARIF; consumers wire their own
  dashboard.
- **Ecosystem coverage**: GitLab's traditional SAST has rule packs for
  ~30 languages. AAK targets the agent / MCP slice specifically.

### Where AAK is genuinely stronger

- **Same-day defense for new payload families**: Out-of-band signed
  corpus refresh decouples threat-data updates from product releases.
- **PR-title IPI rule**: First-to-market on Comment-and-Control class
  (CVSS 9.4, 2026-04-25 disclosure).
- **MCP function-hijacking rule**: First-to-market on the BFCL FHI
  class (arXiv 2604.20994, 2026-04-23, 70-100% ASR).
- **Free + OSS**: No tier paywall, no per-seat licensing.
- **SARIF regression gating**: `aak diff` lets PR-blocking workflows
  gate on `newly_introduced` only — eliminates the "huge backlog
  blocks every PR" failure mode that GitLab Ultimate users report.

### Sources

- GitLab 18.11 release announcement: https://www.helpnetsecurity.com/2026/04/17/gitlab-18-11-agentic-ai/
- AAK v0.3.8 release notes: ../releases/v0.3.8.md
- OWASP Agentic Top 10: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

Reviewed 2026-09-16 (see the date at the top of this page; the GitLab 18.11 comparison itself describes the 2026-04-17 release and has not been re-run against a later GitLab version).
