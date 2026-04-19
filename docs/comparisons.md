# How agent-audit-kit compares

_Context for decision-makers evaluating MCP / AI-agent static scanners
in April 2026._

Verifiable claims only. If you find a claim here that no longer holds,
file an issue and we will correct it within 48 hours.

## At a glance

| | agent-audit-kit | Microsoft AGT | Snyk Agent Scan (ex Invariant) | Semgrep Multimodal SAST | Lakera Guard |
|---|---|---|---|---|---|
| License | Apache 2.0 | MIT | Proprietary | Proprietary + OSS rules | Proprietary |
| Scope | Static scanner + compliance evidence | Runtime governance (policy engine + mesh) | Static + runtime (post-acquisition) | Multimodal SAST | Runtime guardrail |
| Account / cloud required | No | No (but Azure-native paths) | Yes | Optional | Yes |
| Cloud round-trip | No | No | Yes (findings leave your repo) | Optional | Yes |
| Compliance-evidence PDF | **Yes** (EU AI Act, SOC 2, ISO 27001+42001, HIPAA, NIST AI RMF, Singapore, India DPDP, **Alabama DPPA**, **Tennessee SB 1580**) | No (runtime policies, no audit PDFs) | No (findings only) | No | No |
| Regional / US-state compliance | Yes (India DPDP, Singapore, Alabama, Tennessee) | No | No | No | No |
| Signed rule bundle | Yes (Sigstore) | Partial (SLSA provenance on releases) | No (proprietary) | No | No |
| Deterministic (reproducible CI) | **Yes** | Yes (sub-ms policy enforcement) | No (multi-model analysis) | Partial | No |
| Public 48h CVE-to-rule SLA | **Yes** (CHANGELOG.cves.md) | No (internal cadence) | No | No | No |
| MCP Security Index / leaderboard | **Yes** (weekly, 500+ servers) | No | No | No | No |
| Pin + drift verification of tool surface | **Yes** | Yes (via Agent Runtime rings) | No | No | No |
| OWASP Agentic Top 10 coverage | 10/10 | 10/10 | Partial | Partial | Partial |

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
  (EU AI Act Art. 15, ISO 42001, Alabama DPPA, Tennessee SB 1580, etc.).
- **Microsoft AGT** runs at **runtime**. Agent OS (policy engine),
  Agent Mesh (A2A comms), Agent Runtime (dynamic execution rings),
  Agent SRE (reliability), Agent Compliance (automated evidence
  collection), Agent Marketplace, Agent Lightning (RL training
  governance). It enforces policies as agents execute.

Use both: `agent-audit-kit` tells an auditor your design is sound;
Microsoft AGT tells them your runtime actually behaved. Differentiation
is the compliance-evidence PDF stack (EU/US state-by-state), the
**48h CVE-to-rule SLA** with a public ledger, the signed rule bundle,
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
  compliance evidence + pin/verify + CVE SLA.

- **Hosted dashboards.** We ship SARIF for GitHub Security tab. If you
  want a hosted triage dashboard, a commercial product is easier.

- **Vulnerability research.** We ship detection within 48h of a public
  CVE. We do NOT originate CVE research — that's Invariant, Palo Alto
  Unit 42, HiddenLayer, Check Point, etc.

## When to pick agent-audit-kit

- You need an **auditor-ready** compliance report (EU AI Act high-risk
  obligations Aug 2 2026).
- Your environment is **air-gapped** (defense, finance, healthcare) and
  no data can leave the repo.
- You need **reproducible CI** — the same scan on the same commit must
  produce byte-identical output.
- You have **regional compliance** obligations in India (DPDP Act) or
  Singapore (Agentic AI Governance Framework).
- You want to **pin + verify** your MCP tool surface over time.
- You need a **public** scanner whose rule set your security team can
  read, audit, and fork.

## When to pick a commercial scanner instead

- You have zero in-house security review capacity and want a vendor
  SLA, phone number, and on-call.
- You need a hosted triage dashboard beyond SARIF → GitHub.
- You prefer to pay for multi-model semantic analysis of skills/tools
  from third parties.

## The honest state of the market

The OSS agent-security-scanner category is crowded (May 2025–Apr 2026):
`snyk/agent-scan`, `cisco-ai-defense/mcp-scanner`, `riseandignite/mcp-shield`,
`mcpshield/mcpshield`, `affaan-m/agentshield`, `HeadyZhang/agent-audit`,
plus Semgrep's Multimodal SAST.

What's **empty** in the category: compliance evidence mapped to
specific regulatory articles; deterministic reproducibility; a public
CVE-to-rule SLA; a pinning + drift primitive; a public leaderboard.
agent-audit-kit occupies that space.

Last reviewed: 2026-04-18.
