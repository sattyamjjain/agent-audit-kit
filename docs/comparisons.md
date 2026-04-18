# How agent-audit-kit compares

_Context for decision-makers evaluating MCP / AI-agent static scanners
in April 2026._

Verifiable claims only. If you find a claim here that no longer holds,
file an issue and we will correct it within 48 hours.

## At a glance

| | agent-audit-kit | Snyk Agent Scan (ex Invariant) | Checkmarx | Semgrep Multimodal SAST | Lakera Guard |
|---|---|---|---|---|---|
| License | Apache 2.0 | Proprietary | Proprietary | Proprietary + OSS rules | Proprietary |
| Account required | No | Yes | Yes | Optional | Yes |
| Cloud round-trip | No | Yes (findings leave your repo) | Yes | Optional | Yes |
| Compliance-evidence PDF | Yes (EU AI Act / SOC 2 / ISO 27001+42001 / HIPAA / NIST AI RMF) | No (findings only) | Partial (SOC 2) | No | No |
| India DPDP / Singapore AI framework coverage | Yes | No | No | No | No |
| Signed rule bundle | Yes (Sigstore) | No (proprietary) | No | No | No |
| Deterministic (reproducible CI) | Yes | No (multi-model analysis) | Yes | Partial (LLM-assisted reasoning) | No (runtime LLM) |
| Public 48h CVE-to-rule SLA | Yes (CHANGELOG.cves.md) | No (internal cadence) | No | No | No |
| MCP Security Index / leaderboard | Yes (weekly, 500+ servers) | No | No | No | No |
| Pin + drift verification of tool surface | Yes | No | No | No | No |

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
