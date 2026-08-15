# Black Hat Arsenal — submission skeleton (AgentAuditKit)

> **DO NOT SUBMIT AS-IS.** Black Hat prohibits LLM-generated submission text.
> This file is a factual skeleton: the numbers, feature list, and structure are
> pre-filled and verified against the repo; every prose block is marked
> `<-- rewrite this paragraph in your own words before submitting>`. Rewrite each
> block by hand before pasting into the Arsenal CFP form.

- **Track:** Arsenal (live tool demo)
- **Tool:** AgentAuditKit — `pip install agent-audit-kit` · MIT · https://github.com/sattyamjjain/agent-audit-kit
- **Category:** AI/ML security · MCP · SAST / static analysis
- **Demo length:** 20–40 min at a station

## Tool name and one-line

AgentAuditKit — an offline, deterministic security scanner for MCP-connected AI
agent pipelines (303 detection rules, SARIF + auditor-ready compliance evidence).

## Abstract (prose block)

`<-- rewrite this paragraph in your own words before submitting>`

Skeleton of facts to draw from:
- Static scanner for MCP agent configs and source (Python/TS/Rust taint analysis).
- **303 rules** across 12 categories; OWASP MCP Top 10 (10/10) + Agentic Top 10 (10/10).
- **Two properties hosted scanners cannot match:** (1) runs fully offline and
  deterministically — zero network calls in the default path, no LLM in the loop,
  the same input yields a byte-identical finding set (measured: 20/20 identical
  runs, 0% variance); (2) emits auditor-ready compliance-evidence packs — SARIF
  for the GitHub Security tab plus PDF evidence mapped to 12 frameworks
  (EU AI Act, SOC 2, ISO 27001/42001, HIPAA, NIST AI RMF, and regional regimes).
- No account, no telemetry.

## What attendees will see (live demo outline — bullets, keep as bullets)

1. Scan a deliberately vulnerable MCP config: `agent-audit-kit scan examples/vulnerable-configs/04-hook-exfiltration/` → findings + A–F grade in <1s, offline.
2. Re-run the same scan twice → byte-identical output (determinism, shown with a hash diff).
3. `--profile mcp-2026-07-28` → the RFC 9207 / 8707 / 9728 auth-profile readiness check.
4. Export: SARIF → GitHub Security tab annotations; `report --format pdf --framework soc2` → compliance evidence.
5. Run it against the public corpus from the companion research: 1,374 configs, offline, in one command.

## Why it matters (prose block)

`<-- rewrite this paragraph in your own words before submitting>`

Facts: MCP adoption outpaced its security tooling; hosted scanners require an
account and are non-deterministic, so CI diffs and audit re-runs are not
reproducible. AgentAuditKit is the deterministic, auditor-ready OSS alternative.

## Presenter / logistics

- Requires: a laptop, no network (the point). Docker image + PyPI wheel available.
- Prior disclosure: tool is public and MIT-licensed; no 0-day is dropped in this demo.
