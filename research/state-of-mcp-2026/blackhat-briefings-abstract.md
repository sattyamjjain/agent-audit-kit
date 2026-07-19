# Black Hat Briefings — submission skeleton (State of MCP Server Authentication)

> **DO NOT SUBMIT AS-IS.** Black Hat prohibits LLM-generated submission text.
> This file is a factual skeleton: numbers are pre-filled and verified against
> `results.json` / `REPORT.md`; every prose block is marked
> `<-- rewrite this paragraph in your own words before submitting>`. Rewrite each
> block by hand before pasting into the Briefings CFP form.
>
> **CFP deadline: 2026-07-22 23:59 GMT.**

- **Track:** Briefings (research)
- **Suggested tracks:** AI, ML & Data Science · Application Security
- **Based on:** `REPORT.md` (scan date 2026-07-19), corpus of 1,374 distinct public MCP configs

## Title (pick one, then rewrite)

`<-- rewrite this line in your own words before submitting>`
Working title: "The State of MCP Server Authentication: what 1,374 public
configs say about the 2026-07-28 auth spec."

## Abstract (prose block)

`<-- rewrite this paragraph in your own words before submitting>`

Skeleton of verified facts to draw from (each carries n / denominator):
- Corpus: **1,374 distinct public MCP server configs** — 664 GitHub-crawled +
  710 official MCP Registry latest-version servers — deduped by content, scanned
  offline and deterministically. Provenance committed; every number reproducible
  from the manifest.
- **35.1% (482/1,374)** declare a remote MCP server with **no authentication**.
- **0% (0/1,374)** use RFC 9728 Protected Resource Metadata discovery — the
  discovery mechanism the ratified 2025-11-25 auth spec defines.
- Of configs that authenticate to a remote server inline, **100% (318/318)**
  hardcode a static credential rather than obtain an audience-bound token.
- **36.0% (494/1,374)** carry at least one critical-severity finding; median
  config grades **B**.

## Key takeaways (bullets — keep as bullets)

1. The public MCP ecosystem is, in this sample, not structured for the ratified
   auth spec: discovery-based auth (RFC 9728) is at 0%, static credentials at
   100% of inline-auth configs.
2. Migration exposure is asymmetric and partly unmeasurable from configs — stated
   honestly: the 2026-07-28 stateless-transport break has a **config-visible
   proxy** (deprecated SSE, 1.9%), but the `initialize`-handshake /
   `Mcp-Session-Id` and the 2027-07-28 Roots/Sampling/Logging/DCR removals are
   **runtime/server-code properties (0% measurable from configs)** and require
   server-source scanning.
3. The methodology is fully offline and deterministic; the report is a build
   artifact (`make report`) that cannot drift from the code.

## What's new / why accept (prose block)

`<-- rewrite this paragraph in your own words before submitting>`

Facts: prior MCP-security talks are largely qualitative or single-CVE. This is a
quantified, reproducible population study tied to a dated protocol deadline, with
explicit coverage/limitations rather than headline inflation.

## Methodology (bullets)

- Tool: AgentAuditKit (open source, MIT), 262 deterministic rules.
- Corpus: registry API (cursor pagination, cached) + GitHub crawl; content-dedup.
- Scoring: the same penalty-based A–F grade as the shipped `aak score`.
- Reproduce: `make report` (offline) → `results.json`; `fetch_registry.py` refreshes the corpus.

## Responsible disclosure (prose block)

`<-- rewrite this paragraph in your own words before submitting>`

Facts: aggregate-only; no server named. Per-server findings on the public MCP
Security Index follow a coordinated 90-day disclosure policy
(`docs/disclosure-policy.md`).

## Limitations (state plainly — do not omit)

- Sample = public registry + crawled configs, not the whole MCP population
  (private/enterprise servers absent; registry skews to published projects).
- Config-level, not runtime: cannot confirm a no-auth config points at a truly
  open live server; cannot measure runtime-negotiated capabilities.
- Point-in-time (2026-07-19 fetch, 710 of ~17k registry servers).
