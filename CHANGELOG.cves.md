# AAK Response SLA — CVE-to-Rule Ledger

We publicly commit to shipping rule coverage for every disclosed MCP CVE
within **48 hours of NVD disclosure**. This file is the audit trail.

Format: one line per CVE, `CVE-YYYY-NNNNN` → `AAK-XXX-NNN` with the
shipped-at timestamp. The GitHub Action `.github/workflows/cve-watcher.yml`
diffs NVD's MCP keyword feed against this file and opens an
`sla-48h`-labelled issue for anything new.

## Shipped in v0.3.0

| CVE | Advisory | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| CVE-2025-59536 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-59536) | AAK-HOOK-RCE-001, AAK-HOOK-RCE-002, AAK-HOOK-RCE-003 | 2026-04-18 | retroactive |
| CVE-2026-33032 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-33032) | AAK-MCP-011, AAK-MCP-012, AAK-MCP-020 | 2026-04-18 | retroactive |
| CVE-2026-34070 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-34070) | AAK-LANGCHAIN-001, AAK-LANGCHAIN-002 | 2026-04-18 | retroactive |
| CVE-2025-68664 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-68664) | AAK-LANGCHAIN-003 | 2026-04-18 | retroactive |

## Open (48h SLA ticking)

_none — file response-tracking issues get posted here when the SLA fires._
