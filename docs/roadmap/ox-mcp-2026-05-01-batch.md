# OX MCP 2026-05-01 batch — design doc

**Status:** active (v0.3.14 → v0.3.16). **Owner:** maintainer.

## Source

- [OX Security blog (2026-05-01)](https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/) — disclosed 10+ CVEs across single-author MCP-server projects, rooted in the same architectural shape: an MCP server config advertises a "safe" transport (SSE / HTTP / HTTPS) but accepts a post-handshake `transport=stdio` override from MITM-edited JSON, reaching the receiver-side cmd-injection class.
- [BackBox news roundup (2026-05-01)](https://news.backbox.org/2026/05/01/200000-mcp-servers-expose-a-command-execution-flaw-that-anthropic-calls-a-feature/) — reframes the OX disclosure as a 200,000-server exposure footprint.
- v0.3.12 CHANGELOG carry-list — explicit deferral of "DocsGPT, GPT-Researcher, Agent-Zero, LettaAI" each as `>S effort independently`.

## Coverage state

| Vendor | CVE | npm? | PyPI? | git? | v0.3.14 status | Targeted release |
|---|---|---|---|---|---|---|
| **DocsGPT** (`arc53/DocsGPT`) | CVE-2026-26015 | ✅ `docsgpt` | ✅ `docsgpt-mcp` (rare) | ✅ | **shipped** as `AAK-DOCSGPT-MCP-STDIO-MITM-001` (pin + transport-flip) | v0.3.14 |
| **GPT-Researcher** (`assafelovic/gpt-researcher`) | CVE-2025-65720 | partial | ✅ `gpt-researcher` | ✅ | covered class-wide via `AAK-MCP-STDIO-CMD-INJ-001` (Python receiver shape) | v0.3.15 (pin-floor + named row) |
| **Agent-Zero** (`frdel/agent-zero`) | CVE-2026-30624 | ❌ | ❌ (GitHub-only) | ✅ | covered class-wide via `AAK-STDIO-001` | v0.3.15 (git-pin + transport-flip) |
| **LettaAI** (`letta-ai/letta`, formerly MemGPT) | TBD | ✅ `@letta-ai/letta` | ✅ `letta` | ✅ | covered class-wide via `AAK-MCP-STDIO-CMD-INJ-001/002` | v0.3.16 (pin-floor + named row) |
| **transport-flip-resistance generalization** | n/a | n/a | n/a | n/a | DocsGPT-only today | v0.3.16 — promote to umbrella `AAK-MCP-TRANSPORT-FLIP-001` covering all SSE/HTTP-advertising configs |

The four umbrella rules `AAK-MCP-STDIO-CMD-INJ-001/002/003/004` + `AAK-STDIO-001` already catch the **receiver-side** of every entry above (any process that accepts a stdio command from network-controlled input). What's missing per row is:
1. The **product-named pin** consumers expect when grepping `CHANGELOG.cves.md`.
2. The **server-config transport-flip** check (the receiver-side rules don't see it because they only fire post-flip).

## Implementation phases

### Phase 1 — DocsGPT (v0.3.14, 2026-05-05) ✅ shipped

- `AAK-DOCSGPT-MCP-STDIO-MITM-001` (pin + transport-flip arms).
- 7 tests, fixtures under `tests/fixtures/cves/cve-2026-26015-docsgpt/`.

### Phase 2 — GPT-Researcher + Agent-Zero (v0.3.15)

- `AAK-GPT-RESEARCHER-CVE-2025-65720-PIN-001` (pin <patched on PyPI + git).
- `AAK-AGENT-ZERO-CVE-2026-30624-PIN-001` (git+https pin only — package isn't on npm/PyPI).
- Per-vendor tests in `tests/test_v0_3_15_rules.py`.
- Reuse the `_DOCSGPT_*_RE` pattern shape from `supply_chain.py` for both.

### Phase 3 — LettaAI + transport-flip generalization (v0.3.16)

- `AAK-LETTA-MCP-STDIO-MITM-001` (pin + transport-flip arms; npm + PyPI + git all valid surfaces).
- Promote `docsgpt_transport_flip.py` → `mcp_transport_flip.py` covering any DocsGPT/GPT-Researcher/Agent-Zero/LettaAI named config + add a `--strict` mode that fires on any SSE/HTTP-advertising config without an explicit reject-stdio guard.

### Phase 4 — close the carry list

- Once Phase 1 → 3 ship, the v0.3.12 carry-list is fully retired.
- The watcher dedup fix (cve-watcher should consult `closed`-issue lookup so the same CVE ID doesn't re-fire as a new issue every 24h) lands as a separate v0.3.15 patch — see [`scripts/cve_watcher.py`](../scripts/cve_watcher.py) for the current dedup logic.

## Tracking issues (filed 2026-05-05 alongside this doc)

- `Phase 2 — GPT-Researcher CVE-2025-65720 named pin row` (label: `cve-rule`, milestone v0.3.15)
- `Phase 2 — Agent-Zero CVE-2026-30624 named pin row` (label: `cve-rule`, milestone v0.3.15)
- `Phase 3 — LettaAI named pin + transport-flip row` (label: `cve-rule`, milestone v0.3.16)
- `Phase 3 — Promote transport-flip detector to MCP_TRANSPORT_FLIP umbrella` (label: `epic`, `needs-design`, milestone v0.3.16)
- `cve-watcher dedup fix` (label: `bug`, milestone v0.3.15) — **not part of the OX batch but blocks a clean ledger**

## Source-of-truth contract

Every per-vendor rule in this batch shares the same `incident_references=["OX-MCP-2026-05-01"]` tag so consumers can grep the rule registry by incident ID and recover the full coverage slice:

```bash
agent-audit-kit rule lint --incident OX-MCP-2026-05-01
```

(That `--incident` filter is itself a v0.3.16 backlog item — until then, manual grep against `agent_audit_kit/rules/builtin.py`.)
