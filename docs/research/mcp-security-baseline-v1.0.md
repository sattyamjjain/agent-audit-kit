# MCP Security Baseline v1.0 (pre-2026-07-28-spec)

A frozen, citable measurement of the security posture of public MCP server
configurations, taken with [AgentAuditKit](https://github.com/sattyamjjain/agent-audit-kit)
**before** the 2026-07-28 MCP specification revision. It exists so the effect of
the new spec can be measured against a fixed reference instead of a moving one.

- **Baseline ID:** `mcp-security-baseline-v1.0-2026-07-27`
- **Snapshot:** [`research/state-of-mcp-2026/baseline/mcp-security-baseline-v1.0-2026-07-27.json`](https://sattyamjjain.github.io/agent-audit-kit/docs/research/state-of-mcp-2026/baseline/mcp-security-baseline-v1.0-2026-07-27.json)
- **SHA-256:** `320b43072d930edbc18f050795939dbee3831e4da2f88b3483ea12ec7bb6551f`
- **Tool:** agent-audit-kit 0.3.56 · 262 rules · fully offline
- **This is the PRE-spec baseline.** The 2026-07-28 spec has **not** shipped as of
  this snapshot, so this document makes **no** claim about the post-spec world.
  The re-measure is scheduled for **2026-08-11**.

Verify the snapshot is untampered:

```bash
shasum -a 256 research/state-of-mcp-2026/baseline/mcp-security-baseline-v1.0-2026-07-27.json
# 320b43072d930edbc18f050795939dbee3831e4da2f88b3483ea12ec7bb6551f
```

## What was measured

Every metric below is recorded **per config** and **in aggregate** in the
snapshot JSON. AgentAuditKit's shipped engine scanned each config in isolation;
the baseline harness adds **no** detection rules — it reuses `engine.run_scan`,
`scoring.compute_score`, and the `rules.builtin.RULES` table.

| Dimension | Value |
|-----------|-------|
| Distinct configs scanned | **1,374** (664 crawl + 710 registry; 83 duplicates + 1 unparseable removed from 1,458 candidates) |
| No authentication | **484 / 1,374 (35.2%)** |
| Static credential header ("bearer") | 318 / 1,374 (23.1%) |
| OAuth 2.1 discovery (RFC 9728 PRM) | 0 / 1,374 (0.0%) |
| Auth posture unknown (local stdio, no remote surface) | 572 / 1,374 (41.6%) |
| Transport entries — stdio | 1,265 |
| Transport entries — streamable-HTTP | 900 |
| Transport entries — SSE | 41 |
| Configs with ≥1 CRITICAL | 494 / 1,374 (36.0%) |
| Configs with ≥1 HIGH | 164 / 1,374 (11.9%) |

### Top HIGH/CRITICAL rules (config hit counts)

The snapshot records the hit count for **every** HIGH/CRITICAL rule; the largest:

| Rule | Severity | Configs |
|------|----------|--------:|
| `AAK-MCP-001` Remote MCP server without authentication | critical | 482 |
| `AAK-MCP-003` MCP server environment exposes secrets | high | 70 |
| `AAK-MCP-STDIO-LAUNCHER-INJECT-001` stdio launcher shell/exec injection | high | 49 |
| `AAK-MCP-009` MCP server URL points to localhost/internal network | high | 44 |
| `AAK-MCP-004` Excessive number of MCP servers declared | high | 12 |
| `AAK-MCP-002` MCP server command runs with shell expansion | critical | 9 |

## Collection window

The collection window is **data**, not a wall-clock read at emit time — it comes
from the corpus manifest, which is why the payload is byte-deterministic.

- **Registry corpus fetched:** `2026-07-19` (`registry-manifest.json.fetched_at`),
  710 distinct-latest servers from `registry.modelcontextprotocol.io`.
- **Crawl corpus:** GitHub-crawled `.mcp.json` files under `benchmarks/data`.

## Methodology

1. **Corpus.** Two provenance-tracked sources — the crawled `.mcp.json` set and the
   official MCP Registry manifest — deduplicated by canonical config content
   (SHA-256 of the sorted-key JSON). 1,458 candidates → 1,374 distinct configs.
2. **Scan.** Each config is written to a temp dir and scanned with the shipped
   `engine.run_scan` + `scoring.compute_score`. No network, no LLM.
3. **Auth posture.** Derived per config from its content using the existing
   `oauth_misconfig` signals (reused, not re-implemented): an RFC 9728 PRM
   discovery surface → `oauth2.1`; a static credential header on a remote server →
   `bearer`; a remote server with no detectable auth (or `AAK-MCP-001` firing) →
   `no-auth`; everything else (local stdio) → `unknown`.
4. **Determinism.** Sorted keys, stable float rounding, and no wall-clock value in
   the payload. Two runs over the same corpus produce byte-identical output; the
   SHA-256 above is taken over exactly those bytes. Guarded by
   `tests/test_mcp_security_baseline.py`.

### Reproducibility caveat

Only the **710-server registry corpus** is committed to git. The 664 crawl configs
live under `benchmarks/data`, which is **gitignored** (downloaded third-party
configs are not redistributed). So the full-corpus (1,374) numbers above are **not
independently re-scannable** from a clean clone — the **registry subset is**. The
determinism test therefore runs over the committed registry/synthetic corpus, and
the tamper-evidence test hashes the committed snapshot. The headline figures match
the published [State of MCP 2026 report](https://sattyamjjain.github.io/agent-audit-kit/docs/research/state-of-mcp-2026/REPORT/).

## False-positive-rate caveat

The snapshot records the benign-slice HIGH/CRITICAL false-positive rate **with its
denominator**, from `benchmarks/false_positive/results.json`:

- **Benign slice:** 368 configs (official MCP Registry, active, declares an auth
  mode, not in any CVE feed AAK ships). "Benign" is the server's own published
  metadata — **not** "AAK found nothing" (that would be circular).
- **Machine result:** 4 HIGH/CRITICAL findings on the slice — 1.1% of configs
  (Wilson 95% CI [0.4%, 2.8%]).
- **Hand-adjudicated (single rater):** 2 false positives, 1 true positive, 1
  ambiguous → **benign-slice HIGH/CRITICAL false-positive rate = 2 / 4 = 50.0%**
  (Wilson 95% CI [15.0%, 85.0%]).

This is deliberately labelled *benign-slice HIGH/CRITICAL false-positive rate*, not
"false-positive rate" unqualified: of the few high-severity findings AAK raises on
servers that look benign, half were wrong, and both share one fixable root cause
(`AAK-MCP-001` not recognising custom API-key headers). The interval is wide
because n is small — stated plainly. Full adjudication:
[`benchmarks/false_positive/triage.md`](../../benchmarks/false_positive/triage.md).

## Re-measuring after the spec ships

The 2026-08-11 re-measure is one command — it re-scans the corpus and diffs against
this frozen baseline (absolute + percentage-point deltas per dimension):

```bash
python research/state-of-mcp-2026/baseline.py \
    --compare research/state-of-mcp-2026/baseline/mcp-security-baseline-v1.0-2026-07-27.json
```

Until the 2026-07-28 spec actually ships, **no** post-spec comparison is claimed.
