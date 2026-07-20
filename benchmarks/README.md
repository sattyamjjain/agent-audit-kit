# AgentAuditKit Benchmark Dataset

This directory contains tooling to benchmark AgentAuditKit against real-world
MCP configuration files found on public GitHub repositories.

## Purpose

1. **Prove the scanner works at scale** by running it against hundreds of
   publicly available `.mcp.json` files.
2. **Generate aggregate statistics** on the security posture of the MCP
   ecosystem: how many configs contain hardcoded secrets, missing auth,
   shell injection vectors, and other common misconfigurations.
3. **Provide sample configs** that exercise every major rule category so
   developers can verify scanner behaviour without network access.

## Published benchmarks

Two self-benchmarks are published with reproducible, offline, deterministic
harnesses (no LLM in the loop):

- **[Determinism](determinism/RESULTS.md)** — 20/20 runs → one shared SHA-256
  finding-set digest, 0% variance (`determinism/run.py`).
- **[Benign-slice HIGH/CRITICAL false-positive rate](false_positive/RESULTS.md)**
  — measured on a pre-registered 368-config benign slice of the public MCP
  Registry: 4 HIGH/CRITICAL findings (1.1% of the slice), hand-adjudicated to a
  **2/4 = 50% benign-slice HIGH/CRITICAL FP rate** (Wilson 95% CI [15%, 85%];
  small n, wide interval). Root cause filed as an issue. Harness:
  `false_positive/run.py`, benign predicate: `false_positive/corpus.py`,
  adjudication: `false_positive/triage.md`.

## Quick Start

```bash
# Run against the bundled sample configs (no network required)
bash benchmarks/run_benchmark.sh

# Crawl GitHub for public .mcp.json files and benchmark them
python benchmarks/crawler.py --limit 50 --output benchmarks/results.json
```

## Directory Layout

```
benchmarks/
  crawler.py            # GitHub Search API crawler + benchmark runner
  run_benchmark.sh      # Shell script for local sample benchmarks
  sample_configs/       # Hand-crafted configs covering all rule categories
    sample_01_clean.json
    sample_02_secrets.json
    sample_03_no_auth.json
    sample_04_shell_injection.json
    sample_05_mixed.json
  data/                 # Downloaded configs from GitHub (git-ignored)
  results.json          # Aggregate benchmark output (git-ignored)
```

## Notes

- The crawler respects GitHub API rate limits (10 requests/minute for
  unauthenticated access). Set the `GITHUB_TOKEN` environment variable
  to increase throughput.
- Downloaded configs are stored in `benchmarks/data/` which is git-ignored.
- No external Python dependencies are required; the crawler uses only the
  standard library (`urllib`, `json`, `argparse`).
