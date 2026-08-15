"""AgentAuditKit — Security scanner for MCP-connected AI agent pipelines."""
from __future__ import annotations

__version__ = "0.3.78"
RULE_COUNT = 303
SCANNER_COUNT = 90
# Distinct public MCP server configs in the State-of-MCP-2026 corpus, measured from
# research/state-of-mcp-2026/results.json (distinct_configs_scanned), fetched
# 2026-07-26. Published in REPORT.md/PREVALENCE.md/etc.; guarded by
# tests/test_corpus_n_single_source.py so a corpus refresh can't leave a stale
# number behind (as RULE_COUNT once did on the GitHub repo description).
CORPUS_N = 2303
