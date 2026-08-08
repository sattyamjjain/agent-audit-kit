"""Guard: CORPUS_N is the single source for the State-of-MCP corpus size.

2,303 was reconciled by hand across five surfaces in commit 2aba7a6, and a hand
reconciliation drifts the moment the corpus grows — exactly what happened to
RULE_COUNT on the GitHub repo description. `CORPUS_N` in `agent_audit_kit/__init__.py`
is now the code constant, tied here to (a) the `results.json` artifact it was
measured from and (b) every comma-formatted four-digit "N,NNN ... MCP server" claim
in the current published surfaces.

Scope is an explicit file list, not a directory sweep. A broad sweep also catches
dated / frozen artifacts that legitimately quote a *superseded* N and must NOT be
rewritten:
  - research/state-of-mcp-2026/blackhat-briefings-abstract.md — a dated CFP skeleton
    based on the 2026-07-19 scan of 1,374 configs ("DO NOT SUBMIT AS-IS").
  - docs/research/mcp-security-baseline-v1.0.md + research/state-of-mcp-2026/baseline/**
    — the frozen pre-2026-07-28 baseline (N=1,374).
Those are excluded on purpose (per the "fall back to an explicit file list" note in
the work item).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agent_audit_kit import CORPUS_N

REPO = Path(__file__).resolve().parent.parent
RESULTS = REPO / "research" / "state-of-mcp-2026" / "results.json"

# Current published surfaces that quote the corpus size in prose. The source of
# truth (results.json) is checked separately; the dated/frozen artifacts above are
# deliberately absent.
_SURFACES = (
    "README.md",
    "research/state-of-mcp-2026/PREVALENCE.md",
    "research/state-of-mcp-2026/REPORT.md",
    "docs/STATE-OF-MCP-SECURITY-2026.md",
    "docs/DISTRIBUTION-CHECKLIST.md",
)

# A comma-formatted four-digit number immediately preceding "(MCP|Model Context
# Protocol) server" — i.e. the corpus-size claim ("2,303 distinct public MCP server
# configs"). Deliberately narrow so per-metric numbers ("1,205 ... remote server",
# "1,641 ... registry servers") are not swept in.
_CORPUS_CLAIM_RE = re.compile(
    r"(\d,\d{3})\s+(?:distinct\s+)?(?:public\s+)?(?:MCP|Model Context Protocol)\s+server"
)


def test_corpus_n_matches_results_json() -> None:
    n = json.loads(RESULTS.read_text(encoding="utf-8"))["distinct_configs_scanned"]
    assert CORPUS_N == n, (
        f"CORPUS_N ({CORPUS_N}) != results.json distinct_configs_scanned ({n}). "
        "Update CORPUS_N in agent_audit_kit/__init__.py after a corpus refresh."
    )


def test_published_corpus_size_claims_match_corpus_n() -> None:
    want = f"{CORPUS_N:,}"
    found = 0
    bad: list[str] = []
    for rel in _SURFACES:
        text = (REPO / rel).read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for m in _CORPUS_CLAIM_RE.finditer(line):
                found += 1
                if m.group(1) != want:
                    bad.append(f"{rel}:{lineno}: {m.group(0).strip()!r} != {want}")
    assert found, (
        "no 'N,NNN ... MCP server' corpus-size claim matched in any surface — the "
        "guard would silently pass on nothing; check the surface list / regex."
    )
    assert not bad, (
        f"published corpus-size claim(s) disagree with CORPUS_N ({want}) — a corpus "
        "refresh left a stale number behind:\n  " + "\n  ".join(bad)
    )
