"""Regression fence for the OWASP coverage leaderboard (issue #67).

`scripts/gen_coverage.py` emits `docs/coverage/owasp-agentic-top10.md` and
`docs/coverage/owasp-mcp-top10.md` from the live rule registry. These tests
fail CI if the committed tables drift from what the generator would emit, and
assert the leaderboard's honesty invariants (every category has ≥1 rule; the
toolkit-comparison note is present and sourced).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("gen_coverage", _ROOT / "scripts" / "gen_coverage.py")
assert _SPEC and _SPEC.loader
gen_coverage = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gen_coverage)


def test_committed_tables_match_generator() -> None:
    """The committed tables must equal fresh generator output (stale guard)."""
    assert gen_coverage.check() == 0, (
        "docs/coverage/*.md is stale — run `python scripts/gen_coverage.py`"
    )


def test_agentic_table_covers_all_ten() -> None:
    text = gen_coverage.render_agentic()
    for asi in gen_coverage.ASI_TITLES:
        assert asi in text
    # honesty: no ASI row should be labelled None (every category has a rule)
    assert "| None |" not in text


def test_mcp_table_covers_all_ten() -> None:
    text = gen_coverage.render_mcp()
    for code in gen_coverage.OWASP_MCP:
        assert code in text


def test_kong_rule_lands_in_leaderboard() -> None:
    text = gen_coverage.render_mcp()
    assert "AAK-MCP-KONG-CVE-2026-13341-001" in text  # MCP05


def test_toolkit_note_is_sourced_and_honest() -> None:
    text = gen_coverage.render_agentic()
    assert "Microsoft Agent Governance Toolkit" in text
    assert "https://github.com/microsoft/agent-governance-toolkit" in text
    # Full path-qualified URLs (not bare hostnames) so the check can't be
    # satisfied by a look-alike domain.
    assert "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications" in text
    # honest framing — static scanner vs runtime enforcement, not a head-to-head
    assert "static" in text.lower() and "runtime" in text.lower()
