"""OWASP Agentic Top 10 2026 coverage-gap regression test.

Every Top-10 entry (ASI01…ASI10) must have ≥1 rule tagging it. Source:
https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
"""

from __future__ import annotations

import importlib.util
import sys
from collections import defaultdict
from pathlib import Path

import pytest

from agent_audit_kit.rules.builtin import RULES


REPO_ROOT = Path(__file__).resolve().parent.parent
OWASP_TOP_10_IDS: tuple[str, ...] = (
    "ASI01", "ASI02", "ASI03", "ASI04", "ASI05",
    "ASI06", "ASI07", "ASI08", "ASI09", "ASI10",
)


def _coverage_map() -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for rid, rule in RULES.items():
        for asi in rule.owasp_agentic_references:
            out[asi].append(rid)
    return dict(out)


@pytest.mark.parametrize("asi", OWASP_TOP_10_IDS)
def test_every_owasp_agentic_entry_has_at_least_one_rule(asi: str) -> None:
    coverage = _coverage_map()
    assert coverage.get(asi), (
        f"No AAK rule tags {asi}. Add owasp_agentic_references=[\"{asi}\"] "
        "to at least one rule in agent_audit_kit/rules/builtin.py."
    )


def test_no_typo_owasp_agentic_references() -> None:
    """Every ASI reference must be a known ASI01-ASI10. Catches typos."""
    coverage = _coverage_map()
    unknown = sorted(set(coverage) - set(OWASP_TOP_10_IDS))
    assert not unknown, (
        f"Rules reference unknown OWASP Agentic IDs: {unknown}. "
        "Fix the typo in the relevant rule definition."
    )


def test_coverage_doc_exists_and_lists_every_asi() -> None:
    """docs/owasp-agentic-coverage.md must be regenerated before merge."""
    doc = REPO_ROOT / "docs" / "owasp-agentic-coverage.md"
    assert doc.is_file(), "run scripts/gen_owasp_coverage.py"
    text = doc.read_text(encoding="utf-8")
    for asi in OWASP_TOP_10_IDS:
        assert asi in text, f"{asi} missing from docs/owasp-agentic-coverage.md"


def test_gen_coverage_script_runs_clean() -> None:
    """scripts/gen_owasp_coverage.py must exit 0 (no gaps, no write error)."""
    script = REPO_ROOT / "scripts" / "gen_owasp_coverage.py"
    spec = importlib.util.spec_from_file_location("gen_owasp_coverage", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_owasp_coverage"] = module
    spec.loader.exec_module(module)
    assert module.main() == 0
