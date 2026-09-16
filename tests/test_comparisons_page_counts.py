"""docs/comparisons.md states governed counts inside markdown table cells.

The page said `| Compliance frameworks | 12 | ...` while the live count was 14,
and `make count-check` reported clean the whole time. Neither existing guard
could see it: `find_stale_counts` matches phrases like "N compliance
frameworks", and a table puts the label in one cell and the number in another,
so there is no phrase to match. The corroboration sweep reads prose. The number
sat in the one shape nothing looked at.

Two layers close it, and both are asserted here:

1. the cell carries a `<!-- framework-count:total -->` anchor that
   `scripts/sync_rule_count.py` writes from `pdf_report._FRAMEWORK_TITLES`, so
   the value is injected rather than typed;
2. `check_counts.find_table_cell_faults` reads the table *shape* -- row label in
   the first cell, this project's column located from the header -- so a bare
   number in a governed row is checked even when no marker is present.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPARISONS = REPO_ROOT / "docs" / "comparisons.md"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from check_counts import (  # noqa: E402
    canonical_counts,
    find_table_cell_faults,
)

_FRAMEWORK_CELL_RE = re.compile(
    r"\|\s*Compliance frameworks\s*\|\s*"
    r"<!--\s*framework-count:total\s*-->\s*(\d+)\s*<!--\s*/framework-count\s*-->"
)


def _live_framework_count() -> int:
    from agent_audit_kit.output import pdf_report

    return len(pdf_report._FRAMEWORK_TITLES)


# ---------------------------------------------------------------------------
# The cell itself
# ---------------------------------------------------------------------------


def test_framework_cell_matches_the_live_framework_count() -> None:
    """The bug: this cell said 12 against a live 14."""
    text = COMPARISONS.read_text(encoding="utf-8")
    match = _FRAMEWORK_CELL_RE.search(text)
    assert match, (
        "docs/comparisons.md lost its framework-count anchor; the cell is "
        "written by scripts/sync_rule_count.py and must stay inside the marker"
    )
    assert int(match.group(1)) == _live_framework_count()


def test_framework_count_agrees_with_the_guard_canonical() -> None:
    assert canonical_counts()["frameworks"] == _live_framework_count()


def test_sync_rewrites_the_anchor_rather_than_trusting_the_literal() -> None:
    """--check must fail on a hand-edited value, or the anchor is decoration."""
    original = COMPARISONS.read_text(encoding="utf-8")
    broken = _FRAMEWORK_CELL_RE.sub(
        "| Compliance frameworks | <!-- framework-count:total -->99"
        "<!-- /framework-count -->",
        original,
        count=1,
    )
    assert broken != original, "fixture did not apply"
    COMPARISONS.write_text(broken, encoding="utf-8")
    try:
        proc = subprocess.run(
            [sys.executable, "scripts/sync_rule_count.py", "--check"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        assert proc.returncode != 0, (
            "sync_rule_count.py --check passed a framework anchor reading 99"
        )
    finally:
        COMPARISONS.write_text(original, encoding="utf-8")


# ---------------------------------------------------------------------------
# The generalised guard
# ---------------------------------------------------------------------------


def test_repo_has_no_table_cell_count_faults() -> None:
    faults = find_table_cell_faults()
    assert faults == [], "stale count(s) in a markdown table cell:\n  " + "\n  ".join(faults)


@pytest.mark.parametrize(
    ("label", "key"),
    [
        ("Compliance frameworks", "frameworks"),
        ("Rules", "rules"),
        ("Scanner modules", "scanners"),
        ("CLI commands", "commands"),
        ("Agent platforms", "platforms"),
        ("Categories", "categories"),
    ],
)
def test_guard_catches_a_bare_stale_number_for_each_governed_label(
    tmp_path: Path, label: str, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every label in COUNTS, not just the one that happened to rot."""
    import check_counts

    wrong = canonical_counts()[key] + 1
    doc = tmp_path / "t.md"
    doc.write_text(
        "| Feature | agent-audit-kit | Other |\n"
        "|---|---|---|\n"
        f"| {label} | {wrong} | 0 |\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(check_counts, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(check_counts, "_tracked_markdown", lambda: ["t.md"])
    faults = check_counts.find_table_cell_faults()
    assert len(faults) == 1, f"guard missed a stale {key} cell: {faults}"
    assert key in faults[0]


def test_guard_does_not_fire_on_a_competitor_column(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only this project's column is a claim about this project's registry."""
    import check_counts

    doc = tmp_path / "t.md"
    doc.write_text(
        "| Feature | agent-audit-kit | Other |\n"
        "|---|---|---|\n"
        f"| Compliance frameworks | {canonical_counts()['frameworks']} | 3 |\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(check_counts, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(check_counts, "_tracked_markdown", lambda: ["t.md"])
    assert check_counts.find_table_cell_faults() == []


def test_guard_locates_the_column_from_the_header_not_a_fixed_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """comparisons.md puts the AAK column in position 1 in one table and 2 in
    the other, so a hard-coded index would check the wrong competitor."""
    import check_counts

    wrong = canonical_counts()["frameworks"] + 1
    doc = tmp_path / "t.md"
    doc.write_text(
        "| | Vendor A | agent-audit-kit |\n"
        "|---|---|---|\n"
        f"| Compliance frameworks | 3 | {wrong} |\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(check_counts, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(check_counts, "_tracked_markdown", lambda: ["t.md"])
    faults = check_counts.find_table_cell_faults()
    assert len(faults) == 1 and str(wrong) in faults[0]


def test_guard_skips_a_generated_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Inside a marker the value has an owner; re-checking it duplicates that."""
    import check_counts

    doc = tmp_path / "t.md"
    doc.write_text(
        "| Feature | agent-audit-kit |\n"
        "|---|---|\n"
        "| Rules | <!-- rule-count:total -->999<!-- /rule-count --> |\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(check_counts, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(check_counts, "_tracked_markdown", lambda: ["t.md"])
    assert check_counts.find_table_cell_faults() == []
