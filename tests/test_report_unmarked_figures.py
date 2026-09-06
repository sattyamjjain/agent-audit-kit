"""A governed figure stated outside a marker must fail the build.

``test_report_headline_numbers.py`` is a strong lock with one structural blind
spot: it can only compare numbers that already carry a ``report:`` marker. A
second, unmarked copy of the same figure is invisible to it -- and an unmarked
copy is exactly what writing prose produces.

That blind spot had four live instances when this was written. README.md:55,
README.md:573 and docs/STATE-OF-MCP-SECURITY-2026.md:36 all said
``100% (421/421)`` while results.json said 424, and
research/state-of-mcp-2026/PREVALENCE.md:95 said ``421 | 18.3%`` while
REPORT.md:37, in a sibling directory, said ``18.4% (424)``. Every marker test
was green the whole time.

The tests here pin the two decisions that make the guard survivable rather than
switched-off-in-a-week:

* matching is anchored to the *claim*, never to bare digits -- an un-anchored
  ``N% (M)`` pattern matched all nine rows of REPORT.md's table on the first
  draft; and
* REPORT.md is judged differently from the generated surfaces, because it is the
  document the markers are pinned to rather than one of their outputs.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load():
    script = REPO_ROOT / "scripts" / "check_report_figures.py"
    assert script.is_file(), "scripts/check_report_figures.py missing"
    spec = importlib.util.spec_from_file_location("check_report_figures", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_report_figures"] = module
    spec.loader.exec_module(module)
    return module


mod = _load()


# ---------------------------------------------------------------------------
# The tree is clean
# ---------------------------------------------------------------------------

def test_no_governed_figure_is_stated_outside_a_marker() -> None:
    unmarked, disagree = mod.find_violations()
    assert not unmarked, "unmarked governed figures:\n  " + "\n  ".join(unmarked)
    assert not disagree, "source report disagrees with data:\n  " + "\n  ".join(disagree)


def test_the_guard_exits_zero_on_the_current_tree() -> None:
    assert mod.main([]) == 0


# ---------------------------------------------------------------------------
# It actually catches the four defects it was built for
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,label", [
    ("100% (421/421) of inline-auth remote configs hardcode a static credential",
     "README.md:55 / :573 shape"),
    ("0% use RFC 9728 discovery, and 100% (421/421) of\ninline-auth remote configs",
     "docs coverage-doc shape, ratio split across a line break"),
    ("| 3 | `AAK-OAUTH-008` — no RFC 9728 PRM discovery | LOW | 421 | 18.3% |",
     "PREVALENCE.md:95 top-10 row"),
])
def test_each_historical_defect_is_caught(tmp_path, monkeypatch, text, label) -> None:
    """The exact prose that sat published while every other guard was green."""
    rel = "README.md"
    (tmp_path / rel).write_text(text, encoding="utf-8")
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    rows = mod.scan_file(rel, must_be_marked=True)
    assert rows, f"guard missed {label}"


def test_a_correct_but_unmarked_value_is_still_a_defect(tmp_path, monkeypatch) -> None:
    """424 typed by hand is the same class of defect as 421 typed by hand.

    It passes today and rots on the next corpus run, which is the whole failure
    this guard exists to end. The message must say so rather than reporting a
    value mismatch that does not exist.
    """
    (tmp_path / "README.md").write_text(
        "100% (424/424) of inline-auth remote configs", encoding="utf-8"
    )
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    rows = mod.scan_file("README.md", must_be_marked=True)
    assert len(rows) == 1
    assert "not marker-driven" in rows[0]


def test_a_marked_figure_is_invisible_to_the_guard(tmp_path, monkeypatch) -> None:
    """Masking is what makes a correctly generated surface pass."""
    marked = (
        "<!-- report:inline-auth-pct -->100<!-- /report -->% "
        "(<!-- report:inline-auth-n -->424<!-- /report -->/"
        "<!-- report:inline-auth-d -->424<!-- /report -->) of inline-auth configs"
    )
    (tmp_path / "README.md").write_text(marked, encoding="utf-8")
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    assert mod.scan_file("README.md", must_be_marked=True) == []


# ---------------------------------------------------------------------------
# Design point (a): anchored shapes, not bare integers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "The `AAK-MCP-001` rule, added in v0.3.94, maps to CVE-2026-81096.",
    "RFC 9728 Protected-Resource-Metadata, RFC 8707 resource indicators.",
    "| 2 | `AAK-MCP-005` — npx fetch-and-execute | MEDIUM | 450 | 19.5% |",
    "Rules: 332 across 14 categories, 98 scanners, 26 CLI commands.",
    "- **Grade distribution:** A 637, B 1,421, C 111, D 49, F 85.",
])
def test_unrelated_numbers_are_not_flagged(tmp_path, monkeypatch, text) -> None:
    """A guard that fires on rule IDs, RFC numbers, versions and sibling table
    rows gets switched off. The first draft of this file did exactly that -- an
    un-anchored `N% (M)` pattern matched every row of REPORT.md's table."""
    (tmp_path / "README.md").write_text(text, encoding="utf-8")
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    assert mod.scan_file("README.md", must_be_marked=True) == []


def test_masking_preserves_line_numbers(tmp_path, monkeypatch) -> None:
    """Offsets must survive masking or the reported line points at the wrong place."""
    body = "filler\n" * 40 + "100% (421/421) of inline-auth configs\n"
    (tmp_path / "README.md").write_text(body, encoding="utf-8")
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    rows = mod.scan_file("README.md", must_be_marked=True)
    assert rows and rows[0].startswith("README.md:41 "), rows


def test_mask_is_length_preserving() -> None:
    src = "a <!-- report:noauth-n -->1,200<!-- /report --> b"
    assert len(mod.mask_markers(src)) == len(src)
    assert "1,200" not in mod.mask_markers(src)


# ---------------------------------------------------------------------------
# Design point: REPORT.md is judged differently, on purpose
# ---------------------------------------------------------------------------

def test_report_md_tolerates_an_unmarked_but_correct_figure(tmp_path, monkeypatch) -> None:
    """It is the source document -- prose-asserted, never generated. Requiring
    markers there would demand machinery in the text people cite."""
    rel = "research/state-of-mcp-2026/REPORT.md"
    (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / rel).write_text(
        "| no RFC 9728 discovery | `AAK-OAUTH-008` (low) | 18.4% (424) |",
        encoding="utf-8",
    )
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    assert mod.scan_file(rel, must_be_marked=False) == []


def test_report_md_still_fails_on_a_contradicting_figure(tmp_path, monkeypatch) -> None:
    """This is what including REPORT.md buys: its AAK-OAUTH-008 figure is read by
    no other test, so before this guard it could contradict PREVALENCE.md freely
    -- which is exactly what it did."""
    rel = "research/state-of-mcp-2026/REPORT.md"
    (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / rel).write_text(
        "| no RFC 9728 discovery | `AAK-OAUTH-008` (low) | 18.3% (421) |",
        encoding="utf-8",
    )
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    rows = mod.scan_file(rel, must_be_marked=False)
    assert len(rows) == 1 and "results.json says" in rows[0]


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------

def test_every_figure_names_only_real_generator_keys() -> None:
    """A pattern naming a key the generator does not produce raises at scan time
    on a file that happens to match, i.e. in production rather than here."""
    values = mod.governed_values()
    for figure in mod.FIGURES:
        unknown = [k for k in figure.keys if k not in values]
        assert not unknown, f"{figure.name} references unknown key(s) {unknown}"


def test_capture_group_count_matches_key_count() -> None:
    """Groups are zipped against keys positionally, so a mismatch misreports."""
    for figure in mod.FIGURES:
        assert figure.pattern.groups == len(figure.keys), (
            f"{figure.name}: {figure.pattern.groups} groups, {len(figure.keys)} keys"
        )


def test_marker_file_list_matches_the_generator() -> None:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from sync_rule_count import _REPORT_MARKER_FILES  # noqa: PLC0415

    assert sorted(mod.MUST_BE_MARKED) == sorted(_REPORT_MARKER_FILES), (
        "check_report_figures.MUST_BE_MARKED and the generator's list disagree"
    )


def test_makefile_and_ci_run_the_guard() -> None:
    """A guard nothing invokes is a guard that does not exist."""
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "report-figures-check:" in makefile
    assert "scripts/check_report_figures.py" in makefile
    ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "make report-figures-check" in ci, "CI does not run the guard"
