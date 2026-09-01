"""scripts/sync_repo_metadata.py regression fence."""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "sync_repo_metadata.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("sync_repo_metadata", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["sync_repo_metadata"] = module
    spec.loader.exec_module(module)
    return module


def test_readme_pins_match_pyproject_version() -> None:
    module = _load_module()
    version = module._read_version()
    target = f"sattyamjjain/agent-audit-kit@v{version}"
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    pins = re.findall(r"sattyamjjain/agent-audit-kit@v\d+\.\d+\.\d+", readme)
    assert pins, "README must contain at least one action pin"
    for pin in pins:
        assert pin == target, (
            f"README pin {pin!r} drifts from pyproject {target!r}. "
            "Run `python scripts/sync_repo_metadata.py --write`."
        )


def test_description_string_carries_every_derived_count() -> None:
    """The canonical description states counts that are all substituted from code.

    It used to assert the version and the literal "AgentAuditKit" too. Both were
    properties of a *second*, competing description string that this module
    composed itself — see the next test. The canonical one, the template in
    `.github/repo-metadata.yml` that the release gate actually enforces and that
    github.com actually serves, carries no version, so asserting one only pinned
    the wrong string in place.
    """
    from agent_audit_kit.models import Category
    from agent_audit_kit.output import pdf_report

    module = _load_module()
    desc = module._description_string()
    assert str(module._read_rule_count()) in desc
    assert str(len(list(Category))) in desc
    assert str(len(pdf_report._FRAMEWORK_TITLES)) in desc
    assert "MCP" in desc


def test_the_writer_and_the_checker_agree_on_the_description() -> None:
    """One canonical string, or the automation fights its own gate.

    `sync-repo-metadata.yml` WRITES `sync_repo_metadata._description_string()`.
    `description-liveness` in release.yml CHECKS against
    `render_repo_metadata.render()`. Until 2026-09-01 those produced different
    text, so a successful write would have set a description the very next
    release rejected. It never surfaced only because the write step has never
    run — it needs a METADATA_SYNC_TOKEN that does not exist. Two latent bugs
    cancelling out is not the same as either one being fixed, and the day a
    token is added is the day they stop cancelling.
    """
    import importlib.util
    import sys as _sys

    spec = importlib.util.spec_from_file_location(
        "render_repo_metadata", REPO_ROOT / "scripts" / "render_repo_metadata.py"
    )
    assert spec is not None and spec.loader is not None
    render_mod = importlib.util.module_from_spec(spec)
    _sys.modules["render_repo_metadata"] = render_mod
    spec.loader.exec_module(render_mod)

    module = _load_module()
    assert module._description_string() == render_mod.render(), (
        "the description that gets written and the one that gets checked have "
        "drifted apart again"
    )


def test_check_mode_passes_on_clean_tree() -> None:
    module = _load_module()
    # Precondition: run --write so the tree is aligned.
    module.main(["--write"])
    rc = module.main(["--check"])
    assert rc == 0


def test_pre_commit_rev_pin_matches_version() -> None:
    """README pre-commit example must use the live pyproject version."""
    module = _load_module()
    version = module._read_version()
    target_rev = f"v{version}"
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    matches = re.findall(
        r"repo:\s*https://github\.com/sattyamjjain/agent-audit-kit\s*\n\s*rev:\s*(v\d+\.\d+\.\d+)",
        readme,
    )
    assert matches, "README must contain at least one pre-commit rev pin"
    for rev in matches:
        assert rev == target_rev, (
            f"README pre-commit rev pin {rev!r} drifts from "
            f"pyproject {target_rev!r}. "
            "Run `python scripts/sync_repo_metadata.py --write`."
        )


def test_history_files_are_not_rewritten() -> None:
    # release-notes-vX.Y.Z.md should be left alone even though it
    # contains a pin, because it documents the release that shipped at
    # that version.
    module = _load_module()
    hist_files = list((REPO_ROOT / "docs" / "launch").glob("release-notes-v*.md"))
    if not hist_files:
        pytest.skip("no release-notes-vX.Y.Z.md to guard")
    iter_docs = module._iter_docs()
    for hist in hist_files:
        assert hist not in iter_docs


# ---------------------------------------------------------------------------
# scripts/sync_scanner_count.py — README "<!-- scanner-count -->" anchor
# must match the actual filesystem detector count. Mirrors the
# rule-count guard above; added in v0.3.11 after the README's "28
# scanner modules" prose drifted past 50 detectors.
# ---------------------------------------------------------------------------


def _load_scanner_sync():
    spec = importlib.util.spec_from_file_location(
        "sync_scanner_count",
        REPO_ROOT / "scripts" / "sync_scanner_count.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["sync_scanner_count"] = module
    spec.loader.exec_module(module)
    return module


def test_scanner_count_matches_filesystem() -> None:
    """README anchor + SCANNER_COUNT constant must equal the real
    filesystem count of detector modules in agent_audit_kit/scanners/."""
    sync = _load_scanner_sync()
    actual = sync.count_scanners()
    assert actual > 0

    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    anchor_match = re.search(
        r"<!--\s*scanner-count:total\s*-->(\d+)<!--\s*/scanner-count\s*-->",
        readme,
    )
    assert anchor_match, (
        "README is missing the <!-- scanner-count:total -->NN<!-- /scanner-count --> anchor. "
        "Run `python scripts/sync_scanner_count.py` and commit the result."
    )
    assert int(anchor_match.group(1)) == actual, (
        f"README scanner-count anchor reports {anchor_match.group(1)}, "
        f"filesystem has {actual} detector(s). "
        "Run `python scripts/sync_scanner_count.py` and commit."
    )

    from agent_audit_kit import SCANNER_COUNT
    assert SCANNER_COUNT == actual, (
        f"agent_audit_kit.SCANNER_COUNT = {SCANNER_COUNT}, "
        f"filesystem has {actual}. "
        "Run `python scripts/sync_scanner_count.py` and commit."
    )


def test_scanner_count_check_mode_passes_on_clean_tree() -> None:
    sync = _load_scanner_sync()
    # First write to align, then --check should pass.
    rc = sync.main([])
    assert rc == 0
    rc = sync.main(["--check"])
    assert rc == 0


# ---------------------------------------------------------------------------
# v0.3.23 per-category anchor regression (#README sync drift fix)
# The "What It Scans" table was undercount by 81 rules at v0.3.22 ship
# time because each category cell was bare text, not an anchor. As of
# v0.3.23 every cell carries a `<!-- category-count:CATEGORY_NAME -->`
# anchor that `sync_rule_count.py` rewrites in lockstep with the registry.
# ---------------------------------------------------------------------------


def test_readme_per_category_anchors_match_registry() -> None:
    """Every `<!-- category-count:NAME -->` anchor in README must match
    the live `len([r for r in RULES if r.category.name == NAME])`."""
    from collections import Counter
    from agent_audit_kit.rules.builtin import RULES

    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    # `[A-Z0-9_]+` — digits are load-bearing so `A2A_PROTOCOL` is matched.
    pattern = re.compile(
        r"<!--\s*category-count:([A-Z0-9_]+)\s*-->(\d+)<!--\s*/category-count\s*-->",
    )
    matches = pattern.findall(readme)
    assert matches, (
        "README has no `<!-- category-count:NAME -->NN<!-- /category-count -->` "
        "anchors. Run `python scripts/sync_rule_count.py` after re-adding the "
        '"What It Scans" table or accept the v0.3.23 schema.'
    )
    live_counts = Counter(r.category.name for r in RULES.values())
    for cat_name, claimed_str in matches:
        claimed = int(claimed_str)
        actual = live_counts.get(cat_name, 0)
        assert claimed == actual, (
            f"README category-count anchor for `{cat_name}` reports "
            f"{claimed}, registry has {actual}. "
            "Run `python scripts/sync_rule_count.py` and commit."
        )
    # Completeness: every category the registry knows about is anchored somewhere,
    # and the anchored categories account for the whole registry.
    #
    # This used to sum every anchor occurrence and compare that to RULE_COUNT, which
    # only worked while each category appeared exactly once. It does not any more:
    # the comparison table's "A2A protocol scanning | 13 rules" row was hand-written
    # and unguarded, and anchoring it put a second A2A_PROTOCOL anchor in the file.
    # Summing occurrences read that as 13 extra rules. Counting distinct categories
    # asserts the property that was actually intended — no category is missing — and
    # says so directly rather than inferring it from an arithmetic coincidence.
    anchored = {name: int(value) for name, value in matches}
    missing = sorted(set(live_counts) - set(anchored))
    assert not missing, (
        f"README anchors no count for categor(y/ies) {missing}; the What It Scans "
        "table is incomplete. Run `python scripts/sync_rule_count.py`."
    )
    anchor_sum = sum(anchored.values())
    assert anchor_sum == sum(live_counts.values()), (
        f"Per-category anchors sum to {anchor_sum} but live registry has "
        f"{sum(live_counts.values())}. Run `python scripts/sync_rule_count.py`."
    )

    # A category stated in two places must state the same number in both. The
    # per-anchor loop above already compares each to the registry, so this only
    # fails if that loop is ever relaxed — cheap insurance on a file where the
    # same figure now genuinely appears twice.
    from collections import defaultdict

    seen: dict[str, set[str]] = defaultdict(set)
    for name, value in matches:
        seen[name].add(value)
    disagreeing = {k: sorted(v) for k, v in seen.items() if len(v) > 1}
    assert not disagreeing, (
        f"README states two different counts for the same categor(y/ies): {disagreeing}"
    )


# ---------------------------------------------------------------------------
# Dated artifacts keep the version they documented
# ---------------------------------------------------------------------------


def test_frozen_docs_are_excluded_from_the_version_rewrite() -> None:
    """The module docstring's principle, implemented for more than one filename.

    `sync_repo_metadata.py` has always said historical artifacts "should pin the
    version they documented", but enforced it only for `release-notes-v*.md`. So
    every release silently rewrote `@vX.Y.Z` inside dated launch collateral and
    preset docs — editing a published social thread to quote a version it never
    quoted. `scripts/check_counts.py` already treats those same paths as frozen,
    so the two guards disagreed about what "frozen" meant.
    """
    from pathlib import Path

    from scripts.sync_repo_metadata import _is_frozen, _iter_docs

    frozen = [
        Path("docs/launch/x-thread.md"),
        Path("docs/launch/release-notes-v0.3.1.md"),
        Path("docs/presets/mcp-ox-2026-04.md"),
        Path("docs/changelog/archive/CHANGELOG.md"),
    ]
    for path in frozen:
        assert _is_frozen(path), f"{path} must keep the version it documented"

    live = [
        Path("docs/ci-cd.md"),
        Path("docs/getting-started.md"),
        Path("docs/index.md"),
    ]
    for path in live:
        assert not _is_frozen(path), f"{path} is live docs and must track the release"

    # And the selector actually applies it, rather than the predicate being unused.
    selected = {p.as_posix() for p in _iter_docs()}
    assert not any("docs/launch/" in p for p in selected)
    assert not any("docs/presets/" in p for p in selected)
