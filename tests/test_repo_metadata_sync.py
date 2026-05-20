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


def test_description_string_includes_version_and_rule_count() -> None:
    module = _load_module()
    desc = module._description_string()
    version = module._read_version()
    rule_count = module._read_rule_count()
    assert version in desc
    assert str(rule_count) in desc
    assert "AgentAuditKit" in desc


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
    # Sum of per-category anchors must match the total RULE_COUNT.
    anchor_sum = sum(int(c) for _, c in matches)
    assert anchor_sum == sum(live_counts.values()), (
        f"Per-category anchors sum to {anchor_sum} but live registry has "
        f"{sum(live_counts.values())}. Run `python scripts/sync_rule_count.py`."
    )
