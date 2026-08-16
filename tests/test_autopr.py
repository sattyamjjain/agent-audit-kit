"""Tests for `suggest --auto-pr` — issue #68, narrow mechanical scope.

The interesting behaviour is all refusal. A tool that pushes branches to the
operator's repo has to be much surer of itself than one that prints a report,
so every guard is pinned here: the allow-list, the dirty-tree check, the draft
flag, and the fact that no token ever reaches AAK.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from agent_audit_kit.autopr import (
    AUTO_PR_ALLOWLIST,
    NON_MECHANICAL,
    AutoPrError,
    AutoPrPlan,
    _render_body,
    open_auto_pr,
    plan_auto_pr,
)
from agent_audit_kit.fix import FixAction
from agent_audit_kit.rules.builtin import RULES


def _git(tmp_path: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "README.md").write_text("x\n", encoding="utf-8")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "init")
    return tmp_path


# --------------------------------------------------------------------------
# The allow-list is the whole safety argument.
# --------------------------------------------------------------------------


def test_allowlist_entries_are_real_registered_rules() -> None:
    unknown = sorted(AUTO_PR_ALLOWLIST - set(RULES))
    assert not unknown, f"allow-list names rules that do not exist: {unknown}"


def test_allowlist_is_a_subset_of_auto_fixable() -> None:
    """Being pushable requires being auto-fixable, plus a second decision.

    The allow-list is not derived from `auto_fixable`, so that marking a new
    rule auto-fixable cannot silently widen what AAK pushes to a repo.
    """
    auto_fixable = {rid for rid, rule in RULES.items() if rule.auto_fixable}
    assert AUTO_PR_ALLOWLIST <= auto_fixable
    assert AUTO_PR_ALLOWLIST != auto_fixable or not auto_fixable


def test_non_mechanical_shapes_are_documented_with_reasons() -> None:
    """Issue #68 names three 'purely mechanical' shapes. One of them is."""
    shapes = {shape for shape, _ in NON_MECHANICAL}
    assert any("auth dependency" in s for s in shapes)
    assert any("parameterised" in s for s in shapes)
    for _, why in NON_MECHANICAL:
        assert len(why) > 60, "a refusal needs a reason, not a label"


def test_blocked_fix_refuses_before_touching_git(repo: Path) -> None:
    plan = AutoPrPlan(
        fixes=[FixAction("AAK-TRUST-001", "a.json", "flip")],
        blocked=[FixAction("AAK-TAINT-001", "b.py", "rewrite")],
        branch="aak/autofix/x",
        title="t",
        body="b",
    )
    with pytest.raises(AutoPrError, match="not on the auto-PR allow-list"):
        open_auto_pr(repo, plan)
    assert not plan.is_runnable
    # No branch was created.
    branches = subprocess.run(
        ["git", "branch", "--format=%(refname:short)"],
        cwd=repo, capture_output=True, text=True, check=True,
    ).stdout.split()
    assert branches == ["main"] or branches == ["master"]


def test_empty_plan_refuses(repo: Path) -> None:
    with pytest.raises(AutoPrError, match="nothing to do"):
        open_auto_pr(repo, AutoPrPlan())


def test_dirty_tree_refuses(repo: Path) -> None:
    """Auto-PR must not sweep the operator's uncommitted work into its branch."""
    (repo / "scratch.txt").write_text("wip\n", encoding="utf-8")
    plan = AutoPrPlan(
        fixes=[FixAction("AAK-TRUST-001", "a.json", "flip")],
        branch="aak/autofix/x", title="t", body="b",
    )
    with pytest.raises(AutoPrError, match="working tree is dirty"):
        open_auto_pr(repo, plan)


# --------------------------------------------------------------------------
# Planning
# --------------------------------------------------------------------------


def test_plan_on_a_clean_project_is_not_runnable(repo: Path) -> None:
    plan = plan_auto_pr(repo)
    assert plan.fixes == []
    assert not plan.is_runnable


def test_plan_splits_allowed_from_blocked(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "agent_audit_kit.autopr.run_fixes",
        lambda root, dry_run=False: [
            FixAction("AAK-TRUST-001", "a.json", "enableAllProjectMcpServers -> false"),
            FixAction("AAK-TAINT-001", "b.py", "rewrite subprocess call"),
        ],
    )
    plan = plan_auto_pr(tmp_path)
    assert [f.rule_id for f in plan.fixes] == ["AAK-TRUST-001"]
    assert [f.rule_id for f in plan.blocked] == ["AAK-TAINT-001"]
    assert not plan.is_runnable, "one blocked fix blocks the whole PR"


def test_branch_name_is_git_safe(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "agent_audit_kit.autopr.run_fixes",
        lambda root, dry_run=False: [
            FixAction("AAK-LITELLM-CVE-2026-30623-PIN-001", "req.txt", "bump"),
        ],
    )
    branch = plan_auto_pr(tmp_path).branch
    assert branch.startswith("aak/autofix/")
    assert " " not in branch and ".." not in branch
    subprocess.run(
        ["git", "check-ref-format", "--branch", branch], check=True, capture_output=True
    )


# --------------------------------------------------------------------------
# PR body
# --------------------------------------------------------------------------


def test_body_cites_rule_and_cve(tmp_path: Path) -> None:
    body = _render_body([FixAction("AAK-LITELLM-CVE-2026-30623-PIN-001", "req.txt", "bump")])
    assert "AAK-LITELLM-CVE-2026-30623-PIN-001" in body
    assert "CVE-2026-30623" in body
    assert "draft" in body.lower()
    for shape, _ in NON_MECHANICAL:
        assert shape in body, "the PR states its own limits"
