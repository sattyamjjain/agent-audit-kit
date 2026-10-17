"""Tests for `suggest --auto-pr` — issue #68, narrow mechanical scope.

The interesting behaviour is all refusal. A tool that pushes branches to the
operator's repo has to be much surer of itself than one that prints a report,
so every guard is pinned here: the allow-list, the dirty-tree check, the draft
flag, and the fact that no token ever reaches AAK.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner, Result

from agent_audit_kit.autopr import (
    AUTO_PR_ALLOWLIST,
    NON_MECHANICAL,
    AutoPrError,
    AutoPrPlan,
    _render_body,
    open_auto_pr,
    plan_auto_pr,
)
from agent_audit_kit.cli import cli
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
            FixAction("AAK-TRUST-001", "a.json", "enableAllProjectMcpServers -> false", writes=True),
            FixAction("AAK-TAINT-001", "b.py", "rewrite subprocess call", writes=True),
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
            FixAction("AAK-LITELLM-CVE-2026-30623-PIN-001", "req.txt", "bump", writes=True),
        ],
    )
    branch = plan_auto_pr(tmp_path).branch
    assert branch.startswith("aak/autofix/")
    assert " " not in branch and ".." not in branch
    subprocess.run(
        ["git", "check-ref-format", "--branch", branch], check=True, capture_output=True
    )


_LITELLM = "AAK-LITELLM-CVE-2026-30623-PIN-001"
_REFUSED = FixAction("AAK-TRUST-001", ".claude/settings.json", "Failed to fix: .claude/settings.json is a symlink")
_NOT_REWRITTEN = FixAction(
    _LITELLM, "pyproject.toml",
    "pyproject.toml is not a supported manifest for auto-bump (only requirements*.txt is line-safe to rewrite)",
)


def test_a_plan_whose_allow_listed_fixes_write_nothing_refuses(tmp_path: Path, monkeypatch) -> None:
    """The plan comes from a dry run, where every action reads as not applied, a fix the
    recipe would write and a file it refused alike. A plan of refusals counted them as
    fixes and opened a draft PR whose commit held only the fix log."""
    monkeypatch.setattr("agent_audit_kit.autopr.run_fixes", lambda root, dry_run=False: [_REFUSED, _NOT_REWRITTEN])

    plan = plan_auto_pr(tmp_path)

    assert plan.fixes == [] and plan.unchanged == [_REFUSED, _NOT_REWRITTEN]
    assert not plan.is_runnable
    assert (plan.branch, plan.title, plan.body) == ("", "", "")
    with pytest.raises(AutoPrError, match=r"^nothing to do: no allow-listed fix would change a file here\.$"):
        open_auto_pr(tmp_path, plan)


def test_a_mixed_plan_pushes_only_the_fix_that_writes(tmp_path: Path, monkeypatch) -> None:
    """The refused file was listed in the PR body as changed, and named in its branch
    and title; it is left out of all three now."""
    bump = FixAction(_LITELLM, "requirements.txt", "Bumped 1 litellm pin(s) to >=1.83.7", writes=True)
    monkeypatch.setattr("agent_audit_kit.autopr.run_fixes", lambda root, dry_run=False: [_REFUSED, bump])

    plan = plan_auto_pr(tmp_path)

    assert (plan.fixes, plan.unchanged, plan.blocked) == ([bump], [_REFUSED], [])
    assert plan.is_runnable
    assert plan.branch == "aak/autofix/aak-litellm-cve-2026-30623-pin-001"
    assert plan.title == f"fix({_LITELLM}): mechanical remediation"
    assert "AAK-TRUST-001" not in plan.body


def test_a_live_run_that_changes_nothing_but_the_fix_log_commits_nothing(repo: Path, monkeypatch) -> None:
    """A recipe that says it writes but changes nothing would still have pushed a branch
    whose commit held only the fix log. Before `git add`, the live run's changes are
    listed; nothing besides the fix log puts the tree back and raises."""
    claimed = FixAction(_LITELLM, str(repo / "requirements.txt"), "Bumped 1 litellm pin(s)", True, writes=True)

    def live_run(root: Path, dry_run: bool = False) -> list[FixAction]:
        (root / ".agent-audit-kit").mkdir(exist_ok=True)
        (root / ".agent-audit-kit" / "fix-log.json").write_text("{}\n")
        return [claimed]

    monkeypatch.setattr("agent_audit_kit.autopr.run_fixes", live_run)
    base = _branches(repo)
    plan = AutoPrPlan(fixes=[claimed], branch="aak/autofix/x", title="t", body="b")

    with pytest.raises(AutoPrError, match=r"changed no file besides the fix log; nothing was committed"):
        open_auto_pr(repo, plan)

    assert _branches(repo) == base
    assert subprocess.run(["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True).stdout == ""


def test_a_rule_off_the_allow_list_blocks_the_pr_even_when_its_fix_writes_nothing(
    tmp_path: Path, monkeypatch
) -> None:
    """Kept as it was: `open_auto_pr` applies every auto-fixable fix, so anything off the
    allow-list refuses the whole PR, and a refused one is not trusted to stay refused."""
    gitignore = FixAction("AAK-SECRET-006", ".gitignore", "Failed to fix: .gitignore is a symlink")
    bump = FixAction(_LITELLM, "requirements.txt", "Bumped 1 litellm pin(s) to >=1.83.7", writes=True)
    monkeypatch.setattr("agent_audit_kit.autopr.run_fixes", lambda root, dry_run=False: [gitignore, bump])

    plan = plan_auto_pr(tmp_path)

    assert plan.blocked == [gitignore] and not plan.is_runnable
    with pytest.raises(AutoPrError, match="AAK-SECRET-006 is not on the auto-PR allow-list"):
        open_auto_pr(tmp_path, plan)


# --------------------------------------------------------------------------
# End to end: a local remote, and `gh` stubbed
# --------------------------------------------------------------------------


def _delivery(
    tmp_path: Path, monkeypatch, files: dict[str, str], links: dict[str, str]
) -> tuple[Path, Path, Path, Path]:
    """A committed repository with a local bare remote, and a `gh` stub first on PATH that
    records its arguments one per line and prints a PR URL, so `suggest --auto-pr` runs
    end to end without GitHub. A file named `@outside/...` goes in a directory outside
    the repository, where ``links`` point."""
    repo, outside, remote, stub = (tmp_path / name for name in ("repo", "outside", "remote.git", "bin"))
    for directory in (repo, outside, stub):
        directory.mkdir()
    for rel, body in files.items():
        dest = outside / rel[len("@outside/"):] if rel.startswith("@outside/") else repo / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(body, encoding="utf-8")
    for rel, target in links.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).symlink_to(outside / target)
    _git(tmp_path, "init", "-q", "--bare", str(remote))
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "init")
    _git(repo, "remote", "add", "origin", str(remote))
    calls = tmp_path / "gh-calls.txt"
    gh = stub / "gh"
    gh.write_text(
        f"#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{calls}'\necho https://github.com/example/repo/pull/1\n",
        encoding="utf-8",
    )
    gh.chmod(0o755)
    monkeypatch.setenv("PATH", f"{stub}{os.pathsep}{os.environ['PATH']}")
    sarif = tmp_path / "empty.sarif"
    sarif.write_text(json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8")
    return repo.resolve(), outside, remote, sarif


def _suggest(sarif: Path, repo: Path, *extra: str) -> Result:
    return CliRunner().invoke(cli, ["suggest", str(sarif), "--auto-pr", "--project", str(repo), *extra])


def _branches(git_dir: Path) -> list[str]:
    return subprocess.run(
        ["git", "branch", "--format=%(refname:short)"], cwd=git_dir, capture_output=True, text=True, check=True
    ).stdout.split()


_SETTINGS_LINK = ({"@outside/settings.json": '{"enableAllProjectMcpServers": true}\n'}, {".claude/settings.json": "settings.json"})
_WRITES_NOTHING = {
    "refused": (*_SETTINGS_LINK, "AAK-TRUST-001", ".claude/settings.json", _REFUSED.description),
    "already-set": (
        {
            ".claude/settings.json": '{"enabledMcpjsonServers": []}\n',
            ".mcp.json": '{"mcpServers": {"s": {"command": "node", "args": ["server.js"]}}}\n',
        },
        {}, "AAK-TRUST-007", ".claude/settings.json", "Added empty enabledMcpjsonServers allowlist",
    ),
    "not-rewritten": (
        {"pyproject.toml": '[project]\nname = "x"\nversion = "0.1.0"\ndependencies = ["litellm==1.80.0"]\n'},
        {}, _LITELLM, "pyproject.toml", _NOT_REWRITTEN.description,
    ),
    "rewritten-as-it-was": (
        {"requirements.txt": 'litellm>=1.83.7; python_version >= "3.10"\nlitellm[proxy]==1.50.0; python_version < "3.10"\n'},
        {}, _LITELLM, "requirements.txt", "Nothing in requirements.txt this recipe can rewrite",
    ),
}


@pytest.mark.skipif(sys.platform == "win32", reason="the gh stub is a POSIX shell script")
@pytest.mark.parametrize("case", list(_WRITES_NOTHING), ids=list(_WRITES_NOTHING))
def test_auto_pr_refuses_when_no_allow_listed_fix_writes(tmp_path: Path, monkeypatch, case: str) -> None:
    """Each of these opened a draft PR whose commit held only `.agent-audit-kit/fix-log.json`:
    a settings file linked out of the project, which the recipe refuses; an
    `enabledMcpjsonServers: []`, which AAK-TRUST-007 reports and the recipe leaves as it
    is; and litellm pinned in pyproject.toml, which the bump does not rewrite."""
    files, links, rule_id, rel, said = _WRITES_NOTHING[case]
    repo, outside, remote, sarif = _delivery(tmp_path, monkeypatch, files, links)
    base = _branches(repo)
    unchanged = f"  = {rule_id}  {repo / rel}  (changes nothing: {said})"

    dry = _suggest(sarif, repo, "--dry-run")

    assert dry.exit_code == 0, dry.output
    assert unchanged in dry.output.splitlines()
    assert "suggest: would refuse a draft PR on branch '-' with 0 fix(es)." in dry.output.splitlines()

    real = _suggest(sarif, repo)

    assert real.exit_code == 2, real.output
    assert unchanged in real.output.splitlines()
    assert real.output.splitlines()[-1] == "suggest --auto-pr: nothing to do: no allow-listed fix would change a file here."
    assert not (tmp_path / "gh-calls.txt").exists(), "gh was never asked to open a PR"
    assert (_branches(repo), _branches(remote)) == (base, [])
    assert subprocess.run(["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True).stdout == ""
    if links:
        assert (outside / "settings.json").read_text() == files["@outside/settings.json"]


@pytest.mark.skipif(sys.platform == "win32", reason="the gh stub is a POSIX shell script")
def test_auto_pr_opens_a_pr_with_only_the_fixes_that_write(tmp_path: Path, monkeypatch) -> None:
    files, links = _SETTINGS_LINK
    repo, outside, remote, sarif = _delivery(
        tmp_path, monkeypatch, {**files, "requirements.txt": "litellm==1.80.0\n"}, links
    )
    branch = "aak/autofix/aak-litellm-cve-2026-30623-pin-001"

    dry = _suggest(sarif, repo, "--dry-run")

    assert dry.exit_code == 0, dry.output
    assert dry.output.splitlines()[-3:] == [
        f"  + {_LITELLM}  {repo / 'requirements.txt'}",
        f"  = AAK-TRUST-001  {repo / '.claude/settings.json'}  (changes nothing: {_REFUSED.description})",
        f"suggest: would open a draft PR on branch '{branch}' with 1 fix(es).",
    ]

    real = _suggest(sarif, repo)

    assert real.exit_code == 0, real.output
    assert real.output.splitlines()[-1] == "suggest: opened draft PR https://github.com/example/repo/pull/1"
    gh_args = (tmp_path / "gh-calls.txt").read_text(encoding="utf-8")
    assert f"--title\nfix({_LITELLM}): mechanical remediation\n" in gh_args
    assert "AAK-TRUST-001" not in gh_args
    assert _branches(remote) == [branch]
    pushed = subprocess.run(
        ["git", "show", "--name-only", "--format=", branch], cwd=remote, capture_output=True, text=True, check=True
    ).stdout.split()
    assert pushed == [".agent-audit-kit/fix-log.json", "requirements.txt"]
    assert (outside / "settings.json").read_text() == files["@outside/settings.json"]


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
