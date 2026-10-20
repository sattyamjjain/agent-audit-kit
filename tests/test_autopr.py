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
# A file git ignores is in no commit, so no PR carries its fix
# --------------------------------------------------------------------------


def _isolate_git(tmp_path: Path, monkeypatch) -> None:
    """The operator's global and system git config can ignore `.claude/settings.local.json`
    on their own; here only the repository's .gitignore decides."""
    home = tmp_path / "home"
    home.mkdir()
    (home / "gitconfig").write_text("", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / "xdg"))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / "gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


def _committed(root: Path, files: dict[str, str]) -> Path:
    """A repository holding ``files``, committed: those its .gitignore names stay untracked."""
    for rel, body in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(body, encoding="utf-8")
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "t")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "init")
    return root.resolve()


def _ignored_status(repo: Path) -> list[str]:
    return subprocess.run(
        ["git", "status", "--porcelain", "--ignored"], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.splitlines()


_LOCAL_SETTINGS = '{"enableAllProjectMcpServers": true}\n'
_IGNORED_SETTINGS = {
    "settings-ignored": ".claude/settings.local.json\n",
    "settings-and-log-ignored": ".claude/settings.local.json\n.agent-audit-kit/\n",
}
_HELD_BACK = (
    "refusing: git ignores .claude/settings.local.json, so a PR cannot carry the change. "
    "`aak fix` applies it in place."
)


@pytest.mark.skipif(sys.platform == "win32", reason="the gh stub is a POSIX shell script")
@pytest.mark.parametrize("case", list(_IGNORED_SETTINGS), ids=list(_IGNORED_SETTINGS))
def test_auto_pr_refuses_a_fix_whose_file_git_ignores(tmp_path: Path, monkeypatch, case: str) -> None:
    """Most repositories ignore `.claude/settings.local.json`. Its TRUST-001 fix counted,
    the live run rewrote it, and git, seeing no change, had the guard say the tree was as
    it was: the file stayed rewritten, and the fix log that recorded it was deleted, or,
    with `.agent-audit-kit/` ignored too, left behind. The plan refuses it now, so the
    file is never written."""
    _isolate_git(tmp_path, monkeypatch)
    repo, _, remote, sarif = _delivery(
        tmp_path, monkeypatch, {".gitignore": _IGNORED_SETTINGS[case], ".claude/settings.local.json": _LOCAL_SETTINGS}, {}
    )
    settings = repo / ".claude/settings.local.json"
    base, status = _branches(repo), _ignored_status(repo)
    held_back = f"  - AAK-TRUST-001  {settings}  (git ignores it)"

    dry = _suggest(sarif, repo, "--dry-run")

    assert dry.exit_code == 0, dry.output
    assert held_back in dry.output.splitlines()
    assert "suggest: would refuse a draft PR on branch '-' with 0 fix(es)." in dry.output.splitlines()

    real = _suggest(sarif, repo)

    assert real.exit_code == 2, real.output
    assert held_back in real.output.splitlines()
    assert real.output.splitlines()[-1] == f"suggest --auto-pr: {_HELD_BACK}"
    assert settings.read_text(encoding="utf-8") == _LOCAL_SETTINGS
    assert not (repo / ".agent-audit-kit").exists(), "no fix log was written, or left"
    assert not (tmp_path / "gh-calls.txt").exists()
    assert (_branches(repo), _branches(remote), _ignored_status(repo)) == (base, [], status)


def test_a_tracked_file_a_pattern_matches_is_not_ignored(tmp_path: Path, monkeypatch) -> None:
    """git ignores only untracked files: a tracked one that a pattern matches is in every
    commit, and its fix goes in the PR like any other."""
    _isolate_git(tmp_path, monkeypatch)
    repo = _committed(tmp_path / "repo", {".gitignore": "requirements*.txt\n", "requirements.txt": "litellm==1.80.0\n"})
    _git(repo, "add", "-f", "requirements.txt")
    _git(repo, "commit", "-qm", "track it")

    plan = plan_auto_pr(repo)

    assert ([f.rule_id for f in plan.fixes], plan.blocked, plan.ignored) == ([_LITELLM], [], {})
    assert plan.is_runnable


@pytest.mark.skipif(sys.platform == "win32", reason="needs a directory symlink")
def test_a_file_reached_through_a_link_is_asked_about_where_the_fix_writes(tmp_path: Path, monkeypatch) -> None:
    """`aak fix` follows a link to a directory inside the project, and git reads no path
    past a link, so git is asked about the file the fix would write."""
    _isolate_git(tmp_path, monkeypatch)
    root = tmp_path / "repo"
    (root / "conf").mkdir(parents=True)
    (root / ".claude").symlink_to("conf/claude", target_is_directory=True)
    repo = _committed(root, {".gitignore": "conf/claude/\n", "conf/claude/settings.local.json": _LOCAL_SETTINGS})

    plan = plan_auto_pr(repo)

    assert [f.rule_id for f in plan.blocked] == ["AAK-TRUST-001"] and plan.fixes == []
    assert plan.ignored == {str(repo / ".claude/settings.local.json"): "conf/claude/settings.local.json"}
    assert plan.refusal == _HELD_BACK.replace(".claude/settings.local.json", "conf/claude/settings.local.json")


def test_a_held_back_fix_refuses_a_mixed_plan_before_touching_git(tmp_path: Path, monkeypatch) -> None:
    """The live run applies every auto-fixable fix, so one on a file git ignores refuses
    the whole PR, as a rule off the allow-list does, rather than write it outside one."""
    _isolate_git(tmp_path, monkeypatch)
    repo = _committed(tmp_path / "repo", {".gitignore": "local.json\n", "local.json": "{}\n", "requirements.txt": "x\n"})
    ignored = FixAction("AAK-TRUST-001", str(repo / "local.json"), "Set enableAllProjectMcpServers to false", writes=True)
    bump = FixAction(_LITELLM, str(repo / "requirements.txt"), "Bumped 1 litellm pin(s) to >=1.83.7", writes=True)
    monkeypatch.setattr("agent_audit_kit.autopr.run_fixes", lambda root, dry_run=False: [ignored, bump])
    base = _branches(repo)

    plan = plan_auto_pr(repo)

    assert (plan.fixes, plan.blocked, plan.ignored) == ([bump], [ignored], {ignored.file_path: "local.json"})
    assert (plan.blocked_reason(ignored), plan.is_runnable) == ("git ignores it", False)
    with pytest.raises(AutoPrError) as raised:
        open_auto_pr(repo, plan)
    assert str(raised.value) == _HELD_BACK.replace(".claude/settings.local.json", "local.json")
    assert _branches(repo) == base


def test_a_plan_git_cannot_answer_for_is_refused(tmp_path: Path, monkeypatch) -> None:
    """Inside a work tree, `git check-ignore` fails on a path in a submodule; a plan that
    cannot tell whether a PR would carry its fixes is not one to push."""
    _isolate_git(tmp_path, monkeypatch)
    repo = _committed(tmp_path / "repo", {"requirements.txt": "litellm==1.80.0\n"})
    real_run = subprocess.run

    def check_ignore_fails(args, *rest, **kwargs):
        if list(args[:2]) == ["git", "check-ignore"]:
            return subprocess.CompletedProcess(args, 128, "", "fatal: Pathspec 'requirements.txt' is in submodule 'x'\n")
        return real_run(args, *rest, **kwargs)

    monkeypatch.setattr("agent_audit_kit.autopr.subprocess.run", check_ignore_fails)
    sarif = tmp_path / "empty.sarif"
    sarif.write_text(json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8")

    dry = _suggest(sarif, repo, "--dry-run")

    assert dry.exit_code == 2, dry.output
    assert dry.output.splitlines()[-1] == (
        "suggest --auto-pr: git could not say whether it ignores the files these fixes write: "
        "`git check-ignore` failed (128): fatal: Pathspec 'requirements.txt' is in submodule 'x'"
    )
    assert (repo / "requirements.txt").read_text(encoding="utf-8") == "litellm==1.80.0\n"


_REWRITTEN = '{"rewritten": true}\n'
_LEFT_BEHIND = {
    # .gitignore, files committed or left untracked before the run, what the run writes,
    # files the plan's unchanged actions name, the message's end.
    "log-created-in-an-ignored-dir": (".agent-audit-kit/\n", {}, {}, [], "and git shows no change."),
    "ignored-log-rewritten": (
        ".agent-audit-kit/\n", {".agent-audit-kit/fix-log.json": "old\n"}, {}, [],
        "but these files git ignores are not as they were: .agent-audit-kit/fix-log.json.",
    ),
    "tracked-log-rewritten": ("", {".agent-audit-kit/fix-log.json": "old\n"}, {}, [], "and git shows no change."),
    "ignored-file-created": (
        "cache/\n", {}, {"cache/blob": "x\n"}, [], "but these files git ignores are not as they were: cache/.",
    ),
    "unnamed-ignored-file-rewritten": (
        ".claude/settings.local.json\n", {".claude/settings.json": _LOCAL_SETTINGS, ".claude/settings.local.json": "{}\n"},
        {".claude/settings.local.json": _REWRITTEN}, [], "and git shows no change.",
    ),
    "named-ignored-file-rewritten": (
        ".claude/settings.local.json\n", {".claude/settings.json": _LOCAL_SETTINGS, ".claude/settings.local.json": "{}\n"},
        {".claude/settings.local.json": _REWRITTEN}, [".claude/settings.local.json"],
        "but these files git ignores are not as they were: .claude/settings.local.json.",
    ),
}


@pytest.mark.parametrize("case", list(_LEFT_BEHIND), ids=list(_LEFT_BEHIND))
def test_the_guard_names_what_it_could_not_put_back(tmp_path: Path, monkeypatch, case: str) -> None:
    """The guard put back what git tracks and removed the fix log only where git did not
    ignore it, then said the tree was as it was. A log the run created goes now, ignored
    or not, with the directory it made for it. The fix log and every file the plan's
    actions name are hashed before the run, and one whose bytes it changed is named, as
    is anything new git lists as ignored. A recipe that rewrites an ignored file no action
    names leaves git nothing to see, so the guard says git shows no change, never that
    the tree is as it was."""
    gitignore, before, written, named, ending = _LEFT_BEHIND[case]
    _isolate_git(tmp_path, monkeypatch)
    repo = _committed(tmp_path / "repo", {"README.md": "x\n", ".gitignore": gitignore, **before})
    claimed = FixAction(_LITELLM, str(repo / "requirements.txt"), "Bumped 1 litellm pin(s)", True, writes=True)
    unchanged = [FixAction("AAK-TRUST-007", str(repo / rel), "Added empty enabledMcpjsonServers allowlist") for rel in named]

    def live_run(root: Path, dry_run: bool = False) -> list[FixAction]:
        (root / ".agent-audit-kit").mkdir(exist_ok=True)
        (root / ".agent-audit-kit" / "fix-log.json").write_text("new\n")
        for rel, body in written.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(body)
        return [claimed, *unchanged]

    monkeypatch.setattr("agent_audit_kit.autopr.run_fixes", live_run)
    base, status = _branches(repo), _ignored_status(repo)
    plan = AutoPrPlan(fixes=[claimed], unchanged=unchanged, branch="aak/autofix/x", title="t", body="b")

    with pytest.raises(AutoPrError) as raised:
        open_auto_pr(repo, plan)

    said = "the fixes changed no file besides the fix log; nothing was committed or pushed, "
    assert str(raised.value) == said + ending
    assert _branches(repo) == base
    for rel, body in written.items():
        assert (repo / rel).read_text() == body, "a file git ignores is named, not put back"
    if ending.startswith("and"):
        assert _ignored_status(repo) == status
        assert subprocess.run(["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True).stdout == ""
        if ".agent-audit-kit/fix-log.json" in before:
            assert (repo / ".agent-audit-kit" / "fix-log.json").read_text() == "old\n"
        else:
            assert not (repo / ".agent-audit-kit").exists()


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
