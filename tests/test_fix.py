"""Tests for agent_audit_kit.fix module."""
from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import NamedTuple

import pytest
from unittest.mock import patch

import agent_audit_kit
from agent_audit_kit import fix as fix_module
from agent_audit_kit.fix import (
    FixAction,
    _apply_fix,
    _fix_enable_all_mcp,
    _fix_env_gitignore,
    _fix_litellm_version,
    _fix_missing_allowlist,
    _fix_missing_deny,
    _fix_secret_env_ref,
    _write_fix_log,
    _write_inside_project,
    run_fixes,
)
from agent_audit_kit.models import Category, Finding, ScanResult, Severity
from agent_audit_kit.rules.builtin import RULES, RuleDefinition
from agent_audit_kit.scanners import _dependency_pins


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _setup_fixable_scan(
    tmp_path: Path,
    rule_id: str,
    file_path: str,
    auto_fixable: bool = True,
) -> tuple[ScanResult, dict]:
    """Build a mock ScanResult and RULES dict for a single finding."""
    finding = Finding(
        rule_id=rule_id,
        title="Test",
        description="Test",
        severity=Severity.CRITICAL,
        category=Category.TRUST_BOUNDARY,
        file_path=file_path,
    )
    mock_rules = {
        rule_id: RuleDefinition(
            rule_id=rule_id,
            title="T",
            description="D",
            severity=Severity.CRITICAL,
            category=Category.TRUST_BOUNDARY,
            remediation="R",
            auto_fixable=auto_fixable,
        ),
    }
    return ScanResult(findings=[finding]), mock_rules


# ---------------------------------------------------------------------------
# _fix_enable_all_mcp
# ---------------------------------------------------------------------------


class TestFixEnableAllMcp:
    def test_sets_flag_to_false(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text(json.dumps({"enableAllProjectMcpServers": True}))

        fix = _fix_enable_all_mcp(cfg_file, tmp_path, dry_run=False)
        assert fix.applied is True
        assert fix.rule_id == "AAK-TRUST-001"

        data = json.loads(cfg_file.read_text())
        assert data["enableAllProjectMcpServers"] is False

    def test_dry_run_does_not_modify(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        original = json.dumps({"enableAllProjectMcpServers": True})
        cfg_file.write_text(original)

        fix = _fix_enable_all_mcp(cfg_file, tmp_path, dry_run=True)
        assert fix.applied is False
        assert cfg_file.read_text() == original

    def test_malformed_json_returns_failed_action(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text("{bad json}")

        fix = _fix_enable_all_mcp(cfg_file, tmp_path, dry_run=False)
        assert fix.applied is False
        assert "Failed" in fix.description


# ---------------------------------------------------------------------------
# _fix_env_gitignore
# ---------------------------------------------------------------------------


class TestFixEnvGitignore:
    def test_adds_env_to_gitignore(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_text("node_modules/\n")

        fix = _fix_env_gitignore(tmp_path, dry_run=False)
        assert fix.applied is True
        assert fix.rule_id == "AAK-SECRET-006"

        content = (tmp_path / ".gitignore").read_text()
        assert ".env" in content

    def test_creates_gitignore_if_missing(self, tmp_path: Path) -> None:
        fix = _fix_env_gitignore(tmp_path, dry_run=False)
        assert fix.applied is True
        assert (tmp_path / ".gitignore").exists()
        assert ".env" in (tmp_path / ".gitignore").read_text()

    def test_dry_run_does_not_create_gitignore(self, tmp_path: Path) -> None:
        fix = _fix_env_gitignore(tmp_path, dry_run=True)
        assert fix.applied is False

    def test_skips_if_env_already_in_gitignore(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_text(".env\nnode_modules/\n")
        original = (tmp_path / ".gitignore").read_text()

        fix = _fix_env_gitignore(tmp_path, dry_run=False)
        assert fix.applied is True
        assert (tmp_path / ".gitignore").read_text() == original


class TestFixEnvGitignoreAgreesWithTheRule:
    """`aak fix` judged coverage with a substring test after AAK-SECRET-006 stopped
    doing so: with `!.env.example`, `# .env` or `.envrc` in `.gitignore`, or `.env.local`
    beside a `.env` pattern, it reported the finding fixed and wrote nothing."""

    @pytest.mark.parametrize(
        "gitignore", ["!.env.example\n", "# .env\n", ".envrc\n", ".env\n", "  .env\n", "node_modules/\n"]
    )
    def test_run_fixes_leaves_no_env_file_unignored(self, tmp_path: Path, gitignore: str) -> None:
        from agent_audit_kit.scanners.secret_exposure import scan as secret_scan

        (tmp_path / ".env").write_text("A=1\n")
        (tmp_path / ".env.local").write_text("A=1\n")
        (tmp_path / ".gitignore").write_text(gitignore)
        assert [f for f in secret_scan(tmp_path)[0] if f.rule_id == "AAK-SECRET-006"]

        fixes = [f for f in run_fixes(tmp_path) if f.rule_id == "AAK-SECRET-006"]

        assert fixes and all(f.applied for f in fixes)
        assert [f for f in secret_scan(tmp_path)[0] if f.rule_id == "AAK-SECRET-006"] == []

    def test_a_template_the_gitignore_takes_back_stays_committable(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("A=1\n")
        (tmp_path / ".env.example").write_text("A=\n")
        (tmp_path / ".gitignore").write_text("!.env.example\n")

        run_fixes(tmp_path)

        from agent_audit_kit.scanners.secret_exposure import _gitignore_ignores, _gitignore_rules

        rules = _gitignore_rules((tmp_path / ".gitignore").read_text())
        assert _gitignore_ignores(rules, ".env")
        assert not _gitignore_ignores(rules, ".env.example")

    def test_a_gitignore_that_already_ignores_every_env_file_is_left_alone(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("A=1\n")
        (tmp_path / ".gitignore").write_text(".env*\n")

        fix = _fix_env_gitignore(tmp_path, dry_run=False)

        assert fix.applied is True
        assert (tmp_path / ".gitignore").read_text() == ".env*\n"

    def test_the_fix_appends_to_the_whole_gitignore_and_keeps_every_byte(self, tmp_path: Path) -> None:
        """The fix rewrote `.gitignore` from the scanner's read, bounded to 1,000,000 bytes
        and decoded with replacement, so a longer file lost its tail and a byte that is
        not UTF-8 came back as U+FFFD."""
        (tmp_path / ".env").write_text("A=1\n")
        (tmp_path / ".env.example").write_text("A=\n")
        original = b"# caf\xe9\n" + b"# filler line\n" * 80_000 + b"build/\n!.env.example\n"
        (tmp_path / ".gitignore").write_bytes(original)

        fix = _fix_env_gitignore(tmp_path, dry_run=False)

        assert fix.applied is True
        written = (tmp_path / ".gitignore").read_bytes()
        assert written == original + b"\n# Environment files\n.env\n.env.*\n!.env.example\n"

    @pytest.mark.parametrize(
        "original",
        [b"node_modules/\nsecret\\ \n", b"node_modules/\nsecret\t\n", b"node_modules/\nsecret\\ ", b"secret\t"],
    )
    def test_the_fix_leaves_the_last_line_as_it_was(self, tmp_path: Path, original: bytes) -> None:
        """`rstrip()` before appending turned `secret\\ ` into `secret\\` and `secret<tab>`
        into `secret`, which changes what git ignores. Only a missing newline is added."""
        (tmp_path / ".env").write_text("A=1\n")
        (tmp_path / ".gitignore").write_bytes(original)

        assert _fix_env_gitignore(tmp_path, dry_run=False).applied is True

        separator = b"\n" if original.endswith(b"\n") else b"\n\n"
        assert (tmp_path / ".gitignore").read_bytes() == original + separator + b"# Environment files\n.env\n.env.*\n"


# A child process runs the fix, so a write that blocks on a FIFO fails the test on its
# timeout instead of hanging the suite.
_CHILD = (
    "import sys\n"
    "from pathlib import Path\n"
    "from agent_audit_kit.fix import _fix_env_gitignore, _write_inside_project\n"
    "root = Path(sys.argv[1])\n"
    "if sys.argv[2] == 'fix':\n"
    "    print(_fix_env_gitignore(root, dry_run=False).description)\n"
    "else:\n"
    "    print(_write_inside_project(root / '.gitignore', b'x\\n', root, mode='append'))\n"
)


def _run_in_child(project: Path, what: str) -> str:
    package_root = Path(agent_audit_kit.__file__).resolve().parent.parent
    env = {**os.environ, "PYTHONPATH": str(package_root)}
    done = subprocess.run(
        [sys.executable, "-c", _CHILD, str(project), what], capture_output=True, text=True, timeout=30, env=env
    )
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


class TestFixEnvGitignoreWritesOnlyInsideTheProject:
    """A scanned repository controls its `.gitignore` and the env file names that make the
    fix run. Written through `Path.write_text`, a `.gitignore` linked to a file outside the
    project had the fix's lines appended to that file, a dangling link created it, and a
    FIFO named `.gitignore` blocked `aak fix` forever."""

    def _project(self, tmp_path: Path) -> Path:
        project = tmp_path / "proj"
        project.mkdir()
        (project / ".env").write_text("A=1\n")
        return project

    def test_a_symlinked_gitignore_is_refused_and_its_target_left_alone(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"do not touch\n")
        (project / ".gitignore").symlink_to(outside)

        fix = _fix_env_gitignore(project, dry_run=False)

        assert fix.applied is False and fix.description.startswith("Failed to fix: ")
        assert outside.read_bytes() == b"do not touch\n"

    def test_a_dangling_symlink_creates_nothing(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        target = tmp_path / "created-by-fix.txt"
        (project / ".gitignore").symlink_to(target)

        fix = _fix_env_gitignore(project, dry_run=False)

        assert fix.applied is False and fix.description.startswith("Failed to fix: ")
        assert not target.exists()

    def test_a_directory_named_gitignore_is_refused(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        (project / ".gitignore").mkdir()

        fix = _fix_env_gitignore(project, dry_run=False)

        assert fix.applied is False and fix.description.startswith("Failed to fix: ")

    def test_a_dry_run_reports_the_refusal_too(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        (project / ".gitignore").symlink_to(tmp_path / "elsewhere")

        assert _fix_env_gitignore(project, dry_run=True).description.startswith("Failed to fix: ")

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs POSIX FIFOs")
    def test_a_fifo_named_gitignore_is_refused_without_blocking(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        os.mkfifo(project / ".gitignore")

        assert _run_in_child(project, "fix").startswith("Failed to fix: ")


class TestWriteInsideProject:
    """The one write path `aak fix` should use: a regular file, or a missing one, whose path
    and directory resolve inside the project, opened without following a link. It returns
    None once written, or the reason it refused, and never raises for a refusal."""

    @pytest.mark.usefixtures("full_disk")
    def test_a_write_that_fails_after_the_open_says_the_file_may_be_partly_written(self, tmp_path: Path) -> None:
        """The open truncates the file before a byte goes in, so a write that fails part
        way leaves part of it. That is reported apart from a refusal or a failed open,
        which leave the file as it was, so a caller can say which happened."""
        target = tmp_path / "notes.txt"
        target.write_bytes(b"previous content\n")

        refused = _write_inside_project(target, b"a new and longer content\n", tmp_path)

        assert refused == "notes.txt could not be written (No space left on device) and may be partly written"
        assert isinstance(refused, fix_module._PartlyWritten)
        assert target.read_bytes() == b"a new and "
        assert not isinstance(_write_inside_project(tmp_path / "sub" / "x", b"", tmp_path), fix_module._PartlyWritten)

    def test_it_appends_replaces_and_creates(self, tmp_path: Path) -> None:
        target = tmp_path / "notes.txt"
        target.write_bytes(b"a\n")

        assert _write_inside_project(target, b"b\n", tmp_path, mode="append") is None
        assert target.read_bytes() == b"a\nb\n"
        assert _write_inside_project(target, b"c\n", tmp_path, mode="replace") is None
        assert target.read_bytes() == b"c\n"
        assert _write_inside_project(tmp_path / "new.txt", b"d\n", tmp_path, mode="append") is None
        assert (tmp_path / "new.txt").read_bytes() == b"d\n"

    def test_it_refuses_a_symlink_even_to_a_file_inside(self, tmp_path: Path) -> None:
        (tmp_path / "real.txt").write_bytes(b"keep\n")
        (tmp_path / "link.txt").symlink_to(tmp_path / "real.txt")

        reason = _write_inside_project(tmp_path / "link.txt", b"x\n", tmp_path, mode="replace")

        assert reason is not None and "symlink" in reason
        assert (tmp_path / "real.txt").read_bytes() == b"keep\n"

    def test_it_refuses_a_path_under_a_symlinked_directory(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (project / "sub").symlink_to(outside, target_is_directory=True)

        reason = _write_inside_project(project / "sub" / "settings.json", b"{}\n", project, mode="replace")

        assert reason is not None and "outside the project" in reason
        assert not (outside / "settings.json").exists()

    def test_it_refuses_a_path_outside_the_project(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        project.mkdir()

        reason = _write_inside_project(project / ".." / "escaped.txt", b"x\n", project, mode="replace")

        assert reason is not None and "outside the project" in reason
        assert not (tmp_path / "escaped.txt").exists()

    def test_it_refuses_a_directory(self, tmp_path: Path) -> None:
        (tmp_path / "folder").mkdir()

        reason = _write_inside_project(tmp_path / "folder", b"x\n", tmp_path, mode="append")

        assert reason is not None and "not a regular file" in reason

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs POSIX FIFOs")
    def test_it_refuses_a_fifo_without_blocking(self, tmp_path: Path) -> None:
        os.mkfifo(tmp_path / ".gitignore")

        assert "not a regular file" in _run_in_child(tmp_path, "helper")


# ---------------------------------------------------------------------------
# Every recipe writes only inside the project
# ---------------------------------------------------------------------------


class _Recipe(NamedTuple):
    """One write path of `aak fix`: the recipe in `agent_audit_kit.fix`, the file it
    edits, and what it wrote there through `Path.write_text`, which every recipe but the
    `.gitignore` and raised-pin ones used before moving onto `_write_inside_project`.
    `before` holds CRLF and lone-CR line ends and a non-ASCII character where the
    recipe reads them, so `after` pins the newline translation and the JSON escaping."""

    id: str
    rule_id: str
    func: str
    rel: str
    before: bytes
    after: bytes
    said: str  # its description, in a dry run and once applied
    unread: str  # what it says when a FIFO gets past the look before the read
    reader: tuple[ModuleType, str]  # the read the swap test wraps
    extra: tuple[tuple[str, bytes], ...] = ()


_SETTINGS = ".claude/settings.json"
_READ_TEXT = (fix_module, "_read_text")
_RAISED = (_dependency_pins, "_regular_bytes")
_RECIPES = [
    _Recipe(
        "trust-001", "AAK-TRUST-001", "_fix_enable_all_mcp", _SETTINGS,
        b'{\r\n  "enableAllProjectMcpServers": true,\r\n  "note": "caf\xc3\xa9"\r\n}\r\n',
        b'{\n  "enableAllProjectMcpServers": false,\n  "note": "caf\\u00e9"\n}\n',
        "Set enableAllProjectMcpServers to false", "False Failed to fix", _READ_TEXT,
    ),
    _Recipe(
        "trust-004", "AAK-TRUST-004", "_fix_missing_deny", _SETTINGS,
        b'{"permissions": {"allow": ["*"]}}',
        b'{\n  "permissions": {\n    "allow": [\n      "*"\n    ],\n    "deny": [\n'
        b'      "Bash(rm -rf *)",\n      "Bash(curl *)",\n      "Bash(wget *)"\n    ]\n  }\n}\n',
        "Added default deny rules", "False Failed to fix", _READ_TEXT,
    ),
    _Recipe(
        "trust-007", "AAK-TRUST-007", "_fix_missing_allowlist", _SETTINGS,
        b'{"other": "data"}',
        b'{\n  "other": "data",\n  "enabledMcpjsonServers": []\n}\n',
        "Added empty enabledMcpjsonServers allowlist", "False Failed to fix", _READ_TEXT,
    ),
    _Recipe(
        "secret-006", "AAK-SECRET-006", "_fix_env_gitignore", ".gitignore",
        b"node_modules/\n",
        b"node_modules/\n\n# Environment files\n.env\n.env.*\n",
        "Added .env patterns to .gitignore", "False Failed to fix", (fix_module, "_read_bytes"),
        ((".env", b"A=1\n"),),
    ),
    _Recipe(
        "secret-007", "AAK-SECRET-007", "_fix_secret_env_ref", ".mcp.json",
        b'{"mcpServers": {"a": {"command": "npx", "env": {"API_KEY": "literal-value"}}}}',
        b'{\n  "mcpServers": {\n    "a": {\n      "command": "npx",\n      "env": {\n'
        b'        "API_KEY": "${API_KEY}"\n      }\n    }\n  }\n}\n',
        "Replaced literal secret with an environment reference for: API_KEY (export the "
        "variable before starting the server, and rotate the exposed value)",
        "None", _READ_TEXT,
    ),
    _Recipe(
        "langchain-001", "AAK-LANGCHAIN-001", "_fix_raised_pin", "requirements.txt",
        b"langchain-core==1.2.21\n", b"langchain-core>=1.2.22\n",
        "Raised 1 langchain-core declaration(s) to >=1.2.22", "False Unable to read file", _RAISED,
    ),
    _Recipe(
        "langchain-003", "AAK-LANGCHAIN-003", "_fix_raised_pin", "requirements.txt",
        b"langchain-core==0.3.13\n", b"langchain-core>=0.3.14\n",
        "Raised 1 langchain-core declaration(s) to >=0.3.14", "False Unable to read file", _RAISED,
    ),
    _Recipe(
        "neo4j-001", "AAK-NEO4J-001", "_fix_raised_pin", "requirements.txt",
        b"mcp-neo4j-cypher==0.2.1\n", b"mcp-neo4j-cypher>=0.6.0\n",
        "Raised 1 mcp-neo4j-cypher declaration(s) to >=0.6.0", "False Unable to read file", _RAISED,
    ),
    _Recipe(
        "litellm", "AAK-LITELLM-CVE-2026-30623-PIN-001", "_fix_litellm_version", "requirements.txt",
        b"click\r\nlitellm==1.80.0\r\n", b"click\nlitellm>=1.83.7\n",
        "Bumped 1 litellm pin(s) to >=1.83.7", "False Unable to read file", _READ_TEXT,
    ),
    _Recipe(
        "flowise-npm", "AAK-FLOWISE-001", "_fix_dependency_floor", "package.json",
        b'{"dependencies": {"flowise": "3.1.0"}}',
        b'{\n  "dependencies": {\n    "flowise": ">=3.1.3"\n  }\n}\n',
        "Bumped 1 flowise dep(s) to >=3.1.3 (package.json)", "False Unable to read file", _READ_TEXT,
    ),
    _Recipe(
        "flowise-txt", "AAK-FLOWISE-001", "_fix_dependency_floor", "requirements.txt",
        b"flowise==3.1.0\r\n", b"flowise>=3.1.3\n",
        "Bumped 1 flowise pin(s) to >=3.1.3", "False Unable to read file", _READ_TEXT,
    ),
    _Recipe(
        "toolnode", "AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001", "_fix_langgraph_toolnode", "graph.py",
        b"from langgraph.prebuilt import ToolNode\rnode = ToolNode([a, b])\r\n",
        b"from langgraph.prebuilt import ToolNode\nnode = ToolNode(tools=[a, b])\n",
        "Rewrote ToolNode(positional list) to ToolNode(tools=[...])", "False Unable to read file", _READ_TEXT,
    ),
]


def _call(recipe: _Recipe, project: Path, rel: str, dry_run: bool) -> FixAction | None:
    """Run the recipe itself on ``rel``, not `_apply_fix`, whose `is_file()` check would
    keep a dangling link, a FIFO or a directory from reaching the recipe's own guard."""
    func = getattr(fix_module, recipe.func)
    given = {"path": project / rel, "rule_id": recipe.rule_id, "project_root": project, "dry_run": dry_run}
    return func(**{name: value for name, value in given.items() if name in inspect.signature(func).parameters})


def _projects(tmp_path: Path, recipe: _Recipe) -> tuple[Path, Path]:
    """A project holding the recipe's other files, and a directory outside it."""
    project, outside = tmp_path / "proj", tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    for rel, body in recipe.extra:
        (project / rel).write_bytes(body)
    return project, outside


def _placed(project: Path, rel: str) -> Path:
    path = project / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


# The recipe runs in a child process, so a read or write that blocks on a FIFO fails the
# test on its timeout instead of hanging the suite. "look" lets the FIFO through the
# recipe's look before the read, so the read has to refuse it.
_RECIPE_CHILD = (
    "import inspect, sys\n"
    "from pathlib import Path\n"
    "from agent_audit_kit import fix\n"
    "root, name, rule, rel, how = Path(sys.argv[1]), *sys.argv[2:]\n"
    "if how == 'look':\n"
    "    real, looks = fix._write_refusal, []\n"
    "    fix._write_refusal = lambda *args: looks.append(1) if not looks else real(*args)\n"
    "func = getattr(fix, name)\n"
    "given = {'path': root / rel, 'rule_id': rule, 'project_root': root, 'dry_run': False}\n"
    "action = func(**{k: v for k, v in given.items() if k in inspect.signature(func).parameters})\n"
    "print(action if action is None else f'{action.applied} {action.description}')\n"
)


def test_the_table_holds_every_recipe_and_every_rule_aak_fix_fixes() -> None:
    assert {recipe.rule_id for recipe in _RECIPES} == {rid for rid, rule in RULES.items() if rule.auto_fixable}
    assert {recipe.func for recipe in _RECIPES} == {name for name in dir(fix_module) if name.startswith("_fix_")}


@pytest.mark.parametrize("recipe", _RECIPES, ids=[recipe.id for recipe in _RECIPES])
class TestEveryRecipeWritesOnlyInsideTheProject:
    """A scanned repository decides what sits at each path a recipe edits. Through
    `Path.write_text`, a settings file, manifest or source file linked to a file outside
    the project had the fix written over that file, a dangling link created the file it
    named, and a FIFO blocked `aak fix` forever. Each recipe asks `_write_refusal` before
    it reads, reads only a regular file, and writes through `_write_inside_project`."""

    def test_a_regular_file_is_written_byte_for_byte_as_before(self, tmp_path: Path, recipe: _Recipe) -> None:
        project, _ = _projects(tmp_path, recipe)
        path = _placed(project, recipe.rel)
        path.write_bytes(recipe.before)

        dry = _call(recipe, project, recipe.rel, dry_run=True)
        assert dry is not None and (dry.applied, dry.writes, dry.description) == (False, True, recipe.said)
        assert path.read_bytes() == recipe.before

        done = _call(recipe, project, recipe.rel, dry_run=False)
        assert done is not None and (done.applied, done.writes, done.description) == (True, True, recipe.said)
        assert path.read_bytes() == recipe.after

    @pytest.mark.parametrize("dry_run", [False, True], ids=["write", "dry-run"])
    def test_a_link_out_of_the_project_is_refused_and_its_target_left_alone(
        self, tmp_path: Path, recipe: _Recipe, dry_run: bool
    ) -> None:
        project, outside = _projects(tmp_path, recipe)
        target = outside / "target"
        target.write_bytes(recipe.before)
        _placed(project, recipe.rel).symlink_to(target)

        action = _call(recipe, project, recipe.rel, dry_run)

        assert action is not None
        assert (action.applied, action.description) == (False, f"Failed to fix: {recipe.rel} is a symlink")
        assert action.writes is False, "a refused file is not a fix, in a dry run either"
        assert target.read_bytes() == recipe.before

    def test_a_dangling_link_creates_nothing(self, tmp_path: Path, recipe: _Recipe) -> None:
        project, outside = _projects(tmp_path, recipe)
        _placed(project, recipe.rel).symlink_to(outside / "created-by-fix")

        action = _call(recipe, project, recipe.rel, dry_run=False)

        assert action is not None
        assert (action.applied, action.description) == (False, f"Failed to fix: {recipe.rel} is a symlink")
        assert action.writes is False
        assert not os.path.lexists(outside / "created-by-fix")

    def test_a_directory_at_the_path_is_refused(self, tmp_path: Path, recipe: _Recipe) -> None:
        project, _ = _projects(tmp_path, recipe)
        _placed(project, recipe.rel).mkdir()

        action = _call(recipe, project, recipe.rel, dry_run=False)

        assert action is not None
        assert (action.applied, action.description) == (False, f"Failed to fix: {recipe.rel} is not a regular file")
        assert action.writes is False

    def test_a_file_under_a_directory_linked_out_of_the_project_is_refused(
        self, tmp_path: Path, recipe: _Recipe
    ) -> None:
        if recipe.rel == ".gitignore":
            pytest.skip("the .gitignore recipe edits the project root's own file, which has no directory above it")
        project, outside = _projects(tmp_path, recipe)
        rel = recipe.rel if "/" in recipe.rel else f"sub/{recipe.rel}"
        top, below = rel.split("/", 1)
        (outside / below).parent.mkdir(parents=True, exist_ok=True)
        (outside / below).write_bytes(recipe.before)
        (project / top).symlink_to(outside, target_is_directory=True)

        action = _call(recipe, project, rel, dry_run=False)

        assert action is not None
        assert (action.applied, action.description) == (
            False, f"Failed to fix: {rel} is in a directory outside the project"
        )
        assert action.writes is False
        assert (outside / below).read_bytes() == recipe.before

    def test_a_link_put_in_place_after_the_read_is_refused_by_the_write(
        self, tmp_path: Path, recipe: _Recipe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The look before the read refuses every case above by itself, so this one swaps
        the file for a link once it is read: only the write's own check stands between
        the recipe and the link's target."""
        project, outside = _projects(tmp_path, recipe)
        target = outside / "target"
        target.write_bytes(b"keep\n")
        path = _placed(project, recipe.rel)
        path.write_bytes(recipe.before)
        module, name = recipe.reader
        read = getattr(module, name)

        def read_then_swap(*args: object, **kwargs: object) -> object:
            data = read(*args, **kwargs)
            path.unlink()
            path.symlink_to(target)
            return data

        monkeypatch.setattr(module, name, read_then_swap)

        action = _call(recipe, project, recipe.rel, dry_run=False)

        assert action is not None
        assert (action.applied, action.description) == (False, f"Failed to fix: {recipe.rel} is a symlink")
        assert action.writes is False, "a write refused after the read wrote nothing"
        assert target.read_bytes() == b"keep\n"

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs POSIX FIFOs")
    @pytest.mark.parametrize("how", ["fifo", "look"])
    def test_a_fifo_is_refused_without_blocking(self, tmp_path: Path, recipe: _Recipe, how: str) -> None:
        project, _ = _projects(tmp_path, recipe)
        os.mkfifo(_placed(project, recipe.rel))
        package_root = Path(agent_audit_kit.__file__).resolve().parent.parent

        done = subprocess.run(
            [sys.executable, "-c", _RECIPE_CHILD, str(project), recipe.func, recipe.rule_id, recipe.rel, how],
            capture_output=True, text=True, timeout=30, env={**os.environ, "PYTHONPATH": str(package_root)},
        )

        assert done.returncode == 0, done.stderr
        said = f"False Failed to fix: {recipe.rel} is not a regular file" if how == "fifo" else recipe.unread
        assert done.stdout.strip() == said


# ---------------------------------------------------------------------------
# A fix that changes nothing says so
# ---------------------------------------------------------------------------


class _Unchanged(NamedTuple):
    """A recipe run that writes nothing, and what it says. ``applied`` is what a real run
    reports, which three recipes give as True for a value already set; a dry run reports
    False either way, as it does for a fix it would write, so only ``writes`` tells the
    two apart. `suggest --auto-pr` plans from a dry run."""

    id: str
    rule_id: str
    func: str
    rel: str
    before: bytes
    said: str
    applied: bool = False
    extra: tuple[tuple[str, bytes], ...] = ()


_UNCHANGED = [
    _Unchanged("trust-001-bad-json", "AAK-TRUST-001", "_fix_enable_all_mcp", _SETTINGS, b"{bad json}", "Failed to fix"),
    _Unchanged(
        "trust-004-deny-set", "AAK-TRUST-004", "_fix_missing_deny", _SETTINGS,
        b'{"permissions": {"allow": ["*"], "deny": ["Bash(curl *)"]}}', "Added default deny rules", True,
    ),
    _Unchanged(
        "trust-007-list-set", "AAK-TRUST-007", "_fix_missing_allowlist", _SETTINGS,
        b'{"enabledMcpjsonServers": []}', "Added empty enabledMcpjsonServers allowlist", True,
    ),
    _Unchanged(
        "secret-006-covered", "AAK-SECRET-006", "_fix_env_gitignore", ".gitignore", b".env*\n",
        "Added .env patterns to .gitignore", True, ((".env", b"A=1\n"),),
    ),
    _Unchanged(
        "langchain-not-a-manifest", "AAK-LANGCHAIN-001", "_fix_raised_pin", "setup.py",
        b"install_requires = ['langchain-core==1.2.21']\n", "setup.py is not a manifest the langchain-core pin reads",
    ),
    _Unchanged(
        "langchain-already-raised", "AAK-LANGCHAIN-001", "_fix_raised_pin", "requirements.txt",
        b"langchain-core>=1.2.22\n", "No langchain-core declaration admits a release below 1.2.22",
    ),
    _Unchanged(
        "litellm-pyproject", "AAK-LITELLM-CVE-2026-30623-PIN-001", "_fix_litellm_version", "pyproject.toml",
        b'[project]\ndependencies = ["litellm==1.80.0"]\n',
        "pyproject.toml is not a supported manifest for auto-bump (only requirements*.txt is line-safe to rewrite)",
    ),
    _Unchanged(
        "litellm-no-pin", "AAK-LITELLM-CVE-2026-30623-PIN-001", "_fix_litellm_version", "requirements.txt",
        b"click\n", "No matching litellm pin",
    ),
    _Unchanged(
        "litellm-rewritten-as-it-was", "AAK-LITELLM-CVE-2026-30623-PIN-001", "_fix_litellm_version",
        "requirements.txt",
        b'litellm>=1.83.7; python_version >= "3.10"\nlitellm[proxy]==1.50.0; python_version < "3.10"\n',
        "Nothing in requirements.txt this recipe can rewrite",
    ),
    _Unchanged(
        "flowise-rewritten-as-it-was", "AAK-FLOWISE-001", "_fix_dependency_floor", "requirements.txt",
        b"flowise>=3.1.3\nflowise[extra]==3.0.0\n", "Nothing in requirements.txt this recipe can rewrite",
    ),
    _Unchanged(
        "flowise-bad-json", "AAK-FLOWISE-001", "_fix_dependency_floor", "package.json", b"{not json",
        "package.json is not valid JSON",
    ),
    _Unchanged(
        "flowise-no-dep", "AAK-FLOWISE-001", "_fix_dependency_floor", "package.json",
        b'{"dependencies": {"react": "18.0.0"}}', "No matching flowise dep found",
    ),
    _Unchanged(
        "flowise-lockfile", "AAK-FLOWISE-001", "_fix_dependency_floor", "package-lock.json", b"{}",
        "package-lock.json is not a supported manifest for auto-bump "
        "(only requirements*.txt and package.json are safe to rewrite)",
    ),
]


@pytest.mark.parametrize("case", _UNCHANGED, ids=[case.id for case in _UNCHANGED])
@pytest.mark.parametrize("dry_run", [True, False], ids=["dry-run", "write"])
def test_a_fix_that_changes_nothing_does_not_write(tmp_path: Path, case: _Unchanged, dry_run: bool) -> None:
    for rel, body in case.extra:
        (tmp_path / rel).write_bytes(body)
    path = _placed(tmp_path, case.rel)
    path.write_bytes(case.before)
    func = getattr(fix_module, case.func)
    given = {"path": path, "rule_id": case.rule_id, "project_root": tmp_path, "dry_run": dry_run}

    action = func(**{name: value for name, value in given.items() if name in inspect.signature(func).parameters})

    assert (action.applied, action.writes, action.description) == (case.applied and not dry_run, False, case.said)
    assert path.read_bytes() == case.before


@pytest.mark.usefixtures("full_disk")
def test_a_recipe_whose_write_fails_part_way_says_the_file_may_be_partly_written(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"enableAllProjectMcpServers": True}))

    fix = _fix_enable_all_mcp(settings, tmp_path, dry_run=False)

    assert (fix.applied, fix.writes, fix.description) == (
        False, False,
        "Failed to fix: settings.json could not be written (No space left on device) and may be partly written",
    )


def test_run_fixes_says_the_fix_log_may_be_partly_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The fixes stand and the line on stderr said the log was not written; a log whose
    write failed part way may hold part of it."""
    partly = fix_module._PartlyWritten("fix-log.json could not be written (No space left on device) and may be partly written")
    monkeypatch.setattr(fix_module, "_write_fix_log", lambda root, fixes: partly)

    fix_module._log_fixes(tmp_path, [])

    assert capsys.readouterr().err == "fix: " + partly + "\n"


# ---------------------------------------------------------------------------
# _write_fix_log
# ---------------------------------------------------------------------------


class TestWriteFixLog:
    def test_creates_log_file(self, tmp_path: Path) -> None:
        fixes = [
            FixAction("AAK-TRUST-001", "file.json", "Fixed trust", applied=True),
            FixAction("AAK-SECRET-006", ".gitignore", "Fixed env", applied=True),
        ]
        _write_fix_log(tmp_path, fixes)

        log_file = tmp_path / ".agent-audit-kit" / "fix-log.json"
        assert log_file.exists()

        log = json.loads(log_file.read_text())
        assert "timestamp" in log
        assert len(log["fixes_applied"]) == 2
        assert log["fixes_applied"][0]["rule_id"] == "AAK-TRUST-001"

    def test_only_logs_applied_fixes(self, tmp_path: Path) -> None:
        fixes = [
            FixAction("AAK-TRUST-001", "file.json", "Applied", applied=True),
            FixAction("AAK-SECRET-006", ".gitignore", "Dry run", applied=False),
        ]
        _write_fix_log(tmp_path, fixes)

        log_file = tmp_path / ".agent-audit-kit" / "fix-log.json"
        log = json.loads(log_file.read_text())
        assert len(log["fixes_applied"]) == 1


_APPLIED = [FixAction("AAK-TRUST-001", ".claude/settings.json", "Set enableAllProjectMcpServers to false", True)]

_LOG_CHILD = (
    "import sys\n"
    "from pathlib import Path\n"
    "from agent_audit_kit.fix import FixAction, _write_fix_log\n"
    "print(_write_fix_log(Path(sys.argv[1]), [FixAction('AAK-TRUST-001', 'a.json', 'done', True)]))\n"
)


class TestTheFixLogIsWrittenOnlyInsideTheProject:
    """`.agent-audit-kit/` is the tool's own directory, but the scanned repository can ship
    anything under that name. `Path.mkdir(exist_ok=True)` accepted a link to a directory
    outside the project and `Path.write_text` followed a link at the log itself, so the
    log was written wherever either pointed, and a regular file or a dangling link named
    `.agent-audit-kit` raised after every fix had been applied."""

    def _projects(self, tmp_path: Path) -> tuple[Path, Path]:
        project, outside = tmp_path / "proj", tmp_path / "outside"
        project.mkdir()
        outside.mkdir()
        return project, outside

    def test_the_log_and_its_directory_are_written_as_before(self, tmp_path: Path) -> None:
        assert _write_fix_log(tmp_path, _APPLIED) is None

        written = (tmp_path / ".agent-audit-kit" / "fix-log.json").read_bytes()
        log = json.loads(written)
        assert written == (json.dumps(log, indent=2) + "\n").encode()
        assert list(log) == ["timestamp", "fixes_applied"]
        assert log["fixes_applied"] == [
            {"rule_id": "AAK-TRUST-001", "file": ".claude/settings.json",
             "description": "Set enableAllProjectMcpServers to false"},
        ]

    def test_a_linked_log_is_refused_and_its_target_left_alone(self, tmp_path: Path) -> None:
        project, outside = self._projects(tmp_path)
        (outside / "rc").write_bytes(b"keep\n")
        (project / ".agent-audit-kit").mkdir()
        (project / ".agent-audit-kit" / "fix-log.json").symlink_to(outside / "rc")

        assert _write_fix_log(project, _APPLIED) == ".agent-audit-kit/fix-log.json is a symlink"
        assert (outside / "rc").read_bytes() == b"keep\n"

    def test_a_dangling_linked_log_creates_nothing(self, tmp_path: Path) -> None:
        project, outside = self._projects(tmp_path)
        (project / ".agent-audit-kit").mkdir()
        (project / ".agent-audit-kit" / "fix-log.json").symlink_to(outside / "created-by-fix")

        assert _write_fix_log(project, _APPLIED) == ".agent-audit-kit/fix-log.json is a symlink"
        assert not os.path.lexists(outside / "created-by-fix")

    def test_a_directory_named_like_the_log_is_refused(self, tmp_path: Path) -> None:
        (tmp_path / ".agent-audit-kit" / "fix-log.json").mkdir(parents=True)

        assert _write_fix_log(tmp_path, _APPLIED) == ".agent-audit-kit/fix-log.json is not a regular file"

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs POSIX FIFOs")
    def test_a_fifo_named_like_the_log_is_refused_without_blocking(self, tmp_path: Path) -> None:
        (tmp_path / ".agent-audit-kit").mkdir()
        os.mkfifo(tmp_path / ".agent-audit-kit" / "fix-log.json")
        package_root = Path(agent_audit_kit.__file__).resolve().parent.parent

        done = subprocess.run(
            [sys.executable, "-c", _LOG_CHILD, str(tmp_path)], capture_output=True, text=True, timeout=30,
            env={**os.environ, "PYTHONPATH": str(package_root)},
        )

        assert done.returncode == 0, done.stderr
        assert done.stdout.strip() == ".agent-audit-kit/fix-log.json is not a regular file"

    def test_a_directory_linked_out_of_the_project_is_refused(self, tmp_path: Path) -> None:
        project, outside = self._projects(tmp_path)
        (project / ".agent-audit-kit").symlink_to(outside, target_is_directory=True)

        assert _write_fix_log(project, _APPLIED) == ".agent-audit-kit resolves outside the project"
        assert os.listdir(outside) == []

    def test_a_dangling_linked_directory_creates_nothing(self, tmp_path: Path) -> None:
        project, outside = self._projects(tmp_path)
        (project / ".agent-audit-kit").symlink_to(outside / "made-by-fix", target_is_directory=True)

        assert _write_fix_log(project, _APPLIED) == ".agent-audit-kit is not a directory"
        assert not os.path.lexists(outside / "made-by-fix")

    def test_a_file_named_like_the_directory_is_refused(self, tmp_path: Path) -> None:
        (tmp_path / ".agent-audit-kit").write_bytes(b"not a directory\n")

        assert _write_fix_log(tmp_path, _APPLIED) == ".agent-audit-kit is not a directory"
        assert (tmp_path / ".agent-audit-kit").read_bytes() == b"not a directory\n"

    def test_a_directory_linked_inside_the_project_is_followed(self, tmp_path: Path) -> None:
        """A link that stays inside the project is followed like any directory above a
        file `_write_refusal` allows: the write still lands inside the project."""
        (tmp_path / "build").mkdir()
        (tmp_path / ".agent-audit-kit").symlink_to(tmp_path / "build", target_is_directory=True)

        assert _write_fix_log(tmp_path, _APPLIED) is None
        assert json.loads((tmp_path / "build" / "fix-log.json").read_text())["fixes_applied"]

    def test_run_fixes_says_why_it_wrote_no_log_and_keeps_the_fixes(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project, outside = self._projects(tmp_path)
        settings = _placed(project, _SETTINGS)
        settings.write_text(json.dumps({"enableAllProjectMcpServers": True}))
        (project / ".agent-audit-kit").symlink_to(outside, target_is_directory=True)

        fixes = [fix for fix in run_fixes(project) if fix.rule_id == "AAK-TRUST-001"]

        assert [fix.applied for fix in fixes] == [True]
        assert json.loads(settings.read_text())["enableAllProjectMcpServers"] is False
        assert capsys.readouterr().err == (
            "fix: the fix log was not written: .agent-audit-kit resolves outside the project\n"
        )
        assert os.listdir(outside) == []


# ---------------------------------------------------------------------------
# _apply_fix
# ---------------------------------------------------------------------------


class TestApplyFix:
    def test_trust_001_dispatches_correctly(self, tmp_path: Path) -> None:
        cfg = tmp_path / "settings.json"
        cfg.write_text(json.dumps({"enableAllProjectMcpServers": True}))

        fix = _apply_fix(tmp_path, "AAK-TRUST-001", "settings.json", dry_run=False)
        assert fix is not None
        assert fix.rule_id == "AAK-TRUST-001"
        assert fix.applied is True

    def test_secret_006_dispatches_correctly(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_text("node_modules/\n")
        fix = _apply_fix(tmp_path, "AAK-SECRET-006", ".gitignore", dry_run=False)
        assert fix is not None
        assert fix.rule_id == "AAK-SECRET-006"

    def test_trust_004_dispatches_correctly(self, tmp_path: Path) -> None:
        cfg = tmp_path / "settings.json"
        cfg.write_text(json.dumps({"permissions": {"allow": ["*"]}}))

        fix = _apply_fix(tmp_path, "AAK-TRUST-004", "settings.json", dry_run=False)
        assert fix is not None
        assert fix.rule_id == "AAK-TRUST-004"
        assert fix.applied is True

    def test_trust_007_dispatches_correctly(self, tmp_path: Path) -> None:
        cfg = tmp_path / "settings.json"
        cfg.write_text(json.dumps({"other": "data"}))

        fix = _apply_fix(tmp_path, "AAK-TRUST-007", "settings.json", dry_run=False)
        assert fix is not None
        assert fix.rule_id == "AAK-TRUST-007"
        assert fix.applied is True

    def test_unknown_rule_returns_none(self, tmp_path: Path) -> None:
        cfg = tmp_path / "somefile.json"
        cfg.write_text("{}")
        fix = _apply_fix(tmp_path, "AAK-UNKNOWN-999", "somefile.json", dry_run=False)
        assert fix is None

    def test_missing_file_returns_none(self, tmp_path: Path) -> None:
        fix = _apply_fix(tmp_path, "AAK-TRUST-001", "nonexistent.json", dry_run=False)
        assert fix is None


# ---------------------------------------------------------------------------
# run_fixes
# ---------------------------------------------------------------------------


class TestRunFixes:
    def test_dry_run_creates_fix_actions_without_modifying_files(
        self, tmp_path: Path
    ) -> None:
        """run_fixes with dry_run=True creates FixAction objects but doesn't modify files."""
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = {"enableAllProjectMcpServers": True}
        settings_file = claude_dir / "settings.json"
        settings_file.write_text(json.dumps(settings))
        original_content = settings_file.read_text()

        result, mock_rules = _setup_fixable_scan(
            tmp_path, "AAK-TRUST-001", str(settings_file)
        )

        with patch("agent_audit_kit.fix.run_scan") as mock_scan, patch(
            "agent_audit_kit.fix.RULES", mock_rules
        ):
            mock_scan.return_value = result
            fixes = run_fixes(tmp_path, dry_run=True)

        assert len(fixes) > 0
        for fix in fixes:
            assert isinstance(fix, FixAction)
            assert fix.applied is False

        # File should be unchanged
        assert settings_file.read_text() == original_content
        # No fix-log should be written
        assert not (tmp_path / ".agent-audit-kit" / "fix-log.json").exists()

    def test_fixing_trust_001_sets_enable_all_false(self, tmp_path: Path) -> None:
        """Fixing AAK-TRUST-001 sets enableAllProjectMcpServers to false."""
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings_file = claude_dir / "settings.json"
        settings_file.write_text(
            json.dumps({"enableAllProjectMcpServers": True})
        )

        result, mock_rules = _setup_fixable_scan(
            tmp_path, "AAK-TRUST-001", str(settings_file)
        )

        with patch("agent_audit_kit.fix.run_scan") as mock_scan, patch(
            "agent_audit_kit.fix.RULES", mock_rules
        ):
            mock_scan.return_value = result
            fixes = run_fixes(tmp_path, dry_run=False)

        assert any(f.rule_id == "AAK-TRUST-001" and f.applied for f in fixes)
        data = json.loads(settings_file.read_text())
        assert data["enableAllProjectMcpServers"] is False

    def test_fixing_secret_006_adds_env_to_gitignore(self, tmp_path: Path) -> None:
        """Fixing AAK-SECRET-006 adds .env to .gitignore."""
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text("node_modules/\n")

        result, mock_rules = _setup_fixable_scan(
            tmp_path, "AAK-SECRET-006", ".gitignore"
        )

        with patch("agent_audit_kit.fix.run_scan") as mock_scan, patch(
            "agent_audit_kit.fix.RULES", mock_rules
        ):
            mock_scan.return_value = result
            fixes = run_fixes(tmp_path, dry_run=False)

        assert any(f.rule_id == "AAK-SECRET-006" and f.applied for f in fixes)
        content = gitignore.read_text()
        assert ".env" in content

    def test_fix_log_json_is_created(self, tmp_path: Path) -> None:
        """Fix log JSON file is created when fixes are applied."""
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings_file = claude_dir / "settings.json"
        settings_file.write_text(
            json.dumps({"enableAllProjectMcpServers": True})
        )

        result, mock_rules = _setup_fixable_scan(
            tmp_path, "AAK-TRUST-001", str(settings_file)
        )

        with patch("agent_audit_kit.fix.run_scan") as mock_scan, patch(
            "agent_audit_kit.fix.RULES", mock_rules
        ):
            mock_scan.return_value = result
            run_fixes(tmp_path, dry_run=False)

        log_file = tmp_path / ".agent-audit-kit" / "fix-log.json"
        assert log_file.exists()
        log = json.loads(log_file.read_text())
        assert "timestamp" in log
        assert "fixes_applied" in log
        assert len(log["fixes_applied"]) >= 1

    def test_empty_project_no_fixable_findings_returns_empty(
        self, tmp_path: Path
    ) -> None:
        """Empty project (no fixable findings) returns empty list."""
        result = ScanResult(findings=[])

        with patch("agent_audit_kit.fix.run_scan") as mock_scan, patch(
            "agent_audit_kit.fix.RULES", {}
        ):
            mock_scan.return_value = result
            fixes = run_fixes(tmp_path, dry_run=False)

        assert fixes == []
        assert not (tmp_path / ".agent-audit-kit" / "fix-log.json").exists()


# ---------------------------------------------------------------------------
# _fix_missing_deny
# ---------------------------------------------------------------------------


class TestFixMissingDeny:
    def test_adds_deny_rules(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text(json.dumps({"permissions": {"allow": ["*"]}}))

        fix = _fix_missing_deny(cfg_file, tmp_path, dry_run=False)
        assert fix.applied is True
        assert fix.rule_id == "AAK-TRUST-004"

        data = json.loads(cfg_file.read_text())
        assert "deny" in data["permissions"]
        assert len(data["permissions"]["deny"]) > 0

    def test_dry_run_does_not_modify(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        original = json.dumps({"permissions": {"allow": ["*"]}})
        cfg_file.write_text(original)

        fix = _fix_missing_deny(cfg_file, tmp_path, dry_run=True)
        assert fix.applied is False
        assert cfg_file.read_text() == original

    def test_skips_if_deny_already_present(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text(json.dumps({
            "permissions": {"allow": ["*"], "deny": ["Bash(rm -rf *)"]}
        }))
        original = cfg_file.read_text()

        fix = _fix_missing_deny(cfg_file, tmp_path, dry_run=False)
        assert fix.rule_id == "AAK-TRUST-004"
        # File should remain unchanged since deny already exists
        assert cfg_file.read_text() == original

    def test_creates_permissions_if_missing(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text(json.dumps({"other": "data"}))

        fix = _fix_missing_deny(cfg_file, tmp_path, dry_run=False)
        assert fix.applied is True

        data = json.loads(cfg_file.read_text())
        assert "permissions" in data
        assert "deny" in data["permissions"]

    def test_malformed_json_returns_failed(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text("{invalid")

        fix = _fix_missing_deny(cfg_file, tmp_path, dry_run=False)
        assert fix.applied is False
        assert "Failed" in fix.description


# ---------------------------------------------------------------------------
# _fix_missing_allowlist
# ---------------------------------------------------------------------------


class TestFixMissingAllowlist:
    def test_adds_enabled_mcp_servers(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text(json.dumps({"other": "data"}))

        fix = _fix_missing_allowlist(cfg_file, tmp_path, dry_run=False)
        assert fix.applied is True
        assert fix.rule_id == "AAK-TRUST-007"

        data = json.loads(cfg_file.read_text())
        assert "enabledMcpjsonServers" in data
        assert data["enabledMcpjsonServers"] == []

    def test_dry_run_does_not_modify(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        original = json.dumps({"other": "data"})
        cfg_file.write_text(original)

        fix = _fix_missing_allowlist(cfg_file, tmp_path, dry_run=True)
        assert fix.applied is False
        assert cfg_file.read_text() == original

    def test_skips_if_allowlist_already_present(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text(json.dumps({"enabledMcpjsonServers": ["server1"]}))
        original = cfg_file.read_text()

        fix = _fix_missing_allowlist(cfg_file, tmp_path, dry_run=False)
        assert fix.rule_id == "AAK-TRUST-007"
        # File should remain unchanged
        assert cfg_file.read_text() == original

    def test_malformed_json_returns_failed(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text("{invalid")

        fix = _fix_missing_allowlist(cfg_file, tmp_path, dry_run=False)
        assert fix.applied is False
        assert "Failed" in fix.description


class TestRequirementPinRewrite:
    def test_blank_lines_and_indentation_are_kept(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("click\n\n\n  litellm == 1.80.0\nrequests\n", encoding="utf-8")
        assert _fix_litellm_version(req, tmp_path, dry_run=False).applied
        assert req.read_text(encoding="utf-8") == "click\n\n\n  litellm>=1.83.7\nrequests\n"

    def test_a_crafted_requirements_file_rewrites_in_linear_time(self, tmp_path: Path) -> None:
        """1 MB of blank lines with no pin after them, then a name and 1 MB of
        blanks with no version. `^\\s*` started at every blank line and read to
        the end of the run (40,000 took 4.3 seconds), and the blanks around the
        optional operator were split every way (20,000 took 1 second); both
        grew with the square. The bound is loose for slow CI runners."""
        req = tmp_path / "requirements.txt"
        req.write_text("\n" * 1_000_000 + "x\nlitellm" + " " * 1_000_000 + "x\n", encoding="utf-8")
        started = time.perf_counter()
        _fix_litellm_version(req, tmp_path, dry_run=False)
        assert time.perf_counter() - started < 5.0


# ---------------------------------------------------------------------------
# AAK-SECRET-007: the env reference goes back into the map the server came from
# ---------------------------------------------------------------------------


class TestFixSecretEnvRef:
    def test_a_vscode_server_gets_an_env_reference_in_its_own_map(self, tmp_path: Path) -> None:
        """VS Code substitutes `${env:KEY}`; a bare `${KEY}` would reach the server as
        written. The server stays under `servers`, and no `mcpServers` key appears."""
        path = tmp_path / ".vscode" / "mcp.json"
        path.parent.mkdir()
        path.write_text(json.dumps({
            "servers": {"gh": {"command": "npx", "env": {"GITHUB_TOKEN": "literal-value"}}},
        }))
        action = _fix_secret_env_ref(path, tmp_path, dry_run=False)
        assert action is not None and action.applied
        data = json.loads(path.read_text())
        assert data == {
            "servers": {"gh": {"command": "npx", "env": {"GITHUB_TOKEN": "${env:GITHUB_TOKEN}"}}},
        }
        from agent_audit_kit.scanners.secret_exposure import scan as secret_scan
        assert not [f for f in secret_scan(tmp_path)[0] if f.rule_id == "AAK-SECRET-007"]

    def test_each_map_keeps_its_servers_and_its_own_form(self, tmp_path: Path) -> None:
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps({
            "mcpServers": {"a": {"env": {"API_KEY": "one"}}},
            "servers": {"b": {"env": {"API_KEY": "two"}}},
        }))
        assert _fix_secret_env_ref(path, tmp_path, dry_run=False) is not None
        assert json.loads(path.read_text()) == {
            "mcpServers": {"a": {"env": {"API_KEY": "${API_KEY}"}}},
            "servers": {"b": {"env": {"API_KEY": "${env:API_KEY}"}}},
        }

    def test_a_jsonc_config_is_left_alone(self, tmp_path: Path) -> None:
        """Writing a JSONC file back through `json.dumps` would delete its comments."""
        path = tmp_path / "mcp.json"
        text = '{\n  // keep this\n  "servers": {"b": {"env": {"API_KEY": "two"}}}\n}\n'
        path.write_text(text)
        assert _fix_secret_env_ref(path, tmp_path, dry_run=False) is None
        assert path.read_text() == text
