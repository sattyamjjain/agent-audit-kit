"""The declared console scripts must match the commands the docs tell people to run.

`aak` had been used as shorthand throughout the README, changelogs and release
notes for many releases without ever being declared in `[project.scripts]`, so
every one of those snippets exited 127 when a user copied it. These tests keep
the two in step: both names install, both dispatch to the same Click group, and
any command named in the docs as `aak <cmd>` actually exists.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # 3.9 / 3.10 — the project ships tomli for these
    import tomli as tomllib  # type: ignore[no-redef,import-not-found]

from agent_audit_kit.cli import cli

REPO_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_SCRIPTS = {"agent-audit-kit", "aak"}


def _declared_scripts() -> dict[str, str]:
    with (REPO_ROOT / "pyproject.toml").open("rb") as fh:
        return tomllib.load(fh)["project"]["scripts"]


def test_both_console_scripts_are_declared() -> None:
    assert set(_declared_scripts()) == EXPECTED_SCRIPTS


def test_both_scripts_share_one_entry_point() -> None:
    """Same target, so the two names cannot drift apart."""
    targets = set(_declared_scripts().values())
    assert targets == {"agent_audit_kit.cli:cli"}


@pytest.mark.parametrize("script", sorted(EXPECTED_SCRIPTS))
def test_script_is_installed_and_runs(script: str) -> None:
    """A declared script that is not on PATH is the 127 this test exists to catch."""
    exe = Path(sys.executable).parent / script
    if not exe.exists():
        pytest.skip(f"{script} not installed in this environment (pip install -e .)")
    out = subprocess.run([str(exe), "--version"], capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stderr
    assert script in out.stdout


# A command line in a fenced code block: either name at the start of a line,
# after an optional `$ ` prompt.
_FENCE_RE = re.compile(r"^[ \t]*(```|~~~)[^\n]*\n(.*?)^[ \t]*\1[ \t]*$", re.MULTILINE | re.DOTALL)
_FENCED_COMMAND_RE = re.compile(r"^[ \t]*(?:\$[ \t]+)?(aak|agent-audit-kit)[ \t]+([a-z][a-z-]*)", re.MULTILINE)
# A backticked `aak <cmd>` or `agent-audit-kit <cmd>` in prose.
_INLINE_COMMAND_RE = re.compile(r"`(aak|agent-audit-kit) ([a-z][a-z-]*)")


def _named_commands(text: str) -> list[tuple[str, str]]:
    """(script, command) for every command the text tells someone to run."""
    named = [(m.group(1), m.group(2)) for m in _INLINE_COMMAND_RE.finditer(text)]
    for block in _FENCE_RE.finditer(text):
        named += [(m.group(1), m.group(2)) for m in _FENCED_COMMAND_RE.finditer(block.group(2))]
    return named


def test_docs_only_reference_commands_that_exist() -> None:
    """`aak <cmd>` and `agent-audit-kit <cmd>` in the docs must name a real command,
    backticked in prose or on a command line in a fenced code block.

    Catches the other half of the problem: a working binary invoked with a
    command that was renamed or never shipped. Until #1060 only a backticked
    `aak <cmd>` was read, so the long name and every code block went unchecked.
    """
    known = set(cli.commands)
    # Words that follow `aak ` in prose but are not commands.
    prose = {"is", "the", "and", "as", "to", "in", "or", "a", "it", "does", "for", "with"}

    offenders: list[str] = []
    for path in REPO_ROOT.rglob("*.md"):
        rel = path.relative_to(REPO_ROOT).as_posix()
        # `.claude/` holds agent state, Claude Code worktrees (a full copy of the
        # repository each) among it, not docs. The changelogs and release notes
        # record what shipped, including commands later renamed or never built.
        if rel.startswith((
            "node_modules/", "site/", ".venv/", "releases/", "vscode-extension/node_modules/", ".claude/",
            "docs/changelog/",
        )) or path.name.startswith("CHANGELOG"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for script, cmd in _named_commands(text):
            if cmd in prose or cmd in known:
                continue
            offenders.append(f"{rel}: `{script} {cmd}`")

    assert not offenders, (
        "docs reference commands that do not exist:\n  " + "\n  ".join(sorted(set(offenders)))
    )


def test_the_docs_check_reads_both_names_and_code_blocks() -> None:
    text = (
        "Run `aak scan .` or `agent-audit-kit toxic-flow --explain`.\n\n"
        "```bash\n$ aak pin .\nagent-audit-kit frobnicate\npip install agent-audit-kit\n```\n"
        "agent-audit-kit occupies a niche, in prose outside a block.\n"
    )
    assert _named_commands(text) == [
        ("aak", "scan"), ("agent-audit-kit", "toxic-flow"), ("aak", "pin"), ("agent-audit-kit", "frobnicate"),
    ]
