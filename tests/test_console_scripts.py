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


def test_docs_only_reference_commands_that_exist() -> None:
    """`aak <cmd>` in prose must name a real command.

    Catches the other half of the problem: a working binary invoked with a
    command that was renamed or never shipped.
    """
    known = set(cli.commands)
    # Words that follow `aak ` in prose but are not commands.
    prose = {"is", "the", "and", "as", "to", "in", "or", "a", "it", "does", "for", "with"}

    offenders: list[str] = []
    for path in REPO_ROOT.rglob("*.md"):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel.startswith(("node_modules/", "site/", ".venv/", "releases/", "vscode-extension/node_modules/")):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in re.finditer(r"`aak ([a-z][a-z-]*)", text):
            cmd = match.group(1)
            if cmd in prose or cmd in known:
                continue
            offenders.append(f"{rel}: `aak {cmd}`")

    assert not offenders, (
        "docs reference commands that do not exist:\n  " + "\n  ".join(sorted(set(offenders)))
    )
