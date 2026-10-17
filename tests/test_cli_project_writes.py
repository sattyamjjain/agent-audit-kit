"""`aak install-precommit` and `aak pipelock import` write into the project as `aak fix` does.

`install-precommit` read and rewrote `<project>/.pre-commit-config.yaml` through
`Path.is_file`, `Path.read_text` and `Path.write_text`, and `pipelock import` without
`-o` wrote `.agent-audit-kit.yml` in the current directory through `Path.write_text`. A
cloned repository decides what sits at either path: a link to a file outside the project
had that file rewritten, a dangling link created the file it named, a directory ended in
a traceback, and a FIFO blocked the command forever. Both now ask `fix._write_refusal`
before reading or writing, read only a regular file and write through
`fix._write_inside_project`, and exit 2 with the reason when the file is refused.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

import pytest
from click.testing import CliRunner, Result

import agent_audit_kit
from agent_audit_kit.commands import install_precommit
from agent_audit_kit.cli import cli
from agent_audit_kit.translators.pipelock import translate

_POLICY = Path(__file__).parent / "fixtures" / "pipelock" / "policy_minimal.yaml"
_AS_WRITTEN = translate(_POLICY).replace("\n", os.linesep).encode("utf-8")


class _Command(NamedTuple):
    """A command that writes one file into the project: the file, the arguments after
    `aak` (`{project}` stands for the project's path), and how its refusal starts. Each
    runs from inside the project, since `pipelock import` writes to the current directory."""

    id: str
    rel: str
    args: tuple[str, ...]
    lead: str


_COMMANDS = [
    _Command("install-precommit", ".pre-commit-config.yaml", ("install-precommit", "{project}"), "Cannot add the hook"),
    _Command("pipelock-import", ".agent-audit-kit.yml", ("pipelock", "import", str(_POLICY)), "Cannot import the policy"),
]


def _invoke(command: _Command, project: Path, monkeypatch: pytest.MonkeyPatch) -> Result:
    monkeypatch.chdir(project)
    return CliRunner().invoke(cli, [arg.replace("{project}", str(project)) for arg in command.args])


def _refusal(command: _Command, reason: str) -> str:
    return f"{command.lead}: {command.rel} {reason}. {command.rel} was not changed.\n"


def _projects(tmp_path: Path) -> tuple[Path, Path]:
    project, outside = tmp_path / "proj", tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    return project, outside


@pytest.mark.parametrize("command", _COMMANDS, ids=[command.id for command in _COMMANDS])
class TestEachCommandWritesOnlyInsideTheProject:
    def test_a_link_out_of_the_project_is_refused_and_its_target_left_alone(
        self, tmp_path: Path, command: _Command, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project, outside = _projects(tmp_path)
        target = outside / "target"
        target.write_bytes(b"repos:\n  - repo: keep\n")
        (project / command.rel).symlink_to(target)

        result = _invoke(command, project, monkeypatch)

        assert (result.exit_code, result.output) == (2, _refusal(command, "is a symlink"))
        assert target.read_bytes() == b"repos:\n  - repo: keep\n"

    def test_a_link_inside_the_project_is_refused_too(
        self, tmp_path: Path, command: _Command, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """As `aak fix` refuses one: the test reads the path itself, not what it names."""
        project, _ = _projects(tmp_path)
        (project / "real.yaml").write_bytes(b"repos:\n")
        (project / command.rel).symlink_to(project / "real.yaml")

        result = _invoke(command, project, monkeypatch)

        assert (result.exit_code, result.output) == (2, _refusal(command, "is a symlink"))
        assert (project / "real.yaml").read_bytes() == b"repos:\n"

    def test_a_dangling_link_creates_nothing(
        self, tmp_path: Path, command: _Command, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project, outside = _projects(tmp_path)
        (project / command.rel).symlink_to(outside / "created-by-aak")

        result = _invoke(command, project, monkeypatch)

        assert (result.exit_code, result.output) == (2, _refusal(command, "is a symlink"))
        assert not os.path.lexists(outside / "created-by-aak")

    def test_a_directory_at_the_path_is_refused(
        self, tmp_path: Path, command: _Command, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project, _ = _projects(tmp_path)
        (project / command.rel).mkdir()

        result = _invoke(command, project, monkeypatch)

        assert (result.exit_code, result.output) == (2, _refusal(command, "is not a regular file"))
        assert os.listdir(project / command.rel) == []

    def test_a_project_reached_through_a_link_is_written(
        self, tmp_path: Path, command: _Command, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The file sits in the project root, which the user names (`PATH`, or the
        current directory), so the only directory above it is theirs to choose. A
        project reached through a link resolves to the real directory, and is written
        there as before: the checks never refuse the user's own path."""
        project, _ = _projects(tmp_path)
        (tmp_path / "via").symlink_to(project, target_is_directory=True)

        result = _invoke(command, tmp_path / "via", monkeypatch)

        assert result.exit_code == 0, result.output
        assert (project / command.rel).is_file() and not (project / command.rel).is_symlink()

    @pytest.mark.skipif(
        not hasattr(os, "geteuid") or os.geteuid() == 0, reason="needs POSIX permissions that bind the user"
    )
    def test_a_read_only_file_is_reported_not_raised(
        self, tmp_path: Path, command: _Command, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`Path.write_text` raised PermissionError, which ended the command in a traceback."""
        project, _ = _projects(tmp_path)
        path = project / command.rel
        path.write_bytes(b"repos:\n")
        path.chmod(0o444)

        result = _invoke(command, project, monkeypatch)

        path.chmod(0o644)
        assert (result.exit_code, result.output) == (2, _refusal(command, "could not be opened (Permission denied)"))
        assert path.read_bytes() == b"repos:\n"


# The command runs in a child process, so a read or write that blocks on a FIFO fails the
# test on its timeout instead of hanging the suite. "look" lets the FIFO through the first
# `_write_refusal`, so what stands between the command and the FIFO is the read (for
# install-precommit) or the open (for pipelock import, which reads nothing first).
_CHILD = (
    "import os, sys\n"
    "from click.testing import CliRunner\n"
    "from agent_audit_kit import fix\n"
    "from agent_audit_kit.cli import cli\n"
    "root, how, *args = sys.argv[1:]\n"
    "if how == 'look':\n"
    "    real, looks = fix._write_refusal, []\n"
    "    fix._write_refusal = lambda *a: looks.append(1) if not looks else real(*a)\n"
    "os.chdir(root)\n"
    "result = CliRunner().invoke(cli, [a.replace('{project}', root) for a in args])\n"
    "print(result.exit_code, result.output.strip())\n"
)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs POSIX FIFOs")
@pytest.mark.parametrize("command", _COMMANDS, ids=[command.id for command in _COMMANDS])
@pytest.mark.parametrize("how", ["fifo", "look"])
def test_a_fifo_is_refused_without_blocking(tmp_path: Path, command: _Command, how: str) -> None:
    project, _ = _projects(tmp_path)
    os.mkfifo(project / command.rel)
    package_root = Path(agent_audit_kit.__file__).resolve().parent.parent

    done = subprocess.run(
        [sys.executable, "-c", _CHILD, str(project), how, *command.args],
        capture_output=True, text=True, timeout=30, env={**os.environ, "PYTHONPATH": str(package_root)},
    )

    assert done.returncode == 0, done.stderr
    if how == "fifo" or command.id == "install-precommit":
        assert done.stdout.strip() == "2 " + _refusal(command, "is not a regular file").strip()
    else:
        assert done.stdout.startswith(f"2 {command.lead}: {command.rel} could not be opened (")
        assert done.stdout.strip().endswith(f"). {command.rel} was not changed.")


# ---------------------------------------------------------------------------
# install-precommit: a link swapped in after the read, and a config it cannot read
# (what it writes into a regular file is pinned in tests/test_install_precommit.py)
# ---------------------------------------------------------------------------


def test_install_precommit_refuses_a_link_put_in_place_after_the_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The look before the read refuses every link above by itself, so this one swaps the
    file for a link once it is read: only the write's own check stands between the
    command and the link's target."""
    project, outside = _projects(tmp_path)
    target = outside / "target"
    target.write_bytes(b"keep\n")
    config = project / ".pre-commit-config.yaml"
    config.write_bytes(b"repos:\n")
    read = install_precommit._read_config

    def read_then_swap(path: Path) -> bytes:
        data = read(path)
        config.unlink()
        config.symlink_to(target)
        return data

    monkeypatch.setattr(install_precommit, "_read_config", read_then_swap)

    result = _invoke(_COMMANDS[0], project, monkeypatch)

    assert (result.exit_code, result.output) == (2, _refusal(_COMMANDS[0], "is a symlink"))
    assert target.read_bytes() == b"keep\n"


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="needs POSIX permissions that bind the user"
)
def test_install_precommit_reports_a_config_it_cannot_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`Path.read_text` raised PermissionError, which ended the command in a traceback."""
    project, _ = _projects(tmp_path)
    config = project / ".pre-commit-config.yaml"
    config.write_bytes(b"repos:\n")
    config.chmod(0o000)

    result = _invoke(_COMMANDS[0], project, monkeypatch)

    config.chmod(0o644)
    assert (result.exit_code, result.output) == (
        2, _refusal(_COMMANDS[0], "could not be read (Permission denied)")
    )
    assert config.read_bytes() == b"repos:\n"


# ---------------------------------------------------------------------------
# pipelock import: the default target as before, and -o left to the user
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("existing", [None, b"stale: true\r\n" * 50], ids=["created", "replaced"])
@pytest.mark.parametrize("line_ends", ["lf", "crlf"])
def test_pipelock_import_writes_the_default_target_as_before(
    tmp_path: Path, existing: bytes | None, line_ends: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`Path.write_text` replaced the file with the translation, each newline written as
    `os.linesep`; `fix._as_written` gives the same bytes. The policy is read with
    universal newlines, so a CRLF policy translates to the same text."""
    project, _ = _projects(tmp_path)
    policy = _POLICY
    if line_ends == "crlf":
        policy = tmp_path / "policy-crlf.yaml"
        policy.write_bytes(_POLICY.read_bytes().replace(b"\n", b"\r\n"))
    if existing is not None:
        (project / ".agent-audit-kit.yml").write_bytes(existing)
    monkeypatch.chdir(project)

    result = CliRunner().invoke(cli, ["pipelock", "import", str(policy)])

    assert (result.exit_code, result.output) == (0, "wrote .agent-audit-kit.yml\n")
    assert (project / ".agent-audit-kit.yml").read_bytes() == _AS_WRITTEN


def test_pipelock_import_writes_a_named_output_where_the_user_says(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`-o` names the path on the command line, like `scan -o`, so it is written where
    it leads, a link included; only the default target, which the current directory's
    contents decide, goes through the project checks."""
    project, outside = _projects(tmp_path)
    (project / "out.yml").symlink_to(outside / "chosen.yml")
    monkeypatch.chdir(project)

    result = CliRunner().invoke(cli, ["pipelock", "import", str(_POLICY), "-o", "out.yml"])

    assert (result.exit_code, result.output) == (0, "wrote out.yml\n")
    assert (outside / "chosen.yml").read_bytes() == _AS_WRITTEN
