"""The image runs the CLI; the GitHub Action selects its bridge itself.

Through 0.6.9 the Dockerfile's ENTRYPOINT was ``entrypoint.sh``, the GitHub
Action bridge, which reads its positional arguments as the Action's inputs
(``$1`` path, ``$2`` severity, ...). Every documented ``docker run IMAGE
<command>`` therefore handed the bridge a CLI command line: ``docker run IMAGE
scan /project`` ran ``agent-audit-kit scan scan --severity /project`` and exited
2 on the severity choice, and a GitLab job's ``sh -c`` became path ``sh``,
severity ``-c``. The Action is the only caller that speaks the bridge's
argument order, so it is the one that asks for it (``runs.entrypoint``).
"""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

import yaml

from agent_audit_kit.cli import cli

REPO = Path(__file__).resolve().parent.parent
IMAGE = "ghcr.io/sattyamjjain/agent-audit-kit"


def _dockerfile() -> str:
    return (REPO / "Dockerfile").read_text(encoding="utf-8")


def _workflow_steps(name: str, job: str) -> list[dict]:
    doc = yaml.safe_load((REPO / ".github" / "workflows" / name).read_text(encoding="utf-8"))
    return doc["jobs"][job]["steps"]


def test_the_image_runs_the_cli() -> None:
    lines = [ln for ln in _dockerfile().splitlines() if ln.startswith("ENTRYPOINT")]
    assert len(lines) == 1
    assert json.loads(lines[0].split(None, 1)[1]) == ["agent-audit-kit"]


def test_the_action_selects_the_bridge() -> None:
    runs = yaml.safe_load((REPO / "action.yml").read_text(encoding="utf-8"))["runs"]
    assert runs["image"] == "Dockerfile"
    assert runs["entrypoint"] == "/entrypoint.sh"
    assert re.search(r"^COPY entrypoint\.sh /entrypoint\.sh$", _dockerfile(), re.M)


def _documented_docker_runs() -> list[tuple[str, list[str]]]:
    """``(file, arguments after the image)`` for each documented ``docker run``."""
    files = [REPO / "README.md", *sorted((REPO / "docs").rglob("*.md")),
             *sorted((REPO / "examples").rglob("*.sh"))]
    runs: list[tuple[str, list[str]]] = []
    for path in files:
        for line in path.read_text(encoding="utf-8").splitlines():
            if "docker run" not in line or IMAGE not in line:
                continue
            words = shlex.split(line)
            at = next(i for i, w in enumerate(words) if w.startswith(IMAGE))
            runs.append((str(path.relative_to(REPO)), words[at + 1:]))
    return runs


def test_every_documented_docker_run_is_a_cli_command() -> None:
    runs = _documented_docker_runs()
    assert runs, "no documented `docker run` of the image; the guard would be vacuous"
    for where, args in runs:
        assert args and (args[0] in cli.commands or args[0] in ("--version", "--help")), (
            f"{where}: `docker run {IMAGE} {' '.join(args)}` is not a CLI command line"
        )


def test_the_release_image_runs_a_documented_command_before_it_is_pushed() -> None:
    names = [s.get("name", "") for s in _workflow_steps("release.yml", "docker")]
    smoke = next(i for i, n in enumerate(names) if n.startswith("Smoke-test"))
    assert smoke < names.index("Build and push")
    run = _workflow_steps("release.yml", "docker")[smoke]["run"]
    assert "agent-audit-kit:scan scan /project" in run


def test_the_nightly_image_runs_a_documented_command() -> None:
    steps = _workflow_steps("docker-nightly.yml", "rebuild")
    smoke = [s for s in steps if s.get("name", "").startswith("Smoke-test")]
    assert len(smoke) == 1
    assert "scan /project" in smoke[0]["run"]
