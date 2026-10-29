"""AAK-AGENT-SERVER-NOAUTH-001: OpenHands sandbox agent servers started without a session key.

CVE-2026-112346: the OpenHands Software Agent SDK's DockerWorkspace and
ApptainerWorkspace start the agent server with `--host 0.0.0.0` and take its key
only from the `OH_SESSION_API_KEYS_0` or `SESSION_API_KEY` environment variable
(the launchers have no keyword for it). 1.52.0 publishes the Docker port on
127.0.0.1 and changed nothing else. Every source below is a placeholder that
constructs a launcher; nothing is run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.agent_server_noauth import FIXED, RULE, scan

_DOCKER = 'from openhands.workspace import DockerWorkspace\n\nworkspace = DockerWorkspace(server_image="x", host_port=8010)\n'
_APPTAINER = 'from openhands.workspace import ApptainerWorkspace\n\nworkspace = ApptainerWorkspace(server_image="x")\n'


def _found(root: Path) -> list[tuple[str, int | None, Severity]]:
    findings, _ = scan(root)
    assert all(f.rule_id == RULE for f in findings)
    return [(f.file_path, f.line_number, f.severity) for f in findings]


def _lock(root: Path, version: str, name: str = "openhands-workspace") -> None:
    (root / "uv.lock").write_text(f'[[package]]\nname = "{name}"\nversion = "{version}"\n')


def test_the_rule_names_the_cve_and_is_high() -> None:
    rule = RULES[RULE]
    assert rule.severity is Severity.HIGH and rule.cve_references == ["CVE-2026-112346"]
    assert FIXED == "1.52.0"


# ---- Python launchers ------------------------------------------------------------------------------


def test_a_docker_launch_without_a_key_fires_medium_when_the_release_is_unknown(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(_DOCKER)
    findings, scanned = scan(tmp_path)
    assert [(f.file_path, f.line_number, f.severity) for f in findings] == [("agent.py", 3, Severity.MEDIUM)]
    assert "nothing in this file sets SESSION_API_KEY or OH_SESSION_API_KEYS_0" in findings[0].evidence
    assert "below 1.52.0 it is published on every interface" in findings[0].evidence
    assert scanned == {"agent.py"}


@pytest.mark.parametrize(
    "version, name, severity",
    [("1.51.0", "openhands-workspace", Severity.HIGH), ("1.51.0", "openhands-sdk", Severity.HIGH),
     ("1.52.0", "openhands-workspace", Severity.MEDIUM), ("1.59.0", "openhands-sdk", Severity.MEDIUM)],
)
def test_a_docker_launch_is_high_below_1_52_0(tmp_path: Path, version: str, name: str, severity: Severity) -> None:
    (tmp_path / "agent.py").write_text(_DOCKER)
    _lock(tmp_path, version, name)
    ((_file, _line, found),) = _found(tmp_path)
    assert found is severity


def test_the_message_says_what_1_52_0_changed(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(_DOCKER)
    _lock(tmp_path, "1.51.0")
    (high,) = scan(tmp_path)[0]
    assert "publishes port 8000 on every host interface" in high.evidence
    assert "Upgrade to 1.52.0 or later, which publishes it on 127.0.0.1" in high.evidence
    _lock(tmp_path, "1.52.0")
    (medium,) = scan(tmp_path)[0]
    assert "publishes port 8000 on 127.0.0.1 only, so the keyless server is reachable from this host alone" in (
        medium.evidence)


def test_an_apptainer_launch_is_high_in_every_release(tmp_path: Path) -> None:
    """1.52.0 changed only the Docker launcher; ApptainerWorkspace binds 0.0.0.0 on
    the host's network through 1.59.0."""
    (tmp_path / "agent.py").write_text(_APPTAINER)
    _lock(tmp_path, "1.59.0")
    (finding,) = scan(tmp_path)[0]
    assert finding.severity is Severity.HIGH
    assert "binds every interface in every release through 1.59.0" in finding.evidence


@pytest.mark.parametrize(
    "setter",
    [
        'os.environ["SESSION_API_KEY"] = secrets.token_urlsafe(32)',
        'os.environ["OH_SESSION_API_KEYS_0"] = load_key()',
        'os.environ.setdefault("SESSION_API_KEY", load_key())',
        'os.environ.update({"OH_SESSION_API_KEYS_0": load_key()})',
        "os.environ.update(SESSION_API_KEY=load_key())",
        'os.putenv("SESSION_API_KEY", load_key())',
    ],
)
def test_a_launch_with_a_session_key_set_is_clean(tmp_path: Path, setter: str) -> None:
    (tmp_path / "agent.py").write_text("import os\nimport secrets\n" + setter + "\n" + _DOCKER)
    assert _found(tmp_path) == []


def test_a_forward_env_that_leaves_the_keys_out_fires_even_with_a_key_set(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        'import os\nos.environ["SESSION_API_KEY"] = "k"\nfrom openhands.workspace import DockerWorkspace\n'
        'DockerWorkspace(server_image="x", forward_env=["DEBUG"])\n')
    (finding,) = scan(tmp_path)[0]
    assert "its `forward_env` leaves out SESSION_API_KEY and OH_SESSION_API_KEYS_0" in finding.evidence


@pytest.mark.parametrize(
    "source",
    [
        "from openhands.workspace import DockerWorkspace as DW\nDW(server_image='x')\n",
        "import openhands.workspace as ow\now.DockerWorkspace(server_image='x')\n",
        "import openhands.workspace\nopenhands.workspace.DockerWorkspace(server_image='x')\n",
        "from openhands.workspace.docker import DockerWorkspace\nDockerWorkspace(server_image='x')\n",
        "from openhands.workspace import docker\ndocker.DockerWorkspace(server_image='x')\n",
        "from openhands.workspace.docker.dev_workspace import DockerDevWorkspace\nDockerDevWorkspace(base_image='x')\n",
        "from openhands.workspace.apptainer import ApptainerWorkspace\nApptainerWorkspace(sif_file='x.sif')\n",
    ],
)
def test_every_import_form_of_a_launcher_is_read(tmp_path: Path, source: str) -> None:
    (tmp_path / "agent.py").write_text(source)
    assert len(_found(tmp_path)) == 1


@pytest.mark.parametrize(
    "source",
    [
        "from mylib import DockerWorkspace\nDockerWorkspace(server_image='x')\n",  # another package's class of that name
        "from openhands.workspace import DockerWorkspace\nDockerWorkspace(**options)\n",
        "from openhands.workspace import DockerWorkspace\nDockerWorkspace(forward_env=FORWARDED)\n",
        "from openhands.workspace import APIRemoteWorkspace\nAPIRemoteWorkspace(runtime_api_url='x')\n",
    ],
)
def test_what_is_not_judged(tmp_path: Path, source: str) -> None:
    (tmp_path / "agent.py").write_text(source)
    assert _found(tmp_path) == []


# ---- compose services and docker run --------------------------------------------------------------


def _compose(ports: str, extra: str = "", image: str = "ghcr.io/openhands/agent-server:latest-python") -> str:
    return f"services:\n  agent:\n    image: {image}\n    ports:\n{ports}{extra}"


@pytest.mark.parametrize(
    "ports, extra, fires",
    [
        ('      - "8000:8000"\n', "", True),
        ('      - "0.0.0.0:8000:8000"\n', "", True),
        ("      - 8000\n", "", True),
        ('      - "8000-8001:8000-8001"\n', "", True),
        ("      - target: 8000\n        published: 8000\n", "", True),
        ('      - "127.0.0.1:8000:8000"\n', "", False),
        ('      - "[::1]:8000:8000"\n', "", False),
        ("      - target: 8000\n        host_ip: 127.0.0.1\n", "", False),
        ('      - "9000:80"\n', "", False),
        ('      - "8000:8000"\n', "    environment:\n      OH_SESSION_API_KEYS_0: ${KEY}\n", False),
        ('      - "8000:8000"\n', "    environment:\n      - SESSION_API_KEY=${KEY}\n", False),
        ('      - "8000:8000"\n', "    env_file: .env.agent\n", False),
    ],
)
def test_a_compose_service_publishing_the_agent_server(tmp_path: Path, ports: str, extra: str, fires: bool) -> None:
    (tmp_path / "compose.yaml").write_text(_compose(ports, extra))
    found = _found(tmp_path)
    assert bool(found) is fires
    if fires:
        assert found == [("compose.yaml", 2, Severity.MEDIUM)]


def test_a_compose_service_of_another_image_is_not_read(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.yml").write_text(_compose('      - "8000:8000"\n', image="example/agent-server:1"))
    assert _found(tmp_path) == []


@pytest.mark.parametrize(
    "script, fires",
    [
        ("docker run -d -p 8000:8000 ghcr.io/openhands/agent-server:latest\n", True),
        ("docker run -d \\\n  --publish=8000:8000 \\\n  ghcr.io/openhands/agent-server:latest\n", True),
        ("podman run -p 8001:8001 ghcr.io/openhands/agent-server:latest\n", True),
        ("docker run -d -p 127.0.0.1:8000:8000 ghcr.io/openhands/agent-server:latest\n", False),
        ("docker run -d -e SESSION_API_KEY -p 8000:8000 ghcr.io/openhands/agent-server:latest\n", False),
        ("docker run -d --env-file agent.env -p 8000:8000 ghcr.io/openhands/agent-server:latest\n", False),
        ("docker pull ghcr.io/openhands/agent-server:latest\n", False),
    ],
)
def test_a_docker_run_in_a_shell_script(tmp_path: Path, script: str, fires: bool) -> None:
    (tmp_path / "start.sh").write_text("#!/bin/sh\n" + script)
    found = _found(tmp_path)
    assert bool(found) is fires
    if fires:
        assert found == [("start.sh", 2, Severity.MEDIUM)]


def test_the_engine_reports_it_with_the_registry_s_fields(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(_APPTAINER)
    (finding,) = [f for f in run_scan(project_root=tmp_path).findings if f.rule_id == RULE]
    assert finding.cve_references == ["CVE-2026-112346"] and finding.severity is Severity.HIGH


def test_each_service_is_placed_on_its_own_line(tmp_path: Path) -> None:
    """Two services publishing the same "8000:8000" are two alerts, not one folded line."""
    (tmp_path / "compose.yaml").write_text(
        "services:\n"
        "  one:\n    image: ghcr.io/openhands/agent-server:latest\n    ports: ['8000:8000']\n"
        "  two:\n    image: ghcr.io/openhands/agent-server:latest\n    ports: ['8000:8000']\n")
    assert _found(tmp_path) == [("compose.yaml", 2, Severity.MEDIUM), ("compose.yaml", 5, Severity.MEDIUM)]
