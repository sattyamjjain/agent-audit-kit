"""AAK-ANTHROPIC-SDK-001 — OX-MCP-2026-04-15 inheritance check tests."""

from __future__ import annotations

import shutil
import time
from pathlib import Path

import pytest

from agent_audit_kit.scanners import mcp_sdk_hardening

FIXTURES = Path(__file__).parent / "fixtures" / "incidents" / "ox-mcp-2026-04-15"


def _copy(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for entry in src.iterdir():
        target = dst / entry.name
        if entry.is_dir():
            _copy(entry, target)
        else:
            shutil.copy2(entry, target)


def test_python_unsanitized_stdio_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "python" / "vulnerable", tmp_path)
    findings, _ = mcp_sdk_hardening.scan(tmp_path)
    assert any(f.rule_id == "AAK-ANTHROPIC-SDK-001" for f in findings)


def test_python_sanitizer_suppresses(tmp_path: Path) -> None:
    _copy(FIXTURES / "python" / "sanitized", tmp_path)
    findings, _ = mcp_sdk_hardening.scan(tmp_path)
    assert not any(f.rule_id == "AAK-ANTHROPIC-SDK-001" for f in findings)


def test_typescript_unsanitized_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "typescript" / "vulnerable", tmp_path)
    findings, _ = mcp_sdk_hardening.scan(tmp_path)
    assert any(f.rule_id == "AAK-ANTHROPIC-SDK-001" for f in findings)


def test_typescript_sanitizer_suppresses(tmp_path: Path) -> None:
    _copy(FIXTURES / "typescript" / "sanitized", tmp_path)
    findings, _ = mcp_sdk_hardening.scan(tmp_path)
    assert not any(f.rule_id == "AAK-ANTHROPIC-SDK-001" for f in findings)


def test_documented_risk_suppresses(tmp_path: Path) -> None:
    _copy(FIXTURES / "documented-risk", tmp_path)
    findings, _ = mcp_sdk_hardening.scan(tmp_path)
    assert not any(f.rule_id == "AAK-ANTHROPIC-SDK-001" for f in findings)


def test_no_sdk_no_finding(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("click>=8.1\n", encoding="utf-8")
    (tmp_path / "server.py").write_text(
        "class StdioServerTransport: pass\n", encoding="utf-8"
    )
    findings, _ = mcp_sdk_hardening.scan(tmp_path)
    # No SDK declared → we should NOT fire even though the marker exists.
    assert not any(f.rule_id == "AAK-ANTHROPIC-SDK-001" for f in findings)


def test_sdk_without_stdio_is_quiet(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mcp>=1.0\n", encoding="utf-8")
    (tmp_path / "server.py").write_text(
        "# HTTP-only server\nclass HttpServer: pass\n", encoding="utf-8"
    )
    findings, _ = mcp_sdk_hardening.scan(tmp_path)
    assert not any(f.rule_id == "AAK-ANTHROPIC-SDK-001" for f in findings)


def test_http_opt_out_in_server_suppresses(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mcp>=1.0\n", encoding="utf-8")
    (tmp_path / "server.py").write_text(
        'class StdioServerTransport: pass\n'
        'transports = ["http"]\n',
        encoding="utf-8",
    )
    findings, _ = mcp_sdk_hardening.scan(tmp_path)
    assert not any(f.rule_id == "AAK-ANTHROPIC-SDK-001" for f in findings)


# --------------------------------------------------------------------------
# The SDK gate. This scanner kept its own copy of the gate after #989 fixed
# the stateless one: pyproject.toml counted only as the bare quoted "mcp", and
# a requirements line was cut at its first `=`. So "mcp[cli]>=1.2.0", Poetry's
# `mcp = "^1.2.0"` and `mcp~=1.2.0` never opened it, and an unsanitized STDIO
# server declared the usual way was never reported.
# --------------------------------------------------------------------------

_STDIO_SERVER = (
    "from mcp.server.stdio import stdio_server\n\n\n"
    "async def main(server):\n"
    "    async with stdio_server() as (read, write):\n"
    "        await server.run(read, write)\n"
)


def _gate_fires(root: Path, manifest: str, text: str) -> bool:
    (root / manifest).write_text(text, encoding="utf-8")
    (root / "server.py").write_text(_STDIO_SERVER, encoding="utf-8")
    findings, _ = mcp_sdk_hardening.scan(root)
    return any(f.rule_id == "AAK-ANTHROPIC-SDK-001" for f in findings)


@pytest.mark.parametrize(("manifest", "text"), [
    ("pyproject.toml", '[project]\nname = "d"\ndependencies = ["mcp[cli]>=1.2.0"]\n'),
    ("pyproject.toml", '[project]\nname = "d"\ndependencies = ["MCP>=1.2"]\n'),
    ("pyproject.toml", '[tool.poetry.dependencies]\npython = "^3.10"\nmcp = "^1.2.0"\n'),
    ("pyproject.toml", '[dependency-groups]\nserver = ["mcp>=1.2"]\n'),
    ("requirements.txt", "mcp~=1.2.0\n"),
    ("requirements.txt", 'mcp[cli]>=1.2 ; python_version >= "3.10"\n'),
    ("requirements-dev.txt", "MCP==1.2.0  # pinned\n"),
])
def test_the_sdk_gate_reads_real_manifests(tmp_path: Path, manifest: str, text: str) -> None:
    assert _gate_fires(tmp_path, manifest, text)


@pytest.mark.parametrize(("manifest", "text"), [
    ("pyproject.toml", '[project]\nname = "d"\ndependencies = ["mcp-proxy>=0.3"]\n'),
    ("requirements.txt", "mcp-server-git==0.6.2\n"),
    ("requirements.txt", "# mcp>=1.2\nclick>=8.1\n"),
])
def test_the_sdk_gate_stays_shut_for_other_distributions(
    tmp_path: Path, manifest: str, text: str
) -> None:
    assert not _gate_fires(tmp_path, manifest, text)


def test_the_sdk_gate_is_the_one_the_stateless_rules_use(tmp_path: Path) -> None:
    from agent_audit_kit.scanners import _helpers

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "d"\ndependencies = ["mcp[cli]>=1.2.0"]\n', encoding="utf-8"
    )
    (tmp_path / "server.py").write_text(_STDIO_SERVER, encoding="utf-8")
    _, scanned = mcp_sdk_hardening.scan(tmp_path)
    assert {"pyproject.toml", "server.py"} <= scanned
    assert mcp_sdk_hardening.declares_mcp_sdk is _helpers.declares_mcp_sdk


@pytest.mark.parametrize(("source", "hinted"), [
    ("execFile(cmd, [arg])", True),
    ("execFile(execFile(x), [y])", True),
    ("execFile(, [x])", False),
    ("execFile(cmd,\n  [arg])", True),
    ("execFile(cmd, arg)", False),
])
def test_execfile_argv_hint_keeps_its_shape(source: str, hinted: bool) -> None:
    assert bool(mcp_sdk_hardening._SANITIZER_HINTS[1].search(source)) is hinted


def test_the_execfile_hint_reads_a_crafted_file_in_linear_time() -> None:
    """1 MB of `execFile(` and no comma. Each call read the rest of the file:
    80 KB took 0.22 seconds and the time grew with the square. The bound is
    loose for slow CI runners."""
    started = time.perf_counter()
    mcp_sdk_hardening._SANITIZER_HINTS[1].search("execFile(" * 110_000)
    assert time.perf_counter() - started < 5.0
