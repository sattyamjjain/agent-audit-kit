"""AAK-ANTHROPIC-SDK-001 — OX-MCP-2026-04-15 inheritance check tests."""

from __future__ import annotations

import shutil
from pathlib import Path

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
