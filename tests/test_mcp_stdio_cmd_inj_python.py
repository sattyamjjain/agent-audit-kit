"""AAK-MCP-STDIO-CMD-INJ-001 — Python config-to-spawn taint."""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners.mcp_stdio_params import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "ox-mcp-stdio-class"


def test_vulnerable_python_fires(tmp_path: Path) -> None:
    (tmp_path / "vulnerable_py.py").write_text(
        (FIXTURES / "vulnerable_py.py").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-MCP-STDIO-CMD-INJ-001" for f in findings)


def test_patched_python_passes(tmp_path: Path) -> None:
    (tmp_path / "patched_py.py").write_text(
        (FIXTURES / "patched_py.py").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCP-STDIO-CMD-INJ-001" for f in findings)


def test_env_var_taint_fires(tmp_path: Path) -> None:
    (tmp_path / "env.py").write_text(
        "import os\n"
        "from mcp.client.stdio import StdioServerParameters\n"
        "def f():\n"
        "    cmd = os.environ['MCP_CMD']\n"
        "    return StdioServerParameters(command=cmd, args=[])\n",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-MCP-STDIO-CMD-INJ-001" for f in findings)


def test_constant_command_passes(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text(
        "from mcp.client.stdio import StdioServerParameters\n"
        "def f():\n"
        "    return StdioServerParameters(command='/usr/bin/server', args=[])\n",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCP-STDIO-CMD-INJ-001" for f in findings)
