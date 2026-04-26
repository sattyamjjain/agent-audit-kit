"""AAK-AZURE-MCP-NOAUTH-001 — server-author side."""

from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners.mcp_server_auth import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-32211-server"


def test_vulnerable_server_fires(tmp_path: Path) -> None:
    shutil.copytree(FIXTURES, tmp_path, dirs_exist_ok=True)
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-AZURE-MCP-NOAUTH-001" for f in findings)


def test_with_auth_marker_passes(tmp_path: Path) -> None:
    shutil.copytree(FIXTURES, tmp_path, dirs_exist_ok=True)
    (tmp_path / "server.py").write_text(
        """
from fastapi import FastAPI, Header

app = FastAPI()


@app.post("/mcp/tools/run")
async def run_tool(payload: dict, Authorization: str = Header(...)) -> dict:
    verify_jwt(Authorization)
    return {"ok": True, "result": payload}
""",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-AZURE-MCP-NOAUTH-001" for f in findings)


def test_non_azure_repo_passes(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "regular-app"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )
    (tmp_path / "server.py").write_text(
        '@app.post("/mcp/tools/run")\nasync def f(): pass\n',
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-AZURE-MCP-NOAUTH-001" for f in findings)
