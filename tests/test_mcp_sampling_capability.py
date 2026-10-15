"""AAK-MCP-SAMPLING-001 — sampling-without-consent detection tests."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agent_audit_kit.scanners import mcp_sampling_capability

FIXTURES = Path(__file__).parent / "fixtures" / "mcp_sampling"
RULE_ID = "AAK-MCP-SAMPLING-001"


def _copy(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for entry in src.iterdir():
        target = dst / entry.name
        if entry.is_dir():
            _copy(entry, target)
        else:
            shutil.copy2(entry, target)


def test_python_sampling_without_consent_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_python", tmp_path)
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_ID]
    assert matches, "expected AAK-MCP-SAMPLING-001 to fire on unguarded Python sampling"
    assert any(m.file_path.endswith("server.py") for m in matches)


def test_python_sampling_with_elicit_suppresses(tmp_path: Path) -> None:
    _copy(FIXTURES / "clean_python", tmp_path)
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    assert not any(f.rule_id == RULE_ID for f in findings), \
        "elicit_input consent marker must suppress AAK-MCP-SAMPLING-001"


def test_typescript_sampling_without_consent_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_typescript", tmp_path)
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_ID]
    assert matches, "expected AAK-MCP-SAMPLING-001 to fire on unguarded TS sampling"
    assert any(m.file_path.endswith("server.ts") for m in matches)


def test_documented_risk_suppresses(tmp_path: Path) -> None:
    _copy(FIXTURES / "documented_risk", tmp_path)
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    assert not any(f.rule_id == RULE_ID for f in findings), \
        ".agent-audit-kit.yml accepts_sampling_risk must suppress the finding"


def test_config_sampling_without_consent_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "config_vulnerable", tmp_path)
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_ID]
    assert matches, "expected AAK-MCP-SAMPLING-001 to fire on .mcp.json sampling declaration"
    assert all(m.file_path.endswith(".mcp.json") for m in matches)


def test_config_sampling_with_consent_suppresses(tmp_path: Path) -> None:
    _copy(FIXTURES / "config_clean", tmp_path)
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    assert not any(f.rule_id == RULE_ID for f in findings), \
        "requires_consent flag on .mcp.json server entry must suppress the finding"


def test_no_sdk_no_finding(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("click>=8.1\n", encoding="utf-8")
    (tmp_path / "server.py").write_text(
        "# Code mentions CreateMessageRequestSchema but no SDK is declared\n"
        "CreateMessageRequestSchema = None\n",
        encoding="utf-8",
    )
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    assert not any(f.rule_id == RULE_ID for f in findings)


def test_sdk_without_sampling_marker_is_quiet(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mcp>=1.0\n", encoding="utf-8")
    (tmp_path / "server.py").write_text(
        "from mcp.server import Server\n"
        "server = Server('non-sampling')\n",
        encoding="utf-8",
    )
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    assert not any(f.rule_id == RULE_ID for f in findings)


def test_prose_mention_does_not_fire(tmp_path: Path) -> None:
    """Bare prose mentioning the word `sampling` must not trip the rule —
    we only fire on tight protocol/SDK markers."""
    (tmp_path / "requirements.txt").write_text("mcp>=1.0\n", encoding="utf-8")
    (tmp_path / "server.py").write_text(
        "from mcp.server import Server\n"
        "# This server does NOT use sampling — sampling is mentioned only\n"
        "# for documentation purposes.\n"
        "server = Server('docs-only')\n",
        encoding="utf-8",
    )
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    assert not any(f.rule_id == RULE_ID for f in findings)


def test_finding_carries_owasp_mapping(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_python", tmp_path)
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    match = next((f for f in findings if f.rule_id == RULE_ID), None)
    assert match is not None
    # A server steering the client's LLM through sampling is OWASP MCP06 (Intent
    # Flow Subversion) and ASI01 (Agent Goal Hijack); the missing consent gate is
    # ASI09's first mitigation. MCP07/ASI03 (authentication) never fit.
    assert match.owasp_mcp_references == ["MCP06:2025"]
    assert match.owasp_agentic_references == ["ASI01", "ASI09"]


_SAMPLER = (
    "async def ask(ctx, text):\n"
    "    return await ctx.session.create_message(messages=[text], max_tokens=64)\n"
)


def test_the_source_half_runs_for_a_versioned_pyproject_dependency(tmp_path: Path) -> None:
    """The SDK gate took pyproject.toml only as the bare quoted "mcp", so the way
    most servers declare it, with extras and a version, kept this half off."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "d"\ndependencies = ["mcp[cli]>=1.2.0"]\n', encoding="utf-8"
    )
    (tmp_path / "sampler.py").write_text(_SAMPLER, encoding="utf-8")
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    assert [f.file_path for f in findings if f.rule_id == RULE_ID] == ["sampler.py"]


def _vscode_config(root: Path, server: dict) -> None:
    import json

    (root / ".vscode").mkdir(exist_ok=True)
    (root / ".vscode" / "mcp.json").write_text(json.dumps({"servers": {"samp": server}}), encoding="utf-8")


def test_the_config_half_reads_a_vscode_server(tmp_path: Path) -> None:
    """.vscode/mcp.json is in the config half's own file list, but VS Code keeps
    its servers under `servers` and only `mcpServers` was read."""
    _vscode_config(tmp_path, {"command": "node", "args": ["server.js"], "capabilities": ["sampling"]})
    findings, scanned = mcp_sampling_capability.scan(tmp_path)
    assert [f.file_path for f in findings if f.rule_id == RULE_ID] == [".vscode/mcp.json"]
    assert ".vscode/mcp.json" in scanned


def test_the_config_half_honours_a_vscode_consent_flag(tmp_path: Path) -> None:
    _vscode_config(tmp_path, {"command": "node", "capabilities": {"sampling": {}}, "requires_consent": True})
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    assert not any(f.rule_id == RULE_ID for f in findings)


def test_the_config_half_ignores_a_vscode_server_without_sampling(tmp_path: Path) -> None:
    _vscode_config(tmp_path, {"command": "node", "capabilities": ["tools"]})
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    assert not any(f.rule_id == RULE_ID for f in findings)


def test_the_source_half_stays_off_without_an_sdk(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "d"\ndependencies = ["httpx>=0.27"]\n', encoding="utf-8"
    )
    (tmp_path / "sampler.py").write_text(_SAMPLER, encoding="utf-8")
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    assert not any(f.rule_id == RULE_ID for f in findings)


def _declare_sdk_and_write(root: Path, name: str, source: str) -> list[str]:
    (root / "requirements.txt").write_text("mcp\n", encoding="utf-8")
    (root / name).write_text(source, encoding="utf-8")
    findings, _ = mcp_sampling_capability.scan(root)
    return [f.file_path for f in findings if f.rule_id == RULE_ID]


@pytest.mark.parametrize(("name", "source", "fires"), [
    ("caps.ts", "const server = new Server(info, { capabilities: { sampling: {} } });\n", True),
    ("caps.ts", "const caps = {\n  capabilities: {\n    sampling: {},\n  },\n};\n", True),
    # The word `capabilities` inside the object is not an opener, so the read
    # goes past it.
    ("caps.ts", "capabilities: {\n  // advertise sampling capabilities\n  sampling: {},\n}\n", True),
    ("caps.ts", "const c = { capabilities: { experimental_capabilities: [], sampling: {} } };\n", True),
    # Named after the first closing brace or parenthesis: not read (the limitation).
    ("caps.ts", "const c = { capabilities: { roots: { listChanged: true }, sampling: {} } };\n", False),
    ("caps.py", "caps = ServerCapabilities(sampling={})\n", True),
    ("caps.py", "caps = ServerCapabilities(tools=ToolsCapability(), sampling={})\n", False),
])
def test_the_capability_markers_read_up_to_the_first_closer(
    tmp_path: Path, name: str, source: str, fires: bool
) -> None:
    assert _declare_sdk_and_write(tmp_path, name, source) == ([name] if fires else [])


@pytest.mark.parametrize("unit", ["capabilities: {", "ServerCapabilities("])
def test_a_crafted_source_file_scans_in_linear_time(tmp_path: Path, unit: str) -> None:
    """1 MB of a capability opener with no closer. Each opener rescanned to the
    first closer, so 400,000 characters of `capabilities: {` took 4.4 seconds and
    the time grew with the square of the file. The bound is loose for slow CI
    runners; the linear scan takes milliseconds."""
    import time

    started = time.perf_counter()
    hits = _declare_sdk_and_write(tmp_path, "caps.ts", unit * (1_000_000 // len(unit)))
    assert time.perf_counter() - started < 5.0
    assert hits == []
