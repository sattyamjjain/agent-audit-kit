"""Tests for AAK-MCP-UFO-CVE-2026-73296-001 (Microsoft UFO mobile MCP servers).

UFO before 3.0.8 serves `create_mobile_data_collection_server` (TCP 8020) and
`create_mobile_action_server` (TCP 8021) over Streamable HTTP with no inbound
authentication, giving an unauthenticated remote caller the ADB-backed device
tools. UFO ships as a git checkout, not a PyPI/npm artifact, so this is a
detection rule rather than a pin-table row.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.ufo_mobile_mcp import scan

RULE = "AAK-MCP-UFO-CVE-2026-73296-001"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-73296-ufo"


def _ids(root: Path) -> set[str]:
    return {f.rule_id for f in scan(root)[0]}


def _write(tmp_path: Path, name: str, content: str) -> Path:
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return tmp_path


# --- rule registration ------------------------------------------------------


def test_rule_is_registered() -> None:
    assert RULE in RULES
    rule = RULES[RULE]
    assert rule.severity.value == "critical"
    assert rule.category.value == "mcp-config"
    assert "CVE-2026-73296" in rule.cve_references


def test_scanner_always_reports_the_rule_as_evaluated(tmp_path: Path) -> None:
    assert scan(tmp_path)[1] == {RULE}


# --- fixtures ---------------------------------------------------------------


def test_fixtures_positive_and_negative() -> None:
    assert RULE in _ids(FIXTURES / "vulnerable")
    assert RULE not in _ids(FIXTURES / "negative")


# --- vendored source path ---------------------------------------------------


def test_vendored_server_without_auth_fires(tmp_path: Path) -> None:
    src = (
        "from mcp.server.fastmcp import FastMCP\n"
        "def create_mobile_action_server(device):\n"
        "    server = FastMCP('ufo-mobile-action')\n"
        "    return server\n"
        "uvicorn.run(create_mobile_action_server(d).streamable_http_app(),"
        " host='0.0.0.0', port=8021)\n"
    )
    assert RULE in _ids(_write(tmp_path, "mobile_mcp_server.py", src))


def test_vendored_server_with_bearer_auth_clears(tmp_path: Path) -> None:
    src = (
        "from mcp.server.fastmcp import FastMCP\n"
        "def create_mobile_action_server(device, token):\n"
        "    server = FastMCP('ufo-mobile-action', auth=BearerAuth(token))\n"
        "    return server\n"
        "uvicorn.run(create_mobile_action_server(d, t).streamable_http_app(),"
        " host='0.0.0.0', port=8021)\n"
    )
    assert RULE not in _ids(_write(tmp_path, "mobile_mcp_server.py", src))


def test_loopback_only_server_clears(tmp_path: Path) -> None:
    src = (
        "def create_mobile_data_collection_server(device):\n"
        "    return FastMCP('ufo-mobile-data-collection')\n"
        "uvicorn.run(app, host='127.0.0.1', port=8020)\n"
    )
    assert RULE not in _ids(_write(tmp_path, "server.py", src))


def test_unrelated_mcp_server_is_not_flagged(tmp_path: Path) -> None:
    """The rule is UFO-specific; a generic no-auth MCP server is another rule's job."""
    src = (
        "from mcp.server.fastmcp import FastMCP\n"
        "server = FastMCP('some-other-server')\n"
        "uvicorn.run(server.streamable_http_app(), host='0.0.0.0', port=8020)\n"
    )
    assert RULE not in _ids(_write(tmp_path, "other_server.py", src))


# --- config path ------------------------------------------------------------


def test_mcp_config_pointing_at_mobile_ports_fires(tmp_path: Path) -> None:
    cfg = (
        '{"mcpServers": {"ufo-mobile-action": '
        '{"url": "http://0.0.0.0:8021/mcp", '
        '"tools": ["tap", "swipe", "capture_screenshot"]}}}'
    )
    assert RULE in _ids(_write(tmp_path, ".mcp.json", cfg))


def test_mcp_config_with_bearer_header_clears(tmp_path: Path) -> None:
    cfg = (
        '{"mcpServers": {"ufo-mobile-action": '
        '{"url": "http://0.0.0.0:8021/mcp", '
        '"headers": {"Authorization": "Bearer ${UFO_TOKEN}"}, '
        '"tools": ["tap", "capture_screenshot"]}}}'
    )
    assert RULE not in _ids(_write(tmp_path, ".mcp.json", cfg))


def test_bare_port_without_ufo_context_clears(tmp_path: Path) -> None:
    """8020 alone must not carry a finding."""
    cfg = '{"services": {"metrics": {"url": "http://0.0.0.0:8020/healthz"}}}'
    assert RULE not in _ids(_write(tmp_path, "compose.yml", cfg))


# --- dependency path --------------------------------------------------------


def test_git_dependency_below_fix_fires(tmp_path: Path) -> None:
    assert RULE in _ids(
        _write(tmp_path, "requirements.txt", "git+https://github.com/microsoft/UFO@3.0.7\n")
    )


def test_git_dependency_at_fix_clears(tmp_path: Path) -> None:
    assert RULE not in _ids(
        _write(tmp_path, "requirements.txt", "git+https://github.com/microsoft/UFO@3.0.8\n")
    )


def test_git_dependency_above_fix_clears(tmp_path: Path) -> None:
    assert RULE not in _ids(
        _write(tmp_path, "requirements.txt", "git+https://github.com/microsoft/UFO@3.1.0\n")
    )


def test_unpinned_git_dependency_fires(tmp_path: Path) -> None:
    assert RULE in _ids(
        _write(tmp_path, "requirements.txt", "git+https://github.com/microsoft/UFO\n")
    )
