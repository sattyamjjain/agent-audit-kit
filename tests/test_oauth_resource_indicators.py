"""Tests for AAK-OAUTH-007 — RFC 8707 Resource Indicators (`resource` parameter).

The ratified MCP 2025-11-25 authorization spec requires MCP clients to send the
RFC 8707 `resource` parameter on authorization + token requests so issued tokens
are audience-bound. The scanner fires when an OAuth token-acquisition flow is
present but the `resource` parameter is absent, and must stay silent (0 false
positives) when the flow sets `resource`.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.oauth_misconfig import scan

RULE = "AAK-OAUTH-007"


def _rule_ids(tmp_path: Path, name: str, content: str) -> set[str]:
    (tmp_path / name).write_text(content, encoding="utf-8")
    findings, _ = scan(tmp_path)
    return {f.rule_id for f in findings}


# ---------------------------------------------------------------------------
# Positive — a flow that omits the `resource` parameter must fire.
# ---------------------------------------------------------------------------


def test_fires_on_client_config_missing_resource(tmp_path: Path) -> None:
    content = json.dumps(
        {
            "oauth": {
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
                "client_id": "mcp-client",
                "grant_type": "authorization_code",
            }
        }
    )
    assert RULE in _rule_ids(tmp_path, "mcp_client.json", content)


def test_fires_on_python_token_request_missing_resource(tmp_path: Path) -> None:
    content = (
        "import httpx\n\n"
        'token_endpoint = "https://auth.example.com/token"\n\n'
        "def get_token(code: str) -> str:\n"
        "    resp = httpx.post(\n"
        "        token_endpoint,\n"
        '        data={"grant_type": "authorization_code", "code": code,\n'
        '              "code_verifier": verifier, "iss": issuer},\n'
        "    )\n"
        '    return resp.json()["access_token"]\n'
    )
    assert RULE in _rule_ids(tmp_path, "auth.py", content)


# ---------------------------------------------------------------------------
# Negative — a compliant flow that sets `resource` must NOT fire (0 FP).
# ---------------------------------------------------------------------------


def test_quiet_on_compliant_config_with_resource(tmp_path: Path) -> None:
    content = json.dumps(
        {
            "oauth": {
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
                "client_id": "mcp-client",
                "grant_type": "authorization_code",
                "resource": "https://mcp.example.com",
                "code_challenge_method": "S256",
            }
        }
    )
    assert RULE not in _rule_ids(tmp_path, "mcp_client.json", content)


def test_quiet_on_python_flow_setting_resource(tmp_path: Path) -> None:
    content = (
        "import httpx\n\n"
        'token_endpoint = "https://auth.example.com/token"\n\n'
        "def get_token(code: str) -> str:\n"
        "    resp = httpx.post(\n"
        "        token_endpoint,\n"
        '        data={"grant_type": "authorization_code", "code": code,\n'
        '              "resource": "https://mcp.example.com"},\n'
        "    )\n"
        '    return resp.json()["access_token"]\n'
    )
    assert RULE not in _rule_ids(tmp_path, "auth.py", content)


def test_quiet_on_server_protected_resource_metadata(tmp_path: Path) -> None:
    # RFC 9728 protected-resource-metadata carries a top-level `resource` field;
    # an MCP server advertising itself must not be flagged as a client missing
    # its resource indicator.
    content = json.dumps(
        {
            "resource": "https://mcp.example.com",
            "authorization_servers": ["https://auth.example.com"],
            "bearer_methods_supported": ["header"],
        }
    )
    assert RULE not in _rule_ids(tmp_path, ".well-known-oauth-protected-resource.json", content)


def test_quiet_without_oauth_token_flow(tmp_path: Path) -> None:
    # OAuth is mentioned but there is no token-acquisition flow to bind.
    content = "# oauth notes\nclient_id = 'demo'  # documentation only, no flow\n"
    assert RULE not in _rule_ids(tmp_path, "notes.py", content)


# ---------------------------------------------------------------------------
# Rule metadata.
# ---------------------------------------------------------------------------


def test_rule_registered_and_shaped() -> None:
    assert RULE in RULES
    rule = RULES[RULE]
    assert rule.severity.value == "medium"
    assert rule.category.value == "mcp-config"
    assert "MCP01:2025" in rule.owasp_mcp_references
    # The remediation must carry the concrete fix: set `resource` + audience-bind.
    assert "resource" in rule.remediation
    assert "8707" in rule.remediation
    assert rule.aicm_references == ["IAM-01", "IAM-16"]


# ---------------------------------------------------------------------------
# AAK-OAUTH-008 — RFC 9728 Protected Resource Metadata discovery gap.
# ---------------------------------------------------------------------------

PRM = "AAK-OAUTH-008"


def test_prm_fires_on_remote_config_with_embedded_bearer(tmp_path: Path) -> None:
    content = json.dumps(
        {"mcpServers": {"r": {"type": "http", "url": "https://api.x.com/mcp",
                              "headers": {"Authorization": "Bearer ${T}"}}}}
    )
    assert PRM in _rule_ids(tmp_path, "server.mcp.json", content)


def test_prm_fires_on_remote_config_with_oauth_block(tmp_path: Path) -> None:
    content = json.dumps(
        {"mcpServers": {"r": {"type": "sse", "url": "https://x/mcp", "auth": {"type": "oauth"}}}}
    )
    assert PRM in _rule_ids(tmp_path, "server.mcp.json", content)


def test_prm_quiet_when_protected_resource_metadata_present(tmp_path: Path) -> None:
    # A config that references RFC 9728 discovery must NOT be flagged (0 FP).
    content = json.dumps(
        {"mcpServers": {"r": {"type": "http", "url": "https://api.x.com/mcp",
                              "headers": {"Authorization": "Bearer t"},
                              "authorization_servers": ["https://as.x.com"]}}}
    )
    assert PRM not in _rule_ids(tmp_path, "server.mcp.json", content)


def test_prm_quiet_on_stdio_config(tmp_path: Path) -> None:
    content = json.dumps({"mcpServers": {"r": {"command": "python", "args": ["s.py"]}}})
    assert PRM not in _rule_ids(tmp_path, "server.mcp.json", content)


def test_prm_quiet_on_remote_config_without_auth(tmp_path: Path) -> None:
    # A public remote server with no embedded credential is not a PRM gap here.
    content = json.dumps({"mcpServers": {"r": {"type": "http", "url": "https://public.x.com/mcp"}}})
    assert PRM not in _rule_ids(tmp_path, "server.mcp.json", content)


def test_prm_fires_on_server_source_bearer_without_prm(tmp_path: Path) -> None:
    content = (
        "from fastmcp import FastMCP\n"
        "from fastmcp.server.auth import BearerAuthProvider\n"
        "mcp = FastMCP('demo', auth=BearerAuthProvider(public_key=KEY))\n"
    )
    assert PRM in _rule_ids(tmp_path, "server.py", content)


def test_prm_rule_registered_and_shaped() -> None:
    rule = RULES[PRM]
    assert rule.severity.value == "low"
    assert rule.category.value == "mcp-config"
    assert "MCP01:2025" in rule.owasp_mcp_references
    assert "9728" in rule.remediation
    assert rule.aicm_references == ["IAM-01", "IAM-16"]
