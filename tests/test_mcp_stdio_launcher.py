"""Tests for AAK-MCP-STDIO-LAUNCHER-INJECT-001 (CVE-2026-40933 class).

An MCP stdio server definition that launches a shell-style interpreter
(npx/node/bash/sh/python) with a code-exec flag (-c/-e/--eval), or passes a
non-pinned interpolation token (${...} embedded, {{...}}, %s) in argv, is an
arbitrary-code sink. Flowise < 3.1.0 serialised stdio commands unsafely so an
authenticated actor could combine `npx` with `-c` for RCE (CWE-78, CVSS 9.9).

Fixtures pin the contract: `npx -c "<interpolated>"` fires; a pinned static
`command:["my-server"], args:["--port","8080"]` passes; a read-only HTTP MCP
config passes.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_stdio_launcher import scan

RULE_ID = "AAK-MCP-STDIO-LAUNCHER-INJECT-001"


def _write(tmp_path: Path, obj: object, name: str = ".mcp.json") -> None:
    (tmp_path / name).write_text(json.dumps(obj, indent=2), encoding="utf-8")


def _hits(findings: list) -> list:
    return [f for f in findings if f.rule_id == RULE_ID]


# ---------------------------------------------------------------------------
# Rule registration
# ---------------------------------------------------------------------------


def test_rule_is_registered_with_cve_anchor() -> None:
    assert RULE_ID in RULES
    rule = RULES[RULE_ID]
    assert rule.severity.value == "high"
    assert "CVE-2026-40933" in rule.cve_references
    assert "MCP04:2025" in rule.owasp_mcp_references


# ---------------------------------------------------------------------------
# Vulnerable — must fire.
# ---------------------------------------------------------------------------


def test_npx_dash_c_interpolated_is_flagged(tmp_path: Path) -> None:
    """The CVE-2026-40933 shape: npx -c with an interpolated payload."""
    _write(tmp_path, {"mcpServers": {"evil": {
        "command": "npx",
        "args": ["-c", "require('child_process').exec('${PAYLOAD}')"],
    }}})
    findings, scanned = scan(tmp_path)
    assert ".mcp.json" in scanned
    hits = _hits(findings)
    assert hits, f"npx -c interpolated should fire {RULE_ID}"
    assert "evil" in hits[0].evidence


def test_inline_command_string_npx_dash_c_is_flagged(tmp_path: Path) -> None:
    """Launcher + flag packed into a single `command` string (no args split)."""
    _write(tmp_path, {"mcpServers": {"x": {"command": "npx -c 'boom'"}}})
    findings, _ = scan(tmp_path)
    assert _hits(findings), "inline 'npx -c' command should fire"


def test_node_eval_is_flagged(tmp_path: Path) -> None:
    _write(tmp_path, {"mcpServers": {"n": {
        "command": "node", "args": ["-e", "process.exit(0)"],
    }}})
    findings, _ = scan(tmp_path)
    assert _hits(findings), "node -e should fire"


def test_bash_dash_c_is_flagged(tmp_path: Path) -> None:
    _write(tmp_path, {"mcpServers": {"b": {
        "command": "bash", "args": ["-c", "echo hi"],
    }}})
    findings, _ = scan(tmp_path)
    assert _hits(findings), "bash -c should fire"


def test_interpolation_token_without_exec_flag_is_flagged(tmp_path: Path) -> None:
    """Arm 2: a templating token in argv fires even without an exec flag."""
    _write(tmp_path, {"mcpServers": {"t": {
        "command": "my-server", "args": ["--cmd={{user_input}}"],
    }}})
    findings, _ = scan(tmp_path)
    assert _hits(findings), "{{...}} templating in argv should fire"


def test_printf_token_is_flagged(tmp_path: Path) -> None:
    _write(tmp_path, {"mcpServers": {"p": {
        "command": "my-server", "args": ["--fmt=%s"],
    }}})
    findings, _ = scan(tmp_path)
    assert _hits(findings), "%s in argv should fire"


def test_embedded_env_interpolation_is_flagged(tmp_path: Path) -> None:
    """A ${...} embedded in a larger string is not a pinned literal."""
    _write(tmp_path, {"mcpServers": {"e": {
        "command": "my-server", "args": ["--path=/data/${USER_INPUT}/x"],
    }}})
    findings, _ = scan(tmp_path)
    assert _hits(findings), "embedded ${...} should fire"


# ---------------------------------------------------------------------------
# Safe — must pass.
# ---------------------------------------------------------------------------


def test_pinned_static_args_pass(tmp_path: Path) -> None:
    """Pinned executable + static literal args (the remediation form)."""
    _write(tmp_path, {"mcpServers": {"good": {
        "command": ["my-server"], "args": ["--port", "8080"],
    }}})
    findings, scanned = scan(tmp_path)
    assert ".mcp.json" in scanned
    assert not _hits(findings), "pinned static config must produce zero findings"


def test_standalone_env_reference_passes(tmp_path: Path) -> None:
    """A standalone ${VAR} is host-resolved and pinned — must not fire."""
    _write(tmp_path, {"mcpServers": {"g": {
        "command": "my-server", "args": ["--token", "${GITHUB_TOKEN}"],
    }}})
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "standalone ${VAR} env ref must not fire"


def test_http_mcp_config_passes(tmp_path: Path) -> None:
    """A read-only HTTP MCP server (url, no command) is out of scope."""
    _write(tmp_path, {"mcpServers": {"remote": {
        "url": "https://api.example.com/mcp",
        "headers": {"Authorization": "Bearer ${TOKEN}"},
    }}})
    findings, scanned = scan(tmp_path)
    assert ".mcp.json" in scanned
    assert not _hits(findings), "HTTP MCP config must not fire"


def test_plain_launcher_without_flag_passes(tmp_path: Path) -> None:
    """`npx some-package` with static args (no -c/-e) must not fire here —
    that surface is AAK-MCP-005's job, not launcher-injection."""
    _write(tmp_path, {"mcpServers": {"pkg": {
        "command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/data"],
    }}})
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "npx <pkg> without an exec flag must not fire"
