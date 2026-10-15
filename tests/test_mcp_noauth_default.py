"""Tests for AAK-MCP-NOAUTH-DEFAULT (CVE-2026-48814, CWE-306/862).

An MCP server that ships an auth check which fails open on an empty/unset secret,
or ships a placeholder/default credential, is unauthenticated-by-default. Anchor:
CVE-2026-48814 (Network-AI) — an incomplete fix of CVE-2026-46701 whose auth gate
still admitted requests when the secret was unset.

Fixtures pin the contract: empty-secret + 0.0.0.0 bind FLAGS; non-empty secret +
loopback PASSES. Distinct from AAK-MCP-HTTP-NOAUTH-SERVER-001 (no-auth transport):
this rule keys on fail-open auth logic + default credentials.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit.models import ScanResult
from agent_audit_kit.output.sarif import format_results
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_noauth_default import scan

RULE_ID = "AAK-MCP-NOAUTH-DEFAULT"


def _write(tmp_path: Path, name: str, src: str) -> None:
    (tmp_path / name).write_text(src, encoding="utf-8")


def _hits(findings: list) -> list:
    return [f for f in findings if f.rule_id == RULE_ID]


# ---------------------------------------------------------------------------
# Rule registration
# ---------------------------------------------------------------------------


def test_rule_is_registered() -> None:
    assert RULE_ID in RULES
    rule = RULES[RULE_ID]
    assert rule.severity.value == "high"
    assert "CVE-2026-48814" in rule.cve_references
    assert "CVE-2026-46701" in rule.cve_references
    assert "CWE-306" in rule.description and "CWE-862" in rule.description
    assert "MCP07:2025" in rule.owasp_mcp_references


# ---------------------------------------------------------------------------
# Vulnerable — must FLAG
# ---------------------------------------------------------------------------


def test_fail_open_auth_and_empty_default_secret_flags(tmp_path: Path) -> None:
    """CVE-2026-48814 shape: empty-default secret + auth that fails open, 0.0.0.0."""
    _write(tmp_path, "server.py", '''
import os
from mcp.server.fastmcp import FastMCP

API_SECRET = os.environ.get("API_SECRET", "")   # ships unauthenticated
mcp = FastMCP("net-ai", host="0.0.0.0", port=8080)

def _is_authorized(token):
    if not API_SECRET:        # secret unset
        return True            # FAIL OPEN
    return token == API_SECRET
''')
    findings, scanned = scan(tmp_path)
    assert "server.py" in scanned
    assert _hits(findings), f"fail-open auth + empty-default secret must fire {RULE_ID}"


def test_placeholder_secret_literal_flags(tmp_path: Path) -> None:
    _write(tmp_path, "config.py", '''
from mcp.server import Server
server = Server("x")
AUTH_TOKEN = "changeme"   # placeholder credential
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "placeholder secret literal must fire"


def test_warn_only_gate_with_public_bind_flags(tmp_path: Path) -> None:
    _write(tmp_path, "boot.py", '''
import logging
from mcp.server.fastmcp import FastMCP

SECRET = load_secret()
mcp = FastMCP("x", host="0.0.0.0")
if not SECRET:
    logging.getLogger(__name__).warning("no secret configured; running open")
mcp.run(transport="streamable-http")
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "warn-only secret gate + 0.0.0.0 bind must fire"


def test_vulnerable_mcp_config_empty_secret_0000_flags(tmp_path: Path) -> None:
    """Vulnerable MCP-config sample: empty secret + 0.0.0.0 bind."""
    _write(tmp_path, "mcp.json", json.dumps({
        "mcpServers": {
            "net-ai": {
                "host": "0.0.0.0",
                "port": 8080,
                "env": {"API_SECRET": ""},
            }
        }
    }))
    findings, _ = scan(tmp_path)
    assert _hits(findings), "empty-secret + 0.0.0.0 MCP config must fire"


# ---------------------------------------------------------------------------
# Safe — must PASS
# ---------------------------------------------------------------------------


def test_required_secret_loopback_passes(tmp_path: Path) -> None:
    _write(tmp_path, "server.py", '''
import os
from mcp.server.fastmcp import FastMCP

API_SECRET = os.environ["API_SECRET"]   # required, no empty default
mcp = FastMCP("net-ai", host="127.0.0.1", port=8080)

def _is_authorized(token):
    return token == API_SECRET           # no fail-open branch
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "required secret + loopback + no fail-open must pass"


def test_safe_mcp_config_real_secret_loopback_passes(tmp_path: Path) -> None:
    """Safe MCP-config sample: non-empty secret + loopback bind."""
    _write(tmp_path, "mcp.json", json.dumps({
        "mcpServers": {
            "net-ai": {
                "host": "127.0.0.1",
                "port": 8080,
                "env": {"API_SECRET": "S3cretValue-not-a-placeholder-9f2a"},
            }
        }
    }))
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "real secret + loopback config must pass"


def test_non_mcp_file_with_placeholder_passes(tmp_path: Path) -> None:
    """A non-MCP module with a placeholder secret is out of scope here."""
    _write(tmp_path, "util.py", '''
API_TOKEN = "changeme"
def helper():
    return API_TOKEN
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "no MCP context -> must not fire"


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------


def test_sarif_carries_rule_and_remediation(tmp_path: Path) -> None:
    _write(tmp_path, "config.py", '''
from mcp.server import Server
server = Server("x")
AUTH_TOKEN = "changeme"
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings)
    result = ScanResult()
    result.findings.extend(_hits(findings))
    sarif = json.loads(format_results(result))
    run = sarif["runs"][0]
    ro = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == RULE_ID)
    assert any(r["ruleId"] == RULE_ID for r in run["results"])
    assert "fail closed" in ro["help"]["text"].lower()
    assert "CVE-2026-48814" in ro["properties"]["tags"]


# ---------------------------------------------------------------------------
# The config patterns read a crafted file in linear time, and a disabled-auth
# finding names the keyword's own line.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("src", "line"), [
    ("mcp:\n  host: 0.0.0.0\nauth:\n  enabled: false\n", 3),
    ("server:\n  name: mcp\n  bind: 0.0.0.0\n  governance:\n    auth_config:\n      is_enabled: false\n", 4),
])
def test_disabled_auth_config_names_the_keyword_line(tmp_path: Path, src: str, line: int) -> None:
    """A lazy prefix before the keyword let the match start on an earlier line
    (the `0.0.0.0` line here), so the finding named that line."""
    _write(tmp_path, "config.yaml", src)
    findings, _ = scan(tmp_path)
    assert [f.line_number for f in _hits(findings)] == [line]


_CRAFTED_CONFIGS = {
    # 4 KB of this took 16 seconds: the key prefix, the key path, two adjacent
    # `\s*` and the nested-`enabled` window all rescanned the newline run.
    "auth-newlines": "auth:" + "\n" * 990_000 + "x",
    "auth-repeated": "auth: " * 165_000,
    "auth-path": "auth." * 198_000,
    # `[\w-]*secret[\w-]*` started at every character and tried every `secret`
    # in the run: 5,000 characters took 66 seconds.
    "secret-run": "secret" * 165_000,
    "word-run": "a" * 990_000,
}


@pytest.mark.parametrize("shape", sorted(_CRAFTED_CONFIGS))
def test_a_crafted_config_scans_in_linear_time(tmp_path: Path, shape: str) -> None:
    """Just under the scanner's 1,000,000-byte file cap, with the MCP hint and a
    non-loopback bind so the config patterns run. The bound is loose for slow
    CI runners; each takes about a second or less."""
    import time

    src = "mcp 0.0.0.0\n" + _CRAFTED_CONFIGS[shape]
    assert len(src) < 1_000_000
    _write(tmp_path, "config.yaml", src)
    started = time.perf_counter()
    findings, _ = scan(tmp_path)
    assert time.perf_counter() - started < 10.0
    assert _hits(findings) == []
