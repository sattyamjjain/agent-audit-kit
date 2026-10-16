from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_audit_kit.scanners.transport_security import scan


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _write_mcp_config(
    tmp_path: Path,
    servers: dict,
    filename: str = ".mcp.json",
) -> None:
    """Write an .mcp.json with the given mcpServers block."""
    config = {"mcpServers": servers}
    (tmp_path / filename).write_text(json.dumps(config))


def test_vulnerable_triggers_rules(tmp_path: Path) -> None:
    """Vulnerable transport config should trigger AAK-TRANSPORT-001 through 004."""
    servers = {
        "http-remote": {
            "url": "http://mcp.external-server.com/api",
        },
        "tls-disabled": {
            "command": "node",
            "args": ["server.js"],
            "env": {
                "NODE_TLS_REJECT_UNAUTHORIZED": "0",
            },
        },
        "sse-transport": {
            "url": "https://mcp.example.com/sse",
            "transport": "sse",
        },
        "token-in-url": {
            "url": "https://mcp.example.com/api?token=sk-abc123&format=json",
        },
    }
    _write_mcp_config(tmp_path, servers)
    findings, scanned = scan(tmp_path)
    rule_ids = {f.rule_id for f in findings}

    assert ".mcp.json" in scanned, ".mcp.json should be in scanned files"

    assert "AAK-TRANSPORT-001" in rule_ids, "Should detect HTTP URL (non-localhost)"
    assert "AAK-TRANSPORT-002" in rule_ids, "Should detect NODE_TLS_REJECT_UNAUTHORIZED=0"
    assert "AAK-TRANSPORT-003" in rule_ids, "Should detect /sse URL or transport: sse"
    assert "AAK-TRANSPORT-004" in rule_ids, "Should detect ?token= in URL"


def test_clean_zero_findings(tmp_path: Path) -> None:
    """Clean config with HTTPS, no TLS overrides, no SSE should produce zero findings."""
    servers = {
        "secure-server": {
            "url": "https://mcp.example.com/api",
        },
        "local-server": {
            "command": "node",
            "args": ["server.js"],
            "env": {
                "NODE_ENV": "production",
            },
        },
    }
    _write_mcp_config(tmp_path, servers)
    findings, scanned = scan(tmp_path)

    assert ".mcp.json" in scanned
    assert len(findings) == 0, (
        f"Clean transport config should produce zero findings, got: "
        f"{[(f.rule_id, f.evidence) for f in findings]}"
    )


def test_empty_or_missing(tmp_path: Path) -> None:
    """Missing, empty, and malformed files should produce zero findings."""
    # No .mcp.json
    findings, scanned = scan(tmp_path)
    assert len(findings) == 0
    assert len(scanned) == 0

    # Empty .mcp.json
    (tmp_path / ".mcp.json").write_text("")
    findings, scanned = scan(tmp_path)
    assert len(findings) == 0

    # Malformed JSON
    (tmp_path / ".mcp.json").write_text("{broken json!!}")
    findings, scanned = scan(tmp_path)
    assert len(findings) == 0


def test_http_localhost_not_flagged(tmp_path: Path) -> None:
    """HTTP URLs pointing to localhost / 127.0.0.1 / ::1 should NOT trigger AAK-TRANSPORT-001."""
    servers = {
        "localhost-http": {
            "url": "http://localhost:3000/api",
        },
        "loopback-http": {
            "url": "http://127.0.0.1:8080/mcp",
        },
        "ipv6-loopback": {
            "url": "http://[::1]:3000/api",
        },
        "zero-addr": {
            "url": "http://0.0.0.0:5000/",
        },
    }
    _write_mcp_config(tmp_path, servers)
    findings, _ = scan(tmp_path)
    transport_001 = [f for f in findings if f.rule_id == "AAK-TRANSPORT-001"]
    assert len(transport_001) == 0, (
        f"Localhost HTTP should not be flagged, got: "
        f"{[f.evidence for f in transport_001]}"
    )


def test_https_url_not_flagged(tmp_path: Path) -> None:
    """HTTPS URLs should never trigger AAK-TRANSPORT-001."""
    servers = {
        "secure": {
            "url": "https://mcp.production-server.com/api",
        },
    }
    _write_mcp_config(tmp_path, servers)
    findings, _ = scan(tmp_path)
    transport_001 = [f for f in findings if f.rule_id == "AAK-TRANSPORT-001"]
    assert len(transport_001) == 0


def test_tls_reject_unauthorized_set_to_1_not_flagged(tmp_path: Path) -> None:
    """NODE_TLS_REJECT_UNAUTHORIZED=1 should NOT trigger AAK-TRANSPORT-002."""
    servers = {
        "tls-ok": {
            "command": "node",
            "args": ["server.js"],
            "env": {
                "NODE_TLS_REJECT_UNAUTHORIZED": "1",
            },
        },
    }
    _write_mcp_config(tmp_path, servers)
    findings, _ = scan(tmp_path)
    transport_002 = [f for f in findings if f.rule_id == "AAK-TRANSPORT-002"]
    assert len(transport_002) == 0, "TLS enabled (value=1) should not be flagged"


def test_ssl_cert_file_override(tmp_path: Path) -> None:
    """SSL_CERT_FILE override in env should trigger AAK-TRANSPORT-002."""
    servers = {
        "cert-override": {
            "command": "node",
            "args": ["server.js"],
            "env": {
                "SSL_CERT_FILE": "/tmp/custom-ca.pem",
            },
        },
    }
    _write_mcp_config(tmp_path, servers)
    findings, _ = scan(tmp_path)
    transport_002 = [f for f in findings if f.rule_id == "AAK-TRANSPORT-002"]
    assert len(transport_002) >= 1, "SSL_CERT_FILE override should trigger AAK-TRANSPORT-002"


def test_sse_in_url_path_flagged(tmp_path: Path) -> None:
    """URLs containing /sse should trigger AAK-TRANSPORT-003."""
    servers = {
        "sse-endpoint": {
            "url": "https://mcp.example.com/v1/sse",
        },
    }
    _write_mcp_config(tmp_path, servers)
    findings, _ = scan(tmp_path)
    transport_003 = [f for f in findings if f.rule_id == "AAK-TRANSPORT-003"]
    assert len(transport_003) >= 1, "URL with /sse should trigger AAK-TRANSPORT-003"


def test_sse_transport_field_flagged(tmp_path: Path) -> None:
    """transport: 'sse' field should trigger AAK-TRANSPORT-003 independently."""
    servers = {
        "sse-transport-only": {
            "url": "https://mcp.example.com/api",
            "transport": "sse",
        },
    }
    _write_mcp_config(tmp_path, servers)
    findings, _ = scan(tmp_path)
    transport_003 = [f for f in findings if f.rule_id == "AAK-TRANSPORT-003"]
    assert len(transport_003) >= 1, "transport: sse should trigger AAK-TRANSPORT-003"


@pytest.mark.parametrize("value", ["sse", "SSE", "Sse"])
def test_sse_type_field_flagged(tmp_path: Path, value: str) -> None:
    """`type` is the key Claude Code and VS Code declare a transport under.

    The rule read `transport` alone, so a `type: sse` server at a URL without a
    whole-word `/sse` passed: 11 of the 47 State of MCP configs that declare SSE.
    """
    _write_mcp_config(tmp_path, {"x": {"type": value, "url": "https://mcp.example.com/events"}})
    hits = [f for f in scan(tmp_path)[0] if f.rule_id == "AAK-TRANSPORT-003"]
    assert [f.evidence for f in hits] == ["Server 'x' type: sse (deprecated)"]


@pytest.mark.parametrize("key", ["type", "transport"])
def test_a_declared_sse_server_at_an_sse_url_is_reported_once(tmp_path: Path, key: str) -> None:
    """One server, one finding: the declaring key is the evidence, the URL is not a second."""
    _write_mcp_config(tmp_path, {"x": {key: "sse", "url": "https://mcp.example.com/sse"}})
    hits = [f for f in scan(tmp_path)[0] if f.rule_id == "AAK-TRANSPORT-003"]
    assert [f.evidence for f in hits] == [f"Server 'x' {key}: sse (deprecated)"]


def test_another_transport_type_is_not_sse(tmp_path: Path) -> None:
    _write_mcp_config(tmp_path, {
        "h": {"type": "http", "url": "https://mcp.example.com/mcp"},
        "s": {"type": "streamable-http", "url": "https://mcp.example.com/stream"},
    })
    assert not [f for f in scan(tmp_path)[0] if f.rule_id == "AAK-TRANSPORT-003"]


def test_a_declared_sse_finding_sits_on_its_own_server(tmp_path: Path) -> None:
    """The line is the server's `url` line, not the file's first "sse".

    An earlier server named `assessment` holds an "sse" too, and the old search
    put the finding on its line.
    """
    text = json.dumps({"mcpServers": {
        "assessment": {"type": "http", "url": "https://grader.example.com/mcp"},
        "events": {"type": "sse", "url": "https://mcp.example.com/events"},
    }}, indent=2)
    (tmp_path / ".mcp.json").write_text(text, encoding="utf-8")
    (hit,) = [f for f in scan(tmp_path)[0] if f.rule_id == "AAK-TRANSPORT-003"]
    lines = text.splitlines()
    assert "https://mcp.example.com/events" in lines[hit.line_number - 1]


def test_various_token_query_params(tmp_path: Path) -> None:
    """Various credential-like query params should trigger AAK-TRANSPORT-004."""
    servers = {
        "api-key-url": {
            "url": "https://mcp.example.com/api?api_key=sk-123",
        },
        "secret-url": {
            "url": "https://mcp.example.com/api?secret=mysecret",
        },
        "access-token-url": {
            "url": "https://mcp.example.com/api?access_token=tok_abc",
        },
    }
    _write_mcp_config(tmp_path, servers)
    findings, _ = scan(tmp_path)
    transport_004 = [f for f in findings if f.rule_id == "AAK-TRANSPORT-004"]
    assert len(transport_004) >= 3, (
        f"Expected at least 3 credential-in-URL findings, got {len(transport_004)}"
    )


def test_safe_query_params_not_flagged(tmp_path: Path) -> None:
    """Non-credential query params should NOT trigger AAK-TRANSPORT-004."""
    servers = {
        "safe-params": {
            "url": "https://mcp.example.com/api?format=json&page=1&limit=100",
        },
    }
    _write_mcp_config(tmp_path, servers)
    findings, _ = scan(tmp_path)
    transport_004 = [f for f in findings if f.rule_id == "AAK-TRANSPORT-004"]
    assert len(transport_004) == 0, "Non-credential params should not be flagged"


def test_multiple_servers_independent_findings(tmp_path: Path) -> None:
    """Each server should be checked independently; findings should reference the correct server."""
    servers = {
        "server-a": {
            "url": "http://remote-a.com/api",
        },
        "server-b": {
            "url": "http://remote-b.com/api",
        },
    }
    _write_mcp_config(tmp_path, servers)
    findings, _ = scan(tmp_path)
    transport_001 = [f for f in findings if f.rule_id == "AAK-TRANSPORT-001"]
    assert len(transport_001) >= 2, (
        f"Each insecure server should produce a finding, got {len(transport_001)}"
    )
    evidences = [f.evidence for f in transport_001]
    assert any("server-a" in e for e in evidences), "server-a should be mentioned"
    assert any("server-b" in e for e in evidences), "server-b should be mentioned"


def test_empty_mcpservers_block(tmp_path: Path) -> None:
    """Empty mcpServers should produce zero findings but still count as scanned."""
    _write_mcp_config(tmp_path, {})
    findings, scanned = scan(tmp_path)
    assert ".mcp.json" in scanned
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# VS Code's `.vscode/mcp.json` keeps its servers under `servers`. This scanner
# read only `mcpServers` until mcp_server_maps, so a cleartext VS Code server,
# or one with TLS checking off, came back clean.
# ---------------------------------------------------------------------------


def _write_vscode(root: Path, servers: dict[str, Any]) -> None:
    vscode = root / ".vscode"
    vscode.mkdir(exist_ok=True)
    (vscode / "mcp.json").write_text(json.dumps({"servers": servers}), encoding="utf-8")


@pytest.mark.parametrize(("rule_id", "server"), [
    ("AAK-TRANSPORT-001", {"type": "http", "url": "http://mcp.example.com/mcp"}),
    ("AAK-TRANSPORT-002", {"type": "stdio", "command": "node", "args": ["server.js"],
                           "env": {"NODE_TLS_REJECT_UNAUTHORIZED": "0"}}),
    ("AAK-TRANSPORT-003", {"type": "sse", "url": "https://mcp.example.com/sse"}),
    ("AAK-TRANSPORT-004", {"type": "http", "url": "https://mcp.example.com/mcp?token=abc123"}),
])
def test_a_vscode_server_is_read(tmp_path: Path, rule_id: str, server: dict[str, Any]) -> None:
    _write_vscode(tmp_path, {"x": server})
    hits = [f for f in scan(tmp_path)[0] if f.rule_id == rule_id]
    assert [f.file_path for f in hits] == [".vscode/mcp.json"]


def test_a_loopback_vscode_server_is_not_cleartext(tmp_path: Path) -> None:
    _write_vscode(tmp_path, {"x": {"type": "http", "url": "http://localhost:3000/mcp"}})
    assert scan(tmp_path)[0] == []


@pytest.mark.parametrize(("url", "fires"), [
    # The exemption is the one AAK-MCP-001 and 009 share: all of 127.0.0.0/8,
    # where the old anchored regex knew 127.0.0.1 alone.
    ("http://127.0.0.2:8080/mcp", False),
    ("ws://[::1]:9000/mcp", False),
    ("http://localhost.evil.example/mcp", True),
    ("http://127.0.0.1@evil.example/mcp", True),
])
def test_the_loopback_exemption_is_the_shared_one(tmp_path: Path, url: str, fires: bool) -> None:
    _write_mcp_config(tmp_path, {"x": {"url": url}})
    hits = [f for f in scan(tmp_path)[0] if f.rule_id == "AAK-TRANSPORT-001"]
    assert bool(hits) is fires


@pytest.mark.parametrize(("url", "scheme"), [
    (" http://mcp.example.com/mcp", "http"),        # Node strips leading spaces and C0 controls
    ("\x00http://mcp.example.com/mcp", "http"),
    ("h\tttp://mcp.example.com/mcp", "http"),       # and removes every tab and newline
    ("http\n://mcp.example.com/mcp", "http"),
    ("http:/mcp.example.com/mcp", "http"),           # and skips any run of slashes and backslashes
    ("http:mcp.example.com/mcp", "http"),
    ("HTTP:\\\\mcp.example.com\\mcp", "http"),
    ("ws:/mcp.example.com/mcp", "ws"),
])
def test_every_spelling_a_client_opens_as_cleartext_fires(tmp_path: Path, url: str, scheme: str) -> None:
    """`^(?:http|ws)://` read the text, not the URL. Each of these is a cleartext
    URL to Node's `new URL()`, which Claude Code and VS Code connect with, and
    none of them fired."""
    _write_mcp_config(tmp_path, {"x": {"url": url}})
    hits = [f for f in scan(tmp_path)[0] if f.rule_id == "AAK-TRANSPORT-001"]
    assert len(hits) == 1
    assert f"cleartext {scheme}://" in hits[0].evidence


@pytest.mark.parametrize("url", [" https://mcp.example.com/mcp", "HTTPS:/mcp.example.com/mcp", "wss:mcp.example.com"])
def test_an_encrypted_url_in_another_spelling_does_not_fire(tmp_path: Path, url: str) -> None:
    _write_mcp_config(tmp_path, {"x": {"url": url}})
    assert not [f for f in scan(tmp_path)[0] if f.rule_id == "AAK-TRANSPORT-001"]


def test_a_backslash_url_is_loopback_only_when_every_reader_agrees(tmp_path: Path) -> None:
    """localhost to Node, mcp.example.com to curl and httpx: not exempt."""
    _write_mcp_config(tmp_path, {"x": {"url": "http://localhost\\@mcp.example.com/mcp"}})
    assert [f for f in scan(tmp_path)[0] if f.rule_id == "AAK-TRANSPORT-001"]


def test_a_top_level_array_is_skipped_not_a_crash(tmp_path: Path) -> None:
    """`data.get` on a JSON array raised AttributeError and failed the scanner."""
    (tmp_path / ".mcp.json").write_text("[1, 2]", encoding="utf-8")
    assert scan(tmp_path) == ([], {".mcp.json"})
