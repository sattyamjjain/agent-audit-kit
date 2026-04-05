from __future__ import annotations

import json
from pathlib import Path

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
