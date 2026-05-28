"""Tests for AAK-MCP-ATTEST-001 — Attested Tool-Server Admission.

Reference: Metere 2026, "Attested Tool-Server Admission: A Security Extension
to the Model Context Protocol", arXiv:2605.24248. The host config opts in to
attestation by carrying one of: a per-server `attestation`/`clearance` field,
an `MCP-Clearance` header, a named `/.well-known/mcp-clearance` URI, or a
host-level pinned `trust_root`.

Coverage:
- Bare MCP server config fires the finding.
- Per-server `attestation` / `clearance` field suppresses it.
- Host-level `trust_root` suppresses it (covers every server in the file).
- `MCP-Clearance` header suppresses it.
- `.well-known/mcp-clearance` URI named in the entry suppresses it.
- Stub servers (no `url` and no `command`) are skipped.
- SARIF output carries the rule with `security-severity` and a
  `primaryLocationFingerprint`, matching the existing AAK-MCP-* SARIF shape.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_audit_kit.engine import run_scan
from agent_audit_kit.output.sarif import format_results
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_config import scan


# ---------------------------------------------------------------------------
# Rule registry: verify the rule shape is diff-compatible with siblings.
# ---------------------------------------------------------------------------


def test_attest_rule_is_registered_with_expected_shape() -> None:
    rule = RULES["AAK-MCP-ATTEST-001"]
    assert rule.sarif_name == "McpServerUnattested"
    assert rule.owasp_mcp_references == ["MCP07:2025"]
    assert "ASI03" in rule.owasp_agentic_references
    assert "ASI04" in rule.owasp_agentic_references
    assert "arXiv:2605.24248" in rule.incident_references
    # Severity is MEDIUM per the spec; this matches the rule's role as an
    # admission-control gate rather than an exploitable bug.
    assert rule.severity.name == "MEDIUM"
    assert rule.category.name == "MCP_CONFIG"


# ---------------------------------------------------------------------------
# Triggering case: bare server config (no attestation evidence anywhere).
# ---------------------------------------------------------------------------


def _write_mcp_config(tmp_path: Path, payload: dict[str, Any]) -> Path:
    cfg_path = tmp_path / ".mcp.json"
    cfg_path.write_text(json.dumps(payload), encoding="utf-8")
    return cfg_path


def test_bare_server_list_triggers_attest_001(tmp_path: Path) -> None:
    """A server-list config with auth but no attestation must fire ATTEST-001."""
    _write_mcp_config(tmp_path, {
        "mcpServers": {
            "gmail": {
                "url": "https://mcp.gmail.example/v1",
                "headers": {"Authorization": "Bearer ${GMAIL_TOKEN}"},
            },
        },
    })
    findings, _ = scan(tmp_path)
    attest = [f for f in findings if f.rule_id == "AAK-MCP-ATTEST-001"]
    assert attest, f"expected AAK-MCP-ATTEST-001; got {[f.rule_id for f in findings]}"
    ev = attest[0].evidence
    assert "gmail" in ev
    assert "deny-by-default" in ev.lower() or "attestation" in ev.lower()


def test_attest_001_fires_for_each_unattested_server(tmp_path: Path) -> None:
    """Each dispatched server without attestation gets its own finding."""
    _write_mcp_config(tmp_path, {
        "mcpServers": {
            "gmail": {"url": "https://mcp.gmail.example/v1",
                       "headers": {"Authorization": "Bearer x"}},
            "calendar": {"url": "https://mcp.cal.example/v1",
                          "headers": {"Authorization": "Bearer y"}},
        },
    })
    findings, _ = scan(tmp_path)
    attest = [f for f in findings if f.rule_id == "AAK-MCP-ATTEST-001"]
    names = {f.evidence.split("'")[1] for f in attest if "'" in f.evidence}
    assert {"gmail", "calendar"} <= names, f"got names={names}"


# ---------------------------------------------------------------------------
# Suppressing cases: any one attestation indicator is enough.
# ---------------------------------------------------------------------------


def test_per_server_clearance_field_passes(tmp_path: Path) -> None:
    _write_mcp_config(tmp_path, {
        "mcpServers": {
            "gmail": {
                "url": "https://mcp.gmail.example/v1",
                "headers": {"Authorization": "Bearer x"},
                "clearance": "/.well-known/mcp-clearance",
            },
        },
    })
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCP-ATTEST-001" for f in findings)


def test_per_server_attestation_field_passes(tmp_path: Path) -> None:
    _write_mcp_config(tmp_path, {
        "mcpServers": {
            "gmail": {
                "url": "https://mcp.gmail.example/v1",
                "headers": {"Authorization": "Bearer x"},
                "attestation": {"document": "abc", "signature": "sig"},
            },
        },
    })
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCP-ATTEST-001" for f in findings)


def test_host_level_trust_root_passes(tmp_path: Path) -> None:
    """A pinned trust root at host level covers every server in the file."""
    _write_mcp_config(tmp_path, {
        "trust_root": "/etc/mcp/trust-root.pem",
        "mcpServers": {
            "gmail": {"url": "https://mcp.gmail.example/v1",
                       "headers": {"Authorization": "Bearer x"}},
            "calendar": {"url": "https://mcp.cal.example/v1",
                          "headers": {"Authorization": "Bearer y"}},
        },
    })
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCP-ATTEST-001" for f in findings)


def test_mcp_clearance_header_passes(tmp_path: Path) -> None:
    """Transport-level attestation header counts as evidence."""
    _write_mcp_config(tmp_path, {
        "mcpServers": {
            "gmail": {
                "url": "https://mcp.gmail.example/v1",
                "headers": {
                    "Authorization": "Bearer x",
                    "MCP-Clearance": "ck_abc.signature",
                },
            },
        },
    })
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCP-ATTEST-001" for f in findings)


def test_well_known_uri_named_in_entry_passes(tmp_path: Path) -> None:
    _write_mcp_config(tmp_path, {
        "mcpServers": {
            "gmail": {
                "url": "https://mcp.gmail.example/v1",
                "headers": {"Authorization": "Bearer x"},
                "wellKnown": "https://mcp.gmail.example/.well-known/mcp-clearance",
            },
        },
    })
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCP-ATTEST-001" for f in findings)


def test_stub_server_without_url_or_command_is_skipped(tmp_path: Path) -> None:
    """Servers that don't actually dispatch should not be flagged."""
    _write_mcp_config(tmp_path, {
        "mcpServers": {
            "disabled": {"transport": "http"},
        },
    })
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCP-ATTEST-001" for f in findings)


# ---------------------------------------------------------------------------
# SARIF output: rule fingerprint + security-severity, OWASP MCP cross-ref.
# ---------------------------------------------------------------------------


def test_attest_001_sarif_emits_security_severity_and_fingerprint(tmp_path: Path) -> None:
    _write_mcp_config(tmp_path, {
        "mcpServers": {
            "gmail": {
                "url": "https://mcp.gmail.example/v1",
                "headers": {"Authorization": "Bearer x"},
            },
        },
    })
    result = run_scan(tmp_path)
    sarif = json.loads(format_results(result, project_root=tmp_path))

    # SARIF v2.1.0 envelope sanity.
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]

    # Rule must appear in driver.rules with sarif_name + security-severity.
    rule_entries = [r for r in run["tool"]["driver"]["rules"]
                    if r["id"] == "AAK-MCP-ATTEST-001"]
    assert len(rule_entries) == 1, (
        f"AAK-MCP-ATTEST-001 missing from SARIF rules: "
        f"{[r['id'] for r in run['tool']['driver']['rules']]}"
    )
    rule_meta = rule_entries[0]
    assert rule_meta["name"] == "McpServerUnattested"
    assert "security-severity" in rule_meta["properties"]
    # MEDIUM in the existing SEVERITY_TO_SCORE map is a numeric string > 0.
    score = float(rule_meta["properties"]["security-severity"])
    assert 0 < score < 10

    # At least one result must reference the new rule with a fingerprint.
    matching = [r for r in run["results"] if r["ruleId"] == "AAK-MCP-ATTEST-001"]
    assert matching, "expected at least one SARIF result for AAK-MCP-ATTEST-001"
    res = matching[0]
    assert "fingerprints" in res
    assert "primaryLocationFingerprint" in res["fingerprints"]
    # Same property carrier as the other AAK-MCP-* SARIF results.
    assert "security-severity" in res["properties"]


def test_attest_001_owasp_mcp_top10_crossref_preserved(tmp_path: Path) -> None:
    """Rule must be mapped under MCP07:2025 in the OWASP MCP Top 10 surface."""
    _write_mcp_config(tmp_path, {
        "mcpServers": {
            "gmail": {
                "url": "https://mcp.gmail.example/v1",
                "headers": {"Authorization": "Bearer x"},
            },
        },
    })
    result = run_scan(tmp_path)
    finding = next(f for f in result.findings if f.rule_id == "AAK-MCP-ATTEST-001")
    assert "MCP07:2025" in finding.owasp_mcp_references
    # ASI03/ASI04 land the rule under EU AI Act Art. 15 / SOC 2 / ISO 27001
    # via the compliance.py FRAMEWORKS table.
    assert {"ASI03", "ASI04"} <= set(finding.owasp_agentic_references)
    assert "arXiv:2605.24248" in finding.incident_references
