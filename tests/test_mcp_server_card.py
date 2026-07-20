"""Tests for the MCP Server Card (SEP-1649) static audit — AAK-MCP-CARD-001..004.

SEP-1649 server cards (`/.well-known/mcp/server-card.json`) are fetched and
trusted by a client before it connects, so the card is an attack surface. The
scanner statically audits a committed card for tool-description poisoning,
transport/capability mismatch, missing provenance, and over-broad claims.

Fixtures pin the contract: a poisoned card FLAGS (all four arms); a clean, signed,
authenticated, least-privilege card PASSES. SARIF carries the fingerprint + fix.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.models import ScanResult
from agent_audit_kit.output.sarif import format_results
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_server_card import scan

_FIXTURES = Path(__file__).parent / "fixtures" / "server_cards"
_CARD_RULES = ("AAK-MCP-CARD-001", "AAK-MCP-CARD-002", "AAK-MCP-CARD-003", "AAK-MCP-CARD-004")


def _rule_ids(findings: list) -> set:
    return {f.rule_id for f in findings if f.rule_id in _CARD_RULES}


def _copy(fixture: str, tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_text((_FIXTURES / fixture).read_text(), encoding="utf-8")


# ---------------------------------------------------------------------------
# Rule registration
# ---------------------------------------------------------------------------


def test_card_rules_registered() -> None:
    for rid in _CARD_RULES:
        assert rid in RULES, rid
        assert RULES[rid].category.value == "mcp-server-card"
    assert RULES["AAK-MCP-CARD-001"].severity.value == "critical"


# ---------------------------------------------------------------------------
# Poisoned card — must FLAG (all four arms)
# ---------------------------------------------------------------------------


def test_poisoned_card_flags_all_arms(tmp_path: Path) -> None:
    _copy("poisoned.server-card.json", tmp_path, "poisoned.server-card.json")
    findings, scanned = scan(tmp_path)
    hit = _rule_ids(findings)
    assert "poisoned.server-card.json" in scanned
    # (a) tool-description poisoning
    assert "AAK-MCP-CARD-001" in hit
    # (b) remote transport + authentication.required=false
    assert "AAK-MCP-CARD-002" in hit
    # (c) no signature/provenance ... wait, poisoned card has neither -> flagged
    assert "AAK-MCP-CARD-003" in hit
    # (d) all-capabilities + empty schemes while required-ish
    assert "AAK-MCP-CARD-004" in hit


# ---------------------------------------------------------------------------
# Clean card — must PASS
# ---------------------------------------------------------------------------


def test_clean_card_passes(tmp_path: Path) -> None:
    _copy("clean.server-card.json", tmp_path, "clean.server-card.json")
    findings, _ = scan(tmp_path)
    assert not _rule_ids(findings), f"clean card must not fire: {_rule_ids(findings)}"


def test_non_card_json_ignored(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "x", "version": "1.0.0"}', encoding="utf-8")
    findings, _ = scan(tmp_path)
    assert not _rule_ids(findings), "a plain package.json is not a server card"


# ---------------------------------------------------------------------------
# Individual arms
# ---------------------------------------------------------------------------


def test_stdio_with_remote_endpoint_mismatch(tmp_path: Path) -> None:
    (tmp_path / "srv.server-card.json").write_text(json.dumps({
        "serverInfo": {"name": "x"},
        "transport": {"type": "stdio", "endpoint": "https://remote.example/mcp"},
        "authentication": {"required": True, "schemes": ["oauth2"]},
        "capabilities": {"tools": True},
        "signature": "realsig==",
        "tools": [{"name": "t", "description": "ok"}],
    }), encoding="utf-8")
    findings, _ = scan(tmp_path)
    assert "AAK-MCP-CARD-002" in _rule_ids(findings)


def test_placeholder_signature_flags_unsigned(tmp_path: Path) -> None:
    (tmp_path / "srv.server-card.json").write_text(json.dumps({
        "serverInfo": {"name": "x"},
        "transport": {"type": "stdio"},
        "authentication": {"required": True, "schemes": ["oauth2"]},
        "capabilities": {"tools": True},
        "signature": "TODO",
        "tools": [{"name": "t", "description": "ok"}],
    }), encoding="utf-8")
    findings, _ = scan(tmp_path)
    assert "AAK-MCP-CARD-003" in _rule_ids(findings)


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------


def test_sarif_carries_fingerprint_and_fix(tmp_path: Path) -> None:
    _copy("poisoned.server-card.json", tmp_path, "poisoned.server-card.json")
    findings, _ = scan(tmp_path)
    card = [f for f in findings if f.rule_id in _CARD_RULES]
    assert card
    result = ScanResult()
    result.findings.extend(card)
    sarif = json.loads(format_results(result))
    run = sarif["runs"][0]
    res = next(r for r in run["results"] if r["ruleId"] == "AAK-MCP-CARD-001")
    assert "partialFingerprints" in res
    # Remediation is in a valid property bag, NOT an invalid SARIF `fixes` object
    # (a fix requires artifactChanges; prose-only fixes make codeql reject upload).
    assert "fixes" not in res
    assert res["properties"]["remediation"]
    rule_obj = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "AAK-MCP-CARD-001")
    assert "security-severity" in rule_obj["properties"]
