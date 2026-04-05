from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.scanners.a2a_protocol import scan


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _write_agent_card(
    tmp_path: Path,
    data: dict,
    filename: str = "agent-card.json",
) -> None:
    """Write an agent card JSON file."""
    (tmp_path / filename).write_text(json.dumps(data, indent=2))


_VULNERABLE_AGENT_CARD: dict = {
    "name": "Vulnerable Agent",
    "description": "An agent with security issues",
    "url": "http://agent.example.com/api",
    "capabilities": ["search", "admin", "internal", "debug"],
    "skills": [
        {
            "name": "unsafe_skill",
            "description": "Does something unsafe",
        },
        {
            "name": "another_skill",
            "description": "Another skill without schema",
            "inputSchema": {},
        },
    ],
}

_CLEAN_AGENT_CARD: dict = {
    "id": "clean-agent-001",
    "name": "Clean Agent",
    "description": "A properly configured agent",
    "url": "https://agent.example.com/api",
    "authentication": {
        "type": "bearer",
        "token_url": "https://auth.example.com/token",
    },
    "capabilities": ["search", "summarize", "translate"],
    "skills": [
        {
            "name": "search_skill",
            "description": "Searches for documents",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                },
                "required": ["query"],
            },
        },
    ],
}


def test_vulnerable_triggers_rules(tmp_path: Path) -> None:
    """Vulnerable agent card should trigger AAK-A2A-001 through 004."""
    _write_agent_card(tmp_path, _VULNERABLE_AGENT_CARD)
    findings, scanned = scan(tmp_path)
    rule_ids = {f.rule_id for f in findings}

    assert "agent-card.json" in scanned, "agent-card.json should be in scanned files"

    assert "AAK-A2A-001" in rule_ids, "Should detect internal/admin capabilities"
    assert "AAK-A2A-002" in rule_ids, "Should detect missing authentication field"
    assert "AAK-A2A-003" in rule_ids, "Should detect skills without inputSchema"
    assert "AAK-A2A-004" in rule_ids, "Should detect HTTP endpoint (not HTTPS)"


def test_clean_zero_findings(tmp_path: Path) -> None:
    """Properly configured agent card should produce zero findings."""
    _write_agent_card(tmp_path, _CLEAN_AGENT_CARD)
    findings, scanned = scan(tmp_path)

    assert "agent-card.json" in scanned
    assert len(findings) == 0, (
        f"Clean agent card should produce zero findings, got: "
        f"{[(f.rule_id, f.evidence) for f in findings]}"
    )


def test_empty_or_missing(tmp_path: Path) -> None:
    """Missing, empty, and malformed files should produce zero findings."""
    # No agent-card.json
    findings, scanned = scan(tmp_path)
    assert len(findings) == 0
    assert len(scanned) == 0

    # Empty file
    (tmp_path / "agent-card.json").write_text("")
    findings, scanned = scan(tmp_path)
    assert len(findings) == 0

    # Malformed JSON
    (tmp_path / "agent-card.json").write_text("{broken json!!!}")
    findings, scanned = scan(tmp_path)
    assert len(findings) == 0


def test_a2a_001_various_internal_capabilities(tmp_path: Path) -> None:
    """AAK-A2A-001 should detect admin, system, internal, debug, root keywords."""
    card = {
        "name": "Cap Agent",
        "capabilities": ["admin", "system", "internal", "debug", "root"],
        "authentication": {"type": "bearer"},
    }
    _write_agent_card(tmp_path, card)
    findings, _ = scan(tmp_path)
    a2a_001 = [f for f in findings if f.rule_id == "AAK-A2A-001"]
    assert len(a2a_001) >= 5, (
        f"Expected at least 5 internal capability findings, got {len(a2a_001)}"
    )


def test_a2a_001_capabilities_as_dict(tmp_path: Path) -> None:
    """AAK-A2A-001 should also handle capabilities as a dict (key-value form)."""
    card = {
        "name": "Dict Cap Agent",
        "capabilities": {
            "admin": True,
            "search": True,
            "internal": True,
        },
        "authentication": {"type": "bearer"},
    }
    _write_agent_card(tmp_path, card)
    findings, _ = scan(tmp_path)
    a2a_001 = [f for f in findings if f.rule_id == "AAK-A2A-001"]
    assert len(a2a_001) >= 2, (
        f"Expected admin and internal capabilities flagged, got {len(a2a_001)}"
    )


def test_a2a_001_safe_capabilities_not_flagged(tmp_path: Path) -> None:
    """Normal capabilities should not trigger AAK-A2A-001."""
    card = {
        "name": "Safe Agent",
        "capabilities": ["search", "summarize", "translate", "generate"],
        "authentication": {"type": "bearer"},
    }
    _write_agent_card(tmp_path, card)
    findings, _ = scan(tmp_path)
    a2a_001 = [f for f in findings if f.rule_id == "AAK-A2A-001"]
    assert len(a2a_001) == 0, "Normal capabilities should not be flagged"


def test_a2a_002_auth_type_none(tmp_path: Path) -> None:
    """AAK-A2A-002 should fire when authentication type is 'none'."""
    card = {
        "name": "No Auth Agent",
        "authentication": {"type": "none"},
        "capabilities": ["search"],
    }
    _write_agent_card(tmp_path, card)
    findings, _ = scan(tmp_path)
    a2a_002 = [f for f in findings if f.rule_id == "AAK-A2A-002"]
    assert len(a2a_002) >= 1, "Authentication type 'none' should trigger AAK-A2A-002"


def test_a2a_002_auth_string_none(tmp_path: Path) -> None:
    """AAK-A2A-002 should fire when authentication is a string 'none'."""
    card = {
        "name": "String None Auth",
        "authentication": "none",
        "capabilities": ["search"],
    }
    _write_agent_card(tmp_path, card)
    findings, _ = scan(tmp_path)
    a2a_002 = [f for f in findings if f.rule_id == "AAK-A2A-002"]
    assert len(a2a_002) >= 1, "String 'none' authentication should trigger AAK-A2A-002"


def test_a2a_002_proper_auth_not_flagged(tmp_path: Path) -> None:
    """Proper authentication config should NOT trigger AAK-A2A-002."""
    card = {
        "name": "Authed Agent",
        "authentication": {
            "type": "bearer",
            "token_url": "https://auth.example.com/token",
        },
        "capabilities": ["search"],
    }
    _write_agent_card(tmp_path, card)
    findings, _ = scan(tmp_path)
    a2a_002 = [f for f in findings if f.rule_id == "AAK-A2A-002"]
    assert len(a2a_002) == 0, "Proper auth should not be flagged"


def test_a2a_003_empty_input_schema_flagged(tmp_path: Path) -> None:
    """AAK-A2A-003 should fire for skills with empty inputSchema ({})."""
    card = {
        "name": "Empty Schema Agent",
        "authentication": {"type": "bearer"},
        "capabilities": ["search"],
        "skills": [
            {
                "name": "empty_schema_skill",
                "description": "Has an empty schema",
                "inputSchema": {},
            },
        ],
    }
    _write_agent_card(tmp_path, card)
    findings, _ = scan(tmp_path)
    a2a_003 = [f for f in findings if f.rule_id == "AAK-A2A-003"]
    assert len(a2a_003) >= 1, "Empty inputSchema should trigger AAK-A2A-003"


def test_a2a_003_proper_schema_not_flagged(tmp_path: Path) -> None:
    """Skills with proper inputSchema should NOT trigger AAK-A2A-003."""
    card = {
        "name": "Schema Agent",
        "authentication": {"type": "bearer"},
        "capabilities": ["search"],
        "skills": [
            {
                "name": "typed_skill",
                "description": "Properly typed",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                    },
                    "required": ["query"],
                },
            },
        ],
    }
    _write_agent_card(tmp_path, card)
    findings, _ = scan(tmp_path)
    a2a_003 = [f for f in findings if f.rule_id == "AAK-A2A-003"]
    assert len(a2a_003) == 0, "Proper inputSchema should not be flagged"


def test_a2a_004_http_endpoint(tmp_path: Path) -> None:
    """AAK-A2A-004 should flag HTTP (not HTTPS) endpoints."""
    card = {
        "name": "HTTP Agent",
        "url": "http://insecure-agent.com/api",
        "endpoint": "http://insecure-agent.com/rpc",
        "authentication": {"type": "bearer"},
        "capabilities": ["search"],
    }
    _write_agent_card(tmp_path, card)
    findings, _ = scan(tmp_path)
    a2a_004 = [f for f in findings if f.rule_id == "AAK-A2A-004"]
    assert len(a2a_004) >= 2, (
        f"Both url and endpoint HTTP fields should be flagged, got {len(a2a_004)}"
    )


def test_a2a_004_https_not_flagged(tmp_path: Path) -> None:
    """HTTPS endpoints should NOT trigger AAK-A2A-004."""
    card = {
        "name": "HTTPS Agent",
        "url": "https://secure-agent.com/api",
        "authentication": {"type": "bearer"},
        "capabilities": ["search"],
    }
    _write_agent_card(tmp_path, card)
    findings, _ = scan(tmp_path)
    a2a_004 = [f for f in findings if f.rule_id == "AAK-A2A-004"]
    assert len(a2a_004) == 0, "HTTPS endpoints should not be flagged"


def test_a2a_004_skill_level_http_endpoint(tmp_path: Path) -> None:
    """HTTP endpoints at the skill level should also trigger AAK-A2A-004."""
    card = {
        "name": "Skill HTTP Agent",
        "url": "https://secure.com/api",
        "authentication": {"type": "bearer"},
        "capabilities": ["search"],
        "skills": [
            {
                "name": "insecure_skill",
                "description": "A skill with HTTP endpoint",
                "url": "http://insecure-skill.com/rpc",
                "inputSchema": {
                    "type": "object",
                    "properties": {"q": {"type": "string"}},
                },
            },
        ],
    }
    _write_agent_card(tmp_path, card)
    findings, _ = scan(tmp_path)
    a2a_004 = [f for f in findings if f.rule_id == "AAK-A2A-004"]
    assert len(a2a_004) >= 1, "Skill-level HTTP endpoint should be flagged"


def test_well_known_agent_json_discovered(tmp_path: Path) -> None:
    """Agent cards at .well-known/agent.json should be discovered."""
    well_known = tmp_path / ".well-known"
    well_known.mkdir()
    _write_agent_card(
        tmp_path,
        {
            "name": "Well-Known Agent",
            "capabilities": ["admin"],
            "authentication": {"type": "bearer"},
        },
        filename=".well-known/agent.json",
    )
    findings, scanned = scan(tmp_path)
    scanned_str = " ".join(scanned)
    assert "agent.json" in scanned_str, ".well-known/agent.json should be discovered"
    a2a_001 = [f for f in findings if f.rule_id == "AAK-A2A-001"]
    assert len(a2a_001) >= 1


def test_non_dict_data_skipped(tmp_path: Path) -> None:
    """agent-card.json containing a JSON array (not object) should be skipped."""
    (tmp_path / "agent-card.json").write_text(json.dumps(["not", "a", "dict"]))
    findings, scanned = scan(tmp_path)
    assert len(findings) == 0
    # File is parsed but not a dict, so not added to scanned
    assert len(scanned) == 0


def test_multiple_issues_combined(tmp_path: Path) -> None:
    """An agent card with all four issues should trigger all four rules."""
    card = {
        "name": "Full Vuln Agent",
        "url": "http://insecure.com/api",
        "capabilities": ["admin", "search"],
        "skills": [
            {"name": "unschema_skill", "description": "No schema here"},
        ],
    }
    _write_agent_card(tmp_path, card)
    findings, _ = scan(tmp_path)
    rule_ids = {f.rule_id for f in findings}
    assert "AAK-A2A-001" in rule_ids
    assert "AAK-A2A-002" in rule_ids
    assert "AAK-A2A-003" in rule_ids
    assert "AAK-A2A-004" in rule_ids
