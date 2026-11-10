"""AAK-AUTHZ-CALLER-INPUT-001, AAK-MCP-AUTHZ-COVERAGE-001 and AAK-MCP-TOKENVERIFIER-AUD-001."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agent_audit_kit.models import Category, Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_authz_code import RULE_AUD, RULE_CALLER, RULE_COVERAGE, scan

FIXTURES = Path(__file__).parent / "fixtures" / "mcp_authz_code"


def _rules(tmp_path: Path, name: str) -> list[str]:
    shutil.copy(FIXTURES / name, tmp_path / name)
    return [f.rule_id for f in scan(tmp_path)[0]]


@pytest.mark.parametrize("name,rule,count", [
    ("caller_param.py", RULE_CALLER, 1), ("caller_arguments.py", RULE_CALLER, 1), ("caller_role.py", RULE_CALLER, 1),
    ("caller_id_refuses.py", RULE_CALLER, 1),
    ("coverage_gap.py", RULE_COVERAGE, 2), ("coverage_transport.py", RULE_COVERAGE, 1),
    ("context_allows.py", RULE_COVERAGE, 1), ("context_and.py", RULE_COVERAGE, 1),
    ("aud_settings_none.py", RULE_AUD, 1), ("aud_verifier_blind.py", RULE_AUD, 1),
])
def test_each_firing_shape(tmp_path: Path, name: str, rule: str, count: int) -> None:
    assert _rules(tmp_path, name) == [rule] * count


@pytest.mark.parametrize("name", [
    "principal_check.py", "principal_compare.py", "chat_role.py", "coverage_shared.py", "coverage_no_check.py",
    "transport_stdio_skip.py", "context_refuses.py", "aud_verifier_checks.py", "aud_protocol_stub.py",
])
def test_each_quiet_shape(tmp_path: Path, name: str) -> None:
    assert _rules(tmp_path, name) == []


def test_the_coverage_finding_names_the_handlers_left_out(tmp_path: Path) -> None:
    shutil.copy(FIXTURES / "coverage_gap.py", tmp_path / "s.py")
    evidence = [f.evidence for f in scan(tmp_path)[0]]
    assert any("resources/read" in e and "`read`" in e for e in evidence)
    assert any("prompts/get" in e and "`prompt`" in e for e in evidence)


def test_a_name_holding_a_word_inside_it_is_no_principal(tmp_path: Path) -> None:
    (tmp_path / "s.py").write_text(
        "def socket(fam):\n    factory = _socket_factory.get(None)\n    if factory is None:\n        return make(fam)\n"
        "    return factory.socket(fam)\n")
    assert scan(tmp_path)[0] == []


@pytest.mark.parametrize("rule,severity", [
    (RULE_CALLER, Severity.HIGH), (RULE_COVERAGE, Severity.HIGH), (RULE_AUD, Severity.MEDIUM),
])
def test_the_rules_are_registered_as_stated(rule: str, severity: Severity) -> None:
    assert RULES[rule].severity is severity and RULES[rule].category is Category.TRUST_BOUNDARY
    assert RULES[rule].owasp_mcp_references == ["MCP07:2025"] and RULES[rule].limitations.strip()


def test_the_shared_resource_rule_takes_the_actor_from_the_principal() -> None:
    text = RULES["AAK-AGENT-SHARED-RES-AUTHZ-001"].remediation
    assert "authenticated principal" in text and "never trusted on its own" in text
