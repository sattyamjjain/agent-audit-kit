"""CVE-2026-53708 — mcp-contextforge-gateway resolve-then-connect TOCTOU.

GHSA-9hgc-g3w5-67cm. `/admin/gateways/test` calls `validate_gateway_test_url`,
which resolves the host and rejects private ranges, and then hands the
*hostname* to an httpx client that resolves it again at connect time. A record
that flips between the two resolutions reaches the private address anyway.

This is the same defect as CVE-2026-41488, which `AAK-SSRF-TOCTOU-001` already
covered — but the rule recognised guards from a closed list of seven names
borrowed from langchain-openai, and this guard is named after the endpoint it
protects rather than after the check it performs. Guard recognition is now
two-track: the name reads like a URL/host check, or the body actually resolves
a name and range-checks the result.
"""

from __future__ import annotations

import ast
from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.ssrf_toctou import _guard_functions, _is_validator_name, scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-53708"
RULE_ID = "AAK-SSRF-TOCTOU-001"


def test_cve_is_referenced_on_the_rule() -> None:
    assert "CVE-2026-53708" in RULES[RULE_ID].cve_references


def test_vulnerable_resolve_then_connect_fires() -> None:
    findings, _ = scan(FIXTURES / "vulnerable-rebind")
    assert [f.rule_id for f in findings] == [RULE_ID]


def test_pinned_ip_passes() -> None:
    findings, _ = scan(FIXTURES / "patched-pinned")
    assert not findings


def test_endpoint_named_guard_is_recognised_by_name() -> None:
    """The specific miss: a guard named for its endpoint, not for its check."""
    assert _is_validator_name("validate_gateway_test_url")
    assert _is_validator_name("check_target_host")
    assert _is_validator_name("ssrf_protect")


def test_unrelated_names_are_not_treated_as_guards() -> None:
    """The widened matcher still has to say no to ordinary function names."""
    for name in ("validate_payload", "check_quota", "is_admin", "fetch_url", "get"):
        assert not _is_validator_name(name), name


def test_guard_recognised_by_body_when_the_name_gives_nothing_away() -> None:
    """Second track: resolve + range-check is a guard whatever it is called."""
    src = (
        "import socket, ipaddress\n"
        "def preflight(u):\n"
        "    ip = socket.gethostbyname(u)\n"
        "    if ipaddress.ip_address(ip).is_private:\n"
        "        raise ValueError('no')\n"
        "def unrelated(x):\n"
        "    return x + 1\n"
    )
    guards = _guard_functions(ast.parse(src), src)
    assert guards == {"preflight"}
