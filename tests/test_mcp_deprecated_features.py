"""Tests for AAK-MCP-DEPRECATED-001..003 + AAK-OAUTH-006 (MCP 2026-07-28 RC).

SEP-2577 (under the SEP-2596 12-month deprecation policy) annotation-deprecates
the `roots`, `sampling`, and `logging` capabilities. `mcp_deprecated_features`
flags continued use across config + source; the committed fixtures pin the
contract (each deprecated surface fires; a migrated server and ordinary stdlib
logging pass). AAK-OAUTH-006 covers the RC's actual new OAuth requirement — RFC
9207 `iss` validation (SEP-2468) — in `oauth_misconfig`.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.engine import run_scan
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import mcp_deprecated_features, oauth_misconfig

FIXTURES = Path(__file__).parent / "fixtures" / "mcp_deprecated"
ROOTS = "AAK-MCP-DEPRECATED-001"
SAMPLING = "AAK-MCP-DEPRECATED-002"
LOGGING = "AAK-MCP-DEPRECATED-003"
OAUTH_ISS = "AAK-OAUTH-006"


def _ids(findings: list) -> set[str]:
    return {f.rule_id for f in findings}


# ---------------------------------------------------------------------------
# Rule registration / accuracy
# ---------------------------------------------------------------------------


def test_deprecated_rules_registered_and_accurate() -> None:
    for rid, feature in ((ROOTS, "roots"), (SAMPLING, "sampling"), (LOGGING, "logging")):
        assert rid in RULES
        rule = RULES[rid]
        assert rule.severity.value == "medium"
        assert "SEP-2577" in rule.description
        assert "SEP-2596" in rule.description
        assert feature in rule.description
        assert "MCP07:2025" in rule.owasp_mcp_references


def test_oauth006_registered_and_accurate() -> None:
    assert OAUTH_ISS in RULES
    rule = RULES[OAUTH_ISS]
    assert rule.severity.value == "medium"
    assert "RFC 9207" in rule.description
    assert "iss" in rule.description
    assert "MCP01:2025" in rule.owasp_mcp_references


# ---------------------------------------------------------------------------
# Deprecation pack — fixtures
# ---------------------------------------------------------------------------


def test_roots_fixture_fires() -> None:
    findings, _ = mcp_deprecated_features.scan(FIXTURES / "roots_py")
    assert ROOTS in _ids(findings)
    assert SAMPLING not in _ids(findings) and LOGGING not in _ids(findings)


def test_sampling_fixture_fires() -> None:
    findings, _ = mcp_deprecated_features.scan(FIXTURES / "sampling_py")
    assert SAMPLING in _ids(findings)


def test_logging_fixture_fires() -> None:
    findings, _ = mcp_deprecated_features.scan(FIXTURES / "logging_py")
    assert LOGGING in _ids(findings)


def test_config_declares_all_three() -> None:
    findings, _ = mcp_deprecated_features.scan(FIXTURES / "config_all")
    assert {ROOTS, SAMPLING, LOGGING} <= _ids(findings)


def test_migrated_server_passes() -> None:
    findings, _ = mcp_deprecated_features.scan(FIXTURES / "clean_migrated")
    assert not (_ids(findings) & {ROOTS, SAMPLING, LOGGING})


def test_stdlib_logging_is_not_flagged() -> None:
    findings, _ = mcp_deprecated_features.scan(FIXTURES / "stdlib_logging_fp")
    assert LOGGING not in _ids(findings)
    assert not _ids(findings)


def test_engine_wires_deprecation_scanner() -> None:
    result = run_scan(FIXTURES / "config_all")
    assert {ROOTS, SAMPLING, LOGGING} <= {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# AAK-OAUTH-006 — RFC 9207 iss validation (inline)
# ---------------------------------------------------------------------------


def _oauth_ids(tmp_path: Path, name: str, src: str) -> set[str]:
    (tmp_path / name).write_text(src, encoding="utf-8")
    return _ids(oauth_misconfig.scan(tmp_path)[0])


def test_token_exchange_without_iss_fires(tmp_path: Path) -> None:
    src = (
        "import requests\n"
        "# oauth authorization-code client\n"
        'data = {"grant_type": "authorization_code", "code": code, "client_id": cid}\n'
        "requests.post(token_endpoint, data=data)\n"
    )
    assert OAUTH_ISS in _oauth_ids(tmp_path, "client.py", src)


def test_callback_without_iss_fires(tmp_path: Path) -> None:
    src = (
        "# oauth callback, authorization_endpoint\n"
        "def callback(request):\n"
        '    code = request.args.get("code")\n'
        '    state = request.args.get("state")\n'
        "    return exchange(code)\n"
    )
    assert OAUTH_ISS in _oauth_ids(tmp_path, "cb.py", src)


def test_iss_validated_passes(tmp_path: Path) -> None:
    src = (
        "# oauth callback\n"
        "def callback(request):\n"
        '    code = request.args.get("code")\n'
        '    iss = request.args.get("iss")\n'
        "    if iss != EXPECTED_ISSUER:\n"
        '        raise ValueError("issuer mismatch")\n'
        "    return exchange(code)\n"
    )
    assert OAUTH_ISS not in _oauth_ids(tmp_path, "cb.py", src)


def test_non_oauth_code_param_passes(tmp_path: Path) -> None:
    src = (
        "def handler(request):\n"
        '    code = request.args.get("code")\n'
        "    return code\n"
    )
    assert OAUTH_ISS not in _oauth_ids(tmp_path, "misc.py", src)
