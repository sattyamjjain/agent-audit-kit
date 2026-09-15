"""CVE-2026-90898 (maximhq/bifrost, CVSS 9.8) - closing the #731 deferral.

CHANGELOG.cves.md carried "CVE-2026-90898 (#729) is deferred, not covered",
which was a published promise with a measured gap behind it: a Bifrost-shaped
project produced zero findings from a full run_scan. Two arms close it.

**AAK-MCP-STDIO-CMD-INJ-005** is the Go arm of the STDIO command-injection
family, which had Python, TypeScript, Java and Rust arms and no Go arm. It is
modelled on the Rust arm deliberately, including its posture: regex and
proximity, not data flow. The rule text says so, and so does this test file,
because a proximity rule that is described as taint analysis is worse than no
rule.

One precision guard earns its place: a string literal in argv[0] means the
binary was chosen server-side, which is what a patched handler looks like.
Without it the arm reports every server that decoded a request body anywhere
in the preceding 2 KB, including correctly fixed ones.

**AAK-MCP-NOAUTH-DEFAULT** gains a disabled-auth config arm. It previously
wanted a placeholder secret plus a non-loopback bind; Bifrost's config carries
no secret at all, just `governance.auth_config.is_enabled: false`, which is
the same idea spelled differently and matched nothing.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from agent_audit_kit.engine import run_scan
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_stdio_params import scan as stdio_scan

GO_RULE = "AAK-MCP-STDIO-CMD-INJ-005"
NOAUTH_RULE = "AAK-MCP-NOAUTH-DEFAULT"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-90898-bifrost"


def _go(src: str) -> list[str]:
    d = Path(tempfile.mkdtemp())
    (d / "handler.go").write_text(src, encoding="utf-8")
    return [f.rule_id for f in stdio_scan(d)[0]]


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_go_rule_is_registered_and_carries_the_cve() -> None:
    rule = RULES[GO_RULE]
    assert rule.severity.value == "critical"
    assert "CVE-2026-90898" in rule.cve_references


def test_the_rule_text_states_it_is_not_data_flow() -> None:
    """The Rust arm's posture, stated rather than implied."""
    text = RULES[GO_RULE].description.lower()
    assert "regex" in text and "proximity" in text
    assert "not go data-flow analysis" in text


# ---------------------------------------------------------------------------
# The reporter's measurement
# ---------------------------------------------------------------------------


def test_the_reported_shape_now_produces_findings() -> None:
    result = run_scan(FIXTURES / "vulnerable")
    ids = {f.rule_id for f in result.findings}
    assert GO_RULE in ids, "the Go arm must fire on exec.Command(req.StdioCommand, ...)"
    assert NOAUTH_RULE in ids, "is_enabled: false with an 0.0.0.0 bind must fire"
    assert result.scanner_failures == []


def test_the_patched_posture_is_silent() -> None:
    """transports/v2.1.0: 403 on unauthenticated registration, literal argv[0],
    auth on, loopback bind."""
    result = run_scan(FIXTURES / "negative")
    assert {f.rule_id for f in result.findings} == set()
    assert result.scanner_failures == []


# ---------------------------------------------------------------------------
# Go arm precision. The benign-slice benchmark cannot speak to this arm - the
# slice is MCP registry config JSON and contains no Go source - so the
# controls live here instead of being implied by an unchanged number.
# ---------------------------------------------------------------------------


MCP_PREAMBLE = (
    'package t\n'
    'import ("encoding/json"; "net/http"; "os/exec")\n'
    'type MCPClientRequest struct{ StdioCommand string; StdioArgs []string }\n'
)


def test_request_controlled_argv0_fires() -> None:
    assert GO_RULE in _go(
        MCP_PREAMBLE
        + 'func H(w http.ResponseWriter, r *http.Request) {\n'
        '  var req MCPClientRequest\n'
        '  json.NewDecoder(r.Body).Decode(&req)\n'
        '  exec.Command(req.StdioCommand, req.StdioArgs...).Start()\n}\n'
    )


def test_literal_argv0_does_not_fire() -> None:
    """A server-chosen binary with caller data as later argv elements."""
    assert GO_RULE not in _go(
        MCP_PREAMBLE
        + 'func H(w http.ResponseWriter, r *http.Request) {\n'
        '  var req MCPClientRequest\n'
        '  json.NewDecoder(r.Body).Decode(&req)\n'
        '  exec.Command("mcp-runner", req.StdioArgs...).Start()\n}\n'
    )


def test_exec_with_no_request_source_does_not_fire() -> None:
    assert GO_RULE not in _go(
        MCP_PREAMBLE
        + 'func StartDefault() { exec.Command(defaultBinary).Start() }\n'
    )


def test_a_non_mcp_go_file_does_not_fire() -> None:
    """The MCP hint is the gate; a plain HTTP service is not AAK's business."""
    assert GO_RULE not in _go(
        'package t\n'
        'import ("encoding/json"; "net/http"; "os/exec")\n'
        'type Req struct{ Cmd string }\n'
        'func H(w http.ResponseWriter, r *http.Request) {\n'
        '  var q Req\n'
        '  json.NewDecoder(r.Body).Decode(&q)\n'
        '  exec.Command(q.Cmd).Start()\n}\n'
    )


# ---------------------------------------------------------------------------
# Config arm
# ---------------------------------------------------------------------------


def _cfg(body: str, name: str = "config.yaml") -> set[str]:
    d = Path(tempfile.mkdtemp())
    (d / name).write_text(body, encoding="utf-8")
    return {f.rule_id for f in run_scan(d).findings}


def test_disabled_auth_flag_with_a_wildcard_bind_fires() -> None:
    assert NOAUTH_RULE in _cfg(
        "governance:\n  auth_config:\n    is_enabled: false\n"
        "mcp:\n  client_config_store: ./m.json\n"
        "server:\n  host: 0.0.0.0\n"
    )


def test_disabled_auth_on_loopback_does_not_fire() -> None:
    """Auth off behind loopback is a local dev posture, not a finding."""
    assert NOAUTH_RULE not in _cfg(
        "governance:\n  auth_config:\n    is_enabled: false\n"
        "mcp:\n  client_config_store: ./m.json\n"
        "server:\n  host: 127.0.0.1\n"
    )


def test_auth_enabled_does_not_fire() -> None:
    assert NOAUTH_RULE not in _cfg(
        "governance:\n  auth_config:\n    is_enabled: true\n"
        "mcp:\n  client_config_store: ./m.json\n"
        "server:\n  host: 0.0.0.0\n"
    )
