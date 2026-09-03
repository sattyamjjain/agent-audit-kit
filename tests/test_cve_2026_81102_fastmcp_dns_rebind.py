"""CVE-2026-81102 — DNS rebinding reached through the Python FastMCP wrapper.

The Dash MCP server bound its listener to loopback and never checked the `Host`
a request named, so a name rebound to 127.0.0.1 still reached it and could drive
its tools under the credential the server holds. Only the network mode was
reachable; stdio was not.

`AAK-DNS-REBIND-001` already owned this defect for the raw SDK transport classes
and read straight past FastMCP, because FastMCP names none of its markers: it is
built as `FastMCP(...)` and picks its transport with
`run(transport="streamable-http")` — a hyphenated string literal, where the
detector looked for `streamable_http` with an underscore.

**Extension, not a new rule** (`CHANGELOG.cves.md`, 2026-09-02 triage: "the same
claims over a language and a transport the detectors do not currently read, so
they get a scanner path, not a second rule id"). Same defect, same mitigation
marker, same remediation, same id.

The stdio case carries as much weight as the positive: FastMCP defaults to
stdio, so a detector keyed on `FastMCP(` alone would fire on nearly every
FastMCP server written and undo the precision work measured in
`benchmarks/false_positive/RESULTS.md`.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.dns_rebind import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "dns-rebind-sdk-class"
RULE = "AAK-DNS-REBIND-001"


def test_fastmcp_network_transport_without_allowlist_fires() -> None:
    findings, _ = scan(FIXTURES / "python-fastmcp-unguarded")
    assert RULE in {f.rule_id for f in findings}


def test_fastmcp_evidence_names_the_fastmcp_shape() -> None:
    """The finding must say what it matched, not just that something matched."""
    findings, _ = scan(FIXTURES / "python-fastmcp-unguarded")
    hit = next(f for f in findings if f.rule_id == RULE)
    assert "FastMCP" in (hit.evidence or "")
    assert "streamable-http" in (hit.evidence or "")


def test_fastmcp_with_transport_security_settings_passes() -> None:
    """`TransportSecuritySettings(allowed_hosts=[...])` is the documented fix."""
    findings, _ = scan(FIXTURES / "python-fastmcp-guarded")
    assert RULE not in {f.rule_id for f in findings}


def test_fastmcp_stdio_does_not_fire() -> None:
    """stdio has no listener to rebind onto — the advisory says so explicitly."""
    findings, _ = scan(FIXTURES / "python-fastmcp-stdio")
    assert RULE not in {f.rule_id for f in findings}


def test_loopback_bind_is_not_treated_as_mitigation() -> None:
    """The vulnerable fixture binds 127.0.0.1 and must still fire.

    CVE-2026-81102 was loopback-bound. If binding were read as a mitigation the
    rule would miss the exact shape it was widened for.
    """
    src = (FIXTURES / "python-fastmcp-unguarded" / "server.py").read_text()
    assert 'host="127.0.0.1"' in src
    findings, _ = scan(FIXTURES / "python-fastmcp-unguarded")
    assert RULE in {f.rule_id for f in findings}


def test_still_one_rule_with_the_cve_recorded() -> None:
    """No second rule id was minted, and the new CVE is on the existing one."""
    assert "CVE-2026-81102" in RULES[RULE].cve_references
    assert not any(
        rid != RULE and "CVE-2026-81102" in r.cve_references
        for rid, r in RULES.items()
    ), "CVE-2026-81102 should be owned by AAK-DNS-REBIND-001 alone"


def test_raw_sdk_shapes_still_behave() -> None:
    """Every pre-existing fixture keeps its verdict — the widening added only."""
    fires, _ = scan(FIXTURES / "python-pattern-unguarded")
    assert RULE in {f.rule_id for f in fires}
    quiet, _ = scan(FIXTURES / "python-pattern-guarded")
    assert RULE not in {f.rule_id for f in quiet}
