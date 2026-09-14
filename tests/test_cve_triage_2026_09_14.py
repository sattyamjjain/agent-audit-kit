"""Dispositions for the two-CVE queue opened on 2026-09-14 (#727, #728).

Neither CVE got a rule of its own. Both shapes were already in the registry,
and the interesting part of this wave is that the two issues look like
different bugs and are mostly the same one.

**CVE-2026-90617** (GH05TCREW PentestAgent, CVSS 7.3) is filed as os command
injection in `run_task`. Upstream issue #90 is blunter about the root cause:
`interface/main.py` defaults `--host` to `0.0.0.0` and
`interface/mcp_transport_streamable_http.py` builds its `web.Application()`
with no middleware, so `run_task` is reachable by any network peer, and
`LocalRuntime.execute_command` then hands the caller's string to
`asyncio.create_subprocess_shell`. That is two rules, not one, and the CVE is
attached to both: `AAK-MCP-HTTP-NOAUTH-SERVER-001` for the exposure that makes
it reachable, `AAK-TAINT-001` for the sink it reaches.

`AAK-TAINT-001` did not fire on the real shape. Its description has always
claimed "os.system(), subprocess, or similar shell execution functions", but
its sink set listed only the blocking `subprocess` spellings, so the asyncio
form the CVE actually uses passed through it. The fix is in the sink set, not
in the fixture: `asyncio.create_subprocess_shell`, `subprocess.getoutput` and
`subprocess.getstatusoutput` are now sinks. `asyncio.create_subprocess_exec`
is deliberately still not one, and the negative fixture is built on it, since
an argv list never reaches a shell.

**CVE-2026-38924** (Oraios AI Serena before 1.0.0, CVSS 2.9) is the same
exposure with nothing attached to it: the HTTP-mode listen address was
`0.0.0.0`. Upstream fixed it by changing the default to localhost (commit
b00ae292, "The previous default 0.0.0.0 was a potential security hazard").
`AAK-MCP-HTTP-NOAUTH-SERVER-001` is shape-based rather than vendor-gated, so a
Serena-style entry point already satisfies its predicate; it gains the CVE
reference and a fixture, and no rule was written. At CVSS 2.9 a new rule
family would have been the wrong answer even if one had been available.
"""

from __future__ import annotations

import ast
from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import taint_analysis
from agent_audit_kit.scanners.mcp_http_noauth_server import scan as noauth_scan

TAINT_RULE = "AAK-TAINT-001"
NOAUTH_RULE = "AAK-MCP-HTTP-NOAUTH-SERVER-001"

CVES = Path(__file__).resolve().parent / "fixtures" / "cves"
PENTESTAGENT = CVES / "cve-2026-90617-pentestagent"
SERENA = CVES / "cve-2026-38924-serena"


def _taint_ids(root: Path) -> set[str]:
    return {f.rule_id for f in taint_analysis.scan(root)[0]}


def _noauth_ids(root: Path) -> set[str]:
    return {f.rule_id for f in noauth_scan(root)[0]}


# ---------------------------------------------------------------------------
# Registration — no new rule IDs, both CVEs land on rules that already existed
# ---------------------------------------------------------------------------


def test_pentestagent_cve_is_attached_to_both_halves() -> None:
    assert "CVE-2026-90617" in RULES[TAINT_RULE].cve_references
    assert "CVE-2026-90617" in RULES[NOAUTH_RULE].cve_references


def test_serena_cve_is_attached_to_the_wildcard_bind_rule() -> None:
    assert "CVE-2026-38924" in RULES[NOAUTH_RULE].cve_references


def test_taint_rule_identity_is_unchanged() -> None:
    """The wave extends coverage; it must not re-grade the rule."""
    rule = RULES[TAINT_RULE]
    assert rule.rule_id == TAINT_RULE
    assert rule.severity.value == "critical"
    assert rule.category.value == "taint-analysis"


def test_no_rule_was_minted_for_either_cve() -> None:
    """Guards the reflex this wave existed to resist."""
    for rule_id in RULES:
        assert "90617" not in rule_id
        assert "38924" not in rule_id


# ---------------------------------------------------------------------------
# The detector fix: the asyncio shell sink AAK-TAINT-001 used to miss
# ---------------------------------------------------------------------------


def test_asyncio_shell_is_a_sink_and_exec_is_not() -> None:
    sinks = taint_analysis._SINKS[TAINT_RULE]
    assert ("asyncio", "create_subprocess_shell") in sinks
    assert ("subprocess", "getoutput") in sinks
    assert ("subprocess", "getstatusoutput") in sinks
    # The argv form never reaches a shell. If this ever becomes a sink, every
    # correctly-fixed server in the corpus starts reporting.
    assert ("asyncio", "create_subprocess_exec") not in sinks


def test_asyncio_shell_call_resolves_to_the_taint_sink() -> None:
    """`await asyncio.create_subprocess_shell(p)` must resolve through Await."""
    tree = ast.parse(
        "import asyncio\n"
        "@mcp.tool()\n"
        "async def run_task(task: str) -> None:\n"
        "    await asyncio.create_subprocess_shell(task)\n"
    )
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "create_subprocess_shell")
    assert taint_analysis._resolve_callee(call) == ("asyncio", "create_subprocess_shell")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def test_pentestagent_fixture_fires_both_rules() -> None:
    assert TAINT_RULE in _taint_ids(PENTESTAGENT / "vulnerable")
    assert NOAUTH_RULE in _noauth_ids(PENTESTAGENT / "vulnerable")


def test_pentestagent_negative_is_silent() -> None:
    """argv exec behind a credential on loopback: neither half holds."""
    assert TAINT_RULE not in _taint_ids(PENTESTAGENT / "negative")
    assert NOAUTH_RULE not in _noauth_ids(PENTESTAGENT / "negative")


def test_serena_fixture_fires_the_wildcard_bind_rule() -> None:
    assert NOAUTH_RULE in _noauth_ids(SERENA / "vulnerable")


def test_serena_negative_is_silent() -> None:
    assert NOAUTH_RULE not in _noauth_ids(SERENA / "negative")


def test_serena_fixture_needs_no_taint_finding() -> None:
    """Serena is an exposure bug only; the taint rule has nothing to say."""
    assert _taint_ids(SERENA / "vulnerable") == set()
