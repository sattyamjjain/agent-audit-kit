"""CVE-2026-104120 (#851): mcp-server-fetch up to 2026.6.4 fetches any URL.

NVD: "Affected is the function fetch_url of the file mcp_server_fetch/server.py
of the component Fetch Tool. The manipulation of the argument url/path leads to
server-side request forgery." The `fetch` prompt's handler hands its `url`
argument to `fetch_url`, skipping even the robots.txt check the tool path runs,
and neither path checks the destination.

The fix (modelcontextprotocol/servers#4890) is not merged, so there is no fixed
release to pin. `AAK-MCP-SSRF-001` already names the class, a caller-supplied
URL reaching an outbound fetch with no host or scheme allow-list, and fires on
the shape, so the CVE is listed on it.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.engine import run_scan
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_ssrf_toolarg import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-104120-mcp-server-fetch"
RULE_ID = "AAK-MCP-SSRF-001"


def test_cve_is_referenced_on_the_rule() -> None:
    assert "CVE-2026-104120" in RULES[RULE_ID].cve_references


def test_prompt_url_reaching_an_unguarded_fetch_fires() -> None:
    findings, _ = scan(FIXTURES / "vulnerable")
    assert [f.rule_id for f in findings] == [RULE_ID]
    # The finding sits on the fetch inside `fetch_url`, the function NVD names.
    line = findings[0].line_number
    assert line is not None
    lines = (FIXTURES / "vulnerable" / "server.py").read_text(encoding="utf-8").splitlines()
    assert "client.get(" in lines[line - 1]


def test_the_full_scan_reports_it() -> None:
    assert RULE_ID in {f.rule_id for f in run_scan(FIXTURES / "vulnerable").findings}


def test_a_host_allow_list_before_the_fetch_passes() -> None:
    findings, _ = scan(FIXTURES / "negative")
    assert not findings
