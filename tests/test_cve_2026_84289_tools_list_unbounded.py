"""`AAK-MCP-TOOLS-LIST-UNBOUNDED-001` — CVE-2026-84289 (Hermes Agent).

`AAK-MCP-016` covers an unbounded *request body*. This allocation is driven by
the *upstream response*, which arrives from the other direction and which no
body-size limit touches. `test_the_neighbour_rule_does_not_cover_this` states
that as an executable claim rather than a paragraph.

The benign fixture caps the tool count. "Builds a list of tools" on its own
describes every MCP client written, so the bound is the entire finding, and a
rule with no negative fixture cannot appear in the published false-positive rate
honestly.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.models import Category, Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_tools_list_unbounded import scan

RULE = "AAK-MCP-TOOLS-LIST-UNBOUNDED-001"
CVE = "CVE-2026-84289"

POSITIVE = """\
import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hermes")


async def list_tools(server_url: str):
    resp = await httpx.AsyncClient().get(f"{server_url}/tools")
    tools = resp.json()["tools"]
    out = []
    for t in tools:
        out.append({
            "name": t["name"],
            "description": t["description"],
            "schema": t["inputSchema"],
        })
    return out
"""

# Same builder, with a cap on how much an upstream may hand back.
BENIGN = POSITIVE.replace(
    "    tools = resp.json()[\"tools\"]\n",
    "    tools = resp.json()[\"tools\"]\n"
    "    if len(tools) > MAX_TOOLS_PER_SERVER:\n"
    "        raise ValueError(\"upstream returned too many tools\")\n",
)


def _ids(tmp_path: Path, name: str, content: str) -> set[str]:
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return {f.rule_id for f in scan(tmp_path)[0]}


def test_positive_fires(tmp_path: Path) -> None:
    assert RULE in _ids(tmp_path, "tools/mcp_tool.py", POSITIVE)


def test_benign_is_silent(tmp_path: Path) -> None:
    """A count check is all it takes, and it must be enough."""
    assert RULE not in _ids(tmp_path, "tools/mcp_tool.py", BENIGN)


def test_a_slice_also_clears_it(tmp_path: Path) -> None:
    sliced = POSITIVE.replace('resp.json()["tools"]', 'resp.json()["tools"][:200]')
    assert RULE not in _ids(tmp_path, "tools/mcp_tool.py", sliced)


def test_a_local_catalogue_is_not_flagged(tmp_path: Path) -> None:
    """The value has to come off the wire. A catalogue built from a literal in
    the file is bounded by the file."""
    local = """\
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("local")
TOOLS = [{"name": "a"}, {"name": "b"}]

def list_tools():
    out = []
    for t in TOOLS:
        out.append(t)
    return out
"""
    assert RULE not in _ids(tmp_path, "server.py", local)


def test_the_neighbour_rule_does_not_cover_this(tmp_path: Path) -> None:
    """`AAK-MCP-016` is about the inbound request body. If it ever starts firing
    on this shape, one of these two rules is redundant and someone should decide
    which — rather than both firing on every aggregator."""
    from agent_audit_kit.engine import run_scan

    target = tmp_path / "tools" / "mcp_tool.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(POSITIVE, encoding="utf-8")
    ids = {f.rule_id for f in run_scan(tmp_path).findings}
    assert RULE in ids
    assert "AAK-MCP-016" not in ids


def test_rule_metadata() -> None:
    rule = RULES[RULE]
    assert rule.severity is Severity.MEDIUM
    assert rule.category is Category.MCP_CONFIG
    assert rule.cve_references == [CVE]
    assert rule.limitations


def test_rule_is_a_class_not_a_package_signature() -> None:
    rule = RULES[RULE]
    text = f"{rule.title} {rule.description} {rule.remediation}".lower()
    assert "hermes" not in text
