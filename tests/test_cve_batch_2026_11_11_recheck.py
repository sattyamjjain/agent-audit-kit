"""2026-11-11 recheck: two deferrals no fix will close, and #1175's missing ledger section.

Flowise (CVE-2026-119978, #1168) ended after 3.1.4 and mcp-chrome-bridge
(CVE-2026-102878, #847) has had no upstream commit since January, so each is a
presence-only pin. The ranges were read in the npm tarballs through unpkg on
2026-11-11: Flowise's custom function route first ships in 1.4.6, and every
mcp-chrome-bridge release from 1.0.0 to 1.0.31 lets a web page reach its HTTP MCP
endpoint. `CHANGELOG.cves.md` holds the reasoning, and also the 2026-11-02 section
#1175 shipped without (CVE-2026-120338 and CVE-2026-120323).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import mcp_cve_pins_2026_07
from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import _PINS, scan

FLOWISE = "AAK-FLOWISE-CVE-2026-119978-001"
FLOWISE_MCP = "AAK-MCP-FLOWISE-CVE-2026-91931-001"
CHROME = "AAK-MCP-CHROMEBRIDGE-CVE-2026-102878-001"
MCPHUB = "AAK-MCP-MCPHUB-CVE-2026-79748-001"
ROOT = Path(__file__).resolve().parent.parent
CVES = Path(__file__).resolve().parent / "fixtures" / "cves"
LEDGER = ROOT / "CHANGELOG.cves.md"


def _rows(rule_id: str) -> list[tuple]:
    return [(p.names, p.floor, p.introduced, p.requires_version, p.ecosystem)
            for p in _PINS if p.rule_id == rule_id]


def _ids(tmp_path: Path, name: str, content: str) -> set[str]:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return {f.rule_id for f in scan(tmp_path)[0]}


def _lock(name: str, version: str) -> str:
    return json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "x"}, f"node_modules/{name}": {"version": version}}})


# ---- the rules ------------------------------------------------------------------------------


def test_both_pins_are_presence_only_on_npm() -> None:
    """Flowise from 1.4.6, the first release with the custom function route;
    mcp-chrome-bridge from its first release, since 1.0.0 already accepts every
    origin."""
    assert _rows(FLOWISE) == [(("flowise",), None, (1, 4, 6), False, "js")]
    assert _rows(CHROME) == [(("mcp-chrome-bridge",), None, None, False, "js")]


@pytest.mark.parametrize("rule_id, cve", [(FLOWISE, "CVE-2026-119978"), (CHROME, "CVE-2026-102878")])
def test_each_rule_is_high_and_names_only_its_cve(rule_id: str, cve: str) -> None:
    rule = RULES[rule_id]
    assert rule.severity is Severity.HIGH
    assert rule.cve_references == [cve]
    assert rule.category.value == "supply-chain"


def test_flowise_s_flaw_is_not_on_an_mcp_surface() -> None:
    """The custom function sandbox is not an MCP node: no MCP area in the id and no
    MCP Top 10 id, as Langchain-Chatchat's rule (#1055)."""
    rule = RULES[FLOWISE]
    assert not FLOWISE.startswith("AAK-MCP-")
    assert rule.owasp_mcp_references == []
    assert RULES[CHROME].owasp_mcp_references


@pytest.mark.parametrize("rule_id", [FLOWISE, CHROME])
def test_the_text_says_there_is_no_fix_and_never_says_upgrade(rule_id: str) -> None:
    rule = RULES[rule_id]
    assert "There is no fixed version" in rule.remediation
    assert "upgrade" not in rule.remediation.lower()
    assert "There is no fixed release" in rule.description
    assert "with or without a version" in rule.limitations


def test_flowise_s_text_says_the_project_ended() -> None:
    rule = RULES[FLOWISE]
    assert "the repository was archived on 2026-08-13" in rule.description
    assert "project ended on 2026-08-31" in rule.description
    assert "`ALLOW_BUILTIN_DEP=true` from 3.0.8" in rule.description


# ---- the fixtures: oldest affected, newest, the release before -------------------------------


def test_flowise_fixtures() -> None:
    """3.1.4, the last release, fires and nothing else in the pin table does (the
    Custom MCP pin's floor is 3.1.4); 1.4.6, the first release with the route,
    fires beside that pin; 1.4.5 has no route and gets only the older pin."""
    root = CVES / "cve-2026-119978-flowise"
    newest = scan(root / "vulnerable")[0]
    assert [(f.rule_id, f.file_path, f.line_number) for f in newest] == [
        (FLOWISE, "package-lock.json", 12)]
    assert {f.rule_id for f in scan(root / "oldest")[0]} == {FLOWISE, FLOWISE_MCP}
    assert {f.rule_id for f in scan(root / "negative")[0]} == {FLOWISE_MCP}


def test_mcp_chrome_bridge_fixtures() -> None:
    """1.0.31, the newest, and 1.0.0, the oldest, both fire; Google's
    chrome-devtools-mcp, another project, does not."""
    root = CVES / "cve-2026-102878-mcp-chrome-bridge"
    newest = scan(root / "vulnerable")[0]
    assert [(f.rule_id, f.file_path, f.line_number) for f in newest] == [(CHROME, "package.json", 5)]
    oldest = scan(root / "oldest")[0]
    assert [(f.rule_id, f.file_path, f.line_number) for f in oldest] == [
        (CHROME, "package-lock.json", 12)]
    assert scan(root / "negative")[0] == []


@pytest.mark.parametrize("fixture, rule_id", [
    ("cve-2026-119978-flowise/vulnerable", FLOWISE),
    ("cve-2026-102878-mcp-chrome-bridge/vulnerable", CHROME),
])
def test_the_engine_keeps_the_finding(fixture: str, rule_id: str) -> None:
    findings = [f for f in run_scan(project_root=CVES / fixture).findings if f.rule_id == rule_id]
    assert [f.severity for f in findings] == [Severity.HIGH]
    assert "no fixed release" in findings[0].evidence


# ---- the version ranges ------------------------------------------------------------------------


@pytest.mark.parametrize("name, content, fires", [
    ("package.json", '{"dependencies": {"flowise": "1.4.5"}}', False),    # no route yet
    ("package.json", '{"dependencies": {"flowise": "1.4.6"}}', True),     # the route arrives
    ("package.json", '{"dependencies": {"flowise": "2.2.8"}}', True),
    ("package.json", '{"dependencies": {"flowise": "3.0.7"}}', True),     # the list needs no setting
    ("package.json", '{"dependencies": {"flowise": "3.0.8"}}', True),     # ALLOW_BUILTIN_DEP from here
    ("package.json", '{"dependencies": {"flowise": "3.1.4"}}', True),     # the last release
    ("package.json", '{"dependencies": {"flowise": "^1.4.0"}}', True),    # admits 1.4.6
    ("package.json", '{"dependencies": {"flowise": "<=1.4.5"}}', False),
    ("package.json", '{"dependencies": {"flowise": "latest"}}', True),    # installs 3.1.4
    ("package-lock.json", _lock("flowise", "3.0.4"), True),
    ("pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  flowise@3.1.4:\n"
                       "    resolution: {integrity: sha512-x}\n", True),
    (".mcp.json", '{"mcpServers": {"f": {"command": "npx", "args": ["flowise", "start"]}}}', True),
    # PyPI's flowise is FlowiseAI's Python SDK, another package
    ("requirements.txt", "flowise==1.0.4\n", False),
    (".mcp.json", '{"mcpServers": {"f": {"command": "uvx", "args": ["flowise==1.0.4"]}}}', False),
])
def test_flowise_references(tmp_path: Path, name: str, content: str, fires: bool) -> None:
    assert (FLOWISE in _ids(tmp_path, name, content)) is fires


@pytest.mark.parametrize("name, content", [
    # the package that ships the allowlist, which only the finder's write-up names
    ("package-lock.json", _lock("flowise-components", "3.1.4")),
    ("package.json", '{"dependencies": {"flowise-components": "3.1.4"}}'),
    # a sub-directory manifest
    ("packages/app/package.json", '{"dependencies": {"flowise": "3.1.4"}}'),
])
def test_flowise_limitations(tmp_path: Path, name: str, content: str) -> None:
    assert FLOWISE not in _ids(tmp_path, name, content)


@pytest.mark.parametrize("name, content, fires", [
    ("package.json", '{"dependencies": {"mcp-chrome-bridge": "1.0.0"}}', True),    # origin: true
    ("package.json", '{"dependencies": {"mcp-chrome-bridge": "1.0.29"}}', True),
    ("package.json", '{"dependencies": {"mcp-chrome-bridge": "1.0.30"}}', True),   # startsWith
    ("package.json", '{"dependencies": {"mcp-chrome-bridge": "^1.0.31"}}', True),
    ("package-lock.json", _lock("mcp-chrome-bridge", "1.0.31"), True),
    (".mcp.json", '{"mcpServers": {"c": {"command": "npx", "args": ["-y", "mcp-chrome-bridge"]}}}', True),
    (".mcp.json", '{"mcpServers": {"c": {"command": "mcp-chrome-bridge", "args": []}}}', True),
    (".mcp.json", '{"mcpServers": {"c": {"command": "uvx", "args": ["mcp-chrome-bridge"]}}}', False),
    # the README's two connections name no package
    (".mcp.json", '{"mcpServers": {"c": {"type": "streamableHttp", "url": "http://127.0.0.1:12306/mcp"}}}',
     False),
    (".mcp.json", '{"mcpServers": {"c": {"command": "npx", "args": ["node", '
                  '"/g/node_modules/mcp-chrome-bridge/dist/mcp/mcp-server-stdio.js"]}}}', False),
    (".mcp.json", '{"mcpServers": {"c": {"command": "mcp-chrome-stdio", "args": []}}}', False),
])
def test_mcp_chrome_bridge_references(tmp_path: Path, name: str, content: str, fires: bool) -> None:
    assert (CHROME in _ids(tmp_path, name, content)) is fires


# ---- #1175's dispositions, shipped in 0.6.34 ----------------------------------------------------


@pytest.mark.parametrize("version, fires", [("1.0.32", True), ("1.1.7", True), ("1.1.8", False)])
def test_the_mcphub_floor_is_1_1_8(tmp_path: Path, version: str, fires: bool) -> None:
    assert "CVE-2026-120323" in RULES[MCPHUB].cve_references
    content = json.dumps({"dependencies": {"@samanhappy/mcphub": version}})
    assert (MCPHUB in _ids(tmp_path, "package.json", content)) is fires


def test_the_prefab_ui_rules_name_the_record() -> None:
    for rule_id in ("AAK-MCP-CODEEXEC-SANDBOX-001", "AAK-MCP-CODEEXEC-SANDBOX-002"):
        assert "CVE-2026-120338" in RULES[rule_id].cve_references


# ---- the ledger ---------------------------------------------------------------------------------


def _ledger_rows(cve: str) -> list[str]:
    return [line for line in LEDGER.read_text().splitlines() if line.startswith(f"| {cve} ")]


@pytest.mark.parametrize("cve, issue, rule_id", [
    ("CVE-2026-119978", "#1168", FLOWISE),
    ("CVE-2026-102878", "#847", CHROME),
    ("CVE-2026-120338", "#1170", "AAK-MCP-CODEEXEC-SANDBOX-001"),
    ("CVE-2026-120323", "not filed", MCPHUB),
])
def test_every_covered_cve_has_one_row(cve: str, issue: str, rule_id: str) -> None:
    (row,) = _ledger_rows(cve)
    assert row.rstrip().endswith(f"| {issue} |")
    assert f"`{rule_id}`" in row
    assert "out of scope" not in row.lower()


def test_the_1175_section_is_dated_by_its_merge_and_labelled_0_6_34() -> None:
    """#1175 merged at 2026-11-02T09:48:28Z; 0.6.32 and 0.6.33 never reached PyPI.
    NVD published CVE-2026-120338 on 2026-11-01 and CVE-2026-120323 on 2026-11-02,
    so neither latency is negative."""
    lines = LEDGER.read_text().splitlines()
    headings = [line for line in lines if line.startswith("## ")]
    (heading,) = [h for h in headings if h.startswith("## 2026-11-02 ")]
    assert heading.startswith("## 2026-11-02 (v0.6.34): ")
    at = headings.index(heading)
    assert headings[at - 1].startswith("## 2026-11-07 ") and headings[at + 1].startswith("## 2026-10-31 ")
    start = lines.index(heading)
    end = lines.index(headings[at + 1])
    section = lines[start:end]
    assert any(line.startswith("| CVE-2026-120338 ") for line in section)
    assert "Dispositioned at 2026-11-02T09:48:28Z." in section


@pytest.mark.parametrize("cve", ["CVE-2026-116045", "CVE-2026-117569"])
def test_the_out_of_scope_closures_get_no_row(cve: str) -> None:
    """designer-mcp (#1094) and Kali-GPT (#1109): no published package or tag ever
    carried the flaw, and each fix sits where any future release starts from."""
    assert _ledger_rows(cve) == []


def test_the_pin_module_lists_both_pins() -> None:
    doc = mcp_cve_pins_2026_07.__doc__ or ""
    assert "CVE-2026-119978" in doc and "CVE-2026-102878" in doc
