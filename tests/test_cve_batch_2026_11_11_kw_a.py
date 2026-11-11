"""#1103 to #1107, #1131 to #1133 and #1139: nine NVD keyword-feed records, five new pins.

Every range below was read in the published artifacts on 2026-11-11, not taken from
the advisory alone: the npm tarballs of @ai-sdlc/plugin-mcp-server (0.8.1, 0.31.2,
0.32.0, 0.42.0), sf-mcp (1.1.0 to 1.3.2) and functype-mcp-server (0.47.0, 1.4.3,
1.4.4), and the PyPI wheels of droidmind (0.2.0, 0.4.0) and langgraph-api (0.1.0,
0.1.2, 0.12.12, 0.13.8, 0.14.0, 0.14.10, 0.15.0, 0.15.13). The ATXP Gemini CLI
extension, the AnkiMCP add-on and Gearboy are on no registry and get ledger rows as
out of scope; esp-mcp has no release and is deferred with no row.
`CHANGELOG.cves.md` holds the reasoning.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Category, Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import _PINS, scan

AISDLC = "AAK-MCP-AISDLC-CVE-2026-117558-001"
DROIDMIND = "AAK-MCP-DROIDMIND-CVE-2026-117559-001"
SFMCP = "AAK-MCP-SFMCP-CVE-2026-117561-001"
LANGGRAPH = "AAK-MCP-LANGGRAPH-API-CVE-2026-118668-001"
LANGGRAPH_55235 = "AAK-MCP-LANGGRAPH-API-CVE-2026-55235-001"
FUNCTYPE = "AAK-MCP-FUNCTYPE-CVE-2026-59176-001"

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cves"
LEDGER = Path(__file__).resolve().parent.parent / "CHANGELOG.cves.md"


def _rows(rule_id: str) -> list[tuple]:
    return [(p.names, p.floor, p.introduced, p.requires_version, p.ecosystem)
            for p in _PINS if p.rule_id == rule_id]


def _ids(tmp_path: Path, name: str, content: str) -> set[str]:
    (tmp_path / name).write_text(content, encoding="utf-8")
    return {f.rule_id for f in scan(tmp_path)[0]}


def _npx(spec: str) -> str:
    return '{"mcpServers": {"s": {"command": "npx", "args": ["-y", "%s"]}}}' % spec


@pytest.mark.parametrize(("rule_id", "cve"), [
    (AISDLC, "CVE-2026-117558"),
    (DROIDMIND, "CVE-2026-117559"),
    (SFMCP, "CVE-2026-117561"),
    (LANGGRAPH, "CVE-2026-118668"),
    (FUNCTYPE, "CVE-2026-59176"),
])
def test_each_rule_is_high_and_names_only_its_own_cve(rule_id: str, cve: str) -> None:
    rule = RULES[rule_id]
    assert rule.severity is Severity.HIGH
    assert rule.category is Category.SUPPLY_CHAIN
    assert rule.cve_references == [cve]
    assert cve in rule.description


def test_the_pins_are_the_ranges_the_artifacts_show() -> None:
    """ai-sdlc: 0.8.1, the first release, to 0.31.2 build the `gh` strings, and 0.32.0
    calls execFileSync. DroidMind and sf-mcp: the oldest and newest releases both carry
    the flaw and there is no fix, so presence-only; PyPI's sf-mcp is another project.
    langgraph-api: 0.1.0 has no JS auth bridge, 0.1.2 applies metadata only, 0.15.0
    applies every change. functype-mcp-server: 0.47.0, the first release, to 1.4.3
    take any version string. Where `latest` is fixed, a stated version is required."""
    assert _rows(AISDLC) == [(("@ai-sdlc/plugin-mcp-server",), (0, 32, 0), None, True, None)]
    assert _rows(DROIDMIND) == [(("droidmind",), None, None, False, None)]
    assert _rows(SFMCP) == [(("sf-mcp",), None, None, False, "js")]
    assert _rows(LANGGRAPH) == [(("langgraph-api",), (0, 15, 0), (0, 1, 2), True, None)]
    assert _rows(FUNCTYPE) == [(("functype-mcp-server",), (1, 4, 4), None, True, None)]


@pytest.mark.parametrize(("fixture", "rule_id", "where"), [
    ("cve-2026-117558-ai-sdlc-mcp-server", AISDLC, (".mcp.json", 5)),
    ("cve-2026-117559-droidmind", DROIDMIND, (".mcp.json", 5)),
    ("cve-2026-117561-sf-mcp", SFMCP, (".mcp.json", 5)),
    ("cve-2026-118668-langgraph-api", LANGGRAPH, ("requirements.txt", 2)),
    ("cve-2026-59176-functype-mcp-server", FUNCTYPE, (".mcp.json", 5)),
])
def test_fixtures_positive_and_negative(fixture: str, rule_id: str, where: tuple[str, int]) -> None:
    """The affected release fires on its own line and nothing else from the table does;
    every `negative*` tree stays quiet."""
    root = FIXTURES / fixture
    vulnerable = scan(root / "vulnerable")[0]
    assert {f.rule_id for f in vulnerable} == {rule_id}
    assert {(f.file_path, f.line_number) for f in vulnerable} == {where}
    negatives = sorted(p for p in root.iterdir() if p.name.startswith("negative"))
    assert negatives
    for negative in negatives:
        assert not scan(negative)[0], negative.name


@pytest.mark.parametrize(("fixture", "rule_id"), [
    ("cve-2026-117558-ai-sdlc-mcp-server", AISDLC),
    ("cve-2026-117559-droidmind", DROIDMIND),
    ("cve-2026-117561-sf-mcp", SFMCP),
    ("cve-2026-118668-langgraph-api", LANGGRAPH),
    ("cve-2026-59176-functype-mcp-server", FUNCTYPE),
])
def test_the_finding_survives_the_full_engine(fixture: str, rule_id: str) -> None:
    found = [f for f in run_scan(FIXTURES / fixture / "vulnerable").findings if f.rule_id == rule_id]
    assert len(found) == 1 and found[0].severity is Severity.HIGH


@pytest.mark.parametrize(("fixture", "rule_id", "stated"), [
    # the README's `uvx --from git+https://github.com/hyperb1iss/droidmind droidmind`
    ("cve-2026-117559-droidmind", DROIDMIND, "names no release and is not reported"),
    # the README's `npx -y codefriar/sf-mcp`, a GitHub reference, not the npm name
    ("cve-2026-117561-sf-mcp", SFMCP, "none of those is reported"),
])
def test_stated_limitations_are_misses(fixture: str, rule_id: str, stated: str) -> None:
    """Both install the affected default branch and name no release, and the rule text
    says so. If one starts firing, update the limitation."""
    (limitation,) = [p for p in (FIXTURES / fixture).iterdir() if p.name.startswith("limitation")]
    assert rule_id not in {f.rule_id for f in scan(limitation)[0]}
    assert stated in RULES[rule_id].limitations


@pytest.mark.parametrize(("spec", "fires"), [
    ("0.8.1", True),      # the first release
    ("0.31.2", True),     # the last release before the fix
    ("^0.31.0", True),
    ("0.32.0", False),    # execFileSync and an owner/name check (#1982)
    ("0.42.0", False),
    ("latest", False),    # resolves to 0.42.0
])
def test_ai_sdlc_versions(tmp_path: Path, spec: str, fires: bool) -> None:
    content = '{"dependencies": {"@ai-sdlc/plugin-mcp-server": "%s"}}' % spec
    assert (AISDLC in _ids(tmp_path, "package.json", content)) is fires


@pytest.mark.parametrize(("name", "content", "fires"), [
    (".mcp.json", _npx("@ai-sdlc/plugin-mcp-server@0.31.2"), True),
    (".mcp.json", _npx("@ai-sdlc/plugin-mcp-server"), False),   # latest, fixed
    ("package-lock.json", '{"lockfileVersion": 3, "packages": {"": {"name": "x"}, '
                          '"node_modules/@ai-sdlc/plugin-mcp-server": {"version": "0.9.2"}}}', True),
])
def test_ai_sdlc_references(tmp_path: Path, name: str, content: str, fires: bool) -> None:
    assert (AISDLC in _ids(tmp_path, name, content)) is fires


@pytest.mark.parametrize(("name", "content", "fires"), [
    ("requirements.txt", "droidmind==0.2.0\n", True),    # the first release
    ("requirements.txt", "droidmind==0.4.0\n", True),    # the newest
    ("requirements.txt", "droidmind\n", True),           # installs 0.4.0
    ("pyproject.toml", '[project]\nname = "x"\nversion = "0"\ndependencies = ["droidmind>=0.2"]\n', True),
    ("uv.lock", '[[package]]\nname = "droidmind"\nversion = "0.3.1"\n', True),
    (".mcp.json", '{"mcpServers": {"d": {"command": "uvx", "args": ["droidmind"]}}}', True),
    ("requirements.txt", "android-mcp==0.2.0\n", False),  # another Android MCP server
])
def test_droidmind_references(tmp_path: Path, name: str, content: str, fires: bool) -> None:
    assert (DROIDMIND in _ids(tmp_path, name, content)) is fires


@pytest.mark.parametrize(("name", "content", "fires"), [
    ("package.json", '{"dependencies": {"sf-mcp": "1.1.0"}}', True),   # the first release
    ("package.json", '{"dependencies": {"sf-mcp": "1.3.2"}}', True),   # the newest
    ("package-lock.json", '{"lockfileVersion": 3, "packages": {"": {"name": "x"}, '
                          '"node_modules/sf-mcp": {"version": "1.3.1"}}}', True),
    (".mcp.json", _npx("sf-mcp"), True),                                # installs 1.3.2
    # PyPI's sf-mcp is Signal Found's server, another project
    ("requirements.txt", "sf-mcp==0.1.2\n", False),
    (".mcp.json", '{"mcpServers": {"s": {"command": "uvx", "args": ["sf-mcp"]}}}', False),
    # the package's executable is `sfmcp`, which names no package
    (".mcp.json", '{"mcpServers": {"s": {"command": "sfmcp", "args": []}}}', False),
])
def test_sf_mcp_references(tmp_path: Path, name: str, content: str, fires: bool) -> None:
    assert (SFMCP in _ids(tmp_path, name, content)) is fires


@pytest.mark.parametrize(("spec", "new", "old"), [
    ("0.1.0", False, True),      # no JS auth bridge yet; the 55235 row's own range
    ("0.1.2", True, True),       # handle_js_auth_event applies metadata only
    ("0.9.0", True, True),
    ("0.10.0", True, False),     # the 55235 fix; the namespace rewrite is still dropped
    ("0.12.12", True, False),    # the newest 0.12.x, no fix
    ("0.13.8", True, False),     # the newest 0.13.x, no fix
    ("0.14.10", True, False),    # 2026-11-06, after the advisory, no fix
    (">=0.14,<0.16", True, False),
    ("0.15.0", False, False),    # _apply_auth_mutations
    ("0.17.1", False, False),
])
def test_langgraph_api_versions(tmp_path: Path, spec: str, new: bool, old: bool) -> None:
    pinned = spec if spec[0] in "<>=!~" else f"=={spec}"
    found = _ids(tmp_path, "requirements.txt", f"langgraph-api{pinned}\n")
    assert (LANGGRAPH in found, LANGGRAPH_55235 in found) == (new, old)


def test_langgraph_api_unversioned_is_not_this_rules_to_report(tmp_path: Path) -> None:
    """`latest` is 0.17.1, fixed; the older 55235 row still reports an unversioned name."""
    found = _ids(tmp_path, "requirements.txt", "langgraph-api\n")
    assert LANGGRAPH not in found and LANGGRAPH_55235 in found


@pytest.mark.parametrize(("name", "content", "fires"), [
    ("package.json", '{"dependencies": {"functype-mcp-server": "0.47.0"}}', True),   # the first release
    ("package.json", '{"dependencies": {"functype-mcp-server": "1.4.3"}}', True),
    ("package.json", '{"dependencies": {"functype-mcp-server": "^1.4.0"}}', True),
    ("package.json", '{"dependencies": {"functype-mcp-server": "1.4.4"}}', False),   # aliases refused
    ("package.json", '{"dependencies": {"functype": "1.4.3"}}', False),              # the library
    (".mcp.json", _npx("functype-mcp-server@1.4.3"), True),
    # the README's own launch installs latest, 1.26.0, which is fixed
    (".mcp.json", '{"mcpServers": {"f": {"command": "npx", "args": ["functype-mcp-server"]}}}', False),
])
def test_functype_mcp_server_references(tmp_path: Path, name: str, content: str, fires: bool) -> None:
    assert (FUNCTYPE in _ids(tmp_path, name, content)) is fires


def _ledger_rows(cve: str) -> list[str]:
    return [line for line in LEDGER.read_text(encoding="utf-8").splitlines()
            if line.startswith(f"| {cve} ")]


@pytest.mark.parametrize(("cve", "issue", "rule_id"), [
    ("CVE-2026-117558", "#1103", AISDLC),
    ("CVE-2026-117559", "#1104", DROIDMIND),
    ("CVE-2026-117561", "#1106", SFMCP),
    ("CVE-2026-118668", "#1133", LANGGRAPH),
    ("CVE-2026-59176", "#1139", FUNCTYPE),
])
def test_covered_rows_name_their_rule(cve: str, issue: str, rule_id: str) -> None:
    (row,) = _ledger_rows(cve)
    assert row.rstrip().endswith(f"| {issue} |")
    assert rule_id in row and "out of scope" not in row.lower()


@pytest.mark.parametrize(("cve", "issue"), [
    ("CVE-2026-117560", "#1105"),   # the ATXP Gemini CLI extension
    ("CVE-2026-61546", "#1131"),    # the AnkiMCP add-on
    ("CVE-2026-61542", "#1132"),    # Gearboy
])
def test_out_of_scope_rows(cve: str, issue: str) -> None:
    (row,) = _ledger_rows(cve)
    assert row.rstrip().endswith(f"| {issue} |")
    assert "Out of scope" in row
    assert not any(cve in rule.cve_references for rule in RULES.values())


def test_the_deferred_record_has_no_row_and_no_rule() -> None:
    """esp-mcp has no tag, no release and no registry package: a row is a coverage claim."""
    assert _ledger_rows("CVE-2026-117567") == []
    assert not any("CVE-2026-117567" in rule.cve_references for rule in RULES.values())
