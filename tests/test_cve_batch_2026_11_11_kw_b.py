"""#1145 to #1188 (group kw_b): ten NVD keyword-feed matches, read on 2026-11-11.

Two new pins (PDF Reader MCP, LangGraph SDK), a floor raised (Claude Code), one record
measured through the advisory feed (praktor), and six out of scope. The OSV records of
CVE-2026-62331 are saved unedited under tests/fixtures/cves/cve-2026-62331-praktor/osv,
and NVD's record of CVE-2026-88066 under tests/fixtures/nvd_cna. `CHANGELOG.cves.md`
holds the reasoning.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit import advisory_feed, nvd_feed
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import mcp_cve_pins_2026_07
from agent_audit_kit.scanners.supply_chain import scan as supply_chain_scan

FIXTURES = Path(__file__).parent / "fixtures"
CVES = FIXTURES / "cves"
LEDGER = Path(__file__).resolve().parent.parent / "CHANGELOG.cves.md"

PDF = "AAK-MCP-PDFREADER-CVE-2026-62264-001"
LG = "AAK-MCP-LANGGRAPHSDK-CVE-2026-118667-001"
LG_API_PIN = "AAK-MCP-LANGGRAPHSDK-CVE-2026-104873-001"
CC = "AAK-CLAUDECODE-CVE-2026-40068-PIN-001"
CC_LOW = "AAK-MCP-CLAUDECODE-CVE-2026-103012-001"
KNOWN = "AAK-KNOWN-VULN-001"


def _pin_ids(root: Path) -> set[str]:
    return {f.rule_id for f in mcp_cve_pins_2026_07.scan(root)[0]}


def _write(tmp_path: Path, name: str, content: str) -> set[str]:
    (tmp_path / name).write_text(content, encoding="utf-8")
    return _pin_ids(tmp_path)


def _rows(rule_id: str) -> list[tuple[object, ...]]:
    return [(p.names, p.floor, p.introduced, p.requires_version, p.ecosystem)
            for p in mcp_cve_pins_2026_07._PINS if p.rule_id == rule_id]


# -- #1187: PDF Reader MCP's HTTP transport never checks MCP_API_KEY ---------------------------


def test_the_pdf_reader_pin_is_the_range_the_tarballs_show() -> None:
    """dist/index.js: 2.1.0 has no HTTP transport, 2.2.0 and 3.0.0 read MCP_API_KEY and
    only log it, 3.0.1 checks the X-API-Key header and binds 127.0.0.1 by default."""
    assert _rows(PDF) == [(("@sylphx/pdf-reader-mcp",), (3, 0, 1), (2, 2, 0), True, "js")]
    assert RULES[PDF].cve_references == ["CVE-2026-62264"]
    assert RULES[PDF].severity is Severity.HIGH


def test_the_pdf_reader_fixtures_positive_and_negative() -> None:
    root = CVES / "cve-2026-62264-pdf-reader-mcp"
    found = mcp_cve_pins_2026_07.scan(root / "vulnerable")[0]
    assert {f.rule_id for f in found} == {PDF}
    assert {(f.file_path, f.line_number) for f in found} == {(".mcp.json", 5)}
    for negative in sorted(p for p in root.iterdir() if p.name.startswith("negative")):
        assert not mcp_cve_pins_2026_07.scan(negative)[0], negative.name


@pytest.mark.parametrize(("spec", "fires"), [
    ("2.1.0", False),     # no HTTP transport yet
    ("2.2.0", True),      # the HTTP transport arrives and ignores the key
    ("2.7.2", True),
    ("3.0.0", True),      # the last affected release
    ("^3.0.0", True),     # a range that admits 3.0.0
    ("3.0.1", False),     # isApiKeyValid, and 127.0.0.1 by default
    ("8.5.11", False),    # the anymd alias
    ("latest", False),    # states no version, and installs a fixed release
])
def test_pdf_reader_versions(tmp_path: Path, spec: str, fires: bool) -> None:
    content = json.dumps({"dependencies": {"@sylphx/pdf-reader-mcp": spec}})
    assert (PDF in _write(tmp_path, "package.json", content)) is fires


@pytest.mark.parametrize(("name", "content", "fires"), [
    (".mcp.json", '{"mcpServers": {"p": {"command": "npx", "args": ["-y", "@sylphx/pdf-reader-mcp@2.4.3"]}}}',
     True),
    (".mcp.json", '{"mcpServers": {"p": {"command": "npx", "args": ["-y", "@sylphx/pdf-reader-mcp"]}}}', False),
    ("package-lock.json",
     '{"lockfileVersion": 3, "packages": {"node_modules/@sylphx/pdf-reader-mcp": {"version": "3.0.0"}}}', True),
    # PyPI's `pdf-reader-mcp` is zixma13's, another project
    ("requirements.txt", "pdf-reader-mcp==0.1.1\n", False),
])
def test_pdf_reader_reads_a_stated_npm_version(tmp_path: Path, name: str, content: str, fires: bool) -> None:
    assert (PDF in _write(tmp_path, name, content)) is fires


# -- #1146: LangGraph SDK's v3 stream helpers put raw ids in request paths ---------------------


def test_the_langgraph_sdk_pin_is_the_range_the_wheels_show() -> None:
    """0.3.15 has no `_async/stream.py`; 0.4.0 and 0.4.5 build `/assistants/{id}/graph`
    and `/threads/{id}/state` from raw ids; 0.4.6 passes both through
    `_quote_path_param` (langgraph#9213). MEDIUM, beside the HIGH 104873 row."""
    assert _rows(LG) == [(("langgraph-sdk",), (0, 4, 6), (0, 4, 0), True, "py")]
    assert RULES[LG].cve_references == ["CVE-2026-118667"]
    assert RULES[LG].severity is Severity.MEDIUM
    assert RULES[LG_API_PIN].severity is Severity.HIGH
    assert "CVE-2026-118667" not in RULES[LG_API_PIN].cve_references


def test_the_langgraph_sdk_fixtures_positive_and_negative() -> None:
    root = CVES / "cve-2026-118667-langgraph-sdk"
    found = mcp_cve_pins_2026_07.scan(root / "vulnerable")[0]
    assert {f.rule_id for f in found} == {LG}
    assert {(f.file_path, f.line_number) for f in found} == {("requirements.txt", 1)}
    for negative in sorted(p for p in root.iterdir() if p.name.startswith("negative")):
        assert not mcp_cve_pins_2026_07.scan(negative)[0], negative.name


@pytest.mark.parametrize(("spec", "new", "auth"), [
    ("0.3.15", False, True),   # no stream module; the 104873 row's own range
    ("0.4.0", True, True),     # the stream module arrives; both flaws
    ("0.4.3", True, True),
    ("0.4.4", True, False),    # the auth fix; the ids are still raw
    ("0.4.5", True, False),    # the last affected release
    (">=0.4,<0.5", True, True),    # a range admits both rows' releases
    (">=0.4.4,<0.5", True, False),
    ("0.4.6", False, False),   # _quote_path_param
    ("0.4.14", False, False),
])
def test_langgraph_sdk_versions(tmp_path: Path, spec: str, new: bool, auth: bool) -> None:
    pinned = spec if spec[0] in "<>=!~" else f"=={spec}"
    found = _write(tmp_path, "requirements.txt", f"langgraph-sdk{pinned}\n")
    assert (LG in found, LG_API_PIN in found) == (new, auth)


def test_langgraph_alone_is_not_reported_and_its_locked_sdk_is(tmp_path: Path) -> None:
    """The advisory lists `langgraph` 1.2.3 to 1.2.13 too, whose RemoteGraph reaches
    the flaw through the SDK it resolves; only the SDK's version decides."""
    assert LG not in _write(tmp_path, "requirements.txt", "langgraph==1.2.13\n")
    lock = ('version = 1\n\n[[package]]\nname = "langgraph"\nversion = "1.2.13"\n\n'
            '[[package]]\nname = "langgraph-sdk"\nversion = "0.4.5"\n')
    found = [f for f in mcp_cve_pins_2026_07.scan(_lock_dir(tmp_path, lock))[0] if f.rule_id == LG]
    assert [f.line_number for f in found] == [8]
    fixed = lock.replace('"0.4.5"', '"0.4.6"')
    assert LG not in _pin_ids(_lock_dir(tmp_path / "fixed", fixed))


def _lock_dir(root: Path, text: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "requirements.txt").unlink(missing_ok=True)
    (root / "uv.lock").write_text(text, encoding="utf-8")
    return root


# -- #1185: Claude Code's Edit tool symlink race raises the HIGH pin's floor to 2.1.251 --------


def test_the_claude_code_floor_is_2_1_251_and_names_the_new_cve() -> None:
    """GHSA-5xjx-9qx6-jcrv gives `@anthropic-ai/claude-code` below 2.1.251, the class of
    CVE-2026-103435 at the same severity, so the floor rises; the LOW pin is unchanged."""
    assert "CVE-2026-88968" in RULES[CC].cve_references
    assert RULES[CC].severity is Severity.HIGH
    assert "2.1.251" in RULES[CC].title
    assert "CVE-2026-88968" not in RULES[CC_LOW].cve_references
    assert _rows(CC_LOW) == [(("@anthropic-ai/claude-code",), (2, 1, 260), (2, 0, 68), True, "js")]


def test_the_claude_code_fixtures_positive_and_negative() -> None:
    root = CVES / "cve-2026-88968-claude-code"
    vulnerable = [f for f in supply_chain_scan(root / "vulnerable")[0] if f.rule_id == CC]
    assert len(vulnerable) == 1
    assert "CVE-2026-88968" in vulnerable[0].evidence
    assert "CVE-2026-86063" not in vulnerable[0].evidence  # fixed in 2.1.179
    assert not [f for f in supply_chain_scan(root / "negative")[0] if f.rule_id == CC]


@pytest.mark.parametrize("fixture", [
    "cve-2026-103435-claude-code/negative",
    "cve-2026-86063-claude-code/negative",
    "cve-2026-40068-claudecode/pin-safe",
])
def test_the_older_safe_fixtures_moved_to_the_new_floor(fixture: str) -> None:
    text = (CVES / fixture / "package.json").read_text()
    assert "2.1.251" in text
    assert not [f for f in supply_chain_scan(CVES / fixture)[0] if f.rule_id == CC]


# -- #1171: praktor, through the advisory feed after `aak update` ------------------------------

PRAKTOR = CVES / "cve-2026-62331-praktor"


def _cache_osv_records() -> None:
    records = [json.loads(p.read_text()) for p in sorted((PRAKTOR / "osv").glob("*.json"))]
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "records": records,
                                "nvd": [], "launch": []}))


def test_the_osv_records_name_the_go_module_below_0_9_1() -> None:
    for path in sorted((PRAKTOR / "osv").glob("*.json")):
        record = json.loads(path.read_text())
        assert "CVE-2026-62331" in record["aliases"]
        (affected,) = record["affected"]
        assert affected["package"] == {"name": "github.com/mtzanidakis/praktor", "ecosystem": "Go",
                                       "purl": "pkg:golang/github.com/mtzanidakis/praktor"}
        assert affected["ranges"] == [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.9.1"}]}]


def test_known_vuln_reports_praktor_from_go_mod_after_an_update() -> None:
    _cache_osv_records()
    found = [f for f in run_scan(PRAKTOR / "vulnerable").findings if f.rule_id == KNOWN]
    assert len(found) == 1
    assert found[0].severity is Severity.HIGH
    assert "CVE-2026-62331" in found[0].evidence and "0.9.1" in found[0].evidence
    assert not [f for f in run_scan(PRAKTOR / "negative").findings if f.rule_id == KNOWN]


def test_without_an_update_praktor_is_not_reported() -> None:
    assert "praktor" not in advisory_feed.BUNDLED_FEED.read_text()
    assert not [f for f in run_scan(PRAKTOR / "vulnerable").findings if f.rule_id == KNOWN]


def test_no_pin_names_praktor() -> None:
    from agent_audit_kit.scanners import container_image_pins

    assert not any("praktor" in pin.image for pin in container_image_pins._PINS)
    assert not any("praktor" in name for p in mcp_cve_pins_2026_07._PINS for name in p.names)


# -- #1188: Claude Desktop's record shares the CLI's vendor and product ------------------------


def test_the_desktop_record_maps_to_no_package() -> None:
    """The CNA writes Claude Desktop's CVE-2026-88066 (below 1.8089.0) under vendor
    `anthropics`, product `claude-code`, the CLI's repository name. Mapped to npm's
    `@anthropic-ai/claude-code`, it would report every 1.x CLI release under a Windows
    desktop flaw, so the reviewed map holds no such row."""
    (vuln,) = json.loads((FIXTURES / "nvd_cna" / "CVE-2026-88066.json").read_text())["vulnerabilities"]
    assert vuln["cve"]["affected"][0]["affectedData"][0]["product"] == "claude-code"
    assert nvd_feed.record_entries(vuln, nvd_feed.load_package_map(), nvd_feed.Tally()) == []
    assert not [r for r in nvd_feed.load_package_map()
                if (r.vendor.lower(), r.product.lower()) == ("anthropics", "claude-code")]


# -- #1174: Zuke ships on JSR, which AAK does not read -----------------------------------------


def test_a_deno_manifest_naming_zuke_is_not_read(tmp_path: Path) -> None:
    (tmp_path / "deno.json").write_text(json.dumps({"imports": {"@zuke/core": "jsr:@zuke/core@1.50.0"}}))
    findings = run_scan(tmp_path).findings
    assert not [f for f in findings if "zuke" in f.evidence.lower() or "CVE-2026-119287" in f.evidence]


# -- the ledger ---------------------------------------------------------------------------------

ISSUES = [
    ("#1145", "CVE-2026-111960", True), ("#1146", "CVE-2026-118667", False),
    ("#1147", "CVE-2026-111961", True), ("#1171", "CVE-2026-62331", False),
    ("#1174", "CVE-2026-119287", True), ("#1181", "CVE-2026-99164", True),
    ("#1185", "CVE-2026-88968", False), ("#1186", "CVE-2026-110732", True),
    ("#1187", "CVE-2026-62264", False), ("#1188", "CVE-2026-88066", True),
]


@pytest.mark.parametrize(("issue", "cve", "out_of_scope"), ISSUES)
def test_every_issue_has_one_ledger_row(issue: str, cve: str, out_of_scope: bool) -> None:
    rows = [line for line in LEDGER.read_text().splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith(f"| {issue} |")
    assert ("out of scope" in rows[0].lower()) is out_of_scope
