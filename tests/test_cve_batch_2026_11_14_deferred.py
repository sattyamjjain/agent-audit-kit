"""2026-11-14 batch, group "deferred": the six dated deferrals and the Penpot half of #872,
read on 2026-11-14.

PraisonAI's job-workflow sandbox (CVE-2026-61438, #1144) gets a presence-only rule of its
own from 4.6.78: the advisory names 4.6.78 as the fix, but PyPI has no 4.6.78, and the
same `_exec_inline_python` is in every `praisonai` wheel from 4.6.81 to 4.6.102 and in
every `praisonai-code` release (0.0.1 to 0.1.21), which `praisonai` requires and loads it
from from 4.6.103 to 4.7.24. Below 4.6.78 the 4.6.78 rule keeps reporting it, so each
release is reported for it once. Five records with no release a project could name are
out of scope: SurfSense's retired backend (#850), the Continue IDE extension (#1097),
and three git-only servers, esp-mcp (#1107), hagent (#1110) and nmap-mcp (#1114).
Penpot's bridge rule (#872) now says where its fix is published: npm 2.19.1, under the
`next` dist-tag, while `latest` is still 2.15.4.

NVD's records are saved unedited under tests/fixtures/nvd_cna, as the API returned them
on 2026-11-14, and GHSA-26mh-57q7-jfvr under tests/fixtures/osv as OSV gave it on
2026-11-11. A test that needs the feed `aak update` writes builds it from those records in
the empty HOME every test gets. `CHANGELOG.cves.md` holds the reasoning. Nothing here
touches the network.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_audit_kit import advisory_feed, nvd_feed
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Category, Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import container_image_pins, mcp_cve_pins_2026_07

SANDBOX_PIN = "AAK-PRAISONAI-CVE-2026-61438-001"
FLOOR_PIN = "AAK-MCP-PRAISONAI-CVE-2026-61427-001"
NPM_PRAISONAI_PIN = "AAK-MCP-PRAISONAI-TS-CVE-2026-57139-001"
BRIDGE_PIN = "AAK-MCP-PENPOT-CVE-2026-100868-001"
REPL_PIN = "AAK-MCP-PENPOT-CVE-2026-45805-001"
OFFICEPPT_PIN = "AAK-MCP-OFFICEPPT-CVE-2025-71427-001"
KNOWN_VULN_RULE = "AAK-KNOWN-VULN-001"

SANDBOX = "CVE-2026-61438"
SANDBOX_GHSA = "GHSA-26mh-57q7-jfvr"
SURFSENSE = "CVE-2026-102243"
CONTINUE = "CVE-2026-116109"
ESP_MCP = "CVE-2026-117567"
HAGENT = "CVE-2026-117573"
NMAP_MCP = "CVE-2026-117570"
OUT_OF_SCOPE = (SURFSENSE, CONTINUE, ESP_MCP, HAGENT, NMAP_MCP)

HERE = Path(__file__).parent
CVES = HERE / "fixtures" / "cves"
NVD_CNA = HERE / "fixtures" / "nvd_cna"
OSV = HERE / "fixtures" / "osv"
LEDGER = HERE.parent / "CHANGELOG.cves.md"
PRAISONAI_FIXTURES = CVES / "cve-2026-61438-praisonai"
PENPOT_FIXTURES = CVES / "cve-2026-100868-penpot-mcp"
NOW = datetime(2026, 11, 14, 6, 0, tzinfo=timezone.utc)


def _pins(root: Path) -> list:
    return mcp_cve_pins_2026_07.scan(root)[0] + container_image_pins.scan(root)[0]


def _ids(tmp_path: Path, name: str, content: str) -> set[str]:
    (tmp_path / name).write_text(content, encoding="utf-8")
    return {f.rule_id for f in _pins(tmp_path)}


def _rows(rule_id: str) -> list[tuple]:
    return [(p.names, p.floor, p.introduced, p.requires_version, p.ecosystem)
            for p in mcp_cve_pins_2026_07._PINS if p.rule_id == rule_id]


def _nvd_record(cve: str) -> dict:
    (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text(encoding="utf-8"))["vulnerabilities"]
    return vuln


def _mentions(root: Path, cve: str) -> list[str]:
    return [f.rule_id for f in run_scan(root).findings if cve in f.evidence]


def test_nvd_records_are_the_ones_read() -> None:
    """Each saved record is the CVE it is filed under, with the text the ledger quotes."""
    expected = {
        SURFSENSE: "A vulnerability was identified in MODSetter SurfSense up to 2.0.3.",
        CONTINUE: "A vulnerability has been found in continuedev Continue 2.0.0.",
        ESP_MCP: "esp-mcp through commit 28afddf contains an OS command injection",
        HAGENT: "hagent through commit 761eec6 contains an OS command injection",
        NMAP_MCP: "Vorota-ai nmap-mcp through commit 3636afa contains an improper allowlist",
        SANDBOX: "PraisonAI before 4.6.78 contains a remote code execution vulnerability",
    }
    for cve, opening in expected.items():
        record = _nvd_record(cve)["cve"]
        assert record["id"] == cve
        assert record["descriptions"][0]["value"].startswith(opening)


# --- PraisonAI (CVE-2026-61438, #1144): a presence-only rule from 4.6.78 -------------------


def test_the_sandbox_rule() -> None:
    """The executor is PraisonAI's own workflow runner, not MCP: no MCP area, no MCP id."""
    rule = RULES[SANDBOX_PIN]
    assert rule.severity is Severity.HIGH and rule.category is Category.SUPPLY_CHAIN
    assert rule.cve_references == [SANDBOX] and rule.owasp_mcp_references == []
    assert SANDBOX_GHSA in rule.description and "no fixed release" in rule.title
    assert "PRAISONAI_ALLOW_JOB_WORKFLOWS" in rule.remediation and "#6368" in rule.remediation
    assert "`praisonai-code`" in rule.limitations
    assert rule.limitations.endswith("a lockfile entry keeps its line at any depth.")
    # The advisory's `import os` proof fails at run time; the text says so and names
    # the route that does not need it.
    assert "lack `__import__`" in rule.description and "`builtins` module" in rule.description


def test_the_cve_sits_on_two_rules_over_disjoint_ranges() -> None:
    """Below 4.6.78 on the floor rule, as the advisory scopes it; from 4.6.78 on its
    own presence-only row. No release falls in both."""
    assert [rid for rid, rule in RULES.items() if SANDBOX in rule.cve_references] == [FLOOR_PIN, SANDBOX_PIN]
    assert _rows(FLOOR_PIN) == [(("praisonai",), (4, 6, 78), None, False, "py")]
    assert _rows(SANDBOX_PIN) == [(("praisonai",), None, (4, 6, 78), False, "py")]
    assert not [p for p in container_image_pins._PINS if p.rule_id == SANDBOX_PIN]


@pytest.mark.parametrize(("name", "content", "floor", "sandbox"), [
    ("requirements.txt", "praisonai==4.6.70\n", True, False),
    ("requirements.txt", "praisonai==4.6.77\n", True, False),       # the last release below the floor
    ("requirements.txt", "praisonai==4.6.78\n", False, True),       # not on PyPI; its tag allows `os`
    ("requirements.txt", "praisonai==4.6.81\n", False, True),       # PyPI's next release after 4.6.77
    ("requirements.txt", "praisonai==4.6.102\n", False, True),      # the last with the executor in its wheel
    ("requirements.txt", "praisonai==4.6.103\n", False, True),      # from here through praisonai-code
    ("requirements.txt", "praisonai==4.7.24\n", False, True),       # the newest
    ("requirements.txt", "praisonai[ui]==4.7.24\n", False, True),
    ("requirements.txt", "praisonai\n", True, True),                # installs 4.7.24; see the limitations
    ("requirements.txt", "praisonai>=4.6.0\n", True, True),         # admits both sides of 4.6.78
    ("requirements.txt", "praisonai<4.6.78\n", True, False),
    ("requirements.txt", "praisonai>=4.6.81\n", False, True),
    ("requirements.txt", "praisonai~=4.7.0\n", False, True),
    ("requirements.txt", "praisonai-code==0.1.21\n", False, False),  # named by neither record
    ("requirements.txt", "praisonaiagents==1.6.153\n", False, False),
    ("pyproject.toml", '[project]\nname = "x"\nversion = "1"\ndependencies = ["praisonai==4.7.24"]\n',
     False, True),
    ("poetry.lock", '[[package]]\nname = "praisonai"\nversion = "4.6.81"\n', False, True),
    (".mcp.json", '{"mcpServers": {"p": {"command": "uvx", "args": ["praisonai==4.7.24"]}}}', False, True),
    (".mcp.json", '{"mcpServers": {"p": {"command": "npx", "args": ["-y", "praisonai@1.7.4"]}}}',
     False, False),                                                  # npm's praisonai is another project
    ("package.json", '{"dependencies": {"praisonai": "1.7.4"}}', False, False),
])
def test_praisonai_references(tmp_path: Path, name: str, content: str, floor: bool, sandbox: bool) -> None:
    found = _ids(tmp_path, name, content)
    assert (FLOOR_PIN in found, SANDBOX_PIN in found) == (floor, sandbox)


@pytest.mark.parametrize("version", ["4.6.70", "4.6.77", "4.6.78", "4.6.81", "4.6.102", "4.6.103", "4.7.24"])
def test_each_release_is_reported_once_for_the_cve(tmp_path: Path, version: str) -> None:
    (tmp_path / "requirements.txt").write_text(f"praisonai=={version}\n", encoding="utf-8")
    naming = [f.rule_id for f in run_scan(tmp_path).findings if SANDBOX in RULES[f.rule_id].cve_references]
    assert len(naming) == 1, naming


@pytest.mark.parametrize(("fixture", "where"), [
    ("vulnerable", {(FLOOR_PIN, "requirements.txt", 1)}),     # 4.6.77, below the floor
    ("after-floor", {(SANDBOX_PIN, "requirements.txt", 1)}),  # 4.6.81
    ("newest", {(SANDBOX_PIN, "uv.lock", 5)}),                # 4.7.24 with praisonai-code 0.1.21
    ("negative", set()),                                      # npm praisonai 1.7.4
    ("code-only", set()),                                     # praisonai-code alone: a stated limitation
])
def test_praisonai_fixtures(fixture: str, where: set) -> None:
    assert {(f.rule_id, f.file_path, f.line_number) for f in _pins(PRAISONAI_FIXTURES / fixture)} == where


@pytest.mark.parametrize("fixture", ["after-floor", "newest"])
def test_the_finding_survives_the_full_engine(fixture: str) -> None:
    found = [f for f in run_scan(PRAISONAI_FIXTURES / fixture).findings if f.rule_id == SANDBOX_PIN]
    assert found and all(f.severity is Severity.HIGH for f in found)
    assert all("no fixed release" in f.evidence and "#6368" in f.evidence for f in found)


def test_the_bundled_feed_does_not_hold_the_record() -> None:
    bundled = advisory_feed.BUNDLED_FEED.read_text(encoding="utf-8")
    assert SANDBOX not in bundled and SANDBOX_GHSA not in bundled


def _uv_lock(root: Path, version: str) -> None:
    (root / "uv.lock").write_text(
        'version = 1\nrequires-python = ">=3.10"\n\n[[package]]\nname = "praisonai"\n'
        f'version = "{version}"\nsource = {{ registry = "https://pypi.org/simple" }}\n',
        encoding="utf-8")


def _cache_osv() -> None:
    record = json.loads((OSV / f"{SANDBOX_GHSA}.json").read_text(encoding="utf-8"))
    collector = advisory_feed.Collector()
    collector.add("PyPI", record)
    collector.write(now=NOW)


def _cache_nvd() -> None:
    collector = advisory_feed.Collector()
    collector.add_nvd(nvd_feed.record_entries(_nvd_record(SANDBOX), nvd_feed.load_package_map(),
                                              nvd_feed.Tally()), None)
    collector.write(now=NOW)


def test_the_nvd_record_maps_to_the_advisory_s_range() -> None:
    """NVD's CNA data names `pkg:pypi/praisonai` below 4.6.78, the advisory's range."""
    entries = nvd_feed.record_entries(_nvd_record(SANDBOX), nvd_feed.load_package_map(), nvd_feed.Tally())
    assert [(e["ecosystem"], e["name"], e["ranges"], e["severity"]) for e in entries] == [
        ("PyPI", "praisonai", [{"introduced": "0", "fixed": "4.6.78"}], "HIGH")]


@pytest.mark.parametrize("cache", [_cache_osv, _cache_nvd])
@pytest.mark.parametrize(("version", "rule_id"), [
    ("4.6.77", FLOOR_PIN), ("4.6.81", SANDBOX_PIN), ("4.7.24", SANDBOX_PIN),
])
def test_after_update_one_rule_reports_the_cve(tmp_path: Path, cache, version: str, rule_id: str) -> None:
    """Below 4.6.78 the feed's HIGH finding stands down for the floor rule, which names
    the CVE on the same line; from 4.6.81 the feed, which reads the advisory's range,
    is silent and the sandbox rule alone reports it."""
    cache()
    _uv_lock(tmp_path, version)
    findings = run_scan(tmp_path).findings
    assert [f.rule_id for f in findings if f.rule_id in (FLOOR_PIN, SANDBOX_PIN)] == [rule_id]
    assert not [f for f in findings if f.rule_id == KNOWN_VULN_RULE]


# --- Penpot (#872): the fix is on npm as 2.19.1, under `next` -------------------------------


@pytest.mark.parametrize(("name", "content", "rules"), [
    ("package.json", '{"dependencies": {"@penpot/mcp": "2.13.3"}}', {BRIDGE_PIN, REPL_PIN}),
    ("package.json", '{"dependencies": {"@penpot/mcp": "2.15.4"}}', {BRIDGE_PIN}),   # `latest`
    ("package.json", '{"dependencies": {"@penpot/mcp": "2.17.0"}}', {BRIDGE_PIN}),   # before the fix
    ("package.json", '{"dependencies": {"@penpot/mcp": "2.19.1"}}', set()),          # `next`, fixed
    ("package.json", '{"dependencies": {"@penpot/mcp": "^2.19.1"}}', set()),
    ("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"@penpot/mcp": "2.19.1"}},
        "node_modules/@penpot/mcp": {"version": "2.19.1"}}}), set()),
    (".mcp.json", '{"mcpServers": {"p": {"command": "npx", "args": ["-y", "@penpot/mcp@2.19.1"]}}}', set()),
    # Unpinned installs `latest`, 2.15.4, which is affected.
    (".mcp.json", '{"mcpServers": {"p": {"command": "npx", "args": ["-y", "@penpot/mcp"]}}}',
     {BRIDGE_PIN, REPL_PIN}),
    # A dist-tag states no version the pins read; `next` is 2.19.1 today. A stated limitation.
    (".mcp.json", '{"mcpServers": {"p": {"command": "npx", "args": ["-y", "@penpot/mcp@next"]}}}',
     {BRIDGE_PIN, REPL_PIN}),
])
def test_penpot_references(tmp_path: Path, name: str, content: str, rules: set) -> None:
    assert _ids(tmp_path, name, content) & {BRIDGE_PIN, REPL_PIN} == rules


def test_the_penpot_negative_fixture_is_a_published_release() -> None:
    """It read 2.18.0 until 2026-11-14, a number npm never published."""
    manifest = json.loads((PENPOT_FIXTURES / "negative" / "package.json").read_text(encoding="utf-8"))
    assert manifest["dependencies"] == {"@penpot/mcp": "2.19.1"}
    assert not {f.rule_id for f in _pins(PENPOT_FIXTURES / "negative")}


def test_the_penpot_bridge_text_says_where_the_fix_is_published() -> None:
    rule = RULES[BRIDGE_PIN]
    assert "2.19.1 (2026-11-10)" in rule.description and "`next` dist-tag" in rule.description
    assert rule.remediation.startswith("Upgrade `@penpot/mcp` to 2.19.1 or later")
    assert "re-checked 2026-11-14" in rule.limitations and "`npx @penpot/mcp@next`" in rule.limitations
    assert "not on npm yet" not in rule.description + rule.limitations
    assert rule.limitations.endswith("a lockfile entry keeps its line at any depth.")
    (pin,) = [p for p in mcp_cve_pins_2026_07._PINS if p.rule_id == BRIDGE_PIN]
    assert pin.floor == (2, 18, 0) and "2.19.1" in pin.fix_label


def test_powerpoint_stays_presence_only() -> None:
    """Re-checked 2026-11-14: PyPI's newest is still 2.0.7 and upstream PR #33 is open."""
    (pin,) = [p for p in mcp_cve_pins_2026_07._PINS if p.rule_id == OFFICEPPT_PIN]
    assert pin.floor is None and "PR #33 is unmerged and 2.0.7 is the newest" in pin.fix_label


# --- Out of scope: nothing a project names (#850, #1097, #1107, #1110, #1114) ----------------


@pytest.mark.parametrize("cve", OUT_OF_SCOPE)
def test_no_rule_claims_an_out_of_scope_record(cve: str) -> None:
    assert not [rid for rid, r in RULES.items() if cve in r.cve_references]
    assert not [rid for rid, r in RULES.items() if cve in r.title + r.description + r.limitations]


@pytest.mark.parametrize("cve", OUT_OF_SCOPE)
def test_the_feed_cannot_report_them_either(cve: str) -> None:
    """No CNA record names a package, and no reviewed row of the package map names the
    vendor and product, so `aak update` adds nothing for them."""
    tally = nvd_feed.Tally()
    assert nvd_feed.record_entries(_nvd_record(cve), nvd_feed.load_package_map(), tally) == []
    assert tally.unmapped == 1


@pytest.mark.parametrize(("name", "content", "cve"), [
    # SurfSense's last backend image, built from the legacy-v0.0.41 tag, and the 2.3.1
    # product image, built from a codebase without the route.
    ("compose.yaml", "services:\n  backend:\n    image: ghcr.io/modsetter/surfsense-backend:0.0.41\n"
     "  app:\n    image: ghcr.io/modsetter/surfsense:2.3.1\n", SURFSENSE),
    # Continue runs inside the IDE; npm's @continuedev packages are not the extension.
    ("package.json", '{"dependencies": {"@continuedev/cli": "1.5.47", "@continuedev/core": "1.1.0"}}',
     CONTINUE),
    # The three git-only servers run from a clone or a locally built image.
    (".mcp.json", '{"mcpServers": {"esp": {"command": "uv", "args": ["--directory", '
     '"/opt/esp-mcp", "run", "main.py"]}}}', ESP_MCP),
    (".mcp.json", '{"mcpServers": {"hagent": {"command": "uv", "args": ["--directory", '
     '"/opt/hagent", "run", "hagent/mcp/mcp_esp32.py"]}}}', HAGENT),
    (".mcp.json", '{"mcpServers": {"nmap": {"command": "docker", "args": ["run", "-i", "--rm", '
     '"nmap-mcp"]}}}', NMAP_MCP),
])
def test_out_of_scope_projects_draw_no_finding_for_the_record(
        tmp_path: Path, name: str, content: str, cve: str) -> None:
    (tmp_path / name).write_text(content, encoding="utf-8")
    assert _mentions(tmp_path, cve) == []


# --- The ledger --------------------------------------------------------------------------


def _ledger_rows(cve: str) -> list[str]:
    return [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {cve} ")]


@pytest.mark.parametrize(("cve", "issue"), [
    (SURFSENSE, "#850"), (CONTINUE, "#1097"), (ESP_MCP, "#1107"), (HAGENT, "#1110"), (NMAP_MCP, "#1114"),
])
def test_out_of_scope_rows(cve: str, issue: str) -> None:
    (row,) = _ledger_rows(cve)
    assert row.rstrip().endswith(f"| {issue} |") and "**out of scope**" in row.lower()


def test_the_sandbox_row_names_its_rule() -> None:
    (row,) = [line for line in _ledger_rows(SANDBOX) if SANDBOX_PIN in line]
    assert row.rstrip().endswith("| #1144 |") and "out of scope" not in row.lower()


def test_the_penpot_row() -> None:
    (row,) = [line for line in _ledger_rows("CVE-2026-100868") if line.rstrip().endswith("| #872 |")]
    assert BRIDGE_PIN in row and "2.19.1" in row and "out of scope" not in row.lower()
