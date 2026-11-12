"""#1226 and five held records: AgentScope, IBM ContextForge, mcp-atlassian, and three
out of scope (ash_ai on Hex, Apache Axis2/Java, Apache Storm).

Every range below was read in the published artifacts on 2026-11-11: the PyPI wheels
of agentscope (1.0.21, 2.0.0, 2.0.4.post1, 2.0.7.post1, 2.0.11) and of
mcp-contextforge-gateway (0.1.0, 0.6.0, 0.7.0, 0.8.0, 0.9.0, 1.0.0,
1.0.7.post20260921, 1.0.11, 1.1.0), and mcp-atlassian's source at v0.21.1, v0.22.0,
v0.24.0 and v0.24.1. AgentScope's NVD record is saved unedited under
tests/fixtures/nvd_cna (since #1205); the feed tests convert it as `aak update` does,
in the empty HOME every test gets. `CHANGELOG.cves.md` holds the reasoning.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from agent_audit_kit import advisory_feed, nvd_feed
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Category, Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import container_image_pins, mcp_cve_pins_2026_07

AGENTSCOPE_PIN = "AAK-MCP-AGENTSCOPE-CVE-2026-123022-001"
CONTEXTFORGE_PIN = "AAK-MCP-CONTEXTFORGE-CVE-2026-18484-001"
CONTEXTFORGE_CRITICAL_PIN = "AAK-MCP-CONTEXTFORGE-CVE-2026-77822-001"
ATLASSIAN_PIN = "AAK-MCP-ATLASSIAN-CVE-2026-124503-001"
ATLASSIAN_UPLOAD_PIN = "AAK-MCP-ATLASSIAN-CVE-2026-73498-001"
KNOWN = "AAK-KNOWN-VULN-001"

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CVES = FIXTURES / "cves"
NVD_CNA = FIXTURES / "nvd_cna"
LEDGER = Path(__file__).resolve().parent.parent / "CHANGELOG.cves.md"

NEW_RULES = (
    (AGENTSCOPE_PIN, "CVE-2026-123022", Severity.HIGH),
    (CONTEXTFORGE_PIN, "CVE-2026-18484", Severity.MEDIUM),
    (ATLASSIAN_PIN, "CVE-2026-124503", Severity.HIGH),
)
OUT_OF_SCOPE = ("CVE-2026-119613", "CVE-2026-123779", "CVE-2026-82436")
# A later batch's record joined the rule: CVE-2026-123024 (#1232, 2026-11-12), the
# service's caller-set identity, has the same releases and no fix either.
LATER_REFERENCES = {AGENTSCOPE_PIN: ["CVE-2026-123022", "CVE-2026-123024"]}


def _pins(scanned: Path) -> list:
    return mcp_cve_pins_2026_07.scan(scanned)[0] + container_image_pins.scan(scanned)[0]


def _ids(tmp_path: Path, name: str, content: str) -> set[str]:
    (tmp_path / name).write_text(content, encoding="utf-8")
    return {f.rule_id for f in _pins(tmp_path)}


def _rows(rule_id: str) -> list[tuple]:
    return [(p.names, p.floor, p.introduced, p.requires_version, p.ecosystem)
            for p in mcp_cve_pins_2026_07._PINS if p.rule_id == rule_id]


def _image_rows(rule_id: str) -> list[tuple]:
    return [(p.image, p.floor, p.introduced, p.floating_affected, p.cves)
            for p in container_image_pins._PINS if p.rule_id == rule_id]


@pytest.mark.parametrize(("rule_id", "cve", "severity"), NEW_RULES)
def test_each_rule_names_only_its_own_cve(rule_id: str, cve: str, severity: Severity) -> None:
    rule = RULES[rule_id]
    assert rule.severity is severity
    assert rule.category is Category.SUPPLY_CHAIN
    assert rule.cve_references == LATER_REFERENCES.get(rule_id, [cve])
    assert cve in rule.description


def test_the_pins_are_the_ranges_the_artifacts_show() -> None:
    """AgentScope: 1.0.21 has no `agentscope.app`, 2.0.0 and 2.0.11 have the route, and
    there is no fix, so presence-only from 2.0.0, PyPI only. ContextForge: tool names
    unique per team and owner from 0.7.0, fixed in 1.1.0. mcp-atlassian: the
    working-directory guard arrives in 0.22.0, and 0.24.1 adds MCP_ATLASSIAN_FILES_DIR.
    Where `latest` is fixed, a stated version is required."""
    assert _rows(AGENTSCOPE_PIN) == [(("agentscope",), None, (2, 0, 0), False, "py")]
    assert _rows(CONTEXTFORGE_PIN) == [(("mcp-contextforge-gateway",), (1, 1, 0), (0, 7, 0), True, "py")]
    assert _rows(ATLASSIAN_PIN) == [(("mcp-atlassian",), (0, 24, 1), (0, 22, 0), True, "py")]


def test_the_image_rows() -> None:
    """ContextForge's README and chart run its image, so the new rule reads its tags;
    `latest` was the v1.1.1 digest on 2026-11-11. mcp-atlassian's image sets
    `WORKDIR /app`, which holds as the guard's boundary, so its rule has no image row."""
    assert _image_rows(CONTEXTFORGE_PIN) == [
        ("ghcr.io/ibm/mcp-context-forge", (1, 1, 0), (0, 7, 0), False, ("CVE-2026-18484",))]
    assert _image_rows(ATLASSIAN_PIN) == []
    assert _image_rows(AGENTSCOPE_PIN) == []


@pytest.mark.parametrize(("fixture", "rule_id", "where"), [
    ("cve-2026-123022-agentscope", AGENTSCOPE_PIN, {("requirements.txt", 2)}),
    ("cve-2026-18484-contextforge", CONTEXTFORGE_PIN, {("requirements.txt", 2), ("values.yaml", 5)}),
    ("cve-2026-124503-mcp-atlassian", ATLASSIAN_PIN, {(".mcp.json", 5)}),
])
def test_fixtures_positive_and_negative(fixture: str, rule_id: str, where: set) -> None:
    """The affected release fires on its own lines and nothing else from either pin
    table does; every `negative*` tree stays quiet."""
    root = CVES / fixture
    vulnerable = _pins(root / "vulnerable")
    assert {f.rule_id for f in vulnerable} == {rule_id}
    assert {(f.file_path, f.line_number) for f in vulnerable} == where
    negatives = sorted(p for p in root.iterdir() if p.name.startswith("negative"))
    assert negatives
    for negative in negatives:
        assert not _pins(negative), negative.name


@pytest.mark.parametrize(("fixture", "rule_id", "severity"), [
    ("cve-2026-123022-agentscope", AGENTSCOPE_PIN, Severity.HIGH),
    ("cve-2026-18484-contextforge", CONTEXTFORGE_PIN, Severity.MEDIUM),
    ("cve-2026-124503-mcp-atlassian", ATLASSIAN_PIN, Severity.HIGH),
])
def test_the_finding_survives_the_full_engine(fixture: str, rule_id: str, severity: Severity) -> None:
    found = [f for f in run_scan(CVES / fixture / "vulnerable").findings if f.rule_id == rule_id]
    assert found and all(f.severity is severity for f in found)


# --- AgentScope (#1226) ---------------------------------------------------------------


@pytest.mark.parametrize(("name", "content", "fires"), [
    ("requirements.txt", "agentscope==1.0.21\n", False),           # the last 1.x, no service
    ("requirements.txt", "agentscope==2.0.0\n", True),             # the service's first release
    ("requirements.txt", "agentscope==2.0.4.post1\n", True),       # read as 2.0.4; the route is there
    ("requirements.txt", "agentscope==2.0.11\n", True),            # the newest
    ("requirements.txt", "agentscope==2.0.12\n", True),            # presence-only: no fix yet
    ("requirements.txt", "agentscope[service]==2.0.11\n", True),
    ("requirements.txt", "agentscope\n", True),                    # installs 2.0.11
    ("requirements.txt", "agentscope>=1.0\n", True),               # admits 2.x
    ("requirements.txt", "agentscope<2\n", False),
    ("uv.lock", '[[package]]\nname = "agentscope"\nversion = "2.0.8"\n', True),
    (".mcp.json", '{"mcpServers": {"a": {"command": "uvx", "args": ["agentscope"]}}}', True),
    ("package.json", '{"dependencies": {"agentscope": "0.1.1"}}', False),   # npm's is another project
])
def test_agentscope_references(tmp_path: Path, name: str, content: str, fires: bool) -> None:
    assert (AGENTSCOPE_PIN in _ids(tmp_path, name, content)) is fires


def _cache_agentscope_record() -> None:
    """The feed `aak update` writes from NVD, holding CVE-2026-123022 as `nvd_feed`
    converts it through the reviewed `agentscope` row of data/cna_package_map.json."""
    (vuln,) = json.loads((NVD_CNA / "CVE-2026-123022.json").read_text(encoding="utf-8"))["vulnerabilities"]
    entries = nvd_feed.record_entries(vuln, nvd_feed.load_package_map(), nvd_feed.Tally())
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "records": [],
                                "nvd": nvd_feed.merged(entries)}), encoding="utf-8")


def test_the_feed_entry_lists_twelve_releases_and_no_range() -> None:
    """The CNA lists 2.0.0 to 2.0.11 one by one, with no fixed release, so the feed holds
    those twelve versions and nothing a later release or a post release would match."""
    (vuln,) = json.loads((NVD_CNA / "CVE-2026-123022.json").read_text(encoding="utf-8"))["vulnerabilities"]
    (entry,) = nvd_feed.record_entries(vuln, nvd_feed.load_package_map(), nvd_feed.Tally())
    assert (entry["ecosystem"], entry["name"], entry["ranges"], entry["severity"]) == (
        "PyPI", "agentscope", [], "HIGH")
    assert sorted(entry["versions"]) == sorted(f"2.0.{n}" for n in range(12))


def _uv_lock(root: Path, version: str) -> None:
    (root / "uv.lock").write_text(
        'version = 1\nrequires-python = ">=3.10"\n\n[[package]]\nname = "agentscope"\n'
        f'version = "{version}"\nsource = {{ registry = "https://pypi.org/simple" }}\n',
        encoding="utf-8")


@pytest.mark.parametrize("version", ["2.0.0", "2.0.11"])
def test_after_update_the_pin_reports_the_record_alone(tmp_path: Path, version: str) -> None:
    """With the record cached, the HIGH pin stands and the engine drops the feed's HIGH
    finding on the same line, since the rule names its CVE at the same severity."""
    _cache_agentscope_record()
    _uv_lock(tmp_path, version)
    findings = run_scan(tmp_path).findings
    (pin,) = [f for f in findings if f.rule_id == AGENTSCOPE_PIN]
    assert pin.severity is Severity.HIGH
    assert not [f for f in findings if f.rule_id == KNOWN]


@pytest.mark.parametrize(("version", "feed_reports"), [
    ("2.0.11", True),         # a release the record lists
    ("2.0.4.post1", False),   # carries the route, but the record lists no post release
    ("2.0.12", False),        # a later release, which the record cannot name
    ("1.0.21", False),
])
def test_without_the_pin_the_feed_reports_only_the_listed_releases(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: str, feed_reports: bool) -> None:
    """The control: with the pin's reference taken out, AAK-KNOWN-VULN-001 reports what
    0.6.34 reported after `aak update`, the twelve listed releases and nothing else."""
    rule = RULES[AGENTSCOPE_PIN]
    monkeypatch.setitem(RULES, AGENTSCOPE_PIN, dataclasses.replace(rule, cve_references=[]))
    _cache_agentscope_record()
    _uv_lock(tmp_path, version)
    findings = run_scan(tmp_path).findings
    known = [f for f in findings if f.rule_id == KNOWN and "CVE-2026-123022" in f.evidence]
    assert bool(known) is feed_reports


def test_the_bundled_feed_does_not_hold_the_record() -> None:
    """Without `aak update` only the pin reports AgentScope."""
    assert "CVE-2026-123022" not in advisory_feed.BUNDLED_FEED.read_text(encoding="utf-8")


# --- IBM ContextForge (CVE-2026-18484) ------------------------------------------------


@pytest.mark.parametrize(("version", "new", "critical"), [
    ("0.6.0", False, True),               # tool names unique across the database
    ("0.7.0", True, True),                # unique per team and owner from here
    ("0.9.0", True, True),                # `scalar_one_or_none()` fails on a duplicate
    ("1.0.0rc1", True, True),             # read as 1.0.0, where IBM's range starts
    ("1.0.7.post20260921", True, True),   # the 1.0.7 support line
    ("1.0.8", True, True),
    ("1.0.9", True, False),               # the CRITICAL rule's floor
    ("1.0.11", True, False),              # the last release IBM lists
    ("1.1.0", False, False),              # #6534 refuses the collision
    (">=1.0", True, True),
])
def test_contextforge_versions(tmp_path: Path, version: str, new: bool, critical: bool) -> None:
    pinned = version if version[0] in "<>=!~" else f"=={version}"
    found = _ids(tmp_path, "requirements.txt", f"mcp-contextforge-gateway{pinned}\n")
    assert (CONTEXTFORGE_PIN in found, CONTEXTFORGE_CRITICAL_PIN in found) == (new, critical)


def test_contextforge_unversioned_is_not_this_rules_to_report(tmp_path: Path) -> None:
    """`latest` is 1.1.1, fixed; the CRITICAL row still reports an unversioned name."""
    found = _ids(tmp_path, "requirements.txt", "mcp-contextforge-gateway\n")
    assert CONTEXTFORGE_PIN not in found and CONTEXTFORGE_CRITICAL_PIN in found


@pytest.mark.parametrize(("ref", "fires"), [
    ("ghcr.io/ibm/mcp-context-forge:0.6.0", False),
    ("ghcr.io/ibm/mcp-context-forge:v0.7.0", True),
    ("ghcr.io/ibm/mcp-context-forge:1.0.0-RC-2", True),
    ("ghcr.io/ibm/mcp-context-forge:v1.0.7-20260921", True),
    ("ghcr.io/ibm/mcp-context-forge:v1.0.11", True),
    ("ghcr.io/ibm/mcp-context-forge:v1.1.0", False),
    ("ghcr.io/ibm/mcp-context-forge:latest", False),   # the v1.1.1 digest on 2026-11-11
    ("ghcr.io/ibm/mcp-context-forge", False),
])
def test_contextforge_image_tags(tmp_path: Path, ref: str, fires: bool) -> None:
    found = _ids(tmp_path, "docker-compose.yml", f"services:\n  gateway:\n    image: {ref}\n")
    assert (CONTEXTFORGE_PIN in found) is fires


# --- mcp-atlassian (CVE-2026-124503) ---------------------------------------------------


@pytest.mark.parametrize(("version", "new", "older"), [
    ("0.21.1", False, True),    # no upload guard at all: the 0.22.0 row's flaw
    ("0.22.0", True, False),    # validate_safe_path(file_path), boundary os.getcwd()
    ("0.23.1", True, False),
    ("0.24.0", True, False),    # 2026-11-08 10:06, five hours before the fix
    ("0.24.1", False, False),   # MCP_ATLASSIAN_FILES_DIR, and a wide root refused
    (">=0.23", True, False),
])
def test_atlassian_versions(tmp_path: Path, version: str, new: bool, older: bool) -> None:
    pinned = version if version[0] in "<>=!~" else f"=={version}"
    found = _ids(tmp_path, "requirements.txt", f"mcp-atlassian{pinned}\n")
    assert (ATLASSIAN_PIN in found, ATLASSIAN_UPLOAD_PIN in found) == (new, older)


def test_atlassian_unversioned_is_not_this_rules_to_report(tmp_path: Path) -> None:
    assert ATLASSIAN_PIN not in _ids(tmp_path, "requirements.txt", "mcp-atlassian\n")


def test_atlassian_image_is_a_stated_limitation() -> None:
    """The project's image pins WORKDIR /app, so the rule does not read it; a container
    started with `working_dir: /` is exposed and not reported, and the text says so."""
    limitation = CVES / "cve-2026-124503-mcp-atlassian" / "limitation-image"
    assert ATLASSIAN_PIN not in {f.rule_id for f in _pins(limitation)}
    assert "is not read for this rule" in RULES[ATLASSIAN_PIN].limitations


# --- Ledger ----------------------------------------------------------------------------


def _ledger_rows(cve: str) -> list[str]:
    return [line for line in LEDGER.read_text(encoding="utf-8").splitlines()
            if line.startswith(f"| {cve} ")]


@pytest.mark.parametrize(("cve", "issue", "rule_id"), [
    ("CVE-2026-123022", "#1226", AGENTSCOPE_PIN),
    ("CVE-2026-18484", "not filed", CONTEXTFORGE_PIN),
    ("CVE-2026-124503", "not filed", ATLASSIAN_PIN),
])
def test_covered_rows_name_their_rule(cve: str, issue: str, rule_id: str) -> None:
    (row,) = _ledger_rows(cve)
    assert row.rstrip().endswith(f"| {issue} |")
    assert rule_id in row and "out of scope" not in row.lower()


@pytest.mark.parametrize("cve", OUT_OF_SCOPE)
def test_out_of_scope_rows(cve: str) -> None:
    (row,) = _ledger_rows(cve)
    assert row.rstrip().endswith("| not filed |")
    assert "Out of scope" in row
    assert not any(cve in rule.cve_references for rule in RULES.values())


def test_no_older_rule_claims_the_new_records() -> None:
    """Each new record is on its own rule only: the CRITICAL ContextForge pin and the
    0.22.0 mcp-atlassian pin keep their references, which are fixed below 1.0.9 and at
    0.22.0, so a floor raise would have reported the releases in between under them."""
    for _, cve, _ in NEW_RULES:
        assert [rid for rid, rule in RULES.items() if cve in rule.cve_references] == [
            rid for rid, c, _ in NEW_RULES if c == cve]
