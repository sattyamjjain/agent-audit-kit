"""#1231 and #1232: two VulDB records for AgentScope (PyPI `agentscope`).

CVE-2026-123023, the workspace Bash tool counting `tee` as read-only, is fixed in 2.0.9
and gets a ranged rule of its own. CVE-2026-123024, the agent service's caller-set
`X-User-ID` identity, has no fixed release and joins
AAK-MCP-AGENTSCOPE-CVE-2026-123022-001, the presence-only row for the same service and
the same releases.

Every range below was read in the PyPI wheels on 2026-11-12: 1.0.21, every 2.x release
from 2.0.0 to 2.0.11, 2.0.4.post1 and 2.0.7.post1. Both NVD records are saved unedited
under tests/fixtures/nvd_cna; the feed tests convert them as `aak update` does, in the
empty HOME every test gets. `CHANGELOG.cves.md` holds the reasoning.
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

BASH_PIN = "AAK-AGENTSCOPE-CVE-2026-123023-001"
SERVICE_PIN = "AAK-MCP-AGENTSCOPE-CVE-2026-123022-001"
KNOWN = "AAK-KNOWN-VULN-001"
BASH_CVE = "CVE-2026-123023"
IDENTITY_CVE = "CVE-2026-123024"

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CVES = FIXTURES / "cves"
NVD_CNA = FIXTURES / "nvd_cna"
LEDGER = Path(__file__).resolve().parent.parent / "CHANGELOG.cves.md"


def _pins(scanned: Path) -> list:
    return mcp_cve_pins_2026_07.scan(scanned)[0] + container_image_pins.scan(scanned)[0]


def _ids(tmp_path: Path, name: str, content: str) -> set[str]:
    (tmp_path / name).write_text(content, encoding="utf-8")
    return {f.rule_id for f in _pins(tmp_path)}


def _rows(rule_id: str) -> list[tuple]:
    return [(p.names, p.floor, p.introduced, p.requires_version, p.ecosystem)
            for p in mcp_cve_pins_2026_07._PINS if p.rule_id == rule_id]


# --- The rules ------------------------------------------------------------------------


def test_the_bash_rule() -> None:
    """The Bash tool is the agent's own shell tool, not MCP: no MCP area, no MCP id."""
    rule = RULES[BASH_PIN]
    assert rule.severity is Severity.HIGH
    assert rule.category is Category.SUPPLY_CHAIN
    assert rule.cve_references == [BASH_CVE]
    assert BASH_CVE in rule.description and "2.0.9" in rule.remediation
    assert rule.owasp_mcp_references == []
    assert "CVE-2026-123022" not in rule.description and IDENTITY_CVE not in rule.description


def test_the_service_rule_names_both_service_records() -> None:
    rule = RULES[SERVICE_PIN]
    assert rule.severity is Severity.HIGH
    assert rule.cve_references == ["CVE-2026-123022", IDENTITY_CVE]
    assert "CVE-2026-123022" in rule.description and IDENTITY_CVE in rule.description
    assert BASH_CVE not in rule.description
    assert "X-User-ID" in rule.title


@pytest.mark.parametrize(("cve", "rule_ids"), [
    (BASH_CVE, [BASH_PIN]),
    (IDENTITY_CVE, [SERVICE_PIN]),
])
def test_each_record_is_on_one_rule(cve: str, rule_ids: list[str]) -> None:
    assert [rid for rid, rule in RULES.items() if cve in rule.cve_references] == rule_ids


def test_the_rows_are_the_ranges_the_wheels_show() -> None:
    """The Bash row: `tee` in SAFE_COMMANDS from 2.0.0 to 2.0.8, gone in 2.0.9, and
    `latest` (2.0.11) fixed, so a stated version is required. The service row is
    unchanged: presence-only from 2.0.0, since neither of its records is fixed."""
    assert _rows(BASH_PIN) == [(("agentscope",), (2, 0, 9), (2, 0, 0), True, "py")]
    assert _rows(SERVICE_PIN) == [(("agentscope",), None, (2, 0, 0), False, "py")]
    assert not [p for p in container_image_pins._PINS if p.rule_id in (BASH_PIN, SERVICE_PIN)]


# --- Fixtures -------------------------------------------------------------------------


@pytest.mark.parametrize(("fixture", "where", "quiet"), [
    # 2.0.8 has both flaws; 2.0.9 still has the service's; 1.0.21 has neither.
    ("cve-2026-123023-agentscope-bash",
     {(BASH_PIN, "requirements.txt", 2), (SERVICE_PIN, "requirements.txt", 2)},
     {"negative": {SERVICE_PIN}, "negative-1x": set()}),
    ("cve-2026-123024-agentscope-identity",
     {(SERVICE_PIN, "requirements.txt", 2)},
     {"negative": set()}),
])
def test_fixtures_positive_and_negative(fixture: str, where: set, quiet: dict) -> None:
    """The affected release fires on its own line and nothing else from either pin table
    does; each `negative*` tree reports only what the comment in it says is left."""
    root = CVES / fixture
    assert {(f.rule_id, f.file_path, f.line_number) for f in _pins(root / "vulnerable")} == where
    negatives = sorted(p.name for p in root.iterdir() if p.name.startswith("negative"))
    assert negatives == sorted(quiet)
    for name, left in quiet.items():
        assert {f.rule_id for f in _pins(root / name)} == left, name


@pytest.mark.parametrize(("fixture", "rule_id"), [
    ("cve-2026-123023-agentscope-bash", BASH_PIN),
    ("cve-2026-123024-agentscope-identity", SERVICE_PIN),
])
def test_the_finding_survives_the_full_engine(fixture: str, rule_id: str) -> None:
    found = [f for f in run_scan(CVES / fixture / "vulnerable").findings if f.rule_id == rule_id]
    assert found and all(f.severity is Severity.HIGH for f in found)


# --- References -----------------------------------------------------------------------


@pytest.mark.parametrize(("name", "content", "bash", "service"), [
    ("requirements.txt", "agentscope==1.0.21\n", False, False),        # no Bash tool, no service
    ("requirements.txt", "agentscope==2.0.0\n", True, True),           # tee listed from 2.0.0
    ("requirements.txt", "agentscope==2.0.4.post1\n", True, True),     # read as 2.0.4; tee listed
    ("requirements.txt", "agentscope==2.0.7.post1\n", True, True),     # read as 2.0.7; tee listed
    ("requirements.txt", "agentscope==2.0.8\n", True, True),           # the last with tee
    ("requirements.txt", "agentscope==2.0.9\n", False, True),          # tee removed (#2629)
    ("requirements.txt", "agentscope==2.0.11\n", False, True),         # the newest
    ("requirements.txt", "agentscope\n", False, True),                 # installs 2.0.11
    ("requirements.txt", "agentscope>=1.0\n", True, True),             # admits 2.0.0 to 2.0.8
    ("requirements.txt", "agentscope~=2.0.5\n", True, True),
    ("requirements.txt", "agentscope>=2.0.9\n", False, True),
    ("requirements.txt", "agentscope<2\n", False, False),
    ("requirements.txt", "agentscope[service]==2.0.8\n", True, True),
    ("pyproject.toml", '[project]\nname = "x"\nversion = "1"\ndependencies = ["agentscope==2.0.3"]\n',
     True, True),
    ("uv.lock", '[[package]]\nname = "agentscope"\nversion = "2.0.8"\n', True, True),
    ("uv.lock", '[[package]]\nname = "agentscope"\nversion = "2.0.9"\n', False, True),
    (".mcp.json", '{"mcpServers": {"a": {"command": "uvx", "args": ["agentscope==2.0.8"]}}}', True, True),
    (".mcp.json", '{"mcpServers": {"a": {"command": "uvx", "args": ["agentscope"]}}}', False, True),
    ("package.json", '{"dependencies": {"agentscope": "0.1.1"}}', False, False),  # npm's is another project
])
def test_agentscope_references(tmp_path: Path, name: str, content: str, bash: bool, service: bool) -> None:
    found = _ids(tmp_path, name, content)
    assert (BASH_PIN in found, SERVICE_PIN in found) == (bash, service)


def test_the_bash_evidence_names_the_fix(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("agentscope==2.0.8\n", encoding="utf-8")
    (finding,) = [f for f in _pins(tmp_path) if f.rule_id == BASH_PIN]
    assert "fixed in 2.0.9" in finding.evidence


# --- The advisory feed ----------------------------------------------------------------


def _record(cve: str) -> dict:
    (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text(encoding="utf-8"))["vulnerabilities"]
    return vuln


def _entry(cve: str) -> dict:
    (entry,) = nvd_feed.record_entries(_record(cve), nvd_feed.load_package_map(), nvd_feed.Tally())
    return entry


@pytest.mark.parametrize(("cve", "versions"), [
    (BASH_CVE, [f"2.0.{n}" for n in range(9)]),
    (IDENTITY_CVE, [f"2.0.{n}" for n in range(12)]),
])
def test_the_feed_entries_list_releases_by_number(cve: str, versions: list[str]) -> None:
    """The CNA lists each affected release one by one and names no fixed version, so the
    feed holds those numbers, no range, and nothing a post release would match."""
    entry = _entry(cve)
    assert (entry["ecosystem"], entry["name"], entry["ranges"], entry["fixed"], entry["severity"]) == (
        "PyPI", "agentscope", [], [], "HIGH")
    assert sorted(entry["versions"]) == sorted(versions)


def test_the_bundled_feed_does_not_hold_the_records() -> None:
    """Without `aak update` only the pins report these records."""
    bundled = advisory_feed.BUNDLED_FEED.read_text(encoding="utf-8")
    assert BASH_CVE not in bundled and IDENTITY_CVE not in bundled


def _cache_records() -> None:
    """The feed `aak update` writes from NVD, holding both records as `nvd_feed`
    converts them through the reviewed `agentscope` row of data/cna_package_map.json."""
    package_map = nvd_feed.load_package_map()
    entries = [entry for cve in (BASH_CVE, IDENTITY_CVE)
               for entry in nvd_feed.record_entries(_record(cve), package_map, nvd_feed.Tally())]
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "records": [],
                                "nvd": nvd_feed.merged(entries)}), encoding="utf-8")


def _uv_lock(root: Path, version: str) -> None:
    (root / "uv.lock").write_text(
        'version = 1\nrequires-python = ">=3.10"\n\n[[package]]\nname = "agentscope"\n'
        f'version = "{version}"\nsource = {{ registry = "https://pypi.org/simple" }}\n',
        encoding="utf-8")


def _known(findings: list, cve: str) -> list:
    return [f for f in findings if f.rule_id == KNOWN and cve in f.evidence]


@pytest.mark.parametrize(("version", "rules"), [
    ("2.0.0", {BASH_PIN, SERVICE_PIN}),
    ("2.0.8", {BASH_PIN, SERVICE_PIN}),
    ("2.0.9", {SERVICE_PIN}),
    ("2.0.11", {SERVICE_PIN}),
])
def test_after_update_the_pins_report_the_records_alone(tmp_path: Path, version: str, rules: set) -> None:
    """With both records cached, each HIGH pin stands and the engine drops the feed's HIGH
    finding on the same line, since a rule there names the CVE at the same severity."""
    _cache_records()
    _uv_lock(tmp_path, version)
    findings = run_scan(tmp_path).findings
    assert {f.rule_id for f in findings if f.rule_id in (BASH_PIN, SERVICE_PIN)} == rules
    assert all(f.severity is Severity.HIGH for f in findings if f.rule_id in rules)
    assert not [f for f in findings if f.rule_id == KNOWN]


@pytest.mark.parametrize(("version", "feed_reports"), [
    ("2.0.11", True),         # a release the record lists
    ("2.0.4.post1", False),   # has the header identity, but the record lists no post release
    ("2.0.12", False),        # a later release, which the record cannot name
])
def test_without_the_join_the_feed_reports_the_identity_record(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: str, feed_reports: bool) -> None:
    """The control: with the service rule naming only CVE-2026-123022, as in 0.6.35,
    AAK-KNOWN-VULN-001 reports CVE-2026-123024 beside it after `aak update`, on the
    releases the record lists. Naming it on the rule is what drops that repeat."""
    rule = RULES[SERVICE_PIN]
    monkeypatch.setitem(RULES, SERVICE_PIN, dataclasses.replace(rule, cve_references=["CVE-2026-123022"]))
    _cache_records()
    _uv_lock(tmp_path, version)
    assert bool(_known(run_scan(tmp_path).findings, IDENTITY_CVE)) is feed_reports


@pytest.mark.parametrize(("version", "feed_reports"), [
    ("2.0.8", True),
    ("2.0.7.post1", False),   # lists tee, but the record lists no post release
    ("2.0.9", False),
])
def test_without_the_bash_pin_the_feed_reports_only_the_listed_releases(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: str, feed_reports: bool) -> None:
    """The control for the new rule: with its reference taken out, the feed reports
    CVE-2026-123023 on the nine listed releases only, and the pin reports the two post
    releases the record does not list."""
    rule = RULES[BASH_PIN]
    monkeypatch.setitem(RULES, BASH_PIN, dataclasses.replace(rule, cve_references=[]))
    _cache_records()
    _uv_lock(tmp_path, version)
    findings = run_scan(tmp_path).findings
    assert bool(_known(findings, BASH_CVE)) is feed_reports
    assert bool([f for f in findings if f.rule_id == BASH_PIN]) is (version != "2.0.9")


# --- Ledger ---------------------------------------------------------------------------


def _ledger_rows(cve: str) -> list[str]:
    return [line for line in LEDGER.read_text(encoding="utf-8").splitlines()
            if line.startswith(f"| {cve} ")]


@pytest.mark.parametrize(("cve", "issue", "rule_id"), [
    (BASH_CVE, "#1231", BASH_PIN),
    (IDENTITY_CVE, "#1232", SERVICE_PIN),
])
def test_covered_rows_name_their_rule(cve: str, issue: str, rule_id: str) -> None:
    (row,) = _ledger_rows(cve)
    assert row.rstrip().endswith(f"| {issue} |")
    assert rule_id in row and "out of scope" not in row.lower()
