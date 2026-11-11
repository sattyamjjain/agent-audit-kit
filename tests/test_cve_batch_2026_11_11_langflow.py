"""#1157 to #1161, #1165, #1166, #1183 and #1222, and IBM's other Langflow OSS records.

NVD holds 59 records whose CNA data names IBM's "Langflow OSS", published from
7 Oct to 8 Nov 2026 and read from NVD's API on 2026-11-11. Ten were already in
AAK-MCP-LANGFLOW-CVE-2026-12940-001's references; the 49 here join it. Each record's
range is 1.0.0 through 1.12.2, 1.12.3 or 1.12.4, and IBM's bulletin names the fix
(7290694: 1.12.3, 7293015: 1.12.4, 7293016: 1.12.5), all under the rule's 1.13.0
floor, so only the references and the ledger change. The NVD records of the nine
filed issues are saved unedited under tests/fixtures/nvd_cna. `CHANGELOG.cves.md`
holds the reasoning.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from agent_audit_kit import advisory_feed, nvd_feed
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import mcp_cve_pins_2026_07

LANGFLOW = "AAK-MCP-LANGFLOW-CVE-2026-12940-001"
NVD_CNA = Path(__file__).parent / "fixtures" / "nvd_cna"
LEDGER = Path(__file__).resolve().parent.parent / "CHANGELOG.cves.md"

# (CVE, last release the CNA record lists, fixed release IBM's bulletin names, issue)
RECORDS = (
    ("CVE-2026-88962", "1.12.2", "1.12.3", None),
    ("CVE-2026-93443", "1.12.2", "1.12.3", None),
    ("CVE-2026-93445", "1.12.2", "1.12.3", None),
    ("CVE-2026-93447", "1.12.2", "1.12.3", None),
    ("CVE-2026-93448", "1.12.2", "1.12.3", None),
    ("CVE-2026-93449", "1.12.2", "1.12.3", None),
    ("CVE-2026-93674", "1.12.2", "1.12.3", None),
    ("CVE-2026-93675", "1.12.2", "1.12.3", None),
    ("CVE-2026-93677", "1.12.2", "1.12.3", None),
    ("CVE-2026-93678", "1.12.2", "1.12.3", None),
    ("CVE-2026-93679", "1.12.2", "1.12.3", None),
    ("CVE-2026-97655", "1.12.2", "1.12.3", None),
    ("CVE-2026-97671", "1.12.2", "1.12.3", None),
    ("CVE-2026-97673", "1.12.2", "1.12.3", None),
    ("CVE-2026-97674", "1.12.2", "1.12.3", None),
    ("CVE-2026-97676", "1.12.2", "1.12.3", None),
    ("CVE-2026-97677", "1.12.2", "1.12.3", 1222),
    ("CVE-2026-97678", "1.12.2", "1.12.3", None),
    ("CVE-2026-97679", "1.12.2", "1.12.3", None),
    ("CVE-2026-97680", "1.12.2", "1.12.3", None),
    ("CVE-2026-101329", "1.12.2", "1.12.3", None),
    ("CVE-2026-101331", "1.12.2", "1.12.3", None),
    ("CVE-2026-103360", "1.12.2", "1.12.3", None),
    ("CVE-2026-104334", "1.12.2", "1.12.3", None),
    ("CVE-2026-104335", "1.12.2", "1.12.3", None),
    ("CVE-2026-77819", "1.12.3", "1.12.4", None),
    ("CVE-2026-102590", "1.12.3", "1.12.4", 1183),
    ("CVE-2026-103092", "1.12.3", "1.12.4", 1157),
    ("CVE-2026-104308", "1.12.3", "1.12.4", None),
    ("CVE-2026-104309", "1.12.3", "1.12.4", None),
    ("CVE-2026-104310", "1.12.3", "1.12.4", None),
    ("CVE-2026-104312", "1.12.3", "1.12.4", None),
    ("CVE-2026-104314", "1.12.3", "1.12.4", None),
    ("CVE-2026-104315", "1.12.3", "1.12.4", None),
    ("CVE-2026-104316", "1.12.3", "1.12.4", None),
    ("CVE-2026-104324", "1.12.3", "1.12.4", 1158),
    ("CVE-2026-104328", "1.12.3", "1.12.4", 1159),
    ("CVE-2026-104331", "1.12.3", "1.12.4", None),
    ("CVE-2026-77817", "1.12.4", "1.12.5", None),
    ("CVE-2026-90991", "1.12.4", "1.12.5", None),
    ("CVE-2026-107326", "1.12.4", "1.12.5", 1160),
    ("CVE-2026-107328", "1.12.4", "1.12.5", 1161),
    ("CVE-2026-107366", "1.12.4", "1.12.5", None),
    ("CVE-2026-110190", "1.12.4", "1.12.5", None),
    ("CVE-2026-110196", "1.12.4", "1.12.5", 1165),
    ("CVE-2026-110200", "1.12.4", "1.12.5", None),
    ("CVE-2026-110244", "1.12.4", "1.12.5", None),
    ("CVE-2026-110245", "1.12.4", "1.12.5", None),
    ("CVE-2026-110309", "1.12.4", "1.12.5", 1166),
)
FILED = tuple((cve, issue) for cve, _, _, issue in RECORDS if issue)
LINES = sorted({(last, fixed) for _, last, fixed, _ in RECORDS})


def _ver(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split("."))


def _langflow_pin() -> mcp_cve_pins_2026_07._Pin:
    (pin,) = [p for p in mcp_cve_pins_2026_07._PINS if p.rule_id == LANGFLOW and p.display == "langflow"]
    return pin


def test_the_table_holds_49_records_on_three_fixed_releases() -> None:
    assert len(RECORDS) == len({cve for cve, _, _, _ in RECORDS}) == 49
    assert LINES == [("1.12.2", "1.12.3"), ("1.12.3", "1.12.4"), ("1.12.4", "1.12.5")]
    assert sorted(issue for _, issue in FILED) == [1157, 1158, 1159, 1160, 1161, 1165, 1166, 1183, 1222]


@pytest.mark.parametrize("cve", [cve for cve, _, _, _ in RECORDS])
def test_the_langflow_rule_names_the_record(cve: str) -> None:
    assert cve in RULES[LANGFLOW].cve_references


@pytest.mark.parametrize(("last", "fixed"), LINES)
def test_every_fix_is_under_the_floor_and_every_listed_release_inside_the_range(last: str, fixed: str) -> None:
    pin = _langflow_pin()
    assert pin.introduced == (1, 0, 0) and pin.floor == (1, 13, 0)
    assert pin.introduced <= _ver(last) < _ver(fixed) <= pin.floor


@pytest.mark.parametrize(("last", "fixed"), LINES)
@pytest.mark.parametrize(("which", "fires"), [("oldest", True), ("last", True), ("floor", False)])
def test_the_floor_reports_every_release_each_bulletin_lists(
        tmp_path: Path, last: str, fixed: str, which: str, fires: bool) -> None:
    """1.0.0 and the last release a bulletin lists fire; 1.13.0, the floor, does not.
    The fixed releases fire too, for the records of bulletin 7294467 that run to 1.12.8."""
    version = {"oldest": "1.0.0", "last": last, "floor": "1.13.0"}[which]
    (tmp_path / "requirements.txt").write_text(f"langflow=={version}\n")
    assert (LANGFLOW in {f.rule_id for f in mcp_cve_pins_2026_07.scan(tmp_path)[0]}) is fires


@pytest.mark.parametrize("package", ["langflow-base", "lfx"])
def test_the_twin_packages_keep_their_floor(tmp_path: Path, package: str) -> None:
    """No record names `langflow-base` or `lfx`, so 1.12.4 of either stays quiet."""
    (tmp_path / "requirements.txt").write_text(f"{package}==1.12.4\n")
    assert LANGFLOW not in {f.rule_id for f in mcp_cve_pins_2026_07.scan(tmp_path)[0]}


def _cache_filed_records() -> None:
    entries = []
    for cve, _ in FILED:
        (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text())["vulnerabilities"]
        entries.extend(nvd_feed.record_entries(vuln, nvd_feed.load_package_map(), nvd_feed.Tally()))
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "records": [],
                                "nvd": nvd_feed.merged(entries)}))


def _uv_lock(root: Path, version: str) -> None:
    (root / "uv.lock").write_text(
        'version = 1\nrequires-python = ">=3.10"\n\n[[package]]\nname = "langflow"\n'
        f'version = "{version}"\nsource = {{ registry = "https://pypi.org/simple" }}\n')


def test_after_update_the_pin_reports_the_filed_records_alone(tmp_path: Path) -> None:
    """With the nine records in the cached feed, a uv.lock on 1.12.2 gets the CRITICAL
    pin and no AAK-KNOWN-VULN-001 finding: the engine stands one down where a rule on the
    same line names its CVE at or above its severity."""
    _cache_filed_records()
    _uv_lock(tmp_path, "1.12.2")
    findings = run_scan(tmp_path).findings
    (pin,) = [f for f in findings if f.rule_id == LANGFLOW]
    assert pin.severity is Severity.CRITICAL
    assert {cve for cve, _ in FILED} <= set(pin.cve_references)
    assert not [f for f in findings if f.rule_id == "AAK-KNOWN-VULN-001"]


def test_without_the_references_the_feed_repeats_each_filed_record(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The control: the same scan with the nine ids taken out of the rule gives one
    AAK-KNOWN-VULN-001 finding per record, which is what 0.6.34 reported after `aak update`."""
    filed = {cve for cve, _ in FILED}
    rule = RULES[LANGFLOW]
    monkeypatch.setitem(RULES, LANGFLOW, dataclasses.replace(
        rule, cve_references=[c for c in rule.cve_references if c not in filed]))
    _cache_filed_records()
    _uv_lock(tmp_path, "1.12.2")
    findings = run_scan(tmp_path).findings
    assert [f for f in findings if f.rule_id == LANGFLOW]
    named = {cve for f in findings if f.rule_id == "AAK-KNOWN-VULN-001" for cve in filed if cve in f.evidence}
    assert named == filed


@pytest.mark.parametrize(("cve", "last", "fixed", "issue"), RECORDS)
def test_every_record_has_one_ledger_row(cve: str, last: str, fixed: str, issue: int | None) -> None:
    rows = [line for line in LEDGER.read_text().splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1
    (row,) = rows
    assert f"1.0.0 through {last}, fixed in {fixed}." in row
    assert row.rstrip().endswith(f"| #{issue} |" if issue else "| not filed |")
    assert "out of scope" not in row.lower()
