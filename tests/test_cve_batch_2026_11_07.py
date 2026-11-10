"""#1152 to #1156: three IBM Langflow records, one n8n record, one desktop app.

The NVD record of CVE-2026-119408 is saved unedited under tests/fixtures/nvd_cna,
read on 2026-11-07. `CHANGELOG.cves.md` holds the reasoning.
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

LANGFLOW = "AAK-MCP-LANGFLOW-CVE-2026-12940-001"
N8N = "AAK-MCP-N8N-CVE-2026-72768-001"
RECORD = Path(__file__).parent / "fixtures" / "nvd_cna" / "CVE-2026-119408.json"
LEDGER = Path(__file__).resolve().parent.parent / "CHANGELOG.cves.md"


@pytest.mark.parametrize("cve", ["CVE-2026-104317", "CVE-2026-18894", "CVE-2026-101288"])
def test_the_langflow_rule_names_the_records_it_reports(cve: str) -> None:
    assert cve in RULES[LANGFLOW].cve_references


@pytest.mark.parametrize("version,fires", [("1.0.0", True), ("1.12.3", True), ("1.12.4", True), ("1.13.0", False)])
def test_the_langflow_floor_already_reports_every_listed_release(tmp_path: Path, version: str, fires: bool) -> None:
    (tmp_path / "requirements.txt").write_text(f"langflow=={version}\n")
    assert (LANGFLOW in {f.rule_id for f in mcp_cve_pins_2026_07.scan(tmp_path)[0]}) is fires


def _cache_record() -> None:
    (vuln,) = json.loads(RECORD.read_text())["vulnerabilities"]
    entries = nvd_feed.merged(nvd_feed.record_entries(vuln, nvd_feed.load_package_map(), nvd_feed.Tally()))
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "records": [], "nvd": entries}))


@pytest.mark.parametrize("version,fires", [
    ("2.41.4", True), ("2.42.5", True), ("2.42.6", False), ("2.43.0", True), ("2.43.2", True), ("2.43.3", False),
])
def test_the_n8n_record_reaches_the_advisory_feed_rule(tmp_path: Path, version: str, fires: bool) -> None:
    _cache_record()
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {"node_modules/n8n": {"version": version}}}))
    found = [f for f in run_scan(tmp_path).findings if f.rule_id == "AAK-KNOWN-VULN-001"]
    assert bool(found) is fires
    if fires:
        assert all(f.severity is Severity.HIGH and "CVE-2026-119408" in f.evidence for f in found)


def test_the_n8n_mcp_pin_keeps_its_floor_and_makes_no_claim_on_this_record() -> None:
    assert "CVE-2026-119408" not in RULES[N8N].cve_references
    (pin,) = [p for p in mcp_cve_pins_2026_07._PINS if p.rule_id == N8N]
    assert pin.floor == (2, 41, 4)


def test_the_bundled_feed_does_not_hold_the_n8n_record() -> None:
    assert "CVE-2026-119408" not in advisory_feed.BUNDLED_FEED.read_text()


@pytest.mark.parametrize("issue,cve", [("#1152", "CVE-2026-104317"), ("#1153", "CVE-2026-18894"),
                                       ("#1154", "CVE-2026-119979"), ("#1155", "CVE-2026-119408"),
                                       ("#1156", "CVE-2026-101288")])
def test_every_issue_has_a_ledger_row(issue: str, cve: str) -> None:
    rows = [line for line in LEDGER.read_text().splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith(f"| {issue} |")


def test_the_desktop_app_row_is_read_as_out_of_scope() -> None:
    (row,) = [line for line in LEDGER.read_text().splitlines() if line.startswith("| CVE-2026-119979 ")]
    assert "Out of scope" in row
