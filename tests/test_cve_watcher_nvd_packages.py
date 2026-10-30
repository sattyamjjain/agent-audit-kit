"""The CVE watcher's third source: NVD records whose CNA data names a pinned package.

IBM's Langflow OSS CVEs of 28 and 29 Oct 2026 reached no `cve-response` issue:
their text names neither MCP nor LangChain, so the keyword feed dropped them,
and OSV had no record of them. NVD's records carried IBM's affected range,
1.0.0 through 1.12.8, past the langflow pin's 1.12.0 floor, so AAK reported
nothing for 1.12.0 to 1.12.8. These tests pin what the watcher now reads (every
NVD record published in the window, kept when its CNA data names a pinned npm
or PyPI package through a packageURL or the reviewed map), how it reads the
`_Pin` rows with `ast`, when it titles an issue "pin floor stale", and that a
record is filed once and never again once the ledger names it. The pin rows
are a fixture at the old 1.12.0 floor; NVD's answers are the records saved
under tests/fixtures/nvd_cna, or written here. Nothing touches the network.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
NVD_CNA = REPO / "tests" / "fixtures" / "nvd_cna"
NOW = datetime(2026, 10, 30, 9, 0, tzinfo=timezone.utc)
LANGFLOW_RULE = "AAK-MCP-LANGFLOW-CVE-2026-12940-001"


def _load(name: str, filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


w = _load("cve_watcher_nvd_mod", "cve_watcher.py")
gate = _load("cve_ageing_nvd_mod", "check_cve_ageing.py")

# The pin rows as the table read on 0.6.29, before the langflow floor moved, plus
# the shapes `pin_rows` has to read: a constant, a presence-only floor, an `also`
# range, a floor that is not a literal, and a row for the other registry.
_PIN_SOURCE = '''
_NAMES = ("langflow",)
_FLOOR = compute_floor()

_PINS = (
    _Pin("AAK-MCP-LANGFLOW-CVE-2026-12940-001", "langflow", _NAMES,
         (1, 12, 0), introduced=(1, 0, 0),
         fix_label="1.12.0 (affected 1.0.0-1.11.6)",
         ecosystem="py"),
    _Pin("AAK-TEST-PRESENCE-001", "aak-presence", ("aak-presence",), None, fix_label="none"),
    _Pin("AAK-TEST-ALSO-001", "aak-also", ("aak-also",), (2, 0, 0),
         also=(((3, 0, 0), (3, 2, 0)),), ecosystem="js"),
    _Pin("AAK-TEST-DYNAMIC-001", "aak-dynamic", ("aak-dynamic",), _FLOOR),
    _Pin("AAK-TEST-TWO-FLOORS-LOW-001", "aak-two", ("aak-two",), (1, 5, 0), introduced=(1, 0, 0)),
    _Pin("AAK-TEST-TWO-FLOORS-HIGH-001", "aak-two", ("aak-two",), (2, 0, 0), introduced=(1, 8, 0)),
)
'''


@pytest.fixture
def pins(tmp_path: Path) -> list[Any]:
    scanners = tmp_path / "scanners"
    scanners.mkdir()
    (scanners / "pins.py").write_text(_PIN_SOURCE, encoding="utf-8")
    return w.pin_rows(scanners)


PACKAGES = [("PyPI", "langflow"), ("PyPI", "aak-presence"), ("npm", "aak-also"), ("PyPI", "aak-two")]


def _page(*vulns: dict[str, Any]) -> dict[str, Any]:
    return {"totalResults": len(vulns), "vulnerabilities": list(vulns)}


def _fixture(cve: str) -> dict[str, Any]:
    (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text())["vulnerabilities"]
    return vuln


def _record(ident: str, affected: dict[str, Any], description: str = "A flaw.", score: float = 7.5) -> dict[str, Any]:
    return {"cve": {
        "id": ident, "sourceIdentifier": "cna@example.com", "published": "2026-10-29T10:00:00.000",
        "vulnStatus": "Received", "descriptions": [{"lang": "en", "value": description}],
        "affected": [{"source": "cna@example.com", "affectedData": [affected]}],
        "metrics": {"cvssMetricV31": [{"source": "cna@example.com", "type": "Secondary", "cvssData": {
            "version": "3.1", "baseScore": score, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}]},
    }}


def _purl(name: str, *versions: dict[str, Any], registry: str = "pypi") -> dict[str, Any]:
    return {"vendor": "v", "product": name, "packageURL": f"pkg:{registry}/{name}", "versions": list(versions)}


def _lt(start: str, end: str) -> dict[str, Any]:
    return {"version": start, "lessThan": end, "versionType": "semver", "status": "affected"}


def _read(pages: list[dict[str, Any]], pins: list[Any], suppressed: set[str] | None = None,
          queries: list[dict[str, str]] | None = None) -> list[dict[str, Any]]:
    def source(query: dict[str, str]) -> list[dict[str, Any]]:
        if queries is not None:
            queries.append(query)
        return pages

    return w.nvd_package_records(suppressed or set(), packages=PACKAGES, pins=pins, pages=source, now=NOW)


# ---- the pin rows ----------------------------------------------------------------------------------


def test_pin_rows_are_read_with_their_floors_bounds_and_registries(pins: list[Any]) -> None:
    by_rule = {pin.rule_id: pin for pin in pins}
    assert set(by_rule) == {LANGFLOW_RULE, "AAK-TEST-PRESENCE-001", "AAK-TEST-ALSO-001",
                            "AAK-TEST-TWO-FLOORS-LOW-001", "AAK-TEST-TWO-FLOORS-HIGH-001"}  # not the dynamic floor
    langflow = by_rule[LANGFLOW_RULE]
    assert (langflow.names, langflow.floor, langflow.introduced, langflow.ecosystem) == (
        ("langflow",), (1, 12, 0), (1, 0, 0), "py")
    assert by_rule["AAK-TEST-PRESENCE-001"].floor is None
    assert by_rule["AAK-TEST-ALSO-001"].also == (((3, 0, 0), (3, 2, 0)),)
    assert langflow.names_package("PyPI", "Langflow") and not langflow.names_package("npm", "langflow")


def test_every_pin_table_row_is_read() -> None:
    """Every `_Pin(` row of the real table states its floor as a literal, so every
    one is read; the langflow row carries the floor IBM's records moved it to."""
    table = (REPO / "agent_audit_kit" / "scanners" / "mcp_cve_pins_2026_07.py").read_text()
    rows = w.pin_rows()
    assert len(rows) == table.count("    _Pin(\"") > 100
    langflow = next(row for row in rows if row.names == ("langflow",))
    assert (langflow.rule_id, langflow.floor) == (LANGFLOW_RULE, (1, 13, 0))


# ---- what is filed -------------------------------------------------------------------------------


def test_a_langflow_record_with_no_mcp_words_is_filed_as_pin_floor_stale(pins: list[Any]) -> None:
    record = _fixture("CVE-2026-110186")
    description = record["cve"]["descriptions"][0]["value"]
    assert not w.is_relevant(description)  # the keyword feed's filter drops it
    (entry,) = _read([_page(record)], pins)
    assert entry["id"] == "CVE-2026-110186"
    assert entry["title"].startswith(f"pin floor stale: {LANGFLOW_RULE}, CVE-2026-110186")
    assert entry["title"] == f"pin floor stale: {LANGFLOW_RULE}, CVE-2026-110186 (CRITICAL CVSS 9.8)"
    note = entry["pin_note"]
    assert f"`{LANGFLOW_RULE}` reports PyPI `langflow` from 1.0.0 below 1.12.0, its floor." in note
    assert "as its CNA wrote it: 1.0.0 through 1.12.8." in note  # the CVE's upper bound
    assert "Fixed release: none named in the record." in note
    assert entry["source"].startswith("NVD CNA record from psirt@us.ibm.com naming PyPI `langflow` "
                                      "(by its reviewed map row)")
    assert entry["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2026-110186" and entry["aliases"] == []
    assert gate.band_for_issue({"title": entry["title"]}) == "critical"


def test_the_note_names_the_fixed_release_the_record_names(pins: list[Any]) -> None:
    (entry,) = _read([_page(_record("CVE-2026-90011", _purl("langflow", _lt("1.0.0", "1.13.0"))))], pins)
    assert "as its CNA wrote it: 1.0.0 up to 1.13.0. Fixed release: 1.13.0." in entry["pin_note"]
    assert entry["title"] == f"pin floor stale: {LANGFLOW_RULE}, CVE-2026-90011 (HIGH CVSS 7.5)"


def test_an_unmapped_record_is_not_filed(pins: list[Any]) -> None:
    """Never a mapping from a name alone: another vendor's `langflow` is not IBM's."""
    unmapped = _record("CVE-2026-90012", {"vendor": "someone", "product": "langflow",
                                          "versions": [_lt("1.0.0", "2.0.0")]})
    unpinned = _fixture("CVE-2026-119025")  # open, the MCP inspector and opencode-ai: no pin names them
    assert _read([_page(unmapped, unpinned)], pins) == []


def test_a_record_the_pins_report_in_full_is_filed_plainly(pins: list[Any]) -> None:
    (entry,) = _read([_page(_record("CVE-2026-90013", _purl("langflow", _lt("1.0.0", "1.11.0"))))], pins)
    assert "title" not in entry and "pin_note" not in entry
    assert entry["source"].endswith("a package AAK's pin tables name")


@pytest.mark.parametrize(("affected", "stale"), [
    (_purl("aak-also", _lt("1.0.0", "2.0.0"), registry="npm"), False),
    (_purl("aak-also", _lt("3.0.0", "3.2.0"), registry="npm"), False),  # its `also` range
    (_purl("aak-also", _lt("3.0.0", "3.3.0"), registry="npm"), True),
    (_purl("aak-also", _lt("1.0.0", "2.0.0")), False),                  # PyPI: the row is npm's
    (_purl("aak-presence", _lt("1.0.0", "9.0.0")), False),             # presence-only reports all
    (_purl("langflow", _lt("0.1.0", "0.9.0")), False),                 # below `introduced`, not the floor
])
def test_also_ranges_presence_only_rows_and_introduced_bounds(pins: list[Any], affected: dict[str, Any],
                                                              stale: bool) -> None:
    entries = _read([_page(_record("CVE-2026-90014", affected))], pins)
    if affected["packageURL"] == "pkg:pypi/aak-also":
        assert entries == []  # npm's pin does not name PyPI's package
        return
    (entry,) = entries
    assert ("title" in entry) is stale


@pytest.mark.parametrize(("start", "end", "rule"), [
    # The rows report 1.0.0 up to 1.5.0 and 1.8.0 up to 2.0.0.
    ("1.8.0", "3.0.0", "AAK-TEST-TWO-FLOORS-HIGH-001"),  # first unreported release 2.0.0: past both floors
    ("1.0.0", "1.7.0", "AAK-TEST-TWO-FLOORS-LOW-001"),   # first unreported 1.5.0: past the lower floor only
    ("1.0.0", "3.0.0", "AAK-TEST-TWO-FLOORS-LOW-001"),   # the first gap decides
])
def test_the_pin_named_is_the_floor_the_range_runs_past_first(pins: list[Any], start: str, end: str,
                                                              rule: str) -> None:
    (entry,) = _read([_page(_record("CVE-2026-90015", _purl("aak-two", _lt(start, end))))], pins)
    assert entry["title"].startswith(f"pin floor stale: {rule}, ")


def test_the_window_is_the_published_week(pins: list[Any]) -> None:
    queries: list[dict[str, str]] = []
    _read([], pins, queries=queries)
    assert queries == [{"pubStartDate": "2026-10-23T09:00:00.000", "pubEndDate": "2026-10-30T09:00:00.000"}]


def test_an_nvd_failure_costs_only_this_source(pins: list[Any], capsys: pytest.CaptureFixture[str]) -> None:
    def failing(_query: dict[str, str]) -> list[dict[str, Any]]:
        raise w.nvd_feed.NvdUpdateError("NVD answered HTTP 503")

    assert w.nvd_package_records(set(), packages=PACKAGES, pins=pins, pages=failing, now=NOW) == []
    assert "NVD package read failed (NVD answered HTTP 503)" in capsys.readouterr().err


# ---- dedup and the other sources -----------------------------------------------------------------


def _collect(tmp_path: Path, pins: list[Any], pages: list[dict[str, Any]],
             keyword_hits: tuple[dict[str, Any], ...] = (), ledger: str = "") -> list[dict[str, Any]]:
    (tmp_path / "CHANGELOG.cves.md").write_text(ledger, encoding="utf-8")
    results, _ = w.collect_new_cves(
        changelog_path=tmp_path / "CHANGELOG.cves.md",
        state_path=tmp_path / "state.json",
        fetcher=lambda keyword: list(keyword_hits) if keyword == "mcp" else [],
        nvd_source=lambda suppressed: w.nvd_package_records(
            suppressed, packages=PACKAGES, pins=pins, pages=lambda _q: pages, now=NOW),
    )
    return results


def test_a_record_already_in_the_ledger_is_not_filed_again(tmp_path: Path, pins: list[Any]) -> None:
    record = _fixture("CVE-2026-110186")
    assert [e["id"] for e in _collect(tmp_path, pins, [_page(record)])] == ["CVE-2026-110186"]
    ledger = "| CVE-2026-110186 | 9.8 | `langflow` (PyPI) | **Floor raised** | not filed |\n"
    assert _collect(tmp_path, pins, [_page(record)], ledger=ledger) == []


def test_a_keyword_hit_is_filed_once_under_the_stale_title(tmp_path: Path, pins: list[Any]) -> None:
    record = copy.deepcopy(_fixture("CVE-2026-110186"))
    record["cve"]["descriptions"][0]["value"] += " The flaw is reachable through its MCP server."
    (entry,) = _collect(tmp_path, pins, [_page(record)], keyword_hits=(record,))
    assert entry["title"].startswith(f"pin floor stale: {LANGFLOW_RULE}, CVE-2026-110186")
    assert "pin_note" in entry


def test_a_keyword_hit_whose_text_names_nothing_is_filed_on_its_package(tmp_path: Path, pins: list[Any]) -> None:
    record = _fixture("CVE-2026-110186")
    (entry,) = _collect(tmp_path, pins, [_page(record)], keyword_hits=(record,))
    assert entry["id"] == "CVE-2026-110186" and entry["title"].startswith("pin floor stale: ")


# ---- the workflow files it under that title ---------------------------------------------------------

_RUNNER = """
const fs = require('fs');
const script = fs.readFileSync(process.argv[2], 'utf-8');
const created = [];
const github = { rest: { issues: { create: async (args) => { created.push(args); return { data: {} }; } } } };
const context = { repo: { owner: 'o', repo: 'r' } };
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
new AsyncFunction('require', 'github', 'context', script)(require, github, context)
  .then(() => process.stdout.write(JSON.stringify(created)))
  .catch((err) => { console.error(err); process.exit(1); });
"""


def _filing_script() -> str:
    workflow = yaml.safe_load((REPO / ".github" / "workflows" / "cve-watcher.yml").read_text(encoding="utf-8"))
    for job in workflow["jobs"].values():
        for step in job.get("steps") or []:
            if step.get("name") == "File response-tracking issue":
                return step["with"]["script"]
    raise AssertionError("the issue-filing step is gone from cve-watcher.yml")


@pytest.mark.skipif(shutil.which("node") is None, reason="needs node to run the workflow's script")
def test_the_workflow_files_a_stale_pin_under_its_title_and_band(tmp_path: Path, pins: list[Any]) -> None:
    stale = _read([_page(_fixture("CVE-2026-110186"))], pins)
    plain = _read([_page(_record("CVE-2026-90013", _purl("langflow", _lt("1.0.0", "1.11.0"))))], pins)
    (tmp_path / "new_cves.json").write_text(json.dumps(stale + plain), encoding="utf-8")
    (tmp_path / "script.js").write_text(_filing_script(), encoding="utf-8")
    (tmp_path / "runner.cjs").write_text(_RUNNER, encoding="utf-8")
    run = subprocess.run(["node", "runner.cjs", "script.js"], cwd=tmp_path, capture_output=True, text=True,
                         timeout=60, check=False)
    assert run.returncode == 0, run.stderr
    first, second = json.loads(run.stdout)
    assert first["title"] == f"pin floor stale: {LANGFLOW_RULE}, CVE-2026-110186 (CRITICAL CVSS 9.8)"
    assert first["labels"] == ["cve-response", "sev/critical"]  # still holds the release
    assert f"### Pin floor stale\n\n`{LANGFLOW_RULE}` reports PyPI `langflow`" in first["body"]
    assert "**NVD:** https://nvd.nist.gov/vuln/detail/CVE-2026-110186" in first["body"]
    assert second["title"] == "CVE-response: CVE-2026-90013 (HIGH CVSS 7.5)"
    assert "### Pin floor stale" not in second["body"]
