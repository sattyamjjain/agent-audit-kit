"""NVD's records of CNA version data in the advisory feed AAK-KNOWN-VULN-001 reads.

On 0.6.29 a project that locked langflow 1.12.8 passed every rule: IBM's
bulletin of 28 Oct 2026 names Langflow OSS 1.0.0 through 1.12.8 (CVE-2026-110186,
CVSS 9.8), OSV had no record of it, and the feed read only OSV. The one
machine-readable range was IBM's, in NVD's record of the CVE. These tests pin
how `nvd_feed` reads those records (which package, which versions, which
severity), the bundled entries converted from the four records saved unedited
under tests/fixtures/nvd_cna on 2026-10-30, the OSV entry that wins over an NVD
entry for the same CVE, and `aak update`, which keeps the NVD entries scans read
before when NVD cannot be read. Nothing is fetched: every NVD answer here is a
fixture or written in the test.
"""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from agent_audit_kit import advisory_feed, malicious_feed, nvd_feed
from agent_audit_kit.cli import cli
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity
from agent_audit_kit.output.console import format_results as console_results
from agent_audit_kit.scanners.known_vulns import RULE, scan

FIXTURES = Path(__file__).parent / "fixtures" / "nvd_cna"
LANGFLOW_CVES = ("CVE-2026-110186", "CVE-2026-93680", "CVE-2026-104339")
OPEN_CVE = "CVE-2026-119025"
NOW = datetime(2026, 10, 30, 9, 0, tzinfo=timezone.utc)


def _fixture(cve: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{cve}.json").read_text())


def _record(cve: str) -> dict[str, Any]:
    (vuln,) = _fixture(cve)["vulnerabilities"]
    return vuln


def _uv_lock(root: Path, version: str) -> None:
    (root / "uv.lock").write_text(f'[[package]]\nname = "langflow"\nversion = "{version}"\n')


def _package_lock(root: Path, version: str) -> None:
    (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "x"}, "node_modules/open": {"version": version}}}, indent=2))


def _cves(root: Path) -> list[tuple[Severity, str, int | None]]:
    findings, _ = scan(root)
    assert all(f.rule_id == RULE for f in findings)
    return sorted((f.severity, cve, f.line_number) for f in findings
                  for cve in sorted(set(LANGFLOW_CVES + (OPEN_CVE,))) if cve in f.evidence)


# ---- STEP 0: the records as NVD served them ------------------------------------------------------


def test_the_fixtures_are_nvd_api_answers_with_the_cna_data_at_cve_affected() -> None:
    """The CNA's version data is at `vulnerabilities[].cve.affected[].affectedData[]`;
    only CVE-2026-119025's CNA (VulnCheck) wrote packageURLs, IBM's records carry a
    vendor and product alone."""
    purls: dict[str, list[str]] = {}
    for cve in LANGFLOW_CVES + (OPEN_CVE,):
        page = _fixture(cve)
        assert page["format"] == "NVD_CVE" and page["version"] == "2.0" and page["totalResults"] == 1
        record = page["vulnerabilities"][0]["cve"]
        assert record["id"] == cve
        blocks = [data for block in record["affected"] for data in block["affectedData"]]
        assert all(block["versions"] for block in blocks)
        purls[cve] = [block["packageURL"] for block in blocks if "packageURL" in block]
    assert purls == {
        "CVE-2026-110186": [], "CVE-2026-93680": [], "CVE-2026-104339": [],
        OPEN_CVE: ["pkg:npm/open", "pkg:npm/%40modelcontextprotocol/inspector", "pkg:npm/opencode-ai"],
    }


def test_the_bundled_nvd_entries_are_the_fixtures_as_converted() -> None:
    """data/advisories.json's `nvd` list is exactly what `nvd_feed` makes of the four
    records, with the reviewed map shipped beside it; every one of the four maps."""
    rows = nvd_feed.load_package_map()
    tally = nvd_feed.Tally()
    converted = nvd_feed.merged(entry for cve in LANGFLOW_CVES + (OPEN_CVE,)
                                for entry in nvd_feed.record_entries(_record(cve), rows, tally))
    bundled = json.loads(advisory_feed.BUNDLED_FEED.read_text())
    assert bundled["nvd"] == converted
    assert (tally.records, tally.mapped, tally.unmapped, tally.entries) == (4, 4, 0, 6)
    assert [(e["name"], e["id"], e["ranges"]) for e in converted] == [
        ("langflow", "CVE-2026-104339", [{"introduced": "1.0.0", "last_affected": "1.12.3"}]),
        ("langflow", "CVE-2026-110186", [{"introduced": "1.0.0", "last_affected": "1.12.8"}]),
        ("langflow", "CVE-2026-93680", [{"introduced": "1.0.0", "last_affected": "1.12.8"}]),
        ("@modelcontextprotocol/inspector", OPEN_CVE, [{"introduced": "2.0.0", "fixed": "2.12.0"}]),
        ("open", OPEN_CVE, [{"introduced": "7.2.0", "fixed": "11.0.0"}]),
        ("opencode-ai", OPEN_CVE, [{"introduced": "1.0.137", "fixed": "1.18.33"}]),
    ]
    assert {e["severity"] for e in converted if e["name"] == "langflow"} == {"CRITICAL"}
    assert {(e["severity"], e["score"], e["scored_by"]) for e in converted if e["id"] == OPEN_CVE} == {
        ("HIGH", 7.5, "nvd-cvss3")}


def test_the_reviewed_map_names_each_package_s_own_repository() -> None:
    rows = {(row.vendor, row.product): row for row in nvd_feed.load_package_map()}
    assert {key: (row.ecosystem, row.name, row.repo) for key, row in rows.items()} == {
        ("IBM", "Langflow OSS"): ("PyPI", "langflow", "github.com/langflow-ai/langflow"),
        ("sindresorhus", "open"): ("npm", "open", "github.com/sindresorhus/open"),
        ("modelcontextprotocol", "inspector"): (
            "npm", "@modelcontextprotocol/inspector", "github.com/modelcontextprotocol/inspector"),
    }
    assert all(row.reviewed == "2026-10-30" for row in rows.values())


# ---- the order's cases, on the bundled feed -----------------------------------------------------------


@pytest.mark.parametrize("version, expected", [
    ("1.12.8", ["CVE-2026-110186", "CVE-2026-93680"]),
    ("1.13.0", []),
    ("1.0.0", ["CVE-2026-104339", "CVE-2026-110186", "CVE-2026-93680"]),
    ("0.9.9", []),
])
def test_a_langflow_lockfile_is_judged_by_ibm_s_cna_ranges(tmp_path: Path, version: str, expected: list[str]) -> None:
    _uv_lock(tmp_path, version)
    assert _cves(tmp_path) == [(Severity.CRITICAL, cve, 2) for cve in sorted(expected)]


def test_the_langflow_finding_names_the_nvd_record_and_its_last_affected_release(tmp_path: Path) -> None:
    _uv_lock(tmp_path, "1.12.8")
    findings, _ = scan(tmp_path)
    (finding,) = [f for f in findings if "CVE-2026-110186" in f.evidence]
    assert finding.severity is Severity.CRITICAL
    assert finding.evidence.startswith(
        "uv.lock resolves langflow 1.12.8, which CVE-2026-110186 (NVD CNA record, CVSS 3.x 9.8) lists as "
        "affected; the advisory lists no fixed release, and 1.12.8 as the last affected one "
        "(https://nvd.nist.gov/vuln/detail/CVE-2026-110186). Feed: the bundled copy generated ")


@pytest.mark.parametrize("version, fires", [("10.1.0", True), ("11.0.0", False), ("7.1.0", False), ("7.2.0", True)])
def test_an_open_lockfile_is_judged_by_vulncheck_s_packageurl_ranges(tmp_path: Path, version: str, fires: bool) -> None:
    _package_lock(tmp_path, version)
    assert _cves(tmp_path) == ([(Severity.HIGH, OPEN_CVE, 7)] if fires else [])
    if fires:
        (finding,) = scan(tmp_path)[0]
        assert "; it is fixed in 11.0.0 (https://nvd.nist.gov/vuln/detail/CVE-2026-119025)" in finding.evidence


def test_a_range_admitting_releases_on_both_sides_of_the_last_affected_one_is_info(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("langflow>=1.12\n")
    findings, _ = scan(tmp_path)
    (finding,) = findings
    assert finding.severity is Severity.INFO
    assert "CVE-2026-110186 (NVD CNA record, CVSS 3.x 9.8), no fixed release listed, last affected 1.12.8" in (
        finding.evidence)


def test_a_scan_of_the_bundled_feed_reports_through_the_engine(tmp_path: Path) -> None:
    """Nothing else in 0.6.29 reported langflow 1.12.8; through the engine it is CRITICAL."""
    _uv_lock(tmp_path, "1.12.8")
    result = run_scan(project_root=tmp_path)
    named = {cve for f in result.findings for cve in LANGFLOW_CVES if cve in f.evidence}
    assert named == {"CVE-2026-110186", "CVE-2026-93680"}
    assert {f.severity for f in result.findings if "CVE-2026-110186" in f.evidence} == {Severity.CRITICAL}


# ---- which package a record names ---------------------------------------------------------------------


@pytest.mark.parametrize("purl, expected", [
    ("pkg:npm/open", ("npm", "open")),
    ("pkg:npm/%40modelcontextprotocol/inspector", ("npm", "@modelcontextprotocol/inspector")),
    ("pkg:npm/%40modelcontextprotocol/inspector@2.11.0", ("npm", "@modelcontextprotocol/inspector")),
    ("pkg:npm/@scope/name@1.0.0?arch=x#sub", ("npm", "@scope/name")),
    ("pkg:pypi/langflow@1.12.8", ("PyPI", "langflow")),
    ("PKG:PyPI/Lang_Flow", ("PyPI", "Lang_Flow")),
    ("pkg:maven/org.example/lib@1.0", None),
    ("pkg:npm/%40scope", None),
    ("pkg:npm/a/b/c", None),
    ("pkg:pypi/ns/name", None),
    ("https://github.com/sindresorhus/open", None),
    ("", None),
])
def test_purl_package(purl: str, expected: tuple[str, str] | None) -> None:
    assert nvd_feed.purl_package(purl) == expected


def _cna(*affected: dict[str, Any], cna: str = "cna@example.com", metrics: dict[str, Any] | None = None,
         status: str = "Received", ident: str = "CVE-2026-90001") -> dict[str, Any]:
    return {"cve": {"id": ident, "sourceIdentifier": cna, "vulnStatus": status, "lastModified": "2026-10-30T00:00:00.000",
                    "affected": [{"source": cna, "affectedData": list(affected)}], "metrics": metrics or {}}}


def _affected(versions: list[dict[str, Any]], **fields: Any) -> dict[str, Any]:
    return {"vendor": "IBM", "product": "Langflow OSS", "versions": versions, **fields}


def test_a_packageurl_wins_over_the_map_and_one_of_another_registry_is_dropped() -> None:
    rows = nvd_feed.load_package_map()
    versions = [{"version": "1.0.0", "lessThan": "2.0.0", "versionType": "semver", "status": "affected"}]
    tally = nvd_feed.Tally()
    (entry,) = nvd_feed.record_entries(_cna(_affected(versions, packageURL="pkg:pypi/langflow-base")), rows, tally)
    assert (entry["name"], entry["mapped_by"]) == ("langflow-base", "packageURL")
    assert nvd_feed.record_entries(_cna(_affected(versions, packageURL="pkg:maven/ibm/langflow")), rows, tally) == []
    assert (tally.mapped, tally.unmapped) == (1, 1)


def test_a_repository_maps_whatever_the_vendor_is_called() -> None:
    rows = nvd_feed.load_package_map()
    versions = [{"version": "1.0.0", "lessThan": "2.0.0", "versionType": "semver", "status": "affected"}]
    affected = {"vendor": "langflow-ai", "product": "langflow", "repo": "git+https://github.com/Langflow-AI/langflow.git",
                "versions": versions}
    (entry,) = nvd_feed.record_entries(_cna(affected), rows)
    assert (entry["ecosystem"], entry["name"], entry["mapped_by"]) == ("PyPI", "langflow", "map")


def test_an_unmapped_vendor_and_product_is_dropped_and_counted() -> None:
    """Never a mapping from a name alone: `langflow` by another vendor is not IBM's."""
    tally = nvd_feed.Tally()
    versions = [{"version": "1.0.0", "lessThan": "2.0.0", "versionType": "semver", "status": "affected"}]
    for affected in ({"vendor": "someone", "product": "langflow", "versions": versions},
                     {"vendor": "IBM", "product": "Langflow Desktop", "versions": versions},
                     {"vendor": "IBM", "product": "Langflow OSS", "repo": "https://github.com/other/langflow",
                      "versions": versions}):
        found = nvd_feed.record_entries(_cna(affected), nvd_feed.load_package_map(), tally)
        if affected.get("repo"):
            assert [e["name"] for e in found] == ["langflow"]  # no row has that repo; vendor and product still map
        else:
            assert found == []
    assert (tally.records, tally.with_cna, tally.unmapped, tally.mapped) == (3, 3, 2, 1)


def test_a_cpe_only_record_is_counted_and_not_read() -> None:
    record = {"cve": {"id": "CVE-2026-90002", "sourceIdentifier": "cna@example.com", "vulnStatus": "Analyzed",
                      "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
                          {"vulnerable": True, "criteria": "cpe:2.3:a:langflow:langflow:*:*:*:*:*:*:*:*",
                           "versionEndExcluding": "1.13.0"}]}]}]}}
    tally = nvd_feed.Tally()
    assert nvd_feed.record_entries(record, nvd_feed.load_package_map(), tally) == []
    assert (tally.records, tally.no_cna, tally.with_cna, tally.unmapped) == (1, 1, 0, 0)


@pytest.mark.parametrize("record", [
    {}, {"cve": "nope"}, {"cve": {"id": 7}}, {"cve": {"id": "GHSA-x"}},
    {"cve": {"id": "CVE-2026-90003", "affected": "nope"}},
    {"cve": {"id": "CVE-2026-90003", "affected": [{"affectedData": [{"versions": "nope", "packageURL": 5}]}]}},
    {"cve": {"id": "CVE-2026-90003", "affected": [{"affectedData": [{"vendor": "IBM", "product": "Langflow OSS",
                                                                     "versions": [{"version": ["1"]}, 5]}]}]}},
])
def test_an_odd_record_costs_only_itself(record: dict[str, Any]) -> None:
    assert nvd_feed.record_entries(record, nvd_feed.load_package_map()) == []


def test_a_rejected_record_gives_nothing() -> None:
    versions = [{"version": "1.0.0", "lessThan": "2.0.0", "versionType": "semver", "status": "affected"}]
    tally = nvd_feed.Tally()
    assert nvd_feed.record_entries(_cna(_affected(versions), status="Rejected"), nvd_feed.load_package_map(), tally) == []
    assert (tally.records, tally.rejected) == (1, 1)


def test_an_adp_block_is_read_only_when_none_names_the_cna() -> None:
    versions = [{"version": "1.0.0", "lessThan": "2.0.0", "versionType": "semver", "status": "affected"}]
    other = [{"version": "1.0.0", "lessThan": "9.0.0", "versionType": "semver", "status": "affected"}]
    record = _cna(_affected(versions))
    record["cve"]["affected"].append({"source": "adp@example.com", "affectedData": [_affected(other)]})
    (entry,) = nvd_feed.record_entries(record, nvd_feed.load_package_map())
    assert entry["ranges"] == [{"introduced": "1.0.0", "fixed": "2.0.0"}]
    record["cve"]["affected"] = record["cve"]["affected"][1:]
    (entry,) = nvd_feed.record_entries(record, nvd_feed.load_package_map())
    assert entry["ranges"] == [{"introduced": "1.0.0", "fixed": "9.0.0"}]


# ---- which versions ---------------------------------------------------------------------------------


def _ranges(versions: list[dict[str, Any]], ecosystem: str = "PyPI", default: str | None = None) -> object:
    affected: dict[str, Any] = {"versions": versions}
    if default is not None:
        affected["defaultStatus"] = default
    read = nvd_feed.cna_ranges(affected, ecosystem)
    if read is None:
        return None
    return [advisory_feed._interval(row) for row in read[0]], read[1]


@pytest.mark.parametrize("versions, expected", [
    ([{"version": "1.0.0", "lessThan": "1.13.0", "versionType": "semver", "status": "affected"}],
     ([{"introduced": "1.0.0", "fixed": "1.13.0"}], [])),
    ([{"version": "1.0.0", "lessThanOrEqual": "1.12.8", "versionType": "custom", "status": "affected"}],
     ([{"introduced": "1.0.0", "last_affected": "1.12.8"}], [])),
    ([{"version": "0", "lessThan": "2.0", "versionType": "python", "status": "affected"}],
     ([{"introduced": "0", "fixed": "2.0"}], [])),
    ([{"version": "1.0.0", "lessThan": "*", "versionType": "semver", "status": "affected"}],
     ([{"introduced": "1.0.0"}], [])),
    ([{"version": "1.4.2", "status": "affected"}, {"version": "1.5.0", "status": "unaffected"}],
     ([], ["1.4.2"])),
    ([{"version": "< 4.13.5", "status": "affected"}, {"version": "1.0 to 1.8.0", "status": "affected"}], ([], [])),
    ([{"version": "abc123", "lessThan": "def456", "versionType": "git", "status": "affected"}], ([], [])),
    ([{"version": "1.0.0", "lessThan": "2.0.0", "versionType": "semver", "status": "unaffected"}], ([], [])),
    ([{"version": "1.0.0", "lessThan": "2.0.0", "versionType": "semver", "status": "affected",
       "changes": [{"at": "1.5.0", "status": "unaffected"}, {"at": "1.7.0", "status": "affected"}]}],
     ([{"introduced": "1.0.0", "fixed": "1.5.0"}, {"introduced": "1.7.0", "fixed": "2.0.0"}], [])),
])
def test_cna_versions(versions: list[dict[str, Any]], expected: object) -> None:
    assert _ranges(versions) == expected


def test_default_status_affected_leaves_every_release_the_entries_do_not_exclude() -> None:
    versions = [{"version": "2.0.0", "lessThan": "2.4.1", "versionType": "semver", "status": "unaffected"},
                {"version": "3.0.0", "lessThan": "*", "versionType": "semver", "status": "unaffected"}]
    assert _ranges(versions, "npm", default="affected") == (
        [{"introduced": "0", "fixed": "2.0.0"}, {"introduced": "2.4.1", "fixed": "3.0.0"}], [])


@pytest.mark.parametrize("versions", [
    [{"version": "2.4.1", "status": "unaffected"}],
    [{"version": "2.0.0", "lessThanOrEqual": "2.4.0", "versionType": "semver", "status": "unaffected"}],
    [{"version": "abc", "lessThan": "def", "versionType": "git", "status": "unaffected"}],
])
def test_default_status_affected_with_an_exclusion_no_interval_can_state_is_not_read(
        versions: list[dict[str, Any]]) -> None:
    """Reported wider than the CNA wrote it, a hole would become a false finding."""
    assert _ranges(versions, "npm", default="affected") is None


def test_versions_are_read_on_the_registry_s_own_order() -> None:
    (row,), _ = nvd_feed.cna_ranges({"versions": [
        {"version": "1.0.0", "lessThan": "1.13.0", "versionType": "semver", "status": "affected"}]}, "PyPI")
    assert row.admits("1.13.0rc1") and not row.admits("1.13.0")  # PEP 440: a pre-release sorts below its release


# ---- severity ---------------------------------------------------------------------------------------


def _metric(version: str, kind: str, **data: Any) -> dict[str, Any]:
    return {"source": "x", "type": kind, "cvssData": {"version": version, **data}}


@pytest.mark.parametrize("metrics, expected", [
    ({"cvssMetricV31": [_metric("3.1", "Secondary", vectorString="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")]},
     ("CRITICAL", 9.8, "nvd-cvss3")),
    ({"cvssMetricV31": [_metric("3.1", "Secondary", vectorString="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
                        _metric("3.1", "Primary", vectorString="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")]},
     ("HIGH", 8.1, "nvd-cvss3")),
    ({"cvssMetricV40": [_metric("4.0", "Secondary", baseSeverity="HIGH")]}, ("HIGH", None, "nvd-label")),
    ({"cvssMetricV40": [_metric("4.0", "Secondary", baseSeverity="LOW")]}, ("MEDIUM", None, "nvd-label")),
    ({"cvssMetricV31": [_metric("3.1", "Primary", vectorString="CVSS:3.1/AV:N")]}, ("MEDIUM", None, "")),
    ({}, ("MEDIUM", None, "")),
    ("nope", ("MEDIUM", None, "")),
])
def test_nvd_severity(metrics: object, expected: tuple[str, float | None, str]) -> None:
    assert nvd_feed.nvd_severity(metrics) == expected


# ---- OSV wins ---------------------------------------------------------------------------------------


_OSV_LANGFLOW = {"id": "GHSA-aaaa-lang-flow", "aliases": ["CVE-2026-110186"], "modified": "m",
                 "database_specific": {"severity": "CRITICAL"}, "affected": [
    {"package": {"ecosystem": "PyPI", "name": "langflow"},
     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.13.0"}]}]}]}


def test_an_nvd_entry_osv_already_lists_is_reported_once_as_osv_s(tmp_path: Path) -> None:
    bundled = json.loads(advisory_feed.BUNDLED_FEED.read_text())
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test",
                                "entries": advisory_feed.advisory_entries(_OSV_LANGFLOW, "PyPI"),
                                "nvd": bundled["nvd"]}))
    _uv_lock(tmp_path, "1.12.8")
    findings, _ = scan(tmp_path)
    assert sorted(f.evidence.split(" (")[0].rsplit(" ", 1)[-1] for f in findings) == [
        "CVE-2026-93680", "GHSA-aaaa-lang-flow"]
    (osv,) = [f for f in findings if "CVE-2026-110186" in f.evidence]
    assert "GHSA-aaaa-lang-flow (CVE-2026-110186" in osv.evidence and "fixed in 1.13.0" in osv.evidence


def test_the_rebuild_drops_an_nvd_entry_osv_already_lists() -> None:
    collector = advisory_feed.Collector()
    collector.add("PyPI", _OSV_LANGFLOW)
    collector.add_nvd(json.loads(advisory_feed.BUNDLED_FEED.read_text())["nvd"],
                      {"field": "lastModified", "start": "2026-07-02T09:00:00Z", "end": "2026-10-30T09:00:00Z",
                       "days": 120})
    written = collector.write(now=NOW)
    assert (written.nvd, written.nvd_twins) == (5, 1)
    data = json.loads(written.path.read_text())
    assert "CVE-2026-110186" not in {e["id"] for e in data["nvd"]}
    assert data["source"].endswith("; NVD's records of CNA version data modified 2026-07-02 to 2026-10-30, "
                                   "where OSV has no record of the CVE")
    assert advisory_feed.load_feed().summary()["nvdWindow"] == "2026-07-02 to 2026-10-30"


# ---- reading NVD --------------------------------------------------------------------------------------


class _Opener:
    """Answers NVD queries from a list of pages, recording each request."""

    def __init__(self, *answers: object) -> None:
        self.answers = list(answers)
        self.requests: list[urllib.request.Request] = []

    def __call__(self, request: urllib.request.Request, timeout: float | None = None) -> io.BytesIO:
        self.requests.append(request)
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return io.BytesIO(json.dumps(answer).encode())


def _page(vulns: list[dict[str, Any]], total: int, start: int = 0) -> dict[str, Any]:
    return {"resultsPerPage": len(vulns), "startIndex": start, "totalResults": total, "format": "NVD_CVE",
            "version": "2.0", "vulnerabilities": vulns}


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(nvd_feed.NVD_API, code, "x", {}, None)  # type: ignore[arg-type]


def test_fetch_pages_the_window_and_converts_what_maps() -> None:
    cpe_only = {"cve": {"id": "CVE-2026-90002", "sourceIdentifier": "x", "vulnStatus": "Analyzed"}}
    opener = _Opener(_page([_record("CVE-2026-110186"), cpe_only], 4),
                     _page([_record(OPEN_CVE), _record("CVE-2026-93680")], 4, 2))
    sleeps: list[float] = []
    progress: list[tuple[int, int]] = []
    fetched = nvd_feed.fetch(120, opener=opener, sleep=sleeps.append, now=NOW, page_size=2,
                             progress=lambda done, expected: progress.append((done, expected)))
    assert [(e["name"], e["id"]) for e in fetched.entries] == [
        ("langflow", "CVE-2026-110186"), ("langflow", "CVE-2026-93680"),
        ("@modelcontextprotocol/inspector", OPEN_CVE), ("open", OPEN_CVE), ("opencode-ai", OPEN_CVE)]
    assert (fetched.tally.records, fetched.tally.no_cna, fetched.tally.mapped) == (4, 1, 3)
    assert fetched.window == {"field": "lastModified", "start": "2026-07-02T09:00:00Z", "end": "2026-10-30T09:00:00Z",
                              "days": 120}
    assert fetched.pages == 2 and progress == [(1, 2), (2, 2)] and sleeps == [nvd_feed.REQUEST_INTERVAL]
    first, second = (urllib.parse.parse_qs(urllib.parse.urlsplit(r.full_url).query) for r in opener.requests)
    assert first["lastModStartDate"] == ["2026-07-02T09:00:00.000"]
    assert first["lastModEndDate"] == ["2026-10-30T09:00:00.000"]
    assert (first["startIndex"], second["startIndex"], first["resultsPerPage"]) == (["0"], ["2"], ["2"])
    assert all(r.get_header("Apikey") is None for r in opener.requests)


def test_an_api_key_is_sent_as_a_header_and_shortens_the_pause() -> None:
    opener = _Opener(_page([_record(OPEN_CVE)], 2), _page([_record("CVE-2026-93680")], 2, 1))
    sleeps: list[float] = []
    nvd_feed.fetch(1, api_key="test-nvd-key", opener=opener, sleep=sleeps.append, now=NOW, page_size=1)
    assert [r.get_header("Apikey") for r in opener.requests] == ["test-nvd-key", "test-nvd-key"]
    assert sleeps == [nvd_feed.REQUEST_INTERVAL_WITH_KEY]


def test_a_rate_limit_is_retried_with_a_back_off() -> None:
    opener = _Opener(_http_error(429), _http_error(503), _page([_record(OPEN_CVE)], 1))
    sleeps: list[float] = []
    fetched = nvd_feed.fetch(30, opener=opener, sleep=sleeps.append, now=NOW)
    assert len(fetched.entries) == 3 and sleeps == [nvd_feed.BACKOFF, nvd_feed.BACKOFF * 2]


@pytest.mark.parametrize("answers, message", [
    ([_http_error(404)], "NVD answered HTTP 404"),
    ([urllib.error.URLError("offline")] * nvd_feed.ATTEMPTS, "URLError"),
    ([_http_error(429)] * nvd_feed.ATTEMPTS, "NVD answered HTTP 429"),
    ([{"vulnerabilities": "nope", "totalResults": 1}], "without `vulnerabilities` and `totalResults`"),
    ([{"vulnerabilities": [], "totalResults": True}], "without `vulnerabilities` and `totalResults`"),
    ([[1, 2]] * nvd_feed.ATTEMPTS, "not a JSON object"),
])
def test_an_nvd_that_cannot_be_read_raises(answers: list[object], message: str) -> None:
    with pytest.raises(nvd_feed.NvdUpdateError, match=message):
        nvd_feed.fetch(30, opener=_Opener(*answers), sleep=lambda _s: None, now=NOW)


def test_a_query_that_never_ends_stops_at_the_page_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(nvd_feed, "MAX_PAGES", 3)
    opener = _Opener(*[_page([_record(OPEN_CVE)], 10**9, i) for i in range(5)])
    with pytest.raises(nvd_feed.NvdUpdateError, match="more than 3 pages"):
        nvd_feed.fetch(30, opener=opener, sleep=lambda _s: None, now=NOW, page_size=1)
    assert len(opener.requests) == 3


@pytest.mark.parametrize("days", [0, 121, -1])
def test_the_window_is_nvd_s(days: int) -> None:
    with pytest.raises(ValueError, match="days must be 1 to 120"):
        nvd_feed.fetch(days, opener=_Opener(), now=NOW)


# ---- `aak update` -------------------------------------------------------------------------------------


def _export(records: dict[str, dict[str, Any]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, record in records.items():
            archive.writestr(f"{name}.json", json.dumps(record))
    return buffer.getvalue()


_OSV_FLAWED = {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-9002"], "modified": "m",
               "database_specific": {"severity": "HIGH"}, "affected": [
    {"package": {"ecosystem": "PyPI", "name": "aak-flawed"},
     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}]}


class _Response(io.BytesIO):
    headers: dict[str, str] = {"Link": ""}


def _osv(request: urllib.request.Request, timeout: float | None = None) -> _Response:
    if request.full_url.endswith("/PyPI/all.zip"):
        return _Response(_export({"GHSA-aaaa-bbbb-cccc": _OSV_FLAWED}))
    if request.full_url.endswith("/npm/all.zip"):
        return _Response(_export({}))
    raise AssertionError(request.full_url)


@pytest.fixture
def offline_osv(monkeypatch: pytest.MonkeyPatch) -> None:
    """`aak update`'s other downloads, answered locally."""
    from agent_audit_kit import vuln_db

    monkeypatch.setattr(vuln_db, "update_database", lambda: 7)
    monkeypatch.setattr(malicious_feed.urllib.request, "urlopen", _osv)
    for name in ("GITHUB_TOKEN", "GH_TOKEN", "NVD_API_KEY"):
        monkeypatch.delenv(name, raising=False)


def _cached() -> dict[str, Any]:
    return json.loads(advisory_feed.cache_path().read_text())


def test_aak_update_reads_nvd_into_the_feed(offline_osv: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    unmapped = {"cve": {"id": "CVE-2026-90004", "sourceIdentifier": "x", "affected": [{"source": "x", "affectedData": [
        {"vendor": "nobody", "product": "nothing", "versions": [
            {"version": "1.0", "lessThan": "2.0", "versionType": "semver", "status": "affected"}]}]}]}}
    opener = _Opener(_page([_record("CVE-2026-110186"), _record(OPEN_CVE), unmapped], 3))
    monkeypatch.setattr(nvd_feed, "_default_opener", lambda: opener)
    monkeypatch.setenv("NVD_API_KEY", "test-nvd-key-0123")
    result = CliRunner().invoke(cli, ["update", "--nvd-days", "30"])
    assert result.exit_code == 0, result.output
    assert "test-nvd-key-0123" not in result.output and opener.requests[0].get_header("Apikey") == "test-nvd-key-0123"
    assert "NVD: 3 records modified " in result.output
    assert "3 carry CNA version data: 2 name a PyPI or npm package (4 entries), 1 name none that maps and are dropped" in (
        result.output)
    assert "Advisory feed updated: 1 entries for 1 packages (PyPI 1, npm 0)" in result.output
    assert "NVD CNA records: 4 entries, 0 more dropped because OSV already lists their CVE." in result.output
    data = _cached()
    assert sorted((e["name"], e["id"]) for e in data["nvd"]) == [
        ("@modelcontextprotocol/inspector", OPEN_CVE), ("langflow", "CVE-2026-110186"), ("open", OPEN_CVE),
        ("opencode-ai", OPEN_CVE)]
    assert data["nvd_window"]["days"] == 30 and "OSV advisory records" in data["source"]
    assert "; NVD's records of CNA version data modified " in data["source"]
    _uv_lock(tmp_path, "1.12.8")
    assert _cves(tmp_path) == [(Severity.CRITICAL, "CVE-2026-110186", 2)]  # the cache, not the bundled seed
    console = console_results(run_scan(project_root=tmp_path))
    assert "Advisory feed: cached copy, generated " in console and ", NVD CNA records modified " in console


def test_an_nvd_outage_keeps_the_cached_nvd_entries_and_rebuilds_osv(offline_osv: None,
                                                                      monkeypatch: pytest.MonkeyPatch,
                                                                      tmp_path: Path) -> None:
    window = {"field": "lastModified", "start": "2026-07-01T00:00:00Z", "end": "2026-10-29T00:00:00Z", "days": 120}
    cached_nvd = [e for e in json.loads(advisory_feed.BUNDLED_FEED.read_text())["nvd"] if e["name"] == "open"]
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "old", "source": "old", "entries": [], "nvd": cached_nvd,
                                "nvd_window": window}))
    opener = _Opener(*[urllib.error.URLError("offline")] * nvd_feed.ATTEMPTS)
    monkeypatch.setattr(nvd_feed, "_default_opener", lambda: opener)
    result = CliRunner().invoke(cli, ["update"])
    assert result.exit_code == 2, result.output
    assert "NVD read failed: URLError: <urlopen error offline>. The advisory feed is rebuilt from OSV and keeps " \
           "the 1 NVD entries of the cached feed." in result.output
    assert "Advisory feed updated: 1 entries for 1 packages (PyPI 1, npm 0)" in result.output
    data = _cached()
    assert [e["id"] for e in data["entries"]] == ["GHSA-aaaa-bbbb-cccc"]  # the OSV half, rebuilt
    assert data["nvd"] == cached_nvd and data["nvd_window"] == window
    assert data["source"].endswith("; NVD's records of CNA version data modified 2026-07-01 to 2026-10-29, "
                                   "kept from the previous update, where OSV has no record of the CVE")
    assert len(opener.requests) == nvd_feed.ATTEMPTS
    _package_lock(tmp_path, "10.1.0")
    assert _cves(tmp_path) == [(Severity.HIGH, OPEN_CVE, 7)]


def test_without_a_cached_nvd_list_an_outage_keeps_the_bundled_one(offline_osv: None,
                                                                    monkeypatch: pytest.MonkeyPatch,
                                                                    tmp_path: Path) -> None:
    """A first `aak update` that cannot reach NVD must not hide the bundled entries:
    the file it writes is the one scans read from then on."""
    monkeypatch.setattr(nvd_feed, "_default_opener", lambda: _Opener(_http_error(404)))
    result = CliRunner().invoke(cli, ["update"])
    assert result.exit_code == 2 and "keeps the 6 NVD entries of the bundled feed." in result.output
    assert _cached()["nvd"] == json.loads(advisory_feed.BUNDLED_FEED.read_text())["nvd"]
    _uv_lock(tmp_path, "1.12.8")
    assert [cve for _, cve, _ in _cves(tmp_path)] == ["CVE-2026-110186", "CVE-2026-93680"]


def test_nvd_days_0_reads_nothing_and_keeps_what_scans_read(offline_osv: None) -> None:
    result = CliRunner().invoke(cli, ["update", "--nvd-days", "0"])
    assert result.exit_code == 0, result.output
    assert "NVD not read (--nvd-days 0): the advisory feed keeps the 6 NVD entries of the bundled feed." in result.output
    assert len(_cached()["nvd"]) == 6


def test_nvd_days_is_bounded_by_nvd_s_window() -> None:
    result = CliRunner().invoke(cli, ["update", "--nvd-days", "121"])
    assert result.exit_code == 2 and "121 is not in the range 0<=x<=120" in result.output
