"""AAK-KNOWN-VULN-001 and the offline advisory feed it reads.

vLLM 0.31.1, MLflow 3.16.0 and OpenHands SDK 1.51.0 locked in a project passed
every rule on 0.6.28: AAK knew a vulnerable release only through a hand-written
pin. These tests pin the three places the rule reads a release (a lockfile, a
manifest declaration, an installed dist-info), the PEP 440 order an advisory
range is read in (MLflow's `>=3.12.0rc0`), how a manifest range is reported
(INFO unless every release it admits is affected, nothing when a lockfile beside
it decides), that a PYSEC record and its GHSA twin report once, that a version
pin naming the same CVE in the same file stands, the cached-then-bundled load
order, and `aak update` building the feed from the downloads the
malicious-release feed already makes. The advisory file under
tests/fixtures/known_vulns is hand-written in OSV's shape; nothing is fetched.
"""

from __future__ import annotations

import dataclasses
import http.client
import io
import json
import re
import shutil
import socket
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_audit_kit import advisory_feed, malicious_feed
from agent_audit_kit.cli import cli
from agent_audit_kit.engine import _drop_known_vulns_a_rule_reports, run_scan
from agent_audit_kit.models import Severity
from agent_audit_kit.output.console import format_results as console_results
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners._helpers import make_finding
from agent_audit_kit.scanners.known_vulns import MAX_RELEASES_PER_PACKAGE, RULE, evidence_cves, scan

FIXTURES = Path(__file__).parent / "fixtures" / "known_vulns"
VLLM, MLFLOW, OPENHANDS, LITELLM, LODASH = (
    "GHSA-h3rc-j82p-2c3h", "GHSA-26p8-2jq9-3vq9", "AAK-TEST-OPENHANDS-SDK", "GHSA-7488-6r32-c95q", "GHSA-35jh-r3h4-6jhm")


@pytest.fixture
def feed() -> Path:
    """The hand-written advisory file, put where `aak update` caches the feed (the
    test's own empty HOME, see conftest's `_isolated_home`)."""
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FIXTURES / "advisories.json", path)
    return path


_ID_RE = re.compile(r"\b(?:GHSA|PYSEC|AAK-TEST)-[\w-]+")


def _found(root: Path) -> set[tuple[str, int | None, Severity, str]]:
    """(file, line, severity, the advisory id the evidence names first) per finding."""
    findings, _ = scan(root)
    assert all(f.rule_id == RULE for f in findings)
    return {(f.file_path, f.line_number, f.severity, _ID_RE.search(f.evidence).group(0))  # type: ignore[union-attr]
            for f in findings}


# ---- the fixtures ------------------------------------------------------------------------------


def test_each_place_a_release_is_read_fires(feed: Path) -> None:
    # vLLM's record carries GitHub's CVSS 3.1 vector, AC:H, base 8.1: HIGH. NVD scored
    # CVE-2026-115915 9.8, but that score is not in the OSV record the rule reads.
    assert _found(FIXTURES / "firing") == {
        ("uv.lock", 2, Severity.CRITICAL, OPENHANDS),
        ("uv.lock", 6, Severity.HIGH, VLLM),
        ("poetry.lock", 2, Severity.CRITICAL, MLFLOW),
        ("requirements.txt", 1, Severity.CRITICAL, MLFLOW),
        ("package-lock.json", 5, Severity.HIGH, LODASH),
        ("lib/python3.12/site-packages/mlflow-3.16.0.dist-info/METADATA", 3, Severity.CRITICAL, MLFLOW),
    }


def test_the_evidence_names_the_advisory_its_cve_the_release_and_the_fix(feed: Path) -> None:
    findings, _ = scan(FIXTURES / "firing")
    (vllm,) = [f for f in findings if VLLM in f.evidence]
    assert vllm.evidence.startswith(
        "uv.lock resolves vllm 0.31.1, which GHSA-h3rc-j82p-2c3h (CVE-2026-115915, CVSS 3.x 8.1) lists as "
        "affected; it is fixed in 0.32.0 (https://osv.dev/vulnerability/GHSA-h3rc-j82p-2c3h). Feed: the cached copy")
    assert evidence_cves(vllm.evidence) == {"CVE-2026-115915"}


def test_the_fixed_releases_are_clean(feed: Path) -> None:
    assert _found(FIXTURES / "negative") == set()


def test_the_rule_is_registered_critical_and_feed_driven() -> None:
    rule = RULES[RULE]
    assert rule.severity is Severity.CRITICAL and not rule.cve_references
    assert "ADV-SUPPLY-04" in rule.adversa_references


# ---- what matches ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "version, fires",
    [
        ("3.11.4", False),
        ("3.12.0rc0", True),   # MLflow's range opens at its first release candidate
        ("3.12.0", True),
        ("3.16.1", True),
        ("3.17.0rc1", True),   # PEP 440: a pre-release of the fix sorts below it
        ("3.17.0", False),
        ("3.17.1", False),
    ],
)
def test_mlflow_s_range_is_read_in_pep_440_order(feed: Path, tmp_path: Path, version: str, fires: bool) -> None:
    (tmp_path / "poetry.lock").write_text(f'[[package]]\nname = "mlflow"\nversion = "{version}"\n')
    assert bool(_found(tmp_path)) is fires


@pytest.mark.parametrize(
    "lower, higher",
    [("1.0.dev1", "1.0a1"), ("1.0a1", "1.0a1.post1"), ("1.0rc1", "1.0"), ("1.0", "1.0+local"),
     ("1.0+local", "1.0.post1"), ("1.0.post1", "1.0.1"), ("1.9", "1.10"), ("2.0", "1!0.1")],
)
def test_pep440_order(lower: str, higher: str) -> None:
    low, high = malicious_feed.pep440_order(lower), malicious_feed.pep440_order(higher)
    assert low is not None and high is not None and low < high
    assert malicious_feed.pep440_order("3.12") == malicious_feed.pep440_order("3.12.0")


def test_a_pinned_declaration_is_judged_as_an_install(feed: Path, tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("vllm==0.31.1\nmlflow==3.17.0\n")
    assert _found(tmp_path) == {("requirements.txt", 1, Severity.HIGH, VLLM)}


def test_a_range_that_admits_fixed_releases_is_info(feed: Path, tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = ["vllm>=0.30"]\n')
    findings, _ = scan(tmp_path)
    assert [(f.severity, f.line_number) for f in findings] == [(Severity.INFO, 3)]
    assert "admits releases an advisory lists as affected, and releases it does not" in findings[0].evidence
    assert "GHSA-h3rc-j82p-2c3h (CVE-2026-115915, CVSS 3.x 8.1), fixed in 0.32.0" in findings[0].evidence


@pytest.mark.parametrize(
    "spec, expected",
    [("vllm>=0.30,<0.32", Severity.HIGH), ("vllm<0.32", Severity.HIGH), ("vllm>=0.32", None), ("vllm", None)],
)
def test_a_range_is_reported_in_full_only_when_every_release_it_admits_is_affected(
    feed: Path, tmp_path: Path, spec: str, expected: Severity | None
) -> None:
    (tmp_path / "requirements.txt").write_text(spec + "\n")
    assert [f.severity for f in scan(tmp_path)[0]] == ([expected] if expected else [])


def test_a_lockfile_beside_a_range_says_what_is_installed(feed: Path, tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = ["vllm>=0.30"]\n')
    (tmp_path / "uv.lock").write_text('[[package]]\nname = "vllm"\nversion = "0.32.0"\n')
    assert _found(tmp_path) == set()
    (tmp_path / "uv.lock").write_text('[[package]]\nname = "vllm"\nversion = "0.31.1"\n')
    assert _found(tmp_path) == {("uv.lock", 2, Severity.HIGH, VLLM)}


def test_a_pysec_record_and_its_ghsa_twin_report_once(feed: Path, tmp_path: Path) -> None:
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "mlflow"\nversion = "3.16.0"\n')
    (finding,) = scan(tmp_path)[0]
    assert "GHSA-26p8-2jq9-3vq9 (CVE-2026-116692, PYSEC-2026-90001, CVSS 3.x 9.8)" in finding.evidence


def test_a_withdrawn_record_is_ignored(feed: Path, tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("aak-withdrawn==1.0.0\n")
    assert _found(tmp_path) == set()
    assert advisory_feed.load_feed().advisories("PyPI", "aak-withdrawn") == ()


def test_range_events_are_read_in_version_order(feed: Path) -> None:
    """PYSEC-2017-152 lists `last_affected` 7.2.0, 6.1.0, 5.3.0: read as written that
    admits every 6.x and 7.x; sorted, as OSV evaluates it, only 5.3.0 and below."""
    (advisory,) = advisory_feed.load_feed().advisories("PyPI", "instack")
    assert [advisory.matches(v) for v in ("5.3.0", "5.4.0", "6.1.0", "7.2.0")] == [True, False, False, False]


def test_npm_lockfiles_and_last_affected(feed: Path, tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "x"},
        "node_modules/lodash.template": {"version": "4.5.0"},
        "node_modules/a/node_modules/lodash.template": {"version": "4.5.1"},
    }}, indent=2))
    (finding,) = scan(tmp_path)[0]
    assert finding.evidence.startswith("package-lock.json resolves lodash.template 4.5.0, which GHSA-35jh-r3h4-6jhm")
    assert "the advisory lists no fixed release" in finding.evidence


def test_one_finding_per_package_and_advisory_naming_every_affected_release(feed: Path, tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "x"},
        "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/a/node_modules/lodash": {"version": "4.17.19"},
        "node_modules/b/node_modules/lodash": {"version": "4.17.21"},
    }}, indent=2))
    (finding,) = scan(tmp_path)[0]
    assert "resolves lodash 4.17.20 (and 1 more affected release: 4.17.19)" in finding.evidence


def test_a_lockfile_is_read_for_at_most_64_releases_of_a_package(feed: Path, tmp_path: Path) -> None:
    """The bound is in the rule's limitations: a crafted lockfile resolving one package at
    thousands of releases costs at most 64 of them per advisory."""
    assert MAX_RELEASES_PER_PACKAGE == 64
    safe = {f"node_modules/p{i}/node_modules/lodash": {"version": f"4.17.{100 + i}"} for i in range(64)}
    lock = {"lockfileVersion": 3, "packages": {"": {"name": "x"}, **safe,
                                               "node_modules/z/node_modules/lodash": {"version": "4.17.20"}}}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock, indent=2))
    assert scan(tmp_path)[0] == []
    del lock["packages"]["node_modules/p63/node_modules/lodash"]
    (tmp_path / "package-lock.json").write_text(json.dumps(lock, indent=2))
    assert len(scan(tmp_path)[0]) == 1


def test_an_installed_dist_info_is_read(feed: Path, tmp_path: Path) -> None:
    dist = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages" / "openhands_sdk-1.51.0.dist-info"
    dist.mkdir(parents=True)
    (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: openhands-sdk\nVersion: 1.51.0\n")
    assert _found(tmp_path) == {
        (".venv/lib/python3.12/site-packages/openhands_sdk-1.51.0.dist-info/METADATA", 3, Severity.CRITICAL,
         OPENHANDS)}


# ---- a pin rule that names the CVE ------------------------------------------------------------------


def test_a_version_pin_naming_the_cve_in_the_same_file_stands(feed: Path, tmp_path: Path) -> None:
    """AAK-MCP-LITELLM-CVE-2026-59822-001 (HIGH) pins litellm below 1.84.0 for
    CVE-2026-59822, which OSV's GHSA-7488-6r32-c95q (HIGH) also lists. In the root
    uv.lock, which the pin table reads, only the pin's finding is kept; in a uv.lock
    below the root, which it does not read, this rule reports the advisory."""
    lock = '[[package]]\nname = "litellm"\nversion = "1.83.0"\n'
    (tmp_path / "uv.lock").write_text(lock)
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "uv.lock").write_text(lock)
    assert {f.file_path for f in scan(tmp_path)[0] if LITELLM in f.evidence} == {"uv.lock", "svc/uv.lock"}
    result = run_scan(project_root=tmp_path)
    assert ("AAK-MCP-LITELLM-CVE-2026-59822-001", "uv.lock") in {(f.rule_id, f.file_path) for f in result.findings}
    assert {f.file_path for f in result.findings if f.rule_id == RULE and LITELLM in f.evidence} == {"svc/uv.lock"}


def _known(file_path: str, severity: Severity, cves: str) -> object:
    finding = make_finding(RULE, file_path, f"uv.lock resolves x 1.0, which GHSA-x ({cves}, CVSS 3.x 9.8) lists", 2)
    return dataclasses.replace(finding, severity=severity)


def _pin(file_path: str, severity: Severity) -> object:
    finding = make_finding("AAK-MCP-LITELLM-CVE-2026-59822-001", file_path, "litellm below 1.84.0", 2)
    return dataclasses.replace(finding, severity=severity)


@pytest.mark.parametrize(
    "known, pin, kept",
    [
        (_known("uv.lock", Severity.HIGH, "CVE-2026-59822"), _pin("uv.lock", Severity.HIGH), False),
        # A pin below the advisory's severity would let a `--severity` floor hide the flaw.
        (_known("uv.lock", Severity.CRITICAL, "CVE-2026-59822"), _pin("uv.lock", Severity.HIGH), True),
        (_known("svc/uv.lock", Severity.HIGH, "CVE-2026-59822"), _pin("uv.lock", Severity.HIGH), True),
        # Every CVE id must be reported: one the pin does not name keeps the finding.
        (_known("uv.lock", Severity.HIGH, "CVE-2026-59822, CVE-2026-90001"), _pin("uv.lock", Severity.HIGH), True),
    ],
)
def test_the_engine_drops_this_rule_only_where_a_rule_reports_its_cves(known: object, pin: object, kept: bool) -> None:
    left = _drop_known_vulns_a_rule_reports([pin, known])  # type: ignore[list-item]
    assert (known in left) is kept and pin in left


# ---- the feed and its load order ---------------------------------------------------------------------


def test_the_bundled_feed_is_osv_s_records_unedited() -> None:
    data = json.loads(advisory_feed.BUNDLED_FEED.read_text())
    assert [r["id"] for r in data["records"]] == [VLLM, MLFLOW]
    for record in data["records"]:
        assert record["schema_version"] and record["details"] and record["published"]  # as OSV returns it
    feed = advisory_feed.load_feed()
    assert feed.origin == "bundled"
    assert [(a.id, a.severity, a.score) for a in feed.match("PyPI", "vllm", "0.31.1")] == [(VLLM, "HIGH", 8.1)]
    assert [(a.id, a.severity) for a in feed.match("PyPI", "mlflow", "3.16.0")] == [(MLFLOW, "CRITICAL")]
    assert feed.match("PyPI", "vllm", "0.32.0") == [] and feed.match("PyPI", "mlflow", "3.17.0") == []


def test_the_cached_feed_is_read_first_and_a_corrupt_one_falls_back(feed: Path, tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text('[[package]]\nname = "openhands-sdk"\nversion = "1.51.0"\n')
    assert advisory_feed.load_feed().origin == "cached"
    assert len(scan(tmp_path)[0]) == 1
    feed.write_text("{ not json")
    assert advisory_feed.load_feed().origin == "bundled"
    assert scan(tmp_path)[0] == []  # the bundled records know nothing of openhands-sdk


def test_a_scan_never_touches_the_network(feed: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a scan opened a network connection")

    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", refuse)
    monkeypatch.setattr(http.client.HTTPConnection, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    result = run_scan(project_root=FIXTURES / "firing")
    assert len([f for f in result.findings if f.rule_id == RULE]) == 6
    assert not [f for f in result.findings if f.rule_id == "AAK-INTERNAL-SCANNER-FAIL"]


def test_reports_name_the_advisory_feed_copy() -> None:
    result = run_scan(project_root=FIXTURES / "negative")
    feed = result.data_feeds["knownVulnerabilities"]
    assert feed["origin"] == "bundled" and feed["generatedAt"]
    assert f"Advisory feed: bundled copy, generated {feed['generatedAt']}" in console_results(result)


@pytest.mark.parametrize(
    "vector, score",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),
        ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 5.4),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N", None),
        ("CVSS:3.1/AV:N/AC:L", None),
    ],
)
def test_cvss3_base_score(vector: str, score: float | None) -> None:
    assert advisory_feed.cvss3_base_score(vector) == score


def test_severity_falls_back_to_github_s_label_then_medium() -> None:
    v4 = {"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}], "database_specific": {"severity": "MODERATE"}}
    assert advisory_feed.record_severity(v4) == ("MEDIUM", None, "github")
    assert advisory_feed.record_severity({"database_specific": {"severity": "CRITICAL"}})[0] == "CRITICAL"
    assert advisory_feed.record_severity({}) == ("MEDIUM", None, "")


# ---- `aak update`: one download feeds both feeds -----------------------------------------------------


def _export(records: dict[str, dict]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, record in records.items():
            archive.writestr(f"{name}.json", json.dumps(record))
    return buffer.getvalue()


_TWO_RECORDS = {
    "MAL-2026-9001": {"id": "MAL-2026-9001", "affected": [
        {"package": {"ecosystem": "PyPI", "name": "aak-evil"}, "versions": ["1.0.0"]}]},
    "GHSA-aaaa-bbbb-cccc": {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-9002"], "modified": "m",
                            "database_specific": {"severity": "HIGH"}, "affected": [
        {"package": {"ecosystem": "PyPI", "name": "aak-flawed"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}]},
}


class _Response(io.BytesIO):
    headers: dict[str, str] = {"Link": ""}


def _counting_opener(calls: list[str]):
    def opener(request: urllib.request.Request, timeout: float | None = None) -> _Response:
        calls.append(request.full_url)
        if request.full_url.endswith("/PyPI/all.zip"):
            return _Response(_export(_TWO_RECORDS))
        if request.full_url.endswith("/npm/all.zip"):
            return _Response(_export({}))
        raise AssertionError(request.full_url)

    return opener


NOW = datetime(2026, 10, 29, 6, 0, tzinfo=timezone.utc)


def test_one_download_of_each_export_builds_both_feeds() -> None:
    calls: list[str] = []
    collector = advisory_feed.Collector()
    malicious_feed.refresh(opener=_counting_opener(calls), now=NOW, on_record=collector.add)
    written = collector.write(now=NOW)
    assert sorted(calls) == sorted(malicious_feed.OSV_EXPORT.format(ecosystem=e) for e in malicious_feed.ECOSYSTEMS)
    malicious = malicious_feed.load_feed()
    assert malicious.match("PyPI", "aak-evil", "1.0.0") and not malicious.match("PyPI", "aak-flawed", "1.0.0")
    advisories = advisory_feed.load_feed()
    assert advisories.origin == "cached" and written.counts == {"PyPI": 1, "npm": 0}
    assert [a.id for a in advisories.match("PyPI", "aak-flawed", "1.9.9")] == ["GHSA-aaaa-bbbb-cccc"]
    assert advisories.match("PyPI", "aak-evil", "1.0.0") == []
    assert not list(written.path.parent.glob(".advisories-*")) and not list(written.path.parent.glob(".osv-export-*"))


def test_a_feed_over_the_limit_keeps_high_and_critical_only() -> None:
    collector = advisory_feed.Collector()
    for ident, label in (("GHSA-1", "HIGH"), ("GHSA-2", "MODERATE")):
        collector.add("PyPI", {"id": ident, "database_specific": {"severity": label}, "affected": [
            {"package": {"ecosystem": "PyPI", "name": "aak-x"}, "versions": ["1.0.0"]}]})
    written = collector.write(now=NOW, limit=100)
    assert written.severity_floor == "HIGH" and written.full_size > written.size
    loaded = advisory_feed.load_feed()
    assert [a.id for a in loaded.match("PyPI", "aak-x", "1.0.0")] == ["GHSA-1"]
    assert loaded.summary()["severityFloor"] == "HIGH"


def test_aak_update_reports_both_feeds(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_audit_kit import vuln_db

    calls: list[str] = []
    monkeypatch.setattr(vuln_db, "update_database", lambda: 7)
    monkeypatch.setattr(malicious_feed.urllib.request, "urlopen", _counting_opener(calls))
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    result = CliRunner().invoke(cli, ["update"])
    assert result.exit_code == 0, result.output
    assert "Malicious-release feed updated: 2 entries" in result.output  # MAL-2026-9001 and the bundled one
    assert "Advisory feed updated: 1 entries for 1 packages (PyPI 1, npm 0)" in result.output
    assert len(calls) == 2


def test_aak_update_keeps_the_advisory_feed_when_the_download_fails(monkeypatch: pytest.MonkeyPatch,
                                                                    feed: Path) -> None:
    from agent_audit_kit import vuln_db

    before = feed.read_bytes()
    monkeypatch.setattr(vuln_db, "update_database", lambda: 7)
    monkeypatch.setattr(malicious_feed, "refresh", lambda **_: (_ for _ in ()).throw(
        malicious_feed.FeedUpdateError("URLError: offline")))
    result = CliRunner().invoke(cli, ["update"])
    assert result.exit_code == 2
    assert "Advisory feed not rebuilt" in result.output and "the cached feed" in result.output
    assert feed.read_bytes() == before


# ---- hostile and odd input ---------------------------------------------------------------------------


def test_an_odd_record_costs_only_itself() -> None:
    assert advisory_feed.advisory_entries({"id": "GHSA-x", "aliases": 5, "affected": "nope"}, "PyPI") == []
    record = {"id": "GHSA-y", "severity": "nope", "affected": [
        {"package": {"ecosystem": "PyPI", "name": "aak-p"}, "ranges": "nope", "versions": ["1.0.0", 3]}]}
    assert [e["versions"] for e in advisory_feed.advisory_entries(record, "PyPI")] == [["1.0.0"]]


def test_an_info_finding_that_counts_unnamed_advisories_is_never_dropped(tmp_path: Path) -> None:
    """Five advisories are named and the rest counted; the engine reads the CVE ids a
    finding names, so one that leaves some out must not be dropped on those alone."""
    records = [{"id": f"GHSA-many-{i}", "aliases": [f"CVE-2026-9{i:04d}"], "affected": [
        {"package": {"ecosystem": "PyPI", "name": "aak-many"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": f"2.0.{i}"}]}]}]}
        for i in range(7)]
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "records": records}))
    (tmp_path / "requirements.txt").write_text("aak-many>=1.0\n")
    (finding,) = scan(tmp_path)[0]
    assert finding.severity is Severity.INFO and "; and 2 more. " in finding.evidence
    assert evidence_cves(finding.evidence) == frozenset()


def test_two_ghsa_records_a_pysec_record_names_are_never_merged() -> None:
    """A PYSEC record naming two GitHub advisories used to join them into one group,
    reported with one of their ranges (python-jose's GHSA-6c5p-j8vq-pqhj was read only
    as GHSA-3qf3-8w2g-rqmx on 2026-10-29); each now stands for itself."""
    package = {"ecosystem": "PyPI", "name": "aak-twins"}
    records = [
        {"id": "GHSA-aaaa-1111-0001", "aliases": ["CVE-2026-90011"], "affected": [
            {"package": package, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}]},
        {"id": "GHSA-aaaa-1111-0002", "aliases": ["CVE-2026-90012"], "affected": [
            {"package": package, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}, {"fixed": "3.0.0"}]}]}]},
        {"id": "PYSEC-2026-90013", "aliases": ["CVE-2026-90011", "GHSA-aaaa-1111-0001", "GHSA-aaaa-1111-0002"],
         "affected": [{"package": package, "versions": ["1.0.0"]}]},
    ]
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "records": records}))
    feed = advisory_feed.load_feed()
    assert [a.id for a in feed.advisories("PyPI", "aak-twins")] == ["GHSA-aaaa-1111-0001", "GHSA-aaaa-1111-0002"]
    assert [a.id for a in feed.match("PyPI", "aak-twins", "2.5.0")] == ["GHSA-aaaa-1111-0002"]
    assert all("PYSEC-2026-90013" in a.aliases for a in feed.advisories("PyPI", "aak-twins"))


def test_a_rule_citing_the_cve_on_another_line_does_not_drop_the_finding() -> None:
    """A configuration check that cites the CVE elsewhere in the file says nothing about
    the version the entry on line 2 resolves."""
    known = _known("uv.lock", Severity.HIGH, "CVE-2026-59822")
    elsewhere = dataclasses.replace(_pin("uv.lock", Severity.CRITICAL), line_number=9)
    assert known in _drop_known_vulns_a_rule_reports([elsewhere, known])  # type: ignore[list-item]
    unplaced = dataclasses.replace(_pin("uv.lock", Severity.CRITICAL), line_number=None)
    assert known in _drop_known_vulns_a_rule_reports([unplaced, known])  # type: ignore[list-item]
