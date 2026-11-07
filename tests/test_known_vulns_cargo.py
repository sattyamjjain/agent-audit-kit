"""crates.io as a third advisory ecosystem, and AAK-KNOWN-VULN-001 on Cargo.lock.

SurrealDB's CVE-2026-121419 (3 Nov 2026) is the case: NVD's record names
`pkg:cargo/surrealdb`, 3.1.0 up to 3.3.0, and OSV has no record of it. The saved
record is under tests/fixtures/nvd_cna, unedited.
"""

from __future__ import annotations

import io
import json
import urllib.error
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
from agent_audit_kit.malicious_feed import canonical_name, version_order
from agent_audit_kit.models import Severity
from agent_audit_kit.scanners import agent_server_noauth, known_vulns, malicious_releases
from agent_audit_kit.scanners.supply_chain import _lockfile_canon

FIXTURES = Path(__file__).parent / "fixtures"
CVE = "CVE-2026-121419"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
RULE = "AAK-KNOWN-VULN-001"


def _record(cve: str = CVE) -> dict[str, Any]:
    (vuln,) = json.loads((FIXTURES / "nvd_cna" / f"{cve}.json").read_text())["vulnerabilities"]
    return vuln


def _lock(root: Path, version: str = "3.2.1", source: str | None = REGISTRY, name: str = "surrealdb") -> Path:
    block = f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
    if source:
        block += f'source = "{source}"\n'
    path = root / "Cargo.lock"
    path.write_text(f'version = 4\n\n[[package]]\nname = "app"\nversion = "0.1.0"\n\n{block}')
    return path


def _findings(root: Path) -> list[Any]:
    return [f for f in known_vulns.scan(root)[0] if f.rule_id == RULE]


# -- the record ------------------------------------------------------------------------------


def test_the_saved_record_maps_to_one_range_on_crates_io() -> None:
    entries = nvd_feed.record_entries(_record(), nvd_feed.load_package_map())
    assert [(e["ecosystem"], e["name"], e["ranges"], e["fixed"], e["severity"]) for e in entries] == [
        ("crates.io", "surrealdb", [{"introduced": "3.1.0", "fixed": "3.3.0"}], ["3.3.0"], "HIGH")]
    assert entries[0]["mapped_by"] == "packageURL"


def test_the_record_is_bundled() -> None:
    assert [a.id for a in advisory_feed.load_feed().match("crates.io", "surrealdb", "3.2.1")] == [CVE]


@pytest.mark.parametrize("low, high", [("3.2.9", "3.3.0"), ("3.3.0-beta.1", "3.3.0"), ("0.0.0-0", "0.1.0")])
def test_crate_versions_order_as_semver(low: str, high: str) -> None:
    low_key, high_key = version_order("crates.io", low), version_order("crates.io", high)
    assert low_key is not None and high_key is not None and low_key < high_key


# -- the lockfile ----------------------------------------------------------------------------


def test_a_registry_release_in_range_gives_one_finding(tmp_path: Path) -> None:
    (finding,) = _findings(_lock(tmp_path).parent)
    assert finding.file_path == "Cargo.lock" and finding.severity is Severity.HIGH
    assert CVE in finding.evidence and "fixed in 3.3.0" in finding.evidence and "surrealdb 3.2.1" in finding.evidence
    assert finding.line_number == 8


def test_the_committed_fixture_gives_one_finding_through_the_engine() -> None:
    result = run_scan(project_root=FIXTURES / "known_vulns_cargo" / "surrealdb-3.2.1", rules=[RULE])
    assert [(f.rule_id, f.line_number) for f in result.findings] == [(RULE, 13)]


@pytest.mark.parametrize("version", ["3.3.0", "3.0.9", "4.0.0"])
def test_a_release_outside_the_range_gives_none(tmp_path: Path, version: str) -> None:
    assert _findings(_lock(tmp_path, version).parent) == []


@pytest.mark.parametrize("version", ["3.1.0", "3.2.9", "3.3.0-beta.1"])
def test_the_range_is_read_as_semver(tmp_path: Path, version: str) -> None:
    assert len(_findings(_lock(tmp_path, version).parent)) == 1


def test_a_block_with_no_source_is_the_projects_own_code(tmp_path: Path) -> None:
    assert _findings(_lock(tmp_path, source=None).parent) == []


def test_a_git_dependency_is_judged_by_its_crate_version(tmp_path: Path) -> None:
    assert len(_findings(_lock(tmp_path, source="git+https://github.com/surrealdb/surrealdb?rev=abc#abc").parent)) == 1


def test_a_lockfile_with_the_same_name_in_another_format_is_not_read_as_cargo(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text('[[package]]\nname = "surrealdb"\nversion = "3.2.1"\n')
    assert _findings(tmp_path) == []


def test_a_nested_cargo_lock_is_read(tmp_path: Path) -> None:
    nested = tmp_path / "services" / "api"
    nested.mkdir(parents=True)
    _lock(nested)
    assert [f.file_path for f in _findings(tmp_path)] == ["services/api/Cargo.lock"]


# -- names -----------------------------------------------------------------------------------


@pytest.mark.parametrize("purl, expected", [
    ("pkg:cargo/surreal_db", "surreal-db"),
    ("pkg:cargo/surreal-db", "surreal-db"),
    ("pkg:cargo/Surreal_DB@1.2.3", "surreal-db"),
    ("pkg:cargo/SurrealDB", "surrealdb"),
])
def test_a_crate_purl_folds_as_cargo_compares_names(purl: str, expected: str) -> None:
    found = nvd_feed.purl_package(purl)
    assert found is not None and found[0] == "crates.io"
    assert canonical_name("crates.io", found[1]) == expected == _lockfile_canon(found[1], "cargo.lock")


@pytest.mark.parametrize("purl", ["pkg:maven/org.apache/log4j", "pkg:cargo/two/segments", "pkg:cargo/", "pkg:golang/a/b"])
def test_other_purls_name_nothing(purl: str) -> None:
    assert nvd_feed.purl_package(purl) is None


def test_a_crate_written_another_way_in_the_feed_still_matches() -> None:
    feed = advisory_feed.parse_feed({"entries": [{
        "id": "RUSTSEC-2026-0001", "aliases": [], "ecosystem": "crates.io", "name": "Surreal_DB",
        "ranges": [{"introduced": "0", "fixed": "2.0.0"}], "versions": [], "fixed": ["2.0.0"],
        "severity": "HIGH", "modified": "", "url": "",
    }], "nvd": []}, "cached", Path("advisories.json"))
    assert [a.id for a in feed.match("crates.io", "surreal-db", "1.0.0")] == ["RUSTSEC-2026-0001"]
    assert "surreal-db" in feed.names("crates.io")


# -- the export ------------------------------------------------------------------------------


def _export(records: dict[str, dict[str, Any]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        for name, record in records.items():
            bundle.writestr(f"{name}.json", json.dumps(record))
    return buffer.getvalue()


def _crate_record(ident: str, name: str = "crate-a", informational: str | None = None, **extra: Any) -> dict[str, Any]:
    specific = {"informational": informational} if informational else {}
    return {"id": ident, "modified": "2026-11-01T00:00:00Z", **extra, "affected": [{
        "package": {"ecosystem": "crates.io", "name": name},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0.0.0-0"}, {"fixed": "1.2.0"}]}],
        "database_specific": specific,
    }]}


@pytest.mark.parametrize("kind", ["unmaintained", "unsound", "notice"])
def test_a_rustsec_notice_is_no_advisory(kind: str) -> None:
    assert advisory_feed.advisory_entries(_crate_record("RUSTSEC-2026-0001", informational=kind), "crates.io") == []


def test_a_rustsec_vulnerability_is_kept() -> None:
    (entry,) = advisory_feed.advisory_entries(_crate_record("RUSTSEC-2026-0002", aliases=["CVE-2026-1"]), "crates.io")
    assert (entry["ecosystem"], entry["ranges"], entry["severity"]) == (
        "crates.io", [{"introduced": "0.0.0-0", "fixed": "1.2.0"}], "MEDIUM")


def test_a_mal_record_stays_out_of_the_advisory_feed() -> None:
    assert advisory_feed.advisory_entries(_crate_record("MAL-2026-1"), "crates.io") == []


def test_a_crate_named_in_another_ecosystems_block_is_not_read_as_a_crate() -> None:
    record = {"id": "GHSA-aaaa", "modified": "", "affected": [{
        "package": {"ecosystem": "npm", "name": "surrealdb"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}
    assert advisory_feed.advisory_entries(record, "crates.io") == []


def test_an_osv_record_of_the_cve_wins_over_nvds() -> None:
    osv = [{"id": "RUSTSEC-2026-9", "aliases": [CVE], "ecosystem": "crates.io", "name": "SurrealDB"}]
    nvd = [{"id": CVE, "ecosystem": "crates.io", "name": "surrealdb"}]
    assert advisory_feed.without_osv_twins(osv, nvd) == ([], 1)


class _Response(io.BytesIO):
    headers: dict[str, str] = {"Link": ""}


def _opener(calls: list[str], crates: bytes | None):
    def opener(request: urllib.request.Request, timeout: float | None = None) -> _Response:
        calls.append(request.full_url)
        if request.full_url.endswith("/crates.io/all.zip"):
            if crates is None:
                raise urllib.error.URLError("offline")
            return _Response(crates)
        return _Response(_export({}))

    return opener


@pytest.fixture
def update(monkeypatch: pytest.MonkeyPatch):
    from agent_audit_kit import vuln_db

    monkeypatch.setattr(vuln_db, "update_database", lambda: 7)
    for name in ("GITHUB_TOKEN", "GH_TOKEN", "NVD_API_KEY"):
        monkeypatch.delenv(name, raising=False)

    def run(crates: bytes | None) -> Any:
        calls: list[str] = []
        monkeypatch.setattr(malicious_feed.urllib.request, "urlopen", _opener(calls, crates))
        result = CliRunner().invoke(cli, ["update", "--nvd-days", "0"])
        result.calls = calls  # type: ignore[attr-defined]
        return result

    return run


def test_aak_update_reads_the_crates_io_export(update: Any, tmp_path: Path) -> None:
    result = update(_export({
        "RUSTSEC-2026-0002": _crate_record("RUSTSEC-2026-0002"),
        "RUSTSEC-2026-0003": _crate_record("RUSTSEC-2026-0003", name="crate-b", informational="unmaintained"),
        "MAL-2026-1": _crate_record("MAL-2026-1", name="crate-c"),
    }))
    assert result.exit_code == 0, result.output
    assert "1 packages (PyPI 0, npm 0, crates.io 1)" in result.output
    assert result.calls.count(malicious_feed.OSV_EXPORT.format(ecosystem="crates.io")) == 1
    data = json.loads(advisory_feed.cache_path().read_text())
    assert [e["id"] for e in data["entries"]] == ["RUSTSEC-2026-0002"]
    assert malicious_feed.OSV_EXPORT.format(ecosystem="crates.io") in data["source"]
    _lock(tmp_path, "1.0.0", name="crate_a")
    (finding,) = _findings(tmp_path)
    assert "RUSTSEC-2026-0002" in finding.evidence and "fixed in 1.2.0" in finding.evidence


def test_the_malicious_feed_is_left_as_it_was(update: Any, tmp_path: Path) -> None:
    update(_export({"MAL-2026-1": _crate_record("MAL-2026-1", name="crate-c")}))
    assert malicious_feed.ECOSYSTEMS == ("PyPI", "npm")
    data = json.loads(malicious_feed.cache_path().read_text())
    assert not [e for e in data["entries"] if e["ecosystem"] == "crates.io"]
    assert "crates.io" not in data["source"]
    _lock(tmp_path, "1.0.0", name="crate-c")
    assert malicious_releases.scan(tmp_path)[0] == []


def test_a_failed_crates_download_keeps_what_was_cached(update: Any) -> None:
    assert update(_export({"RUSTSEC-2026-0002": _crate_record("RUSTSEC-2026-0002")})).exit_code == 0
    result = update(None)
    assert result.exit_code != 0
    assert "Advisory export read failed" in result.output and "keeps 1 cached entries" in result.output
    data = json.loads(advisory_feed.cache_path().read_text())
    assert [e["id"] for e in data["entries"]] == ["RUSTSEC-2026-0002"]


def test_a_corrupt_export_fails_cleanly(update: Any) -> None:
    result = update(b"not a zip")
    assert result.exit_code != 0 and "Advisory export read failed" in result.output
    assert advisory_feed.cache_path().is_file()


def test_no_export_leaves_a_download_behind(update: Any) -> None:
    update(_export({}))
    assert not list(advisory_feed.cache_path().parent.glob(".osv-export-*"))


def test_a_collector_with_no_crates_read_writes_the_two_registries() -> None:
    written = advisory_feed.Collector().write(now=datetime(2026, 11, 7, tzinfo=timezone.utc))
    assert written.counts == {"PyPI": 0, "npm": 0}


# -- who else reads the lockfile table -------------------------------------------------------


def test_a_crate_named_like_a_python_distribution_is_not_that_distribution(tmp_path: Path) -> None:
    lock = _lock(tmp_path, "1.0.0", name="openhands_sdk")
    assert agent_server_noauth._releases(tmp_path, [lock], []) == []


def test_supply_002_still_reads_the_file_on_its_own(tmp_path: Path) -> None:
    from agent_audit_kit.scanners.supply_chain import _scan_rust_deps

    _lock(tmp_path)
    assert [f.rule_id for f in _scan_rust_deps(tmp_path) if f.rule_id == "AAK-SUPPLY-002"] == []
